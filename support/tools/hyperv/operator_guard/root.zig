const std = @import("std");
pub const records = @import("records.zig");
pub const kernel = @import("kernel.zig");
pub const core = records.core;
pub const runtime = @import("runtime.zig");
pub const recovery = @import("recovery.zig");
pub const Signer = records.Signer;
pub const Expected = records.Expected;
pub const Proof = records.Proof;
pub const WorkerInput = runtime.WorkerInput;
const k = kernel;
const r = records;

pub const Options = struct {
    expected: Expected,
    signer: *const Signer,
    directory: core.private_files.Directory,
    worker_directory: core.private_files.Directory,
    deadline: core.process.Deadline,
    cleanup_ms: u32 = 2000,
    control_reserved: u64,
};
pub const Handle = struct {
    pid: i32,
    pidfd: k.linux.fd_t,
    cancel_fd: k.linux.fd_t,
    feedback_fd: k.linux.fd_t,
    deadline: core.process.Deadline,
    cleanup_ms: u32,
    reaped: bool = false,

    pub fn cancel(self: *Handle) !void {
        if (self.reaped) return error.ProcessRecoveryRequired;
        const value: u64 = 1;
        try k.write(self.cancel_fd, std.mem.asBytes(&value));
    }
    pub fn wait(self: *Handle, a: std.mem.Allocator) !WaitResult {
        const ceiling = try std.math.add(u64, self.deadline.expires_ns, @as(u64, self.cleanup_ms) * std.time.ns_per_ms);
        const kill_at = ceiling - @as(u64, @min(1000, self.cleanup_ms / 2)) * std.time.ns_per_ms;
        var killed = false;
        while (true) {
            if (try k.reap(self.pid)) |status| {
                self.reaped = true;
                var result: WaitResult = .{ .status = status };
                if (killed) {
                    result.failures.primary = .{ .stage = .process_run, .category = .timeout };
                    result.failures.cleanup = .{ .stage = .process_cleanup, .category = .cleanup_failed };
                }
                var buffer: [4096]u8 = undefined;
                const length = k.read(self.feedback_fd, &buffer) catch return error.FailureDeliveryLost;
                if (length != 0) {
                    const parsed = try r.parse(core.diagnostics.Failures, a, buffer[0..length]);
                    defer parsed.deinit();
                    if (parsed.value.primary) |value| try result.failures.record(.primary, value);
                    if (parsed.value.cleanup) |value| try result.failures.record(.cleanup, value);
                    if (parsed.value.recording) |value| try result.failures.record(.recording, value);
                } else {
                    try result.failures.record(.recording, .{ .stage = .process_run, .category = .invalid_response });
                    try result.failures.record(.cleanup, .{ .stage = .process_cleanup, .category = .cleanup_failed });
                }
                if (!k.linux.W.IFEXITED(status) or k.linux.W.EXITSTATUS(status) != 0)
                    try result.failures.record(.primary, .{ .stage = .process_run, .category = .child_failed });
                return result;
            }
            if (try k.now() >= kill_at) {
                if (!killed) {
                    try k.kill(self.pidfd);
                    killed = true;
                }
                // Keep the pidfd and ownership if the kernel cannot complete exit.
                if (try k.now() >= ceiling) return error.ProcessRecoveryRequired;
            }
            k.pause();
        }
    }
    pub fn close(self: *Handle) !void {
        if (!self.reaped) return error.ProcessRecoveryRequired;
        k.close(self.pidfd);
        k.close(self.cancel_fd);
        k.close(self.feedback_fd);
    }
};
pub const WaitResult = struct { status: u32, failures: core.diagnostics.Failures = .{} };

/// Dedicated operator process only. The fixed internal dispatch must be bound
/// in this same verified executable; no executable/argv/environment is accepted.
pub fn start(a: std.mem.Allocator, io: std.Io, options: Options) !Handle {
    try options.expected.validate();
    if (!std.mem.eql(u8, &options.signer.public_key, &options.expected.public_key)) return error.SigningKeyMismatch;
    const current = try k.now();
    if (options.deadline.expires_ns <= current or options.deadline.expires_ns - current > 3600 * std.time.ns_per_s or
        options.cleanup_ms < 100 or options.cleanup_ms > 1200000) return error.InvalidDeadline;
    try k.protect();
    const executable = try k.fd(k.linux.openat(k.linux.AT.FDCWD, "/proc/self/exe", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0));
    defer k.close(executable);
    const identity = try selfIdentity(io, executable);
    if (!std.mem.eql(u8, &identity.digest, &options.expected.implementation)) return error.NativeBindingMismatch;
    if (options.control_reserved > r.max_control or try requiredControl(identity.bytes) > options.control_reserved)
        return error.ControlReservationExceeded;
    const proc = try k.openProc();
    defer k.close(proc);
    try k.requireUnprivileged(proc);
    const owner = try k.identity(proc, k.linux.getpid());
    const owner_fd = try k.pidfd(owner.pid);
    defer k.close(owner_fd);
    var nonce: r.Hash = undefined;
    io.random(&nonce);
    const public: runtime.Dispatch = .{
        .expected = options.expected,
        .nonce = nonce,
        .boot = try k.boot(proc),
        .owner = owner,
        .directory = try k.directory(options.directory.dir.handle),
        .worker_directory = try k.directory(options.worker_directory.dir.handle),
        .deadline_ns = options.deadline.expires_ns,
        .cleanup_ms = options.cleanup_ms,
        .control_reserved = options.control_reserved,
    };
    if (std.meta.eql(public.directory, public.worker_directory)) return error.SeparateGuardDirectoryRequired;
    var sensitive: core.sensitive.Allocator = .{ .backing = a };
    const wiping = sensitive.allocator();
    const bytes = try r.canonical(wiping, public);
    defer wiping.free(bytes);
    const request = try k.memfd(bytes);
    defer k.close(request);
    const key = try k.memfd(&options.signer.seed);
    defer k.close(key);
    const cancellation = try k.eventfd();
    errdefer k.close(cancellation);
    const feedback = try k.pipe();
    errdefer for (feedback) |descriptor| k.close(descriptor);
    const child = try k.spawn(executable, "--operator-guard-custodian", &.{ request, options.directory.dir.handle, owner_fd, executable, options.worker_directory.dir.handle, proc, cancellation, key, feedback[1] }, .{ 1, 2 });
    k.close(feedback[1]);
    return .{ .pid = child.pid, .pidfd = child.pidfd, .cancel_fd = cancellation, .feedback_fd = feedback[0], .deadline = options.deadline, .cleanup_ms = options.cleanup_ms };
}
pub const ExecutableIdentity = struct { digest: r.Hash, bytes: u64 };
pub fn requiredControl(binary_bytes: u64) !u64 {
    const bytes = std.math.add(u64, binary_bytes, r.overhead) catch return error.ControlReservationExceeded;
    if (bytes > r.max_control) return error.ControlReservationExceeded;
    return bytes;
}
pub fn selfIdentity(io: std.Io, descriptor: k.linux.fd_t) !ExecutableIdentity {
    const file: std.Io.File = .{ .handle = descriptor, .flags = .{ .nonblocking = false } };
    const before = try core.private_files.snapshot(file);
    if (before.mode & 0o6000 != 0 or before.size > 64 * 1024 * 1024) return error.UnsafeExecutable;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var offset: u64 = 0;
    var buffer: [16384]u8 = undefined;
    while (offset < before.size) {
        const n = try file.readPositionalAll(io, buffer[0..@intCast(@min(buffer.len, before.size - offset))], offset);
        if (n == 0) return error.ExecutableChanged;
        hash.update(buffer[0..n]);
        offset += n;
    }
    if (!core.private_files.sameSnapshot(before, try core.private_files.snapshot(file))) return error.ExecutableChanged;
    return .{ .digest = hash.finalResult(), .bytes = before.size };
}

/// The worker handler is statically selected by the integrating executable,
/// never by a path, arbitrary command, HTTP record or fixture flag.
pub fn dispatch(comptime kind: r.Kind, init: std.process.Init, comptime handler: fn (WorkerInput) anyerror!void) !bool {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return false;
    if (std.mem.eql(u8, args[1], "--operator-guard-custodian")) {
        var failures: core.diagnostics.Failures = .{};
        runtime.custodian(kind, init.gpa, init.io, &failures) catch |err| {
            if (err == error.RecordingFailed) {
                try failures.record(.recording, .{ .stage = .state_record, .category = .local_io });
            } else try failures.record(.primary, .{ .stage = .process_run, .category = .child_failed });
            try failures.record(.cleanup, .{ .stage = .process_cleanup, .category = .cleanup_failed });
            try deliver(init.gpa, failures);
            return err;
        };
        try deliver(init.gpa, failures);
    } else if (std.mem.eql(u8, args[1], "--operator-guard-init")) {
        try runtime.namespaceInit(kind, init.gpa, init.io);
    } else if (std.mem.eql(u8, args[1], "--operator-guard-worker")) {
        try runtime.worker(kind, init.gpa, init.io, handler);
    } else return false;
    return true;
}
fn deliver(a: std.mem.Allocator, failures: core.diagnostics.Failures) !void {
    // A dead original owner has no feedback consumer. Recovery uses the
    // durable signed witness instead, never absence of this pipe's output.
    if (try k.readable(5)) return;
    const bytes = try r.canonical(a, failures);
    defer a.free(bytes);
    if (bytes.len > 4096) return error.FailureDeliveryLost;
    try k.write(11, bytes);
}
