const std = @import("std");
const r = @import("records.zig");
const k = @import("kernel.zig");
const linux = k.linux;
const root = @import("root.zig");
pub const Dispatch = struct {
    expected: r.Expected,
    nonce: r.Hash,
    boot: r.Uuid,
    owner: r.Identity,
    directory: r.Directory,
    worker_directory: r.Directory,
    deadline_ns: u64,
    cleanup_ms: u32,
    control_reserved: u64,
};
pub const WorkerInput = struct {
    expected: r.Expected,
    directory: r.core.private_files.Directory,
    io: std.Io,
    deadline: r.core.process.Deadline,
};
const Event = extern struct {
    magic: u32 = 0x47554152,
    cause: u32,
    worker_status: u32,
};

fn readDispatch(comptime T: type, a: std.mem.Allocator, io: std.Io) !std.json.Parsed(T) {
    const bytes = try k.readSealed(a, io, 3);
    defer a.free(bytes);
    return r.parse(T, a, bytes);
}
fn validate(comptime kind: r.Kind, io: std.Io, value: Dispatch, executable: i32) !void {
    try value.expected.validate();
    if (value.expected.kind != kind) return error.KindMismatch;
    const image = try root.selfIdentity(io, executable);
    if (!std.mem.eql(u8, &image.digest, &value.expected.implementation)) return error.NativeBindingMismatch;
    try value.expected.budget.admit(image.bytes, value.control_reserved);
    if (value.cleanup_ms < 100 or value.cleanup_ms > 1200000) return error.InvalidDeadline;
    const now = try k.now();
    if (value.deadline_ns <= now or value.deadline_ns - now > 3600 * std.time.ns_per_s) return error.InvalidDeadline;
}
pub fn custodian(comptime kind: r.Kind, a: std.mem.Allocator, io: std.Io, failures: *r.core.diagnostics.Failures) !void {
    try k.protect();
    var sensitive: r.core.sensitive.Allocator = .{ .backing = a };
    const wiping = sensitive.allocator();
    const startup = try readDispatch(Dispatch, wiping, io);
    defer startup.deinit();
    k.close(3);
    const value = startup.value;
    try k.requireProc(8);
    try validate(kind, io, value, 6);
    try k.requireUnprivileged(8);
    if (value.owner.start_ticks != try k.startTicks(8, value.owner.pid) or
        !std.meta.eql(value.owner.namespace, (try k.identity(8, linux.getpid())).namespace) or
        !std.mem.eql(u8, &value.boot, &try k.boot(8)) or
        !std.meta.eql(value.directory, try k.directory(4)) or !std.meta.eql(value.worker_directory, try k.directory(7)))
        return error.DispatchIdentityMismatch;
    if (try k.readable(5) or try k.now() >= value.deadline_ns) return error.OwnerUnavailable;
    _ = try k.checked(linux.fchdir(4));
    const directory = try r.core.private_files.Directory.openWorkerCwd(io);
    defer directory.close(io);
    var lock = try directory.lock(io);
    defer lock.close(io);
    // Claim before namespace creation; a crash or failed registration consumes
    // this attempt directory permanently, without authorizing any work.
    const claim = try r.canonical(a, .{ .nonce = value.nonce, .expected = value.expected });
    defer a.free(claim);
    try publish(&lock, io, "custody-claim.json", claim);
    const configuration = try r.canonical(a, value);
    defer a.free(configuration);
    const public_fd = try k.memfd(configuration);
    defer k.close(public_fd);
    const events = try k.pipe();
    defer for (events) |descriptor| k.close(descriptor);
    const gate = try k.pipe();
    defer for (gate) |descriptor| k.close(descriptor);
    const self = try k.identity(8, linux.getpid());
    const self_fd = try k.pidfd(self.pid);
    defer k.close(self_fd);
    const child = try k.spawnNamespace(6, &.{ public_fd, 7, 5, 6, self_fd, events[1], gate[0], 9 }, value.deadline_ns);
    const pid = child.pid;
    const retained = child.pidfd;
    defer k.close(retained);
    var reaped = false;
    defer if (!reaped) {
        // No proof can be emitted on this path. PID1 also watches the original
        // owner independently, so a blocked recording writer cannot keep work alive.
        terminateAndReap(child, value.cleanup_ms) catch {
            if (failures.cleanup == null) failures.cleanup = .{ .stage = .process_cleanup, .category = .cleanup_failed };
        };
    };
    const ready_deadline = @min(value.deadline_ns, try k.now() + 5 * std.time.ns_per_s);
    var ready: [1]u8 = undefined;
    while (!try k.readable(events[0])) {
        if (try k.readable(retained) or try k.readable(5) or try k.now() >= ready_deadline) return error.NamespaceSetupFailed;
        k.pause();
    }
    if (try k.read(events[0], &ready) != 1 or ready[0] != 0x4d) return error.NamespaceSetupFailed;
    const namespace_init = try k.identity(8, pid);
    try k.requirePid1(8, pid);
    if (std.meta.eql(namespace_init.namespace, self.namespace)) return error.NamespaceIsolationMissing;
    try k.mapChild(8, pid);
    try k.write(gate[1], &.{0x55});
    while (!try k.readable(events[0])) {
        if (try k.readable(retained) or try k.readable(5) or try k.now() >= ready_deadline) return error.NamespaceSetupFailed;
        k.pause();
    }
    if (try k.read(events[0], &ready) != 1 or ready[0] != 0x52 or try k.readable(retained)) return error.NamespaceSetupFailed;
    // Load the signing key only after the isolated child has execed. Its
    // descriptor 10 was replaced with cancellation before the mapping gate.
    const key = try k.readSealed(wiping, io, 10);
    defer wiping.free(key);
    k.close(10);
    if (key.len != 32) return error.InvalidSigningKey;
    var signer = try r.Signer.fromSeed(key[0..32].*, value.expected.public_key);
    defer signer.deinit();
    const registration: r.Registration = .{
        .schema = "uk-operator-custody-registration-v1",
        .expected = value.expected,
        .nonce = value.nonce,
        .boot = value.boot,
        .owner = value.owner,
        .custodian = self,
        .namespace_init = namespace_init,
        .directory = value.directory,
        .worker_directory = value.worker_directory,
        .deadline_ns = value.deadline_ns,
        .registered_ns = try k.now(),
        .cleanup_ms = value.cleanup_ms,
        .control_reserved = value.control_reserved,
    };
    const registration_bytes = try signer.sign(a, registration, "uk-operator-custody-registration-v1");
    defer a.free(registration_bytes);
    try publish(&lock, io, "custody-registration.json", registration_bytes);
    var status: u32 = undefined;
    var owner_lost = try k.readable(5);
    var cancelled = false;
    // Once registered, even a pre-dispatch interruption must reach the kernel
    // reap/seal path. Never open the worker gate after authority has ended.
    if (!owner_lost and try k.now() < value.deadline_ns) {
        try k.write(gate[1], &.{0x47});
    } else try k.kill(retained);
    const ceiling = try std.math.add(u64, value.deadline_ns, @as(u64, value.cleanup_ms) * std.time.ns_per_ms);
    while (true) {
        if (try k.reap(pid)) |exited| {
            status = exited;
            reaped = true;
            break;
        }
        if (try k.readable(5)) {
            owner_lost = true;
            try k.kill(retained);
        }
        if (try k.readable(9)) {
            cancelled = true;
            try k.kill(retained);
        }
        if (try k.now() >= value.deadline_ns) try k.kill(retained);
        if (try k.now() >= ceiling) return error.ProcessRecoveryRequired;
        k.pause();
    }
    var event: Event = undefined;
    var cause: r.Cause = .initializer_failed;
    var worker_status: ?u32 = null;
    const length = k.read(events[0], std.mem.asBytes(&event)) catch |err| switch (err) {
        error.WouldBlock => 0,
        else => return err,
    };
    if (length == @sizeOf(Event) and event.magic == 0x47554152) {
        cause = std.enums.fromInt(r.Cause, event.cause) orelse return error.InvalidInitializerReport;
        if (event.worker_status != std.math.maxInt(u32)) worker_status = event.worker_status;
    }
    if (owner_lost and cause == .initializer_failed) cause = .owner_died;
    if (cancelled and cause == .initializer_failed) cause = .cancelled;
    if (cause == .initializer_failed and try k.now() >= value.deadline_ns) cause = .deadline;
    if (cause == .completed and (!linux.W.IFEXITED(status) or linux.W.EXITSTATUS(status) != 0 or
        worker_status == null or !linux.W.IFEXITED(worker_status.?) or linux.W.EXITSTATUS(worker_status.?) != 0))
        cause = .initializer_failed;
    if (cause != .completed) failures.primary = .{
        .stage = .process_run,
        .category = switch (cause) {
            .deadline => .timeout,
            .cancelled, .owner_died => .cancelled,
            .output_limit => .output_limit,
            else => .child_failed,
        },
    };
    const seal: r.Seal = .{ .schema = "uk-operator-custody-seal-v1", .witness = .pid_namespace_init_reaped, .registration = r.hash(registration_bytes), .cause = cause, .init_status = status, .worker_status = worker_status, .stopped_ns = try k.now(), .failures = failures.* };
    const sealed = try signer.sign(a, seal, "uk-operator-custody-seal-v1");
    defer a.free(sealed);
    try publish(&lock, io, "custody-seal.json", sealed);
}
fn terminateAndReap(child: k.Child, cleanup_ms: u32) !void {
    const deadline = try r.core.process.Deadline.afterMilliseconds(cleanup_ms);
    try k.kill(child.pidfd);
    while (try k.reap(child.pid) == null) {
        if (try deadline.expired()) return error.ProcessRecoveryRequired;
        k.pause();
    }
}
fn publish(lock: *r.core.private_files.Locked, io: std.Io, name: []const u8, bytes: []const u8) !void {
    const result = lock.createImmutable(io, name, bytes) catch return error.RecordingFailed;
    try r.durable(result);
}

pub fn namespaceInit(comptime kind: r.Kind, a: std.mem.Allocator, io: std.Io) !void {
    if (linux.getpid() != 1 or linux.getppid() != 0) return error.NotNamespaceInit;
    _ = try k.checked(linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @intFromEnum(linux.SIG.KILL), 0, 0, 0));
    if (try k.readable(7) or try k.readable(5)) return error.OwnerUnavailable;
    const configuration = try readDispatch(Dispatch, a, io);
    defer configuration.deinit();
    const value = configuration.value;
    try validate(kind, io, value, 6);
    try k.mountProc();
    try k.dropCapabilities();
    try k.write(8, &.{0x52});
    // No worker exists until registration durability has been acknowledged.
    while (!try k.readable(9)) {
        if (try k.readable(5) or try k.readable(7) or try k.now() >= value.deadline_ns) return error.OwnerUnavailable;
        k.pause();
    }
    var gate: [1]u8 = undefined;
    if (try k.read(9, &gate) != 1 or gate[0] != 0x47 or try k.readable(5) or try k.readable(7) or
        try k.now() >= value.deadline_ns) return error.DispatchNotAdmitted;
    const stdout = try k.pipe();
    defer for (stdout) |descriptor| k.close(descriptor);
    const stderr = try k.pipe();
    defer for (stderr) |descriptor| k.close(descriptor);
    _ = try k.checked(linux.fcntl(stdout[1], linux.F.SETFL, 0));
    _ = try k.checked(linux.fcntl(stderr[1], linux.F.SETFL, 0));
    const child = try k.spawn(6, "--operator-guard-worker", &.{ 3, 4, 6 }, .{ stdout[1], stderr[1] });
    const pid = child.pid;
    defer k.close(child.pidfd);
    var counts = [_]usize{ 0, 0 };
    var cause: r.Cause = .initializer_failed;
    var worker_status: u32 = std.math.maxInt(u32);
    while (true) {
        if (try k.readable(5)) {
            cause = .owner_died;
            break;
        }
        if (try k.readable(7)) return error.CustodianLost;
        if (try k.now() >= value.deadline_ns) {
            cause = .deadline;
            break;
        }
        if (try k.readable(10)) {
            var cancel: u64 = 0;
            if (try k.read(10, std.mem.asBytes(&cancel)) == 8 and cancel != 0) {
                cause = .cancelled;
                break;
            }
        }
        var overflow = false;
        for ([_]i32{ stdout[0], stderr[0] }, &counts) |descriptor, *count| {
            var bytes: [4096]u8 = undefined;
            const n = k.read(descriptor, &bytes) catch |err| switch (err) {
                error.WouldBlock => 0,
                else => return err,
            };
            if (n > r.output_limit - count.*) {
                overflow = true;
                break;
            }
            count.* += n;
        }
        if (overflow) {
            cause = .output_limit;
            break;
        }
        if (try k.reap(pid)) |exited| {
            worker_status = exited;
            cause = if (linux.W.IFEXITED(exited) and linux.W.EXITSTATUS(exited) == 0) .completed else .worker_failed;
            for ([_]i32{ stdout[0], stderr[0] }, &counts) |descriptor, *count| {
                while (true) {
                    var bytes: [4096]u8 = undefined;
                    const n = k.read(descriptor, &bytes) catch |err| switch (err) {
                        error.WouldBlock => break,
                        else => return err,
                    };
                    if (n == 0) break;
                    if (n > r.output_limit - count.*) {
                        cause = .output_limit;
                        break;
                    }
                    count.* += n;
                }
            }
            break;
        }
        k.pause();
    }
    const event: Event = .{ .cause = @intFromEnum(cause), .worker_status = worker_status };
    try k.write(8, std.mem.asBytes(&event));
    // Exiting PID1 is the containment primitive, including setsid/double-fork
    // descendants. The custodian must reap this init before signing a witness.
}

pub fn worker(comptime kind: r.Kind, a: std.mem.Allocator, io: std.Io, comptime handler: fn (WorkerInput) anyerror!void) !void {
    if (linux.getpid() <= 1 or linux.getppid() != 1) return error.WorkerOutsideCustody;
    const parsed = try readDispatch(Dispatch, a, io);
    defer parsed.deinit();
    try validate(kind, io, parsed.value, 5);
    if (!std.meta.eql(parsed.value.worker_directory, try k.directory(4))) return error.WorkerDirectoryMismatch;
    k.close(3);
    k.close(5);
    _ = try k.checked(linux.fchdir(4));
    k.close(4);
    const directory = try r.core.private_files.Directory.openWorkerCwd(io);
    defer directory.close(io);
    try k.protect();
    try handler(.{ .expected = parsed.value.expected, .directory = directory, .io = io, .deadline = .{ .expires_ns = parsed.value.deadline_ns } });
}
