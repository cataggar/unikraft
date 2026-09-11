const std = @import("std");
const guard = @import("operator_guard");
const k = guard.kernel;
const r = guard.records;

pub const Mode = enum {
    normal,
    deadline,
    flood,
    before,
    recording,
    registration,
    cancel,
    after_registration,
    pre_dispatch_cancel,
    cancel_observed,
    seal_sync_failure,
    seal_sync_owner_loss,
    seal_interrupted,
};
pub const Request = struct { mode: Mode, expected: r.Expected };
pub const seed = [_]u8{0x59} ** 32;
pub const budget: r.Budget = .{ .control = 8388608, .staging = 268435456 };

// Faults exist only in this separately bound synthetic executable. File markers
// coordinate actual process interruption; they never act as recovery evidence.
const Fault = struct {
    original: std.Io,
    mode: Mode = .normal,
    table: std.Io.VTable = undefined,
    fired: bool = false,
    threadlocal var active: *Fault = undefined;
    fn install(self: *Fault) std.Io {
        self.table = self.original.vtable.*;
        self.table.fileSync = sync;
        self.table.operate = operate;
        active = self;
        return .{ .userdata = self.original.userdata, .vtable = &self.table };
    }
    fn sync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
        const self = active;
        if (self.fired) return self.original.vtable.fileSync(userdata, file);
        const before = k.directory(4) catch return error.InputOutput;
        const actual = k.directory(file.handle) catch return error.InputOutput;
        if (!std.meta.eql(before, actual)) return self.original.vtable.fileSync(userdata, file);
        const registration_boundary = self.mode == .after_registration or self.mode == .pre_dispatch_cancel;
        if (registration_boundary) try self.original.vtable.fileSync(userdata, file);
        const name: [:0]const u8 = if (registration_boundary) "custody-registration.json" else "custody-seal.json";
        const visible = k.linux.openat(4, name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (k.linux.errno(visible)) {
            .SUCCESS => {
                k.close(@intCast(visible));
                self.fired = true;
                switch (self.mode) {
                    .after_registration => self.killOwner() catch return error.InputOutput,
                    .pre_dispatch_cancel => self.cancelBeforeGate() catch return error.InputOutput,
                    .seal_sync_failure => return error.InputOutput,
                    .seal_sync_owner_loss => {
                        self.killOwner() catch return error.InputOutput;
                        return error.InputOutput;
                    },
                    .seal_interrupted => {
                        mark(7, "seal-visible") catch return error.InputOutput;
                        while (true) k.pause();
                    },
                    else => return error.InputOutput,
                }
                return;
            },
            .NOENT => {},
            else => return error.InputOutput,
        }
        if (!registration_boundary) try self.original.vtable.fileSync(userdata, file);
    }
    fn killOwner(_: *Fault) !void {
        try k.kill(5);
        while (!try k.readable(5)) k.pause();
    }
    fn cancelBeforeGate(self: *Fault) !void {
        const cancel: u64 = 1;
        try k.write(9, std.mem.asBytes(&cancel));
        const directory: guard.core.private_files.Directory = .{ .dir = .{ .handle = 4 } };
        const bytes = try directory.read(self.original, std.heap.page_allocator, "custody-registration.json", r.max_record, null);
        defer std.heap.page_allocator.free(bytes);
        const pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        const parsed = try r.verify(r.Registration, std.heap.page_allocator, bytes, pair.public_key.toBytes(), "uk-operator-custody-registration-v1");
        defer parsed.deinit();
        const init_fd = try k.pidfd(parsed.value.namespace_init.pid);
        defer k.close(init_fd);
        const deadline = try guard.core.process.Deadline.afterMilliseconds(750);
        while (!try k.readable(init_fd)) {
            if (try deadline.expired()) return error.PreDispatchCancellationIgnored;
            k.pause();
        }
        try mark(7, "pre-dispatch-observed");
    }
    fn operate(userdata: ?*anyopaque, operation: std.Io.Operation) std.Io.Cancelable!std.Io.Operation.Result {
        const self = active;
        switch (operation) {
            .file_write_streaming => |write| {
                if (self.mode == .cancel_observed and write.file.handle == 8) {
                    if (!(k.readable(10) catch return .{ .file_write_streaming = error.InputOutput }))
                        return .{ .file_write_streaming = error.InputOutput };
                    mark(4, "cancel-observed") catch return .{ .file_write_streaming = error.InputOutput };
                    while (true) k.pause();
                }
            },
            else => {},
        }
        return self.original.vtable.operate(userdata, operation);
    }
};

fn mark(directory: i32, name: [:0]const u8) !void {
    const file = try k.fd(k.linux.openat(directory, name, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o600));
    defer k.close(file);
    try k.write(file, "observed\n");
}

pub fn main(init: std.process.Init) void {
    execute(init) catch |err| {
        // Synthetic executable only; production has no fixture dispatch.
        std.Io.File.stderr().writeStreamingAll(init.io, @errorName(err)) catch {};
        std.Io.File.stderr().writeStreamingAll(init.io, "\n") catch {};
        std.process.exit(2);
    };
}
fn execute(init: std.process.Init) !void {
    // Scope CI kernel-denial evidence to this synthetic executable.
    _ = try k.checked(k.linux.prctl(@intFromEnum(k.linux.PR.SET_NAME), @intFromPtr("uk-custody-test"), 0, 0, 0));
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var fault: Fault = .{ .original = init.io };
    var controlled = init;
    if (args.len == 2 and std.mem.eql(u8, args[1], "--operator-guard-custodian")) {
        const directory: guard.core.private_files.Directory = .{ .dir = .{ .handle = 4 } };
        const mode = try directory.read(init.io, init.gpa, "fixture-mode", 64, null);
        defer init.gpa.free(mode);
        fault.mode = std.meta.stringToEnum(Mode, mode) orelse return error.InvalidFixture;
        if (switch (fault.mode) {
            .after_registration, .pre_dispatch_cancel, .seal_sync_failure, .seal_sync_owner_loss, .seal_interrupted => true,
            else => false,
        }) controlled.io = fault.install();
    } else if (args.len == 2 and std.mem.eql(u8, args[1], "--operator-guard-init")) {
        const directory: guard.core.private_files.Directory = .{ .dir = .{ .handle = 4 } };
        const mode = try directory.read(init.io, init.gpa, "mode", 64, null);
        defer init.gpa.free(mode);
        if (std.mem.eql(u8, mode, "cancel_observed")) {
            fault.mode = .cancel_observed;
            controlled.io = fault.install();
        }
    }
    if (try guard.dispatch(.synthetic, controlled, worker)) return;
    if (args.len != 2 or !std.mem.eql(u8, args[1], "--fixture-owner")) return error.InvalidFixture;
    const bytes = try k.readSealed(init.gpa, init.io, 3);
    defer init.gpa.free(bytes);
    const parsed = try r.parse(Request, init.gpa, bytes);
    defer parsed.deinit();
    k.close(3);
    const directory: guard.core.private_files.Directory = .{ .dir = .{ .handle = 4 } };
    const work: guard.core.private_files.Directory = .{ .dir = .{ .handle = 5 } };
    if (parsed.value.mode == .before) {
        try work.dir.writeFile(init.io, .{ .sub_path = "before", .data = "before-dispatch\n", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
        while (true) k.pause();
    }

    var signer = try guard.Signer.fromSeed(seed, parsed.value.expected.public_key);
    defer signer.deinit();
    var handle = try guard.start(init.gpa, init.io, .{
        .expected = parsed.value.expected,
        .signer = &signer,
        .directory = directory,
        .worker_directory = work,
        .deadline = try guard.core.process.Deadline.afterMilliseconds(if (parsed.value.mode == .deadline) 2000 else 20000),
        .cleanup_ms = 2000,
        .control_reserved = parsed.value.expected.budget.control,
    });
    if (parsed.value.mode == .cancel or parsed.value.mode == .cancel_observed) {
        while (true) {
            const ready = work.openFile(init.io, if (parsed.value.mode == .cancel) "ready" else "request-cancel") catch |err| switch (err) {
                error.FileNotFound => {
                    if (try handle.deadline.expired()) return error.FixtureDeadline;
                    k.pause();
                    continue;
                },
                else => return err,
            };
            ready.close(init.io);
            break;
        }
        try handle.cancel();
        if (parsed.value.mode == .cancel) {
            const first_deadline = handle.cancellation_deadline_ns;
            k.pause();
            try handle.cancel();
            if (handle.cancellation_deadline_ns != first_deadline) return error.CancellationBudgetRenewed;
        }
    }
    const result = try handle.wait(init.gpa);
    try handle.close();
    const result_bytes = try r.canonical(init.gpa, result);
    defer init.gpa.free(result_bytes);
    try work.dir.writeFile(init.io, .{ .sub_path = "owner-result.json", .data = result_bytes, .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    _ = try guard.recovery.load(init.gpa, init.io, directory, parsed.value.expected);
}
fn worker(input: guard.WorkerInput) !void {
    const io = input.io;
    const directory = input.directory;
    try mark(directory.dir.handle, "entered");
    const mode = try directory.read(io, std.heap.page_allocator, "mode", 64, null);
    defer std.heap.page_allocator.free(mode);
    var status_buffer: [4096]u8 = undefined;
    const proc = try k.openProc();
    defer k.close(proc);
    const status = try k.procRead(proc, "self/status", &status_buffer);
    if (std.mem.indexOf(u8, status, "CapEff:\t0000000000000000") == null or
        std.mem.indexOf(u8, status, "CapPrm:\t0000000000000000") == null or
        std.mem.indexOf(u8, status, "NoNewPrivs:\t1") == null) return error.RetainedCapabilities;
    if (std.mem.eql(u8, mode, "flood")) {
        const output = [_]u8{'x'} ** 4096;
        for (0..128) |_| try k.write(1, &output);
        return;
    }
    const child = try k.checked(k.linux.fork());
    if (child == 0) {
        if (k.linux.errno(k.linux.setsid()) != .SUCCESS) k.linux.exit_group(91);
        const nested = k.linux.fork();
        if (k.linux.errno(nested) != .SUCCESS) k.linux.exit_group(92);
        if (nested != 0) k.linux.exit_group(0);
        while (true) k.pause();
    }
    while (try k.reap(@intCast(child)) == null) k.pause();
    try directory.dir.writeFile(io, .{ .sub_path = "ready", .data = "nested-session-ready\n", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    while (true) {
        const release = directory.openFile(io, "release") catch |err| switch (err) {
            error.FileNotFound => {
                k.pause();
                continue;
            },
            else => return err,
        };
        release.close(io);
        return;
    }
}
