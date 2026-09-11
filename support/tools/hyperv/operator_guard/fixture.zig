const std = @import("std");
const guard = @import("operator_guard");
const k = guard.kernel;
const r = guard.records;

pub const Mode = enum { normal, deadline, flood, before, recording, registration, cancel, after_registration };
pub const Request = struct { mode: Mode, expected: r.Expected };
pub const seed = [_]u8{0x59} ** 32;

// Test-only I/O adapter in this separately compiled synthetic executable. Kill
// the real owner after registration directory fsync, before publication returns.
const RegistrationDeath = struct {
    original: std.Io,
    table: std.Io.VTable = undefined,
    fired: bool = false,
    threadlocal var active: *RegistrationDeath = undefined;
    fn install(self: *RegistrationDeath) std.Io {
        self.table = self.original.vtable.*;
        self.table.fileSync = sync;
        active = self;
        return .{ .userdata = self.original.userdata, .vtable = &self.table };
    }
    fn sync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
        const self = active;
        try self.original.vtable.fileSync(userdata, file);
        if (self.fired) return;
        const before = k.directory(4) catch return error.InputOutput;
        const actual = k.directory(file.handle) catch return error.InputOutput;
        if (!std.meta.eql(before, actual)) return;
        const registration = k.linux.openat(4, "custody-registration.json", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (k.linux.errno(registration)) {
            .SUCCESS => {
                k.close(@intCast(registration));
                self.fired = true;
                k.kill(5) catch return error.InputOutput;
                while (!(k.readable(5) catch return error.InputOutput)) k.pause();
            },
            .NOENT => {},
            else => return error.InputOutput,
        }
    }
};

pub fn main(init: std.process.Init) void {
    execute(init) catch |err| {
        // Synthetic executable only; production has no fixture dispatch.
        std.Io.File.stderr().writeStreamingAll(init.io, @errorName(err)) catch {};
        std.Io.File.stderr().writeStreamingAll(init.io, "\n") catch {};
        std.process.exit(2);
    };
}
fn execute(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var fault: RegistrationDeath = .{ .original = init.io };
    var controlled = init;
    if (args.len == 2 and std.mem.eql(u8, args[1], "--operator-guard-custodian")) {
        const marker = k.linux.openat(4, "fixture-owner-death", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        if (k.linux.errno(marker) == .SUCCESS) {
            k.close(@intCast(marker));
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
        .control_reserved = r.max_control,
    });
    if (parsed.value.mode == .cancel) {
        while (true) {
            const ready = work.openFile(init.io, "ready") catch |err| switch (err) {
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
