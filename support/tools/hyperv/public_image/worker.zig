const std = @import("std");
const c = @import("contracts.zig");
const f = @import("files.zig");
const linux = std.os.linux;
pub const Job = struct { schema_version: u8 = 1, supervisor_pid: u32, state_dir: []const u8, efi: c.File, producer: c.File };

/// Native packaging leaf only. It never spawns children or creates another
/// process group. The parent holds the stable workspace lock and hard deadline.
pub fn execute(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const root = try c.core.private_files.Directory.openWorkerCwd(io);
    defer root.close(io);
    const bytes = try root.read(io, a, "package-job.json", c.max_record, null);
    const job = try c.read(Job, a, bytes);
    var death: c_int = 0;
    if (job.schema_version != 1 or job.supervisor_pid != linux.getppid() or linux.getpgid(0) != linux.getpid() or
        linux.errno(linux.prctl(@intFromEnum(linux.PR.GET_PDEATHSIG), @intFromPtr(&death), 0, 0, 0)) != .SUCCESS or
        death != @intFromEnum(linux.SIG.KILL)) return error.InvalidSupervisor;
    if (root.lock(io)) |acquired| {
        var lock = acquired;
        lock.close(io);
        return error.MissingSupervisorLock;
    } else |err| if (err != error.WouldBlock) return err;
    var buffer: [4096]u8 = undefined;
    if (!std.mem.eql(u8, job.state_dir, buffer[0..try root.dir.realPath(io, &buffer)])) return error.WrongWorkspace;
    const self = try std.Io.Dir.cwd().realPathFileAlloc(io, "/proc/self/exe", a);
    if (!std.mem.eql(u8, self, job.producer.path)) return error.InvalidProducer;
    try f.verify(a, io, job.producer, c.max_tool, true);
    const marker = try root.dir.createFile(io, "package-launched", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer marker.close(io);
    try marker.sync(io);
    try f.sync(io, root.dir);
    const maximum: linux.rlimit = .{ .cur = c.vhd_bytes, .max = c.vhd_bytes };
    const no_core: linux.rlimit = .{ .cur = 0, .max = 0 };
    if (linux.errno(linux.setrlimit(.FSIZE, &maximum)) != .SUCCESS or linux.errno(linux.setrlimit(.CORE, &no_core)) != .SUCCESS) return error.LimitFailed;
    const report = try @import("package.zig").build(a, io, root, job.efi);
    const encoded = try c.encode(a, report);
    const output = try root.dir.createFile(io, "package-report.json", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer output.close(io);
    try output.writePositionalAll(io, encoded, 0);
    try output.sync(io);
    try f.sync(io, root.dir);
}
