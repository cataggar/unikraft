const std = @import("std");
const c = @import("contracts.zig");
const f = @import("files.zig");
const compute = @import("compute_artifacts.zig");
const linux = std.os.linux;
pub const Job = struct { schema_version: u8 = 1, supervisor_pid: u32, state_dir: []const u8, efi: c.File, producer: c.File };
pub const Qcow2Job = struct {
    schema_version: u8 = 1,
    supervisor_pid: u32,
    state_dir: []const u8,
    source: compute.PinnedArtifact,
    producer: c.File,
    expected_virtual_bytes: u64,
    expected_workload_sha256: []const u8,
    expected_workload_bytes: u64,
    limits: compute.Limits,
    config_sha256: []const u8,
};
pub const VhdJob = struct {
    schema_version: u8 = 1,
    supervisor_pid: u32,
    state_dir: []const u8,
    source: compute.PinnedArtifact,
    producer: c.File,
    expected_capacity_bytes: u64,
    limits: compute.Limits,
    config_sha256: []const u8,
};

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
    const self = init.environ_map.get("WAMR_CI_EXECUTABLE_PATH") orelse
        try std.Io.Dir.cwd().realPathFileAlloc(io, "/proc/self/exe", a);
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

pub fn executeQcow2(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const root = try supervisedRoot(init, "qcow2-job.json");
    defer root.directory.close(io);
    const job = try c.read(Qcow2Job, a, root.job);
    try validateCommon(init, root.directory, job.schema_version, job.supervisor_pid, job.state_dir, job.producer);
    try job.source.validate(job.limits.max_input_bytes);
    _ = try c.sha(job.expected_workload_sha256);
    _ = try c.sha(job.config_sha256);
    try compute.verifyPinned(io, job.source, job.limits.max_input_bytes);
    try launchMarker(io, root.directory, "qcow2-launched");
    try compute.applyWorkerLimits(job.limits);
    _ = try compute.finalizeQcow2(a, io, root.directory, .{
        .source = job.source,
        .expected_virtual_bytes = job.expected_virtual_bytes,
        .expected_workload_sha256 = try c.sha(job.expected_workload_sha256),
        .expected_workload_bytes = job.expected_workload_bytes,
        .limits = job.limits,
        .producer = job.producer,
        .config_sha256 = try c.sha(job.config_sha256),
    });
}

pub fn executeVhd(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const root = try supervisedRoot(init, "vhd-job.json");
    defer root.directory.close(io);
    const job = try c.read(VhdJob, a, root.job);
    try validateCommon(init, root.directory, job.schema_version, job.supervisor_pid, job.state_dir, job.producer);
    try job.source.validate(job.limits.max_input_bytes);
    _ = try c.sha(job.config_sha256);
    try compute.verifyPinned(io, job.source, job.limits.max_input_bytes);
    try launchMarker(io, root.directory, "vhd-launched");
    try compute.applyWorkerLimits(job.limits);
    _ = try compute.deriveFixedVhd(a, io, root.directory, .{
        .source = job.source,
        .expected_capacity_bytes = job.expected_capacity_bytes,
        .limits = job.limits,
        .producer = job.producer,
        .config_sha256 = try c.sha(job.config_sha256),
    });
}

const SupervisedRoot = struct {
    directory: c.core.private_files.Directory,
    job: []const u8,
};

fn supervisedRoot(init: std.process.Init, name: []const u8) !SupervisedRoot {
    const root = try c.core.private_files.Directory.openWorkerCwd(init.io);
    errdefer root.close(init.io);
    return .{
        .directory = root,
        .job = try root.read(init.io, init.arena.allocator(), name, c.max_record, null),
    };
}

fn validateCommon(
    init: std.process.Init,
    root: c.core.private_files.Directory,
    schema_version: u8,
    supervisor_pid: u32,
    state_dir: []const u8,
    producer: c.File,
) !void {
    const io = init.io;
    var death: c_int = 0;
    if (schema_version != 1 or supervisor_pid != linux.getppid() or
        linux.getpgid(0) != linux.getpid() or
        linux.errno(linux.prctl(@intFromEnum(linux.PR.GET_PDEATHSIG), @intFromPtr(&death), 0, 0, 0)) != .SUCCESS or
        death != @intFromEnum(linux.SIG.KILL)) return error.InvalidSupervisor;
    if (root.lock(io)) |acquired| {
        var lock = acquired;
        lock.close(io);
        return error.MissingSupervisorLock;
    } else |err| if (err != error.WouldBlock) return err;
    var buffer: [4096]u8 = undefined;
    if (!std.mem.eql(u8, state_dir, buffer[0..try root.dir.realPath(io, &buffer)]))
        return error.WrongWorkspace;
    const self = init.environ_map.get("WAMR_CI_EXECUTABLE_PATH") orelse
        try std.Io.Dir.cwd().realPathFileAlloc(io, "/proc/self/exe", init.arena.allocator());
    if (!std.mem.eql(u8, self, producer.path)) return error.InvalidProducer;
    try f.verify(init.arena.allocator(), io, producer, c.max_tool, true);
}

fn launchMarker(io: std.Io, root: c.core.private_files.Directory, name: []const u8) !void {
    const marker = try root.dir.createFile(io, name, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer marker.close(io);
    try marker.sync(io);
    try f.sync(io, root.dir);
}
