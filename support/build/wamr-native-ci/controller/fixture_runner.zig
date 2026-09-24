// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const controller = @import("wamr_controller");
const process = core.process;

pub fn main(init: std.process.Init) void {
    _ = std.os.linux.syscall1(.umask, 0o077);
    const allocator = init.arena.allocator();
    const args = init.minimal.args.toSlice(allocator) catch fail();
    if (args.len == 3 and std.mem.eql(u8, args[1], "--fixture-child")) {
        @import("test_command.zig").runScenario(init.io, args[2]);
        return;
    }
    if (args.len != 3 or !std.mem.eql(u8, args[1], "--fixture-root"))
        fail();
    run(allocator, init.io, args[2]) catch fail();
}

fn run(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !void {
    try core.private_files.absoluteFilePath(root);
    const directory = try core.private_files.Directory.open(io, root);
    defer directory.close(io);
    var iterator = directory.dir.iterate();
    if (try iterator.next(io) != null) return error.FixtureAlreadyUsed;
    const modes = controller.profile.production_modes;
    if (modes.len != 6 or controller.profile.productionSet(.tiny_exact_v2) != .tiny_v2_qcow2_derived_vhd)
        return error.InvalidProfile;
    for (modes, 0..) |mode, index|
        if (mode.legacyApic() != (index % 2 == 1)) return error.InvalidMode;
    for (std.enums.values(controller.command_plan.Stage)) |stage| {
        const selected = controller.command_plan.spec(stage);
        if (selected.stage != stage or selected.seconds == 0 or
            selected.argv.len < 3 or selected.argv[0] != .path or
            !std.mem.eql(u8, selected.argv[0].path.role, selected.executable))
            return error.InvalidStage;
        const environment = try controller.command_plan.environment(allocator, stage);
        defer controller.command_plan.freeEnvironment(allocator, environment);
        for (environment, 0..) |binding, i|
            if (i > 0 and !std.mem.lessThan(u8, environment[i - 1].name, binding.name))
                return error.InvalidEnvironment;
    }
    const encoded = try controller.records.canonicalAlloc(allocator, "{\"b\":2,\"a\":1}");
    if (!std.mem.eql(u8, encoded, "{\"a\":1,\"b\":2}\n")) return error.InvalidEncoder;
    try process.initialize();
    var cancellation = try process.SignalCancellation.install();
    defer cancellation.deinit();
    const self_path = try std.process.executablePathAlloc(io, allocator);
    var executable = try process.Executable.open(io, self_path);
    defer executable.close(io);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var reports: [std.enums.values(controller.fixture_contract.Scenario).len]controller.fixture_contract.Observation = undefined;
    for (std.enums.values(controller.fixture_contract.Scenario), 0..) |scenario, index| {
        if (cancellation.flag().load(.acquire)) return error.Cancelled;
        const duration: u64 = if (scenario == .timeout) 250 else 4000;
        const primary = try process.Deadline.afterMilliseconds(duration);
        const stop = std.atomic.Value(bool).init(scenario == .cancelled);
        var result = try process.runCommand(allocator, io, .{
            .executable = executable,
            .argv = &.{ self_path, "--fixture-child", if (scenario == .cancelled) "timeout" else @tagName(scenario) },
            .environment = &environment,
            .cwd = directory.dir,
            .primary_deadline = primary,
            .cleanup_deadline = .{ .expires_ns = try std.math.add(u64, primary.expires_ns, 10 * std.time.ns_per_s) },
            .cancel = if (scenario == .cancelled) &stop else cancellation.flag(),
            .snapshot_executable = false,
            .limits = .{
                .stdout_bytes = if (scenario == .overflow) 33 else 4096,
                .stderr_bytes = 4096,
                .term_grace_ms = 100,
            },
        });
        defer result.deinit(allocator);
        var after = try process.Executable.open(io, self_path);
        defer after.close(io);
        if (!std.meta.eql(executable.identity, after.identity) or
            !result.executable_stable or !result.cleanup_complete or
            result.descendants.untracked or result.descendants.limit_exceeded)
            return error.FixtureCleanupFailed;
        const stdout_sha = std.fmt.bytesToHex(controller.records.fileIdentity(result.stdout), .lower);
        const stderr_sha = std.fmt.bytesToHex(controller.records.fileIdentity(result.stderr), .lower);
        reports[index] = .{
            .name = @tagName(scenario),
            .primary = @tagName(result.primary),
            .exit_code = switch (result.primary) {
                .exited => |code| @as(i32, code),
                else => -1,
            },
            .stdout_bytes = result.stdout.len,
            .stdout_sha256 = try allocator.dupe(u8, &stdout_sha),
            .stderr_bytes = result.stderr.len,
            .stderr_sha256 = try allocator.dupe(u8, &stderr_sha),
            .cleanup_complete = result.cleanup_complete,
            .executable_stable = result.executable_stable,
        };
    }
    if (cancellation.flag().load(.acquire)) return error.Cancelled;
    const bytes = try controller.fixture_contract.encode(allocator, &reports);
    try controller.fixture_contract.verify(allocator, bytes);
    if (cancellation.flag().load(.acquire)) return error.Cancelled;
    const output = try directory.dir.createFile(io, "native-scenarios.json", .{
        .exclusive = true,
        .read = true,
        .permissions = .fromMode(0o600),
    });
    defer output.close(io);
    try output.writeStreamingAll(io, bytes);
    try output.sync(io);
    try (std.Io.File{ .handle = directory.dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

fn fail() noreturn {
    std.process.exit(1);
}
