// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const controller = @import("wamr_controller");

pub fn main(init: std.process.Init) void {
    _ = std.os.linux.syscall1(.umask, 0o077);
    const allocator = init.arena.allocator();
    const args = init.minimal.args.toSlice(allocator) catch fail();
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
    const record = try std.json.Stringify.valueAlloc(allocator, .{
        .schema = "uk.wamr.native-ci-fixtures",
        .schema_version = 1,
        .production_modes = modes.len,
        .build_stages = std.enums.values(controller.command_plan.Stage).len,
        .status = "passed",
    }, .{});
    const bytes = try controller.records.canonicalAlloc(allocator, record);
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
