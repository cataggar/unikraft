const std = @import("std");
const core = @import("hyperv_core");
const p = @import("hyperv_persistence");

pub const std_options: std.Options = .{ .logFn = log };
fn log(comptime _: std.log.Level, comptime _: @TypeOf(.default), comptime _: []const u8, _: anytype) void {
    std.debug.print("native persistence diagnostic suppressed\n", .{});
}
pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        var stderr = std.Io.File.stderr().writer(init.io, &.{});
        const missing = err == error.PreparationAndCompletedPreflightBindingsUnavailable;
        const bytes = p.local.encode(init.arena.allocator(), .{
            .contract = "uk.hyperv.persistence-cli-failure",
            .schema_version = @as(u8, 1),
            .reason = if (missing) @as([]const u8, "production_bindings_unavailable") else "invalid_input",
            .failures = core.diagnostics.Failures{ .primary = .{ .stage = .admission, .category = if (missing) .unavailable else .invalid_input } },
        }) catch std.process.exit(1);
        stderr.interface.writeAll(bytes) catch {};
        std.process.exit(1);
    };
}
fn run(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3 or !std.mem.eql(u8, args[1], "inspect")) {
        // Production run/prepare/cleanup/internal-worker dispatch is deliberately
        // unavailable until the parent supplies the committed production loaders.
        try p.contract.requireProductionBindings();
        return error.InvalidArguments;
    }
    const directory = try core.private_files.Directory.open(init.io, args[2]);
    defer directory.close(init.io);
    var lock = try directory.lock(init.io);
    defer lock.close(init.io);
    const input = try p.contract.load(init.arena.allocator(), init.io, directory);
    defer input.deinit();
    const state = try p.engine.loadState(init.arena.allocator(), init.io, directory, input.binding);
    const bytes = try p.local.encode(init.arena.allocator(), .{
        .contract = "uk.hyperv.persistence-inspection",
        .schema_version = @as(u8, 1),
        .phase = state.phase,
        .consumed = state.consumed,
        .boot_count = state.boot_count,
        .cleanup_required = state.cleanup_required,
        .local_model_succeeded = state.succeeded(),
        .production_admission = "unavailable",
        .failures = state.failures,
    });
    var out = std.Io.File.stdout().writer(init.io, &.{});
    try out.interface.writeAll(bytes);
}
