const std = @import("std");
const gate = @import("equivalence");

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        var writer = std.Io.File.stderr().writer(init.io, &.{});
        writer.interface.print("fixture_debug_equivalence_failed: {s}\n", .{@errorName(err)}) catch {};
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 4) return error.InvalidArguments;
    const pair_only = std.mem.eql(u8, args[1], "pair");
    if (!pair_only and !std.mem.eql(u8, args[1], "suite")) return error.InvalidArguments;
    const start: usize = if (pair_only) 4 else 6;
    if (args.len < start or args.len > start + (if (pair_only) @as(usize, 2) else 6)) return error.InvalidArguments;
    var report: ?[]const u8 = null;
    var external: ?[]const u8 = null;
    var policy: ?gate.LayoutPolicy = null;
    var index = start;
    while (index < args.len) : (index += 2) {
        if (index + 1 >= args.len) return error.InvalidArguments;
        if (std.mem.eql(u8, args[index], "--layout-policy") and policy == null) {
            policy = std.meta.stringToEnum(gate.LayoutPolicy, args[index + 1]) orelse return error.InvalidArguments;
        } else if (!pair_only and std.mem.eql(u8, args[index], "--report") and report == null) {
            report = args[index + 1];
        } else if (!pair_only and std.mem.eql(u8, args[index], "--external") and external == null) {
            external = args[index + 1];
        } else return error.InvalidArguments;
    }
    const selected_policy = policy orelse .identical_program_headers;
    const helper = try gate.Pair.openWithPolicy(allocator, io, args[2], args[3], selected_policy);
    defer helper.close(allocator, io);
    if (pair_only) {
        try helper.recheck(io);
        return;
    }
    const fixture = try gate.Pair.openWithPolicy(allocator, io, args[4], args[5], selected_policy);
    defer fixture.close(allocator, io);
    const copy: ?gate.Pinned = if (external) |path| try gate.Pinned.open(allocator, io, path) else null;
    defer if (copy) |file| file.close(allocator, io);
    if (copy) |file| {
        if (!std.mem.eql(u8, file.bytes, fixture.candidate.bytes)) return error.ExternalFixtureMismatch;
        try file.recheck(io);
    }
    try helper.recheck(io);
    try fixture.recheck(io);
    // The caller owns these private caches through subsequent consumption.
    // This is a fresh observation, not a lock against later owner mutation.
    if (report) |path| try gate.publish(allocator, io, path, gate.SuiteProof{
        .layout_policy = selected_policy,
        .pairs = [_]gate.PairProof{ helper.proof(.namespace_helper), fixture.proof(.namespace_fixture) },
        .external_fixture = if (copy) |file| @as(?gate.FileProof, file.proof()) else null,
    });
}
