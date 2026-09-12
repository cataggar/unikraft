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
    if (args.len == 4 and std.mem.eql(u8, args[1], "pair")) {
        const pair = try gate.Pair.open(allocator, io, args[2], args[3]);
        defer pair.close(allocator, io);
        try pair.recheck(io);
        return;
    }
    if (args.len < 6 or args.len > 10 or !std.mem.eql(u8, args[1], "suite")) return error.InvalidArguments;
    var report: ?[]const u8 = null;
    var external: ?[]const u8 = null;
    var index: usize = 6;
    while (index < args.len) : (index += 2) {
        if (index + 1 >= args.len) return error.InvalidArguments;
        if (std.mem.eql(u8, args[index], "--report") and report == null) {
            report = args[index + 1];
        } else if (std.mem.eql(u8, args[index], "--external") and external == null) {
            external = args[index + 1];
        } else return error.InvalidArguments;
    }
    const helper = try gate.Pair.open(allocator, io, args[2], args[3]);
    defer helper.close(allocator, io);
    const fixture = try gate.Pair.open(allocator, io, args[4], args[5]);
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
        .pairs = [_]gate.PairProof{ helper.proof(.namespace_helper), fixture.proof(.namespace_fixture) },
        .external_fixture = if (copy) |file| @as(?gate.FileProof, file.proof()) else null,
    });
}
