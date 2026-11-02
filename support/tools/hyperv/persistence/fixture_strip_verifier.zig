const std = @import("std");
const qualification = @import("qualification");

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        std.debug.print("persistence_fixture_strip_refused: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    try qualification.qualify(allocator, init.io, try qualification.Options.parse(args));
}
