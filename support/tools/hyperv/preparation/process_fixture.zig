const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) std.process.exit(2);
    if (std.mem.eql(u8, args[1], "failure")) std.process.exit(19);
    if (std.mem.eql(u8, args[1], "progress")) {
        var output = std.Io.File.stdout().writer(init.io, &.{});
        try output.interface.writeAll("{\"fixture\":\"native-progress\"}");
        return;
    }
    std.process.exit(2);
}
