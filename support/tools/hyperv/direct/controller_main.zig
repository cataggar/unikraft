// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const controller = @import("controller.zig");

pub fn main(init: std.process.Init) void {
    _ = std.os.linux.syscall1(.umask, 0o077);
    const status = run(init) catch 1;
    if (status == 0) {
        var writer = std.Io.File.stdout().writerStreaming(init.io, &.{});
        writer.interface.writeAll("Direct two-boot persistence evidence passed; owned group independently absent.\n") catch std.process.exit(1);
    } else {
        var writer = std.Io.File.stderr().writerStreaming(init.io, &.{});
        writer.interface.writeAll("direct two-boot refused; inspect private attempt records\n") catch {};
    }
    std.process.exit(status);
}

fn run(init: std.process.Init) !u8 {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    return controller.execute(controller.Native, .{}, init, try controller.Inputs.parse(args[1..]));
}
