// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub fn main(init: std.process.Init) void {
    run(init) catch std.process.exit(3);
}

fn run(init: std.process.Init) !void {
    const mode = try std.Io.Dir.cwd().readFileAlloc(init.io, "tool-mode", init.arena.allocator(), .limited(32));
    if (std.mem.eql(u8, mode, "fail")) {
        var stderr = std.Io.File.stderr().writer(init.io, &.{});
        try stderr.interface.writeAll("SYNTHETIC_SECRET/private/path\n");
        std.process.exit(7);
    }
    if (std.mem.eql(u8, mode, "silent")) return;
    if (std.mem.eql(u8, mode, "hang")) while (true) {
        const pause: std.os.linux.timespec = .{ .sec = 1, .nsec = 0 };
        _ = std.os.linux.nanosleep(&pause, null);
    };
    const flood = std.mem.eql(u8, mode, "stdout-limit") or std.mem.eql(u8, mode, "stderr-limit");
    var writer = (if (std.mem.eql(u8, mode, "stderr-limit")) std.Io.File.stderr() else std.Io.File.stdout()).writer(init.io, &.{});
    if (flood) {
        const bytes = [_]u8{'x'} ** 8192;
        while (true) try writer.interface.writeAll(&bytes);
    }
    try writer.interface.writeAll("SYNTHETIC_SECRET invalid tool output\n");
}
