// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const linux = std.os.linux;

pub fn main(init: std.process.Init) !void {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    if (arguments.len != 2) return error.InvalidArguments;
    if (std.mem.eql(u8, arguments[1], "success")) {
        var stdout = std.Io.File.stdout().writer(init.io, &.{});
        try stdout.interface.writeAll("fixture-success\n");
    } else if (std.mem.eql(u8, arguments[1], "failure")) {
        var stderr = std.Io.File.stderr().writer(init.io, &.{});
        try stderr.interface.writeAll("private-fixture-failure\n");
        std.process.exit(7);
    } else if (std.mem.eql(u8, arguments[1], "stdout-flood")) {
        var stdout = std.Io.File.stdout().writer(init.io, &.{});
        while (true) try stdout.interface.writeAll("0123456789abcdef\n");
    } else if (std.mem.eql(u8, arguments[1], "sleep")) {
        while (true) try std.Io.sleep(init.io, .fromSeconds(1), .awake);
    } else if (std.mem.eql(u8, arguments[1], "signal")) {
        if (linux.errno(linux.kill(linux.getpid(), .TERM)) != .SUCCESS)
            return error.SignalFailed;
        unreachable;
    } else {
        return error.InvalidArguments;
    }
}
