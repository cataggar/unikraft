// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const linux = std.os.linux;

pub fn main(init: std.process.Init) void {
    const args = init.minimal.args.toSlice(init.arena.allocator()) catch std.process.exit(2);
    if (args.len != 3 or !std.mem.eql(u8, args[1], "--fixture-root"))
        std.process.exit(2);
    const directory = std.Io.Dir.openDirAbsolute(init.io, args[2], .{
        .follow_symlinks = false,
    }) catch std.process.exit(2);
    defer directory.close(init.io);
    const file = directory.openFile(init.io, "scenario", .{ .follow_symlinks = false }) catch std.process.exit(2);
    defer file.close(init.io);
    var buffer: [32]u8 = undefined;
    const count = file.readPositionalAll(init.io, &buffer, 0) catch std.process.exit(2);
    runScenario(init.io, buffer[0..count]);
}

pub fn runScenario(io: std.Io, scenario: []const u8) void {
    if (std.mem.eql(u8, scenario, "ok")) {
        std.Io.File.stdout().writeStreamingAll(io, "native fixture ok\n") catch std.process.exit(2);
        return;
    }
    if (std.mem.eql(u8, scenario, "reported-error")) {
        std.Io.File.stderr().writeStreamingAll(io, "UnsafeFile /private/secret\n") catch std.process.exit(2);
        return;
    }
    if (std.mem.eql(u8, scenario, "nonzero")) {
        std.Io.File.stderr().writeStreamingAll(io, "PermissionDenied /private/secret\n") catch {};
        std.process.exit(7);
    }
    if (std.mem.eql(u8, scenario, "partial")) {
        std.Io.File.stdout().writeStreamingAll(io, "partial private output\n") catch {};
        std.process.exit(9);
    }
    if (std.mem.eql(u8, scenario, "signal")) {
        _ = linux.kill(linux.getpid(), .USR1);
        std.process.exit(2);
    }
    if (std.mem.eql(u8, scenario, "overflow")) {
        const chunk = [_]u8{'X'} ** 65536;
        for (0..140) |_|
            std.Io.File.stdout().writeStreamingAll(io, &chunk) catch std.process.exit(2);
        return;
    }
    if (std.mem.eql(u8, scenario, "large-3m") or std.mem.eql(u8, scenario, "large-8m")) {
        const chunk = [_]u8{'A'} ** 65536;
        const count: usize = if (std.mem.eql(u8, scenario, "large-3m")) 48 else 64;
        for (0..count) |_|
            std.Io.File.stdout().writeStreamingAll(io, &chunk) catch std.process.exit(2);
        if (count == 64) {
            const stderr_chunk = [_]u8{'B'} ** 65536;
            for (0..64) |_|
                std.Io.File.stderr().writeStreamingAll(io, &stderr_chunk) catch std.process.exit(2);
        }
        return;
    }
    if (std.mem.eql(u8, scenario, "timeout")) {
        while (true) {
            var fds: [0]linux.pollfd = .{};
            _ = linux.poll(&fds, 0, 1000);
        }
    }
    std.process.exit(2);
}
