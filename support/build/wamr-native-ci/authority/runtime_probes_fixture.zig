// SPDX-License-Identifier: BSD-3-Clause
//! Fault-only native child. This cannot answer Python, loader or Azure probes.
const std = @import("std");
const linux = std.os.linux;

fn emit(fd: linux.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (linux.errno(count)) {
            .SUCCESS => {
                if (count == 0) return error.FixtureWrite;
                offset += count;
            },
            .INTR => continue,
            else => return error.FixtureWrite,
        }
    }
}
fn waitForever() noreturn {
    while (true) {
        var fds: [0]linux.pollfd = .{};
        _ = linux.poll(&fds, 0, 1000);
    }
}
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidFixture;
    const mode = args[1];
    if (std.mem.eql(u8, mode, "exit")) {
        try emit(2, "private-fault?sig=never-publish\n");
        std.process.exit(29);
    } else if (std.mem.eql(u8, mode, "overflow")) {
        const bytes = [_]u8{'x'} ** 4096;
        while (true) {
            try emit(1, &bytes);
            try emit(2, &bytes);
        }
    } else if (std.mem.eql(u8, mode, "timeout")) {
        try emit(2, "private-timeout?sig=never-publish\n");
        waitForever();
    } else if (std.mem.eql(u8, mode, "cancelled")) {
        const marker = try std.Io.Dir.cwd().createFile(init.io, "cancel-ready", .{ .exclusive = true, .permissions = .fromMode(0o600) });
        marker.close(init.io);
        waitForever();
    } else if (std.mem.eql(u8, mode, "signal")) {
        if (linux.errno(linux.kill(linux.getpid(), .USR1)) != .SUCCESS) return error.FixtureSignal;
        waitForever();
    } else if (std.mem.eql(u8, mode, "stdin_environment")) {
        if (init.environ_map.count() != 0) return error.InvalidFixtureEnvironment;
        var byte: [1]u8 = undefined;
        if (linux.read(0, &byte, 1) != 0) return error.InvalidFixtureStdin;
        try emit(1, "fixture-stdin-eof\n");
        std.process.exit(17);
    } else if (std.mem.eql(u8, mode, "escaped_descendant")) {
        var ready: [2]linux.fd_t = undefined;
        if (linux.errno(linux.pipe2(&ready, .{ .CLOEXEC = true })) != .SUCCESS) return error.FixturePipe;
        const child = linux.fork();
        if (linux.errno(child) != .SUCCESS) return error.FixtureFork;
        if (child == 0) {
            _ = linux.close(ready[0]);
            if (linux.errno(linux.setsid()) != .SUCCESS) linux.exit_group(126);
            const marker = [_]u8{1};
            if (linux.write(ready[1], &marker, 1) != 1) linux.exit_group(126);
            _ = linux.close(ready[1]);
            _ = linux.close(1);
            _ = linux.close(2);
            waitForever();
        }
        _ = linux.close(ready[1]);
        var marker: [1]u8 = undefined;
        while (true) {
            const count = linux.read(ready[0], &marker, 1);
            if (linux.errno(count) == .INTR) continue;
            if (count != 1 or marker[0] != 1) return error.FixtureHandshake;
            break;
        }
        _ = linux.close(ready[0]);
        const file = try std.Io.Dir.cwd().createFile(init.io, "escaped-pid", .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(init.io);
        var text: [32]u8 = undefined;
        try file.writeStreamingAll(init.io, try std.fmt.bufPrint(&text, "{d}\n", .{child}));
        std.process.exit(0);
    } else return error.InvalidFixture;
}
