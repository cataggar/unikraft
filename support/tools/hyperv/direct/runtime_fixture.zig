// SPDX-License-Identifier: BSD-3-Clause
//! Isolated process fixture; never an Azure CLI fallback.
const std = @import("std");
const linux = std.os.linux;
const core = @import("hyperv_core");

fn emit(fd: linux.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (linux.errno(n)) {
            .SUCCESS => if (n == 0) return error.WriteFailed else {
                offset += n;
            },
            .INTR => continue,
            else => return error.WriteFailed,
        }
    }
}

fn sleep(milliseconds: u32) void {
    const end = (core.process.Deadline.afterMilliseconds(milliseconds) catch unreachable);
    while (!(end.expired() catch unreachable)) {
        var fds: [0]linux.pollfd = .{};
        _ = linux.poll(&fds, 0, 10);
    }
}

fn ignoreTerm() !void {
    var action: linux.Sigaction = .{
        .handler = .{ .handler = linux.SIG.IGN },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    if (linux.errno(linux.sigaction(.TERM, &action, null)) != .SUCCESS) return error.SignalSetup;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) return error.InvalidFixture;
    const mode = args[1];
    if (std.mem.eql(u8, mode, "bytes")) {
        if (args.len != 5) return error.InvalidFixture;
        const stdout = try std.fmt.parseInt(usize, args[2], 10);
        const stderr = try std.fmt.parseInt(usize, args[3], 10);
        var buffer: [4096]u8 = undefined;
        for ([_]usize{ stdout, stderr }, 0..) |count, stream| {
            @memset(&buffer, if (stream == 0) 'o' else 'e');
            var left = count;
            while (left != 0) {
                const amount = @min(left, buffer.len);
                try emit(@intCast(stream + 1), buffer[0..amount]);
                left -= amount;
            }
        }
        std.process.exit(try std.fmt.parseInt(u8, args[4], 10));
    } else if (std.mem.eql(u8, mode, "partial") or std.mem.eql(u8, mode, "ignore-term")) {
        if (std.mem.eql(u8, mode, "ignore-term")) try ignoreTerm();
        try emit(1, "private-stdout?sig=synthetic-secret\n");
        try emit(2, "private-stderr?sig=synthetic-secret\n");
        while (true) sleep(1000);
    } else if (std.mem.eql(u8, mode, "term-output")) {
        var cancellation = try core.process.SignalCancellation.install();
        defer cancellation.deinit();
        try emit(1, "before-term\n");
        while (!cancellation.flag().load(.acquire)) sleep(10);
        try emit(2, "private-after-term\n");
    } else if (std.mem.eql(u8, mode, "transfer")) {
        if (args.len != 4) return error.InvalidFixture;
        try emit(1, "{\"fixture_only\":true}\n");
    } else if (std.mem.eql(u8, mode, "environment")) {
        if (init.environ_map.get("LC_ALL")) |locale| {
            if (!std.mem.eql(u8, locale, "C")) return error.InvalidEnvironment;
        } else return error.InvalidEnvironment;
        if (init.environ_map.get("PRIVATE_SECRET") != null or init.environ_map.get("PATH") != null or
            init.environ_map.get("PYTHONPATH") != null or init.environ_map.get("SAS") != null)
            return error.InvalidEnvironment;
        try emit(1, "environment-ok\n");
    } else if (std.mem.eql(u8, mode, "nested")) {
        var cancellation = try core.process.SignalCancellation.install();
        defer cancellation.deinit();
        try core.process.initialize();
        var environment = std.process.Environ.Map.init(init.arena.allocator());
        defer environment.deinit();
        try emit(1, "nested-ready\n");
        var result = try core.process.run(init.arena.allocator(), init.io, .{
            .argv = &.{ args[0], "ignore-term" },
            .environment = &environment,
            .cwd = .cwd(),
            .deadline = try core.process.Deadline.afterMilliseconds(15000),
            .cleanup_ms = 5000,
            .cancel = cancellation.flag(),
        });
        defer result.deinit(init.arena.allocator());
        if (!result.cleanup_complete) return error.UnreapedFixture;
        // Simulate bounded native reconciliation after its worker is reaped.
        sleep(try std.fmt.parseInt(u32, args[2], 10));
        try emit(1, "nested-reaped\n");
        std.process.exit(if (result.failures.primary != null) 7 else 0);
    } else if (std.mem.eql(u8, mode, "escaped") or std.mem.eql(u8, mode, "tree")) {
        const child = linux.fork();
        if (linux.errno(child) != .SUCCESS) return error.ForkFailed;
        if (child == 0) {
            if (std.mem.eql(u8, mode, "escaped")) _ = linux.setpgid(0, 0);
            while (true) {
                var fds: [0]linux.pollfd = .{};
                _ = linux.poll(&fds, 0, 1000);
            }
        }
        var text: [32]u8 = undefined;
        try emit(1, try std.fmt.bufPrint(&text, "{d}\n", .{child}));
        if (std.mem.eql(u8, mode, "escaped")) {
            // Wait until the child's group change is observable before exit.
            while (linux.getpgid(@intCast(child)) != child) sleep(10);
            return;
        }
        while (true) sleep(1000);
    } else if (std.mem.eql(u8, mode, "fd-closed")) {
        const fd = try std.fmt.parseInt(linux.fd_t, args[2], 10);
        if (linux.errno(linux.fcntl(fd, linux.F.GETFD, 0)) != .BADF) return error.DescriptorLeaked;
        try emit(1, "closed\n");
    } else return error.InvalidFixture;
}
