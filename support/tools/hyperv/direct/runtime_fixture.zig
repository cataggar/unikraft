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

const ChildStyle = enum { ordinary, session, closed, resistant };

fn childLoop(style: ChildStyle, ready: linux.fd_t) noreturn {
    if (style == .session or style == .resistant) {
        if (linux.errno(linux.setsid()) != .SUCCESS) linux.exit_group(126);
    }
    if (style == .closed) {
        _ = linux.close(1);
        _ = linux.close(2);
    }
    if (style == .resistant) ignoreTerm() catch linux.exit_group(126);
    const marker = [_]u8{1};
    if (linux.write(ready, &marker, marker.len) != marker.len) linux.exit_group(126);
    _ = linux.close(ready);
    while (true) {
        var fds: [0]linux.pollfd = .{};
        _ = linux.poll(&fds, 0, 1000);
    }
}

fn spawnChild(style: ChildStyle) !linux.pid_t {
    var ready: [2]linux.fd_t = undefined;
    if (linux.errno(linux.pipe2(&ready, .{ .CLOEXEC = true })) != .SUCCESS) return error.PipeFailed;
    defer _ = linux.close(ready[0]);
    const child = linux.fork();
    if (linux.errno(child) != .SUCCESS) {
        _ = linux.close(ready[1]);
        return error.ForkFailed;
    }
    if (child == 0) {
        _ = linux.close(ready[0]);
        childLoop(style, ready[1]);
    }
    _ = linux.close(ready[1]);
    var marker: [1]u8 = undefined;
    while (true) {
        const amount = linux.read(ready[0], &marker, marker.len);
        if (linux.errno(amount) == .INTR) continue;
        if (amount != marker.len or marker[0] != 1) return error.FixtureHandshake;
        break;
    }
    return @intCast(child);
}

fn spawnImmediateChild() !linux.pid_t {
    const child = linux.fork();
    if (linux.errno(child) != .SUCCESS) return error.ForkFailed;
    if (child == 0) linux.exit_group(0);
    return @intCast(child);
}

fn emitPid(pid: linux.pid_t) !void {
    var text: [32]u8 = undefined;
    try emit(1, try std.fmt.bufPrint(&text, "{d}\n", .{pid}));
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) return error.InvalidFixture;
    const mode = args[1];
    if (std.mem.eql(u8, mode, "version") or std.mem.eql(u8, mode, "cli-interpreter")) {
        for ([_][]const u8{ "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "PRIVATE_SECRET" }) |key|
            if (init.environ_map.get(key) != null) return error.InvalidEnvironment;
        if (std.mem.eql(u8, mode, "version")) {
            if (args.len != 5 or !std.mem.eql(u8, args[2], "--output") or
                !std.mem.eql(u8, args[3], "json") or !std.mem.eql(u8, args[4], "--only-show-errors")) return error.InvalidFixture;
            const name = std.fs.path.basename(args[0]);
            if (std.mem.eql(u8, name, "cli-version-exit29")) std.process.exit(29);
            if (std.mem.eql(u8, name, "requires-python") and init.environ_map.get("AZ_PYTHON") == null)
                return error.MissingExplicitInterpreter;
            if (init.environ_map.get("AZ_PYTHON")) |python| {
                return std.process.replace(init.io, .{ .argv = &.{ python, "cli-interpreter" }, .environ_map = init.environ_map });
            }
        } else if (init.environ_map.get("AZ_PYTHON") == null) return error.InvalidEnvironment;
        try emit(1, "{\"azure-cli\":\"2.80.0\",\"azure-cli-core\":\"2.80.0\",\"azure-cli-telemetry\":\"1.1.0\",\"extensions\":{}}\n");
        return;
    }
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
    } else if (std.mem.eql(u8, mode, "gate-marker")) {
        if (args.len != 3) return error.InvalidFixture;
        const marker = try std.Io.Dir.cwd().createFile(init.io, args[2], .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        });
        marker.close(init.io);
    } else if (std.mem.eql(u8, mode, "ordinary-child") or std.mem.eql(u8, mode, "setsid-child") or
        std.mem.eql(u8, mode, "closed-child") or std.mem.eql(u8, mode, "resistant-child"))
    {
        const style: ChildStyle = if (std.mem.eql(u8, mode, "ordinary-child"))
            .ordinary
        else if (std.mem.eql(u8, mode, "setsid-child"))
            .session
        else if (std.mem.eql(u8, mode, "closed-child"))
            .closed
        else
            .resistant;
        try emitPid(try spawnChild(style));
    } else if (std.mem.eql(u8, mode, "double-fork")) {
        var ready: [2]linux.fd_t = undefined;
        if (linux.errno(linux.pipe2(&ready, .{ .CLOEXEC = true })) != .SUCCESS) return error.PipeFailed;
        defer _ = linux.close(ready[0]);
        const intermediate = linux.fork();
        if (linux.errno(intermediate) != .SUCCESS) {
            _ = linux.close(ready[1]);
            return error.ForkFailed;
        }
        if (intermediate == 0) {
            _ = linux.close(ready[0]);
            const grandchild = linux.fork();
            if (linux.errno(grandchild) != .SUCCESS) linux.exit_group(126);
            if (grandchild == 0) {
                if (linux.errno(linux.setsid()) != .SUCCESS) linux.exit_group(126);
                const pid: linux.pid_t = linux.getpid();
                if (linux.write(ready[1], @ptrCast(&pid), @sizeOf(linux.pid_t)) != @sizeOf(linux.pid_t))
                    linux.exit_group(126);
                _ = linux.close(ready[1]);
                while (true) {
                    var fds: [0]linux.pollfd = .{};
                    _ = linux.poll(&fds, 0, 1000);
                }
            }
            _ = linux.close(ready[1]);
            linux.exit_group(0);
        }
        _ = linux.close(ready[1]);
        var pid: linux.pid_t = 0;
        while (true) {
            const amount = linux.read(ready[0], @ptrCast(&pid), @sizeOf(linux.pid_t));
            if (linux.errno(amount) == .INTR) continue;
            if (amount != @sizeOf(linux.pid_t) or pid <= 1) return error.FixtureHandshake;
            break;
        }
        var status: u32 = 0;
        while (linux.errno(linux.waitpid(@intCast(intermediate), &status, 0)) == .INTR) {}
        if (!linux.W.IFEXITED(status) or linux.W.EXITSTATUS(status) != 0) return error.FixtureHandshake;
        try emitPid(pid);
    } else if (std.mem.eql(u8, mode, "many-children") or
        std.mem.eql(u8, mode, "many-resistant") or
        std.mem.eql(u8, mode, "many-immediate"))
    {
        if (args.len != 3) return error.InvalidFixture;
        const count = try std.fmt.parseInt(usize, args[2], 10);
        if (count == 0 or count > 32) return error.InvalidFixture;
        for (0..count) |index| {
            if (std.mem.eql(u8, mode, "many-immediate")) {
                try emitPid(try spawnImmediateChild());
            } else {
                try emitPid(try spawnChild(if (std.mem.eql(u8, mode, "many-resistant"))
                    .resistant
                else if (index % 2 == 0)
                    .ordinary
                else
                    .session));
            }
        }
    } else if (std.mem.eql(u8, mode, "drip")) {
        while (true) {
            try emit(1, "x");
            sleep(20);
        }
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
    } else if (std.mem.eql(u8, mode, "closed-running")) {
        try ignoreTerm();
        _ = linux.close(1);
        _ = linux.close(2);
        while (true) sleep(1000);
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
    } else if (std.mem.eql(u8, mode, "orphan-pipes") or std.mem.eql(u8, mode, "orphan-closed") or
        std.mem.eql(u8, mode, "escaped-closed"))
    {
        const close_output = !std.mem.eql(u8, mode, "orphan-pipes");
        const escape = std.mem.eql(u8, mode, "escaped-closed");
        var ready: [2]linux.fd_t = undefined;
        if (linux.errno(linux.pipe2(&ready, .{ .CLOEXEC = true })) != .SUCCESS) return error.PipeFailed;
        defer _ = linux.close(ready[0]);
        const child = linux.fork();
        if (linux.errno(child) != .SUCCESS) {
            _ = linux.close(ready[1]);
            return error.ForkFailed;
        }
        if (child == 0) {
            // Only raw syscalls and stack operations after fork. The leader
            // cannot exit until this live child's pipe/signal state is fixed.
            _ = linux.close(ready[0]);
            ignoreTerm() catch linux.exit_group(126);
            if (close_output) {
                _ = linux.close(1);
                _ = linux.close(2);
            }
            if (escape and linux.errno(linux.setpgid(0, 0)) != .SUCCESS) linux.exit_group(126);
            const marker = [_]u8{1};
            if (linux.write(ready[1], &marker, 1) != 1) linux.exit_group(126);
            _ = linux.close(ready[1]);
            while (true) {
                var fds: [0]linux.pollfd = .{};
                _ = linux.poll(&fds, 0, 1000);
            }
        }
        _ = linux.close(ready[1]);
        var marker: [1]u8 = undefined;
        while (true) {
            const count = linux.read(ready[0], &marker, 1);
            if (linux.errno(count) == .INTR) continue;
            if (count != 1 or marker[0] != 1) return error.FixtureHandshake;
            break;
        }
        var text: [32]u8 = undefined;
        try emit(1, try std.fmt.bufPrint(&text, "{d}\n", .{child}));
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
