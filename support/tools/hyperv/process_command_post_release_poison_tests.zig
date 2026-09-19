//! Fork-isolated cases: command-supervisor poison is irreversible.
const std = @import("std");
const support = @import("process_private_test_support.zig");
const process = support.process;
const testing = std.testing;
const allocator = support.allocator;
const io = support.io;
const linux = std.os.linux;

fn markerPresent(fixture: support.Fixture, name: [:0]const u8) !void {
    const opened = linux.openat(fixture.directory.dir.handle, name, .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    try testing.expectEqual(.SUCCESS, linux.errno(opened));
    _ = linux.close(@intCast(opened));
}

fn request(
    executable: process.Executable,
    argv: []const []const u8,
    environment: *const std.process.Environ.Map,
    cwd: std.Io.Dir,
) !process.CommandRequest {
    var command: process.CommandRequest = .{
        .executable = executable,
        .argv = argv,
        .environment = environment,
        .cwd = cwd,
        .primary_deadline = try process.Deadline.afterMilliseconds(3000),
        .cleanup_deadline = try process.Deadline.afterMilliseconds(5000),
    };
    command.limits.term_grace_ms = 20;
    return command;
}

fn runCase(mode: []const u8, unwind: bool) !void {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    const path = try support.executable();
    defer allocator.free(path);
    var executable = try process.Executable.open(io, path);
    defer executable.close(io);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var marker_buffer: [96:0]u8 = undefined;
    const marker = try std.fmt.bufPrintZ(
        &marker_buffer,
        "{s}-{s}-poison",
        .{ mode, if (unwind) "unwind" else "result" },
    );
    var fault: process.CommandPostReleaseTestState = .{
        .fault = if (unwind) .unwind_cleanup_proof else .cleanup_proof,
    };
    const command = try request(
        executable,
        &.{ path, mode, marker },
        &environment,
        fixture.directory.dir,
    );
    if (unwind) {
        try testing.expectError(
            error.PostReleaseTestFailure,
            process.runCommandTest(
                allocator,
                io,
                command,
                .{ .post_release = &fault },
            ),
        );
        try testing.expectEqual(@as(u32, 1), fault.boundaries);
    } else {
        var result = try process.runCommandTest(
            allocator,
            io,
            command,
            .{ .post_release = &fault },
        );
        defer result.deinit(allocator);
        try testing.expectEqual(@as(u8, 0), result.primary.exited);
        try testing.expectEqual(.reap_failed, result.cleanup);
        try testing.expect(!result.cleanup_complete);
    }
    try testing.expectEqual(@as(u32, 1), fault.fault_injections);
    try markerPresent(fixture, marker);
    try support.noChildren();
    try testing.expectError(
        error.UnresolvedCleanup,
        process.runCommand(allocator, io, command),
    );
}

fn failChild(err: anyerror) noreturn {
    const name = @errorName(err);
    _ = linux.write(2, name.ptr, name.len);
    _ = linux.write(2, "\n", 1);
    linux.exit_group(125);
}

test "cleanup proof failure poisons after removing every released tree" {
    for ([_][]const u8{ "ordinary-child", "setsid-child", "double-fork" }) |mode| {
        for ([_]bool{ false, true }) |unwind| {
            const forked = linux.fork();
            if (linux.errno(forked) != .SUCCESS) return error.FixtureFork;
            if (forked == 0) {
                runCase(mode, unwind) catch |err| failChild(err);
                linux.exit_group(0);
            }
            const pid: linux.pid_t = @intCast(forked);
            var status: u32 = 0;
            while (true) switch (linux.errno(linux.waitpid(pid, &status, 0))) {
                .SUCCESS => break,
                .INTR => continue,
                else => return error.FixtureReap,
            };
            try testing.expect(linux.W.IFEXITED(status));
            try testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
        }
    }
    try support.noChildren();
}
