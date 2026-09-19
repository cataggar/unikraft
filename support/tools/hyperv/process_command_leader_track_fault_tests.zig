//! Fork-isolated cases: command-supervisor poison is irreversible.
const std = @import("std");
const support = @import("process_private_test_support.zig");
const process = support.process;
const testing = std.testing;
const allocator = support.allocator;
const io = support.io;
const linux = std.os.linux;

fn runCase(offset: i2) !void {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    const path = try support.executable();
    defer allocator.free(path);
    var executable = try process.Executable.open(io, path);
    defer executable.close(io);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const primary_deadline_ns = std.math.maxInt(u64) - 2;
    const observed_ns = if (offset < 0)
        primary_deadline_ns - 1
    else
        primary_deadline_ns + @as(u64, @intCast(offset));
    var leader_track: process.CommandLeaderTrackTest = .{
        .observed_ns = observed_ns,
    };
    const command: process.CommandRequest = .{
        .executable = executable,
        .argv = &.{ path, "gate-marker", "leader-track-marker" },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .primary_deadline = .{ .expires_ns = primary_deadline_ns },
        .cleanup_deadline = .{ .expires_ns = std.math.maxInt(u64) },
    };
    var result = try process.runCommandTest(
        allocator,
        io,
        command,
        .{ .leader_track = &leader_track },
    );
    defer result.deinit(allocator);

    try testing.expectEqual(@as(u32, 1), leader_track.fault_injections);
    try testing.expectEqual(@as(u32, 1), leader_track.timestamp_observations);
    try testing.expectEqual(observed_ns, result.primary_completed_ns);
    try testing.expectEqual(.complete, result.cleanup);
    try testing.expect(result.cleanup_complete);
    try testing.expect(result.cleanup_events >= 3);
    try testing.expectEqual(@as(u16, 2), result.reap_events);
    try testing.expect(result.termination != null);
    try testing.expectEqual(@as(usize, 0), result.stdout.len);
    try testing.expectEqual(@as(usize, 0), result.stderr.len);
    try testing.expectEqual(.complete, result.stdout_status);
    try testing.expectEqual(.complete, result.stderr_status);
    if (offset < 0) {
        try testing.expectEqual(.local_io, result.primary);
        try testing.expect(!result.primary_deadline_reached);
    } else {
        try testing.expectEqual(.timeout, result.primary);
        try testing.expect(result.primary_deadline_reached);
    }
    try testing.expect(result.completed_ns >= result.primary_completed_ns);
    try support.noChildren();
    const marker = linux.openat(fixture.directory.dir.handle, "leader-track-marker", .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    try testing.expectEqual(.NOENT, linux.errno(marker));

    var followup = try process.runCommand(allocator, io, .{
        .executable = executable,
        .argv = &.{ path, "bytes", "0", "0", "0" },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .primary_deadline = .{ .expires_ns = std.math.maxInt(u64) },
        .cleanup_deadline = .{ .expires_ns = std.math.maxInt(u64) },
    });
    defer followup.deinit(allocator);
    try testing.expect(followup.succeeded());
    try support.noChildren();
}

fn failChild(err: anyerror) noreturn {
    const name = @errorName(err);
    _ = linux.write(2, name.ptr, name.len);
    _ = linux.write(2, "\n", 1);
    linux.exit_group(125);
}

test "addLeader failure samples one inclusive deadline timestamp and reaps the leader" {
    for ([_]i2{ -1, 0, 1 }) |offset| {
        const forked = linux.fork();
        if (linux.errno(forked) != .SUCCESS) return error.FixtureFork;
        if (forked == 0) {
            runCase(offset) catch |err| failChild(err);
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
    try support.noChildren();
}
