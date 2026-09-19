const std = @import("std");
const support = @import("process_private_test_support.zig");
const process = support.process;
const testing = std.testing;
const allocator = support.allocator;
const io = support.io;
const linux = std.os.linux;

fn openExecutable() !process.Executable {
    const path = try support.executable();
    defer allocator.free(path);
    return process.Executable.open(io, path);
}

fn request(
    executable: process.Executable,
    argv: []const []const u8,
    environment: *const std.process.Environ.Map,
    cwd: std.Io.Dir,
) !process.CommandRequest {
    return .{
        .executable = executable,
        .argv = argv,
        .environment = environment,
        .cwd = cwd,
        .primary_deadline = try process.Deadline.afterMilliseconds(3000),
        .cleanup_deadline = try process.Deadline.afterMilliseconds(5000),
    };
}

fn expectMarkerMissing(fixture: support.Fixture, name: [:0]const u8) !void {
    const opened = linux.openat(fixture.directory.dir.handle, name, .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    try testing.expectEqual(.NOENT, linux.errno(opened));
}

fn expectMarkerPresent(fixture: support.Fixture, name: [:0]const u8) !void {
    const opened = linux.openat(fixture.directory.dir.handle, name, .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    try testing.expectEqual(.SUCCESS, linux.errno(opened));
    _ = linux.close(@intCast(opened));
}

fn expectCompletePreReleaseFailure(
    result: process.CommandResult,
    primary: std.meta.Tag(process.CommandPrimary),
) !void {
    try testing.expectEqual(primary, std.meta.activeTag(result.primary));
    try testing.expectEqual(.complete, result.cleanup);
    try testing.expect(result.cleanup_complete);
    try testing.expectEqual(@as(u32, 0), result.primary_events);
    try testing.expect(result.cleanup_events >= 3);
    try testing.expectEqual(@as(u16, 2), result.reap_events);
    try testing.expect(result.termination != null);
    try testing.expectEqual(process.CommandDescendants{}, result.descendants);
    try testing.expectEqual(@as(usize, 0), result.stdout.len);
    try testing.expectEqual(@as(usize, 0), result.stderr.len);
    try testing.expectEqual(.complete, result.stdout_status);
    try testing.expectEqual(.complete, result.stderr_status);
    try testing.expect(result.started_ns <= result.primary_completed_ns);
    try testing.expect(result.primary_completed_ns <= result.completed_ns);
    try testing.expectEqual(primary == .timeout, result.primary_deadline_reached);
    try testing.expectEqual(primary == .cancelled, result.cancellation_observed);
}

test "every parent gate phase fails before user code and reaps through ECHILD" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();

    const faults = [_]process.CommandGateTestFault{
        .pidfd,
        .procfs,
        .identity,
        .tracker,
        .clock,
        .ready_eof,
        .ready_bad,
        .release_write,
        .parent_close,
    };
    for (faults, 0..) |fault, index| {
        var marker_buffer: [32:0]u8 = undefined;
        const marker = try std.fmt.bufPrintZ(&marker_buffer, "gate-failure-{d}", .{index});
        var gate: process.CommandGateTestState = .{ .fault = fault };
        var result = try process.runCommandTest(
            allocator,
            io,
            try request(
                executable,
                &.{ path, "gate-marker", marker },
                &environment,
                fixture.directory.dir,
            ),
            .{ .gate = &gate },
        );
        defer result.deinit(allocator);
        try expectCompletePreReleaseFailure(result, .local_io);
        try testing.expectEqual(@as(u32, 1), gate.fault_injections);
        try expectMarkerMissing(fixture, marker);
        try support.noChildren();
    }
}

test "timeout and cancellation before release retain the original deadline" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();

    var timeout = try request(
        executable,
        &.{ path, "gate-marker", "timeout-marker" },
        &environment,
        fixture.directory.dir,
    );
    timeout.primary_deadline = try process.Deadline.afterMilliseconds(200);
    var timeout_result = try process.runCommandTest(
        allocator,
        io,
        timeout,
        .{ .leader_track_delay_ms = 300 },
    );
    defer timeout_result.deinit(allocator);
    try expectCompletePreReleaseFailure(timeout_result, .timeout);
    try testing.expect(timeout_result.primary_completed_ns >= timeout.primary_deadline.expires_ns);
    try expectMarkerMissing(fixture, "timeout-marker");
    try support.noChildren();

    var cancellation = std.atomic.Value(bool).init(false);
    var cancelled = try request(
        executable,
        &.{ path, "gate-marker", "cancel-marker" },
        &environment,
        fixture.directory.dir,
    );
    cancelled.cancel = &cancellation;
    const thread = try std.Thread.spawn(.{}, support.cancelAfter, .{ &cancellation, 200 });
    defer thread.join();
    var cancel_result = try process.runCommandTest(
        allocator,
        io,
        cancelled,
        .{ .leader_track_delay_ms = 300 },
    );
    defer cancel_result.deinit(allocator);
    try expectCompletePreReleaseFailure(cancel_result, .cancelled);
    try testing.expect(cancel_result.primary_completed_ns < cancelled.primary_deadline.expires_ns);
    try expectMarkerMissing(fixture, "cancel-marker");
    try support.noChildren();
}

test "successful release runs exactly the selected child and bad release is rejected" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();

    var released = try process.runCommandTest(
        allocator,
        io,
        try request(
            executable,
            &.{ path, "gate-marker", "released-marker" },
            &environment,
            fixture.directory.dir,
        ),
        .{ .leader_track_delay_ms = 20 },
    );
    defer released.deinit(allocator);
    try testing.expect(released.succeeded());
    try expectMarkerPresent(fixture, "released-marker");
    try support.noChildren();

    var gate: process.CommandGateTestState = .{ .fault = .release_bad };
    var rejected = try process.runCommandTest(
        allocator,
        io,
        try request(
            executable,
            &.{ path, "gate-marker", "bad-release-marker" },
            &environment,
            fixture.directory.dir,
        ),
        .{ .gate = &gate },
    );
    defer rejected.deinit(allocator);
    try testing.expectEqual(.exec_failed, rejected.primary);
    try testing.expectEqual(.complete, rejected.cleanup);
    try testing.expect(rejected.cleanup_complete);
    try testing.expect(rejected.primary_events >= 1);
    try testing.expectEqual(@as(u16, 2), rejected.reap_events);
    try testing.expectEqual(@as(u32, 1), gate.fault_injections);
    try expectMarkerMissing(fixture, "bad-release-marker");
    try support.noChildren();
}

test "parent death closes the gate and cannot run user code" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const command = try request(
        executable,
        &.{ path, "gate-marker", "parent-death-marker" },
        &environment,
        fixture.directory.dir,
    );

    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.FixtureFork;
    if (forked == 0) {
        process.initialize() catch linux.exit_group(122);
        var gate: process.CommandGateTestState = .{ .fault = .parent_crash };
        _ = process.runCommandTest(allocator, io, command, .{ .gate = &gate }) catch
            linux.exit_group(124);
        linux.exit_group(125);
    }
    const parent: linux.pid_t = @intCast(forked);
    var status: u32 = 0;
    while (true) switch (linux.errno(linux.waitpid(parent, &status, 0))) {
        .SUCCESS => break,
        .INTR => continue,
        else => return error.FixtureReap,
    };
    try testing.expect(linux.W.IFEXITED(status));
    try testing.expectEqual(@as(u8, 123), linux.W.EXITSTATUS(status));

    while (true) switch (linux.errno(linux.waitpid(-1, &status, 0))) {
        .SUCCESS => break,
        .INTR => continue,
        else => return error.FixtureReap,
    };
    try testing.expect(linux.W.IFSIGNALED(status) or
        (linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 126));
    try expectMarkerMissing(fixture, "parent-death-marker");
    try support.noChildren();
}
