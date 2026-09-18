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

fn expectPidsGone(bytes: []const u8, expected: usize) !void {
    var lines = std.mem.tokenizeScalar(u8, bytes, '\n');
    var count: usize = 0;
    while (lines.next()) |line| {
        const pid = try std.fmt.parseInt(linux.pid_t, line, 10);
        try testing.expectEqual(.SRCH, linux.errno(linux.kill(pid, @enumFromInt(0))));
        count += 1;
    }
    try testing.expectEqual(expected, count);
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

test "command contract captures successful bounded stdout and stderr" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const path = try support.executable();
    defer allocator.free(path);
    var result = try process.runCommand(allocator, io, try request(
        executable,
        &.{ path, "bytes", "17", "23", "0" },
        &environment,
        fixture.directory.dir,
    ));
    defer result.deinit(allocator);
    try testing.expect(result.succeeded());
    try testing.expectEqual(.complete, result.stdout_status);
    try testing.expectEqual(.complete, result.stderr_status);
    try testing.expectEqual(@as(usize, 17), result.stdout.len);
    try testing.expectEqual(@as(usize, 23), result.stderr.len);
    try testing.expect(std.mem.allEqual(u8, result.stdout, 'o'));
    try testing.expect(std.mem.allEqual(u8, result.stderr, 'e'));
    try testing.expect(result.executable_stable);
    try testing.expectEqual(@as(u16, 0), result.descendants.observed);
    try support.noChildren();
}

test "command cleanup owns ordinary setsid double-fork and closed-fd descendants" {
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    for ([_][]const u8{ "ordinary-child", "setsid-child", "double-fork", "closed-child" }) |mode| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var command = try request(executable, &.{ path, mode }, &environment, fixture.directory.dir);
        command.limits.term_grace_ms = 50;
        var result = try process.runCommand(allocator, io, command);
        defer result.deinit(allocator);
        try testing.expect(result.succeeded());
        try testing.expectEqual(@as(u16, 1), result.descendants.observed);
        try testing.expectEqual(result.descendants.observed, result.descendants.identity_validated);
        try testing.expect(result.descendants.adopted >= 1);
        try expectPidsGone(result.stdout, 1);
        try support.noChildren();
    }
}

test "TERM-resistant descendants receive one grace then KILL" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var command = try request(executable, &.{ path, "resistant-child" }, &environment, fixture.directory.dir);
    command.limits.term_grace_ms = 120;
    const started = try process.monotonicNanoseconds();
    var result = try process.runCommand(allocator, io, command);
    defer result.deinit(allocator);
    const elapsed = (try process.monotonicNanoseconds()) - started;
    try testing.expect(elapsed >= 100 * std.time.ns_per_ms);
    try testing.expect(elapsed < 1000 * std.time.ns_per_ms);
    try testing.expect(result.succeeded());
    try expectPidsGone(result.stdout, 1);
    try support.noChildren();
}

test "primary deadline and cancellation do not reset on activity" {
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    for ([_]bool{ false, true }) |use_cancel| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var cancellation = std.atomic.Value(bool).init(false);
        const thread = try std.Thread.spawn(.{}, support.cancelAfter, .{ &cancellation, @as(u32, 150) });
        defer thread.join();
        var command = try request(
            executable,
            &.{ path, if (use_cancel) "partial" else "drip" },
            &environment,
            fixture.directory.dir,
        );
        command.primary_deadline = try process.Deadline.afterMilliseconds(if (use_cancel) 3000 else 150);
        command.cleanup_deadline = try process.Deadline.afterMilliseconds(1200);
        command.cancel = if (use_cancel) &cancellation else null;
        command.limits.term_grace_ms = 50;
        const started = try process.monotonicNanoseconds();
        var result = try process.runCommand(allocator, io, command);
        defer result.deinit(allocator);
        const elapsed = (try process.monotonicNanoseconds()) - started;
        try testing.expect(elapsed < 800 * std.time.ns_per_ms);
        if (use_cancel) {
            try testing.expectEqual(.cancelled, result.primary);
            try testing.expect(result.cancellation_observed);
        } else {
            try testing.expectEqual(.timeout, result.primary);
            try testing.expect(result.primary_deadline_reached);
        }
        try testing.expect(result.cleanup_complete);
        try testing.expect(result.stdout.len > 0);
        try support.noChildren();
    }
}

test "timeout and cancellation reap live descendant trees" {
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    for ([_]bool{ false, true }) |use_cancel| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var cancellation = std.atomic.Value(bool).init(false);
        const thread = try std.Thread.spawn(.{}, support.cancelAfter, .{ &cancellation, @as(u32, 120) });
        defer thread.join();
        var command = try request(executable, &.{ path, "tree" }, &environment, fixture.directory.dir);
        command.primary_deadline = try process.Deadline.afterMilliseconds(if (use_cancel) 3000 else 120);
        command.cleanup_deadline = try process.Deadline.afterMilliseconds(1200);
        command.cancel = if (use_cancel) &cancellation else null;
        command.limits.term_grace_ms = 50;
        var result = try process.runCommand(allocator, io, command);
        defer result.deinit(allocator);
        if (use_cancel) {
            try testing.expectEqual(.cancelled, result.primary);
        } else {
            try testing.expectEqual(.timeout, result.primary);
        }
        try testing.expect(result.cleanup_complete);
        try testing.expectEqual(@as(u16, 1), result.descendants.observed);
        try expectPidsGone(result.stdout, 1);
        try support.noChildren();
    }
}

test "stdout and stderr overflow are explicit and bounded" {
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    for ([_]bool{ false, true }) |stderr| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var command = try request(
            executable,
            &.{ path, "bytes", if (stderr) "0" else "33", if (stderr) "33" else "0", "0" },
            &environment,
            fixture.directory.dir,
        );
        command.limits.stdout_bytes = 32;
        command.limits.stderr_bytes = 32;
        var result = try process.runCommand(allocator, io, command);
        defer result.deinit(allocator);
        try testing.expectEqual(.output_overflow, result.primary);
        if (stderr) {
            try testing.expectEqual(.overflow, result.stderr_status);
            try testing.expectEqual(@as(usize, 32), result.stderr.len);
        } else {
            try testing.expectEqual(.overflow, result.stdout_status);
            try testing.expectEqual(@as(usize, 32), result.stdout.len);
        }
        try testing.expect(result.cleanup_complete);
        try support.noChildren();
    }
}

test "nonzero and real exec-format failure retain primary outcomes" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const path = try support.executable();
    defer allocator.free(path);
    {
        var executable = try process.Executable.open(io, path);
        defer executable.close(io);
        var result = try process.runCommand(allocator, io, try request(
            executable,
            &.{ path, "bytes", "0", "0", "7" },
            &environment,
            fixture.directory.dir,
        ));
        defer result.deinit(allocator);
        try testing.expectEqual(@as(u8, 7), result.primary.exited);
        try testing.expect(result.cleanup_complete);
    }
    {
        const opened = linux.openat(fixture.directory.dir.handle, "invalid-executable", .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .EXCL = true,
            .CLOEXEC = true,
        }, 0o700);
        if (linux.errno(opened) != .SUCCESS) return error.FixtureOpen;
        const descriptor: linux.fd_t = @intCast(opened);
        const bytes = "not an executable\n";
        if (linux.write(descriptor, bytes.ptr, bytes.len) != bytes.len) return error.FixtureWrite;
        _ = linux.close(descriptor);
        const invalid_path = try fixture.directory.dir.realPathFileAlloc(io, "invalid-executable", allocator);
        defer allocator.free(invalid_path);
        var executable = try process.Executable.open(io, invalid_path);
        defer executable.close(io);
        var result = try process.runCommand(allocator, io, try request(
            executable,
            &.{invalid_path},
            &environment,
            fixture.directory.dir,
        ));
        defer result.deinit(allocator);
        try testing.expectEqual(.exec_failed, result.primary);
        try testing.expect(result.cleanup_complete);
    }
    try support.noChildren();
}

test "descendant limit accepts the limit and reports the first excess without poison" {
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    for ([_]u16{ 3, 4 }) |limit| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var command = try request(executable, &.{ path, "many-children", "4" }, &environment, fixture.directory.dir);
        command.limits.descendants = limit;
        command.limits.reap_events = 16;
        var result = try process.runCommand(allocator, io, command);
        defer result.deinit(allocator);
        try testing.expectEqual(@as(u16, 4), result.descendants.observed);
        try testing.expectEqual(limit == 3, result.descendants.limit_exceeded);
        try testing.expect(!result.descendants.untracked);
        try testing.expect(result.cleanup_complete);
        try testing.expectEqual(limit == 4, result.succeeded());
        try expectPidsGone(result.stdout, 4);
        try support.noChildren();
    }
}

test "cleanup grace and deadline are absolute across many descendants" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var command = try request(executable, &.{ path, "many-resistant", "6" }, &environment, fixture.directory.dir);
    command.limits.descendants = 6;
    command.limits.term_grace_ms = 150;
    command.cleanup_deadline = try process.Deadline.afterMilliseconds(700);
    const started = try process.monotonicNanoseconds();
    var result = try process.runCommand(allocator, io, command);
    defer result.deinit(allocator);
    const elapsed = (try process.monotonicNanoseconds()) - started;
    try testing.expect(elapsed >= 120 * std.time.ns_per_ms);
    try testing.expect(elapsed < 650 * std.time.ns_per_ms);
    try testing.expect(result.succeeded());
    try expectPidsGone(result.stdout, 6);
    try support.noChildren();
}

test "command bounds and executable identity refuse before spawn" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var bounded = try request(executable, &.{ path, "bytes", "0", "0", "0" }, &environment, fixture.directory.dir);
    bounded.limits.descendants = 0;
    try testing.expectError(error.InvalidOptions, process.runCommand(allocator, io, bounded));
    var changed = executable;
    changed.identity.inode +%= 1;
    bounded = try request(changed, &.{ path, "bytes", "0", "0", "0" }, &environment, fixture.directory.dir);
    try testing.expectError(error.ExecutableIdentityChanged, process.runCommand(allocator, io, bounded));
    try support.noChildren();
}
