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

test "post-release faults clean ordinary setsid and double-fork trees" {
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();

    const cases = [_]struct {
        fault: process.CommandPostReleaseTestFault,
        primary: std.meta.Tag(process.CommandPrimary),
    }{
        .{ .fault = .monitor_clock, .primary = .local_io },
        .{ .fault = .monitor_cancelled, .primary = .cancelled },
        .{ .fault = .monitor_event, .primary = .event_limit },
        .{ .fault = .monitor_output, .primary = .output_overflow },
        .{ .fault = .monitor_io, .primary = .local_io },
        .{ .fault = .monitor_poll, .primary = .local_io },
        .{ .fault = .fallback_clock, .primary = .local_io },
        .{ .fault = .result_build, .primary = .local_io },
    };
    for ([_][]const u8{ "ordinary-child", "setsid-child", "double-fork" }) |mode| {
        for (cases) |case| {
            var fixture = try support.Fixture.init();
            defer fixture.deinit();
            var marker_buffer: [96:0]u8 = undefined;
            const marker = try std.fmt.bufPrintZ(
                &marker_buffer,
                "{s}-{s}",
                .{ mode, @tagName(case.fault) },
            );
            var fault: process.CommandPostReleaseTestState = .{
                .fault = case.fault,
            };
            var result = try process.runCommandTest(
                allocator,
                io,
                try request(
                    executable,
                    &.{ path, mode, marker },
                    &environment,
                    fixture.directory.dir,
                ),
                .{ .post_release = &fault },
            );
            defer result.deinit(allocator);

            try testing.expectEqual(case.primary, std.meta.activeTag(result.primary));
            try testing.expectEqual(.complete, result.cleanup);
            try testing.expect(result.cleanup_complete);
            try testing.expectEqual(@as(u32, 1), fault.fault_injections);
            try testing.expectEqual(@as(u16, 1), result.descendants.observed);
            try testing.expectEqual(
                result.descendants.observed,
                result.descendants.identity_validated,
            );
            try testing.expectEqual(
                result.descendants.observed + 2,
                result.reap_events,
            );
            try markerPresent(fixture, marker);
            try support.noChildren();
        }
    }

    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var followup = try process.runCommand(
        allocator,
        io,
        try request(
            executable,
            &.{ path, "bytes", "0", "0", "0" },
            &environment,
            fixture.directory.dir,
        ),
    );
    defer followup.deinit(allocator);
    try testing.expect(followup.succeeded());
    try support.noChildren();
}

test "unexpected post-release unwind is recovered by the cleanup guard" {
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();

    for ([_][]const u8{ "ordinary-child", "setsid-child", "double-fork" }) |mode| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var marker_buffer: [64:0]u8 = undefined;
        const marker = try std.fmt.bufPrintZ(&marker_buffer, "{s}-unwind", .{mode});
        var fault: process.CommandPostReleaseTestState = .{ .fault = .unwind };
        try testing.expectError(
            error.PostReleaseTestFailure,
            process.runCommandTest(
                allocator,
                io,
                try request(
                    executable,
                    &.{ path, mode, marker },
                    &environment,
                    fixture.directory.dir,
                ),
                .{ .post_release = &fault },
            ),
        );
        try testing.expectEqual(@as(u32, 1), fault.boundaries);
        try markerPresent(fixture, marker);
        try support.noChildren();

        var followup = try process.runCommand(
            allocator,
            io,
            try request(
                executable,
                &.{ path, "bytes", "0", "0", "0" },
                &environment,
                fixture.directory.dir,
            ),
        );
        try testing.expect(followup.succeeded());
        followup.deinit(allocator);
        try support.noChildren();
    }
}
