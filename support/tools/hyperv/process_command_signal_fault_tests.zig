//! Separate process: command-supervisor poison is irreversible.
const std = @import("std");
const support = @import("process_private_test_support.zig");
const process = support.process;
const testing = std.testing;
const allocator = support.allocator;
const io = support.io;
const linux = std.os.linux;

fn nextDescriptor() !linux.fd_t {
    const opened = linux.openat(linux.AT.FDCWD, "/dev/null", .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.FixtureOpen;
    const descriptor: linux.fd_t = @intCast(opened);
    _ = linux.close(descriptor);
    return descriptor;
}

test "temporary signal failure closes overflow pidfd once and preserves poison" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    const path = try support.executable();
    defer allocator.free(path);
    var executable = try process.Executable.open(io, path);
    defer executable.close(io);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const expected_descriptor = try nextDescriptor();
    var command: process.CommandRequest = .{
        .executable = executable,
        .argv = &.{ path, "many-children", "3" },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .primary_deadline = try process.Deadline.afterMilliseconds(3000),
        .cleanup_deadline = try process.Deadline.afterMilliseconds(5000),
    };
    command.limits.descendants = 1;
    var pidfd: process.CommandPidfdTestState = .{ .fault = .temporary_signal };
    var result = try process.runCommandTest(
        allocator,
        io,
        command,
        .{ .pidfd = &pidfd },
    );
    defer result.deinit(allocator);
    var pids = std.mem.tokenizeScalar(u8, result.stdout, '\n');
    while (pids.next()) |line|
        support.reapFixtureChildIfOwned(try std.fmt.parseInt(linux.pid_t, line, 10));

    try testing.expectEqual(@as(u8, 0), result.primary.exited);
    try testing.expect(!result.cleanup_complete);
    try testing.expectEqual(.signal_failed, result.cleanup);
    try testing.expectEqual(@as(u32, 1), pidfd.fault_injections);
    try testing.expect(pidfd.fault_candidate != null);
    try testing.expectEqual(@as(u32, 1), pidfd.fault_candidate_closes);
    try testing.expectEqual(@as(u32, 0), pidfd.fault_candidate_transfers);
    try testing.expectEqual(
        pidfd.candidate_opens,
        pidfd.candidate_closes + pidfd.candidate_transfers,
    );
    try testing.expectEqual(expected_descriptor, try nextDescriptor());
    try testing.expectError(error.UnresolvedCleanup, process.runCommand(allocator, io, .{
        .executable = executable,
        .argv = &.{ path, "bytes", "0", "0", "0" },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .primary_deadline = try process.Deadline.afterMilliseconds(1000),
        .cleanup_deadline = try process.Deadline.afterMilliseconds(2000),
    }));
}
