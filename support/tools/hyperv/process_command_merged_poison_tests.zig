//! Separate process: merged capture cannot clear unresolved descendant custody.
const std = @import("std");
const support = @import("process_private_test_support.zig");
const process = support.process;
const testing = std.testing;
const allocator = support.allocator;
const io = support.io;
const linux = std.os.linux;

test "merged partial capture preserves cleanup deadline poison and blocks later commands" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    const path = try support.executable();
    defer allocator.free(path);
    var executable = try process.Executable.open(io, path);
    defer executable.close(io);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var request: process.CommandRequest = .{
        .executable = executable,
        .argv = &.{ path, "orphan-pipes" },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .capture = .{ .merged = 64 * 1024 },
        .primary_deadline = try process.Deadline.afterMilliseconds(3000),
        .cleanup_deadline = try process.Deadline.afterMilliseconds(1),
        .limits = .{ .term_grace_ms = 100 },
    };
    var result = try process.runCommand(allocator, io, request);
    defer result.deinit(allocator);
    const child = try std.fmt.parseInt(linux.pid_t, std.mem.trim(u8, result.stdout, "\n"), 10);
    defer support.reapFixtureChildIfOwned(child);
    try testing.expectEqual(@as(u8, 0), result.primary.exited);
    try testing.expect(!result.succeeded());
    try testing.expect(!result.cleanup_complete);
    try testing.expectEqual(.deadline, result.cleanup);
    try testing.expectEqual(.incomplete, result.stdout_status);
    try testing.expectEqual(.complete, result.stderr_status);
    try testing.expectEqualStrings("", result.stderr);
    request.primary_deadline = try process.Deadline.afterMilliseconds(1000);
    request.cleanup_deadline = try process.Deadline.afterMilliseconds(2000);
    try testing.expectError(error.UnresolvedCleanup, process.runCommand(allocator, io, request));
}
