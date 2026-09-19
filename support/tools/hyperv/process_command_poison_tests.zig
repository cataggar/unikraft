//! Separate process: command-supervisor poison is irreversible.
const std = @import("std");
const support = @import("process_private_test_support.zig");
const process = support.process;
const testing = std.testing;
const allocator = support.allocator;
const io = support.io;
const linux = std.os.linux;

test "cleanup deadline preserves successful primary and poisons unresolved custody" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    const path = try support.executable();
    defer allocator.free(path);
    var executable = try process.Executable.open(io, path);
    defer executable.close(io);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var result = try process.runCommand(allocator, io, .{
        .executable = executable,
        .argv = &.{ path, "resistant-child" },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .primary_deadline = try process.Deadline.afterMilliseconds(3000),
        .cleanup_deadline = try process.Deadline.afterMilliseconds(1),
        .limits = .{ .term_grace_ms = 100 },
    });
    defer result.deinit(allocator);
    var lines = std.mem.tokenizeScalar(u8, result.stdout, '\n');
    const child = try std.fmt.parseInt(linux.pid_t, lines.next() orelse return error.MissingFixturePid, 10);
    defer support.reapFixtureChildIfOwned(child);
    try testing.expectEqual(@as(u8, 0), result.primary.exited);
    try testing.expect(!result.cleanup_complete);
    try testing.expectEqual(.deadline, result.cleanup);
    try testing.expectError(error.UnresolvedCleanup, process.runCommand(allocator, io, .{
        .executable = executable,
        .argv = &.{ path, "bytes", "0", "0", "0" },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .primary_deadline = try process.Deadline.afterMilliseconds(1000),
        .cleanup_deadline = try process.Deadline.afterMilliseconds(2000),
    }));
}
