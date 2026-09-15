//! Separate process: closed-pipe completion must not bypass irreversible poison.
const std = @import("std");
const support = @import("process_private_test_support.zig");
const process = support.process;
const testing = std.testing;
const allocator = support.allocator;
const io = support.io;
const linux = std.os.linux;

test "completed leader and both EOFs still refuse a live escaped writer" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    const executable = try support.executable();
    defer allocator.free(executable);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const options: process.PrivateOptions = .{ .process = .{
        .argv = &.{ executable, "escaped-closed" },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .deadline = try process.Deadline.afterMilliseconds(5000),
        .cleanup_ms = 3000,
    } };
    const started = try process.monotonicNanoseconds();
    const result = try process.runPrivate(allocator, io, &lock, "out", "err", options);
    const elapsed = (try process.monotonicNanoseconds()) - started;
    var output = try fixture.read("out");
    defer output.deinit();
    const owned_fixture_pid = try std.fmt.parseInt(linux.pid_t, std.mem.trim(u8, output.bytes(), "\n"), 10);
    defer support.reapFixtureChildIfOwned(owned_fixture_pid);
    try testing.expect(elapsed >= 3000 * std.time.ns_per_ms and elapsed < 4000 * std.time.ns_per_ms);
    try testing.expectEqual(@as(u8, 0), result.execution.termination.?.exited);
    try testing.expect(!result.execution.cleanup_complete);
    try testing.expectEqual(.cleanup_failed, result.execution.failures.cleanup.?.category);
    try testing.expectEqual(.partial, result.capture);
    try testing.expectError(error.UnsuccessfulCapture, result.requireSuccess());
    try testing.expectError(error.UnresolvedCleanup, process.run(allocator, io, options.process));
    try testing.expectError(error.UnresolvedCleanup, process.runPrivate(allocator, io, &lock, "again", "again-err", options));
    lock.close(io);
    try testing.expectError(error.WouldBlock, fixture.directory.lock(io));
}
