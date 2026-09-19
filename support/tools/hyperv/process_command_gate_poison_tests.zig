const std = @import("std");
const support = @import("process_private_test_support.zig");
const process = support.process;
const testing = std.testing;
const allocator = support.allocator;
const io = support.io;

test "unavailable gated ECHILD proof fails closed after reaping" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    const path = try support.executable();
    defer allocator.free(path);
    var executable = try process.Executable.open(io, path);
    defer executable.close(io);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const command: process.CommandRequest = .{
        .executable = executable,
        .argv = &.{ path, "gate-marker", "proof-marker" },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .primary_deadline = try process.Deadline.afterMilliseconds(3000),
        .cleanup_deadline = try process.Deadline.afterMilliseconds(5000),
    };
    var gate: process.CommandGateTestState = .{ .fault = .recovery_proof };
    var result = try process.runCommandTest(
        allocator,
        io,
        command,
        .{ .leader_track_delay_ms = 10, .gate = &gate },
    );
    defer result.deinit(allocator);
    try testing.expectEqual(.local_io, result.primary);
    try testing.expectEqual(.reap_failed, result.cleanup);
    try testing.expect(!result.cleanup_complete);
    try testing.expectEqual(@as(u32, 1), gate.fault_injections);
    try support.noChildren();
    try testing.expectError(
        error.UnresolvedCleanup,
        process.runCommand(allocator, io, command),
    );
}
