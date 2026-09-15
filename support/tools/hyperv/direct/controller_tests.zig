// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const controller = @import("controller.zig");
const local = @import("controller_io.zig");
const custody = @import("custody.zig");
const support = @import("process_test_support");
const t = std.testing;
const a = t.allocator;
const io = t.io;
const core = @import("hyperv_core");

test "exact six-input CLI has no bypass or resume surface" {
    try t.expectError(error.InvalidArguments, controller.Inputs.parse(&.{}));
    try t.expectError(error.InvalidArguments, controller.Inputs.parse(&.{ "/scope", "/attempt", "/ledger", "/az", "/upload", "/validate", "--skip-admission" }));
    try t.expectError(error.UnsafePath, controller.Inputs.parse(&.{ "/scope", "attempt", "/ledger", "/az", "/upload", "/validate" }));
    try t.expectError(error.UnsafePath, controller.Inputs.parse(&.{ "/scope\n", "/attempt", "/ledger", "/az", "/upload", "/validate" }));
    const parsed = try controller.Inputs.parse(&.{ "/scope", "/attempt", "/ledger", "/az", "/upload", "/validate" });
    try t.expectEqualStrings("/validate", parsed.programs.validator);
}

test "typed observation classifications preserve declared reference statuses" {
    try t.expectEqual(@as(u8, 1), controller.observationExit(error.ObservationRefused));
    inline for (.{ error.InvalidUint, error.InvalidPowerCode, error.InvalidGrantShape, error.InvalidSerialWrapper }) |err|
        try t.expectEqual(@as(u8, 5), controller.observationExit(err));
    inline for (.{ error.MalformedJson, error.DuplicateField, error.CaptureFailed, error.FileChanged }) |err|
        try t.expectEqual(@as(u8, 1), controller.observationExit(err));
}

test "child exit timeout cancellation and capture outcomes remain distinct" {
    var cancellation = try core.process.SignalCancellation.install();
    defer cancellation.deinit();
    var result: core.process.PrivateResult = .{
        .execution = .{ .termination = .{ .exited = 0 } },
        .capture = .complete,
        .stdout_bytes = 0,
        .stderr_bytes = 0,
    };
    try t.expectEqual(@as(u8, 0), controller.processExit(result, &cancellation));
    for ([_]u8{ 2, 12, 17, 18, 19, 20, 21, 22, 23 }) |code| {
        result.execution.termination = .{ .exited = code };
        result.capture = .partial;
        result.execution.failures.primary = .{ .stage = .process_run, .category = .child_failed };
        try t.expectEqual(code, controller.processExit(result, &cancellation));
        try t.expect(!result.succeeded());
    }
    result.execution.termination = .{ .signal = .TERM };
    result.execution.failures.primary = .{ .stage = .process_run, .category = .timeout };
    try t.expectEqual(@as(u8, 124), controller.processExit(result, &cancellation));
    result.execution.failures.primary = null;
    try t.expectEqual(@as(u8, 143), controller.processExit(result, &cancellation));
    result.execution.termination = .{ .exited = 0 };
    for ([_]core.process.CaptureState{ .partial, .overflow, .io_failed, .durability_failed }) |capture| {
        result.capture = capture;
        try t.expectEqual(@as(u8, 1), controller.processExit(result, &cancellation));
    }
    result.capture = .complete;
    result.execution.cleanup_complete = false;
    try t.expectEqual(@as(u8, 1), controller.processExit(result, &cancellation));
    try t.expectEqual(@as(u8, 125), controller.errorExit(error.ApprovalExpired, &cancellation));
    try t.expectEqual(@as(u8, 124), controller.errorExit(error.BudgetExhausted, &cancellation));
}

test "scratch replacement never reuses immutable authoritative evidence names" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var writer = try fixture.directory.lock(io);
    defer writer.close(io);
    try local.scratch(io, &writer, .@"boot2-candidate.log", "first");
    const pin = try local.pin(a, io, fixture.directory, "boot2-candidate.log", custody.cli_limit);
    try local.scratch(io, &writer, .@"boot2-candidate.log", "different");
    try t.expectError(error.FileChanged, local.verify(a, io, fixture.directory, "boot2-candidate.log", pin, custody.cli_limit));
    try local.immutableRaw(io, &writer, "boot2.log", "authoritative");
    try t.expectError(error.PathAlreadyExists, local.immutableRaw(io, &writer, "boot2.log", "replaced"));
    var bytes = try fixture.read("boot2.log");
    defer bytes.deinit();
    try t.expectEqualStrings("authoritative", bytes.bytes());
    try local.verifyLock(io, &writer);
}

test "large raw publication preserves eight-MiB boundary and byte-exact NULs" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var writer = try fixture.directory.lock(io);
    defer writer.close(io);
    const bytes = try a.alloc(u8, custody.cli_limit + 1);
    defer a.free(bytes);
    @memset(bytes, 0);
    bytes[0] = 'x';
    bytes[custody.cli_limit - 1] = 'z';
    try local.scratch(io, &writer, .@"boot1-candidate.log", bytes[0..custody.cli_limit]);
    try local.immutableRaw(io, &writer, "boot1.log", bytes[0..custody.cli_limit]);
    try t.expectError(error.InvalidCapture, local.immutableRaw(io, &writer, "overflow.log", bytes));
    var actual = try fixture.read("boot1.log");
    defer actual.deinit();
    try t.expectEqualSlices(u8, bytes[0..custody.cli_limit], actual.bytes());
}

test "unsafe scratch entries and replaced lock inode are refused" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var writer = try fixture.directory.lock(io);
    defer writer.close(io);
    try local.immutableRaw(io, &writer, "target", "untouched");
    try fixture.directory.dir.symLink(io, "target", "boot1-candidate.log", .{});
    if (local.scratch(io, &writer, .@"boot1-candidate.log", "unsafe")) |_| return error.ExpectedRefusal else |_| {}
    var bytes = try fixture.read("target");
    defer bytes.deinit();
    try t.expectEqualStrings("untouched", bytes.bytes());
    try fixture.directory.dir.rename(".writer.lock", fixture.directory.dir, "saved-lock", io);
    var replacement = try fixture.directory.lock(io);
    defer replacement.close(io);
    try t.expectError(error.LockChanged, local.verifyLock(io, &writer));
}

test "custody uncertainty conservatively retains cleanup failure without erasing primary exit" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var writer = try fixture.directory.lock(io);
    defer writer.close(io);
    // No accepted evidence is asserted, so finishing only needs the private
    // record writer and capability cleanup, not synthetic scope/artifact data.
    var store: custody.Store = .{
        .allocator = a,
        .io = io,
        .directory = fixture.directory,
        .writer = writer,
        .ledger = fixture.directory,
        .scope = undefined,
        .scope_bytes = undefined,
        .scope_pin = undefined,
        .healthy = false,
    };
    const finished = store.finish(.{
        .phase = .@"boot2-start-intent",
        .primary_exit = 17,
        .cleanup_exit = 0,
        .persistence_evidence_complete = false,
        .owned_group_absent = true,
        .group_creation_attempted = true,
        .final_input_exit = 0,
    });
    try custody.requireDurable(finished.recording);
    try t.expectEqual(@as(u8, 17), finished.exit_code);
    try t.expectEqual(@as(u8, 17), finished.outcome.primary_exit);
    try t.expectEqual(@as(u8, 1), finished.outcome.cleanup_exit);
    try t.expect(!finished.outcome.accepted);
}
