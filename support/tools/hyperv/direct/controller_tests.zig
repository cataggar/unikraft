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
    inline for (.{ error.MalformedJson, error.DuplicateField }) |err|
        try t.expectEqual(@as(u8, 4), controller.observationExit(err));
    inline for (.{ error.CaptureFailed, error.FileChanged }) |err|
        try t.expectEqual(@as(u8, 1), controller.observationExit(err));
}

test "serial call policies do not latch poll failures or incomplete parser status as primary" {
    try t.expectEqual(@as(?u8, null), controller.primaryStatus(.required, 0));
    for ([_]u8{ 1, 2, 12, 17, 23, 124, 125, 143 }) |code| {
        try t.expectEqual(@as(?u8, code), controller.primaryStatus(.required, code));
        try t.expectEqual(@as(?u8, null), controller.primaryStatus(.serial_poll, code));
        try t.expectEqual(@as(?u8, null), controller.primaryStatus(.serial_parser, code));
    }
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
    result.execution.failures.primary = .{ .stage = .process_run, .category = .output_limit };
    result.capture = .overflow;
    try t.expectEqual(@as(u8, 153), controller.processExit(result, &cancellation));
    try t.expectEqual(@as(?u32, 15), controller.childTermination(result).signal);
    try t.expectEqual(@as(?u8, null), controller.childTermination(result).exit);
    result.execution.termination = .{ .exited = 12 };
    try t.expectEqual(@as(u8, 153), controller.processExit(result, &cancellation));
    try t.expectEqual(@as(?u8, 12), controller.childTermination(result).exit);
    result.execution.failures.primary = null;
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

test "directory path binding permits local writes but refuses replacement directories" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    const original = try local.directory(io, fixture.directory, "attempt");
    defer original.close(io);
    const path = try std.fmt.allocPrint(a, "{s}/{s}/attempt", .{ support.options.test_root.?, fixture.name });
    defer a.free(path);
    try local.verifyDirectory(io, original, path);
    var writer = try original.lock(io);
    defer writer.close(io);
    try local.immutableRaw(io, &writer, "observation.json", "{}");
    try local.verifyDirectory(io, original, path);
    try fixture.directory.dir.rename("attempt", fixture.directory.dir, "original-attempt", io);
    const replacement = try local.directory(io, fixture.directory, "attempt");
    defer replacement.close(io);
    try t.expectError(error.DirectoryChanged, local.verifyDirectory(io, original, path));
}

test "uploader lock handoff retains the original inode without holding the worker lock" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    const upload = try local.directory(io, fixture.directory, "upload-os");
    defer upload.close(io);
    var writer = try upload.lock(io);
    defer writer.close(io);
    const original = try core.private_files.snapshot(writer.file.?);
    writer.close(io);
    {
        var worker = try upload.lock(io);
        defer worker.close(io);
        try custody.requireDurable(try worker.createImmutable(io, "transfer-intent.json", "{}"));
    }
    writer = try upload.lock(io);
    try t.expect(core.private_files.sameSnapshot(original, try core.private_files.snapshot(writer.file.?)));
    try local.verifyLock(io, &writer);
}

fn finalResult(primary: u8, cleanup: u8, accepted: bool) custody.FinalResult {
    return .{
        .outcome = .{
            .phase = .@"persistence-evidence-complete",
            .primary_exit = primary,
            .cleanup_exit = cleanup,
            .reserved_boots = 2,
            .persistence_evidence_complete = true,
            .owned_group_absent = true,
            .group_creation_attempted = true,
            .failure_diagnostics = .{},
            .boot2_freshness = .{ .cached_reads = 0, .cached_reason = null },
            .accepted = accepted,
        },
        .recording = .{ .status = .durable },
        .exit_code = if (primary != 0) primary else if (accepted) 0 else 1,
    };
}

test "final evidence refusal does not become cleanup failure or erase primary status" {
    var result = finalResult(17, 0, false);
    result.evidence_error = error.FileChanged;
    try t.expectEqual(@as(u8, 17), controller.finalExit(result, null));
    try t.expectEqual(@as(u8, 17), controller.finalExit(result, 15));
    try t.expectEqual(@as(u8, 0), result.outcome.cleanup_exit);
    result.recording.status = .publication_unknown;
    try t.expectEqual(@as(u8, 17), controller.finalExit(result, null));
}

test "final result rejects every uncertainty and retains a late cancellation" {
    const success = finalResult(0, 0, true);
    try t.expectEqual(@as(u8, 0), controller.finalExit(success, null));
    try t.expectEqual(@as(u8, 143), controller.finalExit(success, 15));
    inline for (.{ "evidence_error", "recording_error", "cleanup_error" }) |field| {
        var result = success;
        @field(result, field) = error.Injected;
        try t.expectEqual(@as(u8, 1), controller.finalExit(result, null));
    }
    for ([_]core.private_files.CommitStatus{ .not_committed, .publication_unknown, .visible_not_durable }) |status| {
        var result = success;
        result.recording.status = status;
        try t.expectEqual(@as(u8, 1), controller.finalExit(result, null));
    }
    inline for (.{ "primary", "cleanup", "recording" }) |field| {
        var result = success;
        @field(result.recording.failures, field) = .{ .stage = .state_record, .category = .local_io };
        try t.expectEqual(@as(u8, 1), controller.finalExit(result, null));
    }
    var refused = success;
    refused.outcome.accepted = false;
    try t.expectEqual(@as(u8, 1), controller.finalExit(refused, null));
}
