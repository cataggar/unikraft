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
const runtime = @import("runtime.zig");

const StoreFixture = struct {
    backing: support.Fixture,
    arena: std.heap.ArenaAllocator,
    store: custody.Store,
    source: []const u8,
    attempt: []const u8,
    ledger: []const u8,

    fn init() !StoreFixture {
        var backing = try support.Fixture.init();
        errdefer backing.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const memory = arena.allocator();
        var writer = try backing.directory.lock(io);
        defer writer.close(io);
        const bytes = try custody.encode(memory, @import("observation_fixtures.zig").scope);
        try custody.requireDurable(try writer.createImmutable(io, "source.json", bytes));
        const directory = try local.directory(io, backing.directory, "ledger");
        defer directory.close(io);
        const base = try std.fmt.allocPrint(memory, "{s}/{s}", .{ support.options.test_root.?, backing.name });
        const source = try std.fs.path.join(memory, &.{ base, "source.json" });
        const attempt = try std.fs.path.join(memory, &.{ base, "attempt" });
        const ledger = try std.fs.path.join(memory, &.{ base, "ledger" });
        return .{
            .backing = backing,
            .arena = arena,
            .store = try custody.Store.create(a, io, source, attempt, ledger),
            .source = source,
            .attempt = attempt,
            .ledger = ledger,
        };
    }

    fn driftScope(self: *StoreFixture) !void {
        const changed = try self.store.directory.dir.createFile(io, "scope.json", .{ .read = true, .truncate = false, .permissions = .fromMode(0o600) });
        defer changed.close(io);
        try changed.writePositionalAll(io, " \n", self.store.scope_pin.metadata.size);
        try changed.sync(io);
    }

    fn deinit(self: *StoreFixture) void {
        self.store.close();
        self.arena.deinit();
        self.backing.deinit();
    }
};

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

test "local capture failures permanently deny retry admission and preserve meaningful exits" {
    var cancellation = try core.process.SignalCancellation.install();
    defer cancellation.deinit();
    for ([_]core.process.CaptureState{ .io_failed, .durability_failed }) |capture| {
        for ([_]runtime.Lane{ .primary, .cleanup, .diagnostic }) |lane| {
            for ([_]u8{ 0, 12 }) |child_exit| {
                var fixture = try StoreFixture.init();
                defer fixture.deinit();
                const store = &fixture.store;
                try store.consume();
                const result: core.process.PrivateResult = .{
                    .execution = .{ .termination = .{ .exited = child_exit } },
                    .capture = capture,
                    .stdout_bytes = 17,
                    .stderr_bytes = 23,
                };
                const status = controller.processExit(result, &cancellation);
                try t.expectEqual(@as(u8, if (child_exit == 0) 1 else child_exit), status);
                var primary: u8 = 0;
                const failure = controller.recordCaptureFailure(store, lane, &primary, capture, status) orelse return error.ExpectedCaptureFailure;
                try t.expectEqual(@as(u8, if (lane == .primary) status else 0), primary);
                try t.expect(store.recording_failure.? == failure);
                try t.expect(!store.healthy);
                try t.expectError(error.CustodyPoisoned, store.requireConsumed());
                try t.expect(controller.recordCaptureFailure(store, lane, &primary, .complete, 0) == null);
                try t.expect(!store.healthy);
                var earlier_primary: u8 = 19;
                const later_capture: core.process.CaptureState = if (capture == .io_failed) .durability_failed else .io_failed;
                try t.expect(controller.recordCaptureFailure(store, lane, &earlier_primary, later_capture, 1) != null);
                try t.expectEqual(@as(u8, 19), earlier_primary);
                try t.expect(store.recording_failure.? == failure);
                try store.event(.@"cleanup-intent");
                const final = store.finish(.{
                    .phase = .@"seed-consumed",
                    .primary_exit = primary,
                    .cleanup_exit = 0,
                    .persistence_evidence_complete = false,
                    .owned_group_absent = true,
                    .group_creation_attempted = false,
                    .final_input_exit = 0,
                });
                try custody.requireDurable(final.recording);
                try t.expect(final.recording_error.? == failure);
                try t.expectEqual(@as(u8, 1), final.outcome.cleanup_exit);
                try t.expectEqual(primary, final.outcome.primary_exit);
                try t.expect(!final.outcome.accepted);
                try t.expect(final.exit_code != 0);
            }
        }
    }
}

test "ordinary provider and overflow outcomes do not fabricate local recording failures" {
    var fixture = try StoreFixture.init();
    defer fixture.deinit();
    try fixture.store.consume();
    var primary: u8 = 0;
    for ([_]core.process.CaptureState{ .complete, .partial, .overflow }) |capture| {
        try t.expect(controller.recordCaptureFailure(&fixture.store, .primary, &primary, capture, if (capture == .overflow) 153 else 12) == null);
        try t.expectEqual(@as(u8, 0), primary);
        try t.expect(fixture.store.healthy);
        try t.expect(fixture.store.recording_failure == null);
        try fixture.store.requireConsumed();
    }
}

test "real private write and sync failures remain refused after a successful synthetic poll" {
    var cancellation = try core.process.SignalCancellation.install();
    defer cancellation.deinit();
    const executable = try support.executable();
    defer a.free(executable);
    var environment = std.process.Environ.Map.init(a);
    defer environment.deinit();
    for ([_]core.process.PrivateTestFault{ .capture_write, .sync }) |fault| {
        var fixture = try StoreFixture.init();
        defer fixture.deinit();
        try fixture.store.consume();
        var options: core.process.PrivateOptions = .{ .process = .{
            .argv = &.{ executable, "bytes", "17", "23", "0" },
            .environment = &environment,
            .cwd = fixture.store.directory.dir,
            .deadline = try core.process.Deadline.afterMilliseconds(3000),
            .cleanup_ms = 3000,
        } };
        const failed = try core.process.runPrivateTest(a, io, &fixture.store.writer, "failed.stdout", "failed.stderr", options, fault);
        try t.expectEqual(@as(core.process.CaptureState, if (fault == .sync) .durability_failed else .io_failed), failed.capture);
        const status = controller.processExit(failed, &cancellation);
        var primary: u8 = 0;
        try t.expect(controller.recordCaptureFailure(&fixture.store, .primary, &primary, failed.capture, status) != null);
        if (fault == .sync) {
            try t.expectEqual(@as(?u8, 0), controller.childTermination(failed).exit);
            try t.expectEqual(@as(u8, 1), primary);
        }
        options.process.deadline = try core.process.Deadline.afterMilliseconds(3000);
        const next = try core.process.runPrivate(a, io, &fixture.store.writer, "next.stdout", "next.stderr", options);
        try t.expect(next.succeeded());
        try t.expect(controller.recordCaptureFailure(&fixture.store, .primary, &primary, next.capture, 0) == null);
        try t.expectEqual(status, primary);
        try t.expectError(error.CustodyPoisoned, fixture.store.requireConsumed());
        try t.expect(fixture.store.recording_failure != null);
        try support.noChildren();
    }
}

test "scratch replacement never reuses immutable authoritative evidence names" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var writer = try fixture.directory.lock(io);
    defer writer.close(io);
    var cleanup_failure: ?anyerror = null;
    try local.scratch(io, &writer, .@"boot2-candidate.log", "first", &cleanup_failure);
    const pin = try local.pin(a, io, fixture.directory, "boot2-candidate.log", custody.cli_limit);
    try local.scratch(io, &writer, .@"boot2-candidate.log", "different", &cleanup_failure);
    try t.expectError(error.FileChanged, local.verify(a, io, fixture.directory, "boot2-candidate.log", pin, custody.cli_limit));
    try local.immutableRaw(io, &writer, "boot2.log", "authoritative", &cleanup_failure);
    try t.expectError(error.PathAlreadyExists, local.immutableRaw(io, &writer, "boot2.log", "replaced", &cleanup_failure));
    var bytes = try fixture.read("boot2.log");
    defer bytes.deinit();
    try t.expectEqualStrings("authoritative", bytes.bytes());
    try local.verifyLock(io, &writer);
    try t.expect(cleanup_failure == null);
}

test "large raw publication preserves eight-MiB boundary and byte-exact NULs" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var writer = try fixture.directory.lock(io);
    defer writer.close(io);
    var cleanup_failure: ?anyerror = null;
    const bytes = try a.alloc(u8, custody.cli_limit + 1);
    defer a.free(bytes);
    @memset(bytes, 0);
    bytes[0] = 'x';
    bytes[custody.cli_limit - 1] = 'z';
    try local.scratch(io, &writer, .@"boot1-candidate.log", bytes[0..custody.cli_limit], &cleanup_failure);
    try local.immutableRaw(io, &writer, "boot1.log", bytes[0..custody.cli_limit], &cleanup_failure);
    try t.expectError(error.InvalidCapture, local.immutableRaw(io, &writer, "overflow.log", bytes, &cleanup_failure));
    var actual = try fixture.read("boot1.log");
    defer actual.deinit();
    try t.expectEqualSlices(u8, bytes[0..custody.cli_limit], actual.bytes());
    try t.expect(cleanup_failure == null);
}

test "unsafe scratch entries and replaced lock inode are refused" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var writer = try fixture.directory.lock(io);
    defer writer.close(io);
    var cleanup_failure: ?anyerror = null;
    try local.immutableRaw(io, &writer, "target", "untouched", &cleanup_failure);
    try fixture.directory.dir.symLink(io, "target", "boot1-candidate.log", .{});
    if (local.scratch(io, &writer, .@"boot1-candidate.log", "unsafe", &cleanup_failure)) |_| return error.ExpectedRefusal else |_| {}
    var bytes = try fixture.read("target");
    defer bytes.deinit();
    try t.expectEqualStrings("untouched", bytes.bytes());
    try fixture.directory.dir.rename(".writer.lock", fixture.directory.dir, "saved-lock", io);
    var replacement = try fixture.directory.lock(io);
    defer replacement.close(io);
    try t.expectError(error.LockChanged, local.verifyLock(io, &writer));
    try t.expect(cleanup_failure == null);
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
    var cleanup_failure: ?anyerror = null;
    try local.immutableRaw(io, &writer, "observation.json", "{}", &cleanup_failure);
    try local.verifyDirectory(io, original, path);
    try fixture.directory.dir.rename("attempt", fixture.directory.dir, "original-attempt", io);
    const replacement = try local.directory(io, fixture.directory, "attempt");
    defer replacement.close(io);
    try t.expectError(error.DirectoryChanged, local.verifyDirectory(io, original, path));
    try t.expect(cleanup_failure == null);
}

test "named controller scratch cleanup is independent and never silently retried" {
    for ([_]@FieldType(local.ScratchTest, "cleanup"){ .none, .unlink, .directory_sync }) |failure| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var writer = try fixture.directory.lock(io);
        defer writer.close(io);
        var cleanup_failure: ?anyerror = null;
        var fault: local.ScratchTest = .{ .cleanup = failure };
        try t.expectError(error.InjectedPublicationRefusal, local.scratchFault(io, &writer, .@"boot1-candidate.log", "private candidate", &cleanup_failure, &fault));
        try t.expectEqual(@as(usize, 1), fault.unlink_attempts);
        try t.expectEqual(@as(usize, if (failure == .unlink) 0 else 1), fault.sync_attempts);
        const name = std.fmt.hex(fault.named_scratch orelse return error.NamedTemporaryRequired);
        if (failure == .unlink) {
            var retained = try fixture.read(&name);
            defer retained.deinit();
            try t.expectEqualStrings("private candidate", retained.bytes());
            try t.expect(cleanup_failure.? == error.InjectedScratchUnlinkFailure);
        } else {
            try t.expectError(error.FileNotFound, fixture.directory.openFile(io, &name));
            if (failure == .directory_sync) {
                try t.expect(cleanup_failure.? == error.InjectedScratchSyncFailure);
            } else try t.expect(cleanup_failure == null);
        }
        try t.expectError(error.FileNotFound, fixture.directory.openFile(io, "boot1-candidate.log"));
        try local.verifyLock(io, &writer);
    }
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

test "late scope proof refusal is recorded without replacing final-input or earlier primary status" {
    var fixture = try StoreFixture.init();
    defer fixture.deinit();
    const store = &fixture.store;
    var earlier_primary: u8 = 12;
    try controller.checkScopeEvidence(store, &earlier_primary);
    try fixture.driftScope();
    try t.expectError(error.FileChanged, controller.checkScopeEvidence(store, &earlier_primary));
    try t.expectEqual(@as(u8, 12), earlier_primary);
    var new_primary: u8 = 0;
    try t.expectError(error.FileChanged, controller.checkScopeEvidence(store, &new_primary));
    try t.expectEqual(@as(u8, 1), new_primary);
    try t.expect(!store.healthy);
    try store.event(.@"cleanup-intent");
    const result = store.finish(.{
        .phase = .@"local-admission",
        .primary_exit = earlier_primary,
        .cleanup_exit = 0,
        .persistence_evidence_complete = false,
        .owned_group_absent = false,
        .group_creation_attempted = false,
        .final_input_exit = 0,
    });
    try custody.requireDurable(result.recording);
    try t.expectEqual(@as(u8, 12), result.exit_code);
    try t.expectEqual(@as(u8, 0), result.outcome.cleanup_exit);
    try t.expect(!result.outcome.accepted);
}

test "poisoned cleanup always audits new scope drift without running a final child" {
    for ([_]bool{ false, true }) |cleanup_already_started| {
        for ([_]u8{ 0, 17 }) |earlier_primary| {
            var fixture = try StoreFixture.init();
            defer fixture.deinit();
            const memory = fixture.arena.allocator();
            var cancellation = try core.process.SignalCancellation.install();
            defer cancellation.deinit();
            var environment: runtime.Environment = .{ .azure = .init(a), .native = .init(a) };
            defer environment.deinit();
            var budgets = try runtime.Budgets.start(fixture.store.scope.value);
            if (cleanup_already_started) try budgets.beginCleanup();
            const source = try core.private_files.openAbsolute(io, fixture.source, .private);
            defer source.close(io);
            const programs: runtime.Programs = .{
                .azure = "/nonexistent-poisoned-controller-program",
                .uploader = "/nonexistent-poisoned-controller-program",
                .validator = "/nonexistent-poisoned-controller-program",
            };
            const expected = try @import("observations.zig").Expectations.init(memory, fixture.store.scope.value);
            defer expected.deinit();
            var state: controller.testing.State = .{
                .a = memory,
                .temporary = a,
                .io = io,
                .inputs = .{ .scope = fixture.source, .attempt = fixture.attempt, .ledger = fixture.ledger, .programs = programs },
                .hooks = .{},
                .store = &fixture.store,
                .expected = expected,
                .source = .{ .path = fixture.source, .policy = .private, .metadata = try core.private_files.snapshot(source) },
                .runtime = .{ .allocator = a, .io = io, .programs = programs, .environment = &environment, .budgets = &budgets, .cancellation = &cancellation },
                .poisoned = true,
                .primary_exit = earlier_primary,
            };
            const run_id = fixture.store.scope.value.run_id;
            try fixture.driftScope();
            controller.testing.cleanup(&state);
            try t.expectEqual(@as(u8, if (earlier_primary == 0) 1 else earlier_primary), state.primary_exit);
            try t.expectEqual(@as(u8, 1), state.cleanup_exit);
            try t.expectEqual(@as(?u8, null), state.final_input_exit);
            try t.expect(!state.complete);
            try t.expect(!fixture.store.healthy);
            try t.expect(fixture.store.recording_failure == null);
            try t.expectEqualStrings(run_id, fixture.store.scope.value.run_id);
            try t.expect(std.mem.indexOf(u8, state.log_bytes.items, "final scope evidence refused: FileChanged") != null);
            try t.expect(std.mem.indexOf(u8, state.log_bytes.items, "final input validation unavailable") == null);
            try support.noChildren();
        }
    }
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
