// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const authority = @import("root.zig");
const cli = authority.cli;
const records = authority.records;
const types = authority.types;
const tx = authority.transaction;
const a = std.testing.allocator;
const io = std.testing.io;
const fixtures = @import("test_fixtures.zig");
const goldenRecord = fixtures.goldenRecord;

test "shared producer and owner entry points typecheck without installing handlers" {
    std.testing.refAllDecls(records);
    std.testing.refAllDecls(tx);
}

fn arguments(allocator: std.mem.Allocator, command: []const u8, flags: []const []const u8) ![][]const u8 {
    var result: std.ArrayList([]const u8) = .empty;
    try result.append(allocator, command);
    for (flags) |flag| {
        try result.append(allocator, flag);
        try result.append(allocator, if (std.mem.eql(u8, flag, "--decision")) "denied" else if (std.mem.endsWith(u8, flag, "-unix") or std.mem.endsWith(u8, flag, "-microusd")) "1800000100" else "/explicit/input");
    }
    return result.toOwnedSlice(allocator);
}

test "authority parser freezes all four required surfaces and help without dispatch" {
    const c = authority.contracts.cli;
    const cases = .{
        .{ "prepare-azure-runtime", c.prepare_required ++ c.prepare_repeated_required },
        .{ "plan", c.plan_required },
        .{ "record-authorization", c.authorize_required },
        .{ "admit", c.admit_required },
    };
    inline for (cases) |case| {
        const flags = case[1];
        const argv = try arguments(a, case[0], &flags);
        defer a.free(argv);
        var parsed = try cli.parse(a, argv);
        defer parsed.deinit();
        try std.testing.expectEqualStrings(case[0], @tagName(parsed.result.command));
        var helped = try cli.parse(a, &.{ case[0], "--help" });
        defer helped.deinit();
        try std.testing.expect(helped.result == .help);
        for (0..case[1].len) |omitted| {
            var missing: std.ArrayList([]const u8) = .empty;
            defer missing.deinit(a);
            try missing.append(a, case[0]);
            for (case[1], 0..) |_, index| if (index != omitted) try missing.appendSlice(a, argv[1 + 2 * index .. 3 + 2 * index]);
            try std.testing.expectError(error.MissingOption, cli.parse(a, missing.items));
        }
    }
    var help = try cli.parse(a, &.{"--help"});
    defer help.deinit();
    try std.testing.expect(help.result.help == null);
    try std.testing.expectError(error.MissingCommand, cli.parse(a, &.{}));
    try std.testing.expectError(error.UnknownCommand, cli.parse(a, &.{"candidate"}));
}

test "authority parser retains repeated roots and signed integers but rejects open options" {
    const argv = try arguments(a, "prepare-azure-runtime", &(authority.contracts.cli.prepare_required ++ authority.contracts.cli.prepare_repeated_required));
    defer a.free(argv);
    var repeated: std.ArrayList([]const u8) = .empty;
    defer repeated.deinit(a);
    try repeated.appendSlice(a, argv);
    try repeated.appendSlice(a, &.{ "--package-root=/second", "--data-root", "/data", "--native-dependency", "/loader" });
    var parsed = try cli.parse(a, repeated.items);
    defer parsed.deinit();
    const prepare = parsed.result.command.@"prepare-azure-runtime";
    try std.testing.expectEqual(@as(usize, 2), prepare.package_root.len);
    try std.testing.expectEqualStrings("/second", prepare.package_root[1]);
    try std.testing.expectEqualStrings("/loader", prepare.native_dependency[0]);
    inline for (.{ "--git=/git", "--validation-output=/fresh", "--azure=/duplicate", "--approved=true" }) |extra| {
        try repeated.append(a, extra);
        try std.testing.expectError(if (std.mem.startsWith(u8, extra, "--azure=")) error.DuplicateOption else error.UnknownOption, cli.parse(a, repeated.items));
        _ = repeated.pop();
    }
    try std.testing.expectError(error.InvalidInteger, cli.parse(a, &.{ "plan", "--created-unix=1.5" }));
    try std.testing.expectError(error.InvalidDecision, cli.parse(a, &.{ "record-authorization", "--decision=pending" }));
    try std.testing.expectError(error.MissingValue, cli.parse(a, &.{ "admit", "--output", "--plan", "/plan" }));
    const signed = try arguments(a, "plan", &authority.contracts.cli.plan_required);
    defer a.free(signed);
    var optional: std.ArrayList([]const u8) = .empty;
    defer optional.deinit(a);
    try optional.appendSlice(a, signed);
    try optional.append(a, "--created-unix=-1");
    var signed_parsed = try cli.parse(a, optional.items);
    defer signed_parsed.deinit();
    try std.testing.expectEqual(@as(types.Integer, -1), signed_parsed.result.command.plan.created_unix.?);
    try std.testing.expectError(error.InvalidInteger, records.unsigned(signed_parsed.result.command.plan.created_unix.?));
}

test "native producers reproduce frozen runtime plan template both decisions and admission bytes" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const allocator = arena.allocator();
    const plan_bytes = try goldenRecord(allocator, "plan");
    var plan = try records.parse(types.Plan, allocator, plan_bytes);
    defer plan.deinit();
    const encoded_plan = try records.planBytes(allocator, plan.value);
    try std.testing.expectEqualStrings(plan_bytes, encoded_plan);
    const digest = std.fmt.bytesToHex(tx.hash(encoded_plan), .lower);
    const template = try records.approvalTemplate(plan.value, &digest);
    try std.testing.expectEqualStrings(try goldenRecord(allocator, "approval_template"), try records.templateBytes(allocator, plan.value, &digest, template));
    inline for (.{ "authorization_approved", "authorization_denied" }) |name| {
        const expected = try goldenRecord(allocator, name);
        var fixture = try records.parse(types.Authorization, allocator, expected);
        defer fixture.deinit();
        const decision = fixture.value;
        const constructed = try records.authorization(plan.value, &digest, template, .{
            .decision = decision.decision,
            .approver = decision.approver,
            .reference = decision.reference,
            .recorded_unix = decision.recorded_unix,
            .expires_unix = decision.expires_unix,
            .now = decision.recorded_unix,
        });
        try std.testing.expectEqualStrings(expected, try records.authorizationBytes(allocator, plan.value, &digest, constructed, decision.recorded_unix));
    }
    const runtime_bytes = try goldenRecord(allocator, "azure_runtime");
    var runtime = try records.parse(types.runtime.Contract, allocator, runtime_bytes);
    defer runtime.deinit();
    try std.testing.expectEqualStrings(runtime_bytes, try records.runtimeBytes(allocator, runtime.value));
    const admitted_bytes = try goldenRecord(allocator, "admission");
    var fixture_admission = try records.parse(types.Admission, allocator, admitted_bytes);
    defer fixture_admission.deinit();
    const authorization_bytes = try goldenRecord(allocator, "authorization_approved");
    var approved = try records.parse(types.Authorization, allocator, authorization_bytes);
    defer approved.deinit();
    const admitted = try records.admission(plan.value, fixture_admission.value.plan, approved.value, fixture_admission.value.authorization, approved.value.recorded_unix);
    try std.testing.expectEqualStrings(admitted_bytes, try records.admissionBytes(allocator, admitted, approved.value.recorded_unix));
}

test "decision construction enforces exact binding UTF8 controls and freshness without rejecting current denial" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const allocator = arena.allocator();
    var plan = try records.parse(types.Plan, allocator, try goldenRecord(allocator, "plan"));
    defer plan.deinit();
    var template = try records.parse(types.ApprovalTemplate, allocator, try goldenRecord(allocator, "approval_template"));
    defer template.deinit();
    var foreign = plan.value;
    foreign.ledger.directory.uid ^= 1;
    try std.testing.expectError(error.InvalidLedgerIdentity, records.approvalTemplate(foreign, template.value.plan_sha256));
    const inputs: types.AuthorizationInputs = .{
        .decision = .denied,
        .approver = "réview",
        .reference = "reference",
        .recorded_unix = 100,
        .expires_unix = 3700,
        .now = 100,
    };
    const denied = try records.authorization(plan.value, template.value.plan_sha256, template.value, inputs);
    try records.decisionCurrent(denied, 3699);
    try std.testing.expectError(error.NotAuthorized, denied.current(100));
    try std.testing.expectError(error.ApprovalExpired, records.decisionCurrent(denied, 99));
    try std.testing.expectError(error.ApprovalExpired, records.decisionCurrent(denied, 3700));
    var changed = template.value;
    changed.ledger_initialization_required = !changed.ledger_initialization_required;
    try std.testing.expectError(error.InvalidApprovalTemplate, records.authorization(plan.value, template.value.plan_sha256, changed, inputs));
    var unsafe = inputs;
    unsafe.approver = "name\n";
    try std.testing.expectError(error.InvalidAuthorityField, records.authorization(plan.value, template.value.plan_sha256, template.value, unsafe));
    unsafe = inputs;
    unsafe.expires_unix += 1;
    try std.testing.expectError(error.InvalidApprovalWindow, records.authorization(plan.value, template.value.plan_sha256, template.value, unsafe));
    var admission = try records.parse(types.Admission, allocator, try goldenRecord(allocator, "admission"));
    defer admission.deinit();
    try std.testing.expectError(error.NotAuthorized, records.admission(plan.value, admission.value.plan, denied, admission.value.authorization, 100));
    try std.testing.expectError(error.NonCanonical, records.parse(types.Plan, allocator, "{}"));
    const extra = try std.mem.replaceOwned(u8, allocator, try goldenRecord(allocator, "plan"), "\"version\":2", "\"version\":2,\"zzz\":0");
    var extra_document = try core.contracts.Document.parse(allocator, extra, authority.contracts.json_limits);
    defer extra_document.deinit();
    try std.testing.expectError(error.UnknownField, records.parse(types.Plan, allocator, try extra_document.canonicalAlloc(allocator)));
}

test "UUID producers match every frozen spelling and reject every frozen refusal" {
    for (authority.contracts.uuid.normalization_inputs, authority.contracts.uuid.normalization_outputs) |input, expected| {
        const normalized = try records.normalizeUuid(a, input);
        defer a.free(normalized);
        try std.testing.expectEqualStrings(expected, normalized);
    }
    for (authority.contracts.uuid.rejection_inputs) |input| try std.testing.expectError(error.InvalidUuid, records.normalizeUuid(a, input));
}

const Fixture = struct {
    root: std.Io.Dir,
    parent: std.Io.Dir,
    name: []const u8,
    path: []const u8,
    fn init() !Fixture {
        const parent = try std.Io.Dir.openDirAbsolute(io, @import("test_options").fixture_root, .{});
        errdefer parent.close(io);
        const name = try std.fmt.allocPrint(a, "authority-{d}", .{std.os.linux.getpid()});
        errdefer a.free(name);
        try parent.createDir(io, name, .fromMode(0o700));
        errdefer parent.deleteTree(io, name) catch @panic("authority fixture cleanup failed");
        const root = try parent.openDir(io, name, .{});
        errdefer root.close(io);
        return .{ .root = root, .parent = parent, .name = name, .path = try std.fs.path.join(a, &.{ @import("test_options").fixture_root, name }) };
    }
    fn deinit(self: Fixture) void {
        self.root.close(io);
        self.parent.deleteTree(io, self.name) catch @panic("authority fixture cleanup failed");
        self.parent.close(io);
        a.free(self.name);
        a.free(self.path);
    }
    fn output(self: Fixture) ![]u8 {
        return std.fs.path.join(a, &.{ self.path, "record.json" });
    }
};
const Checks = struct {
    count: usize = 0,
    fail_at: ?usize = null,
    fn check(raw: *anyopaque) !void {
        const self: *Checks = @ptrCast(@alignCast(raw));
        self.count += 1;
        if (self.fail_at == self.count) return error.FreshnessChanged;
    }
    fn barrier(self: *Checks) tx.Barrier {
        return .{ .context = self, .check = check };
    }
};

test "retained transaction publishes durably once preserves evidence and refuses reuse and replacement" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const output = try fixture.output();
    defer a.free(output);
    var checks: Checks = .{};
    var transaction = try tx.Transaction.init(.{ .allocator = a, .io = io }, output);
    defer transaction.deinit();
    try std.testing.expect(transaction.publish("{\"key\":\"value\"}\n", checks.barrier()) == .success);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, transaction.publication);
    try std.testing.expectEqual(@as(usize, 6), checks.count);
    try std.testing.expectEqual(error.TransactionSpent, transaction.publish("{\"key\":\"other\"}\n", checks.barrier()).poisoned.err);
    try std.testing.expectError(error.PathAlreadyExists, tx.Transaction.init(.{ .allocator = a, .io = io }, output));
    var bytes = try transaction.published.?.read(a, null);
    defer bytes.deinit();
    try std.testing.expectEqualStrings("{\"key\":\"value\"}\n", bytes.bytes());
    const changed = try fixture.root.createFile(io, "record.json", .{ .permissions = .fromMode(0o600) });
    defer changed.close(io);
    try changed.writeStreamingAll(io, "{}\n");
    try std.testing.expectError(error.FileChanged, transaction.revalidate(checks.barrier()));
}

test "transaction freshness failures bracket publication and keep late durable output poisoned" {
    for ([_]usize{ 1, 6 }) |fail_at| {
        const fixture = try Fixture.init();
        defer fixture.deinit();
        const output = try fixture.output();
        defer a.free(output);
        var checks: Checks = .{ .fail_at = fail_at };
        var transaction = try tx.Transaction.init(.{ .allocator = a, .io = io }, output);
        defer transaction.deinit();
        const outcome = transaction.publish("{}\n", checks.barrier());
        if (fail_at == 1) {
            try std.testing.expectEqual(error.FreshnessChanged, outcome.refused.err);
            try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, outcome.refused.publication);
            try std.testing.expectError(error.FileNotFound, fixture.root.openFile(io, "record.json", .{}));
        } else {
            try std.testing.expectEqual(error.FreshnessChanged, outcome.poisoned.err);
            try std.testing.expectEqual(core.private_files.CommitStatus.durable, outcome.poisoned.publication);
            try transaction.published.?.revalidate(null);
        }
    }
}

test "transaction refuses earlier failures replaced parents and cancellation without publishing" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const output = try fixture.output();
    defer a.free(output);
    var checks: Checks = .{};
    {
        var transaction = try tx.Transaction.init(.{ .allocator = a, .io = io }, output);
        defer transaction.deinit();
        transaction.failures.primary = .{ .stage = .process_run, .category = .child_failed };
        const failure = transaction.publish("{}\n", checks.barrier()).refused;
        try std.testing.expectEqual(error.PreviousFailure, failure.err);
        try std.testing.expectEqual(core.diagnostics.Category.child_failed, failure.failures.primary.?.category);
    }
    {
        var transaction = try tx.Transaction.init(.{ .allocator = a, .io = io }, output);
        defer transaction.deinit();
        transaction.lock.close(io);
        try std.testing.expectEqual(error.LockNotHeld, transaction.publish("{}\n", checks.barrier()).poisoned.err);
    }
    {
        var signal = try core.process.SignalCancellation.install();
        defer signal.deinit();
        var transaction = try tx.Transaction.init(.{ .allocator = a, .io = io, .signal = &signal }, output);
        defer transaction.deinit();
        if (std.os.linux.errno(std.os.linux.kill(std.os.linux.getpid(), .INT)) != .SUCCESS) return error.FixtureSignal;
        try std.testing.expectEqual(error.Cancelled, transaction.publish("{}\n", checks.barrier()).refused.err);
    }
    {
        var transaction = try tx.Transaction.init(.{ .allocator = a, .io = io }, output);
        defer transaction.deinit();
        const moved = try std.fmt.allocPrint(a, "{s}-moved", .{fixture.name});
        defer a.free(moved);
        try fixture.parent.rename(fixture.name, fixture.parent, moved, io);
        defer fixture.parent.deleteTree(io, moved) catch @panic("moved authority fixture cleanup failed");
        try fixture.parent.createDir(io, fixture.name, .fromMode(0o700));
        try std.testing.expectEqual(error.FileChanged, transaction.publish("{}\n", checks.barrier()).refused.err);
    }
    const current = try fixture.parent.openDir(io, fixture.name, .{});
    defer current.close(io);
    try std.testing.expectError(error.FileNotFound, current.openFile(io, "record.json", .{}));
}

test "transaction fault seam retains publication uncertainty and independent recording cleanup failures" {
    for (std.enums.values(core.private_files.TestFault)) |fault| {
        const fixture = try Fixture.init();
        defer fixture.deinit();
        const output = try fixture.output();
        defer a.free(output);
        var checks: Checks = .{};
        var named_vtable = io.vtable.*;
        named_vtable.dirCreateFileAtomic = fixtures.namedAtomic;
        const fault_io: std.Io = if (fault == .cleanup) .{ .userdata = io.userdata, .vtable = &named_vtable } else io;
        var transaction = try tx.Transaction.init(.{ .allocator = a, .io = fault_io }, output);
        defer transaction.deinit();
        const diagnostic = transaction.publishFault("{}\n", checks.barrier(), fault).poisoned;
        try std.testing.expectEqual(error.PublicationUncertain, diagnostic.err);
        try std.testing.expect(diagnostic.failures.recording != null);
        try std.testing.expectEqual(fault == .cleanup, diagnostic.failures.cleanup != null);
        if (fault == .cleanup) {
            const primary: core.diagnostics.Diagnostic = .{ .stage = .process_run, .category = .child_failed };
            const combined = tx.combineFailures(.{ .primary = primary }, diagnostic.failures);
            try std.testing.expectEqualDeep(primary, combined.primary.?);
            try std.testing.expect(combined.cleanup != null and combined.recording != null);
            const partial = try (core.private_files.Directory{ .dir = fixture.root }).read(io, a, &std.fmt.hex(@as(u64, 0xa170c)), 32, null);
            defer a.free(partial);
            try std.testing.expectEqualStrings("{}\n", partial);
        }
        try std.testing.expectEqual(if (fault == .publication) core.private_files.CommitStatus.publication_unknown else if (fault == .after_rename) core.private_files.CommitStatus.visible_not_durable else core.private_files.CommitStatus.not_committed, diagnostic.publication);
    }
}

const ShortWrite = struct {
    mode: enum { zero, io_zero, invalid_count, short, cancel, io_cancel, deadline, freshness },
    transaction: ?*tx.Transaction = null,
    count: usize = 0,
    var active: ?*ShortWrite = null;

    fn write(userdata: ?*anyopaque, file: std.Io.File, header: []const u8, data: []const []const u8, splat: usize, offset: u64) std.Io.File.WritePositionalError!usize {
        const self = active.?;
        self.count += 1;
        std.debug.assert(header.len == 0 and data.len == 1 and data[0].len != 0 and splat == 1);
        if (self.mode == .zero or self.mode == .io_zero) return 0;
        if (self.mode == .invalid_count) return data[0].len + 1;
        const count = try io.vtable.fileWritePositional(userdata, file, header, &.{data[0][0..1]}, splat, offset);
        if (self.count == 1) switch (self.mode) {
            .cancel => @constCast(self.transaction.?.ctx.signal.?.flag()).store(true, .release),
            .deadline => self.transaction.?.deadline.expires_ns = 0,
            else => {},
        };
        return count;
    }

    fn checkCancel(userdata: ?*anyopaque) std.Io.Cancelable!void {
        const self = active.?;
        if (self.count != 0 and (self.mode == .io_cancel or self.mode == .io_zero)) return error.Canceled;
        return io.vtable.checkCancel(userdata);
    }
};

test "publication rejects zero progress and checks cancellation deadline and custody between short writes" {
    for (std.enums.values(@TypeOf(@as(ShortWrite, undefined).mode))) |mode| {
        const fixture = try Fixture.init();
        defer fixture.deinit();
        const output = try fixture.output();
        defer a.free(output);
        var checks: Checks = .{ .fail_at = if (mode == .freshness) 3 else null };
        var signal = try core.process.SignalCancellation.install();
        defer signal.deinit();
        var state: ShortWrite = .{ .mode = mode };
        ShortWrite.active = &state;
        defer ShortWrite.active = null;
        var vtable = io.vtable.*;
        vtable.fileWritePositional = ShortWrite.write;
        vtable.checkCancel = ShortWrite.checkCancel;
        const short_io: std.Io = .{ .userdata = io.userdata, .vtable = &vtable };
        {
            var transaction = try tx.Transaction.init(.{
                .allocator = a,
                .io = short_io,
                .signal = &signal,
                .publication_deadline = try core.process.Deadline.afterMilliseconds(5000),
            }, output);
            defer transaction.deinit();
            state.transaction = &transaction;
            const outcome = transaction.publish("{}\n", checks.barrier());
            if (mode == .short) {
                try std.testing.expect(outcome == .success);
                try std.testing.expectEqual(@as(usize, 3), state.count);
                var bytes = try transaction.published.?.read(a, null);
                defer bytes.deinit();
                try std.testing.expectEqualStrings("{}\n", bytes.bytes());
            } else {
                try std.testing.expect(outcome == .poisoned);
                try std.testing.expectEqual(switch (mode) {
                    .zero, .io_zero => error.WriteNoProgress,
                    .invalid_count => error.InvalidWriteCount,
                    .cancel => error.Cancelled,
                    .io_cancel => error.Canceled,
                    .deadline => error.DeadlineExceeded,
                    .freshness => error.FreshnessChanged,
                    .short => unreachable,
                }, outcome.poisoned.err);
                try std.testing.expectEqual(@as(usize, 1), state.count);
                try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, outcome.poisoned.publication);
                try std.testing.expect(outcome.poisoned.failures.recording != null);
                try std.testing.expectError(error.FileNotFound, fixture.root.openFile(io, "record.json", .{}));
            }
        }
        const directory = try core.private_files.Directory.open(io, fixture.path);
        defer directory.close(io);
        var released = try directory.lock(io);
        released.close(io);
    }
}

const CleanupFailure = struct {
    count: usize = 0,
    file: ?std.Io.File = null,
    var active: ?*CleanupFailure = null;

    fn create(userdata: ?*anyopaque, dir: std.Io.Dir, destination: []const u8, options: std.Io.Dir.CreateFileAtomicOptions) std.Io.Dir.CreateFileAtomicError!std.Io.File.Atomic {
        const atomic = try fixtures.namedAtomic(userdata, dir, destination, options);
        active.?.file = atomic.file;
        return atomic;
    }
    fn delete(userdata: ?*anyopaque, dir: std.Io.Dir, name: []const u8) std.Io.Dir.DeleteFileError!void {
        const self = active.?;
        self.count += 1;
        if (self.count == 1) return error.AccessDenied;
        return io.vtable.dirDeleteFile(userdata, dir, name);
    }
};

test "named cleanup failure preserves bytes without deferred deletion retry or descriptor leak" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const output = try fixture.output();
    defer a.free(output);
    var checks: Checks = .{};
    var state: CleanupFailure = .{};
    CleanupFailure.active = &state;
    defer CleanupFailure.active = null;
    var vtable = io.vtable.*;
    vtable.dirCreateFileAtomic = CleanupFailure.create;
    vtable.dirDeleteFile = CleanupFailure.delete;
    const fault_io: std.Io = .{ .userdata = io.userdata, .vtable = &vtable };
    {
        var transaction = try tx.Transaction.init(.{ .allocator = a, .io = fault_io }, output);
        defer transaction.deinit();
        const diagnostic = transaction.publishFault("{}\n", checks.barrier(), .before_file_sync).poisoned;
        try std.testing.expectEqual(error.PublicationUncertain, diagnostic.err);
        try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, diagnostic.publication);
        try std.testing.expect(diagnostic.failures.cleanup != null and diagnostic.failures.recording != null);
        try std.testing.expectEqual(@as(usize, 1), state.count);
        try std.testing.expectEqual(std.os.linux.E.BADF, std.os.linux.errno(std.os.linux.fcntl(state.file.?.handle, std.os.linux.F.GETFD, 0)));
    }
    const partial = try (core.private_files.Directory{ .dir = fixture.root }).read(io, a, &std.fmt.hex(@as(u64, 0xa170c)), 32, null);
    defer a.free(partial);
    try std.testing.expectEqualStrings("{}\n", partial);
    try std.testing.expectEqual(@as(usize, 1), state.count);
    try std.testing.expectError(error.FileNotFound, fixture.root.openFile(io, "record.json", .{}));
}

const NamedSwap = struct {
    root: std.Io.Dir,
    at: ?usize,
    count: usize = 0,
    var active: ?*NamedSwap = null;

    fn replace(self: *NamedSwap) !void {
        const name = std.fmt.hex(@as(u64, 0xa170c));
        const bytes = try (core.private_files.Directory{ .dir = self.root }).read(io, a, &name, 32, null);
        defer a.free(bytes);
        try self.root.rename(&name, self.root, "retained-partial", io);
        const replacement = try self.root.createFile(io, &name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer replacement.close(io);
        try replacement.writeStreamingAll(io, bytes);
    }
    fn check(raw: *anyopaque) !void {
        const self: *NamedSwap = @ptrCast(@alignCast(raw));
        self.count += 1;
        if (self.count == self.at) try self.replace();
    }
    fn rename(userdata: ?*anyopaque, old_dir: std.Io.Dir, old_name: []const u8, new_dir: std.Io.Dir, new_name: []const u8) std.Io.Dir.RenamePreserveError!void {
        active.?.replace() catch |err| std.debug.panic("named replacement fixture failed: {s}", .{@errorName(err)});
        return io.vtable.dirRenamePreserve(userdata, old_dir, old_name, new_dir, new_name);
    }
    fn barrier(self: *NamedSwap) tx.Barrier {
        return .{ .context = self, .check = check };
    }
};

test "named atomic custody rejects same-byte replacement during writes before link and in the link window" {
    for ([_]?usize{ 3, 4, null }) |at| {
        const fixture = try Fixture.init();
        defer fixture.deinit();
        const output = try fixture.output();
        defer a.free(output);
        var checks: NamedSwap = .{ .root = fixture.root, .at = at };
        NamedSwap.active = &checks;
        defer NamedSwap.active = null;
        var writer: ShortWrite = .{ .mode = .short };
        ShortWrite.active = &writer;
        defer ShortWrite.active = null;
        var vtable = io.vtable.*;
        vtable.dirCreateFileAtomic = fixtures.namedAtomic;
        if (at == 3) vtable.fileWritePositional = ShortWrite.write;
        if (at == null) vtable.dirRenamePreserve = NamedSwap.rename;
        const fault_io: std.Io = .{ .userdata = io.userdata, .vtable = &vtable };
        var transaction = try tx.Transaction.init(.{
            .allocator = a,
            .io = fault_io,
            .publication_deadline = try core.process.Deadline.afterMilliseconds(5000),
        }, output);
        defer transaction.deinit();
        const outcome = transaction.publish("{}\n", checks.barrier());
        try std.testing.expect(outcome == .poisoned);
        const diagnostic = outcome.poisoned;
        try std.testing.expectEqual(error.FileChanged, diagnostic.err);
        try std.testing.expectEqual(if (at == null) core.private_files.CommitStatus.durable else core.private_files.CommitStatus.not_committed, diagnostic.publication);
        const partial = try (core.private_files.Directory{ .dir = fixture.root }).read(io, a, "retained-partial", 32, null);
        defer a.free(partial);
        try std.testing.expectEqualStrings(if (at == 3) "{" else "{}\n", partial);
        if (at != null) {
            const replacement = try (core.private_files.Directory{ .dir = fixture.root }).read(io, a, &std.fmt.hex(@as(u64, 0xa170c)), 32, null);
            defer a.free(replacement);
            try std.testing.expectEqualStrings(partial, replacement);
            try std.testing.expect(diagnostic.failures.recording != null and diagnostic.failures.cleanup != null);
            try std.testing.expectError(error.FileNotFound, fixture.root.openFile(io, "record.json", .{}));
            if (at == 3) try std.testing.expectEqual(@as(usize, 1), writer.count);
        } else {
            var published = try transaction.published.?.read(a, null);
            defer published.deinit();
            try std.testing.expectEqualStrings("{}\n", published.bytes());
        }
    }
}

const Collision = struct {
    root: std.Io.Dir,
    mode: enum { production, named, ambiguous },
    count: usize = 0,
    named: bool = false,
    foreign: ?core.private_files.Snapshot = null,
    var active: ?*Collision = null;

    fn create(userdata: ?*anyopaque, dir: std.Io.Dir, destination: []const u8, options: std.Io.Dir.CreateFileAtomicOptions) std.Io.Dir.CreateFileAtomicError!std.Io.File.Atomic {
        const self = active.?;
        const atomic = if (self.mode == .production)
            try io.vtable.dirCreateFileAtomic(userdata, dir, destination, options)
        else
            try fixtures.namedAtomic(userdata, dir, destination, options);
        self.named = atomic.file_exists;
        return atomic;
    }
    fn check(raw: *anyopaque) !void {
        const self: *Collision = @ptrCast(@alignCast(raw));
        self.count += 1;
        if (self.count == 4 and self.mode != .ambiguous) {
            const file = try self.root.createFile(io, "record.json", .{ .exclusive = true, .permissions = .fromMode(0o600) });
            defer file.close(io);
            try file.writeStreamingAll(io, "{\"foreign\":true}\n");
            self.foreign = try core.private_files.snapshot(file);
        }
    }
    fn rename(userdata: ?*anyopaque, old_dir: std.Io.Dir, old_name: []const u8, new_dir: std.Io.Dir, new_name: []const u8) std.Io.Dir.RenamePreserveError!void {
        try io.vtable.dirRenamePreserve(userdata, old_dir, old_name, new_dir, new_name);
        return error.HardwareFailure;
    }
    fn barrier(self: *Collision) tx.Barrier {
        return .{ .context = self, .check = check };
    }
};

test "kernel create-only collisions preserve foreign custody and distinguish visible link ambiguity" {
    for (std.enums.values(@TypeOf(@as(Collision, undefined).mode))) |mode| {
        const fixture = try Fixture.init();
        defer fixture.deinit();
        const output = try fixture.output();
        defer a.free(output);
        var state: Collision = .{ .root = fixture.root, .mode = mode };
        Collision.active = &state;
        defer Collision.active = null;
        var vtable = io.vtable.*;
        vtable.dirCreateFileAtomic = Collision.create;
        if (mode == .ambiguous) vtable.dirRenamePreserve = Collision.rename;
        const fault_io: std.Io = .{ .userdata = io.userdata, .vtable = &vtable };
        {
            var transaction = try tx.Transaction.init(.{
                .allocator = a,
                .io = fault_io,
                .publication_deadline = try core.process.Deadline.afterMilliseconds(5000),
            }, output);
            defer transaction.deinit();
            const outcome = transaction.publish("{}\n", state.barrier());
            try std.testing.expect(outcome == .poisoned);
            const diagnostic = outcome.poisoned;
            try std.testing.expectEqual(if (mode == .ambiguous) error.HardwareFailure else error.PathAlreadyExists, diagnostic.err);
            try std.testing.expectEqual(if (mode == .ambiguous) core.private_files.CommitStatus.publication_unknown else core.private_files.CommitStatus.not_committed, diagnostic.publication);
            try std.testing.expectEqual(core.diagnostics.Category.local_io, diagnostic.failures.recording.?.category);
            try std.testing.expectEqual(state.named, diagnostic.failures.cleanup != null);
            try std.testing.expect(transaction.published == null);
            try std.testing.expectEqual(error.TransactionSpent, transaction.publish("{}\n", state.barrier()).poisoned.err);
        }
        const file = try (core.private_files.Directory{ .dir = fixture.root }).openFile(io, "record.json");
        defer file.close(io);
        const observed = try core.private_files.snapshot(file);
        if (state.foreign) |foreign| try std.testing.expect(core.private_files.sameSnapshot(foreign, observed));
        const bytes = try (core.private_files.Directory{ .dir = fixture.root }).read(io, a, "record.json", 32, null);
        defer a.free(bytes);
        try std.testing.expectEqualStrings(if (mode == .ambiguous) "{}\n" else "{\"foreign\":true}\n", bytes);
        if (mode == .named) {
            const partial = try (core.private_files.Directory{ .dir = fixture.root }).read(io, a, &std.fmt.hex(@as(u64, 0xa170c)), 32, null);
            defer a.free(partial);
            try std.testing.expectEqualStrings("{}\n", partial);
        }
        const directory = try core.private_files.Directory.open(io, fixture.path);
        defer directory.close(io);
        var released = try directory.lock(io);
        released.close(io);
    }
}

test "supervision preserves primary and cleanup when a post-run owner barrier refuses" {
    try core.process.initialize();
    var checks: Checks = .{ .fail_at = 2 };
    var environment = std.process.Environ.Map.init(a);
    defer environment.deinit();
    const cwd = try std.Io.Dir.openDirAbsolute(io, @import("test_options").fixture_root, .{});
    defer cwd.close(io);
    const fixture_path = try std.Io.Dir.cwd().realPathFileAlloc(io, @import("test_options").process_fixture, a);
    defer a.free(fixture_path);
    const executable = try core.process.Executable.open(io, fixture_path);
    defer executable.close(io);
    var result = try tx.supervise(.{ .allocator = a, .io = io }, .{
        .executable = executable,
        .argv = &.{ fixture_path, "failure" },
        .cwd = cwd,
        .environment = &environment,
        .primary_deadline = try core.process.Deadline.afterMilliseconds(1000),
        .cleanup_deadline = try core.process.Deadline.afterMilliseconds(2000),
    }, checks.barrier());
    defer result.deinit(a);
    try std.testing.expect(!result.succeeded());
    try std.testing.expectEqual(@as(u8, 7), result.result.primary.exited);
    try std.testing.expectEqual(error.FreshnessChanged, result.freshness.?);
    try std.testing.expectEqual(core.process.CommandCleanup.complete, result.result.cleanup);
    try std.testing.expect(std.mem.indexOf(u8, result.result.stderr, "never-publish") != null);
}
