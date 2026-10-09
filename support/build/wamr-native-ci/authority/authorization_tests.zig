// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const authorization = @import("authorization.zig");
const records = @import("records.zig");
const contracts = @import("contracts.zig");
const types = @import("types.zig");
const tx = @import("transaction.zig");
const core = @import("hyperv_core");
const a = std.testing.allocator;
const io = std.testing.io;
const options = @import("test_options");

test "authorization operation refuses invalid windows signed overflow and authority text without output" {
    const now: i128 = std.Io.Clock.real.now(io).toSeconds();
    var command: types.AuthorizationCommand = .{
        .plan = "/not-opened/plan",
        .template = "/not-opened/template",
        .output = "/not-created/authorization",
        .approver = "synthetic-operator",
        .reference = "source-only fixture",
        .recorded_unix = now - 1,
        .expires_unix = now + 1,
    };
    for ([_]types.Integer{ -1, @as(i128, std.math.maxInt(u64)) + 1 }) |bad| {
        command.recorded_unix = bad;
        try std.testing.expectEqual(error.InvalidInteger, authorization.run(.{ .allocator = a, .io = io }, command).refused.err);
    }
    command.recorded_unix = now - 1;
    command.expires_unix = now - 1 + 3601;
    try std.testing.expectEqual(error.InvalidApprovalWindow, authorization.run(.{ .allocator = a, .io = io }, command).refused.err);
    command.expires_unix = now;
    try std.testing.expectEqual(error.ApprovalExpired, authorization.run(.{ .allocator = a, .io = io }, command).refused.err);
    command.recorded_unix = now + 100;
    command.expires_unix = now + 200;
    try std.testing.expectEqual(error.ApprovalExpired, authorization.run(.{ .allocator = a, .io = io }, command).refused.err);
    command.recorded_unix = now - 1;
    command.expires_unix = now + 600;
    for ([_][]const u8{ "", "bad\n", "\x7f", "\xff", "a" ** 129 }) |bad| {
        command.approver = bad;
        try std.testing.expectEqual(error.InvalidAuthorityField, authorization.run(.{ .allocator = a, .io = io }, command).refused.err);
    }
    command.approver = "operator";
    command.reference = "r" ** 257;
    try std.testing.expectEqual(error.InvalidAuthorityField, authorization.run(.{ .allocator = a, .io = io }, command).refused.err);
}

test "authorization frozen current decisions bind exact template and denied cannot be admitted" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const allocator = arena.allocator();
    var document = try contracts.parseCanonical(allocator, @embedFile("goldens/contracts.json"));
    defer document.deinit();
    const golden = document.value().object.get("canonical_records").?.object;
    const plan_bytes = golden.get("plan").?.string;
    const plan = try records.parse(types.Plan, allocator, plan_bytes);
    defer plan.deinit();
    const digest = std.fmt.bytesToHex(tx.hash(plan_bytes), .lower);
    const template = try records.approvalTemplate(plan.value, &digest);
    inline for (.{ "authorization_approved", "authorization_denied" }) |name| {
        const fixture = try records.parse(types.Authorization, allocator, golden.get(name).?.string);
        defer fixture.deinit();
        const value = fixture.value;
        const decision = try records.authorization(plan.value, &digest, template, .{
            .decision = value.decision,
            .approver = value.approver,
            .reference = value.reference,
            .recorded_unix = value.recorded_unix,
            .expires_unix = value.expires_unix,
            .now = value.recorded_unix,
        });
        try std.testing.expectEqualStrings(golden.get(name).?.string, try records.authorizationBytes(allocator, plan.value, &digest, decision, value.recorded_unix));
        try records.decisionCurrent(decision, value.expires_unix - 1);
        try std.testing.expectError(error.ApprovalExpired, records.decisionCurrent(decision, value.expires_unix));
        if (value.decision == .denied) try std.testing.expectError(error.NotAuthorized, decision.current(value.recorded_unix));
    }
    var inputs: types.AuthorizationInputs = .{
        .decision = .denied,
        .approver = "é" ** 64,
        .reference = "é" ** 128,
        .recorded_unix = std.math.maxInt(u64) - 3600,
        .expires_unix = std.math.maxInt(u64),
        .now = std.math.maxInt(u64) - 3600,
    };
    const current_denial = try records.authorization(plan.value, &digest, template, inputs);
    try records.decisionCurrent(current_denial, inputs.expires_unix - 1);
    try std.testing.expectError(error.ApprovalExpired, records.decisionCurrent(current_denial, inputs.expires_unix));
    inputs.recorded_unix -= 1;
    try std.testing.expectError(error.InvalidApprovalWindow, records.authorization(plan.value, &digest, template, inputs));
    inputs.recorded_unix += 1;
    inputs.approver = "é" ** 64 ++ "x";
    try std.testing.expectError(error.InvalidAuthorityField, records.authorization(plan.value, &digest, template, inputs));
    inputs.approver = "é" ** 64;
    inputs.reference = "é" ** 128 ++ "x";
    try std.testing.expectError(error.InvalidAuthorityField, records.authorization(plan.value, &digest, template, inputs));
    inputs.reference = "operator-reference";
    for (0..33) |index| {
        const control = [_]u8{ 'x', if (index == 32) 0x7f else @intCast(index) };
        inputs.approver = &control;
        try std.testing.expectError(error.InvalidAuthorityField, records.authorization(plan.value, &digest, template, inputs));
    }
}

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    path: []const u8,
    directory: std.Io.Dir,
    plan: types.Plan,
    command: types.AuthorizationCommand,

    fn init() !*Fixture {
        const self = try a.create(Fixture);
        errdefer a.destroy(self);
        self.* = .{ .arena = .init(a), .path = undefined, .directory = undefined, .plan = undefined, .command = .{} };
        errdefer self.arena.deinit();
        const allocator = self.arena.allocator();
        self.path = try std.fmt.allocPrint(allocator, "{s}/authorization-pipeline-{d}", .{ options.fixture_root, std.os.linux.getpid() });
        const package = try std.Io.Dir.cwd().realPathFileAlloc(io, options.authorization_package, allocator);
        const native_tool = try std.Io.Dir.cwd().realPathFileAlloc(io, options.process_fixture, allocator);
        const generated = try std.process.run(allocator, io, .{
            .argv = &.{ "python3", "-B", options.authorization_fixture, self.path, package, native_tool },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        if (generated.term != .exited or generated.term.exited != 0) {
            std.debug.print("authorization synthetic fixture failed: {s}\n", .{generated.stderr});
            return error.FixtureFailed;
        }
        self.directory = try std.Io.Dir.openDirAbsolute(io, self.path, .{ .iterate = true });
        errdefer self.directory.close(io);
        const bytes = try self.directory.readFileAlloc(io, "plan-seed.json", allocator, .limited(65536));
        self.plan = (try records.parse(types.Plan, allocator, bytes)).value;
        self.plan.ledger = try types.compute.ledgerProposal(
            allocator,
            io,
            self.plan.ledger_path,
            self.plan.campaign_id,
            self.plan.ledger.ledger_id,
        );
        try self.savePlan();
        const now = std.Io.Clock.real.now(io).toSeconds();
        self.command = .{
            .plan = try std.fs.path.join(allocator, &.{ self.path, "plan.json" }),
            .template = try std.fs.path.join(allocator, &.{ self.path, "template.json" }),
            .output = try std.fs.path.join(allocator, &.{ self.path, "approved.json" }),
            .decision = .approved,
            .approver = "synthetic source-test operator",
            .reference = "synthetic source-test reference; not a real approval",
            .recorded_unix = now - 1,
            .expires_unix = now + 600,
            .tools = .{
                .azure = self.plan.tools.azure.path,
                .uploader = self.plan.tools.uploader.path,
                .validator = self.plan.tools.validator.path,
                .supervisor = self.plan.tools.supervisor.path,
                .az_python = self.plan.tools.az_python.path,
                .azure_runtime = self.plan.azure_runtime_document.path,
            },
        };
        return self;
    }
    fn savePlan(self: *Fixture) !void {
        const allocator = self.arena.allocator();
        const bytes = try records.planBytes(allocator, self.plan);
        try self.write("plan.json", bytes);
        const digest = std.fmt.bytesToHex(tx.hash(bytes), .lower);
        const template = try records.approvalTemplate(self.plan, &digest);
        try self.write("template.json", try records.templateBytes(allocator, self.plan, &digest, template));
    }
    fn write(self: *Fixture, name: []const u8, bytes: []const u8) !void {
        const file = try self.directory.createFile(io, name, .{ .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
        try file.sync(io);
    }
    fn output(self: *Fixture, name: []const u8) !types.AuthorizationCommand {
        var command = self.command;
        command.output = try std.fs.path.join(self.arena.allocator(), &.{ self.path, name });
        return command;
    }
    fn partialCount(self: *Fixture, name: []const u8) !usize {
        const prefix = try std.fmt.allocPrint(self.arena.allocator(), "{s}.partial-", .{name});
        var entries = self.directory.iterate();
        var count: usize = 0;
        while (try entries.next(io)) |entry| {
            if (std.mem.startsWith(u8, entry.name, prefix)) count += 1;
        }
        return count;
    }
    fn deinit(self: *Fixture) void {
        self.directory.close(io);
        const result = std.process.run(self.arena.allocator(), io, .{
            .argv = &.{ "python3", "-B", options.authorization_fixture, "--cleanup", self.path },
        }) catch @panic("authorization fixture cleanup failed");
        if (result.term != .exited or result.term.exited != 0) @panic("authorization fixture cleanup failed");
        self.arena.deinit();
        a.destroy(self);
    }
};

test "authorization actual source pipeline durably records both current synthetic decisions and retains inputs" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    inline for (.{ types.Decision.approved, types.Decision.denied }) |decision| {
        var command = try fixture.output(@tagName(decision) ++ ".json");
        command.decision = decision;
        const outcome = authorization.run(.{ .allocator = a, .io = io }, command);
        if (outcome != .success) {
            const diagnostic = switch (outcome) {
                .refused, .poisoned => |failure| failure,
                .success => unreachable,
            };
            std.debug.print("source authorization refused: {s} {s}\n", .{ @tagName(diagnostic.phase), @errorName(diagnostic.err) });
            return error.UnexpectedRefusal;
        }
        const owner = outcome.success;
        defer owner.deinit();
        try std.testing.expectEqual(decision, owner.value().decision);
        try std.testing.expectEqual(core.private_files.CommitStatus.durable, owner.transaction.?.publication);
        try std.testing.expectEqualStrings(owner.plan_record.?.artifact().sha256, owner.value().plan_sha256);
        try owner.revalidate();
        try types.compute.verifyAuthorization(fixture.arena.allocator(), io, command.plan, command.output, true);
        if (decision == .denied) {
            try std.testing.expectError(error.NotAuthorized, owner.value().current(@intCast(command.recorded_unix)));
            try std.testing.expectError(error.NotAuthorized, records.admission(
                fixture.plan,
                owner.plan_record.?.artifact(),
                owner.value(),
                owner.artifact(),
                @intCast(command.recorded_unix),
            ));
        }
        var bytes = try owner.transaction.?.published.?.read(a, null);
        defer bytes.deinit();
        const expected = try records.authorizationBytes(a, fixture.plan, owner.value().plan_sha256, owner.value(), @intCast(command.recorded_unix));
        defer a.free(expected);
        try std.testing.expectEqualStrings(expected, bytes.bytes());
        const collision = authorization.run(.{ .allocator = a, .io = io }, command);
        try std.testing.expectEqual(error.PathAlreadyExists, collision.refused.err);
        if (decision == .approved) {
            const template_bytes = try fixture.directory.readFileAlloc(io, "template.json", fixture.arena.allocator(), .limited(65536));
            try fixture.write("template.json", "{}\n");
            try std.testing.expectError(error.FileChanged, owner.revalidate());
            try fixture.write("template.json", template_bytes);
        }
    }
}

test "authorization input parser rejects duplicate unknown coercive and noncanonical records" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const allocator = arena.allocator();
    var golden = try contracts.parseCanonical(allocator, @embedFile("goldens/contracts.json"));
    defer golden.deinit();
    const bytes = golden.value().object.get("canonical_records").?.object.get("plan").?.string;
    const cases = .{
        .{ "\"created_unix\":1800000000", "\"created_unix\":true", error.ExpectedInteger },
        .{ "\"version\":2", "\"version\":\"2\"", error.ExpectedInteger },
        .{ "\"version\":2", "\"version\":2,\"version\":2", error.DuplicateField },
        .{ "\"version\":2", "\"version\":2,\"zzz\":false", error.UnexpectedFields },
        .{ "\"replacement_resources\":false", "\"replacement_resources\":0", error.ExpectedBoolean },
        .{ "\"replacement_resources\":false", "\"replacement_resources\":\"false\"", error.ExpectedBoolean },
        .{ "\"replacement_resources\":false", "\"replacement_resources\":false,\"zzz\":0", error.UnexpectedFields },
    };
    inline for (cases) |case| {
        const raw = try std.mem.replaceOwned(u8, allocator, bytes, case[0], case[1]);
        const changed = if (case[2] == error.DuplicateField)
            raw
        else changed: {
            var document = try core.contracts.Document.parse(allocator, raw, contracts.json_limits);
            defer document.deinit();
            break :changed try document.canonicalAlloc(allocator);
        };
        try std.testing.expectError(case[2], authorization.Test.parseRecord(types.Plan, allocator, changed));
    }
    const extra_lf = try std.fmt.allocPrint(allocator, "{s}\n", .{bytes});
    try std.testing.expectError(error.NonCanonical, authorization.Test.parseRecord(types.Plan, allocator, extra_lf));
    const numeric_overflow = try std.mem.replaceOwned(u8, allocator, bytes, "\"version\":2", "\"version\":18446744073709551616");
    try std.testing.expectError(error.IntegerOverflow, authorization.Test.parseRecord(types.Plan, allocator, numeric_overflow));
    const template_bytes = golden.value().object.get("canonical_records").?.object.get("approval_template").?.string;
    const not_pending = try std.mem.replaceOwned(u8, allocator, template_bytes, "\"pending\"", "\"approved\"");
    try std.testing.expectError(error.InvalidEnum, authorization.Test.parseRecord(types.ApprovalTemplate, allocator, not_pending));
}

test "authorization fully rehashed policy and candidate substitution fail the actual operation before output" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const allocator = fixture.arena.allocator();
    const original = try fixture.directory.readFileAlloc(io, "plan.json", allocator, .limited(65536));
    const wrong_uuid = try std.mem.replaceOwned(u8, allocator, original, fixture.plan.attempt_id, "GGGGGGGG-GGGG-GGGG-GGGG-GGGGGGGGGGGG");
    try fixture.write("plan.json", wrong_uuid);
    const invalid_identity = authorization.run(.{ .allocator = a, .io = io }, try fixture.output("bad-identity.json"));
    try std.testing.expectEqual(error.InvalidIdentity, invalid_identity.refused.err);
    try std.testing.expectError(error.FileNotFound, fixture.directory.openFile(io, "bad-identity.json", .{}));
    try fixture.savePlan();
    var wrong_tool = try fixture.output("bad-tool.json");
    wrong_tool.tools.validator = "/not-the-bound-validator";
    const tool = authorization.run(.{ .allocator = a, .io = io }, wrong_tool);
    try std.testing.expectEqual(error.WrongToolBinding, tool.refused.err);
    try std.testing.expectError(error.FileNotFound, fixture.directory.openFile(io, "bad-tool.json", .{}));
    const invalid = try std.mem.replaceOwned(u8, allocator, original, "\"boot_count\":2", "\"boot_count\":3");
    try fixture.write("plan.json", invalid);
    var template_bytes = try fixture.directory.readFileAlloc(io, "template.json", allocator, .limited(65536));
    const original_digest = std.fmt.bytesToHex(tx.hash(original), .lower);
    const invalid_digest = std.fmt.bytesToHex(tx.hash(invalid), .lower);
    template_bytes = try std.mem.replaceOwned(u8, allocator, template_bytes, &original_digest, &invalid_digest);
    template_bytes = try std.mem.replaceOwned(u8, allocator, template_bytes, "\"boot_count\":2", "\"boot_count\":3");
    try fixture.write("template.json", template_bytes);
    const policy = authorization.run(.{ .allocator = a, .io = io }, try fixture.output("bad-policy.json"));
    try std.testing.expectEqual(error.InvalidTopology, policy.refused.err);
    try std.testing.expectError(error.FileNotFound, fixture.directory.openFile(io, "bad-policy.json", .{}));
    try fixture.savePlan();
    const candidate_bytes = try fixture.directory.readFileAlloc(io, "candidate.json", allocator, .limited(65536));
    const replacement = try std.mem.replaceOwned(u8, allocator, candidate_bytes, fixture.plan.subscription, "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa");
    try fixture.write("candidate.json", replacement);
    const digest = std.fmt.bytesToHex(tx.hash(replacement), .lower);
    fixture.plan.candidate.sha256 = try allocator.dupe(u8, &digest);
    fixture.plan.candidate.size = replacement.len;
    try fixture.savePlan();
    const candidate = authorization.run(.{ .allocator = a, .io = io }, try fixture.output("bad-candidate.json"));
    try std.testing.expectEqual(error.WrongCandidate, candidate.refused.err);
    try std.testing.expectError(error.FileNotFound, fixture.directory.openFile(io, "bad-candidate.json", .{}));
}

fn expireAfterValidation(count: usize, owner: *authorization.Recorded) !void {
    if (count == 1) owner.hooks.?.now_seconds = owner.value().expires_unix;
}
fn expireAfterPublication(_: usize, owner: *authorization.Recorded) !void {
    const transaction = &(owner.transaction orelse return);
    if (transaction.published == null or transaction.publication != .durable) return;
    owner.hooks.?.now_seconds = owner.value().expires_unix;
}
fn expireAfterPrivateValidation(count: usize, owner: *authorization.Recorded) !void {
    if (count == 3) owner.hooks.?.now_seconds = owner.value().expires_unix;
}
fn changeInput(count: usize, owner: *authorization.Recorded) !void {
    if (count != 3) return;
    const file = try std.Io.Dir.cwd().createFile(io, owner.command.template, .{ .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, "{}\n");
}
fn cancelAfterPublication(_: usize, owner: *authorization.Recorded) !void {
    const transaction = &(owner.transaction orelse return);
    if (transaction.published == null or transaction.publication != .durable) return;
    owner.hooks.?.after_action = null;
    if (std.os.linux.errno(std.os.linux.kill(std.os.linux.getpid(), .INT)) != .SUCCESS) return error.FixtureSignal;
}
fn collideAtPublication(_: usize, owner: *authorization.Recorded) !void {
    const transaction = &(owner.transaction orelse return);
    if (owner.phase != .publication or owner.private_record == null or
        !transaction.attempted or transaction.published != null) return;
    owner.hooks.?.action = null;
    const file = try std.Io.Dir.cwd().createFile(io, owner.command.output, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, "{}\n");
}

test "authorization real pipeline preserves short writes sync uncertainty and cleanup independently" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const cases = [_]authorization.Test.Hooks{
        .{ .short_private_write = true },
        .{ .private_fault = .before_file_sync },
        .{ .private_fault = .after_rename },
        .{ .final_fault = .cleanup },
    };
    for (cases, 0..) |selected, index| {
        var hooks = selected;
        const name = try std.fmt.allocPrint(fixture.arena.allocator(), "write-fault-{d}.json", .{index});
        var named_vtable = io.vtable.*;
        named_vtable.dirCreateFileAtomic = @import("test_fixtures.zig").namedAtomic;
        const fault_io: std.Io = if (selected.final_fault == .cleanup) .{ .userdata = io.userdata, .vtable = &named_vtable } else io;
        const outcome = authorization.Test.run(.{ .allocator = a, .io = fault_io }, try fixture.output(name), &hooks);
        try std.testing.expect(outcome == .poisoned);
        const failure = outcome.poisoned;
        try std.testing.expectEqual(if (selected.short_private_write) error.ShortWrite else error.PublicationUncertain, failure.err);
        if (selected.private_fault == .after_rename) try std.testing.expectEqual(core.private_files.CommitStatus.visible_not_durable, failure.publication);
        if (selected.final_fault == .cleanup) {
            try std.testing.expect(failure.failures.recording != null);
            try std.testing.expect(failure.failures.cleanup != null);
            try std.testing.expect(failure.failures.primary == null);
        }
        if (selected.short_private_write or selected.private_fault == .after_rename or selected.final_fault == .cleanup)
            try std.testing.expectEqual(@as(usize, 1), try fixture.partialCount(name));
        try std.testing.expectError(error.FileNotFound, fixture.directory.openFile(io, name, .{}));
    }
    var hooks: authorization.Test.Hooks = .{ .action = collideAtPublication };
    const collision = authorization.Test.run(.{ .allocator = a, .io = io }, try fixture.output("racing-output.json"), &hooks);
    try std.testing.expectEqual(error.PathAlreadyExists, collision.poisoned.err);
    try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, collision.poisoned.publication);
    const existing = try fixture.directory.readFileAlloc(io, "racing-output.json", fixture.arena.allocator(), .limited(64));
    try std.testing.expectEqualStrings("{}\n", existing);
    try std.testing.expectEqual(@as(usize, 1), try fixture.partialCount("racing-output.json"));
}

test "authorization freshness barriers refuse after slow validation and keep late outputs poisoned" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    {
        var signal = try core.process.SignalCancellation.install();
        defer signal.deinit();
        if (std.os.linux.errno(std.os.linux.kill(std.os.linux.getpid(), .INT)) != .SUCCESS) return error.FixtureSignal;
        const outcome = authorization.run(.{ .allocator = a, .io = io, .signal = &signal }, try fixture.output("cancelled-before.json"));
        try std.testing.expectEqual(error.Cancelled, outcome.refused.err);
        try std.testing.expectError(error.FileNotFound, fixture.directory.openFile(io, "cancelled-before.json", .{}));
    }
    {
        var hooks: authorization.Test.Hooks = .{ .after_action = expireAfterValidation };
        const refused = authorization.Test.run(.{ .allocator = a, .io = io }, try fixture.output("expired-before.json"), &hooks);
        try std.testing.expectEqual(error.ApprovalExpired, refused.refused.err);
        try std.testing.expectError(error.FileNotFound, fixture.directory.openFile(io, "expired-before.json", .{}));
    }
    {
        var hooks: authorization.Test.Hooks = .{ .after_action = expireAfterPrivateValidation };
        const outcome = authorization.Test.run(.{ .allocator = a, .io = io }, try fixture.output("expired-private.json"), &hooks);
        try std.testing.expectEqual(error.ApprovalExpired, outcome.poisoned.err);
        try std.testing.expectEqual(core.private_files.CommitStatus.durable, outcome.poisoned.publication);
        try std.testing.expectError(error.FileNotFound, fixture.directory.openFile(io, "expired-private.json", .{}));
        try std.testing.expectEqual(@as(usize, 1), try fixture.partialCount("expired-private.json"));
    }
    {
        var hooks: authorization.Test.Hooks = .{ .after_action = expireAfterPublication };
        const outcome = authorization.Test.run(.{ .allocator = a, .io = io }, try fixture.output("expired-after.json"), &hooks);
        try std.testing.expectEqual(error.ApprovalExpired, outcome.poisoned.err);
        try std.testing.expectEqual(core.private_files.CommitStatus.durable, outcome.poisoned.publication);
        const file = try fixture.directory.openFile(io, "expired-after.json", .{});
        file.close(io);
    }
    {
        var signal = try core.process.SignalCancellation.install();
        defer signal.deinit();
        var hooks: authorization.Test.Hooks = .{ .after_action = cancelAfterPublication };
        const outcome = authorization.Test.run(.{ .allocator = a, .io = io, .signal = &signal }, try fixture.output("cancelled-after.json"), &hooks);
        try std.testing.expectEqual(error.Cancelled, outcome.poisoned.err);
        try std.testing.expectEqual(core.private_files.CommitStatus.durable, outcome.poisoned.publication);
        const file = try fixture.directory.openFile(io, "cancelled-after.json", .{});
        file.close(io);
    }
    {
        var hooks: authorization.Test.Hooks = .{ .action = changeInput };
        const outcome = authorization.Test.run(.{ .allocator = a, .io = io }, try fixture.output("changed-input.json"), &hooks);
        try std.testing.expectEqual(error.FileChanged, outcome.poisoned.err);
        try std.testing.expectEqual(core.private_files.CommitStatus.durable, outcome.poisoned.publication);
        try std.testing.expectError(error.FileNotFound, fixture.directory.openFile(io, "changed-input.json", .{}));
        try std.testing.expectEqual(@as(usize, 1), try fixture.partialCount("changed-input.json"));
    }
}
