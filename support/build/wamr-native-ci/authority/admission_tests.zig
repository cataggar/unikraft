// SPDX-License-Identifier: BSD-3-Clause
//! Synthetic approvals below are byte/guard fixtures, never approval consumption
//! or evidence of a genuine imported Finalized -> admission success.
const std = @import("std");
const core = @import("hyperv_core");
const handoff = @import("wamr_handoff");
const admission = @import("admission.zig");
const records = @import("records.zig");
const tx = @import("transaction.zig");
const types = @import("types.zig");
const t = std.testing;
const a = t.allocator;
const io = t.io;
const ctx: types.Context = .{ .allocator = a, .io = io };

fn golden(allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
    return @import("test_fixtures.zig").goldenRecord(allocator, name);
}
fn paths(plan: types.Plan) types.ToolPaths {
    return .{
        .azure = plan.tools.azure.path,
        .uploader = plan.tools.uploader.path,
        .validator = plan.tools.validator.path,
        .supervisor = plan.tools.supervisor.path,
        .az_python = plan.tools.az_python.path,
        .azure_runtime = plan.azure_runtime_document.path,
    };
}

const Fixture = struct {
    parent: std.Io.Dir,
    root: std.Io.Dir,
    name: [32]u8,
    path: []u8,
    fn init() !Fixture {
        const parent = try std.Io.Dir.openDirAbsolute(io, @import("test_options").fixture_root, .{});
        errdefer parent.close(io);
        var random: [16]u8 = undefined;
        io.random(&random);
        const name = std.fmt.bytesToHex(random, .lower);
        try parent.createDir(io, &name, .fromMode(0o700));
        errdefer parent.deleteTree(io, &name) catch @panic("admission fixture cleanup failed");
        const root = try parent.openDir(io, &name, .{});
        errdefer root.close(io);
        return .{ .parent = parent, .root = root, .name = name, .path = try std.fs.path.join(a, &.{ @import("test_options").fixture_root, &name }) };
    }
    fn deinit(self: Fixture) void {
        self.root.close(io);
        self.parent.deleteTree(io, &self.name) catch @panic("admission fixture cleanup failed");
        self.parent.close(io);
        a.free(self.path);
    }
    fn join(self: Fixture, allocator: std.mem.Allocator, name: []const u8) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.path, name });
    }
    fn write(self: Fixture, name: []const u8, bytes: []const u8) !void {
        const file = try self.root.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writePositionalAll(io, bytes, 0);
        try file.sync(io);
    }
    fn missing(self: Fixture, name: []const u8) !void {
        try t.expectError(error.FileNotFound, self.root.openFile(io, name, .{}));
    }
};

test "admission synthetic frozen context preserves exact canonical fields and every explicit tool role" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const plan = try records.parse(types.Plan, alloc, try golden(alloc, "plan"));
    const approved = try records.parse(types.Authorization, alloc, try golden(alloc, "authorization_approved"));
    const expected = try records.parse(types.Admission, alloc, try golden(alloc, "admission"));
    const value = try records.admission(plan.value, expected.value.plan, approved.value, expected.value.authorization, approved.value.recorded_unix);
    try t.expectEqualStrings(try golden(alloc, "admission"), try records.admissionBytes(alloc, value, approved.value.recorded_unix));
    try admission.Test.paths(plan.value, paths(plan.value));
    inline for (std.meta.fields(types.ToolPaths)) |field| {
        var supplied = paths(plan.value);
        @field(supplied, field.name) = "/different/tool";
        try t.expectError(error.ToolBindingMismatch, admission.Test.paths(plan.value, supplied));
        @field(supplied, field.name) = "";
        try t.expectError(error.UnsafePath, admission.Test.paths(plan.value, supplied));
    }
    try admission.Test.planBinding(a, plan.value, plan.value);
    var rehashed = plan.value;
    rehashed.run.run_id = "999";
    const changed_bytes = try records.planBytes(alloc, rehashed);
    const changed_sha = std.fmt.bytesToHex(tx.hash(changed_bytes), .lower);
    const template = try records.approvalTemplate(rehashed, &changed_sha);
    const reauthorized = try records.authorization(rehashed, &changed_sha, template, .{
        .decision = .approved,
        .approver = approved.value.approver,
        .reference = approved.value.reference,
        .recorded_unix = approved.value.recorded_unix,
        .expires_unix = approved.value.expires_unix,
        .now = approved.value.recorded_unix,
    });
    try reauthorized.validate(rehashed, &changed_sha);
    try t.expectError(error.CandidatePlanMismatch, admission.Test.planBinding(a, plan.value, rehashed));
}

test "admission real run refuses denial pending expiry and exact mismatches before missing opaque owner" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const plan_bytes = try golden(alloc, "plan");
    const plan = try records.parse(types.Plan, alloc, plan_bytes);
    const parsed = try records.parse(types.Authorization, alloc, try golden(alloc, "authorization_approved"));
    const now: u64 = @intCast(std.Io.Clock.real.now(io).toSeconds());
    var decision = parsed.value;
    decision.recorded_unix = now - 1;
    decision.expires_unix = now + 3599;
    try fixture.write("plan.json", plan_bytes);
    const output = try fixture.join(alloc, "admission.json");
    const plan_path = try fixture.join(alloc, "plan.json");
    for (0..6) |case| {
        var changed = decision;
        if (case == 0) changed.decision = .denied;
        if (case == 1) {
            changed.recorded_unix = now - 3600;
            changed.expires_unix = now;
        }

        if (case == 2) changed.candidate_sha256 = "f" ** 64;
        if (case == 5) {
            const replacement = try alloc.alloc(u8, decision.reference.len);
            @memset(replacement, 'x');
            changed.reference = replacement;
        }
        var bytes = try canonical(alloc, changed);
        if (case == 3) bytes = try std.mem.replaceOwned(u8, alloc, bytes, "\"decision\":\"approved\"", "\"decision\":\"pending\"");
        const name = try std.fmt.allocPrint(alloc, "authorization-{d}.json", .{case});
        try fixture.write(name, bytes);
        const authorization_path = try fixture.join(alloc, name);
        const plan_digest = std.fmt.bytesToHex(tx.hash(plan_bytes), .lower);
        const committed_authorization_bytes = if (case == 5) try canonical(alloc, decision) else bytes;
        const authorization_digest = std.fmt.bytesToHex(tx.hash(committed_authorization_bytes), .lower);
        const result = admission.run(.{
            .base = ctx,
            .candidate = null,
            .plan_commitment = .{ .path = plan_path, .size = plan_bytes.len, .sha256 = &plan_digest },
            .authorization_commitment = .{ .path = authorization_path, .size = committed_authorization_bytes.len, .sha256 = &authorization_digest },
        }, .{
            .plan = plan_path,
            .authorization = authorization_path,
            .output = output,
            .tools = paths(plan.value),
        });
        const failure = result.refused;
        try t.expectEqual(switch (case) {
            0 => error.NotAuthorized,
            1 => error.ApprovalExpired,
            2 => error.InvalidAuthorization,
            3 => error.InvalidEnumTag,
            5 => error.ArtifactBindingMismatch,
            else => error.MissingCandidateOwner,
        }, failure.err);
        try t.expectEqual(core.private_files.CommitStatus.not_committed, failure.publication);
        try fixture.missing("admission.json");
        try fixture.missing("admission.json.validation.json");
    }
}

test "admission candidate remains no authority with all six flags false and both times zero" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const plan = try records.parse(types.Plan, alloc, try golden(alloc, "plan"));
    var candidate: types.compute.CandidateScope = undefined;
    inline for (std.meta.fields(types.compute.CandidateScope)) |field| {
        if (comptime !std.mem.eql(u8, field.name, "schema") and !std.mem.eql(u8, field.name, "version") and !std.mem.eql(u8, field.name, "purpose") and !std.mem.eql(u8, field.name, "authority") and !std.mem.eql(u8, field.name, "approval"))
            @field(candidate, field.name) = @field(plan.value, field.name);
    }
    candidate.schema = "uk.wamr.direct-compute";
    candidate.version = 2;
    candidate.purpose = .@"qcow2-derived-vhd";
    candidate.authority = .not_admitted;
    candidate.approval = .{
        .direct_specialized_gen2 = false,
        .os_only_private = false,
        .two_boots_only = false,
        .cleanup_owned_group = false,
        .exact_image_and_local_bundle_reviewed = false,
        .fresh_final_approval = false,
        .approved_unix = 0,
        .expires_unix = 0,
    };
    try admission.Test.candidateBytes(a, try canonical(alloc, candidate));
    inline for (std.meta.fields(@TypeOf(candidate.approval))) |field| {
        var changed = candidate;
        @field(changed.approval, field.name) = if (field.type == bool) true else 1;
        try t.expectError(error.AuthorityNotAllowed, admission.Test.candidateBytes(a, try canonical(alloc, changed)));
    }
}

fn canonical(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    const bytes = try std.json.Stringify.valueAlloc(allocator, value, .{});
    var document = try core.contracts.Document.parse(allocator, bytes, @import("contracts.zig").json_limits);
    defer document.deinit();
    return document.canonicalAlloc(allocator);
}

test "admission requires real Finalized construction and an unpublished imported product never supplies it" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const output = try fixture.join(a, "candidate.json");
    defer a.free(output);
    const validation = try fixture.join(a, "validation");
    defer a.free(validation);
    // Deliberately empty, not a fabricated successful ImportedProduct/Finalized.
    const product = try a.create(handoff.public_products.ImportedProduct);
    product.* = .{ .allocator = a, .io = io, .arena = std.heap.ArenaAllocator.init(a) };
    defer product.deinit();
    const result = handoff.candidate.create(.{
        .allocator = a,
        .io = io,
        .source = .{ .imported_product = product },
        .output = output,
        .validation_output = validation,
    });
    try t.expectEqual(error.ImportNotPublished, result.refused.err);
    try fixture.missing("candidate.json");
    try fixture.missing("validation");
}

const Late = struct {
    fresh: admission.Test.FinalFreshness,
    transaction: *tx.Transaction,
    after_publication: bool,
    fn check(raw: *anyopaque) !void {
        const self: *Late = @ptrCast(@alignCast(raw));
        if (!self.after_publication or (self.transaction.publication == .durable and self.transaction.published != null))
            self.fresh.clock.seconds = self.fresh.decision.expires_unix;
        try self.fresh.revalidate();
    }
    fn barrier(self: *Late) tx.Barrier {
        return .{ .context = self, .check = check };
    }
};

test "admission final retained barrier has exclusive expiry before write and poisons a late durable output" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const parsed = try records.parse(types.Authorization, alloc, try golden(alloc, "authorization_approved"));
    for ([_]bool{ false, true }) |after_publication| {
        const fixture = try Fixture.init();
        defer fixture.deinit();
        const output = try fixture.join(alloc, "admission.json");
        var transaction = try tx.Transaction.init(ctx, output);
        defer transaction.deinit();
        var late: Late = .{
            .fresh = .{ .ctx = ctx, .inputs = &.{}, .decision = parsed.value, .clock = .{ .seconds = parsed.value.recorded_unix } },
            .transaction = &transaction,
            .after_publication = after_publication,
        };
        const result = transaction.publish(try golden(alloc, "admission"), late.barrier());
        if (!after_publication) {
            try t.expectEqual(error.ApprovalExpired, result.refused.err);
            try t.expectEqual(core.private_files.CommitStatus.not_committed, result.refused.publication);
            try fixture.missing("admission.json");
        } else {
            try t.expectEqual(error.ApprovalExpired, result.poisoned.err);
            try t.expectEqual(core.private_files.CommitStatus.durable, result.poisoned.publication);
            try transaction.published.?.revalidate(null);
        }
    }
}

test "admission retained final barrier refuses same-byte input replacement" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const decision = try records.parse(types.Authorization, alloc, try golden(alloc, "authorization_approved"));
    const fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.write("authorization.json", try golden(alloc, "authorization_approved"));
    const input = try fixture.join(alloc, "authorization.json");
    var retained = try tx.Record.open(ctx, input, 65536);
    defer retained.deinit();
    var fresh: admission.Test.FinalFreshness = .{
        .ctx = ctx,
        .inputs = &.{&retained},
        .decision = decision.value,
        .clock = .{ .seconds = decision.value.recorded_unix },
    };
    try fresh.revalidate();
    try fixture.root.rename("authorization.json", fixture.root, "original.json", io);
    try fixture.write("authorization.json", try golden(alloc, "authorization_approved"));
    try t.expectError(error.FileChanged, fresh.revalidate());
    try fixture.root.deleteFile(io, "authorization.json");
    try fixture.root.rename("original.json", fixture.root, "authorization.json", io);
    try t.expectError(error.FileChanged, fresh.revalidate());
}

test "admission retained tool custody rejects links and renamed ancestors" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const tool_path = try fixture.join(a, "tool");
    defer a.free(tool_path);
    const file = try fixture.root.createFile(io, "tool", .{ .exclusive = true, .permissions = .fromMode(0o700) });
    defer file.close(io);
    try file.writePositionalAll(io, "synthetic retained executable", 0);
    try file.sync(io);
    const digest = std.fmt.bytesToHex(tx.hash("synthetic retained executable"), .lower);
    const bound: types.Artifact = .{ .path = tool_path, .size = "synthetic retained executable".len, .sha256 = &digest };
    var held = try admission.Test.RetainedArtifact.open(ctx, bound, .tool, 65536);
    defer held.file.close(io);
    try held.revalidate(ctx);
    try fixture.root.symLink(io, "tool", "symlink", .{});
    const link = try fixture.join(a, "symlink");
    defer a.free(link);
    var changed = bound;
    changed.path = link;
    try t.expectError(error.UnsafeFile, admission.Test.RetainedArtifact.open(ctx, changed, .tool, 65536));
    const tool_z = try a.dupeZ(u8, tool_path);
    defer a.free(tool_z);
    const hardlink = try fixture.join(a, "hardlink");
    defer a.free(hardlink);
    const hardlink_z = try a.dupeZ(u8, hardlink);
    defer a.free(hardlink_z);
    if (std.os.linux.errno(std.os.linux.linkat(std.os.linux.AT.FDCWD, tool_z, std.os.linux.AT.FDCWD, hardlink_z, 0)) != .SUCCESS) return error.FixtureLink;
    try t.expectError(error.FileChanged, held.revalidate(ctx));
    changed.path = hardlink;
    try t.expectError(error.UnsafeFile, admission.Test.RetainedArtifact.open(ctx, changed, .tool, 65536));
    try fixture.root.deleteFile(io, "hardlink");
    var fresh = try admission.Test.RetainedArtifact.open(ctx, bound, .tool, 65536);
    defer fresh.file.close(io);
    var renamed: [33]u8 = undefined;
    @memcpy(renamed[0..32], &fixture.name);
    renamed[32] = 'x';
    try fixture.parent.rename(&fixture.name, fixture.parent, &renamed, io);
    defer fixture.parent.deleteTree(io, &renamed) catch @panic("renamed admission tool cleanup failed");
    try fixture.parent.createDir(io, &fixture.name, .fromMode(0o700));
    try t.expectError(error.FileChanged, fresh.revalidate(ctx));
}

fn shortWrite(userdata: ?*anyopaque, file: std.Io.File, _: []const u8, data: []const []const u8, _: usize, offset: u64) std.Io.File.WritePositionalError!usize {
    return io.vtable.fileWritePositional(userdata, file, &.{}, &.{data[0][0..@min(7, data[0].len)]}, 1, offset);
}
fn failedShortWrite(userdata: ?*anyopaque, file: std.Io.File, _: []const u8, data: []const []const u8, _: usize, offset: u64) std.Io.File.WritePositionalError!usize {
    if (offset != 0) return error.InputOutput;
    return io.vtable.fileWritePositional(userdata, file, &.{}, &.{data[0][0..@min(7, data[0].len)]}, 1, offset);
}
fn noFileSync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
    if ((file.stat(io) catch return error.InputOutput).kind == .file) return error.InputOutput;
    return io.vtable.fileSync(userdata, file);
}
fn noDirSync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
    if ((file.stat(io) catch return error.InputOutput).kind == .directory) return error.InputOutput;
    return io.vtable.fileSync(userdata, file);
}

test "admission writer handles real short writes and refuses interrupted short writes and actual fsync failures" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const decision = try records.parse(types.Authorization, alloc, try golden(alloc, "authorization_approved"));
    for (0..4) |case| {
        const fixture = try Fixture.init();
        defer fixture.deinit();
        var table = io.vtable.*;
        const injected: std.Io = .{ .userdata = io.userdata, .vtable = &table };
        var transaction = try tx.Transaction.init(.{ .allocator = a, .io = injected }, try fixture.join(alloc, "admission.json"));
        defer transaction.deinit();
        switch (case) {
            0 => table.fileWritePositional = shortWrite,
            1 => table.fileWritePositional = failedShortWrite,
            2 => table.fileSync = noFileSync,
            3 => table.fileSync = noDirSync,
            else => unreachable,
        }
        var fresh: admission.Test.FinalFreshness = .{ .ctx = ctx, .inputs = &.{}, .decision = decision.value, .clock = .{ .seconds = decision.value.recorded_unix } };
        const result = transaction.publish(try golden(alloc, "admission"), fresh.barrier());
        if (case == 0) {
            try t.expect(result == .success);
            var bytes = try transaction.published.?.read(a, null);
            defer bytes.deinit();
            try t.expectEqualStrings(try golden(alloc, "admission"), bytes.bytes());
        } else {
            try t.expectEqual(error.InputOutput, result.poisoned.err);
            try t.expect(result.poisoned.failures.recording != null);
            try t.expectEqual(core.diagnostics.Stage.state_record, result.poisoned.failures.recording.?.stage);
            try t.expectEqual(core.diagnostics.Category.local_io, result.poisoned.failures.recording.?.category);
            try t.expect(result.poisoned.failures.primary == null);
            try t.expect(result.poisoned.failures.cleanup == null);
            try t.expectEqual(if (case == 3) core.private_files.CommitStatus.visible_not_durable else core.private_files.CommitStatus.not_committed, result.poisoned.publication);
            if (case == 3) {
                const visible = try fixture.root.readFileAlloc(io, "admission.json", alloc, .limited(65536));
                try t.expectEqualStrings(try golden(alloc, "admission"), visible);
            } else try fixture.missing("admission.json");
        }
    }
}

test "admission publication collisions fsync cleanup and cancellation never become success" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const decision = try records.parse(types.Authorization, alloc, try golden(alloc, "authorization_approved"));
    for (std.enums.values(core.private_files.TestFault)) |fault| {
        const fixture = try Fixture.init();
        defer fixture.deinit();
        var named_vtable = io.vtable.*;
        named_vtable.dirCreateFileAtomic = @import("test_fixtures.zig").namedAtomic;
        var fault_ctx = ctx;
        if (fault == .cleanup) fault_ctx.io = .{ .userdata = io.userdata, .vtable = &named_vtable };
        var fresh: admission.Test.FinalFreshness = .{ .ctx = fault_ctx, .inputs = &.{}, .decision = decision.value, .clock = .{ .seconds = decision.value.recorded_unix } };
        var transaction = try tx.Transaction.init(fault_ctx, try fixture.join(alloc, "admission.json"));
        defer transaction.deinit();
        const failed = transaction.publishFault(try golden(alloc, "admission"), fresh.barrier(), fault).poisoned;
        try t.expectEqual(error.PublicationUncertain, failed.err);
        try t.expect(failed.failures.recording != null);
        try t.expectEqual(fault == .cleanup, failed.failures.cleanup != null);
        if (fault == .after_rename) {
            try t.expectEqual(core.private_files.CommitStatus.visible_not_durable, failed.publication);
            try t.expectError(error.PathAlreadyExists, tx.Transaction.init(ctx, transaction.path));
        }
        const primary: core.diagnostics.Failures = .{ .primary = .{ .stage = .process_run, .category = .child_failed } };
        try t.expectEqualDeep(primary.primary, tx.combineFailures(primary, failed.failures).primary);
    }
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const output = try fixture.join(alloc, "admission.json");
    try fixture.write("admission.json", "existing\n");
    try t.expectError(error.PathAlreadyExists, tx.Transaction.init(ctx, output));
    var signal = try core.process.SignalCancellation.install();
    defer signal.deinit();
    const cancelled: types.Context = .{ .allocator = a, .io = io, .signal = &signal };
    var transaction = try tx.Transaction.init(cancelled, try fixture.join(alloc, "cancelled.json"));
    defer transaction.deinit();
    var fresh: admission.Test.FinalFreshness = .{ .ctx = cancelled, .inputs = &.{}, .decision = decision.value, .clock = .{ .seconds = decision.value.recorded_unix } };
    if (std.os.linux.errno(std.os.linux.kill(std.os.linux.getpid(), .INT)) != .SUCCESS) return error.FixtureSignal;
    try t.expectEqual(error.Cancelled, transaction.publish(try golden(alloc, "admission"), fresh.barrier()).refused.err);
    try fixture.missing("cancelled.json");
}

test "admission preserves existing ledger old-marker missing-sentinel verifier refusal without initializing it" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const campaign = "11111111-1111-1111-1111-111111111111";
    const ledger = "22222222-2222-2222-2222-222222222222";
    const marker = try types.compute.ledgerMarkerBytes(a, campaign, ledger, "a" ** 64);
    defer a.free(marker);
    try fixture.write(types.compute.ledger_marker_name, marker);
    try t.expectError(error.FileNotFound, types.compute.ledgerProposal(a, io, fixture.path, campaign, ledger));
    try fixture.missing(types.compute.ledger_sentinel_name);
}
