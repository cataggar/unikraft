// SPDX-License-Identifier: BSD-3-Clause
//! Source-only admission. The caller retains the genuine imported Finalized
//! owner in this process; standalone receipts cannot supply that context.
//! Independently acquired plan/decision commitments are explicit caller inputs,
//! not digests inferred from the selected paths. This is not approval acquisition.
//! The create-only OUTPUT.validation.json is privately verified before OUTPUT;
//! neither failed staging nor uncertain final publication is removed or resumed.
//! No ledger initialization, claim, approval consumption or Azure execution.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const handoff = @import("wamr_handoff");
const types = @import("types.zig");
const records = @import("records.zig");
const tx = @import("transaction.zig");
const compute = types.compute;
const files = core.private_files;
const copy = handoff.retained_copy;
const json_limit = 65536;

pub const AdmitCommand = types.AdmitCommand;
pub const Context = struct {
    base: types.Context,
    /// Borrowed until Admitted.deinit; null is an explicit missing-context refusal.
    candidate: ?*handoff.candidate.Finalized,
    plan_commitment: types.Artifact,
    authorization_commitment: types.Artifact,
};
pub const Diagnostic = struct {
    phase: types.Phase,
    err: anyerror,
    publication: files.CommitStatus = .not_committed,
    validation_publication: files.CommitStatus = .not_committed,
    failures: core.diagnostics.Failures = .{},
};
pub const Outcome = union(enum) { success: *Admitted, refused: Diagnostic, poisoned: Diagnostic };

pub const Admitted = opaque {
    fn state(self: *Admitted) *State {
        return @ptrCast(@alignCast(self));
    }
    pub fn revalidate(self: *Admitted) !void {
        const owner = self.state();
        try owner.output.?.revalidate(owner.barrier());
        try compute.verifyAdmission(owner.ctx.base.allocator, owner.ctx.base.io, owner.command.output, false);
        try owner.output.?.revalidate(owner.barrier());
    }
    pub fn artifact(self: *Admitted) !types.Artifact {
        try self.revalidate();
        return self.state().output.?.published.?.artifact();
    }
    /// Closes descriptors but deliberately preserves staged and final evidence.
    pub fn deinit(self: *Admitted) void {
        self.state().deinit();
    }
};

const HeldArtifact = struct {
    file: files.RetainedFile,
    sha256: [64]u8,
    limit: u64,
    pub fn open(ctx: types.Context, item: types.Artifact, policy: files.FilePolicy, limit: u64) !HeldArtifact {
        var file = try files.RetainedFile.open(ctx.io, item.path, policy);
        errdefer file.close(ctx.io);
        const digest = try copy.hashRetained(ctx.io, &file, limit, cancel(ctx));
        if (file.file_snapshot.size != item.size or !std.mem.eql(u8, &digest, item.sha256))
            return error.ArtifactBindingMismatch;
        return .{ .file = file, .sha256 = digest, .limit = limit };
    }
    pub fn revalidate(self: *HeldArtifact, ctx: types.Context) !void {
        const digest = try copy.hashRetained(ctx.io, &self.file, self.limit, cancel(ctx));
        if (!std.mem.eql(u8, &digest, &self.sha256)) return error.ArtifactBindingMismatch;
    }
};

const Clock = if (builtin.is_test) struct {
    seconds: ?u64 = null,
    fn now(self: @This(), io: std.Io) !u64 {
        return self.seconds orelse try realNow(io);
    }
} else struct {
    fn now(_: @This(), io: std.Io) !u64 {
        return realNow(io);
    }
};
fn realNow(io: std.Io) !u64 {
    const now = std.Io.Clock.real.now(io).toSeconds();
    return std.math.cast(u64, now) orelse error.InvalidClock;
}
fn cancel(ctx: types.Context) ?*const std.atomic.Value(bool) {
    return if (ctx.signal) |signal| signal.flag() else null;
}

/// The same last, cheap retained-input/time barrier is used after the slow
/// native validators, immediately before immutable publication, and afterward.
const Freshness = struct {
    ctx: types.Context,
    inputs: []const *tx.Record,
    decision: types.Authorization,
    clock: Clock = .{},
    pub fn revalidate(self: *Freshness) !void {
        for (self.inputs) |input| try input.revalidate(self.ctx.signal);
        try copy.checkCancellation(cancel(self.ctx));
        try self.decision.current(try self.clock.now(self.ctx.io));
    }
    fn check(raw: *anyopaque) !void {
        const self: *Freshness = @ptrCast(@alignCast(raw));
        try self.revalidate();
    }
    pub fn barrier(self: *Freshness) tx.Barrier {
        return .{ .context = self, .check = check };
    }
};

const State = struct {
    ctx: Context,
    command: AdmitCommand,
    arena: std.heap.ArenaAllocator,
    plan_record: ?tx.Record = null,
    authorization_record: ?tx.Record = null,
    runtime_record: ?tx.Record = null,
    candidate_record: ?tx.Record = null,
    staged: ?tx.Record = null,
    runtime_members: std.ArrayList(HeldArtifact) = .empty,
    tools: std.ArrayList(HeldArtifact) = .empty,
    plan: types.Plan = undefined,
    authorization: types.Authorization = undefined,
    output: ?tx.Transaction = null,
    phase: types.Phase = .inputs,
    stage_publication: files.CommitStatus = .not_committed,
    stage_failures: core.diagnostics.Failures = .{},
    reserved: bool = false,

    fn barrier(self: *State) tx.Barrier {
        return .{ .context = self, .check = check };
    }
    fn check(raw: *anyopaque) !void {
        const self: *State = @ptrCast(@alignCast(raw));
        try self.revalidate();
    }
    fn revalidate(self: *State) !void {
        const ctx = self.ctx.base;
        try copy.checkCancellation(cancel(ctx));
        const candidate = self.ctx.candidate orelse return error.MissingCandidateOwner;
        try checkOwner(ctx, candidate, self.plan);
        try compute.verifyAuthorization(ctx.allocator, ctx.io, self.command.plan, self.command.authorization, false);
        if (self.staged) |*stage| try stage.revalidate(ctx.signal);
        try candidate.revalidate(ctx.signal);
        for (self.runtime_members.items) |*member| try member.revalidate(ctx);
        for (self.tools.items) |*tool| try tool.revalidate(ctx);
        var fresh: Freshness = .{
            .ctx = ctx,
            .inputs = &.{ &self.plan_record.?, &self.authorization_record.?, &self.runtime_record.?, &self.candidate_record.? },
            .decision = self.authorization,
        };
        try fresh.revalidate();
    }
    fn diagnostic(self: *State, err: anyerror) Diagnostic {
        return .{
            .phase = self.phase,
            .err = err,
            .publication = if (self.output) |*output| output.publication else .not_committed,
            .validation_publication = self.stage_publication,
            .failures = if (self.output) |*output| tx.combineFailures(self.stage_failures, output.failures) else self.stage_failures,
        };
    }
    fn deinit(self: *State) void {
        const ctx = self.ctx.base;
        if (self.output) |*output| output.deinit();
        if (self.staged) |*stage| stage.deinit();
        for (self.tools.items) |*tool| tool.file.close(ctx.io);
        self.tools.deinit(ctx.allocator);
        for (self.runtime_members.items) |*member| member.file.close(ctx.io);
        self.runtime_members.deinit(ctx.allocator);
        if (self.candidate_record) |*record| record.deinit();
        if (self.runtime_record) |*record| record.deinit();
        if (self.authorization_record) |*record| record.deinit();
        if (self.plan_record) |*record| record.deinit();
        self.arena.deinit();
        ctx.allocator.destroy(self);
    }
};

pub fn run(ctx: Context, command: AdmitCommand) Outcome {
    const owner = ctx.base.allocator.create(State) catch |err|
        return .{ .refused = .{ .phase = .inputs, .err = err } };
    owner.* = .{ .ctx = ctx, .command = command, .arena = std.heap.ArenaAllocator.init(ctx.base.allocator) };
    finish(owner) catch |err| {
        const diagnostic = owner.diagnostic(err);
        const poisoned = owner.reserved;
        owner.deinit();
        return if (poisoned) .{ .poisoned = diagnostic } else .{ .refused = diagnostic };
    };
    return .{ .success = @ptrCast(owner) };
}

fn finish(owner: *State) !void {
    const ctx = owner.ctx.base;
    const a = owner.arena.allocator();
    try copy.checkCancellation(cancel(ctx));
    owner.command = try ownCommand(a, owner.command);
    owner.ctx.plan_commitment = try ownArtifact(a, owner.ctx.plan_commitment);
    owner.ctx.authorization_commitment = try ownArtifact(a, owner.ctx.authorization_commitment);
    try files.absoluteFilePath(owner.command.plan);
    try files.absoluteFilePath(owner.command.authorization);
    try files.absoluteFilePath(owner.command.output);
    const stage_path = try std.fmt.allocPrint(a, "{s}.validation.json", .{owner.command.output});
    try files.absoluteFilePath(stage_path);
    owner.plan_record = try tx.Record.open(ctx, owner.command.plan, json_limit);
    owner.authorization_record = try tx.Record.open(ctx, owner.command.authorization, json_limit);
    try exactArtifact(owner.plan_record.?.artifact(), owner.ctx.plan_commitment);
    try exactArtifact(owner.authorization_record.?.artifact(), owner.ctx.authorization_commitment);
    var plan_bytes = try owner.plan_record.?.read(a, ctx.signal);
    defer plan_bytes.deinit();
    var authorization_bytes = try owner.authorization_record.?.read(a, ctx.signal);
    defer authorization_bytes.deinit();
    const plan = try records.parse(types.Plan, a, plan_bytes.bytes());
    owner.plan = plan.value;
    const authorization = try records.parse(types.Authorization, a, authorization_bytes.bytes());
    owner.authorization = authorization.value;
    try owner.plan.validate();
    try owner.authorization.validate(owner.plan, &owner.plan_record.?.sha256);
    try owner.authorization.current(try realNow(ctx.io));
    try toolPaths(owner.plan, owner.command.tools);
    owner.phase = .custody;
    const candidate = owner.ctx.candidate orelse return error.MissingCandidateOwner;
    try checkOwner(ctx, candidate, owner.plan);
    const metadata = try candidate.metadata(ctx.signal);
    if (!std.meta.eql(ctx.io, metadata.reader.io)) return error.ReaderContextMismatch;
    try outputPath(owner.command.output, owner.plan, metadata.reader);
    owner.runtime_record = try tx.Record.open(ctx, owner.command.tools.azure_runtime, json_limit);
    try exactArtifact(owner.runtime_record.?.artifact(), owner.plan.azure_runtime_document);
    var runtime_bytes = try owner.runtime_record.?.read(a, ctx.signal);
    defer runtime_bytes.deinit();
    const runtime = try records.parse(types.runtime.Contract, a, runtime_bytes.bytes());
    if (!types.runtime.equal(runtime.value, owner.plan.azure_runtime)) return error.WrongAzureRuntime;
    owner.candidate_record = try tx.Record.open(ctx, owner.plan.candidate.path, json_limit);
    try exactArtifact(owner.candidate_record.?.artifact(), owner.plan.candidate);
    var candidate_bytes = try owner.candidate_record.?.read(a, ctx.signal);
    defer candidate_bytes.deinit();
    try validateCandidateBytes(a, candidate_bytes.bytes());
    inline for (std.meta.fields(compute.Tools)) |field| {
        var tool = try HeldArtifact.open(ctx, @field(owner.plan.tools, field.name), .tool, types.runtime.max_file_bytes);
        errdefer tool.file.close(ctx.io);
        try owner.tools.append(ctx.allocator, tool);
    }
    try retainRuntime(owner, runtime.value.manifest, types.runtime.max_manifest_bytes);
    try retainRuntime(owner, runtime.value.launcher, types.runtime.max_file_bytes);
    try retainRuntime(owner, runtime.value.interpreter, types.runtime.max_file_bytes);
    for (runtime.value.loader_dependencies) |dependency|
        try retainRuntime(owner, dependency, types.runtime.max_file_bytes);
    owner.phase = .validation;
    try owner.revalidate();
    owner.phase = .construction;
    const value = try records.admission(owner.plan, owner.plan_record.?.artifact(), owner.authorization, owner.authorization_record.?.artifact(), try realNow(ctx.io));
    const bytes = try records.admissionBytes(a, value, try realNow(ctx.io));
    owner.output = try tx.Transaction.init(ctx, owner.command.output);
    // Use the existing lock/parent rather than taking a second lock on it.
    owner.phase = .freshness;
    try owner.output.?.revalidate(owner.barrier());
    owner.phase = .validation;
    owner.reserved = true;
    const committed = try owner.output.?.lock.createImmutable(ctx.io, std.fs.path.basename(stage_path), bytes);
    owner.stage_publication = committed.status;
    owner.stage_failures = committed.failures;
    if (committed.status != .durable or committed.failures.primary != null or committed.failures.cleanup != null or committed.failures.recording != null)
        return error.ValidationPublicationUncertain;
    owner.staged = try tx.Record.open(ctx, stage_path, json_limit);
    const digest = std.fmt.bytesToHex(tx.hash(bytes), .lower);
    if (owner.staged.?.artifact().size != bytes.len or !std.mem.eql(u8, &digest, &owner.staged.?.sha256))
        return error.RecordChanged;
    try compute.verifyAdmission(ctx.allocator, ctx.io, stage_path, false);
    owner.phase = .freshness;
    try owner.revalidate();
    owner.phase = .publication;
    switch (owner.output.?.publish(bytes, owner.barrier())) {
        .success => {},
        .refused, .poisoned => |failure| {
            owner.phase = failure.phase;
            return failure.err;
        },
    }
    owner.phase = .final_revalidation;
    try compute.verifyAdmission(ctx.allocator, ctx.io, owner.command.output, false);
    try owner.output.?.revalidate(owner.barrier());
}

fn retainRuntime(owner: *State, item: types.runtime.Artifact, limit: u64) !void {
    var record = try HeldArtifact.open(owner.ctx.base, .{ .path = item.path, .size = item.size, .sha256 = item.sha256 }, .artifact, limit);
    errdefer record.file.close(owner.ctx.base.io);
    try owner.runtime_members.append(owner.ctx.base.allocator, record);
}
fn exactArtifact(actual: types.Artifact, expected: types.Artifact) !void {
    if (!std.mem.eql(u8, actual.path, expected.path) or actual.size != expected.size or !std.mem.eql(u8, actual.sha256, expected.sha256))
        return error.ArtifactBindingMismatch;
}
fn validateCandidateBytes(a: std.mem.Allocator, bytes: []const u8) !void {
    var document = try handoff.contracts.parseCanonical(a, bytes);
    defer document.deinit();
    _ = try handoff.contracts.validateDirectComputeCandidate(document.value());
}
fn toolPaths(plan: types.Plan, paths: types.ToolPaths) !void {
    inline for (std.meta.fields(compute.Tools)) |field| {
        const path = @field(paths, field.name);
        try files.absoluteFilePath(path);
        if (!std.mem.eql(u8, path, @field(plan.tools, field.name).path)) return error.ToolBindingMismatch;
    }
    try files.absoluteFilePath(paths.azure_runtime);
    if (!std.mem.eql(u8, paths.azure_runtime, plan.azure_runtime_document.path)) return error.ToolBindingMismatch;
}
fn checkOwner(ctx: types.Context, candidate: *handoff.candidate.Finalized, plan: types.Plan) !void {
    const reconstructed = try records.plan(.{
        .candidate = candidate,
        .created_unix = plan.created_unix,
        .campaign_id = plan.campaign_id,
        .ledger_path = plan.ledger_path,
        .ledger = plan.ledger,
        .maximum_authorized_cost_microusd = plan.cost.maximum_authorized,
        .tools = plan.tools,
        .azure_runtime_document = plan.azure_runtime_document,
        .azure_runtime = plan.azure_runtime,
    }, ctx.signal);
    try exactPlan(ctx.allocator, plan, reconstructed);
}
fn exactPlan(a: std.mem.Allocator, expected: types.Plan, actual: types.Plan) !void {
    const expected_bytes = try records.planBytes(a, expected);
    defer a.free(expected_bytes);
    const actual_bytes = try records.planBytes(a, actual);
    defer a.free(actual_bytes);
    if (!std.mem.eql(u8, expected_bytes, actual_bytes)) return error.CandidatePlanMismatch;
}
fn inside(path: []const u8, root: []const u8) bool {
    return std.mem.eql(u8, path, root) or (std.mem.startsWith(u8, path, root) and path.len > root.len and path[root.len] == '/');
}
fn outputPath(path: []const u8, plan: types.Plan, reader: handoff.candidate.ReaderContext) !void {
    for ([_][]const u8{ plan.azure_runtime.root, reader.repository, reader.validation_output, std.fs.path.dirname(plan.public_bundle.path).? }) |root|
        if (inside(path, root)) return error.AliasedOutput;
}
fn ownCommand(a: std.mem.Allocator, command: AdmitCommand) !AdmitCommand {
    var result = command;
    result.plan = try a.dupe(u8, command.plan);
    result.authorization = try a.dupe(u8, command.authorization);
    result.output = try a.dupe(u8, command.output);
    inline for (std.meta.fields(types.ToolPaths)) |field|
        @field(result.tools, field.name) = try a.dupe(u8, @field(command.tools, field.name));
    return result;
}
fn ownArtifact(a: std.mem.Allocator, value: types.Artifact) !types.Artifact {
    return .{ .path = try a.dupe(u8, value.path), .size = value.size, .sha256 = try a.dupe(u8, value.sha256) };
}

/// Narrow native fixtures, not a replacement owner or a production clock seam.
pub const Test = if (builtin.is_test) struct {
    pub const FinalFreshness = Freshness;
    pub const RetainedArtifact = HeldArtifact;
    pub fn paths(plan: types.Plan, supplied: types.ToolPaths) !void {
        try toolPaths(plan, supplied);
    }
    pub fn planBinding(a: std.mem.Allocator, expected: types.Plan, actual: types.Plan) !void {
        try exactPlan(a, expected, actual);
    }
    pub fn candidateBytes(a: std.mem.Allocator, bytes: []const u8) !void {
        try validateCandidateBytes(a, bytes);
    }
} else struct {};
