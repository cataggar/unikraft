// SPDX-License-Identifier: BSD-3-Clause
//! Source-only authorization recording. The existing compute engines validate
//! seeded inputs in-process; tool paths are bindings, not executable discovery
//! or proof of a current reader. No approvals are consumed or cloud calls made.
const std = @import("std");
const core = @import("hyperv_core");
const types = @import("types.zig");
const contracts = @import("contracts.zig");
const records = @import("records.zig");
const tx = @import("transaction.zig");
const copy = @import("wamr_handoff").retained_copy;
const files = core.private_files;
const compute = types.compute;
const log = std.log.scoped(.authority_authorization);
const record_limit = 64 * 1024;
pub const Context = types.Context;
pub const Command = types.AuthorizationCommand;

/// Heap-stable, retained context. All command strings and parsed values are
/// owned. Context.io and Context.signal remain borrowed for this owner's life.
/// The private validation record and any uncertain outputs stay on disk.
pub const Recorded = struct {
    ctx: types.Context,
    sensitive: core.sensitive.Allocator,
    arena: std.heap.ArenaAllocator,
    command: types.AuthorizationCommand = .{},
    plan: ?types.Plan = null,
    template: ?types.ApprovalTemplate = null,
    plan_document: ?std.json.Parsed(types.Plan) = null,
    template_document: ?std.json.Parsed(types.ApprovalTemplate) = null,
    decision: ?types.Authorization = null,
    plan_record: ?tx.Record = null,
    template_record: ?tx.Record = null,
    runtime_record: ?tx.Record = null,
    bound: std.ArrayList(Bound) = .empty,
    transaction: ?tx.Transaction = null,
    private_record: ?tx.Record = null,
    private_status: files.CommitStatus = .not_committed,
    phase: types.Phase = .inputs,
    hooks: ?*Test.Hooks = null,

    pub fn value(self: *const Recorded) types.Authorization {
        return self.decision.?;
    }
    pub fn artifact(self: *const Recorded) types.Artifact {
        return self.transaction.?.published.?.artifact();
    }
    pub fn revalidate(self: *Recorded) !void {
        try self.transaction.?.revalidate(self.barrier());
        try self.current();
        try copy.checkCancellation(if (self.ctx.signal) |s| s.flag() else null);
    }
    pub fn deinit(self: *Recorded) void {
        const backing = self.ctx.allocator;
        if (self.transaction) |*transaction| transaction.deinit();
        if (self.private_record) |*record| record.deinit();
        for (self.bound.items) |*item| item.file.close(self.ctx.io);
        if (self.runtime_record) |*record| record.deinit();
        if (self.template_record) |*record| record.deinit();
        if (self.plan_record) |*record| record.deinit();
        if (self.template_document) |document| document.deinit();
        if (self.plan_document) |document| document.deinit();
        self.arena.deinit();
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        backing.destroy(self);
    }
    fn allocator(self: *Recorded) std.mem.Allocator {
        return self.arena.allocator();
    }
    fn initialize(ctx: types.Context, command: types.AuthorizationCommand) !*Recorded {
        const self = try ctx.allocator.create(Recorded);
        self.* = .{
            .ctx = ctx,
            .sensitive = .{ .backing = ctx.allocator },
            .arena = undefined,
        };
        self.arena = .init(self.sensitive.allocator());
        errdefer self.deinit();
        self.command = command;
        inline for (.{ "plan", "template", "output", "approver", "reference" }) |name|
            @field(self.command, name) = try self.allocator().dupe(u8, @field(command, name));
        inline for (std.meta.fields(types.ToolPaths)) |field|
            @field(self.command.tools, field.name) = try self.allocator().dupe(u8, @field(command.tools, field.name));
        return self;
    }
    fn retain(self: *Recorded, item: types.Artifact, policy: files.FilePolicy) !void {
        for (self.bound.items) |*prior| {
            if (!std.mem.eql(u8, prior.file.path, item.path)) continue;
            if (prior.file.policy != policy or prior.file.file_snapshot.size != item.size or
                !std.mem.eql(u8, &prior.sha256, item.sha256)) return error.ConflictingInputBinding;
            return;
        }
        const path = try self.allocator().dupe(u8, item.path);
        var file = try files.RetainedFile.open(self.ctx.io, path, policy);
        errdefer file.close(self.ctx.io);
        if (file.file_snapshot.size != item.size) return error.ArtifactChanged;
        const digest = try copy.hashRetained(self.ctx.io, &file, item.size, if (self.ctx.signal) |s| s.flag() else null);
        if (!std.mem.eql(u8, &digest, item.sha256)) return error.HashMismatch;
        try self.bound.append(self.allocator(), .{ .file = file, .sha256 = digest });
    }
    fn retainInputs(self: *Recorded) !void {
        const a = self.allocator();
        const context = types.Context{ .allocator = a, .io = self.ctx.io, .signal = self.ctx.signal };
        self.plan_record = try tx.Record.open(context, self.command.plan, record_limit);
        self.template_record = try tx.Record.open(context, self.command.template, record_limit);
        var plan_bytes = try self.plan_record.?.read(a, self.ctx.signal);
        defer plan_bytes.deinit();
        var template_bytes = try self.template_record.?.read(a, self.ctx.signal);
        defer template_bytes.deinit();
        self.plan_document = try parse(types.Plan, a, plan_bytes.bytes());
        self.plan = self.plan_document.?.value;
        try self.plan.?.validate();
        self.template_document = try parse(types.ApprovalTemplate, a, template_bytes.bytes());
        self.template = self.template_document.?.value;
        try self.template.?.validate(self.plan.?, &self.plan_record.?.sha256);
        self.phase = .custody;
        const planned = self.plan.?;
        inline for (std.meta.fields(compute.Tools)) |field| {
            const item = @field(planned.tools, field.name);
            if (!std.mem.eql(u8, item.path, @field(self.command.tools, field.name)))
                return error.WrongToolBinding;
            try self.retain(item, .tool);
        }
        if (!std.mem.eql(u8, self.command.tools.azure_runtime, planned.azure_runtime_document.path))
            return error.WrongAzureRuntime;
        self.runtime_record = try tx.Record.open(context, planned.azure_runtime_document.path, record_limit);
        if (!same(self.runtime_record.?.artifact(), planned.azure_runtime_document)) return error.WrongAzureRuntime;
        var runtime_bytes = try self.runtime_record.?.read(a, self.ctx.signal);
        defer runtime_bytes.deinit();
        const runtime = try parse(types.runtime.Contract, a, runtime_bytes.bytes());
        defer runtime.deinit();
        try runtime.value.validate();
        if (!types.runtime.equal(runtime.value, planned.azure_runtime)) return error.WrongAzureRuntime;

        try self.retain(planned.candidate, .private);
        inline for (.{ "bundle", "public_bundle", "transport", "qcow2", "os_vhd" }) |field|
            try self.retain(@field(planned, field), .artifact);
        for (self.bound.items) |*item| {
            if (!std.mem.eql(u8, item.file.path, planned.candidate.path) and
                !std.mem.eql(u8, item.file.path, planned.bundle.path) and
                !std.mem.eql(u8, item.file.path, planned.transport.path)) continue;
            var bytes = try files.readSensitiveFile(self.ctx.io, a, item.file.file, record_limit, item.file.policy);
            defer bytes.deinit();
            var document = try contracts.parseCanonical(a, bytes.bytes());
            defer document.deinit();
            if (std.mem.eql(u8, item.file.path, planned.candidate.path))
                try strict(compute.CandidateScope, document.value());
        }
        var bundle_bytes = try files.readSensitiveAbsolute(self.ctx.io, a, planned.public_bundle.path, record_limit, null);
        defer bundle_bytes.deinit();
        const bundle = try parse(compute.BundleV2, a, bundle_bytes.bytes());
        defer bundle.deinit();
        for (bundle.value.artifacts) |item| try self.retain(item, .artifact);
        for (bundle.value.evidence) |item| try self.retain(item, .artifact);
        for (bundle.value.boots) |boot|
            inline for (.{ "serial", "request", "report", "compute" }) |field|
                try self.retain(@field(boot, field), .artifact);
        const closure = planned.azure_runtime;
        try self.retain(project(closure.manifest), .artifact);
        for (closure.loader_dependencies) |item| {
            // A loader is explicitly named by the contract, never inferred
            // from its path or executed by the authorization recorder.
            try self.retain(project(item), if (std.mem.eql(u8, item.path, closure.dynamic_loader.path)) .tool else .artifact);
        }
    }
    fn checkInputs(self: *Recorded) !void {
        try copy.checkCancellation(if (self.ctx.signal) |s| s.flag() else null);
        try self.plan_record.?.revalidate(self.ctx.signal);
        try self.template_record.?.revalidate(self.ctx.signal);
        try self.runtime_record.?.revalidate(self.ctx.signal);
        for (self.bound.items) |*item| {
            const digest = try copy.hashRetained(self.ctx.io, &item.file, item.file.file_snapshot.size, if (self.ctx.signal) |s| s.flag() else null);
            if (!std.mem.eql(u8, &digest, &item.sha256)) return error.RecordChanged;
        }
        if (self.private_record) |*record| try record.revalidate(self.ctx.signal);
        if (self.transaction) |*transaction|
            if (transaction.published) |*record| try record.revalidate(self.ctx.signal);
    }
    fn now(self: *Recorded) !u64 {
        if (comptime @import("builtin").is_test)
            if (self.hooks) |hooks|
                if (hooks.now_seconds) |seconds| return seconds;
        const seconds = std.Io.Clock.real.now(self.ctx.io).toSeconds();
        return std.math.cast(u64, seconds) orelse error.InvalidClock;
    }
    fn current(self: *Recorded) !void {
        try records.decisionCurrent(self.decision.?, try self.now());
    }
    fn check(self: *Recorded) !void {
        if (comptime @import("builtin").is_test) {
            if (self.hooks) |hooks| {
                hooks.checks += 1;
                if (hooks.action) |action| try action(hooks.checks, self);
            }
        }
        try self.current();
        try self.checkInputs();
        var sensitive = core.sensitive.Allocator{ .backing = self.ctx.allocator };
        var scratch = std.heap.ArenaAllocator.init(sensitive.allocator());
        defer scratch.deinit();
        const a = scratch.allocator();
        const authorization_path = if (self.transaction) |*transaction|
            if (transaction.published) |*record| record.file.path else if (self.private_record) |*record| record.file.path else null
        else
            null;
        if (authorization_path) |path| {
            // verifyAuthorization's current check deliberately accepts CURRENT
            // denials. Authorization.current is approved-only for admission.
            try compute.verifyAuthorization(a, self.ctx.io, self.command.plan, path, true);
        } else {
            try compute.verifyPlan(a, self.ctx.io, self.command.plan, self.command.template);
        }
        try self.template.?.validate(self.plan.?, &self.plan_record.?.sha256);
        try self.checkInputs();
        if (comptime @import("builtin").is_test)
            if (self.hooks) |hooks|
                if (hooks.after_action) |action| try action(hooks.checks, self);
        try self.current();
        try copy.checkCancellation(if (self.ctx.signal) |s| s.flag() else null);
    }
    fn checkBarrier(raw: *anyopaque) !void {
        const self: *Recorded = @ptrCast(@alignCast(raw));
        try self.check();
    }
    fn barrier(self: *Recorded) tx.Barrier {
        return .{ .context = self, .check = checkBarrier };
    }
    fn execute(self: *Recorded) !?types.Diagnostic {
        const command = self.command;
        const recorded = try records.unsigned(command.recorded_unix);
        const expires = try records.unsigned(command.expires_unix);
        if (!contracts.validApprovalWindow(recorded, expires)) return error.InvalidApprovalWindow;
        if (!std.unicode.utf8ValidateSlice(command.approver) or !std.unicode.utf8ValidateSlice(command.reference) or
            !contracts.boundedAuthorityText(command.approver, 1, 128) or
            !contracts.boundedAuthorityText(command.reference, 1, 256)) return error.InvalidAuthorityField;
        if (try self.now() < recorded or try self.now() >= expires) return error.ApprovalExpired;
        try self.retainInputs();
        self.phase = .construction;
        self.decision = try records.authorization(self.plan.?, &self.plan_record.?.sha256, self.template.?, .{
            .decision = command.decision,
            .approver = command.approver,
            .reference = command.reference,
            .recorded_unix = recorded,
            .expires_unix = expires,
            .now = try self.now(),
        });
        const bytes = try records.authorizationBytes(self.allocator(), self.plan.?, &self.plan_record.?.sha256, self.decision.?, try self.now());
        // Enforce the existing verifier's smaller bound before any publication.
        if (bytes.len > record_limit) return error.FileTooLarge;
        self.phase = .custody;
        self.transaction = try tx.Transaction.init(self.ctx, command.output);
        self.phase = .validation;
        try self.check();
        self.phase = .freshness;
        try self.transaction.?.revalidate(self.barrier());
        const uuid = try records.freshUuid(self.allocator(), self.ctx.io);
        const private_path = try std.fmt.allocPrint(self.allocator(), "{s}.partial-{s}", .{ command.output, uuid });
        const transaction = &self.transaction.?;
        self.phase = .publication;
        const private_bytes = if (comptime @import("builtin").is_test)
            if (self.hooks) |hooks| if (hooks.short_private_write) bytes[0 .. bytes.len / 2] else bytes else bytes
        else
            bytes;
        const committed = if (comptime @import("builtin").is_test)
            if (self.hooks) |hooks|
                if (hooks.private_fault) |fault|
                    try transaction.lock.createImmutableFault(self.ctx.io, std.fs.path.basename(private_path), private_bytes, fault)
                else
                    try transaction.lock.createImmutable(self.ctx.io, std.fs.path.basename(private_path), private_bytes)
            else
                try transaction.lock.createImmutable(self.ctx.io, std.fs.path.basename(private_path), private_bytes)
        else
            try transaction.lock.createImmutable(self.ctx.io, std.fs.path.basename(private_path), bytes);
        self.private_status = committed.status;
        transaction.failures = tx.combineFailures(transaction.failures, committed.failures);
        if (committed.status != .durable or hasFailures(committed.failures))
            return .{ .phase = .publication, .err = error.PublicationUncertain, .publication = committed.status, .failures = transaction.failures };
        self.private_record = try tx.Record.open(self.ctx, private_path, record_limit);
        if (self.private_record.?.file.file_snapshot.size != bytes.len) return error.ShortWrite;
        if (!std.mem.eql(u8, &self.private_record.?.sha256, &std.fmt.bytesToHex(tx.hash(bytes), .lower)))
            return error.RecordChanged;
        self.phase = .validation;
        try self.check();
        self.phase = .publication;
        const outcome = if (comptime @import("builtin").is_test)
            if (self.hooks) |hooks|
                if (hooks.final_fault) |fault|
                    transaction.publishFault(bytes, self.barrier(), fault)
                else
                    transaction.publish(bytes, self.barrier())
            else
                transaction.publish(bytes, self.barrier())
        else
            transaction.publish(bytes, self.barrier());
        return switch (outcome) {
            .success => result: {
                self.phase = .final_revalidation;
                try self.current();
                try copy.checkCancellation(if (self.ctx.signal) |s| s.flag() else null);
                break :result null;
            },
            .refused, .poisoned => |failure| failure,
        };
    }
    fn diagnostic(self: *Recorded, err: anyerror) types.Diagnostic {
        return .{
            .phase = self.phase,
            .err = err,
            .publication = if (self.transaction) |transaction|
                if (transaction.publication != .not_committed) transaction.publication else self.private_status
            else
                self.private_status,
            .failures = if (self.transaction) |transaction| transaction.failures else .{},
        };
    }
};

const Bound = struct {
    file: files.RetainedFile,
    sha256: [64]u8,
};

pub fn run(ctx: types.Context, command: types.AuthorizationCommand) types.Outcome(*Recorded) {
    return runImpl(ctx, command, null);
}
fn runImpl(ctx: types.Context, command: types.AuthorizationCommand, hooks: ?*Test.Hooks) types.Outcome(*Recorded) {
    const owner = Recorded.initialize(ctx, command) catch |err|
        return refusal(.{ .phase = .inputs, .err = err }, false);
    owner.hooks = hooks;
    const failure = owner.execute() catch |err| {
        const diagnostic = owner.diagnostic(err);
        const partial = owner.private_status != .not_committed;
        owner.deinit();
        return refusal(diagnostic, partial);
    };
    if (failure) |diagnostic| {
        const partial = owner.private_status != .not_committed;
        owner.deinit();
        return refusal(diagnostic, partial);
    }
    return .{ .success = owner };
}

/// Fault injection never replaces an engine or qualifies an owner.
pub const Test = struct {
    pub const Hooks = struct {
        checks: usize = 0,
        action: ?*const fn (usize, *Recorded) anyerror!void = null,
        after_action: ?*const fn (usize, *Recorded) anyerror!void = null,
        now_seconds: ?u64 = null,
        short_private_write: bool = false,
        private_fault: ?files.TestFault = null,
        final_fault: ?files.TestFault = null,
    };
    pub fn run(ctx: types.Context, command: types.AuthorizationCommand, hooks: *Hooks) types.Outcome(*Recorded) {
        if (!@import("builtin").is_test) @compileError("authorization faults are test-only");
        return runImpl(ctx, command, hooks);
    }
    pub fn parseRecord(comptime T: type, allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(T) {
        if (!@import("builtin").is_test) @compileError("authorization parser test seam");
        return parse(T, allocator, bytes);
    }
};

fn refusal(diagnostic: types.Diagnostic, partial: bool) types.Outcome(*Recorded) {
    log.warn("recording refused phase={s} error={s} publication={s}", .{ @tagName(diagnostic.phase), @errorName(diagnostic.err), @tagName(diagnostic.publication) });
    return if (partial or diagnostic.publication != .not_committed or hasFailures(diagnostic.failures))
        .{ .poisoned = diagnostic }
    else
        .{ .refused = diagnostic };
}
fn hasFailures(failures: core.diagnostics.Failures) bool {
    return failures.primary != null or failures.cleanup != null or failures.recording != null;
}
fn same(left: types.Artifact, right: types.Artifact) bool {
    return left.size == right.size and std.mem.eql(u8, left.path, right.path) and std.mem.eql(u8, left.sha256, right.sha256);
}
fn project(value: types.runtime.Artifact) types.Artifact {
    return .{ .path = value.path, .size = value.size, .sha256 = value.sha256 };
}

// std.json's typed decoder accepts numeric strings. Check recursive scalar
// kinds first, using the existing bounded canonical document engine.
fn parse(comptime T: type, a: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(T) {
    var document = try contracts.parseCanonical(a, bytes);
    defer document.deinit();
    try strict(T, document.value());
    return std.json.parseFromValue(T, a, document.value(), .{ .allocate = .alloc_always });
}
fn strict(comptime T: type, value: std.json.Value) anyerror!void {
    const c = core.contracts;
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            const names = comptime blk: {
                var names: [info.fields.len][]const u8 = undefined;
                for (info.fields, 0..) |field, index| names[index] = field.name;
                break :blk names;
            };
            const object = try c.exactFields(value, &names);
            inline for (info.fields) |field| try strict(field.type, object.get(field.name).?);
        },
        .int => _ = try c.integer(T, value),
        .bool => if (value != .bool) return error.ExpectedBoolean,
        .@"enum" => _ = try c.enumeration(T, value),
        .pointer => |info| {
            if (info.size != .slice) @compileError("unsupported record pointer");
            if (info.child == u8) {
                if (!std.unicode.utf8ValidateSlice(try c.string(value))) return error.InvalidUtf8;
            } else {
                if (value != .array) return error.ExpectedArray;
                for (value.array.items) |item| try strict(info.child, item);
            }
        },
        .array => |info| {
            if (value != .array or value.array.items.len != info.len) return error.ExpectedArray;
            for (value.array.items) |item| try strict(info.child, item);
        },
        else => @compileError("unsupported record type"),
    }
}
