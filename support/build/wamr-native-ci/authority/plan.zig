// SPDX-License-Identifier: BSD-3-Clause
//! Source-library operation. The caller keeps the imported Finalized and its
//! complete source/reader ownership chain alive until Prepared.deinit.
const std = @import("std");
const core = @import("hyperv_core");
const handoff = @import("wamr_handoff");
const candidate = handoff.candidate;
const types = @import("types.zig");
const contracts = @import("contracts.zig");
const records = @import("records.zig");
const tx = @import("transaction.zig");
const files = core.private_files;
const compute = types.compute;
const max_tool_bytes: u64 = 64 * 1024 * 1024;

pub const Publications = struct {
    pending_plan: files.CommitStatus = .not_committed,
    pending_template: files.CommitStatus = .not_committed,
    validation: files.CommitStatus = .not_committed,
    plan: files.CommitStatus = .not_committed,
    template: files.CommitStatus = .not_committed,
    failure_record: files.CommitStatus = .not_committed,

    fn started(self: Publications) bool {
        inline for (std.meta.fields(Publications)) |field|
            if (@field(self, field.name) != .not_committed) return true;
        return false;
    }
};
pub const ProcessStatus = struct {
    primary: core.process.CommandPrimary,
    stdout_status: core.process.CommandStreamStatus,
    stderr_status: core.process.CommandStreamStatus,
    cleanup: core.process.CommandCleanup,
    cleanup_complete: bool,
    freshness: ?anyerror,
};
pub const Diagnostic = struct {
    phase: types.Phase,
    err: anyerror,
    outputs: Publications,
    failures: core.diagnostics.Failures,
    process: ?ProcessStatus,
    recording_error: ?anyerror = null,
};
pub const Outcome = union(enum) {
    success: *Prepared,
    refused: Diagnostic,
    poisoned: Diagnostic,
};
pub const Result = struct {
    plan: types.Plan,
    template: types.ApprovalTemplate,
    plan_artifact: types.Artifact,
    template_artifact: types.Artifact,
    validation_artifact: types.Artifact,
};

pub const Prepared = opaque {
    fn state(self: *Prepared) *State {
        return @ptrCast(@alignCast(self));
    }
    pub fn revalidate(self: *Prepared) !void {
        const owner = self.state();
        try owner.revalidate();
        try compute.verifyPlan(owner.arena.allocator(), owner.ctx.io, owner.paths.plan, owner.paths.template);
        try owner.revalidate();
    }
    pub fn result(self: *Prepared) !Result {
        try self.revalidate();
        const owner = self.state();
        return .{
            .plan = owner.plan.?,
            .template = owner.template.?,
            .plan_artifact = owner.plan_record.?.artifact(),
            .template_artifact = owner.template_record.?.artifact(),
            .validation_artifact = owner.validation_record.?.artifact(),
        };
    }
    pub fn deinit(self: *Prepared) void {
        self.state().deinit();
    }
};

const Paths = struct {
    plan: []const u8,
    template: []const u8,
    pending_plan: []const u8,
    pending_template: []const u8,
    validation: []const u8,
    failure_record: []const u8,

    fn init(a: std.mem.Allocator, command: types.PlanCommand) !Paths {
        const value: Paths = .{
            .plan = try a.dupe(u8, command.output),
            .template = try a.dupe(u8, command.approval_template),
            .pending_plan = try std.fmt.allocPrint(a, "{s}.pending-plan.json", .{command.output}),
            .pending_template = try std.fmt.allocPrint(a, "{s}.pending-template.json", .{command.approval_template}),
            .validation = try std.fmt.allocPrint(a, "{s}.validation.json", .{command.output}),
            .failure_record = try std.fmt.allocPrint(a, "{s}.failure.json", .{command.output}),
        };
        inline for (std.meta.fields(Paths), 0..) |field, index| {
            const path = @field(value, field.name);
            try files.absoluteFilePath(path);
            if (equal(std.fs.path.basename(path), ".writer.lock")) return error.OutputCollision;
            inline for (std.meta.fields(Paths)[0..index]) |previous|
                if (equal(path, @field(value, previous.name))) return error.OutputCollision;
        }
        return value;
    }
    fn fresh(self: Paths, io: std.Io) !void {
        inline for (std.meta.fields(Paths)) |field| try absent(io, @field(self, field.name));
    }
};

const Tool = struct {
    retained: files.RetainedFile,
    sha256: [64]u8,

    fn open(ctx: types.Context, path: []const u8) !Tool {
        var retained = try files.RetainedFile.open(ctx.io, path, .tool);
        errdefer retained.close(ctx.io);
        return .{
            .retained = retained,
            .sha256 = try handoff.retained_copy.hashRetained(ctx.io, &retained, max_tool_bytes, flag(ctx)),
        };
    }
    fn artifact(self: *const Tool) types.Artifact {
        return .{ .path = self.retained.path, .size = self.retained.file_snapshot.size, .sha256 = &self.sha256 };
    }
    fn verify(self: *Tool, ctx: types.Context) !void {
        const digest = try handoff.retained_copy.hashRetained(ctx.io, &self.retained, max_tool_bytes, flag(ctx));
        if (!equal(&digest, &self.sha256)) return error.ToolChanged;
    }
};

const Parent = struct {
    retained: files.FileParent,
    snapshot: files.Snapshot,
    path: []const u8,

    fn open(io: std.Io, path: []const u8) !Parent {
        const retained = try files.FileParent.open(io, path, .private);
        errdefer retained.close(io);
        return .{
            .retained = retained,
            .path = path,
            .snapshot = try files.snapshot(.{ .handle = retained.directory.handle, .flags = .{ .nonblocking = false } }),
        };
    }
    fn verify(self: Parent, io: std.Io) !void {
        const named = try files.FileParent.open(io, self.path, .private);
        defer named.close(io);
        for ([_]std.Io.Dir{ self.retained.directory, named.directory }) |directory| {
            const snapshot = try files.snapshot(.{ .handle = directory.handle, .flags = .{ .nonblocking = false } });
            if (!sameDirectory(snapshot, self.snapshot) or snapshot.uid != self.snapshot.uid or snapshot.mode != self.snapshot.mode)
                return error.OutputParentChanged;
        }
    }
};

const Ledger = struct {
    directory: files.Directory,
    snapshot: files.Snapshot,
    path: []const u8,
    binding: compute.LedgerBinding,
    binding_bytes: []const u8,
    state_sha256: [64]u8,

    fn open(ctx: types.Context, a: std.mem.Allocator, path: []const u8, campaign_id: []const u8, ledger_id: []const u8) !Ledger {
        const directory = try files.Directory.open(ctx.io, path);
        errdefer directory.close(ctx.io);
        const before = try files.snapshot(.{ .handle = directory.dir.handle, .flags = .{ .nonblocking = false } });
        const binding = try compute.ledgerProposal(a, ctx.io, path, campaign_id, ledger_id);
        const digest = try currentLedgerDigest(ctx, a, directory, path, binding);
        var value: Ledger = .{
            .directory = directory,
            .snapshot = before,
            .path = path,
            .binding = binding,
            .binding_bytes = try compute.ledgerBindingBytes(a, binding),
            .state_sha256 = digest,
        };
        try value.verify(ctx, a);
        return value;
    }
    fn verify(self: *Ledger, ctx: types.Context, allocator: std.mem.Allocator) !void {
        try handoff.retained_copy.checkCancellation(flag(ctx));
        const named = try files.Directory.open(ctx.io, self.path);
        defer named.close(ctx.io);
        if (!files.sameSnapshot(self.snapshot, try files.snapshot(.{ .handle = self.directory.dir.handle, .flags = .{ .nonblocking = false } })) or
            !files.sameSnapshot(self.snapshot, try files.snapshot(.{ .handle = named.dir.handle, .flags = .{ .nonblocking = false } })))
            return error.LedgerChanged;
        var scratch = std.heap.ArenaAllocator.init(allocator);
        defer scratch.deinit();
        const a = scratch.allocator();
        if (!equal(&self.state_sha256, &try currentLedgerDigest(ctx, a, self.directory, self.path, self.binding)))
            return error.LedgerChanged;
        const proposal = try compute.ledgerProposal(a, ctx.io, self.path, self.binding.campaign_id, self.binding.ledger_id);
        if (!equal(self.binding_bytes, try compute.ledgerBindingBytes(a, proposal)))
            return error.LedgerChanged;
        try handoff.retained_copy.checkCancellation(flag(ctx));
    }
};

// The existing pre-state digest deliberately refuses an initialized marker.
// Keep its constructor/validator authoritative; separately freeze *current*
// initialized state (including identity metadata) without modifying the ledger.
fn currentLedgerDigest(ctx: types.Context, a: std.mem.Allocator, directory: files.Directory, path: []const u8, binding: compute.LedgerBinding) ![64]u8 {
    if (binding.initialization_required) return compute.ledgerStateDigest(a, ctx.io, directory);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var inventory: LedgerInventory = .{ .ctx = ctx, .a = arena.allocator(), .hash = core.Sha256.init(.{}) };
    inventory.hash.update("wamr-authority-ledger-current-v1\x00");
    try inventory.scan(directory, path, 0);
    return std.fmt.bytesToHex(inventory.hash.finalResult(), .lower);
}
const LedgerInventory = struct {
    ctx: types.Context,
    a: std.mem.Allocator,
    hash: core.Sha256,
    entries: usize = 0,
    bytes: u64 = 0,

    fn metadata(self: *LedgerInventory, value: files.Snapshot) !void {
        self.hash.update(try std.json.Stringify.valueAlloc(self.a, .{
            .device_major = value.dev_major,
            .device_minor = value.dev_minor,
            .inode = value.ino,
            .size = value.size,
            .mode = value.mode,
            .uid = value.uid,
            .nlink = value.nlink,
            .mtime_seconds = value.mtime.sec,
            .mtime_nanoseconds = value.mtime.nsec,
            .ctime_seconds = value.ctime.sec,
            .ctime_nanoseconds = value.ctime.nsec,
        }, .{}));
    }
    fn scan(self: *LedgerInventory, directory: files.Directory, path: []const u8, depth: usize) !void {
        try handoff.retained_copy.checkCancellation(flag(self.ctx));
        if (depth > 16) return error.LedgerTooLarge;
        const before = try files.snapshot(.{ .handle = directory.dir.handle, .flags = .{ .nonblocking = false } });
        if (before.mode & 0o7777 != 0o700 or before.uid != std.os.linux.geteuid()) return error.UnsafeLedger;
        try self.metadata(before);
        var names: std.ArrayList([]const u8) = .empty;
        var iterator = directory.dir.iterate();
        while (try iterator.next(self.ctx.io)) |entry| {
            if (names.items.len >= 4098) return error.LedgerTooLarge;
            try files.basename(entry.name);
            try names.append(self.a, try self.a.dupe(u8, entry.name));
        }
        std.mem.sort([]const u8, names.items, {}, struct {
            fn less(_: void, first: []const u8, second: []const u8) bool {
                return std.mem.lessThan(u8, first, second);
            }
        }.less);
        for (names.items) |name| {
            try handoff.retained_copy.checkCancellation(flag(self.ctx));
            const identity = depth == 0 and (equal(name, compute.ledger_marker_name) or equal(name, compute.ledger_sentinel_name));
            if (!identity) {
                self.entries += 1;
                if (self.entries > 4096) return error.LedgerTooLarge;
            }
            const child_path = try std.fs.path.join(self.a, &.{ path, name });
            const probe = try directory.dir.openFile(self.ctx.io, name, .{ .path_only = true, .follow_symlinks = false });
            defer probe.close(self.ctx.io);
            const snapshot = try files.snapshot(probe);
            var length: [4]u8 = undefined;
            std.mem.writeInt(u32, &length, @intCast(child_path.len), .big);
            self.hash.update(&length);
            self.hash.update(child_path);
            try self.metadata(snapshot);
            switch (snapshot.mode & std.os.linux.S.IFMT) {
                std.os.linux.S.IFDIR => {
                    const child = try files.Directory.open(self.ctx.io, child_path);
                    defer child.close(self.ctx.io);
                    if (!files.sameSnapshot(snapshot, try files.snapshot(.{ .handle = child.dir.handle, .flags = .{ .nonblocking = false } })))
                        return error.LedgerChanged;
                    try self.scan(child, child_path, depth + 1);
                },
                std.os.linux.S.IFREG => {
                    if (identity) {
                        if (snapshot.size > 64 * 1024) return error.LedgerTooLarge;
                    } else {
                        self.bytes = try std.math.add(u64, self.bytes, snapshot.size);
                        if (self.bytes > 4 * 1024 * 1024) return error.LedgerTooLarge;
                    }
                    var file = try files.RetainedFile.open(self.ctx.io, child_path, .private);
                    defer file.close(self.ctx.io);
                    if (!files.sameSnapshot(snapshot, file.file_snapshot)) return error.LedgerChanged;
                    self.hash.update(&try handoff.retained_copy.hashRetained(self.ctx.io, &file, 4 * 1024 * 1024, flag(self.ctx)));
                },
                else => return error.UnsafeLedger,
            }
        }
        if (!files.sameSnapshot(before, try files.snapshot(.{ .handle = directory.dir.handle, .flags = .{ .nonblocking = false } })))
            return error.LedgerChanged;
        try handoff.retained_copy.checkCancellation(flag(self.ctx));
    }
};

const State = struct {
    ctx: types.Context,
    arena: std.heap.ArenaAllocator,
    source: *candidate.Finalized,
    paths: Paths = undefined,
    paths_ready: bool = false,
    recording_safe: bool = false,
    ledger_path: []const u8 = "",
    parents: [6]Parent = undefined,
    parent_count: usize = 0,
    metadata: ?candidate.Metadata = null,
    tools: [5]Tool = undefined,
    tool_count: usize = 0,
    runtime_record: ?tx.Record = null,
    runtime: ?types.runtime.Contract = null,
    ledger: ?Ledger = null,
    plan: ?types.Plan = null,
    template: ?types.ApprovalTemplate = null,
    pending_plan: ?tx.Record = null,
    pending_template: ?tx.Record = null,
    validation_record: ?tx.Record = null,
    plan_record: ?tx.Record = null,
    template_record: ?tx.Record = null,
    phase: types.Phase = .inputs,
    outputs: Publications = .{},
    failures: core.diagnostics.Failures = .{},
    process: ?ProcessStatus = null,
    recording_error: ?anyerror = null,
    deadline: ?core.process.Deadline = null,
    poisoned: bool = false,

    fn deinit(self: *State) void {
        inline for (.{ "runtime_record", "pending_plan", "pending_template", "validation_record", "plan_record", "template_record" }) |field|
            if (@field(self, field)) |*record| record.deinit();
        if (self.ledger) |ledger| ledger.directory.close(self.ctx.io);
        for (self.tools[0..self.tool_count]) |*tool| tool.retained.close(self.ctx.io);
        for (self.parents[0..self.parent_count]) |parent| parent.retained.close(self.ctx.io);
        const a = self.ctx.allocator;
        self.arena.deinit();
        a.destroy(self);
    }
    fn checkTime(self: *State) !void {
        try handoff.retained_copy.checkCancellation(flag(self.ctx));
        if (self.deadline) |deadline| if (try deadline.expired()) return error.DeadlineExceeded;
    }
    fn revalidate(self: *State) !void {
        try self.checkTime();
        for (self.parents[0..self.parent_count]) |parent| try parent.verify(self.ctx.io);
        try self.source.revalidate(self.ctx.signal);
        if (self.metadata) |metadata| try readerController(self.ctx, metadata.reader);
        for (self.tools[0..self.tool_count]) |*tool| try tool.verify(self.ctx);
        if (self.runtime_record) |*record| try record.revalidate(self.ctx.signal);
        if (self.runtime) |runtime| try types.runtime.verify(self.ctx.allocator, self.ctx.io, runtime);
        if (self.recording_safe) try physicalSeparation(self.ctx, self.paths, &protectedRoots(self.metadata.?, self.runtime.?, self.ledger_path));
        if (self.ledger) |*ledger| try ledger.verify(self.ctx, self.ctx.allocator);
        inline for (.{ "pending_plan", "pending_template", "validation_record", "plan_record", "template_record" }) |field|
            if (@field(self, field)) |*record| try record.revalidate(self.ctx.signal);
        try self.source.revalidate(self.ctx.signal);
        for (self.parents[0..self.parent_count]) |parent| try parent.verify(self.ctx.io);
        try self.checkTime();
    }
    fn check(raw: *anyopaque) !void {
        const self: *State = @ptrCast(@alignCast(raw));
        try self.revalidate();
    }
    fn barrier(self: *State) tx.Barrier {
        return .{ .context = self, .check = check };
    }
    fn publish(self: *State, path: []const u8, bytes: []const u8, status: *files.CommitStatus, bound: bool) !tx.Record {
        var ctx = self.ctx;
        if (!bound) ctx.signal = null;
        var transaction = try tx.Transaction.init(ctx, path);
        defer transaction.deinit();
        const outcome = transaction.publish(bytes, if (bound) self.barrier() else .{ .context = self, .check = recordingBarrier });
        status.* = transaction.publication;
        self.failures = tx.combineFailures(self.failures, transaction.failures);
        switch (outcome) {
            .success => {},
            .refused => |failure| {
                self.failures = tx.combineFailures(self.failures, failure.failures);
                return failure.err;
            },
            .poisoned => |failure| {
                self.poisoned = true;
                self.failures = tx.combineFailures(self.failures, failure.failures);
                return failure.err;
            },
        }
        // Move the retained record out before releasing this directory's lock.
        // Two concurrent Transactions in one parent would contend on that lock.
        const record = transaction.published.?;
        transaction.published = null;
        return record;
    }
    fn recordingBarrier(_: *anyopaque) !void {}

    fn nativeValidation(self: *State) !void {
        const a = self.arena.allocator();
        const metadata = self.metadata.?;
        try self.revalidate();
        try core.process.initialize();
        const executable = try core.process.Executable.fromFile(self.ctx.io, metadata.reader.validator.file);
        defer executable.close(self.ctx.io);
        const cwd = try files.openDirectory(self.ctx.io, metadata.reader.repository, .artifact);
        defer cwd.close(self.ctx.io);
        var environment = std.process.Environ.Map.init(a);
        defer environment.deinit();
        const primary = self.deadline.?;
        const cleanup: core.process.Deadline = .{
            .expires_ns = try std.math.add(u64, primary.expires_ns, @as(u64, contracts.policy.cleanup_seconds) * std.time.ns_per_s),
        };
        const controller_digest = try handoff.retained_copy.hashRetained(self.ctx.io, metadata.reader.controller, max_tool_bytes, flag(self.ctx));
        const git_digest = try handoff.retained_copy.hashRetained(self.ctx.io, metadata.reader.git, max_tool_bytes, flag(self.ctx));
        var supervised = try tx.supervise(self.ctx, .{
            .executable = executable,
            .argv = &.{ metadata.reader.validator.path, "plan", self.paths.pending_plan, self.paths.pending_template },
            .environment = &environment,
            .cwd = cwd,
            .primary_deadline = primary,
            .cleanup_deadline = cleanup,
            .limits = .{ .stdout_bytes = 4096, .stderr_bytes = 4096 },
        }, self.barrier());
        defer supervised.deinit(self.ctx.allocator);
        const result = supervised.result;
        self.process = .{
            .primary = result.primary,
            .stdout_status = result.stdout_status,
            .stderr_status = result.stderr_status,
            .cleanup = result.cleanup,
            .cleanup_complete = result.cleanup_complete,
            .freshness = supervised.freshness,
        };
        if (!result.succeeded()) {
            self.failures.primary = .{ .stage = .process_run, .category = switch (result.primary) {
                .timeout => .timeout,
                .cancelled => .cancelled,
                .output_overflow => .output_limit,
                else => .child_failed,
            } };
            if (!result.cleanup_complete) self.failures.cleanup = .{ .stage = .process_cleanup, .category = .cleanup_failed };
        }
        const captured = canonical(a, .{
            .schema = "uk.wamr.azure-plan-native-validation",
            .version = @as(u8, 1),
            .authority = "not_admitted",
            .reader = .{
                .repository = metadata.reader.repository,
                .revision = metadata.reader.reader_revision,
                .tree = metadata.reader.reader_tree,
                .git = types.Artifact{ .path = metadata.reader.git.path, .size = metadata.reader.git.file_snapshot.size, .sha256 = &git_digest },
                .controller = types.Artifact{ .path = metadata.reader.controller.path, .size = metadata.reader.controller.file_snapshot.size, .sha256 = &controller_digest },
                .supervisor = self.tools[3].artifact(),
                .validator = self.tools[2].artifact(),
                .candidate_validation_record = metadata.reader.validation_record,
                .candidate_validation_log = metadata.reader.validation_log,
            },
            .argv = &[_][]const u8{ metadata.reader.validator.path, "plan", self.paths.pending_plan, self.paths.pending_template },
            .executable = result.executable,
            .primary = result.primary,
            .termination = result.termination,
            .started_ns = result.started_ns,
            .primary_completed_ns = result.primary_completed_ns,
            .completed_ns = result.completed_ns,
            .primary_deadline_reached = result.primary_deadline_reached,
            .cancellation_observed = result.cancellation_observed,
            .executable_stable = result.executable_stable,
            .stdout_hex = hexBytes(a, result.stdout) catch |err| return self.captureFailure(err, supervised),
            .stderr_hex = hexBytes(a, result.stderr) catch |err| return self.captureFailure(err, supervised),
            .stdout_status = result.stdout_status,
            .stderr_status = result.stderr_status,
            .cleanup = result.cleanup,
            .cleanup_complete = result.cleanup_complete,
            .descendants = result.descendants,
            .primary_events = result.primary_events,
            .cleanup_events = result.cleanup_events,
            .reap_events = result.reap_events,
            .freshness_error = if (supervised.freshness) |err| @errorName(err) else null,
            .failures = self.failures,
        }) catch |err| return self.captureFailure(err, supervised);
        self.validation_record = self.publish(self.paths.validation, captured, &self.outputs.validation, false) catch |err| {
            return self.captureFailure(err, supervised);
        };
        if (!result.succeeded()) return error.NativeValidationFailed;
        if (result.stdout.len != 0 or result.stderr.len != 0) return error.UnexpectedValidationOutput;
        if (supervised.freshness) |err| return err;
        try self.revalidate();
    }
    fn captureFailure(self: *State, err: anyerror, supervised: tx.Supervised) anyerror {
        self.recording_error = err;
        self.failures.recording = self.failures.recording orelse .{ .stage = .state_record, .category = .local_io };
        if (!supervised.result.succeeded()) return error.NativeValidationFailed;
        if (supervised.freshness) |freshness| return freshness;
        return err;
    }

    fn finish(self: *State, command: types.PlanCommand) !void {
        try self.checkTime();
        const a = self.arena.allocator();
        self.paths = try Paths.init(a, command);
        self.paths_ready = true;
        try self.paths.fresh(self.ctx.io);
        inline for (std.meta.fields(Paths)) |field| {
            self.parents[self.parent_count] = try Parent.open(self.ctx.io, @field(self.paths, field.name));
            self.parent_count += 1;
        }
        for (self.parents[0..self.parent_count], 0..) |parent, index|
            for (self.parents[0..index]) |previous|
                if (sameDirectory(parent.snapshot, previous.snapshot) and equal(parent.retained.name, previous.retained.name))
                    return error.OutputCollision;
        self.deadline = try core.process.Deadline.afterMilliseconds(contracts.policy.operation_seconds * 1000);
        try self.checkTime();
        self.phase = .custody;
        const metadata = try self.source.metadata(self.ctx.signal);
        const normalized = try bindCommand(a, self.ctx.io, command, metadata);
        self.metadata = metadata;
        try readerController(self.ctx, metadata.reader);
        self.ledger_path = try a.dupe(u8, command.ledger);
        const tool_paths = [_][]const u8{ command.tools.azure, command.tools.uploader, command.tools.validator, command.tools.supervisor, command.tools.az_python };
        for (tool_paths) |path| {
            self.tools[self.tool_count] = try Tool.open(self.ctx, try a.dupe(u8, path));
            self.tool_count += 1;
        }
        var tools: compute.Tools = undefined;
        inline for (std.meta.fields(compute.Tools), 0..) |field, index|
            @field(tools, field.name) = self.tools[index].artifact();
        if (!equal(tools.validator.path, metadata.reader.validator.path) or
            !equal(tools.supervisor.path, metadata.reader.supervisor.path))
            return error.ReaderToolMismatch;
        self.runtime_record = try tx.Record.open(self.ctx, command.tools.azure_runtime, 64 * 1024);
        var runtime_bytes = try self.runtime_record.?.read(a, self.ctx.signal);
        defer runtime_bytes.deinit();
        const parsed = try records.parse(types.runtime.Contract, a, runtime_bytes.bytes());
        self.runtime = parsed.value;
        try self.runtime.?.validate();
        try outputSeparation(self.paths, command, metadata, self.runtime.?);
        try physicalSeparation(self.ctx, self.paths, &protectedRoots(metadata, self.runtime.?, self.ledger_path));
        self.recording_safe = true;
        try self.revalidate();
        self.ledger = try Ledger.open(self.ctx, a, self.ledger_path, normalized.campaign_id, normalized.ledger_id);
        self.phase = .construction;
        self.plan = try records.plan(.{
            .candidate = self.source,
            .created_unix = normalized.created_unix,
            .campaign_id = normalized.campaign_id,
            .ledger_path = self.ledger.?.path,
            .ledger = self.ledger.?.binding,
            .maximum_authorized_cost_microusd = normalized.maximum_cost,
            .tools = tools,
            .azure_runtime_document = self.runtime_record.?.artifact(),
            .azure_runtime = self.runtime.?,
        }, self.ctx.signal);
        const bytes = try records.planBytes(a, self.plan.?);
        const digest = try a.dupe(u8, &std.fmt.bytesToHex(tx.hash(bytes), .lower));
        self.template = try records.approvalTemplate(self.plan.?, digest);
        const template_bytes = try records.templateBytes(a, self.plan.?, digest, self.template.?);
        self.phase = .freshness;
        try self.revalidate();
        self.pending_plan = try self.publish(self.paths.pending_plan, bytes, &self.outputs.pending_plan, true);
        self.pending_template = try self.publish(self.paths.pending_template, template_bytes, &self.outputs.pending_template, true);
        self.phase = .validation;
        try self.nativeValidation();
        try compute.verifyPlan(a, self.ctx.io, self.paths.pending_plan, self.paths.pending_template);
        try self.revalidate();
        self.phase = .publication;
        self.plan_record = try self.publish(self.paths.plan, bytes, &self.outputs.plan, true);
        // The final template is published only after the final plan and staged
        // template pass the real validator. This is not cross-directory atomic.
        try compute.verifyPlan(a, self.ctx.io, self.paths.plan, self.paths.pending_template);
        try self.revalidate();
        self.template_record = try self.publish(self.paths.template, template_bytes, &self.outputs.template, true);
        self.phase = .final_revalidation;
        try compute.verifyPlan(a, self.ctx.io, self.paths.plan, self.paths.template);
        try self.revalidate();
    }
    fn refusal(self: *State, err: anyerror) Outcome {
        const already_published = self.outputs.started();
        self.failures.primary = self.failures.primary orelse .{ .stage = .contract, .category = .invalid_input };
        if (self.paths_ready and self.recording_safe) {
            self.recordFailure(err) catch |recording_error| {
                self.recording_error = recording_error;
                self.failures.recording = self.failures.recording orelse .{ .stage = .state_record, .category = .local_io };
            };
        }
        const diagnostic: Diagnostic = .{
            .phase = self.phase,
            .err = err,
            .outputs = self.outputs,
            .failures = self.failures,
            .process = self.process,
            .recording_error = self.recording_error,
        };
        const poisoned = already_published or self.poisoned;
        self.deinit();
        return if (poisoned) .{ .poisoned = diagnostic } else .{ .refused = diagnostic };
    }
    fn recordFailure(self: *State, err: anyerror) !void {
        for (self.parents[0..self.parent_count]) |parent| try parent.verify(self.ctx.io);
        try physicalSeparation(self.ctx, self.paths, &protectedRoots(self.metadata.?, self.runtime.?, self.ledger_path));
        const bytes = try canonical(self.arena.allocator(), .{
            .schema = "uk.wamr.azure-plan-failure",
            .version = @as(u8, 1),
            .authority = "not_admitted",
            .phase = self.phase,
            .error_code = @errorName(err),
            .plan = self.paths.plan,
            .template = self.paths.template,
            .pending_plan = self.paths.pending_plan,
            .pending_template = self.paths.pending_template,
            .validation = self.paths.validation,
            .outputs = self.outputs,
            .failures = self.failures,
            .process = if (self.process) |process| .{
                .primary = process.primary,
                .cleanup = process.cleanup,
                .cleanup_complete = process.cleanup_complete,
                .stdout_status = process.stdout_status,
                .stderr_status = process.stderr_status,
                .freshness_error = if (process.freshness) |freshness| @errorName(freshness) else null,
            } else null,
        });
        var record = try self.publish(self.paths.failure_record, bytes, &self.outputs.failure_record, false);
        defer record.deinit();
    }
};

/// bundle/candidate_output identify the retained imported manifest and existing
/// no-authority candidate. No owner is acquired from these CLI-shaped paths.
pub fn run(ctx: types.Context, command: types.PlanCommand, source: *candidate.Finalized) Outcome {
    const owner = ctx.allocator.create(State) catch |err| return .{ .refused = .{
        .phase = .inputs,
        .err = err,
        .outputs = .{},
        .failures = .{},
        .process = null,
    } };
    owner.* = .{ .ctx = ctx, .arena = std.heap.ArenaAllocator.init(ctx.allocator), .source = source };
    owner.finish(command) catch |err| return owner.refusal(err);
    return .{ .success = @ptrCast(owner) };
}

const Normalized = struct {
    campaign_id: []const u8,
    ledger_id: []const u8,
    created_unix: u64,
    maximum_cost: u64,
};
fn bindCommand(a: std.mem.Allocator, io: std.Io, command: types.PlanCommand, metadata: candidate.Metadata) !Normalized {
    if (metadata.source != .imported_product) return error.ImportedProductRequired;
    const scope = metadata.scope;
    if (scope.version != 2 or !equal(scope.purpose, contracts.policy.profile)) return error.Version2Required;
    inline for (std.meta.fields(@TypeOf(scope.approval))) |field| {
        if (comptime field.type == bool) {
            if (@field(scope.approval, field.name)) return error.AuthorityNotAllowed;
        } else if (@field(scope.approval, field.name) != 0) return error.AuthorityNotAllowed;
    }
    if (!equal(scope.location, contracts.policy.location) or !equal(scope.vm_size, contracts.policy.vm_size) or
        scope.runtime_seconds != contracts.policy.runtime_seconds or scope.cleanup_seconds != contracts.policy.cleanup_seconds or
        scope.operation_seconds != contracts.policy.operation_seconds or scope.poll_seconds != contracts.policy.poll_seconds)
        return error.InvalidBudget;
    const campaign = try records.normalizeUuid(a, command.campaign_id);
    const subscription = try records.normalizeUuid(a, command.subscription);
    if (!equal(subscription, scope.subscription) or !equal(command.prefix, scope.prefix) or
        !equal(command.candidate_output, metadata.candidate.path) or !equal(command.bundle, metadata.provenance.public_bundle.path))
        return error.WrongCandidate;
    if (command.attempt_id) |attempt|
        if (!equal(try records.normalizeUuid(a, attempt), scope.attempt_id)) return error.WrongCandidate;
    const maximum = try records.unsigned(command.maximum_authorized_cost_microusd);
    if (maximum < contracts.policy.estimated_cost_upper_bound_microusd or maximum > contracts.policy.repository_maximum_cost_microusd)
        return error.InvalidCost;
    const now = std.Io.Clock.real.now(io).toSeconds();
    if (now <= 0) return error.InvalidClock;
    const created = if (command.created_unix) |value| try records.unsigned(value) else @as(u64, @intCast(now));
    if (created == 0) return error.InvalidInteger;
    return .{
        .campaign_id = campaign,
        .ledger_id = if (command.ledger_id) |value| try records.normalizeUuid(a, value) else try records.freshUuid(a, io),
        .created_unix = created,
        .maximum_cost = maximum,
    };
}
fn outputSeparation(paths: Paths, command: types.PlanCommand, metadata: candidate.Metadata, runtime: types.runtime.Contract) !void {
    const roots = protectedRoots(metadata, runtime, command.ledger);
    const inputs = [_][]const u8{
        metadata.candidate.path,                metadata.scope.bundle.path,          metadata.scope.os_vhd.path,
        metadata.provenance.public_bundle.path, metadata.provenance.transport.path,  metadata.provenance.qcow2.path,
        metadata.reader.validation_record.path, metadata.reader.validation_log.path, command.tools.azure_runtime,
        command.tools.azure,                    command.tools.uploader,              command.tools.validator,
        command.tools.supervisor,               command.tools.az_python,
    };
    inline for (std.meta.fields(Paths)) |field| {
        const path = @field(paths, field.name);
        for (roots) |root| if (inside(path, root)) return error.OutputInsideInput;
        for (inputs) |input| if (equal(path, input)) return error.OutputCollision;
    }
}
fn protectedRoots(metadata: candidate.Metadata, runtime: types.runtime.Contract, ledger: []const u8) [6][]const u8 {
    return .{
        ledger,
        runtime.root,
        metadata.reader.repository,
        metadata.reader.validation_output,
        std.fs.path.dirname(metadata.provenance.public_bundle.path).?,
        std.fs.path.dirname(metadata.provenance.transport.path).?,
    };
}
fn sameDirectory(first: files.Snapshot, second: files.Snapshot) bool {
    return first.ino == second.ino and first.dev_major == second.dev_major and first.dev_minor == second.dev_minor;
}
fn physicalSeparation(ctx: types.Context, paths: Paths, roots: []const []const u8) !void {
    var snapshots: [6]files.Snapshot = undefined;
    if (roots.len > snapshots.len) return error.InvalidContext;
    for (roots, 0..) |root, index| {
        const directory = try files.openDirectory(ctx.io, root, .artifact);
        defer directory.close(ctx.io);
        snapshots[index] = try files.snapshot(.{ .handle = directory.handle, .flags = .{ .nonblocking = false } });
    }
    inline for (std.meta.fields(Paths)) |field| {
        var parent = std.fs.path.dirname(@field(paths, field.name)).?;
        while (parent.len > 1) {
            const directory = try files.openDirectory(ctx.io, parent, .artifact);
            defer directory.close(ctx.io);
            const current = try files.snapshot(.{ .handle = directory.handle, .flags = .{ .nonblocking = false } });
            for (snapshots[0..roots.len]) |root| if (sameDirectory(current, root)) return error.OutputInsideInput;
            parent = std.fs.path.dirname(parent).?;
        }
    }
}
fn readerController(ctx: types.Context, reader: candidate.ReaderContext) !void {
    const current = try std.Io.Dir.realPathFileAbsoluteAlloc(ctx.io, "/proc/self/exe", ctx.allocator);
    defer ctx.allocator.free(current);
    if (!equal(current, reader.controller.path)) return error.ImportSupervisorChanged;
    try reader.controller.verify(ctx.io);
    try reader.supervisor.verify(ctx.io);
    const controller_digest = try handoff.retained_copy.hashRetained(ctx.io, reader.controller, max_tool_bytes, flag(ctx));
    const supervisor_digest = try handoff.retained_copy.hashRetained(ctx.io, reader.supervisor, max_tool_bytes, flag(ctx));
    if (!equal(&controller_digest, &supervisor_digest) or reader.controller.file_snapshot.size != reader.supervisor.file_snapshot.size)
        return error.ImportSupervisorChanged;
}
fn absent(io: std.Io, path: []const u8) !void {
    const parent = try files.FileParent.open(io, path, .private);
    defer parent.close(io);
    const existing = parent.openFile(io) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    existing.close(io);
    return error.PathAlreadyExists;
}
fn inside(path: []const u8, root: []const u8) bool {
    return equal(path, root) or (path.len > root.len and std.mem.startsWith(u8, path, root) and path[root.len] == '/');
}
fn equal(first: []const u8, second: []const u8) bool {
    return std.mem.eql(u8, first, second);
}
fn flag(ctx: types.Context) ?*const std.atomic.Value(bool) {
    return if (ctx.signal) |signal| signal.flag() else null;
}
fn hexBytes(a: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const result = try a.alloc(u8, try std.math.mul(usize, bytes.len, 2));
    for (bytes, 0..) |byte, index| {
        const digits = "0123456789abcdef";
        result[2 * index] = digits[byte >> 4];
        result[2 * index + 1] = digits[byte & 15];
    }
    return result;
}
fn canonical(a: std.mem.Allocator, value: anytype) ![]u8 {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(raw);
    var document = try core.contracts.Document.parse(a, raw, contracts.json_limits);
    defer document.deinit();
    return document.canonicalAlloc(a);
}

const TestFixture = struct {
    a: std.mem.Allocator,
    io: std.Io,
    parent: std.Io.Dir,
    root: std.Io.Dir,
    path: []const u8,
    name: []const u8,

    fn init(a: std.mem.Allocator, io: std.Io) !TestFixture {
        const parent = try std.Io.Dir.openDirAbsolute(io, @import("test_options").fixture_root, .{});
        errdefer parent.close(io);
        const name = try std.fmt.allocPrint(a, "plan-guards-{d}", .{std.os.linux.getpid()});
        errdefer a.free(name);
        try parent.createDir(io, name, .fromMode(0o700));
        errdefer parent.deleteTree(io, name) catch @panic("plan guard fixture cleanup failed");
        const root = try parent.openDir(io, name, .{ .iterate = true });
        errdefer root.close(io);
        return .{
            .a = a,
            .io = io,
            .parent = parent,
            .root = root,
            .name = name,
            .path = try std.fs.path.join(a, &.{ @import("test_options").fixture_root, name }),
        };
    }
    fn deinit(self: TestFixture) void {
        self.root.close(self.io);
        self.parent.deleteTree(self.io, self.name) catch @panic("plan guard fixture cleanup failed");
        self.parent.close(self.io);
        self.a.free(self.path);
        self.a.free(self.name);
    }
};
fn project(comptime T: type, value: anytype) T {
    var result: T = undefined;
    inline for (std.meta.fields(T)) |field| @field(result, field.name) = @field(value, field.name);
    return result;
}
fn testMetadata(value: types.Plan) candidate.Metadata {
    // A pure constructor view only: never an opaque owner or import proof.
    return .{
        .source = .imported_product,
        .reader = undefined,
        .scope = .{
            .version = 2,
            .purpose = contracts.policy.profile,
            .attempt_id = value.attempt_id,
            .subscription = value.subscription,
            .prefix = value.prefix,
            .source_revision = value.source_revision,
            .source_tree = value.source_tree,
            .identity = project(candidate.Identity, value.identity),
            .os_vhd = project(candidate.Artifact, value.os_vhd),
            .bundle = project(candidate.Artifact, value.bundle),
        },
        .candidate = project(candidate.Artifact, value.candidate),
        .provenance = project(candidate.Provenance, .{
            .public_bundle = project(candidate.Artifact, value.public_bundle),
            .transport = project(candidate.Artifact, value.transport),
            .qcow2 = project(candidate.Artifact, value.qcow2),
            .run = project(@TypeOf(@as(candidate.Provenance, undefined).run), value.run),
            .lineage = project(@TypeOf(@as(candidate.Provenance, undefined).lineage), value.lineage),
            .artifact_id = value.artifact_id,
            .inner_zip_sha256 = value.inner_zip_sha256,
            .container_digest = value.container_digest,
        }),
    };
}
fn testPlan(a: std.mem.Allocator) !types.Plan {
    var document = try contracts.parseCanonical(a, @embedFile("goldens/contracts.json"));
    defer document.deinit();
    return (try records.parse(types.Plan, a, document.value().object.get("canonical_records").?.object.get("plan").?.string)).value;
}

test "plan command binds exact imported selectors and frozen no-authority policy without manufacturing an owner" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const value = try testPlan(a);
    var metadata = testMetadata(value);
    const command: types.PlanCommand = .{
        .bundle = value.public_bundle.path,
        .candidate_output = value.candidate.path,
        .campaign_id = value.campaign_id,
        .subscription = value.subscription,
        .prefix = value.prefix,
        .attempt_id = value.attempt_id,
        .ledger_id = value.ledger.ledger_id,
        .created_unix = value.created_unix,
        .maximum_authorized_cost_microusd = value.cost.maximum_authorized,
    };
    const bound = try bindCommand(a, std.testing.io, command, metadata);
    try std.testing.expectEqualStrings(value.campaign_id, bound.campaign_id);
    try std.testing.expectEqual(value.created_unix, bound.created_unix);
    metadata.source = .private_bundle;
    try std.testing.expectError(error.ImportedProductRequired, bindCommand(a, std.testing.io, command, metadata));
    metadata = testMetadata(value);
    metadata.scope.version = 1;
    try std.testing.expectError(error.Version2Required, bindCommand(a, std.testing.io, command, metadata));
    inline for (std.meta.fields(@TypeOf(metadata.scope.approval))) |field| {
        metadata = testMetadata(value);
        @field(metadata.scope.approval, field.name) = if (comptime field.type == bool) true else 1;
        try std.testing.expectError(error.AuthorityNotAllowed, bindCommand(a, std.testing.io, command, metadata));
    }
    inline for (.{ "runtime_seconds", "cleanup_seconds", "operation_seconds", "poll_seconds" }) |field| {
        metadata = testMetadata(value);
        @field(metadata.scope, field) -= 1;
        try std.testing.expectError(error.InvalidBudget, bindCommand(a, std.testing.io, command, metadata));
    }
    metadata = testMetadata(value);
    inline for (.{ "attempt_id", "subscription", "prefix", "candidate_output", "bundle" }) |field| {
        var changed = command;
        @field(changed, field) = if (comptime equal(field, "attempt_id") or equal(field, "subscription"))
            "00000000-0000-4000-8000-000000000999"
        else
            "/wrong-input";
        try std.testing.expectError(error.WrongCandidate, bindCommand(a, std.testing.io, changed, metadata));
    }
    for ([_]types.Integer{ contracts.policy.estimated_cost_upper_bound_microusd - 1, contracts.policy.repository_maximum_cost_microusd + 1 }) |cost| {
        var changed = command;
        changed.maximum_authorized_cost_microusd = cost;
        try std.testing.expectError(error.InvalidCost, bindCommand(a, std.testing.io, changed, metadata));
    }
    for ([_]types.Integer{ -1, 0 }) |time| {
        var changed = command;
        changed.created_unix = time;
        try std.testing.expectError(error.InvalidInteger, bindCommand(a, std.testing.io, changed, metadata));
    }
}

test "plan outputs reserve every create-only name and reject unsafe paths modes and physical input overlap" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const fixture = try TestFixture.init(std.testing.allocator, io);
    defer fixture.deinit();
    const command: types.PlanCommand = .{
        .output = try std.fs.path.join(a, &.{ fixture.path, "plan.json" }),
        .approval_template = try std.fs.path.join(a, &.{ fixture.path, "template.json" }),
    };
    const paths = try Paths.init(a, command);
    try paths.fresh(io);
    var collision = command;
    collision.approval_template = command.output;
    try std.testing.expectError(error.OutputCollision, Paths.init(a, collision));
    collision.approval_template = paths.validation;
    try std.testing.expectError(error.OutputCollision, Paths.init(a, collision));
    collision.output = try std.fs.path.join(a, &.{ fixture.path, ".writer.lock" });
    try std.testing.expectError(error.OutputCollision, Paths.init(a, collision));
    collision.output = "relative.json";
    try std.testing.expectError(error.UnsafePath, Paths.init(a, collision));
    const ctx: types.Context = .{ .allocator = a, .io = io };
    try std.testing.expectError(error.OutputInsideInput, physicalSeparation(ctx, paths, &.{fixture.path}));
    const existing = try fixture.root.createFile(io, "plan.json", .{ .permissions = .fromMode(0o600) });
    existing.close(io);
    try std.testing.expectError(error.PathAlreadyExists, paths.fresh(io));
    try fixture.root.deleteFile(io, "plan.json");
    try fixture.root.symLink(io, "absent", "plan.json", .{});
    try std.testing.expectError(error.UnsafeFile, paths.fresh(io));
    try fixture.root.deleteFile(io, "plan.json");
    const public = try fixture.root.createFile(io, "plan.json", .{ .permissions = .fromMode(0o644) });
    defer public.close(io);
    if (std.os.linux.errno(std.os.linux.fchmod(public.handle, 0o644)) != .SUCCESS) return error.FixtureMode;
    try std.testing.expectError(error.UnsafeFile, paths.fresh(io));
}

test "plan ledger proposal is read-only and detects changes independently of candidate ownership" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const fixture = try TestFixture.init(std.testing.allocator, io);
    defer fixture.deinit();
    const ctx: types.Context = .{ .allocator = a, .io = io };
    const id = "00000000-0000-4000-8000-000000000001";
    var ledger = try Ledger.open(ctx, a, fixture.path, id, id);
    defer ledger.directory.close(io);
    try ledger.verify(ctx, a);
    try std.testing.expect(ledger.binding.initialization_required);
    var entries = fixture.root.iterate();
    try std.testing.expectEqual(@as(?std.Io.Dir.Entry, null), try entries.next(io));
    const changed = try fixture.root.createFile(io, "changed.json", .{ .permissions = .fromMode(0o600) });
    defer changed.close(io);
    try changed.writeStreamingAll(io, "{}\n");
    try std.testing.expectError(error.LedgerChanged, ledger.verify(ctx, a));
}

test "plan rejects a real retained validator substituted for the executing controller" {
    const validator_path = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, @import("test_options").validator, std.testing.allocator);
    defer std.testing.allocator.free(validator_path);
    var validator = try files.RetainedFile.open(std.testing.io, validator_path, .tool);
    defer validator.close(std.testing.io);
    const reader: candidate.ReaderContext = .{
        .io = std.testing.io,
        .repository = "",
        .git = undefined,
        .controller = &validator,
        .supervisor = &validator,
        .validator = &validator,
        .reader_revision = "",
        .reader_tree = "",
        .validation_output = "",
        .validation_record = undefined,
        .validation_log = undefined,
    };
    try std.testing.expectError(error.ImportSupervisorChanged, readerController(.{ .allocator = std.testing.allocator, .io = std.testing.io }, reader));
}

test "plan pins output parents before slow custody and refuses replacement without creating output" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try TestFixture.init(a, io);
    defer fixture.deinit();
    const path = try std.fs.path.join(a, &.{ fixture.path, "plan.json" });
    defer a.free(path);
    const parent = try Parent.open(io, path);
    defer parent.retained.close(io);
    try parent.verify(io);
    const moved = try std.fmt.allocPrint(a, "{s}-moved", .{fixture.name});
    defer a.free(moved);
    try fixture.parent.rename(fixture.name, fixture.parent, moved, io);
    defer fixture.parent.deleteTree(io, moved) catch @panic("replaced plan parent fixture cleanup failed");
    try fixture.parent.createDir(io, fixture.name, .fromMode(0o700));
    try std.testing.expectError(error.OutputParentChanged, parent.verify(io));
    try absent(io, path);
}

test "plan preserves initialized ledger identity and state instead of initializing or replacing it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const fixture = try TestFixture.init(std.testing.allocator, io);
    defer fixture.deinit();
    const directory = try files.Directory.open(io, fixture.path);
    defer directory.close(io);
    const id = "00000000-0000-4000-8000-000000000001";
    const proposed = "00000000-0000-4000-8000-000000000002";
    const history = try fixture.root.createFile(io, "history.json", .{ .permissions = .fromMode(0o600) });
    defer history.close(io);
    try history.writeStreamingAll(io, "{}\n");
    const initial = try compute.ledgerStateDigest(a, io, directory);
    const bytes = try compute.ledgerMarkerBytes(a, id, id, &initial);
    const marker = try fixture.root.createFile(io, compute.ledger_marker_name, .{ .permissions = .fromMode(0o600) });
    defer marker.close(io);
    try marker.writeStreamingAll(io, bytes);
    try marker.sync(io);
    try fixture.root.createDir(io, compute.ledger_sentinel_name, .fromMode(0o700));
    const ctx: types.Context = .{ .allocator = a, .io = io };
    const binding = try compute.ledgerProposal(a, io, fixture.path, id, proposed);
    const before = try currentLedgerDigest(ctx, a, directory, fixture.path, binding);
    var ledger = try Ledger.open(ctx, a, fixture.path, id, proposed);
    defer ledger.directory.close(io);
    try std.testing.expect(!ledger.binding.initialization_required);
    try std.testing.expectEqualStrings(id, ledger.binding.ledger_id);
    try ledger.verify(ctx, a);
    try std.testing.expectEqualStrings(&before, &try currentLedgerDigest(ctx, a, directory, fixture.path, binding));
    try history.writePositionalAll(io, "[]\n", 0);
    try std.testing.expectError(error.LedgerChanged, ledger.verify(ctx, a));
}
