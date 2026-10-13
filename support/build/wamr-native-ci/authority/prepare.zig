// SPDX-License-Identifier: BSD-3-Clause
//! Source-only retained preparation. A physical manifest precedes validation;
//! only complete isolated probes permit publication of azure-runtime.json.
const std = @import("std");
const core = @import("hyperv_core");
const types = @import("types.zig");
const records = @import("records.zig");
const tx = @import("transaction.zig");
const copy = @import("runtime_copy.zig");
const probes = @import("runtime_probes.zig");
const helper = @import("prepare_helper.zig");
const files = core.private_files;
const retained_copy = @import("wamr_handoff").retained_copy;
const runtime = types.runtime;
const linux = std.os.linux;

pub const Publications = struct {
    copy: files.CommitStatus = .not_committed,
    manifest: files.CommitStatus = .not_committed,
    pending: files.CommitStatus = .not_committed,
    validation: files.CommitStatus = .not_committed,
    output: files.CommitStatus = .not_committed,
    failure: files.CommitStatus = .not_committed,
};
pub const Diagnostic = struct {
    phase: types.Phase,
    err: anyerror,
    publications: Publications = .{},
    failures: core.diagnostics.Failures = .{},
    probes: ?probes.Failure = null,
    helper_cleanup_complete: bool = true,
    recording_error: ?anyerror = null,
    native_validation: ?NativeEvidence = null,
};
pub const NativeEvidence = struct {
    primary: core.process.CommandPrimary,
    cleanup: core.process.CommandCleanup,
    cleanup_complete: bool,
    termination: ?std.process.Child.Term,
    stdout_status: core.process.CommandStreamStatus,
    stderr_status: core.process.CommandStreamStatus,
    executable: core.process.ExecutableIdentity,
    executable_stable: bool,
    descendants: core.process.CommandDescendants,
    cancellation_observed: bool,
    primary_deadline_reached: bool,
    started_ns: u64,
    primary_completed_ns: u64,
    completed_ns: u64,
    stdout_bytes: usize,
    stderr_bytes: usize,
    stdout_sha256: [64]u8,
    stderr_sha256: [64]u8,
    validator_sha256: [64]u8,
    runtime_document_sha256: [64]u8,
    freshness: ?anyerror,
};
pub const Outcome = union(enum) { success: *Prepared, refused: Diagnostic, poisoned: Diagnostic };
pub const Result = struct {
    contract: runtime.Contract,
    manifest: types.Artifact,
    runtime_document: types.Artifact,
    validation: types.Artifact,
    evidence: probes.Evidence,
    native_validations: [2]NativeEvidence,
};
pub const Prepared = opaque {
    fn state(self: *Prepared) *State {
        return @ptrCast(@alignCast(self));
    }
    pub fn revalidate(self: *Prepared) !void {
        const owner = self.state();
        try owner.check();
        try runtime.verify(owner.ctx.allocator, owner.ctx.io, owner.contract.?);
        try owner.check();
    }
    pub fn result(self: *Prepared) !Result {
        try self.revalidate();
        const owner = self.state();
        return .{
            .contract = owner.contract.?,
            .manifest = owner.manifest.?.artifact(),
            .runtime_document = owner.output.?.artifact(),
            .validation = owner.validation.?.artifact(),
            .evidence = owner.evidence.?,
            .native_validations = .{ owner.native_validations[0].?, owner.native_validations[1].? },
        };
    }
    pub fn deinit(self: *Prepared) void {
        self.state().deinit();
    }
};

const State = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    ctx: types.Context,
    deadline: core.process.Deadline,
    stage: ?copy.Stage = null,
    validator: ?files.RetainedFile = null,
    validator_digest: [64]u8 = undefined,
    manifest: ?tx.Record = null,
    pending: ?tx.Record = null,
    validation: ?tx.Record = null,
    output: ?tx.Record = null,
    commitments: copy.Commitments = undefined,
    contract: ?runtime.Contract = null,
    evidence: ?probes.Evidence = null,
    native_validations: [2]?NativeEvidence = .{ null, null },
    native_runs: u8 = 0,
    phase: types.Phase = .inputs,
    publications: Publications = .{},
    failures: core.diagnostics.Failures = .{},
    probe_failure: ?probes.Failure = null,
    helper_cleanup_complete: bool = true,
    recording_error: ?anyerror = null,
    pending_path: []const u8 = "",
    validation_path: []const u8 = "",
    output_path: []const u8 = "",
    failure_path: []const u8 = "",

    fn deinit(self: *State) void {
        const allocator = self.allocator;
        if (self.output) |*record| record.deinit();
        if (self.validation) |*record| record.deinit();
        if (self.pending) |*record| record.deinit();
        if (self.manifest) |*record| record.deinit();
        if (self.validator) |*file| file.close(self.ctx.io);
        if (self.stage) |*stage| stage.deinit();
        self.arena.deinit();
        allocator.destroy(self);
    }
    fn check(self: *State) !void {
        try self.ctx.io.checkCancel();
        try retained_copy.checkCancellation(if (self.ctx.signal) |s| s.flag() else null);
        if (try self.deadline.expired()) return error.BudgetExhausted;
        try self.stage.?.revalidate();
        if (self.validator) |*file| {
            const digest = try retained_copy.hashRetained(self.ctx.io, file, 128 * 1024 * 1024, if (self.ctx.signal) |s| s.flag() else null);
            if (!std.mem.eql(u8, &digest, &self.validator_digest)) return error.ValidatorChanged;
        }
        inline for (.{ "manifest", "pending", "validation", "output" }) |field|
            if (@field(self, field)) |*record| try record.revalidate(self.ctx.signal);
        try retained_copy.checkCancellation(if (self.ctx.signal) |s| s.flag() else null);
        if (try self.deadline.expired()) return error.BudgetExhausted;
    }
    fn barrierCheck(raw: *anyopaque) !void {
        try (@as(*State, @ptrCast(@alignCast(raw)))).check();
    }
    fn barrier(self: *State) tx.Barrier {
        return .{ .context = self, .check = barrierCheck };
    }
    fn publish(self: *State, path: []const u8, bytes: []const u8, status: *files.CommitStatus) !tx.Record {
        var transaction = try tx.Transaction.init(self.ctx, path);
        defer transaction.deinit();
        const outcome = transaction.publish(bytes, self.barrier());
        status.* = transaction.publication;
        self.failures = tx.combineFailures(self.failures, transaction.failures);
        switch (outcome) {
            .success => {},
            .refused, .poisoned => |diagnostic| return diagnostic.err,
        }
        const result = transaction.published.?;
        transaction.published = null;
        return result;
    }
    fn publishManifest(self: *State) !void {
        try self.check();
        const inputs = try self.stage.?.manifestInputs();
        const parent = try files.FileParent.open(self.ctx.io, inputs.manifest.path, .private);
        defer parent.close(self.ctx.io);
        var lock = try (files.Directory{ .dir = parent.directory }).lock(self.ctx.io);
        defer lock.close(self.ctx.io);
        try self.check();
        const file = try parent.directory.createFile(self.ctx.io, parent.name, .{
            .exclusive = true,
            .read = true,
            .permissions = .fromMode(0o600),
        });
        defer file.close(self.ctx.io);
        self.publications.manifest = .visible_not_durable;
        const identity = try files.snapshot(file);
        if (identity.mode & linux.S.IFMT != linux.S.IFREG or
            identity.mode & 0o7777 != 0o600 or identity.uid != linux.geteuid() or
            identity.nlink != 1 or identity.size != 0)
            return error.UnsafeManifest;
        var expected = identity;
        var offset: usize = 0;
        while (offset < inputs.bytes.len) {
            try self.checkManifest(file, parent, expected);
            const end = @min(inputs.bytes.len, offset + 64 * 1024);
            const written = try file.writePositional(self.ctx.io, &.{inputs.bytes[offset..end]}, offset);
            if (written == 0) return error.ManifestWriteNoProgress;
            if (written > end - offset) return error.InvalidManifestWriteProgress;
            offset += written;
            expected = try files.snapshot(file);
            if (expected.ino != identity.ino or expected.dev_major != identity.dev_major or
                expected.dev_minor != identity.dev_minor or expected.mode != identity.mode or
                expected.uid != identity.uid or expected.nlink != identity.nlink or
                expected.size != offset)
                return error.ManifestChanged;
            try self.checkManifest(file, parent, expected);
        }
        try file.sync(self.ctx.io);
        try self.checkManifest(file, parent, expected);
        if (linux.errno(linux.fsync(parent.directory.handle)) != .SUCCESS) return error.ManifestSyncFailed;
        self.publications.manifest = .durable;
        try self.checkManifest(file, parent, expected);
        self.manifest = try tx.Record.open(self.ctx, inputs.manifest.path, runtime.max_manifest_bytes);
        self.commitments = try inputs.bindManifest(self.ctx, &self.manifest.?.file);
        try self.check();
    }
    fn checkManifest(self: *State, file: std.Io.File, parent: files.FileParent, expected: files.Snapshot) !void {
        try self.check();
        if (!files.sameSnapshot(expected, try files.snapshot(file))) return error.ManifestChanged;
        const named = try parent.openFile(self.ctx.io);
        defer named.close(self.ctx.io);
        if (!files.sameSnapshot(expected, try files.snapshot(named))) return error.ManifestChanged;
    }
    fn validateNative(self: *State, path: []const u8) !void {
        try self.check();
        const executable = try core.process.Executable.fromFile(self.ctx.io, self.validator.?.file);
        defer executable.close(self.ctx.io);
        const cwd = try files.openDirectory(self.ctx.io, (try self.stage.?.layout()).output, .private);
        defer cwd.close(self.ctx.io);
        var env = std.process.Environ.Map.init(self.ctx.allocator);
        defer env.deinit();
        try env.put("LC_ALL", "C");
        const now = try core.process.monotonicNanoseconds();
        const primary: core.process.Deadline = .{ .expires_ns = @min(self.deadline.expires_ns, try std.math.add(u64, now, 300 * std.time.ns_per_s)) };
        var supervised = try tx.supervise(self.ctx, .{
            .executable = executable,
            .argv = &.{ self.validator.?.path, "azure-runtime", path },
            .cwd = cwd,
            .environment = &env,
            .primary_deadline = primary,
            .cleanup_deadline = .{ .expires_ns = try std.math.add(u64, primary.expires_ns, 10 * std.time.ns_per_s) },
            .capture = .separate,
            .limits = .{ .stdout_bytes = 1024 * 1024, .stderr_bytes = 1024 * 1024 },
        }, self.barrier());
        defer supervised.deinit(self.ctx.allocator);
        const result = supervised.result;
        if (self.native_runs >= self.native_validations.len) return error.NativeValidationSpent;
        self.native_validations[self.native_runs] = .{
            .primary = result.primary,
            .cleanup = result.cleanup,
            .cleanup_complete = result.cleanup_complete,
            .termination = result.termination,
            .stdout_status = result.stdout_status,
            .stderr_status = result.stderr_status,
            .executable = result.executable,
            .executable_stable = result.executable_stable,
            .descendants = result.descendants,
            .cancellation_observed = result.cancellation_observed,
            .primary_deadline_reached = result.primary_deadline_reached,
            .started_ns = result.started_ns,
            .primary_completed_ns = result.primary_completed_ns,
            .completed_ns = result.completed_ns,
            .stdout_bytes = result.stdout.len,
            .stderr_bytes = result.stderr.len,
            .stdout_sha256 = std.fmt.bytesToHex(tx.hash(result.stdout), .lower),
            .stderr_sha256 = std.fmt.bytesToHex(tx.hash(result.stderr), .lower),
            .validator_sha256 = self.validator_digest,
            .runtime_document_sha256 = self.pending.?.sha256,
            .freshness = supervised.freshness,
        };
        self.native_runs += 1;
        if (!supervised.succeeded()) {
            self.failures.primary = .{ .stage = .inspection, .category = .invalid_input };
            if (!supervised.result.cleanup_complete)
                self.failures.cleanup = .{ .stage = .inspection, .category = .cleanup_failed };
            return supervised.freshness orelse error.NativeRuntimeValidationFailed;
        }
    }
    fn perform(self: *State, request: types.PrepareRuntime, discovery_input: probes.DiscoveryInput, hooks: ?*const Test.Hooks) !void {
        if (!std.mem.eql(u8, request.az_python, discovery_input.interpreter.path))
            return error.DiscoveryInterpreterMismatch;
        try files.absoluteFilePath(request.validator);
        const interpreter_digest = try retained_copy.hashRetained(self.ctx.io, discovery_input.interpreter, copy.canonicalLimits().file_bytes, if (self.ctx.signal) |s| s.flag() else null);
        var discovery = try probes.discover(self.ctx, discovery_input);
        defer discovery.deinit();
        if (@import("builtin").is_test) if (hooks) |selected| if (selected.after_discovery) |action| try action(selected.context);
        self.stage = try copy.Stage.initNamed(self.ctx, request, discovery.inventory, discovery.names);
        try self.stage.?.bindInterpreter(discovery_input.interpreter, interpreter_digest);
        const owned_validator_path = try self.ctx.allocator.dupe(u8, request.validator);
        self.validator = try files.RetainedFile.open(self.ctx.io, owned_validator_path, .tool);
        self.validator_digest = try retained_copy.hashRetained(self.ctx.io, &self.validator.?, 128 * 1024 * 1024, if (self.ctx.signal) |s| s.flag() else null);
        self.phase = .construction;
        switch (self.stage.?.copyStage()) {
            .staged => {},
            .refused, .poisoned => |diagnostic| {
                self.publications.copy = diagnostic.publication;
                self.failures = tx.combineFailures(self.failures, diagnostic.failures);
                return diagnostic.err;
            },
        }
        self.publications.copy = self.stage.?.publication;
        const layout = try self.stage.?.layout();
        self.pending_path = try std.fs.path.join(self.ctx.allocator, &.{ layout.output, "azure-runtime.pending.json" });
        self.validation_path = try std.fs.path.join(self.ctx.allocator, &.{ layout.output, "azure-runtime.validation.json" });
        self.output_path = try std.fs.path.join(self.ctx.allocator, &.{ layout.output, "azure-runtime.json" });
        self.failure_path = try std.fs.path.join(self.ctx.allocator, &.{ layout.output, "azure-runtime.failure.json" });
        self.phase = .publication;
        try self.publishManifest();
        const inputs = try self.stage.?.manifestInputs();
        self.contract = .{
            .schema = "uk.wamr.azure-cli-runtime-closure",
            .version = 1,
            .canonicalization = @import("contracts.zig").canonicalization,
            .root = layout.root,
            .python_version = layout.python_version,
            .extensions = layout.extensions,
            .launcher = inputs.launcher,
            .interpreter = inputs.interpreter,
            .dynamic_loader = inputs.dynamic_loader,
            .manifest = inputs.manifest,
            .limits = copy.canonicalLimits(),
            .observed = inputs.observed,
            .content_sha256 = &self.commitments.content_sha256,
            .metadata_sha256 = &self.commitments.metadata_sha256,
            .parents_sha256 = &self.commitments.parents_sha256,
            .loader_dependencies = inputs.loader_dependencies,
            .commands = &runtime.commands,
            .isolation = .{
                .python_home = .closure_root,
                .module_layout = .flat_python_home_v1,
                .extensions = .closure_empty,
                .dynamic_extension_install = .disabled,
                .user_site = .disabled,
                .site_import = .disabled,
                .bytecode_writes = .disabled,
                .path_environment = .forbidden,
                .startup_hooks = .forbidden,
                .loader_environment = .retained_readonly_root,
                .host_loader_fallback = .forbidden,
                .package_restore = .forbidden_after_custody,
            },
        };
        const bytes = try records.runtimeBytes(self.ctx.allocator, self.contract.?);
        self.pending = try self.publish(self.pending_path, bytes, &self.publications.pending);
        self.phase = .validation;
        try runtime.verify(self.ctx.allocator, self.ctx.io, self.contract.?);
        try self.validateNative(self.pending_path);
        const copied: probes.CopiedInput = .{
            .root = try self.stage.?.root(),
            .layout = layout,
            .contract = self.contract.?,
            .barrier = self.barrier(),
        };
        _ = try probes.inspectCopied(self.ctx, copied);
        const isolated = helper.run(self.ctx, copied, self.deadline);
        self.helper_cleanup_complete = isolated.cleanup_complete;
        switch (isolated.result) {
            .complete => |evidence| self.evidence = evidence,
            .refused => |diagnostic| {
                self.probe_failure = diagnostic;
                self.failures.primary = .{ .stage = .process_run, .category = .child_failed };
                if (!isolated.cleanup_complete)
                    self.failures.cleanup = .{ .stage = .process_cleanup, .category = .cleanup_failed };
                return diagnostic.cause;
            },
        }
        if (!isolated.cleanup_complete) return error.PreparationHelperCleanupFailed;
        try self.check();
        try runtime.verify(self.ctx.allocator, self.ctx.io, self.contract.?);
        try self.validateNative(self.pending_path);
        const summary = try canonicalSummary(self.ctx.allocator, .{
            .schema = "uk.wamr.azure-runtime-source-validation",
            .version = @as(u8, 1),
            .complete = true,
            .command_probes = runtime.commands.len,
            .completed_steps = self.evidence.?.probes.len,
            .helper_cleanup_complete = isolated.cleanup_complete,
            .content_sha256 = self.contract.?.content_sha256,
            .metadata_sha256 = self.contract.?.metadata_sha256,
            .parents_sha256 = self.contract.?.parents_sha256,
            .manifest = self.manifest.?.artifact(),
            .pending = self.pending.?.artifact(),
            .native_validations = .{ nativeSummary(self.native_validations[0].?), nativeSummary(self.native_validations[1].?) },
        });
        self.validation = try self.publish(self.validation_path, summary, &self.publications.validation);
        self.phase = .publication;
        self.output = try self.publish(self.output_path, bytes, &self.publications.output);
        self.phase = .final_revalidation;
        try types.compute.verifyAzureRuntime(self.ctx.allocator, self.ctx.io, self.output_path);
        try self.check();
    }
    fn failure(self: *State, err: anyerror) Diagnostic {
        var diagnostic: Diagnostic = .{
            .phase = self.phase,
            .err = err,
            .publications = self.publications,
            .failures = self.failures,
            .probes = self.probe_failure,
            .helper_cleanup_complete = self.helper_cleanup_complete,
            .native_validation = if (self.native_runs == 0) null else self.native_validations[self.native_runs - 1],
        };
        // No safe output exists before copy. Never write diagnostic paths inside
        // a refused input or reconstruct a missing stage from its path.
        if (self.failure_path.len != 0) self.recordFailure(diagnostic) catch |recording| {
            diagnostic.recording_error = recording;
        };
        diagnostic.publications = self.publications;
        diagnostic.failures = self.failures;
        return diagnostic;
    }
    fn recordFailure(self: *State, diagnostic: Diagnostic) !void {
        var recording_ctx = self.ctx;
        recording_ctx.signal = null;
        var recording: RecordingBarrier = .{
            .owner = self,
            .deadline = try core.process.Deadline.afterMilliseconds(15_000),
        };
        recording_ctx.publication_deadline = recording.deadline;
        try RecordingBarrier.check(&recording);
        const bytes = try canonicalSummary(recording_ctx.allocator, .{
            .schema = "uk.wamr.azure-runtime-source-failure",
            .version = @as(u8, 1),
            .phase = @tagName(diagnostic.phase),
            .err = @errorName(diagnostic.err),
            .publications = diagnostic.publications,
            .failures = .{
                .schema_version = @as(u8, 1),
                .primary = diagnostic.failures.primary,
                .cleanup = diagnostic.failures.cleanup,
                .recording = diagnostic.failures.recording,
            },
            .helper_cleanup_complete = diagnostic.helper_cleanup_complete,
            .completed_steps = if (diagnostic.probes) |failure_| failure_.completed_steps else @as(u8, 0),
            .native_validation = if (diagnostic.native_validation) |evidence| nativeSummary(evidence) else null,
        });
        // Earlier copy/manifest/record transactions have released their locks.
        // Original failures belong in the payload, not this independent lane.
        var transaction = try tx.Transaction.init(recording_ctx, self.failure_path);
        defer transaction.deinit();
        const outcome = transaction.publish(bytes, .{ .context = &recording, .check = RecordingBarrier.check });
        self.publications.failure = transaction.publication;
        self.failures = tx.combineFailures(self.failures, transaction.failures);
        switch (outcome) {
            .success => {},
            .refused, .poisoned => |failure_| return failure_.err,
        }
    }
};

const RecordingBarrier = struct {
    owner: *State,
    deadline: core.process.Deadline,

    fn check(raw: *anyopaque) !void {
        const self: *RecordingBarrier = @ptrCast(@alignCast(raw));
        try self.owner.ctx.io.checkCancel();
        if (try self.deadline.expired()) return error.DeadlineExceeded;
        const directory = try files.openDirectory(self.owner.ctx.io, (try self.owner.stage.?.layout()).output, .private);
        defer directory.close(self.owner.ctx.io);
        if (!retained_copy.sameDirectory(
            try retained_copy.directorySnapshot(directory),
            try retained_copy.directorySnapshot(try self.owner.stage.?.outputDirectory()),
        )) return error.OutputParentChanged;
        if (try self.deadline.expired()) return error.DeadlineExceeded;
    }
};

fn nativeSummary(evidence: NativeEvidence) struct {
    process: struct {
        primary: core.process.CommandPrimary,
        cleanup: core.process.CommandCleanup,
        cleanup_complete: bool,
        stdout_status: core.process.CommandStreamStatus,
        stderr_status: core.process.CommandStreamStatus,
        executable: core.process.ExecutableIdentity,
        executable_stable: bool,
        descendants: core.process.CommandDescendants,
        cancellation_observed: bool,
        primary_deadline_reached: bool,
    },
    times: [3]u64,
    stream_bytes: [2]usize,
    stream_sha256: [2][64]u8,
    validator_sha256: [64]u8,
    runtime_document_sha256: [64]u8,
    freshness: ?[]const u8,
} {
    return .{
        .process = .{
            .primary = evidence.primary,
            .cleanup = evidence.cleanup,
            .cleanup_complete = evidence.cleanup_complete,
            .stdout_status = evidence.stdout_status,
            .stderr_status = evidence.stderr_status,
            .executable = evidence.executable,
            .executable_stable = evidence.executable_stable,
            .descendants = evidence.descendants,
            .cancellation_observed = evidence.cancellation_observed,
            .primary_deadline_reached = evidence.primary_deadline_reached,
        },
        .times = .{ evidence.started_ns, evidence.primary_completed_ns, evidence.completed_ns },
        .stream_bytes = .{ evidence.stdout_bytes, evidence.stderr_bytes },
        .stream_sha256 = .{ evidence.stdout_sha256, evidence.stderr_sha256 },
        .validator_sha256 = evidence.validator_sha256,
        .runtime_document_sha256 = evidence.runtime_document_sha256,
        .freshness = if (evidence.freshness) |err| @errorName(err) else null,
    };
}

fn canonicalSummary(a: std.mem.Allocator, value: anytype) ![]u8 {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(raw);
    var document = try core.contracts.Document.parse(a, raw, @import("contracts.zig").json_limits);
    defer document.deinit();
    return document.canonicalAlloc(a);
}

pub fn run(ctx: types.Context, request: types.PrepareRuntime, discovery: probes.DiscoveryInput) Outcome {
    return runImpl(ctx, request, discovery, null);
}

fn runImpl(ctx: types.Context, request: types.PrepareRuntime, discovery: probes.DiscoveryInput, hooks: ?*const Test.Hooks) Outcome {
    const owner = ctx.allocator.create(State) catch |err|
        return .{ .refused = .{ .phase = .inputs, .err = err } };
    owner.* = .{
        .allocator = ctx.allocator,
        .arena = std.heap.ArenaAllocator.init(ctx.allocator),
        .ctx = ctx,
        .deadline = core.process.Deadline.afterMilliseconds(900_000) catch |err| {
            ctx.allocator.destroy(owner);
            return .{ .refused = .{ .phase = .inputs, .err = err } };
        },
    };
    owner.ctx.allocator = owner.arena.allocator();
    core.process.initialize() catch |err| {
        owner.deinit();
        return .{ .refused = .{ .phase = .inputs, .err = err } };
    };
    owner.perform(request, discovery, hooks) catch |err| {
        const diagnostic = owner.failure(err);
        const published = diagnostic.publications.copy != .not_committed or
            diagnostic.publications.manifest != .not_committed or diagnostic.publications.output != .not_committed;
        owner.deinit();
        return if (published) .{ .poisoned = diagnostic } else .{ .refused = diagnostic };
    };
    return .{ .success = @ptrCast(owner) };
}

pub const Test = struct {
    pub const Hooks = struct {
        context: *anyopaque,
        after_discovery: ?*const fn (*anyopaque) anyerror!void = null,
    };
    pub fn run(ctx: types.Context, request: types.PrepareRuntime, discovery: probes.DiscoveryInput, hooks: *const Hooks) Outcome {
        if (!@import("builtin").is_test) @compileError("Preparation phase faults are test-only");
        return runImpl(ctx, request, discovery, hooks);
    }
};
