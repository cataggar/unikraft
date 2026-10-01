// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const files = core.private_files;
const controller = @import("wamr_controller");
const accepted_run = controller.accepted_run;
const retained_copy = @import("retained_copy.zig");
const contracts = @import("contracts.zig");
const layout = @import("layout.zig");
const profile = @import("profile.zig");

pub const Phase = enum {
    invocation,
    runtime_opened,
    accepted_run_pinned,
    output_reserved,
    artifacts_copied,
    boots_copied,
    evidence_copied,
    source_revalidated,
    handoff_staged,
    handoff_validated,
    handoff_published,
};

pub const Diagnostic = struct {
    phase: Phase,
    err: anyerror,
};

pub fn Outcome(comptime T: type) type {
    return union(enum) {
        success: T,
        refused: Diagnostic,
        poisoned: Diagnostic,
    };
}

pub const PublishFault = enum { none, before_file_sync, before_parent_sync };

pub const Faults = struct {
    copy: retained_copy.TestFault = .none,
    publish: PublishFault = .none,
    fail_revalidate_after_copy: bool = false,
};

pub const Invocation = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    runtime_path: []const u8,
    repository_path: []const u8,
    output_path: []const u8,
    signal: ?*core.process.SignalCancellation = null,
    aggregate_limit: u64 = retained_copy.aggregate_budget,
    faults: Faults = .{},

    pub fn openRuntime(self: Invocation) Outcome(RuntimeOpened) {
        const runtime = files.Directory.open(self.io, self.runtime_path) catch |err|
            return classify(RuntimeOpened, .runtime_opened, err);
        return .{ .success = .{ .invocation = self, .runtime = runtime } };
    }
};

pub const RuntimeOpened = struct {
    invocation: Invocation,
    runtime: files.Directory,

    pub fn deinit(self: *RuntimeOpened) void {
        self.runtime.close(self.invocation.io);
        self.* = undefined;
    }

    pub fn pinAccepted(self: *RuntimeOpened) Outcome(AcceptedRunPinned) {
        var accepted = accepted_run.openAndValidateWithSignal(
            self.invocation.allocator,
            self.invocation.io,
            self.invocation.environ,
            &self.runtime,
            self.invocation.runtime_path,
            self.invocation.repository_path,
            self.invocation.signal,
        ) catch |err| return classify(AcceptedRunPinned, .accepted_run_pinned, err);
        errdefer accepted.deinit();
        if (accepted.compatibility != .tiny_v2_qcow2_derived_vhd) {
            accepted.deinit();
            return .{ .refused = .{ .phase = .accepted_run_pinned, .err = error.UnsupportedVersion } };
        }
        return .{ .success = .{ .invocation = self.invocation, .runtime = self.runtime, .accepted = accepted } };
    }
};

pub const AcceptedRunPinned = struct {
    invocation: Invocation,
    runtime: files.Directory,
    accepted: accepted_run.AcceptedRun,

    pub fn deinit(self: *AcceptedRunPinned) void {
        self.accepted.deinit();
        self.runtime.close(self.invocation.io);
        self.* = undefined;
    }

    pub fn reserveOutput(self: *AcceptedRunPinned) Outcome(OutputReserved) {
        if (self.invocation.faults.copy != .none and !builtin.is_test)
            return .{ .refused = .{ .phase = .output_reserved, .err = error.InvalidFault } };
        _ = controller.handoff_inspect.run(
            self.invocation.allocator,
            self.invocation.io,
            &self.accepted,
            self.invocation.output_path,
            false,
            self.invocation.signal,
        ) catch |err| return classify(OutputReserved, .output_reserved, err);
        const output = files.Directory.open(self.invocation.io, self.invocation.output_path) catch |err|
            return classify(OutputReserved, .output_reserved, err);
        createTopDirectory(self.invocation.io, output.dir, "artifacts") catch |err|
            return classify(OutputReserved, .output_reserved, err);
        createTopDirectory(self.invocation.io, output.dir, "boots") catch |err|
            return classify(OutputReserved, .output_reserved, err);
        return .{ .success = .{
            .invocation = self.invocation,
            .runtime = self.runtime,
            .accepted = self.accepted,
            .output = output,
            .budget = .{ .limit = self.invocation.aggregate_limit },
        } };
    }
};

pub const Member = struct {
    path: []const u8,
    size: u64,
    sha256: []const u8,
};

pub const Boot = struct {
    mode: []const u8,
    serial: Member,
    request: Member,
    report: Member,
    compute: Member,
};

const CopySet = struct {
    artifacts: []Member = &.{},
    boots: []Boot = &.{},
    evidence: []Member = &.{},
};

pub const OutputReserved = struct {
    invocation: Invocation,
    runtime: files.Directory,
    accepted: accepted_run.AcceptedRun,
    output: files.Directory,
    budget: retained_copy.Budget,

    pub fn deinit(self: *OutputReserved) void {
        self.output.close(self.invocation.io);
        self.accepted.deinit();
        self.runtime.close(self.invocation.io);
        self.* = undefined;
    }

    pub fn copyArtifacts(self: *OutputReserved) Outcome(ArtifactsCopied) {
        var artifacts: std.ArrayList(Member) = .empty;
        for (layout.artifact_names_v2) |name| {
            const role = artifactRole(name) catch |err| return classify(ArtifactsCopied, .artifacts_copied, err);
            var retained = openArtifact(self, name, role) catch |err| return classify(ArtifactsCopied, .artifacts_copied, err);
            defer retained.close(self.invocation.io);
            const relative = std.fmt.allocPrint(self.invocation.allocator, "artifacts/{s}", .{name}) catch |err|
                return classify(ArtifactsCopied, .artifacts_copied, err);
            const copied = retained_copy.copyRetained(
                self.invocation.allocator,
                self.invocation.io,
                &retained,
                self.output.dir,
                self.invocation.output_path,
                relative,
                layout.artifactLimit(name),
                &self.budget,
                .{ .fault = self.invocation.faults.copy },
            ) catch |err| return classify(ArtifactsCopied, .artifacts_copied, err);
            const member = toMember(self.invocation.allocator, copied) catch |err|
                return classify(ArtifactsCopied, .artifacts_copied, err);
            artifacts.append(self.invocation.allocator, member) catch |err|
                return classify(ArtifactsCopied, .artifacts_copied, err);
        }
        return .{ .success = .{
            .invocation = self.invocation,
            .runtime = self.runtime,
            .accepted = self.accepted,
            .output = self.output,
            .budget = self.budget,
            .copies = .{ .artifacts = artifacts.items },
        } };
    }
};

pub const ArtifactsCopied = struct {
    invocation: Invocation,
    runtime: files.Directory,
    accepted: accepted_run.AcceptedRun,
    output: files.Directory,
    budget: retained_copy.Budget,
    copies: CopySet,

    pub fn copyBoots(self: *ArtifactsCopied) Outcome(BootsCopied) {
        var boots: std.ArrayList(Boot) = .empty;
        for (controller.profile.modes(self.accepted.compatibility)) |mode| {
            const boot = copyBoot(self, mode) catch |err| return classify(BootsCopied, .boots_copied, err);
            boots.append(self.invocation.allocator, boot) catch |err|
                return classify(BootsCopied, .boots_copied, err);
        }
        self.copies.boots = boots.items;
        return .{ .success = .{
            .invocation = self.invocation,
            .runtime = self.runtime,
            .accepted = self.accepted,
            .output = self.output,
            .budget = self.budget,
            .copies = self.copies,
        } };
    }
};

pub const BootsCopied = struct {
    invocation: Invocation,
    runtime: files.Directory,
    accepted: accepted_run.AcceptedRun,
    output: files.Directory,
    budget: retained_copy.Budget,
    copies: CopySet,

    pub fn copyEvidence(self: *BootsCopied) Outcome(EvidenceCopied) {
        var evidence: std.ArrayList(Member) = .empty;
        for (self.accepted.records) |record| {
            var retained = openEvidence(self, record.name) catch |err| return classify(EvidenceCopied, .evidence_copied, err);
            defer retained.close(self.invocation.io);
            const relative = std.fmt.allocPrint(self.invocation.allocator, "evidence/{s}", .{record.name}) catch |err|
                return classify(EvidenceCopied, .evidence_copied, err);
            const copied = retained_copy.copyRetained(
                self.invocation.allocator,
                self.invocation.io,
                &retained,
                self.output.dir,
                self.invocation.output_path,
                relative,
                layout.max_json_bytes,
                &self.budget,
                .{ .fault = self.invocation.faults.copy },
            ) catch |err| return classify(EvidenceCopied, .evidence_copied, err);
            if (copied.size != record.bytes or !std.mem.eql(u8, &copied.sha256, &record.sha256))
                return classify(EvidenceCopied, .evidence_copied, error.RecordChanged);
            const member = toMember(self.invocation.allocator, copied) catch |err|
                return classify(EvidenceCopied, .evidence_copied, err);
            evidence.append(self.invocation.allocator, member) catch |err|
                return classify(EvidenceCopied, .evidence_copied, err);
        }
        self.copies.evidence = evidence.items;
        return .{ .success = .{
            .invocation = self.invocation,
            .runtime = self.runtime,
            .accepted = self.accepted,
            .output = self.output,
            .budget = self.budget,
            .copies = self.copies,
        } };
    }
};

pub const EvidenceCopied = struct {
    invocation: Invocation,
    runtime: files.Directory,
    accepted: accepted_run.AcceptedRun,
    output: files.Directory,
    budget: retained_copy.Budget,
    copies: CopySet,

    pub fn revalidateSource(self: *EvidenceCopied) Outcome(SourceRevalidated) {
        if (self.invocation.faults.fail_revalidate_after_copy) {
            if (!builtin.is_test) return .{ .refused = .{ .phase = .source_revalidated, .err = error.InvalidFault } };
            return classify(SourceRevalidated, .source_revalidated, error.FileChanged);
        }
        self.accepted.revalidateWithSignal(self.invocation.signal) catch |err|
            return classify(SourceRevalidated, .source_revalidated, err);
        return .{ .success = .{
            .invocation = self.invocation,
            .runtime = self.runtime,
            .accepted = self.accepted,
            .output = self.output,
            .budget = self.budget,
            .copies = self.copies,
        } };
    }
};

pub const SourceRevalidated = struct {
    invocation: Invocation,
    runtime: files.Directory,
    accepted: accepted_run.AcceptedRun,
    output: files.Directory,
    budget: retained_copy.Budget,
    copies: CopySet,

    pub fn stageHandoff(self: *SourceRevalidated) Outcome(HandoffStaged) {
        const run_info = runIdentity(self.invocation.environ) catch |err| return classify(HandoffStaged, .handoff_staged, err);
        const bytes = buildBundleBytes(
            self.invocation.allocator,
            self.accepted.source.revision,
            self.accepted.source.tree,
            run_info.run_id,
            run_info.run_attempt,
            self.copies.artifacts,
            self.copies.boots,
            self.copies.evidence,
        ) catch |err| return classify(HandoffStaged, .handoff_staged, err);
        if (bytes.len > layout.max_json_bytes)
            return classify(HandoffStaged, .handoff_staged, error.ManifestTooLarge);
        return .{ .success = .{
            .invocation = self.invocation,
            .runtime = self.runtime,
            .accepted = self.accepted,
            .output = self.output,
            .copies = self.copies,
            .bundle = bytes,
        } };
    }
};

pub const HandoffStaged = struct {
    invocation: Invocation,
    runtime: files.Directory,
    accepted: accepted_run.AcceptedRun,
    output: files.Directory,
    copies: CopySet,
    bundle: []const u8,

    pub fn validateHandoff(self: *HandoffStaged) Outcome(HandoffValidated) {
        var document = contracts.parseCanonical(self.invocation.allocator, self.bundle) catch |err|
            return classify(HandoffValidated, .handoff_validated, err);
        defer document.deinit();
        const compatibility = contracts.validateLocalImageHandoffWithRoot(document.value(), self.invocation.output_path) catch |err|
            return classify(HandoffValidated, .handoff_validated, err);
        if (compatibility != .tiny_qcow2_derived_vhd_v2)
            return classify(HandoffValidated, .handoff_validated, error.UnsupportedVersion);
        return .{ .success = .{
            .invocation = self.invocation,
            .runtime = self.runtime,
            .accepted = self.accepted,
            .output = self.output,
            .copies = self.copies,
            .bundle = self.bundle,
        } };
    }
};

pub const HandoffValidated = struct {
    invocation: Invocation,
    runtime: files.Directory,
    accepted: accepted_run.AcceptedRun,
    output: files.Directory,
    copies: CopySet,
    bundle: []const u8,

    pub fn publish(self: *HandoffValidated) Outcome(HandoffPublished) {
        self.accepted.revalidateWithSignal(self.invocation.signal) catch |err|
            return classify(HandoffPublished, .handoff_published, err);
        publishBundle(self.invocation.io, self.output.dir, self.bundle, self.invocation.faults.publish) catch |err|
            return classify(HandoffPublished, .handoff_published, err);
        return .{ .success = .{
            .output_path = self.invocation.output_path,
            .bundle_bytes = self.bundle.len,
            .artifacts = self.copies.artifacts.len,
            .boots = self.copies.boots.len,
            .evidence = self.copies.evidence.len,
        } };
    }
};

pub const HandoffPublished = struct {
    output_path: []const u8,
    bundle_bytes: usize,
    artifacts: usize,
    boots: usize,
    evidence: usize,
};

pub fn run(invocation: Invocation) Outcome(HandoffPublished) {
    var opened = switch (invocation.openRuntime()) {
        .success => |state| state,
        .refused => |diagnostic| return .{ .refused = diagnostic },
        .poisoned => |diagnostic| return .{ .poisoned = diagnostic },
    };
    var pinned = switch (opened.pinAccepted()) {
        .success => |state| state,
        .refused => |diagnostic| return .{ .refused = diagnostic },
        .poisoned => |diagnostic| return .{ .poisoned = diagnostic },
    };
    var reserved = switch (pinned.reserveOutput()) {
        .success => |state| state,
        .refused => |diagnostic| return .{ .refused = diagnostic },
        .poisoned => |diagnostic| return .{ .poisoned = diagnostic },
    };
    var artifacts = switch (reserved.copyArtifacts()) {
        .success => |state| state,
        .refused => |diagnostic| return .{ .refused = diagnostic },
        .poisoned => |diagnostic| return .{ .poisoned = diagnostic },
    };
    var boots = switch (artifacts.copyBoots()) {
        .success => |state| state,
        .refused => |diagnostic| return .{ .refused = diagnostic },
        .poisoned => |diagnostic| return .{ .poisoned = diagnostic },
    };
    var evidence = switch (boots.copyEvidence()) {
        .success => |state| state,
        .refused => |diagnostic| return .{ .refused = diagnostic },
        .poisoned => |diagnostic| return .{ .poisoned = diagnostic },
    };
    var revalidated = switch (evidence.revalidateSource()) {
        .success => |state| state,
        .refused => |diagnostic| return .{ .refused = diagnostic },
        .poisoned => |diagnostic| return .{ .poisoned = diagnostic },
    };
    var staged = switch (revalidated.stageHandoff()) {
        .success => |state| state,
        .refused => |diagnostic| return .{ .refused = diagnostic },
        .poisoned => |diagnostic| return .{ .poisoned = diagnostic },
    };
    var validated = switch (staged.validateHandoff()) {
        .success => |state| state,
        .refused => |diagnostic| return .{ .refused = diagnostic },
        .poisoned => |diagnostic| return .{ .poisoned = diagnostic },
    };
    return validated.publish();
}

fn copyBoot(self: *ArtifactsCopied, mode: controller.profile.Mode) !Boot {
    return .{
        .mode = @tagName(mode),
        .serial = try copyBootPart(self, mode, .serial),
        .request = try copyBootPart(self, mode, .request),
        .report = try copyBootPart(self, mode, .report),
        .compute = try copyBootPart(self, mode, .compute),
    };
}

fn copyBootPart(self: *ArtifactsCopied, mode: controller.profile.Mode, part: accepted_run.BootRole) !Member {
    var retained = try self.accepted.pinBoot(mode, part);
    defer retained.close(self.invocation.io);
    const relative = try std.fmt.allocPrint(self.invocation.allocator, "boots/{s}/{s}", .{ @tagName(mode), @tagName(part) });
    const copied = try retained_copy.copyRetained(
        self.invocation.allocator,
        self.invocation.io,
        &retained,
        self.output.dir,
        self.invocation.output_path,
        relative,
        if (part == .serial) layout.max_serial_bytes else layout.max_json_bytes,
        &self.budget,
        .{ .fault = self.invocation.faults.copy },
    );
    return toMember(self.invocation.allocator, copied);
}

fn openEvidence(self: *BootsCopied, name: []const u8) !files.RetainedFile {
    try files.basename(name);
    const path = try std.fs.path.join(self.invocation.allocator, &.{ self.accepted.root, "compute/evidence", name });
    return files.RetainedFile.open(self.invocation.io, path, .private);
}

fn openArtifact(self: *OutputReserved, name: []const u8, role: accepted_run.ArtifactRole) !files.RetainedFile {
    if (!std.mem.eql(u8, name, "cleanup"))
        return self.accepted.pinArtifact(role);
    const path = try std.fs.path.join(self.invocation.allocator, &.{ self.accepted.root, "evidence/runtime-cleanup.txt" });
    return files.RetainedFile.open(self.invocation.io, path, .private);
}

fn artifactRole(name: []const u8) !accepted_run.ArtifactRole {
    if (std.mem.eql(u8, name, "build")) return .build_record;
    return std.meta.stringToEnum(accepted_run.ArtifactRole, name) orelse error.UnknownArtifactRole;
}

fn toMember(allocator: std.mem.Allocator, result: retained_copy.Result) !Member {
    return .{ .path = result.path, .size = result.size, .sha256 = try allocator.dupe(u8, &result.sha256) };
}

const RunIdentity = struct { run_id: []const u8, run_attempt: []const u8 };

fn runIdentity(environ: std.process.Environ) !RunIdentity {
    const repository = std.process.Environ.getPosix(environ, "GITHUB_REPOSITORY") orelse return error.MissingRunIdentity;
    const run_id = std.process.Environ.getPosix(environ, "GITHUB_RUN_ID") orelse return error.MissingRunIdentity;
    const run_attempt = std.process.Environ.getPosix(environ, "GITHUB_RUN_ATTEMPT") orelse return error.MissingRunIdentity;
    if (!std.mem.eql(u8, repository, profile.repository) or !decimal(run_id) or !decimal(run_attempt))
        return error.InvalidRunIdentity;
    return .{ .run_id = run_id, .run_attempt = run_attempt };
}

fn decimal(value: []const u8) bool {
    if (value.len == 0 or value.len > 20 or value[0] == '0') return false;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return false;
    return true;
}

fn buildBundleBytes(
    allocator: std.mem.Allocator,
    source_revision: []const u8,
    source_tree: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
    artifacts: []const Member,
    boots: []const Boot,
    evidence: []const Member,
) ![]const u8 {
    if (artifacts.len != layout.artifact_names_v2.len or boots.len != profile.production_modes.len or
        evidence.len != layout.evidence_v2.len)
        return error.InvalidMemberCount;
    const by_name = ArtifactMap{ .items = artifacts };
    const value = .{
        .schema = "uk.wamr.local-image-handoff",
        .version = @as(u8, 2),
        .profile = profile.current_profile,
        .authority = profile.authority,
        .source_revision = source_revision,
        .source_tree = source_tree,
        .run = .{ .repository = profile.repository, .run_id = run_id, .run_attempt = run_attempt },
        .identity = .{
            .wamr_revision = profile.wamr_revision,
            .wasm_sha256 = try by_name.sha("wasm"),
            .cwasm_sha256 = try by_name.sha("cwasm"),
            .runtime_sha256 = try by_name.sha("runtime"),
            .compiler_sha256 = try by_name.sha("compiler"),
            .config_sha256 = try by_name.sha("config"),
        },
        .lineage = .{
            .raw_sha256 = try by_name.sha("raw"),
            .accepted_qcow2_sha256 = try by_name.sha("qcow2"),
            .derived_vhd_sha256 = try by_name.sha("vhd"),
            .qcow2_finalization_sha256 = try by_name.sha("qcow2_finalization"),
            .qcow2_acceptance_sha256 = try by_name.sha("qcow2_acceptance"),
            .fixed_vhd_derivation_sha256 = try by_name.sha("fixed_vhd_derivation"),
            .fixed_vhd_derivation_gate_sha256 = try by_name.sha("fixed_vhd_derivation_gate"),
            .final_inspection_sha256 = try by_name.sha("final_inspection"),
        },
        .artifacts = artifacts,
        .boots = boots,
        .evidence = evidence,
    };
    const raw = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(raw);
    return controller.records.canonicalAlloc(allocator, raw);
}

const ArtifactMap = struct {
    items: []const Member,

    fn sha(self: ArtifactMap, name: []const u8) ![]const u8 {
        for (layout.artifact_names_v2, self.items) |candidate, member|
            if (std.mem.eql(u8, candidate, name)) return member.sha256;
        return error.MissingArtifact;
    }
};

fn publishBundle(io: std.Io, output: std.Io.Dir, bundle: []const u8, fault: PublishFault) !void {
    if (fault != .none and !builtin.is_test) return error.InvalidFault;
    var atomic = try output.createFileAtomic(io, "bundle.json", .{
        .permissions = .fromMode(0o600),
    });
    defer atomic.deinit(io);
    try atomic.file.writePositionalAll(io, bundle, 0);
    if (fault == .before_file_sync) return error.AmbiguousWrite;
    try atomic.file.sync(io);
    atomic.link(io) catch |err| switch (err) {
        error.PathAlreadyExists => return error.OutputExists,
        else => return err,
    };
    if (fault == .before_parent_sync) return error.AmbiguousWrite;
    try (std.Io.File{ .handle = output.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

fn createTopDirectory(io: std.Io, output: std.Io.Dir, name: []const u8) !void {
    try files.basename(name);
    output.createDir(io, name, .fromMode(0o700)) catch |err| switch (err) {
        error.PathAlreadyExists => return error.OutputExists,
        else => return err,
    };
    try (std.Io.File{ .handle = output.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

fn classify(comptime T: type, phase: Phase, err: anyerror) Outcome(T) {
    const diagnostic: Diagnostic = .{ .phase = phase, .err = err };
    return switch (err) {
        error.FileChanged,
        error.RuntimeChanged,
        error.ArtifactChanged,
        error.BootChanged,
        error.RecordChanged,
        error.InputChanged,
        error.ResultChanged,
        error.SourceChanged,
        error.CommandOutputChanged,
        error.CleanupPoisoned,
        error.AmbiguousWrite,
        error.DeadlineExceeded,
        error.Cancelled,
        error.GitTimedOut,
        error.GitCleanupTimedOut,
        => .{ .poisoned = diagnostic },
        else => .{ .refused = diagnostic },
    };
}

pub const Test = if (builtin.is_test) struct {
    pub fn publishBundleForTest(io: std.Io, output: std.Io.Dir, bundle: []const u8, fault: PublishFault) !void {
        try publishBundle(io, output, bundle, fault);
    }

    pub fn buildRootBoundBundleV2(allocator: std.mem.Allocator, root: []const u8, sha256: []const u8) ![]const u8 {
        var artifacts = try allocator.alloc(Member, layout.artifact_names_v2.len);
        for (layout.artifact_names_v2, 0..) |name, i| {
            artifacts[i] = .{
                .path = try std.fs.path.join(allocator, &.{ root, "artifacts", name }),
                .size = 1,
                .sha256 = sha256,
            };
        }
        const modes = profile.production_modes;
        var boots = try allocator.alloc(Boot, modes.len);
        for (modes, 0..) |mode, i| {
            boots[i] = .{
                .mode = @tagName(mode),
                .serial = try fixtureMember(allocator, root, "boots", @tagName(mode), "serial", sha256),
                .request = try fixtureMember(allocator, root, "boots", @tagName(mode), "request", sha256),
                .report = try fixtureMember(allocator, root, "boots", @tagName(mode), "report", sha256),
                .compute = try fixtureMember(allocator, root, "boots", @tagName(mode), "compute", sha256),
            };
        }
        var evidence = try allocator.alloc(Member, layout.evidence_v2.len);
        for (layout.evidence_v2, 0..) |name, i| {
            evidence[i] = .{
                .path = try std.fs.path.join(allocator, &.{ root, "evidence", name }),
                .size = 1,
                .sha256 = sha256,
            };
        }
        return buildBundleBytes(
            allocator,
            "0123456789012345678901234567890123456789",
            "0123456789012345678901234567890123456789",
            "1",
            "1",
            artifacts,
            boots,
            evidence,
        );
    }

    fn fixtureMember(
        allocator: std.mem.Allocator,
        root: []const u8,
        a: []const u8,
        b: []const u8,
        c: []const u8,
        sha256: []const u8,
    ) !Member {
        return .{
            .path = try std.fs.path.join(allocator, &.{ root, a, b, c }),
            .size = 1,
            .sha256 = sha256,
        };
    }
} else struct {};
