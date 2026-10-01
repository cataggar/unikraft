// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const files = core.private_files;
const controller = @import("wamr_controller");
const accepted_run = controller.accepted_run;
const copy = @import("retained_copy.zig");
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
    publication: files.CommitStatus = .not_committed,
};

pub fn Outcome(comptime T: type) type {
    return union(enum) { success: T, refused: Diagnostic, poisoned: Diagnostic };
}

pub const PublishFault = enum { none, before_file_sync, before_parent_sync, after_publication };
pub const Faults = struct {
    copy: copy.TestFault = .none,
    publish: PublishFault = .none,
    fail_revalidate_after_copy: bool = false,
    phase: ?Phase = null,
};

pub const Invocation = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    runtime_path: []const u8,
    repository_path: []const u8,
    output_path: []const u8,
    signal: ?*core.process.SignalCancellation = null,
    aggregate_limit: u64 = copy.aggregate_budget,
    faults: Faults = .{},

    pub fn openRuntime(self: Invocation) Outcome(RuntimeOpened) {
        const attempt = Attempt.create(self) catch |err| return classify(RuntimeOpened, .runtime_opened, err, false, .not_committed);
        attempt.openRuntime() catch |err| {
            attempt.destroy();
            return classify(RuntimeOpened, .runtime_opened, err, false, .not_committed);
        };
        attempt.phase = .runtime_opened;
        return .{ .success = .{ .attempt = attempt } };
    }
};

pub const RuntimeOpened = State(.runtime_opened);
pub const AcceptedRunPinned = State(.accepted_run_pinned);
pub const OutputReserved = State(.output_reserved);
pub const ArtifactsCopied = State(.artifacts_copied);
pub const BootsCopied = State(.boots_copied);
pub const EvidenceCopied = State(.evidence_copied);
pub const SourceRevalidated = State(.source_revalidated);
pub const HandoffStaged = State(.handoff_staged);
pub const HandoffValidated = State(.handoff_validated);

// Tokens borrow one attempt owner. A transition consumes its phase, including
// through copied tokens; the owner is released exactly once by the caller.
fn State(comptime phase: Phase) type {
    return struct {
        attempt: *anyopaque,
        const Self = @This();

        fn owner(self: Self) *Attempt {
            return @ptrCast(@alignCast(self.attempt));
        }
        pub fn deinit(self: Self) void {
            self.owner().destroy();
        }
        pub fn pinAccepted(self: Self) Outcome(AcceptedRunPinned) {
            requirePhase(phase, .runtime_opened);
            return self.owner().next(AcceptedRunPinned, phase, .accepted_run_pinned);
        }
        pub fn reserveOutput(self: Self) Outcome(OutputReserved) {
            requirePhase(phase, .accepted_run_pinned);
            return self.owner().next(OutputReserved, phase, .output_reserved);
        }
        pub fn copyArtifacts(self: Self) Outcome(ArtifactsCopied) {
            requirePhase(phase, .output_reserved);
            return self.owner().next(ArtifactsCopied, phase, .artifacts_copied);
        }
        pub fn copyBoots(self: Self) Outcome(BootsCopied) {
            requirePhase(phase, .artifacts_copied);
            return self.owner().next(BootsCopied, phase, .boots_copied);
        }
        pub fn copyEvidence(self: Self) Outcome(EvidenceCopied) {
            requirePhase(phase, .boots_copied);
            return self.owner().next(EvidenceCopied, phase, .evidence_copied);
        }
        pub fn revalidateSource(self: Self) Outcome(SourceRevalidated) {
            requirePhase(phase, .evidence_copied);
            return self.owner().next(SourceRevalidated, phase, .source_revalidated);
        }
        pub fn stageHandoff(self: Self) Outcome(HandoffStaged) {
            requirePhase(phase, .source_revalidated);
            return self.owner().next(HandoffStaged, phase, .handoff_staged);
        }
        pub fn validateHandoff(self: Self) Outcome(HandoffValidated) {
            requirePhase(phase, .handoff_staged);
            return self.owner().next(HandoffValidated, phase, .handoff_validated);
        }
        pub fn publish(self: Self) Outcome(HandoffPublished) {
            requirePhase(phase, .handoff_validated);
            return self.owner().next(HandoffPublished, phase, .handoff_published);
        }
    };
}

fn requirePhase(comptime actual: Phase, comptime expected: Phase) void {
    if (actual != expected) @compileError("export transition used on the wrong ownership token");
}

pub const HandoffPublished = struct {
    output_path: []const u8,
    bundle_bytes: usize,
    artifacts: usize,
    boots: usize,
    evidence: usize,
    result_sha256: [64]u8,
};
pub const Member = struct { path: []const u8, size: u64, sha256: []const u8 };
pub const Boot = struct { mode: []const u8, serial: Member, request: Member, report: Member, compute: Member };
const Held = struct { retained: files.RetainedFile, sha256: [64]u8, limit: u64 };
const Source = struct { held: Held, phase: Phase, relative: []const u8, member: *Member };
const SealedDirectory = struct { path: []const u8, snapshot: files.Snapshot };
const TreeInput = struct { path: []const u8, directory: std.Io.Dir, snapshot: files.Snapshot };
const Terminal = struct { diagnostic: Diagnostic, poisoned: bool };

const Attempt = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    invocation: Invocation,
    phase: Phase = .invocation,
    transition: std.Io.Mutex = .init,
    terminal: ?Terminal = null,
    runtime: ?files.Directory = null,
    runtime_snapshot: files.Snapshot = undefined,
    accepted: ?accepted_run.AcceptedRun = null,
    output: ?files.Directory = null,
    reservation_started: bool = false,
    output_snapshot: files.Snapshot = undefined,
    lock: ?files.Locked = null,
    private: ?files.Directory = null,
    private_lock: ?files.Locked = null,
    anchor: ?files.RetainedFile = null,
    private_anchor: ?files.RetainedFile = null,
    sources: std.ArrayList(Source) = .empty,
    inputs: std.ArrayList(files.RetainedFile) = .empty,
    input_trees: std.ArrayList(TreeInput) = .empty,
    destinations: std.ArrayList(Held) = .empty,
    sealed: std.ArrayList(SealedDirectory) = .empty,
    sealed_root: ?files.Snapshot = null,
    budget: copy.Budget,
    artifacts: []Member = &.{},
    boots: []Boot = &.{},
    evidence: []Member = &.{},
    bundle: []const u8 = "",
    staged: ?Held = null,
    inspection: ?controller.handoff_inspect.RetainedInspection = null,
    inspection_sha256: [64]u8 = undefined,
    publication: files.CommitStatus = .not_committed,
    fixture: bool = false,
    owned_signal: ?core.process.SignalCancellation = null,

    fn create(invocation: Invocation) !*Attempt {
        if (invocation.aggregate_limit > copy.aggregate_budget) return error.CopyBudgetExceeded;
        if (!builtin.is_test and (invocation.faults.copy != .none or invocation.faults.publish != .none or
            invocation.faults.fail_revalidate_after_copy or invocation.faults.phase != null)) return error.InvalidFault;
        try files.absoluteFilePath(invocation.runtime_path);
        try files.absoluteFilePath(invocation.repository_path);
        try files.absoluteFilePath(invocation.output_path);
        if (std.mem.eql(u8, invocation.runtime_path, invocation.output_path) or
            (std.mem.startsWith(u8, invocation.output_path, invocation.runtime_path) and
                invocation.output_path[invocation.runtime_path.len] == '/')) return error.OutputInsideRuntime;
        const result = try invocation.allocator.create(Attempt);
        result.* = .{
            .allocator = invocation.allocator,
            .arena = std.heap.ArenaAllocator.init(invocation.allocator),
            .invocation = invocation,
            .budget = .{ .limit = invocation.aggregate_limit },
        };
        return result;
    }

    fn a(self: *Attempt) std.mem.Allocator {
        return self.arena.allocator();
    }
    fn cancel(self: *Attempt) ?*const std.atomic.Value(bool) {
        return if (self.invocation.signal) |signal| signal.flag() else null;
    }
    fn destroy(self: *Attempt) void {
        const io = self.invocation.io;
        for (self.sources.items) |*source| source.held.retained.close(io);
        for (self.inputs.items) |*retained| retained.close(io);
        for (self.input_trees.items) |tree| tree.directory.close(io);
        for (self.destinations.items) |*held| held.retained.close(io);
        if (self.staged) |*held| held.retained.close(io);
        if (self.inspection) |*inspection| inspection.deinit(io);
        if (self.anchor) |*anchor| anchor.close(io);
        if (self.private_anchor) |*anchor| anchor.close(io);
        if (self.private_lock) |*lock| lock.close(io);
        if (self.private) |dir| dir.close(io);
        if (self.lock) |*lock| lock.close(io);
        if (self.output) |dir| dir.close(io);
        if (self.accepted) |*accepted| accepted.deinit();
        if (self.runtime) |dir| dir.close(io);
        if (self.owned_signal) |*signal| signal.deinit();
        const allocator = self.allocator;
        self.arena.deinit();
        allocator.destroy(self);
    }

    fn openRuntime(self: *Attempt) !void {
        if (self.invocation.signal == null) {
            self.owned_signal = try core.process.SignalCancellation.install();
            self.invocation.signal = &self.owned_signal.?;
        }
        try copy.checkCancellation(self.cancel());
        self.runtime = try files.Directory.open(self.invocation.io, self.invocation.runtime_path);
        self.runtime_snapshot = try copy.directorySnapshot(self.runtime.?.dir);
    }

    fn next(self: *Attempt, comptime T: type, expected: Phase, target: Phase) Outcome(T) {
        self.transition.lockUncancelable(self.invocation.io);
        defer self.transition.unlock(self.invocation.io);
        if (self.terminal) |terminal| return terminalOutcome(T, terminal);
        if (self.phase != expected) {
            if (self.phase == .handoff_published)
                return .{ .refused = .{ .phase = target, .err = error.AttemptFinished, .publication = self.publication } };
            return self.fail(T, target, error.InvalidTransition);
        }
        self.perform(target) catch |err| return self.fail(T, target, err);
        if (target != .handoff_published)
            self.journal(target, null) catch |err| return self.fail(T, target, err);
        self.phase = target;
        if (T == HandoffPublished) {
            return .{ .success = .{
                .output_path = self.invocation.output_path,
                .bundle_bytes = self.bundle.len,
                .artifacts = self.artifacts.len,
                .boots = self.boots.len,
                .evidence = self.evidence.len,
                .result_sha256 = self.accepted.?.result.sha256,
            } };
        }
        return .{ .success = .{ .attempt = self } };
    }

    fn fail(self: *Attempt, comptime T: type, phase: Phase, err: anyerror) Outcome(T) {
        const outcome = classify(T, phase, err, self.reservation_started, self.publication);
        const terminal: Terminal = switch (outcome) {
            .refused => |diagnostic| .{ .diagnostic = diagnostic, .poisoned = false },
            .poisoned => |diagnostic| .{ .diagnostic = diagnostic, .poisoned = true },
            .success => unreachable,
        };
        self.terminal = terminal;
        self.journal(phase, terminal) catch {};
        return outcome;
    }

    fn journal(self: *Attempt, phase: Phase, terminal: ?Terminal) !void {
        if (self.private_lock == null or self.private_anchor == null) return;
        try copy.verifyRetained(self.invocation.io, &self.private_anchor.?);
        const name = try std.fmt.allocPrint(self.a(), "{s}-{s}.json", .{
            if (terminal != null) "failed" else "phase", @tagName(phase),
        });
        const bytes = try canonical(self.a(), .{
            .phase = @tagName(phase),
            .outcome = if (terminal) |value| (if (value.poisoned) "poisoned" else "refused") else "success",
            .err = if (terminal) |value| @as(?[]const u8, @errorName(value.diagnostic.err)) else null,
            .publication = @tagName(self.publication),
        });
        try requireDurable(try self.private_lock.?.createImmutable(self.invocation.io, name, bytes));
    }

    fn perform(self: *Attempt, phase: Phase) !void {
        try copy.checkCancellation(self.cancel());
        if (self.invocation.faults.phase == phase) return error.AmbiguousWrite;
        switch (phase) {
            .accepted_run_pinned => {
                self.accepted = try accepted_run.openAndValidateWithSignal(self.a(), self.invocation.io, self.invocation.environ, &self.runtime.?, self.invocation.runtime_path, self.invocation.repository_path, self.invocation.signal);
                try self.pinSources();
            },
            .output_reserved => try self.reserve(),
            .artifacts_copied, .boots_copied, .evidence_copied => {
                for (self.sources.items) |*source| {
                    if (source.phase != phase) continue;
                    try self.copySource(source);
                }
                if (phase == .evidence_copied) try self.sealDirectories();
            },
            .source_revalidated => {
                if (self.invocation.faults.fail_revalidate_after_copy) return error.FileChanged;
                try self.verifySources();
                try self.verifyOutput();
            },
            .handoff_staged => try self.stage(),
            .handoff_validated => try self.validate(),
            .handoff_published => try self.publish(),
            else => return error.InvalidTransition,
        }
    }

    fn pinSources(self: *Attempt) !void {
        const accepted = &self.accepted.?;
        if (accepted.compatibility != .tiny_v2_qcow2_derived_vhd or accepted.context != .local_runtime)
            return error.UnsupportedVersion;
        if (accepted.records.len != layout.evidence_v2.len) return error.InvalidMemberCount;
        self.artifacts = try self.a().alloc(Member, layout.artifact_names_v2.len);
        self.boots = try self.a().alloc(Boot, profile.production_modes.len);
        self.evidence = try self.a().alloc(Member, layout.evidence_v2.len);
        for (layout.artifact_names_v2, 0..) |name, i| {
            const role = if (std.mem.eql(u8, name, "build")) accepted_run.ArtifactRole.build_record else std.meta.stringToEnum(accepted_run.ArtifactRole, name) orelse return error.UnknownArtifactRole;
            const relative = try std.fmt.allocPrint(self.a(), "artifacts/{s}", .{name});
            const retained = try accepted.pinArtifact(role);
            try self.addSource(retained, .artifacts_copied, relative, &self.artifacts[i], layout.artifactLimit(name));
        }
        for (controller.profile.modes(accepted.compatibility), 0..) |mode, i| {
            self.boots[i].mode = @tagName(mode);
            inline for (.{ "serial", "request", "report", "compute" }) |part| {
                const relative = try std.fmt.allocPrint(self.a(), "boots/{s}/{s}", .{ @tagName(mode), part });
                const retained = try accepted.pinBoot(mode, @field(accepted_run.BootRole, part));
                try self.addSource(retained, .boots_copied, relative, &@field(self.boots[i], part), if (std.mem.eql(u8, part, "serial")) layout.max_serial_bytes else layout.max_json_bytes);
            }
        }
        for (layout.evidence_v2, 0..) |name, i| {
            const relative = try std.fmt.allocPrint(self.a(), "evidence/{s}", .{name});
            const retained = try accepted.pinRecord(name);
            try self.addSource(retained, .evidence_copied, relative, &self.evidence[i], layout.max_json_bytes);
        }
        for (accepted.runtime_inputs) |input| {
            if (input.snapshot.tree != null) {
                const directory = try accepted.pinInputTree(input.role);
                errdefer directory.close(self.invocation.io);
                try self.input_trees.append(self.a(), .{
                    .path = input.path,
                    .directory = directory,
                    .snapshot = try copy.directorySnapshot(directory),
                });
                continue;
            }
            var retained = try accepted.pinInput(input.role);
            errdefer retained.close(self.invocation.io);
            try self.inputs.append(self.a(), retained);
        }
        for (self.sources.items) |source| {
            if (!std.mem.eql(u8, source.relative, "artifacts/local_result")) continue;
            if (source.held.retained.file_snapshot.size != accepted.result.bytes or
                !std.mem.eql(u8, &source.held.sha256, &accepted.result.sha256)) return error.ResultChanged;
        }
    }

    fn addSource(self: *Attempt, retained_: files.RetainedFile, phase: Phase, relative: []const u8, member: *Member, limit: u64) !void {
        var retained = retained_;
        errdefer retained.close(self.invocation.io);
        const digest = try copy.hashRetained(self.invocation.io, &retained, limit, self.cancel());
        try self.sources.append(self.a(), .{
            .held = .{ .retained = retained, .sha256 = digest, .limit = limit },
            .phase = phase,
            .relative = relative,
            .member = member,
        });
    }

    fn reserve(self: *Attempt) !void {
        try self.verifySources();
        const parent = try files.FileParent.open(self.invocation.io, self.invocation.output_path, .private);
        defer parent.close(self.invocation.io);
        if (parent.directory.statFile(self.invocation.io, parent.name, .{ .follow_symlinks = false })) |_| {
            return error.OutputExists;
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }
        self.reservation_started = true;
        if (builtin.is_test and self.fixture) {
            try parent.directory.createDir(self.invocation.io, parent.name, .fromMode(0o700));
            try parent.sync(self.invocation.io);
            const output = try files.Directory.open(self.invocation.io, self.invocation.output_path);
            defer output.close(self.invocation.io);
            try output.dir.createDir(self.invocation.io, "private", .fromMode(0o700));
            try output.dir.createDir(self.invocation.io, "evidence", .fromMode(0o700));
        } else {
            self.inspection = try controller.handoff_inspect.runRetained(self.a(), self.invocation.io, &self.accepted.?, self.invocation.output_path, false, self.invocation.signal);
            self.inspection_sha256 = try copy.hashRetained(self.invocation.io, &self.inspection.?.record, layout.max_json_bytes, self.cancel());
        }
        self.output = try files.Directory.open(self.invocation.io, self.invocation.output_path);
        self.output_snapshot = try copy.directorySnapshot(self.output.?.dir);
        if (self.inspection) |*inspection| try copy.verifyRetained(self.invocation.io, &inspection.record);
        try parent.sync(self.invocation.io);
        try createDirectory(self.invocation.io, self.output.?.dir, "artifacts");
        try createDirectory(self.invocation.io, self.output.?.dir, "boots");
        self.lock = try self.output.?.lock(self.invocation.io);
        self.anchor = try files.RetainedFile.open(self.invocation.io, try std.fs.path.join(self.a(), &.{ self.invocation.output_path, ".writer.lock" }), .private);
        const private = try self.output.?.dir.openDir(self.invocation.io, "private", .{ .follow_symlinks = false, .iterate = true });
        defer private.close(self.invocation.io);
        try createDirectory(self.invocation.io, private, "export");
        self.private = try files.Directory.open(self.invocation.io, try std.fs.path.join(self.a(), &.{ self.invocation.output_path, "private/export" }));
        self.private_lock = try self.private.?.lock(self.invocation.io);
        self.private_anchor = try files.RetainedFile.open(self.invocation.io, try std.fs.path.join(self.a(), &.{ self.invocation.output_path, "private/export/.writer.lock" }), .private);
        try self.verifySources();
    }

    fn copySource(self: *Attempt, source: *Source) !void {
        const copied = try copy.copyRetained(self.a(), self.invocation.io, &source.held.retained, self.output.?.dir, self.invocation.output_path, source.relative, source.held.limit, &self.budget, .{ .fault = self.invocation.faults.copy, .cancel = self.cancel() });
        if (!std.mem.eql(u8, &copied.sha256, &source.held.sha256)) return error.CopyChanged;
        var retained = try files.RetainedFile.open(self.invocation.io, copied.path, .private);
        errdefer retained.close(self.invocation.io);
        if (!copy.sameCustodySnapshot(copied.destination_snapshot, retained.file_snapshot)) return error.CopyChanged;
        const sha256 = try self.a().dupe(u8, &copied.sha256);
        try self.destinations.append(self.a(), .{ .retained = retained, .sha256 = copied.sha256, .limit = source.held.limit });
        source.member.* = .{ .path = copied.path, .size = copied.size, .sha256 = sha256 };
    }

    fn sealDirectories(self: *Attempt) !void {
        for ([_][]const u8{ "artifacts", "boots", "evidence" }) |relative| try self.sealDirectory(relative);
        for (profile.production_modes) |mode|
            try self.sealDirectory(try std.fmt.allocPrint(self.a(), "boots/{s}", .{@tagName(mode)}));
        self.sealed_root = try copy.directorySnapshot(self.output.?.dir);
    }
    fn sealDirectory(self: *Attempt, relative: []const u8) !void {
        const path = try std.fs.path.join(self.a(), &.{ self.invocation.output_path, relative });
        const dir = try files.Directory.open(self.invocation.io, path);
        defer dir.close(self.invocation.io);
        try syncDirectory(self.invocation.io, dir.dir);
        try self.sealed.append(self.a(), .{ .path = path, .snapshot = try copy.directorySnapshot(dir.dir) });
    }

    fn verifySources(self: *Attempt) !void {
        try copy.checkCancellation(self.cancel());
        const runtime = try files.Directory.open(self.invocation.io, self.invocation.runtime_path);
        defer runtime.close(self.invocation.io);
        if (!copy.sameDirectory(self.runtime_snapshot, try copy.directorySnapshot(runtime.dir))) return error.RuntimeChanged;
        if (!(builtin.is_test and self.fixture))
            try self.accepted.?.revalidateWithSignal(self.invocation.signal);
        for (self.sources.items) |*source| {
            try self.verifyHeld(&source.held);
            const retained = &source.held.retained;
            const leaf_parent = retained.directory_count - 1;
            if (!copy.sameCustodySnapshot(retained.directory_snapshots[leaf_parent], try copy.directorySnapshot(retained.directories[leaf_parent]))) return error.SourceChanged;
        }
        for (self.inputs.items) |*retained| try copy.verifyRetained(self.invocation.io, retained);
        for (self.input_trees.items) |tree| {
            const named = try files.openDirectory(self.invocation.io, tree.path, .artifact);
            defer named.close(self.invocation.io);
            if (!copy.sameCustodySnapshot(tree.snapshot, try copy.directorySnapshot(tree.directory)) or
                !copy.sameCustodySnapshot(tree.snapshot, try copy.directorySnapshot(named))) return error.InputChanged;
        }
        try copy.checkCancellation(self.cancel());
    }
    fn verifyHeld(self: *Attempt, held: *Held) !void {
        const digest = try copy.hashRetained(self.invocation.io, &held.retained, held.limit, self.cancel());
        if (!std.mem.eql(u8, &digest, &held.sha256)) return error.CopyChanged;
    }
    fn verifyOutput(self: *Attempt) !void {
        if (self.destinations.items.len != layout.selectedMemberCount(.tiny_qcow2_derived_vhd_v2) or
            self.sealed.items.len != 3 + profile.production_modes.len) return error.MissingMembers;
        try copy.verifyRoot(self.invocation.io, self.invocation.output_path, self.output_snapshot);
        try copy.verifyRetained(self.invocation.io, &self.anchor.?);
        try copy.verifyRetained(self.invocation.io, &self.private_anchor.?);
        if (self.publication == .not_committed and
            !copy.sameCustodySnapshot(self.sealed_root.?, try copy.directorySnapshot(self.output.?.dir))) return error.CopyChanged;
        try self.exactOutput();
        if (self.inspection) |*inspection| {
            const digest = try copy.hashRetained(self.invocation.io, &inspection.record, layout.max_json_bytes, self.cancel());
            if (!std.mem.eql(u8, &digest, &self.inspection_sha256)) return error.CommandOutputChanged;
        }
        for (self.destinations.items) |*held| try self.verifyHeld(held);
        for (self.sealed.items) |sealed| {
            const dir = try files.Directory.open(self.invocation.io, sealed.path);
            defer dir.close(self.invocation.io);
            if (!copy.sameCustodySnapshot(sealed.snapshot, try copy.directorySnapshot(dir.dir))) return error.CopyChanged;
        }
    }
    fn exactOutput(self: *Attempt) !void {
        var iterator = self.output.?.dir.iterate();
        var count: usize = 0;
        while (try iterator.next(self.invocation.io)) |entry| {
            const known = std.mem.eql(u8, entry.name, ".writer.lock") or
                std.mem.eql(u8, entry.name, "artifacts") or std.mem.eql(u8, entry.name, "boots") or
                std.mem.eql(u8, entry.name, "evidence") or std.mem.eql(u8, entry.name, "private") or
                (self.publication == .durable and std.mem.eql(u8, entry.name, "bundle.json"));
            if (!known) return error.UnexpectedMember;
            count += 1;
        }
        if (count != 5 + @as(usize, @intFromBool(self.publication == .durable))) return error.MissingMembers;
        for (self.sealed.items) |sealed| {
            const relative = sealed.path[self.invocation.output_path.len + 1 ..];
            const directory = try files.Directory.open(self.invocation.io, sealed.path);
            defer directory.close(self.invocation.io);
            var entries = directory.dir.iterate();
            var found: usize = 0;
            while (try entries.next(self.invocation.io)) |entry| {
                const name = try std.fs.path.join(self.a(), &.{ relative, entry.name });
                var known = false;
                for (self.sources.items) |source| {
                    if (std.mem.eql(u8, source.relative, name)) known = true;
                    if (std.mem.eql(u8, relative, "boots") and std.mem.startsWith(u8, source.relative, name) and
                        source.relative.len > name.len and source.relative[name.len] == '/') known = true;
                }
                if (!self.fixture and std.mem.eql(u8, name, "evidence/command-handoff-inspect.json")) known = true;
                if (!known) return error.UnexpectedMember;
                found += 1;
            }
            const expected: usize = if (std.mem.eql(u8, relative, "artifacts")) layout.artifact_names_v2.len else if (std.mem.eql(u8, relative, "evidence")) layout.evidence_v2.len + @as(usize, @intFromBool(!self.fixture)) else if (std.mem.eql(u8, relative, "boots")) profile.production_modes.len else layout.boot_keys.len;
            if (found != expected) return error.MissingMembers;
        }
    }

    fn stage(self: *Attempt) !void {
        try self.verifySources();
        try self.verifyOutput();
        const run_info = try runIdentity(self.invocation.environ);
        self.bundle = try buildBundleBytes(self.a(), self.accepted.?.source.revision, self.accepted.?.source.tree, run_info.run_id, run_info.run_attempt, self.artifacts, self.boots, self.evidence);
        if (self.bundle.len > layout.max_json_bytes) return error.ManifestTooLarge;
        try requireDurable(try self.private_lock.?.createImmutable(self.invocation.io, "handoff.json", self.bundle));
        var retained = try files.RetainedFile.open(self.invocation.io, try std.fs.path.join(self.a(), &.{ self.invocation.output_path, "private/export/handoff.json" }), .private);
        errdefer retained.close(self.invocation.io);
        var held: Held = .{ .retained = retained, .sha256 = std.fmt.bytesToHex(controller.records.fileIdentity(self.bundle), .lower), .limit = layout.max_json_bytes };
        try self.verifyHeld(&held);
        self.staged = held;
    }
    fn validate(self: *Attempt) !void {
        if (self.accepted == null or self.staged == null) return error.MissingMembers;
        try self.verifySources();
        try self.verifyOutput();
        try self.verifyHeld(&self.staged.?);
        var bytes = try files.readSensitiveFile(self.invocation.io, self.a(), self.staged.?.retained.file, layout.max_json_bytes, .private);
        defer bytes.deinit();
        var document = try contracts.parseCanonical(self.a(), bytes.bytes());
        defer document.deinit();
        if (try contracts.validateLocalImageHandoffWithRoot(document.value(), self.invocation.output_path) != .tiny_qcow2_derived_vhd_v2)
            return error.UnsupportedVersion;
        if (!std.mem.eql(u8, bytes.bytes(), self.bundle)) return error.CopyChanged;
    }
    fn publish(self: *Attempt) !void {
        try self.validate();
        // Record intent before the final commit, never a success-shaped receipt.
        try requireDurable(try self.private_lock.?.createImmutable(self.invocation.io, "publication-intent.json", try canonical(self.a(), .{ .phase = "handoff_published", .outcome = "pending" })));
        try self.validate();
        try copy.checkCancellation(self.cancel());
        const result = try publishBundle(self.invocation.io, &self.lock.?, self.bundle, self.invocation.faults.publish);
        self.publication = result.status;
        try requireDurable(result);
        var final = try files.RetainedFile.open(self.invocation.io, try std.fs.path.join(self.a(), &.{ self.invocation.output_path, "bundle.json" }), .private);
        defer final.close(self.invocation.io);
        const digest = try copy.hashRetained(self.invocation.io, &final, layout.max_json_bytes, self.cancel());
        if (!std.mem.eql(u8, &digest, &self.staged.?.sha256)) return error.CopyChanged;
        try self.verifySources();
        try self.verifyOutput();
    }
};

pub fn run(invocation: Invocation) Outcome(HandoffPublished) {
    const opened = switch (invocation.openRuntime()) {
        .success => |state| state,
        .refused => |d| return .{ .refused = d },
        .poisoned => |d| return .{ .poisoned = d },
    };
    defer opened.deinit();
    return finish(opened);
}

fn finish(opened: RuntimeOpened) Outcome(HandoffPublished) {
    const pinned = switch (opened.pinAccepted()) {
        .success => |s| s,
        .refused => |d| return .{ .refused = d },
        .poisoned => |d| return .{ .poisoned = d },
    };
    return finishPinned(pinned);
}
fn finishPinned(pinned: AcceptedRunPinned) Outcome(HandoffPublished) {
    const reserved = switch (pinned.reserveOutput()) {
        .success => |s| s,
        .refused => |d| return .{ .refused = d },
        .poisoned => |d| return .{ .poisoned = d },
    };
    const artifacts = switch (reserved.copyArtifacts()) {
        .success => |s| s,
        .refused => |d| return .{ .refused = d },
        .poisoned => |d| return .{ .poisoned = d },
    };
    const boots = switch (artifacts.copyBoots()) {
        .success => |s| s,
        .refused => |d| return .{ .refused = d },
        .poisoned => |d| return .{ .poisoned = d },
    };
    const evidence = switch (boots.copyEvidence()) {
        .success => |s| s,
        .refused => |d| return .{ .refused = d },
        .poisoned => |d| return .{ .poisoned = d },
    };
    const source = switch (evidence.revalidateSource()) {
        .success => |s| s,
        .refused => |d| return .{ .refused = d },
        .poisoned => |d| return .{ .poisoned = d },
    };
    const staged = switch (source.stageHandoff()) {
        .success => |s| s,
        .refused => |d| return .{ .refused = d },
        .poisoned => |d| return .{ .poisoned = d },
    };
    const validated = switch (staged.validateHandoff()) {
        .success => |s| s,
        .refused => |d| return .{ .refused = d },
        .poisoned => |d| return .{ .poisoned = d },
    };
    return validated.publish();
}

fn terminalOutcome(comptime T: type, terminal: Terminal) Outcome(T) {
    return if (terminal.poisoned) .{ .poisoned = terminal.diagnostic } else .{ .refused = terminal.diagnostic };
}
fn classify(comptime T: type, phase: Phase, err: anyerror, output_reserved: bool, publication: files.CommitStatus) Outcome(T) {
    const diagnostic: Diagnostic = .{ .phase = phase, .err = err, .publication = publication };
    return switch (err) {
        error.FileChanged, error.CopyChanged, error.RuntimeChanged, error.ArtifactChanged, error.BootChanged, error.RecordChanged, error.InputChanged, error.ResultChanged, error.SourceChanged, error.EvidenceChanged, error.CommandOutputChanged, error.CleanupPoisoned, error.AmbiguousWrite, error.DeadlineExceeded, error.Cancelled, error.GitTimedOut, error.GitCleanupTimedOut => .{ .poisoned = diagnostic },
        else => if (output_reserved) .{ .poisoned = diagnostic } else .{ .refused = diagnostic },
    };
}
fn requireDurable(result: files.CommitResult) !void {
    if (result.status != .durable or result.failures.primary != null or
        result.failures.cleanup != null or result.failures.recording != null) return error.AmbiguousWrite;
}
fn publishBundle(io: std.Io, lock: *files.Locked, bytes: []const u8, fault: PublishFault) !files.CommitResult {
    if (!builtin.is_test and fault != .none) return error.InvalidFault;
    // A known failed prepublication barrier must not make the final name visible.
    if (fault == .before_parent_sync) return error.AmbiguousWrite;
    try syncDirectory(io, lock.directory.dir);
    if (builtin.is_test) {
        if (fault == .before_file_sync) return lock.createImmutableFault(io, "bundle.json", bytes, .before_file_sync);
        if (fault == .after_publication) return lock.createImmutableFault(io, "bundle.json", bytes, .after_rename);
    }
    return lock.createImmutable(io, "bundle.json", bytes);
}
fn syncDirectory(io: std.Io, dir: std.Io.Dir) !void {
    try (std.Io.File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}
fn createDirectory(io: std.Io, parent: std.Io.Dir, name: []const u8) !void {
    try parent.createDir(io, name, .fromMode(0o700));
    const dir = try parent.openDir(io, name, .{ .follow_symlinks = false, .iterate = true });
    defer dir.close(io);
    try syncDirectory(io, dir);
    try syncDirectory(io, parent);
}
fn canonical(a: std.mem.Allocator, value: anytype) ![]const u8 {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(raw);
    return controller.records.canonicalAlloc(a, raw);
}
const RunIdentity = struct { run_id: []const u8, run_attempt: []const u8 };
fn runIdentity(environ: std.process.Environ) !RunIdentity {
    const repository = std.process.Environ.getPosix(environ, "GITHUB_REPOSITORY") orelse return error.MissingRunIdentity;
    const id = std.process.Environ.getPosix(environ, "GITHUB_RUN_ID") orelse return error.MissingRunIdentity;
    const attempt = std.process.Environ.getPosix(environ, "GITHUB_RUN_ATTEMPT") orelse return error.MissingRunIdentity;
    if (!std.mem.eql(u8, repository, profile.repository) or !decimal(id) or !decimal(attempt)) return error.InvalidRunIdentity;
    return .{ .run_id = id, .run_attempt = attempt };
}
fn decimal(value: []const u8) bool {
    if (value.len == 0 or value.len > 20 or value[0] == '0') return false;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return false;
    return true;
}
fn buildBundleBytes(a: std.mem.Allocator, revision: []const u8, tree: []const u8, id: []const u8, attempt: []const u8, artifacts: []const Member, boots: []const Boot, evidence: []const Member) ![]const u8 {
    if (artifacts.len != layout.artifact_names_v2.len or boots.len != profile.production_modes.len or evidence.len != layout.evidence_v2.len)
        return error.InvalidMemberCount;
    const by_name = ArtifactMap{ .items = artifacts };
    return canonical(a, .{
        .schema = "uk.wamr.local-image-handoff",
        .version = @as(u8, 2),
        .profile = profile.current_profile,
        .authority = profile.authority,
        .source_revision = revision,
        .source_tree = tree,
        .run = .{ .repository = profile.repository, .run_id = id, .run_attempt = attempt },
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
    });
}
const ArtifactMap = struct {
    items: []const Member,
    fn sha(self: ArtifactMap, name: []const u8) ![]const u8 {
        for (layout.artifact_names_v2, self.items) |candidate, member|
            if (std.mem.eql(u8, candidate, name)) return member.sha256;
        return error.MissingArtifact;
    }
};

pub const Test = if (builtin.is_test) struct {
    pub fn begin(invocation: Invocation, accepted: accepted_run.AcceptedRun) !AcceptedRunPinned {
        var owned_accepted = accepted;
        const attempt = Attempt.create(invocation) catch |err| {
            owned_accepted.deinit();
            return err;
        };
        errdefer attempt.destroy();
        attempt.accepted = accepted;
        try attempt.openRuntime();
        attempt.fixture = true;
        try attempt.pinSources();
        attempt.phase = .accepted_run_pinned;
        return .{ .attempt = attempt };
    }
    pub fn finishFixture(pinned: AcceptedRunPinned) Outcome(HandoffPublished) {
        return finishPinned(pinned);
    }
    pub fn stagedWithoutMembers(invocation: Invocation) !HandoffStaged {
        const attempt = try Attempt.create(invocation);
        attempt.phase = .handoff_staged;
        return .{ .attempt = attempt };
    }
    pub fn cancelAttempt(token: anytype) void {
        @constCast(token.owner().cancel().?).store(true, .release);
    }
    pub fn publishBundleForTest(io: std.Io, output: std.Io.Dir, bundle: []const u8, fault: PublishFault) !void {
        var lock = try (files.Directory{ .dir = output }).lock(io);
        defer lock.close(io);
        try requireDurable(try publishBundle(io, &lock, bundle, fault));
    }
    pub fn buildRootBoundBundleV2(a: std.mem.Allocator, root: []const u8, sha256: []const u8) ![]const u8 {
        const artifacts = try a.alloc(Member, layout.artifact_names_v2.len);
        for (layout.artifact_names_v2, 0..) |name, i|
            artifacts[i] = try fixtureMember(a, root, try std.fmt.allocPrint(a, "artifacts/{s}", .{name}), sha256);
        const boots = try a.alloc(Boot, profile.production_modes.len);
        for (profile.production_modes, 0..) |mode, i| {
            boots[i].mode = @tagName(mode);
            inline for (.{ "serial", "request", "report", "compute" }) |part|
                @field(boots[i], part) = try fixtureMember(a, root, try std.fmt.allocPrint(a, "boots/{s}/{s}", .{ @tagName(mode), part }), sha256);
        }
        const evidence = try a.alloc(Member, layout.evidence_v2.len);
        for (layout.evidence_v2, 0..) |name, i|
            evidence[i] = try fixtureMember(a, root, try std.fmt.allocPrint(a, "evidence/{s}", .{name}), sha256);
        return buildBundleBytes(a, "0123456789012345678901234567890123456789", "0123456789012345678901234567890123456789", "1", "1", artifacts, boots, evidence);
    }
    fn fixtureMember(a: std.mem.Allocator, root: []const u8, relative: []const u8, sha256: []const u8) !Member {
        return .{ .path = try std.fs.path.join(a, &.{ root, relative }), .size = 1, .sha256 = sha256 };
    }
} else struct {};
