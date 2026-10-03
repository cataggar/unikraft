// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const contracts = core.contracts;
const accepted_run = @import("accepted_run.zig");
const adapter = @import("command_adapter.zig");
const physical = @import("custody_files.zig");
const inputs = @import("input_custody.zig");
const limits = @import("custody_limits.zig");
const plan = @import("command_plan.zig");
const profile = @import("profile.zig");
const records = @import("records.zig");
const source = @import("source_custody.zig");
const supervisor_identity = @import("import_supervisor_identity.zig");

const handoff_success = "Compute handoff revalidated; authority=not_admitted.\n";

pub const LocalTools = struct {
    git: []const u8,
    supervisor: []const u8,
    validator: []const u8,
};

pub const PortableTools = struct {
    allocator: std.mem.Allocator,
    git: files.RetainedFile,
    controller: files.RetainedFile,
    supervisor: supervisor_identity.PinnedRuntime,
    validator: files.RetainedFile,
    runtime: std.ArrayList(RuntimePin),
    before: source.Source,

    pub fn bind(
        allocator: std.mem.Allocator,
        io: std.Io,
        context: accepted_run.EvidenceContext,
        identity: accepted_run.SourceIdentity,
        start: std.json.Value,
        repository: []const u8,
        controller_path: []const u8,
        local: LocalTools,
        signal: ?*core.process.SignalCancellation,
    ) !PortableTools {
        return bindWithPolicy(allocator, io, context, identity, start, repository, controller_path, local, signal, false);
    }

    fn bindLegacy(
        allocator: std.mem.Allocator,
        io: std.Io,
        accepted: *accepted_run.AcceptedRun,
        start: std.json.Value,
        repository: []const u8,
        controller_path: []const u8,
        local: LocalTools,
        signal: ?*core.process.SignalCancellation,
    ) !PortableTools {
        if (accepted.compatibility != .tiny_v1_legacy)
            return error.InvalidContext;
        return bindWithPolicy(allocator, io, accepted.context, accepted.source, start, repository, controller_path, local, signal, true);
    }

    fn bindWithPolicy(
        allocator: std.mem.Allocator,
        io: std.Io,
        context: accepted_run.EvidenceContext,
        identity: accepted_run.SourceIdentity,
        start: std.json.Value,
        repository: []const u8,
        controller_path: []const u8,
        local: LocalTools,
        signal: ?*core.process.SignalCancellation,
        legacy: bool,
    ) !PortableTools {
        if (context != .trusted_inner_zip) return error.InvalidContext;
        if (signal) |active|
            if (active.flag().load(.acquire)) return error.Cancelled;
        var git = try adapter.openPinnedTool(io, local.git, "tool:git");
        errdefer git.close(io);
        var native = try files.RetainedFile.open(io, controller_path, .tool);
        errdefer native.close(io);
        var validator = try adapter.openPinnedTool(io, local.validator, "input:validator");
        errdefer validator.close(io);
        const validator_identity = try physical.readFile(io, local.validator, 64 * limits.mib, false);
        if (!std.mem.eql(u8, &validator_identity.sha256, @import("import_validator_identity").sha256) or
            !std.meta.eql(validator_identity.metadata, physical.metadata(validator.file_snapshot)))
            return error.InvalidValidator;

        var runtime: std.ArrayList(RuntimePin) = .empty;
        errdefer {
            for (runtime.items) |*entry| entry.deinit(allocator, io);
            runtime.deinit(allocator);
        }
        for ([_][]const u8{ local.git, controller_path, local.validator }) |path|
            try pinLocalRuntime(allocator, io, path, &runtime);
        try git.verify(io);
        try native.verify(io);
        try validator.verify(io);
        for (runtime.items) |*entry| try entry.file.verify(io);
        var supervisor = if (legacy) blk: {
            // Historical v1 predates recorded supervisor custody. Its reader
            // uses the current native owner, never an unauthenticated old tool.
            var retained = try files.RetainedFile.open(io, local.supervisor, .tool);
            errdefer retained.close(io);
            break :blk supervisor_identity.PinnedRuntime{
                .supervisor = retained,
                .loaders = try allocator.alloc(files.RetainedFile, 0),
            };
        } else blk: {
            const source_map = try get(try get(start, "command_supervisor"), "source_map");
            const source_records = try get(source_map, "records");
            if (source_records != .object or source_records.object.count() != source.closure.len)
                return error.UnsupportedSupervisorSource;
            const source_sha = try supervisor_identity.verifyGitSource(allocator, io, identity, repository, local.git, source_map, signal);
            const native_source_sha = try supervisor_identity.nativeSourceContentClosure(allocator);
            if (!std.mem.eql(u8, source_sha, &native_source_sha)) return error.ImportSourceChanged;
            break :blk try supervisor_identity.verifyRuntime(allocator, io, local.supervisor, start, signal);
        };
        errdefer supervisor.deinit(allocator, io);
        const owner = try physical.readFile(io, controller_path, 64 * limits.mib, false);
        const supplied = try physical.readFile(io, local.supervisor, 64 * limits.mib, false);
        if (!std.meta.eql(owner.sha256, supplied.sha256) or owner.bytes != supplied.bytes or
            !std.meta.eql(owner.metadata, physical.metadata(native.file_snapshot)))
            return error.ImportSupervisorChanged;

        try git.verify(io);
        const before = try source.portableSource(allocator, io, repository, local.git);
        if (!std.mem.eql(u8, before.custody.object_format, "sha1") or
            (!legacy and (!std.mem.eql(u8, before.revision, identity.revision) or
                !std.mem.eql(u8, before.tree, identity.tree))))
            return error.ImportSourceChanged;
        if (!legacy) try checkoutSource(before, start);
        try source.verifyPhysical(io, allocator, repository);
        var result = PortableTools{
            .allocator = allocator,
            .git = git,
            .controller = native,
            .supervisor = supervisor,
            .validator = validator,
            .runtime = runtime,
            .before = before,
        };
        try result.verify(io, repository, local.git);
        return result;
    }

    pub fn verify(self: *PortableTools, io: std.Io, repository: []const u8, git: []const u8) !void {
        try self.verifyExecutables(io);
        const after = try source.portableSource(self.allocator, io, repository, git);
        if (!self.before.same(after)) return error.SourceChanged;
        try self.verifyExecutables(io);
    }

    fn verifyExecutables(self: *PortableTools, io: std.Io) !void {
        try self.git.verify(io);
        try self.controller.verify(io);
        try self.supervisor.verify(io);
        try self.validator.verify(io);
        for (self.runtime.items) |*entry| try entry.file.verify(io);
    }

    pub fn deinit(self: *PortableTools, io: std.Io) void {
        self.git.close(io);
        self.controller.close(io);
        self.supervisor.deinit(self.allocator, io);
        self.validator.close(io);
        for (self.runtime.items) |*entry| entry.deinit(self.allocator, io);
        self.runtime.deinit(self.allocator);
    }
};

const Tool = struct {
    path: []const u8,
    pinned: files.RetainedFile,

    fn deinit(self: *Tool, io: std.Io) void {
        self.pinned.close(io);
    }
};

const RuntimePin = struct {
    path: []const u8,
    file: files.RetainedFile,

    fn deinit(self: *RuntimePin, allocator: std.mem.Allocator, io: std.Io) void {
        self.file.close(io);
        allocator.free(self.path);
    }
};

fn pinLocalRuntime(
    allocator: std.mem.Allocator,
    io: std.Io,
    executable: []const u8,
    pinned: *std.ArrayList(RuntimePin),
) !void {
    const paths = try inputs.executableRuntimePaths(allocator, io, executable);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }
    if (paths.len > 256 or paths.len > 512 - pinned.items.len) return error.RuntimeInventoryRefused;
    for (paths) |path| {
        const owned = try allocator.dupe(u8, path);
        errdefer allocator.free(owned);
        var file = try files.RetainedFile.open(io, owned, .artifact);
        errdefer file.close(io);
        try file.verify(io);
        try pinned.append(allocator, .{ .path = owned, .file = file });
    }
}

pub fn runPortable(
    allocator: std.mem.Allocator,
    io: std.Io,
    accepted: *accepted_run.AcceptedRun,
    repository: []const u8,
    output: []const u8,
    local: LocalTools,
    signal: ?*core.process.SignalCancellation,
) !void {
    if (accepted.context != .trusted_inner_zip)
        return error.InvalidContext;
    try files.absoluteFilePath(output);
    if (contained(output, accepted.root) or contained(output, repository) or
        contained(accepted.root, output) or contained(repository, output))
        return error.AliasedOutput;
    try accepted.revalidateWithSignal(signal);
    var pinned_start = try accepted.pinArtifact(.build_start);
    defer pinned_start.close(io);
    var raw = try files.readSensitiveFile(io, allocator, pinned_start.file, records.max_record_bytes, .private);
    defer raw.deinit();
    var document = try contracts.Document.parse(allocator, raw.bytes(), .{
        .bytes = records.max_record_bytes,
        .depth = 32,
        .items = 4096,
        .tokens = 65536,
    });
    defer document.deinit();
    try document.requireCanonical(allocator, raw.bytes());
    const owner_path = try std.process.executablePathAlloc(io, allocator);
    var authenticated = if (accepted.compatibility == .tiny_v1_legacy)
        try PortableTools.bindLegacy(allocator, io, accepted, document.value(), repository, owner_path, local, signal)
    else
        try PortableTools.bind(allocator, io, accepted.context, accepted.source, document.value(), repository, owner_path, local, signal);
    defer authenticated.deinit(io);
    const candidate = try handoffCandidate(allocator, io, accepted);
    const parent_path = std.fs.path.dirname(output) orelse return error.UnsafePath;
    const name = std.fs.path.basename(output);
    try files.basename(name);
    const parent = try files.openDirectory(io, parent_path, .private);
    defer parent.close(io);
    try parent.createDir(io, name, .fromMode(0o700));
    const work = try files.openDirectory(io, output, .private);
    defer work.close(io);
    for ([_][]const u8{ "private", "evidence" }) |entry| try work.createDir(io, entry, .fromMode(0o700));
    const private = try work.openDir(io, "private", .{ .iterate = true });
    defer private.close(io);
    const evidence = try work.openDir(io, "evidence", .{ .iterate = true });
    defer evidence.close(io);
    const candidate_path = try std.fs.path.join(allocator, &.{ output, "private/candidate-bundle.json" });
    {
        const file = try private.createFile(io, "candidate-bundle.json", .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writeStreamingAll(io, candidate);
        try file.sync(io);
    }
    const observed = try physical.readFile(io, candidate_path, 65536, true);
    const candidate_sha = std.fmt.bytesToHex(records.fileIdentity(candidate), .lower);
    if (observed.bytes != candidate.len or !std.mem.eql(u8, &observed.sha256, &candidate_sha))
        return error.CandidateChanged;
    var pinned_candidate = try files.RetainedFile.open(io, candidate_path, .private);
    defer pinned_candidate.close(io);
    if (!std.meta.eql(observed.metadata, physical.metadata(pinned_candidate.file_snapshot)))
        return error.CandidateChanged;
    try authenticated.verify(io, repository, local.git);
    try accepted.revalidateWithSignal(signal);
    _ = try revalidateHandoffCommand(allocator, io, .{
        .source_root = repository,
        .work = output,
        .runtime = accepted.root,
        .zig = "",
        .producer = "",
        .supervisor = local.supervisor,
        .package_tool = "",
        .validator = "",
        .direct_validator = local.validator,
        .bundle = candidate_path,
        .tools = @splat(""),
    }, private, evidence, signal);
    try authenticated.verify(io, repository, local.git);
    try accepted.revalidateWithSignal(signal);
    try pinned_start.verify(io);
    try pinned_candidate.verify(io);
}

fn get(value: std.json.Value, key: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidImportedTool;
    return value.object.get(key) orelse error.InvalidImportedTool;
}

fn contained(path: []const u8, root: []const u8) bool {
    return std.mem.eql(u8, path, root) or
        (path.len > root.len and std.mem.startsWith(u8, path, root) and path[root.len] == '/');
}

fn recordedFile(
    io: std.Io,
    start: std.json.Value,
    role: []const u8,
    path: []const u8,
    bound: usize,
) !physical.File {
    const record = try get(try get(try get(start, "consumer_inputs"), "files"), role);
    if (!std.mem.eql(u8, path, try contracts.string(try get(record, "path"))))
        return error.ImportedToolChanged;
    try files.absoluteFilePath(path);
    const identity = try physical.readFile(io, path, bound, false);
    if (!std.mem.eql(u8, &identity.sha256, try contracts.string(try get(record, "sha256"))))
        return error.ImportedToolChanged;
    const metadata = try get(record, "metadata");
    if (metadata != .array or metadata.array.items.len != identity.metadata.len)
        return error.InvalidImportedTool;
    for (metadata.array.items, identity.metadata) |recorded, observed|
        if (try contracts.integer(i128, recorded) != observed) return error.ImportedToolChanged;
    return identity;
}

fn tool(
    allocator: std.mem.Allocator,
    io: std.Io,
    start: std.json.Value,
    name: []const u8,
    bound: usize,
) !Tool {
    const role = try std.fmt.allocPrint(allocator, "tool:{s}", .{name});
    defer allocator.free(role);
    const record = try get(try get(try get(start, "consumer_inputs"), "files"), role);
    const path = try contracts.string(try get(record, "path"));
    const identity = try recordedFile(io, start, role, path, bound);
    var pinned = try adapter.openPinnedTool(io, path, role);
    errdefer pinned.close(io);
    if (!std.meta.eql(identity.metadata, physical.metadata(pinned.file_snapshot)))
        return error.ImportedToolChanged;
    try pinned.verify(io);
    return .{ .path = path, .pinned = pinned };
}

fn pinRecordedRuntime(
    allocator: std.mem.Allocator,
    io: std.Io,
    start: std.json.Value,
    path: []const u8,
    pinned: *std.ArrayList(RuntimePin),
) !void {
    const role = try std.fmt.allocPrint(allocator, "runtime:{s}", .{path});
    defer allocator.free(role);
    const identity = try recordedFile(io, start, role, path, 64 * limits.mib);
    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);
    var retained = try files.RetainedFile.open(io, owned_path, .artifact);
    errdefer retained.close(io);
    if (!std.meta.eql(identity.metadata, physical.metadata(retained.file_snapshot)))
        return error.ImportedToolChanged;
    try retained.verify(io);
    try pinned.append(allocator, .{ .path = owned_path, .file = retained });
}

fn pinRuntime(
    allocator: std.mem.Allocator,
    io: std.Io,
    start: std.json.Value,
    executable: []const u8,
    pinned: *std.ArrayList(RuntimePin),
) !void {
    const paths = try inputs.executableRuntimePaths(allocator, io, executable);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }
    if (paths.len > 256 or paths.len > 512 - pinned.items.len) return error.RuntimeInventoryRefused;
    for (paths) |path| try pinRecordedRuntime(allocator, io, start, path, pinned);
}

pub const Fixture = if (@import("builtin").is_test) struct {
    pub fn runtimePathRemainsPinned(
        allocator: std.mem.Allocator,
        io: std.Io,
        start: std.json.Value,
        path: []const u8,
    ) !void {
        var pinned: std.ArrayList(RuntimePin) = .empty;
        defer {
            for (pinned.items) |*entry| entry.deinit(allocator, io);
            pinned.deinit(allocator);
        }
        {
            const transient_path = try allocator.dupe(u8, path);
            defer allocator.free(transient_path);
            try pinRecordedRuntime(allocator, io, start, transient_path, &pinned);
        }
        for (pinned.items) |*entry| {
            if (@intFromPtr(entry.file.path.ptr) != @intFromPtr(entry.path.ptr))
                return error.UnretainedRuntimePath;
            try entry.file.verify(io);
        }
    }

    pub fn rebaseMember(
        allocator: std.mem.Allocator,
        root: []const u8,
        item: *std.json.Value,
        prefix: []const u8,
    ) !void {
        try rebase(allocator, root, item, prefix);
    }
} else struct {};

fn rebase(
    allocator: std.mem.Allocator,
    root: []const u8,
    item: *std.json.Value,
    prefix: []const u8,
) !void {
    if (item.* != .object) return error.InvalidImportedBundle;
    const member = item.object.getPtr("path") orelse return error.InvalidImportedBundle;
    const relative = try contracts.string(member.*);
    try limits.relative(relative, 128, 3);
    if (!std.mem.startsWith(u8, relative, prefix) or relative.len == prefix.len)
        return error.InvalidImportedBundle;
    member.* = .{ .string = try std.fs.path.join(allocator, &.{ root, relative }) };
}

fn handoffCandidate(
    allocator: std.mem.Allocator,
    io: std.Io,
    accepted: *accepted_run.AcceptedRun,
) ![]const u8 {
    const root = accepted.root;
    const path = try std.fs.path.join(allocator, &.{ root, "portable-bundle.json" });
    var pinned = try files.RetainedFile.open(io, path, .private);
    defer pinned.close(io);
    var raw = try files.readSensitiveFile(io, allocator, pinned.file, 64 * 1024, .private);
    defer raw.deinit();
    var document = try contracts.Document.parse(allocator, raw.bytes(), .{
        .bytes = 64 * 1024,
        .depth = 32,
        .items = 4096,
        .tokens = 65536,
    });
    defer document.deinit();
    try document.requireCanonical(allocator, raw.bytes());
    const bundle = document.value();
    const artifacts = try get(bundle, "artifacts");
    const boots = try get(bundle, "boots");
    const evidence = try get(bundle, "evidence");
    const modes = profile.modes(accepted.compatibility);
    const mode_count = modes.len;
    if (accepted.artifacts.len < mode_count * 4 or
        artifacts != .array or artifacts.array.items.len != accepted.artifacts.len - mode_count * 4 or
        boots != .array or boots.array.items.len != modes.len or
        evidence != .array or evidence.array.items.len != accepted.records.len)
        return error.InvalidImportedBundle;
    for (artifacts.array.items) |*item| try rebase(allocator, root, item, "artifacts/");
    for (modes, boots.array.items) |mode, *boot| {
        if (boot.* != .object or
            !std.mem.eql(u8, try contracts.string(try get(boot.*, "mode")), @tagName(mode)))
            return error.InvalidImportedBundle;
        const prefix = try std.fmt.allocPrint(allocator, "boots/{s}/", .{@tagName(mode)});
        for ([_][]const u8{ "serial", "request", "report", "compute" }) |part| {
            const item = boot.object.getPtr(part) orelse return error.InvalidImportedBundle;
            try rebase(allocator, root, item, prefix);
        }
    }
    for (evidence.array.items) |*item| try rebase(allocator, root, item, "evidence/");
    const serialized = try std.json.Stringify.valueAlloc(allocator, bundle, .{});
    const candidate = try records.canonicalAlloc(allocator, serialized);
    if (candidate.len > 65536) return error.InvalidImportedBundle;
    try pinned.verify(io);
    return candidate;
}

fn tree(allocator: std.mem.Allocator, io: std.Io, start: std.json.Value, zig_path: []const u8) !inputs.TreeRecord {
    const root = std.fs.path.dirname(zig_path) orelse return error.UnsafePath;
    const recorded = try get(try get(try get(start, "consumer_inputs"), "trees"), "zig");
    if (!std.mem.eql(u8, root, try contracts.string(try get(recorded, "path"))))
        return error.ImportedToolChanged;
    const observed = try inputs.tree(allocator, io, .{ .role = "zig", .path = root });
    if (observed.files != try contracts.integer(usize, try get(recorded, "files")) or
        observed.directories != try contracts.integer(usize, try get(recorded, "directories")) or
        observed.symlinks != try contracts.integer(usize, try get(recorded, "symlinks")) or
        observed.bytes != try contracts.integer(usize, try get(recorded, "bytes")) or
        !std.mem.eql(u8, &observed.content_sha256, try contracts.string(try get(recorded, "content_sha256"))))
        return error.ImportedToolChanged;
    return observed;
}

fn checkoutSource(before: source.Source, start: std.json.Value) !void {
    const custody = try get(start, "source_custody");
    if (before.custody.files != try contracts.integer(usize, try get(custody, "files")) or
        before.custody.directories != try contracts.integer(usize, try get(custody, "directories")) or
        before.custody.bytes != try contracts.integer(usize, try get(custody, "bytes")) or
        !std.mem.eql(u8, &before.custody.content_sha256, try contracts.string(try get(custody, "content_sha256"))))
        return error.ImportSourceChanged;
}

fn postRun(
    allocator: std.mem.Allocator,
    io: std.Io,
    output: []const u8,
    stage: plan.Stage,
    expected_bytes: usize,
) !void {
    _ = try validatedPostRun(allocator, io, output, stage, expected_bytes);
}

fn validatedPostRun(
    allocator: std.mem.Allocator,
    io: std.Io,
    output: []const u8,
    stage: plan.Stage,
    expected_bytes: usize,
) !@import("command_validation.zig").ValidatedCommand {
    const record_path = try std.fmt.allocPrint(allocator, "{s}/evidence/command-{s}.json", .{ output, @tagName(stage) });
    const identity = try physical.readFile(io, record_path, records.max_record_bytes, true);
    var retained = try files.RetainedFile.open(io, record_path, .private);
    defer retained.close(io);
    var raw = try files.readSensitiveFile(io, allocator, retained.file, records.max_record_bytes, .private);
    defer raw.deinit();
    const digest = std.fmt.bytesToHex(records.fileIdentity(raw.bytes()), .lower);
    if (identity.bytes != raw.bytes().len or
        !std.meta.eql(identity.metadata, physical.metadata(retained.file_snapshot)) or
        !std.mem.eql(u8, &identity.sha256, &digest))
        return error.CommandOutputChanged;
    const checked = try accepted_run.validateCommandBinding(
        allocator,
        raw.bytes(),
        stage,
        .trusted_inner_zip,
    );
    const log_path = try std.fmt.allocPrint(allocator, "{s}/private/{s}.log", .{ output, @tagName(stage) });
    const log = try physical.readFile(io, log_path, plan.spec(stage).output_limit + 1, true);
    if (checked.output_bytes != expected_bytes or checked.output_bytes != log.bytes or
        !std.mem.eql(u8, &checked.output_sha256, &log.sha256))
        return error.CommandOutputChanged;
    try retained.verify(io);
    return checked;
}

pub fn revalidateHandoffCommand(
    allocator: std.mem.Allocator,
    io: std.Io,
    roots: plan.Roots,
    private: std.Io.Dir,
    evidence: std.Io.Dir,
    signal: ?*core.process.SignalCancellation,
) !@import("command_validation.zig").ValidatedCommand {
    var validator = try files.RetainedFile.open(io, roots.direct_validator, .tool);
    defer validator.close(io);
    var bundle = try files.RetainedFile.open(io, roots.bundle, .private);
    defer bundle.close(io);
    const outcome = try adapter.execute(allocator, io, .{
        .roots = roots,
        .stage = .@"import-native-revalidation",
        .private_dir = private,
        .evidence_dir = evidence,
        .cancel = if (signal) |active| active.flag() else null,
        .capture_stdout = true,
    });
    defer allocator.free(outcome.stdout);
    if (outcome.poisoned) return error.CleanupPoisoned;
    if (!outcome.accepted or outcome.stderr_bytes != 0 or
        !std.mem.eql(u8, outcome.stdout, handoff_success))
        return error.StageRefused;
    const checked = try validatedPostRun(allocator, io, roots.work, .@"import-native-revalidation", outcome.bytes);
    try validator.verify(io);
    try bundle.verify(io);
    return checked;
}

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    accepted: *accepted_run.AcceptedRun,
    repository: []const u8,
    output: []const u8,
    revalidate: bool,
    signal: ?*core.process.SignalCancellation,
) !void {
    if (accepted.context != .trusted_inner_zip or
        accepted.compatibility != .tiny_v2_qcow2_derived_vhd)
        return error.InvalidContext;
    try files.absoluteFilePath(output);
    if (contained(output, accepted.root) or contained(output, repository) or
        contained(accepted.root, output) or contained(repository, output))
        return error.AliasedOutput;
    if (signal) |active|
        if (active.flag().load(.acquire)) return error.Cancelled;
    try accepted.revalidateWithSignal(signal);
    var pinned_start = try accepted.pinArtifact(.build_start);
    defer pinned_start.close(io);
    var raw = try files.readSensitiveFile(io, allocator, pinned_start.file, records.max_record_bytes, .private);
    defer raw.deinit();
    var document = try contracts.Document.parse(allocator, raw.bytes(), .{
        .bytes = records.max_record_bytes,
        .depth = 32,
        .items = 4096,
        .tokens = 65536,
    });
    defer document.deinit();
    try document.requireCanonical(allocator, raw.bytes());
    const start = document.value();
    var git = try tool(allocator, io, start, "git", 64 * limits.mib);
    defer git.deinit(io);
    var zig = try tool(allocator, io, start, "zig", 256 * limits.mib);
    defer zig.deinit(io);
    var runtime: std.ArrayList(RuntimePin) = .empty;
    defer {
        for (runtime.items) |*entry| entry.deinit(allocator, io);
        runtime.deinit(allocator);
    }
    try pinRuntime(allocator, io, start, git.path, &runtime);
    try pinRuntime(allocator, io, start, zig.path, &runtime);
    const zig_root = std.fs.path.dirname(zig.path) orelse return error.UnsafePath;
    if (contained(zig_root, output) or contained(output, zig_root) or
        contained(zig_root, repository) or contained(repository, zig_root) or
        contained(zig_root, accepted.root) or contained(accepted.root, zig_root))
        return error.AliasedTool;
    const compiler_before = try tree(allocator, io, start, zig.path);
    const before = try source.source(allocator, io, repository, git.path);
    if (!std.mem.eql(u8, before.revision, accepted.source.revision) or
        !std.mem.eql(u8, before.tree, accepted.source.tree) or
        !std.mem.eql(u8, before.custody.object_format, "sha1"))
        return error.ImportSourceChanged;
    try checkoutSource(before, start);
    const executable_path = try std.process.executablePathAlloc(io, allocator);
    var supervisor = try files.RetainedFile.open(io, executable_path, .tool);
    defer supervisor.close(io);
    try git.pinned.verify(io);
    try zig.pinned.verify(io);
    try accepted.revalidateWithSignal(signal);
    const candidate = if (revalidate) try handoffCandidate(allocator, io, accepted) else &.{};
    if (signal) |active|
        if (active.flag().load(.acquire)) return error.Cancelled;

    const parent_path = std.fs.path.dirname(output) orelse return error.UnsafePath;
    const name = std.fs.path.basename(output);
    try files.basename(name);
    const parent = try files.openDirectory(io, parent_path, .private);
    defer parent.close(io);
    try parent.createDir(io, name, .fromMode(0o700));
    const work = try files.openDirectory(io, output, .private);
    defer work.close(io);
    for ([_][]const u8{ "private", "evidence", "public-source", "cache", "global-cache" }) |entry|
        try work.createDir(io, entry, .fromMode(0o700));
    const private = try work.openDir(io, "private", .{ .iterate = true });
    defer private.close(io);
    const evidence = try work.openDir(io, "evidence", .{ .iterate = true });
    defer evidence.close(io);
    const candidate_path = if (revalidate)
        try std.fs.path.join(allocator, &.{ output, "private/candidate-bundle.json" })
    else
        "";
    if (revalidate) {
        const file = try private.createFile(io, "candidate-bundle.json", .{
            .exclusive = true,
            .read = true,
            .permissions = .fromMode(0o600),
        });
        defer file.close(io);
        try file.writeStreamingAll(io, candidate);
        try file.sync(io);
    }
    var tools: [inputs.host_tools.len][]const u8 = @splat("");
    tools[0] = git.path;
    var roots = plan.Roots{
        .source_root = repository,
        .work = output,
        .runtime = accepted.root,
        .zig = zig.path,
        .producer = "",
        .supervisor = executable_path,
        .package_tool = "",
        .validator = "",
        .tools = tools,
    };
    const outcome = try adapter.execute(allocator, io, .{
        .roots = roots,
        .stage = .@"import-validator-build",
        .private_dir = private,
        .evidence_dir = evidence,
        .cancel = if (signal) |active| active.flag() else null,
    });
    if (outcome.poisoned) return error.CleanupPoisoned;
    if (!outcome.accepted) return error.StageRefused;
    const validator_path = try std.fs.path.join(allocator, &.{ output, "public-source/tools/bin/uk-wamr-direct-validate" });
    var validator = try files.RetainedFile.open(io, validator_path, .tool);
    defer validator.close(io);
    const installed = try physical.readFile(io, validator_path, 64 * limits.mib, false);
    if (installed.bytes < 20 or !std.meta.eql(installed.metadata, physical.metadata(validator.file_snapshot)))
        return error.InvalidValidator;
    var header: [20]u8 = undefined;
    if (try validator.file.readPositionalAll(io, &header, 0) != header.len or
        !std.mem.eql(u8, header[0..4], "\x7fELF") or header[4] != 2 or header[5] != 1 or
        header[18] != 62 or header[19] != 0)
        return error.InvalidValidator;
    try postRun(allocator, io, output, .@"import-validator-build", outcome.bytes);
    var revalidated_bytes: usize = 0;
    var pinned_candidate: ?files.RetainedFile = null;
    defer if (pinned_candidate) |*item| item.close(io);
    if (revalidate) {
        const observed = try physical.readFile(io, candidate_path, 65536, true);
        const digest = std.fmt.bytesToHex(records.fileIdentity(candidate), .lower);
        if (observed.bytes != candidate.len or
            !std.mem.eql(u8, &observed.sha256, &digest))
            return error.CandidateChanged;
        pinned_candidate = try files.RetainedFile.open(io, candidate_path, .private);
        try pinned_candidate.?.verify(io);
        roots.direct_validator = validator_path;
        roots.bundle = candidate_path;
        const checked = try revalidateHandoffCommand(allocator, io, roots, private, evidence, signal);
        revalidated_bytes = @intCast(checked.output_bytes);
        try postRun(allocator, io, output, .@"import-native-revalidation", revalidated_bytes);
        try pinned_candidate.?.verify(io);
    }
    try accepted.revalidateWithSignal(signal);
    const after = try source.source(allocator, io, repository, git.path);
    if (!before.same(after)) return error.SourceChanged;
    const compiler_after = try tree(allocator, io, start, zig.path);
    if (!std.meta.eql(compiler_before.physical_sha256, compiler_after.physical_sha256))
        return error.ImportedToolChanged;
    try postRun(allocator, io, output, .@"import-validator-build", outcome.bytes);
    if (revalidate) {
        try postRun(allocator, io, output, .@"import-native-revalidation", revalidated_bytes);
        try pinned_candidate.?.verify(io);
    }
    try pinned_start.verify(io);
    try git.pinned.verify(io);
    try zig.pinned.verify(io);
    for (runtime.items) |*entry| try entry.file.verify(io);
    try supervisor.verify(io);
    try validator.verify(io);
}
