// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const contracts = core.contracts;
const physical = @import("custody_files.zig");
const inputs = @import("input_custody.zig");
const records = @import("records.zig");
const profile = @import("profile.zig");
const build = @import("build_pipeline.zig");
const boot = @import("boot_pipeline.zig");
const plan = @import("command_plan.zig");
const command = @import("command_validation.zig");
const limits = @import("custody_limits.zig");
const validator = @import("wamr_log_validator");

pub const EvidenceContext = command.EvidenceContext;
pub const ValidatedCommand = command.ValidatedCommand;
pub const Stage = plan.Stage;
pub const SourceIdentity = struct { revision: []const u8, tree: []const u8 };
pub const ResultRecord = struct {
    relative_path: []const u8,
    bytes: u64,
    sha256: [64]u8,
};
pub const PinnedRecord = struct {
    name: []const u8,
    relative_path: []const u8,
    bytes: u64,
    sha256: [64]u8,
};
pub const PinnedArtifact = struct {
    role: []const u8,
    relative_path: []const u8,
    bytes: u64,
    sha256: [64]u8,
    snapshot: [9]i128,
};
pub const PinnedInput = struct {
    role: []const u8,
    path: []const u8,
    snapshot: struct {
        bytes: u64,
        sha256: [64]u8,
        metadata: [9]i128,
        tree: ?struct {
            files: usize,
            directories: usize,
            symlinks: usize,
            physical_sha256: [64]u8,
        } = null,
    },
};
pub const ArtifactRole = enum {
    efi,
    debug_elf,
    bootinfo,
    raw,
    qcow2,
    vhd,
    runtime,
    compiler,
    wasm,
    cwasm,
    config,
    runtime_identity,
    image_identity,
    local_result,
    package,
    build_record,
    build_start,
    boot_inputs,
    qcow2_finalization_intent,
    qcow2_finalization,
    qcow2_acceptance,
    fixed_vhd_derivation_intent,
    fixed_vhd_derivation_gate,
    fixed_vhd_derivation,
    final_inspection,
    cleanup,
};
pub const BootRole = enum { serial, request, report, compute };
const ArtifactSpec = struct {
    role: ArtifactRole,
    relative: []const u8,
    source: bool = false,
};
const artifact_specs = [_]ArtifactSpec{
    .{ .role = .efi, .relative = "support/apps/wamr-aot/build/wamr_hyperv-x86_64-efi", .source = true },
    .{ .role = .debug_elf, .relative = "support/apps/wamr-aot/build/wamr_hyperv-x86_64-efi.dbg", .source = true },
    .{ .role = .bootinfo, .relative = "support/apps/wamr-aot/build/wamr_hyperv-x86_64-efi.bootinfo", .source = true },
    .{ .role = .raw, .relative = "compute/package/unikraft.raw" },
    .{ .role = .qcow2, .relative = "compute/package/unikraft.qcow2" },
    .{ .role = .vhd, .relative = "compute/package/unikraft-derived.vhd" },
    .{ .role = .runtime, .relative = "support/apps/wamr-aot/build/artifacts/libwamr-aot.a", .source = true },
    .{ .role = .compiler, .relative = "support/apps/wamr-aot/build/artifacts/wamrc", .source = true },
    .{ .role = .wasm, .relative = "support/apps/wamr-aot/build/artifacts/tiny.wasm", .source = true },
    .{ .role = .cwasm, .relative = "support/apps/wamr-aot/build/artifacts/tiny.cwasm", .source = true },
    .{ .role = .config, .relative = "support/apps/wamr-aot/.config", .source = true },
    .{ .role = .runtime_identity, .relative = "support/apps/wamr-aot/build/artifacts/identity.json", .source = true },
    .{ .role = .image_identity, .relative = "support/apps/wamr-aot/build/image-identity.json", .source = true },
    .{ .role = .local_result, .relative = "compute/evidence/result.json" },
    .{ .role = .package, .relative = "compute/evidence/package.json" },
    .{ .role = .build_record, .relative = "compute/evidence/build.json" },
    .{ .role = .build_start, .relative = "compute/evidence/build-start.json" },
    .{ .role = .boot_inputs, .relative = "compute/evidence/boot-inputs.json" },
    .{ .role = .qcow2_finalization_intent, .relative = "compute/evidence/qcow2-finalization-intent.json" },
    .{ .role = .qcow2_finalization, .relative = "compute/evidence/qcow2-finalization.json" },
    .{ .role = .qcow2_acceptance, .relative = "compute/evidence/qcow2-acceptance.json" },
    .{ .role = .fixed_vhd_derivation_intent, .relative = "compute/evidence/fixed-vhd-derivation-intent.json" },
    .{ .role = .fixed_vhd_derivation_gate, .relative = "compute/evidence/fixed-vhd-derivation-gate.json" },
    .{ .role = .fixed_vhd_derivation, .relative = "compute/evidence/fixed-vhd-derivation.json" },
    .{ .role = .final_inspection, .relative = "compute/evidence/final-inspection.json" },
    .{ .role = .cleanup, .relative = "evidence/runtime-cleanup.txt" },
};
const max_handoff_bytes = 2 * 1024 * 1024;
const max_artifact_bytes = 256 * 1024 * 1024 + 512;

pub const AcceptedRun = struct {
    arena: std.heap.ArenaAllocator,
    io: std.Io,
    context: EvidenceContext,
    compatibility: profile.CompatibleRecordSet,
    production_profile: ?profile.ProductionProfile,
    source: SourceIdentity,
    result: ResultRecord,
    records: []const PinnedRecord,
    artifacts: []const PinnedArtifact,
    runtime_inputs: []const PinnedInput,
    root: []const u8,
    repository: ?[]const u8,
    environ: ?std.process.Environ,

    pub fn deinit(self: *AcceptedRun) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn allocator(self: *AcceptedRun) std.mem.Allocator {
        return self.arena.allocator();
    }

    fn artifactPath(self: *AcceptedRun, role: ArtifactRole) ![]const u8 {
        for (artifact_specs) |spec| {
            if (spec.role != role) continue;
            if (self.context == .trusted_inner_zip) {
                if (role == .build_record) return join(self.allocator(), &.{ self.root, "artifacts/build" });
                return join(self.allocator(), &.{ self.root, "artifacts", stageRole(role) });
            }
            return join(self.allocator(), &.{
                if (spec.source) self.repository orelse return error.InvalidContext else self.root,
                spec.relative,
            });
        }
        return error.UnknownArtifactRole;
    }

    pub fn pinArtifact(self: *AcceptedRun, role: ArtifactRole) !files.RetainedFile {
        const name = stageRole(role);
        for (self.artifacts) |artifact| {
            if (!std.mem.eql(u8, artifact.role, name)) continue;
            const path = try self.artifactPath(role);
            var retained = try files.RetainedFile.open(self.io, path, if (self.context == .local_runtime and isSource(role)) .artifact else .private);
            errdefer retained.close(self.io);
            const observed = try physical.readFile(self.io, path, max_artifact_bytes, !(self.context == .local_runtime and isSource(role)));
            if (observed.bytes != artifact.bytes or !std.meta.eql(observed.sha256, artifact.sha256) or
                !std.meta.eql(observed.metadata, artifact.snapshot))
                return error.ArtifactChanged;
            try retained.verify(self.io);
            return retained;
        }
        return error.UnknownArtifactRole;
    }

    pub fn pinBoot(self: *AcceptedRun, mode: profile.Mode, part: BootRole) !files.RetainedFile {
        var role_buffer: [64]u8 = undefined;
        const role = try std.fmt.bufPrint(&role_buffer, "boot:{s}:{s}", .{ @tagName(mode), @tagName(part) });
        for (self.artifacts) |item| {
            if (!std.mem.eql(u8, item.role, role)) continue;
            const path = try bootPath(self, mode, part);
            var retained = try files.RetainedFile.open(self.io, path, .private);
            errdefer retained.close(self.io);
            const observed = try physical.readFile(self.io, path, if (part == .serial) 4 * 1024 * 1024 else records.max_record_bytes, true);
            if (observed.bytes != item.bytes or !std.meta.eql(observed.sha256, item.sha256) or
                !std.meta.eql(observed.metadata, item.snapshot))
                return error.BootChanged;
            try retained.verify(self.io);
            return retained;
        }
        return error.UnknownBootRole;
    }

    pub fn revalidate(self: *AcceptedRun) !void {
        return self.revalidateWithSignal(null);
    }

    pub fn revalidateWithSignal(self: *AcceptedRun, signal: ?*core.process.SignalCancellation) !void {
        if (self.context == .local_runtime) {
            try revalidateLocal(self, signal);
        } else {
            try revalidateImported(self);
        }
        for (self.artifacts) |item| {
            if (std.mem.startsWith(u8, item.role, "boot:")) {
                var parts = std.mem.splitScalar(u8, item.role["boot:".len..], ':');
                const mode = std.meta.stringToEnum(profile.Mode, parts.next() orelse return error.UnknownBootRole) orelse return error.UnknownBootRole;
                const part = std.meta.stringToEnum(BootRole, parts.next() orelse return error.UnknownBootRole) orelse return error.UnknownBootRole;
                if (parts.next() != null) return error.UnknownBootRole;
                var retained = try self.pinBoot(mode, part);
                retained.close(self.io);
            } else {
                const role = if (std.mem.eql(u8, item.role, "build")) ArtifactRole.build_record else std.meta.stringToEnum(ArtifactRole, item.role) orelse return error.UnknownArtifactRole;
                var retained = try self.pinArtifact(role);
                retained.close(self.io);
            }
        }
    }

    pub fn handoffV1(self: *AcceptedRun) ![]const u8 {
        const a = self.allocator();
        const modes = profile.modes(self.compatibility);
        var names: std.ArrayList([]const u8) = .empty;
        for (modes) |mode| try names.append(a, @tagName(mode));
        const raw = try std.json.Stringify.valueAlloc(a, .{
            .schema = "uk.wamr.native-ci-controller-records",
            .schema_version = @as(u8, 1),
            .context = if (self.context == .local_runtime) "local-runtime" else "trusted-inner-zip",
            .compatibility = if (self.compatibility == .tiny_v1_legacy) "tiny-v1" else "tiny-v2",
            .profile = if (self.production_profile == null) @as(?[]const u8, null) else "qcow2-derived-vhd",
            .source = self.source,
            .modes = names.items,
            .result = self.result,
            .records = self.records,
            .artifacts = self.artifacts,
            .runtime_inputs = self.runtime_inputs,
        }, .{});
        if (raw.len >= max_handoff_bytes) return error.HandoffTooLarge;
        const encoded = try records.canonicalAlloc(a, raw);
        if (encoded.len > max_handoff_bytes) return error.HandoffTooLarge;
        return encoded;
    }
};

pub fn openAndValidate(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    runtime: *const files.Directory,
    root: []const u8,
    repository: []const u8,
) !AcceptedRun {
    return openAndValidateWithSignal(allocator, io, environ, runtime, root, repository, null);
}

pub fn openAndValidateWithSignal(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    runtime: *const files.Directory,
    root: []const u8,
    repository: []const u8,
    signal: ?*core.process.SignalCancellation,
) !AcceptedRun {
    try files.absoluteFilePath(root);
    try files.absoluteFilePath(repository);
    var accepted = AcceptedRun{
        .arena = std.heap.ArenaAllocator.init(allocator),
        .io = io,
        .context = .local_runtime,
        .compatibility = undefined,
        .production_profile = null,
        .source = undefined,
        .result = undefined,
        .records = &.{},
        .artifacts = &.{},
        .runtime_inputs = &.{},
        .root = root,
        .repository = repository,
        .environ = environ,
    };
    errdefer accepted.deinit();
    const root_snapshot = try files.snapshot(.{ .handle = runtime.dir.handle, .flags = .{ .nonblocking = false } });
    const current_root = try physical.directory(io, root, true);
    if (!files.sameSnapshot(root_snapshot, current_root)) return error.RuntimeChanged;
    accepted.root = try accepted.allocator().dupe(u8, root);
    accepted.repository = try accepted.allocator().dupe(u8, repository);
    try loadResult(&accepted);
    if (accepted.compatibility != .tiny_v2_qcow2_derived_vhd)
        return error.UnsupportedLocalLegacyRun;
    try revalidateLocal(&accepted, signal);
    try collectArtifacts(&accepted);
    return accepted;
}

pub fn openImportedStage(
    allocator: std.mem.Allocator,
    io: std.Io,
    stage: *const files.Directory,
    root: []const u8,
) !AcceptedRun {
    try files.absoluteFilePath(root);
    var accepted = AcceptedRun{
        .arena = std.heap.ArenaAllocator.init(allocator),
        .io = io,
        .context = .trusted_inner_zip,
        .compatibility = undefined,
        .production_profile = null,
        .source = undefined,
        .result = undefined,
        .records = &.{},
        .artifacts = &.{},
        .runtime_inputs = &.{},
        .root = root,
        .repository = null,
        .environ = null,
    };
    errdefer accepted.deinit();
    const stage_snapshot = try files.snapshot(.{ .handle = stage.dir.handle, .flags = .{ .nonblocking = false } });
    const current_stage = try physical.directory(io, root, true);
    if (!files.sameSnapshot(stage_snapshot, current_stage)) return error.StageChanged;
    accepted.root = try accepted.allocator().dupe(u8, root);
    try loadResult(&accepted);
    try revalidateImported(&accepted);
    try collectArtifacts(&accepted);
    return accepted;
}

fn join(a: std.mem.Allocator, parts: []const []const u8) ![]const u8 {
    return std.fs.path.join(a, parts);
}

fn isSource(role: ArtifactRole) bool {
    for (artifact_specs) |spec| if (spec.role == role) return spec.source;
    return false;
}

fn stageRole(role: ArtifactRole) []const u8 {
    return if (role == .build_record) "build" else @tagName(role);
}

fn get(value: std.json.Value, key: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidEvidence;
    return value.object.get(key) orelse error.InvalidEvidence;
}

fn text(value: std.json.Value) ![]const u8 {
    return contracts.string(value);
}

fn number(comptime T: type, value: std.json.Value) !T {
    return contracts.integer(T, value);
}

fn equal(a: []const u8, b: []const u8) !void {
    if (!std.mem.eql(u8, a, b)) return error.EvidenceChanged;
}

fn sameJson(a: std.mem.Allocator, first: std.json.Value, second: std.json.Value) !void {
    const left = try records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, first, .{}));
    const right = try records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, second, .{}));
    try equal(left, right);
}

fn canonicalFile(self: *AcceptedRun, path: []const u8, limit: usize) !std.json.Value {
    return documentFile(self, path, limit, true);
}

fn documentFile(self: *AcceptedRun, path: []const u8, limit: usize, canonical: bool) !std.json.Value {
    const a = self.allocator();
    var retained = try files.RetainedFile.open(self.io, path, .private);
    defer retained.close(self.io);
    var buffer = try files.readSensitiveFile(self.io, a, retained.file, limit, .private);
    defer buffer.deinit();
    var document = try contracts.Document.parse(a, buffer.bytes(), .{
        .bytes = limit,
        .depth = 32,
        .items = 4096,
        .tokens = 65536,
    });
    defer document.deinit();
    if (canonical) try document.requireCanonical(a, buffer.bytes());
    try retained.verify(self.io);
    return std.json.parseFromSliceLeaky(std.json.Value, a, buffer.bytes(), .{
        .duplicate_field_behavior = .@"error",
        .allocate = .alloc_always,
        .parse_numbers = false,
        .max_value_len = 4096,
    });
}

fn recordPath(self: *AcceptedRun, name: []const u8) ![]const u8 {
    try files.basename(name);
    return join(self.allocator(), &.{
        self.root, if (self.context == .local_runtime) "compute/evidence" else "evidence", name,
    });
}

fn resultPath(self: *AcceptedRun) ![]const u8 {
    return if (self.context == .local_runtime)
        recordPath(self, "result.json")
    else
        join(self.allocator(), &.{ self.root, "artifacts/local_result" });
}

fn loadResult(self: *AcceptedRun) !void {
    const a = self.allocator();
    const path = try resultPath(self);
    var retained = try files.RetainedFile.open(self.io, path, .private);
    defer retained.close(self.io);
    var buffer = try files.readSensitiveFile(self.io, a, retained.file, records.max_record_bytes, .private);
    defer buffer.deinit();
    const parsed = try records.parseCanonicalResult(a, buffer.bytes());
    const value = parsed.value;
    if (self.context == .trusted_inner_zip and value.set == .tiny_v1_legacy and
        value.records.count() != 20)
        return error.InvalidRecords;
    self.compatibility = value.set;
    self.production_profile = if (value.set == .tiny_v2_qcow2_derived_vhd) .tiny_exact_v2 else null;
    const observed = try physical.readFile(self.io, path, records.max_record_bytes, true);
    try retained.verify(self.io);
    self.result = .{
        .relative_path = if (self.context == .local_runtime)
            "runtime/compute/evidence/result.json"
        else
            "artifacts/local_result",
        .bytes = observed.bytes,
        .sha256 = observed.sha256,
    };
    const directory_path = try join(a, &.{ self.root, if (self.context == .local_runtime) "compute/evidence" else "evidence" });
    const directory = try files.openDirectory(self.io, directory_path, .private);
    defer directory.close(self.io);
    var iterator = directory.iterate();
    var count: usize = 0;
    while (try iterator.next(self.io)) |entry| {
        if (count > 64 or (self.context == .trusted_inner_zip and
            std.mem.eql(u8, entry.name, "result.json")))
            return error.UnexpectedEvidence;
        if (!value.records.contains(entry.name) and
            !(self.context == .local_runtime and std.mem.eql(u8, entry.name, "result.json")))
            return error.UnexpectedEvidence;
        count += 1;
    }
    if (count != value.records.count() + @intFromBool(self.context == .local_runtime))
        return error.MissingEvidence;
    var pinned: std.ArrayList(PinnedRecord) = .empty;
    var records_iterator = value.records.iterator();
    while (records_iterator.next()) |entry| {
        const path_name = try recordPath(self, entry.key_ptr.*);
        const current = try physical.readFile(self.io, path_name, records.max_record_bytes, true);
        if (!std.mem.eql(u8, &current.sha256, try text(entry.value_ptr.*)))
            return error.RecordChanged;
        _ = try canonicalFile(self, path_name, records.max_record_bytes);
        try pinned.append(a, .{
            .name = entry.key_ptr.*,
            .relative_path = try join(a, &.{ if (self.context == .local_runtime)
                "runtime/compute/evidence"
            else
                "evidence", entry.key_ptr.* }),
            .bytes = current.bytes,
            .sha256 = current.sha256,
        });
    }
    std.mem.sort(PinnedRecord, pinned.items, {}, struct {
        fn less(_: void, x: PinnedRecord, y: PinnedRecord) bool {
            return std.mem.lessThan(u8, x.name, y.name);
        }
    }.less);
    self.records = try pinned.toOwnedSlice(a);
    const build_value = try canonicalFile(self, try recordPath(self, "build.json"), records.max_record_bytes);
    const start_value = try canonicalFile(self, try recordPath(self, "build-start.json"), records.max_record_bytes);
    const source = try get(build_value, "source");
    const start_source = try get(start_value, "source");
    _ = try contracts.exactFields(source, &.{ "revision", "tree" });
    try sameJson(a, source, start_source);
    self.source = .{ .revision = try text(try get(source, "revision")), .tree = try text(try get(source, "tree")) };
    for ([_][]const u8{ self.source.revision, self.source.tree }) |digest| {
        if (digest.len != 40) return error.InvalidSource;
        for (digest) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return error.InvalidSource;
    }
}

fn revalidateLocal(self: *AcceptedRun, signal: ?*core.process.SignalCancellation) !void {
    if (signal) |active| return revalidateLocalWithSignal(self, active);
    var installed = try build.installCancellation();
    defer installed.deinit();
    return revalidateLocalWithSignal(self, &installed);
}

fn revalidateLocalWithSignal(self: *AcceptedRun, signal: *core.process.SignalCancellation) !void {
    const a = self.allocator();
    const raw = try canonicalFile(self, try resultPath(self), records.max_record_bytes);
    const result = try records.readResult(raw);
    if (result.set != self.compatibility or result.set != .tiny_v2_qcow2_derived_vhd)
        return error.InvalidResult;
    const compute = try join(a, &.{ self.root, "compute" });
    var context: build.Context = .{
        .allocator = a,
        .io = self.io,
        .environ = self.environ orelse return error.InvalidContext,
        .runtime = self.root,
        .repository = self.repository orelse return error.InvalidContext,
        .wamr = "",
        .compute = compute,
        .git = undefined,
        .tools = undefined,
        .roots = undefined,
        .signal = signal,
    };
    var boot_context: boot.Context = .{
        .build_context = &context,
        .pinned = std.StringHashMap(physical.File).init(a),
    };
    defer boot_context.pinned.deinit();
    try boot.revalidateComplete(&boot_context, result);
    try validateCommands(self, false);
    const current = try physical.readFile(self.io, try resultPath(self), records.max_record_bytes, true);
    if (!std.meta.eql(current.sha256, self.result.sha256) or current.bytes != self.result.bytes)
        return error.ResultChanged;
    for (self.records) |item| {
        const observed = try physical.readFile(self.io, try recordPath(self, item.name), records.max_record_bytes, true);
        if (!std.meta.eql(observed.sha256, item.sha256) or observed.bytes != item.bytes)
            return error.RecordChanged;
    }
    if (self.runtime_inputs.len == 0)
        try collectRuntimeInputs(self, &context, &boot_context);
}

pub fn validateCommandBinding(
    allocator: std.mem.Allocator,
    record: []const u8,
    stage: Stage,
    context: EvidenceContext,
) !ValidatedCommand {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var document = try contracts.Document.parse(a, record, .{
        .bytes = records.max_record_bytes,
        .depth = 32,
        .items = 4096,
        .tokens = 65536,
    });
    defer document.deinit();
    try document.requireCanonical(a, record);
    return command.validate(a, document.value(), stage, context);
}

pub fn validateLocalHandoffCommand(self: *AcceptedRun, raw: []const u8) !ValidatedCommand {
    if (self.context != .local_runtime or self.repository == null)
        return error.InvalidContext;
    const a = self.allocator();
    var document = try contracts.Document.parse(a, raw, .{
        .bytes = records.max_record_bytes,
        .depth = 32,
        .items = 4096,
        .tokens = 65536,
    });
    defer document.deinit();
    try document.requireCanonical(a, raw);
    const record = document.value();
    const checked = try command.validate(a, record, .@"handoff-inspect", .local_runtime);
    const request = try get(try get(record, "supervisor"), "request");
    const start = try canonicalFile(self, try recordPath(self, "build-start.json"), records.max_record_bytes);
    const boot_inputs = try canonicalFile(self, try recordPath(self, "boot-inputs.json"), records.max_record_bytes);
    for ([_][]const u8{ "supervisor", "native_executable", "command_executable" }) |key|
        try checkRoleIdentity(try get(request, key), start, boot_inputs);
    const retained = try get(request, "retained_executables");
    for (retained.array.items) |binding|
        try checkRoleIdentity(binding, start, boot_inputs);
    return checked;
}

fn validateCommands(self: *AcceptedRun, legacy: bool) !void {
    const start = if (legacy) std.json.Value.null else try canonicalFile(self, try recordPath(self, "build-start.json"), records.max_record_bytes);
    const boot_inputs = if (legacy) std.json.Value.null else try canonicalFile(self, try recordPath(self, "boot-inputs.json"), records.max_record_bytes);
    for (self.records) |item| {
        if (!std.mem.startsWith(u8, item.name, "command-")) continue;
        const stage_name = item.name["command-".len .. item.name.len - ".json".len];
        const stage = std.meta.stringToEnum(plan.Stage, stage_name) orelse return error.UnknownStage;
        const value = try canonicalFile(self, try recordPath(self, item.name), records.max_record_bytes);
        if (legacy) {
            _ = try contracts.exactFields(value, &.{ "scope", "stage", "exit_code", "bytes", "sha256", "over_limit", "known_error_markers" });
            try equal(try text(try get(value, "scope")), "command_diagnostic_not_acceptance");
            try equal(try text(try get(value, "stage")), stage_name);
            if (try number(u8, try get(value, "exit_code")) != 0 or
                try number(u64, try get(value, "bytes")) > plan.spec(stage).output_limit)
                return error.InvalidCommand;
            _ = try contracts.parseSha256(try text(try get(value, "sha256")));
            const over = try get(value, "over_limit");
            const markers = try get(value, "known_error_markers");
            if (over != .bool or over.bool or markers != .array or markers.array.items.len != 0)
                return error.InvalidCommand;
        } else {
            _ = try command.validate(self.allocator(), value, stage, self.context);
            if (self.context == .local_runtime) {
                const log = try join(self.allocator(), &.{ self.root, "compute/private", try std.fmt.allocPrint(self.allocator(), "{s}.log", .{stage_name}) });
                const observed = try physical.readFile(self.io, log, plan.spec(stage).output_limit + 1, true);
                if (observed.bytes != try number(u64, try get(value, "bytes")))
                    return error.CommandOutputChanged;
                try equal(&observed.sha256, try text(try get(value, "sha256")));
            }
            const request = try get(try get(value, "supervisor"), "request");
            for ([_][]const u8{ "supervisor", "native_executable", "command_executable" }) |key|
                try checkRoleIdentity(try get(request, key), start, boot_inputs);
            const interpreter = try get(request, "interpreter");
            if (interpreter != .null)
                try checkRoleIdentity(interpreter, start, boot_inputs);
            const retained = try get(request, "retained_executables");
            for (retained.array.items) |binding|
                try checkRoleIdentity(binding, start, boot_inputs);
        }
    }
}

fn checkRoleIdentity(binding: std.json.Value, start: std.json.Value, boot_inputs: std.json.Value) !void {
    const path = try get(binding, "path");
    const role = try text(try get(path, "role"));
    const record = if (std.mem.startsWith(u8, role, "input:"))
        try get(try get(boot_inputs, "files"), role["input:".len..])
    else
        try get(try get(try get(start, "consumer_inputs"), "files"), role);
    const identity = try get(binding, "identity");
    try equal(try text(try get(identity, "content_sha256")), try text(try get(record, "sha256")));
    const metadata = try get(record, "metadata");
    if (metadata != .array or metadata.array.items.len != 9)
        return error.InvalidCommandIdentity;
    const raw_device = try number(u64, metadata.array.items[0]);
    const major = (raw_device >> 8 & 0xfff) | (raw_device >> 32 & ~@as(u64, 0xfff));
    const minor = (raw_device & 0xff) | (raw_device >> 12 & ~@as(u64, 0xff));
    const mtime = try number(i128, metadata.array.items[7]);
    const ctime = try number(i128, metadata.array.items[8]);
    if (try number(u64, try get(identity, "device_major")) != major or
        try number(u64, try get(identity, "device_minor")) != minor or
        try number(u64, try get(identity, "inode")) != try number(u64, metadata.array.items[1]) or
        try number(u64, try get(identity, "mode")) != try number(u64, metadata.array.items[2]) or
        try number(u64, try get(identity, "uid")) != try number(u64, metadata.array.items[3]) or
        try number(u64, try get(identity, "size")) != try number(u64, metadata.array.items[6]) or
        try number(i64, try get(identity, "mtime_seconds")) != @divFloor(mtime, std.time.ns_per_s) or
        try number(i64, try get(identity, "ctime_seconds")) != @divFloor(ctime, std.time.ns_per_s) or
        try number(u32, try get(identity, "mtime_nanoseconds")) != @mod(mtime, std.time.ns_per_s) or
        try number(u32, try get(identity, "ctime_nanoseconds")) != @mod(ctime, std.time.ns_per_s))
        return error.InvalidCommandIdentity;
}

fn collectRuntimeInputs(self: *AcceptedRun, context: *build.Context, boot_context: *boot.Context) !void {
    const a = self.allocator();
    var result: std.ArrayList(PinnedInput) = .empty;
    for ([_]inputs.Custody{ context.consumer.?.custody, boot_context.boot_inputs.? }) |custody| {
        for (custody.files) |item| {
            const observed = try physical.readFile(self.io, item.path, limits.input_file, false);
            if (!std.meta.eql(observed.metadata, item.metadata) or
                !std.meta.eql(observed.sha256, item.sha256))
                return error.InputChanged;
            try result.append(a, .{ .role = item.role, .path = item.path, .snapshot = .{ .bytes = observed.bytes, .sha256 = observed.sha256, .metadata = observed.metadata } });
        }
        for (custody.trees) |tree| {
            const root = physical.metadata(try physical.directory(self.io, tree.path, false));
            try result.append(a, .{
                .role = try std.fmt.allocPrint(a, "tree:{s}", .{tree.role}),
                .path = tree.path,
                .snapshot = .{
                    .bytes = tree.bytes,
                    .sha256 = tree.content_sha256,
                    .metadata = root,
                    .tree = .{
                        .files = tree.files,
                        .directories = tree.directories,
                        .symlinks = tree.symlinks,
                        .physical_sha256 = tree.physical_sha256,
                    },
                },
            });
        }
    }
    if (result.items.len > 512) return error.InputLimit;
    self.runtime_inputs = try result.toOwnedSlice(a);
}

fn collectArtifacts(self: *AcceptedRun) !void {
    const a = self.allocator();
    var result: std.ArrayList(PinnedArtifact) = .empty;
    for (artifact_specs) |spec| {
        if (self.context == .local_runtime and spec.role == .cleanup) continue;
        if (self.compatibility == .tiny_v1_legacy and
            (spec.role == .qcow2 or spec.role == .cleanup or
                @intFromEnum(spec.role) >= @intFromEnum(ArtifactRole.qcow2_finalization_intent)))
            continue;
        const path_name = try self.artifactPath(spec.role);
        const observed = try physical.readFile(self.io, path_name, max_artifact_bytes, self.context == .trusted_inner_zip or !spec.source);
        try result.append(a, .{
            .role = stageRole(spec.role),
            .relative_path = if (self.context == .local_runtime)
                try join(a, &.{ if (spec.source) "source" else "runtime", spec.relative })
            else
                try join(a, &.{ "artifacts", stageRole(spec.role) }),
            .bytes = observed.bytes,
            .sha256 = observed.sha256,
            .snapshot = observed.metadata,
        });
    }
    for (profile.modes(self.compatibility)) |mode| {
        for ([_]BootRole{ .serial, .request, .report, .compute }) |part| {
            const path_name = try bootPath(self, mode, part);
            const observed = try physical.readFile(self.io, path_name, if (part == .serial) 4 * 1024 * 1024 else records.max_record_bytes, true);
            const role = try std.fmt.allocPrint(a, "boot:{s}:{s}", .{ @tagName(mode), @tagName(part) });
            const relative_path = if (self.context == .local_runtime)
                (if (part == .compute)
                    try join(a, &.{ "runtime/compute/evidence", try std.fmt.allocPrint(a, "{s}-compute.json", .{@tagName(mode)}) })
                else
                    try join(a, &.{ "runtime/compute", try std.fmt.allocPrint(a, "boot-{s}", .{@tagName(mode)}), switch (part) {
                        .serial => "hyperv-efi-boot.log",
                        .request => "request.json",
                        .report => "report.json",
                        .compute => unreachable,
                    } }))
            else
                try join(a, &.{ "boots", @tagName(mode), @tagName(part) });
            try result.append(a, .{ .role = role, .relative_path = relative_path, .bytes = observed.bytes, .sha256 = observed.sha256, .snapshot = observed.metadata });
        }
    }
    if (result.items.len > 64) return error.ArtifactLimit;
    self.artifacts = try result.toOwnedSlice(a);
}

fn bootPath(self: *AcceptedRun, mode: profile.Mode, part: BootRole) ![]const u8 {
    const a = self.allocator();
    if (self.context == .trusted_inner_zip)
        return join(a, &.{ self.root, "boots", @tagName(mode), @tagName(part) });
    if (part == .compute)
        return recordPath(self, try std.fmt.allocPrint(a, "{s}-compute.json", .{@tagName(mode)}));
    return join(a, &.{ self.root, "compute", try std.fmt.allocPrint(a, "boot-{s}", .{@tagName(mode)}), switch (part) {
        .serial => "hyperv-efi-boot.log",
        .request => "request.json",
        .report => "report.json",
        .compute => unreachable,
    } });
}

fn revalidateImported(self: *AcceptedRun) !void {
    const a = self.allocator();
    const version: u8 = if (self.compatibility == .tiny_v1_legacy) 1 else 2;
    const portable = try canonicalFile(self, try join(a, &.{ self.root, "portable-bundle.json" }), 64 * 1024);
    _ = try contracts.exactFields(portable, if (version == 1)
        &.{ "schema", "version", "authority", "source_revision", "source_tree", "identity", "artifacts", "boots", "evidence" }
    else
        &.{ "schema", "version", "profile", "authority", "source_revision", "source_tree", "run", "identity", "lineage", "artifacts", "boots", "evidence" });
    try equal(try text(try get(portable, "schema")), "uk.wamr.local-image-handoff");
    try equal(try text(try get(portable, "authority")), "not_admitted");
    if (try number(u8, try get(portable, "version")) != version)
        return error.InvalidImportedBundle;
    try equal(try text(try get(portable, "source_revision")), self.source.revision);
    try equal(try text(try get(portable, "source_tree")), self.source.tree);
    if (version == 2)
        try equal(try text(try get(portable, "profile")), "qcow2-derived-vhd");
    const legacy = version == 1 and legacySource(self.source);
    if (version == 1 and !legacy) return error.UnsupportedLegacySource;
    const manifest = try canonicalFile(self, try join(a, &.{ self.root, "public-source.json" }), 64 * 1024);
    _ = try contracts.exactFields(manifest, if (version == 1)
        &.{ "schema", "version", "authority", "source", "members" }
    else
        &.{ "schema", "version", "profile", "authority", "source", "members" });
    try equal(try text(try get(manifest, "schema")), "uk.wamr.public-source-bundle");
    try equal(try text(try get(manifest, "authority")), "not_admitted");
    if (try number(u8, try get(manifest, "version")) != version)
        return error.InvalidImportedBundle;
    const source = try get(manifest, "source");
    _ = try contracts.exactFields(source, &.{
        "repository", "run_id", "run_attempt", "source_revision", "source_tree", "wamr_revision",
    });
    try equal(try text(try get(source, "repository")), "cataggar/unikraft");
    try equal(try text(try get(source, "source_revision")), self.source.revision);
    try equal(try text(try get(source, "source_tree")), self.source.tree);
    try equal(try text(try get(source, "wamr_revision")), @import("custody_limits.zig").wamr_revision);
    for ([_][]const u8{ "run_id", "run_attempt" }) |key| {
        const identifier = try text(try get(source, key));
        if (identifier.len == 0 or identifier.len > 20 or identifier[0] < '1' or identifier[0] > '9')
            return error.InvalidImportedBundle;
        for (identifier[1..]) |digit|
            if (!std.ascii.isDigit(digit)) return error.InvalidImportedBundle;
    }
    if (version == 2)
        try equal(try text(try get(manifest, "profile")), "qcow2-derived-vhd");
    if (version == 2) {
        const run = try get(portable, "run");
        _ = try contracts.exactFields(run, &.{ "repository", "run_id", "run_attempt" });
        for ([_][]const u8{ "repository", "run_id", "run_attempt" }) |key|
            try equal(try text(try get(run, key)), try text(try get(source, key)));
    }
    const members = try get(manifest, "members");
    if (members != .object) return error.InvalidImportedBundle;
    const artifact_items = try get(portable, "artifacts");
    const boot_items = try get(portable, "boots");
    const evidence_items = try get(portable, "evidence");
    const expected_artifacts: usize = if (version == 1) 17 else artifact_specs.len;
    if (artifact_items != .array or artifact_items.array.items.len != expected_artifacts or
        boot_items != .array or boot_items.array.items.len != profile.modes(self.compatibility).len or
        evidence_items != .array or evidence_items.array.items.len != self.records.len or
        members.object.count() != expected_artifacts + self.records.len + 4 * boot_items.array.items.len)
        return error.InvalidImportedBundle;
    var total: u64 = 0;
    for (members.object.keys(), members.object.values()) |path, item| {
        try limits.relative(path, 128, 3);
        _ = try contracts.exactFields(item, &.{ "size", "sha256" });
        const size = try number(u64, try get(item, "size"));
        if (size == 0 or size > max_artifact_bytes or total > 512 * limits.mib - 128 * 1024 - size)
            return error.InvalidImportedBundle;
        total += size;
        _ = try contracts.parseSha256(try text(try get(item, "sha256")));
    }
    var cursor: usize = 0;
    for (artifact_specs) |spec| {
        if (version == 1 and (spec.role == .qcow2 or spec.role == .cleanup or
            @intFromEnum(spec.role) >= @intFromEnum(ArtifactRole.qcow2_finalization_intent)))
            continue;
        const name = stageRole(spec.role);
        const relative = try join(a, &.{ "artifacts", name });
        try verifyBundleItem(self, artifact_items.array.items[cursor], members, relative, try self.artifactPath(spec.role), if (spec.role == .cleanup) 128 else if (spec.role == .config) 1024 * 1024 else max_artifact_bytes);
        cursor += 1;
    }
    for (profile.modes(self.compatibility), boot_items.array.items) |mode, entry| {
        _ = try contracts.exactFields(entry, &.{ "mode", "serial", "request", "report", "compute" });
        try equal(try text(try get(entry, "mode")), @tagName(mode));
        for ([_]BootRole{ .serial, .request, .report, .compute }) |part| {
            const relative = try join(a, &.{ "boots", @tagName(mode), @tagName(part) });
            try verifyBundleItem(self, try get(entry, @tagName(part)), members, relative, try bootPath(self, mode, part), if (part == .serial) 4 * 1024 * 1024 else records.max_record_bytes);
        }
    }
    for (self.records, evidence_items.array.items) |entry, item| {
        try verifyBundleItem(self, item, members, entry.relative_path, try recordPath(self, entry.name), records.max_record_bytes);
    }
    var found: usize = 0;
    try inspectImportedTree(self, self.root, "", members, &found, 0);
    if (found != members.object.count() + 2) return error.InvalidImportedBundle;
    const copied_result = try canonicalFile(self, try resultPath(self), records.max_record_bytes);
    const accepted = try records.readResult(copied_result);
    if (accepted.set != self.compatibility or accepted.records.count() != self.records.len)
        return error.InvalidResult;
    for (self.records) |item| {
        const current = try physical.readFile(self.io, try recordPath(self, item.name), records.max_record_bytes, true);
        if (current.bytes != item.bytes or !std.meta.eql(current.sha256, item.sha256))
            return error.RecordChanged;
        try equal(try text(accepted.records.get(item.name) orelse return error.MissingRecord), &current.sha256);
    }
    const actual_result = try physical.readFile(self.io, try resultPath(self), records.max_record_bytes, true);
    if (actual_result.bytes != self.result.bytes or
        !std.meta.eql(actual_result.sha256, self.result.sha256))
        return error.ResultChanged;
    try validateCommands(self, legacy);
    try verifyImportedEvidence(self, portable);
}

fn inspectImportedTree(
    self: *AcceptedRun,
    path: []const u8,
    relative: []const u8,
    members: std.json.Value,
    found: *usize,
    depth: usize,
) !void {
    if (depth > 3) return error.InvalidImportedBundle;
    const directory = try files.openDirectory(self.io, path, .private);
    defer directory.close(self.io);
    var iterator = directory.iterate();
    while (try iterator.next(self.io)) |entry| {
        if (found.* > members.object.count() + 8) return error.InvalidImportedBundle;
        try files.basename(entry.name);
        const child = try join(self.allocator(), &.{ path, entry.name });
        const name = if (relative.len == 0) entry.name else try join(self.allocator(), &.{ relative, entry.name });
        if (entry.kind == .directory) {
            if (relative.len == 0) {
                if (!std.mem.eql(u8, name, "artifacts") and
                    !std.mem.eql(u8, name, "boots") and
                    !std.mem.eql(u8, name, "evidence"))
                    return error.InvalidImportedBundle;
            } else if (std.mem.eql(u8, relative, "boots")) {
                var expected = false;
                for (profile.modes(self.compatibility)) |mode|
                    if (std.mem.eql(u8, entry.name, @tagName(mode))) {
                        expected = true;
                        break;
                    };
                if (!expected) return error.InvalidImportedBundle;
            } else return error.InvalidImportedBundle;
            _ = try physical.directory(self.io, child, true);
            try inspectImportedTree(self, child, name, members, found, depth + 1);
        } else if (entry.kind == .file) {
            if (!members.object.contains(name) and
                !std.mem.eql(u8, name, "portable-bundle.json") and
                !std.mem.eql(u8, name, "public-source.json"))
                return error.UnexpectedImportedFile;
            found.* += 1;
        } else return error.UnexpectedImportedFile;
    }
}

fn verifyBundleItem(
    self: *AcceptedRun,
    item: std.json.Value,
    members: std.json.Value,
    relative: []const u8,
    path: []const u8,
    limit: u64,
) !void {
    _ = try contracts.exactFields(item, &.{ "path", "sha256", "size" });
    try equal(try text(try get(item, "path")), relative);
    const observed = try physical.readFile(self.io, path, limit, true);
    if (observed.bytes == 0 or observed.bytes != try number(u64, try get(item, "size")))
        return error.ArtifactChanged;
    try equal(&observed.sha256, try text(try get(item, "sha256")));
    const member = try get(members, relative);
    _ = try contracts.exactFields(member, &.{ "size", "sha256" });
    if (try number(u64, try get(member, "size")) != observed.bytes) return error.ArtifactChanged;
    try equal(&observed.sha256, try text(try get(member, "sha256")));
}

fn legacySource(source: SourceIdentity) bool {
    const pairs = [_]SourceIdentity{
        .{ .revision = "993e4d0d394c08202c0d0c57ea97450a19a4f394", .tree = "54f8e118146c78c24e7c802657c6ec62b268a5de" },
        .{ .revision = "34e5c88a165c4da878b3122b8b91716116d65d4b", .tree = "54f8e118146c78c24e7c802657c6ec62b268a5de" },
        .{ .revision = "b5a8fdbee033349f7145fbc76aebfee29b2fa04f", .tree = "54f8e118146c78c24e7c802657c6ec62b268a5de" },
        .{ .revision = "0711a0b6bf2285a4ba6ab6dd3bd4088478d665e1", .tree = "3d9def2872f41248b518a850a48a5c462e158890" },
        .{ .revision = "c9c00535399354063486957611bf6e09c8ae4592", .tree = "02827e49c25d06eba21bb2157833fc135811eedb" },
        .{ .revision = "3c6d5d98dc5736d86e97884184b26be39c3f11d5", .tree = "feb57a66615a6083378c7261e1e53c37730e0650" },
    };
    for (pairs) |item|
        if (std.mem.eql(u8, source.revision, item.revision) and
            std.mem.eql(u8, source.tree, item.tree)) return true;
    return false;
}

fn oldLegacySource(source: SourceIdentity) bool {
    return std.mem.eql(u8, source.tree, "54f8e118146c78c24e7c802657c6ec62b268a5de") and
        (std.mem.eql(u8, source.revision, "993e4d0d394c08202c0d0c57ea97450a19a4f394") or
            std.mem.eql(u8, source.revision, "34e5c88a165c4da878b3122b8b91716116d65d4b") or
            std.mem.eql(u8, source.revision, "b5a8fdbee033349f7145fbc76aebfee29b2fa04f"));
}

fn verifyImportedEvidence(self: *AcceptedRun, portable: std.json.Value) !void {
    const a = self.allocator();
    const start = try canonicalFile(self, try recordPath(self, "build-start.json"), records.max_record_bytes);
    const built = try canonicalFile(self, try recordPath(self, "build.json"), records.max_record_bytes);
    const package = try canonicalFile(self, try recordPath(self, "package.json"), records.max_record_bytes);
    const boot_inputs = try canonicalFile(self, try recordPath(self, "boot-inputs.json"), records.max_record_bytes);
    const v2 = self.compatibility == .tiny_v2_qcow2_derived_vhd;
    const old = !v2 and oldLegacySource(self.source);
    if (!old) {
        _ = try contracts.exactFields(start, if (v2)
            &.{ "source", "source_custody", "tools", "bison_data", "dependencies", "consumer_inputs", "command_supervisor" }
        else
            &.{ "source", "source_custody", "tools", "bison_data", "dependencies", "consumer_inputs" });
        try verifyImportedStart(a, start, v2);
    } else {
        if (start != .object) return error.InvalidSourceCustody;
        for (start.object.keys()) |name|
            if (!std.mem.eql(u8, name, "source") and
                !std.mem.eql(u8, name, "tools") and
                !std.mem.eql(u8, name, "bison_data"))
                return error.UnsupportedLegacySource;
    }
    try sameJson(a, try get(start, "source"), try get(built, "source"));
    try compareCopy(self, "build.json", .build_record);
    try compareCopy(self, "build-start.json", .build_start);
    try compareCopy(self, "boot-inputs.json", .boot_inputs);
    try compareCopy(self, "package.json", .package);
    // Producer identity artifacts are not canonical JSON; archive member hashes pin their exact bytes.
    const identity = try documentFile(self, try self.artifactPath(.runtime_identity), 64 * 1024, false);
    if (v2) try build.admitPreparedIdentity(identity);
    try sameJson(a, try get(built, "runtime"), identity);
    const image = try documentFile(self, try self.artifactPath(.image_identity), 1024 * 1024, false);
    try sameJson(a, try get(built, "image"), image);
    for ([_]struct { name: []const u8, role: ArtifactRole }{
        .{ .name = "wamr_hyperv-x86_64-efi", .role = .efi },
        .{ .name = "wamr_hyperv-x86_64-efi.dbg", .role = .debug_elf },
        .{ .name = "wamr_hyperv-x86_64-efi.bootinfo", .role = .bootinfo },
    }) |entry| {
        const expected = try get(try get(image, "files"), entry.name);
        try equal(try text(expected), &(try stagedArtifact(self, entry.role)).sha256);
    }
    const config = try stagedArtifact(self, .config);
    try equal(try text(try get(image, "solved_config_sha256")), &config.sha256);
    const recorded_identity = try stagedArtifact(self, .runtime_identity);
    try equal(try text(try get(image, "runtime_inputs_sha256")), &recorded_identity.sha256);
    if (v2) {
        for ([_]struct { name: []const u8, role: ArtifactRole }{
            .{ .name = "libwamr-aot.a", .role = .runtime },
            .{ .name = "wamrc", .role = .compiler },
            .{ .name = "tiny.wasm", .role = .wasm },
            .{ .name = "tiny.cwasm", .role = .cwasm },
        }) |entry| {
            const expected = try get(try get(identity, "files"), entry.name);
            try equal(try text(expected), &(try stagedArtifact(self, entry.role)).sha256);
        }
    }
    if (v2 or !old) {
        const consumer = try get(start, "consumer_inputs");
        try verifyCustodyDocument(a, consumer);
        try verifyCustodyDocument(a, boot_inputs);
        const consumer_files = try get(consumer, "files");
        for (inputs.host_tools) |name| {
            const tool = try get(consumer_files, try std.fmt.allocPrint(a, "tool:{s}", .{name}));
            try equal(try text(try get(try get(start, "tools"), name)), try text(try get(tool, "sha256")));
        }
        _ = try get(consumer_files, "wamr-source-archive");
        if (v2) {
            _ = try get(consumer_files, "command-supervisor");
            _ = try get(consumer_files, "native:wamr-aot-build");
        }
        const consumer_trees = try get(consumer, "trees");
        for ([_][]const u8{ "bison", "python-stdlib", "zig", "llvm" }) |role|
            _ = try get(consumer_trees, role);
        if (!v2 and consumer_trees.object.contains("system-bin"))
            return error.InvalidInputCustody;
        const boot_files = try get(boot_inputs, "files");
        for ([_][]const u8{ "package_tool", "local_boot_tool", "qemu", "ovmf_code", "ovmf_vars", "efi" }) |role|
            _ = try get(boot_files, role);
        _ = try get(try get(boot_inputs, "trees"), "qemu-data");
        try equal(try text(try get(try get(boot_files, "efi"), "sha256")), &(try stagedArtifact(self, .efi)).sha256);
        if (v2) {
            const supervisor = try get(try get(start, "command_supervisor"), "runtime_map");
            const executable = try get(try get(supervisor, "records"), "executable");
            const copied = try get(consumer_files, "command-supervisor");
            try sameJson(a, executable, try valueOf(a, .{
                .bytes = try number(u64, (try get(copied, "metadata")).array.items[6]),
                .sha256 = try text(try get(copied, "sha256")),
                .metadata = try get(copied, "metadata"),
            }));
        }
    }
    _ = try contracts.exactFields(package, &.{ "scope", "acceptance", "producer_sha256", "image" });
    try equal(try text(try get(package, "scope")), "public_local_compute_packaging_only");
    try equal(try text(try get(package, "acceptance")), "not_established");
    const packaged = try get(package, "image");
    if (v2) {
        _ = try contracts.exactFields(packaged, &.{
            "schema_version", "miz_revision", "efi", "raw", "vhd",
            "footer_sha256",  "packaging",
        });
        if (try number(u8, try get(packaged, "schema_version")) != 1)
            return error.PackageChanged;
        try equal(try text(try get(packaged, "miz_revision")), limits.miz_revision);
        _ = try contracts.parseSha256(try text(try get(packaged, "footer_sha256")));
    }
    for ([_]struct { name: []const u8, role: ArtifactRole }{
        .{ .name = "efi", .role = .efi }, .{ .name = "raw", .role = .raw },
    }) |entry| {
        const value = try get(packaged, entry.name);
        const observed = try stagedArtifact(self, entry.role);
        try equal(try text(try get(value, "sha256")), &observed.sha256);
        if (try number(u64, try get(value, "size")) != observed.bytes)
            return error.PackageChanged;
    }
    if (v2) {
        try equal(try text(try get(package, "producer_sha256")), try text(try get(try get(try get(boot_inputs, "files"), "package_tool"), "sha256")));
        const original_vhd = try get(packaged, "vhd");
        const raw = try stagedArtifact(self, .raw);
        const efi = try stagedArtifact(self, .efi);
        if (raw.bytes != 66 * limits.mib or efi.bytes > 64 * limits.mib or
            try number(u64, try get(original_vhd, "size")) != 66 * limits.mib + 512)
            return error.PackageChanged;
        _ = try contracts.parseSha256(try text(try get(original_vhd, "sha256")));
        try sameJson(a, try get(packaged, "packaging"), try valueOf(a, .{
            .architecture = "x86_64",
            .@"boot-file-sha256" = efi.sha256,
            .@"boot-path" = "EFI/BOOT/BOOTX64.EFI",
            .contract = "miz.efi-application-image",
            .@"esp-length" = 64 * limits.mib,
            .@"esp-offset" = limits.mib,
            .@"file-size" = 66 * limits.mib + 512,
            .format = "vhd",
            .generation = 2,
            .@"schema-version" = 1,
            .subformat = "fixed",
            .valid = true,
            .@"virtual-size" = 66 * limits.mib,
        }));
    } else {
        const producer = if (old)
            try text(try get(boot_inputs, "package_tool"))
        else
            try text(try get(try get(try get(boot_inputs, "files"), "package_tool"), "sha256"));
        try equal(try text(try get(package, "producer_sha256")), producer);
        const original_vhd = try get(packaged, "vhd");
        const observed = try stagedArtifact(self, .vhd);
        try equal(try text(try get(original_vhd, "sha256")), &observed.sha256);
    }
    if (!v2) {
        const efi_file = try stagedArtifact(self, .efi);
        const raw_file = try stagedArtifact(self, .raw);
        const vhd_file = try stagedArtifact(self, .vhd);
        var vhd = try files.RetainedFile.open(self.io, try self.artifactPath(.vhd), .private);
        defer vhd.close(self.io);
        if (efi_file.bytes > 64 * limits.mib or raw_file.bytes != 66 * limits.mib or
            vhd_file.bytes != raw_file.bytes + 512)
            return error.PackageChanged;
        var hash = core.Sha256.init(.{});
        var buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (offset < raw_file.bytes) {
            const count: usize = @intCast(@min(buffer.len, raw_file.bytes - offset));
            if (try vhd.file.readPositionalAll(self.io, buffer[0..count], offset) != count)
                return error.PackageChanged;
            hash.update(buffer[0..count]);
            offset += count;
        }
        const prefix = std.fmt.bytesToHex(hash.finalResult(), .lower);
        try equal(&raw_file.sha256, &prefix);
        var footer: [512]u8 = undefined;
        if (try vhd.file.readPositionalAll(self.io, &footer, raw_file.bytes) != footer.len)
            return error.PackageChanged;
        try verifyFixedVhdFooter(&footer, vhd_file.bytes);
        try vhd.verify(self.io);
        const footer_sha = std.fmt.bytesToHex(records.fileIdentity(&footer), .lower);
        try equal(try text(try get(packaged, "footer_sha256")), &footer_sha);
        try equal(try text(try get(packaged, "miz_revision")), limits.miz_revision);
        try sameJson(a, try get(packaged, "packaging"), try valueOf(a, .{
            .architecture = "x86_64",
            .@"boot-file-sha256" = efi_file.sha256,
            .@"boot-path" = "EFI/BOOT/BOOTX64.EFI",
            .contract = "miz.efi-application-image",
            .@"esp-length" = 64 * limits.mib,
            .@"esp-offset" = limits.mib,
            .@"file-size" = 66 * limits.mib + 512,
            .format = "vhd",
            .generation = 2,
            .@"schema-version" = 1,
            .subformat = "fixed",
            .valid = true,
            .@"virtual-size" = 66 * limits.mib,
        }));
    }
    const hashes = try get(portable, "identity");
    _ = try contracts.exactFields(hashes, &.{
        "wamr_revision",  "wasm_sha256",     "cwasm_sha256",
        "runtime_sha256", "compiler_sha256", "config_sha256",
    });
    try equal(try text(try get(hashes, "wamr_revision")), @import("custody_limits.zig").wamr_revision);
    for ([_]struct { name: []const u8, role: ArtifactRole }{
        .{ .name = "wasm_sha256", .role = .wasm },
        .{ .name = "cwasm_sha256", .role = .cwasm },
        .{ .name = "runtime_sha256", .role = .runtime },
        .{ .name = "compiler_sha256", .role = .compiler },
        .{ .name = "config_sha256", .role = .config },
    }) |entry|
        try equal(try text(try get(hashes, entry.name)), &(try stagedArtifact(self, entry.role)).sha256);

    var boots = std.json.Value{ .object = .empty };
    for (profile.modes(self.compatibility)) |mode| {
        const summary = try verifyImportedBoot(self, mode, boot_inputs);
        try boots.object.put(a, @tagName(mode), summary);
    }
    if (v2)
        try verifyImportedChain(self, portable, package, boot_inputs, boots);
    const result = try canonicalFile(self, try resultPath(self), records.max_record_bytes);
    const modes = try get(result, "modes");
    if (modes != .array or modes.array.items.len != profile.modes(self.compatibility).len)
        return error.InvalidResult;
    for (modes.array.items, profile.modes(self.compatibility)) |item, mode|
        try equal(try text(item), @tagName(mode));
}

fn verifyImportedStart(a: std.mem.Allocator, start: std.json.Value, supervised: bool) !void {
    const custody = try get(start, "source_custody");
    _ = try contracts.exactFields(custody, &.{
        "schema",         "version",         "object_format",         "files", "directories", "bytes",
        "content_sha256", "physical_sha256", "role_excluded_outputs",
    });
    try equal(try text(try get(custody, "schema")), "uk.wamr.git-physical-source");
    try equal(try text(try get(custody, "object_format")), "sha1");
    if (try number(u8, try get(custody, "version")) != 1 or
        try number(u64, try get(custody, "files")) == 0 or
        try number(u64, try get(custody, "files")) > limits.tracked_entries or
        try number(u64, try get(custody, "directories")) == 0 or
        try number(u64, try get(custody, "bytes")) == 0 or
        try number(u64, try get(custody, "bytes")) > limits.tracked_bytes)
        return error.InvalidSourceCustody;
    _ = try contracts.parseSha256(try text(try get(custody, "content_sha256")));
    _ = try contracts.parseSha256(try text(try get(custody, "physical_sha256")));
    const roles = try get(custody, "role_excluded_outputs");
    if (roles != .array or roles.array.items.len != limits.roles.len)
        return error.InvalidSourceCustody;
    for (roles.array.items, limits.roles) |role, expected|
        try equal(try text(role), expected);
    const tools = try get(start, "tools");
    if (tools != .object or tools.object.count() != inputs.host_tools.len)
        return error.InvalidInputCustody;
    for (inputs.host_tools) |tool|
        _ = try contracts.parseSha256(try text(try get(tools, tool)));
    const dependencies = try get(start, "dependencies");
    _ = try contracts.exactFields(dependencies, &.{
        "schema",            "version", "request",  "source_manifests",
        "restore_directory", "restore", "packages",
    });
    try equal(try text(try get(dependencies, "schema")), "uk.wamr.zig-dependency-custody");
    if (try number(u8, try get(dependencies, "version")) != 1)
        return error.InvalidDependency;
    const request = try get(dependencies, "request");
    _ = try contracts.exactFields(request, &.{ "url", "revision", "package_hash" });
    try equal(try text(try get(request, "url")), limits.miz_url);
    try equal(try text(try get(request, "revision")), limits.miz_revision);
    try equal(try text(try get(request, "package_hash")), limits.miz_package_hash);
    try verifyImportedDependencies(a, dependencies);
    if (!supervised) return;
    const supervisor = try get(start, "command_supervisor");
    _ = try contracts.exactFields(supervisor, &.{ "schema", "version", "protocol", "source_map", "runtime_map" });
    try equal(try text(try get(supervisor, "schema")), "uk.wamr.command-supervisor");
    try equal(try text(try get(supervisor, "protocol")), "uk.wamr.command-supervisor/1 process-command/1");
    if (try number(u8, try get(supervisor, "version")) != 1)
        return error.InvalidCommand;
    try guardedMap(a, try get(supervisor, "source_map"), "uk.wamr.command-supervisor-source-v1");
    try guardedMap(a, try get(supervisor, "runtime_map"), "uk.wamr.command-supervisor-runtime-v1");
    const runtime_map = try get(try get(supervisor, "runtime_map"), "records");
    _ = try get(runtime_map, "executable");
}

fn verifyFixedVhdFooter(footer: *const [512]u8, size: u64) !void {
    const capacity = std.mem.readInt(u64, footer[48..56], .big);
    if (size != 66 * limits.mib + 512 or capacity != size - 512 or
        !std.mem.eql(u8, footer[0..8], "conectix") or
        std.mem.readInt(u32, footer[8..12], .big) != 2 or
        std.mem.readInt(u32, footer[12..16], .big) != 0x10000 or
        std.mem.readInt(u64, footer[16..24], .big) != std.math.maxInt(u64) or
        std.mem.readInt(u64, footer[40..48], .big) != capacity or
        std.mem.readInt(u32, footer[60..64], .big) != 2 or
        footer[84] != 0 or
        std.mem.allEqual(u8, footer[68..84], 0) or
        !std.mem.allEqual(u8, footer[85..], 0))
        return error.InvalidFixedVhd;
    var sum: u32 = 0;
    for (footer, 0..) |byte, index|
        if (index < 64 or index >= 68) {
            sum +%= byte;
        };
    if (std.mem.readInt(u32, footer[64..68], .big) != ~sum)
        return error.InvalidFixedVhd;
    const cylinders: u64 = std.mem.readInt(u16, footer[56..58], .big);
    const heads: u64 = footer[58];
    const sectors: u64 = footer[59];
    const geometry = cylinders * heads * sectors;
    const exact = capacity / 512;
    if (cylinders == 0 or heads == 0 or heads > 16 or sectors == 0 or
        geometry > exact or exact - geometry >= heads * sectors)
        return error.InvalidFixedVhd;
    for ([_][]const u8{ "vpc ", "vs  ", "qemu" }) |creator|
        if (std.mem.eql(u8, footer[28..32], creator) and geometry != exact)
            return error.InvalidFixedVhd;
}

fn recordedMetadata(value: std.json.Value, kind: u32, permissions: ?u32, size: ?u64) ![]const std.json.Value {
    if (value != .array or value.array.items.len != 9) return error.InvalidRecordedMetadata;
    const metadata = value.array.items;
    for (metadata) |item| _ = try number(u64, item);
    if (try number(u64, metadata[0]) == 0 or
        try number(u64, metadata[1]) == 0 or
        try number(u64, metadata[5]) == 0)
        return error.InvalidRecordedMetadata;
    const mode = try number(u32, metadata[2]);
    if (mode & std.os.linux.S.IFMT != kind or mode & 0o022 != 0 or
        (permissions != null and mode & 0o7777 != permissions.?))
        return error.InvalidRecordedMetadata;
    if (size) |expected|
        if (try number(u64, metadata[6]) != expected) return error.InvalidRecordedMetadata;
    return metadata;
}

fn verifyImportedDependencies(a: std.mem.Allocator, dependencies: std.json.Value) !void {
    const source_manifests = try get(dependencies, "source_manifests");
    _ = try contracts.exactFields(source_manifests, &.{ "build.zig", "build.zig.zon" });
    for ([_][]const u8{ "build.zig", "build.zig.zon" }, [_][]const u8{
        "support/tools/hyperv/local_boot/build.zig",
        "support/tools/hyperv/local_boot/build.zig.zon",
    }) |name, path| {
        const pair = try get(source_manifests, name);
        _ = try contracts.exactFields(pair, &.{ "source", "copy" });
        const source = try get(pair, "source");
        _ = try contracts.exactFields(source, &.{
            "path", "mode", "bytes", "sha256", "git_oid", "metadata", "metadata_sha256",
        });
        try equal(try text(try get(source, "path")), path);
        try equal(try text(try get(source, "mode")), "100644");
        const source_size = try number(u64, try get(source, "bytes"));
        if (source_size == 0 or source_size > limits.mib) return error.InvalidDependency;
        const hash = try text(try get(source, "sha256"));
        _ = try contracts.parseSha256(hash);
        const git_oid = try text(try get(source, "git_oid"));
        if (git_oid.len != 40) return error.InvalidDependency;
        for (git_oid) |digit|
            if (!std.ascii.isDigit(digit) and !(digit >= 'a' and digit <= 'f'))
                return error.InvalidDependency;
        const metadata = try get(source, "metadata");
        _ = try recordedMetadata(metadata, std.os.linux.S.IFREG, 0o644, source_size);
        const expected_metadata_hash = std.fmt.bytesToHex(try records.identity(a, try std.json.Stringify.valueAlloc(a, metadata, .{})), .lower);
        try equal(try text(try get(source, "metadata_sha256")), &expected_metadata_hash);
        const copy = try get(pair, "copy");
        _ = try contracts.exactFields(copy, &.{ "bytes", "sha256", "metadata" });
        if (try number(u64, try get(copy, "bytes")) != source_size) return error.InvalidDependency;
        try equal(try text(try get(copy, "sha256")), hash);
        const copied = try recordedMetadata(try get(copy, "metadata"), std.os.linux.S.IFREG, 0o600, source_size);
        if (try number(u64, copied[5]) != 1) return error.InvalidDependency;
    }
    const restore_directory = try get(dependencies, "restore_directory");
    _ = try contracts.exactFields(restore_directory, &.{"metadata"});
    _ = try recordedMetadata(try get(restore_directory, "metadata"), std.os.linux.S.IFDIR, 0o700, null);
    const restore = try get(dependencies, "restore");
    _ = try contracts.exactFields(restore, &.{
        "scope", "stage", "exit_code", "bytes", "sha256", "over_limit", "known_error_markers",
    });
    try equal(try text(try get(restore, "scope")), "command_diagnostic_not_acceptance");
    try equal(try text(try get(restore, "stage")), "dependency-restore");
    if (try number(u8, try get(restore, "exit_code")) != 0 or
        try number(u64, try get(restore, "bytes")) > 8 * limits.mib)
        return error.InvalidDependency;
    _ = try contracts.parseSha256(try text(try get(restore, "sha256")));
    const over = try get(restore, "over_limit");
    const markers = try get(restore, "known_error_markers");
    if (over != .bool or over.bool or markers != .array or markers.array.items.len != 0)
        return error.InvalidDependency;

    const packages = try get(dependencies, "packages");
    _ = try contracts.exactFields(packages, &.{
        "roots",         "files",                "directories", "bytes",             "closure_sha256", "physical_sha256",
        "root_metadata", "root_metadata_sha256", "manifests",   "hash_verification", "records",
    });
    const entries = try get(packages, "records");
    if (entries != .array or entries.array.items.len == 0 or entries.array.items.len > limits.dependency_roots or
        try number(u64, try get(packages, "roots")) != entries.array.items.len)
        return error.InvalidDependency;
    const root_metadata = try get(packages, "root_metadata");
    _ = try recordedMetadata(root_metadata, std.os.linux.S.IFDIR, 0o700, null);
    const root_hash = std.fmt.bytesToHex(try records.identity(a, try std.json.Stringify.valueAlloc(a, root_metadata, .{})), .lower);
    try equal(try text(try get(packages, "root_metadata_sha256")), &root_hash);
    var names = std.StringHashMap(std.json.Value).init(a);
    var counts: [3]u64 = .{ 0, 0, 0 };
    var manifests_count: u64 = 0;
    var manifests_bytes: u64 = 0;
    var closure = core.Sha256.init(.{});
    closure.update("uk.wamr.package-closure-v1\x00");
    var physical_hash = core.Sha256.init(.{});
    physical_hash.update("uk.wamr.package-physical-closure-v1\x00");
    var manifests_hash = core.Sha256.init(.{});
    manifests_hash.update("uk.wamr.package-manifests-v1\x00");
    var hash_records = std.json.Value{ .array = std.array_list.Managed(std.json.Value).init(a) };
    var previous: []const u8 = "";
    for (entries.array.items) |entry| {
        _ = try contracts.exactFields(entry, &.{ "package_hash", "content", "manifest" });
        const name = try text(try get(entry, "package_hash"));
        try limits.packageName(name);
        if (previous.len != 0 and !std.mem.lessThan(u8, previous, name))
            return error.InvalidDependency;
        previous = name;
        try names.put(name, entry);
        const content = try get(entry, "content");
        _ = try contracts.exactFields(content, &.{
            "files", "directories", "bytes", "tree_sha256", "physical_sha256",
        });
        for ([_][]const u8{ "files", "directories", "bytes" }, &counts, [_]u64{
            limits.dependency_entries, limits.dependency_entries, limits.dependency_bytes,
        }) |key, *total, maximum| {
            const amount = try number(u64, try get(content, key));
            if (amount == 0 or amount > maximum or total.* > maximum - amount)
                return error.InvalidDependency;
            total.* += amount;
        }
        if (counts[0] + counts[1] > limits.dependency_entries)
            return error.InvalidDependency;
        _ = try contracts.parseSha256(try text(try get(content, "tree_sha256")));
        const content_hash = try text(try get(content, "physical_sha256"));
        _ = try contracts.parseSha256(content_hash);
        const manifest = try get(entry, "manifest");
        if (manifest != .null) {
            _ = try contracts.exactFields(manifest, &.{ "bytes", "sha256", "dependencies" });
            const size = try number(u64, try get(manifest, "bytes"));
            if (size == 0 or size > 4 * limits.mib or manifests_bytes > limits.dependency_bytes - size)
                return error.InvalidDependency;
            manifests_count += 1;
            manifests_bytes += size;
            _ = try contracts.parseSha256(try text(try get(manifest, "sha256")));
            const deps = try get(manifest, "dependencies");
            if (deps != .array or deps.array.items.len > limits.dependency_roots)
                return error.InvalidDependency;
            var prior: []const u8 = "";
            for (deps.array.items) |dependency| {
                const next = try text(dependency);
                try limits.packageName(next);
                if (prior.len != 0 and !std.mem.lessThan(u8, prior, next))
                    return error.InvalidDependency;
                prior = next;
            }
            try physical.bind(a, &manifests_hash, .{ name, manifest });
        }
        try physical.bind(a, &closure, entry);
        try physical.bind(a, &physical_hash, .{ name, content_hash });
        const name_line = try std.fmt.allocPrint(a, "{s}\n", .{name});
        const verification_hash = std.fmt.bytesToHex(records.fileIdentity(name_line), .lower);
        try hash_records.array.append(try valueOf(a, .{ .package_hash = name, .sha256 = verification_hash }));
    }
    if (!names.contains(limits.miz_package_hash) or
        counts[0] != try number(u64, try get(packages, "files")) or
        counts[1] != try number(u64, try get(packages, "directories")) or
        counts[1] < entries.array.items.len or
        counts[2] != try number(u64, try get(packages, "bytes")))
        return error.InvalidDependency;
    const closure_hash = physical.hex(&closure);
    const physical_digest = physical.hex(&physical_hash);
    try equal(try text(try get(packages, "closure_sha256")), &closure_hash);
    try equal(try text(try get(packages, "physical_sha256")), &physical_digest);
    const summary = try get(packages, "manifests");
    _ = try contracts.exactFields(summary, &.{ "count", "bytes", "sha256" });
    const manifests_digest = physical.hex(&manifests_hash);
    if (manifests_count != try number(u64, try get(summary, "count")) or
        manifests_bytes != try number(u64, try get(summary, "bytes")))
        return error.InvalidDependency;
    try equal(try text(try get(summary, "sha256")), &manifests_digest);
    const hash_verification = try get(packages, "hash_verification");
    _ = try contracts.exactFields(hash_verification, &.{ "algorithm", "count", "sha256" });
    try equal(try text(try get(hash_verification, "algorithm")), "zig-0.16.0-fetch-path");
    if (try number(u64, try get(hash_verification, "count")) != entries.array.items.len)
        return error.InvalidDependency;
    const hash_digest = std.fmt.bytesToHex(try records.identity(a, try std.json.Stringify.valueAlloc(a, hash_records, .{})), .lower);
    try equal(try text(try get(hash_verification, "sha256")), &hash_digest);
    var reached = std.StringHashMap(void).init(a);
    var pending: std.ArrayList([]const u8) = .empty;
    try pending.append(a, limits.miz_package_hash);
    while (pending.pop()) |name| {
        if (reached.contains(name)) continue;
        const entry = names.get(name) orelse return error.InvalidDependency;
        try reached.put(name, {});
        const manifest = try get(entry, "manifest");
        if (manifest == .null) continue;
        const deps = try get(manifest, "dependencies");
        for (deps.array.items) |dependency|
            try pending.append(a, try text(dependency));
        if (reached.count() + pending.items.len > 2 * limits.dependency_roots)
            return error.InvalidDependency;
    }
    if (reached.count() != entries.array.items.len) return error.InvalidDependency;
}

fn guardedMap(a: std.mem.Allocator, value: std.json.Value, domain: []const u8) !void {
    _ = try contracts.exactFields(value, &.{ "count", "bytes", "content_closure_sha256", "physical_closure_sha256", "records" });
    const map = try get(value, "records");
    if (map != .object or map.object.count() == 0 or map.object.count() > 256 or
        try number(u64, try get(value, "count")) != map.object.count())
        return error.InvalidCommand;
    var content = core.Sha256.init(.{});
    content.update(try std.fmt.allocPrint(a, "{s}-content\x00", .{domain}));
    var physical_hash = core.Sha256.init(.{});
    physical_hash.update(try std.fmt.allocPrint(a, "{s}-physical\x00", .{domain}));
    const names = try a.dupe([]const u8, map.object.keys());
    std.mem.sort([]const u8, names, {}, struct {
        fn less(_: void, first: []const u8, second: []const u8) bool {
            return std.mem.lessThan(u8, first, second);
        }
    }.less);
    var total: u64 = 0;
    for (names) |name| {
        const entry = try get(map, name);
        _ = try contracts.exactFields(entry, &.{ "bytes", "sha256", "metadata" });
        const bytes = try number(u64, try get(entry, "bytes"));
        if (bytes == 0 or bytes > 256 * 1024 * 1024 or total > 512 * 1024 * 1024 - bytes)
            return error.InvalidCommand;
        total += bytes;
        const sha = try text(try get(entry, "sha256"));
        _ = try contracts.parseSha256(sha);
        const metadata = try get(entry, "metadata");
        if (metadata != .array or metadata.array.items.len != 9 or
            try number(u64, metadata.array.items[6]) != bytes)
            return error.InvalidCommand;
        var values: [9]i128 = undefined;
        for (metadata.array.items, &values) |part, *slot| slot.* = try number(i128, part);
        try physical.bind(a, &content, .{ name, bytes, sha });
        try physical.bind(a, &physical_hash, .{ name, values });
    }
    if (total != try number(u64, try get(value, "bytes"))) return error.InvalidCommand;
    const content_hash = physical.hex(&content);
    const metadata_hash = physical.hex(&physical_hash);
    try equal(try text(try get(value, "content_closure_sha256")), &content_hash);
    try equal(try text(try get(value, "physical_closure_sha256")), &metadata_hash);
}

fn stagedArtifact(self: *AcceptedRun, role: ArtifactRole) !physical.File {
    return physical.readFile(self.io, try self.artifactPath(role), if (role == .cleanup) 128 else max_artifact_bytes, true);
}

fn compareCopy(self: *AcceptedRun, filename: []const u8, role: ArtifactRole) !void {
    const one = try physical.readFile(self.io, try recordPath(self, filename), records.max_record_bytes, true);
    const other = try stagedArtifact(self, role);
    if (one.bytes != other.bytes or !std.meta.eql(one.sha256, other.sha256))
        return error.RecordCopyChanged;
}

fn verifyCustodyDocument(a: std.mem.Allocator, value: std.json.Value) !void {
    _ = try contracts.exactFields(value, &.{ "schema", "version", "files", "trees", "directories", "aggregate_sha256" });
    try equal(try text(try get(value, "schema")), "uk.wamr.consumer-input-custody");
    if (try number(u8, try get(value, "version")) != 2) return error.InvalidInputCustody;
    const file_map = try get(value, "files");
    const tree_map = try get(value, "trees");
    const directories = try get(value, "directories");
    if (file_map != .object or file_map.object.count() == 0 or file_map.object.count() > 256 or
        tree_map != .object or tree_map.object.count() == 0 or tree_map.object.count() > 16 or
        directories != .object or directories.object.count() == 0 or directories.object.count() > 512)
        return error.InvalidInputCustody;
    for (file_map.object.keys(), file_map.object.values()) |role, file| {
        if (role.len == 0 or role.len > 4096) return error.InvalidInputCustody;
        _ = try contracts.exactFields(file, &.{ "path", "metadata", "sha256" });
        try files.absoluteFilePath(try text(try get(file, "path")));
        const metadata = try get(file, "metadata");
        const checked = try recordedMetadata(metadata, std.os.linux.S.IFREG, null, null);
        if (try number(u64, checked[6]) == 0 or
            try number(u64, checked[6]) > limits.input_file)
            return error.InvalidInputCustody;
        _ = try contracts.parseSha256(try text(try get(file, "sha256")));
    }
    for (tree_map.object.keys(), tree_map.object.values()) |role, tree| {
        if (role.len == 0 or role.len > 64) return error.InvalidInputCustody;
        _ = try contracts.exactFields(tree, &.{ "path", "files", "directories", "symlinks", "bytes", "content_sha256", "physical_sha256" });
        try files.absoluteFilePath(try text(try get(tree, "path")));
        const files_count = try number(u64, try get(tree, "files"));
        const directory_count = try number(u64, try get(tree, "directories"));
        const symlink_count = try number(u64, try get(tree, "symlinks"));
        if (directory_count == 0 or
            files_count > limits.input_entries or
            directory_count > limits.input_entries - files_count or
            symlink_count > limits.input_entries - files_count - directory_count or
            try number(u64, try get(tree, "bytes")) > limits.input_bytes)
            return error.InvalidInputCustody;
        _ = try contracts.parseSha256(try text(try get(tree, "content_sha256")));
        _ = try contracts.parseSha256(try text(try get(tree, "physical_sha256")));
    }
    for (directories.object.keys(), directories.object.values()) |path, metadata| {
        if (!std.mem.eql(u8, path, "/")) try files.absoluteFilePath(path);
        _ = try recordedMetadata(metadata, std.os.linux.S.IFDIR, null, null);
    }
    const hash = try text(try get(value, "aggregate_sha256"));
    _ = try contracts.parseSha256(hash);
    var unsealed = std.json.Value{ .object = .empty };
    var iterator = value.object.iterator();
    while (iterator.next()) |entry|
        if (!std.mem.eql(u8, entry.key_ptr.*, "aggregate_sha256"))
            try unsealed.object.put(a, entry.key_ptr.*, entry.value_ptr.*);
    const raw = try std.json.Stringify.valueAlloc(a, unsealed, .{});
    const expected = std.fmt.bytesToHex(try records.identity(a, raw), .lower);
    try equal(hash, &expected);
}

fn evidenceHash(self: *AcceptedRun, name: []const u8) ![]const u8 {
    for (self.records) |*entry| if (std.mem.eql(u8, entry.name, name))
        return &entry.sha256;
    return error.MissingRecord;
}

fn valueOf(a: std.mem.Allocator, value: anytype) !std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, a, try std.json.Stringify.valueAlloc(a, value, .{}), .{ .allocate = .alloc_always, .parse_numbers = false });
}

fn verifyImportedBoot(self: *AcceptedRun, mode: profile.Mode, boot_inputs: std.json.Value) !std.json.Value {
    const a = self.allocator();
    const request_path = try bootPath(self, mode, .request);
    const report_path = try bootPath(self, mode, .report);
    const serial_path = try bootPath(self, mode, .serial);
    const request = try canonicalFile(self, request_path, records.max_record_bytes);
    const report = try canonicalFile(self, report_path, records.max_record_bytes);
    const name = try std.fmt.allocPrint(a, "{s}-compute.json", .{@tagName(mode)});
    const compute = try canonicalFile(self, try recordPath(self, name), records.max_record_bytes);
    try compareBootCopy(self, mode, name);
    _ = try contracts.exactFields(request, &.{ "schema_version", "supervisor_pid", "config", "pins" });
    const old = self.compatibility == .tiny_v1_legacy and oldLegacySource(self.source);
    if (try number(u32, try get(request, "supervisor_pid")) == 0 or
        try number(u8, try get(request, "schema_version")) !=
            @as(u8, if (old) 1 else 2))
        return error.InvalidBootRequest;
    const config = try get(request, "config");
    const image_role: ArtifactRole = switch (mode) {
        .@"raw-x2apic", .@"raw-legacy-apic" => .raw,
        .@"qcow2-x2apic", .@"qcow2-legacy-apic" => .qcow2,
        .@"vpc-x2apic", .@"vpc-legacy-apic" => .vhd,
    };
    const work_dir = try text(try get(config, "work_dir"));
    try files.absoluteFilePath(work_dir);
    const mode_suffix = try std.fmt.allocPrint(a, "/compute/boot-{s}", .{@tagName(mode)});
    if (!std.mem.endsWith(u8, work_dir, mode_suffix))
        return error.InvalidBootRequest;
    const runtime = work_dir[0 .. work_dir.len - mode_suffix.len];
    if (!std.mem.eql(u8, runtime, "/d/wamr-ci/wamr-native-runtime") and
        !std.mem.endsWith(u8, runtime, "/.d/wamr-native-runtime"))
        return error.InvalidBootRequest;
    const compute_root = try join(a, &.{ runtime, "compute" });
    const expected_config = try boot.expectedModeConfig(
        a,
        mode,
        try join(a, &.{ compute_root, "package", if (image_role == .vhd and self.compatibility == .tiny_v1_legacy)
            "unikraft.vhd"
        else
            plan.bootImage(mode) }),
        try join(a, &.{ runtime, "firmware/code.fd" }),
        try join(a, &.{ runtime, "firmware/vars.fd" }),
        try join(a, &.{ runtime, "bin/qemu-system-x86_64" }),
        work_dir,
    );
    try sameJson(a, config, expected_config);
    const pins = try get(request, "pins");
    if (pins != .array or pins.array.items.len != 4)
        return error.InvalidBootPins;
    const first = pins.array.items[0];
    try verifyBootPin(first, null, !old);
    const observed_image = try stagedArtifact(self, image_role);
    if (try number(u64, try get(first, "size")) != observed_image.bytes)
        return error.InvalidBootPins;
    const raw_hash = try get(first, "sha256");
    if (raw_hash != .array or raw_hash.array.items.len != 32) return error.InvalidBootPins;
    const sha = try contracts.parseSha256(&observed_image.sha256);
    for (raw_hash.array.items, sha) |item, byte|
        if (try number(u8, item) != byte) return error.InvalidBootPins;
    if (!old) {
        const files_map = try get(boot_inputs, "files");
        for ([_][]const u8{ "ovmf_code", "ovmf_vars", "qemu" }, 1..) |role, index| {
            const original = try get(files_map, role);
            const metadata = try get(original, "metadata");
            const expected_pin = pins.array.items[index];
            try equal(try text(try get(config, role)), try text(try get(original, "path")));
            try verifyBootPin(expected_pin, .{ .metadata = metadata, .digest = try text(try get(original, "sha256")) }, true);
        }
    } else for (pins.array.items[1..]) |pin| try verifyBootPin(pin, null, false);
    try equal(try text(try get(report, "scope")), "public_local_qemu_only");
    try equal(try text(try get(report, "acceptance")), "not_established");
    if (try number(u8, try get(report, "schema_version")) != 1)
        return error.InvalidBootReport;
    for ([_][]const u8{ "passed", "consumed", "cleanup_complete", "input_unchanged", "serial_valid" }) |key| {
        const checked = try get(report, key);
        if (checked != .bool or !checked.bool) return error.InvalidBootReport;
    }
    const exceeded = try get(report, "serial_limit_reached");
    if (exceeded != .bool or exceeded.bool) return error.InvalidBootReport;
    const termination = try get(report, "termination");
    _ = try contracts.exactFields(termination, &.{"exited"});
    if (try number(u8, try get(termination, "exited")) != 0)
        return error.InvalidBootReport;
    const failures = try get(report, "failures");
    _ = try contracts.exactFields(failures, &.{ "primary", "cleanup", "recording" });
    for ([_][]const u8{ "primary", "cleanup", "recording" }) |key|
        if (try get(failures, key) != .null) return error.InvalidBootReport;
    const raw = try physical.readFile(self.io, serial_path, 4 * 1024 * 1024, true);
    if (raw.bytes == 0 or raw.bytes >= 4 * 1024 * 1024 or
        try number(u64, try get(report, "serial_bytes")) != raw.bytes)
        return error.SerialChanged;
    try equal(try text(try get(report, "serial_sha256")), &raw.sha256);
    var parsed = try validator.validate(a, self.io, serial_path, try self.artifactPath(.runtime_identity), .{ .tiny = if (mode.legacyApic()) .required else .forbidden });
    defer parsed.deinit();
    if (parsed.raw_serial_bytes != raw.bytes or
        !std.meta.eql(parsed.raw_serial_sha256, try contracts.parseSha256(&raw.sha256)))
        return error.SerialChanged;
    try equal(try text(try get(compute, "scope")), "local_native_compute_only");
    try sameJson(a, try get(compute, "report"), report);
    try sameJson(a, try get(compute, "input_pins"), pins);
    const request_file = try physical.readFile(self.io, request_path, records.max_record_bytes, true);
    const report_file = try physical.readFile(self.io, report_path, records.max_record_bytes, true);
    try equal(try text(try get(compute, "request_sha256")), &request_file.sha256);
    try equal(try text(try get(compute, "report_sha256")), &report_file.sha256);
    try sameJson(a, try get(compute, "compute"), try valueOf(a, parsed.compute orelse return error.InvalidComputeEvidence));
    var summary = std.json.Value{ .object = .empty };
    try summary.object.put(a, "request_sha256", .{ .string = try a.dupe(u8, &request_file.sha256) });
    try summary.object.put(a, "report_sha256", .{ .string = try a.dupe(u8, &report_file.sha256) });
    try summary.object.put(a, "serial_sha256", .{ .string = try a.dupe(u8, &raw.sha256) });
    try summary.object.put(a, "compute_sha256", .{ .string = try evidenceHash(self, name) });
    return summary;
}

fn verifyBootPin(pin: std.json.Value, recorded: ?struct { metadata: std.json.Value, digest: []const u8 }, detailed: bool) !void {
    const hash = try get(pin, "sha256");
    if (hash != .array or hash.array.items.len != 32) return error.InvalidBootPins;
    const size = try number(u64, try get(pin, "size"));
    if (size == 0 or size > max_artifact_bytes) return error.InvalidBootPins;
    for (hash.array.items) |item| _ = try number(u8, item);
    if (detailed) {
        _ = try contracts.exactFields(pin, &.{
            "device_major", "device_minor", "inode",         "mode",              "uid",           "gid",
            "nlink",        "size",         "mtime_seconds", "mtime_nanoseconds", "ctime_seconds", "ctime_nanoseconds",
            "sha256",
        });
        for ([_][]const u8{ "device_major", "device_minor", "inode", "mode", "uid", "gid", "nlink" }) |key|
            _ = try number(u64, try get(pin, key));
        const mode = try number(u32, try get(pin, "mode"));
        if (try number(u64, try get(pin, "inode")) == 0 or
            try number(u64, try get(pin, "nlink")) == 0 or
            mode & std.os.linux.S.IFMT != std.os.linux.S.IFREG or mode & 0o022 != 0 or
            try number(u32, try get(pin, "mtime_nanoseconds")) >= std.time.ns_per_s or
            try number(u32, try get(pin, "ctime_nanoseconds")) >= std.time.ns_per_s)
            return error.InvalidBootPins;
        _ = try number(i64, try get(pin, "mtime_seconds"));
        _ = try number(i64, try get(pin, "ctime_seconds"));
    } else _ = try contracts.exactFields(pin, &.{ "size", "sha256" });
    if (recorded) |original| {
        if (!detailed or original.metadata != .array or original.metadata.array.items.len != 9)
            return error.InvalidBootPins;
        const metadata = original.metadata.array.items;
        const dev = try number(u64, metadata[0]);
        const mtime = try number(i128, metadata[7]);
        const ctime = try number(i128, metadata[8]);
        for ([_]struct { key: []const u8, expected: u64 }{
            .{ .key = "device_major", .expected = (dev >> 8 & 0xfff) | (dev >> 32 & ~@as(u64, 0xfff)) },
            .{ .key = "device_minor", .expected = (dev & 0xff) | (dev >> 12 & ~@as(u64, 0xff)) },
            .{ .key = "inode", .expected = try number(u64, metadata[1]) },
            .{ .key = "mode", .expected = try number(u64, metadata[2]) },
            .{ .key = "uid", .expected = try number(u64, metadata[3]) },
            .{ .key = "gid", .expected = try number(u64, metadata[4]) },
            .{ .key = "nlink", .expected = try number(u64, metadata[5]) },
            .{ .key = "size", .expected = try number(u64, metadata[6]) },
            .{ .key = "mtime_nanoseconds", .expected = @intCast(@mod(mtime, std.time.ns_per_s)) },
            .{ .key = "ctime_nanoseconds", .expected = @intCast(@mod(ctime, std.time.ns_per_s)) },
        }) |field|
            if (try number(u64, try get(pin, field.key)) != field.expected)
                return error.InvalidBootPins;
        if (try number(i64, try get(pin, "mtime_seconds")) != @divFloor(mtime, std.time.ns_per_s) or
            try number(i64, try get(pin, "ctime_seconds")) != @divFloor(ctime, std.time.ns_per_s))
            return error.InvalidBootPins;
        const expected_hash = try contracts.parseSha256(original.digest);
        for (hash.array.items, expected_hash) |item, byte|
            if (try number(u8, item) != byte) return error.InvalidBootPins;
    }
}

fn compareBootCopy(self: *AcceptedRun, mode: profile.Mode, name: []const u8) !void {
    const first = try physical.readFile(self.io, try recordPath(self, name), records.max_record_bytes, true);
    const second = try physical.readFile(self.io, try bootPath(self, mode, .compute), records.max_record_bytes, true);
    if (first.bytes != second.bytes or !std.meta.eql(first.sha256, second.sha256))
        return error.RecordCopyChanged;
}

fn verifyImportedChain(
    self: *AcceptedRun,
    portable: std.json.Value,
    package: std.json.Value,
    boot_inputs: std.json.Value,
    boots: std.json.Value,
) !void {
    const a = self.allocator();
    const mib: u64 = 1024 * 1024;
    const raw = try stagedArtifact(self, .raw);
    const efi = try stagedArtifact(self, .efi);
    const qcow2 = try stagedArtifact(self, .qcow2);
    const vhd = try stagedArtifact(self, .vhd);
    for ([_]struct { name: []const u8, role: ArtifactRole }{
        .{ .name = "qcow2-finalization-intent.json", .role = .qcow2_finalization_intent },
        .{ .name = "qcow2-finalization.json", .role = .qcow2_finalization },
        .{ .name = "qcow2-acceptance.json", .role = .qcow2_acceptance },
        .{ .name = "fixed-vhd-derivation-intent.json", .role = .fixed_vhd_derivation_intent },
        .{ .name = "fixed-vhd-derivation-gate.json", .role = .fixed_vhd_derivation_gate },
        .{ .name = "fixed-vhd-derivation.json", .role = .fixed_vhd_derivation },
        .{ .name = "final-inspection.json", .role = .final_inspection },
    }) |entry| try compareCopy(self, entry.name, entry.role);
    var cleanup = try files.RetainedFile.open(self.io, try self.artifactPath(.cleanup), .private);
    defer cleanup.close(self.io);
    var cleanup_bytes = try files.readSensitiveFile(self.io, a, cleanup.file, 128, .private);
    defer cleanup_bytes.deinit();
    try equal(cleanup_bytes.bytes(), "primary=0 cleanup=0\n");
    try cleanup.verify(self.io);

    const intent = try chainRecord(self, "qcow2-finalization-intent.json", "uk.wamr.compute-qcow2-finalization-intent");
    _ = try contracts.exactFields(intent, &.{
        "schema",                "schema_version",         "source_path",              "expected_source_sha256",
        "expected_source_bytes", "expected_virtual_bytes", "expected_workload_sha256", "expected_workload_bytes",
        "timeout_ms",            "limits",
    });
    try sourceSuffix(intent, "source_path", "/package/unikraft.raw");
    try equal(try text(try get(intent, "expected_source_sha256")), &raw.sha256);
    try equal(try text(try get(intent, "expected_workload_sha256")), &efi.sha256);
    if (try number(u64, try get(intent, "expected_source_bytes")) != raw.bytes or
        try number(u64, try get(intent, "expected_virtual_bytes")) != raw.bytes or
        try number(u64, try get(intent, "expected_workload_bytes")) != efi.bytes or
        try number(u32, try get(intent, "timeout_ms")) != 120_000)
        return error.InvalidImageChain;
    try sameJson(a, try get(intent, "limits"), try valueOf(a, boot.compute_limits));
    const finalization = try chainRecord(self, "qcow2-finalization.json", "uk.wamr.compute-qcow2-finalization");
    _ = try contracts.exactFields(finalization, &.{
        "schema", "schema_version", "status",  "source_sha256", "source_bytes",
        "output", "identity",       "profile", "limits",        "provenance",
    });
    try equal(try text(try get(finalization, "status")), "succeeded");
    try equal(try text(try get(finalization, "source_sha256")), &raw.sha256);
    if (try number(u64, try get(finalization, "source_bytes")) != raw.bytes)
        return error.InvalidImageChain;
    try sameJson(a, try get(finalization, "limits"), try get(intent, "limits"));
    const finalized = try get(finalization, "output");
    try imageOutput(finalized, qcow2, raw.bytes);
    try sameJson(a, try get(finalization, "profile"), try valueOf(a, .{
        .format = "qcow2",
        .version = 3,
        .cluster_bytes = 64 * 1024,
        .compression = "zstd",
        .incompatible_features = 8,
        .compatible_features = 0,
        .autoclear_features = 0,
        .header_extensions = false,
        .extended_l2 = false,
        .encryption = false,
        .snapshots = 0,
        .backing_file = false,
        .external_data_file = false,
        .standalone = true,
    }));
    const original_identity = try get(finalization, "identity");
    try equal(try text(try get(original_identity, "workload_sha256")), &efi.sha256);
    if (try number(u64, try get(original_identity, "workload_bytes")) != efi.bytes)
        return error.InvalidImageChain;
    const producer = try text(try get(package, "producer_sha256"));
    try provenance(try get(finalization, "provenance"), "raw", &raw.sha256, producer);

    const acceptance = try chainRecord(self, "qcow2-acceptance.json", "uk.wamr.compute-qcow2-acceptance");
    _ = try contracts.exactFields(acceptance, &.{
        "schema",              "schema_version", "profile", "status",       "source",             "accepted_qcow2",
        "finalization_sha256", "modes",          "boots",   "build_sha256", "boot_inputs_sha256",
    });
    try equal(try text(try get(acceptance, "profile")), "qcow2-derived-vhd");
    try equal(try text(try get(acceptance, "status")), "accepted");
    try sameJson(a, try get(acceptance, "source"), try valueOf(a, self.source));
    try imageOutput(try get(acceptance, "accepted_qcow2"), qcow2, raw.bytes);
    try evidenceReference(self, acceptance, "finalization_sha256", "qcow2-finalization.json");
    try evidenceReference(self, acceptance, "build_sha256", "build.json");
    try evidenceReference(self, acceptance, "boot_inputs_sha256", "boot-inputs.json");
    try matchModes(try get(acceptance, "modes"), profile.production_modes[0..4]);
    try matchBoots(a, try get(acceptance, "boots"), boots, profile.production_modes[0..4]);

    const vhd_intent = try chainRecord(self, "fixed-vhd-derivation-intent.json", "uk.wamr.compute-fixed-vhd-derivation-intent");
    _ = try contracts.exactFields(vhd_intent, &.{
        "schema",                "schema_version",          "source_path", "accepted_qcow2_sha256",
        "expected_source_bytes", "expected_capacity_bytes", "timeout_ms",  "limits",
    });
    try sourceSuffix(vhd_intent, "source_path", "/package/unikraft.qcow2");
    try equal(try text(try get(vhd_intent, "accepted_qcow2_sha256")), &qcow2.sha256);
    if (try number(u64, try get(vhd_intent, "expected_source_bytes")) != qcow2.bytes or
        try number(u64, try get(vhd_intent, "expected_capacity_bytes")) != raw.bytes or
        try number(u32, try get(vhd_intent, "timeout_ms")) != 120_000)
        return error.InvalidImageChain;
    try sameJson(a, try get(vhd_intent, "limits"), try get(intent, "limits"));
    const gate = try chainRecord(self, "fixed-vhd-derivation-gate.json", "uk.wamr.compute-fixed-vhd-derivation-gate");
    _ = try contracts.exactFields(gate, &.{
        "schema",                  "schema_version",           "profile",               "status", "accepted_qcow2_sha256",
        "qcow2_acceptance_sha256", "derivation_intent_sha256", "derived_output_absent",
    });
    try equal(try text(try get(gate, "profile")), "qcow2-derived-vhd");
    try equal(try text(try get(gate, "status")), "accepted_qcow2_only");
    try equal(try text(try get(gate, "accepted_qcow2_sha256")), &qcow2.sha256);
    try evidenceReference(self, gate, "qcow2_acceptance_sha256", "qcow2-acceptance.json");
    try evidenceReference(self, gate, "derivation_intent_sha256", "fixed-vhd-derivation-intent.json");
    const absent = try get(gate, "derived_output_absent");
    if (absent != .bool or !absent.bool) return error.InvalidImageChain;

    const derivation = try chainRecord(self, "fixed-vhd-derivation.json", "uk.wamr.compute-fixed-vhd-derivation");
    _ = try contracts.exactFields(derivation, &.{
        "schema",                        "schema_version",         "status",          "accepted_qcow2",
        "accepted_qcow2_decoded_sha256", "accepted_qcow2_profile", "source_identity", "output",
        "output_identity",               "footer",                 "relocation",      "limits",
        "provenance",
    });
    try equal(try text(try get(derivation, "status")), "succeeded");
    for ([_][]const u8{ "sha256", "file_bytes", "virtual_bytes" }) |key|
        try sameJson(a, try get(try get(derivation, "accepted_qcow2"), key), try get(finalized, key));
    try equal(try text(try get(derivation, "accepted_qcow2_decoded_sha256")), &raw.sha256);
    try sameJson(a, try get(derivation, "accepted_qcow2_profile"), try get(finalization, "profile"));
    try sameJson(a, try get(derivation, "source_identity"), original_identity);
    try sameJson(a, try get(derivation, "output_identity"), original_identity);
    try sameJson(a, try get(derivation, "limits"), try get(intent, "limits"));
    if (vhd.bytes != 66 * mib + 512) return error.InvalidImageChain;
    try imageOutput(try get(derivation, "output"), vhd, 66 * mib);
    try provenance(try get(derivation, "provenance"), "qcow2", &qcow2.sha256, producer);
    const footer = try get(derivation, "footer");
    try equal(try text(try get(footer, "creator")), "miz ");
    if (try number(u64, try get(footer, "timestamp")) != 0) return error.InvalidImageChain;
    var retained = try files.RetainedFile.open(self.io, try self.artifactPath(.vhd), .private);
    defer retained.close(self.io);
    var last: [512]u8 = undefined;
    if (try retained.file.readPositionalAll(self.io, &last, vhd.bytes - 512) != 512)
        return error.InvalidImageChain;
    try retained.verify(self.io);
    const footer_hash = std.fmt.bytesToHex(records.fileIdentity(&last), .lower);
    try equal(try text(try get(footer, "sha256")), &footer_hash);
    const relocation = try get(derivation, "relocation");
    try sameJson(a, relocation, try valueOf(a, .{
        .was_relocated = false,
        .old_backup_lba = try get(relocation, "new_backup_lba"),
        .new_backup_lba = try get(relocation, "new_backup_lba"),
        .old_last_usable_lba = try get(relocation, "new_last_usable_lba"),
        .new_last_usable_lba = try get(relocation, "new_last_usable_lba"),
        .allowed_differences = "protective-mbr,primary-gpt,relocated-backup-gpt,zero-padding",
    }));
    const inspection = try chainRecord(self, "final-inspection.json", "uk.wamr.compute-image-chain-inspection");
    _ = try contracts.exactFields(inspection, &.{
        "schema",    "schema_version", "profile", "status", "source",
        "artifacts", "records",        "modes",   "boots",
    });
    try equal(try text(try get(inspection, "profile")), "qcow2-derived-vhd");
    try equal(try text(try get(inspection, "status")), "complete");
    try sameJson(a, try get(inspection, "source"), try get(acceptance, "source"));
    try matchModes(try get(inspection, "modes"), &profile.production_modes);
    try matchBoots(a, try get(inspection, "boots"), boots, &profile.production_modes);
    const accepted_artifacts = try get(inspection, "artifacts");
    if (accepted_artifacts != .object or accepted_artifacts.object.count() != 4)
        return error.InvalidImageChain;
    for ([_]struct { key: []const u8, value: physical.File }{
        .{ .key = "efi", .value = efi },     .{ .key = "raw", .value = raw },
        .{ .key = "qcow2", .value = qcow2 }, .{ .key = "vhd", .value = vhd },
    }) |entry| {
        const item = try get(accepted_artifacts, entry.key);
        try equal(try text(try get(item, "sha256")), &entry.value.sha256);
        if (try number(u64, try get(item, "file_bytes")) != entry.value.bytes)
            return error.InvalidImageChain;
    }
    const map = try get(inspection, "records");
    const names = [_][]const u8{
        "build-start.json",               "build.json",                "boot-inputs.json",      "package.json",
        "qcow2-finalization-intent.json", "qcow2-finalization.json",   "qcow2-acceptance.json", "fixed-vhd-derivation-intent.json",
        "fixed-vhd-derivation-gate.json", "fixed-vhd-derivation.json",
    };
    if (map != .object or map.object.count() != names.len) return error.InvalidImageChain;
    for (names) |name|
        try equal(try text(try get(map, name)), try evidenceHash(self, name));
    const lineage = try get(portable, "lineage");
    _ = try contracts.exactFields(lineage, &.{
        "raw_sha256",                  "accepted_qcow2_sha256",   "derived_vhd_sha256",
        "qcow2_finalization_sha256",   "qcow2_acceptance_sha256", "fixed_vhd_derivation_gate_sha256",
        "fixed_vhd_derivation_sha256", "final_inspection_sha256",
    });
    for ([_]struct { key: []const u8, hash: []const u8 }{
        .{ .key = "raw_sha256", .hash = &raw.sha256 },
        .{ .key = "accepted_qcow2_sha256", .hash = &qcow2.sha256 },
        .{ .key = "derived_vhd_sha256", .hash = &vhd.sha256 },
        .{ .key = "qcow2_finalization_sha256", .hash = try evidenceHash(self, "qcow2-finalization.json") },
        .{ .key = "qcow2_acceptance_sha256", .hash = try evidenceHash(self, "qcow2-acceptance.json") },
        .{ .key = "fixed_vhd_derivation_gate_sha256", .hash = try evidenceHash(self, "fixed-vhd-derivation-gate.json") },
        .{ .key = "fixed_vhd_derivation_sha256", .hash = try evidenceHash(self, "fixed-vhd-derivation.json") },
        .{ .key = "final_inspection_sha256", .hash = try evidenceHash(self, "final-inspection.json") },
    }) |entry| try equal(try text(try get(lineage, entry.key)), entry.hash);
    _ = boot_inputs;
}

fn chainRecord(self: *AcceptedRun, name: []const u8, schema: []const u8) !std.json.Value {
    const value = try canonicalFile(self, try recordPath(self, name), records.max_record_bytes);
    try equal(try text(try get(value, "schema")), schema);
    if (try number(u8, try get(value, "schema_version")) != 1)
        return error.InvalidImageChain;
    return value;
}

fn sourceSuffix(value: std.json.Value, key: []const u8, suffix: []const u8) !void {
    const path = try text(try get(value, key));
    try files.absoluteFilePath(path);
    if (!std.mem.endsWith(u8, path, suffix)) return error.InvalidImageChain;
}

fn imageOutput(value: std.json.Value, file: physical.File, virtual: u64) !void {
    try equal(try text(try get(value, "sha256")), &file.sha256);
    if (try number(u64, try get(value, "file_bytes")) != file.bytes or
        try number(u64, try get(value, "virtual_bytes")) != virtual)
        return error.InvalidImageChain;
}

fn provenance(value: std.json.Value, kind: []const u8, parent: []const u8, producer: []const u8) !void {
    try equal(try text(try get(value, "parent_kind")), kind);
    try equal(try text(try get(value, "parent_sha256")), parent);
    try equal(try text(try get(value, "producer_sha256")), producer);
}

fn evidenceReference(self: *AcceptedRun, value: std.json.Value, key: []const u8, name: []const u8) !void {
    try equal(try text(try get(value, key)), try evidenceHash(self, name));
}

fn matchModes(value: std.json.Value, expected: []const profile.Mode) !void {
    if (value != .array or value.array.items.len != expected.len)
        return error.InvalidModes;
    for (value.array.items, expected) |entry, mode| try equal(try text(entry), @tagName(mode));
}

fn matchBoots(a: std.mem.Allocator, value: std.json.Value, expected: std.json.Value, modes: []const profile.Mode) !void {
    if (value != .object or value.object.count() != modes.len) return error.InvalidModes;
    for (modes) |mode| try sameJson(a, try get(value, @tagName(mode)), try get(expected, @tagName(mode)));
}
