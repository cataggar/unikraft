// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const controller = @import("wamr_controller");
const files = core.private_files;
const contracts = controller.handoff_contracts;
const copy = @import("retained_copy.zig");
const products = @import("public_products.zig");
const validation = controller.import_validator_build;

pub const Settings = struct {
    attempt_id: ?[]const u8 = null,
    subscription: ?[]const u8 = null,
    prefix: ?[]const u8 = null,
};
pub const Source = union(enum) {
    private_bundle: *controller.accepted_run.PrivateBundle,
    imported_product: *products.ImportedProduct,

    fn bundle(self: Source) !*controller.accepted_run.PrivateBundle {
        return switch (self) {
            .private_bundle => |owner| owner,
            .imported_product => |owner| if (owner.publication == .durable and owner.bundle != null)
                &owner.bundle.?
            else
                error.ImportNotPublished,
        };
    }
    fn revalidate(self: Source, signal: ?*core.process.SignalCancellation) !void {
        switch (self) {
            .private_bundle => |owner| try owner.revalidate(signal),
            .imported_product => |owner| try owner.revalidate(signal),
        }
    }
};
pub const Invocation = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    source: Source,
    output: []const u8,
    validation_output: []const u8,
    settings: Settings = .{},
    signal: ?*core.process.SignalCancellation = null,
};
pub const Phase = enum { inputs, native_validation, bindings, admission, publication, final_revalidation };
pub const Diagnostic = struct { phase: Phase, err: anyerror, publication: files.CommitStatus = .not_committed };
pub const Outcome = union(enum) { success: *Finalized, refused: Diagnostic, poisoned: Diagnostic };

pub const Artifact = struct { path: []const u8, sha256: []const u8, size: u64 };
pub const Identity = struct {
    wamr_revision: []const u8,
    wasm_sha256: []const u8,
    cwasm_sha256: []const u8,
    runtime_sha256: []const u8,
    compiler_sha256: []const u8,
    config_sha256: []const u8,
};
pub const Scope = struct {
    schema: []const u8 = "uk.wamr.direct-compute",
    version: u8,
    purpose: []const u8,
    authority: enum { not_admitted } = .not_admitted,
    approval: struct {
        direct_specialized_gen2: bool = false,
        os_only_private: bool = false,
        two_boots_only: bool = false,
        cleanup_owned_group: bool = false,
        exact_image_and_local_bundle_reviewed: bool = false,
        fresh_final_approval: bool = false,
        approved_unix: u64 = 0,
        expires_unix: u64 = 0,
    } = .{},
    attempt_id: []const u8,
    subscription: []const u8,
    location: []const u8 = "northeurope",
    prefix: []const u8,
    vm_size: []const u8 = "Standard_D2s_v5",
    serial_mode: enum { azure_cumulative } = .azure_cumulative,
    runtime_seconds: u32 = 3600,
    cleanup_seconds: u32 = 1800,
    operation_seconds: u32 = 600,
    poll_seconds: u32 = 10,
    source_revision: []const u8,
    source_tree: []const u8,
    identity: Identity,
    os_vhd: Artifact,
    bundle: Artifact,
};

// Only successful construction yields this boundary. The borrowed source must
// outlive it; authority consumers revalidate it instead of re-parsing metadata.
pub const Finalized = opaque {
    fn state(self: *Finalized) *State {
        return @ptrCast(@alignCast(self));
    }
    pub fn revalidate(self: *Finalized, signal: ?*core.process.SignalCancellation) !void {
        try self.state().revalidate(signal);
    }
    pub fn inspect(self: *Finalized, signal: ?*core.process.SignalCancellation) !Scope {
        try self.revalidate(signal);
        return self.state().scope;
    }
    pub fn artifact(self: *Finalized, signal: ?*core.process.SignalCancellation) !Artifact {
        try self.revalidate(signal);
        return self.state().candidate.?.artifact();
    }
    pub fn result(
        self: *Finalized,
        first_path: []const u8,
        second_path: ?[]const u8,
        signal: ?*core.process.SignalCancellation,
    ) !controller.tiny.Result {
        const owner = self.state();
        try owner.revalidate(signal);
        var first = try owner.retain(first_path, contracts.layout.max_serial_bytes, signal);
        defer first.file.close(owner.inv.io);
        var first_bytes = try files.readSensitiveFile(owner.inv.io, owner.arena.allocator(), first.file.file, contracts.layout.max_serial_bytes, .private);
        defer first_bytes.deinit();
        const identity = owner.scope.identity;
        var observed = try checkSerial(owner.arena.allocator(), first_bytes.bytes(), identity);
        if (second_path) |path| {
            var second = try owner.retain(path, contracts.layout.max_serial_bytes, signal);
            defer second.file.close(owner.inv.io);
            var second_bytes = try files.readSensitiveFile(owner.inv.io, owner.arena.allocator(), second.file.file, contracts.layout.max_serial_bytes, .private);
            defer second_bytes.deinit();
            observed = try checkSerial(owner.arena.allocator(), try secondBytes(second_bytes.bytes(), first_bytes.bytes()), identity);
            try owner.verifyHeld(&second, signal);
        }
        try owner.verifyHeld(&first, signal);
        try owner.revalidate(signal);
        return observed;
    }
    pub fn deinit(self: *Finalized) void {
        self.state().deinit();
    }
};

const Held = struct {
    file: files.RetainedFile,
    digest: [64]u8,
    limit: u64,

    fn artifact(self: *const Held) Artifact {
        return .{ .path = self.file.path, .sha256 = &self.digest, .size = self.file.file_snapshot.size };
    }
};
const State = struct {
    inv: Invocation,
    arena: std.heap.ArenaAllocator,
    held: std.ArrayList(Held) = .empty,
    candidate: ?Held = null,
    admission: ?Held = null,
    scope: Scope = undefined,
    phase: Phase = .inputs,
    publication: files.CommitStatus = .not_committed,
    reserved: bool = false,

    fn retain(self: *State, path: []const u8, limit: u64, signal: ?*core.process.SignalCancellation) !Held {
        const owned_path = try self.arena.allocator().dupe(u8, path);
        var file = try files.RetainedFile.open(self.inv.io, owned_path, .private);
        errdefer file.close(self.inv.io);
        return .{ .file = file, .digest = try copy.hashRetained(self.inv.io, &file, limit, if (signal) |active| active.flag() else null), .limit = limit };
    }
    fn verifyHeld(self: *State, held: *Held, signal: ?*core.process.SignalCancellation) !void {
        const digest = try copy.hashRetained(self.inv.io, &held.file, held.limit, if (signal) |active| active.flag() else null);
        if (!std.mem.eql(u8, &digest, &held.digest)) return error.CandidateInputChanged;
    }
    fn revalidate(self: *State, signal: ?*core.process.SignalCancellation) !void {
        try copy.checkCancellation(if (signal) |active| active.flag() else null);
        try self.inv.source.revalidate(signal);
        for (self.held.items) |*held| try self.verifyHeld(held, signal);
        if (self.admission) |*held| try self.verifyHeld(held, signal);
        if (self.candidate) |*held| try self.verifyHeld(held, signal);
        try self.inv.source.revalidate(signal);
    }
    fn deinit(self: *State) void {
        if (self.candidate) |*held| held.file.close(self.inv.io);
        if (self.admission) |*held| held.file.close(self.inv.io);
        for (self.held.items) |*held| held.file.close(self.inv.io);
        self.held.deinit(self.inv.allocator);
        const allocator = self.inv.allocator;
        self.arena.deinit();
        allocator.destroy(self);
    }
    fn document(self: *State, held: *Held) !core.contracts.Document {
        var bytes = try files.readSensitiveFile(self.inv.io, self.arena.allocator(), held.file.file, contracts.layout.max_json_bytes, .private);
        defer bytes.deinit();
        return contracts.parseCanonical(self.arena.allocator(), bytes.bytes());
    }
    fn publish(self: *State, path: []const u8, bytes: []const u8) !files.CommitStatus {
        const parent = try files.FileParent.open(self.inv.io, path, .private);
        defer parent.close(self.inv.io);
        var lock = try (files.Directory{ .dir = parent.directory }).lock(self.inv.io);
        defer lock.close(self.inv.io);
        const committed = try lock.createImmutable(self.inv.io, parent.name, bytes);
        if (self.phase == .publication) self.publication = committed.status;
        if (committed.status != .durable or committed.failures.primary != null or committed.failures.cleanup != null or committed.failures.recording != null)
            return error.PublicationUncertain;
        return committed.status;
    }
};

pub fn create(inv: Invocation) Outcome {
    return construct(inv, false);
}

pub fn open(inv: Invocation) Outcome {
    return construct(inv, true);
}

fn construct(inv: Invocation, existing: bool) Outcome {
    const owner = inv.allocator.create(State) catch |err| return .{ .refused = .{ .phase = .inputs, .err = err } };
    owner.* = .{ .inv = inv, .arena = std.heap.ArenaAllocator.init(inv.allocator) };
    finish(owner, existing) catch |err| {
        const diagnostic: Diagnostic = .{ .phase = owner.phase, .err = err, .publication = owner.publication };
        const reserved = owner.reserved;
        owner.deinit();
        return if (reserved) .{ .poisoned = diagnostic } else .{ .refused = diagnostic };
    };
    return .{ .success = @ptrCast(owner) };
}

fn finish(owner: *State, existing: bool) !void {
    const inv = owner.inv;
    const a = owner.arena.allocator();
    try files.absoluteFilePath(inv.output);
    try files.absoluteFilePath(inv.validation_output);
    const bundle = try inv.source.bundle();
    if (inside(inv.output, bundle.evidence.root) or inside(bundle.evidence.root, inv.output) or
        inside(inv.output, bundle.evidence.repository.?) or inside(bundle.evidence.repository.?, inv.output))
        return error.AliasedOutput;
    try inv.source.revalidate(inv.signal);
    owner.phase = .native_validation;
    owner.reserved = true;
    try validation.runPrivate(inv.allocator, inv.io, bundle, inv.validation_output, inv.signal);
    for ([_][]const u8{ "evidence/command-import-native-revalidation.json", "private/import-native-revalidation.log" }) |relative| {
        var retained = try owner.retain(try std.fs.path.join(a, &.{ inv.validation_output, relative }), contracts.layout.max_json_bytes, inv.signal);
        errdefer retained.file.close(inv.io);
        try owner.held.append(inv.allocator, retained);
    }
    owner.phase = .bindings;
    var manifest = try owner.retain(bundle.manifest.path, contracts.layout.max_json_bytes, inv.signal);
    defer manifest.file.close(inv.io);
    var document = try owner.document(&manifest);
    defer document.deinit();
    const value = document.value();
    const compatibility = try contracts.validateLocalImageHandoffWithRoot(value, bundle.evidence.root);
    const version = compatibility.version();
    var scope_bundle = manifest.artifact();
    var admission_bytes: ?[]const u8 = null;
    const admission_path = try std.fmt.allocPrint(a, "{s}.admission.json", .{inv.output});
    if (version == 2) {
        var transport = try owner.retain(try std.fs.path.join(a, &.{ bundle.evidence.root, "transport.json" }), contracts.layout.max_json_bytes, inv.signal);
        errdefer transport.file.close(inv.io);
        var transport_document = try owner.document(&transport);
        defer transport_document.deinit();
        try contracts.validatePublicSourceTransportV2(transport_document.value());
        const receipt = transport_document.value().object;
        const fields = value.object;
        const run = fields.get("run").?.object;
        inline for (.{ "repository", "run_id", "run_attempt" }) |key|
            if (!std.mem.eql(u8, try core.contracts.string(receipt.get(key).?), try core.contracts.string(run.get(key).?)))
                return error.TransportMismatch;
        inline for (.{ "source_revision", "source_tree" }) |key|
            if (!std.mem.eql(u8, try core.contracts.string(receipt.get(key).?), try core.contracts.string(fields.get(key).?)))
                return error.TransportMismatch;
        admission_bytes = try canonical(a, .{
            .schema = "uk.wamr.direct-compute-admission",
            .version = @as(u8, 2),
            .profile = contracts.profile.current_profile,
            .authority = "not_admitted",
            .source_revision = fields.get("source_revision").?,
            .source_tree = fields.get("source_tree").?,
            .run = fields.get("run").?,
            .lineage = fields.get("lineage").?,
            .public_bundle = manifest.artifact(),
            .transport = transport.artifact(),
        });
        var admission_document = try contracts.parseCanonical(a, admission_bytes.?);
        defer admission_document.deinit();
        try contracts.validateDirectComputeAdmissionV2(admission_document.value());
        scope_bundle = .{
            .path = admission_path,
            .sha256 = try a.dupe(u8, &std.fmt.bytesToHex(controller.records.fileIdentity(admission_bytes.?), .lower)),
            .size = admission_bytes.?.len,
        };
        try owner.held.append(inv.allocator, transport);
    }
    var settings = inv.settings;
    if (existing) {
        owner.candidate = try owner.retain(inv.output, contracts.layout.max_json_bytes, inv.signal);
        var candidate_document = try owner.document(&owner.candidate.?);
        defer candidate_document.deinit();
        _ = try contracts.validateDirectComputeCandidate(candidate_document.value());
        const fields = candidate_document.value().object;
        settings = .{
            .attempt_id = try a.dupe(u8, try core.contracts.string(fields.get("attempt_id").?)),
            .subscription = try a.dupe(u8, try core.contracts.string(fields.get("subscription").?)),
            .prefix = try a.dupe(u8, try core.contracts.string(fields.get("prefix").?)),
        };
    }
    if (settings.attempt_id == null) settings.attempt_id = try freshUuid(a, inv.io);
    const encoded = try encode(a, value, scope_bundle, settings);
    var candidate_document = try contracts.parseCanonical(a, encoded);
    defer candidate_document.deinit();
    _ = try contracts.validateDirectComputeCandidate(candidate_document.value());
    const parsed = try std.json.parseFromSlice(Scope, a, encoded, .{ .allocate = .alloc_always });
    owner.scope = parsed.value;
    try owner.revalidate(inv.signal);
    owner.phase = .admission;
    if (admission_bytes) |bytes| {
        if (!existing) _ = try owner.publish(admission_path, bytes);
        owner.admission = try owner.retain(admission_path, contracts.layout.max_json_bytes, inv.signal);
        if (!std.mem.eql(u8, &owner.admission.?.digest, scope_bundle.sha256) or owner.admission.?.file.file_snapshot.size != bytes.len)
            return error.CandidateBindingChanged;
    }
    try owner.revalidate(inv.signal);
    owner.phase = .publication;
    if (!existing) {
        owner.publication = try owner.publish(inv.output, encoded);
        owner.candidate = try owner.retain(inv.output, contracts.layout.max_json_bytes, inv.signal);
    }
    const digest = std.fmt.bytesToHex(controller.records.fileIdentity(encoded), .lower);
    if (!std.mem.eql(u8, &owner.candidate.?.digest, &digest) or owner.candidate.?.file.file_snapshot.size != encoded.len)
        return error.CandidateBindingChanged;
    owner.phase = .final_revalidation;
    try owner.revalidate(inv.signal);
}

fn encode(a: std.mem.Allocator, bundle: std.json.Value, scope_bundle: Artifact, settings: Settings) ![]const u8 {
    const fields = bundle.object;
    const version = try core.contracts.integer(u8, fields.get("version").?);
    const identity_bytes = try std.json.Stringify.valueAlloc(a, fields.get("identity").?, .{});
    const identity = try std.json.parseFromSlice(Identity, a, identity_bytes, .{ .allocate = .alloc_always });
    const names = contracts.layout.artifactNames(if (version == 1) .frozen_tiny_v1 else .tiny_qcow2_derived_vhd_v2);
    var vhd: ?Artifact = null;
    for (names, fields.get("artifacts").?.array.items) |name, item| if (std.mem.eql(u8, name, "vhd")) {
        const artifact_fields = item.object;
        vhd = .{
            .path = try core.contracts.string(artifact_fields.get("path").?),
            .sha256 = try core.contracts.string(artifact_fields.get("sha256").?),
            .size = try core.contracts.integer(u64, artifact_fields.get("size").?),
        };
    };
    return canonical(a, Scope{
        .version = version,
        .purpose = if (version == 1) "tiny-aot-two-boot" else contracts.profile.current_profile,
        .attempt_id = settings.attempt_id orelse return error.MissingAttemptId,
        .subscription = if (version == 1) "FINAL-APPROVED-SUBSCRIPTION-UUID" else settings.subscription orelse "00000000-0000-0000-0000-000000000001",
        .prefix = if (version == 1) "FINAL-APPROVED-FRESH-NAME" else settings.prefix orelse "not-admitted-candidate",
        .source_revision = try core.contracts.string(fields.get("source_revision").?),
        .source_tree = try core.contracts.string(fields.get("source_tree").?),
        .identity = identity.value,
        .os_vhd = vhd orelse return error.MissingVhd,
        .bundle = scope_bundle,
    });
}

fn canonical(a: std.mem.Allocator, value: anytype) ![]const u8 {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(raw);
    return controller.records.canonicalAlloc(a, raw);
}
fn freshUuid(a: std.mem.Allocator, io: std.Io) ![]const u8 {
    var bytes: [16]u8 = undefined;
    io.random(&bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = std.fmt.bytesToHex(bytes, .lower);
    return std.fmt.allocPrint(a, "{s}-{s}-{s}-{s}-{s}", .{ hex[0..8], hex[8..12], hex[12..16], hex[16..20], hex[20..32] });
}
fn inside(path: []const u8, root: []const u8) bool {
    return std.mem.eql(u8, path, root) or (path.len > root.len and std.mem.startsWith(u8, path, root) and path[root.len] == '/');
}
fn checkSerial(a: std.mem.Allocator, raw: []const u8, identity: Identity) !controller.tiny.Result {
    return controller.tiny.checkSerial(a, raw, .{
        .wamr_revision = identity.wamr_revision,
        .minimal_wasi = false,
        .tiny_wasm = identity.wasm_sha256,
        .tiny_cwasm = identity.cwasm_sha256,
        .runtime = identity.runtime_sha256,
    }, .{ .scope = .direct });
}
fn secondBytes(raw: []const u8, first: []const u8) ![]const u8 {
    const prefix = std.mem.trimEnd(u8, first, "\x00");
    if (prefix.len == 0 or !std.mem.startsWith(u8, raw, prefix)) return error.WrongSerialPrefix;
    return raw[prefix.len..];
}

test "candidate encoding preserves frozen selectors and refuses authorizing edits" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    inline for (.{ "goldens/root-bound-v1.json", "goldens/root-bound-v2.json" }) |name| {
        var document = try contracts.parseCanonical(a, @embedFile(name));
        defer document.deinit();
        const artifact: Artifact = .{ .path = "/private/scope.json", .size = 1, .sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
        const encoded = try encode(a, document.value(), artifact, .{ .attempt_id = "00000000-0000-4000-8000-000000000001" });
        var candidate_document = try contracts.parseCanonical(a, encoded);
        defer candidate_document.deinit();
        _ = try contracts.validateDirectComputeCandidate(candidate_document.value());
        const changed = try std.mem.replaceOwned(u8, a, encoded, "\"fresh_final_approval\":false", "\"fresh_final_approval\":true");
        var changed_document = try contracts.parseCanonical(a, changed);
        defer changed_document.deinit();
        try std.testing.expectError(error.AuthorityNotAllowed, contracts.validateDirectComputeCandidate(changed_document.value()));
    }
}

test "candidate cumulative result requires the exact original prefix with Azure NUL padding" {
    try std.testing.expectEqualStrings("second", try secondBytes("firstsecond", "first\x00\x00"));
    try std.testing.expectError(error.WrongSerialPrefix, secondBytes("changedsecond", "first"));
    try std.testing.expectError(error.WrongSerialPrefix, secondBytes("second", "\x00\x00"));
}
