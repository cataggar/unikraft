// SPDX-License-Identifier: BSD-3-Clause
//! WAMR-only approval and result adapter. No Azure calls or authority discovery.
const std = @import("std");
const core = @import("hyperv_core");
const base = @import("main.zig");
const serial = @import("local_serial");
const c = core.contracts;
const files = core.private_files;
pub const Artifact = base.Artifact;
pub const SerialMode = base.SerialMode;
pub const parse = base.parse;
pub const sdk = "a53205d77be3b880eb8f8b96679512ba58e2331a";
pub const marker = "WAMR_NATIVE_AOT_OK answer=42 teardown=0";
pub const prefix = "WAMR_NATIVE_COMPUTE=";
pub const forbidden = [_][]const u8{
    "HYPERV_ACCEPTANCE",        "UK_HYPERV_IO_READY", "UK_HYPERV_NETWORK_APP_READY",
    "UK_HYPERV_PLATFORM_READY", "WAMR_NATIVE_WASI=",  "WAMR_NATIVE_AOT_FAIL",
};
pub const artifact_names = .{
    "efi",   "debug_elf",   "bootinfo",    "raw",              "vhd",            "runtime",      "compiler",
    "wasm",  "cwasm",       "config",      "runtime_identity", "image_identity", "local_result", "package",
    "build", "build_start", "boot_inputs",
};
pub const artifact_names_v2 = .{
    "efi",                         "debug_elf",                 "bootinfo",
    "raw",                         "qcow2",                     "vhd",
    "runtime",                     "compiler",                  "wasm",
    "cwasm",                       "config",                    "runtime_identity",
    "image_identity",              "local_result",              "package",
    "build",                       "build_start",               "boot_inputs",
    "qcow2_finalization_intent",   "qcow2_finalization",        "qcow2_acceptance",
    "fixed_vhd_derivation_intent", "fixed_vhd_derivation_gate", "fixed_vhd_derivation",
    "final_inspection",            "cleanup",
};
const evidence_names_v2 = [_][]const u8{
    "boot-inputs.json",
    "build-start.json",
    "build.json",
    "command-adapter.json",
    "command-config.json",
    "command-derive-fixed-vhd.json",
    "command-finalize-qcow2.json",
    "command-fixtures.json",
    "command-inspect.json",
    "command-local-boot-tool.json",
    "command-native-image.json",
    "command-package.json",
    "command-prepare.json",
    "command-qcow2-legacy-apic.json",
    "command-qcow2-x2apic.json",
    "command-raw-legacy-apic.json",
    "command-raw-x2apic.json",
    "command-vpc-legacy-apic.json",
    "command-vpc-x2apic.json",
    "final-inspection.json",
    "fixed-vhd-derivation-gate.json",
    "fixed-vhd-derivation-intent.json",
    "fixed-vhd-derivation.json",
    "package.json",
    "qcow2-acceptance.json",
    "qcow2-finalization-intent.json",
    "qcow2-finalization.json",
    "qcow2-legacy-apic-compute.json",
    "qcow2-x2apic-compute.json",
    "raw-legacy-apic-compute.json",
    "raw-x2apic-compute.json",
    "vpc-legacy-apic-compute.json",
    "vpc-x2apic-compute.json",
};
pub const Identity = struct {
    wamr_revision: []const u8,
    wasm_sha256: []const u8,
    cwasm_sha256: []const u8,
    runtime_sha256: []const u8,
    compiler_sha256: []const u8,
    config_sha256: []const u8,
};
pub const Scope = struct {
    schema: []const u8,
    version: u8,
    purpose: enum { @"tiny-aot-two-boot", @"qcow2-derived-vhd" },
    authority: enum { not_admitted, final_image_approved },
    approval: struct {
        direct_specialized_gen2: bool,
        os_only_private: bool,
        two_boots_only: bool,
        cleanup_owned_group: bool,
        exact_image_and_local_bundle_reviewed: bool,
        fresh_final_approval: bool,
        approved_unix: u64,
        expires_unix: u64,
    },
    attempt_id: []const u8,
    subscription: []const u8,
    location: []const u8,
    prefix: []const u8,
    vm_size: []const u8,
    serial_mode: SerialMode,
    runtime_seconds: u32,
    cleanup_seconds: u32,
    operation_seconds: u32,
    poll_seconds: u32,
    source_revision: []const u8,
    source_tree: []const u8,
    identity: Identity,
    os_vhd: Artifact,
    bundle: Artifact,

    pub fn validate(self: Scope) !void {
        try self.validateCandidate();
        if (self.authority != .final_image_approved) return error.NotAuthorized;
        inline for (.{ "direct_specialized_gen2", "os_only_private", "cleanup_owned_group", "exact_image_and_local_bundle_reviewed", "fresh_final_approval" }) |name|
            if (!@field(self.approval, name)) return error.NotAuthorized;
        if (self.approval.two_boots_only != (self.version == 1))
            return error.NotAuthorized;
    }

    pub fn validateCandidate(self: Scope) !void {
        if (!eq(self.schema, "uk.wamr.direct-compute") or
            (self.version == 1 and self.purpose != .@"tiny-aot-two-boot") or
            (self.version == 2 and self.purpose != .@"qcow2-derived-vhd") or
            (self.version != 1 and self.version != 2))
            return error.InvalidScope;
        if (self.authority != .not_admitted and self.authority != .final_image_approved)
            return error.InvalidScope;
        try uuid(self.attempt_id);
        try uuid(self.subscription);
        if (!eq(self.location, "northeurope") or !eq(self.vm_size, "Standard_D2s_v5")) return error.InvalidTopology;
        if (self.prefix.len < 6 or self.prefix.len > 32) return error.InvalidPrefix;
        for (self.prefix) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '-') return error.InvalidPrefix;
        if (self.runtime_seconds < 60 or self.runtime_seconds > 3600 or
            self.cleanup_seconds < 60 or self.cleanup_seconds > 1800 or
            self.operation_seconds < 10 or self.operation_seconds > 600 or
            self.poll_seconds < 1 or self.poll_seconds > 30) return error.InvalidBudget;
        if (self.authority == .final_image_approved) {
            if (self.approval.approved_unix == 0 or self.approval.expires_unix <= self.approval.approved_unix or
                self.approval.expires_unix - self.approval.approved_unix > 3600) return error.InvalidApprovalWindow;
        } else if (self.approval.approved_unix != 0 or self.approval.expires_unix != 0) {
            return error.InvalidApprovalWindow;
        }
        try hex(self.source_revision, 40);
        try hex(self.source_tree, 40);
        if (!eq(self.identity.wamr_revision, sdk)) return error.WrongSdk;
        inline for (std.meta.fields(Identity)) |member| {
            if (comptime !eq(member.name, "wamr_revision")) _ = try c.parseSha256(@field(self.identity, member.name));
        }
        try artifact(self.os_vhd);
        try artifact(self.bundle);
        if (self.os_vhd.size != 66 * 1024 * 1024 + 512 or self.bundle.size > 65536) return error.InvalidArtifact;
    }

    pub fn current(self: Scope, now: u64) !void {
        try self.validate();
        if (now < self.approval.approved_unix or now >= self.approval.expires_unix) return error.ApprovalExpired;
    }
};

pub const Boot = struct {
    mode: enum { @"raw-x2apic", @"raw-legacy-apic", @"vpc-x2apic", @"vpc-legacy-apic" },
    serial: Artifact,
    request: Artifact,
    report: Artifact,
    compute: Artifact,
};
pub const Bundle = struct {
    schema: []const u8,
    version: u8,
    authority: enum { not_admitted },
    source_revision: []const u8,
    source_tree: []const u8,
    identity: Identity,
    artifacts: [artifact_names.len]Artifact,
    boots: [4]Boot,
    evidence: []Artifact,

    pub fn get(self: Bundle, comptime name: []const u8) Artifact {
        inline for (artifact_names, 0..) |found, i| if (comptime eq(name, found)) return self.artifacts[i];
        @compileError("unknown compute artifact");
    }
};

pub const BootV2 = struct {
    mode: enum {
        @"raw-x2apic",
        @"raw-legacy-apic",
        @"qcow2-x2apic",
        @"qcow2-legacy-apic",
        @"vpc-x2apic",
        @"vpc-legacy-apic",
    },
    serial: Artifact,
    request: Artifact,
    report: Artifact,
    compute: Artifact,
};

pub const RunIdentity = struct {
    repository: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
};

pub const Lineage = struct {
    raw_sha256: []const u8,
    accepted_qcow2_sha256: []const u8,
    derived_vhd_sha256: []const u8,
    qcow2_finalization_sha256: []const u8,
    qcow2_acceptance_sha256: []const u8,
    fixed_vhd_derivation_gate_sha256: []const u8,
    fixed_vhd_derivation_sha256: []const u8,
    final_inspection_sha256: []const u8,
};

pub const BundleV2 = struct {
    schema: []const u8,
    version: u8,
    profile: enum { @"qcow2-derived-vhd" },
    authority: enum { not_admitted },
    source_revision: []const u8,
    source_tree: []const u8,
    run: RunIdentity,
    identity: Identity,
    lineage: Lineage,
    artifacts: [artifact_names_v2.len]Artifact,
    boots: [6]BootV2,
    evidence: [33]Artifact,

    pub fn get(self: BundleV2, comptime name: []const u8) Artifact {
        inline for (artifact_names_v2, 0..) |found, i|
            if (comptime eq(name, found)) return self.artifacts[i];
        @compileError("unknown version-2 compute artifact");
    }
};

fn legacyLocalPins(source_revision: []const u8, source_tree: []const u8) bool {
    return (eq(source_revision, "993e4d0d394c08202c0d0c57ea97450a19a4f394") or
        eq(source_revision, "34e5c88a165c4da878b3122b8b91716116d65d4b") or
        eq(source_revision, "b5a8fdbee033349f7145fbc76aebfee29b2fa04f")) and
        eq(source_tree, "54f8e118146c78c24e7c802657c6ec62b268a5de");
}

pub const Result = struct {
    version: u8,
    workload: enum { tiny },
    wamr_revision: []const u8,
    wasm_sha256: []const u8,
    cwasm_sha256: []const u8,
    runtime_sha256: []const u8,
    platform_status: i32,
    checks: u32,
    answer: i32,
    terminal: u32,
    detail: u32,
    reserved_bytes: u64,
    frame_bytes: u64,
    accessible_bytes: u64,
    allocation_bytes: u64,
    system_page_table_bytes: u64,
    error_name: []const u8,

    pub fn validate(self: Result, identity: Identity) !void {
        if (self.version != 1 or self.platform_status != 0 or self.checks != 2 or self.answer != 42 or
            self.terminal != 1 or self.detail != 2 or self.reserved_bytes != 0 or self.frame_bytes != 0 or
            self.accessible_bytes != 0 or self.allocation_bytes != 0 or self.error_name.len != 0 or
            self.system_page_table_bytes == 0 or self.system_page_table_bytes > 256 * 1024 * 1024 or
            self.system_page_table_bytes % 4096 != 0) return error.ComputeFailed;
        inline for (.{ "wamr_revision", "wasm_sha256", "cwasm_sha256", "runtime_sha256" }) |name|
            if (!eq(@field(self, name), @field(identity, name))) return error.WrongComputeIdentity;
    }
};

pub const CaptureRecord = struct {
    schema: []const u8 = "uk.wamr.direct-serial-capture",
    version: u8 = 1,
    boot: u8,
    poll: u8,
    serial_mode: SerialMode,
    serial_sha256: []const u8,
    cli_wrapper_sha256: []const u8,
    scope_sha256: []const u8,
    vm_id: []const u8,
    vm_uuid: []const u8,
    os_id: []const u8,
    os_uuid: []const u8,
    data_id: ?[]const u8,
    data_uuid: ?[]const u8,
    vm_observation_sha256: []const u8,
    original_boot1_sha256: []const u8,
    boot2_admission_sha256: []const u8,
    compute_result_sha256: []const u8 = "",
    serial_bytes: u64 = 0,
};

pub fn checkSerial(a: std.mem.Allocator, raw: []const u8, identity: Identity) !Result {
    if (raw.len == 0) return error.EvidenceIncomplete;
    if (raw.len >= 4 * 1024 * 1024) return error.SerialLimit;
    const text = try serial.normalize(a, raw);
    defer a.free(text);
    for (forbidden ++ .{ "Unikraft Crash", "Assertion failure", "Exception Type" }) |bad|
        if (std.mem.indexOf(u8, text, bad) != null) return error.ForbiddenMarker;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var record: ?Result = null;
    var complete = false;
    var returned = false;
    var starts: u8 = 0;
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (std.mem.indexOf(u8, line, "Calling main(") != null) {
            if (starts != 0 or record != null) return error.DuplicateStart;
            starts += 1;
        }
        if (std.mem.indexOf(u8, line, prefix) != null) {
            if (record != null or starts != 1 or complete or returned or !std.mem.startsWith(u8, line, prefix))
                return error.InvalidComputeRecord;
            const parsed = try parse(Result, a, line[prefix.len..]);
            defer parsed.deinit();
            try parsed.value.validate(identity);
            // All strings in a validated result equal the scope's stable pins.
            var result = parsed.value;
            inline for (.{ "wamr_revision", "wasm_sha256", "cwasm_sha256", "runtime_sha256" }) |name|
                @field(result, name) = @field(identity, name);
            result.error_name = "";
            record = result;
        }
        if (std.mem.indexOf(u8, line, marker) != null) {
            if (!eq(line, marker) or complete or record == null or returned) return error.InvalidCompletion;
            complete = true;
        }
        if (std.mem.indexOf(u8, line, "main returned") != null) {
            if (!complete or returned) return error.InvalidMainReturn;
            returned = true;
        }
    }
    if (!returned) return error.EvidenceIncomplete;
    try serial.validateEnvelope(a, raw, marker, 0, &.{}, &forbidden);
    return record orelse error.EvidenceIncomplete;
}

pub fn secondBytes(raw: []const u8, first: []const u8, mode: SerialMode) ![]const u8 {
    if (mode == .per_boot) return raw;
    const prefix_bytes = if (mode == .azure_cumulative) std.mem.trimEnd(u8, first, "\x00") else first;
    if (prefix_bytes.len == 0 or !std.mem.startsWith(u8, raw, prefix_bytes)) return error.WrongSerialPrefix;
    return raw[prefix_bytes.len..];
}

pub fn loadScope(a: std.mem.Allocator, io: std.Io, path: []const u8) !std.json.Parsed(Scope) {
    var bytes = try files.readSensitiveAbsolute(io, a, path, 65536, null);
    defer bytes.deinit();
    const scope = try parse(Scope, a, bytes.bytes());
    errdefer scope.deinit();
    try scope.value.validate();
    return scope;
}

pub fn loadCandidateScope(a: std.mem.Allocator, io: std.Io, path: []const u8) !std.json.Parsed(Scope) {
    var bytes = try files.readSensitiveAbsolute(io, a, path, 65536, null);
    defer bytes.deinit();
    const scope = try parse(Scope, a, bytes.bytes());
    errdefer scope.deinit();
    try scope.value.validateCandidate();
    return scope;
}

pub fn inspectArtifact(io: std.Io, item: Artifact) !void {
    try artifact(item);
    const file = try files.openAbsolute(io, item.path, .artifact);
    defer file.close(io);
    const before = try files.snapshot(file);
    if (before.size != item.size) return error.ArtifactChanged;
    var hash = core.Sha256.init(.{});
    var buffer: [65536]u8 = undefined;
    var offset: u64 = 0;
    while (offset < item.size) {
        const n: usize = @intCast(@min(buffer.len, item.size - offset));
        if (try file.readPositionalAll(io, buffer[0..n], offset) != n) return error.ArtifactChanged;
        hash.update(buffer[0..n]);
        offset += n;
    }
    if (try file.readPositionalAll(io, buffer[0..1], offset) != 0 or !files.sameSnapshot(before, try files.snapshot(file))) return error.ArtifactChanged;
    if (!std.mem.eql(u8, &hash.finalResult(), &try c.parseSha256(item.sha256))) return error.HashMismatch;
}

fn read(a: std.mem.Allocator, io: std.Io, item: Artifact, limit: usize) ![]u8 {
    if (item.size > limit) return error.FileTooLarge;
    try inspectArtifact(io, item);
    const file = try files.openAbsolute(io, item.path, .artifact);
    defer file.close(io);
    const before = try files.snapshot(file);
    const bytes = try a.alloc(u8, @intCast(item.size));
    errdefer a.free(bytes);
    if (try file.readPositionalAll(io, bytes, 0) != bytes.len or !files.sameSnapshot(before, try files.snapshot(file))) return error.ArtifactChanged;
    var hash: [32]u8 = undefined;
    core.Sha256.hash(bytes, &hash, .{});
    if (!std.mem.eql(u8, &hash, &try c.parseSha256(item.sha256))) return error.HashMismatch;
    return bytes;
}

pub fn inspect(a: std.mem.Allocator, io: std.Io, scope: Scope) !void {
    if (scope.version == 2) return inspectV2(a, io, scope);
    const bytes = try read(a, io, scope.bundle, 65536);
    defer a.free(bytes);
    const parsed = try parse(Bundle, a, bytes);
    defer parsed.deinit();
    const bundle = parsed.value;
    if (!eq(bundle.schema, "uk.wamr.local-image-handoff") or bundle.version != 1 or
        !eq(bundle.source_revision, scope.source_revision) or !eq(bundle.source_tree, scope.source_tree))
        return error.WrongSource;
    inline for (std.meta.fields(Identity)) |member|
        if (!eq(@field(bundle.identity, member.name), @field(scope.identity, member.name))) return error.WrongComputeIdentity;
    if (!same(bundle.get("vhd"), scope.os_vhd)) return error.WrongImage;
    inline for (.{ .{ "runtime", "runtime_sha256" }, .{ "compiler", "compiler_sha256" }, .{ "wasm", "wasm_sha256" }, .{ "cwasm", "cwasm_sha256" }, .{ "config", "config_sha256" } }) |pair|
        if (!eq(bundle.get(pair[0]).sha256, @field(scope.identity, pair[1]))) return error.WrongComputeIdentity;
    try verifyBundle(a, io, bundle);
}

const Admission = struct {
    schema: []const u8,
    version: u8,
    profile: enum { @"qcow2-derived-vhd" },
    authority: enum { not_admitted },
    source_revision: []const u8,
    source_tree: []const u8,
    run: RunIdentity,
    lineage: Lineage,
    public_bundle: Artifact,
    transport: Artifact,
};

const Transport = struct {
    schema: []const u8,
    version: u8,
    repository: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
    source_revision: []const u8,
    source_tree: []const u8,
    inner_zip_sha256: []const u8,
    artifact_id: []const u8,
    container_digest: []const u8,
};

fn inspectV2(a: std.mem.Allocator, io: std.Io, scope: Scope) !void {
    const admission_bytes = try read(a, io, scope.bundle, 65536);
    defer a.free(admission_bytes);
    const admission_parsed = try parse(Admission, a, admission_bytes);
    defer admission_parsed.deinit();
    const admission = admission_parsed.value;
    if (!eq(admission.schema, "uk.wamr.direct-compute-admission") or
        admission.version != 2 or
        !eq(admission.source_revision, scope.source_revision) or
        !eq(admission.source_tree, scope.source_tree))
        return error.WrongSource;
    const bundle_bytes = try read(a, io, admission.public_bundle, 65536);
    defer a.free(bundle_bytes);
    const bundle_parsed = try parse(BundleV2, a, bundle_bytes);
    defer bundle_parsed.deinit();
    const bundle = bundle_parsed.value;
    try verifyBundleV2(a, io, bundle);
    if (!eq(bundle.source_revision, scope.source_revision) or
        !eq(bundle.source_tree, scope.source_tree) or
        !same(bundle.get("vhd"), scope.os_vhd) or
        !sameLineage(bundle.lineage, admission.lineage) or
        !sameRun(bundle.run, admission.run))
        return error.WrongImage;
    inline for (std.meta.fields(Identity)) |member|
        if (!eq(@field(bundle.identity, member.name), @field(scope.identity, member.name)))
            return error.WrongComputeIdentity;

    const transport_bytes = try read(a, io, admission.transport, 65536);
    defer a.free(transport_bytes);
    const transport_parsed = try parse(Transport, a, transport_bytes);
    defer transport_parsed.deinit();
    const transport = transport_parsed.value;
    if (!eq(transport.schema, "uk.wamr.public-source-transport") or
        transport.version != 2 or
        !eq(transport.repository, bundle.run.repository) or
        !eq(transport.run_id, bundle.run.run_id) or
        !eq(transport.run_attempt, bundle.run.run_attempt) or
        !eq(transport.source_revision, bundle.source_revision) or
        !eq(transport.source_tree, bundle.source_tree))
        return error.WrongSource;
    try hex(transport.inner_zip_sha256, 64);
    try hex(transport.container_digest, 64);
    if (transport.artifact_id.len == 0 or transport.artifact_id.len > 20 or
        transport.artifact_id[0] == '0')
        return error.InvalidIdentity;
    for (transport.artifact_id) |byte|
        if (!std.ascii.isDigit(byte)) return error.InvalidIdentity;
}

pub fn verifyHandoff(a: std.mem.Allocator, io: std.Io, bytes: []const u8) !void {
    const document = try c.Document.parse(a, bytes, .{ .bytes = 65536 });
    defer document.deinit();
    const version = try c.integer(u8, try field(document.value(), "version"));
    if (version == 1) {
        const parsed = try parse(Bundle, a, bytes);
        defer parsed.deinit();
        return verifyBundle(a, io, parsed.value);
    }
    if (version == 2) {
        const parsed = try parse(BundleV2, a, bytes);
        defer parsed.deinit();
        return verifyBundleV2(a, io, parsed.value);
    }
    return error.InvalidScope;
}

pub fn verifyBundle(a: std.mem.Allocator, io: std.Io, bundle: Bundle) !void {
    if (!eq(bundle.schema, "uk.wamr.local-image-handoff") or bundle.version != 1 or
        !eq(bundle.identity.wamr_revision, sdk)) return error.WrongSdk;
    try hex(bundle.source_revision, 40);
    try hex(bundle.source_tree, 40);
    inline for (.{ .{ "runtime", "runtime_sha256" }, .{ "compiler", "compiler_sha256" }, .{ "wasm", "wasm_sha256" }, .{ "cwasm", "cwasm_sha256" }, .{ "config", "config_sha256" } }) |pair|
        if (!eq(bundle.get(pair[0]).sha256, @field(bundle.identity, pair[1]))) return error.WrongComputeIdentity;
    for (bundle.artifacts) |item| try inspectArtifact(io, item);
    try evidenceRecords(a, io, bundle, true);
    try rawVhd(io, bundle.get("raw"), bundle.get("vhd"));
    for (bundle.boots, 0..) |boot, i| {
        if (@intFromEnum(boot.mode) != i) return error.WrongLocalMode;
        inline for (.{ "request", "report", "compute" }) |name| try inspectArtifact(io, @field(boot, name));
        const raw = try read(a, io, boot.serial, 4 * 1024 * 1024);
        defer a.free(raw);
        const result = try checkSerial(a, raw, bundle.identity);
        const text = try serial.normalize(a, raw);
        defer a.free(text);
        if (std.mem.count(u8, text, "Using legacy xAPIC MMIO") != i % 2) return error.WrongLocalMode;
        try localReport(
            a,
            io,
            boot,
            if (i < 2) bundle.get("raw") else bundle.get("vhd"),
            result,
            legacyLocalPins(bundle.source_revision, bundle.source_tree),
        );
    }
}

pub fn verifyBundleV2(a: std.mem.Allocator, io: std.Io, bundle: BundleV2) !void {
    if (!eq(bundle.schema, "uk.wamr.local-image-handoff") or
        bundle.version != 2 or bundle.profile != .@"qcow2-derived-vhd" or
        !eq(bundle.identity.wamr_revision, sdk) or
        !eq(bundle.run.repository, "cataggar/unikraft"))
        return error.WrongSdk;
    try decimal(bundle.run.run_id);
    try decimal(bundle.run.run_attempt);
    try hex(bundle.source_revision, 40);
    try hex(bundle.source_tree, 40);
    inline for (.{ .{ "runtime", "runtime_sha256" }, .{ "compiler", "compiler_sha256" }, .{ "wasm", "wasm_sha256" }, .{ "cwasm", "cwasm_sha256" }, .{ "config", "config_sha256" } }) |pair|
        if (!eq(bundle.get(pair[0]).sha256, @field(bundle.identity, pair[1])))
            return error.WrongComputeIdentity;
    inline for (artifact_names_v2, 0..) |name, i| {
        const item = bundle.artifacts[i];
        if (!eq(std.fs.path.basename(item.path), name))
            return error.WrongImage;
        try inspectArtifact(io, item);
    }
    try evidenceRecords(a, io, bundle, false);
    try rawVhd(io, bundle.get("raw"), bundle.get("vhd"));
    for (bundle.boots, 0..) |boot, i| {
        if (@intFromEnum(boot.mode) != i) return error.WrongLocalMode;
        if (!eq(std.fs.path.basename(boot.serial.path), "serial"))
            return error.WrongLocalReport;
        inline for (.{ "request", "report", "compute" }) |name| {
            if (!eq(std.fs.path.basename(@field(boot, name).path), name))
                return error.WrongLocalReport;
            try inspectArtifact(io, @field(boot, name));
        }
        const raw = try read(a, io, boot.serial, 4 * 1024 * 1024);
        defer a.free(raw);
        const result = try checkSerial(a, raw, bundle.identity);
        const text = try serial.normalize(a, raw);
        defer a.free(text);
        if (std.mem.count(u8, text, "Using legacy xAPIC MMIO") != i % 2)
            return error.WrongLocalMode;
        try localReport(
            a,
            io,
            boot,
            if (i < 2) bundle.get("raw") else if (i < 4) bundle.get("qcow2") else bundle.get("vhd"),
            result,
            false,
        );
    }
    try lineageV2(a, io, bundle);
}

fn evidenceRecords(a: std.mem.Allocator, io: std.Io, bundle: anytype, package_vhd: bool) !void {
    const bytes = try read(a, io, bundle.get("local_result"), 65536);
    defer a.free(bytes);
    const document = try c.Document.parse(a, bytes, .{ .bytes = 65536 });
    defer document.deinit();
    const value = document.value();
    if (!eq(try string(value, "scope"), "local_native_compute_only") or
        !eq(try string(value, "cloud_authority"), "not_admitted") or
        !eq(try string(value, "hardware_acceptance"), "not_established") or
        !eq(try string(value, "benchmark"), "not_measured") or
        !eq(try string(value, "workload"), "tiny")) return error.WrongLocalReport;
    if (!package_vhd) {
        if (try c.integer(u8, try field(value, "schema_version")) != 2 or
            !eq(try string(value, "profile"), "qcow2-derived-vhd"))
            return error.WrongLocalReport;
        try exactModes(try field(value, "modes"), &.{
            "raw-x2apic",   "raw-legacy-apic",
            "qcow2-x2apic", "qcow2-legacy-apic",
            "vpc-x2apic",   "vpc-legacy-apic",
        });
    }
    const passed = try field(value, "passed");
    if (passed != .bool or !passed.bool) return error.LocalBootFailed;
    const records = try field(value, "records");
    if (records != .object or records.object.count() != bundle.evidence.len or bundle.evidence.len < 8) return error.WrongLocalReport;
    for (bundle.evidence, 0..) |item, i| {
        const name = std.fs.path.basename(item.path);
        if (!package_vhd and !eq(name, evidence_names_v2[i]))
            return error.WrongLocalReport;
        for (bundle.evidence[0..i]) |prior|
            if (eq(std.fs.path.basename(prior.path), name)) return error.DuplicateField;
        if (!eq(try c.string(records.object.get(name) orelse return error.MissingField), item.sha256)) return error.HashMismatch;
        try inspectArtifact(io, item);
    }
    inline for (.{ "build", "build_start", "boot_inputs", "package" }, .{ "build.json", "build-start.json", "boot-inputs.json", "package.json" }) |name, filename| {
        if (!eq(try c.string(records.object.get(filename) orelse return error.MissingField), bundle.get(name).sha256)) return error.HashMismatch;
    }
    for (bundle.boots) |boot| {
        const filename = try std.fmt.allocPrint(a, "{s}-compute.json", .{@tagName(boot.mode)});
        defer a.free(filename);
        if (!eq(try c.string(records.object.get(filename) orelse return error.MissingField), boot.compute.sha256)) return error.HashMismatch;
    }
    const build_bytes = try read(a, io, bundle.get("build"), 65536);
    defer a.free(build_bytes);
    const build_doc = try c.Document.parse(a, build_bytes, .{ .bytes = 65536 });
    defer build_doc.deinit();
    const source = try field(build_doc.value(), "source");
    if (!eq(try string(source, "revision"), bundle.source_revision) or !eq(try string(source, "tree"), bundle.source_tree))
        return error.WrongSource;
    const runtime = try field(build_doc.value(), "runtime");
    if (!eq(try string(runtime, "wamr_revision"), sdk) or
        !eq(try string(runtime, "compiler_profile"), "unikraft-x86_64") or
        !eq(try string(runtime, "zig_version"), "0.16.0")) return error.WrongSdk;
    const wasi = try field(runtime, "minimal_wasi");
    if (wasi != .bool or wasi.bool) return error.WrongSdk;
    const runtime_files = try field(runtime, "files");
    inline for (.{ .{ "tiny.wasm", "wasm" }, .{ "tiny.cwasm", "cwasm" }, .{ "wamrc", "compiler" }, .{ "libwamr-aot.a", "runtime" } }) |pair|
        if (!eq(try string(runtime_files, pair[0]), bundle.get(pair[1]).sha256)) return error.WrongComputeIdentity;
    const image = try field(build_doc.value(), "image");
    if (!eq(try string(image, "unikraft_revision"), bundle.source_revision) or
        !eq(try string(image, "runtime_inputs_sha256"), bundle.get("runtime_identity").sha256) or
        !eq(try string(image, "solved_config_sha256"), bundle.get("config").sha256)) return error.WrongSource;
    inline for (.{ .{ "wamr_hyperv-x86_64-efi", "efi" }, .{ "wamr_hyperv-x86_64-efi.dbg", "debug_elf" }, .{ "wamr_hyperv-x86_64-efi.bootinfo", "bootinfo" } }) |pair|
        if (!eq(try string(try field(image, "files"), pair[0]), bundle.get(pair[1]).sha256)) return error.WrongImage;
    const package_bytes = try read(a, io, bundle.get("package"), 65536);
    defer a.free(package_bytes);
    const package_doc = try c.Document.parse(a, package_bytes, .{ .bytes = 65536 });
    defer package_doc.deinit();
    const package = package_doc.value();
    if (!eq(try string(package, "scope"), "public_local_compute_packaging_only") or
        !eq(try string(package, "acceptance"), "not_established")) return error.WrongLocalReport;
    inline for (.{ "efi", "raw" }) |name| {
        const item = try field(try field(package, "image"), name);
        if (!eq(try string(item, "sha256"), bundle.get(name).sha256) or
            try c.integer(u64, try field(item, "size")) != bundle.get(name).size) return error.WrongImage;
    }
    if (package_vhd) {
        const item = try field(try field(package, "image"), "vhd");
        if (!eq(try string(item, "sha256"), bundle.get("vhd").sha256) or
            try c.integer(u64, try field(item, "size")) != bundle.get("vhd").size)
            return error.WrongImage;
    }
}

fn localReport(
    a: std.mem.Allocator,
    io: std.Io,
    boot: anytype,
    image: Artifact,
    result: Result,
    legacy_pins: bool,
) !void {
    const bytes = try read(a, io, boot.report, 65536);
    defer a.free(bytes);
    const doc = try c.Document.parse(a, bytes, .{ .bytes = 65536 });
    defer doc.deinit();
    const value = doc.value();
    if (!eq(try string(value, "scope"), "public_local_qemu_only") or
        !eq(try string(value, "acceptance"), "not_established") or
        try c.integer(u8, try field(value, "schema_version")) != 1) return error.WrongLocalReport;
    inline for (.{ "passed", "consumed", "cleanup_complete", "input_unchanged", "serial_valid" }) |name| {
        const flag = try field(value, name);
        if (flag != .bool or !flag.bool) return error.LocalBootFailed;
    }
    const limited = try field(value, "serial_limit_reached");
    if (limited != .bool or limited.bool or
        try c.integer(u64, try field(value, "serial_bytes")) != boot.serial.size or
        !eq(try string(value, "serial_sha256"), boot.serial.sha256) or
        try c.integer(u8, try field(try field(value, "termination"), "exited")) != 0) return error.LocalBootFailed;
    inline for (.{ "primary", "cleanup", "recording" }) |name|
        if (try field(try field(value, "failures"), name) != .null) return error.LocalBootFailed;
    const request_bytes = try read(a, io, boot.request, 65536);
    defer a.free(request_bytes);
    const request = try c.Document.parse(a, request_bytes, .{ .bytes = 65536 });
    defer request.deinit();
    const request_version = try c.integer(u8, try field(request.value(), "schema_version"));
    const config = try field(request.value(), "config");
    const source = try field(config, "source");
    const mode = @intFromEnum(boot.mode);
    const mode_name = @tagName(boot.mode);
    const expected_kind = if (std.mem.startsWith(u8, mode_name, "raw-"))
        "raw_disk"
    else if (std.mem.startsWith(u8, mode_name, "qcow2-"))
        "qcow2"
    else
        "fixed_vhd";
    if ((request_version != 2 and !(request_version == 1 and legacy_pins)) or
        !eq(try string(config, "expect"), marker) or
        try c.integer(i32, try field(config, "expect_main_return")) != 0 or
        try c.integer(u8, try field(config, "cpus")) != 1 or
        try c.integer(u32, try field(config, "timeout_ms")) != 60000 or
        !eq(try string(source, "kind"), expected_kind))
        return error.WrongLocalReport;
    _ = try string(source, "path");
    const legacy = try field(config, "disable_x2apic");
    if (legacy != .bool or legacy.bool != (mode % 2 == 1)) return error.WrongLocalMode;
    const pins = try field(request.value(), "pins");
    if (pins != .array or pins.array.items.len != 4) return error.WrongLocalReport;
    const pin_member_count: usize = if (request_version == 1) 2 else 13;
    for (pins.array.items) |candidate| {
        if (candidate != .object or candidate.object.count() != pin_member_count)
            return error.WrongLocalReport;
        if (request_version == 2) {
            const mode_value = try c.integer(u16, try field(candidate, "mode"));
            if (try c.integer(u64, try field(candidate, "inode")) == 0 or
                try c.integer(u32, try field(candidate, "nlink")) == 0 or
                mode_value & 0o170000 != 0o100000 or mode_value & 0o022 != 0 or
                try c.integer(u32, try field(candidate, "mtime_nanoseconds")) >= std.time.ns_per_s or
                try c.integer(u32, try field(candidate, "ctime_nanoseconds")) >= std.time.ns_per_s)
                return error.WrongLocalReport;
            _ = try c.integer(u32, try field(candidate, "device_major"));
            _ = try c.integer(u32, try field(candidate, "device_minor"));
            _ = try c.integer(u32, try field(candidate, "uid"));
            _ = try c.integer(u32, try field(candidate, "gid"));
            _ = try c.integer(u64, try field(candidate, "size"));
            _ = try c.integer(i64, try field(candidate, "mtime_seconds"));
            _ = try c.integer(i64, try field(candidate, "ctime_seconds"));
        }
        const candidate_hash = try field(candidate, "sha256");
        if (candidate_hash != .array or candidate_hash.array.items.len != 32)
            return error.WrongLocalReport;
        for (candidate_hash.array.items) |byte| _ = try c.integer(u8, byte);
    }
    const pin = pins.array.items[0];
    if (try c.integer(u64, try field(pin, "size")) != image.size) return error.WrongImage;
    const hash = try field(pin, "sha256");
    if (hash != .array or hash.array.items.len != 32) return error.WrongImage;
    for (hash.array.items, try c.parseSha256(image.sha256)) |byte, expected|
        if (try c.integer(u8, byte) != expected) return error.WrongImage;
    const compute_bytes = try read(a, io, boot.compute, 65536);
    defer a.free(compute_bytes);
    const computed = try c.Document.parse(a, compute_bytes, .{ .bytes = 65536 });
    defer computed.deinit();
    const observation = computed.value();
    if (!eq(try string(observation, "scope"), "local_native_compute_only") or
        !eq(try string(observation, "request_sha256"), boot.request.sha256) or
        !eq(try string(observation, "report_sha256"), boot.report.sha256)) return error.WrongLocalReport;
    if (request_version == 2) {
        const request_pins = try std.json.Stringify.valueAlloc(a, pins, .{});
        defer a.free(request_pins);
        const observed_pins = try std.json.Stringify.valueAlloc(a, try field(observation, "input_pins"), .{});
        defer a.free(observed_pins);
        if (!eq(request_pins, observed_pins)) return error.WrongLocalReport;
    }
    const encoded = try std.json.Stringify.valueAlloc(a, try field(observation, "compute"), .{});
    defer a.free(encoded);
    const checked = try parse(Result, a, encoded);
    defer checked.deinit();
    inline for (std.meta.fields(Result)) |member| {
        const actual = @field(checked.value, member.name);
        const expected = @field(result, member.name);
        if (comptime member.type == []const u8) {
            if (!eq(actual, expected)) return error.WrongLocalReport;
        } else if (actual != expected) return error.WrongLocalReport;
    }
}

fn lineageV2(a: std.mem.Allocator, io: std.Io, bundle: BundleV2) !void {
    if (!eq(bundle.lineage.raw_sha256, bundle.get("raw").sha256) or
        !eq(bundle.lineage.accepted_qcow2_sha256, bundle.get("qcow2").sha256) or
        !eq(bundle.lineage.derived_vhd_sha256, bundle.get("vhd").sha256) or
        !eq(bundle.lineage.qcow2_finalization_sha256, bundle.get("qcow2_finalization").sha256) or
        !eq(bundle.lineage.qcow2_acceptance_sha256, bundle.get("qcow2_acceptance").sha256) or
        !eq(bundle.lineage.fixed_vhd_derivation_gate_sha256, bundle.get("fixed_vhd_derivation_gate").sha256) or
        !eq(bundle.lineage.fixed_vhd_derivation_sha256, bundle.get("fixed_vhd_derivation").sha256) or
        !eq(bundle.lineage.final_inspection_sha256, bundle.get("final_inspection").sha256))
        return error.WrongImage;
    const cleanup = try read(a, io, bundle.get("cleanup"), 128);
    defer a.free(cleanup);
    if (!eq(cleanup, "primary=0 cleanup=0\n")) return error.LocalBootFailed;

    const boot_inputs_bytes = try read(a, io, bundle.get("boot_inputs"), 65536);
    defer a.free(boot_inputs_bytes);
    const boot_inputs_doc = try c.Document.parse(a, boot_inputs_bytes, .{ .bytes = 65536 });
    defer boot_inputs_doc.deinit();
    const package_tool = try field(
        try field(boot_inputs_doc.value(), "files"),
        "package_tool",
    );
    const package_tool_sha256 = try string(package_tool, "sha256");
    const package_tool_metadata = try field(package_tool, "metadata");
    if (package_tool_metadata != .array or
        package_tool_metadata.array.items.len != 9)
        return error.WrongImage;
    const package_tool_bytes = try c.integer(
        u64,
        package_tool_metadata.array.items[6],
    );

    const finalization_intent_bytes = try read(
        a,
        io,
        bundle.get("qcow2_finalization_intent"),
        65536,
    );
    defer a.free(finalization_intent_bytes);
    const finalization_intent_doc = try c.Document.parse(
        a,
        finalization_intent_bytes,
        .{ .bytes = 65536 },
    );
    defer finalization_intent_doc.deinit();
    const finalization_intent = finalization_intent_doc.value();
    if (finalization_intent != .object or
        finalization_intent.object.count() != 10 or
        !eq(
            try string(finalization_intent, "schema"),
            "uk.wamr.compute-qcow2-finalization-intent",
        ) or
        try c.integer(
            u8,
            try field(finalization_intent, "schema_version"),
        ) != 1 or
        !eq(
            try string(finalization_intent, "expected_source_sha256"),
            bundle.get("raw").sha256,
        ) or
        try c.integer(
            u64,
            try field(finalization_intent, "expected_source_bytes"),
        ) != bundle.get("raw").size or
        try c.integer(
            u64,
            try field(finalization_intent, "expected_virtual_bytes"),
        ) != bundle.get("raw").size or
        !eq(
            try string(finalization_intent, "expected_workload_sha256"),
            bundle.get("efi").sha256,
        ) or
        try c.integer(
            u64,
            try field(finalization_intent, "expected_workload_bytes"),
        ) != bundle.get("efi").size or
        try c.integer(
            u32,
            try field(finalization_intent, "timeout_ms"),
        ) != 120_000)
        return error.WrongImage;
    _ = try string(finalization_intent, "source_path");
    try exactLimits(try field(finalization_intent, "limits"));

    const finalization_bytes = try read(a, io, bundle.get("qcow2_finalization"), 65536);
    defer a.free(finalization_bytes);
    const finalization_doc = try c.Document.parse(a, finalization_bytes, .{ .bytes = 65536 });
    defer finalization_doc.deinit();
    const finalization = finalization_doc.value();
    if (finalization != .object or finalization.object.count() != 10 or
        !eq(try string(finalization, "schema"), "uk.wamr.compute-qcow2-finalization") or
        try c.integer(u8, try field(finalization, "schema_version")) != 1 or
        !eq(try string(finalization, "status"), "succeeded") or
        !eq(try string(finalization, "source_sha256"), bundle.get("raw").sha256) or
        try c.integer(u64, try field(finalization, "source_bytes")) != bundle.get("raw").size)
        return error.WrongImage;
    const final_output = try field(finalization, "output");
    try computedArtifact(
        final_output,
        bundle.get("qcow2"),
        bundle.get("raw").size,
    );
    try qcow2Profile(try field(finalization, "profile"));
    const final_identity = try field(finalization, "identity");
    try diskIdentity(final_identity, bundle.get("efi"));
    try exactLimits(try field(finalization, "limits"));
    const final_provenance = try field(finalization, "provenance");
    try provenance(
        final_provenance,
        package_tool_sha256,
        package_tool_bytes,
        "raw",
        bundle.get("raw").sha256,
    );

    const acceptance_bytes = try read(a, io, bundle.get("qcow2_acceptance"), 65536);
    defer a.free(acceptance_bytes);
    const acceptance_doc = try c.Document.parse(a, acceptance_bytes, .{ .bytes = 65536 });
    defer acceptance_doc.deinit();
    const acceptance = acceptance_doc.value();
    if (acceptance != .object or acceptance.object.count() != 11 or
        !eq(try string(acceptance, "schema"), "uk.wamr.compute-qcow2-acceptance") or
        try c.integer(u8, try field(acceptance, "schema_version")) != 1 or
        !eq(try string(acceptance, "profile"), "qcow2-derived-vhd") or
        !eq(try string(acceptance, "status"), "accepted") or
        !eq(try string(acceptance, "finalization_sha256"), bundle.get("qcow2_finalization").sha256))
        return error.WrongImage;
    const accepted = try field(acceptance, "accepted_qcow2");
    try inspectedArtifact(
        accepted,
        bundle.get("qcow2"),
        bundle.get("raw").size,
    );
    const accepted_source = try field(acceptance, "source");
    if (!eq(try string(accepted_source, "revision"), bundle.source_revision) or
        !eq(try string(accepted_source, "tree"), bundle.source_tree) or
        !eq(try string(acceptance, "build_sha256"), bundle.get("build").sha256) or
        !eq(
            try string(acceptance, "boot_inputs_sha256"),
            bundle.get("boot_inputs").sha256,
        ))
        return error.WrongSource;
    try exactModes(try field(acceptance, "modes"), &.{
        "raw-x2apic",   "raw-legacy-apic",
        "qcow2-x2apic", "qcow2-legacy-apic",
    });
    const accepted_boots = try field(acceptance, "boots");
    if (accepted_boots != .object or accepted_boots.object.count() != 4)
        return error.WrongLocalReport;
    for (bundle.boots[0..4]) |boot| try bootDigestRecord(accepted_boots, boot);

    const derive_intent_bytes = try read(
        a,
        io,
        bundle.get("fixed_vhd_derivation_intent"),
        65536,
    );
    defer a.free(derive_intent_bytes);
    const derive_intent_doc = try c.Document.parse(
        a,
        derive_intent_bytes,
        .{ .bytes = 65536 },
    );
    defer derive_intent_doc.deinit();
    const derive_intent = derive_intent_doc.value();
    if (derive_intent != .object or derive_intent.object.count() != 8 or
        !eq(
            try string(derive_intent, "schema"),
            "uk.wamr.compute-fixed-vhd-derivation-intent",
        ) or
        try c.integer(
            u8,
            try field(derive_intent, "schema_version"),
        ) != 1 or
        !eq(
            try string(derive_intent, "accepted_qcow2_sha256"),
            bundle.get("qcow2").sha256,
        ) or
        try c.integer(
            u64,
            try field(derive_intent, "expected_source_bytes"),
        ) != bundle.get("qcow2").size or
        try c.integer(
            u64,
            try field(derive_intent, "expected_capacity_bytes"),
        ) != bundle.get("raw").size or
        try c.integer(
            u32,
            try field(derive_intent, "timeout_ms"),
        ) != 120_000)
        return error.WrongImage;
    _ = try string(derive_intent, "source_path");
    try exactLimits(try field(derive_intent, "limits"));

    const gate_bytes = try read(a, io, bundle.get("fixed_vhd_derivation_gate"), 65536);
    defer a.free(gate_bytes);
    const gate_doc = try c.Document.parse(a, gate_bytes, .{ .bytes = 65536 });
    defer gate_doc.deinit();
    const gate = gate_doc.value();
    if (gate != .object or gate.object.count() != 8 or
        !eq(try string(gate, "schema"), "uk.wamr.compute-fixed-vhd-derivation-gate") or
        try c.integer(u8, try field(gate, "schema_version")) != 1 or
        !eq(try string(gate, "profile"), "qcow2-derived-vhd") or
        !eq(try string(gate, "status"), "accepted_qcow2_only") or
        !eq(try string(gate, "accepted_qcow2_sha256"), bundle.get("qcow2").sha256) or
        !eq(try string(gate, "qcow2_acceptance_sha256"), bundle.get("qcow2_acceptance").sha256) or
        !eq(try string(gate, "derivation_intent_sha256"), bundle.get("fixed_vhd_derivation_intent").sha256))
        return error.WrongImage;
    const absent = try field(gate, "derived_output_absent");
    if (absent != .bool or !absent.bool) return error.WrongImage;

    const derivation_bytes = try read(a, io, bundle.get("fixed_vhd_derivation"), 65536);
    defer a.free(derivation_bytes);
    const derivation_doc = try c.Document.parse(a, derivation_bytes, .{ .bytes = 65536 });
    defer derivation_doc.deinit();
    const derivation = derivation_doc.value();
    if (derivation != .object or derivation.object.count() != 13 or
        !eq(try string(derivation, "schema"), "uk.wamr.compute-fixed-vhd-derivation") or
        try c.integer(u8, try field(derivation, "schema_version")) != 1 or
        !eq(try string(derivation, "status"), "succeeded") or
        !eq(
            try string(derivation, "accepted_qcow2_decoded_sha256"),
            bundle.get("raw").sha256,
        ))
        return error.WrongImage;
    const derived_source = try field(derivation, "accepted_qcow2");
    try computedArtifact(
        derived_source,
        bundle.get("qcow2"),
        bundle.get("raw").size,
    );
    try qcow2Profile(try field(derivation, "accepted_qcow2_profile"));
    const derived_output = try field(derivation, "output");
    try computedArtifact(
        derived_output,
        bundle.get("vhd"),
        bundle.get("vhd").size - 512,
    );
    const derived_provenance = try field(derivation, "provenance");
    try provenance(
        derived_provenance,
        package_tool_sha256,
        package_tool_bytes,
        "qcow2",
        bundle.get("qcow2").sha256,
    );
    try exactLimits(try field(derivation, "limits"));
    const source_identity = try std.json.Stringify.valueAlloc(a, try field(derivation, "source_identity"), .{});
    defer a.free(source_identity);
    const output_identity = try std.json.Stringify.valueAlloc(a, try field(derivation, "output_identity"), .{});
    defer a.free(output_identity);
    if (!eq(source_identity, output_identity)) return error.WrongImage;
    try diskIdentity(try field(derivation, "source_identity"), bundle.get("efi"));
    try diskIdentity(try field(derivation, "output_identity"), bundle.get("efi"));
    try footerRecord(
        io,
        try field(derivation, "footer"),
        bundle.get("vhd"),
    );
    const relocation = try field(derivation, "relocation");
    if (relocation != .object or relocation.object.count() != 6 or
        (try field(relocation, "was_relocated")) != .bool or
        (try field(relocation, "was_relocated")).bool or
        try c.integer(
            u64,
            try field(relocation, "old_backup_lba"),
        ) != try c.integer(
            u64,
            try field(relocation, "new_backup_lba"),
        ) or
        try c.integer(
            u64,
            try field(relocation, "old_last_usable_lba"),
        ) != try c.integer(
            u64,
            try field(relocation, "new_last_usable_lba"),
        ) or
        !eq(
            try string(relocation, "allowed_differences"),
            "protective-mbr,primary-gpt,relocated-backup-gpt,zero-padding",
        ))
        return error.WrongImage;

    const inspection_bytes = try read(a, io, bundle.get("final_inspection"), 65536);
    defer a.free(inspection_bytes);
    const inspection_doc = try c.Document.parse(a, inspection_bytes, .{ .bytes = 65536 });
    defer inspection_doc.deinit();
    const inspection = inspection_doc.value();
    if (inspection != .object or inspection.object.count() != 9 or
        !eq(try string(inspection, "schema"), "uk.wamr.compute-image-chain-inspection") or
        try c.integer(u8, try field(inspection, "schema_version")) != 1 or
        !eq(try string(inspection, "profile"), "qcow2-derived-vhd") or
        !eq(try string(inspection, "status"), "complete"))
        return error.WrongImage;
    const inspection_source = try field(inspection, "source");
    if (!eq(
        try string(inspection_source, "revision"),
        bundle.source_revision,
    ) or !eq(
        try string(inspection_source, "tree"),
        bundle.source_tree,
    ))
        return error.WrongSource;
    try exactModes(try field(inspection, "modes"), &.{
        "raw-x2apic",   "raw-legacy-apic",
        "qcow2-x2apic", "qcow2-legacy-apic",
        "vpc-x2apic",   "vpc-legacy-apic",
    });
    const inspected_artifacts = try field(inspection, "artifacts");
    if (inspected_artifacts != .object or inspected_artifacts.object.count() != 4)
        return error.WrongImage;
    inline for (.{ "efi", "raw", "qcow2", "vhd" }) |name| {
        const observed = inspected_artifacts.object.get(name) orelse return error.MissingField;
        try inspectedArtifact(
            observed,
            bundle.get(name),
            if (comptime eq(name, "vhd"))
                bundle.get("vhd").size - 512
            else if (comptime eq(name, "efi"))
                bundle.get("efi").size
            else
                bundle.get("raw").size,
        );
    }
    const records = try field(inspection, "records");
    if (records != .object or records.object.count() != 10)
        return error.WrongImage;
    inline for (.{
        .{ "build-start.json", "build_start" },
        .{ "build.json", "build" },
        .{ "boot-inputs.json", "boot_inputs" },
        .{ "package.json", "package" },
        .{ "qcow2-finalization-intent.json", "qcow2_finalization_intent" },
        .{ "qcow2-finalization.json", "qcow2_finalization" },
        .{ "qcow2-acceptance.json", "qcow2_acceptance" },
        .{ "fixed-vhd-derivation-intent.json", "fixed_vhd_derivation_intent" },
        .{ "fixed-vhd-derivation-gate.json", "fixed_vhd_derivation_gate" },
        .{ "fixed-vhd-derivation.json", "fixed_vhd_derivation" },
    }) |pair| {
        if (!eq(
            try c.string(
                records.object.get(pair[0]) orelse
                    return error.MissingField,
            ),
            bundle.get(pair[1]).sha256,
        ))
            return error.WrongImage;
    }
    const inspected_boots = try field(inspection, "boots");
    if (inspected_boots != .object or inspected_boots.object.count() != 6)
        return error.WrongLocalReport;
    for (bundle.boots) |boot| try bootDigestRecord(inspected_boots, boot);
}

fn qcow2Profile(value: std.json.Value) !void {
    if (value != .object or value.object.count() != 14 or
        !eq(try string(value, "format"), "qcow2") or
        try c.integer(u32, try field(value, "version")) != 3 or
        try c.integer(u64, try field(value, "cluster_bytes")) != 64 * 1024 or
        !eq(try string(value, "compression"), "zstd") or
        try c.integer(u64, try field(value, "incompatible_features")) != 8 or
        try c.integer(u64, try field(value, "compatible_features")) != 0 or
        try c.integer(u64, try field(value, "autoclear_features")) != 0 or
        try c.integer(u32, try field(value, "snapshots")) != 0)
        return error.WrongImage;
    inline for (.{ "header_extensions", "extended_l2", "encryption", "backing_file", "external_data_file" }) |name| {
        const flag = try field(value, name);
        if (flag != .bool or flag.bool) return error.WrongImage;
    }
    const standalone = try field(value, "standalone");
    if (standalone != .bool or !standalone.bool) return error.WrongImage;
}

fn exactModes(value: std.json.Value, expected: []const []const u8) !void {
    if (value != .array or value.array.items.len != expected.len)
        return error.WrongLocalMode;
    for (value.array.items, expected) |item, name|
        if (!eq(try c.string(item), name)) return error.WrongLocalMode;
}

fn bootDigestRecord(value: std.json.Value, boot: anytype) !void {
    const observed = value.object.get(@tagName(boot.mode)) orelse return error.MissingField;
    if (observed != .object or observed.object.count() != 4 or
        !eq(try string(observed, "request_sha256"), boot.request.sha256) or
        !eq(try string(observed, "report_sha256"), boot.report.sha256) or
        !eq(try string(observed, "serial_sha256"), boot.serial.sha256) or
        !eq(try string(observed, "compute_sha256"), boot.compute.sha256))
        return error.WrongLocalReport;
}

fn exactLimits(value: std.json.Value) !void {
    if (value != .object or value.object.count() != 9 or
        try c.integer(u64, try field(value, "max_input_bytes")) != 66 * 1024 * 1024 or
        try c.integer(u64, try field(value, "max_output_bytes")) != 66 * 1024 * 1024 + 512 or
        try c.integer(u64, try field(value, "max_virtual_bytes")) != 66 * 1024 * 1024 or
        try c.integer(u64, try field(value, "max_partition_array_bytes")) != 1024 * 1024 or
        try c.integer(u64, try field(value, "max_metadata_bytes")) != 128 * 1024 or
        try c.integer(u64, try field(value, "max_metadata_work")) != 8194 or
        try c.integer(u64, try field(value, "max_work_bytes")) != 4 * 66 * 1024 * 1024 or
        try c.integer(u64, try field(value, "max_memory_bytes")) != 512 * 1024 * 1024 or
        try c.integer(u64, try field(value, "max_workload_bytes")) != 64 * 1024 * 1024)
        return error.WrongImage;
}

fn allocation(value: std.json.Value) !void {
    if (value != .object or value.object.count() != 2)
        return error.WrongImage;
    const state = try string(value, "state");
    const bytes = try field(value, "bytes");
    if (eq(state, "available")) {
        _ = try c.integer(u64, bytes);
    } else if (eq(state, "unavailable")) {
        if (bytes != .null) return error.WrongImage;
    } else {
        return error.WrongImage;
    }
}

fn computedArtifact(
    value: std.json.Value,
    item: Artifact,
    virtual_bytes: u64,
) !void {
    if (value != .object or value.object.count() != 4 or
        !eq(try string(value, "sha256"), item.sha256) or
        try c.integer(u64, try field(value, "file_bytes")) != item.size or
        try c.integer(u64, try field(value, "virtual_bytes")) != virtual_bytes)
        return error.WrongImage;
    try allocation(try field(value, "allocated"));
}

fn inspectedArtifact(
    value: std.json.Value,
    item: Artifact,
    virtual_bytes: u64,
) !void {
    if (value != .object or value.object.count() != 6 or
        (try string(value, "path")).len == 0 or
        !eq(try string(value, "sha256"), item.sha256) or
        try c.integer(u64, try field(value, "file_bytes")) != item.size or
        try c.integer(u64, try field(value, "virtual_bytes")) != virtual_bytes)
        return error.WrongImage;
    try allocation(try field(value, "allocated"));
    const metadata = try field(value, "metadata");
    if (metadata != .array or metadata.array.items.len != 9 or
        try c.integer(u64, metadata.array.items[6]) != item.size)
        return error.WrongImage;
    for (metadata.array.items) |part| _ = try c.integer(u64, part);
}

fn diskIdentity(value: std.json.Value, efi: Artifact) !void {
    if (value != .object or value.object.count() != 11 or
        try c.integer(u32, try field(value, "partition_count")) == 0 or
        try c.integer(u64, try field(value, "esp_length_bytes")) == 0 or
        try c.integer(u64, try field(value, "workload_bytes")) != efi.size or
        !eq(try string(value, "workload_sha256"), efi.sha256) or
        (try string(value, "workload_path")).len == 0)
        return error.WrongImage;
    try hex(try string(value, "disk_guid"), 32);
    try hex(try string(value, "esp_partition_guid"), 32);
    try hex(try string(value, "partition_array_sha256"), 64);
    try hex(try string(value, "partition_contents_sha256"), 64);
    _ = try c.integer(u64, try field(value, "esp_offset_bytes"));
    _ = try c.integer(u32, try field(value, "esp_volume_id"));
}

fn provenance(
    value: std.json.Value,
    producer_sha256: []const u8,
    producer_bytes: u64,
    parent_kind: []const u8,
    parent_sha256: []const u8,
) !void {
    if (value != .object or value.object.count() != 6 or
        !eq(try string(value, "producer_sha256"), producer_sha256) or
        try c.integer(u64, try field(value, "producer_bytes")) != producer_bytes or
        !eq(try string(value, "parent_kind"), parent_kind) or
        !eq(try string(value, "parent_sha256"), parent_sha256))
        return error.WrongImage;
    try hex(try string(value, "miz_revision"), 40);
    try hex(try string(value, "config_sha256"), 64);
}

fn footerRecord(io: std.Io, value: std.json.Value, vhd: Artifact) !void {
    if (value != .object or value.object.count() != 9 or
        !eq(try string(value, "creator"), "miz ") or
        try c.integer(u32, try field(value, "creator_version")) != 0x0001_0000 or
        try c.integer(u32, try field(value, "timestamp")) != 0 or
        try c.integer(u16, try field(value, "cylinders")) == 0 or
        try c.integer(u8, try field(value, "heads")) == 0 or
        try c.integer(u8, try field(value, "sectors_per_track")) == 0)
        return error.WrongImage;
    try hex(try string(value, "sha256"), 64);
    try hex(try string(value, "unique_id"), 32);
    _ = try c.integer(u32, try field(value, "checksum"));

    const file = try files.openAbsolute(io, vhd.path, .artifact);
    defer file.close(io);
    const before = try files.snapshot(file);
    var bytes: [512]u8 = undefined;
    if (try file.readPositionalAll(io, &bytes, vhd.size - bytes.len) != bytes.len or
        !files.sameSnapshot(before, try files.snapshot(file)))
        return error.ArtifactChanged;
    var hash = core.Sha256.init(.{});
    hash.update(&bytes);
    if (!std.mem.eql(
        u8,
        &hash.finalResult(),
        &try c.parseSha256(try string(value, "sha256")),
    ))
        return error.WrongImage;
}

pub fn rawVhd(io: std.Io, raw: Artifact, vhd: Artifact) !void {
    if (raw.size != 66 * 1024 * 1024 or vhd.size != raw.size + 512) return error.InvalidArtifact;
    const file = try files.openAbsolute(io, vhd.path, .artifact);
    defer file.close(io);
    const before = try files.snapshot(file);
    var hash = core.Sha256.init(.{});
    var buffer: [65536]u8 = undefined;
    var offset: u64 = 0;
    while (offset < raw.size) {
        const n: usize = @intCast(@min(buffer.len, raw.size - offset));
        if (try file.readPositionalAll(io, buffer[0..n], offset) != n) return error.ArtifactChanged;
        hash.update(buffer[0..n]);
        offset += n;
    }
    if (!std.mem.eql(u8, &hash.finalResult(), &try c.parseSha256(raw.sha256))) return error.WrongRawPrefix;
    var footer: [512]u8 = undefined;
    if (try file.readPositionalAll(io, &footer, offset) != 512) return error.ArtifactChanged;
    try base.footer(&footer, raw.size, null);
    if (try file.readPositionalAll(io, buffer[0..1], vhd.size) != 0 or !files.sameSnapshot(before, try files.snapshot(file))) return error.ArtifactChanged;
}

fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidObject;
    return value.object.get(name) orelse error.MissingField;
}
fn string(value: std.json.Value, name: []const u8) ![]const u8 {
    return c.string(try field(value, name));
}
fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
fn same(a: Artifact, b: Artifact) bool {
    return a.size == b.size and eq(a.sha256, b.sha256) and eq(a.path, b.path);
}
fn sameRun(a: RunIdentity, b: RunIdentity) bool {
    return eq(a.repository, b.repository) and
        eq(a.run_id, b.run_id) and eq(a.run_attempt, b.run_attempt);
}
fn sameLineage(a: Lineage, b: Lineage) bool {
    inline for (std.meta.fields(Lineage)) |member|
        if (!eq(@field(a, member.name), @field(b, member.name))) return false;
    return true;
}
fn artifact(item: Artifact) !void {
    try files.absoluteFilePath(item.path);
    _ = try c.parseSha256(item.sha256);
    if (item.size == 0 or item.size > 256 * 1024 * 1024 + 512) return error.InvalidArtifact;
}
fn hex(text: []const u8, length: usize) !void {
    if (text.len != length) return error.InvalidIdentity;
    var nonzero = false;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidIdentity;
        nonzero = nonzero or byte != '0';
    }
    if (!nonzero) return error.InvalidIdentity;
}
fn decimal(text: []const u8) !void {
    if (text.len == 0 or text.len > 20 or text[0] == '0')
        return error.InvalidIdentity;
    for (text) |byte| if (!std.ascii.isDigit(byte))
        return error.InvalidIdentity;
}
fn uuid(text: []const u8) !void {
    if (text.len != 36) return error.InvalidIdentity;
    var compact: [32]u8 = undefined;
    var n: usize = 0;
    for (text, 0..) |byte, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (byte != '-') return error.InvalidIdentity;
        } else {
            compact[n] = byte;
            n += 1;
        }
    }
    try hex(&compact, 32);
}
