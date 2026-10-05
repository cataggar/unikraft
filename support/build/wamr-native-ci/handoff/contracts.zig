// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const c = core.contracts;
pub const layout = @import("layout.zig");
pub const profile = @import("profile.zig");

pub const json_limits = c.Limits{
    .bytes = @intCast(layout.max_json_bytes),
    .depth = 16,
    .string_bytes = 4096,
    .items = 256,
    .tokens = 8192,
};

pub const schema_fields = struct {
    pub const artifact = [_][]const u8{ "path", "sha256", "size" };
    pub const manifest_member = [_][]const u8{ "sha256", "size" };
    pub const boot = [_][]const u8{ "compute", "mode", "report", "request", "serial" };
    pub const identity = [_][]const u8{ "compiler_sha256", "config_sha256", "cwasm_sha256", "runtime_sha256", "wamr_revision", "wasm_sha256" };
    pub const local_image_handoff_v1 = [_][]const u8{ "artifacts", "authority", "boots", "evidence", "identity", "schema", "source_revision", "source_tree", "version" };
    pub const local_image_handoff_v2 = [_][]const u8{ "artifacts", "authority", "boots", "evidence", "identity", "lineage", "profile", "run", "schema", "source_revision", "source_tree", "version" };
    pub const public_source_manifest_v1 = [_][]const u8{ "authority", "members", "schema", "source", "version" };
    pub const public_source_manifest_v2 = [_][]const u8{ "authority", "members", "profile", "schema", "source", "version" };
    pub const public_source_transport_v2 = [_][]const u8{ "schema", "version", "repository", "run_id", "run_attempt", "source_revision", "source_tree", "inner_zip_sha256", "artifact_id", "container_digest" };
    pub const direct_compute_candidate = [_][]const u8{ "schema", "version", "purpose", "authority", "approval", "attempt_id", "subscription", "location", "prefix", "vm_size", "serial_mode", "runtime_seconds", "cleanup_seconds", "operation_seconds", "poll_seconds", "source_revision", "source_tree", "identity", "os_vhd", "bundle" };
    pub const direct_compute_admission_v2 = [_][]const u8{ "authority", "lineage", "profile", "public_bundle", "run", "schema", "source_revision", "source_tree", "transport", "version" };
    pub const run = [_][]const u8{ "repository", "run_attempt", "run_id" };
    pub const lineage = [_][]const u8{ "accepted_qcow2_sha256", "derived_vhd_sha256", "final_inspection_sha256", "fixed_vhd_derivation_gate_sha256", "fixed_vhd_derivation_sha256", "qcow2_acceptance_sha256", "qcow2_finalization_sha256", "raw_sha256" };
    pub const public_context = [_][]const u8{ "repository", "run_id", "run_attempt", "source_revision", "source_tree", "wamr_revision" };
    pub const approval = [_][]const u8{ "direct_specialized_gen2", "os_only_private", "two_boots_only", "cleanup_owned_group", "exact_image_and_local_bundle_reviewed", "fresh_final_approval", "approved_unix", "expires_unix" };
};

const max_selected_member_bytes = layout.max_total_bytes - 2 * layout.max_json_bytes;

pub fn parseCanonical(allocator: std.mem.Allocator, bytes: []const u8) !c.Document {
    var document = try c.Document.parse(allocator, bytes, json_limits);
    errdefer document.deinit();
    try document.requireCanonical(allocator, bytes);
    return document;
}

pub fn validateLocalImageHandoff(value: std.json.Value) !profile.Compatibility {
    return validateLocalImageHandoffWithRoot(value, null);
}

pub fn validateLocalImageHandoffWithRoot(value: std.json.Value, root: ?[]const u8) !profile.Compatibility {
    if (root) |path| if (path.len == 0) return error.InvalidPath;
    const initial = try object(value);
    const version = try integer(u8, initial, "version");
    return switch (version) {
        1 => validateBundleV1(value, root),
        2 => validateBundleV2(value, root),
        else => error.UnsupportedVersion,
    };
}

pub fn validatePublicSourceManifest(value: std.json.Value) !profile.Compatibility {
    const initial = try object(value);
    const version = try integer(u8, initial, "version");
    const compatibility = try profile.compatibility(version, if (version == 2)
        try string(initial, "profile")
    else
        null);
    _ = try c.exactFields(value, if (compatibility == .tiny_qcow2_derived_vhd_v2) &schema_fields.public_source_manifest_v2 else &schema_fields.public_source_manifest_v1);
    try literal(initial, "schema", "uk.wamr.public-source-bundle");
    try literal(initial, "authority", profile.authority);
    try validatePublicContext(initial.get("source") orelse return error.MissingField);
    try validateMemberMap(initial.get("members") orelse return error.MissingField, compatibility);
    return compatibility;
}

pub fn validatePublicSourceTransportV2(value: std.json.Value) !void {
    const fields = try c.exactFields(value, &schema_fields.public_source_transport_v2);
    try literal(fields, "schema", "uk.wamr.public-source-transport");
    if (try integer(u8, fields, "version") != 2) return error.UnsupportedVersion;
    try literal(fields, "repository", profile.repository);
    try decimalString(try string(fields, "run_id"));
    try decimalString(try string(fields, "run_attempt"));
    try hex(try string(fields, "source_revision"), 40);
    try hex(try string(fields, "source_tree"), 40);
    _ = try c.parseSha256(try string(fields, "inner_zip_sha256"));
    try decimalString(try string(fields, "artifact_id"));
    _ = try c.parseSha256(try string(fields, "container_digest"));
}

pub fn validateDirectComputeCandidate(value: std.json.Value) !profile.Compatibility {
    const fields = try c.exactFields(value, &schema_fields.direct_compute_candidate);
    try literal(fields, "schema", "uk.wamr.direct-compute");
    try literal(fields, "authority", profile.authority);
    const version = try integer(u8, fields, "version");
    const compatibility = try profile.compatibility(version, if (version == 2) profile.current_profile else null);
    try literal(fields, "purpose", if (compatibility == .frozen_tiny_v1) "tiny-aot-two-boot" else profile.current_profile);
    try validateApproval(fields.get("approval").?);
    try uuid(try string(fields, "attempt_id"));
    const subscription = try string(fields, "subscription");
    try literal(fields, "location", "northeurope");
    const prefix = try string(fields, "prefix");
    if (compatibility == .frozen_tiny_v1) {
        if (!std.mem.eql(u8, subscription, "FINAL-APPROVED-SUBSCRIPTION-UUID") or
            !std.mem.eql(u8, prefix, "FINAL-APPROVED-FRESH-NAME"))
            return error.InvalidCandidateScope;
    } else {
        try boundedName(prefix);
    }
    try literal(fields, "vm_size", "Standard_D2s_v5");
    try literal(fields, "serial_mode", "azure_cumulative");
    if (try integer(u32, fields, "runtime_seconds") != 3600 or
        try integer(u32, fields, "cleanup_seconds") != 1800 or
        try integer(u32, fields, "operation_seconds") != 600 or
        try integer(u32, fields, "poll_seconds") != 10)
        return error.InvalidBudget;
    try hex(try string(fields, "source_revision"), 40);
    try hex(try string(fields, "source_tree"), 40);
    try validateIdentity(fields.get("identity").?);
    try validateArtifact(fields.get("os_vhd").?, layout.max_large_artifact_bytes);
    try validateArtifact(fields.get("bundle").?, layout.max_json_bytes);
    return compatibility;
}

pub fn validateDirectComputeAdmissionV2(value: std.json.Value) !void {
    const fields = try c.exactFields(value, &schema_fields.direct_compute_admission_v2);
    try literal(fields, "schema", "uk.wamr.direct-compute-admission");
    if (try integer(u8, fields, "version") != 2) return error.UnsupportedVersion;
    try literal(fields, "profile", profile.current_profile);
    try literal(fields, "authority", profile.authority);
    try hex(try string(fields, "source_revision"), 40);
    try hex(try string(fields, "source_tree"), 40);
    try validateRun(fields.get("run").?);
    try validateLineage(fields.get("lineage").?, null);
    try validateArtifact(fields.get("public_bundle").?, layout.max_json_bytes);
    try validateArtifact(fields.get("transport").?, layout.max_json_bytes);
}

fn validateBundleV1(value: std.json.Value, root: ?[]const u8) !profile.Compatibility {
    const fields = try c.exactFields(value, &schema_fields.local_image_handoff_v1);
    try commonBundle(fields, .frozen_tiny_v1, root);
    return .frozen_tiny_v1;
}

fn validateBundleV2(value: std.json.Value, root: ?[]const u8) !profile.Compatibility {
    const fields = try c.exactFields(value, &schema_fields.local_image_handoff_v2);
    try commonBundle(fields, .tiny_qcow2_derived_vhd_v2, root);
    try literal(fields, "profile", profile.current_profile);
    try validateRun(fields.get("run").?);
    try validateLineage(fields.get("lineage").?, fields.get("artifacts").?);
    return .tiny_qcow2_derived_vhd_v2;
}

fn commonBundle(fields: std.json.ObjectMap, compatibility: profile.Compatibility, root: ?[]const u8) !void {
    try literal(fields, "schema", "uk.wamr.local-image-handoff");
    if (try integer(u8, fields, "version") != compatibility.version()) return error.UnsupportedVersion;
    try literal(fields, "authority", profile.authority);
    try hex(try string(fields, "source_revision"), 40);
    try hex(try string(fields, "source_tree"), 40);
    try validateIdentity(fields.get("identity").?);
    var total: u64 = 0;
    total = try addBounded(total, try validateArtifacts(fields.get("artifacts").?, compatibility, root));
    total = try addBounded(total, try validateBoots(fields.get("boots").?, compatibility, root));
    total = try addBounded(total, try validateEvidence(fields.get("evidence").?, compatibility, root));
    if (total > max_selected_member_bytes) return error.InvalidTotalSize;
}

fn validateArtifacts(value: std.json.Value, compatibility: profile.Compatibility, root: ?[]const u8) !u64 {
    const items = try array(value);
    const names = layout.artifactNames(compatibility);
    if (items.len != names.len) return error.InvalidArtifacts;
    var total: u64 = 0;
    for (items, names) |item, name| {
        var path_buffer: [64]u8 = undefined;
        const expected = try std.fmt.bufPrint(&path_buffer, "artifacts/{s}", .{name});
        total = try addBounded(total, try validateArtifactPath(item, root, expected, layout.artifactLimit(name)));
    }
    return total;
}

fn validateBoots(value: std.json.Value, compatibility: profile.Compatibility, root: ?[]const u8) !u64 {
    const items = try array(value);
    const modes = profile.modes(compatibility);
    if (items.len != modes.len) return error.InvalidBoots;
    var total: u64 = 0;
    for (items, modes) |item, mode| {
        const fields = try c.exactFields(item, &schema_fields.boot);
        try literal(fields, "mode", @tagName(mode));
        inline for (.{ "serial", "request", "report", "compute" }) |name| {
            var path_buffer: [128]u8 = undefined;
            const expected = try std.fmt.bufPrint(&path_buffer, "boots/{s}/{s}", .{ @tagName(mode), name });
            total = try addBounded(total, try validateArtifactPath(fields.get(name).?, root, expected, if (std.mem.eql(u8, name, "serial")) layout.max_serial_bytes else layout.max_json_bytes));
        }
    }
    return total;
}

fn validateEvidence(value: std.json.Value, compatibility: profile.Compatibility, root: ?[]const u8) !u64 {
    const items = try array(value);
    const names = layout.evidenceNames(compatibility);
    if (items.len != names.len) return error.InvalidEvidence;
    var total: u64 = 0;
    for (items, names) |item, name| {
        var path_buffer: [128]u8 = undefined;
        const expected = try std.fmt.bufPrint(&path_buffer, "evidence/{s}", .{name});
        total = try addBounded(total, try validateArtifactPath(item, root, expected, layout.max_json_bytes));
    }
    return total;
}

fn validateMemberMap(value: std.json.Value, compatibility: profile.Compatibility) !void {
    const members = try object(value);
    if (members.count() != layout.selectedMemberCount(compatibility)) return error.InvalidMembers;
    var total: u64 = 0;
    for (members.keys(), members.values()) |name, item| {
        if (!layout.containsSelectedPublicMember(compatibility, name)) return error.UnexpectedMember;
        const fields = try c.exactFields(item, &schema_fields.manifest_member);
        const size = try integer(u64, fields, "size");
        if (size == 0 or size > try layout.memberLimit(name)) return error.InvalidArtifact;
        total = try addBounded(total, size);
        _ = try c.parseSha256(try string(fields, "sha256"));
    }
    if (total > max_selected_member_bytes) return error.InvalidTotalSize;
}

fn validateIdentity(value: std.json.Value) !void {
    const fields = try c.exactFields(value, &schema_fields.identity);
    try hex(try string(fields, "wamr_revision"), 40);
    inline for (.{ "wasm_sha256", "cwasm_sha256", "runtime_sha256", "compiler_sha256", "config_sha256" }) |name|
        _ = try c.parseSha256(try string(fields, name));
}

fn validateRun(value: std.json.Value) !void {
    const fields = try c.exactFields(value, &schema_fields.run);
    try literal(fields, "repository", profile.repository);
    try decimalString(try string(fields, "run_id"));
    try decimalString(try string(fields, "run_attempt"));
}

fn validateLineage(value: std.json.Value, artifacts: ?std.json.Value) !void {
    const fields = try c.exactFields(value, &schema_fields.lineage);
    inline for (schema_fields.lineage) |name| _ = try c.parseSha256(try string(fields, name));
    if (artifacts) |artifact_value| {
        try equalField(fields, "raw_sha256", try artifactSha(artifact_value, "raw"));
        try equalField(fields, "accepted_qcow2_sha256", try artifactSha(artifact_value, "qcow2"));
        try equalField(fields, "derived_vhd_sha256", try artifactSha(artifact_value, "vhd"));
        try equalField(fields, "qcow2_finalization_sha256", try artifactSha(artifact_value, "qcow2_finalization"));
        try equalField(fields, "qcow2_acceptance_sha256", try artifactSha(artifact_value, "qcow2_acceptance"));
        try equalField(fields, "fixed_vhd_derivation_gate_sha256", try artifactSha(artifact_value, "fixed_vhd_derivation_gate"));
        try equalField(fields, "fixed_vhd_derivation_sha256", try artifactSha(artifact_value, "fixed_vhd_derivation"));
        try equalField(fields, "final_inspection_sha256", try artifactSha(artifact_value, "final_inspection"));
    }
}

fn validatePublicContext(value: std.json.Value) !void {
    const fields = try c.exactFields(value, &schema_fields.public_context);
    try literal(fields, "repository", profile.repository);
    try decimalString(try string(fields, "run_id"));
    try decimalString(try string(fields, "run_attempt"));
    try hex(try string(fields, "source_revision"), 40);
    try hex(try string(fields, "source_tree"), 40);
    try literal(fields, "wamr_revision", profile.wamr_revision);
}

fn validateApproval(value: std.json.Value) !void {
    const fields = try c.exactFields(value, &schema_fields.approval);
    inline for (.{
        "direct_specialized_gen2",               "os_only_private",      "two_boots_only", "cleanup_owned_group",
        "exact_image_and_local_bundle_reviewed", "fresh_final_approval",
    }) |name| if ((fields.get(name) orelse return error.MissingField) != .bool or fields.get(name).?.bool)
        return error.AuthorityNotAllowed;
    if (try integer(u64, fields, "approved_unix") != 0 or
        try integer(u64, fields, "expires_unix") != 0)
        return error.AuthorityNotAllowed;
}

fn validateArtifact(value: std.json.Value, maximum: u64) !void {
    _ = try artifactFields(value, maximum);
}

fn validateArtifactPath(value: std.json.Value, root: ?[]const u8, expected_path: []const u8, maximum: u64) !u64 {
    const fields = try artifactFields(value, maximum);
    if (!pathMatchesMember(fields.path, root, expected_path)) return error.InvalidPath;
    return fields.size;
}

fn pathMatchesMember(path: []const u8, root: ?[]const u8, member: []const u8) bool {
    const base = root orelse return std.mem.eql(u8, path, member);
    if (std.mem.eql(u8, base, "/"))
        return path.len == member.len + 1 and path[0] == '/' and std.mem.eql(u8, path[1..], member);
    return path.len == base.len + 1 + member.len and
        std.mem.startsWith(u8, path, base) and
        path[base.len] == '/' and
        std.mem.eql(u8, path[base.len + 1 ..], member);
}

fn artifactFields(value: std.json.Value, maximum: u64) !struct { path: []const u8, size: u64 } {
    const fields = try c.exactFields(value, &schema_fields.artifact);
    const path = try string(fields, "path");
    if (path.len == 0 or path.len > 4096) return error.InvalidPath;
    _ = try c.parseSha256(try string(fields, "sha256"));
    const size = try integer(u64, fields, "size");
    if (size == 0 or size > maximum) return error.InvalidArtifact;
    return .{ .path = path, .size = size };
}

fn artifactSha(artifacts: std.json.Value, name: []const u8) ![]const u8 {
    const items = try array(artifacts);
    for (layout.artifact_names_v2, 0..) |candidate, i| {
        if (!std.mem.eql(u8, candidate, name)) continue;
        const fields = try c.exactFields(items[i], &schema_fields.artifact);
        return try string(fields, "sha256");
    }
    return error.UnknownArtifact;
}

fn object(value: std.json.Value) !std.json.ObjectMap {
    return switch (value) {
        .object => |map| map,
        else => error.ExpectedObject,
    };
}

fn array(value: std.json.Value) ![]std.json.Value {
    return switch (value) {
        .array => |items| items.items,
        else => error.ExpectedArray,
    };
}

fn string(fields: std.json.ObjectMap, name: []const u8) ![]const u8 {
    return c.string(fields.get(name) orelse return error.MissingField);
}

fn integer(comptime T: type, fields: std.json.ObjectMap, name: []const u8) !T {
    return c.integer(T, fields.get(name) orelse return error.MissingField);
}

fn literal(fields: std.json.ObjectMap, name: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, try string(fields, name), expected)) return error.InvalidLiteral;
}

fn equalField(fields: std.json.ObjectMap, name: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, try string(fields, name), expected)) return error.InvalidLineage;
}

fn addBounded(current: u64, item: u64) !u64 {
    return std.math.add(u64, current, item) catch error.IntegerOverflow;
}

fn hex(value: []const u8, len: usize) !void {
    if (value.len != len) return error.InvalidHex;
    for (value) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
        return error.InvalidHex;
}

fn decimalString(value: []const u8) !void {
    if (value.len == 0 or value.len > 20 or value[0] == '0') return error.InvalidDecimal;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidDecimal;
}

fn uuid(value: []const u8) !void {
    _ = try c.parseUuid(value);
}

fn boundedName(value: []const u8) !void {
    if (value.len < 6 or value.len > 32) return error.InvalidName;
    for (value) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '-')
        return error.InvalidName;
}
