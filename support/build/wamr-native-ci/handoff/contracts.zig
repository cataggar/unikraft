// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const c = core.contracts;
const layout = @import("layout.zig");
const profile = @import("profile.zig");

pub const json_limits = c.Limits{
    .bytes = @intCast(layout.max_json_bytes),
    .depth = 16,
    .string_bytes = 4096,
    .items = 256,
    .tokens = 8192,
};

pub fn parseCanonical(allocator: std.mem.Allocator, bytes: []const u8) !c.Document {
    var document = try c.Document.parse(allocator, bytes, json_limits);
    errdefer document.deinit();
    try document.requireCanonical(allocator, bytes);
    return document;
}

pub fn validateLocalImageHandoff(value: std.json.Value) !profile.Compatibility {
    const initial = try object(value);
    const version = try integer(u8, initial, "version");
    return switch (version) {
        1 => validateBundleV1(value),
        2 => validateBundleV2(value),
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
    _ = try c.exactFields(value, if (compatibility == .tiny_qcow2_derived_vhd_v2)
        &.{ "schema", "version", "profile", "authority", "source", "members" }
    else
        &.{ "schema", "version", "authority", "source", "members" });
    try literal(initial, "schema", "uk.wamr.public-source-bundle");
    try literal(initial, "authority", profile.authority);
    try validatePublicContext(initial.get("source") orelse return error.MissingField);
    try validateMemberMap(initial.get("members") orelse return error.MissingField, compatibility);
    return compatibility;
}

pub fn validatePublicSourceTransportV2(value: std.json.Value) !void {
    const fields = try c.exactFields(value, &.{
        "schema",          "version",     "repository",       "run_id",      "run_attempt",
        "source_revision", "source_tree", "inner_zip_sha256", "artifact_id", "container_digest",
    });
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
    const fields = try c.exactFields(value, &.{
        "schema",          "version",           "purpose",      "authority",       "approval",    "attempt_id",
        "subscription",    "location",          "prefix",       "vm_size",         "serial_mode", "runtime_seconds",
        "cleanup_seconds", "operation_seconds", "poll_seconds", "source_revision", "source_tree", "identity",
        "os_vhd",          "bundle",
    });
    try literal(fields, "schema", "uk.wamr.direct-compute");
    try literal(fields, "authority", profile.authority);
    const version = try integer(u8, fields, "version");
    const compatibility = try profile.compatibility(version, if (version == 2) profile.current_profile else null);
    try literal(fields, "purpose", if (compatibility == .frozen_tiny_v1) "tiny-aot-two-boot" else profile.current_profile);
    try validateApproval(fields.get("approval").?);
    try uuid(try string(fields, "attempt_id"));
    _ = try string(fields, "subscription");
    try literal(fields, "location", "northeurope");
    try boundedName(try string(fields, "prefix"));
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
    const fields = try c.exactFields(value, &.{
        "schema", "version", "profile",       "authority", "source_revision", "source_tree",
        "run",    "lineage", "public_bundle", "transport",
    });
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

fn validateBundleV1(value: std.json.Value) !profile.Compatibility {
    const fields = try c.exactFields(value, &.{
        "schema",   "version",   "authority", "source_revision", "source_tree",
        "identity", "artifacts", "boots",     "evidence",
    });
    try commonBundle(fields, .frozen_tiny_v1);
    return .frozen_tiny_v1;
}

fn validateBundleV2(value: std.json.Value) !profile.Compatibility {
    const fields = try c.exactFields(value, &.{
        "schema", "version",  "profile", "authority", "source_revision", "source_tree",
        "run",    "identity", "lineage", "artifacts", "boots",           "evidence",
    });
    try commonBundle(fields, .tiny_qcow2_derived_vhd_v2);
    try literal(fields, "profile", profile.current_profile);
    try validateRun(fields.get("run").?);
    try validateLineage(fields.get("lineage").?, fields.get("artifacts").?);
    return .tiny_qcow2_derived_vhd_v2;
}

fn commonBundle(fields: std.json.ObjectMap, compatibility: profile.Compatibility) !void {
    try literal(fields, "schema", "uk.wamr.local-image-handoff");
    if (try integer(u8, fields, "version") != compatibility.version()) return error.UnsupportedVersion;
    try literal(fields, "authority", profile.authority);
    try hex(try string(fields, "source_revision"), 40);
    try hex(try string(fields, "source_tree"), 40);
    try validateIdentity(fields.get("identity").?);
    try validateArtifacts(fields.get("artifacts").?, compatibility);
    try validateBoots(fields.get("boots").?, compatibility);
    try validateEvidence(fields.get("evidence").?, compatibility);
}

fn validateArtifacts(value: std.json.Value, compatibility: profile.Compatibility) !void {
    const items = try array(value);
    const names = layout.artifactNames(compatibility);
    if (items.len != names.len) return error.InvalidArtifacts;
    for (items, names) |item, name| try validateArtifact(item, layout.artifactLimit(name));
}

fn validateBoots(value: std.json.Value, compatibility: profile.Compatibility) !void {
    const items = try array(value);
    const modes = profile.modes(compatibility);
    if (items.len != modes.len) return error.InvalidBoots;
    for (items, modes) |item, mode| {
        const fields = try c.exactFields(item, &.{ "mode", "serial", "request", "report", "compute" });
        try literal(fields, "mode", @tagName(mode));
        try validateArtifact(fields.get("serial").?, layout.max_serial_bytes);
        inline for (.{ "request", "report", "compute" }) |name|
            try validateArtifact(fields.get(name).?, layout.max_json_bytes);
    }
}

fn validateEvidence(value: std.json.Value, compatibility: profile.Compatibility) !void {
    const items = try array(value);
    if (items.len != layout.evidenceNames(compatibility).len) return error.InvalidEvidence;
    for (items) |item| try validateArtifact(item, layout.max_json_bytes);
}

fn validateMemberMap(value: std.json.Value, compatibility: profile.Compatibility) !void {
    const members = try object(value);
    if (members.count() != layout.selectedMemberCount(compatibility)) return error.InvalidMembers;
    for (members.keys(), members.values()) |name, item| {
        if (!layout.containsSelectedPublicMember(compatibility, name)) return error.UnexpectedMember;
        const fields = try c.exactFields(item, &.{ "size", "sha256" });
        const size = try integer(u64, fields, "size");
        if (size == 0 or size > try layout.memberLimit(name)) return error.InvalidArtifact;
        _ = try c.parseSha256(try string(fields, "sha256"));
    }
}

fn validateIdentity(value: std.json.Value) !void {
    const fields = try c.exactFields(value, &.{
        "wamr_revision",  "wasm_sha256",     "cwasm_sha256",
        "runtime_sha256", "compiler_sha256", "config_sha256",
    });
    try hex(try string(fields, "wamr_revision"), 40);
    inline for (.{ "wasm_sha256", "cwasm_sha256", "runtime_sha256", "compiler_sha256", "config_sha256" }) |name|
        _ = try c.parseSha256(try string(fields, name));
}

fn validateRun(value: std.json.Value) !void {
    const fields = try c.exactFields(value, &.{ "repository", "run_id", "run_attempt" });
    try literal(fields, "repository", profile.repository);
    try decimalString(try string(fields, "run_id"));
    try decimalString(try string(fields, "run_attempt"));
}

fn validateLineage(value: std.json.Value, artifacts: ?std.json.Value) !void {
    const fields = try c.exactFields(value, &.{
        "raw_sha256",                  "accepted_qcow2_sha256",   "derived_vhd_sha256",
        "qcow2_finalization_sha256",   "qcow2_acceptance_sha256", "fixed_vhd_derivation_gate_sha256",
        "fixed_vhd_derivation_sha256", "final_inspection_sha256",
    });
    inline for (.{
        "raw_sha256",                  "accepted_qcow2_sha256",   "derived_vhd_sha256",
        "qcow2_finalization_sha256",   "qcow2_acceptance_sha256", "fixed_vhd_derivation_gate_sha256",
        "fixed_vhd_derivation_sha256", "final_inspection_sha256",
    }) |name| _ = try c.parseSha256(try string(fields, name));
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
    const fields = try c.exactFields(value, &.{
        "repository", "run_id", "run_attempt", "source_revision", "source_tree", "wamr_revision",
    });
    try literal(fields, "repository", profile.repository);
    try decimalString(try string(fields, "run_id"));
    try decimalString(try string(fields, "run_attempt"));
    try hex(try string(fields, "source_revision"), 40);
    try hex(try string(fields, "source_tree"), 40);
    try literal(fields, "wamr_revision", profile.wamr_revision);
}

fn validateApproval(value: std.json.Value) !void {
    const fields = try c.exactFields(value, &.{
        "direct_specialized_gen2",               "os_only_private",      "two_boots_only", "cleanup_owned_group",
        "exact_image_and_local_bundle_reviewed", "fresh_final_approval", "approved_unix",  "expires_unix",
    });
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
    const fields = try c.exactFields(value, &.{ "path", "sha256", "size" });
    const path = try string(fields, "path");
    if (path.len == 0 or path.len > 4096) return error.InvalidPath;
    _ = try c.parseSha256(try string(fields, "sha256"));
    const size = try integer(u64, fields, "size");
    if (size == 0 or size > maximum) return error.InvalidArtifact;
}

fn artifactSha(artifacts: std.json.Value, name: []const u8) ![]const u8 {
    const items = try array(artifacts);
    for (layout.artifact_names_v2, 0..) |candidate, i| {
        if (!std.mem.eql(u8, candidate, name)) continue;
        const fields = try c.exactFields(items[i], &.{ "path", "sha256", "size" });
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
