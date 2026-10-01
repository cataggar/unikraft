// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const c = core.contracts;
const handoff = @import("root.zig");
const contracts = handoff.contracts;
const layout = handoff.layout;
const profile = handoff.profile;

const golden = @embedFile("goldens/contracts-profile-layout.json");
const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const rev = "0123456789012345678901234567890123456789";
const uuid = "00000000-0000-4000-8000-000000000001";

const golden_fields = struct {
    pub const root = [_][]const u8{ "schema", "schema_version", "authority", "canonicalization", "limits", "profiles", "historical_sources", "tables", "schemas" };
    pub const limits = [_][]const u8{ "max_members", "max_total_bytes", "json_bytes", "serial_bytes", "config_bytes", "large_artifact_bytes", "v1_zip_members", "v2_zip_members" };
    pub const profile = [_][]const u8{ "version", "compatibility", "profile", "production", "workload", "modes", "artifact_count", "evidence_count", "boot_member_count", "zip_member_count" };
    pub const historical_sources = [_][]const u8{ "legacy_v1_without_external_archive_digest", "pre_supervisor_with_external_archive_digest" };
    pub const source_identity = [_][]const u8{ "revision", "tree" };
    pub const tables = [_][]const u8{ "artifact_names_v1", "artifact_names_v2", "artifact_limits_v1", "artifact_limits_v2", "boot_keys", "evidence_v1", "evidence_v2", "zip_members_v1", "zip_members_v2" };
    pub const artifact_limit = [_][]const u8{ "name", "max_bytes" };
    pub const schemas = [_][]const u8{ "artifact", "manifest_member", "boot", "identity", "local_image_handoff_v1", "local_image_handoff_v2", "public_source_manifest_v1", "public_source_manifest_v2", "public_source_transport_v2", "direct_compute_candidate", "direct_compute_candidate_v1", "direct_compute_candidate_v2", "direct_compute_admission_v2", "run", "lineage", "public_context", "approval" };
};

test "Python contract golden is canonical and matches native literal tables" {
    var document = try contracts.parseCanonical(std.testing.allocator, golden);
    defer document.deinit();
    try expectGolden(document.value());
}

test "Python contract golden refuses unknown object fields" {
    const a = std.testing.allocator;
    try expectGoldenMutationRefused(a, "{\"authority\"", "{\"_extra\":0,\"authority\"");
    try expectGoldenMutationRefused(a, "\"limits\":{", "\"limits\":{\"_extra\":0,");
    try expectGoldenMutationRefused(a, "{\"artifact_count\":17", "{\"_extra\":0,\"artifact_count\":17");
    try expectGoldenMutationRefused(a, "{\"artifact_count\":26", "{\"_extra\":0,\"artifact_count\":26");
    try expectGoldenMutationRefused(a, "\"historical_sources\":{", "\"historical_sources\":{\"_extra\":0,");
    try expectGoldenMutationRefused(a, "\"tables\":{", "\"tables\":{\"_extra\":0,");
    try expectGoldenMutationRefused(a, "\"schemas\":{", "\"schemas\":{\"_extra\":0,");
}

fn expectGolden(value: std.json.Value) !void {
    const root = try c.exactFields(value, &golden_fields.root);
    try expectLiteral(root, "schema", "uk.wamr.handoff-contract-golden");
    try expectInt(root, "schema_version", @as(u8, 1));
    try expectLiteral(root, "authority", profile.authority);
    try expectLiteral(root, "canonicalization", profile.canonicalization);
    try expectLimits(root.get("limits") orelse return error.MissingGolden);
    try expectProfiles(root.get("profiles") orelse return error.MissingGolden);
    try expectHistoricalSources(root.get("historical_sources") orelse return error.MissingGolden);
    const tables = try c.exactFields(root.get("tables") orelse return error.MissingGolden, &golden_fields.tables);
    try expectBootKeys(tables, "boot_keys");
    try expectStringArray(tables, "artifact_names_v1", &layout.artifact_names_v1);
    try expectStringArray(tables, "artifact_names_v2", &layout.artifact_names_v2);
    try expectArtifactLimits(tables, "artifact_limits_v1", .frozen_tiny_v1);
    try expectArtifactLimits(tables, "artifact_limits_v2", .tiny_qcow2_derived_vhd_v2);
    try expectStringArray(tables, "evidence_v1", &layout.evidence_v1);
    try expectStringArray(tables, "evidence_v2", &layout.evidence_v2);
    try expectGeneratedMembers(tables, "zip_members_v1", .frozen_tiny_v1);
    try expectGeneratedMembers(tables, "zip_members_v2", .tiny_qcow2_derived_vhd_v2);
    try std.testing.expectEqual(@as(usize, 17), layout.artifact_names_v1.len);
    try std.testing.expectEqual(@as(usize, 20), layout.evidence_v1.len);
    try std.testing.expectEqual(@as(usize, 16), layout.bootMemberCount(.frozen_tiny_v1));
    try std.testing.expectEqual(@as(usize, 55), layout.expectedZipMemberCount(.frozen_tiny_v1));
    try std.testing.expectEqual(@as(usize, 26), layout.artifact_names_v2.len);
    try std.testing.expectEqual(@as(usize, 33), layout.evidence_v2.len);
    try std.testing.expectEqual(@as(usize, 24), layout.bootMemberCount(.tiny_qcow2_derived_vhd_v2));
    try std.testing.expectEqual(@as(usize, 85), layout.expectedZipMemberCount(.tiny_qcow2_derived_vhd_v2));
    try std.testing.expect(layout.expectedZipMemberCount(.tiny_qcow2_derived_vhd_v2) <= layout.max_members);
    const schemas = try c.exactFields(root.get("schemas") orelse return error.MissingGolden, &golden_fields.schemas);
    try expectStringArray(schemas, "artifact", &contracts.schema_fields.artifact);
    try expectStringArray(schemas, "manifest_member", &contracts.schema_fields.manifest_member);
    try expectStringArray(schemas, "boot", &contracts.schema_fields.boot);
    try expectStringArray(schemas, "identity", &contracts.schema_fields.identity);
    try expectStringArray(schemas, "local_image_handoff_v1", &contracts.schema_fields.local_image_handoff_v1);
    try expectStringArray(schemas, "local_image_handoff_v2", &contracts.schema_fields.local_image_handoff_v2);
    try expectStringArray(schemas, "public_source_manifest_v1", &contracts.schema_fields.public_source_manifest_v1);
    try expectStringArray(schemas, "public_source_manifest_v2", &contracts.schema_fields.public_source_manifest_v2);
    try expectStringArray(schemas, "public_source_transport_v2", &contracts.schema_fields.public_source_transport_v2);
    try expectStringArray(schemas, "direct_compute_candidate", &contracts.schema_fields.direct_compute_candidate);
    try expectStringArray(schemas, "direct_compute_candidate_v1", &contracts.schema_fields.direct_compute_candidate);
    try expectStringArray(schemas, "direct_compute_candidate_v2", &contracts.schema_fields.direct_compute_candidate);
    try expectStringArray(schemas, "direct_compute_admission_v2", &contracts.schema_fields.direct_compute_admission_v2);
    try expectStringArray(schemas, "run", &contracts.schema_fields.run);
    try expectStringArray(schemas, "lineage", &contracts.schema_fields.lineage);
    try expectStringArray(schemas, "public_context", &contracts.schema_fields.public_context);
    try expectStringArray(schemas, "approval", &contracts.schema_fields.approval);
}

test "closed external handoff, manifest, transport, candidate and admission contracts" {
    const a = std.testing.allocator;
    for ([_]profile.Compatibility{ .frozen_tiny_v1, .tiny_qcow2_derived_vhd_v2 }) |compatibility| {
        const bundle = try sampleBundle(a, compatibility);
        defer a.free(bundle);
        var bundle_doc = try c.Document.parse(a, bundle, contracts.json_limits);
        defer bundle_doc.deinit();
        try std.testing.expectEqual(compatibility, try contracts.validateLocalImageHandoff(bundle_doc.value()));

        const rooted = try sampleBundleWithRoot(a, compatibility, "/var/tmp/wamr-handoff-stage");
        defer a.free(rooted);
        var rooted_doc = try c.Document.parse(a, rooted, contracts.json_limits);
        defer rooted_doc.deinit();
        try std.testing.expectError(error.InvalidPath, contracts.validateLocalImageHandoff(rooted_doc.value()));
        try std.testing.expectEqual(compatibility, try contracts.validateLocalImageHandoffWithRoot(rooted_doc.value(), "/var/tmp/wamr-handoff-stage"));

        const manifest = try sampleManifest(a, compatibility);
        defer a.free(manifest);
        var manifest_doc = try c.Document.parse(a, manifest, contracts.json_limits);
        defer manifest_doc.deinit();
        try std.testing.expectEqual(compatibility, try contracts.validatePublicSourceManifest(manifest_doc.value()));

        const candidate = try sampleCandidate(a, compatibility);
        defer a.free(candidate);
        var candidate_doc = try c.Document.parse(a, candidate, contracts.json_limits);
        defer candidate_doc.deinit();
        try std.testing.expectEqual(compatibility, try contracts.validateDirectComputeCandidate(candidate_doc.value()));
    }

    try validateStatic(contracts.validatePublicSourceTransportV2, "{\"artifact_id\":\"1\",\"container_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"inner_zip_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"repository\":\"cataggar/unikraft\",\"run_attempt\":\"1\",\"run_id\":\"1\",\"schema\":\"uk.wamr.public-source-transport\",\"source_revision\":\"0123456789012345678901234567890123456789\",\"source_tree\":\"0123456789012345678901234567890123456789\",\"version\":2}\n");
    const admission = try sampleAdmission(a);
    defer a.free(admission);
    try validateStatic(contracts.validateDirectComputeAdmissionV2, admission);
}

test "unknown fields, versions, authority and lineage substitutions fail closed" {
    try expectRefused(contracts.validatePublicSourceTransportV2, "{\"artifact_id\":\"1\",\"container_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"extra\":0,\"inner_zip_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"repository\":\"cataggar/unikraft\",\"run_attempt\":\"1\",\"run_id\":\"1\",\"schema\":\"uk.wamr.public-source-transport\",\"source_revision\":\"0123456789012345678901234567890123456789\",\"source_tree\":\"0123456789012345678901234567890123456789\",\"version\":2}\n");
    const a = std.testing.allocator;
    const candidate = try replaceOwned(a, try sampleCandidate(a, .tiny_qcow2_derived_vhd_v2), "\"authority\":\"not_admitted\"", "\"authority\":\"approved\"");
    defer a.free(candidate);
    try expectRefused(contracts.validateDirectComputeCandidate, candidate);
    const bundle = try replaceOwned(a, try sampleBundle(a, .tiny_qcow2_derived_vhd_v2), "\"raw_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"", "\"raw_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"");
    defer a.free(bundle);
    try expectRefused(contracts.validateLocalImageHandoff, bundle);

    const bare = try replaceOwned(a, try sampleBundle(a, .frozen_tiny_v1), "\"path\":\"artifacts/efi\"", "\"path\":\"efi\"");
    defer a.free(bare);
    try expectRefused(contracts.validateLocalImageHandoff, bare);

    const swapped = try replaceOwned(a, try sampleBundle(a, .tiny_qcow2_derived_vhd_v2), "\"path\":\"evidence/boot-inputs.json\"", "\"path\":\"evidence/build-start.json\"");
    defer a.free(swapped);
    try expectRefused(contracts.validateLocalImageHandoff, swapped);

    const big = try oversizedBundle(a);
    defer a.free(big);
    try expectRefused(contracts.validateLocalImageHandoff, big);

    const big_manifest = try oversizedManifest(a);
    defer a.free(big_manifest);
    try expectRefused(contracts.validatePublicSourceManifest, big_manifest);
}

fn sampleBundle(a: std.mem.Allocator, compatibility: profile.Compatibility) ![]u8 {
    return sampleBundleWithRoot(a, compatibility, null);
}

fn sampleBundleWithRoot(a: std.mem.Allocator, compatibility: profile.Compatibility, root: ?[]const u8) ![]u8 {
    var out = std.Io.Writer.Allocating.init(a);
    defer out.deinit();
    const w = &out.writer;
    try w.print("{{\"schema\":\"uk.wamr.local-image-handoff\",\"version\":{},", .{compatibility.version()});
    if (compatibility == .tiny_qcow2_derived_vhd_v2) try w.writeAll("\"profile\":\"qcow2-derived-vhd\",");
    try w.print("\"authority\":\"not_admitted\",\"source_revision\":\"{s}\",\"source_tree\":\"{s}\",", .{ rev, rev });
    if (compatibility == .tiny_qcow2_derived_vhd_v2) try writeRun(w);
    try writeIdentityField(w);
    if (compatibility == .tiny_qcow2_derived_vhd_v2) try writeLineage(w);
    try w.writeAll("\"artifacts\":[");
    for (layout.artifactNames(compatibility), 0..) |name, i| {
        if (i != 0) try w.writeByte(',');
        try writeMemberArtifact(w, root, "artifacts", name, 1);
    }
    try w.writeAll("],\"boots\":[");
    for (profile.modes(compatibility), 0..) |mode, i| {
        if (i != 0) try w.writeByte(',');
        try w.print("{{\"mode\":\"{s}\",", .{@tagName(mode)});
        inline for (.{ "serial", "request", "report", "compute" }, 0..) |key, j| {
            if (j != 0) try w.writeByte(',');
            try w.print("\"{s}\":", .{key});
            var path_buffer: [128]u8 = undefined;
            const path = try std.fmt.bufPrint(&path_buffer, "boots/{s}/{s}", .{ @tagName(mode), key });
            try writeMemberPathArtifact(w, root, path, 1);
        }
        try w.writeByte('}');
    }
    try w.writeAll("],\"evidence\":[");
    for (layout.evidenceNames(compatibility), 0..) |name, i| {
        if (i != 0) try w.writeByte(',');
        try writeMemberArtifact(w, root, "evidence", name, 1);
    }
    try w.writeAll("]}\n");
    return out.toOwnedSlice();
}

fn sampleManifest(a: std.mem.Allocator, compatibility: profile.Compatibility) ![]u8 {
    var out = std.Io.Writer.Allocating.init(a);
    defer out.deinit();
    const w = &out.writer;
    try w.print("{{\"schema\":\"uk.wamr.public-source-bundle\",\"version\":{},", .{compatibility.version()});
    if (compatibility == .tiny_qcow2_derived_vhd_v2) try w.writeAll("\"profile\":\"qcow2-derived-vhd\",");
    try w.writeAll("\"authority\":\"not_admitted\",\"source\":{");
    try w.print("\"repository\":\"cataggar/unikraft\",\"run_id\":\"1\",\"run_attempt\":\"1\",\"source_revision\":\"{s}\",\"source_tree\":\"{s}\",\"wamr_revision\":\"{s}\"}},\"members\":{{", .{ rev, rev, profile.wamr_revision });
    const members = try generatedPublicMembers(a, compatibility);
    defer freeMembers(a, members);
    for (members[0 .. members.len - 2], 0..) |name, i| {
        if (i != 0) try w.writeByte(',');
        try w.print("\"{s}\":{{\"size\":1,\"sha256\":\"{s}\"}}", .{ name, sha });
    }
    try w.writeAll("}}\n");
    return out.toOwnedSlice();
}

fn sampleCandidate(a: std.mem.Allocator, compatibility: profile.Compatibility) ![]u8 {
    var out = std.Io.Writer.Allocating.init(a);
    defer out.deinit();
    const w = &out.writer;
    try w.print("{{\"schema\":\"uk.wamr.direct-compute\",\"version\":{},\"purpose\":\"{s}\",\"authority\":\"not_admitted\",", .{ compatibility.version(), if (compatibility == .frozen_tiny_v1) "tiny-aot-two-boot" else profile.current_profile });
    try w.writeAll("\"approval\":{\"direct_specialized_gen2\":false,\"os_only_private\":false,\"two_boots_only\":false,\"cleanup_owned_group\":false,\"exact_image_and_local_bundle_reviewed\":false,\"fresh_final_approval\":false,\"approved_unix\":0,\"expires_unix\":0},");
    try w.print("\"attempt_id\":\"{s}\",\"subscription\":\"{s}\",\"location\":\"northeurope\",\"prefix\":\"{s}\",\"vm_size\":\"Standard_D2s_v5\",\"serial_mode\":\"azure_cumulative\",\"runtime_seconds\":3600,\"cleanup_seconds\":1800,\"operation_seconds\":600,\"poll_seconds\":10,\"source_revision\":\"{s}\",\"source_tree\":\"{s}\",", .{
        uuid,
        if (compatibility == .frozen_tiny_v1) "FINAL-APPROVED-SUBSCRIPTION-UUID" else uuid,
        if (compatibility == .frozen_tiny_v1) "FINAL-APPROVED-FRESH-NAME" else "not-admitted-candidate",
        rev,
        rev,
    });
    try writeIdentityField(w);
    try w.writeAll("\"os_vhd\":");
    try writeArtifact(w, "artifacts/vhd", 1);
    try w.writeAll(",\"bundle\":");
    try writeArtifact(w, "bundle.json", 1);
    try w.writeAll("}\n");
    return out.toOwnedSlice();
}

fn sampleAdmission(a: std.mem.Allocator) ![]u8 {
    var out = std.Io.Writer.Allocating.init(a);
    defer out.deinit();
    const w = &out.writer;
    try w.print("{{\"schema\":\"uk.wamr.direct-compute-admission\",\"version\":2,\"profile\":\"qcow2-derived-vhd\",\"authority\":\"not_admitted\",\"source_revision\":\"{s}\",\"source_tree\":\"{s}\",", .{ rev, rev });
    try writeRun(w);
    try writeLineage(w);
    try w.writeAll("\"public_bundle\":");
    try writeArtifact(w, "bundle.json", 1);
    try w.writeAll(",\"transport\":");
    try writeArtifact(w, "transport.json", 1);
    try w.writeAll("}\n");
    return out.toOwnedSlice();
}

fn writeRun(w: *std.Io.Writer) !void {
    try w.writeAll("\"run\":{\"repository\":\"cataggar/unikraft\",\"run_id\":\"1\",\"run_attempt\":\"1\"},");
}

fn writeIdentityField(w: *std.Io.Writer) !void {
    try w.print("\"identity\":{{\"wamr_revision\":\"{s}\",\"wasm_sha256\":\"{s}\",\"cwasm_sha256\":\"{s}\",\"runtime_sha256\":\"{s}\",\"compiler_sha256\":\"{s}\",\"config_sha256\":\"{s}\"}},", .{ profile.wamr_revision, sha, sha, sha, sha, sha });
}

fn writeLineage(w: *std.Io.Writer) !void {
    try w.print("\"lineage\":{{\"raw_sha256\":\"{s}\",\"accepted_qcow2_sha256\":\"{s}\",\"derived_vhd_sha256\":\"{s}\",\"qcow2_finalization_sha256\":\"{s}\",\"qcow2_acceptance_sha256\":\"{s}\",\"fixed_vhd_derivation_sha256\":\"{s}\",\"fixed_vhd_derivation_gate_sha256\":\"{s}\",\"final_inspection_sha256\":\"{s}\"}},", .{ sha, sha, sha, sha, sha, sha, sha, sha });
}

fn writeMemberArtifact(w: *std.Io.Writer, root: ?[]const u8, prefix: []const u8, name: []const u8, size: u64) !void {
    var path_buffer: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "{s}/{s}", .{ prefix, name });
    try writeMemberPathArtifact(w, root, path, size);
}

fn writeMemberPathArtifact(w: *std.Io.Writer, root: ?[]const u8, member: []const u8, size: u64) !void {
    if (root) |base| {
        if (std.mem.eql(u8, base, "/"))
            try w.print("{{\"path\":\"/{s}\",\"size\":{},\"sha256\":\"{s}\"}}", .{ member, size, sha })
        else
            try w.print("{{\"path\":\"{s}/{s}\",\"size\":{},\"sha256\":\"{s}\"}}", .{ base, member, size, sha });
    } else {
        try writeArtifact(w, member, size);
    }
}

fn writeArtifact(w: *std.Io.Writer, path: []const u8, size: u64) !void {
    try w.print("{{\"path\":\"{s}\",\"size\":{},\"sha256\":\"{s}\"}}", .{ path, size, sha });
}

fn validateStatic(comptime f: anytype, bytes: []const u8) !void {
    var document = try c.Document.parse(std.testing.allocator, bytes, contracts.json_limits);
    defer document.deinit();
    try f(document.value());
}

fn expectRefused(comptime f: anytype, bytes: []const u8) !void {
    var document = c.Document.parse(std.testing.allocator, bytes, contracts.json_limits) catch return;
    defer document.deinit();
    if (f(document.value())) |_| return error.ExpectedRefusal else |_| {}
}

fn replaceOwned(a: std.mem.Allocator, source: []u8, old: []const u8, new: []const u8) ![]u8 {
    defer a.free(source);
    try std.testing.expect(std.mem.indexOf(u8, source, old) != null);
    return std.mem.replaceOwned(u8, a, source, old, new);
}

fn oversizedBundle(a: std.mem.Allocator) ![]u8 {
    const raw_big = try std.fmt.allocPrint(a, "\"path\":\"artifacts/raw\",\"size\":{},\"sha256\":\"{s}\"", .{ layout.max_large_artifact_bytes, sha });
    defer a.free(raw_big);
    const qcow2_big = try std.fmt.allocPrint(a, "\"path\":\"artifacts/qcow2\",\"size\":{},\"sha256\":\"{s}\"", .{ layout.max_large_artifact_bytes, sha });
    defer a.free(qcow2_big);
    const first = try replaceOwned(a, try sampleBundle(a, .tiny_qcow2_derived_vhd_v2), "\"path\":\"artifacts/raw\",\"size\":1,\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"", raw_big);
    return replaceOwned(a, first, "\"path\":\"artifacts/qcow2\",\"size\":1,\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"", qcow2_big);
}

fn oversizedManifest(a: std.mem.Allocator) ![]u8 {
    const raw_big = try std.fmt.allocPrint(a, "\"artifacts/raw\":{{\"size\":{},\"sha256\":\"{s}\"}}", .{ layout.max_large_artifact_bytes, sha });
    defer a.free(raw_big);
    const qcow2_big = try std.fmt.allocPrint(a, "\"artifacts/qcow2\":{{\"size\":{},\"sha256\":\"{s}\"}}", .{ layout.max_large_artifact_bytes, sha });
    defer a.free(qcow2_big);
    const first = try replaceOwned(a, try sampleManifest(a, .tiny_qcow2_derived_vhd_v2), "\"artifacts/raw\":{\"size\":1,\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}", raw_big);
    return replaceOwned(a, first, "\"artifacts/qcow2\":{\"size\":1,\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}", qcow2_big);
}

fn expectStringArray(map: std.json.ObjectMap, key: []const u8, expected: []const []const u8) !void {
    const items = (map.get(key) orelse return error.MissingGolden).array.items;
    try std.testing.expectEqual(expected.len, items.len);
    for (items, expected) |item, name| try std.testing.expectEqualStrings(name, try c.string(item));
}

fn expectArtifactLimits(map: std.json.ObjectMap, key: []const u8, compatibility: profile.Compatibility) !void {
    const items = (map.get(key) orelse return error.MissingGolden).array.items;
    const names = layout.artifactNames(compatibility);
    try std.testing.expectEqual(names.len, items.len);
    for (items, names) |item, name| {
        const object_map = try c.exactFields(item, &golden_fields.artifact_limit);
        try expectLiteral(object_map, "name", name);
        try expectInt(object_map, "max_bytes", layout.artifactLimit(name));
    }
}

fn expectGeneratedMembers(map: std.json.ObjectMap, key: []const u8, compatibility: profile.Compatibility) !void {
    const expected = try generatedPublicMembers(std.testing.allocator, compatibility);
    defer freeMembers(std.testing.allocator, expected);
    try expectStringArray(map, key, expected);
}

fn expectLimits(value: std.json.Value) !void {
    const limits = try c.exactFields(value, &golden_fields.limits);
    try expectInt(limits, "max_members", layout.max_members);
    try expectInt(limits, "max_total_bytes", layout.max_total_bytes);
    try expectInt(limits, "json_bytes", layout.max_json_bytes);
    try expectInt(limits, "serial_bytes", layout.max_serial_bytes);
    try expectInt(limits, "config_bytes", layout.max_config_bytes);
    try expectInt(limits, "large_artifact_bytes", layout.max_large_artifact_bytes);
    try expectInt(limits, "v1_zip_members", layout.v1_zip_member_count);
    try expectInt(limits, "v2_zip_members", layout.v2_zip_member_count);
}

fn expectProfiles(value: std.json.Value) !void {
    const items = value.array.items;
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try expectProfile(items[0].object, .frozen_tiny_v1, "tiny-v1", false);
    try expectProfile(items[1].object, .tiny_qcow2_derived_vhd_v2, "tiny-v2", true);
}

fn expectProfile(map: std.json.ObjectMap, compatibility: profile.Compatibility, name: []const u8, production: bool) !void {
    _ = try c.exactFields(.{ .object = map }, &golden_fields.profile);
    try expectInt(map, "version", compatibility.version());
    try expectLiteral(map, "compatibility", name);
    if (profile.profileName(compatibility)) |profile_name|
        try expectLiteral(map, "profile", profile_name)
    else
        try std.testing.expect((map.get("profile") orelse return error.MissingGolden) == .null);
    try std.testing.expectEqual(production, (map.get("production") orelse return error.MissingGolden).bool);
    try expectLiteral(map, "workload", profile.workload);
    try expectModeArray(map, "modes", compatibility);
    try expectInt(map, "artifact_count", layout.artifactNames(compatibility).len);
    try expectInt(map, "evidence_count", layout.evidenceNames(compatibility).len);
    try expectInt(map, "boot_member_count", layout.bootMemberCount(compatibility));
    try expectInt(map, "zip_member_count", layout.expectedZipMemberCount(compatibility));
}

fn expectHistoricalSources(value: std.json.Value) !void {
    const sources = try c.exactFields(value, &golden_fields.historical_sources);
    try expectSourceArray(sources, "legacy_v1_without_external_archive_digest", &profile.legacy_v1_without_external_archive_digest);
    try expectSourceArray(sources, "pre_supervisor_with_external_archive_digest", &profile.pre_supervisor_with_external_archive_digest);
}

fn expectSourceArray(map: std.json.ObjectMap, key: []const u8, expected: []const profile.SourceIdentity) !void {
    const items = (map.get(key) orelse return error.MissingGolden).array.items;
    try std.testing.expectEqual(expected.len, items.len);
    for (items, expected) |item, source| {
        const object_map = try c.exactFields(item, &golden_fields.source_identity);
        try expectLiteral(object_map, "revision", source.revision);
        try expectLiteral(object_map, "tree", source.tree);
    }
}

fn expectGoldenMutationRefused(a: std.mem.Allocator, old: []const u8, new: []const u8) !void {
    const mutated = try replaceOwned(a, try a.dupe(u8, golden), old, new);
    defer a.free(mutated);
    var document = try c.Document.parse(a, mutated, contracts.json_limits);
    defer document.deinit();
    if (expectGolden(document.value())) |_| return error.ExpectedRefusal else |_| {}
}

fn expectBootKeys(map: std.json.ObjectMap, key: []const u8) !void {
    const items = (map.get(key) orelse return error.MissingGolden).array.items;
    try std.testing.expectEqual(layout.boot_keys.len, items.len);
    for (items, layout.boot_keys) |item, boot_key| try std.testing.expectEqualStrings(@tagName(boot_key), try c.string(item));
}

fn expectModeArray(map: std.json.ObjectMap, key: []const u8, compatibility: profile.Compatibility) !void {
    const items = (map.get(key) orelse return error.MissingGolden).array.items;
    const modes = profile.modes(compatibility);
    try std.testing.expectEqual(modes.len, items.len);
    for (items, modes) |item, mode| try std.testing.expectEqualStrings(@tagName(mode), try c.string(item));
}

fn expectLiteral(map: std.json.ObjectMap, key: []const u8, expected: []const u8) !void {
    try std.testing.expectEqualStrings(expected, try c.string(map.get(key) orelse return error.MissingGolden));
}

fn expectInt(map: std.json.ObjectMap, key: []const u8, expected: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(expected), expected), try c.integer(@TypeOf(expected), map.get(key) orelse return error.MissingGolden));
}

fn generatedPublicMembers(a: std.mem.Allocator, compatibility: profile.Compatibility) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |item| a.free(item);
        list.deinit(a);
    }
    for (layout.artifactNames(compatibility)) |name|
        try list.append(a, try std.fmt.allocPrint(a, "artifacts/{s}", .{name}));
    for (profile.modes(compatibility)) |mode| {
        inline for (.{ "serial", "request", "report", "compute" }) |key|
            try list.append(a, try std.fmt.allocPrint(a, "boots/{s}/{s}", .{ @tagName(mode), key }));
    }
    for (layout.evidenceNames(compatibility)) |name|
        try list.append(a, try std.fmt.allocPrint(a, "evidence/{s}", .{name}));
    std.mem.sort([]const u8, list.items, {}, struct {
        fn less(_: void, lhs: []const u8, rhs: []const u8) bool {
            return std.mem.lessThan(u8, lhs, rhs);
        }
    }.less);
    try list.append(a, try a.dupe(u8, "bundle.json"));
    try list.append(a, try a.dupe(u8, "public-source.json"));
    return list.toOwnedSlice(a);
}

fn freeMembers(a: std.mem.Allocator, members: []const []const u8) void {
    for (members) |member| a.free(member);
    a.free(members);
}
