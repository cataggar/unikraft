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

test "Python contract golden is canonical and matches native literal tables" {
    var document = try contracts.parseCanonical(std.testing.allocator, golden);
    defer document.deinit();
    const root = document.value().object;
    try expectLiteral(root, "schema", "uk.wamr.handoff-contract-golden");
    try expectLiteral(root, "authority", profile.authority);
    try expectLiteral(root, "canonicalization", profile.canonicalization);
    const tables = root.get("tables").?.object;
    try expectStringArray(tables, "artifact_names_v1", &layout.artifact_names_v1);
    try expectStringArray(tables, "artifact_names_v2", &layout.artifact_names_v2);
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
}

test "closed external handoff, manifest, transport, candidate and admission contracts" {
    const a = std.testing.allocator;
    for ([_]profile.Compatibility{ .frozen_tiny_v1, .tiny_qcow2_derived_vhd_v2 }) |compatibility| {
        const bundle = try sampleBundle(a, compatibility);
        defer a.free(bundle);
        var bundle_doc = try c.Document.parse(a, bundle, contracts.json_limits);
        defer bundle_doc.deinit();
        try std.testing.expectEqual(compatibility, try contracts.validateLocalImageHandoff(bundle_doc.value()));

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
}

fn sampleBundle(a: std.mem.Allocator, compatibility: profile.Compatibility) ![]u8 {
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
        try writeArtifact(w, name, 1);
    }
    try w.writeAll("],\"boots\":[");
    for (profile.modes(compatibility), 0..) |mode, i| {
        if (i != 0) try w.writeByte(',');
        try w.print("{{\"mode\":\"{s}\",", .{@tagName(mode)});
        inline for (.{ "serial", "request", "report", "compute" }, 0..) |key, j| {
            if (j != 0) try w.writeByte(',');
            try w.print("\"{s}\":", .{key});
            try writeArtifact(w, key, 1);
        }
        try w.writeByte('}');
    }
    try w.writeAll("],\"evidence\":[");
    for (layout.evidenceNames(compatibility), 0..) |name, i| {
        if (i != 0) try w.writeByte(',');
        try writeArtifact(w, name, 1);
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
    try w.print("\"attempt_id\":\"{s}\",\"subscription\":\"{s}\",\"location\":\"northeurope\",\"prefix\":\"not-admitted-candidate\",\"vm_size\":\"Standard_D2s_v5\",\"serial_mode\":\"azure_cumulative\",\"runtime_seconds\":3600,\"cleanup_seconds\":1800,\"operation_seconds\":600,\"poll_seconds\":10,\"source_revision\":\"{s}\",\"source_tree\":\"{s}\",", .{ uuid, uuid, rev, rev });
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
    try w.print("\"lineage\":{{\"raw_sha256\":\"{s}\",\"accepted_qcow2_sha256\":\"{s}\",\"derived_vhd_sha256\":\"{s}\",\"qcow2_finalization_sha256\":\"{s}\",\"qcow2_acceptance_sha256\":\"{s}\",\"fixed_vhd_derivation_gate_sha256\":\"{s}\",\"fixed_vhd_derivation_sha256\":\"{s}\",\"final_inspection_sha256\":\"{s}\"}},", .{ sha, sha, sha, sha, sha, sha, sha, sha });
}

fn writeArtifact(w: *std.Io.Writer, path: []const u8, size: u64) !void {
    try w.print("{{\"path\":\"{s}\",\"sha256\":\"{s}\",\"size\":{}}}", .{ path, sha, size });
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

fn expectStringArray(map: std.json.ObjectMap, key: []const u8, expected: []const []const u8) !void {
    const items = (map.get(key) orelse return error.MissingGolden).array.items;
    try std.testing.expectEqual(expected.len, items.len);
    for (items, expected) |item, name| try std.testing.expectEqualStrings(name, try c.string(item));
}

fn expectGeneratedMembers(map: std.json.ObjectMap, key: []const u8, compatibility: profile.Compatibility) !void {
    const expected = try generatedPublicMembers(std.testing.allocator, compatibility);
    defer freeMembers(std.testing.allocator, expected);
    try expectStringArray(map, key, expected);
}

fn expectLiteral(map: std.json.ObjectMap, key: []const u8, expected: []const u8) !void {
    try std.testing.expectEqualStrings(expected, try c.string(map.get(key) orelse return error.MissingGolden));
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
