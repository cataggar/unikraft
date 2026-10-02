// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const controller = @import("wamr_controller");
const c = core.contracts;
const handoff = @import("root.zig");
const contracts = handoff.contracts;
const layout = handoff.layout;
const native_export = handoff.export_state;
const profile = handoff.profile;
const retained_copy = handoff.retained_copy;
const zip = handoff.zip;
const test_options = @import("test_options");

const golden = @embedFile("goldens/contracts-profile-layout.json");
const zip_multi_golden = @embedFile("goldens/zip-stored-multi.zip");
const zip_empty_golden = @embedFile("goldens/zip-stored-empty.zip");
const zip_pack_v1_golden = @embedFile("goldens/zip-pack-v1.zip");
const zip_pack_v2_golden = @embedFile("goldens/zip-pack-v2.zip");
const zip_pack_v1_bundle = @embedFile("goldens/zip-pack-v1-bundle.json");
const zip_pack_v1_public_source = @embedFile("goldens/zip-pack-v1-public-source.json");
const zip_pack_v2_bundle = @embedFile("goldens/zip-pack-v2-bundle.json");
const zip_pack_v2_public_source = @embedFile("goldens/zip-pack-v2-public-source.json");
const root_bound_v1_golden = @embedFile("goldens/root-bound-v1.json");
const root_bound_v2_golden = @embedFile("goldens/root-bound-v2.json");
const export_bundle_v2_golden = @embedFile("goldens/export-bundle-v2.json");
const root_bound_stage = "/opt/wamr-handoff-golden-stage";
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

test "Python ZIP32 goldens are byte-identical and accepted by strict native codec" {
    const multi_entries = [_]zip.SliceEntry{
        .{ .name = "alpha.txt", .bytes = "alpha\n", .limit = 1024 },
        .{ .name = "dir/nested.bin", .bytes = "\x00stored bytes\n", .limit = 1024 },
        .{ .name = "omega.dat", .bytes = "last member", .limit = 1024 },
    };
    try expectZipGolden(zip_multi_golden, &multi_entries);

    const empty_entries = [_]zip.SliceEntry{
        .{ .name = "empty.bin", .bytes = "", .limit = 1024 },
        .{ .name = "nonempty.txt", .bytes = "non-empty\n", .limit = 1024 },
    };
    try expectZipGolden(zip_empty_golden, &empty_entries);
}

test "real Python pack goldens are byte-identical and accepted by strict native codec" {
    try expectPackGolden(.frozen_tiny_v1, zip_pack_v1_golden, zip_pack_v1_bundle, zip_pack_v1_public_source);
    try expectPackGolden(.tiny_qcow2_derived_vhd_v2, zip_pack_v2_golden, zip_pack_v2_bundle, zip_pack_v2_public_source);
}

test "Python-written root-bound local handoff goldens validate only with their root" {
    try expectRootBoundGolden(root_bound_v1_golden, .frozen_tiny_v1);
    try expectRootBoundGolden(root_bound_v2_golden, .tiny_qcow2_derived_vhd_v2);
}

test "native v2 handoff manifest builder is byte-identical to Python export-shaped golden" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const bytes = try native_export.Test.buildRootBoundBundleV2(
        arena.allocator(),
        root_bound_stage,
        "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
    );
    try expectEqualManifest(export_bundle_v2_golden, bytes);
}

test "retained copy hashes, fsyncs and reopens a private member" {
    var fixture = try CopyFixture.init("success");
    defer fixture.deinit();
    try fixture.writeSource("input.bin", "member-bytes\n");
    var retained = try core.private_files.RetainedFile.open(std.testing.io, fixture.source_path, .private);
    defer retained.close(std.testing.io);
    var budget: retained_copy.Budget = .{};
    const copied = try retained_copy.copyRetained(
        std.testing.allocator,
        std.testing.io,
        &retained,
        fixture.output.dir,
        fixture.output_path,
        "artifacts/efi",
        layout.max_json_bytes,
        &budget,
        .{},
    );
    defer std.testing.allocator.free(copied.path);
    try std.testing.expectEqual(@as(u64, 13), copied.size);
    try std.testing.expectEqual(@as(u64, 13), budget.used);
    const observed = try fixture.readOutput("artifacts/efi", 64);
    defer std.testing.allocator.free(observed);
    try std.testing.expectEqualStrings("member-bytes\n", observed);
}

test "retained copy refuses sensitive public pattern across chunk boundary" {
    var fixture = try CopyFixture.init("sensitive");
    defer fixture.deinit();
    const pattern = "Authorization: Bearer ";
    const bytes = try std.testing.allocator.alloc(u8, 64 * 1024 + pattern.len);
    defer std.testing.allocator.free(bytes);
    @memset(bytes, 'a');
    @memcpy(bytes[64 * 1024 - 7 .. 64 * 1024], pattern[0..7]);
    @memcpy(bytes[64 * 1024 .. 64 * 1024 + pattern.len - 7], pattern[7..]);
    try fixture.writeSource("input.bin", bytes);
    var retained = try core.private_files.RetainedFile.open(std.testing.io, fixture.source_path, .private);
    defer retained.close(std.testing.io);
    var budget: retained_copy.Budget = .{};
    try std.testing.expectError(error.SensitivePattern, retained_copy.copyRetained(
        std.testing.allocator,
        std.testing.io,
        &retained,
        fixture.output.dir,
        fixture.output_path,
        "evidence/build.json",
        layout.max_large_artifact_bytes,
        &budget,
        .{ .scan = .public_bundle },
    ));
}

test "retained copy refuses budget overflow and existing output" {
    var fixture = try CopyFixture.init("budget-existing");
    defer fixture.deinit();
    try fixture.writeSource("input.bin", "12345");
    var retained = try core.private_files.RetainedFile.open(std.testing.io, fixture.source_path, .private);
    defer retained.close(std.testing.io);
    var small: retained_copy.Budget = .{ .limit = 4 };
    try std.testing.expectError(error.CopyBudgetExceeded, retained_copy.copyRetained(
        std.testing.allocator,
        std.testing.io,
        &retained,
        fixture.output.dir,
        fixture.output_path,
        "artifacts/efi",
        layout.max_json_bytes,
        &small,
        .{},
    ));
    try fixture.writeOutput("artifacts/efi", "old");
    var budget: retained_copy.Budget = .{};
    try std.testing.expectError(error.OutputExists, retained_copy.copyRetained(
        std.testing.allocator,
        std.testing.io,
        &retained,
        fixture.output.dir,
        fixture.output_path,
        "artifacts/efi",
        layout.max_json_bytes,
        &budget,
        .{},
    ));
}

test "retained copy poisons source mutation and ambiguous durability faults" {
    var fixture = try CopyFixture.init("faults");
    defer fixture.deinit();
    const bytes = try std.testing.allocator.alloc(u8, 70 * 1024);
    defer std.testing.allocator.free(bytes);
    @memset(bytes, 'm');
    try fixture.writeSource("input.bin", bytes);
    var retained = try core.private_files.RetainedFile.open(std.testing.io, fixture.source_path, .private);
    defer retained.close(std.testing.io);
    var budget: retained_copy.Budget = .{};
    try std.testing.expectError(error.FileChanged, retained_copy.copyRetained(
        std.testing.allocator,
        std.testing.io,
        &retained,
        fixture.output.dir,
        fixture.output_path,
        "artifacts/raw",
        layout.max_large_artifact_bytes,
        &budget,
        .{ .fault = .mutate_source_after_first_chunk },
    ));

    try fixture.writeSource("second.bin", "durability");
    var second = try core.private_files.RetainedFile.open(std.testing.io, fixture.second_source_path, .private);
    defer second.close(std.testing.io);
    try std.testing.expectError(error.AmbiguousWrite, retained_copy.copyRetained(
        std.testing.allocator,
        std.testing.io,
        &second,
        fixture.output.dir,
        fixture.output_path,
        "artifacts/vhd",
        layout.max_json_bytes,
        null,
        .{ .fault = .before_file_sync },
    ));
}

test "handoff manifest publish fault is poisoned before bundle is visible" {
    var fixture = try CopyFixture.init("publish-fault");
    defer fixture.deinit();
    try std.testing.expectError(error.AmbiguousWrite, native_export.Test.publishBundleForTest(
        std.testing.io,
        fixture.output.dir,
        "{}\n",
        .before_file_sync,
    ));
    const bundle_path = try std.fs.path.join(std.testing.allocator, &.{ fixture.output_path, "bundle.json" });
    defer std.testing.allocator.free(bundle_path);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.openFileAbsolute(
        std.testing.io,
        bundle_path,
        .{ .mode = .read_only, .follow_symlinks = false },
    ));
}

test "export runner refuses absent runtime" {
    const outcome = native_export.run(.{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .environ = .empty,
        .runtime_path = "/missing-export-review-runtime",
        .repository_path = "/missing-export-review-repository",
        .output_path = "/missing-export-review-output",
    });
    try std.testing.expect(outcome == .refused);
}

fn descriptorCount() !usize {
    const proc = try std.Io.Dir.openDirAbsolute(std.testing.io, "/proc/self/fd", .{ .iterate = true });
    defer proc.close(std.testing.io);
    var iterator = proc.iterate();
    var count: usize = 0;
    while (try iterator.next(std.testing.io)) |_| count += 1;
    return count;
}

test "export accepted-record refusal releases runtime descriptor" {
    var fixture = try CopyFixture.init("runtime-refusal");
    defer fixture.deinit();
    const before = try descriptorCount();
    const outcome = native_export.run(.{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .environ = .empty,
        .runtime_path = std.fs.path.dirname(fixture.source_path).?,
        .repository_path = std.fs.path.dirname(fixture.source_path).?,
        .output_path = fixture.output_path,
    });
    try std.testing.expect(outcome == .refused);
    try std.testing.expectEqual(before, try descriptorCount());
}

test "strict scan refuses binary pattern ending in one-byte final chunk" {
    var fixture = try CopyFixture.init("sensitive-final-byte");
    defer fixture.deinit();
    const pattern = "Authorization: Bearer ";
    const bytes = try std.testing.allocator.alloc(u8, 64 * 1024 + 1);
    defer std.testing.allocator.free(bytes);
    @memset(bytes, 0xff);
    @memcpy(bytes[bytes.len - pattern.len ..], pattern);
    try fixture.writeSource("input.bin", bytes);
    var retained = try core.private_files.RetainedFile.open(std.testing.io, fixture.source_path, .private);
    defer retained.close(std.testing.io);
    try std.testing.expectError(error.SensitivePattern, retained_copy.copyRetained(
        std.testing.allocator,
        std.testing.io,
        &retained,
        fixture.output.dir,
        fixture.output_path,
        "evidence/build.json",
        layout.max_large_artifact_bytes,
        null,
        .{ .scan = .public_bundle },
    ));
}

test "copied root path must identify retained output directory" {
    var fixture = try CopyFixture.init("output-binding");
    defer fixture.deinit();
    try fixture.writeSource("input.bin", "member\n");
    var retained = try core.private_files.RetainedFile.open(std.testing.io, fixture.source_path, .private);
    defer retained.close(std.testing.io);
    try std.testing.expectError(error.UnsafeDestination, retained_copy.copyRetained(
        std.testing.allocator,
        std.testing.io,
        &retained,
        fixture.output.dir,
        std.fs.path.dirname(fixture.source_path).?,
        "artifacts/efi",
        layout.max_json_bytes,
        null,
        .{},
    ));
}

test "staged validation refuses absent members and latches refusal across tokens" {
    var fixture = try CopyFixture.init("missing-stage");
    defer fixture.deinit();
    const staged = try native_export.Test.stagedWithoutMembers(.{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .environ = .empty,
        .runtime_path = fixture.source_path,
        .repository_path = fixture.source_path,
        .output_path = fixture.output_path,
    });
    defer staged.deinit();
    const alias = staged;
    const result = staged.validateHandoff();
    const replay = alias.validateHandoff();
    try std.testing.expect(result == .refused and replay == .refused);
    try std.testing.expectEqual(error.MissingMembers, result.refused.err);
    try std.testing.expectEqual(result.refused, replay.refused);
}

test "failed prepublication parent sync barrier leaves no final bundle" {
    var fixture = try CopyFixture.init("parent-sync");
    defer fixture.deinit();
    try std.testing.expectError(error.AmbiguousWrite, native_export.Test.publishBundleForTest(
        std.testing.io,
        fixture.output.dir,
        "{}\n",
        .before_parent_sync,
    ));
    try std.testing.expectError(error.FileNotFound, fixture.output.dir.openFile(std.testing.io, "bundle.json", .{ .follow_symlinks = false }));
}

test "sensitive scan matches streaming byte semantics for every pattern and split" {
    for (retained_copy.sensitive_patterns) |pattern| {
        for (1..pattern.len) |split| {
            var scanner: retained_copy.Scanner = .{};
            try scanner.observe("\x00\xffbinary");
            try scanner.observe(pattern[0..split]);
            try std.testing.expectError(error.SensitivePattern, scanner.observe(pattern[split..]));
        }
        var scanner: retained_copy.Scanner = .{};
        for (pattern[0 .. pattern.len - 1]) |byte| try scanner.observe(&.{byte});
        try std.testing.expectError(error.SensitivePattern, scanner.observe(pattern[pattern.len - 1 ..]));
    }
    var scanner: retained_copy.Scanner = .{};
    try scanner.observe("\xffAuthorization: bearer \x00accesssas\x80?SV=&SIG=");
}

test "complete typed v2 runtime exports every byte with live Python export parity" {
    var fixture = try ExportFixture.init("export-parity");
    defer fixture.deinit();
    const before = try descriptorCount();
    {
        const pinned = try fixture.begin(.{});
        defer pinned.deinit();
        const result = native_export.Test.finishFixture(pinned);
        if (result != .success) {
            std.debug.print("export parity failed: {any}\n", .{result});
            return error.TestUnexpectedResult;
        }
        try std.testing.expectEqualStrings(&fixture.result_sha256, &result.success.result_sha256);
        try std.testing.expectEqual(@as(usize, 26), result.success.artifacts);
        try std.testing.expectEqual(@as(usize, 6), result.success.boots);
        try std.testing.expectEqual(@as(usize, 33), result.success.evidence);
    }
    try std.testing.expectEqual(before, try descriptorCount());
    const parity = try std.process.run(std.testing.allocator, std.testing.io, .{
        .argv = &.{ "python3", "-B", test_options.python_oracle, "--export-parity", fixture.root_path },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(8192),
    });
    defer std.testing.allocator.free(parity.stdout);
    defer std.testing.allocator.free(parity.stderr);
    if (!std.meta.eql(parity.term, std.process.Child.Term{ .exited = 0 })) {
        std.debug.print("Python export parity: {s}\n", .{parity.stderr});
        return error.TestUnexpectedResult;
    }
}

test "every export phase failure retains private evidence forbids final bundle and replay" {
    for ([_]native_export.Phase{
        .output_reserved,    .artifacts_copied, .boots_copied,      .evidence_copied,
        .source_revalidated, .handoff_staged,   .handoff_validated, .handoff_published,
    }) |phase| {
        var fixture = try ExportFixture.init(@tagName(phase));
        defer fixture.deinit();
        const before = try descriptorCount();
        {
            const pinned = try fixture.begin(.{ .phase = phase });
            defer pinned.deinit();
            const result = native_export.Test.finishFixture(pinned);
            try std.testing.expect(result == .poisoned);
            try std.testing.expectEqual(phase, result.poisoned.phase);
            try std.testing.expectEqual(result.poisoned, pinned.reserveOutput().poisoned);
            try fixture.noBundle();
            if (phase != .output_reserved) {
                const output = try core.private_files.Directory.open(std.testing.io, fixture.output_path);
                defer output.close(std.testing.io);
                const journal = try std.fmt.allocPrint(std.testing.allocator, "private/export/failed-{s}.json", .{@tagName(phase)});
                defer std.testing.allocator.free(journal);
                const diagnostic = try output.dir.openFile(std.testing.io, journal, .{ .follow_symlinks = false });
                defer diagnostic.close(std.testing.io);
                try std.testing.expect((try diagnostic.stat(std.testing.io)).size <= 64 * 1024);
            }
        }
        try std.testing.expectEqual(before, try descriptorCount());
        if (phase != .output_reserved) {
            const retry = try fixture.begin(.{});
            defer retry.deinit();
            try std.testing.expect(retry.reserveOutput() == .refused);
        }
    }
}

test "copied tokens cannot replay or skip export ownership transitions" {
    var fixture = try ExportFixture.init("ownership");
    defer fixture.deinit();
    {
        const pinned = try fixture.begin(.{});
        defer pinned.deinit();
        const reserved = pinned.reserveOutput().success;
        const alias = reserved;
        const artifacts = reserved.copyArtifacts().success;
        const result = alias.copyArtifacts();
        try std.testing.expect(result == .poisoned);
        try std.testing.expectEqual(error.InvalidTransition, result.poisoned.err);
        try std.testing.expectEqual(result.poisoned, artifacts.copyBoots().poisoned);
        try fixture.noBundle();
    }
    var skipped_fixture = try ExportFixture.init("skip-phase");
    defer skipped_fixture.deinit();
    const other = try skipped_fixture.begin(.{});
    defer other.deinit();
    const forged = native_export.HandoffValidated{ .attempt = other.attempt };
    try std.testing.expect(forged.publish() == .refused);
    try std.testing.expect(other.reserveOutput() == .refused);
    try skipped_fixture.noBundle();
}

test "source and destination inode replacements are poisoned before publication" {
    for ([_]bool{ false, true }) |source| {
        var fixture = try ExportFixture.init(if (source) "source-replacement" else "output-replacement");
        defer fixture.deinit();
        const pinned = try fixture.begin(.{});
        defer pinned.deinit();
        const reserved = pinned.reserveOutput().success;
        const artifacts = reserved.copyArtifacts().success;
        const boots = artifacts.copyBoots().success;
        const evidence = boots.copyEvidence().success;
        const relative = if (source) "source/repository/support/apps/wamr-aot/build/artifacts/tiny.wasm" else "handoff/artifacts/wasm";
        try fixture.replaceIdentical(relative);
        const result = evidence.revalidateSource();
        try std.testing.expect(result == .poisoned);
        try fixture.noBundle();
    }
}

test "concurrent token aliases serialize before latching irreversible refusal" {
    var fixture = try ExportFixture.init("concurrent-alias");
    defer fixture.deinit();
    const pinned = try fixture.begin(.{});
    defer pinned.deinit();
    const reserved = pinned.reserveOutput().success;
    var start = std.atomic.Value(bool).init(false);
    var outcomes: [2]native_export.Outcome(native_export.ArtifactsCopied) = undefined;
    const first = try std.Thread.spawn(.{}, copyAlias, .{ reserved, &start, &outcomes[0] });
    const second = std.Thread.spawn(.{}, copyAlias, .{ reserved, &start, &outcomes[1] }) catch |err| {
        start.store(true, .release);
        first.join();
        return err;
    };
    start.store(true, .release);
    first.join();
    second.join();
    const failure = if (outcomes[0] == .poisoned) outcomes[0] else outcomes[1];
    try std.testing.expect(failure == .poisoned);
    try std.testing.expectEqual(error.InvalidTransition, failure.poisoned.err);
    try std.testing.expectEqual(failure.poisoned, reserved.copyArtifacts().poisoned);
    try fixture.noBundle();
}

fn copyAlias(token: native_export.OutputReserved, start: *std.atomic.Value(bool), outcome: *native_export.Outcome(native_export.ArtifactsCopied)) void {
    while (!start.load(.acquire)) std.atomic.spinLoopHint();
    outcome.* = token.copyArtifacts();
}

test "allocation refusal while acquiring source pins releases every descriptor" {
    var fixture = try ExportFixture.init("pin-allocation");
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, pinWithAllocator, .{&fixture});
}

fn pinWithAllocator(allocator: std.mem.Allocator, fixture: *ExportFixture) !void {
    const before = try descriptorCount();
    const accepted = try fixture.capture();
    const pinned = native_export.Test.begin(.{
        .allocator = allocator,
        .io = std.testing.io,
        .environ = fixture_environment,
        .runtime_path = fixture.runtime_path,
        .repository_path = fixture.repository_path,
        .output_path = fixture.output_path,
    }, accepted) catch |err| {
        try std.testing.expectEqual(before, try descriptorCount());
        return err;
    };
    pinned.deinit();
    try std.testing.expectEqual(before, try descriptorCount());
}

test "source evidence additions and retained input directory replacement poison export" {
    for ([_]bool{ false, true }) |tree| {
        var fixture = try ExportFixture.init(if (tree) "input-tree" else "source-directory");
        defer fixture.deinit();
        const pinned = try fixture.begin(.{});
        defer pinned.deinit();
        const reserved = pinned.reserveOutput().success;
        const evidence = reserved.copyArtifacts().success.copyBoots().success.copyEvidence().success;
        if (tree) {
            try fixture.root.rename("source/runtime/inputs/tree", fixture.root, "old-input-tree", std.testing.io);
            try fixture.root.createDir(std.testing.io, "source/runtime/inputs/tree", .fromMode(0o700));
        } else {
            try fixture.put("source/runtime/compute/evidence/unexpected.json", "{}\n");
        }
        try std.testing.expect(evidence.revalidateSource() == .poisoned);
        try fixture.noBundle();
    }
}

test "accepted record and runtime input pins reject identical-content replacement" {
    for ([_]bool{ false, true }) |input| {
        var fixture = try ExportFixture.init(if (input) "input-pin" else "record-pin");
        defer fixture.deinit();
        var accepted = try fixture.capture();
        defer accepted.deinit();
        const before = try descriptorCount();
        try fixture.replaceIdentical(if (input) "source/runtime/inputs/tool" else "source/runtime/compute/evidence/build.json");
        if (input) {
            try std.testing.expectError(error.InputChanged, accepted.pinInput("fixture-tool"));
        } else {
            try std.testing.expectError(error.RecordChanged, accepted.pinRecord("build.json"));
        }
        try std.testing.expectEqual(before, try descriptorCount());
    }
}

test "accepted pin identity belongs to the returned descriptor across ancestor ABA" {
    for ([_]enum { record, input, cleanup, artifact, boot }{ .record, .input, .cleanup, .artifact, .boot }) |role| {
        var fixture = try ExportFixture.init(@tagName(role));
        defer fixture.deinit();
        var accepted = try fixture.capture();
        defer accepted.deinit();
        const relative = switch (role) {
            .record => "compute/evidence/build.json",
            .input => "inputs/tool",
            .cleanup => "evidence/runtime-cleanup.txt",
            .artifact => "compute/package/unikraft.raw",
            .boot => "compute/boot-raw-x2apic/hyperv-efi-boot.log",
        };
        try fixture.root.rename("source/runtime", fixture.root, "accepted-runtime", std.testing.io);
        try fixture.put(try std.fs.path.join(fixture.arena.allocator(), &.{ "source/runtime", relative }), "unaccepted-A\n");
        var aba = PinAncestorAba{ .root = fixture.root };
        controller.accepted_run.Fixture.pin_hooks = .{ .context = &aba, .before_read = PinAncestorAba.exposeAccepted, .after_read = PinAncestorAba.restoreUnaccepted };
        defer controller.accepted_run.Fixture.pin_hooks = null;
        const before = try descriptorCount();
        const outcome = switch (role) {
            .record => accepted.pinRecord("build.json"),
            .input => accepted.pinInput("fixture-tool"),
            .cleanup => accepted.pinArtifact(.cleanup),
            .artifact => accepted.pinArtifact(.raw),
            .boot => accepted.pinBoot(controller.profile.modes(accepted.compatibility)[0], .serial),
        };
        if (outcome) |value| {
            var leaked = value;
            leaked.close(std.testing.io);
            return error.UnacceptedDescriptorPassedAncestorAba;
        } else |err| switch (err) {
            error.RecordChanged, error.InputChanged, error.ArtifactChanged, error.BootChanged, error.FileChanged => {},
            else => return err,
        }
        try std.testing.expect(aba.opened_unaccepted and aba.restored);
        try std.testing.expectEqual(before, try descriptorCount());
    }
}

const PinAncestorAba = struct {
    root: std.Io.Dir,
    opened_unaccepted: bool = false,
    restored: bool = false,

    fn exposeAccepted(context: *anyopaque, retained: *const core.private_files.RetainedFile) !void {
        const self: *PinAncestorAba = @ptrCast(@alignCast(context));
        var data: [13]u8 = undefined;
        try std.testing.expectEqual(data.len, try retained.file.readPositionalAll(std.testing.io, &data, 0));
        try std.testing.expectEqualStrings("unaccepted-A\n", &data);
        self.opened_unaccepted = true;
        try self.root.rename("source/runtime", self.root, "unaccepted-runtime", std.testing.io);
        try self.root.rename("accepted-runtime", self.root, "source/runtime", std.testing.io);
    }

    fn restoreUnaccepted(context: *anyopaque) !void {
        const self: *PinAncestorAba = @ptrCast(@alignCast(context));
        try self.root.rename("source/runtime", self.root, "accepted-runtime", std.testing.io);
        try self.root.rename("unaccepted-runtime", self.root, "source/runtime", std.testing.io);
        self.restored = true;
    }
};

test "destination FIFO substitution refuses in a bounded helper and releases custody" {
    try fifoSubstitutionBounded(.replace_destination_with_fifo);
}

test "SIGINT at destination FIFO reopen poisons in a bounded helper and releases custody" {
    try fifoSubstitutionBounded(.replace_destination_with_fifo_and_cancel);
}

fn fifoSubstitutionBounded(fault: retained_copy.TestFault) !void {
    var fixture = try ExportFixture.init(@tagName(fault));
    defer fixture.deinit();
    const linux = std.os.linux;
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.FixtureFork;
    if (forked == 0) {
        fifoSubstitutionChild(&fixture, fault) catch |err| {
            std.debug.print("bounded FIFO helper failed: {s}\n", .{@errorName(err)});
            linux.exit(1);
        };
        linux.exit(0);
    }
    const pid: linux.pid_t = @intCast(forked);
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        var status: u32 = 0;
        while (linux.errno(linux.waitpid(pid, &status, 0)) == .INTR) {}
    };
    const deadline = try core.process.Deadline.afterMilliseconds(5000);
    while (true) {
        var status: u32 = 0;
        const result = linux.waitpid(pid, &status, linux.W.NOHANG);
        switch (linux.errno(result)) {
            .SUCCESS => if (result != 0) {
                reaped = true;
                try std.testing.expect(linux.W.IFEXITED(status));
                try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
                break;
            },
            .INTR => continue,
            else => return error.FixtureReap,
        }
        if (try deadline.expired()) return error.DestinationFifoReopenBlocked;
        try std.Io.sleep(std.testing.io, .fromMilliseconds(10), .awake);
    }
    try fixture.noBundle();
}

fn fifoSubstitutionChild(fixture: *ExportFixture, fault: retained_copy.TestFault) !void {
    const before = try descriptorCount();
    {
        const pinned = try fixture.begin(.{ .copy = fault });
        defer pinned.deinit();
        const outcome = native_export.Test.finishFixture(pinned);
        try std.testing.expect(outcome == .poisoned);
        try std.testing.expectEqual(if (fault == .replace_destination_with_fifo) error.UnsafeFile else error.Cancelled, outcome.poisoned.err);
        try std.testing.expectEqual(outcome.poisoned, pinned.reserveOutput().poisoned);
        try fixture.noBundle();
    }
    try std.testing.expectEqual(before, try descriptorCount());
}

test "symlinked source and replaced staged manifest poison the final publication barrier" {
    for ([_]bool{ false, true }) |source| {
        var fixture = try ExportFixture.init(if (source) "source-symlink" else "stage-replacement");
        defer fixture.deinit();
        const pinned = try fixture.begin(.{});
        defer pinned.deinit();
        const reserved = pinned.reserveOutput().success;
        const validated = reserved.copyArtifacts().success.copyBoots().success.copyEvidence().success.revalidateSource().success.stageHandoff().success.validateHandoff().success;
        const relative = if (source) "source/repository/support/apps/wamr-aot/build/artifacts/tiny.wasm" else "handoff/private/export/handoff.json";
        try fixture.replaceIdentical(relative);
        if (source) {
            try fixture.root.deleteFile(std.testing.io, relative);
            const target = try std.fs.path.join(fixture.arena.allocator(), &.{ fixture.root_path, "replaced-original" });
            try fixture.root.symLink(std.testing.io, target, relative, .{});
        }
        try std.testing.expect(validated.publish() == .poisoned);
        try fixture.noBundle();
    }
}

test "output directory replacement and member hardlinks are poisoned at final barrier" {
    for ([_]bool{ false, true }) |swap| {
        var fixture = try ExportFixture.init(if (swap) "root-swap" else "output-hardlink");
        defer fixture.deinit();
        const pinned = try fixture.begin(.{});
        defer pinned.deinit();
        const reserved = pinned.reserveOutput().success;
        const artifacts = reserved.copyArtifacts().success;
        const boots = artifacts.copyBoots().success;
        const evidence = boots.copyEvidence().success;
        const validated = evidence.revalidateSource().success.stageHandoff().success.validateHandoff().success;
        if (swap) {
            try fixture.root.rename("handoff", fixture.root, "old-handoff", std.testing.io);
            try fixture.root.createDir(std.testing.io, "handoff", .fromMode(0o700));
        } else {
            try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.linkat(fixture.root.handle, "handoff/artifacts/wasm", fixture.root.handle, "extra-hardlink", 0)));
        }
        const result = validated.publish();
        try std.testing.expect(result == .poisoned);
        try fixture.noBundle();
    }
}

test "private namespace replacement cannot adopt an earlier export journal" {
    var fixture = try ExportFixture.init("private-swap");
    defer fixture.deinit();
    const pinned = try fixture.begin(.{});
    defer pinned.deinit();
    const reserved = pinned.reserveOutput().success;
    const artifacts = reserved.copyArtifacts().success;
    try fixture.root.rename("handoff/private", fixture.root, "old-private", std.testing.io);
    try fixture.root.createDir(std.testing.io, "handoff/private", .fromMode(0o700));
    try fixture.root.rename("old-private/export", fixture.root, "handoff/private/export", std.testing.io);
    try std.testing.expect(artifacts.copyBoots() == .poisoned);
    try fixture.noBundle();
    try std.testing.expectError(error.FileNotFound, fixture.root.openFile(std.testing.io, "handoff/private/export/phase-boots_copied.json", .{ .follow_symlinks = false }));
}

test "known publication failures retain staged manifest and unknown durability never succeeds" {
    for ([_]native_export.PublishFault{ .before_file_sync, .before_parent_sync, .after_publication }) |fault| {
        var fixture = try ExportFixture.init(@tagName(fault));
        defer fixture.deinit();
        const pinned = try fixture.begin(.{ .publish = fault });
        defer pinned.deinit();
        const result = native_export.Test.finishFixture(pinned);
        try std.testing.expect(result == .poisoned);
        const output = try core.private_files.Directory.open(std.testing.io, fixture.output_path);
        defer output.close(std.testing.io);
        const staged = try output.dir.openFile(std.testing.io, "private/export/handoff.json", .{ .follow_symlinks = false });
        defer staged.close(std.testing.io);
        try std.testing.expect((try staged.stat(std.testing.io)).size > 0);
        if (fault == .after_publication) {
            try std.testing.expectEqual(core.private_files.CommitStatus.visible_not_durable, result.poisoned.publication);
            const uncertain = try output.dir.openFile(std.testing.io, "bundle.json", .{ .follow_symlinks = false });
            defer uncertain.close(std.testing.io);
        } else {
            try fixture.noBundle();
        }
        try std.testing.expectEqual(result.poisoned, pinned.reserveOutput().poisoned);
    }
}

test "copy cancellation and I/O faults poison the attempt and retain only private partials" {
    for ([_]retained_copy.TestFault{
        .cancel_after_first_chunk, .before_file_sync, .before_parent_sync, .replace_destination_before_reopen,
    }) |fault| {
        var fixture = try ExportFixture.init(@tagName(fault));
        defer fixture.deinit();
        const before = try descriptorCount();
        {
            const pinned = try fixture.begin(.{ .copy = fault });
            defer pinned.deinit();
            const result = native_export.Test.finishFixture(pinned);
            try std.testing.expect(result == .poisoned);
            try std.testing.expectEqual(native_export.Phase.artifacts_copied, result.poisoned.phase);
            try std.testing.expectEqual(result.poisoned, pinned.reserveOutput().poisoned);
            try fixture.noBundle();
        }
        try std.testing.expectEqual(before, try descriptorCount());
    }
}

test "late cancellation and missing staged output member forbid publication" {
    for ([_]bool{ false, true }) |cancelled| {
        var fixture = try ExportFixture.init(if (cancelled) "late-cancel" else "missing-output");
        defer fixture.deinit();
        const pinned = try fixture.begin(.{});
        defer pinned.deinit();
        const reserved = pinned.reserveOutput().success;
        const staged = reserved.copyArtifacts().success.copyBoots().success.copyEvidence().success.revalidateSource().success.stageHandoff().success;
        if (cancelled) native_export.Test.cancelAttempt(staged) else try fixture.root.deleteFile(std.testing.io, "handoff/artifacts/wasm");
        const result = staged.validateHandoff();
        try std.testing.expect(result == .poisoned);
        try std.testing.expectEqual(result.poisoned, staged.validateHandoff().poisoned);
        try fixture.noBundle();
    }
}

test "native publication cannot be repeated and an existing output cannot be adopted" {
    var fixture = try ExportFixture.init("success-terminal");
    defer fixture.deinit();
    {
        const pinned = try fixture.begin(.{});
        defer pinned.deinit();
        const reserved = pinned.reserveOutput().success;
        const validated = reserved.copyArtifacts().success.copyBoots().success.copyEvidence().success.revalidateSource().success.stageHandoff().success.validateHandoff().success;
        try std.testing.expect(validated.publish() == .success);
        const replay = validated.publish();
        try std.testing.expect(replay == .refused);
        try std.testing.expectEqual(error.AttemptFinished, replay.refused.err);
    }
    const fresh_attempt = try fixture.begin(.{});
    defer fresh_attempt.deinit();
    try std.testing.expect(fresh_attempt.reserveOutput() == .refused);
}

test "export refuses caller budget expansion and unsafe output directory mode" {
    var fixture = try ExportFixture.init("policy-modes");
    defer fixture.deinit();
    const before = try descriptorCount();
    const expanded = native_export.run(.{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .environ = fixture_environment,
        .runtime_path = fixture.runtime_path,
        .repository_path = fixture.repository_path,
        .output_path = fixture.output_path,
        .aggregate_limit = retained_copy.aggregate_budget + 1,
    });
    try std.testing.expect(expanded == .refused);
    try fixture.noBundle();
    try std.testing.expectEqual(before, try descriptorCount());
    const pinned = try fixture.begin(.{});
    defer pinned.deinit();
    const reserved = pinned.reserveOutput().success;
    const output = try core.private_files.Directory.open(std.testing.io, fixture.output_path);
    defer output.close(std.testing.io);
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.fchmod(output.dir.handle, 0o750)));
    try std.testing.expect(reserved.copyArtifacts() == .poisoned);
    try fixture.noBundle();
}

test "strict ZIP32 reader refuses malformed archives with typed errors" {
    const a = std.testing.allocator;
    const entries = baseZipEntries();
    var archive_hash: [32]u8 = undefined;
    const base = try writeZipBytes(a, &entries, &archive_hash);
    defer a.free(base);
    var expected_storage: [zip.max_members]zip.ExpectedMember = undefined;
    const expected = try zip.expectedFromSlices(&entries, &expected_storage);
    const offsets = zipOffsets(&entries);

    try expectZipErrorOwned(error.TrailingBytes, try withSuffix(a, base, "x"), expected, archive_hash);
    try expectZipErrorOwned(error.PrependedBytes, try withPatchedPrefix(a, base, offsets, 1), expected, archive_hash);
    try expectZipErrorOwned(error.MultipleEndRecords, try withSuffix(a, base, base[offsets.eocd..]), expected, archive_hash);
    try expectZipErrorOwned(error.ArchiveComment, try patchedU16(a, base, offsets.eocd + 20, 1), expected, archive_hash);
    try expectZipErrorOwned(error.ExtraField, try patchedU16(a, base, offsets.local[0] + 28, 1), expected, archive_hash);
    try expectZipErrorOwned(error.ExtraField, try patchedU16(a, base, offsets.central[0] + 30, 1), expected, archive_hash);
    try expectZipErrorOwned(error.MemberComment, try patchedU16(a, base, offsets.central[0] + 32, 1), expected, archive_hash);
    try expectZipErrorOwned(error.UnsupportedCompression, try patchedU16(a, base, offsets.central[0] + 10, 8), expected, archive_hash);
    try expectZipErrorOwned(error.Encrypted, try patchedU16(a, base, offsets.central[0] + 8, 1), expected, archive_hash);
    try expectZipErrorOwned(error.DataDescriptor, try patchedU16(a, base, offsets.central[0] + 8, 8), expected, archive_hash);
    try expectZipErrorOwned(error.UnsupportedFlags, try patchedU16(a, base, offsets.central[0] + 8, 0x0800), expected, archive_hash);
    try expectZipErrorOwned(error.Zip64, try patchedU32(a, base, offsets.central[0] + 20, 0xffffffff), expected, archive_hash);
    try expectZipErrorOwned(error.NameMismatch, try patchedByte(a, base, offsets.local_name[0], 'c'), expected, archive_hash);
    try expectZipErrorOwned(error.HeaderMismatch, try patchedU32(a, base, offsets.local[0] + 14, 0), expected, archive_hash);
    try expectZipErrorOwned(error.SizeMismatch, try patchedU32(a, base, offsets.local[0] + 18, 2), expected, archive_hash);
    const wrong_crc = try patchedU32(a, base, offsets.local[0] + 14, 0);
    putU32(wrong_crc, offsets.central[0] + 16, 0);
    try expectZipErrorOwned(error.CrcMismatch, wrong_crc, expected, archive_hash);
    try expectZipErrorOwned(error.Overlap, try patchedU32(a, base, offsets.central[1] + 42, 0), expected, archive_hash);
    try expectZipErrorOwned(error.OutOfBounds, try patchedU32(a, base, offsets.central[1] + 42, @intCast(offsets.local[1] + 1)), expected, archive_hash);
    try expectZipErrorOwned(error.WrongMode, try patchedU32(a, base, offsets.central[0] + 38, @as(u32, 0o100644) << 16), expected, archive_hash);
    try expectZipErrorOwned(error.WrongCreateSystem, try patchedU16(a, base, offsets.central[0] + 4, 20), expected, archive_hash);
    try expectZipErrorOwned(error.WrongVersion, try patchedU16(a, base, offsets.central[0] + 4, (@as(u16, zip.create_system_unix) << 8) | 21), expected, archive_hash);
    try expectZipErrorOwned(error.WrongTimestamp, try patchedU16(a, base, offsets.central[0] + 14, 0x0022), expected, archive_hash);
    try expectZipErrorOwned(error.WrongInternalAttributes, try patchedU16(a, base, offsets.central[0] + 36, 1), expected, archive_hash);
    try expectZipErrorOwned(error.DiskUnsupported, try patchedU16(a, base, offsets.eocd + 4, 1), expected, archive_hash);
    const wrong_count = try a.dupe(u8, base);
    putU16(wrong_count, offsets.eocd + 8, 3);
    putU16(wrong_count, offsets.eocd + 10, 3);
    try expectZipErrorOwned(error.UnexpectedMemberCount, wrong_count, expected, archive_hash);
    try expectZipErrorOwned(error.Truncated, try patchedU16(a, base, offsets.central[0] + 28, 0xffff), expected, archive_hash);
    try expectZipErrorOwned(error.InvalidZip, try patchedByte(a, base, offsets.eocd, 0), expected, archive_hash);
    const truncated_cuts = [_]usize{
        0,
        1,
        29,
        offsets.local[1] + 29,
        offsets.central[0] + 45,
        offsets.eocd + 21,
    };
    for (truncated_cuts) |cut| {
        try expectZipRefused(base[0..cut], expected, zip.sha256(base[0..cut]));
    }
    const swapped = [_]zip.ExpectedMember{ expected[1], expected[0] };
    try expectZipError(error.OrderMismatch, base, &swapped, archive_hash);
    var bad_member_digest = [_]zip.ExpectedMember{ expected[0], expected[1] };
    bad_member_digest[0].sha256[0] ^= 0xff;
    try expectZipError(error.DigestMismatch, base, &bad_member_digest, archive_hash);
    var bad_hash = archive_hash;
    bad_hash[0] ^= 0xff;
    try expectZipError(error.DigestMismatch, base, expected, bad_hash);
}

test "strict ZIP32 name, count and limit refusals are deterministic" {
    inline for ([_][]const u8{
        "",        ".",           "..",          "/absolute",   "trailing/",   "a//b",                "a/./b",      "a/../b",
        "C:drive", "//unc/share", "back\\slash", "nul\x00byte", "ctl\x1fbyte", "snowman\xe2\x98\x83", "space name",
    }) |name| {
        try std.testing.expectError(error.InvalidName, zip.validateName(name));
        try expectMalformedZipName(name);
    }

    const duplicate = [_]zip.SliceEntry{
        .{ .name = "dup.txt", .bytes = "", .limit = 1 },
        .{ .name = "dup.txt", .bytes = "", .limit = 1 },
    };
    try expectSliceWriteError(error.DuplicateName, &duplicate);

    const collision = [_]zip.SliceEntry{
        .{ .name = "fold.txt", .bytes = "", .limit = 1 },
        .{ .name = "FOLD.txt", .bytes = "", .limit = 1 },
    };
    try expectSliceWriteError(error.NameCollision, &collision);
    try expectReaderCasefoldDuplicate();

    const too_large = [_]zip.SliceEntry{.{ .name = "tiny.txt", .bytes = "xx", .limit = 1 }};
    try expectSliceWriteError(error.TooLarge, &too_large);

    var many_names: [zip.max_members + 1][8]u8 = undefined;
    var many_entries: [zip.max_members + 1]zip.SliceEntry = undefined;
    for (&many_entries, 0..) |*entry, i| {
        const name = try std.fmt.bufPrint(&many_names[i], "m{d:0>3}", .{i});
        entry.* = .{ .name = name, .bytes = "", .limit = 1 };
    }
    try expectSliceWriteError(error.TooManyMembers, &many_entries);
}

test "strict ZIP32 writer streams and removes failed file output" {
    const io = std.testing.io;
    const cwd = std.Io.Dir.cwd();
    const dir_name = "handoff-zip-stream-test";
    cwd.deleteTree(io, dir_name) catch {};
    try cwd.createDir(io, dir_name, .fromMode(0o700));
    defer cwd.deleteTree(io, dir_name) catch {};
    const dir = try cwd.openDir(io, dir_name, .{ .follow_symlinks = false });
    defer dir.close(io);

    var actual_long = std.Io.Reader.fixed("xx");
    var digest: [32]u8 = undefined;
    const size_mismatch = [_]zip.Entry{.{
        .name = "bad.txt",
        .reader = &actual_long,
        .size = 1,
        .crc32 = zip.crc32("x"),
        .sha256 = zip.sha256("x"),
        .limit = 16,
    }};
    try std.testing.expectError(error.SizeMismatch, zip.writeArchiveFile(io, dir, "bad-size.zip", &size_mismatch, &digest));
    try std.testing.expectError(error.FileNotFound, dir.openFile(io, "bad-size.zip", .{}));

    var actual_crc = std.Io.Reader.fixed("x");
    const crc_mismatch = [_]zip.Entry{.{
        .name = "bad.txt",
        .reader = &actual_crc,
        .size = 1,
        .crc32 = 0,
        .sha256 = zip.sha256("x"),
        .limit = 16,
    }};
    try std.testing.expectError(error.CrcMismatch, zip.writeArchiveFile(io, dir, "bad-crc.zip", &crc_mismatch, &digest));
    try std.testing.expectError(error.FileNotFound, dir.openFile(io, "bad-crc.zip", .{}));
}

test "strict ZIP32 reader accepts EOCD with central offset matching EOCD signature bytes" {
    const a = std.testing.allocator;
    const name = "pad.bin";
    const central_offset: usize = 0x06054b50;
    const data_start = 30 + name.len;
    const data_len = central_offset - data_start;
    const central_size = 46 + name.len;
    const eocd = central_offset + central_size;
    const total_len = eocd + 22;
    var bytes = try a.alloc(u8, total_len);
    defer a.free(bytes);
    @memset(bytes, 0);

    const member = bytes[data_start..central_offset];
    const member_crc = zip.crc32(member);
    const member_sha = zip.sha256(member);

    putU32(bytes, 0, 0x04034b50);
    putU16(bytes, 4, zip.version_needed);
    putU16(bytes, 6, zip.flags);
    putU16(bytes, 8, zip.method_stored);
    putU16(bytes, 10, zip.dos_time_midnight);
    putU16(bytes, 12, zip.dos_date_1980_01_01);
    putU32(bytes, 14, member_crc);
    putU32(bytes, 18, @intCast(data_len));
    putU32(bytes, 22, @intCast(data_len));
    putU16(bytes, 26, name.len);
    @memcpy(bytes[30..][0..name.len], name);

    putU32(bytes, central_offset, 0x02014b50);
    putU16(bytes, central_offset + 4, zip.version_made_by);
    putU16(bytes, central_offset + 6, zip.version_needed);
    putU16(bytes, central_offset + 8, zip.flags);
    putU16(bytes, central_offset + 10, zip.method_stored);
    putU16(bytes, central_offset + 12, zip.dos_time_midnight);
    putU16(bytes, central_offset + 14, zip.dos_date_1980_01_01);
    putU32(bytes, central_offset + 16, member_crc);
    putU32(bytes, central_offset + 20, @intCast(data_len));
    putU32(bytes, central_offset + 24, @intCast(data_len));
    putU16(bytes, central_offset + 28, name.len);
    putU16(bytes, central_offset + 36, zip.internal_attr);
    putU32(bytes, central_offset + 38, zip.external_attr_regular_0600);
    @memcpy(bytes[central_offset + 46 ..][0..name.len], name);

    putU32(bytes, eocd, 0x06054b50);
    putU16(bytes, eocd + 8, 1);
    putU16(bytes, eocd + 10, 1);
    putU32(bytes, eocd + 12, @intCast(central_size));
    putU32(bytes, eocd + 16, @intCast(central_offset));

    const expected = [_]zip.ExpectedMember{.{
        .name = name,
        .size = data_len,
        .sha256 = member_sha,
        .limit = data_len,
    }};
    try zip.verifyArchive(bytes, .{ .members = &expected, .archive_sha256 = zip.sha256(bytes) });
}

test "strict ZIP32 fuzz mutations never become acceptable" {
    const entries = [_]zip.SliceEntry{
        .{ .name = "alpha.txt", .bytes = "alpha\n", .limit = 1024 },
        .{ .name = "dir/nested.bin", .bytes = "\x00stored bytes\n", .limit = 1024 },
        .{ .name = "omega.dat", .bytes = "last member", .limit = 1024 },
    };
    var expected_storage: [zip.max_members]zip.ExpectedMember = undefined;
    const expected = try zip.expectedFromSlices(&entries, &expected_storage);
    const a = std.testing.allocator;
    var state: u64 = 0x18702a5eed;
    for (0..256) |i| {
        const next = fuzzNext(&state);
        if ((next & 1) == 0) {
            const cut = @as(usize, @intCast(fuzzNext(&state) % (zip_multi_golden.len - 1)));
            try expectZipRefused(zip_multi_golden[0..cut], expected, zip.sha256(zip_multi_golden[0..cut]));
        } else {
            const mutated = try a.dupe(u8, zip_multi_golden);
            defer a.free(mutated);
            const pos = @as(usize, @intCast(fuzzNext(&state) % mutated.len));
            mutated[pos] ^= @as(u8, @intCast((i % 251) + 1));
            try expectZipRefused(mutated, expected, zip.sha256(mutated));
        }
    }
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

fn expectZipGolden(golden_bytes: []const u8, entries: []const zip.SliceEntry) !void {
    const a = std.testing.allocator;
    var archive_hash: [32]u8 = undefined;
    const actual = try writeZipBytes(a, entries, &archive_hash);
    defer a.free(actual);
    try std.testing.expectEqualSlices(u8, golden_bytes, actual);
    try std.testing.expectEqualSlices(u8, &zip.sha256(golden_bytes), &archive_hash);
    var expected_storage: [zip.max_members]zip.ExpectedMember = undefined;
    const expected = try zip.expectedFromSlices(entries, &expected_storage);
    try zip.verifyArchive(golden_bytes, .{ .members = expected, .archive_sha256 = zip.sha256(golden_bytes) });
}

fn expectPackGolden(
    compatibility: profile.Compatibility,
    golden_bytes: []const u8,
    bundle_bytes: []const u8,
    manifest_bytes: []const u8,
) !void {
    const a = std.testing.allocator;
    const names = try generatedPublicMembers(a, compatibility);
    defer freeMembers(a, names);
    try std.testing.expectEqual(layout.expectedZipMemberCount(compatibility), names.len);
    var entries: [zip.max_members]zip.SliceEntry = undefined;
    for (names, 0..) |name, i| {
        const bytes =
            if (std.mem.eql(u8, name, "bundle.json"))
                bundle_bytes
            else if (std.mem.eql(u8, name, "public-source.json"))
                manifest_bytes
            else
                "x";
        entries[i] = .{ .name = name, .bytes = bytes, .limit = packMemberLimit(name) };
    }
    try expectZipGolden(golden_bytes, entries[0..names.len]);
}

fn packMemberLimit(name: []const u8) u64 {
    if (std.mem.eql(u8, name, "bundle.json") or std.mem.eql(u8, name, "public-source.json"))
        return layout.max_json_bytes;
    if (std.mem.startsWith(u8, name, "boots/") and std.mem.endsWith(u8, name, "/serial"))
        return layout.max_serial_bytes;
    if (std.mem.startsWith(u8, name, "artifacts/"))
        return layout.artifactLimit(name["artifacts/".len..]);
    if (std.mem.endsWith(u8, name, "/config") or std.mem.eql(u8, name, "artifacts/config"))
        return layout.max_config_bytes;
    return layout.max_large_artifact_bytes;
}

fn expectRootBoundGolden(bytes: []const u8, compatibility: profile.Compatibility) !void {
    var document = try c.Document.parse(std.testing.allocator, bytes, contracts.json_limits);
    defer document.deinit();
    try std.testing.expectError(error.InvalidPath, contracts.validateLocalImageHandoff(document.value()));
    try std.testing.expectEqual(compatibility, try contracts.validateLocalImageHandoffWithRoot(document.value(), root_bound_stage));
}

fn baseZipEntries() [2]zip.SliceEntry {
    return .{
        .{ .name = "a.txt", .bytes = "A", .limit = 16 },
        .{ .name = "b.txt", .bytes = "BB", .limit = 16 },
    };
}

fn writeZipBytes(a: std.mem.Allocator, entries: []const zip.SliceEntry, archive_hash: *[32]u8) ![]u8 {
    var out = std.Io.Writer.Allocating.init(a);
    defer out.deinit();
    var readers: [zip.max_members + 1]std.Io.Reader = undefined;
    var streaming: [zip.max_members + 1]zip.Entry = undefined;
    const converted = try streamingEntries(entries, &readers, &streaming);
    try zip.writeArchive(&out.writer, converted, archive_hash);
    return out.toOwnedSlice();
}

fn expectSliceWriteError(expected_error: anyerror, entries: []const zip.SliceEntry) !void {
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    var digest: [32]u8 = undefined;
    var readers: [zip.max_members + 1]std.Io.Reader = undefined;
    var streaming: [zip.max_members + 1]zip.Entry = undefined;
    const converted = try streamingEntries(entries, &readers, &streaming);
    try std.testing.expectError(expected_error, zip.writeArchive(&out.writer, converted, &digest));
}

fn streamingEntries(
    entries: []const zip.SliceEntry,
    readers: []std.Io.Reader,
    streaming: []zip.Entry,
) ![]const zip.Entry {
    if (readers.len < entries.len or streaming.len < entries.len) return error.InvalidFixture;
    for (entries, 0..) |entry, i| {
        readers[i] = std.Io.Reader.fixed(entry.bytes);
        streaming[i] = entryFromSlice(entry, &readers[i]);
    }
    return streaming[0..entries.len];
}

fn entryFromSlice(entry: zip.SliceEntry, reader: *std.Io.Reader) zip.Entry {
    return .{
        .name = entry.name,
        .reader = reader,
        .size = entry.bytes.len,
        .crc32 = zip.crc32(entry.bytes),
        .sha256 = zip.sha256(entry.bytes),
        .limit = entry.limit,
    };
}

const ZipOffsets = struct {
    count: usize,
    local: [zip.max_members]usize,
    local_name: [zip.max_members]usize,
    central: [zip.max_members]usize,
    eocd: usize,
};

fn zipOffsets(entries: []const zip.SliceEntry) ZipOffsets {
    var result: ZipOffsets = .{
        .count = entries.len,
        .local = undefined,
        .local_name = undefined,
        .central = undefined,
        .eocd = 0,
    };
    var pos: usize = 0;
    for (entries, 0..) |entry, i| {
        result.local[i] = pos;
        result.local_name[i] = pos + 30;
        pos += 30 + entry.name.len + entry.bytes.len;
    }
    for (entries, 0..) |entry, i| {
        result.central[i] = pos;
        pos += 46 + entry.name.len;
    }
    result.eocd = pos;
    return result;
}

fn expectZipErrorOwned(expected_error: anyerror, bytes: []u8, expected: []const zip.ExpectedMember, digest: [32]u8) !void {
    defer std.testing.allocator.free(bytes);
    try expectZipError(expected_error, bytes, expected, digest);
}

fn expectZipError(expected_error: anyerror, bytes: []const u8, expected: []const zip.ExpectedMember, digest: [32]u8) !void {
    try std.testing.expectError(expected_error, zip.verifyArchive(bytes, .{ .members = expected, .archive_sha256 = digest }));
}

fn expectZipRefused(bytes: []const u8, expected: []const zip.ExpectedMember, digest: [32]u8) !void {
    if (zip.verifyArchive(bytes, .{ .members = expected, .archive_sha256 = digest })) |_| {
        return error.ExpectedRefusal;
    } else |_| {}
}

fn expectMalformedZipName(name: []const u8) !void {
    const a = std.testing.allocator;
    var name_buffer: [64]u8 = undefined;
    const valid_name = if (name.len == 0) "n" else blk: {
        @memset(name_buffer[0..name.len], 'n');
        break :blk name_buffer[0..name.len];
    };
    const entries = [_]zip.SliceEntry{.{ .name = valid_name, .bytes = "x", .limit = 16 }};
    var digest: [32]u8 = undefined;
    const base = try writeZipBytes(a, &entries, &digest);
    defer a.free(base);
    var expected_storage: [zip.max_members]zip.ExpectedMember = undefined;
    const expected = try zip.expectedFromSlices(&entries, &expected_storage);
    const offsets = zipOffsets(&entries);
    const mutated = try a.dupe(u8, base);
    if (name.len == 0) {
        putU16(mutated, offsets.central[0] + 28, 0);
    } else {
        @memcpy(mutated[offsets.central[0] + 46 ..][0..name.len], name);
    }
    try expectZipErrorOwned(error.InvalidName, mutated, expected, digest);
}

fn expectReaderCasefoldDuplicate() !void {
    const a = std.testing.allocator;
    const entries = [_]zip.SliceEntry{
        .{ .name = "fold.txt", .bytes = "x", .limit = 16 },
        .{ .name = "gold.txt", .bytes = "y", .limit = 16 },
    };
    var digest: [32]u8 = undefined;
    const base = try writeZipBytes(a, &entries, &digest);
    defer a.free(base);
    var expected_storage: [zip.max_members]zip.ExpectedMember = undefined;
    const expected = try zip.expectedFromSlices(&entries, &expected_storage);
    const offsets = zipOffsets(&entries);
    const mutated = try a.dupe(u8, base);
    @memcpy(mutated[offsets.central[1] + 46 ..][0.."FOLD.txt".len], "FOLD.txt");
    try expectZipErrorOwned(error.NameCollision, mutated, expected, digest);
}

fn withSuffix(a: std.mem.Allocator, base: []const u8, suffix: []const u8) ![]u8 {
    const out = try a.alloc(u8, base.len + suffix.len);
    @memcpy(out[0..base.len], base);
    @memcpy(out[base.len..], suffix);
    return out;
}

fn withPatchedPrefix(a: std.mem.Allocator, base: []const u8, offsets: ZipOffsets, prefix_len: usize) ![]u8 {
    const out = try a.alloc(u8, prefix_len + base.len);
    @memset(out[0..prefix_len], 0);
    @memcpy(out[prefix_len..], base);
    for (0..offsets.count) |i| {
        const raw = readU32(out[prefix_len + offsets.central[i] + 42 ..][0..4]);
        putU32(out, prefix_len + offsets.central[i] + 42, raw + @as(u32, @intCast(prefix_len)));
    }
    const cd = readU32(out[prefix_len + offsets.eocd + 16 ..][0..4]);
    putU32(out, prefix_len + offsets.eocd + 16, cd + @as(u32, @intCast(prefix_len)));
    return out;
}

fn patchedByte(a: std.mem.Allocator, base: []const u8, offset: usize, value: u8) ![]u8 {
    const out = try a.dupe(u8, base);
    out[offset] = value;
    return out;
}

fn patchedU16(a: std.mem.Allocator, base: []const u8, offset: usize, value: u16) ![]u8 {
    const out = try a.dupe(u8, base);
    putU16(out, offset, value);
    return out;
}

fn patchedU32(a: std.mem.Allocator, base: []const u8, offset: usize, value: u32) ![]u8 {
    const out = try a.dupe(u8, base);
    putU32(out, offset, value);
    return out;
}

fn putU16(bytes: []u8, offset: usize, value: u16) void {
    std.mem.writeInt(u16, bytes[offset..][0..2], value, .little);
}

fn putU32(bytes: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], value, .little);
}

fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

fn fuzzNext(state: *u64) u64 {
    state.* = state.* *% 6364136223846793005 +% 1442695040888963407;
    return state.*;
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

fn expectEqualManifest(expected: []const u8, actual: []const u8) !void {
    if (std.mem.eql(u8, expected, actual)) return;
    const end = @min(expected.len, actual.len);
    var index: usize = 0;
    while (index < end and expected[index] == actual[index]) : (index += 1) {}
    const start = index - @min(index, 96);
    const stop_expected = @min(expected.len, index + 96);
    const stop_actual = @min(actual.len, index + 96);
    std.debug.print(
        "manifest diff at byte {d}: expected 0x{x:0>2}, actual 0x{x:0>2}\nexpected: {s}\nactual:   {s}\n",
        .{
            index,
            if (index < expected.len) expected[index] else 0,
            if (index < actual.len) actual[index] else 0,
            expected[start..stop_expected],
            actual[start..stop_actual],
        },
    );
    return error.TestExpectedEqual;
}

var copy_fixture_counter: usize = 0;

const fixture_environment: std.process.Environ = .{ .block = .{ .slice = &.{
    "GITHUB_REPOSITORY=cataggar/unikraft",
    "GITHUB_RUN_ID=1",
    "GITHUB_RUN_ATTEMPT=1",
} } };

const ExportFixture = struct {
    copy_fixture: CopyFixture,
    arena: std.heap.ArenaAllocator,
    root: std.Io.Dir,
    root_path: []const u8,
    runtime_path: []const u8,
    repository_path: []const u8,
    output_path: []const u8,
    result_sha256: [64]u8,

    fn init(label: []const u8) !ExportFixture {
        var base = try CopyFixture.init(label);
        errdefer base.deinit();
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        const io = std.testing.io;
        const root_path = try std.Io.Dir.cwd().realPathFileAlloc(io, base.rel_path, a);
        const root = try core.private_files.Directory.open(io, root_path);
        errdefer root.close(io);
        const runtime_path = try std.fs.path.join(a, &.{ root_path, "source/runtime" });
        const repository_path = try std.fs.path.join(a, &.{ root_path, "source/repository" });
        const output_path = try std.fs.path.join(a, &.{ root_path, "handoff" });
        var self: ExportFixture = .{
            .copy_fixture = base,
            .arena = arena,
            .root = root.dir,
            .root_path = root_path,
            .runtime_path = runtime_path,
            .repository_path = repository_path,
            .output_path = output_path,
            .result_sha256 = undefined,
        };
        errdefer arena = self.arena;
        try self.materialize();
        return self;
    }

    fn materialize(self: *ExportFixture) !void {
        const a = self.arena.allocator();
        const io = std.testing.io;
        const result_file = try core.private_files.openAbsolute(io, test_options.accepted_result_fixture, .artifact);
        defer result_file.close(io);
        var result_raw_fixture = try core.private_files.readSensitiveFile(io, a, result_file, 64 * 1024, .artifact);
        defer result_raw_fixture.deinit();
        var result = try c.Document.parse(a, result_raw_fixture.bytes(), .{});
        defer result.deinit();
        var hashes = result.value().object.get("records").?.object;
        for (layout.evidence_v2) |name| {
            const bytes = if (std.mem.eql(u8, name, "build-start.json"))
                try fixtureJson(a, .{
                    .source = .{ .revision = rev, .tree = rev },
                    .command_supervisor = .{},
                    .consumer_inputs = .{
                        .schema = "uk.wamr.consumer-input-custody",
                        .version = 2,
                        .files = .{ .@"command-supervisor" = .{ .path = try std.fs.path.join(a, &.{ self.runtime_path, "controller/bin/uk-wamr-native-ci" }) } },
                    },
                })
            else if (std.mem.eql(u8, name, "build.json"))
                try fixtureJson(a, .{ .source = .{ .revision = rev, .tree = rev }, .runtime = .{} })
            else if (std.mem.eql(u8, name, "boot-inputs.json"))
                try fixtureJson(a, .{ .files = .{} })
            else if (std.mem.eql(u8, name, "package.json"))
                try fixtureJson(a, .{ .producer_sha256 = sha, .image = .{ .fixture = true } })
            else
                try fixtureJson(a, .{ .fixture_record = name });
            try self.put(try std.fmt.allocPrint(a, "source/runtime/compute/evidence/{s}", .{name}), bytes);
            hashes.getPtr(name).?.* = .{ .string = try a.dupe(u8, &std.fmt.bytesToHex(controller.records.fileIdentity(bytes), .lower)) };
        }
        const result_raw = try std.json.Stringify.valueAlloc(a, result.value(), .{});
        const result_bytes = try controller.records.canonicalAlloc(a, result_raw);
        try self.put("source/runtime/compute/evidence/result.json", result_bytes);
        self.result_sha256 = std.fmt.bytesToHex(controller.records.fileIdentity(result_bytes), .lower);
        const source_paths = [_][]const u8{
            "repository/support/apps/wamr-aot/build/wamr_hyperv-x86_64-efi",
            "repository/support/apps/wamr-aot/build/wamr_hyperv-x86_64-efi.dbg",
            "repository/support/apps/wamr-aot/build/wamr_hyperv-x86_64-efi.bootinfo",
            "runtime/compute/package/unikraft.raw",
            "runtime/compute/package/unikraft.qcow2",
            "runtime/compute/package/unikraft-derived.vhd",
            "repository/support/apps/wamr-aot/build/artifacts/libwamr-aot.a",
            "repository/support/apps/wamr-aot/build/artifacts/wamrc",
            "repository/support/apps/wamr-aot/build/artifacts/tiny.wasm",
            "repository/support/apps/wamr-aot/build/artifacts/tiny.cwasm",
            "repository/support/apps/wamr-aot/.config",
            "repository/support/apps/wamr-aot/build/artifacts/identity.json",
            "repository/support/apps/wamr-aot/build/image-identity.json",
        };
        for (source_paths, 0..) |path, i|
            try self.put(try std.fmt.allocPrint(a, "source/{s}", .{path}), try std.fmt.allocPrint(a, "{s}\x00\xff\n", .{layout.artifact_names_v2[i]}));
        try self.put("source/runtime/evidence/runtime-cleanup.txt", "primary=0 cleanup=0\n");
        try self.put("source/runtime/inputs/tool", "fixture-tool\x00\xff\n");
        try self.put("source/runtime/inputs/tree/data", "fixture-tree-data\n");
        for (profile.production_modes) |mode| {
            inline for (.{ "serial", "request", "report" }) |part|
                try self.put(try std.fmt.allocPrint(a, "source/runtime/compute/boot-{s}/{s}", .{ @tagName(mode), if (std.mem.eql(u8, part, "serial")) "hyperv-efi-boot.log" else part ++ ".json" }), try fixtureJson(a, .{ .mode = @tagName(mode), .part = part }));
        }
        var accepted = try self.capture();
        defer accepted.deinit();
        try self.put("controller-records.json", try accepted.handoffV1());
    }

    fn begin(self: *ExportFixture, faults: native_export.Faults) !native_export.AcceptedRunPinned {
        const accepted = try self.capture();
        return native_export.Test.begin(.{
            .allocator = std.testing.allocator,
            .io = std.testing.io,
            .environ = fixture_environment,
            .runtime_path = self.runtime_path,
            .repository_path = self.repository_path,
            .output_path = self.output_path,
            .faults = faults,
        }, accepted);
    }

    fn capture(self: *ExportFixture) !controller.accepted_run.AcceptedRun {
        const io = std.testing.io;
        var accepted = try controller.accepted_run.Fixture.capture(std.testing.allocator, io, self.runtime_path, self.repository_path);
        errdefer accepted.deinit();
        const a = accepted.arena.allocator();
        const tool_path = try std.fs.path.join(a, &.{ self.runtime_path, "inputs/tool" });
        const tree_path = try std.fs.path.join(a, &.{ self.runtime_path, "inputs/tree" });
        const tool = try controller.custody_files.readFile(io, tool_path, 64 * 1024, false);
        const tree = try controller.input_custody.tree(a, io, .{ .role = "fixture-tree", .path = tree_path });
        const selected = try a.alloc(controller.accepted_run.PinnedInput, 2);
        selected[0] = .{ .role = "fixture-tool", .path = tool_path, .snapshot = .{
            .bytes = tool.bytes,
            .sha256 = tool.sha256,
            .metadata = tool.metadata,
        } };
        selected[1] = .{ .role = "tree:fixture-tree", .path = tree_path, .snapshot = .{
            .bytes = tree.bytes,
            .sha256 = tree.content_sha256,
            .metadata = controller.custody_files.metadata(try controller.custody_files.directory(io, tree_path, false)),
            .tree = .{ .files = tree.files, .directories = tree.directories, .symlinks = tree.symlinks, .physical_sha256 = tree.physical_sha256 },
        } };
        accepted.runtime_inputs = selected;
        return accepted;
    }

    fn put(self: *ExportFixture, path: []const u8, bytes: []const u8) !void {
        var parent = try testEnsureParent(std.testing.io, self.root, path);
        defer parent.close(std.testing.io);
        try writeFile(std.testing.io, parent.dir, std.fs.path.basename(path), bytes);
    }
    fn noBundle(self: *ExportFixture) !void {
        try std.testing.expectError(error.FileNotFound, self.root.openFile(std.testing.io, "handoff/bundle.json", .{ .follow_symlinks = false }));
    }
    fn replaceIdentical(self: *ExportFixture, relative: []const u8) !void {
        const io = std.testing.io;
        const file = try self.root.openFile(io, relative, .{ .follow_symlinks = false });
        const size = (try file.stat(io)).size;
        const bytes = try self.arena.allocator().alloc(u8, @intCast(size));
        try std.testing.expectEqual(bytes.len, try file.readPositionalAll(io, bytes, 0));
        file.close(io);
        try self.root.rename(relative, self.root, "replaced-original", io);
        try self.put(relative, bytes);
    }
    fn deinit(self: *ExportFixture) void {
        self.root.close(std.testing.io);
        self.arena.deinit();
        self.copy_fixture.deinit();
        self.* = undefined;
    }
};

fn fixtureJson(a: std.mem.Allocator, value: anytype) ![]const u8 {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(raw);
    return controller.records.canonicalAlloc(a, raw);
}

const CopyFixture = struct {
    rel_path: []const u8,
    source_path: []const u8,
    second_source_path: []const u8,
    output_path: []const u8,
    source_dir: std.Io.Dir,
    output: core.private_files.Directory,

    fn init(label: []const u8) !CopyFixture {
        const a = std.testing.allocator;
        const io = std.testing.io;
        var fixture_root = try std.Io.Dir.openDirAbsolute(io, test_options.fixture_root, .{ .iterate = true });
        defer fixture_root.close(io);
        try fixture_root.createDirPath(io, "handoff-export-tests");
        var parent = try fixture_root.openDir(io, "handoff-export-tests", .{ .iterate = true });
        defer parent.close(io);
        copy_fixture_counter += 1;
        const leaf = try std.fmt.allocPrint(a, "{s}-{d}-{d}", .{ label, std.os.linux.getpid(), copy_fixture_counter });
        defer a.free(leaf);
        try parent.createDir(io, leaf, .fromMode(0o700));
        const rel_path = try std.fs.path.join(a, &.{ test_options.fixture_root, "handoff-export-tests", leaf });
        var root = try parent.openDir(io, leaf, .{ .iterate = true });
        defer root.close(io);
        try root.createDir(io, "source", .fromMode(0o700));
        try root.createDir(io, "output", .fromMode(0o700));
        const source_dir = try root.openDir(io, "source", .{ .iterate = true });
        const root_path = try std.Io.Dir.cwd().realPathFileAlloc(io, rel_path, a);
        defer a.free(root_path);
        const source_path = try std.fs.path.join(a, &.{ root_path, "source/input.bin" });
        const second_source_path = try std.fs.path.join(a, &.{ root_path, "source/second.bin" });
        const output_path = try std.fs.path.join(a, &.{ root_path, "output" });
        const output = try core.private_files.Directory.open(io, output_path);
        return .{
            .rel_path = rel_path,
            .source_path = source_path,
            .second_source_path = second_source_path,
            .output_path = output_path,
            .source_dir = source_dir,
            .output = output,
        };
    }

    fn deinit(self: *CopyFixture) void {
        const a = std.testing.allocator;
        const io = std.testing.io;
        self.output.close(io);
        self.source_dir.close(io);
        std.Io.Dir.cwd().deleteTree(io, self.rel_path) catch @panic("handoff copy fixture cleanup failed");
        a.free(self.rel_path);
        a.free(self.source_path);
        a.free(self.second_source_path);
        a.free(self.output_path);
        self.* = undefined;
    }

    fn writeSource(self: *CopyFixture, name: []const u8, bytes: []const u8) !void {
        try writeFile(std.testing.io, self.source_dir, name, bytes);
    }

    fn writeOutput(self: *CopyFixture, relative: []const u8, bytes: []const u8) !void {
        var parent = try testEnsureParent(std.testing.io, self.output.dir, relative);
        defer parent.close(std.testing.io);
        try writeFile(std.testing.io, parent.dir, std.fs.path.basename(relative), bytes);
    }

    fn readOutput(self: *CopyFixture, relative: []const u8, limit: usize) ![]const u8 {
        const path = try std.fs.path.join(std.testing.allocator, &.{ self.output_path, relative });
        defer std.testing.allocator.free(path);
        const file = try std.Io.Dir.openFileAbsolute(std.testing.io, path, .{ .mode = .read_only, .follow_symlinks = false });
        defer file.close(std.testing.io);
        const stat = try file.stat(std.testing.io);
        if (stat.size > limit) return error.FileTooLarge;
        const data = try std.testing.allocator.alloc(u8, @intCast(stat.size));
        errdefer std.testing.allocator.free(data);
        try std.testing.expectEqual(data.len, try file.readPositionalAll(std.testing.io, data, 0));
        return data;
    }
};

const TestParent = struct {
    dir: std.Io.Dir,
    close_dir: bool,

    fn close(self: *TestParent, io: std.Io) void {
        if (self.close_dir) self.dir.close(io);
        self.* = undefined;
    }
};

fn testEnsureParent(io: std.Io, root: std.Io.Dir, relative: []const u8) !TestParent {
    var parts = std.mem.splitScalar(u8, relative, '/');
    var component = parts.next() orelse return error.InvalidPath;
    var current = root;
    var close_current = false;
    errdefer if (close_current) current.close(io);
    while (parts.next()) |next| {
        current.createDir(io, component, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const child = try current.openDir(io, component, .{ .iterate = true, .follow_symlinks = false });
        if (close_current) current.close(io);
        current = child;
        close_current = true;
        component = next;
    }
    return .{ .dir = current, .close_dir = close_current };
}

fn writeFile(io: std.Io, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try dir.createFile(io, name, .{
        .exclusive = true,
        .read = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
    try file.sync(io);
    try (std.Io.File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}
