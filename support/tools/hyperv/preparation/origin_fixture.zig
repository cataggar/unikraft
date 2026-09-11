//! Explicitly synthetic witnesses for focused fixtures. They establish no
//! authentication or archive membership of any actual installed distribution.
const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const o = @import("origin.zig");
pub const tree: c.Tree = .{ .sha256 = "1".* ** 64, .files = 1, .bytes = 128 };
pub fn local() o.Origin {
    return .{ .payload = .{ .local_build = .{
        .source_revision = "1" ** 40,
        .source_physical_sha256 = c.digest("public synthetic source SHAPE only"),
        .compiler_executable_sha256 = c.digest("public synthetic compiler SHAPE only"),
    } } };
}
pub fn shapeDistribution() o.Origin {
    return .{ .payload = .{ .distribution = .{
        .runtime_revision = c.compiler_version,
        .evidence_set_sha256 = c.digest("no physical evidence: shape only"),
        .components = &.{.{ .artifact_id = "synthetic", .scope = .{ .whole = .{} }, .selected_tree = tree }},
    } } };
}
pub fn shapePackage() o.Origin {
    return .{ .payload = .{ .zig_packages = .{ .packages = &.{.{
        .package_hash = @import("provenance.zig").miz_package_hash,
        .locator = "git+https://github.com/cataggar/miz.git#" ++ c.miz_revision,
        .revision = .{ .git_commit = c.miz_revision },
        .declaration = .{
            .directory = .{ .path = "/synthetic/manifest", .device = 1, .inode = 1, .mode = 0o40700, .uid = 1000 },
            .file = .{ .path = "build.zig.zon", .sha256 = "2".* ** 64, .mode = 0o644, .size = 128 },
            .entry = "miz_source",
        },
        .scope = .{ .whole = .{} },
        .selected_tree = tree,
    }} } } };
}
pub fn write(allocator: std.mem.Allocator, io: std.Io, root: fs.Directory, path: []const u8, bytes: []const u8) !c.File {
    const file = try root.dir.createFile(io, path, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    return root.record(allocator, io, path, 1024 * 1024 * 1024, .artifact);
}
pub fn distribution(allocator: std.mem.Allocator, io: std.Io, root: fs.Directory) !struct { origin: o.Origin, evidence: []const o.Binding } {
    const path = try std.fmt.allocPrint(allocator, "{s}-origin-evidence", .{root.path});
    try std.Io.Dir.cwd().createDir(io, path, .fromMode(0o700));
    const evidence = try fs.Directory.open(allocator, io, path);
    defer evidence.close(allocator, io);
    const selected = (try fs.inventory(allocator, io, root, 100000, 4 * 1024 * 1024 * 1024)).tree;
    const subject: o.Subject = .{
        .publisher = "synthetic.invalid",
        .repository = "fixture-channel",
        .asset_id = "synthetic",
        .locator = "https://synthetic.invalid/package",
        .revision = c.compiler_version,
        .artifact_sha256 = c.digest("synthetic archive; not an actual distribution"),
    };
    const transcript = try write(allocator, io, evidence, "transcript.txt", "SYNTHETIC ONLY: no acquisition, verification or real archive evidence.\n");
    const metadata = try write(allocator, io, evidence, "metadata.json", "{}\n");
    const acquisition: o.Acquisition = .{
        .schema = .hyperv_origin_https_acquisition_v1,
        .subject_sha256 = try o.hash(allocator, subject),
        .metadata_sha256 = metadata.sha256,
        .url = "https://synthetic.invalid/metadata",
        .tls_peer_name = "synthetic.invalid",
        .tls_peer_certificate_sha256 = c.digest("synthetic TLS peer"),
        .acquired_at = "2001-01-01T00:00:00Z",
        .transport_evidence = transcript,
    };
    const authentication: o.Authentication = .{ .publisher_https_sha256 = .{
        .subject = subject,
        .metadata = metadata,
        .metadata_url = acquisition.url,
        .acquisition = try write(allocator, io, evidence, "acquisition.json", try c.canonical(allocator, acquisition)),
    } };
    const maps = try allocator.alloc(o.Map, 1);
    maps[0] = .{ .tree = .{ .member_prefix = "", .destination_prefix = "", .tree = selected } };
    const payload: o.RealizationPayload = .{ .unchanged_extraction = .{ .artifact_sha256 = subject.artifact_sha256, .selected_tree = selected, .maps = maps } };
    const verification: o.ArchiveVerification = .{
        .schema = .hyperv_origin_archive_verification_v1,
        .artifact_sha256 = subject.artifact_sha256,
        .realization_payload_sha256 = try o.hash(allocator, payload),
        .verifier = .{ .name = "synthetic-fixture", .version = "shape-only", .executable_sha256 = c.digest("synthetic verifier"), .transcript = transcript },
    };
    const verified = try write(allocator, io, evidence, "realization.json", try c.canonical(allocator, verification));
    const catalog: o.Catalog = .{
        .schema = .hyperv_runtime_origin_evidence_v1,
        .artifacts = &.{.{ .id = "synthetic", .subject = subject, .authentication = authentication, .realizations = &.{.{ .payload = payload, .verification = verified }} }},
    };
    const catalog_file = try write(allocator, io, evidence, "catalog.json", try c.canonical(allocator, catalog));
    const bindings = try allocator.alloc(o.Binding, 1);
    const policy = try allocator.alloc(o.Policy, 1);
    const verifications = try allocator.alloc(c.Sha, 1);
    verifications[0] = verified.sha256;
    policy[0] = .{
        .artifact_id = "synthetic",
        .authority = .{ .publisher_https_sha256 = .{ .publisher = subject.publisher, .repository = subject.repository } },
        .authentication_sha256 = try o.hash(allocator, authentication),
        .realization_verification_sha256 = verifications,
    };
    bindings[0] = .{
        .directory = try o.Identity.directory(evidence),
        .set = .{ .tree = (try fs.inventory(allocator, io, evidence, 256, 4 * 1024 * 1024)).tree, .catalog = catalog_file },
        .physical_sha256 = try fs.physicalDigest(allocator, io, evidence),
        .policy = policy,
    };
    bindings[0].directory.path = try allocator.dupe(u8, evidence.path);
    const components = try allocator.alloc(o.Component, 1);
    components[0] = .{ .artifact_id = "synthetic", .selected_tree = selected, .scope = .{ .whole = .{} } };
    return .{
        .origin = .{ .payload = .{ .distribution = .{
            .runtime_revision = c.compiler_version,
            .evidence_set_sha256 = try o.hash(allocator, bindings[0].set),
            .components = components,
        } } },
        .evidence = bindings,
    };
}
