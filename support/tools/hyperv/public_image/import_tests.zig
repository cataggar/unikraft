const std = @import("std");
const image = @import("public_image");
const c = image.contracts;
const ic = image.import_contracts;
const p = image.core.private_files;
const fixtures = @import("import_fixture.zig");
const options = @import("test_options");
const t = std.testing;
const a = t.allocator;
const io = t.io;
fn fixture() !fixtures.Fixture {
    return fixtures.Fixture.init(a, io, options.test_root orelse return error.MissingFixtureRoot);
}

test "physical import reload preserve independent source importer and source boot claims" {
    const f = try fixture();
    defer f.deinit(a);
    const result = try f.run("imported");
    if (!result.succeeded()) std.debug.print("synthetic import failure: {any}\n", .{result});
    try t.expect(result.succeeded());
    const receipt = try image.importer.load(f.a, io, try f.destination("imported"), f.expected, result.receipt_sha256.?);
    try t.expectEqualStrings(f.expected.native_producer_sha256, receipt.source_producer.sha256);
    try t.expect(!std.mem.eql(u8, receipt.source_producer.sha256, receipt.importer.executable.sha256));
    try image.files.same(f.a, f.manifest.preflight, receipt.source_boot_claims);
    try t.expectEqual(.not_admitted, receipt.authority);
    try t.expectEqual(.not_verified, receipt.attestation);
    try t.expectEqual(.source_manifest, receipt.boot_claim_origin);
    try t.expectEqualStrings(f.expected.manifest_sha256, receipt.manifest.digest.sha256);
    const dir = try p.Directory.open(io, try f.destination("imported"));
    defer dir.close(io);
    const inspection = try c.read(image.package.Inspection, f.a, try dir.read(io, f.a, ic.inspection_name, c.max_record, null));
    try t.expectEqual(@as(u64, 512), inspection.efi.size);
    try t.expectEqualStrings(f.manifest.artifacts.efi.sha256, inspection.efi.sha256);
    try t.expectEqualStrings(f.manifest.artifacts.raw.sha256, inspection.raw.sha256);
    try t.expectEqualStrings(f.manifest.artifacts.vhd.sha256, inspection.vhd.sha256);
    try t.expectError(error.FileNotFound, dir.openFile(io, "state.json"));
    try t.expectError(error.FileNotFound, dir.openFile(io, "local-raw-x2apic-serial.log"));
    const again = try f.run("imported");
    try t.expect(!again.succeeded() and again.receipt_sha256 == null);
    try t.expectEqual(.conflict, again.failures.primary.?.category);
}
test "explicit expectation mismatches and canonical manifest violations refuse before publication" {
    const f = try fixture();
    defer f.deinit(a);
    var changed = f.expected;
    changed.manifest_sha256 = "0" ** 64;
    try t.expect(!image.importer.importPrepared(f.a, io, f.artifact_path, try f.destination("digest"), changed).succeeded());
    changed = f.expected;
    changed.native_producer_sha256 = "b" ** 64;
    try t.expect(!image.importer.importPrepared(f.a, io, f.artifact_path, try f.destination("producer"), changed).succeeded());
    changed = f.expected;
    changed.source.run_attempt += 1;
    try t.expect(!image.importer.importPrepared(f.a, io, f.artifact_path, try f.destination("source"), changed).succeeded());
    for ([_][]const u8{
        "",
        " " ** (c.max_record + 1),
        try std.fmt.allocPrint(f.a, " {s}", .{f.bytes}),
        try std.fmt.allocPrint(f.a, "{{\"schema\":\"duplicate\",{s}", .{f.bytes[1..]}),
        try std.fmt.allocPrint(f.a, "{{\"authority\":true,{s}", .{f.bytes[1..]}),
        try std.mem.replaceOwned(u8, f.a, f.bytes, "\"controller_revision\":4", "\"controller_revision\":3"),
        try std.mem.replaceOwned(u8, f.a, f.bytes, "\"run_id\":456", "\"run_id\":4.56e2"),
    }, 0..) |bytes, index| {
        const expected = try f.writeManifest(bytes);
        const path = try f.destination(try std.fmt.allocPrint(f.a, "canonical-{d}", .{index}));
        const result = image.importer.importPrepared(f.a, io, f.artifact_path, path, expected);
        try t.expect(!result.succeeded() and result.destination == .not_committed);
        try t.expectError(error.FileNotFound, p.Directory.open(io, path));
    }
}
test "native import faults retain consumption and independent publication recording cleanup lanes" {
    const f = try fixture();
    defer f.deinit(a);
    inline for ([_]image.importer.TestFault{
        .destination_creation, .destination_sync,    .request,              .inspection,
        .receipt_before_sync,  .receipt_publication, .receipt_after_rename, .receipt_cleanup,
    }, 0..) |fault, index| {
        const path = try f.destination(try std.fmt.allocPrint(f.a, "fault-{d}", .{index}));
        const result = image.importer.importFault(f.a, io, f.artifact_path, path, f.expected, fault);
        try t.expect(!result.succeeded() and result.receipt_sha256 == null);
        if (fault == .destination_creation) {
            try t.expect(result.failures.primary != null);
            try t.expectEqual(.publication_unknown, result.destination);
        } else try t.expect(result.failures.recording != null);
        if (fault == .receipt_publication) try t.expectEqual(.publication_unknown, result.publication);
        if (fault == .receipt_after_rename) try t.expectEqual(.visible_not_durable, result.publication);
        if (fault == .inspection or fault == .receipt_cleanup) try t.expect(result.failures.cleanup != null);
        const reused = image.importer.importPrepared(f.a, io, f.artifact_path, path, f.expected);
        try t.expect(!reused.succeeded() and reused.failures.primary.?.category == .conflict);
        const dir = try p.Directory.open(io, path);
        defer dir.close(io);
        if (fault == .receipt_after_rename) {
            const visible = try dir.openFile(io, ic.receipt_name);
            visible.close(io);
        } else try t.expectError(error.FileNotFound, dir.openFile(io, ic.receipt_name));
    }
    const result = image.importer.importFault(f.a, io, f.artifact_path, try f.destination("changed"), f.expected, .input_changed_after_copy);
    try t.expect(!result.succeeded() and result.failures.primary.?.category == .integrity);
    const dir = try p.Directory.open(io, try f.destination("changed"));
    defer dir.close(io);
    try t.expectError(error.FileNotFound, dir.openFile(io, ic.receipt_name));
}

test "artifact exact namespace rejects extra missing symlink fifo and unsafe modes" {
    const f = try fixture();
    defer f.deinit(a);
    try f.artifact.dir.writeFile(io, .{ .sub_path = "extra", .data = "public extra", .flags = .{ .permissions = .fromMode(0o600) } });
    try t.expect(!(try f.run("extra-file")).succeeded());
    try f.artifact.dir.deleteFile(io, "extra");
    try f.artifact.dir.renamePreserve(image.manifest.name, f.dir.dir, "saved-manifest", io);
    try t.expect(!(try f.run("missing")).succeeded());
    try f.artifact.dir.symLink(io, "../saved-manifest", image.manifest.name, .{});
    try t.expect(!(try f.run("symlink-file")).succeeded());
    try f.artifact.dir.deleteFile(io, image.manifest.name);
    try t.expectEqual(.SUCCESS, std.os.linux.errno(std.os.linux.mknodat(f.artifact.dir.handle, image.manifest.name, std.os.linux.S.IFIFO | 0o600, 0)));
    try t.expect(!(try f.run("fifo")).succeeded());
    try f.artifact.dir.deleteFile(io, image.manifest.name);
    try f.dir.dir.renamePreserve("saved-manifest", f.artifact.dir, image.manifest.name, io);
    const manifest_file = try f.artifact.dir.openFile(io, image.manifest.name, .{ .mode = .read_write });
    defer manifest_file.close(io);
    for ([_]u16{ 0o666, 0o755, 0o4600 }) |mode| {
        try manifest_file.setPermissions(io, .fromMode(mode));
        try t.expect(!(try f.run("bad-mode")).succeeded());
    }
    try manifest_file.setPermissions(io, .fromMode(0o644));
    try t.expectEqual(.SUCCESS, std.os.linux.errno(std.os.linux.linkat(f.artifact.dir.handle, image.manifest.name, f.dir.dir.handle, "manifest-hardlink", 0)));
    try t.expect(!(try f.run("hardlink-file")).succeeded());
    try f.dir.dir.deleteFile(io, "manifest-hardlink");
    try f.artifact.dir.setPermissions(io, .fromMode(0o777));
    try t.expect(!(try f.run("writable-directory")).succeeded());
    try f.artifact.dir.setPermissions(io, .fromMode(0o700));
    try f.dir.dir.symLink(io, "artifact", "artifact-link", .{ .is_directory = true });
    try t.expect(!image.importer.importPrepared(f.a, io, try f.destination("artifact-link"), try f.destination("symlink-directory"), f.expected).succeeded());
    try f.dir.dir.createDir(io, "holder", .fromMode(0o700));
    try f.dir.dir.symLink(io, "..", "holder/alias", .{ .is_directory = true });
    const alias = try f.destination("holder/alias/artifact");
    try t.expect(!image.importer.importPrepared(f.a, io, alias, try f.destination("symlink-ancestor"), f.expected).succeeded());
}

test "publication refuses altered copied records and suppresses late durable receipt success" {
    const f = try fixture();
    defer f.deinit(a);
    for ([_]image.importer.TestFault{ .copied_manifest, .inspection_record, .request_after_receipt, .receipt_record }, 0..) |fault, index| {
        const path = try f.destination(try std.fmt.allocPrint(f.a, "record-mutation-{d}", .{index}));
        const result = image.importer.importFault(f.a, io, f.artifact_path, path, f.expected, fault);
        try t.expect(!result.succeeded() and result.receipt_sha256 == null);
        try t.expectEqual(.integrity, result.failures.primary.?.category);
        try t.expectEqual(.durable, result.destination);
        const after_publication = fault == .request_after_receipt or fault == .receipt_record;
        const publication: p.CommitStatus = if (after_publication) .durable else .not_committed;
        try t.expectEqual(publication, result.publication);
        const dir = try p.Directory.open(io, path);
        defer dir.close(io);
        if (after_publication) {
            const retained = try dir.openFile(io, ic.receipt_name);
            retained.close(io);
        } else try t.expectError(error.FileNotFound, dir.openFile(io, ic.receipt_name));
        const reused = image.importer.importPrepared(f.a, io, f.artifact_path, path, f.expected);
        try t.expect(!reused.succeeded() and reused.failures.primary.?.category == .conflict);
    }
}

test "output reuse within-input paths and aliased ancestry cannot mutate the artifact" {
    const f = try fixture();
    defer f.deinit(a);
    const before = try image.files.record(f.a, io, try image.files.path(f.a, f.artifact_path, ic.image_name), c.vhd_bytes, false);
    for ([_][]const u8{
        f.artifact_path,                                           try image.files.path(f.a, f.artifact_path, "child"),
        try image.files.path(f.a, f.artifact_path, ic.image_name), try std.fmt.allocPrint(f.a, "{s}/../alias", .{f.artifact_path}),
    }) |target| try t.expect(!image.importer.importPrepared(f.a, io, f.artifact_path, target, f.expected).succeeded());
    try f.dir.dir.symLink(io, "artifact", "output-link", .{ .is_directory = true });
    try t.expect(!image.importer.importPrepared(f.a, io, f.artifact_path, try f.destination("output-link/child"), f.expected).succeeded());
    try image.files.verify(f.a, io, before, c.vhd_bytes, false);
    const path = try f.destination("empty-existing");
    const existing = try image.files.create(io, path);
    defer existing.close(io);
    try t.expect(!image.importer.importPrepared(f.a, io, f.artifact_path, path, f.expected).succeeded());
}

fn checksumFooter(bytes: *[512]u8) void {
    @memset(bytes[64..68], 0);
    var sum: u32 = 0;
    for (bytes) |byte| sum +%= byte;
    std.mem.writeInt(u32, bytes[64..68], ~sum, .big);
}
test "coherent hashes cannot excuse corrupted footer GPT EFI or logical size" {
    const f = try fixture();
    defer f.deinit(a);
    const disk = try f.artifact.dir.openFile(io, ic.image_name, .{ .mode = .read_write });
    defer disk.close(io);
    var footer: [512]u8 = undefined;
    try t.expectEqual(footer.len, try disk.readPositionalAll(io, &footer, c.raw_bytes));
    for (0..2) |kind| {
        var malformed = footer;
        malformed[if (kind == 0) 64 else 68] ^= 1;
        if (kind == 1) checksumFooter(&malformed);
        try disk.writePositionalAll(io, &malformed, c.raw_bytes);
        const expected = try f.coherentImage(f.manifest);
        const result = image.importer.importPrepared(f.a, io, f.artifact_path, try f.destination(try std.fmt.allocPrint(f.a, "footer-{d}", .{kind})), expected);
        try t.expect(!result.succeeded() and result.destination == .not_committed);
    }
    try disk.writePositionalAll(io, &footer, c.raw_bytes);
    var gpt: [1]u8 = undefined;
    _ = try disk.readPositionalAll(io, &gpt, 512);
    try disk.writePositionalAll(io, &.{gpt[0] ^ 1}, 512);
    var expected = try f.coherentImage(f.manifest);
    try t.expect(!image.importer.importPrepared(f.a, io, f.artifact_path, try f.destination("gpt"), expected).succeeded());
    try disk.writePositionalAll(io, &gpt, 512);
    const efi_at = try f.efiOffset();
    var changed_efi = fixtures.syntheticEfi();
    changed_efi[256] ^= 1;
    try disk.writePositionalAll(io, &changed_efi, efi_at);
    expected = try f.coherentImage(f.manifest);
    try t.expect(!image.importer.importPrepared(f.a, io, f.artifact_path, try f.destination("efi-digest"), expected).succeeded());
    var coherent = f.manifest;
    coherent.artifacts.efi.sha256 = try c.hex(f.a, c.hash(&changed_efi));
    coherent.packaging.@"boot-file-sha256" = coherent.artifacts.efi.sha256;
    expected = try f.coherentImage(coherent);
    try t.expect(!image.importer.importPrepared(f.a, io, f.artifact_path, try f.destination("efi-identity"), expected).succeeded());
    try disk.writePositionalAll(io, &fixtures.syntheticEfi(), efi_at);
    _ = try f.writeManifest(f.bytes);
    for ([_]i64{ c.vhd_bytes - 1, c.vhd_bytes + 1 }) |size| {
        try t.expectEqual(.SUCCESS, std.os.linux.errno(std.os.linux.ftruncate(disk.handle, size)));
        try t.expect(!(try f.run("size")).succeeded());
    }
}

test "reload requires separately retained receipt digest and the original physical namespace" {
    const f = try fixture();
    defer f.deinit(a);
    const result = try f.run("loaded");
    try t.expect(result.succeeded());
    const path = try f.destination("loaded");
    try t.expectError(error.HashMismatch, image.importer.load(f.a, io, path, f.expected, [_]u8{0} ** 32));
    var wrong = f.expected;
    wrong.native_producer_sha256 = "b" ** 64;
    if (image.importer.load(f.a, io, path, wrong, result.receipt_sha256.?)) |_| return error.AcceptedWrongProducer else |_| {}
    const root = try p.Directory.open(io, path);
    defer root.close(io);
    var locked = try root.lock(io);
    try t.expectError(error.WouldBlock, image.importer.load(f.a, io, path, f.expected, result.receipt_sha256.?));
    locked.close(io);
    const alias = try image.files.create(io, try f.destination("copied-import"));
    defer alias.close(io);
    for (ic.output_names) |name| {
        if (std.mem.eql(u8, name, ".writer.lock")) {
            try alias.dir.writeFile(io, .{ .sub_path = name, .data = "", .flags = .{ .permissions = .fromMode(0o600) } });
        } else try image.files.copy(io, try image.files.record(f.a, io, try image.files.path(f.a, path, name), c.vhd_bytes, false), alias, name);
    }
    if (image.importer.load(f.a, io, try f.destination("copied-import"), f.expected, result.receipt_sha256.?)) |_| return error.AcceptedCopiedReceipt else |_| {}
    // Reload has no dependency on the original artifact directory or its paths.
    try f.artifact.dir.deleteFile(io, image.manifest.name);
    try f.artifact.dir.deleteFile(io, ic.image_name);
    _ = try image.importer.load(f.a, io, path, f.expected, result.receipt_sha256.?);
}

test "reloader rejects each later byte metadata namespace and receipt commitment mutation" {
    const f = try fixture();
    defer f.deinit(a);
    for ([_][]const u8{ image.manifest.name, ic.image_name, ic.inspection_name, ic.request_name, ic.receipt_name, ".writer.lock" }, 0..) |name, index| {
        const label = try std.fmt.allocPrint(f.a, "mutation-{d}", .{index});
        const result = try f.run(label);
        try t.expect(result.succeeded());
        const root = try p.Directory.open(io, try f.destination(label));
        defer root.close(io);
        const file = try root.dir.openFile(io, name, .{ .mode = .read_write });
        defer file.close(io);
        try file.writePositionalAll(io, "changed", 0);
        if (image.importer.load(f.a, io, try f.destination(label), f.expected, result.receipt_sha256.?)) |_| return error.AcceptedMutation else |_| {}
    }
    for (0..3) |kind| {
        const label = try std.fmt.allocPrint(f.a, "namespace-{d}", .{kind});
        const imported = try f.run(label);
        try t.expect(imported.succeeded());
        const changed = try p.Directory.open(io, try f.destination(label));
        defer changed.close(io);
        if (kind == 0) {
            try fixtures.rewrite(io, changed, "extra.json", "{}");
        } else {
            try changed.dir.deleteFile(io, ic.inspection_name);
            if (kind == 2) try changed.dir.symLink(io, ic.request_name, ic.inspection_name, .{});
        }
        if (image.importer.load(f.a, io, try f.destination(label), f.expected, imported.receipt_sha256.?)) |_| return error.AcceptedNamespaceMutation else |_| {}
    }
    const result = try f.run("metadata");
    try t.expect(result.succeeded());
    const root = try p.Directory.open(io, try f.destination("metadata"));
    defer root.close(io);
    const file = try root.openFile(io, ic.image_name);
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o644));
    if (image.importer.load(f.a, io, try f.destination("metadata"), f.expected, result.receipt_sha256.?)) |_| return error.AcceptedPublicCopy else |_| {}
    try file.setPermissions(io, .fromMode(0o600));
    if (image.importer.load(f.a, io, try f.destination("metadata"), f.expected, result.receipt_sha256.?)) |_| return error.AcceptedChangedMetadata else |_| {}
}

test "coherent receipt changes cannot manufacture admitted phase producer claims or inspection" {
    const f = try fixture();
    defer f.deinit(a);
    const result = try f.run("receipt");
    try t.expect(result.succeeded());
    const path = try f.destination("receipt");
    const root = try p.Directory.open(io, path);
    defer root.close(io);
    const bytes = try root.read(io, f.a, ic.receipt_name, c.max_record, result.receipt_sha256);
    for ([_][]const u8{
        try std.mem.replaceOwned(u8, f.a, bytes, "\"phase\":\"imported\"", "\"phase\":\"prepared\""),
        try std.mem.replaceOwned(u8, f.a, bytes, "\"authority\":\"not_admitted\"", "\"authority\":\"admitted\""),
        try std.mem.replaceOwned(u8, f.a, bytes, "\"boot_claim_origin\":\"source_manifest\"", "\"boot_claim_origin\":\"local_observation\""),
        try std.mem.replaceOwned(u8, f.a, bytes, "\"io_ready\":false", "\"io_ready\":true"),
    }) |changed| {
        try fixtures.rewrite(io, root, ic.receipt_name, changed);
        if (image.importer.load(f.a, io, path, f.expected, c.hash(changed))) |_| return error.AcceptedCoherentReceipt else |_| {}
    }
    var receipt = try c.read(ic.Receipt, f.a, bytes);
    receipt.importer.executable.sha256 = f.expected.native_producer_sha256;
    const wrong_importer = try c.encode(f.a, receipt);
    try fixtures.rewrite(io, root, ic.receipt_name, wrong_importer);
    if (image.importer.load(f.a, io, path, f.expected, c.hash(wrong_importer))) |_| return error.AcceptedImporterSubstitution else |_| {}
    receipt = try c.read(ic.Receipt, f.a, bytes);
    receipt.image.digest.sha256 = "b" ** 64;
    const wrong_commitment = try c.encode(f.a, receipt);
    try fixtures.rewrite(io, root, ic.receipt_name, wrong_commitment);
    if (image.importer.load(f.a, io, path, f.expected, c.hash(wrong_commitment))) |_| return error.AcceptedPhysicalCommitment else |_| {}
    var inspection = try c.read(image.package.Inspection, f.a, try root.read(io, f.a, ic.inspection_name, c.max_record, null));
    inspection.footer_sha256 = "b" ** 64;
    const altered_inspection = try c.encode(f.a, inspection);
    try fixtures.rewrite(io, root, ic.inspection_name, altered_inspection);
    const inspected = try root.openFile(io, ic.inspection_name);
    defer inspected.close(io);
    const stat = try p.snapshot(inspected);
    receipt = try c.read(ic.Receipt, f.a, bytes);
    receipt.inspection.digest = .{ .size = stat.size, .sha256 = try c.hex(f.a, c.hash(altered_inspection)) };
    receipt.inspection.modified_seconds = stat.mtime.sec;
    receipt.inspection.modified_nanoseconds = stat.mtime.nsec;
    receipt.inspection.changed_seconds = stat.ctime.sec;
    receipt.inspection.changed_nanoseconds = stat.ctime.nsec;
    const coherent_inspection_receipt = try c.encode(f.a, receipt);
    try fixtures.rewrite(io, root, ic.receipt_name, coherent_inspection_receipt);
    try t.expectError(error.RecordMismatch, image.importer.load(f.a, io, path, f.expected, c.hash(coherent_inspection_receipt)));
}

test "network acceptance and boot claims remain source assertions not local observations" {
    const f = try fixture();
    defer f.deinit(a);
    var manifest = f.manifest;
    manifest.acceptance = try image.network.fromConfig(f.a, "CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION=y\n" ++
        "CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4=\"10.77.0.20\"\n" ++
        "CONFIG_APPHYPERVACCEPTANCE_PEER_TCP_PORT=42001\n" ++
        "CONFIG_APPHYPERVACCEPTANCE_PEER_UDP_PORT=42002\n" ++
        "CONFIG_APPHYPERVACCEPTANCE_NONCE=\"0123456789abcdef\"\n");
    manifest.preflight = try image.manifest.preflight(f.a, c.platform_marker, manifest.acceptance);
    const expected = try f.writeManifest(try c.encode(f.a, manifest));
    const path = try f.destination("network-claims");
    const result = image.importer.importPrepared(f.a, io, f.artifact_path, path, expected);
    try t.expect(result.succeeded());
    const receipt = try image.importer.load(f.a, io, path, expected, result.receipt_sha256.?);
    try image.files.same(f.a, manifest.acceptance, receipt.acceptance);
    try image.files.same(f.a, manifest.preflight, receipt.source_boot_claims);
    try t.expectEqual(.source_manifest, receipt.boot_claim_origin);
    try t.expectEqual(.not_verified, receipt.attestation);
    try t.expectEqual(.not_admitted, receipt.authority);
}

fn cli(f: fixtures.Fixture, args: []const []const u8) !std.process.RunResult {
    var env: std.process.Environ.Map = .init(f.a);
    defer env.deinit();
    try env.put("TMPDIR", f.path);
    return std.process.run(f.a, io, .{ .argv = args, .cwd = .{ .dir = f.dir.dir }, .environ_map = &env, .stdout_limit = .limited(c.max_record), .stderr_limit = .limited(c.max_record) });
}
fn expectedArgs(f: fixtures.Fixture) [18][]const u8 {
    return .{
        "--expected-manifest-sha256", f.expected.manifest_sha256,   "--expected-producer-sha256", f.expected.native_producer_sha256,
        "--expected-repository",      fixtures.source.repository,   "--expected-repository-id",   "123",
        "--expected-workflow-ref",    fixtures.source.workflow_ref, "--expected-job",             fixtures.source.job,
        "--expected-run-id",          "456",                        "--expected-run-attempt",     "1",
        "--expected-head-sha",        fixtures.source.head_sha,
    };
}
test "native CLI requires independently supplied artifact and receipt expectations" {
    const f = try fixture();
    defer f.deinit(a);
    const executable = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, f.a);
    const path = try f.destination("cli-import");
    const expected_args = expectedArgs(f);
    const prefix = [_][]const u8{ executable, "import-prepared", "--state-dir", path, "--artifact-dir", f.artifact_path };
    for (0..expected_args.len / 2) |omitted| {
        const args = try std.mem.concat(f.a, []const u8, &.{ &prefix, expected_args[0 .. omitted * 2], expected_args[(omitted + 1) * 2 ..] });
        const failed = try cli(f, args);
        try t.expect(failed.term == .exited and failed.term.exited != 0 and failed.stdout.len == 0);
        try t.expect(std.mem.indexOf(u8, failed.stderr, f.path) == null);
    }
    const passed = try cli(f, try std.mem.concat(f.a, []const u8, &.{ &prefix, &expected_args }));
    try t.expect(passed.term == .exited and passed.term.exited == 0 and passed.stderr.len == 0);
    var parsed = try image.core.contracts.Document.parse(f.a, passed.stdout, .{ .bytes = c.max_record });
    defer parsed.deinit();
    const digest = try image.core.contracts.string(parsed.value().object.get("receipt_sha256").?);
    const validate_args = [_][]const u8{ executable, "validate-import", "--state-dir", path };
    const missing_receipt = try cli(f, try std.mem.concat(f.a, []const u8, &.{ &validate_args, &expected_args }));
    try t.expect(missing_receipt.term == .exited and missing_receipt.term.exited != 0);
    const loaded = try cli(f, try std.mem.concat(f.a, []const u8, &.{ &validate_args, &expected_args, &.{ "--expected-import-sha256", digest } }));
    try t.expect(loaded.term == .exited and loaded.term.exited == 0);
    try t.expect(std.mem.indexOf(u8, loaded.stdout, "\"authority\":\"not_admitted\"") != null);
    try t.expect(std.mem.indexOf(u8, loaded.stdout, "\"attestation\":\"not_verified\"") != null);
    const override = try cli(f, try std.mem.concat(f.a, []const u8, &.{ &prefix, &expected_args, &.{ "--trust-artifact", "true" } }));
    try t.expect(override.term == .exited and override.term.exited != 0);
    // API reload cannot silently pretend its different test executable was the importer.
    if (image.importer.load(f.a, io, path, f.expected, try c.sha(digest))) |_| return error.AcceptedDifferentImporter else |_| {}
}

test "delivery failure keeps operation certainty and first failures without the command allocator" {
    const completed: ic.Result = .{ .destination = .durable, .publication = .durable, .receipt_sha256 = c.hash("synthetic receipt") };
    const failed: ic.Result = .{
        .destination = .durable,
        .publication = .publication_unknown,
        .failures = .{
            .primary = .{ .stage = .inspection, .category = .integrity },
            .cleanup = .{ .stage = .cleanup, .category = .cleanup_failed },
            .recording = .{ .stage = .state_record, .category = .output_limit },
        },
    };
    for ([_]ic.Result{ completed, failed }) |original| {
        try t.expectError(error.OutOfMemory, original.encode(std.testing.failing_allocator));
        const delivery = original.deliveryFailed();
        try t.expectEqual(original.destination, delivery.destination);
        try t.expectEqual(original.publication, delivery.publication);
        try t.expectEqualDeep(original.failures.primary, delivery.failures.primary);
        try t.expectEqualDeep(original.failures.cleanup, delivery.failures.cleanup);
        if (original.failures.recording != null) {
            try t.expectEqualDeep(original.failures.recording, delivery.failures.recording);
        } else {
            try t.expectEqual(.state_record, delivery.failures.recording.?.stage);
            try t.expectEqual(.local_io, delivery.failures.recording.?.category);
        }
        try t.expect(!delivery.succeeded() and delivery.receipt_sha256 == null);
        var storage: [c.max_record]u8 = undefined;
        var fallback = std.heap.FixedBufferAllocator.init(&storage);
        const bytes = try delivery.encode(fallback.allocator());
        var document = try image.core.contracts.Document.parse(a, bytes, .{ .bytes = c.max_record });
        defer document.deinit();
        try document.requireCanonical(a, bytes);
        try t.expect(document.value().object.get("receipt_sha256").? == .null);
    }
}

fn cliOutputFailure(f: fixtures.Fixture, args: []const []const u8, sink: std.Io.File, stream: enum { stdout, stderr }) !std.process.RunResult {
    var env: std.process.Environ.Map = .init(f.a);
    defer env.deinit();
    try env.put("TMPDIR", f.path);
    var child = try std.process.spawn(io, .{
        .argv = args,
        .cwd = .{ .dir = f.dir.dir },
        .environ_map = &env,
        .stdin = .ignore,
        .stdout = if (stream == .stdout) .{ .file = sink } else .pipe,
        .stderr = if (stream == .stderr) .{ .file = sink } else .pipe,
    });
    defer child.kill(io);
    var buffer: std.Io.File.MultiReader.Buffer(1) = undefined;
    var reader: std.Io.File.MultiReader = undefined;
    reader.init(f.a, io, buffer.toStreams(), &.{if (stream == .stdout) child.stderr.? else child.stdout.?});
    defer reader.deinit();
    const deadline: std.Io.Timeout = .{ .deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(120) }) };
    while (reader.fill(256, deadline)) |_| {
        if (reader.reader(0).buffered().len > c.max_record) return error.StreamTooLong;
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => return err,
    }
    try reader.checkAnyError();
    const term = try child.wait(io);
    const captured = try reader.toOwnedSlice(0);
    return .{ .term = term, .stdout = if (stream == .stderr) captured else &.{}, .stderr = if (stream == .stdout) captured else &.{} };
}

fn deliveryReport(f: fixtures.Fixture, result: std.process.RunResult) !std.json.ObjectMap {
    try t.expect(result.term == .exited and result.term.exited == 3);
    try t.expectEqual(@as(usize, 0), result.stdout.len);
    var document = try image.core.contracts.Document.parse(f.a, result.stderr, .{ .bytes = c.max_record });
    defer document.deinit();
    try document.requireCanonical(f.a, result.stderr);
    const value = try std.json.parseFromSliceLeaky(std.json.Value, f.a, result.stderr, .{});
    const object = value.object;
    try t.expectEqualStrings("public_local_import_only", object.get("scope").?.string);
    try t.expectEqualStrings("not_admitted", object.get("authority").?.string);
    try t.expectEqualStrings("not_verified", object.get("attestation").?.string);
    try t.expect(object.get("receipt_sha256").? == .null);
    const failures = object.get("failures").?.object;
    try t.expect(failures.get("primary").? == .null and failures.get("cleanup").? == .null);
    const recording = failures.get("recording").?.object;
    try t.expectEqualStrings("state_record", recording.get("stage").?.string);
    try t.expectEqualStrings("local_io", recording.get("category").?.string);
    try t.expect(std.mem.indexOf(u8, result.stderr, f.path) == null);
    return object;
}

test "real full and broken stdout retain durable import evidence and output failure exit status" {
    const f = try fixture();
    defer f.deinit(a);
    const executable = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, f.a);
    const expected_args = expectedArgs(f);
    const full = try std.Io.Dir.openFileAbsolute(io, "/dev/full", .{ .mode = .write_only });
    defer full.close(io);
    var descriptors: [2]std.os.linux.fd_t = undefined;
    try t.expectEqual(.SUCCESS, std.os.linux.errno(std.os.linux.pipe2(&descriptors, .{ .CLOEXEC = true })));
    const broken: std.Io.File = .{ .handle = descriptors[1], .flags = .{ .nonblocking = false } };
    defer broken.close(io);
    (std.Io.File{ .handle = descriptors[0], .flags = .{ .nonblocking = false } }).close(io);
    for ([_]std.Io.File{ full, broken }, 0..) |sink, index| {
        const path = try f.destination(try std.fmt.allocPrint(f.a, "failed-delivery-{d}", .{index}));
        const args = try std.mem.concat(f.a, []const u8, &.{ &.{ executable, "import-prepared", "--state-dir", path, "--artifact-dir", f.artifact_path }, &expected_args });
        const report = try deliveryReport(f, try cliOutputFailure(f, args, sink, .stdout));
        try t.expect(!report.get("succeeded").?.bool);
        try t.expectEqualStrings("durable", report.get("destination").?.string);
        try t.expectEqualStrings("durable", report.get("publication").?.string);
        const root = try p.Directory.open(io, path);
        defer root.close(io);
        const receipt_bytes = try root.read(io, f.a, ic.receipt_name, c.max_record, null);
        const receipt = try c.read(ic.Receipt, f.a, receipt_bytes);
        try t.expectEqual(.imported, receipt.phase);
        try t.expectEqualStrings(f.expected.manifest_sha256, receipt.manifest.digest.sha256);
        try t.expectEqualStrings(f.manifest.artifacts.vhd.sha256, receipt.image.digest.sha256);
        const disk = try root.openFile(io, ic.image_name);
        defer disk.close(io);
        _ = try image.package.inspectVhd(f.a, io, disk, .{
            .efi = try c.sha(f.manifest.artifacts.efi.sha256),
            .raw = try c.sha(f.manifest.artifacts.raw.sha256),
            .vhd = try c.sha(f.manifest.artifacts.vhd.sha256),
        });
        // A second invocation is a real conflict; losing its error output must
        // still exit 3, never replay or alter the already durable import.
        const conflict = try cli(f, args);
        try t.expect(conflict.term == .exited and conflict.term.exited == 1);
        try t.expect(std.mem.indexOf(u8, conflict.stderr, "\"category\":\"conflict\"") != null);
        const failed_conflict = try cliOutputFailure(f, args, full, .stderr);
        try t.expect(failed_conflict.term == .exited and failed_conflict.term.exited == 3 and failed_conflict.stdout.len == 0);
        try t.expectEqualStrings(receipt_bytes, try root.read(io, f.a, ic.receipt_name, c.max_record, null));
    }

    // Validation uses only a separately successful import's delivered digest.
    const path = try f.destination("successful-delivery");
    const imported = try cli(f, try std.mem.concat(f.a, []const u8, &.{ &.{ executable, "import-prepared", "--state-dir", path, "--artifact-dir", f.artifact_path }, &expected_args }));
    try t.expect(imported.term == .exited and imported.term.exited == 0);
    const value = try std.json.parseFromSliceLeaky(std.json.Value, f.a, imported.stdout, .{});
    const digest = value.object.get("receipt_sha256").?.string;
    const args = try std.mem.concat(f.a, []const u8, &.{ &.{ executable, "validate-import", "--state-dir", path, "--expected-import-sha256", digest }, &expected_args });
    const validated = try deliveryReport(f, try cliOutputFailure(f, args, full, .stdout));
    try t.expect(validated.get("validated").?.bool);
    try t.expect(!validated.contains("destination") and !validated.contains("publication"));
    const delivered = try cli(f, args);
    try t.expect(delivered.term == .exited and delivered.term.exited == 0);
    const validation = try std.json.parseFromSliceLeaky(std.json.Value, f.a, delivered.stdout, .{});
    try t.expectEqualStrings(digest, validation.object.get("receipt_sha256").?.string);
}
