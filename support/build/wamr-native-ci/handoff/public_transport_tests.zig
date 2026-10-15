// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const controller = @import("wamr_controller");
const archive = @import("public_archive.zig");
const transport = @import("public_transport.zig");
const publication = transport.publication;
const actions = transport.actions_container;
const copy = @import("retained_copy.zig");
const zip = @import("zip.zig");
const options = @import("test_options");
const a = std.testing.allocator;
const io = std.testing.io;
const v1 = @embedFile("goldens/zip-pack-v1.zip");
const v2 = @embedFile("goldens/zip-pack-v2.zip");
const revision = "0123456789012345678901234567890123456789";
const context: archive.Context = .{ .run_id = "1", .run_attempt = "1", .source_revision = revision, .source_tree = revision };
const genuine_context: archive.Context = .{
    .run_id = options.genuine_run,
    .run_attempt = options.genuine_attempt,
    .source_revision = options.genuine_source,
    .source_tree = options.genuine_tree,
};
const genuine_sha = options.genuine_sha;
const container_sha = "d1f3055c1eba55b1f21f7a78c63e8d9f8b340052f66dfc1369b53b50a33cefef";

fn expected(ctx: archive.Context, digest: [32]u8) !transport.Expected {
    return .{
        .upload = .{
            .context = ctx,
            .artifact_id = try transport.ArtifactId.parse("11356844780"),
            .container_digest = try transport.ContainerDigest.parse(container_sha),
        },
        .inner_digest = .{ .bytes = digest },
    };
}

test "transport stages only one fixed durable standalone file and refuses create-only collisions" {
    var fixture = try Fixture.init("stage");
    defer fixture.deinit();
    try fixture.write("source.zip", v2);
    var source = try archive.Archive.open(a, io, fixture.source, context, zip.sha256(v2), null);
    defer source.deinit(io);
    const result = transport.stageUpload(invocation(&fixture, &source, .none, null));
    if (result != .success) std.debug.print("transport stage: {any}\n", .{result});
    try std.testing.expect(result == .success);
    var staged = result.success;
    defer staged.deinit(io);
    try staged.revalidate(io, null);
    const bytes = try staged.directory.dir.readFileAlloc(io, transport.filename, a, .limited(v2.len + 1));
    defer a.free(bytes);
    try std.testing.expectEqualSlices(u8, v2, bytes);
    try std.testing.expectEqual(@as(u32, 0o600), staged.archive.retained.file_snapshot.mode & 0o7777);
    try std.testing.expectEqual(@as(u32, 0o700), staged.snapshot.mode & 0o7777);
    try std.testing.expectError(error.FileNotFound, staged.directory.dir.openFile(io, "upload.partial", .{}));
    const repeated = transport.stageUpload(invocation(&fixture, &source, .none, null));
    try std.testing.expect(repeated == .refused);
    try std.testing.expectEqual(error.OutputExists, repeated.refused.err);
    try staged.revalidate(io, null);
}

test "transport staging retains partial evidence and explicit uncertain publication durability" {
    for ([_]transport.Fault{
        .partial_write,      .before_file_sync,  .before_parent_sync,    .replace_partial,
        .cancel_during_copy, .cancel_after_copy, .publication_collision, .after_publication,
    }) |fault| {
        var fixture = try Fixture.init(@tagName(fault));
        defer fixture.deinit();
        try fixture.write("source.zip", v2);
        var source = try archive.Archive.open(a, io, fixture.source, context, zip.sha256(v2), null);
        defer source.deinit(io);
        var cancel: std.atomic.Value(bool) = .init(false);
        const result = transport.stageUpload(invocation(&fixture, &source, fault, &cancel));
        if (result != .poisoned) std.debug.print("transport fault {s}: {any}\n", .{ @tagName(fault), result });
        try std.testing.expect(result == .poisoned);
        const output = try std.Io.Dir.openDirAbsolute(io, fixture.output, .{ .iterate = true });
        defer output.close(io);
        if (fault == .after_publication) {
            try std.testing.expectEqual(core.private_files.CommitStatus.visible_not_durable, result.poisoned.publication);
            try std.testing.expectEqual(transport.Phase.parent_sync, result.poisoned.phase);
            const file = try output.openFile(io, transport.filename, .{});
            file.close(io);
            try std.testing.expectError(error.FileNotFound, output.openFile(io, "upload.partial", .{}));
        } else {
            try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, result.poisoned.publication);
            const file = try output.openFile(io, "upload.partial", .{});
            defer file.close(io);
            if (fault == .partial_write) try std.testing.expectEqual(@as(u64, 2), (try core.private_files.snapshot(file)).size);
            if (fault == .cancel_during_copy)
                try std.testing.expectEqual(@as(u64, @min(v2.len, 64 * 1024)), (try core.private_files.snapshot(file)).size);
            if (fault == .publication_collision) {
                const foreign = try output.readFileAlloc(io, transport.filename, a, .limited(32));
                defer a.free(foreign);
                try std.testing.expectEqualStrings("foreign", foreign);
                try std.testing.expectEqual(transport.Phase.publication, result.poisoned.phase);
            } else try std.testing.expectError(error.FileNotFound, output.openFile(io, transport.filename, .{}));
        }
        try source.revalidate(io, null);
    }
}

test "transport staging refuses changed retained inputs and wrong digest context before reservation" {
    for ([_][]const u8{ "source-replace", "source-mutate", "source-digest", "source-context" }) |kind| {
        var fixture = try Fixture.init(kind);
        defer fixture.deinit();
        try fixture.write("source.zip", v2);
        var source = try archive.Archive.open(a, io, fixture.source, context, zip.sha256(v2), null);
        defer source.deinit(io);
        var inv = invocation(&fixture, &source, .none, null);
        if (std.mem.eql(u8, kind, "source-replace")) {
            try fixture.root.renamePreserve("source.zip", fixture.root, "old.zip", io);
            try fixture.write("source.zip", v2);
        } else if (std.mem.eql(u8, kind, "source-mutate")) {
            const file = try fixture.root.openFile(io, "source.zip", .{ .mode = .read_write });
            defer file.close(io);
            try file.writePositionalAll(io, "!", 31);
            try file.sync(io);
        } else if (std.mem.eql(u8, kind, "source-digest")) {
            inv.inner_digest.bytes[0] ^= 1;
        } else inv.context.run_id = "2";
        const result = transport.stageUpload(inv);
        try std.testing.expect(result == .refused);
        try std.testing.expectEqual(transport.Phase.inputs, result.refused.phase);
        try std.testing.expectError(error.FileNotFound, fixture.root.openDir(io, "upload", .{}));
    }
}

test "transport binds independently supplied exact artifact selection and distinct container metadata" {
    var fixture = try Fixture.init("selection");
    defer fixture.deinit();
    try fixture.write("redownload/" ++ transport.filename, v2);
    const trusted = try expected(context, zip.sha256(v2));
    var selected = trusted.upload;
    selected.artifact_id = try transport.ArtifactId.parse("11356844781");
    try std.testing.expectError(error.ArtifactIdMismatch, transport.Download.open(a, io, fixture.download, trusted, .{ .upload = selected }, null));
    selected = trusted.upload;
    selected.container_digest.bytes = trusted.inner_digest.bytes;
    try std.testing.expectError(error.ContainerDigestMismatch, transport.Download.open(a, io, fixture.download, trusted, .{ .upload = selected }, null));
    inline for (.{ "run_id", "run_attempt", "source_revision", "source_tree" }) |field| {
        selected = trusted.upload;
        @field(selected.context, field) = if (comptime std.mem.startsWith(u8, field, "source")) "1123456789012345678901234567890123456789" else "2";
        try std.testing.expectError(error.ContextMismatch, transport.Download.open(a, io, fixture.download, trusted, .{ .upload = selected }, null));
    }
    var owner = try transport.Download.open(a, io, fixture.download, trusted, .{ .upload = trusted.upload }, null);
    defer owner.deinit(io);
    const receipt = try owner.receipt(a, io, null);
    defer a.free(receipt);
    var doc = try controller.handoff_contracts.parseCanonical(a, receipt);
    defer doc.deinit();
    try controller.handoff_contracts.validatePublicSourceTransportV2(doc.value());
    const fields = doc.value().object;
    try std.testing.expectEqualStrings(container_sha, fields.get("container_digest").?.string);
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(zip.sha256(v2), .lower), fields.get("inner_zip_sha256").?.string);
    try std.testing.expectEqual(@as(usize, 10), fields.count());
}

test "transport validates inner source run and digest even when upload selection metadata agrees" {
    var fixture = try Fixture.init("inner");
    defer fixture.deinit();
    try fixture.write("redownload/" ++ transport.filename, v2);
    var trusted = try expected(context, zip.sha256(v2));
    trusted.inner_digest.bytes[0] ^= 1;
    try std.testing.expectError(error.DigestMismatch, transport.Download.open(a, io, fixture.download, trusted, .{ .upload = trusted.upload }, null));
    inline for (.{ "run_id", "run_attempt", "source_revision", "source_tree" }) |field| {
        trusted = try expected(context, zip.sha256(v2));
        @field(trusted.upload.context, field) = if (comptime std.mem.startsWith(u8, field, "source")) "1123456789012345678901234567890123456789" else "2";
        try std.testing.expectError(error.ContextMismatch, transport.Download.open(a, io, fixture.download, trusted, .{ .upload = trusted.upload }, null));
    }
    inline for (.{ "", "0", "01", "-1", "1,2", "1/2", "123456789012345678901" }) |id|
        try std.testing.expectError(error.InvalidArtifactId, transport.ArtifactId.parse(id));
    trusted = try expected(context, zip.sha256(v2));
    trusted.upload.artifact_id.len = 255;
    try std.testing.expectError(error.InvalidArtifactId, transport.Download.open(a, io, fixture.download, trusted, .{ .upload = trusted.upload }, null));
}

test "transport exact download directory refuses extras case path links and directories" {
    for ([_][]const u8{ "empty", "extra", "case", "nested", "symlink", "hardlink", "directory", "fifo" }) |kind| {
        var fixture = try Fixture.init(kind);
        defer fixture.deinit();
        if (std.mem.eql(u8, kind, "case")) {
            try fixture.write("redownload/Tiny-aot-public-source.zip", v2);
        } else if (std.mem.eql(u8, kind, "nested")) {
            try fixture.root.createDir(io, "redownload/nested", .fromMode(0o700));
            try fixture.write("redownload/nested/" ++ transport.filename, v2);
        } else if (std.mem.eql(u8, kind, "symlink")) {
            try fixture.write("source.zip", v2);
            try fixture.root.symLink(io, "../source.zip", "redownload/" ++ transport.filename, .{});
        } else if (std.mem.eql(u8, kind, "directory")) {
            try fixture.root.createDir(io, "redownload/" ++ transport.filename, .fromMode(0o700));
        } else if (std.mem.eql(u8, kind, "fifo")) {
            if (std.os.linux.errno(std.os.linux.mknodat(fixture.root.handle, "redownload/" ++ transport.filename, std.os.linux.S.IFIFO | 0o600, 0)) != .SUCCESS)
                return error.FixtureFifo;
        } else if (!std.mem.eql(u8, kind, "empty")) {
            try fixture.write("redownload/" ++ transport.filename, v2);
            if (std.mem.eql(u8, kind, "extra")) try fixture.write("redownload/extra", "x");
            if (std.mem.eql(u8, kind, "hardlink")) {
                if (std.os.linux.errno(std.os.linux.linkat(fixture.root.handle, "redownload/" ++ transport.filename, fixture.root.handle, "other.zip", 0)) != .SUCCESS)
                    return error.FixtureLink;
            }
        }
        const trusted = try expected(context, zip.sha256(v2));
        if (transport.Download.open(a, io, fixture.download, trusted, .{ .upload = trusted.upload }, null)) |value| {
            var owner = value;
            owner.deinit(io);
            return error.UnsafeDownloadAccepted;
        } else |err| {
            try std.testing.expectEqual(if (std.mem.eql(u8, kind, "hardlink")) error.UnsafeSource else error.InvalidDownloadMembers, err);
        }
    }
}

test "transport refuses linked directory paths and nonprivate exact download roots" {
    var fixture = try Fixture.init("root");
    defer fixture.deinit();
    try fixture.write("redownload/" ++ transport.filename, v2);
    const trusted = try expected(context, zip.sha256(v2));
    try fixture.root.symLink(io, "redownload", "alias", .{ .is_directory = true });
    const alias = try std.fs.path.join(a, &.{ fixture.path, "alias" });
    defer a.free(alias);
    if (transport.Download.open(a, io, alias, trusted, .{ .upload = trusted.upload }, null)) |value| {
        var owner = value;
        owner.deinit(io);
        return error.LinkedRootAccepted;
    } else |_| {}
    if (std.os.linux.errno(std.os.linux.fchmodat(fixture.root.handle, "redownload", 0o755)) != .SUCCESS)
        return error.FixtureMode;
    if (transport.Download.open(a, io, fixture.download, trusted, .{ .upload = trusted.upload }, null)) |value| {
        var owner = value;
        owner.deinit(io);
        return error.PublicRootAccepted;
    } else |_| {}
}

test "transport live revalidation refuses identical replacement mutation and transient extra members" {
    for ([_][]const u8{ "replace", "mutate", "transient", "extra", "root-replace" }) |kind| {
        var fixture = try Fixture.init(kind);
        defer fixture.deinit();
        try fixture.write("redownload/" ++ transport.filename, v2);
        const trusted = try expected(context, zip.sha256(v2));
        var owner = try transport.Download.open(a, io, fixture.download, trusted, .{ .upload = trusted.upload }, null);
        defer owner.deinit(io);
        if (std.mem.eql(u8, kind, "replace")) {
            try fixture.root.renamePreserve("redownload/" ++ transport.filename, fixture.root, "old.zip", io);
            try fixture.write("redownload/" ++ transport.filename, v2);
        } else if (std.mem.eql(u8, kind, "mutate")) {
            const file = try fixture.root.openFile(io, "redownload/" ++ transport.filename, .{ .mode = .read_write });
            defer file.close(io);
            try file.writePositionalAll(io, "!", 31);
            try file.sync(io);
        } else if (std.mem.eql(u8, kind, "root-replace")) {
            try fixture.root.renamePreserve("redownload", fixture.root, "old-root", io);
            try fixture.root.createDir(io, "redownload", .fromMode(0o700));
            try fixture.write("redownload/" ++ transport.filename, v2);
        } else {
            try fixture.write("redownload/extra", "x");
            if (std.mem.eql(u8, kind, "transient")) try fixture.root.deleteFile(io, "redownload/extra");
        }
        if (owner.revalidate(io, null)) |_| return error.ChangedDownloadAccepted else |_| {}
        if (owner.receipt(a, io, null)) |bytes| {
            a.free(bytes);
            return error.ChangedReceiptAccepted;
        } else |_| {}
        try std.testing.expectError(error.FileNotFound, fixture.root.openFile(io, "imported/bundle.json", .{}));
    }
}

test "transport cancellation refuses before reservation binding receipt and materialization" {
    var fixture = try Fixture.init("cancel");
    defer fixture.deinit();
    try fixture.write("source.zip", v2);
    try fixture.write("redownload/" ++ transport.filename, v2);
    var source = try archive.Archive.open(a, io, fixture.source, context, zip.sha256(v2), null);
    defer source.deinit(io);
    var cancel: std.atomic.Value(bool) = .init(true);
    const result = transport.stageUpload(invocation(&fixture, &source, .none, &cancel));
    try std.testing.expect(result == .refused);
    try std.testing.expectEqual(error.Cancelled, result.refused.err);
    try std.testing.expectError(error.FileNotFound, fixture.root.openDir(io, "upload", .{}));
    const trusted = try expected(context, zip.sha256(v2));
    try std.testing.expectError(error.Cancelled, transport.Download.open(a, io, fixture.download, trusted, .{ .upload = trusted.upload }, &cancel));
    var owner = try transport.Download.open(a, io, fixture.download, trusted, .{ .upload = trusted.upload }, null);
    defer owner.deinit(io);
    try std.testing.expectError(error.Cancelled, owner.receipt(a, io, &cancel));
    try std.testing.expectError(error.Cancelled, owner.materialize(io, fixture.imported, &cancel));
    try std.testing.expectError(error.FileNotFound, fixture.root.openDir(io, "imported", .{}));
}

test "transport never adds v2 artifact metadata to historical v1" {
    var fixture = try Fixture.init("v1");
    defer fixture.deinit();
    try fixture.write("redownload/" ++ transport.filename, v1);
    const trusted = try expected(context, zip.sha256(v1));
    try std.testing.expectError(error.TransportRequiresV2, transport.Download.open(a, io, fixture.download, trusted, .{ .upload = trusted.upload }, null));
}

test "transport fixed member size bounds reject empty and oversized sparse files before reading" {
    for ([_]u64{ 0, controller.handoff_contracts.layout.max_total_bytes + 1 }, 0..) |size, index| {
        var fixture = try Fixture.init(if (index == 0) "empty-file" else "oversized-file");
        defer fixture.deinit();
        const file = try fixture.root.createFile(io, "redownload/" ++ transport.filename, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.setLength(io, size);
        try file.sync(io);
        try std.testing.expectEqual(size, (try core.private_files.snapshot(file)).size);
        const trusted = try expected(context, zip.sha256(v2));
        try std.testing.expectError(error.TooLarge, transport.Download.open(a, io, fixture.download, trusted, .{ .upload = trusted.upload }, null));
    }
}

test "genuine transport fixed upload native imported acceptance and canonical Python receipt parity" {
    const path = options.genuine_archive orelse return error.SkipZigTest;
    var fixture = try Fixture.init("genuine");
    defer fixture.deinit();
    const digest = try core.contracts.parseSha256(genuine_sha);
    var source = try archive.Archive.open(a, io, path, genuine_context, digest, null);
    defer source.deinit(io);
    var inv = invocation(&fixture, &source, .none, null);
    inv.context = genuine_context;
    inv.inner_digest.bytes = digest;
    const result = transport.stageUpload(inv);
    if (result != .success) std.debug.print("genuine transport: {any}\n", .{result});
    try std.testing.expect(result == .success);
    var staged = result.success;
    defer staged.deinit(io);
    try std.testing.expectEqual(options.genuine_bytes, staged.archive.retained.file_snapshot.size);
    try std.testing.expectEqual(@as(usize, 83), staged.archive.metadata.selected.len);
    var trusted = try expected(genuine_context, digest);
    trusted.upload.artifact_id = try transport.ArtifactId.parse(options.genuine_artifact_id);
    trusted.upload.container_digest = try transport.ContainerDigest.parse(options.genuine_container_sha);
    var owner = try transport.Download.open(a, io, fixture.output, trusted, .{ .upload = trusted.upload }, null);
    defer owner.deinit(io);
    const receipt = try owner.receipt(a, io, null);
    defer a.free(receipt);
    if (std.mem.eql(u8, options.genuine_source, "c8f45aefcb855480605830ea47a8990c72d0fda3") and
        std.mem.eql(u8, options.genuine_run, "37321447300") and
        std.mem.eql(u8, options.genuine_artifact_id, "11356844780"))
    {
        const historical_receipt =
            "{\"artifact_id\":\"11356844780\",\"container_digest\":\"" ++ container_sha ++
            "\",\"inner_zip_sha256\":\"269d0c17d48ac5c722d79774f6b399bd56d8b8e68f9d2ff24f827deab63c27c4" ++
            "\",\"repository\":\"cataggar/unikraft\",\"run_attempt\":\"1\",\"run_id\":\"37321447300\"," ++
            "\"schema\":\"uk.wamr.public-source-transport\",\"source_revision\":\"c8f45aefcb855480605830ea47a8990c72d0fda3\"," ++
            "\"source_tree\":\"47fafaddda9b4c56cba06c868c1cad0a62084c60\",\"version\":2}\n";
        try std.testing.expectEqualStrings(historical_receipt, receipt);
    }
    const oracle_path = options.python_receipt orelse return error.MissingPythonTransportReceipt;
    const oracle = try std.Io.Dir.cwd().readFileAlloc(io, oracle_path, a, .limited(controller.handoff_contracts.layout.max_json_bytes));
    defer a.free(oracle);
    try std.testing.expectEqualSlices(u8, oracle, receipt);
    try std.testing.expectError(error.OutputInsideDownload, owner.materialize(io, fixture.output, null));
    var imported = try owner.materialize(io, fixture.imported, null);
    defer imported.deinit(io);
    try std.testing.expectEqual(controller.accepted_run.EvidenceContext.trusted_inner_zip, imported.stage.accepted.context);
    try std.testing.expectEqualStrings(genuine_context.source_revision, imported.stage.accepted.source.revision);
    try imported.revalidate(io, null);
    try std.testing.expectError(error.OutputExists, owner.materialize(io, fixture.imported, null));
    for ([_][]const u8{ "bundle.json", "candidate-bundle.json", "transport.json" }) |name|
        try std.testing.expectError(error.FileNotFound, imported.stage.directory.dir.openFile(io, name, .{}));
    const file = try imported.stage.directory.dir.openFile(io, "boots/raw-x2apic/report", .{ .mode = .read_write });
    defer file.close(io);
    try file.writePositionalAll(io, "!", 0);
    try file.sync(io);
    if (imported.revalidate(io, null)) |_| return error.ChangedImportedAccepted else |_| {}
}

fn invocation(fixture: *const Fixture, source: *archive.Archive, fault: transport.Fault, cancel: ?*const std.atomic.Value(bool)) transport.Invocation {
    return .{
        .allocator = a,
        .io = io,
        .source = source,
        .context = context,
        .inner_digest = .{ .bytes = zip.sha256(v2) },
        .output_path = fixture.output,
        .fault = fault,
        .cancel = cancel,
    };
}

test "publication sealing preserves exact bytes and owner group read-only one-file product" {
    var fixture = try Fixture.init("sealed");
    defer fixture.deinit();
    try fixture.write("source.zip", v2);
    const result = publication.sealUploadForTest(sealInvocation(&fixture));
    if (result != .success) std.debug.print("sealing: {any}\n", .{result});
    try std.testing.expect(result == .success);
    var sealed = result.success;
    defer sealed.deinit(io);
    try sealed.revalidate(io, null);
    const directory = try std.Io.Dir.openDirAbsolute(io, fixture.output, .{ .iterate = true });
    defer directory.close(io);
    try transport.exactMember(io, directory);
    const snapshot = try copy.directorySnapshot(directory);
    try std.testing.expectEqual(@as(u16, 0o550), snapshot.mode & 0o7777);
    try std.testing.expectEqual(std.os.linux.geteuid(), snapshot.uid);
    try std.testing.expectEqual(std.os.linux.getegid(), snapshot.gid);
    var file = try core.private_files.RetainedFile.open(io, sealed.output.path, .artifact);
    defer file.close(io);
    try std.testing.expectEqual(@as(u16, 0o440), file.file_snapshot.mode & 0o7777);
    try std.testing.expectEqual(@as(u32, 1), file.file_snapshot.nlink);
    try std.testing.expectEqual(std.os.linux.geteuid(), file.file_snapshot.uid);
    try std.testing.expectEqual(std.os.linux.getegid(), file.file_snapshot.gid);
    const bytes = try directory.readFileAlloc(io, transport.filename, a, .limited(v2.len + 1));
    defer a.free(bytes);
    try std.testing.expectEqualSlices(u8, v2, bytes);
    try std.testing.expectEqualSlices(u8, &zip.sha256(v2), &sealed.digest);
    const repeated = publication.sealUploadForTest(sealInvocation(&fixture));
    try std.testing.expect(repeated == .refused);
    try std.testing.expectEqual(error.OutputExists, repeated.refused.err);
    try sealed.revalidate(io, null);
    try setFixtureMode(fixture.root, "upload", 0o700);
}

test "publication refuses unprivileged invocation unsafe source custody and wrong commitments before reservation" {
    for ([_][]const u8{ "privilege", "uid", "gid", "mode", "hardlink", "symlink", "digest", "context", "cancel" }) |kind| {
        const name = try a.print("seal-input-{s}", .{kind});
        defer a.free(name);
        var fixture = try Fixture.init(name);
        defer fixture.deinit();
        try fixture.write("source.zip", v2);
        var inv = sealInvocation(&fixture);
        var cancel: std.atomic.Value(bool) = .init(true);
        if (std.mem.eql(u8, kind, "uid")) inv.source_uid += 1;
        if (std.mem.eql(u8, kind, "gid")) inv.source_gid += 1;
        if (std.mem.eql(u8, kind, "mode")) try setFixtureMode(fixture.root, "source.zip", 0o640);
        if (std.mem.eql(u8, kind, "hardlink"))
            if (std.os.linux.errno(std.os.linux.linkat(fixture.root.handle, "source.zip", fixture.root.handle, "other.zip", 0)) != .SUCCESS)
                return error.FixtureLink;
        if (std.mem.eql(u8, kind, "symlink")) {
            try fixture.root.renamePreserve("source.zip", fixture.root, "actual.zip", io);
            try fixture.root.symLink(io, "actual.zip", "source.zip", .{});
        }
        if (std.mem.eql(u8, kind, "digest")) inv.inner_digest.bytes[0] ^= 1;
        if (std.mem.eql(u8, kind, "context")) inv.context.run_attempt = "2";
        if (std.mem.eql(u8, kind, "cancel")) inv.cancel = &cancel;
        const result = if (std.mem.eql(u8, kind, "privilege")) publication.sealUpload(inv) else publication.sealUploadForTest(inv);
        try std.testing.expect(result == .refused);
        if (std.mem.eql(u8, kind, "privilege"))
            try std.testing.expectEqual(error.PrivilegeRequired, result.refused.err);
        try std.testing.expectEqual(publication.Phase.inputs, result.refused.phase);
        try std.testing.expectError(error.FileNotFound, fixture.root.openDir(io, "upload", .{}));
    }
}

test "publication faults retain evidence and refuse source destination replacement cancellation and uncertain sync" {
    for ([_]publication.Fault{
        .partial_write,         .source_mutation,    .source_replacement, .destination_replacement,
        .publication_collision, .cancel_during_copy, .before_file_sync,   .after_publication,
    }) |fault| {
        const name = try a.print("seal-fault-{s}", .{@tagName(fault)});
        defer a.free(name);
        var fixture = try Fixture.init(name);
        defer fixture.deinit();
        try fixture.write("source.zip", v2);
        var inv = sealInvocation(&fixture);
        inv.fault = fault;
        var cancel: std.atomic.Value(bool) = .init(false);
        inv.cancel = &cancel;
        const result = publication.sealUploadForTest(inv);
        if (result != .poisoned) std.debug.print("seal fault {s}: {any}\n", .{ @tagName(fault), result });
        try std.testing.expect(result == .poisoned);
        const output = try fixture.root.openDir(io, "upload", .{ .iterate = true });
        defer output.close(io);
        if (fault == .after_publication) {
            try std.testing.expectEqual(core.private_files.CommitStatus.visible_not_durable, result.poisoned.publication);
            const file = try output.openFile(io, transport.filename, .{});
            file.close(io);
        } else {
            try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, result.poisoned.publication);
            const file = try output.openFile(io, "upload.partial", .{});
            file.close(io);
            if (fault == .publication_collision) {
                const bytes = try output.readFileAlloc(io, transport.filename, a, .limited(16));
                defer a.free(bytes);
                try std.testing.expectEqualStrings("foreign", bytes);
            } else try std.testing.expectError(error.FileNotFound, output.openFile(io, transport.filename, .{}));
        }
    }
}

test "sealed upload live custody refuses same-byte replacement directory replacement links and extra members" {
    for ([_][]const u8{ "source-replace", "output-replace", "root-replace", "ancestor-mode", "extra", "transient", "output-link" }) |kind| {
        const name = try a.print("seal-live-{s}", .{kind});
        defer a.free(name);
        var fixture = try Fixture.init(name);
        defer fixture.deinit();
        try fixture.write("source.zip", v2);
        const result = publication.sealUploadForTest(sealInvocation(&fixture));
        try std.testing.expect(result == .success);
        var sealed = result.success;
        defer sealed.deinit(io);
        try setFixtureMode(fixture.root, "upload", 0o700);
        if (std.mem.eql(u8, kind, "source-replace")) {
            try fixture.root.renamePreserve("source.zip", fixture.root, "old-source.zip", io);
            try fixture.write("source.zip", v2);
        } else if (std.mem.eql(u8, kind, "output-replace")) {
            try fixture.root.renamePreserve("upload/" ++ transport.filename, fixture.root, "old-output", io);
            try fixture.write("upload/" ++ transport.filename, v2);
            try setFixtureMode(fixture.root, "upload/" ++ transport.filename, 0o440);
        } else if (std.mem.eql(u8, kind, "root-replace")) {
            try fixture.root.renamePreserve("upload", fixture.root, "old-root", io);
            try fixture.root.createDir(io, "upload", .fromMode(0o700));
            try fixture.write("upload/" ++ transport.filename, v2);
            try setFixtureMode(fixture.root, "upload/" ++ transport.filename, 0o440);
        } else if (std.mem.eql(u8, kind, "ancestor-mode")) {
            if (std.os.linux.errno(std.os.linux.fchmod(fixture.root.handle, 0o755)) != .SUCCESS) return error.FixtureMode;
        } else if (std.mem.eql(u8, kind, "output-link")) {
            if (std.os.linux.errno(std.os.linux.linkat(fixture.root.handle, "upload/" ++ transport.filename, fixture.root.handle, "linked", 0)) != .SUCCESS)
                return error.FixtureLink;
        } else {
            try fixture.write("upload/extra", "x");
            if (std.mem.eql(u8, kind, "transient")) try fixture.root.deleteFile(io, "upload/extra");
        }
        try setFixtureMode(fixture.root, "upload", 0o550);
        if (sealed.revalidate(io, null)) |_| return error.ChangedSealAccepted else |_| {}
        try setFixtureMode(fixture.root, "upload", 0o700);
        if (std.os.linux.errno(std.os.linux.fchmod(fixture.root.handle, 0o700)) != .SUCCESS) return error.FixtureMode;
    }
}

test "Actions raw container independently binds commitments and extracts stored and deflated descriptor bytes" {
    for ([_]u16{ 0, 8 }) |method| {
        var fixture = try Fixture.init(if (method == 0) "actions-stored" else "actions-deflated");
        defer fixture.deinit();
        const outer = try outerContainer(method, method == 8, false);
        defer a.free(outer);
        try fixture.write("source.zip", outer);
        const inv = try actionsInvocation(&fixture, outer);
        const result = actions.retainDownload(inv);
        if (result != .success) std.debug.print("Actions extraction: {any}\n", .{result});
        try std.testing.expect(result == .success);
        var retained = result.success;
        defer retained.deinit(io);
        try retained.revalidate(io, null);
        const bytes = try retained.download.standalone.directory.dir.readFileAlloc(io, transport.filename, a, .limited(v2.len + 1));
        defer a.free(bytes);
        try std.testing.expectEqualSlices(u8, v2, bytes);
        try std.testing.expectEqual(@as(u16, 0o700), retained.download.standalone.snapshot.mode & 0o7777);
        try std.testing.expectEqual(@as(u16, 0o600), retained.download.standalone.archive.retained.file_snapshot.mode & 0o7777);
        try std.testing.expect(!std.mem.eql(u8, &inv.expected.inner_digest.bytes, &inv.expected.upload.container_digest.bytes));
        const repeated = actions.retainDownload(inv);
        try std.testing.expect(repeated == .refused);
        try std.testing.expectEqual(error.OutputExists, repeated.refused.err);
        const original = try fixture.root.readFileAlloc(io, "source.zip", a, .limited(outer.len + 1));
        defer a.free(original);
        try std.testing.expectEqualSlices(u8, outer, original);
    }
}

test "Actions extraction refuses wrong selection missing raw and independently wrong inner digest" {
    for ([_][]const u8{ "artifact", "attempt", "selected-container", "container", "inner", "missing", "cancel" }) |kind| {
        const name = try a.print("actions-input-{s}", .{kind});
        defer a.free(name);
        var fixture = try Fixture.init(name);
        defer fixture.deinit();
        const outer = try outerContainer(0, false, false);
        defer a.free(outer);
        if (!std.mem.eql(u8, kind, "missing")) try fixture.write("source.zip", outer);
        var inv = try actionsInvocation(&fixture, outer);
        var cancel: std.atomic.Value(bool) = .init(true);
        if (std.mem.eql(u8, kind, "artifact")) inv.selection.upload.artifact_id = try transport.ArtifactId.parse("2");
        if (std.mem.eql(u8, kind, "attempt")) inv.selection.upload.context.run_attempt = "2";
        if (std.mem.eql(u8, kind, "selected-container")) inv.selection.upload.container_digest.bytes = inv.expected.inner_digest.bytes;
        if (std.mem.eql(u8, kind, "container")) {
            inv.expected.upload.container_digest.bytes[0] ^= 1;
            inv.selection.upload.container_digest = inv.expected.upload.container_digest;
        }

        if (std.mem.eql(u8, kind, "inner")) inv.expected.inner_digest.bytes[0] ^= 1;
        if (std.mem.eql(u8, kind, "cancel")) inv.cancel = &cancel;
        const result = actions.retainDownload(inv);
        try std.testing.expect(result == .refused);
        try std.testing.expectError(error.FileNotFound, fixture.root.openDir(io, "upload", .{}));
    }
}

test "publication adapters refuse sparse oversized and empty inputs before reading or reservation" {
    for ([_]bool{ false, true }) |sealing| {
        for ([_]bool{ false, true }) |oversized| {
            var fixture = try Fixture.init(if (sealing)
                (if (oversized) "seal-oversized" else "seal-empty")
            else
                (if (oversized) "actions-oversized" else "actions-empty"));
            defer fixture.deinit();
            const file = try fixture.root.createFile(io, "source.zip", .{ .exclusive = true, .permissions = .fromMode(0o600) });
            defer file.close(io);
            const bound = if (sealing) controller.handoff_contracts.layout.max_total_bytes else actions.max_container_bytes;
            try file.setLength(io, if (oversized) bound + 1 else 0);
            try file.sync(io);
            if (sealing) {
                const result = publication.sealUploadForTest(sealInvocation(&fixture));
                try std.testing.expect(result == .refused);
                try std.testing.expectEqual(error.UnsafeSource, result.refused.err);
            } else {
                const result = actions.retainDownload(try actionsInvocation(&fixture, v2));
                try std.testing.expect(result == .refused);
                try std.testing.expectEqual(error.TooLarge, result.refused.err);
            }
            try std.testing.expectError(error.FileNotFound, fixture.root.openDir(io, "upload", .{}));
        }
    }
}

test "Actions outer profile refuses duplicate extra path encrypted link zip64 truncated bad deflate and trailing codecs" {
    for ([_][]const u8{ "duplicate", "extra", "path", "encrypted", "link", "zip64", "truncated", "codec", "deflate", "crc", "descriptor", "deflate-trailing", "comment" }) |kind| {
        const name = try a.print("actions-format-{s}", .{kind});
        defer a.free(name);
        var fixture = try Fixture.init(name);
        defer fixture.deinit();
        const deflated = std.mem.startsWith(u8, kind, "deflate");
        const outer = try outerContainer(if (deflated) 8 else 0, std.mem.eql(u8, kind, "descriptor"), std.mem.eql(u8, kind, "deflate-trailing"));
        defer a.free(outer);
        const end = outer.len - 22;
        const central = std.mem.readInt(u32, outer[end + 16 ..][0..4], .little);
        if (std.mem.eql(u8, kind, "duplicate") or std.mem.eql(u8, kind, "extra")) {
            set16(outer, end + 8, 2);
            set16(outer, end + 10, 2);
        } else if (std.mem.eql(u8, kind, "path")) {
            outer[30] = '/';
        } else if (std.mem.eql(u8, kind, "encrypted")) {
            set16(outer, central + 8, 1);
        } else if (std.mem.eql(u8, kind, "link")) {
            set32(outer, central + 38, @as(u32, 0o120777) << 16);
        } else if (std.mem.eql(u8, kind, "zip64")) {
            set16(outer, central + 6, 45);
        } else if (std.mem.eql(u8, kind, "codec")) {
            set16(outer, central + 10, 9);
        } else if (std.mem.eql(u8, kind, "deflate")) {
            outer[30 + transport.filename.len] = 7;
        } else if (std.mem.eql(u8, kind, "crc")) {
            set32(outer, 14, 0);
            set32(outer, central + 16, 0);
        } else if (std.mem.eql(u8, kind, "descriptor")) {
            outer[central - 16] ^= 1;
        } else if (std.mem.eql(u8, kind, "comment")) {
            set16(outer, end + 20, 1);
        }
        const bytes = if (std.mem.eql(u8, kind, "truncated")) outer[0 .. outer.len - 1] else outer;
        try fixture.write("source.zip", bytes);
        const inv = try actionsInvocation(&fixture, bytes);
        const result = actions.retainDownload(inv);
        if (result != .refused) std.debug.print("format {s}: {any}\n", .{ kind, result });
        try std.testing.expect(result == .refused);
        try std.testing.expectError(error.FileNotFound, fixture.root.openDir(io, "upload", .{}));
        const original = try fixture.root.readFileAlloc(io, "source.zip", a, .limited(bytes.len + 1));
        defer a.free(original);
        try std.testing.expectEqualSlices(u8, bytes, original);
    }
}

test "Actions extraction retains partial collision cancellation and uncertain publication evidence" {
    for ([_]actions.Fault{ .partial_write, .replace_partial, .raw_mutation, .raw_replacement, .publication_collision, .cancel_during_copy, .before_file_sync, .after_publication }) |fault| {
        const name = try a.print("actions-fault-{s}", .{@tagName(fault)});
        defer a.free(name);
        var fixture = try Fixture.init(name);
        defer fixture.deinit();
        const outer = try outerContainer(8, true, false);
        defer a.free(outer);
        try fixture.write("source.zip", outer);
        var inv = try actionsInvocation(&fixture, outer);
        inv.fault = fault;
        var cancel: std.atomic.Value(bool) = .init(false);
        inv.cancel = &cancel;
        const result = actions.retainDownload(inv);
        try std.testing.expect(result == .poisoned);
        try std.testing.expectEqual(if (fault == .after_publication)
            core.private_files.CommitStatus.visible_not_durable
        else
            core.private_files.CommitStatus.not_committed, result.poisoned.publication);
        const output = try fixture.root.openDir(io, "upload", .{});
        defer output.close(io);
        const partial = try output.openFile(io, if (fault == .after_publication) transport.filename else "download.partial", .{});
        partial.close(io);
        if (fault == .publication_collision) {
            const bytes = try output.readFileAlloc(io, transport.filename, a, .limited(16));
            defer a.free(bytes);
            try std.testing.expectEqualStrings("foreign", bytes);
        }
    }
}

test "Actions retained raw owner refuses replacement mutation links and independently changed output" {
    for ([_][]const u8{ "raw-replace", "raw-mutate", "raw-link", "output-replace" }) |kind| {
        const name = try a.print("actions-live-{s}", .{kind});
        defer a.free(name);
        var fixture = try Fixture.init(name);
        defer fixture.deinit();
        const outer = try outerContainer(0, false, false);
        defer a.free(outer);
        try fixture.write("source.zip", outer);
        const result = actions.retainDownload(try actionsInvocation(&fixture, outer));
        try std.testing.expect(result == .success);
        var retained = result.success;
        defer retained.deinit(io);
        if (std.mem.eql(u8, kind, "raw-replace")) {
            try fixture.root.renamePreserve("source.zip", fixture.root, "old-container.zip", io);
            try fixture.write("source.zip", outer);
        } else if (std.mem.eql(u8, kind, "raw-mutate")) {
            const file = try fixture.root.openFile(io, "source.zip", .{ .mode = .read_write });
            defer file.close(io);
            try file.writePositionalAll(io, "!", 0);
        } else if (std.mem.eql(u8, kind, "raw-link")) {
            if (std.os.linux.errno(std.os.linux.linkat(fixture.root.handle, "source.zip", fixture.root.handle, "other-container.zip", 0)) != .SUCCESS)
                return error.FixtureLink;
        } else {
            try fixture.root.renamePreserve("upload/" ++ transport.filename, fixture.root, "old-inner.zip", io);
            try fixture.write("upload/" ++ transport.filename, v2);
        }
        if (retained.revalidate(io, null)) |_| return error.ChangedContainerAccepted else |_| {}
    }
}

test "publication adapter CLI closes privilege arguments and keeps selected run identity independent" {
    const cli = controller.cli;
    const digest = "0123456789012345678901234567890123456789012345678901234567890123";
    const retain = [_][]const u8{
        "uk-wamr-native-ci",           "retain-public-source-download",
        "--container-archive",         "/private/container.zip",
        "--output",                    "/private/inner",
        "--expected-source",           revision,
        "--expected-tree",             revision,
        "--run-id",                    "1",
        "--run-attempt",               "1",
        "--expected-archive-sha256",   digest,
        "--artifact-id",               "123",
        "--container-digest",          digest,
        "--selected-artifact-id",      "124",
        "--selected-container-digest", digest,
        "--selected-source",           revision,
        "--selected-tree",             revision,
        "--selected-run-id",           "2",
        "--selected-run-attempt",      "3",
    };
    const parsed = try cli.parse(&retain);
    try std.testing.expectEqualStrings("1", parsed.run_id.?);
    try std.testing.expectEqualStrings("2", parsed.selected_run_id.?);
    try std.testing.expectEqualStrings("3", parsed.selected_run_attempt.?);
    try std.testing.expectEqualStrings("123", parsed.artifact_id.?);
    try std.testing.expectEqualStrings("124", parsed.selected_artifact_id.?);
    try std.testing.expectError(error.InvalidUsage, cli.parse(retain[0 .. retain.len - 2]));
    var changed = retain;
    changed[22] = "--artifact-id";
    try std.testing.expectError(error.InvalidUsage, cli.parse(&changed));
    changed = retain;
    changed[3] = "/private/../container.zip";
    try std.testing.expectError(error.InvalidUsage, cli.parse(&changed));
    const seal = [_][]const u8{
        "uk-wamr-native-ci",         "seal-public-source-upload", "--archive",       "/private/source.zip",
        "--output",                  "/protected/upload",         "--source-uid",    "1000",
        "--source-gid",              "1000",                      "--upload-gid",    "1000",
        "--expected-source",         revision,                    "--expected-tree", revision,
        "--run-id",                  "1",                         "--run-attempt",   "1",
        "--expected-archive-sha256", digest,
    };
    _ = try cli.parse(&seal);
    try std.testing.expectError(error.InvalidUsage, cli.parse(seal[0..10]));
    for ([_][]const u8{ "01", "-1", "4294967295", "4294967296" }) |id| {
        var unsafe = seal;
        unsafe[7] = id;
        try std.testing.expectError(error.InvalidUsage, cli.parse(&unsafe));
    }
    var not_seal = seal;
    not_seal[1] = "stage-public-source-upload";
    try std.testing.expectError(error.InvalidUsage, cli.parse(&not_seal));
}

fn sealInvocation(fixture: *const Fixture) publication.Invocation {
    return .{
        .allocator = a,
        .io = io,
        .source_path = fixture.source,
        .source_uid = std.os.linux.geteuid(),
        .source_gid = std.os.linux.getegid(),
        .upload_gid = std.os.linux.getegid(),
        .output_path = fixture.output,
        .context = context,
        .inner_digest = .{ .bytes = zip.sha256(v2) },
    };
}

fn actionsInvocation(fixture: *const Fixture, bytes: []const u8) !actions.Invocation {
    var trusted = try expected(context, zip.sha256(v2));
    trusted.upload.container_digest.bytes = zip.sha256(bytes);
    return .{
        .allocator = a,
        .io = io,
        .container_path = fixture.source,
        .output_path = fixture.output,
        .expected = trusted,
        .selection = .{ .upload = trusted.upload },
    };
}

fn setFixtureMode(directory: std.Io.Dir, name: [:0]const u8, mode: u32) !void {
    if (std.os.linux.errno(std.os.linux.fchmodat(directory.handle, name, mode)) != .SUCCESS) return error.FixtureMode;
}

fn outerContainer(method: u16, descriptor: bool, trailing: bool) ![]u8 {
    const data = 30 + transport.filename.len;
    const compressed = v2.len + (if (method == 8) @as(usize, 5) else 0) + (if (trailing) @as(usize, 1) else 0);
    const central = data + compressed + (if (descriptor) @as(usize, 16) else 0);
    const end = central + 46 + transport.filename.len;
    const bytes = try a.alloc(u8, end + 22);
    @memset(bytes, 0);
    set32(bytes, 0, 0x04034b50);
    set16(bytes, 4, 20);
    set16(bytes, 6, if (descriptor) 8 else 0);
    set16(bytes, 8, method);
    set16(bytes, 12, 0x21);
    if (!descriptor) {
        set32(bytes, 14, zip.crc32(v2));
        set32(bytes, 18, @intCast(compressed));
        set32(bytes, 22, v2.len);
    }
    set16(bytes, 26, transport.filename.len);
    @memcpy(bytes[30..data], transport.filename);
    if (method == 8) {
        bytes[data] = 1;
        set16(bytes, data + 1, v2.len);
        set16(bytes, data + 3, ~@as(u16, v2.len));
        @memcpy(bytes[data + 5 ..][0..v2.len], v2);
    } else @memcpy(bytes[data..][0..v2.len], v2);
    if (descriptor) {
        set32(bytes, central - 16, 0x08074b50);
        set32(bytes, central - 12, zip.crc32(v2));
        set32(bytes, central - 8, @intCast(compressed));
        set32(bytes, central - 4, v2.len);
    }
    set32(bytes, central, 0x02014b50);
    set16(bytes, central + 4, 0x0314);
    set16(bytes, central + 6, 20);
    set16(bytes, central + 8, if (descriptor) 8 else 0);
    set16(bytes, central + 10, method);
    set16(bytes, central + 14, 0x21);
    set32(bytes, central + 16, zip.crc32(v2));
    set32(bytes, central + 20, @intCast(compressed));
    set32(bytes, central + 24, v2.len);
    set16(bytes, central + 28, transport.filename.len);
    set32(bytes, central + 38, @as(u32, 0o100440) << 16);
    @memcpy(bytes[central + 46 .. end], transport.filename);
    set32(bytes, end, 0x06054b50);
    set16(bytes, end + 8, 1);
    set16(bytes, end + 10, 1);
    set32(bytes, end + 12, @intCast(end - central));
    set32(bytes, end + 16, @intCast(central));
    return bytes;
}

fn set16(bytes: []u8, offset: usize, value: u16) void {
    std.mem.writeInt(u16, bytes[offset..][0..2], value, .little);
}
fn set32(bytes: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], value, .little);
}

const Fixture = struct {
    path: []const u8,
    root: std.Io.Dir,
    source: []const u8,
    output: []const u8,
    download: []const u8,
    imported: []const u8,

    fn init(name: []const u8) !Fixture {
        const path = try a.print("{s}/transport-{s}", .{ options.fixture_root, name });
        errdefer a.free(path);
        if (std.Io.Dir.openDirAbsolute(io, path, .{ .follow_symlinks = false })) |previous| {
            defer previous.close(io);
            cleanupSeals(previous);
        } else |_| {}
        std.Io.Dir.cwd().deleteTree(io, path) catch {};
        try std.Io.Dir.cwd().createDir(io, path, .fromMode(0o700));
        const root = try std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true });
        errdefer root.close(io);
        try root.createDir(io, "redownload", .fromMode(0o700));
        const source = try std.fs.path.join(a, &.{ path, "source.zip" });
        errdefer a.free(source);
        const output = try std.fs.path.join(a, &.{ path, "upload" });
        errdefer a.free(output);
        const download = try std.fs.path.join(a, &.{ path, "redownload" });
        errdefer a.free(download);
        const imported = try std.fs.path.join(a, &.{ path, "imported" });
        return .{ .path = path, .root = root, .source = source, .output = output, .download = download, .imported = imported };
    }

    fn write(self: *const Fixture, relative: []const u8, bytes: []const u8) !void {
        const file = try self.root.createFile(io, relative, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writePositionalAll(io, bytes, 0);
        try file.sync(io);
    }

    fn deinit(self: *Fixture) void {
        cleanupSeals(self.root);
        self.root.close(io);
        std.Io.Dir.cwd().deleteTree(io, self.path) catch {};
        inline for (.{ "path", "source", "output", "download", "imported" }) |field| a.free(@field(self, field));
        self.* = undefined;
    }
};

fn cleanupSeals(root: std.Io.Dir) void {
    for ([_][]const u8{ "upload", "old-root" }) |name| {
        const directory = root.openDir(io, name, .{ .follow_symlinks = false, .iterate = true }) catch continue;
        defer directory.close(io);
        const snapshot = copy.directorySnapshot(directory) catch continue;
        if (snapshot.uid == std.os.linux.geteuid() and snapshot.mode & 0o7777 == 0o550)
            _ = std.os.linux.fchmod(directory.handle, 0o700);
    }
}
