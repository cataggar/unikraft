// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const controller = @import("wamr_controller");
const archive = @import("public_archive.zig");
const transport = @import("public_transport.zig");
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

const Fixture = struct {
    path: []const u8,
    root: std.Io.Dir,
    source: []const u8,
    output: []const u8,
    download: []const u8,
    imported: []const u8,

    fn init(name: []const u8) !Fixture {
        const path = try std.fmt.allocPrint(a, "{s}/transport-{s}", .{ options.fixture_root, name });
        errdefer a.free(path);
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
        self.root.close(io);
        std.Io.Dir.cwd().deleteTree(io, self.path) catch {};
        inline for (.{ "path", "source", "output", "download", "imported" }) |field| a.free(@field(self, field));
        self.* = undefined;
    }
};
