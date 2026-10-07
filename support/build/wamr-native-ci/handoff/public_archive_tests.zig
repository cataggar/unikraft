// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const controller = @import("wamr_controller");
const contracts = controller.handoff_contracts;
const archive = @import("public_archive.zig");
const zip = @import("zip.zig");
const options = @import("test_options");
const a = std.testing.allocator;
const io = std.testing.io;
const revision = "0123456789012345678901234567890123456789";
const context: archive.Context = .{ .run_id = "1", .run_attempt = "1", .source_revision = revision, .source_tree = revision };
const genuine_context: archive.Context = .{
    .run_id = options.genuine_run,
    .run_attempt = options.genuine_attempt,
    .source_revision = options.genuine_source,
    .source_tree = options.genuine_tree,
};
const genuine_sha = options.genuine_sha;
const v1 = @embedFile("goldens/zip-pack-v1.zip");
const v2 = @embedFile("goldens/zip-pack-v2.zip");

test "public metadata preserves both Python positional profiles canonical bytes and ZIP order" {
    for ([_][]const u8{ v1, v2 }, 0..) |image, i| {
        var verified = try archive.verifyBytes(a, image, context, zip.sha256(image));
        defer verified.deinit();
        const rooted = if (i == 0) @embedFile("goldens/root-bound-v1.json") else @embedFile("goldens/root-bound-v2.json");
        var metadata = try archive.Metadata.fromRootBound(a, rooted, "/opt/wamr-handoff-golden-stage", context);
        defer metadata.deinit();
        try std.testing.expectEqualStrings(verified.bundle, metadata.bundle);
        try std.testing.expectEqualStrings(verified.manifest, metadata.manifest);
        const rebound = try verified.rootBoundBundle(a, "/opt/wamr-handoff-golden-stage");
        defer a.free(rebound);
        try std.testing.expectEqualStrings(rooted, rebound);
        var storage: [96]zip.MemberView = undefined;
        const views = try zip.indexArchive(image, &storage);
        const rebuilt = try buildZip(views);
        defer a.free(rebuilt);
        try std.testing.expectEqualSlices(u8, image, rebuilt);
        try std.testing.expectEqual(@as(usize, if (i == 0) 53 else 83), metadata.selected.len);
    }
}

test "public archive requires independently supplied source run and archive hash" {
    var wrong = context;
    wrong.run_id = "2";
    try std.testing.expectError(error.ContextMismatch, archive.verifyBytes(a, v2, wrong, zip.sha256(v2)));
    wrong = context;
    wrong.source_revision = "1123456789012345678901234567890123456789";
    try std.testing.expectError(error.ContextMismatch, archive.verifyBytes(a, v2, wrong, zip.sha256(v2)));
    wrong = context;
    wrong.source_tree = "1123456789012345678901234567890123456789";
    try std.testing.expectError(error.ContextMismatch, archive.verifyBytes(a, v2, wrong, zip.sha256(v2)));
    try std.testing.expectError(error.MissingArchiveDigest, archive.verifyBytes(a, v2, context, null));
    var digest = zip.sha256(v2);
    digest[0] ^= 1;
    try std.testing.expectError(error.DigestMismatch, archive.verifyBytes(a, v2, context, digest));
}

test "public ZIP streaming observes cancellation before consuming member bytes" {
    var cancel: std.atomic.Value(bool) = .init(true);
    var reader = std.Io.Reader.fixed("member");
    const entry: zip.Entry = .{
        .name = "member",
        .reader = &reader,
        .size = 6,
        .crc32 = zip.crc32("member"),
        .sha256 = zip.sha256("member"),
        .limit = 6,
        .cancel = &cancel,
    };
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    var digest: [32]u8 = undefined;
    try std.testing.expectError(error.Cancelled, zip.writeArchive(&writer.writer, &.{entry}, &digest));
    try std.testing.expectEqual(@as(usize, 0), reader.seek);
}

test "public producer context accepts only the fixed public CI source and job" {
    const environment: std.process.Environ = .{ .block = .{ .slice = &.{
        "GITHUB_ACTIONS=true",                 "GITHUB_REPOSITORY=cataggar/unikraft",
        "GITHUB_JOB=wamr-native-compute",      "GITHUB_EVENT_NAME=pull_request",
        "GITHUB_REPOSITORY_VISIBILITY=public", "GITHUB_WORKSPACE=/opt/public-checkout",
        "GITHUB_SHA=" ++ revision,             "GITHUB_RUN_ID=1",
        "GITHUB_RUN_ATTEMPT=1",                "GITHUB_WORKFLOW_REF=cataggar/unikraft/.github/workflows/wamr-native-compute.yaml@refs/pull/258/merge",
    } } };
    const source: controller.accepted_run.SourceIdentity = .{ .revision = revision, .tree = revision };
    const bound = try archive.Context.fromCI(environment, "/opt/public-checkout", source);
    try std.testing.expectEqualStrings(context.run_id, bound.run_id);
    try std.testing.expectError(error.MissingCiContext, archive.Context.fromCI(.empty, "/opt/public-checkout", source));
    try std.testing.expectError(error.ContextMismatch, archive.Context.fromCI(environment, "/opt/different-checkout", source));
    try std.testing.expectError(error.ContextMismatch, archive.Context.fromCI(environment, "/opt/public-checkout", .{ .revision = genuine_context.source_revision, .tree = revision }));
}

test "fully rehashed public archives still refuse unexpected members changed data order and manifest" {
    var storage: [96]zip.MemberView = undefined;
    const original = try zip.indexArchive(v2, &storage);
    var views: [96]zip.MemberView = undefined;
    @memcpy(views[0..original.len], original);
    views[0].name = "artifacts/extra";
    try expectRehashedRefused(views[0..original.len]);
    @memcpy(views[0..original.len], original);
    views[0].bytes = "y";
    try expectRehashedRefused(views[0..original.len]);
    @memcpy(views[0..original.len], original);
    std.mem.swap(zip.MemberView, &views[0], &views[1]);
    try expectRehashedRefused(views[0..original.len]);
    @memcpy(views[0..original.len], original);
    views[original.len] = .{ .name = "private/extra.json", .bytes = "{}\n" };
    try expectRehashedRefused(views[0 .. original.len + 1]);
    @memcpy(views[0..original.len], original);
    views[original.len - 1].bytes = "{}\n";
    try expectRehashedRefused(views[0..original.len]);
    @memcpy(views[0..original.len], original);
    views[0].bytes = "Authorization: Bearer sensitive";
    try expectRehashedRefused(views[0..original.len]);
}

test "rehashed public ZIP paths duplicate collisions and link attributes refuse before acceptance" {
    const duplicate = try a.dupe(u8, v2);
    defer a.free(duplicate);
    var storage: [96]zip.MemberView = undefined;
    const views = try zip.indexArchive(v2, &storage);
    try renameMember(duplicate, 0, "artifacts/../aaaaaaab");
    try std.testing.expectError(error.InvalidName, archive.verifyBytes(a, duplicate, context, zip.sha256(duplicate)));
    var twin: usize = 1;
    while (views[twin].name.len != views[0].name.len) : (twin += 1) {}
    @memcpy(duplicate, v2);
    try renameMember(duplicate, twin, views[0].name);
    try std.testing.expectError(error.DuplicateName, archive.verifyBytes(a, duplicate, context, zip.sha256(duplicate)));
    @memcpy(duplicate, v2);
    try renameMember(duplicate, twin, "Artifacts/boot_inputs");
    try std.testing.expectError(error.NameCollision, archive.verifyBytes(a, duplicate, context, zip.sha256(duplicate)));
    @memcpy(duplicate, v2);
    const central = std.mem.indexOf(u8, duplicate, "PK\x01\x02") orelse return error.NoCentral;
    std.mem.writeInt(u32, duplicate[central + 38 ..][0..4], @as(u32, 0o120600) << 16, .little);
    try std.testing.expectError(error.WrongMode, archive.verifyBytes(a, duplicate, context, zip.sha256(duplicate)));
}

test "native public pack is create-only durable byte-identical and retains partial fault evidence" {
    for ([_]archive.Fault{ .none, .write, .before_file_sync, .before_parent_sync, .after_publication, .mutate_member, .replace_staged, .cancel_after_write, .publication_collision, .transient_source_entry }) |fault| {
        var fixture = try Fixture.init(@tagName(fault), v2);
        defer fixture.deinit();
        var retained = try files.RetainedFile.open(io, fixture.manifest_path, .private);
        defer retained.close(io);
        var signal = try core.process.SignalCancellation.install();
        defer signal.deinit();
        var accepted: controller.accepted_run.AcceptedRun = undefined;
        const result = archive.Test.packFixture(.{
            .allocator = a,
            .io = io,
            .source = .{ .local_handoff = .{ .accepted = &accepted, .manifest = &retained, .root = fixture.stage_path } },
            .context = context,
            .output_path = fixture.output_path,
            .signal = &signal,
            .fault = fault,
        });
        if (fault == .none) {
            if (result != .success) std.debug.print("public pack: {any}\n", .{result});
            try std.testing.expect(result == .success);
            try std.testing.expectEqualSlices(u8, &zip.sha256(v2), &result.success.sha256);
            const final = try fixture.root.readFileAlloc(io, "output/public-inner.zip", a, .limited(v2.len + 1));
            defer a.free(final);
            try std.testing.expectEqualSlices(u8, v2, final);
            const repeated = archive.Test.packFixture(.{
                .allocator = a,
                .io = io,
                .source = .{ .local_handoff = .{ .accepted = &accepted, .manifest = &retained, .root = fixture.stage_path } },
                .context = context,
                .output_path = fixture.output_path,
                .signal = &signal,
            });
            try std.testing.expect(repeated == .refused);
            try std.testing.expectEqual(error.OutputExists, repeated.refused.err);
        } else {
            if (result != .poisoned) std.debug.print("public pack fault {s}: {any}\n", .{ @tagName(fault), result });
            try std.testing.expect(result == .poisoned);
            if (fault == .transient_source_entry)
                try std.testing.expectEqual(error.SourceChanged, result.poisoned.err);
            if (fault == .after_publication) {
                try std.testing.expectEqual(files.CommitStatus.visible_not_durable, result.poisoned.publication);
                const final = try fixture.root.openFile(io, "output/public-inner.zip", .{});
                final.close(io);
            } else if (fault == .publication_collision) {
                try std.testing.expectEqual(files.CommitStatus.not_committed, result.poisoned.publication);
                const final = try fixture.root.readFileAlloc(io, "output/public-inner.zip", a, .limited(32));
                defer a.free(final);
                try std.testing.expectEqualStrings("foreign", final);
                const partial = try fixture.root.openFile(io, "output/archive.partial", .{});
                partial.close(io);
            } else {
                try std.testing.expectError(error.FileNotFound, fixture.root.openFile(io, "output/public-inner.zip", .{}));
                const partial = try fixture.root.openFile(io, "output/archive.partial", .{});
                partial.close(io);
            }
        }
    }
}

test "public pack refuses source extras links and post-capture input mutations" {
    for ([_][]const u8{ "extra", "mutate", "link" }) |kind| {
        var fixture = try Fixture.init(kind, v2);
        defer fixture.deinit();
        var retained = try files.RetainedFile.open(io, fixture.manifest_path, .private);
        defer retained.close(io);
        if (std.mem.eql(u8, kind, "extra")) {
            try writeFile(fixture.root, "stage/extra", "x");
        } else if (std.mem.eql(u8, kind, "mutate")) {
            try writeFile(fixture.root, "stage/artifacts/wasm", "y");
        } else {
            try fixture.root.deleteFile(io, "stage/artifacts/wasm");
            try fixture.root.symLink(io, "cwasm", "stage/artifacts/wasm", .{});
        }

        var accepted: controller.accepted_run.AcceptedRun = undefined;
        const result = archive.Test.packFixture(.{
            .allocator = a,
            .io = io,
            .source = .{ .local_handoff = .{ .accepted = &accepted, .manifest = &retained, .root = fixture.stage_path } },
            .context = context,
            .output_path = fixture.output_path,
        });
        try std.testing.expect(result == .refused);
        try std.testing.expectError(error.FileNotFound, fixture.root.openDir(io, "output", .{}));
    }
}

test "native public pack preserves the frozen v1 product without promoting its profile" {
    var fixture = try Fixture.init("v1-pack", v1);
    defer fixture.deinit();
    var retained = try files.RetainedFile.open(io, fixture.manifest_path, .private);
    defer retained.close(io);
    var accepted: controller.accepted_run.AcceptedRun = undefined;
    const result = archive.Test.packFixture(.{
        .allocator = a,
        .io = io,
        .source = .{ .local_handoff = .{ .accepted = &accepted, .manifest = &retained, .root = fixture.stage_path } },
        .context = context,
        .output_path = fixture.output_path,
    });
    try std.testing.expect(result == .success);
    try std.testing.expectEqual(@as(usize, 55), result.success.members);
    try std.testing.expectEqualSlices(u8, &zip.sha256(v1), &result.success.sha256);
}

test "retained public archive revalidation refuses in-place changes and identical replacements" {
    for ([_]bool{ false, true }) |replace| {
        var fixture = try Fixture.init(if (replace) "archive-replace" else "archive-mutate", v2);
        defer fixture.deinit();
        try writeFile(fixture.root, "input.zip", v2);
        const path = try std.fs.path.join(a, &.{ fixture.path, "input.zip" });
        defer a.free(path);
        var owner = try archive.Archive.open(a, io, path, context, zip.sha256(v2), null);
        defer owner.deinit(io);
        if (replace) {
            try fixture.root.renamePreserve("input.zip", fixture.root, "old.zip", io);
            try writeFile(fixture.root, "input.zip", v2);
        } else {
            const input = try fixture.root.openFile(io, "input.zip", .{ .mode = .read_write });
            defer input.close(io);
            try input.writePositionalAll(io, "!", 31);
            try input.sync(io);
        }
        if (owner.revalidate(io, null)) |_| return error.MutationAccepted else |_| {}
    }
}

test "genuine public v2 archive validates original synthetic merge identity and native AcceptedRun" {
    const path = options.genuine_archive orelse return error.SkipZigTest;
    var owner = try archive.Archive.open(a, io, path, genuine_context, try core.contracts.parseSha256(genuine_sha), null);
    defer owner.deinit(io);
    try std.testing.expectEqual(@as(usize, 83), owner.metadata.selected.len);
    const root_path = try std.fs.path.join(a, &.{ options.fixture_root, "public-archive-genuine" });
    defer a.free(root_path);
    std.Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer std.Io.Dir.cwd().deleteTree(io, root_path) catch {};
    var imported = try owner.materialize(io, root_path, null);
    defer imported.deinit(io);
    try std.testing.expectEqual(controller.accepted_run.EvidenceContext.trusted_inner_zip, imported.accepted.context);
    try std.testing.expectEqualStrings(genuine_context.source_revision, imported.accepted.source.revision);
    try imported.revalidate(io, null);
    var fixture = try Fixture.init("genuine-repack", owner.image.bytes());
    defer fixture.deinit();
    var manifest = try files.RetainedFile.open(io, fixture.manifest_path, .private);
    defer manifest.close(io);
    const repacked = archive.Test.packAcceptedFixture(.{
        .allocator = a,
        .io = io,
        .source = .{ .local_handoff = .{ .accepted = &imported.accepted, .manifest = &manifest, .root = fixture.stage_path } },
        .context = genuine_context,
        .output_path = fixture.output_path,
    });
    if (repacked != .success) std.debug.print("genuine retained repack: {any}\n", .{repacked});
    try std.testing.expect(repacked == .success);
    try std.testing.expectEqualSlices(u8, &owner.digest, &repacked.success.sha256);
    try std.testing.expectEqual(options.genuine_bytes, repacked.success.bytes);
}

test "genuine fully rehashed public archives refuse substituted reviewed source run and unexpected member" {
    const path = options.genuine_archive orelse return error.SkipZigTest;
    var owner = try archive.Archive.open(a, io, path, genuine_context, try core.contracts.parseSha256(genuine_sha), null);
    defer owner.deinit(io);
    var storage: [96]zip.MemberView = undefined;
    const original = try zip.indexArchive(owner.image.bytes(), &storage);
    var views: [96]zip.MemberView = undefined;
    for ([_][2][]const u8{
        .{ genuine_context.source_revision, "4ae2e33e1139d94e4fe02a11acffdc52c8e5192b" },
        .{ genuine_context.run_id, "99999999999" },
    }) |substitution| {
        @memcpy(views[0..original.len], original);
        const bundle = try std.mem.replaceOwned(u8, a, original[original.len - 2].bytes, substitution[0], substitution[1]);
        defer a.free(bundle);
        const manifest = try std.mem.replaceOwned(u8, a, original[original.len - 1].bytes, substitution[0], substitution[1]);
        defer a.free(manifest);
        views[original.len - 2].bytes = bundle;
        views[original.len - 1].bytes = manifest;
        const image = try buildZip(views[0..original.len]);
        defer a.free(image);
        try std.testing.expectError(error.ContextMismatch, archive.verifyBytes(a, image, genuine_context, zip.sha256(image)));
    }
    @memcpy(views[0..original.len], original);
    views[original.len] = .{ .name = "private/unexpected.json", .bytes = "{}\n" };
    const expanded = try buildZip(views[0 .. original.len + 1]);
    defer a.free(expanded);
    if (archive.verifyBytes(a, expanded, genuine_context, zip.sha256(expanded))) |metadata_| {
        var metadata = metadata_;
        metadata.deinit();
        return error.AdversaryAccepted;
    } else |_| {}
}

fn expectRehashedRefused(views: []const zip.MemberView) !void {
    const image = try buildZip(views);
    defer a.free(image);
    try expectBytesRefused(image);
}
fn expectBytesRefused(image: []const u8) !void {
    if (archive.verifyBytes(a, image, context, zip.sha256(image))) |metadata_| {
        var metadata = metadata_;
        metadata.deinit();
        return error.AdversaryAccepted;
    } else |_| {}
}
fn buildZip(views: []const zip.MemberView) ![]u8 {
    const readers = try a.alloc(std.Io.Reader, views.len);
    defer a.free(readers);
    const entries = try a.alloc(zip.Entry, views.len);
    defer a.free(entries);
    for (views, 0..) |view, i| {
        readers[i] = .fixed(view.bytes);
        entries[i] = .{ .name = view.name, .reader = &readers[i], .size = view.bytes.len, .crc32 = zip.crc32(view.bytes), .sha256 = zip.sha256(view.bytes), .limit = 512 * 1024 * 1024 };
    }
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    var digest: [32]u8 = undefined;
    try zip.writeArchive(&writer.writer, entries, &digest);
    return writer.toOwnedSlice();
}
fn renameMember(bytes: []u8, index: usize, name: []const u8) !void {
    var storage: [96]zip.MemberView = undefined;
    const views = try zip.indexArchive(bytes, &storage);
    try std.testing.expectEqual(views[index].name.len, name.len);
    const central_name = @intFromPtr(views[index].name.ptr) - @intFromPtr(bytes.ptr);
    const local = std.mem.readInt(u32, bytes[central_name - 46 + 42 ..][0..4], .little);
    @memcpy(bytes[local + 30 ..][0..name.len], name);
    @memcpy(bytes[central_name..][0..name.len], name);
}
fn writeFile(dir: std.Io.Dir, path: []const u8, bytes: []const u8) !void {
    if (std.fs.path.dirname(path)) |parent| _ = try dir.createDirPathStatus(io, parent, .fromMode(0o700));
    const file = try dir.createFile(io, path, .{ .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
    try file.sync(io);
}
const Fixture = struct {
    path: []const u8,
    root: std.Io.Dir,
    stage_path: []const u8,
    output_path: []const u8,
    manifest_path: []const u8,

    fn init(name: []const u8, image: []const u8) !Fixture {
        const path = try std.fmt.allocPrint(a, "{s}/public-archive-{s}", .{ options.fixture_root, name });
        errdefer a.free(path);
        std.Io.Dir.cwd().deleteTree(io, path) catch {};
        _ = try std.Io.Dir.cwd().createDirPathStatus(io, path, .fromMode(0o700));
        const root = try std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true });
        errdefer root.close(io);
        const stage = try std.fs.path.join(a, &.{ path, "stage" });
        errdefer a.free(stage);
        const output = try std.fs.path.join(a, &.{ path, "output" });
        errdefer a.free(output);
        const manifest = try std.fs.path.join(a, &.{ stage, "bundle.json" });
        errdefer a.free(manifest);
        var storage: [96]zip.MemberView = undefined;
        const views = try zip.indexArchive(image, &storage);
        for (views) |view| {
            if (std.mem.eql(u8, view.name, "bundle.json") or std.mem.eql(u8, view.name, "public-source.json")) continue;
            const relative = try std.fs.path.join(a, &.{ "stage", view.name });
            defer a.free(relative);
            try writeFile(root, relative, view.bytes);
        }
        const prefix = try std.fmt.allocPrint(a, "\"path\":\"{s}/", .{stage});
        defer a.free(prefix);
        const rooted = try std.mem.replaceOwned(u8, a, views[views.len - 2].bytes, "\"path\":\"", prefix);
        defer a.free(rooted);
        try writeFile(root, "stage/bundle.json", rooted);
        return .{ .path = path, .root = root, .stage_path = stage, .output_path = output, .manifest_path = manifest };
    }
    fn deinit(self: *Fixture) void {
        self.root.close(io);
        std.Io.Dir.cwd().deleteTree(io, self.path) catch {};
        a.free(self.path);
        a.free(self.stage_path);
        a.free(self.output_path);
        a.free(self.manifest_path);
    }
};
