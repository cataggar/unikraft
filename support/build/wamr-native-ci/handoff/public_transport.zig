// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const files = core.private_files;
const contracts = @import("wamr_controller").handoff_contracts;
const archive = @import("public_archive.zig");
const copy = @import("retained_copy.zig");

pub const filename = "tiny-aot-public-source.zip";

pub const ArtifactId = struct {
    storage: [20]u8,
    len: u8,

    pub fn parse(input: []const u8) !ArtifactId {
        if (input.len == 0 or input.len > 20 or input[0] < '1' or input[0] > '9')
            return error.InvalidArtifactId;
        for (input) |digit| if (!std.ascii.isDigit(digit)) return error.InvalidArtifactId;
        var result: ArtifactId = .{ .storage = @splat(0), .len = @intCast(input.len) };
        @memcpy(result.storage[0..input.len], input);
        return result;
    }

    pub fn text(self: *const ArtifactId) []const u8 {
        return self.storage[0..@min(self.len, self.storage.len)];
    }
};

pub const ContainerDigest = struct {
    bytes: [32]u8,

    pub fn parse(text: []const u8) !ContainerDigest {
        return .{ .bytes = try core.contracts.parseSha256(text) };
    }
};

pub const InnerDigest = struct {
    bytes: [32]u8,

    pub fn parse(text: []const u8) !InnerDigest {
        return .{ .bytes = try core.contracts.parseSha256(text) };
    }
};

// Upload metadata must come from the caller's independently trusted upload
// result, never from a directory name or an untrusted receipt beside the ZIP.
pub const UploadMetadata = struct {
    context: archive.Context,
    artifact_id: ArtifactId,
    container_digest: ContainerDigest,
};

pub const Expected = struct {
    upload: UploadMetadata,
    inner_digest: InnerDigest,
};

pub const DownloadSelection = struct {
    upload: UploadMetadata,
};

fn matchUpload(expected: UploadMetadata, selected: UploadMetadata) !void {
    try expected.context.validate();
    try selected.context.validate();
    if (expected.artifact_id.len > 20 or selected.artifact_id.len > 20)
        return error.InvalidArtifactId;
    _ = try ArtifactId.parse(expected.artifact_id.text());
    _ = try ArtifactId.parse(selected.artifact_id.text());
    if (!std.mem.eql(u8, expected.artifact_id.text(), selected.artifact_id.text()))
        return error.ArtifactIdMismatch;
    if (!std.mem.eql(u8, &expected.container_digest.bytes, &selected.container_digest.bytes))
        return error.ContainerDigestMismatch;
    inline for (.{ "repository", "run_id", "run_attempt", "source_revision", "source_tree", "wamr_revision" }) |name|
        if (!std.mem.eql(u8, @field(expected.context, name), @field(selected.context, name)))
            return error.ContextMismatch;
}

pub const Standalone = struct {
    allocator: std.mem.Allocator,
    directory: files.Directory,
    path: []const u8,
    snapshot: files.Snapshot,
    archive: archive.Archive,

    pub fn open(allocator: std.mem.Allocator, io: std.Io, path: []const u8, context: archive.Context, digest: InnerDigest, cancel: ?*const std.atomic.Value(bool)) !Standalone {
        try copy.checkCancellation(cancel);
        const owned_path = try allocator.dupe(u8, path);
        errdefer allocator.free(owned_path);
        const directory = try files.Directory.open(io, owned_path);
        errdefer directory.close(io);
        const snapshot = try copy.directorySnapshot(directory.dir);
        try exactMember(io, directory.dir);
        const member_path = try std.fs.path.join(allocator, &.{ path, filename });
        defer allocator.free(member_path);
        var member = try files.RetainedFile.open(io, member_path, .artifact);
        defer member.close(io);
        try copy.verifyRetained(io, &member);
        if (member.file_snapshot.nlink != 1) return error.UnsafeSource;
        var retained = try archive.Archive.open(allocator, io, member_path, context, digest.bytes, cancel);
        errdefer retained.deinit(io);
        if (!copy.sameCustodySnapshot(member.file_snapshot, retained.retained.file_snapshot))
            return error.FileChanged;
        var result: Standalone = .{
            .allocator = allocator,
            .directory = directory,
            .path = owned_path,
            .snapshot = snapshot,
            .archive = retained,
        };
        try result.revalidate(io, cancel);
        return result;
    }

    pub fn revalidate(self: *const Standalone, io: std.Io, cancel: ?*const std.atomic.Value(bool)) !void {
        try copy.checkCancellation(cancel);
        try copy.verifyRoot(io, self.path, self.snapshot);
        try exactMember(io, self.directory.dir);
        if (!copy.sameCustodySnapshot(self.snapshot, try copy.directorySnapshot(self.directory.dir)))
            return error.DownloadChanged;
        try self.archive.revalidate(io, cancel);
        try exactMember(io, self.directory.dir);
        if (!copy.sameCustodySnapshot(self.snapshot, try copy.directorySnapshot(self.directory.dir)))
            return error.DownloadChanged;
        try copy.verifyRoot(io, self.path, self.snapshot);
    }

    pub fn deinit(self: *Standalone, io: std.Io) void {
        self.archive.deinit(io);
        self.directory.close(io);
        self.allocator.free(self.path);
        self.* = undefined;
    }
};

fn exactMember(io: std.Io, directory: std.Io.Dir) !void {
    var iterator = directory.iterate();
    const entry = (try iterator.next(io)) orelse return error.InvalidDownloadMembers;
    if (!std.mem.eql(u8, entry.name, filename) or entry.kind != .file or
        try iterator.next(io) != null)
        return error.InvalidDownloadMembers;
}

pub const Download = struct {
    standalone: Standalone,
    arena: std.heap.ArenaAllocator,
    expected: Expected,

    pub fn open(allocator: std.mem.Allocator, io: std.Io, path: []const u8, expected: Expected, selection: DownloadSelection, cancel: ?*const std.atomic.Value(bool)) !Download {
        try matchUpload(expected.upload, selection.upload);
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        var owned = expected;
        inline for (.{ "repository", "run_id", "run_attempt", "source_revision", "source_tree", "wamr_revision" }) |name|
            @field(owned.upload.context, name) = try arena.allocator().dupe(u8, @field(expected.upload.context, name));
        var standalone = try Standalone.open(allocator, io, path, owned.upload.context, owned.inner_digest, cancel);
        errdefer standalone.deinit(io);
        if (standalone.archive.metadata.compatibility != .tiny_qcow2_derived_vhd_v2)
            return error.TransportRequiresV2;
        return .{ .standalone = standalone, .arena = arena, .expected = owned };
    }

    pub fn revalidate(self: *const Download, io: std.Io, cancel: ?*const std.atomic.Value(bool)) !void {
        try self.standalone.revalidate(io, cancel);
        if (!std.mem.eql(u8, &self.expected.inner_digest.bytes, &self.standalone.archive.digest))
            return error.DigestMismatch;
    }

    // This encodes metadata only. It neither hashes an Actions container nor
    // authenticates a remote artifact, and deliberately publishes no receipt.
    pub fn receipt(self: *const Download, allocator: std.mem.Allocator, io: std.Io, cancel: ?*const std.atomic.Value(bool)) ![]u8 {
        try self.revalidate(io, cancel);
        const expected = self.expected;
        const inner = std.fmt.bytesToHex(expected.inner_digest.bytes, .lower);
        const container = std.fmt.bytesToHex(expected.upload.container_digest.bytes, .lower);
        const context = expected.upload.context;
        const raw = try std.json.Stringify.valueAlloc(allocator, .{
            .schema = "uk.wamr.public-source-transport",
            .version = @as(u8, 2),
            .repository = context.repository,
            .run_id = context.run_id,
            .run_attempt = context.run_attempt,
            .source_revision = context.source_revision,
            .source_tree = context.source_tree,
            .inner_zip_sha256 = inner[0..],
            .artifact_id = expected.upload.artifact_id.text(),
            .container_digest = container[0..],
        }, .{});
        defer allocator.free(raw);
        var doc = try core.contracts.Document.parse(allocator, raw, contracts.json_limits);
        defer doc.deinit();
        try contracts.validatePublicSourceTransportV2(doc.value());
        const canonical = try doc.canonicalAlloc(allocator);
        errdefer allocator.free(canonical);
        try self.revalidate(io, cancel);
        return canonical;
    }

    pub fn materialize(self: *Download, io: std.Io, output_path: []const u8, cancel: ?*const std.atomic.Value(bool)) !Imported {
        try self.revalidate(io, cancel);
        const root = self.standalone.path;
        if (std.mem.eql(u8, root, output_path) or
            (std.mem.startsWith(u8, output_path, root) and output_path.len > root.len and output_path[root.len] == '/'))
            return error.OutputInsideDownload;
        var stage = try self.standalone.archive.materialize(io, output_path, cancel);
        errdefer stage.deinit(io);
        try self.revalidate(io, cancel);
        return .{ .download = self, .stage = stage };
    }

    pub fn deinit(self: *Download, io: std.Io) void {
        self.standalone.deinit(io);
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const Imported = struct {
    download: *Download,
    stage: archive.Imported,

    pub fn revalidate(self: *Imported, io: std.Io, signal: ?*core.process.SignalCancellation) !void {
        const cancel = if (signal) |active| active.flag() else null;
        try self.download.revalidate(io, cancel);
        try self.stage.revalidate(io, signal);
        try self.download.revalidate(io, cancel);
    }

    pub fn deinit(self: *Imported, io: std.Io) void {
        self.stage.deinit(io);
        self.* = undefined;
    }
};

pub const Phase = enum { inputs, reserved, copying, reopen, publication, parent_sync, revalidation };
pub const Fault = enum { none, partial_write, before_file_sync, before_parent_sync, replace_partial, cancel_during_copy, cancel_after_copy, publication_collision, after_publication };
pub const Diagnostic = struct { phase: Phase, err: anyerror, publication: files.CommitStatus };
pub const Outcome = union(enum) { success: Standalone, refused: Diagnostic, poisoned: Diagnostic };
pub const Invocation = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *archive.Archive,
    context: archive.Context,
    inner_digest: InnerDigest,
    output_path: []const u8,
    cancel: ?*const std.atomic.Value(bool) = null,
    fault: Fault = .none,
};

pub fn stageUpload(invocation: Invocation) Outcome {
    var staging: Staging = .{ .invocation = invocation };
    const result = staging.run() catch |err| {
        const diagnostic: Diagnostic = .{ .phase = staging.phase, .err = err, .publication = staging.publication };
        return if (staging.reserved) .{ .poisoned = diagnostic } else .{ .refused = diagnostic };
    };
    return .{ .success = result };
}

const Staging = struct {
    invocation: Invocation,
    phase: Phase = .inputs,
    reserved: bool = false,
    publication: files.CommitStatus = .not_committed,

    fn run(self: *Staging) !Standalone {
        const inv = self.invocation;
        if (!builtin.is_test and inv.fault != .none) return error.InvalidFault;
        try copy.checkCancellation(inv.cancel);
        try inv.source.revalidate(inv.io, inv.cancel);
        var metadata = try archive.verifyBytes(inv.allocator, inv.source.image.bytes(), inv.context, inv.inner_digest.bytes);
        defer metadata.deinit();
        try copy.checkCancellation(inv.cancel);
        const parent = try files.FileParent.open(inv.io, inv.output_path, .private);
        defer parent.close(inv.io);
        parent.directory.createDir(inv.io, parent.name, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => return error.OutputExists,
            else => return err,
        };
        self.reserved = true;
        self.phase = .reserved;
        const directory = try files.Directory.open(inv.io, inv.output_path);
        defer directory.close(inv.io);
        const root_snapshot = try copy.directorySnapshot(directory.dir);
        try syncDir(inv.io, directory.dir);
        try parent.sync(inv.io);
        self.phase = .copying;
        if (inv.fault == .partial_write) {
            const partial = try directory.dir.createFile(inv.io, "upload.partial", .{ .exclusive = true, .permissions = .fromMode(0o600) });
            defer partial.close(inv.io);
            try partial.writePositionalAll(inv.io, "PK", 0);
            return error.AmbiguousWrite;
        }
        const copied = try copy.copyRetained(inv.allocator, inv.io, &inv.source.retained, directory.dir, inv.output_path, "upload.partial", contracts.layout.max_total_bytes, null, .{
            .cancel = inv.cancel,
            .fault = switch (inv.fault) {
                .before_file_sync => .before_file_sync,
                .before_parent_sync => .before_parent_sync,
                .replace_partial => .replace_destination_before_reopen,
                .cancel_during_copy => .cancel_after_first_chunk,
                else => .none,
            },
        });
        defer inv.allocator.free(copied.path);
        const copied_directory = try copy.directorySnapshot(directory.dir);
        self.phase = .reopen;
        var reopened = try archive.Archive.open(inv.allocator, inv.io, copied.path, inv.context, inv.inner_digest.bytes, inv.cancel);
        defer reopened.deinit(inv.io);
        if (!copy.sameCustodySnapshot(copied.destination_snapshot, reopened.retained.file_snapshot))
            return error.FileChanged;
        try inv.source.revalidate(inv.io, inv.cancel);
        try reopened.revalidate(inv.io, inv.cancel);
        try copy.verifyRoot(inv.io, inv.output_path, root_snapshot);
        var iterator = directory.dir.iterate();
        const partial = (try iterator.next(inv.io)) orelse return error.StagingChanged;
        if (!std.mem.eql(u8, partial.name, "upload.partial") or partial.kind != .file or
            try iterator.next(inv.io) != null or
            !copy.sameCustodySnapshot(copied_directory, try copy.directorySnapshot(directory.dir)))
            return error.StagingChanged;
        if (inv.fault == .cancel_after_copy) {
            const cancel = inv.cancel orelse return error.InvalidFault;
            @constCast(cancel).store(true, .release);
        }
        try copy.checkCancellation(inv.cancel);
        if (inv.fault == .publication_collision) {
            const foreign = try directory.dir.createFile(inv.io, filename, .{ .exclusive = true, .permissions = .fromMode(0o600) });
            defer foreign.close(inv.io);
            try foreign.writePositionalAll(inv.io, "foreign", 0);
            try foreign.sync(inv.io);
        }
        self.phase = .publication;
        self.publication = .publication_unknown;
        directory.dir.renamePreserve("upload.partial", directory.dir, filename, inv.io) catch |err| {
            if (err == error.PathAlreadyExists) self.publication = .not_committed;
            return err;
        };
        self.publication = .visible_not_durable;
        self.phase = .parent_sync;
        if (inv.fault == .after_publication) return error.AmbiguousWrite;
        try syncDir(inv.io, directory.dir);
        self.publication = .durable;
        self.phase = .revalidation;
        var result = try Standalone.open(inv.allocator, inv.io, inv.output_path, inv.context, inv.inner_digest, inv.cancel);
        errdefer result.deinit(inv.io);
        if (!copy.sameDirectory(copied.destination_snapshot, result.archive.retained.file_snapshot))
            return error.FileChanged;
        try copy.verifyRoot(inv.io, inv.output_path, root_snapshot);
        try inv.source.revalidate(inv.io, inv.cancel);
        try result.revalidate(inv.io, inv.cancel);
        return result;
    }
};

fn syncDir(io: std.Io, dir: std.Io.Dir) !void {
    try (std.Io.File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}
