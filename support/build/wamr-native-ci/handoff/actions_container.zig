// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const files = core.private_files;
const archive = @import("public_archive.zig");
const transport = @import("public_transport.zig");
const copy = @import("retained_copy.zig");
const zip = @import("zip.zig");
const layout = @import("wamr_controller").handoff_contracts.layout;

pub const max_container_bytes = layout.max_total_bytes + 128 * 1024;
pub const Phase = enum { inputs, reserved, extracting, publication, parent_sync, revalidation };
pub const Fault = enum { none, partial_write, replace_partial, raw_mutation, raw_replacement, publication_collision, cancel_during_copy, before_file_sync, after_publication };
pub const Diagnostic = struct { phase: Phase, err: anyerror, publication: files.CommitStatus };
pub const Outcome = union(enum) { success: RetainedDownload, refused: Diagnostic, poisoned: Diagnostic };
pub const Invocation = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    container_path: []const u8,
    output_path: []const u8,
    expected: transport.Expected,
    selection: transport.DownloadSelection,
    cancel: ?*const std.atomic.Value(bool) = null,
    fault: Fault = .none,
};

pub const RetainedDownload = struct {
    allocator: std.mem.Allocator,
    parent: transport.publication.ParentCustody,
    raw: files.RetainedFile,
    digest: [64]u8,
    download: transport.Download,

    pub fn revalidate(self: *const RetainedDownload, io: std.Io, cancel: ?*const std.atomic.Value(bool)) !void {
        try self.parent.verify(io);
        const digest = try copy.hashRetained(io, &self.raw, max_container_bytes, cancel);
        if (!std.mem.eql(u8, &digest, &self.digest)) return error.ContainerDigestMismatch;
        try self.download.revalidate(io, cancel);
        try copy.verifyRetained(io, &self.raw);
        try self.parent.verify(io);
    }

    pub fn deinit(self: *RetainedDownload, io: std.Io) void {
        self.download.deinit(io);
        const path = self.raw.path;
        self.raw.close(io);
        self.allocator.free(path);
        self.parent.deinit(io);
        self.* = undefined;
    }
};

pub fn retainDownload(inv: Invocation) Outcome {
    var state: State = .{ .inv = inv };
    const result = state.run() catch |err| {
        const diagnostic: Diagnostic = .{ .phase = state.phase, .err = err, .publication = state.publication };
        return if (state.reserved) .{ .poisoned = diagnostic } else .{ .refused = diagnostic };
    };
    return .{ .success = result };
}

const Member = struct {
    compressed: []const u8,
    size: u32,
    crc: u32,
    method: u16,
};

// Actions containers are not the canonical inner stored ZIP. This separate
// ZIP32 profile accepts one ASCII filename, stored/raw-deflate data, and an
// optional signed ZIP32 descriptor. No extras, comments or alternate paths.
fn index(bytes: []const u8) !Member {
    if (bytes.len > max_container_bytes) return error.TooLarge;
    if (bytes.len < 30 + 46 + 22) return error.Truncated;
    const end = bytes.len - 22;
    if (u32At(bytes, end) != 0x06054b50) return error.InvalidContainer;
    if (u16At(bytes, end + 4) != 0 or u16At(bytes, end + 6) != 0) return error.MultiDiskContainer;
    if (u16At(bytes, end + 8) != 1 or u16At(bytes, end + 10) != 1) return error.InvalidContainerMembers;
    if (u16At(bytes, end + 20) != 0) return error.ContainerComment;
    const central: usize = u32At(bytes, end + 16);
    const central_size: usize = u32At(bytes, end + 12);
    if (central_size != 46 + transport.filename.len or central > end or central_size != end - central)
        return error.InvalidContainer;
    if (u32At(bytes, central) != 0x02014b50 or u32At(bytes, central + 42) != 0) return error.InvalidContainer;
    const system = u16At(bytes, central + 4) >> 8;
    if (system != 0 and system != 3) return error.UnsupportedContainerSystem;
    const version = u16At(bytes, central + 6);
    if (version != 10 and version != 20) return error.UnsupportedContainerVersion;
    const flags = u16At(bytes, central + 8);
    if (flags & ~@as(u16, 0x0808) != 0) return error.UnsupportedContainerFlags;
    const method = u16At(bytes, central + 10);
    if (method != 0 and method != 8) return error.UnsupportedContainerCompression;
    if (method == 8 and version != 20) return error.UnsupportedContainerVersion;
    if (u16At(bytes, central + 28) != transport.filename.len or
        !std.mem.eql(u8, bytes[central + 46 .. end], transport.filename))
        return error.InvalidContainerName;
    if (u16At(bytes, central + 30) != 0 or u16At(bytes, central + 32) != 0 or
        u16At(bytes, central + 34) != 0 or u16At(bytes, central + 36) != 0)
        return error.ContainerExtra;
    const attrs = u32At(bytes, central + 38);
    const unix_type = (attrs >> 16) & 0o170000;
    if (attrs & 0x10 != 0 or (unix_type != 0 and unix_type != 0o100000))
        return error.InvalidContainerType;
    if (u32At(bytes, 0) != 0x04034b50 or u16At(bytes, 4) != version or
        u16At(bytes, 6) != flags or u16At(bytes, 8) != method or
        u32At(bytes, 10) != u32At(bytes, central + 12))
        return error.ContainerHeaderMismatch;
    if (u16At(bytes, 26) != transport.filename.len or u16At(bytes, 28) != 0)
        return error.InvalidContainerName;
    const data = 30 + transport.filename.len;
    if (data > central or !std.mem.eql(u8, bytes[30..data], transport.filename))
        return error.InvalidContainerName;
    const crc = u32At(bytes, central + 16);
    const compressed: usize = u32At(bytes, central + 20);
    const size = u32At(bytes, central + 24);
    if (size == 0 or size > layout.max_total_bytes or compressed == 0 or compressed > max_container_bytes)
        return error.TooLarge;
    if (compressed > central - data) return error.Truncated;
    const data_end = data + compressed;
    if (flags & 8 != 0) {
        if (u32At(bytes, 14) != 0 or u32At(bytes, 18) != 0 or u32At(bytes, 22) != 0 or
            central - data_end != 16 or u32At(bytes, data_end) != 0x08074b50 or
            u32At(bytes, data_end + 4) != crc or u32At(bytes, data_end + 8) != compressed or
            u32At(bytes, data_end + 12) != size)
            return error.ContainerDescriptorMismatch;
    } else if (data_end != central or u32At(bytes, 14) != crc or
        u32At(bytes, 18) != compressed or u32At(bytes, 22) != size)
        return error.ContainerHeaderMismatch;
    if (method == 0 and compressed != size) return error.ContainerSizeMismatch;
    return .{ .compressed = bytes[data..data_end], .size = size, .crc = crc, .method = method };
}

fn u16At(bytes: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, bytes[offset..][0..2], .little);
}
fn u32At(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn decode(a: std.mem.Allocator, member: Member, cancel: ?*const std.atomic.Value(bool)) ![]u8 {
    const bytes = try a.alloc(u8, member.size);
    errdefer a.free(bytes);
    var input: std.Io.Reader = .fixed(member.compressed);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor: std.compress.flate.Decompress = .init(&input, .raw, &window);
    const reader = if (member.method == 0) &input else &decompressor.reader;
    var offset: usize = 0;
    while (offset < bytes.len) {
        try copy.checkCancellation(cancel);
        const end = @min(bytes.len, offset + 64 * 1024);
        reader.readSliceAll(bytes[offset..end]) catch return error.InvalidContainerData;
        offset = end;
    }
    if (reader.takeByte()) |_| return error.ContainerSizeMismatch else |err| {
        if (err != error.EndOfStream) return error.InvalidContainerData;
    }
    if (input.seek != member.compressed.len) return error.TrailingContainerData;
    if (zip.crc32(bytes) != member.crc) return error.ContainerCrcMismatch;
    try copy.checkCancellation(cancel);
    return bytes;
}

const State = struct {
    inv: Invocation,
    phase: Phase = .inputs,
    reserved: bool = false,
    publication: files.CommitStatus = .not_committed,

    fn run(self: *State) !RetainedDownload {
        const inv = self.inv;
        if (!builtin.is_test and inv.fault != .none) return error.InvalidFault;
        try copy.checkCancellation(inv.cancel);
        try transport.matchUpload(inv.expected.upload, inv.selection.upload);
        try files.absoluteFilePath(inv.output_path);
        if (std.mem.eql(u8, inv.container_path, inv.output_path) or
            (std.mem.startsWith(u8, inv.container_path, inv.output_path) and inv.container_path.len > inv.output_path.len and inv.container_path[inv.output_path.len] == '/'))
            return error.AliasedOutput;
        const raw_path = try inv.allocator.dupe(u8, inv.container_path);
        errdefer inv.allocator.free(raw_path);
        var raw = try files.RetainedFile.open(inv.io, raw_path, .private);
        errdefer raw.close(inv.io);
        if (raw.file_snapshot.size == 0 or raw.file_snapshot.size > max_container_bytes) return error.TooLarge;
        const digest = try copy.hashRetained(inv.io, &raw, max_container_bytes, inv.cancel);
        if (!std.mem.eql(u8, &digest, &std.fmt.bytesToHex(inv.expected.upload.container_digest.bytes, .lower)))
            return error.ContainerDigestMismatch;
        const image = try inv.allocator.alloc(u8, @intCast(raw.file_snapshot.size));
        defer inv.allocator.free(image);
        var read_offset: usize = 0;
        while (read_offset < image.len) {
            try copy.checkCancellation(inv.cancel);
            const end = @min(image.len, read_offset + 64 * 1024);
            if (try raw.file.readPositionalAll(inv.io, image[read_offset..end], read_offset) != end - read_offset)
                return error.FileChanged;
            read_offset = end;
        }
        try copy.verifyRetained(inv.io, &raw);
        if (!std.mem.eql(u8, &zip.sha256(image), &inv.expected.upload.container_digest.bytes))
            return error.ContainerDigestMismatch;
        const inner = try decode(inv.allocator, try index(image), inv.cancel);
        defer inv.allocator.free(inner);
        var metadata = try archive.verifyBytes(inv.allocator, inner, inv.expected.upload.context, inv.expected.inner_digest.bytes);
        defer metadata.deinit();
        if (metadata.compatibility != .tiny_qcow2_derived_vhd_v2) return error.TransportRequiresV2;
        try copy.verifyRetained(inv.io, &raw);
        try copy.checkCancellation(inv.cancel);
        const parent = try files.FileParent.open(inv.io, inv.output_path, .private);
        defer parent.close(inv.io);
        var custody = try transport.publication.ParentCustody.open(inv.allocator, inv.io, std.fs.path.dirname(inv.output_path).?, std.os.linux.geteuid());
        errdefer custody.deinit(inv.io);
        if (!copy.sameDirectory(try copy.directorySnapshot(parent.directory), try copy.directorySnapshot(custody.last())))
            return error.AncestorChanged;
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
        self.phase = .extracting;
        const partial = try directory.dir.createFile(inv.io, "download.partial", .{ .exclusive = true, .read = true, .permissions = .fromMode(0o600) });
        defer partial.close(inv.io);
        if (inv.fault == .partial_write) {
            try partial.writePositionalAll(inv.io, "PK", 0);
            return error.AmbiguousWrite;
        }
        var offset: usize = 0;
        while (offset < inner.len) {
            try copy.checkCancellation(inv.cancel);
            const end = @min(inner.len, offset + 64 * 1024);
            try partial.writePositionalAll(inv.io, inner[offset..end], offset);
            offset = end;
            if (inv.fault == .cancel_during_copy)
                @constCast(inv.cancel orelse return error.InvalidFault).store(true, .release);
        }
        try copy.checkCancellation(inv.cancel);
        if (inv.fault == .raw_mutation) {
            const changed = try std.Io.Dir.openFileAbsolute(inv.io, inv.container_path, .{ .mode = .read_write, .follow_symlinks = false });
            defer changed.close(inv.io);
            try changed.writePositionalAll(inv.io, "!", 0);
        }
        if (inv.fault == .raw_replacement) {
            const raw_parent = try files.FileParent.open(inv.io, inv.container_path, .private);
            defer raw_parent.close(inv.io);
            try raw_parent.directory.renamePreserve(raw_parent.name, raw_parent.directory, "old-container.zip", inv.io);
            const changed = try raw_parent.directory.createFile(inv.io, raw_parent.name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
            defer changed.close(inv.io);
            try changed.writePositionalAll(inv.io, image, 0);
        }
        if (inv.fault == .before_file_sync) return error.AmbiguousWrite;
        try partial.sync(inv.io);
        const snapshot = try files.snapshot(partial);
        if (inv.fault == .replace_partial) {
            try directory.dir.renamePreserve("download.partial", directory.dir, "old-download", inv.io);
            const foreign = try directory.dir.createFile(inv.io, "download.partial", .{ .exclusive = true, .permissions = .fromMode(0o600) });
            defer foreign.close(inv.io);
            try foreign.writePositionalAll(inv.io, inner, 0);
        }
        const partial_path = try std.fs.path.join(inv.allocator, &.{ inv.output_path, "download.partial" });
        defer inv.allocator.free(partial_path);
        var reopened = try archive.Archive.open(inv.allocator, inv.io, partial_path, inv.expected.upload.context, inv.expected.inner_digest.bytes, inv.cancel);
        defer reopened.deinit(inv.io);
        if (!copy.sameCustodySnapshot(snapshot, reopened.retained.file_snapshot)) return error.OutputChanged;
        var iterator = directory.dir.iterate();
        const entry = (try iterator.next(inv.io)) orelse return error.OutputChanged;
        if (!std.mem.eql(u8, entry.name, "download.partial") or entry.kind != .file or try iterator.next(inv.io) != null)
            return error.OutputChanged;
        try copy.verifyRoot(inv.io, inv.output_path, root_snapshot);
        try custody.verify(inv.io);
        const final_digest = try copy.hashRetained(inv.io, &raw, max_container_bytes, inv.cancel);
        if (!std.mem.eql(u8, &final_digest, &digest)) return error.ContainerDigestMismatch;
        if (inv.fault == .publication_collision) {
            const foreign = try directory.dir.createFile(inv.io, transport.filename, .{ .exclusive = true, .permissions = .fromMode(0o600) });
            defer foreign.close(inv.io);
            try foreign.writePositionalAll(inv.io, "foreign", 0);
        }
        self.phase = .publication;
        self.publication = .publication_unknown;
        directory.dir.renamePreserve("download.partial", directory.dir, transport.filename, inv.io) catch |err| {
            if (err == error.PathAlreadyExists) self.publication = .not_committed;
            return err;
        };
        self.publication = .visible_not_durable;
        self.phase = .parent_sync;
        if (inv.fault == .after_publication) return error.AmbiguousWrite;
        try syncDir(inv.io, directory.dir);
        self.publication = .durable;
        self.phase = .revalidation;
        var download = try transport.Download.open(inv.allocator, inv.io, inv.output_path, inv.expected, inv.selection, inv.cancel);
        errdefer download.deinit(inv.io);
        const published = download.standalone.archive.retained.file_snapshot;
        if (!copy.sameDirectory(snapshot, published) or snapshot.size != published.size or
            published.nlink != 1 or snapshot.mtime.sec != published.mtime.sec or snapshot.mtime.nsec != published.mtime.nsec or
            !copy.sameCustodySnapshot(try files.snapshot(partial), published))
            return error.OutputChanged;
        var result: RetainedDownload = .{ .allocator = inv.allocator, .parent = custody, .raw = raw, .digest = digest, .download = download };
        try result.revalidate(inv.io, inv.cancel);
        return result;
    }
};

fn syncDir(io: std.Io, directory: std.Io.Dir) !void {
    try (std.Io.File{ .handle = directory.handle, .flags = .{ .nonblocking = false } }).sync(io);
}
