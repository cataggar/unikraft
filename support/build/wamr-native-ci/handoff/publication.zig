// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const core = @import("hyperv_core");
const files = core.private_files;
const archive = @import("public_archive.zig");
const transport = @import("public_transport.zig");
const copy = @import("retained_copy.zig");
const limit = @import("wamr_controller").handoff_contracts.layout.max_total_bytes;

pub const Phase = enum { inputs, reserved, copying, sealing, publication, parent_sync, revalidation };
pub const Fault = enum { none, partial_write, source_mutation, source_replacement, destination_replacement, publication_collision, cancel_during_copy, before_file_sync, after_publication };
pub const Diagnostic = struct { phase: Phase, err: anyerror, publication: files.CommitStatus };
pub const Outcome = union(enum) { success: SealedUpload, refused: Diagnostic, poisoned: Diagnostic };
pub const Invocation = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    source_path: []const u8,
    source_uid: u32,
    source_gid: u32,
    upload_gid: u32,
    output_path: []const u8,
    context: archive.Context,
    inner_digest: transport.InnerDigest,
    cancel: ?*const std.atomic.Value(bool) = null,
    fault: Fault = .none,
};

pub fn sealUpload(inv: Invocation) Outcome {
    if (linux.geteuid() != 0) return .{ .refused = .{ .phase = .inputs, .err = error.PrivilegeRequired, .publication = .not_committed } };
    files.verifyInitialNamespace(inv.io) catch |err|
        return .{ .refused = .{ .phase = .inputs, .err = err, .publication = .not_committed } };
    return run(inv, 0);
}

// Simulates only the root identity, never acquiring privilege or changing a
// pre-existing directory. Production callers cannot select another owner.
pub fn sealUploadForTest(inv: Invocation) Outcome {
    if (!builtin.is_test) return .{ .refused = .{ .phase = .inputs, .err = error.InvalidFault, .publication = .not_committed } };
    return run(inv, linux.geteuid());
}

fn run(inv: Invocation, root_uid: u32) Outcome {
    var state: State = .{ .inv = inv, .root_uid = root_uid };
    const result = state.run() catch |err| {
        const diagnostic: Diagnostic = .{ .phase = state.phase, .err = err, .publication = state.publication };
        return if (state.reserved) .{ .poisoned = diagnostic } else .{ .refused = diagnostic };
    };
    return .{ .success = result };
}

pub const SealedUpload = struct {
    allocator: std.mem.Allocator,
    parent: ParentCustody,
    source: Held,
    output: Held,
    source_uid: u32,
    source_gid: u32,
    root_uid: u32,
    upload_gid: u32,
    digest: [32]u8,

    pub fn revalidate(self: *const SealedUpload, io: std.Io, cancel: ?*const std.atomic.Value(bool)) !void {
        try self.parent.verify(io);
        try self.source.verify(io);
        try validateSource(self.source.snapshot, self.source_uid, self.source_gid);
        try self.output.verify(io);
        try self.parent.verify(io);
        try validateOutput(&self.output, self.root_uid, self.upload_gid);
        const directory = self.output.directories[self.output.count - 1];
        try transport.exactMember(io, directory);
        if (!copy.sameCustodySnapshot(self.output.snapshots[self.output.count - 1], try copy.directorySnapshot(directory)))
            return error.OutputChanged;
        if (!std.mem.eql(u8, &try self.source.hash(io, cancel), &self.digest) or
            !std.mem.eql(u8, &try self.output.hash(io, cancel), &self.digest))
            return error.DigestMismatch;
        try self.source.verify(io);
        try self.output.verify(io);
        try transport.exactMember(io, directory);
        if (!copy.sameCustodySnapshot(self.output.snapshots[self.output.count - 1], try copy.directorySnapshot(directory)))
            return error.OutputChanged;
        try self.parent.verify(io);
    }

    pub fn deinit(self: *SealedUpload, io: std.Io) void {
        self.output.deinit(self.allocator, io);
        self.source.deinit(self.allocator, io);
        self.parent.deinit(io);
        self.* = undefined;
    }
};

pub const ParentCustody = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    owner_uid: u32,
    directories: [files.retained_path_components]std.Io.Dir,
    snapshots: [files.retained_path_components]files.Snapshot,
    count: usize,

    pub fn open(a: std.mem.Allocator, io: std.Io, path: []const u8, uid: u32) !ParentCustody {
        if (path.len != 1) try files.absoluteFilePath(path);
        if (path.len == 1 and path[0] != '/') return error.UnsafePath;
        var result: ParentCustody = undefined;
        result.allocator = a;
        result.path = try a.dupe(u8, path);
        result.owner_uid = uid;
        result.count = 0;
        errdefer {
            for (result.directories[0..result.count]) |dir| dir.close(io);
            a.free(result.path);
        }
        const root = try std.Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false, .iterate = true });
        result.directories[0] = root;
        result.count = 1;
        result.snapshots[0] = try copy.directorySnapshot(root);
        try validateAncestor(result.snapshots[0], uid, uid);
        var parts = std.mem.splitScalar(u8, path[1..], '/');
        while (parts.next()) |part| {
            if (part.len == 0) continue;
            if (result.count == result.directories.len) return error.UnsafePath;
            const child = try result.last().openDir(io, part, .{ .follow_symlinks = false, .iterate = true });
            result.directories[result.count] = child;
            result.count += 1;
            result.snapshots[result.count - 1] = try copy.directorySnapshot(child);
            try validateAncestor(result.snapshots[result.count - 1], uid, uid);
        }
        return result;
    }

    pub fn last(self: *const ParentCustody) std.Io.Dir {
        return self.directories[self.count - 1];
    }

    pub fn verify(self: *const ParentCustody, io: std.Io) !void {
        var named = try ParentCustody.open(self.allocator, io, self.path, self.owner_uid);
        defer named.deinit(io);
        if (self.count != named.count) return error.AncestorChanged;
        for (0..self.count) |i| {
            const live = try copy.directorySnapshot(self.directories[i]);
            if (!copy.sameDirectory(self.snapshots[i], live) or !copy.sameDirectory(self.snapshots[i], named.snapshots[i]))
                return error.AncestorChanged;
        }
    }

    pub fn deinit(self: *ParentCustody, io: std.Io) void {
        for (self.directories[0..self.count]) |dir| dir.close(io);
        self.allocator.free(self.path);
        self.* = undefined;
    }
};

// This scoped walk permits only the explicitly named source owner alongside
// root. It does not relax private_files' global ownership/mode policy.
const Held = struct {
    path: []const u8,
    allowed_uid: u32,
    root_uid: u32,
    directories: [files.retained_path_components]std.Io.Dir,
    snapshots: [files.retained_path_components]files.Snapshot,
    count: usize,
    file: std.Io.File,
    snapshot: files.Snapshot,

    fn open(a: std.mem.Allocator, io: std.Io, path: []const u8, allowed_uid: u32, root_uid: u32) !Held {
        try files.absoluteFilePath(path);
        var result: Held = undefined;
        result.path = try a.dupe(u8, path);
        errdefer a.free(result.path);
        result.allowed_uid = allowed_uid;
        result.root_uid = root_uid;
        result.count = 0;
        var current = try std.Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false, .iterate = true });
        errdefer {
            if (result.count == 0) current.close(io);
            for (result.directories[0..result.count]) |dir| dir.close(io);
        }
        const root_snapshot = try copy.directorySnapshot(current);
        try validateAncestor(root_snapshot, allowed_uid, root_uid);
        result.directories[0] = current;
        result.snapshots[0] = root_snapshot;
        result.count = 1;
        var parts = std.mem.splitScalar(u8, std.fs.path.dirname(path).?[1..], '/');
        while (parts.next()) |part| {
            if (part.len == 0) continue;
            if (result.count == result.directories.len) return error.UnsafePath;
            const next = try current.openDir(io, part, .{ .follow_symlinks = false, .iterate = true });
            const snap = copy.directorySnapshot(next) catch |err| {
                next.close(io);
                return err;
            };
            validateAncestor(snap, allowed_uid, root_uid) catch |err| {
                next.close(io);
                return err;
            };
            result.directories[result.count] = next;
            result.snapshots[result.count] = snap;
            result.count += 1;
            current = next;
        }
        result.file = try (files.FileParent{ .directory = current, .name = std.fs.path.basename(path), .policy = .artifact }).openFile(io);
        errdefer result.file.close(io);
        result.snapshot = try files.snapshot(result.file);
        if (!result.snapshot.mask.GID or result.snapshot.nlink != 1 or result.snapshot.size == 0 or result.snapshot.size > limit)
            return error.UnsafeSource;
        return result;
    }

    fn verify(self: *const Held, io: std.Io) !void {
        if (!copy.sameCustodySnapshot(self.snapshot, try files.snapshot(self.file))) return error.FileChanged;
        var named = try Held.open(std.heap.page_allocator, io, self.path, self.allowed_uid, self.root_uid);
        defer named.deinit(std.heap.page_allocator, io);
        if (self.count != named.count or !copy.sameCustodySnapshot(self.snapshot, named.snapshot)) return error.FileChanged;
        for (0..self.count) |i| {
            const live = try copy.directorySnapshot(self.directories[i]);
            try validateAncestor(live, self.allowed_uid, self.root_uid);
            if (!copy.sameDirectory(self.snapshots[i], live) or !copy.sameDirectory(self.snapshots[i], named.snapshots[i]))
                return error.AncestorChanged;
        }
    }

    fn hash(self: *const Held, io: std.Io, cancel: ?*const std.atomic.Value(bool)) ![32]u8 {
        try self.verify(io);
        var hasher = core.Sha256.init(.{});
        var buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (offset < self.snapshot.size) {
            try copy.checkCancellation(cancel);
            const want: usize = @intCast(@min(buffer.len, self.snapshot.size - offset));
            if (try self.file.readPositionalAll(io, buffer[0..want], offset) != want) return error.FileChanged;
            hasher.update(buffer[0..want]);
            offset += want;
        }
        if (try self.file.readPositionalAll(io, buffer[0..1], offset) != 0) return error.FileChanged;
        try self.verify(io);
        return hasher.finalResult();
    }

    fn deinit(self: *Held, a: std.mem.Allocator, io: std.Io) void {
        self.file.close(io);
        for (self.directories[0..self.count]) |dir| dir.close(io);
        a.free(self.path);
        self.* = undefined;
    }
};

fn validateAncestor(s: files.Snapshot, allowed_uid: u32, root_uid: u32) !void {
    if (!s.mask.GID or s.mode & linux.S.IFMT != linux.S.IFDIR or s.mode & 0o022 != 0 or
        (s.uid != 0 and s.uid != root_uid and s.uid != allowed_uid))
        return error.UnsafeAncestor;
}

fn validateSource(s: files.Snapshot, uid: u32, gid: u32) !void {
    if (!s.mask.GID or s.uid != uid or s.gid != gid or s.mode & linux.S.IFMT != linux.S.IFREG or
        s.mode & 0o7777 != 0o600 or s.nlink != 1 or s.size == 0 or s.size > limit)
        return error.UnsafeSource;
}

fn validateOutput(held: *const Held, uid: u32, gid: u32) !void {
    const s = held.snapshot;
    const dir = held.snapshots[held.count - 1];
    if (s.uid != uid or s.gid != gid or s.mode & 0o7777 != 0o440 or s.nlink != 1 or
        dir.uid != uid or dir.gid != gid or dir.mode & 0o7777 != 0o550)
        return error.UnsafeDestination;
}

const State = struct {
    inv: Invocation,
    root_uid: u32,
    phase: Phase = .inputs,
    reserved: bool = false,
    publication: files.CommitStatus = .not_committed,

    fn run(self: *State) !SealedUpload {
        const inv = self.inv;
        if (!builtin.is_test and inv.fault != .none) return error.InvalidFault;
        try copy.checkCancellation(inv.cancel);
        try inv.context.validate();
        var source = try Held.open(inv.allocator, inv.io, inv.source_path, inv.source_uid, self.root_uid);
        errdefer source.deinit(inv.allocator, inv.io);
        try validateSource(source.snapshot, inv.source_uid, inv.source_gid);
        const bytes = try inv.allocator.alloc(u8, @intCast(source.snapshot.size));
        defer inv.allocator.free(bytes);
        var read_offset: usize = 0;
        while (read_offset < bytes.len) {
            try copy.checkCancellation(inv.cancel);
            const end = @min(bytes.len, read_offset + 64 * 1024);
            if (try source.file.readPositionalAll(inv.io, bytes[read_offset..end], read_offset) != end - read_offset)
                return error.FileChanged;
            read_offset = end;
        }
        var metadata = try archive.verifyBytes(inv.allocator, bytes, inv.context, inv.inner_digest.bytes);
        defer metadata.deinit();
        if (metadata.compatibility != .tiny_qcow2_derived_vhd_v2) return error.TransportRequiresV2;
        try source.verify(inv.io);
        try files.absoluteFilePath(inv.output_path);
        var custody = try ParentCustody.open(inv.allocator, inv.io, std.fs.path.dirname(inv.output_path).?, self.root_uid);
        errdefer custody.deinit(inv.io);
        const parent: files.FileParent = .{ .directory = custody.last(), .name = std.fs.path.basename(inv.output_path), .policy = .artifact };
        const parent_snapshot = try copy.directorySnapshot(parent.directory);
        if (parent_snapshot.uid != self.root_uid or parent_snapshot.mode & 0o022 != 0) return error.UnsafeDestination;
        try copy.checkCancellation(inv.cancel);
        parent.directory.createDir(inv.io, parent.name, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => return error.OutputExists,
            else => return err,
        };
        self.reserved = true;
        self.phase = .reserved;
        const directory = try parent.directory.openDir(inv.io, parent.name, .{ .follow_symlinks = false, .iterate = true });
        defer directory.close(inv.io);
        const initial_dir = try copy.directorySnapshot(directory);
        if (initial_dir.uid != self.root_uid or initial_dir.mode & 0o7777 != 0o700) return error.UnsafeDestination;
        try syncDir(inv.io, directory);
        try parent.sync(inv.io);
        const destination = try directory.createFile(inv.io, "upload.partial", .{ .exclusive = true, .read = true, .permissions = .fromMode(0o600) });
        defer destination.close(inv.io);
        self.phase = .copying;
        if (inv.fault == .partial_write) {
            try destination.writePositionalAll(inv.io, "PK", 0);
            return error.AmbiguousWrite;
        }
        var hasher = core.Sha256.init(.{});
        var buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (offset < source.snapshot.size) {
            try copy.checkCancellation(inv.cancel);
            const want: usize = @intCast(@min(buffer.len, source.snapshot.size - offset));
            if (try source.file.readPositionalAll(inv.io, buffer[0..want], offset) != want) return error.FileChanged;
            hasher.update(buffer[0..want]);
            try destination.writePositionalAll(inv.io, buffer[0..want], offset);
            offset += want;
            if (inv.fault == .cancel_during_copy) {
                @constCast(inv.cancel orelse return error.InvalidFault).store(true, .release);
            }
        }
        try copy.checkCancellation(inv.cancel);
        if (inv.fault == .source_mutation) {
            const changed = try std.Io.Dir.openFileAbsolute(inv.io, inv.source_path, .{ .mode = .read_write, .follow_symlinks = false });
            defer changed.close(inv.io);
            try changed.writePositionalAll(inv.io, "!", 0);
        }
        if (inv.fault == .source_replacement) {
            const source_parent = try files.FileParent.open(inv.io, inv.source_path, .artifact);
            defer source_parent.close(inv.io);
            try source_parent.directory.renamePreserve(source_parent.name, source_parent.directory, "old-source.zip", inv.io);
            const changed = try source_parent.directory.createFile(inv.io, source_parent.name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
            defer changed.close(inv.io);
            try changed.writePositionalAll(inv.io, bytes, 0);
        }
        try source.verify(inv.io);
        try custody.verify(inv.io);
        if (!std.mem.eql(u8, &hasher.finalResult(), &inv.inner_digest.bytes) or
            try source.file.readPositionalAll(inv.io, buffer[0..1], offset) != 0)
            return error.DigestMismatch;
        self.phase = .sealing;
        try setOwnerMode(destination.handle, self.root_uid, inv.upload_gid, 0o440);
        if (inv.fault == .before_file_sync) return error.AmbiguousWrite;
        try destination.sync(inv.io);
        const sealed_file = try files.snapshot(destination);
        if (inv.fault == .destination_replacement) {
            try directory.renamePreserve("upload.partial", directory, "old-upload", inv.io);
            const replacement = try directory.createFile(inv.io, "upload.partial", .{ .exclusive = true, .permissions = .fromMode(0o600) });
            defer replacement.close(inv.io);
            try replacement.writePositionalAll(inv.io, bytes, 0);
        }
        const partial_path = try std.fs.path.join(inv.allocator, &.{ inv.output_path, "upload.partial" });
        defer inv.allocator.free(partial_path);
        var partial = try Held.open(inv.allocator, inv.io, partial_path, self.root_uid, self.root_uid);
        defer partial.deinit(inv.allocator, inv.io);
        if (!copy.sameCustodySnapshot(sealed_file, partial.snapshot) or
            !std.mem.eql(u8, &try partial.hash(inv.io, inv.cancel), &inv.inner_digest.bytes))
            return error.OutputChanged;
        var iterator = directory.iterate();
        const entry = (try iterator.next(inv.io)) orelse return error.OutputChanged;
        if (!std.mem.eql(u8, entry.name, "upload.partial") or entry.kind != .file or try iterator.next(inv.io) != null)
            return error.OutputChanged;
        try source.verify(inv.io);
        try verifyNamedDir(inv.io, inv.output_path, initial_dir);
        if (inv.fault == .publication_collision) {
            const foreign = try directory.createFile(inv.io, transport.filename, .{ .exclusive = true, .permissions = .fromMode(0o600) });
            defer foreign.close(inv.io);
            try foreign.writePositionalAll(inv.io, "foreign", 0);
        }
        self.phase = .publication;
        try copy.checkCancellation(inv.cancel);
        self.publication = .publication_unknown;
        directory.renamePreserve("upload.partial", directory, transport.filename, inv.io) catch |err| {
            if (err == error.PathAlreadyExists) self.publication = .not_committed;
            return err;
        };
        self.publication = .visible_not_durable;
        self.phase = .parent_sync;
        if (inv.fault == .after_publication) return error.AmbiguousWrite;
        try setOwnerMode(directory.handle, self.root_uid, inv.upload_gid, 0o550);
        try syncDir(inv.io, directory);
        try parent.sync(inv.io);
        self.publication = .durable;
        self.phase = .revalidation;
        const output_path = try std.fs.path.join(inv.allocator, &.{ inv.output_path, transport.filename });
        defer inv.allocator.free(output_path);
        var output = try Held.open(inv.allocator, inv.io, output_path, self.root_uid, self.root_uid);
        errdefer output.deinit(inv.allocator, inv.io);
        if (!copy.sameDirectory(sealed_file, output.snapshot) or sealed_file.size != output.snapshot.size or
            output.snapshot.nlink != 1 or sealed_file.mtime.sec != output.snapshot.mtime.sec or
            sealed_file.mtime.nsec != output.snapshot.mtime.nsec or
            !copy.sameCustodySnapshot(try files.snapshot(destination), output.snapshot))
            return error.OutputChanged;
        var result: SealedUpload = .{
            .allocator = inv.allocator,
            .parent = custody,
            .source = source,
            .output = output,
            .source_uid = inv.source_uid,
            .source_gid = inv.source_gid,
            .root_uid = self.root_uid,
            .upload_gid = inv.upload_gid,
            .digest = inv.inner_digest.bytes,
        };
        try result.revalidate(inv.io, inv.cancel);
        return result;
    }
};

fn setOwnerMode(fd: linux.fd_t, uid: u32, gid: u32, mode: u32) !void {
    if (linux.errno(linux.fchown(fd, uid, gid)) != .SUCCESS) return error.SealingFailed;
    if (linux.errno(linux.fchmod(fd, mode)) != .SUCCESS) return error.SealingFailed;
}

fn syncDir(io: std.Io, dir: std.Io.Dir) !void {
    try (std.Io.File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

fn verifyNamedDir(io: std.Io, path: []const u8, expected: files.Snapshot) !void {
    const named = try files.openDirectory(io, path, .artifact);
    defer named.close(io);
    if (!copy.sameDirectory(expected, try copy.directorySnapshot(named))) return error.OutputChanged;
}
