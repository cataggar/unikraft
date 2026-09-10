const std = @import("std");
const linux = std.os.linux;
const core = @import("hyperv_core");
const p = @import("protocol.zig");

/// Core validates components with O_PATH. Retain that validation while opening
/// the very same directory inode with a descriptor usable for fsync and flock.
pub fn durableDirectory(io: std.Io, path: []const u8) !core.private_files.Directory {
    const checked = try core.private_files.Directory.open(io, path);
    defer checked.close(io);
    const directory = try checked.dir.openDir(io, ".", .{ .iterate = true, .follow_symlinks = false });
    errdefer directory.close(io);
    if ((try checked.dir.stat(io)).inode != (try directory.stat(io)).inode) return error.DirectoryChanged;
    return .{ .dir = directory };
}

pub fn cwdPath(io: std.Io, buffer: []u8) !usize {
    const directory = try std.Io.Dir.cwd().openDir(io, ".", .{ .follow_symlinks = false });
    defer directory.close(io);
    return directory.realPath(io, buffer);
}

pub fn isDurable(result: core.private_files.CommitResult) bool {
    return result.status == .durable and result.failures.primary == null and result.failures.cleanup == null and result.failures.recording == null;
}

pub fn syncDirectory(io: std.Io, directory: std.Io.Dir) !void {
    const file: std.Io.File = .{ .handle = directory.handle, .flags = .{ .nonblocking = false } };
    try file.sync(io);
}

pub const Parent = struct {
    directory: core.private_files.Directory,
    name: []const u8,

    pub fn close(self: Parent, io: std.Io) void {
        self.directory.close(io);
    }
};

pub fn parent(allocator: std.mem.Allocator, io: std.Io, root: []const u8, name: []const u8, create: bool) !Parent {
    var directory = try durableDirectory(io, root);
    errdefer directory.close(io);
    var components = std.mem.splitScalar(u8, name, '/');
    var component = components.next() orelse return error.InvalidArtifactName;
    while (components.next()) |next| {
        if (component.len == 0 or component.len > 240 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) return error.InvalidArtifactName;
        if (create) {
            directory.dir.createDir(io, component, .fromMode(0o700)) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
            try syncDirectory(io, directory.dir);
        }
        const child = try directory.dir.openDir(io, component, .{ .follow_symlinks = false, .iterate = true });
        directory.close(io);
        directory = .{ .dir = child };
        // Validate the retained descriptor through its canonical descriptor path.
        var path: [std.fs.max_path_bytes]u8 = undefined;
        const length = try child.realPath(io, &path);
        const checked = try core.private_files.Directory.open(io, path[0..length]);
        defer checked.close(io);
        if ((try checked.dir.stat(io)).inode != (try child.stat(io)).inode) return error.DirectoryChanged;
        component = next;
    }
    _ = allocator;
    if (component.len == 0 or component.len > 240 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) return error.InvalidArtifactName;
    return .{ .directory = directory, .name = component };
}

pub fn open(io: std.Io, directory: core.private_files.Directory, name: []const u8, executable: bool, links: u32) !std.Io.File {
    if (!executable and links == 1) return directory.openFile(io, name);
    if (name.len == 0 or name.len > 240 or std.mem.indexOfAny(u8, name, "/\x00") != null) return error.UnsafeFile;
    var z: [256:0]u8 = undefined;
    @memcpy(z[0..name.len], name);
    z[name.len] = 0;
    const raw = linux.openat(directory.dir.handle, z[0..name.len :0], .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .NONBLOCK = true, .CLOEXEC = true }, 0);
    if (linux.errno(raw) != .SUCCESS) return error.UnsafeFile;
    const file: std.Io.File = .{ .handle = @intCast(raw), .flags = .{ .nonblocking = true } };
    errdefer file.close(io);
    var stat: linux.Statx = undefined;
    if (linux.errno(linux.statx(file.handle, "", linux.AT.EMPTY_PATH, .{ .UID = true }, &stat)) != .SUCCESS or !stat.mask.UID) return error.UnsafeFile;
    const metadata = try file.stat(io);
    if (metadata.kind != .file or metadata.permissions.toMode() & 0o7777 != @as(u16, if (executable) 0o700 else 0o600) or stat.uid != linux.geteuid() or metadata.nlink != links) return error.UnsafeFile;
    return file;
}

pub fn digest(io: std.Io, file: std.Io.File, size: u64) !p.Hash {
    const before = try file.stat(io);
    if (before.kind != .file or before.size != size or size > p.max_artifact) return error.ArtifactIntegrity;
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [32 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var position: u64 = 0;
    while (position < size) {
        const count = try file.readPositionalAll(io, buffer[0..@min(buffer.len, size - position)], position);
        if (count == 0) return error.ArtifactIntegrity;
        sha.update(buffer[0..count]);
        position += count;
    }
    try unchanged(io, file, before);
    return sha.finalResult();
}

pub fn unchanged(io: std.Io, file: std.Io.File, before: std.Io.File.Stat) !void {
    const after = try file.stat(io);
    if (before.inode != after.inode or before.size != after.size or before.mtime.nanoseconds != after.mtime.nanoseconds or before.ctime.nanoseconds != after.ctime.nanoseconds) return error.ArtifactChanged;
}

pub fn verify(allocator: std.mem.Allocator, io: std.Io, root: []const u8, artifact: p.Artifact, links: u32) !std.Io.File {
    const container = try parent(allocator, io, root, artifact.name, false);
    defer container.close(io);
    const file = try open(io, container.directory, container.name, artifact.role == .qemu, links);
    errdefer file.close(io);
    if (!std.mem.eql(u8, &try digest(io, file, artifact.size), &artifact.sha256)) return error.ArtifactIntegrity;
    return file;
}

pub fn copy(io: std.Io, source: std.Io.File, destination: std.Io.File, size: u64) !void {
    var buffer: [32 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var position: u64 = 0;
    while (position < size) {
        const count = try source.readPositionalAll(io, buffer[0..@min(buffer.len, size - position)], position);
        if (count == 0) return error.ArtifactIntegrity;
        try destination.writePositionalAll(io, buffer[0..count], position);
        position += count;
    }
    try destination.sync(io);
}

pub fn verifyVhd(io: std.Io, file: std.Io.File, raw_size: u64, expected: p.Hash) !void {
    const before = try file.stat(io);
    if (before.size != raw_size + 512) return error.InvalidVhd;
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [32 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var position: u64 = 0;
    while (position < raw_size) {
        const count = try file.readPositionalAll(io, buffer[0..@min(buffer.len, raw_size - position)], position);
        if (count == 0) return error.InvalidVhd;
        sha.update(buffer[0..count]);
        position += count;
    }
    var footer: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &footer);
    if (try file.readPositionalAll(io, &footer, raw_size) != 512 or !std.mem.eql(u8, footer[0..8], "conectix") or !std.mem.eql(u8, &sha.finalResult(), &expected)) return error.InvalidVhd;
    try unchanged(io, file, before);
}

pub fn hostBootId(io: std.Io) !p.Uuid {
    const file = try std.Io.Dir.openFileAbsolute(io, "/proc/sys/kernel/random/boot_id", .{ .mode = .read_only });
    defer file.close(io);
    var bytes: [38]u8 = undefined;
    const count = try file.readPositionalAll(io, &bytes, 0);
    const id = try core.contracts.parseUuid(std.mem.trim(u8, bytes[0..count], "\r\n"));
    try p.validUuid(id);
    return id;
}
