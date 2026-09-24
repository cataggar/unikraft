// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const Sha256 = core.Sha256;
const records = @import("records.zig");
const limits = @import("custody_limits.zig");
const linux = std.os.linux;

pub const Digest = [Sha256.digest_length]u8;
pub const File = struct {
    bytes: u64,
    sha256: [64]u8,
    metadata: [9]i128,
};

pub fn metadata(value: files.Snapshot) [9]i128 {
    const major: u64 = value.dev_major;
    const minor: u64 = value.dev_minor;
    const device = (minor & 0xff) | ((major & 0xfff) << 8) |
        ((minor & ~@as(u64, 0xff)) << 12) | ((major & ~@as(u64, 0xfff)) << 32);
    return .{
        device,                                                            value.ino,                                                         value.mode, value.uid, value.gid, value.nlink, value.size,
        @as(i128, value.mtime.sec) * std.time.ns_per_s + value.mtime.nsec, @as(i128, value.ctime.sec) * std.time.ns_per_s + value.ctime.nsec,
    };
}

pub fn directory(io: std.Io, path: []const u8, private: bool) !files.Snapshot {
    const opened = try files.openDirectory(io, path, if (private) .private else .artifact);
    defer opened.close(io);
    const info = try files.snapshot(.{ .handle = opened.handle, .flags = .{ .nonblocking = false } });
    if (info.mode & linux.S.IFMT != linux.S.IFDIR or
        (info.uid != linux.geteuid() and info.uid != 0) or
        (if (private) info.mode & 0o7777 != 0o700 else info.mode & 0o022 != 0))
        return error.UnsafeDirectory;
    return info;
}

pub fn readFile(io: std.Io, path: []const u8, limit: u64, private: bool) !File {
    var retained = try files.RetainedFile.open(io, path, if (private) .private else .artifact);
    defer retained.close(io);
    const before = retained.file_snapshot;
    if (before.mode & linux.S.IFMT != linux.S.IFREG or
        (before.uid == 0 and before.nlink == 0) or
        (before.uid != 0 and before.nlink != 1) or
        (before.uid != linux.geteuid() and before.uid != 0) or
        before.mode & 0o022 != 0 or before.size > limit)
        return error.UnsafeFile;
    var hash = Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < before.size) {
        const count = try retained.file.readPositionalAll(io, buffer[0..@intCast(@min(buffer.len, before.size - offset))], offset);
        if (count == 0) return error.FileChanged;
        hash.update(buffer[0..count]);
        offset += count;
    }
    if (try retained.file.readPositionalAll(io, buffer[0..1], offset) != 0)
        return error.FileChanged;
    try retained.verify(io);
    return .{
        .bytes = before.size,
        .sha256 = std.fmt.bytesToHex(hash.finalResult(), .lower),
        .metadata = metadata(before),
    };
}

pub fn bind(allocator: std.mem.Allocator, hash: *Sha256, value: anytype) !void {
    const raw = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(raw);
    const canonical = try records.canonicalAlloc(allocator, raw);
    defer allocator.free(canonical);
    const bytes = canonical[0 .. canonical.len - 1];
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, bytes.len, .big);
    hash.update(&length);
    hash.update(bytes);
}

pub fn hex(hash: *Sha256) [64]u8 {
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}

pub fn safeSize(count: *usize, value: usize, max: usize) !void {
    try limits.addBounded(count, value, max);
}
