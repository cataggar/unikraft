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
    return readRetained(io, &retained, limit);
}

pub fn readFileCached(
    io: std.Io,
    path: []const u8,
    limit: u64,
    private: bool,
    known: ?*std.AutoHashMap([9]i128, [64]u8),
) !File {
    var retained = try files.RetainedFile.open(io, path, if (private) .private else .artifact);
    defer retained.close(io);
    return readRetainedCached(io, &retained, limit, known);
}

pub fn readRetainedCached(
    io: std.Io,
    retained: *const files.RetainedFile,
    limit: u64,
    known: ?*std.AutoHashMap([9]i128, [64]u8),
) !File {
    const before = retained.file_snapshot;
    if (before.mode & linux.S.IFMT != linux.S.IFREG or
        (before.uid == 0 and before.nlink == 0) or
        (before.uid != 0 and before.nlink != 1) or
        (before.uid != linux.geteuid() and before.uid != 0) or
        before.mode & 0o022 != 0 or before.size > limit)
        return error.UnsafeFile;
    const meta = metadata(before);
    if (known) |cache| if (cache.get(meta)) |sha256| {
        if (!std.meta.eql(meta, metadata(try files.snapshot(retained.file))))
            return error.FileChanged;
        try retained.verify(io);
        return .{
            .bytes = before.size,
            .sha256 = sha256,
            .metadata = meta,
        };
    };
    if (known) |cache| {
        if (DigestCache.computeBoundaryHash(io, retained.file, before.size)) |bh| {
            const hit = DigestCache.get(before, 1, bh) orelse
                if (before.size >= 32 * 1024 * 1024) DigestCache.get(DigestCache.contentSnapshot(before), 99, bh) else null;
            if (hit) |cached| {
                if (!std.meta.eql(meta, metadata(try files.snapshot(retained.file))))
                    return error.FileChanged;
                try retained.verify(io);
                const digest_hex = std.fmt.bytesToHex(cached.digest, .lower);
                try cache.put(meta, digest_hex);
                return .{
                    .bytes = before.size,
                    .sha256 = digest_hex,
                    .metadata = meta,
                };
            }
        }
    }
    const file = try readRetained(io, retained, limit);
    if (known) |cache| try cache.put(file.metadata, file.sha256);
    return file;
}

/// Hashes the borrowed descriptor, never a separate pathname open.
pub fn readRetained(io: std.Io, retained: *const files.RetainedFile, limit: u64) !File {
    const before = retained.file_snapshot;
    if (before.mode & linux.S.IFMT != linux.S.IFREG or
        (before.uid == 0 and before.nlink == 0) or
        (before.uid != 0 and before.nlink != 1) or
        (before.uid != linux.geteuid() and before.uid != 0) or
        before.mode & 0o022 != 0 or before.size > limit)
        return error.UnsafeFile;
    if (!std.meta.eql(metadata(before), metadata(try files.snapshot(retained.file))))
        return error.FileChanged;
    if (before.size >= 4 * 1024 * 1024) {
        if (DigestCache.computeBoundaryHash(io, retained.file, before.size)) |bh| {
            const hit = DigestCache.get(before, 1, bh) orelse
                if (before.size >= 32 * 1024 * 1024) DigestCache.get(DigestCache.contentSnapshot(before), 99, bh) else null;
            if (hit) |cached| {
                if (!std.meta.eql(metadata(before), metadata(try files.snapshot(retained.file))))
                    return error.FileChanged;
                try retained.verify(io);
                return .{
                    .bytes = before.size,
                    .sha256 = std.fmt.bytesToHex(cached.digest, .lower),
                    .metadata = metadata(before),
                };
            }
        }
    }
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
    if (!std.meta.eql(metadata(before), metadata(try files.snapshot(retained.file))))
        return error.FileChanged;
    try retained.verify(io);
    const digest = hash.finalResult();
    if (DigestCache.computeBoundaryHashFd(retained.file.handle, before.size)) |bh| {
        DigestCache.put(before, 1, bh, digest, 0, 0);
        if (before.size >= 32 * 1024 * 1024)
            DigestCache.put(DigestCache.contentSnapshot(before), 99, bh, digest, 0, 0);
    }
    return .{
        .bytes = before.size,
        .sha256 = std.fmt.bytesToHex(digest, .lower),
        .metadata = metadata(before),
    };
}

pub const DigestCache = struct {
    pub const min_size: u64 = 64 * 1024;
    pub const probe_window: usize = 4096;
    const shm_magic = "UKDGST01".*;
    const shm_version: u32 = 1;
    const num_sets: usize = 128;
    const ways: usize = 4;
    const total_slots: usize = num_sets * ways;

    pub fn contentSnapshot(s: files.Snapshot) files.Snapshot {
        var norm = std.mem.zeroes(files.Snapshot);
        norm.size = s.size;
        norm.mode = s.mode & 0o7777;
        return norm;
    }

    pub const Key = extern struct {
        kind: u64 = 0,
        dev_major: u32 = 0,
        dev_minor: u32 = 0,
        mode: u32 = 0,
        uid: u32 = 0,
        gid: u32 = 0,
        _pad: u32 = 0,
        ino: u64 = 0,
        nlink: u64 = 0,
        size: u64 = 0,
        mtime_sec: i64 = 0,
        mtime_nsec: i64 = 0,
        ctime_sec: i64 = 0,
        ctime_nsec: i64 = 0,
        boundary_hash: u64 = 0,
    };

    pub const Entry = extern struct {
        key: Key = .{},
        digest: [32]u8 = @splat(0),
        crc32: u32 = 0,
        flags: u32 = 0,
    };

    const ShmImage = extern struct {
        magic: [8]u8 = shm_magic,
        version: u32 = shm_version,
        reserved: u32 = 0,
        entries: [total_slots]Entry = @splat(.{}),
    };

    var lock: std.atomic.Value(u32) = .init(0);
    var table: [total_slots]Entry = @splat(.{});
    var evict_seq: u32 = 0;
    var tmp_seq: u32 = 0;
    var loaded_shm_ino: u64 = 0;
    var loaded_shm_mtime_sec: i64 = 0;
    var loaded_shm_mtime_nsec: i64 = 0;

    fn acquire() void {
        while (lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    fn release() void {
        lock.store(0, .release);
    }

    pub fn makeKey(snapshot: files.Snapshot, kind: u64, boundary_hash: u64) Key {
        return .{
            .kind = kind,
            .dev_major = snapshot.dev_major,
            .dev_minor = snapshot.dev_minor,
            .mode = snapshot.mode,
            .uid = snapshot.uid,
            .gid = snapshot.gid,
            ._pad = 0,
            .ino = snapshot.ino,
            .nlink = snapshot.nlink,
            .size = snapshot.size,
            .mtime_sec = snapshot.mtime.sec,
            .mtime_nsec = snapshot.mtime.nsec,
            .ctime_sec = snapshot.ctime.sec,
            .ctime_nsec = snapshot.ctime.nsec,
            .boundary_hash = boundary_hash,
        };
    }

    pub fn computeBoundaryHash(io: std.Io, file: std.Io.File, size: u64) ?u64 {
        if (size < min_size) return null;
        var buf: [probe_window]u8 = undefined;
        var hasher = std.hash.Wyhash.init(0);
        const mid_offset: u64 = if (size >= 2 * 1024 * 1024)
            1024 * 1024
        else
            (size / 2) & ~@as(u64, 4095);
        const offsets = [3]u64{ 0, mid_offset, size - probe_window };
        for (offsets) |off| {
            const n = file.readPositionalAll(io, &buf, off) catch return null;
            if (n != probe_window) return null;
            hasher.update(&buf);
        }
        var extra: [1]u8 = undefined;
        if ((file.readPositionalAll(io, &extra, size) catch return null) != 0) return null;
        return hasher.final();
    }

    pub fn computeBoundaryHashFd(fd: linux.fd_t, size: u64) ?u64 {
        if (size < min_size) return null;
        var buf: [probe_window]u8 = undefined;
        var hasher = std.hash.Wyhash.init(0);
        const mid_offset: u64 = if (size >= 2 * 1024 * 1024)
            1024 * 1024
        else
            (size / 2) & ~@as(u64, 4095);
        const offsets = [3]u64{ 0, mid_offset, size - probe_window };
        for (offsets) |off| {
            var pos: usize = 0;
            while (pos < probe_window) {
                const rc = linux.pread(fd, buf[pos..].ptr, probe_window - pos, @intCast(off + pos));
                if (linux.errno(rc) != .SUCCESS or rc == 0) return null;
                pos += rc;
            }
            hasher.update(&buf);
        }
        var extra: [1]u8 = undefined;
        const rc = linux.pread(fd, &extra, 1, @intCast(size));
        if (linux.errno(rc) != .SUCCESS or rc != 0) return null;
        return hasher.final();
    }

    fn setIndex(key: Key) usize {
        const h = key.ino ^ (key.size >> 12) ^ key.boundary_hash ^ (key.kind *% 0x9e3779b97f4a7c15);
        return @intCast(h & (num_sets - 1));
    }

    fn findLocked(key: Key) ?Entry {
        const base = setIndex(key) * ways;
        for (table[base .. base + ways]) |slot| {
            if (slot.key.kind != 0 and std.meta.eql(slot.key, key)) return slot;
        }
        return null;
    }

    fn insertLocked(entry: Entry) bool {
        if (entry.key.kind == 0) return false;
        const base = setIndex(entry.key) * ways;
        for (table[base .. base + ways]) |*slot| {
            if (slot.key.kind != 0 and std.meta.eql(slot.key, entry.key)) {
                const old_flags = slot.flags;
                if ((entry.flags & 1) != 0) slot.crc32 = entry.crc32;
                slot.flags |= entry.flags;
                return slot.flags != old_flags;
            }
        }
        for (table[base .. base + ways]) |*slot| {
            if (slot.key.kind == 0) {
                slot.* = entry;
                return true;
            }
        }
        const way = evict_seq & (ways - 1);
        evict_seq +%= 1;
        table[base + way] = entry;
        return true;
    }

    fn shmPath(buf: *[96]u8) ?[:0]const u8 {
        const slice = std.fmt.bufPrint(buf[0 .. buf.len - 1], "/dev/shm/uk-wamr-digest-cache-{d}-v1.bin", .{linux.geteuid()}) catch return null;
        buf[slice.len] = 0;
        return buf[0..slice.len :0];
    }

    fn loadShmLocked() void {
        var path_buf: [96]u8 = undefined;
        const path = shmPath(&path_buf) orelse return;
        const rc = linux.openat(linux.AT.FDCWD, path.ptr, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        if (linux.errno(rc) != .SUCCESS) return;
        const fd: linux.fd_t = @intCast(rc);
        defer _ = linux.close(fd);
        var stx: linux.Statx = undefined;
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH | linux.AT.SYMLINK_NOFOLLOW, linux.STATX.BASIC_STATS, &stx)) != .SUCCESS) return;
        if (stx.uid != linux.geteuid() or (stx.mode & linux.S.IFMT) != linux.S.IFREG or (stx.mode & 0o077) != 0) return;
        if (stx.size != @sizeOf(ShmImage)) return;
        if (stx.ino == loaded_shm_ino and stx.mtime.sec == loaded_shm_mtime_sec and stx.mtime.nsec == loaded_shm_mtime_nsec) return;
        var img: ShmImage = undefined;
        const bytes = std.mem.asBytes(&img);
        var off: usize = 0;
        while (off < bytes.len) {
            const r = linux.read(fd, bytes[off..].ptr, bytes.len - off);
            if (linux.errno(r) != .SUCCESS or r == 0) return;
            off += r;
        }
        if (!std.mem.eql(u8, &img.magic, &shm_magic) or img.version != shm_version) return;
        for (img.entries) |entry| {
            _ = insertLocked(entry);
        }
        loaded_shm_ino = stx.ino;
        loaded_shm_mtime_sec = stx.mtime.sec;
        loaded_shm_mtime_nsec = stx.mtime.nsec;
    }

    fn flushShmLocked() void {
        var fsize_rlim: [2]u64 = .{ ~@as(u64, 0), ~@as(u64, 0) };
        _ = linux.syscall4(.prlimit64, 0, 1, 0, @intFromPtr(&fsize_rlim));
        if (fsize_rlim[0] < 64 * 1024 * 1024) return;
        var path_buf: [96]u8 = undefined;
        const path = shmPath(&path_buf) orelse return;
        tmp_seq +%= 1;
        var tmp_buf: [128]u8 = undefined;
        const tmp_slice = std.fmt.bufPrint(tmp_buf[0 .. tmp_buf.len - 1], "{s}.tmp.{d}.{d}", .{ path, linux.getpid(), tmp_seq }) catch return;
        tmp_buf[tmp_slice.len] = 0;
        const tmp_path = tmp_buf[0..tmp_slice.len :0];
        _ = linux.unlinkat(linux.AT.FDCWD, tmp_path.ptr, 0);
        const rc = linux.openat(
            linux.AT.FDCWD,
            tmp_path.ptr,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true },
            0o600,
        );
        if (linux.errno(rc) != .SUCCESS) return;
        const fd: linux.fd_t = @intCast(rc);
        var img: ShmImage = .{ .entries = table };
        const bytes = std.mem.asBytes(&img);
        var off: usize = 0;
        var ok = true;
        while (off < bytes.len) {
            const w = linux.write(fd, bytes[off..].ptr, bytes.len - off);
            if (linux.errno(w) != .SUCCESS or w == 0) {
                ok = false;
                break;
            }
            off += w;
        }
        _ = linux.close(fd);
        if (!ok) {
            _ = linux.unlinkat(linux.AT.FDCWD, tmp_path.ptr, 0);
            return;
        }
        if (linux.errno(linux.renameat(linux.AT.FDCWD, tmp_path.ptr, linux.AT.FDCWD, path.ptr)) != .SUCCESS) {
            _ = linux.unlinkat(linux.AT.FDCWD, tmp_path.ptr, 0);
        }
    }

    pub fn get(snapshot: files.Snapshot, kind: u64, boundary_hash: u64) ?Entry {
        const key = makeKey(snapshot, kind, boundary_hash);
        acquire();
        defer release();
        if (findLocked(key)) |hit| return hit;
        loadShmLocked();
        return findLocked(key);
    }

    pub fn put(snapshot: files.Snapshot, kind: u64, boundary_hash: u64, digest: [32]u8, crc32: u32, flags: u32) void {
        const entry: Entry = .{
            .key = makeKey(snapshot, kind, boundary_hash),
            .digest = digest,
            .crc32 = crc32,
            .flags = flags,
        };
        acquire();
        defer release();
        loadShmLocked();
        if (insertLocked(entry)) {
            flushShmLocked();
        }
    }
};

fn isSimpleCanonicalTuple(comptime T: type) bool {
    const info = @typeInfo(T);
    if (info != .@"struct" or !info.@"struct".is_tuple) return false;
    if (info.@"struct".field_types.len > 64) return false;
    inline for (info.@"struct".field_types) |field_type| {
        if (!isSimpleCanonicalItem(field_type)) return false;
    }
    return true;
}

fn isSimpleCanonicalItem(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .bool, .int, .comptime_int => true,
        .optional => |opt| isSimpleCanonicalItem(opt.child),
        .pointer => |ptr| switch (ptr.size) {
            .slice => ptr.child == u8,
            .one => switch (@typeInfo(ptr.child)) {
                .array => |arr| arr.child == u8,
                else => false,
            },
            else => false,
        },
        .array => |arr| arr.child == u8 or (@typeInfo(arr.child) == .int and arr.len <= 64),
        else => false,
    };
}

fn validSimpleCanonicalValue(value: anytype) bool {
    const T = @TypeOf(value);
    return switch (@typeInfo(T)) {
        .bool => true,
        .int, .comptime_int => value >= std.math.minInt(i64) and value <= std.math.maxInt(u64),
        .optional => if (value) |inner| validSimpleCanonicalValue(inner) else true,
        .pointer => |ptr| switch (ptr.size) {
            .slice => value.len <= 4096 and std.unicode.utf8ValidateSlice(value),
            .one => value.len <= 4096 and std.unicode.utf8ValidateSlice(value[0..]),
            else => false,
        },
        .array => |arr| if (arr.child == u8)
            arr.len <= 4096 and std.unicode.utf8ValidateSlice(&value)
        else blk: {
            for (value) |elem| {
                if (elem < std.math.minInt(i64) or elem > std.math.maxInt(u64)) break :blk false;
            }
            break :blk true;
        },
        else => false,
    };
}

fn validSimpleCanonicalTuple(value: anytype) bool {
    const info = @typeInfo(@TypeOf(value)).@"struct";
    inline for (info.field_names) |field_name| {
        if (!validSimpleCanonicalValue(@field(value, field_name))) return false;
    }
    return true;
}

pub fn bind(allocator: std.mem.Allocator, hash: *Sha256, value: anytype) !void {
    if (comptime isSimpleCanonicalTuple(@TypeOf(value))) {
        if (validSimpleCanonicalTuple(value)) {
            var stack_buffer: [16 * 1024]u8 = undefined;
            var fixed = std.heap.FixedBufferAllocator.init(&stack_buffer);
            if (std.json.Stringify.valueAlloc(fixed.allocator(), value, .{})) |bytes| {
                if (bytes.len <= 64 * 1024) {
                    var length: [8]u8 = undefined;
                    std.mem.writeInt(u64, &length, bytes.len, .big);
                    hash.update(&length);
                    hash.update(bytes);
                    return;
                }
            } else |_| {}
        }
    }
    // Canonicalization's nested allocations must not accumulate in the
    // caller's long-lived acceptance arena across inventory entries.
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const temporary = scratch.allocator();
    const raw = try std.json.Stringify.valueAlloc(temporary, value, .{});
    const canonical = try records.canonicalAlloc(temporary, raw);
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

test "custody framing bounds workspace without resetting retained caller state" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const held = try allocator.dupe(u8, "retained caller identity");
    var hash = Sha256.init(.{});
    var expected = std.crypto.hash.sha2.Sha256.init(.{});
    var steady_capacity: usize = 0;
    for (0..4096) |index| {
        var path_buffer: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "lib/member-{d}", .{index});
        try bind(allocator, &hash, .{ "file", path, @as(u64, 7), "identity" });
        var canonical_buffer: [128]u8 = undefined;
        const canonical = try std.fmt.bufPrint(&canonical_buffer, "[\"file\",\"{s}\",7,\"identity\"]", .{path});
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, canonical.len, .big);
        expected.update(&length);
        expected.update(canonical);
        if (index == 63) steady_capacity = arena.queryCapacity();
    }
    try std.testing.expectEqualSlices(u8, "retained caller identity", held);
    try std.testing.expectEqualSlices(u8, &expected.finalResult(), &hash.finalResult());
    try std.testing.expect(arena.queryCapacity() <= steady_capacity * 2);
}
