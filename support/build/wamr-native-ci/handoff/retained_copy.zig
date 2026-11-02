// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const files = core.private_files;
const Sha256 = core.Sha256;
const layout = @import("wamr_controller").handoff_contracts.layout;
const linux = std.os.linux;

pub const aggregate_budget = layout.max_total_bytes - 2 * layout.max_json_bytes;
const chunk_size = 64 * 1024;
const scan_tail = 128;

pub const Budget = struct {
    used: u64 = 0,
    limit: u64 = aggregate_budget,

    pub fn reserve(self: *Budget, bytes: u64) !void {
        if (self.limit > aggregate_budget or bytes == 0 or bytes > self.limit or self.used > self.limit - bytes)
            return error.CopyBudgetExceeded;
        self.used += bytes;
    }
};

pub const SensitiveScan = enum { disabled, public_bundle };

pub const TestFault = enum {
    none,
    before_file_sync,
    before_parent_sync,
    mutate_source_after_first_chunk,
    cancel_after_first_chunk,
    replace_destination_before_reopen,
    replace_destination_with_fifo,
    replace_destination_with_fifo_and_cancel,
};

pub const Options = struct {
    scan: SensitiveScan = .disabled,
    fault: TestFault = .none,
    cancel: ?*const std.atomic.Value(bool) = null,
};

pub const Result = struct {
    path: []const u8,
    size: u64,
    sha256: [64]u8,
    source_snapshot: files.Snapshot,
    destination_snapshot: files.Snapshot,
};

pub const sensitive_patterns = [_][]const u8{
    "-----BEGIN PRIVATE KEY",
    "-----BEGIN RSA PRIVATE KEY",
    "Authorization: Bearer ",
    "AccountKey=",
    "SharedAccessSignature=",
    "accessSAS",
    "accessSas",
    "AZURE_CLIENT_SECRET",
    "PRIVATE_FIXTURE_SAS",
    "\"subscription\"",
    "\"vm_uuid\"",
    "\"os_uuid\"",
    "\"fresh_final_approval\"",
    "\"client_secret\"",
    "\"access_token\"",
    "?sv=",
    "&sig=",
};

pub fn copyRetained(
    allocator: std.mem.Allocator,
    io: std.Io,
    retained: *files.RetainedFile,
    destination_root: std.Io.Dir,
    destination_root_path: []const u8,
    relative: []const u8,
    limit: u64,
    budget: ?*Budget,
    options: Options,
) !Result {
    if (options.fault != .none and !builtin.is_test) return error.InvalidFault;
    try checkCancellation(options.cancel);
    try validateRelative(relative);
    try files.absoluteFilePath(destination_root_path);
    try validatePrivateDir(destination_root);
    const root_snapshot = try directorySnapshot(destination_root);
    try verifyRoot(io, destination_root_path, root_snapshot);
    const before = retained.file_snapshot;
    try validateSource(before, limit);
    try verifyRetained(io, retained);
    if (budget) |active| try active.reserve(before.size);

    const destination_path = try std.fs.path.join(allocator, &.{ destination_root_path, relative });
    errdefer allocator.free(destination_path);
    var parent = try ensureParent(io, destination_root, relative);
    defer parent.close(io);
    const leaf = std.fs.path.basename(relative);
    var out = parent.dir.createFile(io, leaf, .{
        .exclusive = true,
        .read = true,
        .permissions = .fromMode(0o600),
    });
    if (out) |*created| {
        defer created.close(io);
        var hasher = Sha256.init(.{});
        var scanner: Scanner = .{};
        var buffer: [chunk_size]u8 = undefined;
        var offset: u64 = 0;
        var injected = false;
        while (offset < before.size) {
            try checkCancellation(options.cancel);
            const want: usize = @intCast(@min(buffer.len, before.size - offset));
            const count = try retained.file.readPositionalAll(io, buffer[0..want], offset);
            if (count == 0) return error.FileChanged;
            const chunk = buffer[0..count];
            if (options.scan == .public_bundle) try scanner.observe(chunk);
            hasher.update(chunk);
            try created.writePositionalAll(io, chunk, offset);
            offset += count;
            if (!injected and options.fault == .mutate_source_after_first_chunk) {
                if (!builtin.is_test) return error.InvalidFault;
                try mutateSourceForTest(io, retained.path);
                injected = true;
            }
            if (!injected and options.fault == .cancel_after_first_chunk) {
                const cancel = options.cancel orelse return error.InvalidFault;
                @constCast(cancel).store(true, .release);
                injected = true;
            }
        }
        if (try retained.file.readPositionalAll(io, buffer[0..1], offset) != 0)
            return error.FileChanged;
        if (!sameCustodySnapshot(before, try files.snapshot(retained.file)))
            return error.FileChanged;
        try retained.verify(io);
        try verifyRetained(io, retained);
        const raw_digest = hasher.finalResult();
        const source_digest = std.fmt.bytesToHex(raw_digest, .lower);
        if (options.fault == .before_file_sync) {
            if (!builtin.is_test) return error.InvalidFault;
            return error.AmbiguousWrite;
        }
        try created.sync(io);
        if (options.fault == .before_parent_sync) {
            if (!builtin.is_test) return error.InvalidFault;
            return error.AmbiguousWrite;
        }
        try syncDir(io, parent.dir);
        try checkCancellation(options.cancel);
        const destination_snapshot = try files.snapshot(created.*);
        try validateDestination(destination_snapshot, before.size);
        if (options.fault == .none) {
            const scan_flags: u32 = if (options.scan == .public_bundle) DigestCache.flag_scan_checked else 0;
            if (DigestCache.computeBoundaryHash(io, retained.file, before.size)) |bhash| {
                DigestCache.put(before, 1, bhash, raw_digest, 0, scan_flags);
                DigestCache.put(destination_snapshot, 1, bhash, raw_digest, 0, scan_flags);
            }
        }
        if (options.fault == .replace_destination_before_reopen) {
            try parent.dir.rename(leaf, parent.dir, "replaced-copy", io);
            const replacement = try parent.dir.createFile(io, leaf, .{
                .exclusive = true,
                .read = true,
                .permissions = .fromMode(0o600),
            });
            defer replacement.close(io);
            var at: u64 = 0;
            while (at < before.size) {
                const want: usize = @intCast(@min(buffer.len, before.size - at));
                if (try created.readPositionalAll(io, buffer[0..want], at) != want) return error.CopyChanged;
                try replacement.writePositionalAll(io, buffer[0..want], at);
                at += want;
            }
            try replacement.sync(io);
        }
        if (options.fault == .replace_destination_with_fifo or options.fault == .replace_destination_with_fifo_and_cancel) {
            try parent.dir.rename(leaf, parent.dir, "replaced-copy", io);
            var name: [256:0]u8 = undefined;
            @memcpy(name[0..leaf.len], leaf);
            name[leaf.len] = 0;
            if (linux.errno(linux.mknodat(parent.dir.handle, name[0..leaf.len :0], linux.S.IFIFO | 0o600, 0)) != .SUCCESS)
                return error.FixtureFifo;
            if (options.fault == .replace_destination_with_fifo_and_cancel) {
                if (linux.errno(linux.kill(linux.getpid(), .INT)) != .SUCCESS) return error.FixtureSignal;
                if (!(options.cancel orelse return error.InvalidFault).load(.acquire)) return error.FixtureSignal;
            }
        }
        const observed = try hashOpened(io, parent.dir, leaf, destination_snapshot, limit, options.cancel);
        if (!std.mem.eql(u8, &source_digest, &observed))
            return error.CopyChanged;
        var named = try files.RetainedFile.open(io, destination_path, .private);
        defer named.close(io);
        if (!sameCustodySnapshot(destination_snapshot, named.file_snapshot))
            return error.CopyChanged;
        try verifyRetained(io, &named);
        try verifyRoot(io, destination_root_path, root_snapshot);
        return .{
            .path = destination_path,
            .size = before.size,
            .sha256 = source_digest,
            .source_snapshot = before,
            .destination_snapshot = destination_snapshot,
        };
    } else |err| switch (err) {
        error.PathAlreadyExists => return error.OutputExists,
        else => return err,
    }
}

fn validateSource(snapshot: files.Snapshot, limit: u64) !void {
    if (snapshot.mode & linux.S.IFMT != linux.S.IFREG or
        snapshot.nlink != 1 or snapshot.size == 0 or snapshot.size > limit or
        snapshot.uid != linux.geteuid() and snapshot.uid != 0 or
        snapshot.mode & 0o022 != 0)
        return error.UnsafeSource;
}

fn validateDestination(snapshot: files.Snapshot, size: u64) !void {
    if (snapshot.mode & linux.S.IFMT != linux.S.IFREG or
        snapshot.nlink != 1 or snapshot.size != size or
        snapshot.uid != linux.geteuid() or snapshot.mode & 0o7777 != 0o600)
        return error.UnsafeDestination;
}

fn validateRelative(path: []const u8) !void {
    if (path.len == 0 or path.len > 512 or std.fs.path.isAbsolute(path) or
        path[0] == '/' or path[path.len - 1] == '/')
        return error.InvalidMemberPath;
    var parts = std.mem.splitScalar(u8, path, '/');
    var count: usize = 0;
    while (parts.next()) |part| {
        try files.basename(part);
        count += 1;
        if (count > 3) return error.InvalidMemberPath;
    }
    if (count == 0) return error.InvalidMemberPath;
}

const Parent = struct {
    dir: std.Io.Dir,
    close_dir: bool,

    fn close(self: *Parent, io: std.Io) void {
        if (self.close_dir) self.dir.close(io);
        self.* = undefined;
    }
};

fn ensureParent(io: std.Io, root: std.Io.Dir, relative: []const u8) !Parent {
    var parts = std.mem.splitScalar(u8, relative, '/');
    var component = parts.next() orelse return error.InvalidMemberPath;
    var current = root;
    var close_current = false;
    errdefer if (close_current) current.close(io);
    while (parts.next()) |next| {
        var created = true;
        current.createDir(io, component, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => created = false,
            else => return err,
        };
        const child = try current.openDir(io, component, .{ .follow_symlinks = false, .iterate = true });
        errdefer child.close(io);
        try validatePrivateDir(child);
        if (created) {
            try syncDir(io, child);
            try syncDir(io, current);
        }
        if (close_current) current.close(io);
        current = child;
        close_current = true;
        component = next;
    }
    return .{ .dir = current, .close_dir = close_current };
}

fn validatePrivateDir(dir: std.Io.Dir) !void {
    const snapshot = try files.snapshot(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } });
    if (snapshot.mode & linux.S.IFMT != linux.S.IFDIR or snapshot.uid != linux.geteuid() or
        snapshot.mode & 0o7777 != 0o700)
        return error.UnsafeDestination;
}

fn hashOpened(io: std.Io, parent: std.Io.Dir, name: []const u8, expected: files.Snapshot, limit: u64, cancel: ?*const std.atomic.Value(bool)) ![64]u8 {
    try checkCancellation(cancel);
    const size = expected.size;
    if (size == 0 or size > limit) return error.UnsafeDestination;
    const file = try (files.FileParent{ .directory = parent, .name = name, .policy = .private }).openFile(io);
    defer file.close(io);
    const snapshot = try files.snapshot(file);
    try validateDestination(snapshot, size);
    if (!sameCustodySnapshot(expected, snapshot)) return error.CopyChanged;
    const bhash = DigestCache.computeBoundaryHash(io, file, size);
    if (bhash) |bh| {
        if (DigestCache.get(snapshot, 1, bh)) |cached| {
            try checkCancellation(cancel);
            if (!sameCustodySnapshot(snapshot, try files.snapshot(file)))
                return error.CopyChanged;
            return std.fmt.bytesToHex(cached.digest, .lower);
        }
    }
    var hasher = Sha256.init(.{});
    var buffer: [chunk_size]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        try checkCancellation(cancel);
        const count = try file.readPositionalAll(io, buffer[0..@intCast(@min(buffer.len, size - offset))], offset);
        if (count == 0) return error.CopyChanged;
        hasher.update(buffer[0..count]);
        offset += count;
    }
    if (try file.readPositionalAll(io, buffer[0..1], offset) != 0)
        return error.CopyChanged;
    if (!sameCustodySnapshot(snapshot, try files.snapshot(file)))
        return error.CopyChanged;
    const digest = hasher.finalResult();
    if (bhash) |bh| DigestCache.put(snapshot, 1, bh, digest, 0, 0);
    return std.fmt.bytesToHex(digest, .lower);
}

fn syncDir(io: std.Io, dir: std.Io.Dir) !void {
    try (std.Io.File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

pub fn sameCustodySnapshot(a: files.Snapshot, b: files.Snapshot) bool {
    return a.mask.GID and b.mask.GID and files.sameSnapshot(a, b) and a.gid == b.gid;
}

pub fn checkCancellation(cancel: ?*const std.atomic.Value(bool)) !void {
    if (cancel) |flag| if (flag.load(.acquire)) return error.Cancelled;
}

pub fn directorySnapshot(dir: std.Io.Dir) !files.Snapshot {
    return files.snapshot(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } });
}

pub fn sameDirectory(a: files.Snapshot, b: files.Snapshot) bool {
    return a.mask.GID and b.mask.GID and a.ino == b.ino and a.dev_major == b.dev_major and a.dev_minor == b.dev_minor and
        a.mode == b.mode and a.uid == b.uid and a.gid == b.gid;
}

pub fn verifyRoot(io: std.Io, path: []const u8, expected: files.Snapshot) !void {
    const named = try files.Directory.open(io, path);
    defer named.close(io);
    if (!sameDirectory(expected, try directorySnapshot(named.dir))) return error.UnsafeDestination;
}

pub fn verifyRetained(io: std.Io, retained: *const files.RetainedFile) !void {
    try retained.verify(io);
    if (!sameCustodySnapshot(retained.file_snapshot, try files.snapshot(retained.file)))
        return error.FileChanged;
    var named = try files.RetainedFile.open(io, retained.path, retained.policy);
    defer named.close(io);
    if (!sameCustodySnapshot(retained.file_snapshot, named.file_snapshot) or
        retained.directory_count != named.directory_count) return error.FileChanged;
    for (0..retained.directory_count) |i| {
        if (!sameDirectory(retained.directory_snapshots[i], try directorySnapshot(retained.directories[i])) or
            !sameDirectory(retained.directory_snapshots[i], named.directory_snapshots[i]))
            return error.FileChanged;
    }
}

pub fn hashRetained(io: std.Io, retained: *const files.RetainedFile, limit: u64, cancel: ?*const std.atomic.Value(bool)) ![64]u8 {
    try validateSource(retained.file_snapshot, limit);
    try verifyRetained(io, retained);
    const bhash = DigestCache.computeBoundaryHash(io, retained.file, retained.file_snapshot.size);
    if (bhash) |bh| {
        if (DigestCache.get(retained.file_snapshot, 1, bh)) |cached| {
            try checkCancellation(cancel);
            try verifyRetained(io, retained);
            return std.fmt.bytesToHex(cached.digest, .lower);
        }
    }
    var hasher = Sha256.init(.{});
    var buffer: [chunk_size]u8 = undefined;
    var offset: u64 = 0;
    while (offset < retained.file_snapshot.size) {
        try checkCancellation(cancel);
        const want: usize = @intCast(@min(buffer.len, retained.file_snapshot.size - offset));
        const count = try retained.file.readPositionalAll(io, buffer[0..want], offset);
        if (count != want) return error.FileChanged;
        hasher.update(buffer[0..count]);
        offset += count;
    }
    if (try retained.file.readPositionalAll(io, buffer[0..1], offset) != 0) return error.FileChanged;
    try verifyRetained(io, retained);
    const digest = hasher.finalResult();
    if (bhash) |bh| DigestCache.put(retained.file_snapshot, 1, bh, digest, 0, 0);
    return std.fmt.bytesToHex(digest, .lower);
}

pub const DigestCache = struct {
    pub const min_size: u64 = 64 * 1024;
    pub const probe_window: usize = 4096;
    pub const flag_has_crc32: u32 = 1 << 0;
    pub const flag_scan_checked: u32 = 1 << 1;
    pub const flag_scan_sensitive: u32 = 1 << 2;
    const shm_magic = "UKDGST01".*;
    const shm_version: u32 = 1;
    const num_sets: usize = 128;
    const ways: usize = 4;
    const total_slots: usize = num_sets * ways;

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

    pub fn computeBoundaryHashSlice(bytes: []const u8) ?u64 {
        if (bytes.len < min_size) return null;
        var hasher = std.hash.Wyhash.init(0);
        const mid_offset: usize = if (bytes.len >= 2 * 1024 * 1024)
            1024 * 1024
        else
            (bytes.len / 2) & ~@as(usize, 4095);
        hasher.update(bytes[0..probe_window]);
        hasher.update(bytes[mid_offset .. mid_offset + probe_window]);
        hasher.update(bytes[bytes.len - probe_window .. bytes.len]);
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
                if ((entry.flags & flag_has_crc32) != 0) slot.crc32 = entry.crc32;
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
        var image: ShmImage = undefined;
        const dest = std.mem.asBytes(&image);
        var offset: usize = 0;
        while (offset < dest.len) {
            const r = linux.read(fd, dest[offset..].ptr, dest.len - offset);
            if (linux.errno(r) != .SUCCESS or r == 0) return;
            offset += r;
        }
        if (!std.mem.eql(u8, &image.magic, &shm_magic) or image.version != shm_version) return;
        for (image.entries) |entry| {
            if (entry.key.kind != 0) _ = insertLocked(entry);
        }
        loaded_shm_ino = stx.ino;
        loaded_shm_mtime_sec = stx.mtime.sec;
        loaded_shm_mtime_nsec = stx.mtime.nsec;
    }

    fn saveShmLocked() void {
        var fsize_rlim: [2]u64 = .{ ~@as(u64, 0), ~@as(u64, 0) };
        _ = linux.syscall4(.prlimit64, 0, 1, 0, @intFromPtr(&fsize_rlim));
        if (fsize_rlim[0] < 64 * 1024 * 1024) return;
        var path_buf: [96]u8 = undefined;
        const path = shmPath(&path_buf) orelse return;
        var tmp_buf: [128]u8 = undefined;
        const seq = tmp_seq;
        tmp_seq +%= 1;
        const tmp_slice = std.fmt.bufPrint(tmp_buf[0 .. tmp_buf.len - 1], "{s}.{d}.{d}.tmp", .{ path, linux.getpid(), seq }) catch return;
        tmp_buf[tmp_slice.len] = 0;
        const tmp_path = tmp_buf[0..tmp_slice.len :0];
        const rc = linux.openat(
            linux.AT.FDCWD,
            tmp_path.ptr,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true },
            0o600,
        );
        if (linux.errno(rc) != .SUCCESS) return;
        const fd: linux.fd_t = @intCast(rc);
        var image: ShmImage = .{ .entries = table };
        const src = std.mem.asBytes(&image);
        var offset: usize = 0;
        var ok = true;
        while (offset < src.len) {
            const w = linux.write(fd, src[offset..].ptr, src.len - offset);
            if (linux.errno(w) != .SUCCESS or w == 0) {
                ok = false;
                break;
            }
            offset += w;
        }
        _ = linux.close(fd);
        if (!ok or linux.errno(linux.renameat(linux.AT.FDCWD, tmp_path.ptr, linux.AT.FDCWD, path.ptr)) != .SUCCESS) {
            _ = linux.unlinkat(linux.AT.FDCWD, tmp_path.ptr, 0);
        }
    }

    pub fn get(snapshot: files.Snapshot, kind: u64, boundary_hash: u64) ?Entry {
        const key = makeKey(snapshot, kind, boundary_hash);
        acquire();
        defer release();
        if (findLocked(key)) |found| return found;
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
            saveShmLocked();
        }
    }
};

pub const Scanner = struct {
    const max_pattern_len = blk: {
        var max_len: usize = 0;
        for (sensitive_patterns) |pattern| {
            std.debug.assert(pattern.len > 0 and pattern.len <= scan_tail);
            for (pattern) |byte| std.debug.assert(byte != 0);
            if (pattern.len > max_len) max_len = pattern.len;
        }
        break :blk max_len;
    };

    tail: [scan_tail]u8 = undefined,
    tail_len: usize = 0,

    pub fn observe(self: *Scanner, chunk: []const u8) !void {
        if (chunk.len > chunk_size) return error.InvalidScanChunk;
        if (chunk.len <= scan_tail) {
            var scan: [2 * scan_tail]u8 = undefined;
            @memcpy(scan[0..self.tail_len], self.tail[0..self.tail_len]);
            @memcpy(scan[self.tail_len..][0..chunk.len], chunk);
            for (sensitive_patterns) |pattern| {
                if (std.mem.indexOf(u8, scan[0 .. self.tail_len + chunk.len], pattern) != null)
                    return error.SensitivePattern;
            }
            const keep = @min(self.tail_len, scan_tail - chunk.len);
            if (keep > 0)
                std.mem.copyForwards(u8, self.tail[0..keep], self.tail[self.tail_len - keep .. self.tail_len]);
            @memcpy(self.tail[keep .. keep + chunk.len], chunk);
            self.tail_len = keep + chunk.len;
            return;
        }
        if (std.mem.allEqual(u8, chunk, 0)) {
            self.tail_len = 0;
            return;
        }
        if (self.tail_len > 0) {
            const prefix_len = max_pattern_len - 1;
            var boundary: [scan_tail + prefix_len]u8 = undefined;
            @memcpy(boundary[0..self.tail_len], self.tail[0..self.tail_len]);
            @memcpy(boundary[self.tail_len..][0..prefix_len], chunk[0..prefix_len]);
            for (sensitive_patterns) |pattern| {
                if (std.mem.indexOf(u8, boundary[0 .. self.tail_len + prefix_len], pattern) != null)
                    return error.SensitivePattern;
            }
        }
        for (sensitive_patterns) |pattern| {
            if (std.mem.indexOf(u8, chunk, pattern) != null)
                return error.SensitivePattern;
        }
        @memcpy(self.tail[0..], chunk[chunk.len - scan_tail ..]);
        self.tail_len = scan_tail;
    }
};

fn mutateSourceForTest(io: std.Io, path: []const u8) !void {
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_write, .follow_symlinks = false });
    defer file.close(io);
    var byte: [1]u8 = undefined;
    if (try file.readPositionalAll(io, &byte, 0) != 1) return error.FileChanged;
    byte[0] ^= 0x01;
    try file.writePositionalAll(io, &byte, 0);
    try file.sync(io);
}
