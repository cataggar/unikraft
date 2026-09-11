const std = @import("std");
const linux = std.os.linux;
const c = @import("contracts.zig");
const paths = @import("facade_paths");

/// The current foundation validates with an O_PATH directory. Retain its policy
/// and identity, but obtain a readable directory descriptor for lock/publication
/// fsync until the shared foundation supplies that descriptor itself.
pub fn openPrivate(io: std.Io, path: []const u8) !c.core.private_files.Directory {
    const validated = try c.core.private_files.Directory.open(io, path);
    defer validated.close(io);
    const directory = try validated.dir.openDir(io, ".", .{ .follow_symlinks = false, .iterate = true });
    errdefer directory.close(io);
    if (!std.meta.eql(
        try metadata(.{ .handle = validated.dir.handle, .flags = .{ .nonblocking = false } }),
        try metadata(.{ .handle = directory.handle, .flags = .{ .nonblocking = false } }),
    )) return error.SourceChanged;
    return .{ .dir = directory };
}

pub const Policy = enum { source, artifact, executable, private };
pub const Metadata = struct {
    device: u64,
    inode: u64,
    size: u64,
    mode: u16,
    uid: u32,
    links: u64,
    modified_ns: i128,
    changed_ns: i128,
};

pub fn metadata(file: std.Io.File) !Metadata {
    var value: linux.Statx = undefined;
    while (true) {
        switch (linux.errno(linux.statx(file.handle, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &value))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.MetadataUnavailable,
        }
    }
    if (!value.mask.UID or !value.mask.INO or !value.mask.SIZE or !value.mask.MODE or !value.mask.CTIME or !value.mask.MTIME)
        return error.MetadataUnavailable;
    return .{
        .device = (@as(u64, value.dev_major) << 32) | value.dev_minor,
        .inode = value.ino,
        .size = value.size,
        .mode = value.mode,
        .uid = value.uid,
        .links = value.nlink,
        .modified_ns = @as(i128, value.mtime.sec) * std.time.ns_per_s + value.mtime.nsec,
        .changed_ns = @as(i128, value.ctime.sec) * std.time.ns_per_s + value.ctime.nsec,
    };
}

pub const Directory = struct {
    dir: std.Io.Dir,
    path: []const u8,

    /// Source/artifact directories deliberately differ from the core's 0700 state directories.
    pub fn open(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Directory {
        if (!std.fs.path.isAbsolute(path) or path.len < 2 or path[path.len - 1] == '/') return error.UnsafePath;
        var current = try std.Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false });
        errdefer current.close(io);
        var parts = std.mem.splitScalar(u8, path[1..], '/');
        while (parts.next()) |part| {
            try c.core.private_files.basename(part);
            try checkDirectory(current);
            const next = try current.openDir(io, part, .{ .follow_symlinks = false, .iterate = true });
            current.close(io);
            current = next;
        }
        try checkDirectory(current);
        const canonical = try paths.canonicalizeNearestExisting(allocator, io, path);
        errdefer allocator.free(canonical.path);
        if (!canonical.exists or !std.mem.eql(u8, canonical.path, path)) return error.UnsafePath;
        return .{ .dir = current, .path = canonical.path };
    }
    pub fn close(self: Directory, allocator: std.mem.Allocator, io: std.Io) void {
        self.dir.close(io);
        allocator.free(self.path);
    }
    pub fn parent(self: Directory, io: std.Io, relative: []const u8) !std.Io.Dir {
        try c.relative(relative);
        var current = try self.dir.openDir(io, ".", .{ .follow_symlinks = false, .iterate = true });
        errdefer current.close(io);
        try checkDirectory(current);
        var parts = std.mem.splitScalar(u8, relative, '/');
        while (parts.next()) |part| {
            if (parts.peek() == null) break;
            const next = try current.openDir(io, part, .{ .follow_symlinks = false, .iterate = true });
            current.close(io);
            current = next;
            try checkDirectory(current);
        }
        return current;
    }
    pub fn openFile(self: Directory, io: std.Io, relative: []const u8, policy: Policy) !std.Io.File {
        const directory = try self.parent(io, relative);
        defer directory.close(io);
        const path_file = try directory.openFile(io, std.fs.path.basename(relative), .{ .path_only = true, .follow_symlinks = false });
        defer path_file.close(io);
        const before = try metadata(path_file);
        try checkFile(before, policy);
        var path: [64]u8 = undefined;
        const handle_path = try std.fmt.bufPrint(&path, "/proc/self/fd/{d}", .{path_file.handle});
        const file = try std.Io.Dir.openFileAbsolute(io, handle_path, .{});
        errdefer file.close(io);
        if (!std.meta.eql(before, try metadata(file))) return error.SourceChanged;
        return file;
    }
    pub fn read(self: Directory, allocator: std.mem.Allocator, io: std.Io, relative: []const u8, maximum: usize, policy: Policy) ![]u8 {
        const file = try self.openFile(io, relative, policy);
        defer file.close(io);
        const before = try metadata(file);
        if (before.size > maximum) return error.FileTooLarge;
        const data = try allocator.alloc(u8, @as(usize, @intCast(before.size)) + 1);
        defer {
            std.crypto.secureZero(u8, data);
            allocator.free(data);
        }
        const count = try file.readPositionalAll(io, data, 0);
        if (count != before.size or !std.meta.eql(before, try metadata(file))) return error.SourceChanged;
        const named = try self.openFile(io, relative, policy);
        defer named.close(io);
        if (!std.meta.eql(before, try metadata(named))) return error.SourceChanged;
        return allocator.dupe(u8, data[0..count]);
    }
    pub fn record(self: Directory, allocator: std.mem.Allocator, io: std.Io, relative: []const u8, maximum: u64, policy: Policy) !c.File {
        const file = try self.openFile(io, relative, policy);
        defer file.close(io);
        const before = try metadata(file);
        if (before.size > maximum) return error.FileTooLarge;
        const sha = try hashFile(io, file, before.size);
        if (!std.meta.eql(before, try metadata(file))) return error.SourceChanged;
        const again = try self.openFile(io, relative, policy);
        defer again.close(io);
        if (!std.meta.eql(before, try metadata(again))) return error.SourceChanged;
        return .{ .path = try allocator.dupe(u8, relative), .size = before.size, .sha256 = sha, .mode = before.mode & 0o7777 };
    }
};

fn checkDirectory(dir: std.Io.Dir) !void {
    const value = try metadata(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } });
    if (value.mode & linux.S.IFMT != linux.S.IFDIR or value.mode & 0o022 != 0 or
        (value.uid != 0 and value.uid != linux.geteuid())) return error.UnsafeFile;
}
fn checkFile(value: Metadata, policy: Policy) !void {
    if (value.mode & linux.S.IFMT != linux.S.IFREG or value.mode & 0o7022 != 0 or
        (value.uid != 0 and value.uid != linux.geteuid())) return error.UnsafeFile;
    if (policy == .private and (value.mode & 0o7777 != 0o600 or value.links != 1 or value.uid != linux.geteuid()))
        return error.UnsafeFile;
    if (policy == .executable and value.mode & 0o111 == 0) return error.UnsafeFile;
}
pub fn hashFile(io: std.Io, file: std.Io.File, size: u64) !c.Sha {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var offset: u64 = 0;
    while (offset < size) {
        const count = try file.readPositionalAll(io, buffer[0..@min(buffer.len, size - offset)], offset);
        if (count == 0) return error.SourceChanged;
        hash.update(buffer[0..count]);
        offset += count;
    }
    if (try file.readPositionalAll(io, buffer[0..1], offset) != 0) return error.SourceChanged;
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}

pub const Inventory = struct {
    entries: []c.File,
    tree: c.Tree,
};
const Subdirectory = struct { path: []const u8, mode: u16 };

fn collect(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: Directory,
    directory: std.Io.Dir,
    prefix: []const u8,
    entries: *std.ArrayList(c.File),
    directories: *std.ArrayList(Subdirectory),
    total: *u64,
    maximum_files: usize,
    maximum_bytes: u64,
    depth: usize,
) anyerror!void {
    if (depth > 64) return error.LimitExceeded;
    try checkDirectory(directory);
    const before = try metadata(.{ .handle = directory.handle, .flags = .{ .nonblocking = false } });
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        const relative = if (prefix.len == 0)
            try allocator.dupe(u8, entry.name)
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, entry.name });
        defer allocator.free(relative);
        try c.relative(relative);
        const handle = try directory.openFile(io, entry.name, .{ .path_only = true, .follow_symlinks = false });
        defer handle.close(io);
        const identity = try metadata(handle);
        switch (identity.mode & linux.S.IFMT) {
            linux.S.IFDIR => {
                if (directories.items.len >= maximum_files) return error.LimitExceeded;
                const child = try directory.openDir(io, entry.name, .{ .follow_symlinks = false, .iterate = true });
                defer child.close(io);
                if (!std.meta.eql(identity, try metadata(.{ .handle = child.handle, .flags = .{ .nonblocking = false } })))
                    return error.SourceChanged;
                try directories.append(allocator, .{ .path = try allocator.dupe(u8, relative), .mode = identity.mode & 0o7777 });
                try collect(allocator, io, root, child, relative, entries, directories, total, maximum_files, maximum_bytes, depth + 1);
                const named = try directory.openDir(io, entry.name, .{ .follow_symlinks = false });
                defer named.close(io);
                if (!std.meta.eql(identity, try metadata(.{ .handle = named.handle, .flags = .{ .nonblocking = false } })))
                    return error.SourceChanged;
            },
            linux.S.IFREG => {
                if (entries.items.len >= maximum_files or total.* > maximum_bytes) return error.LimitExceeded;
                const record = try root.record(allocator, io, relative, maximum_bytes - total.*, .artifact);
                const named = try root.openFile(io, relative, .artifact);
                defer named.close(io);
                if (!std.meta.eql(identity, try metadata(named))) return error.SourceChanged;
                total.* = try std.math.add(u64, total.*, record.size);
                try entries.append(allocator, record);
            },
            else => return error.UnsafeFile,
        }
    }
    if (!std.meta.eql(before, try metadata(.{ .handle = directory.handle, .flags = .{ .nonblocking = false } })))
        return error.SourceChanged;
}

pub fn inventory(allocator: std.mem.Allocator, io: std.Io, directory: Directory, maximum_files: usize, maximum_bytes: u64) !Inventory {
    var entries: std.ArrayList(c.File) = .empty;
    var directories: std.ArrayList(Subdirectory) = .empty;
    defer {
        for (directories.items) |item| allocator.free(item.path);
        directories.deinit(allocator);
    }
    var total: u64 = 0;
    errdefer {
        for (entries.items) |entry| allocator.free(entry.path);
        entries.deinit(allocator);
    }
    try collect(allocator, io, directory, directory.dir, "", &entries, &directories, &total, maximum_files, maximum_bytes, 0);
    std.mem.sort(c.File, entries.items, {}, struct {
        fn less(_: void, a: c.File, b: c.File) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.less);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("hyperv-native-tree-v1\x00");
    std.mem.sort(Subdirectory, directories.items, {}, struct {
        fn less(_: void, a: Subdirectory, b: Subdirectory) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.less);
    for (directories.items) |entry| {
        var numbers: [6]u8 = undefined;
        std.mem.writeInt(u32, numbers[0..4], @intCast(entry.path.len), .big);
        std.mem.writeInt(u16, numbers[4..6], entry.mode, .big);
        hash.update("D");
        hash.update(&numbers);
        hash.update(entry.path);
    }
    for (entries.items) |entry| {
        var numbers: [14]u8 = undefined;
        std.mem.writeInt(u32, numbers[0..4], @intCast(entry.path.len), .big);
        std.mem.writeInt(u64, numbers[4..12], entry.size, .big);
        std.mem.writeInt(u16, numbers[12..14], entry.mode, .big);
        hash.update("F");
        hash.update(&numbers);
        hash.update(entry.path);
        hash.update(&entry.sha256);
    }
    const count: u32 = @intCast(entries.items.len);
    return .{ .entries = try entries.toOwnedSlice(allocator), .tree = .{
        .sha256 = std.fmt.bytesToHex(hash.finalResult(), .lower),
        .files = count,
        .bytes = total,
    } };
}

pub fn requireFile(actual: c.File, expected: c.File) !void {
    if (!std.mem.eql(u8, actual.path, expected.path) or actual.size != expected.size or actual.mode != expected.mode or
        !std.crypto.timing_safe.eql(c.Sha, actual.sha256, expected.sha256)) return error.HashMismatch;
}
pub fn requireTree(actual: c.Tree, expected: c.Tree) !void {
    if (!std.meta.eql(actual, expected)) return error.HashMismatch;
}

pub fn requireDirectoryIdentity(actual: Directory, expected: Directory) !void {
    if (!std.mem.eql(u8, actual.path, expected.path)) return error.UnreviewedInput;
    const left = try metadata(.{ .handle = actual.dir.handle, .flags = .{ .nonblocking = false } });
    const right = try metadata(.{ .handle = expected.dir.handle, .flags = .{ .nonblocking = false } });
    if (left.device != right.device or left.inode != right.inode or left.mode != right.mode or left.uid != right.uid)
        return error.UnreviewedInput;
}

/// State/receipt publication retains the core's independent recording and cleanup lanes.
pub fn publish(lock: *c.core.private_files.Locked, io: std.Io, name: []const u8, bytes: []const u8) !c.core.private_files.CommitResult {
    return lock.createImmutable(io, name, bytes);
}

pub fn requireLock(io: std.Io, lock: *c.core.private_files.Locked) !void {
    const held = lock.file orelse return error.LockNotHeld;
    const named = try lock.directory.openFile(io, ".writer.lock");
    defer named.close(io);
    if (!std.meta.eql(try metadata(held), try metadata(named))) return error.LockNotHeld;
    const directory = try metadata(.{ .handle = lock.directory.dir.handle, .flags = .{ .nonblocking = false } });
    if (directory.mode & 0o7777 != 0o700 or directory.uid != linux.geteuid()) return error.UnsafeFile;
}

fn privateParents(io: std.Io, lock: *c.core.private_files.Locked, path: []const u8) !void {
    try requireLock(io, lock);
    var current = try lock.directory.dir.openDir(io, ".", .{ .follow_symlinks = false, .iterate = true });
    defer current.close(io);
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (parts.peek() == null) break;
        current.createDir(io, part, .fromMode(0o700)) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
        const next = try current.openDir(io, part, .{ .follow_symlinks = false, .iterate = true });
        errdefer next.close(io);
        const identity = try metadata(.{ .handle = next.handle, .flags = .{ .nonblocking = false } });
        if (identity.mode & 0o7777 != 0o700 or identity.uid != linux.geteuid()) return error.UnsafeFile;
        try (std.Io.File{ .handle = current.handle, .flags = .{ .nonblocking = false } }).sync(io);
        current.close(io);
        current = next;
    }
}

/// Large immutable artifact publication shares std.Io's atomic-file mechanism
/// with core state publication, but streams rather than buffering a disk image.
pub fn copyImmutable(
    allocator: std.mem.Allocator,
    io: std.Io,
    lock: *c.core.private_files.Locked,
    source: Directory,
    expected: c.File,
    destination: []const u8,
    deadline: c.core.process.Deadline,
) !c.core.private_files.CommitResult {
    try requireLock(io, lock);
    try c.relative(destination);
    if (destination[0] == '.') return error.UnsafePath;
    if (expected.size > c.total_cap) return error.FileTooLarge;
    if (try deadline.expired()) return .{ .failures = c.failure(error.DeadlineExceeded) };
    const input = try source.openFile(io, expected.path, .artifact);
    defer input.close(io);
    const before = try metadata(input);
    if (before.size != expected.size or before.mode & 0o7777 != expected.mode) return error.SourceChanged;
    try privateParents(io, lock, destination);
    const target: Directory = .{ .dir = lock.directory.dir, .path = "" };
    const parent = try target.parent(io, destination);
    defer parent.close(io);
    const parent_meta = try metadata(.{ .handle = parent.handle, .flags = .{ .nonblocking = false } });
    if (parent_meta.mode & 0o7777 != 0o700 or parent_meta.uid != linux.geteuid()) return error.UnsafeFile;
    var result: c.core.private_files.CommitResult = .{};
    var atomic = try parent.createFileAtomic(io, std.fs.path.basename(destination), .{ .permissions = .fromMode(0o600), .replace = false });
    defer atomic.deinit(io);
    copyAndPublish(allocator, io, &atomic, source, input, before, expected, deadline, &result) catch |err| {
        if (result.failures.primary == null) result.failures.primary = c.failure(err).primary;
    };
    if (atomic.file_exists) {
        const name = std.fmt.hex(atomic.file_basename_hex);
        atomic.dir.deleteFile(io, &name) catch {
            result.failures.cleanup = .{ .stage = .private_file, .category = .cleanup_failed };
            return result;
        };
        atomic.file_exists = false;
        const directory_file: std.Io.File = .{ .handle = atomic.dir.handle, .flags = .{ .nonblocking = false } };
        directory_file.sync(io) catch {
            result.failures.cleanup = .{ .stage = .private_file, .category = .cleanup_failed };
        };
    }
    return result;
}

fn copyAndPublish(
    allocator: std.mem.Allocator,
    io: std.Io,
    atomic: *std.Io.File.Atomic,
    source: Directory,
    input: std.Io.File,
    before: Metadata,
    expected: c.File,
    deadline: c.core.process.Deadline,
    result: *c.core.private_files.CommitResult,
) !void {
    _ = allocator;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var offset: u64 = 0;
    while (offset < expected.size) {
        if (try deadline.expired()) return error.DeadlineExceeded;
        const count = try input.readPositional(io, &.{buffer[0..@min(buffer.len, expected.size - offset)]}, offset);
        if (try deadline.expired()) return error.DeadlineExceeded;
        if (count == 0) return error.SourceChanged;
        hash.update(buffer[0..count]);
        var written: usize = 0;
        while (written < count) {
            if (try deadline.expired()) return error.DeadlineExceeded;
            const progress = try atomic.file.writePositional(io, &.{buffer[written..count]}, offset + written);
            if (try deadline.expired()) return error.DeadlineExceeded;
            if (progress == 0) return error.NoProgress;
            written += progress;
        }
        offset += count;
    }
    if (try deadline.expired()) return error.DeadlineExceeded;
    const tail = try input.readPositional(io, &.{buffer[0..1]}, offset);
    if (try deadline.expired()) return error.DeadlineExceeded;
    if (tail != 0 or
        !std.meta.eql(before, try metadata(input)) or
        !std.meta.eql(std.fmt.bytesToHex(hash.finalResult(), .lower), expected.sha256)) return error.SourceChanged;
    const named = try source.openFile(io, expected.path, .artifact);
    defer named.close(io);
    if (!std.meta.eql(before, try metadata(named))) return error.SourceChanged;
    try atomic.file.sync(io);
    if (try deadline.expired()) return error.DeadlineExceeded;
    result.status = .publication_unknown;
    try atomic.link(io);
    result.status = .visible_not_durable;
    const directory: std.Io.File = .{ .handle = atomic.dir.handle, .flags = .{ .nonblocking = false } };
    directory.sync(io) catch |err| {
        result.failures.recording = .{ .stage = .private_file, .category = .local_io };
        return err;
    };
    result.status = .durable;
}
