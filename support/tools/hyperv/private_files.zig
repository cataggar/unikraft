const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const contracts = @import("contracts.zig");
const diagnostics = @import("diagnostics.zig");
const sensitive = @import("sensitive.zig");

comptime {
    if (builtin.os.tag != .linux) @compileError("Hyper-V private host files currently require Linux");
}

pub const Directory = struct {
    dir: std.Io.Dir,

    /// Opens each path component without following symlinks, then retains the descriptor.
    pub fn open(io: std.Io, path: []const u8) !Directory {
        return .{ .dir = try openDirectory(io, path, .private) };
    }

    /// The supervisor selected cwd through its already validated descriptor.
    pub fn openWorkerCwd(io: std.Io) !Directory {
        const dir = try std.Io.Dir.cwd().openDir(io, ".", .{ .follow_symlinks = false, .iterate = true });
        errdefer dir.close(io);
        try validateDirectory(io, dir, true);
        return .{ .dir = dir };
    }

    pub fn close(self: Directory, io: std.Io) void {
        self.dir.close(io);
    }

    /// Safe for hostile FIFO/device names: the descriptor is opened nonblocking before stat.
    pub fn openFile(self: Directory, io: std.Io, name: []const u8) !std.Io.File {
        return openFilePolicy(io, self.dir, name, .private);
    }

    pub fn read(
        self: Directory,
        io: std.Io,
        allocator: std.mem.Allocator,
        name: []const u8,
        maximum: usize,
        expected_sha256: ?contracts.Sha256,
    ) ![]u8 {
        var contents = try self.readSensitive(io, allocator, name, maximum, expected_sha256);
        defer contents.deinit();
        return allocator.dupe(u8, contents.bytes());
    }

    pub fn readSensitive(
        self: Directory,
        io: std.Io,
        allocator: std.mem.Allocator,
        name: []const u8,
        maximum: usize,
        expected_sha256: ?contracts.Sha256,
    ) !sensitive.Buffer {
        if (maximum == 0 or maximum > 64 * 1024 * 1024) return error.InvalidLimit;
        const file = try self.openFile(io, name);
        defer file.close(io);
        const before = try snapshot(file);
        if (before.size > maximum) return error.FileTooLarge;
        var result: sensitive.Buffer = .{
            .allocator = allocator,
            .storage = try allocator.alloc(u8, @as(usize, @intCast(before.size)) + 1),
            .length = @intCast(before.size),
        };
        errdefer result.deinit();
        const count = try file.readPositionalAll(io, result.storage, 0);
        const after = try snapshot(file);
        try validateFile(io, file);
        if (count != before.size or !sameSnapshot(before, after))
            return error.FileChanged;
        if (expected_sha256) |expected| {
            var observed: contracts.Sha256 = undefined;
            std.crypto.hash.sha2.Sha256.hash(result.bytes(), &observed, .{});
            if (!std.crypto.timing_safe.eql(contracts.Sha256, observed, expected))
                return error.HashMismatch;
        }
        return result;
    }

    /// The stable lock inode is never renamed or unlinked, including on release.
    pub fn lock(self: Directory, io: std.Io) !Locked {
        const name = ".writer.lock";
        const fd = try openat(self.dir.handle, name, .{
            .ACCMODE = .RDWR,
            .CREAT = true,
            .NOFOLLOW = true,
            .NONBLOCK = true,
            .CLOEXEC = true,
        });
        const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = true } };
        errdefer file.close(io);
        try validateFile(io, file);
        if (!try file.tryLock(io, .exclusive)) return error.WouldBlock;
        try file.sync(io);
        try syncDirectory(io, self.dir);
        return .{ .directory = self, .file = file };
    }
};

pub const FilePolicy = enum { private, artifact };
pub const Snapshot = linux.Statx;

pub fn snapshot(file: std.Io.File) !Snapshot {
    var result: Snapshot = undefined;
    while (true) {
        switch (linux.errno(linux.statx(file.handle, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &result))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.MetadataUnavailable,
        }
    }
    const mask = result.mask;
    if (!mask.TYPE or !mask.MODE or !mask.UID or !mask.INO or !mask.SIZE or !mask.CTIME or !mask.MTIME or !mask.NLINK)
        return error.IncompleteMetadata;
    return result;
}

pub fn sameSnapshot(a: Snapshot, b: Snapshot) bool {
    return a.ino == b.ino and a.dev_major == b.dev_major and a.dev_minor == b.dev_minor and
        a.size == b.size and a.mode == b.mode and a.uid == b.uid and a.nlink == b.nlink and
        a.mtime.sec == b.mtime.sec and a.mtime.nsec == b.mtime.nsec and
        a.ctime.sec == b.ctime.sec and a.ctime.nsec == b.ctime.nsec;
}

pub fn absoluteFilePath(path: []const u8) !void {
    if (path.len < 2 or path.len > 4095 or path[0] != '/' or path[path.len - 1] == '/')
        return error.UnsafePath;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| try basename(part);
}

/// Shared descriptor walk; artifact policy intentionally does not require a
/// private file mode, current-user ownership or a single hard link.
pub const FileParent = struct {
    directory: std.Io.Dir,
    name: []const u8,
    policy: FilePolicy,

    pub fn open(io: std.Io, path: []const u8, policy: FilePolicy) !FileParent {
        try absoluteFilePath(path);
        return .{
            .directory = try openDirectory(io, std.fs.path.dirname(path).?, policy),
            .name = std.fs.path.basename(path),
            .policy = policy,
        };
    }

    pub fn close(self: FileParent, io: std.Io) void {
        self.directory.close(io);
    }

    pub fn dir(self: FileParent) std.Io.Dir {
        return self.directory;
    }

    pub fn sync(self: FileParent, io: std.Io) !void {
        try syncDirectory(io, self.directory);
    }

    pub fn openFile(self: FileParent, io: std.Io) !std.Io.File {
        return openFilePolicy(io, self.directory, self.name, self.policy);
    }
};

pub fn openAbsolute(io: std.Io, path: []const u8, policy: FilePolicy) !std.Io.File {
    const parent = try FileParent.open(io, path, policy);
    defer parent.close(io);
    return parent.openFile(io);
}

pub fn readSensitiveAbsolute(io: std.Io, allocator: std.mem.Allocator, path: []const u8, maximum: usize, expected: ?contracts.Sha256) !sensitive.Buffer {
    const parent = try FileParent.open(io, path, .private);
    defer parent.close(io);
    return (Directory{ .dir = parent.directory }).readSensitive(io, allocator, parent.name, maximum, expected);
}

pub fn openDirectory(io: std.Io, path: []const u8, policy: FilePolicy) !std.Io.Dir {
    if (!std.fs.path.isAbsolute(path) or path.len == 0 or path.len > 4095 or
        (path.len > 1 and path[path.len - 1] == '/')) return error.UnsafePath;
    var current = try std.Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false, .iterate = true });
    errdefer current.close(io);
    if (path.len > 1) {
        var parts = std.mem.splitScalar(u8, path[1..], '/');
        while (parts.next()) |part| {
            try basename(part);
            try validateDirectory(io, current, false);
            const next = try current.openDir(io, part, .{ .follow_symlinks = false, .iterate = true });
            current.close(io);
            current = next;
        }
    }
    try validateDirectory(io, current, policy == .private);
    return current;
}

fn openFilePolicy(io: std.Io, dir: std.Io.Dir, name: []const u8, policy: FilePolicy) !std.Io.File {
    try basename(name);
    var buffer: [256:0]u8 = undefined;
    @memcpy(buffer[0..name.len], name);
    buffer[name.len] = 0;
    const fd = try openat(dir.handle, buffer[0..name.len :0], .{
        .ACCMODE = .RDONLY,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    });
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = true } };
    errdefer file.close(io);
    if (policy == .private) {
        try validateFile(io, file);
    } else if ((try file.stat(io)).kind != .file) return error.UnsafeFile;
    return file;
}

pub const CommitStatus = enum { not_committed, publication_unknown, visible_not_durable, durable };
pub const CommitResult = struct {
    status: CommitStatus = .not_committed,
    failures: diagnostics.Failures = .{},
};
pub const TestFault = enum { before_file_sync, before_rename, publication, after_rename, cleanup };

/// Borrows Directory, which must remain open. Closing this guard releases writer ownership.
pub const Locked = struct {
    directory: Directory,
    file: ?std.Io.File,

    pub fn close(self: *Locked, io: std.Io) void {
        if (self.file) |file| file.close(io);
        self.file = null;
    }

    pub fn commit(self: *Locked, io: std.Io, name: []const u8, contents: []const u8) !CommitResult {
        return self.commitImpl(io, name, contents, true, null);
    }

    pub fn createImmutable(self: *Locked, io: std.Io, name: []const u8, contents: []const u8) !CommitResult {
        return self.commitImpl(io, name, contents, false, null);
    }

    pub fn commitFault(self: *Locked, io: std.Io, name: []const u8, contents: []const u8, fault: TestFault) !CommitResult {
        if (!builtin.is_test) @compileError("Fault injection is only available to native tests");
        return self.commitImpl(io, name, contents, true, fault);
    }

    fn commitImpl(self: *Locked, io: std.Io, name: []const u8, contents: []const u8, replace: bool, fault: ?TestFault) !CommitResult {
        if (self.file == null) return error.LockNotHeld;
        try basename(name);
        if (name[0] == '.' or contents.len > 4 * 1024 * 1024) return error.InvalidState;
        try validateDirectory(io, self.directory.dir, true);
        const existing = self.directory.openFile(io, name) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (existing) |file| {
            file.close(io);
            if (!replace) return error.PathAlreadyExists;
        }
        var result: CommitResult = .{};
        var atomic = self.directory.dir.createFileAtomic(io, name, .{
            .permissions = .fromMode(0o600),
            .replace = replace,
        }) catch {
            result.failures.recording = recordingFailure();
            return result;
        };
        defer atomic.deinit(io);
        writeAndReplace(io, &atomic, contents, replace, fault, &result) catch {
            result.failures.recording = recordingFailure();
        };
        // std.Io owns the atomic-file mechanism; explicitly observe cleanup errors its
        // deinit normally suppresses so a failed write and failed cleanup stay separate.
        if (atomic.file_exists) {
            if (fault == .cleanup) {
                result.failures.cleanup = .{ .stage = .state_record, .category = .cleanup_failed };
                return result;
            }
            const scratch_name = std.fmt.hex(atomic.file_basename_hex);
            atomic.dir.deleteFile(io, &scratch_name) catch {
                result.failures.cleanup = .{ .stage = .state_record, .category = .cleanup_failed };
                return result;
            };
            atomic.file_exists = false;
            syncDirectory(io, atomic.dir) catch {
                result.failures.cleanup = .{ .stage = .state_record, .category = .cleanup_failed };
            };
        }
        return result;
    }
};

fn recordingFailure() diagnostics.Diagnostic {
    return .{ .stage = .state_record, .category = .local_io };
}

fn writeAndReplace(io: std.Io, atomic: *std.Io.File.Atomic, contents: []const u8, replace: bool, fault: ?TestFault, result: *CommitResult) !void {
    try validateFileWithLinks(io, atomic.file, true);
    try atomic.file.writePositionalAll(io, contents, 0);
    if (fault == .before_file_sync or fault == .cleanup) return error.Injected;
    try atomic.file.sync(io);
    if (fault == .before_rename) return error.Injected;
    result.status = .publication_unknown;
    if (fault == .publication) return error.Injected;
    if (replace) try atomic.replace(io) else try atomic.link(io);
    result.status = .visible_not_durable;
    if (fault == .after_rename) return error.Injected;
    try syncDirectory(io, atomic.dir);
    result.status = .durable;
}

pub fn basename(name: []const u8) !void {
    if (name.len == 0 or name.len > 255 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, ".."))
        return error.UnsafePath;
    for (name) |byte| if (byte == '/' or byte == '\\' or byte == 0 or byte < 0x20 or byte == 0x7f)
        return error.UnsafePath;
}

fn validateDirectory(io: std.Io, dir: std.Io.Dir, private: bool) !void {
    const stat = try dir.stat(io);
    const uid = try owner(dir.handle);
    const mode = stat.permissions.toMode() & 0o7777;
    if (stat.kind != .directory) return error.UnsafeFile;
    if (private) {
        if (uid != linux.geteuid() or mode != 0o700) return error.UnsafeFile;
    } else if ((uid != 0 and uid != linux.geteuid()) or mode & 0o022 != 0) return error.UnsafeFile;
}

fn validateFile(io: std.Io, file: std.Io.File) !void {
    try validateFileWithLinks(io, file, false);
}

fn validateFileWithLinks(io: std.Io, file: std.Io.File, allow_unlinked: bool) !void {
    const stat = try file.stat(io);
    if (stat.kind != .file or stat.permissions.toMode() & 0o7777 != 0o600 or
        (stat.nlink != 1 and !(allow_unlinked and stat.nlink == 0)) or
        try owner(file.handle) != linux.geteuid()) return error.UnsafeFile;
}

// File.Stat deliberately omits ownership; request only the missing Linux metadata.
fn owner(fd: linux.fd_t) !u32 {
    return (try snapshot(.{ .handle = fd, .flags = .{ .nonblocking = false } })).uid;
}

fn openat(dir: linux.fd_t, path: [:0]const u8, flags: linux.O) !linux.fd_t {
    while (true) {
        const result = linux.openat(dir, path.ptr, flags, 0o600);
        switch (linux.errno(result)) {
            .SUCCESS => return @intCast(result),
            .INTR => continue,
            .NOENT => return error.FileNotFound,
            .LOOP, .ISDIR, .NOTDIR, .ACCES, .PERM => return error.UnsafeFile,
            else => return error.FileOpenFailed,
        }
    }
}

fn syncDirectory(io: std.Io, dir: std.Io.Dir) !void {
    const file: std.Io.File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
    try file.sync(io);
}
