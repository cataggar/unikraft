const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const contracts = @import("contracts.zig");
const diagnostics = @import("diagnostics.zig");

comptime {
    if (builtin.os.tag != .linux) @compileError("Hyper-V private host files currently require Linux");
}

pub const Directory = struct {
    dir: std.Io.Dir,

    /// Opens each path component without following symlinks, then retains the descriptor.
    pub fn open(io: std.Io, path: []const u8) !Directory {
        if (!std.fs.path.isAbsolute(path) or path.len < 2 or path[path.len - 1] == '/')
            return error.UnsafePath;
        var current = try std.Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false });
        errdefer current.close(io);
        var parts = std.mem.splitScalar(u8, path[1..], '/');
        while (parts.next()) |part| {
            try basename(part);
            try validateDirectory(io, current, false);
            const next = try current.openDir(io, part, .{ .follow_symlinks = false });
            current.close(io);
            current = next;
        }
        try validateDirectory(io, current, true);
        return .{ .dir = current };
    }

    pub fn close(self: Directory, io: std.Io) void {
        self.dir.close(io);
    }

    /// Safe for hostile FIFO/device names: the descriptor is opened nonblocking before stat.
    pub fn openFile(self: Directory, io: std.Io, name: []const u8) !std.Io.File {
        try basename(name);
        var buffer: [256:0]u8 = undefined;
        @memcpy(buffer[0..name.len], name);
        buffer[name.len] = 0;
        const fd = try openat(self.dir.handle, buffer[0..name.len :0], .{
            .ACCMODE = .RDONLY,
            .NOFOLLOW = true,
            .NONBLOCK = true,
            .CLOEXEC = true,
        });
        const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = true } };
        errdefer file.close(io);
        try validateFile(io, file);
        return file;
    }

    pub fn read(
        self: Directory,
        io: std.Io,
        allocator: std.mem.Allocator,
        name: []const u8,
        maximum: usize,
        expected_sha256: ?contracts.Sha256,
    ) ![]u8 {
        if (maximum == 0 or maximum > 64 * 1024 * 1024) return error.InvalidLimit;
        const file = try self.openFile(io, name);
        defer file.close(io);
        const before = try file.stat(io);
        if (before.size > maximum) return error.FileTooLarge;
        const bytes = try allocator.alloc(u8, @as(usize, @intCast(before.size)) + 1);
        defer allocator.free(bytes);
        const count = try file.readPositionalAll(io, bytes, 0);
        const after = try file.stat(io);
        try validateFile(io, file);
        if (count != before.size or before.size != after.size or
            before.mtime.nanoseconds != after.mtime.nanoseconds or
            before.ctime.nanoseconds != after.ctime.nanoseconds)
            return error.FileChanged;
        const contents = bytes[0..count];
        if (expected_sha256) |expected| {
            var observed: contracts.Sha256 = undefined;
            std.crypto.hash.sha2.Sha256.hash(contents, &observed, .{});
            if (!std.crypto.timing_safe.eql(contracts.Sha256, observed, expected))
                return error.HashMismatch;
        }
        return allocator.dupe(u8, contents);
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
    var stat: linux.Statx = undefined;
    while (true) {
        switch (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .UID = true }, &stat))) {
            .SUCCESS => {
                if (!stat.mask.UID) return error.IncompleteMetadata;
                return stat.uid;
            },
            .INTR => continue,
            else => return error.MetadataUnavailable,
        }
    }
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
