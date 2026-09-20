const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
var user_namespace_active = std.atomic.Value(bool).init(false);
var namespace_host_uid = std.atomic.Value(u32).init(0);
var namespace_host_gid = std.atomic.Value(u32).init(0);
pub const namespace_marker = "WAMR_AZURE_RUNTIME_NAMESPACE";
pub const namespace_uid = "WAMR_AZURE_RUNTIME_HOST_UID";
pub const namespace_gid = "WAMR_AZURE_RUNTIME_HOST_GID";

pub fn enterUserNamespace(uid: u32, gid: u32) void {
    namespace_host_uid.store(uid, .release);
    namespace_host_gid.store(gid, .release);
    user_namespace_active.store(true, .release);
}

pub fn enterUserNamespaceFromEnvironment(
    io: std.Io,
    environment: *const std.process.Environ.Map,
) !void {
    const marker = environment.get(namespace_marker) orelse return;
    if (!std.mem.eql(u8, marker, "1") or linux.geteuid() != 0 or
        linux.getegid() != 0)
        return error.InvalidUserNamespace;
    const uid = try std.fmt.parseInt(
        u32,
        environment.get(namespace_uid) orelse return error.InvalidUserNamespace,
        10,
    );
    const gid = try std.fmt.parseInt(
        u32,
        environment.get(namespace_gid) orelse return error.InvalidUserNamespace,
        10,
    );
    try verifyNamespace(io, uid, gid);
    enterUserNamespace(uid, gid);
}

fn verifyNamespace(io: std.Io, host_uid: u32, host_gid: u32) !void {
    try verifyIdMap(io, "/proc/self/uid_map", host_uid);
    try verifyIdMap(io, "/proc/self/gid_map", host_gid);
    var groups_buffer: [32]u8 = undefined;
    if (!std.mem.eql(
        u8,
        std.mem.trim(
            u8,
            try readKernelFile(io, "/proc/self/setgroups", &groups_buffer),
            " \t\r\n",
        ),
        "deny",
    )) return error.InvalidUserNamespace;
    var mount_buffer: [64 * 1024]u8 = undefined;
    const mountinfo = try readKernelFile(
        io,
        "/proc/self/mountinfo",
        &mount_buffer,
    );
    var root_found = false;
    var lines = std.mem.splitScalar(u8, mountinfo, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        var index: usize = 0;
        var root = false;
        var private = true;
        while (fields.next()) |field| : (index += 1) {
            if (index == 4) root = std.mem.eql(u8, field, "/");
            if (std.mem.startsWith(u8, field, "shared:") or
                std.mem.startsWith(u8, field, "master:") or
                std.mem.startsWith(u8, field, "propagate_from:"))
                private = false;
            if (std.mem.eql(u8, field, "-")) break;
        }
        if (root) {
            if (root_found or !private) return error.InvalidUserNamespace;
            root_found = true;
        }
    }
    if (!root_found) return error.InvalidUserNamespace;
}

fn verifyIdMap(io: std.Io, path: []const u8, host_id: u32) !void {
    var buffer: [128]u8 = undefined;
    const bytes = try readKernelFile(io, path, &buffer);
    var fields = std.mem.tokenizeAny(u8, bytes, " \t\r\n");
    const inside = try std.fmt.parseInt(
        u32,
        fields.next() orelse return error.InvalidUserNamespace,
        10,
    );
    const outside = try std.fmt.parseInt(
        u32,
        fields.next() orelse return error.InvalidUserNamespace,
        10,
    );
    const count = try std.fmt.parseInt(
        u32,
        fields.next() orelse return error.InvalidUserNamespace,
        10,
    );
    if (inside != 0 or outside != host_id or count != 1 or
        fields.next() != null)
        return error.InvalidUserNamespace;
}

fn readKernelFile(
    io: std.Io,
    path: []const u8,
    buffer: []u8,
) ![]const u8 {
    const file = try std.Io.Dir.openFileAbsolute(io, path, .{
        .mode = .read_only,
        .follow_symlinks = false,
    });
    defer file.close(io);
    const count = try file.readPositionalAll(io, buffer, 0);
    if (count == buffer.len) return error.InvalidUserNamespace;
    return buffer[0..count];
}

pub fn hostUid(id: u32) u32 {
    if (!user_namespace_active.load(.acquire)) return id;
    if (id == 0) return namespace_host_uid.load(.acquire);
    return id;
}

pub fn hostGid(id: u32) u32 {
    if (!user_namespace_active.load(.acquire)) return id;
    if (id == 0) return namespace_host_gid.load(.acquire);
    return id;
}

fn trustedArtifactOwner(uid: u32) bool {
    return uid == 0 or
        (!user_namespace_active.load(.acquire) and uid == linux.geteuid());
}
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
        try validateDirectory(io, dir, true, false);
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
        expected_sha256: anytype,
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
        expected_sha256: anytype,
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
        // Literal-null readers, including Zig's build runner, have never
        // hashed. Specialize that existing path without a hash-link dependency.
        if (comptime @TypeOf(expected_sha256) != @TypeOf(null)) {
            if (@as(?contracts.Sha256, expected_sha256)) |expected| {
                var observed: contracts.Sha256 = undefined;
                @import("sha256.zig").Sha256.hash(result.bytes(), &observed, .{});
                if (!std.crypto.timing_safe.eql(contracts.Sha256, observed, expected))
                    return error.HashMismatch;
            }
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

pub const FilePolicy = enum { private, artifact, tool };
pub const Snapshot = linux.Statx;
pub const retained_path_components = 64;

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

fn sameDirectoryIdentity(a: Snapshot, b: Snapshot) bool {
    return a.dev_major == b.dev_major and a.dev_minor == b.dev_minor and
        a.ino == b.ino and a.mode == b.mode and a.uid == b.uid;
}

pub fn absoluteFilePath(path: []const u8) !void {
    if (path.len < 2 or path.len > 4095 or path[0] != '/' or path[path.len - 1] == '/')
        return error.UnsafePath;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| try basename(part);
}

pub const RetainedFile = struct {
    path: []const u8,
    policy: FilePolicy,
    directories: [retained_path_components]std.Io.Dir,
    directory_snapshots: [retained_path_components]Snapshot,
    directory_count: usize,
    file: std.Io.File,
    file_snapshot: Snapshot,

    pub fn open(io: std.Io, path: []const u8, policy: FilePolicy) !RetainedFile {
        try absoluteFilePath(path);
        var result: RetainedFile = undefined;
        result.path = path;
        result.policy = policy;
        result.directory_count = 0;
        var current = try std.Io.Dir.openDirAbsolute(io, "/", .{
            .follow_symlinks = false,
            .iterate = true,
        });
        errdefer {
            if (result.directory_count == 0) current.close(io);
            var index: usize = 0;
            while (index < result.directory_count) : (index += 1)
                result.directories[index].close(io);
        }
        try validateDirectory(io, current, false, true);
        result.directories[0] = current;
        result.directory_snapshots[0] = try snapshot(.{
            .handle = current.handle,
            .flags = .{ .nonblocking = false },
        });
        result.directory_count = 1;
        const parent_path = std.fs.path.dirname(path).?;
        if (parent_path.len > 1) {
            var parts = std.mem.splitScalar(u8, parent_path[1..], '/');
            while (parts.next()) |part| {
                try basename(part);
                if (result.directory_count >= retained_path_components)
                    return error.UnsafePath;
                const next = try current.openDir(io, part, .{
                    .follow_symlinks = false,
                    .iterate = true,
                });
                validateDirectory(io, next, false, false) catch |err| {
                    next.close(io);
                    return err;
                };
                current = next;
                result.directories[result.directory_count] = next;
                result.directory_snapshots[result.directory_count] = snapshot(.{
                    .handle = next.handle,
                    .flags = .{ .nonblocking = false },
                }) catch |err| {
                    next.close(io);
                    return err;
                };
                result.directory_count += 1;
            }
        }
        try validateDirectory(
            io,
            result.directories[result.directory_count - 1],
            policy == .private,
            false,
        );
        result.file = try openFilePolicy(
            io,
            result.directories[result.directory_count - 1],
            std.fs.path.basename(path),
            policy,
        );
        errdefer result.file.close(io);
        result.file_snapshot = try snapshot(result.file);
        return result;
    }

    pub fn close(self: *RetainedFile, io: std.Io) void {
        self.file.close(io);
        var index = self.directory_count;
        while (index > 0) {
            index -= 1;
            self.directories[index].close(io);
        }
        self.* = undefined;
    }

    pub fn verify(self: RetainedFile, io: std.Io) !void {
        if (!sameSnapshot(self.file_snapshot, try snapshot(self.file)))
            return error.FileChanged;
        for (0..self.directory_count) |index| {
            try validateDirectory(
                io,
                self.directories[index],
                self.policy == .private and index + 1 == self.directory_count,
                index == 0,
            );
            if (!sameDirectoryIdentity(
                self.directory_snapshots[index],
                try snapshot(.{
                    .handle = self.directories[index].handle,
                    .flags = .{ .nonblocking = false },
                }),
            )) return error.FileChanged;
        }
        var current = try std.Io.Dir.openDirAbsolute(io, "/", .{
            .follow_symlinks = false,
            .iterate = true,
        });
        defer current.close(io);
        if (!sameDirectoryIdentity(
            self.directory_snapshots[0],
            try snapshot(.{
                .handle = current.handle,
                .flags = .{ .nonblocking = false },
            }),
        )) return error.FileChanged;
        const parent_path = std.fs.path.dirname(self.path).?;
        var index: usize = 1;
        if (parent_path.len > 1) {
            var parts = std.mem.splitScalar(u8, parent_path[1..], '/');
            while (parts.next()) |part| {
                const next = try current.openDir(io, part, .{
                    .follow_symlinks = false,
                    .iterate = true,
                });
                current.close(io);
                current = next;
                if (index >= self.directory_count or !sameDirectoryIdentity(
                    self.directory_snapshots[index],
                    try snapshot(.{
                        .handle = current.handle,
                        .flags = .{ .nonblocking = false },
                    }),
                )) return error.FileChanged;
                index += 1;
            }
        }
        if (index != self.directory_count) return error.FileChanged;
        const named = try openFilePolicy(io, current, std.fs.path.basename(self.path), self.policy);
        defer named.close(io);
        if (!sameSnapshot(self.file_snapshot, try snapshot(named)))
            return error.FileChanged;
    }
};

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

pub fn readSensitiveAbsolute(io: std.Io, allocator: std.mem.Allocator, path: []const u8, maximum: usize, expected: anytype) !sensitive.Buffer {
    const parent = try FileParent.open(io, path, .private);
    defer parent.close(io);
    return (Directory{ .dir = parent.directory }).readSensitive(io, allocator, parent.name, maximum, expected);
}

pub fn readSensitiveFile(
    io: std.Io,
    allocator: std.mem.Allocator,
    file: std.Io.File,
    maximum: usize,
    policy: FilePolicy,
) !sensitive.Buffer {
    if (maximum == 0 or maximum > 64 * 1024 * 1024)
        return error.InvalidLimit;
    switch (policy) {
        .private => try validateFile(io, file),
        .artifact => if ((try file.stat(io)).kind != .file)
            return error.UnsafeFile,
        .tool => try validateToolFile(file),
    }
    const before = try snapshot(file);
    if (before.size > maximum) return error.FileTooLarge;
    var result: sensitive.Buffer = .{
        .allocator = allocator,
        .storage = try allocator.alloc(u8, @as(usize, @intCast(before.size)) + 1),
        .length = @intCast(before.size),
    };
    errdefer result.deinit();
    if (try file.readPositionalAll(io, result.storage, 0) != before.size or
        !sameSnapshot(before, try snapshot(file)))
        return error.FileChanged;
    return result;
}

pub fn openDirectory(io: std.Io, path: []const u8, policy: FilePolicy) !std.Io.Dir {
    if (!std.fs.path.isAbsolute(path) or path.len == 0 or path.len > 4095 or
        (path.len > 1 and path[path.len - 1] == '/')) return error.UnsafePath;
    var current = try std.Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false, .iterate = true });
    errdefer current.close(io);
    var root = true;
    if (path.len > 1) {
        var parts = std.mem.splitScalar(u8, path[1..], '/');
        while (parts.next()) |part| {
            try basename(part);
            try validateDirectory(io, current, false, root);
            const next = try current.openDir(io, part, .{ .follow_symlinks = false, .iterate = true });
            current.close(io);
            current = next;
            root = false;
        }
    }
    try validateDirectory(io, current, policy == .private, root);
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
    switch (policy) {
        .private => try validateFile(io, file),
        .artifact => if ((try file.stat(io)).kind != .file)
            return error.UnsafeFile,
        .tool => try validateToolFile(file),
    }
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

    pub fn createImmutableFault(self: *Locked, io: std.Io, name: []const u8, contents: []const u8, fault: TestFault) !CommitResult {
        if (!builtin.is_test) @compileError("Fault injection is only available to native tests");
        return self.commitImpl(io, name, contents, false, fault);
    }

    fn commitImpl(self: *Locked, io: std.Io, name: []const u8, contents: []const u8, replace: bool, fault: ?TestFault) !CommitResult {
        if (self.file == null) return error.LockNotHeld;
        try basename(name);
        if (name[0] == '.' or contents.len > 4 * 1024 * 1024) return error.InvalidState;
        try validateDirectory(io, self.directory.dir, true, false);
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
        writeAndReplace(io, &atomic, contents, replace, fault, &result) catch |err| {
            // A racing create-only publisher is still an immutable collision.
            if (!replace and err == error.PathAlreadyExists) return error.PathAlreadyExists;
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

fn validateDirectory(
    io: std.Io,
    dir: std.Io.Dir,
    private: bool,
    trusted_root: bool,
) !void {
    const stat = try dir.stat(io);
    const uid = try owner(dir.handle);
    const mode = stat.permissions.toMode() & 0o7777;
    if (stat.kind != .directory) return error.UnsafeFile;
    if (private) {
        if (uid != linux.geteuid() or mode != 0o700) return error.UnsafeFile;
    } else if ((!trustedArtifactOwner(uid) and
        !(trusted_root and user_namespace_active.load(.acquire))) or
        mode & 0o022 != 0) return error.UnsafeFile;
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

fn validateToolFile(file: std.Io.File) !void {
    const value = try snapshot(file);
    if (value.mode & linux.S.IFMT != linux.S.IFREG or
        !trustedArtifactOwner(value.uid) or
        value.mode & 0o111 == 0 or value.mode & 0o6022 != 0 or
        value.nlink != 1 or value.size == 0 or
        value.size > 64 * 1024 * 1024)
        return error.UnsafeFile;
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
