const std = @import("std");
const linux = std.os.linux;
pub const buffer_size = 16 * 1024;

pub const Guard = struct {
    context: *anyopaque,
    checkFn: *const fn (*anyopaque) anyerror!void,

    pub fn check(self: Guard) !void {
        try self.checkFn(self.context);
    }
};

fn asFile(fd: std.posix.fd_t) std.Io.File {
    return .{ .handle = fd, .flags = .{ .nonblocking = true } };
}

pub fn metadata(file: std.Io.File) !linux.Statx {
    var result: linux.Statx = undefined;
    if (linux.errno(linux.statx(file.handle, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &result)) != .SUCCESS)
        return error.UnsafeFile;
    const mask = result.mask;
    if (!mask.TYPE or !mask.MODE or !mask.UID or !mask.INO or !mask.SIZE or !mask.CTIME or !mask.MTIME or !mask.NLINK)
        return error.UnsafeFile;
    return result;
}

fn same(a: linux.Statx, b: linux.Statx) bool {
    return a.ino == b.ino and a.dev_major == b.dev_major and a.dev_minor == b.dev_minor and
        a.size == b.size and a.mode == b.mode and a.uid == b.uid and a.nlink == b.nlink and
        a.mtime.sec == b.mtime.sec and a.mtime.nsec == b.mtime.nsec and
        a.ctime.sec == b.ctime.sec and a.ctime.nsec == b.ctime.nsec;
}

pub fn validPath(path: []const u8) bool {
    if (path.len < 2 or path.len > 4095 or path[0] != '/' or path[path.len - 1] == '/' or std.mem.indexOfScalar(u8, path, 0) != null)
        return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) return false;
    }
    return true;
}

/// Walk every component with O_NOFOLLOW, then retain the containing directory
/// descriptor so output creation/removal never re-resolves an untrusted path.
pub const Parent = struct {
    file: std.Io.File,
    name: []const u8,

    pub fn open(io: std.Io, path: []const u8, private: bool) !Parent {
        if (!validPath(path)) return error.UnsafeFile;
        var current = asFile(try std.posix.openat(linux.AT.FDCWD, "/", .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .NOFOLLOW = true,
            .NONBLOCK = true,
            .CLOEXEC = true,
        }, 0));
        errdefer current.close(io);
        var components = std.mem.splitScalar(u8, path[1..], '/');
        var component = components.next().?;
        while (components.next()) |next| {
            const child = asFile(try std.posix.openat(current.handle, component, .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .NOFOLLOW = true,
                .NONBLOCK = true,
                .CLOEXEC = true,
            }, 0));
            current.close(io);
            current = child;
            component = next;
        }
        if (private) {
            const stat = try metadata(current);
            if (stat.uid != linux.getuid() or stat.mode & 0o077 != 0) return error.UnsafeFile;
        }
        return .{ .file = current, .name = component };
    }

    pub fn close(self: Parent, io: std.Io) void {
        self.file.close(io);
    }

    pub fn dir(self: Parent) std.Io.Dir {
        return .{ .handle = self.file.handle };
    }
};

pub fn openRegular(io: std.Io, path: []const u8, private: bool) !std.Io.File {
    const parent = try Parent.open(io, path, false);
    defer parent.close(io);
    const file = asFile(try std.posix.openat(parent.file.handle, parent.name, .{
        .ACCMODE = .RDONLY,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    }, 0));
    errdefer file.close(io);
    const stat = try metadata(file);
    if (stat.mode & linux.S.IFMT != linux.S.IFREG) return error.UnsafeFile;
    if (private and (stat.uid != linux.getuid() or stat.mode & 0o077 != 0 or stat.nlink != 1))
        return error.UnsafeFile;
    return file;
}

pub fn readPrivate(allocator: std.mem.Allocator, io: std.Io, path: []const u8, maximum: usize) ![]u8 {
    const file = try openRegular(io, path, true);
    defer file.close(io);
    const before = try metadata(file);
    if (before.size > maximum) return error.UnsafeFile;
    const bytes = try allocator.alloc(u8, @intCast(before.size));
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    if (try file.readPositionalAll(io, bytes, 0) != bytes.len) return error.UnsafeFile;
    var extra: [1]u8 = undefined;
    if (try file.readPositionalAll(io, &extra, before.size) != 0 or !same(before, try metadata(file)))
        return error.UnsafeFile;
    return bytes;
}

pub const Fingerprint = struct { sha256: [32]u8, md5: [16]u8 };
pub const Input = struct {
    path: []const u8,
    size: u64,
    sha256: [32]u8,
};

pub const SealedInput = struct {
    file: std.Io.File,
    io: std.Io,
    expected: Input,
    before: linux.Statx,
    fingerprint: Fingerprint,

    pub fn open(io: std.Io, expected: Input, guard: Guard) !SealedInput {
        try guard.check();
        const file = try openRegular(io, expected.path, false);
        errdefer file.close(io);
        const before = try metadata(file);
        if (before.size != expected.size) return error.InputChanged;
        const fingerprint = try hash(file, io, expected.size, guard);
        if (!std.mem.eql(u8, &fingerprint.sha256, &expected.sha256) or !same(before, try metadata(file)))
            return error.InputChanged;
        return .{ .file = file, .io = io, .expected = expected, .before = before, .fingerprint = fingerprint };
    }

    pub fn close(self: SealedInput) void {
        self.file.close(self.io);
    }

    pub fn verify(self: SealedInput, guard: Guard) !void {
        const actual = try hash(self.file, self.io, self.expected.size, guard);
        if (!std.mem.eql(u8, &actual.sha256, &self.expected.sha256) or
            !same(self.before, try metadata(self.file))) return error.InputChanged;
        const path_file = try openRegular(self.io, self.expected.path, false);
        defer path_file.close(self.io);
        if (!same(self.before, try metadata(path_file))) return error.InputChanged;
        try guard.check();
    }
};

fn hash(file: std.Io.File, io: std.Io, size: u64, guard: Guard) !Fingerprint {
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    var md5 = std.crypto.hash.Md5.init(.{});
    var buffer: [buffer_size]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        try guard.check();
        const wanted: usize = @intCast(@min(size - offset, buffer.len));
        const count = try file.readPositionalAll(io, buffer[0..wanted], offset);
        if (count != wanted) return error.InputChanged;
        sha.update(buffer[0..count]);
        md5.update(buffer[0..count]);
        offset += count;
    }
    var extra: [1]u8 = undefined;
    try guard.check();
    if (try file.readPositionalAll(io, &extra, offset) != 0) return error.InputChanged;
    var md5_result: [16]u8 = undefined;
    md5.final(&md5_result);
    return .{ .sha256 = sha.finalResult(), .md5 = md5_result };
}

pub const InputReader = struct {
    interface: std.Io.Reader = .{ .vtable = &.{ .stream = stream }, .buffer = &.{}, .seek = 0, .end = 0 },
    source: *const SealedInput,
    guard: Guard,
    offset: u64 = 0,
    sha: std.crypto.hash.sha2.Sha256 = .init(.{}),
    failure: ?anyerror = null,

    fn stream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *InputReader = @alignCast(@fieldParentPtr("interface", reader));
        self.guard.check() catch |err| {
            self.failure = err;
            return error.ReadFailed;
        };

        var buffer: [buffer_size]u8 = undefined;
        const count = self.source.file.readPositional(self.source.io, &.{buffer[0..limit.minInt(buffer.len)]}, self.offset) catch |err| {
            self.failure = err;
            return error.ReadFailed;
        };
        if (count == 0) return error.EndOfStream;
        // A short Writer may consume only part of this read; positional I/O
        // allows the unread bytes to be obtained again without hiding them.
        const written = try writer.write(buffer[0..count]);
        self.offset += written;
        self.sha.update(buffer[0..written]);
        return written;
    }
};

pub const PageReader = struct {
    interface: std.Io.Reader = .{ .vtable = &.{ .stream = stream }, .buffer = &.{}, .seek = 0, .end = 0 },
    bytes: []const u8,
    guard: Guard,
    offset: usize = 0,
    failure: ?anyerror = null,

    fn stream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *PageReader = @alignCast(@fieldParentPtr("interface", reader));
        self.guard.check() catch |err| {
            self.failure = err;
            return error.ReadFailed;
        };
        if (self.offset == self.bytes.len) return error.EndOfStream;
        const length = @min(limit.minInt(buffer_size), self.bytes.len - self.offset);
        const count = try writer.write(self.bytes[self.offset..][0..length]);
        self.offset += count;
        return count;
    }
};
