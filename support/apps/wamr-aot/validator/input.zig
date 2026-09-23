// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const core = @import("hyperv_core");
const files = core.private_files;

pub const Kind = enum { tiny_serial, optional_serial, identity };

pub const Input = struct {
    allocator: std.mem.Allocator,
    bytes: []const u8,
    sha256: [32]u8,

    pub fn deinit(self: *Input) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

/// The bound applies to raw bytes, before serial escape/CRLF normalization.
pub fn read(allocator: std.mem.Allocator, io: std.Io, path: []const u8, kind: Kind) !Input {
    return readImpl(allocator, io, path, kind, null);
}

pub const Stage = enum { before_open, after_open, after_read, after_close };
pub const Fault = struct {
    stage: Stage,
    action: *const fn (std.Io, []const u8) anyerror!void,
};

pub fn readFault(allocator: std.mem.Allocator, io: std.Io, path: []const u8, kind: Kind, fault: Fault) !Input {
    if (!builtin.is_test) @compileError("Input fault hooks are native-test-only");
    return readImpl(allocator, io, path, kind, fault);
}

fn readImpl(allocator: std.mem.Allocator, io: std.Io, path: []const u8, kind: Kind, fault: ?Fault) !Input {
    if (path.len == 0 or path.len > 4095 or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.UnsafePath;
    var terminated: [4096:0]u8 = undefined;
    @memcpy(terminated[0..path.len], path);
    terminated[path.len] = 0;
    const name = terminated[0..path.len :0];
    const before = try pathSnapshot(name);
    try validate(before, kind);
    try inject(io, path, fault, .before_open);

    const file = try open(io, name);
    var held = true;
    defer if (held) file.close(io);
    const opened = try files.snapshot(file);
    if (!files.sameSnapshot(before, opened)) return error.FileChanged;
    try inject(io, path, fault, .after_open);

    const count: usize = @intCast(before.size);
    const bytes = try allocator.alloc(u8, count);
    errdefer allocator.free(bytes);
    if (try file.readPositionalAll(io, bytes, 0) != count) return error.FileChanged;
    var extra: [1]u8 = undefined;
    if (try file.readPositionalAll(io, &extra, count) != 0) return error.FileChanged;
    try inject(io, path, fault, .after_read);
    if (!files.sameSnapshot(before, try files.snapshot(file))) return error.FileChanged;
    file.close(io);
    held = false;
    try inject(io, path, fault, .after_close);
    if (!files.sameSnapshot(before, try pathSnapshot(name))) return error.FileChanged;
    const reopened = try open(io, name);
    defer reopened.close(io);
    if (!files.sameSnapshot(before, try files.snapshot(reopened)) or
        !files.sameSnapshot(before, try pathSnapshot(name))) return error.FileChanged;

    var sha256: [32]u8 = undefined;
    core.Sha256.hash(bytes, &sha256, .{});
    return .{ .allocator = allocator, .bytes = bytes, .sha256 = sha256 };
}

fn validate(info: files.Snapshot, kind: Kind) !void {
    if (info.mode & linux.S.IFMT != linux.S.IFREG or info.mode & 0o022 != 0)
        return error.UnsafeFile;
    const max: u64 = switch (kind) {
        .tiny_serial => 4 * 1024 * 1024 - 1,
        .optional_serial => 2 * 1024 * 1024,
        .identity => 64 * 1024,
    };
    if (info.size == 0 or info.size > max) return error.InputLimit;
}

fn pathSnapshot(name: [:0]const u8) !files.Snapshot {
    var info: files.Snapshot = undefined;
    while (true) {
        switch (linux.errno(linux.statx(linux.AT.FDCWD, name.ptr, linux.AT.SYMLINK_NOFOLLOW, .BASIC_STATS, &info))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.InputUnavailable,
        }
    }
    const mask = info.mask;
    if (!mask.TYPE or !mask.MODE or !mask.UID or !mask.INO or !mask.SIZE or
        !mask.CTIME or !mask.MTIME or !mask.NLINK) return error.IncompleteMetadata;
    return info;
}

fn open(io: std.Io, name: [:0]const u8) !std.Io.File {
    _ = io;
    while (true) {
        const result = linux.openat(linux.AT.FDCWD, name.ptr, .{
            .ACCMODE = .RDONLY,
            .NOFOLLOW = true,
            .NONBLOCK = true,
            .CLOEXEC = true,
        }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => return .{ .handle = @intCast(result), .flags = .{ .nonblocking = true } },
            .INTR => continue,
            else => return error.InputUnavailable,
        }
    }
}

fn inject(io: std.Io, path: []const u8, fault: ?Fault, stage: Stage) !void {
    if (builtin.is_test) if (fault) |f| {
        if (f.stage == stage) try f.action(io, path);
    };
}
