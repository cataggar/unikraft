// SPDX-License-Identifier: BSD-3-Clause
//! Private controller scratch is separate from create-only custody records.
const std = @import("std");
const core = @import("hyperv_core");
const custody = @import("custody.zig");
const files = core.private_files;

pub fn verifyDirectory(io: std.Io, original: files.Directory, path: []const u8) !void {
    const named = try files.Directory.open(io, path);
    defer named.close(io);
    const before = try files.snapshot(.{ .handle = original.dir.handle, .flags = .{ .nonblocking = false } });
    const after = try files.snapshot(.{ .handle = named.dir.handle, .flags = .{ .nonblocking = false } });
    if (before.ino != after.ino or before.dev_major != after.dev_major or before.dev_minor != after.dev_minor or
        before.mode != after.mode or before.uid != after.uid) return error.DirectoryChanged;
}

pub fn verifyLock(io: std.Io, writer: *files.Locked) !void {
    const held = writer.file orelse return error.LockNotHeld;
    const named = try writer.directory.openFile(io, ".writer.lock");
    defer named.close(io);
    if (!files.sameSnapshot(try files.snapshot(held), try files.snapshot(named))) return error.LockChanged;
}

pub fn sync(io: std.Io, dir: std.Io.Dir) !void {
    const file: std.Io.File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
    try file.sync(io);
}

pub fn directory(io: std.Io, parent: files.Directory, name: []const u8) !files.Directory {
    try files.basename(name);
    try parent.dir.createDir(io, name, .fromMode(0o700));
    const dir = try parent.dir.openDir(io, name, .{ .follow_symlinks = false, .iterate = true });
    errdefer dir.close(io);
    const stat = try files.snapshot(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } });
    if (stat.mode & 0o7777 != 0o700 or stat.uid != std.os.linux.geteuid()) return error.UnsafeFile;
    try sync(io, dir);
    try sync(io, parent.dir);
    return .{ .dir = dir };
}

pub fn pin(allocator: std.mem.Allocator, io: std.Io, dir: files.Directory, name: []const u8, limit: usize) !custody.FileSnapshot {
    const file = try dir.openFile(io, name);
    defer file.close(io);
    const metadata = try files.snapshot(file);
    var bytes = try dir.readSensitive(io, allocator, name, limit, null);
    defer bytes.deinit();
    var digest: custody.Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes.bytes(), &digest, .{});
    const named = try dir.openFile(io, name);
    defer named.close(io);
    if (!files.sameSnapshot(metadata, try files.snapshot(named)) or !files.sameSnapshot(metadata, try files.snapshot(file)))
        return error.FileChanged;
    return .{ .metadata = metadata, .sha256 = digest };
}

pub fn verify(allocator: std.mem.Allocator, io: std.Io, dir: files.Directory, name: []const u8, expected: custody.FileSnapshot, limit: usize) !void {
    const current = try pin(allocator, io, dir, name, limit);
    if (!files.sameSnapshot(current.metadata, expected.metadata) or
        !std.crypto.timing_safe.eql(custody.Digest, current.sha256, expected.sha256)) return error.FileChanged;
}

pub const Scratch = enum {
    @"boot1-candidate.log",
    @"boot2-candidate.log",
    @"serial-check.stdout",
    @"serial-check.stderr",
};

/// Only these non-authoritative aliases may be replaced. Existing unsafe names
/// are refused before atomic publication; authoritative names cannot be passed.
pub fn scratch(io: std.Io, writer: *files.Locked, name: Scratch, bytes: []const u8) !void {
    try writeBytes(io, writer, @tagName(name), bytes, true);
}

pub fn immutableRaw(io: std.Io, writer: *files.Locked, name: []const u8, bytes: []const u8) !void {
    try writeBytes(io, writer, name, bytes, false);
}

fn writeBytes(io: std.Io, writer: *files.Locked, name: []const u8, bytes: []const u8, replace: bool) !void {
    if (writer.file == null or bytes.len > custody.cli_limit) return error.InvalidCapture;
    try files.basename(name);
    const old = writer.directory.openFile(io, name) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    const before = if (old) |file| blk: {
        defer file.close(io);
        if (!replace) return error.PathAlreadyExists;
        break :blk try files.snapshot(file);
    } else null;
    var atomic = try writer.directory.dir.createFileAtomic(io, name, .{ .permissions = .fromMode(0o600), .replace = replace });
    defer atomic.deinit(io);
    const created = try files.snapshot(atomic.file);
    if (created.mode & 0o7777 != 0o600 or created.uid != std.os.linux.geteuid() or created.nlink > 1)
        return error.UnsafeFile;
    try atomic.file.writePositionalAll(io, bytes, 0);
    try atomic.file.sync(io);
    const current = writer.directory.openFile(io, name) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (current) |file| {
        defer file.close(io);
        if (before == null or !files.sameSnapshot(before.?, try files.snapshot(file))) return error.FileChanged;
    } else if (before != null) return error.FileChanged;
    if (replace) try atomic.replace(io) else try atomic.link(io);
    try sync(io, writer.directory.dir);
    var read = try writer.directory.readSensitive(io, std.heap.page_allocator, name, custody.cli_limit, null);
    defer read.deinit();
    if (!std.mem.eql(u8, read.bytes(), bytes)) return error.FileChanged;
}
