const std = @import("std");
const c = @import("contracts.zig");
const p = c.core.private_files;
pub const sync = c.boot.files.sync;
pub const durable = c.boot.files.durable;

pub fn record(a: std.mem.Allocator, io: std.Io, filename: []const u8, maximum: u64, executable: bool) !c.File {
    const file = try p.openAbsolute(io, filename, .artifact);
    defer file.close(io);
    const before = try p.snapshot(file);
    if (before.size == 0 or before.size > maximum or before.mode & 0o022 != 0) return error.InvalidArtifact;
    if (executable) {
        if (before.mode & 0o111 == 0 or before.mode & 0o6000 != 0) return error.InvalidExecutable;
        const bytes = try a.alloc(u8, @intCast(before.size));
        defer a.free(bytes);
        if (try file.readPositionalAll(io, bytes, 0) != bytes.len) return error.ArtifactChanged;
        var elf = try @import("native_elf").Image.parse(a, bytes);
        defer elf.deinit();
    }
    const result: c.File = .{ .path = try a.dupe(u8, filename), .size = before.size, .sha256 = try c.hex(a, try c.boot.files.digest(io, file, before)) };
    const named = try p.openAbsolute(io, filename, .artifact);
    defer named.close(io);
    if (!p.sameSnapshot(before, try p.snapshot(named))) return error.ArtifactChanged;
    return result;
}
pub fn verify(a: std.mem.Allocator, io: std.Io, expected: c.File, maximum: u64, executable: bool) !void {
    try expected.validate(maximum);
    const actual = try record(a, io, expected.path, maximum, executable);
    if (actual.size != expected.size or !std.mem.eql(u8, actual.sha256, expected.sha256)) return error.ArtifactChanged;
}
pub fn readArtifact(a: std.mem.Allocator, io: std.Io, expected: c.File, maximum: usize) ![]u8 {
    try expected.validate(maximum);
    const source = try p.openAbsolute(io, expected.path, .artifact);
    defer source.close(io);
    const before = try p.snapshot(source);
    if (before.size != expected.size) return error.ArtifactChanged;
    const bytes = try a.alloc(u8, @intCast(expected.size));
    errdefer a.free(bytes);
    if (try source.readPositionalAll(io, bytes, 0) != bytes.len or
        !std.mem.eql(u8, &c.hash(bytes), &try c.sha(expected.sha256)) or
        !p.sameSnapshot(before, try p.snapshot(source))) return error.ArtifactChanged;
    return bytes;
}
pub fn copy(io: std.Io, source: c.File, to: p.Directory, name: []const u8) !void {
    try p.basename(name);
    const file = try p.openAbsolute(io, source.path, .artifact);
    defer file.close(io);
    const before = try p.snapshot(file);
    if (before.size != source.size) return error.ArtifactChanged;
    try c.boot.files.copy(io, .{ .file = file, .before = before, .pin = .{ .size = source.size, .sha256 = try c.sha(source.sha256) } }, to.dir, name);
}
pub fn create(io: std.Io, filename: []const u8) !p.Directory {
    const parent = try p.FileParent.open(io, filename, .artifact);
    defer parent.close(io);
    try parent.directory.createDir(io, parent.name, .fromMode(0o700));
    try sync(io, parent.directory);
    return p.Directory.open(io, filename);
}
pub fn path(a: std.mem.Allocator, root: []const u8, name: []const u8) ![]const u8 {
    return std.fs.path.join(a, &.{ root, name });
}
pub fn same(a: std.mem.Allocator, left: anytype, right: @TypeOf(left)) !void {
    const l = try c.encode(a, left);
    defer a.free(l);
    const r = try c.encode(a, right);
    defer a.free(r);
    if (!std.mem.eql(u8, l, r)) return error.RecordMismatch;
}
pub fn immutable(a: std.mem.Allocator, io: std.Io, lock: *p.Locked, name: []const u8, value: anytype) !void {
    const encoded = try c.encode(a, value);
    defer a.free(encoded);
    try durable(try lock.createImmutable(io, name, encoded));
}
pub fn cleanupStage(io: std.Io, root: p.Directory, name: []const u8) !void {
    try p.basename(name);
    const dir = root.dir.openDir(io, name, .{ .follow_symlinks = false, .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer dir.close(io);
    var entries = dir.iterate();
    var count: u8 = 0;
    while (try entries.next(io)) |entry| {
        if (entry.kind != .file or count == 16) return error.InvalidStage;
        count += 1;
        try dir.deleteFile(io, entry.name);
    }
    try sync(io, dir);
    try root.dir.deleteDir(io, name);
    try sync(io, root.dir);
}
