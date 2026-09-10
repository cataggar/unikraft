const std = @import("std");
const shared = @import("hyperv_core").private_files;
pub const buffer_size = 16 * 1024;

pub const Guard = struct {
    context: *anyopaque,
    checkFn: *const fn (*anyopaque) anyerror!void,

    pub fn check(self: Guard) !void {
        try self.checkFn(self.context);
    }
};

pub const metadata = shared.snapshot;
const same = shared.sameSnapshot;
pub const Parent = shared.FileParent;
pub const openRegular = shared.openAbsolute;
pub const readSensitive = shared.readSensitiveAbsolute;

pub fn validPath(path: []const u8) bool {
    shared.absoluteFilePath(path) catch return false;
    return true;
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
    before: shared.Snapshot,
    fingerprint: Fingerprint,

    pub fn open(io: std.Io, expected: Input, guard: Guard) !SealedInput {
        try guard.check();
        const file = try openRegular(io, expected.path, .artifact);
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
        const path_file = try openRegular(self.io, self.expected.path, .artifact);
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
        if (self.offset > self.source.expected.size) {
            self.failure = error.InputChanged;
            return error.ReadFailed;
        }
        // A failed stream may expose one excess-byte probe, never an unbounded
        // growing suffix. Successful streams still provide exactly the input.
        const wanted: usize = @intCast(@min(limit.minInt(buffer.len), self.source.expected.size - self.offset + 1));
        const count = self.source.file.readPositional(self.source.io, &.{buffer[0..wanted]}, self.offset) catch |err| {
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
