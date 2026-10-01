// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const files = core.private_files;
const Sha256 = core.Sha256;
const layout = @import("layout.zig");
const linux = std.os.linux;

pub const aggregate_budget = layout.max_total_bytes - 2 * layout.max_json_bytes;
const chunk_size = 64 * 1024;
const scan_tail = 128;

pub const Budget = struct {
    used: u64 = 0,
    limit: u64 = aggregate_budget,

    pub fn reserve(self: *Budget, bytes: u64) !void {
        if (bytes == 0 or bytes > self.limit or self.used > self.limit - bytes)
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
};

pub const Options = struct {
    scan: SensitiveScan = .disabled,
    fault: TestFault = .none,
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
    try validateRelative(relative);
    try files.absoluteFilePath(destination_root_path);
    const before = retained.file_snapshot;
    try validateSource(before, limit);
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
        }
        if (try retained.file.readPositionalAll(io, buffer[0..1], offset) != 0)
            return error.FileChanged;
        if (!sameCustodySnapshot(before, try files.snapshot(retained.file)))
            return error.FileChanged;
        try retained.verify(io);
        const source_digest = std.fmt.bytesToHex(hasher.finalResult(), .lower);
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
        const destination_snapshot = try files.snapshot(created.*);
        try validateDestination(destination_snapshot, before.size);
        const observed = try hashOpened(io, parent.dir, leaf, before.size, limit);
        if (!std.mem.eql(u8, &source_digest, &observed))
            return error.CopyChanged;
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
        current.createDir(io, component, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const child = try current.openDir(io, component, .{ .follow_symlinks = false, .iterate = true });
        try validatePrivateDir(child);
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

fn hashOpened(io: std.Io, parent: std.Io.Dir, name: []const u8, size: u64, limit: u64) ![64]u8 {
    if (size == 0 or size > limit) return error.UnsafeDestination;
    const file = try parent.openFile(io, name, .{ .follow_symlinks = false });
    defer file.close(io);
    const snapshot = try files.snapshot(file);
    try validateDestination(snapshot, size);
    var hasher = Sha256.init(.{});
    var buffer: [chunk_size]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        const count = try file.readPositionalAll(io, buffer[0..@intCast(@min(buffer.len, size - offset))], offset);
        if (count == 0) return error.CopyChanged;
        hasher.update(buffer[0..count]);
        offset += count;
    }
    if (try file.readPositionalAll(io, buffer[0..1], offset) != 0)
        return error.CopyChanged;
    if (!sameCustodySnapshot(snapshot, try files.snapshot(file)))
        return error.CopyChanged;
    return std.fmt.bytesToHex(hasher.finalResult(), .lower);
}

fn syncDir(io: std.Io, dir: std.Io.Dir) !void {
    try (std.Io.File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

fn sameCustodySnapshot(a: files.Snapshot, b: files.Snapshot) bool {
    return files.sameSnapshot(a, b) and a.gid == b.gid;
}

const Scanner = struct {
    tail: [scan_tail]u8 = undefined,
    tail_len: usize = 0,

    fn observe(self: *Scanner, chunk: []const u8) !void {
        for (sensitive_patterns) |pattern| {
            if (std.mem.indexOf(u8, chunk, pattern) != null)
                return error.SensitivePattern;
            const max_overlap = @min(@min(self.tail_len, pattern.len - 1), chunk.len);
            var overlap: usize = 1;
            while (overlap <= max_overlap) : (overlap += 1) {
                if (std.mem.eql(u8, self.tail[self.tail_len - overlap .. self.tail_len], pattern[0..overlap]) and
                    std.mem.startsWith(u8, chunk, pattern[overlap..]))
                    return error.SensitivePattern;
            }
        }
        if (chunk.len >= scan_tail) {
            @memcpy(self.tail[0..], chunk[chunk.len - scan_tail ..]);
            self.tail_len = scan_tail;
        } else {
            const keep = @min(self.tail_len, scan_tail - chunk.len);
            if (keep > 0)
                std.mem.copyForwards(u8, self.tail[0..keep], self.tail[self.tail_len - keep .. self.tail_len]);
            @memcpy(self.tail[keep .. keep + chunk.len], chunk);
            self.tail_len = keep + chunk.len;
        }
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
