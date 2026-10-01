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
        if (self.limit > aggregate_budget or bytes == 0 or bytes > self.limit or self.used > self.limit - bytes)
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
    cancel_after_first_chunk,
    replace_destination_before_reopen,
};

pub const Options = struct {
    scan: SensitiveScan = .disabled,
    fault: TestFault = .none,
    cancel: ?*const std.atomic.Value(bool) = null,
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
    if (options.fault != .none and !builtin.is_test) return error.InvalidFault;
    try checkCancellation(options.cancel);
    try validateRelative(relative);
    try files.absoluteFilePath(destination_root_path);
    try validatePrivateDir(destination_root);
    const root_snapshot = try directorySnapshot(destination_root);
    try verifyRoot(io, destination_root_path, root_snapshot);
    const before = retained.file_snapshot;
    try validateSource(before, limit);
    try verifyRetained(io, retained);
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
            try checkCancellation(options.cancel);
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
            if (!injected and options.fault == .cancel_after_first_chunk) {
                const cancel = options.cancel orelse return error.InvalidFault;
                @constCast(cancel).store(true, .release);
                injected = true;
            }
        }
        if (try retained.file.readPositionalAll(io, buffer[0..1], offset) != 0)
            return error.FileChanged;
        if (!sameCustodySnapshot(before, try files.snapshot(retained.file)))
            return error.FileChanged;
        try retained.verify(io);
        try verifyRetained(io, retained);
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
        try checkCancellation(options.cancel);
        const destination_snapshot = try files.snapshot(created.*);
        try validateDestination(destination_snapshot, before.size);
        if (options.fault == .replace_destination_before_reopen) {
            try parent.dir.rename(leaf, parent.dir, "replaced-copy", io);
            const replacement = try parent.dir.createFile(io, leaf, .{
                .exclusive = true,
                .read = true,
                .permissions = .fromMode(0o600),
            });
            defer replacement.close(io);
            var at: u64 = 0;
            while (at < before.size) {
                const want: usize = @intCast(@min(buffer.len, before.size - at));
                if (try created.readPositionalAll(io, buffer[0..want], at) != want) return error.CopyChanged;
                try replacement.writePositionalAll(io, buffer[0..want], at);
                at += want;
            }
            try replacement.sync(io);
        }
        const observed = try hashOpened(io, parent.dir, leaf, destination_snapshot, limit, options.cancel);
        if (!std.mem.eql(u8, &source_digest, &observed))
            return error.CopyChanged;
        var named = try files.RetainedFile.open(io, destination_path, .private);
        defer named.close(io);
        if (!sameCustodySnapshot(destination_snapshot, named.file_snapshot))
            return error.CopyChanged;
        try verifyRetained(io, &named);
        try verifyRoot(io, destination_root_path, root_snapshot);
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
        var created = true;
        current.createDir(io, component, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => created = false,
            else => return err,
        };
        const child = try current.openDir(io, component, .{ .follow_symlinks = false, .iterate = true });
        errdefer child.close(io);
        try validatePrivateDir(child);
        if (created) {
            try syncDir(io, child);
            try syncDir(io, current);
        }
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

fn hashOpened(io: std.Io, parent: std.Io.Dir, name: []const u8, expected: files.Snapshot, limit: u64, cancel: ?*const std.atomic.Value(bool)) ![64]u8 {
    const size = expected.size;
    if (size == 0 or size > limit) return error.UnsafeDestination;
    const file = try parent.openFile(io, name, .{ .follow_symlinks = false });
    defer file.close(io);
    const snapshot = try files.snapshot(file);
    try validateDestination(snapshot, size);
    if (!sameCustodySnapshot(expected, snapshot)) return error.CopyChanged;
    var hasher = Sha256.init(.{});
    var buffer: [chunk_size]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        try checkCancellation(cancel);
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

pub fn sameCustodySnapshot(a: files.Snapshot, b: files.Snapshot) bool {
    return a.mask.GID and b.mask.GID and files.sameSnapshot(a, b) and a.gid == b.gid;
}

pub fn checkCancellation(cancel: ?*const std.atomic.Value(bool)) !void {
    if (cancel) |flag| if (flag.load(.acquire)) return error.Cancelled;
}

pub fn directorySnapshot(dir: std.Io.Dir) !files.Snapshot {
    return files.snapshot(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } });
}

pub fn sameDirectory(a: files.Snapshot, b: files.Snapshot) bool {
    return a.mask.GID and b.mask.GID and a.ino == b.ino and a.dev_major == b.dev_major and a.dev_minor == b.dev_minor and
        a.mode == b.mode and a.uid == b.uid and a.gid == b.gid;
}

pub fn verifyRoot(io: std.Io, path: []const u8, expected: files.Snapshot) !void {
    const named = try files.Directory.open(io, path);
    defer named.close(io);
    if (!sameDirectory(expected, try directorySnapshot(named.dir))) return error.UnsafeDestination;
}

pub fn verifyRetained(io: std.Io, retained: *const files.RetainedFile) !void {
    try retained.verify(io);
    if (!sameCustodySnapshot(retained.file_snapshot, try files.snapshot(retained.file)))
        return error.FileChanged;
    var named = try files.RetainedFile.open(io, retained.path, retained.policy);
    defer named.close(io);
    if (!sameCustodySnapshot(retained.file_snapshot, named.file_snapshot) or
        retained.directory_count != named.directory_count) return error.FileChanged;
    for (0..retained.directory_count) |i| {
        if (!sameDirectory(retained.directory_snapshots[i], try directorySnapshot(retained.directories[i])) or
            !sameDirectory(retained.directory_snapshots[i], named.directory_snapshots[i]))
            return error.FileChanged;
    }
}

pub fn hashRetained(io: std.Io, retained: *const files.RetainedFile, limit: u64, cancel: ?*const std.atomic.Value(bool)) ![64]u8 {
    try validateSource(retained.file_snapshot, limit);
    try verifyRetained(io, retained);
    var hasher = Sha256.init(.{});
    var buffer: [chunk_size]u8 = undefined;
    var offset: u64 = 0;
    while (offset < retained.file_snapshot.size) {
        try checkCancellation(cancel);
        const want: usize = @intCast(@min(buffer.len, retained.file_snapshot.size - offset));
        const count = try retained.file.readPositionalAll(io, buffer[0..want], offset);
        if (count != want) return error.FileChanged;
        hasher.update(buffer[0..count]);
        offset += count;
    }
    if (try retained.file.readPositionalAll(io, buffer[0..1], offset) != 0) return error.FileChanged;
    try verifyRetained(io, retained);
    return std.fmt.bytesToHex(hasher.finalResult(), .lower);
}

pub const Scanner = struct {
    tail: [scan_tail]u8 = undefined,
    tail_len: usize = 0,

    pub fn observe(self: *Scanner, chunk: []const u8) !void {
        if (chunk.len > chunk_size) return error.InvalidScanChunk;
        var scan: [scan_tail + chunk_size]u8 = undefined;
        @memcpy(scan[0..self.tail_len], self.tail[0..self.tail_len]);
        @memcpy(scan[self.tail_len..][0..chunk.len], chunk);
        for (sensitive_patterns) |pattern| {
            if (std.mem.indexOf(u8, scan[0 .. self.tail_len + chunk.len], pattern) != null)
                return error.SensitivePattern;
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
