// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const core = @import("hyperv_core");
const preparation_files = @import("preparation_files");
const paths = @import("facade_paths");
const json = @import("build-tool-json.zig");

pub const PrivateDirectory = core.private_files.Directory;
pub const RetainedFile = core.private_files.RetainedFile;
pub const FileParent = core.private_files.FileParent;
pub const Locked = core.private_files.Locked;
pub const Snapshot = core.private_files.Snapshot;
pub const SourceDirectory = preparation_files.Directory;
pub const snapshot = core.private_files.snapshot;
pub const sameSnapshot = core.private_files.sameSnapshot;

const block_bytes = 512;
const maximum_pax_bytes = 64 * 1024;

pub const Repository = struct {
    root: SourceDirectory,
    app: SourceDirectory,

    pub fn open(
        allocator: std.mem.Allocator,
        io: std.Io,
        repository_path: []const u8,
    ) !Repository {
        const canonical = try paths.canonicalizeNearestExisting(allocator, io, repository_path);
        defer allocator.free(canonical.path);
        if (!canonical.exists or !std.mem.eql(u8, repository_path, canonical.path))
            return error.UnsafeRepository;
        const root = try SourceDirectory.open(allocator, io, repository_path);
        errdefer root.close(allocator, io);
        const app_path = try std.fs.path.join(
            allocator,
            &.{ repository_path, "support", "apps", "wamr-aot" },
        );
        defer allocator.free(app_path);
        const app = SourceDirectory.open(allocator, io, app_path) catch
            return error.InvalidRepository;
        return .{ .root = root, .app = app };
    }

    pub fn close(self: Repository, allocator: std.mem.Allocator, io: std.Io) void {
        self.app.close(allocator, io);
        self.root.close(allocator, io);
    }
};

pub fn createPrivateDirectory(
    io: std.Io,
    parent: std.Io.Dir,
    name: []const u8,
) !std.Io.Dir {
    try core.private_files.basename(name);
    try parent.createDir(io, name, .fromMode(0o700));
    const directory = try parent.openDir(io, name, .{
        .follow_symlinks = false,
        .iterate = true,
    });
    errdefer directory.close(io);
    try directory.setPermissions(io, .fromMode(0o700));
    try validateOwnedDirectory(directory);
    return directory;
}

pub fn ensurePrivateDirectory(
    io: std.Io,
    parent: std.Io.Dir,
    name: []const u8,
) !std.Io.Dir {
    return createPrivateDirectory(io, parent, name) catch |err| switch (err) {
        error.PathAlreadyExists => {
            try core.private_files.basename(name);
            const directory = try parent.openDir(io, name, .{
                .follow_symlinks = false,
                .iterate = true,
            });
            errdefer directory.close(io);
            try directory.setPermissions(io, .fromMode(0o700));
            try validateOwnedDirectory(directory);
            return directory;
        },
        else => return err,
    };
}

pub fn writePrivateCreate(
    io: std.Io,
    directory: std.Io.Dir,
    name: []const u8,
    contents: []const u8,
) !void {
    try core.private_files.basename(name);
    const file = try directory.createFile(io, name, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o600));
    try file.writePositionalAll(io, contents, 0);
    try file.setLength(io, contents.len);
    try file.sync(io);
    const metadata = try preparation_files.metadata(file);
    if (metadata.mode & linux.S.IFMT != linux.S.IFREG or
        metadata.mode & 0o7777 != 0o600 or metadata.uid != linux.geteuid() or
        metadata.links != 1)
        return error.UnsafeFile;
}

pub fn writePrivateAtomicCreate(
    io: std.Io,
    directory: std.Io.Dir,
    name: []const u8,
    contents: []const u8,
) !void {
    try core.private_files.basename(name);
    try validateOwnedDirectory(directory);
    var atomic = try directory.createFileAtomic(io, name, .{
        .permissions = .fromMode(0o600),
        .replace = false,
    });
    var active = true;
    defer if (active) atomic.deinit(io);
    try atomic.file.setPermissions(io, .fromMode(0o600));
    try atomic.file.writePositionalAll(io, contents, 0);
    try atomic.file.setLength(io, contents.len);
    try atomic.file.sync(io);
    try atomic.link(io);
    atomic.deinit(io);
    active = false;
    const directory_file: std.Io.File = .{
        .handle = directory.handle,
        .flags = .{ .nonblocking = false },
    };
    try directory_file.sync(io);
    const published = try directory.openFile(io, name, .{
        .mode = .read_only,
        .follow_symlinks = false,
    });
    defer published.close(io);
    const metadata = try preparation_files.metadata(published);
    if (metadata.mode & linux.S.IFMT != linux.S.IFREG or
        metadata.mode & 0o7777 != 0o600 or metadata.uid != linux.geteuid() or
        metadata.links != 1 or metadata.size != contents.len)
        return error.UnsafeFile;
}

pub fn hashStableFile(
    io: std.Io,
    file: std.Io.File,
    maximum: u64,
) ![64]u8 {
    const before = try preparation_files.metadata(file);
    if (before.mode & linux.S.IFMT != linux.S.IFREG) return error.UnsafeFile;
    if (before.size > maximum) return error.FileTooLarge;
    const digest = try preparation_files.hashFile(io, file, before.size);
    if (!std.meta.eql(before, try preparation_files.metadata(file)))
        return error.FileChanged;
    return digest;
}

pub const ArchiveLimits = struct {
    archive_bytes: u64 = 512 * 1024 * 1024,
    entries: usize = 200_000,
    file_bytes: u64 = 256 * 1024 * 1024,
    total_file_bytes: u64 = 512 * 1024 * 1024,
    path_bytes: usize = 4095,
    depth: usize = 64,
};

fn validateLimits(limits: ArchiveLimits) !void {
    if (limits.archive_bytes == 0 or limits.entries == 0 or limits.file_bytes == 0 or
        limits.total_file_bytes == 0 or limits.path_bytes == 0 or
        limits.path_bytes > std.fs.max_path_bytes or limits.depth == 0)
        return error.InvalidLimits;
}

pub const Extraction = struct {
    archive_sha256: [64]u8,
    entries: usize,
    files: usize,
    directories: usize,
    symbolic_links: usize,
    hard_links: usize,
    file_bytes: u64,
};

pub const TestFault = struct {
    interrupt_after_archive_bytes: ?u64 = null,
};

pub fn extractGitArchive(
    allocator: std.mem.Allocator,
    io: std.Io,
    archive_path: []const u8,
    destination_path: []const u8,
    limits: ArchiveLimits,
) !Extraction {
    return extractGitArchiveImpl(
        allocator,
        io,
        archive_path,
        destination_path,
        limits,
        .{},
    );
}

pub fn extractGitArchiveFault(
    allocator: std.mem.Allocator,
    io: std.Io,
    archive_path: []const u8,
    destination_path: []const u8,
    limits: ArchiveLimits,
    fault: TestFault,
) !Extraction {
    if (!builtin.is_test) @compileError("archive interruption is test-only");
    return extractGitArchiveImpl(
        allocator,
        io,
        archive_path,
        destination_path,
        limits,
        fault,
    );
}

fn extractGitArchiveImpl(
    allocator: std.mem.Allocator,
    io: std.Io,
    archive_path: []const u8,
    destination_path: []const u8,
    limits: ArchiveLimits,
    fault: TestFault,
) !Extraction {
    try validateLimits(limits);
    var archive = try RetainedFile.open(io, archive_path, .artifact);
    defer archive.close(io);
    if (archive.file_snapshot.size == 0 or archive.file_snapshot.size > limits.archive_bytes)
        return error.ArchiveTooLarge;
    const destination_parent = try FileParent.open(io, destination_path, .private);
    defer destination_parent.close(io);
    try core.private_files.basename(destination_parent.name);
    const root = try createPrivateDirectory(io, destination_parent.directory, destination_parent.name);
    defer root.close(io);

    var reader: ArchiveReader = .{
        .io = io,
        .file = archive.file,
        .size = archive.file_snapshot.size,
        .fault = fault,
    };
    var names = std.StringHashMap(void).init(allocator);
    defer {
        var keys = names.keyIterator();
        while (keys.next()) |key| allocator.free(key.*);
        names.deinit();
    }
    var pending: Pending = .{};
    defer pending.deinit(allocator);
    var result: Extraction = .{
        .archive_sha256 = undefined,
        .entries = 0,
        .files = 0,
        .directories = 0,
        .symbolic_links = 0,
        .hard_links = 0,
        .file_bytes = 0,
    };
    var name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;

    while (true) {
        var header_bytes: [block_bytes]u8 = undefined;
        try reader.readExact(&header_bytes);
        if (allZero(&header_bytes)) {
            var second: [block_bytes]u8 = undefined;
            try reader.readExact(&second);
            if (!allZero(&second)) return error.MalformedArchiveEnd;
            try reader.requireTrailingZeroes();
            break;
        }
        const header = try Header.parse(&header_bytes);
        switch (header.kind) {
            .global_pax => {
                if (pending.hasValues()) return error.MalformedArchiveMetadata;
                const data = try reader.readDataAlloc(allocator, header.size, maximum_pax_bytes);
                defer allocator.free(data);
                var ignored: Pending = .{};
                defer ignored.deinit(allocator);
                try parsePax(allocator, data, &ignored);
                if (ignored.hasValues()) return error.UnsupportedGlobalPax;
            },
            .pax => {
                if (pending.hasValues()) return error.MalformedArchiveMetadata;
                const data = try reader.readDataAlloc(allocator, header.size, maximum_pax_bytes);
                defer allocator.free(data);
                try parsePax(allocator, data, &pending);
            },
            .gnu_long_name, .gnu_long_link => {
                const value = try reader.readStringAlloc(allocator, header.size, limits.path_bytes);
                if (header.kind == .gnu_long_name) {
                    if (pending.path != null) return error.DuplicateArchiveAttribute;
                    pending.path = value;
                } else {
                    if (pending.link_path != null) return error.DuplicateArchiveAttribute;
                    pending.link_path = value;
                }
            },
            .file, .directory, .symbolic_link, .hard_link => {
                const header_name = try header.fullName(&name_buffer);
                const header_link = try header.linkName(&link_buffer);
                const name = pending.path orelse header_name;
                const link_name = pending.link_path orelse header_link;
                const size = pending.size orelse header.size;
                try processEntry(
                    allocator,
                    io,
                    root,
                    &reader,
                    &names,
                    &result,
                    header.kind,
                    name,
                    link_name,
                    size,
                    header.mode,
                    limits,
                );
                pending.deinit(allocator);
                pending = .{};
            },
            .unsupported => return error.UnsupportedArchiveType,
        }
    }
    if (pending.hasValues()) return error.OrphanArchiveMetadata;
    try archive.verify(io);
    result.archive_sha256 = std.fmt.bytesToHex(reader.hasher.finalResult(), .lower);
    return result;
}

const EntryKind = enum {
    file,
    directory,
    hard_link,
    symbolic_link,
    global_pax,
    pax,
    gnu_long_name,
    gnu_long_link,
    unsupported,
};

const Header = struct {
    bytes: *const [block_bytes]u8,
    kind: EntryKind,
    mode: u32,
    size: u64,

    fn parse(bytes: *const [block_bytes]u8) !Header {
        const expected = try octal(bytes[148..156]);
        var checksum: u64 = 0;
        for (bytes, 0..) |byte, index|
            checksum += if (index >= 148 and index < 156) 0x20 else byte;
        if (expected != checksum) return error.ArchiveChecksumMismatch;
        if (!std.mem.eql(u8, bytes[257..262], "ustar"))
            return error.UnsupportedArchiveFormat;
        const kind: EntryKind = switch (bytes[156]) {
            0, '0' => .file,
            '1' => .hard_link,
            '2' => .symbolic_link,
            '5' => .directory,
            'g' => .global_pax,
            'x' => .pax,
            'L' => .gnu_long_name,
            'K' => .gnu_long_link,
            else => .unsupported,
        };
        return .{
            .bytes = bytes,
            .kind = kind,
            .mode = @intCast(try octal(bytes[100..108])),
            .size = try octal(bytes[124..136]),
        };
    }

    fn fullName(self: Header, buffer: []u8) ![]const u8 {
        const name = stringField(self.bytes[0..100]);
        const prefix = stringField(self.bytes[345..500]);
        if (prefix.len == 0) {
            if (name.len > buffer.len) return error.ArchivePathTooLong;
            @memcpy(buffer[0..name.len], name);
            return buffer[0..name.len];
        }
        if (prefix.len + 1 + name.len > buffer.len) return error.ArchivePathTooLong;
        @memcpy(buffer[0..prefix.len], prefix);
        buffer[prefix.len] = '/';
        @memcpy(buffer[prefix.len + 1 ..][0..name.len], name);
        return buffer[0 .. prefix.len + 1 + name.len];
    }

    fn linkName(self: Header, buffer: []u8) ![]const u8 {
        const link = stringField(self.bytes[157..257]);
        if (link.len > buffer.len) return error.ArchivePathTooLong;
        @memcpy(buffer[0..link.len], link);
        return buffer[0..link.len];
    }
};

const ArchiveReader = struct {
    io: std.Io,
    file: std.Io.File,
    size: u64,
    offset: u64 = 0,
    hasher: core.Sha256 = core.Sha256.init(.{}),
    fault: TestFault,

    fn readExact(self: *ArchiveReader, output: []u8) !void {
        const end = std.math.add(u64, self.offset, output.len) catch
            return error.TruncatedArchive;
        if (end > self.size) return error.TruncatedArchive;
        if (self.fault.interrupt_after_archive_bytes) |limit| {
            if (self.offset >= limit or end > limit) return error.InjectedInterruption;
        }
        if (try self.file.readPositionalAll(self.io, output, self.offset) != output.len)
            return error.TruncatedArchive;
        self.hasher.update(output);
        self.offset = end;
    }

    fn readDataAlloc(
        self: *ArchiveReader,
        allocator: std.mem.Allocator,
        size: u64,
        maximum: usize,
    ) ![]u8 {
        if (size > maximum or size > std.math.maxInt(usize))
            return error.ArchiveMetadataTooLarge;
        const data = try allocator.alloc(u8, @intCast(size));
        errdefer allocator.free(data);
        try self.readExact(data);
        try self.readPadding(size);
        return data;
    }

    fn readStringAlloc(
        self: *ArchiveReader,
        allocator: std.mem.Allocator,
        size: u64,
        maximum: usize,
    ) ![]u8 {
        const raw = try self.readDataAlloc(allocator, size, maximum + 1);
        defer allocator.free(raw);
        const value = std.mem.trimEnd(u8, raw, "\x00\n");
        if (value.len == 0 or value.len > maximum or std.mem.indexOfScalar(u8, value, 0) != null)
            return error.MalformedArchiveMetadata;
        return allocator.dupe(u8, value);
    }

    fn readPadding(self: *ArchiveReader, size: u64) !void {
        const remainder = size % block_bytes;
        if (remainder == 0) return;
        var padding: [block_bytes]u8 = undefined;
        try self.readExact(padding[0 .. block_bytes - remainder]);
    }

    fn streamFile(self: *ArchiveReader, io: std.Io, destination: std.Io.File, size: u64) !void {
        var buffer: [64 * 1024]u8 = undefined;
        var written: u64 = 0;
        while (written < size) {
            const count: usize = @intCast(@min(buffer.len, size - written));
            try self.readExact(buffer[0..count]);
            try destination.writePositionalAll(io, buffer[0..count], written);
            written += count;
        }
        try self.readPadding(size);
    }

    fn discardEntry(self: *ArchiveReader, size: u64) !void {
        var buffer: [64 * 1024]u8 = undefined;
        var consumed: u64 = 0;
        while (consumed < size) {
            const count: usize = @intCast(@min(buffer.len, size - consumed));
            try self.readExact(buffer[0..count]);
            consumed += count;
        }
        try self.readPadding(size);
    }

    fn requireTrailingZeroes(self: *ArchiveReader) !void {
        var buffer: [64 * 1024]u8 = undefined;
        while (self.offset < self.size) {
            const count: usize = @intCast(@min(buffer.len, self.size - self.offset));
            try self.readExact(buffer[0..count]);
            if (!allZero(buffer[0..count])) return error.TrailingArchiveData;
        }
    }
};

const Pending = struct {
    path: ?[]u8 = null,
    link_path: ?[]u8 = null,
    size: ?u64 = null,

    fn hasValues(self: Pending) bool {
        return self.path != null or self.link_path != null or self.size != null;
    }

    fn deinit(self: *Pending, allocator: std.mem.Allocator) void {
        if (self.path) |value| allocator.free(value);
        if (self.link_path) |value| allocator.free(value);
        self.* = .{};
    }
};

fn parsePax(allocator: std.mem.Allocator, data: []const u8, pending: *Pending) !void {
    var offset: usize = 0;
    while (offset < data.len) {
        const space = std.mem.indexOfScalarPos(u8, data, offset, ' ') orelse
            return error.MalformedPax;
        if (space == offset) return error.MalformedPax;
        for (data[offset..space]) |byte| if (!std.ascii.isDigit(byte))
            return error.MalformedPax;
        const length = std.fmt.parseInt(usize, data[offset..space], 10) catch
            return error.MalformedPax;
        if (length == 0 or length > data.len - offset) return error.MalformedPax;
        const record = data[offset .. offset + length];
        if (record[record.len - 1] != '\n') return error.MalformedPax;
        const equals = std.mem.indexOfScalarPos(u8, record, space - offset + 1, '=') orelse
            return error.MalformedPax;
        const key = record[space - offset + 1 .. equals];
        const value = record[equals + 1 .. record.len - 1];
        if (key.len == 0 or std.mem.indexOfScalar(u8, key, 0) != null or
            std.mem.indexOfScalar(u8, value, 0) != null)
            return error.MalformedPax;
        if (std.mem.eql(u8, key, "path")) {
            if (pending.path != null) return error.DuplicateArchiveAttribute;
            pending.path = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "linkpath")) {
            if (pending.link_path != null) return error.DuplicateArchiveAttribute;
            pending.link_path = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "size")) {
            if (pending.size != null or value.len == 0) return error.DuplicateArchiveAttribute;
            pending.size = std.fmt.parseInt(u64, value, 10) catch return error.MalformedPax;
        }
        offset += length;
    }
}

fn processEntry(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: std.Io.Dir,
    reader: *ArchiveReader,
    names: *std.StringHashMap(void),
    result: *Extraction,
    kind: EntryKind,
    raw_name: []const u8,
    link_name: []const u8,
    size: u64,
    mode: u32,
    limits: ArchiveLimits,
) !void {
    const name = try normalizeEntryName(raw_name, kind == .directory, limits);
    if (names.count() >= limits.entries) return error.ArchiveEntryLimit;
    const owned_name = try allocator.dupe(u8, name);
    const entry = names.getOrPut(owned_name) catch |err| {
        allocator.free(owned_name);
        return err;
    };
    if (entry.found_existing) {
        allocator.free(owned_name);
        return error.DuplicateArchiveEntry;
    }
    result.entries += 1;
    switch (kind) {
        .file => {
            if (link_name.len != 0) return error.MalformedArchiveEntry;
            const next_total = std.math.add(u64, result.file_bytes, size) catch
                return error.ArchiveByteLimit;
            if (size > limits.file_bytes or next_total > limits.total_file_bytes)
                return error.ArchiveByteLimit;
            const permissions = try gitFileMode(mode);
            var parent = try createParentDirectories(io, root, name);
            defer parent.close(io);
            const file = try parent.directory.createFile(io, parent.name, .{
                .exclusive = true,
                .permissions = .fromMode(permissions),
            });
            defer file.close(io);
            try reader.streamFile(io, file, size);
            try file.setLength(io, size);
            try file.setPermissions(io, .fromMode(permissions));
            try file.sync(io);
            const metadata = try preparation_files.metadata(file);
            if (metadata.mode & linux.S.IFMT != linux.S.IFREG or
                metadata.mode & 0o7777 != permissions or metadata.links != 1)
                return error.UnsafeExtractedFile;
            result.files += 1;
            result.file_bytes += size;
        },
        .directory => {
            if (size != 0 or link_name.len != 0 or !gitDirectoryMode(mode))
                return error.MalformedArchiveEntry;
            var parent = try createParentDirectories(io, root, name);
            defer parent.close(io);
            const directory = try createPrivateDirectory(io, parent.directory, parent.name);
            directory.close(io);
            result.directories += 1;
        },
        .symbolic_link => {
            if (size != 0 or link_name.len == 0) return error.MalformedArchiveEntry;
            try requireContainedLink(allocator, name, link_name, false, limits);
            var parent = try createParentDirectories(io, root, name);
            defer parent.close(io);
            try parent.directory.symLink(io, link_name, parent.name, .{});
            result.symbolic_links += 1;
        },
        .hard_link => {
            if (size != 0 or link_name.len == 0) return error.MalformedArchiveEntry;
            const target = try containedLinkTarget(allocator, name, link_name, true, limits);
            defer allocator.free(target);
            const target_file = try openNoFollow(io, root, target);
            defer target_file.close(io);
            const metadata = try preparation_files.metadata(target_file);
            if (metadata.mode & linux.S.IFMT != linux.S.IFREG)
                return error.InvalidHardLinkTarget;
            var parent = try createParentDirectories(io, root, name);
            defer parent.close(io);
            const target_z = try allocator.dupeZ(u8, target);
            defer allocator.free(target_z);
            const name_z = try allocator.dupeZ(u8, parent.name);
            defer allocator.free(name_z);
            if (linux.errno(linux.linkat(
                root.handle,
                target_z,
                parent.directory.handle,
                name_z,
                0,
            )) != .SUCCESS) return error.HardLinkFailed;
            const linked = try parent.directory.openFile(io, parent.name, .{
                .mode = .read_only,
                .follow_symlinks = false,
            });
            defer linked.close(io);
            const linked_metadata = try preparation_files.metadata(linked);
            if (linked_metadata.device != metadata.device or
                linked_metadata.inode != metadata.inode)
                return error.InvalidHardLinkTarget;
            result.hard_links += 1;
        },
        else => unreachable,
    }
    if (kind != .file) try reader.discardEntry(size);
}

const Parent = struct {
    directory: std.Io.Dir,
    name: []const u8,

    fn close(self: *Parent, io: std.Io) void {
        self.directory.close(io);
        self.* = undefined;
    }
};

fn createParentDirectories(io: std.Io, root: std.Io.Dir, path: []const u8) !Parent {
    var current = try root.openDir(io, ".", .{
        .follow_symlinks = false,
        .iterate = true,
    });
    errdefer current.close(io);
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (components.peek() == null)
            return .{ .directory = current, .name = component };
        const next = current.openDir(io, component, .{
            .follow_symlinks = false,
            .iterate = true,
        }) catch |err| switch (err) {
            error.FileNotFound => try createPrivateDirectory(io, current, component),
            else => return err,
        };
        current.close(io);
        current = next;
        try validateOwnedDirectory(current);
    }
    unreachable;
}

fn openNoFollow(io: std.Io, root: std.Io.Dir, path: []const u8) !std.Io.File {
    var current = try root.openDir(io, ".", .{
        .follow_symlinks = false,
        .iterate = true,
    });
    defer current.close(io);
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (components.peek() == null)
            return current.openFile(io, component, .{
                .mode = .read_only,
                .follow_symlinks = false,
            });
        const next = try current.openDir(io, component, .{
            .follow_symlinks = false,
            .iterate = true,
        });
        current.close(io);
        current = next;
    }
    unreachable;
}

fn normalizeEntryName(raw: []const u8, directory: bool, limits: ArchiveLimits) ![]const u8 {
    var name = raw;
    if (directory and name.len != 0 and name[name.len - 1] == '/')
        name = name[0 .. name.len - 1];
    if (name.len == 0 or name.len > limits.path_bytes or name[0] == '/' or
        name[name.len - 1] == '/' or std.mem.indexOfScalar(u8, name, 0) != null)
        return error.UnsafeArchivePath;
    var depth: usize = 0;
    var components = std.mem.splitScalar(u8, name, '/');
    while (components.next()) |component| {
        if (component.len == 0 or component.len > 255 or
            std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return error.UnsafeArchivePath;
        depth += 1;
        if (depth > limits.depth) return error.ArchiveDepthLimit;
    }
    return name;
}

fn requireContainedLink(
    allocator: std.mem.Allocator,
    entry: []const u8,
    target: []const u8,
    hard: bool,
    limits: ArchiveLimits,
) !void {
    const normalized = try containedLinkTarget(allocator, entry, target, hard, limits);
    allocator.free(normalized);
}

fn containedLinkTarget(
    allocator: std.mem.Allocator,
    entry: []const u8,
    target: []const u8,
    hard: bool,
    limits: ArchiveLimits,
) ![]u8 {
    if (target.len == 0 or target.len > limits.path_bytes or target[0] == '/' or
        std.mem.indexOfScalar(u8, target, 0) != null)
        return error.EscapingArchiveLink;
    var components: std.ArrayList([]const u8) = .empty;
    defer components.deinit(allocator);
    if (!hard) {
        if (std.fs.path.dirname(entry)) |parent| {
            var parents = std.mem.splitScalar(u8, parent, '/');
            while (parents.next()) |component| try components.append(allocator, component);
        }
    }
    var targets = std.mem.splitScalar(u8, target, '/');
    while (targets.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) {
            if (components.items.len == 0) return error.EscapingArchiveLink;
            _ = components.pop();
            continue;
        }
        if (component.len > 255) return error.EscapingArchiveLink;
        try components.append(allocator, component);
        if (components.items.len > limits.depth) return error.ArchiveDepthLimit;
    }
    if (hard and components.items.len == 0) return error.EscapingArchiveLink;
    return std.mem.join(allocator, "/", components.items);
}

fn gitFileMode(mode: u32) !u16 {
    if (mode & 0o7000 != 0) return error.UnsupportedArchiveMode;
    var filtered: u16 = @intCast(mode & 0o755);
    if (filtered & 0o100 == 0) filtered &= ~@as(u16, 0o111);
    filtered |= 0o600;
    return switch (filtered) {
        0o644, 0o755 => filtered,
        else => error.UnsupportedArchiveMode,
    };
}

fn gitDirectoryMode(mode: u32) bool {
    return mode & 0o7000 == 0 and mode & 0o755 == 0o755;
}

fn validateOwnedDirectory(directory: std.Io.Dir) !void {
    const metadata = try preparation_files.metadata(.{
        .handle = directory.handle,
        .flags = .{ .nonblocking = false },
    });
    if (metadata.mode & linux.S.IFMT != linux.S.IFDIR or
        metadata.mode & 0o7777 != 0o700 or metadata.uid != linux.geteuid())
        return error.UnsafeDirectory;
}

fn stringField(bytes: []const u8) []const u8 {
    return bytes[0 .. std.mem.indexOfScalar(u8, bytes, 0) orelse bytes.len];
}

fn octal(bytes: []const u8) !u64 {
    if (bytes.len == 0 or bytes[0] & 0x80 != 0) return error.UnsupportedArchiveNumber;
    const value = std.mem.trim(u8, bytes, " \x00");
    if (value.len == 0) return 0;
    for (value) |byte| if (byte < '0' or byte > '7')
        return error.MalformedArchiveNumber;
    return std.fmt.parseInt(u64, value, 8) catch return error.MalformedArchiveNumber;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

pub const SourceIdentity = struct {
    bytes: []u8,
    sha256: [64]u8,
    files: usize,
    file_bytes: u64,

    pub fn deinit(self: *SourceIdentity, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

const SourceRecord = struct {
    path: []u8,
    size: u64,
    sha256: [64]u8,

    fn less(_: void, left: SourceRecord, right: SourceRecord) bool {
        return std.mem.lessThan(u8, left.path, right.path);
    }
};

pub fn sourceIdentity(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_path: []const u8,
    limits: ArchiveLimits,
) !SourceIdentity {
    try validateLimits(limits);
    const root = try SourceDirectory.open(allocator, io, root_path);
    defer root.close(allocator, io);
    const root_before = try preparation_files.metadata(.{
        .handle = root.dir.handle,
        .flags = .{ .nonblocking = false },
    });
    var records: std.ArrayList(SourceRecord) = .empty;
    defer {
        for (records.items) |record| allocator.free(record.path);
        records.deinit(allocator);
    }
    var total: u64 = 0;
    try collectSource(
        allocator,
        io,
        root,
        root.dir,
        "",
        0,
        limits,
        &records,
        &total,
    );
    std.mem.sort(SourceRecord, records.items, {}, SourceRecord.less);
    var output = std.Io.Writer.Allocating.init(allocator);
    defer output.deinit();
    try output.writer.writeByte('{');
    for (records.items, 0..) |record, index| {
        if (index != 0) try output.writer.writeByte(',');
        try json.writeString(&output.writer, record.path);
        try output.writer.print(
            ":{{\"bytes\":{d},\"sha256\":\"{s}\"}}",
            .{ record.size, record.sha256[0..] },
        );
    }
    try output.writer.writeAll("}\n");
    const bytes = try output.toOwnedSlice();
    errdefer allocator.free(bytes);
    var digest: [32]u8 = undefined;
    core.Sha256.hash(bytes[0 .. bytes.len - 1], &digest, .{});
    if (!std.meta.eql(root_before, try preparation_files.metadata(.{
        .handle = root.dir.handle,
        .flags = .{ .nonblocking = false },
    }))) return error.SourceChanged;
    const reopened = try SourceDirectory.open(allocator, io, root_path);
    defer reopened.close(allocator, io);
    try preparation_files.requireDirectoryIdentity(root, reopened);
    return .{
        .bytes = bytes,
        .sha256 = std.fmt.bytesToHex(digest, .lower),
        .files = records.items.len,
        .file_bytes = total,
    };
}

fn collectSource(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: SourceDirectory,
    directory: std.Io.Dir,
    prefix: []const u8,
    depth: usize,
    limits: ArchiveLimits,
    records: *std.ArrayList(SourceRecord),
    total: *u64,
) !void {
    if (depth > limits.depth) return error.ArchiveDepthLimit;
    const before = try preparation_files.metadata(.{
        .handle = directory.handle,
        .flags = .{ .nonblocking = false },
    });
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        const relative = if (prefix.len == 0)
            try allocator.dupe(u8, entry.name)
        else
            try std.fs.path.join(allocator, &.{ prefix, entry.name });
        defer allocator.free(relative);
        if (relative.len > limits.path_bytes) return error.ArchivePathTooLong;
        switch (entry.kind) {
            .directory => {
                const path_file = try directory.openFile(io, entry.name, .{
                    .path_only = true,
                    .follow_symlinks = false,
                });
                defer path_file.close(io);
                const identity = try preparation_files.metadata(path_file);
                if (identity.mode & linux.S.IFMT != linux.S.IFDIR)
                    return error.SourceChanged;
                const child = try directory.openDir(io, entry.name, .{
                    .follow_symlinks = false,
                    .iterate = true,
                });
                defer child.close(io);
                if (!std.meta.eql(identity, try preparation_files.metadata(.{
                    .handle = child.handle,
                    .flags = .{ .nonblocking = false },
                }))) return error.SourceChanged;
                try collectSource(
                    allocator,
                    io,
                    root,
                    child,
                    relative,
                    depth + 1,
                    limits,
                    records,
                    total,
                );
                const named = try directory.openDir(io, entry.name, .{
                    .follow_symlinks = false,
                });
                defer named.close(io);
                if (!std.meta.eql(identity, try preparation_files.metadata(.{
                    .handle = named.handle,
                    .flags = .{ .nonblocking = false },
                }))) return error.SourceChanged;
            },
            .file => {
                const record = try sourceRecord(
                    allocator,
                    io,
                    root,
                    relative,
                    false,
                    limits.file_bytes,
                ) orelse
                    return error.SourceChanged;
                try appendSourceRecord(allocator, limits, records, total, record);
            },
            .sym_link => {
                const record = try sourceRecord(
                    allocator,
                    io,
                    root,
                    relative,
                    true,
                    limits.file_bytes,
                ) orelse
                    continue;
                try appendSourceRecord(allocator, limits, records, total, record);
            },
            else => return error.UnsupportedSourceEntry,
        }
    }
    if (!std.meta.eql(before, try preparation_files.metadata(.{
        .handle = directory.handle,
        .flags = .{ .nonblocking = false },
    }))) return error.SourceChanged;
}

fn appendSourceRecord(
    allocator: std.mem.Allocator,
    limits: ArchiveLimits,
    records: *std.ArrayList(SourceRecord),
    total: *u64,
    record: SourceRecord,
) !void {
    errdefer allocator.free(record.path);
    if (records.items.len >= limits.entries) return error.ArchiveEntryLimit;
    total.* = std.math.add(u64, total.*, record.size) catch return error.ArchiveByteLimit;
    if (total.* > limits.total_file_bytes) return error.ArchiveByteLimit;
    try records.append(allocator, record);
}

fn sourceRecord(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: SourceDirectory,
    relative: []const u8,
    link: bool,
    maximum: u64,
) !?SourceRecord {
    if (!link) {
        const recorded = try root.record(
            allocator,
            io,
            relative,
            maximum,
            .source,
        );
        defer allocator.free(recorded.path);
        return .{
            .path = try allocator.dupe(u8, relative),
            .size = recorded.size,
            .sha256 = recorded.sha256,
        };
    }
    var link_file: ?std.Io.File = null;
    defer if (link_file) |file| file.close(io);
    var link_before: ?preparation_files.Metadata = null;
    if (link) {
        const parent = try sourceParent(io, root.dir, relative);
        defer parent.directory.close(io);
        const opened = try parent.directory.openFile(io, parent.name, .{
            .path_only = true,
            .follow_symlinks = false,
        });
        link_file = opened;
        link_before = try preparation_files.metadata(opened);
        if (link_before.?.mode & linux.S.IFMT != linux.S.IFLNK)
            return error.SourceChanged;
    }
    const file = if (link)
        root.dir.openFile(io, relative, .{
            .mode = .read_only,
            .follow_symlinks = true,
        }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir, error.IsDir => return null,
            else => return err,
        }
    else
        try openNoFollow(io, root.dir, relative);
    defer file.close(io);
    const before = try preparation_files.metadata(file);
    if (before.mode & linux.S.IFMT != linux.S.IFREG) return null;
    if (before.size > maximum) return error.FileTooLarge;
    if (link) {
        var descriptor_path: [64]u8 = undefined;
        const proc_path = try std.fmt.bufPrint(&descriptor_path, "/proc/self/fd/{d}", .{file.handle});
        var resolved_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try std.Io.Dir.realPathFileAbsolute(io, proc_path, &resolved_buffer);
        const resolved = resolved_buffer[0..length];
        if (!paths.isDescendant(root.path, resolved)) return error.EscapingSourceLink;
    }
    const digest = try preparation_files.hashFile(io, file, before.size);
    if (!std.meta.eql(before, try preparation_files.metadata(file)))
        return error.SourceChanged;
    if (link) {
        if (!std.meta.eql(link_before.?, try preparation_files.metadata(link_file.?)))
            return error.SourceChanged;
        const reopened = root.dir.openFile(io, relative, .{
            .mode = .read_only,
            .follow_symlinks = true,
        }) catch return error.SourceChanged;
        defer reopened.close(io);
        if (!std.meta.eql(before, try preparation_files.metadata(reopened)))
            return error.SourceChanged;
    }
    return .{
        .path = try allocator.dupe(u8, relative),
        .size = before.size,
        .sha256 = digest,
    };
}

fn sourceParent(io: std.Io, root: std.Io.Dir, path: []const u8) !Parent {
    var current = try root.openDir(io, ".", .{
        .follow_symlinks = false,
        .iterate = true,
    });
    errdefer current.close(io);
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (components.peek() == null)
            return .{ .directory = current, .name = component };
        const next = try current.openDir(io, component, .{
            .follow_symlinks = false,
            .iterate = true,
        });
        current.close(io);
        current = next;
    }
    unreachable;
}
