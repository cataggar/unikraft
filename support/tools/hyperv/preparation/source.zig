const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const rt = @import("runtime.zig");

pub const Entry = struct {
    path: []const u8,
    mode: []const u8,
    oid: []const u8,
    target: ?[]const u8 = null,
    size: u64 = 0,
    sha256: c.Sha = undefined,
};

const Hash = union(enum) {
    sha1: std.crypto.hash.Sha1,
    sha256: std.crypto.hash.sha2.Sha256,
    fn init(width: usize, kind: []const u8, size: u64) !Hash {
        var value: Hash = switch (width) {
            40 => .{ .sha1 = .init(.{}) },
            64 => .{ .sha256 = .init(.{}) },
            else => return error.InvalidObjectId,
        };
        var buffer: [96]u8 = undefined;
        value.update(try std.fmt.bufPrint(&buffer, "{s} {d}\x00", .{ kind, size }));
        return value;
    }
    fn update(self: *Hash, bytes: []const u8) void {
        switch (self.*) {
            inline else => |*hash| hash.update(bytes),
        }
    }
    fn finish(self: *Hash, allocator: std.mem.Allocator) ![]const u8 {
        return switch (self.*) {
            inline else => |*hash| allocator.dupe(u8, &std.fmt.bytesToHex(hash.finalResult(), .lower)),
        };
    }
};

pub fn parseTree(allocator: std.mem.Allocator, raw: []const u8, width: usize) ![]Entry {
    if (width != 40 and width != 64) return error.InvalidObjectId;
    if (raw.len == 0 or raw.len > 4 * 1024 * 1024 or raw[raw.len - 1] != 0) return error.InvalidTree;
    var entries: std.ArrayList(Entry) = .empty;
    var names = std.StringHashMap(void).init(allocator);
    var records = std.mem.splitScalar(u8, raw[0 .. raw.len - 1], 0);
    while (records.next()) |record| {
        const tab = std.mem.indexOfScalar(u8, record, '\t') orelse return error.InvalidTree;
        var fields = std.mem.splitScalar(u8, record[0..tab], ' ');
        const mode = fields.next() orelse return error.InvalidTree;
        const kind = fields.next() orelse return error.InvalidTree;
        const oid = fields.next() orelse return error.InvalidTree;
        if (fields.next() != null or !std.mem.eql(u8, kind, "blob") or oid.len != width) return error.InvalidTree;
        if (!std.mem.eql(u8, mode, "100644") and !std.mem.eql(u8, mode, "100755") and !std.mem.eql(u8, mode, "120000"))
            return error.InvalidTree;
        try c.objectId(oid);
        const path = record[tab + 1 ..];
        try c.relative(path);
        if (excluded(path) or names.contains(path) or entries.items.len >= 40000) return error.InvalidTree;
        try names.put(path, {});
        try entries.append(allocator, .{ .path = try allocator.dupe(u8, path), .mode = try allocator.dupe(u8, mode), .oid = try allocator.dupe(u8, oid) });
    }
    // The physical digest has one canonical order, independent of caller order.
    std.mem.sort(Entry, entries.items, {}, entryLess);
    return entries.toOwnedSlice(allocator);
}

fn entryLess(_: void, left: Entry, right: Entry) bool {
    return std.mem.lessThan(u8, left.path, right.path);
}

fn entryPosition(entries: []const Entry, path: []const u8) usize {
    var left: usize = 0;
    var right = entries.len;
    while (left < right) {
        const middle = left + (right - left) / 2;
        if (std.mem.lessThan(u8, entries[middle].path, path)) left = middle + 1 else right = middle;
    }
    return left;
}

pub fn verifyIndex(allocator: std.mem.Allocator, entries: []const Entry, raw: []const u8, flags: []const u8) !void {
    var expected = std.StringHashMap(Entry).init(allocator);
    var staged = std.StringHashMap(void).init(allocator);
    for (entries) |entry| try expected.put(entry.path, entry);
    if (raw.len == 0 or raw.len > 4 * 1024 * 1024 or raw[raw.len - 1] != 0 or
        flags.len == 0 or flags.len > 4 * 1024 * 1024 or flags[flags.len - 1] != 0) return error.InvalidIndex;
    var records = std.mem.splitScalar(u8, raw[0 .. raw.len - 1], 0);
    while (records.next()) |record| {
        const tab = std.mem.indexOfScalar(u8, record, '\t') orelse return error.InvalidIndex;
        var fields = std.mem.splitScalar(u8, record[0..tab], ' ');
        const mode = fields.next() orelse return error.InvalidIndex;
        const oid = fields.next() orelse return error.InvalidIndex;
        const stage = fields.next() orelse return error.InvalidIndex;
        const path = record[tab + 1 ..];
        const wanted = expected.get(path) orelse return error.InvalidIndex;
        if (fields.next() != null or !std.mem.eql(u8, stage, "0") or !std.mem.eql(u8, mode, wanted.mode) or
            !std.mem.eql(u8, oid, wanted.oid) or staged.contains(path)) return error.InvalidIndex;
        try staged.put(path, {});
    }
    if (staged.count() != expected.count()) return error.InvalidIndex;
    staged.clearRetainingCapacity();
    records = std.mem.splitScalar(u8, flags[0 .. flags.len - 1], 0);
    while (records.next()) |record| {
        if (record.len < 3 or !std.mem.startsWith(u8, record, "H ") or !expected.contains(record[2..]) or staged.contains(record[2..]))
            return error.ConcealedIndex;
        try staged.put(record[2..], {});
    }
    if (staged.count() != expected.count()) return error.InvalidIndex;
}

const Node = struct {
    name: []const u8,
    mode: []const u8,
    oid: ?[]const u8 = null,
    children: std.ArrayList(*Node) = .empty,
};

pub fn treeObject(allocator: std.mem.Allocator, entries: []const Entry, width: usize) ![]const u8 {
    if ((width != 40 and width != 64) or entries.len == 0 or entries.len > 40000) return error.InvalidTree;
    var root: Node = .{ .name = "", .mode = "40000" };
    for (entries) |entry| {
        try c.relative(entry.path);
        try c.objectId(entry.oid);
        if (entry.oid.len != width or excluded(entry.path) or
            (!std.mem.eql(u8, entry.mode, "100644") and !std.mem.eql(u8, entry.mode, "100755") and
                !std.mem.eql(u8, entry.mode, "120000"))) return error.InvalidTree;
        var current = &root;
        var parts = std.mem.splitScalar(u8, entry.path, '/');
        var depth: usize = 0;
        while (parts.next()) |part| {
            depth += 1;
            if (depth > 64) return error.InvalidTree;
            const last = parts.peek() == null;
            var existing: ?*Node = null;
            for (current.children.items) |child| if (std.mem.eql(u8, child.name, part)) {
                existing = child;
            };
            if (existing) |child| {
                if (last or child.oid != null) return error.InvalidTree;
                current = child;
            } else {
                const child = try allocator.create(Node);
                child.* = .{ .name = part, .mode = if (last) entry.mode else "40000", .oid = if (last) entry.oid else null };
                try current.children.append(allocator, child);
                current = child;
            }
        }
    }
    return hashNode(allocator, &root, width, 0);
}

fn hashNode(allocator: std.mem.Allocator, node: *Node, width: usize, depth: usize) ![]const u8 {
    if (depth > 64) return error.InvalidTree;
    if (node.oid) |oid| return oid;
    std.mem.sort(*Node, node.children.items, {}, struct {
        fn less(_: void, left: *Node, right: *Node) bool {
            const count = @min(left.name.len, right.name.len);
            const order = std.mem.order(u8, left.name[0..count], right.name[0..count]);
            if (order != .eq) return order == .lt;
            const l: u8 = if (left.name.len > count) left.name[count] else if (left.oid == null) '/' else 0;
            const r: u8 = if (right.name.len > count) right.name[count] else if (right.oid == null) '/' else 0;
            return l < r;
        }
    }.less);
    var data = std.Io.Writer.Allocating.init(allocator);
    for (node.children.items) |child| {
        const oid = try hashNode(allocator, child, width, depth + 1);
        var binary: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(binary[0 .. width / 2], oid);
        try data.writer.print("{s} {s}\x00", .{ child.mode, child.name });
        try data.writer.writeAll(binary[0 .. width / 2]);
    }
    var hash = try Hash.init(width, "tree", data.written().len);
    hash.update(data.written());
    return hash.finish(allocator);
}

pub fn physical(allocator: std.mem.Allocator, io: std.Io, directory: fs.Directory, entries: []Entry) !c.Tree {
    if (entries.len == 0 or entries.len > 40000) return error.InvalidTree;
    _ = try treeObject(allocator, entries, entries[0].oid.len);
    std.mem.sort(Entry, entries, {}, entryLess);
    const before_directory = try dirMetadata(directory.dir);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var total: u64 = 0;
    for (entries) |*entry| {
        var object: Hash = undefined;
        if (std.mem.eql(u8, entry.mode, "120000")) {
            const parent = try directory.parent(io, entry.path);
            defer parent.close(io);
            const base = std.fs.path.basename(entry.path);
            const link = try parent.openFile(io, base, .{ .path_only = true, .follow_symlinks = false });
            defer link.close(io);
            const before = try fs.metadata(link);
            if (before.mode & std.os.linux.S.IFMT != std.os.linux.S.IFLNK or before.size == 0 or before.size >= 4096 or
                (before.uid != 0 and before.uid != std.os.linux.geteuid())) return error.SourceChanged;
            var buffer: [4096]u8 = undefined;
            // Linux readlinkat with an empty name reads the pinned O_PATH link.
            const link_handle: std.Io.Dir = .{ .handle = link.handle };
            const target = buffer[0..try link_handle.readLink(io, "", &buffer)];
            if (target.len != before.size or !std.meta.eql(before, try fs.metadata(link))) return error.SourceChanged;
            const final_parent = try directory.parent(io, entry.path);
            defer final_parent.close(io);
            const named = try final_parent.openFile(io, base, .{ .path_only = true, .follow_symlinks = false });
            defer named.close(io);
            if (!std.meta.eql(before, try fs.metadata(named))) return error.SourceChanged;
            entry.target = try allocator.dupe(u8, target);
            entry.size = target.len;
            entry.sha256 = c.digest(target);
            object = try Hash.init(entry.oid.len, "blob", target.len);
            object.update(target);
        } else {
            entry.target = null;
            const file = try directory.openFile(io, entry.path, .source);
            defer file.close(io);
            const before = try fs.metadata(file);
            if ((before.mode & 0o7777 != (if (std.mem.eql(u8, entry.mode, "100755")) @as(u16, 0o755) else @as(u16, 0o644))) or
                before.size > 256 * 1024 * 1024)
                return error.SourceChanged;
            object = try Hash.init(entry.oid.len, "blob", before.size);
            var content = std.crypto.hash.sha2.Sha256.init(.{});
            var buffer: [64 * 1024]u8 = undefined;
            var offset: u64 = 0;
            while (offset < before.size) {
                const count = try file.readPositionalAll(io, buffer[0..@min(buffer.len, before.size - offset)], offset);
                if (count == 0) return error.SourceChanged;
                object.update(buffer[0..count]);
                content.update(buffer[0..count]);
                offset += count;
            }
            if (try file.readPositionalAll(io, buffer[0..1], offset) != 0 or !std.meta.eql(before, try fs.metadata(file)))
                return error.SourceChanged;
            const final = try directory.openFile(io, entry.path, .source);
            defer final.close(io);
            if (!std.meta.eql(before, try fs.metadata(final))) return error.SourceChanged;
            entry.size = before.size;
            entry.sha256 = std.fmt.bytesToHex(content.finalResult(), .lower);
        }
        if (!std.mem.eql(u8, try object.finish(allocator), entry.oid)) return error.SourceChanged;
        total = try std.math.add(u64, total, entry.size);
        if (total > 2 * 1024 * 1024 * 1024) return error.LimitExceeded;
        var lengths: [12]u8 = undefined;
        std.mem.writeInt(u32, lengths[0..4], @intCast(entry.path.len), .big);
        std.mem.writeInt(u64, lengths[4..12], entry.size, .big);
        hash.update(&lengths);
        hash.update(entry.path);
        hash.update(entry.mode);
        hash.update(&entry.sha256);
        hash.update(entry.oid);
    }
    for (entries) |entry| if (entry.target != null) try resolveLink(allocator, entries, entry.path);
    try checkUntracked(allocator, io, directory, directory.dir, entries, "", 0);
    const named_directory = try fs.Directory.open(allocator, io, directory.path);
    defer named_directory.close(allocator, io);
    if (!std.meta.eql(before_directory, try dirMetadata(directory.dir)) or
        !std.meta.eql(before_directory, try dirMetadata(named_directory.dir))) return error.SourceChanged;
    return .{ .sha256 = std.fmt.bytesToHex(hash.finalResult(), .lower), .files = @intCast(entries.len), .bytes = total };
}

fn excluded(path: []const u8) bool {
    return std.mem.eql(u8, path, ".git") or std.mem.startsWith(u8, path, ".git/") or
        std.mem.eql(u8, path, ".d") or std.mem.startsWith(u8, path, ".d/");
}

fn checkUntracked(allocator: std.mem.Allocator, io: std.Io, root: fs.Directory, dir: std.Io.Dir, entries: []const Entry, prefix: []const u8, depth: usize) !void {
    if (depth > 64) return error.LimitExceeded;
    var iterator = dir.iterate();
    while (try iterator.next(io)) |item| {
        const path = if (prefix.len == 0) item.name else try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, item.name });
        if (excluded(path)) continue;
        try c.relative(path);
        const named = try dir.openFile(io, item.name, .{ .path_only = true, .follow_symlinks = false });
        defer named.close(io);
        const before = try fs.metadata(named);
        const is_directory = before.mode & std.os.linux.S.IFMT == std.os.linux.S.IFDIR;
        const wanted = if (is_directory) try std.fmt.allocPrint(allocator, "{s}/", .{path}) else path;
        const position = entryPosition(entries, wanted);
        const found = position < entries.len and
            (if (is_directory) std.mem.startsWith(u8, entries[position].path, wanted) else std.mem.eql(u8, entries[position].path, path));
        if (!found) return error.UnreviewedInput;
        if (is_directory) {
            const child = try dir.openDir(io, item.name, .{ .follow_symlinks = false, .iterate = true });
            defer child.close(io);
            if (!std.meta.eql(before, try dirMetadata(child))) return error.SourceChanged;
            try checkUntracked(allocator, io, root, child, entries, path, depth + 1);
        }
        const again = try root.parent(io, path);
        defer again.close(io);
        const final = try again.openFile(io, item.name, .{ .path_only = true, .follow_symlinks = false });
        defer final.close(io);
        if (!std.meta.eql(before, try fs.metadata(final))) return error.SourceChanged;
    }
}

fn dirMetadata(dir: std.Io.Dir) !fs.Metadata {
    return fs.metadata(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } });
}

fn resolveLink(allocator: std.mem.Allocator, entries: []const Entry, path: []const u8) !void {
    var pending = try allocator.dupe(u8, path);
    defer allocator.free(pending);
    var resolved: std.ArrayList(u8) = .empty;
    defer resolved.deinit(allocator);
    var offset: usize = 0;
    var more = true;
    var links: usize = 0;
    while (more) {
        const separator = std.mem.indexOfScalarPos(u8, pending, offset, '/');
        const part = pending[offset .. separator orelse pending.len];
        more = separator != null;
        offset = if (separator) |position| position + 1 else pending.len;
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) {
            if (resolved.items.len == 0) return error.UnsafePath;
            resolved.shrinkRetainingCapacity(std.mem.lastIndexOfScalar(u8, resolved.items, '/') orelse 0);
            continue;
        }
        try c.core.private_files.basename(part);
        const parent_length = resolved.items.len;
        if (parent_length != 0) try resolved.append(allocator, '/');
        try resolved.appendSlice(allocator, part);
        if (resolved.items.len > 4096 or excluded(resolved.items)) return error.UnsafePath;
        const index = entryPosition(entries, resolved.items);
        if (index < entries.len and std.mem.eql(u8, entries[index].path, resolved.items)) {
            if (entries[index].target) |target| {
                links += 1;
                if (links > 32 or target.len == 0 or target.len > 4096 or std.fs.path.isAbsolute(target))
                    return error.UnsafePath;
                // Expand a link before interpreting later "." or "..", exactly
                // as filesystem traversal does. Never lexically cancel a link.
                const next = if (more)
                    try std.fmt.allocPrint(allocator, "{s}/{s}", .{ target, pending[offset..] })
                else
                    try allocator.dupe(u8, target);
                allocator.free(pending);
                pending = next;
                if (pending.len > 4096) return error.UnsafePath;
                resolved.shrinkRetainingCapacity(parent_length);
                offset = 0;
                more = true;
                continue;
            }
            if (more) return error.UnreviewedInput;
            return;
        }
        const prefix = try std.fmt.allocPrint(allocator, "{s}/", .{resolved.items});
        defer allocator.free(prefix);
        const child = entryPosition(entries, prefix);
        if (child == entries.len or !std.mem.startsWith(u8, entries[child].path, prefix)) return error.UnreviewedInput;
    }
    if (resolved.items.len == 0) return error.UnsafePath;
}

fn outputLine(raw: []const u8) ![]const u8 {
    if (raw.len < 2 or raw[raw.len - 1] != '\n' or std.mem.indexOfScalar(u8, raw[0 .. raw.len - 1], '\n') != null)
        return error.InvalidGitOutput;
    return raw[0 .. raw.len - 1];
}

const Stamp = struct {
    directory: fs.Directory,
    name: []const u8,
    metadata: ?fs.Metadata,
    sha256: ?c.Sha,
};

const Metadata = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    git: fs.Directory,
    common: fs.Directory,
    stamps: std.ArrayList(Stamp) = .empty,
    index: []const u8,
    format: enum { sha1, sha256 } = .sha1,

    fn open(allocator: std.mem.Allocator, io: std.Io, repository: fs.Directory) !Metadata {
        const dotgit = try repository.dir.openFile(io, ".git", .{ .path_only = true, .follow_symlinks = false });
        defer dotgit.close(io);
        const kind = (try fs.metadata(dotgit)).mode & std.os.linux.S.IFMT;
        var pointer: ?[]const u8 = null;
        const git_path = if (kind == std.os.linux.S.IFDIR)
            try std.fs.path.join(allocator, &.{ repository.path, ".git" })
        else if (kind == std.os.linux.S.IFREG) blk: {
            pointer = try repository.read(allocator, io, ".git", 4096, .source);
            const line = try outputLine(pointer.?);
            if (!std.mem.startsWith(u8, line, "gitdir: ")) return error.InvalidGitMetadata;
            break :blk try std.fs.path.resolve(allocator, &.{ repository.path, line[8..] });
        } else return error.InvalidGitMetadata;
        try metadataPath(repository.path, git_path);
        const git_dir = try fs.Directory.open(allocator, io, git_path);
        errdefer git_dir.close(allocator, io);
        var result: Metadata = .{ .allocator = allocator, .io = io, .git = git_dir, .common = undefined, .index = undefined };
        if (pointer) |bytes| {
            const again = (try result.capture(repository, ".git", 4096)) orelse return error.SourceChanged;
            if (!std.mem.eql(u8, bytes, again)) return error.SourceChanged;
        }
        const common_pointer = try result.capture(git_dir, "commondir", 4096);
        const common_path = if (common_pointer) |bytes|
            try std.fs.path.resolve(allocator, &.{ git_dir.path, try outputLine(bytes) })
        else
            git_dir.path;
        try metadataPath(repository.path, common_path);
        result.common = try fs.Directory.open(allocator, io, common_path);
        errdefer result.common.close(allocator, io);
        if (try result.capture(result.common, "config", 64 * 1024)) |config| result.format = try safeConfig(config);
        if (try result.capture(git_dir, "config.worktree", 64 * 1024)) |config| {
            if (try safeConfig(config) != .sha1) return error.InvalidGitMetadata;
        }
        const head = try outputLine((try result.capture(git_dir, "HEAD", 4096)) orelse return error.InvalidGitMetadata);
        if (std.mem.startsWith(u8, head, "ref: refs/")) {
            try c.relative(head[5..]);
        } else try c.objectId(head);
        _ = try result.capture(result.common, "packed-refs", 4 * 1024 * 1024);
        result.index = (try result.capture(git_dir, "index", 16 * 1024 * 1024)) orelse return error.InvalidIndex;
        try result.noAlternateHistory();
        return result;
    }

    fn close(self: Metadata) void {
        self.git.close(self.allocator, self.io);
        self.common.close(self.allocator, self.io);
    }

    fn capture(self: *Metadata, directory: fs.Directory, name: []const u8, maximum: usize) !?[]const u8 {
        const file = directory.openFile(self.io, name, .source) catch |err| {
            if (err != error.FileNotFound) return err;
            try self.stamps.append(self.allocator, .{ .directory = directory, .name = name, .metadata = null, .sha256 = null });
            return null;
        };
        defer file.close(self.io);
        const before = try fs.metadata(file);
        if (before.size > maximum) return error.FileTooLarge;
        const bytes = try self.allocator.alloc(u8, @as(usize, @intCast(before.size)) + 1);
        if (try file.readPositionalAll(self.io, bytes, 0) != before.size or !std.meta.eql(before, try fs.metadata(file)))
            return error.SourceChanged;
        const named = try directory.openFile(self.io, name, .source);
        defer named.close(self.io);
        if (!std.meta.eql(before, try fs.metadata(named))) return error.SourceChanged;
        const exact = bytes[0..@intCast(before.size)];
        try self.stamps.append(self.allocator, .{ .directory = directory, .name = name, .metadata = before, .sha256 = c.digest(exact) });
        return exact;
    }

    fn noAlternateHistory(self: Metadata) !void {
        for ([_]fs.Directory{ self.git, self.common }) |directory| {
            for ([_][]const u8{ "info/grafts", "objects/info/alternates", "objects/info/http-alternates", "shallow" }) |name| {
                const parent = directory.parent(self.io, name) catch |err| {
                    if (err == error.FileNotFound) continue;
                    return err;
                };
                defer parent.close(self.io);
                const file = parent.openFile(self.io, std.fs.path.basename(name), .{ .path_only = true, .follow_symlinks = false }) catch |err| {
                    if (err == error.FileNotFound) continue;
                    return err;
                };
                file.close(self.io);
                return error.AlternateHistoryForbidden;
            }
        }
        var count: usize = 0;
        try self.noMetadataLinks(self.common, "objects", 0, &count);
        try self.noMetadataLinks(self.common, "refs", 0, &count);
    }

    fn noMetadataLinks(self: Metadata, directory: fs.Directory, path: []const u8, depth: usize, count: *usize) anyerror!void {
        if (depth > 64) return error.LimitExceeded;
        const parent = try directory.parent(self.io, path);
        defer parent.close(self.io);
        const child = parent.openDir(self.io, std.fs.path.basename(path), .{ .follow_symlinks = false, .iterate = true }) catch |err| {
            if (err == error.FileNotFound and std.mem.eql(u8, path, "refs")) return;
            return err;
        };
        defer child.close(self.io);
        const before = try dirMetadata(child);
        if (before.mode & 0o022 != 0 or (before.uid != 0 and before.uid != std.os.linux.geteuid())) return error.UnsafeFile;
        var iterator = child.iterate();
        while (try iterator.next(self.io)) |item| {
            count.* += 1;
            if (count.* > 200000) return error.LimitExceeded;
            if (std.mem.eql(u8, item.name, ".d")) return error.UnsafePath;
            if (std.mem.endsWith(u8, item.name, ".promisor")) return error.AlternateHistoryForbidden;
            const relative = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ path, item.name });
            defer self.allocator.free(relative);
            try c.relative(relative);
            const named = try child.openFile(self.io, item.name, .{ .path_only = true, .follow_symlinks = false });
            defer named.close(self.io);
            const value = try fs.metadata(named);
            switch (value.mode & std.os.linux.S.IFMT) {
                std.os.linux.S.IFREG => {
                    const file = try directory.openFile(self.io, relative, .source);
                    defer file.close(self.io);
                    if (!std.meta.eql(value, try fs.metadata(file))) return error.SourceChanged;
                },
                std.os.linux.S.IFDIR => try self.noMetadataLinks(directory, relative, depth + 1, count),
                else => return error.InvalidGitMetadata,
            }
        }
        const final_parent = try directory.parent(self.io, path);
        defer final_parent.close(self.io);
        const final = try final_parent.openDir(self.io, std.fs.path.basename(path), .{ .follow_symlinks = false });
        defer final.close(self.io);
        if (!std.meta.eql(before, try dirMetadata(child)) or !std.meta.eql(before, try dirMetadata(final))) return error.SourceChanged;
    }

    fn recheck(self: Metadata) !void {
        try self.noAlternateHistory();
        for (self.stamps.items) |stamp| {
            const file = stamp.directory.openFile(self.io, stamp.name, .source) catch |err| {
                if (err == error.FileNotFound and stamp.metadata == null) continue;
                return error.SourceChanged;
            };
            defer file.close(self.io);
            const before = try fs.metadata(file);
            if (stamp.metadata == null or !std.meta.eql(stamp.metadata.?, before) or
                !std.meta.eql(stamp.sha256.?, try fs.hashFile(self.io, file, before.size)) or
                !std.meta.eql(before, try fs.metadata(file))) return error.SourceChanged;
            const named = try stamp.directory.openFile(self.io, stamp.name, .source);
            defer named.close(self.io);
            if (!std.meta.eql(before, try fs.metadata(named))) return error.SourceChanged;
        }
        for ([_]fs.Directory{ self.git, self.common }) |directory| {
            const named = try fs.Directory.open(self.allocator, self.io, directory.path);
            defer named.close(self.allocator, self.io);
            if (!std.meta.eql(try dirMetadata(directory.dir), try dirMetadata(named.dir))) return error.SourceChanged;
        }
    }

    fn command(self: Metadata, git: *rt.Git, repository: fs.Directory, operation: rt.GitCommand) ![]u8 {
        try self.recheck();
        const bytes = try git.command(repository, operation);
        try self.recheck();
        return bytes;
    }
};

fn metadataPath(repository: []const u8, path: []const u8) !void {
    if (!std.fs.path.isAbsolute(path)) return error.InvalidGitMetadata;
    var root = std.mem.splitScalar(u8, repository, '/');
    var parts = std.mem.splitScalar(u8, path, '/');
    var shared = true;
    while (parts.next()) |part| {
        const corresponding = root.next();
        shared = shared and corresponding != null and std.mem.eql(u8, corresponding.?, part);
        if (!shared and std.mem.eql(u8, part, ".d")) return error.UnsafePath;
    }
}

// This grammar deliberately cannot interpret includes, quoted escapes, line
// continuations, command-valued config, or an unknown repository extension.
fn safeConfig(bytes: []const u8) !@FieldType(Metadata, "format") {
    if (bytes.len > 64 * 1024 or std.mem.indexOfAny(u8, bytes, "\x00\\\r") != null) return error.UnsafeGitConfig;
    var section: []const u8 = "";
    var format: @FieldType(Metadata, "format") = .sha1;
    var object_format_seen = false;
    var version: ?u8 = null;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;
        if (line[0] == '[') {
            if (!std.mem.endsWith(u8, line, "]")) return error.UnsafeGitConfig;
            section = line[1 .. line.len - 1];
            if (std.mem.indexOfScalar(u8, section, ' ')) |space| {
                const subsection = section[space + 1 ..];
                if (subsection.len < 3 or subsection[0] != '"' or subsection[subsection.len - 1] != '"' or
                    std.mem.indexOfScalar(u8, subsection[1 .. subsection.len - 1], '"') != null) return error.UnsafeGitConfig;
                section = section[0..space];
                if (!std.ascii.eqlIgnoreCase(section, "remote") and !std.ascii.eqlIgnoreCase(section, "branch"))
                    return error.UnsafeGitConfig;
            }
            continue;
        }
        const equals = std.mem.indexOfScalar(u8, line, '=') orelse return error.UnsafeGitConfig;
        const key = std.mem.trim(u8, line[0..equals], " \t");
        const value = std.mem.trim(u8, line[equals + 1 ..], " \t");
        if (std.mem.indexOfAny(u8, value, "\"#;") != null) return error.UnsafeGitConfig;
        if (std.ascii.eqlIgnoreCase(section, "core")) {
            if (std.ascii.eqlIgnoreCase(key, "repositoryformatversion")) {
                if (version != null or (!std.mem.eql(u8, value, "0") and !std.mem.eql(u8, value, "1"))) return error.UnsafeGitConfig;
                version = value[0] - '0';
            } else if (std.ascii.eqlIgnoreCase(key, "bare") or std.ascii.eqlIgnoreCase(key, "fsmonitor") or
                std.ascii.eqlIgnoreCase(key, "sparseCheckout") or std.ascii.eqlIgnoreCase(key, "untrackedCache") or
                std.ascii.eqlIgnoreCase(key, "splitIndex"))
            {
                if (!std.ascii.eqlIgnoreCase(value, "false")) return error.UnsafeGitConfig;
            } else if (std.ascii.eqlIgnoreCase(key, "filemode") or std.ascii.eqlIgnoreCase(key, "logallrefupdates") or
                std.ascii.eqlIgnoreCase(key, "symlinks") or std.ascii.eqlIgnoreCase(key, "ignorecase") or
                std.ascii.eqlIgnoreCase(key, "precomposeunicode") or std.ascii.eqlIgnoreCase(key, "autocrlf"))
            {
                if (!std.ascii.eqlIgnoreCase(value, "false") and !std.ascii.eqlIgnoreCase(value, "true")) return error.UnsafeGitConfig;
            } else return error.UnsafeGitConfig;
        } else if (std.ascii.eqlIgnoreCase(section, "extensions")) {
            if (std.ascii.eqlIgnoreCase(key, "objectformat")) {
                if (object_format_seen) return error.UnsafeGitConfig;
                object_format_seen = true;
                format = if (std.mem.eql(u8, value, "sha256")) .sha256 else if (std.mem.eql(u8, value, "sha1")) .sha1 else return error.UnsafeGitConfig;
            } else if (std.ascii.eqlIgnoreCase(key, "worktreeConfig")) {
                if (!std.ascii.eqlIgnoreCase(value, "true")) return error.UnsafeGitConfig;
            } else return error.UnsafeGitConfig;
        } else if (std.ascii.eqlIgnoreCase(section, "index")) {
            if (!std.ascii.eqlIgnoreCase(key, "version") or
                (!std.mem.eql(u8, value, "2") and !std.mem.eql(u8, value, "3") and !std.mem.eql(u8, value, "4"))) return error.UnsafeGitConfig;
        } else if (std.ascii.eqlIgnoreCase(section, "remote")) {
            if (!std.ascii.eqlIgnoreCase(key, "url") and !std.ascii.eqlIgnoreCase(key, "fetch") and
                !std.ascii.eqlIgnoreCase(key, "pushurl")) return error.UnsafeGitConfig;
        } else if (std.ascii.eqlIgnoreCase(section, "branch")) {
            if (!std.ascii.eqlIgnoreCase(key, "remote") and !std.ascii.eqlIgnoreCase(key, "merge")) return error.UnsafeGitConfig;
        } else if (std.ascii.eqlIgnoreCase(section, "user")) {
            if (!std.ascii.eqlIgnoreCase(key, "name") and !std.ascii.eqlIgnoreCase(key, "email")) return error.UnsafeGitConfig;
        } else return error.UnsafeGitConfig;
    }
    if (object_format_seen and version != 1) return error.UnsafeGitConfig;
    return format;
}

fn physicalIndex(allocator: std.mem.Allocator, bytes: []const u8, entries: []const Entry, width: usize) !void {
    if (width != 40 and width != 64) return error.InvalidIndex;
    const digest_len = width / 2;
    if (bytes.len < 12 + digest_len or bytes.len > 16 * 1024 * 1024 or !std.mem.eql(u8, bytes[0..4], "DIRC")) return error.InvalidIndex;
    const version = std.mem.readInt(u32, bytes[4..8], .big);
    if (version < 2 or version > 4 or std.mem.readInt(u32, bytes[8..12], .big) != entries.len) return error.InvalidIndex;
    const end = bytes.len - digest_len;
    if (width == 40) {
        var digest: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(bytes[0..end], &digest, .{});
        if (!std.mem.eql(u8, &digest, bytes[end..])) return error.InvalidIndex;
    } else {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes[0..end], &digest, .{});
        if (!std.mem.eql(u8, &digest, bytes[end..])) return error.InvalidIndex;
    }
    var position: usize = 12;
    var previous: []const u8 = "";
    for (entries) |expected| {
        const start = position;
        const fixed = 42 + digest_len;
        if (position > end or fixed > end - position) return error.InvalidIndex;
        const entry = bytes[position..][0..fixed];
        const flags = std.mem.readInt(u16, entry[40 + digest_len ..][0..2], .big);
        if (flags & 0xf000 != 0) return error.ConcealedIndex;
        const mode = std.mem.readInt(u32, entry[24..28], .big);
        if (mode != try std.fmt.parseInt(u32, expected.mode, 8)) return error.InvalidIndex;
        var binary: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(binary[0..digest_len], expected.oid);
        if (!std.mem.eql(u8, binary[0..digest_len], entry[40..][0..digest_len])) return error.InvalidIndex;
        position += fixed;
        var strip: usize = 0;
        if (version == 4) {
            var count: usize = 0;
            while (true) {
                if (position >= end or count >= 5) return error.InvalidIndex;
                const ch = bytes[position];
                position += 1;
                count += 1;
                strip = std.math.add(usize, std.math.mul(usize, strip, 128) catch return error.InvalidIndex, ch & 0x7f) catch return error.InvalidIndex;
                if (ch & 0x80 == 0) break;
                strip = std.math.add(usize, strip, 1) catch return error.InvalidIndex;
            }
            if (strip > previous.len) return error.InvalidIndex;
        }
        const nul = std.mem.indexOfScalar(u8, bytes[position..end], 0) orelse return error.InvalidIndex;
        const suffix = bytes[position..][0..nul];
        const name = if (version == 4) try std.mem.concat(allocator, u8, &.{ previous[0 .. previous.len - strip], suffix }) else suffix;
        if (!std.mem.eql(u8, name, expected.path) or flags & 0x0fff != @min(name.len, 0x0fff)) return error.InvalidIndex;
        position += nul + 1;
        if (version != 4) {
            const padding = (8 - (position - start) % 8) % 8;
            if (padding > end - position) return error.InvalidIndex;
            for (bytes[position..][0..padding]) |ch| if (ch != 0) return error.InvalidIndex;
            position += padding;
        }
        previous = name;
    }
    while (position < end) {
        if (end - position < 8) return error.InvalidIndex;
        const signature = bytes[position..][0..4];
        if (!std.mem.eql(u8, signature, "TREE") and !std.mem.eql(u8, signature, "REUC") and
            !std.mem.eql(u8, signature, "EOIE") and !std.mem.eql(u8, signature, "IEOT")) return error.ConcealedIndex;
        const size = std.mem.readInt(u32, bytes[position + 4 ..][0..4], .big);
        position += 8;
        if (size > end - position) return error.InvalidIndex;
        position += size;
    }
}

pub fn inspect(git: *rt.Git, repository: fs.Directory) !c.Source {
    const allocator = git.allocator;
    try git.validate();
    const metadata = try Metadata.open(allocator, git.io, repository);
    defer metadata.close();
    if (!std.mem.eql(u8, try outputLine(try metadata.command(git, repository, .root)), repository.path) or
        !std.mem.eql(u8, try outputLine(try metadata.command(git, repository, .common_directory)), metadata.common.path) or
        !std.mem.eql(u8, try outputLine(try metadata.command(git, repository, .git_directory)), metadata.git.path)) return error.UnreviewedInput;
    if ((try metadata.command(git, repository, .replacements)).len != 0) return error.ReplacementsForbidden;
    const head = try outputLine(try metadata.command(git, repository, .head));
    try c.objectId(head);
    const format = try outputLine(try metadata.command(git, repository, .format));
    if (!std.mem.eql(u8, format, if (head.len == 40) "sha1" else "sha256") or
        !std.mem.eql(u8, format, @tagName(metadata.format))) return error.InvalidObjectId;
    const commit = try metadata.command(git, repository, .{ .commit = head });
    var commit_hash = try Hash.init(head.len, "commit", commit.len);
    commit_hash.update(commit);
    if (!std.mem.eql(u8, try commit_hash.finish(allocator), head)) return error.SourceChanged;
    const line = commit[0..(std.mem.indexOfScalar(u8, commit, '\n') orelse return error.InvalidGitOutput)];
    if (!std.mem.startsWith(u8, line, "tree ")) return error.InvalidGitOutput;
    const tree = line[5..];
    try c.objectId(tree);
    if (tree.len != head.len) return error.InvalidObjectId;
    const raw = try metadata.command(git, repository, .{ .tree = tree });
    const entries = try parseTree(allocator, raw, head.len);
    if (!std.mem.eql(u8, try treeObject(allocator, entries, head.len), tree)) return error.SourceChanged;
    try physicalIndex(allocator, metadata.index, entries, head.len);
    try verifyIndex(allocator, entries, try metadata.command(git, repository, .index), try metadata.command(git, repository, .flags));
    const physical_tree = try physical(allocator, git.io, repository, entries);
    try verifyIndex(allocator, entries, try metadata.command(git, repository, .index), try metadata.command(git, repository, .flags));
    if (!std.mem.eql(u8, head, try outputLine(try metadata.command(git, repository, .head))) or
        (try metadata.command(git, repository, .replacements)).len != 0) return error.SourceChanged;
    try fs.requireTree(try physical(allocator, git.io, repository, entries), physical_tree);
    try metadata.recheck();
    try git.validate();
    return .{
        .scheme = .git_physical_native_v1,
        .head = head,
        .tree = tree,
        .tree_sha256 = c.digest(raw),
        .physical = physical_tree,
    };
}

pub fn require(actual: c.Source, expected: c.Source) !void {
    if (actual.scheme != expected.scheme or !std.mem.eql(u8, actual.head, expected.head) or
        !std.mem.eql(u8, actual.tree, expected.tree) or !std.meta.eql(actual.tree_sha256, expected.tree_sha256) or
        !std.meta.eql(actual.physical, expected.physical)) return error.UnreviewedInput;
}

fn initializeTree(fixture: *rt.TestFixture, format: []const u8) !void {
    const allocator = fixture.git.allocator;
    _ = try fixture.setup(&.{
        "init",                                                                                   "--quiet",                                                           "--initial-branch=synthetic",
        try std.fmt.allocPrint(allocator, "--template={s}/empty-template", .{fixture.root.path}), try std.fmt.allocPrint(allocator, "--object-format={s}", .{format}),
    });
    try fixture.repository.dir.createDir(fixture.git.io, ".git/info", .fromMode(0o755));
    try fixture.repository.dir.createDir(fixture.git.io, "dir", .fromMode(0o755));
    try fixture.write(".gitignore", "ignored.c\n", 0o644);
    try fixture.write("alpha", "synthetic public source\n", 0o644);
    try fixture.write("dir/file", "nested synthetic public source\n", 0o644);
    try fixture.write("dir.c", "tree sort boundary\n", 0o644);
    try fixture.write("executable", "synthetic executable bytes, never executed\n", 0o755);
    try fixture.repository.dir.symLink(fixture.git.io, "dir/file", "link", .{});
    _ = try fixture.setup(&.{ "add", "--all", "--", "." });
    _ = try fixture.setup(&.{ "commit", "--quiet", "-m", "Synthetic provenance fixture" });
}

test "source tree parser rejects ambiguous modes paths gitlinks and object widths" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const oid = "0123456789012345678901234567890123456789";
    const valid = "100644 blob " ++ oid ++ "\talpha\x00";
    const entries = try parseTree(allocator, valid, 40);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    for ([_][]const u8{
        "100644 blob " ++ oid ++ "\talpha",
        "100644 blob " ++ oid ++ "\talpha\x00\x00",
        "160000 commit " ++ oid ++ "\tsubmodule\x00",
        "100664 blob " ++ oid ++ "\talpha\x00",
        "100644 blob " ++ oid ++ "\t../escape\x00",
        "100644 blob " ++ oid ++ "\t.d/evidence\x00",
        "100644 blob " ++ oid ++ "\t.git/config\x00",
        valid ++ valid,
    }) |raw| try std.testing.expectError(if (std.mem.indexOf(u8, raw, "../") != null) error.UnsafePath else error.InvalidTree, parseTree(allocator, raw, 40));
    try std.testing.expectError(error.InvalidTree, parseTree(allocator, valid, 64));
    try std.testing.expectError(error.InvalidObjectId, parseTree(allocator, valid, 41));
    try std.testing.expectError(error.InvalidTree, treeObject(allocator, &.{
        .{ .path = "a", .mode = "100644", .oid = oid },
        .{ .path = "a/b", .mode = "100644", .oid = oid },
    }, 40));
    try std.testing.expectError(error.InvalidTree, treeObject(allocator, &.{
        .{ .path = "a/b", .mode = "100644", .oid = oid },
        .{ .path = "a", .mode = "100644", .oid = oid },
    }, 40));
}

test "source rejects staged changes nonzero stages and all concealed index tags" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const oid = "0123456789012345678901234567890123456789";
    const entries = try parseTree(allocator, "100644 blob " ++ oid ++ "\talpha\x00", 40);
    const raw = "100644 " ++ oid ++ " 0\talpha\x00";
    try verifyIndex(allocator, entries, raw, "H alpha\x00");
    for ([_][]const u8{ "h alpha\x00", "S alpha\x00", "s alpha\x00", "M alpha\x00", "H alpha\x00H alpha\x00" }) |flags|
        try std.testing.expectError(error.ConcealedIndex, verifyIndex(allocator, entries, raw, flags));
    for ([_][]const u8{
        "100644 " ++ oid ++ " 1\talpha\x00",
        "100755 " ++ oid ++ " 0\talpha\x00",
        "100644 " ++ oid ++ " 0\textra\x00",
        raw ++ raw,
    }) |changed| try std.testing.expectError(error.InvalidIndex, verifyIndex(allocator, entries, changed, "H alpha\x00"));
}

test "source config preflight cannot interpret includes helpers alternate formats or injection" {
    try std.testing.expectEqual(.sha1, try safeConfig("[core]\nrepositoryformatversion = 0\nbare = false\nfilemode = true\n"));
    try std.testing.expectEqual(.sha256, try safeConfig("[core]\nrepositoryformatversion = 1\n[extensions]\nobjectformat = sha256\n"));
    for ([_][]const u8{
        "[include]\npath = /synthetic/not-read\n",
        "[includeIf \"gitdir:*\"]\npath = /synthetic/not-read\n",
        "[core]\nfsmonitor = /synthetic/not-executed\n",
        "[core]\nworktree = /synthetic/elsewhere\n",
        "[core]\nhooksPath = /synthetic/not-executed\n",
        "[filter \"unreviewed\"]\nclean = /synthetic/not-executed\n",
        "[extensions]\nobjectformat = sha512\n",
        "[extensions]\nobjectformat = sha256\n",
        "[extensions]\nrefStorage = reftable\n",
        "[core]\nrepositoryformatversion = 9\n",
        "[core]\nfilemode = true\\\n[include]\npath = elsewhere\n",
        "[core]\nfilemode = \"true\"\n",
        "[index]\nversion = 99\n",
        "[core]\nfilemode = true\x00\n",
    }) |config| try std.testing.expectError(error.UnsafeGitConfig, safeConfig(config));
}

test "source real relocated Git verifies physical SHA1 commit tree index and complete checkout" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = try rt.TestFixture.init(allocator, io);
    defer fixture.deinit();
    try initializeTree(&fixture, "sha1");
    const expected = try inspect(&fixture.git, fixture.repository);
    try std.testing.expectEqual(@as(usize, 40), expected.head.len);
    try std.testing.expectEqual(@as(u32, 6), expected.physical.files);
    try require(try inspect(&fixture.git, fixture.repository), expected);
    const json = try c.canonical(allocator, expected);
    const roundtrip = try c.parse(c.Source, allocator, json);
    defer roundtrip.deinit();
    try require(roundtrip.value, expected);
    var unreviewed = expected;
    unreviewed.physical.sha256 = c.digest("different independently reviewed source");
    try std.testing.expectError(error.UnreviewedInput, require(expected, unreviewed));

    try fixture.repository.dir.symLink(io, "../not-opened-evidence", ".d", .{ .is_directory = true });
    try require(try inspect(&fixture.git, fixture.repository), expected);
    try fixture.write("ignored.c", "ignored but unreviewed extra source\n", 0o644);
    try std.testing.expectError(error.UnreviewedInput, inspect(&fixture.git, fixture.repository));
    try fixture.repository.dir.deleteFile(io, "ignored.c");
    try fixture.write("extra.c", "untracked extra source\n", 0o644);
    try std.testing.expectError(error.UnreviewedInput, inspect(&fixture.git, fixture.repository));
    _ = try fixture.setup(&.{ "add", "--", "extra.c" });
    try std.testing.expectError(error.InvalidIndex, inspect(&fixture.git, fixture.repository));
    _ = try fixture.setup(&.{ "reset", "--quiet", "HEAD", "--", "extra.c" });
    try fixture.repository.dir.deleteFile(io, "extra.c");

    _ = try fixture.setup(&.{ "update-index", "--assume-unchanged", "alpha" });
    try std.testing.expectError(error.ConcealedIndex, inspect(&fixture.git, fixture.repository));
    _ = try fixture.setup(&.{ "update-index", "--no-assume-unchanged", "alpha" });
    _ = try fixture.setup(&.{ "update-index", "--skip-worktree", "alpha" });
    try std.testing.expectError(error.ConcealedIndex, inspect(&fixture.git, fixture.repository));
    _ = try fixture.setup(&.{ "update-index", "--no-skip-worktree", "alpha" });

    try fixture.write("alpha", "mutated but not staged\n", 0o644);
    try std.testing.expectError(error.SourceChanged, inspect(&fixture.git, fixture.repository));
    try fixture.write("alpha", "synthetic public source\n", 0o600);
    try std.testing.expectError(error.SourceChanged, inspect(&fixture.git, fixture.repository));
    try fixture.write("alpha", "synthetic public source\n", 0o644);
    try fixture.write("executable", "synthetic executable bytes, never executed\n", 0o644);
    try std.testing.expectError(error.SourceChanged, inspect(&fixture.git, fixture.repository));
    try fixture.write("executable", "synthetic executable bytes, never executed\n", 0o755);
    try fixture.repository.dir.deleteFile(io, "link");
    try fixture.repository.dir.symLink(io, "dir/./file", "link", .{});
    try std.testing.expectError(error.SourceChanged, inspect(&fixture.git, fixture.repository));
    try fixture.repository.dir.deleteFile(io, "link");
    try fixture.repository.dir.symLink(io, "dir/file", "link", .{});

    const replacement = try std.fmt.allocPrint(allocator, "refs/replace/{s}", .{expected.head});
    _ = try fixture.setup(&.{ "update-ref", replacement, expected.head });
    try std.testing.expectError(error.ReplacementsForbidden, inspect(&fixture.git, fixture.repository));
    _ = try fixture.setup(&.{ "update-ref", "-d", replacement });
    for ([_][]const u8{ ".git/info/grafts", ".git/objects/info/alternates", ".git/objects/info/http-alternates", ".git/shallow" }) |name| {
        try fixture.write(name, "", 0o644);
        try std.testing.expectError(error.AlternateHistoryForbidden, inspect(&fixture.git, fixture.repository));
        try fixture.repository.dir.deleteFile(io, name);
    }
    const original_config = try fixture.repository.read(allocator, io, ".git/config", 65536, .source);
    _ = try fixture.setup(&.{ "config", "--local", "include.path", "/synthetic/not-read" });
    try std.testing.expectError(error.UnsafeGitConfig, inspect(&fixture.git, fixture.repository));
    try fixture.write(".git/config", original_config, 0o644);
    try require(try inspect(&fixture.git, fixture.repository), expected);
    const original_head = try fixture.repository.read(allocator, io, ".git/HEAD", 4096, .source);
    const entries = try parseTree(allocator, try fixture.git.command(fixture.repository, .{ .tree = expected.tree }), 40);
    try fixture.write(".git/HEAD", try std.fmt.allocPrint(allocator, "{s}\n", .{entries[0].oid}), 0o644);
    try std.testing.expectError(error.CommandFailed, inspect(&fixture.git, fixture.repository));
    try fixture.write(".git/HEAD", original_head, 0o644);
    fixture.git.failures = .{};
    _ = try fixture.setup(&.{ "commit", "--quiet", "--allow-empty", "-m", "Unreviewed synthetic HEAD" });
    const changed_head = try inspect(&fixture.git, fixture.repository);
    try std.testing.expectEqualStrings(expected.tree, changed_head.tree);
    try std.testing.expectError(error.UnreviewedInput, require(changed_head, expected));
}

test "source real SHA256 and version four index preserve native object identity" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = try rt.TestFixture.init(allocator, io);
    defer fixture.deinit();
    try initializeTree(&fixture, "sha256");
    const expected = try inspect(&fixture.git, fixture.repository);
    try std.testing.expectEqual(@as(usize, 64), expected.head.len);
    _ = try fixture.setup(&.{ "update-index", "--index-version", "4" });
    try require(try inspect(&fixture.git, fixture.repository), expected);
    const metadata = try Metadata.open(allocator, io, fixture.repository);
    defer metadata.close();
    const raw = try fixture.git.command(fixture.repository, .{ .tree = expected.tree });
    const entries = try parseTree(allocator, raw, 64);
    const corrupted = try allocator.dupe(u8, metadata.index);
    corrupted[corrupted.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidIndex, physicalIndex(allocator, corrupted, entries, 64));
    const index_end = metadata.index.len - 32;
    for ([_]u16{ 0x8000, 0x4000, 0x1000 }) |forbidden| {
        const changed = try allocator.dupe(u8, metadata.index);
        const flags = std.mem.readInt(u16, changed[84..86], .big);
        std.mem.writeInt(u16, changed[84..86], flags | forbidden, .big);
        std.crypto.hash.sha2.Sha256.hash(changed[0..index_end], changed[index_end..][0..32], .{});
        try std.testing.expectError(error.ConcealedIndex, physicalIndex(allocator, changed, entries, 64));
    }
    for ([_][]const u8{ "FSMN", "UNTR", "link", "sdir" }) |extension| {
        const changed = try allocator.alloc(u8, metadata.index.len + 8);
        @memcpy(changed[0..index_end], metadata.index[0..index_end]);
        @memcpy(changed[index_end..][0..4], extension);
        @memset(changed[index_end + 4 ..][0..4], 0);
        std.crypto.hash.sha2.Sha256.hash(changed[0 .. index_end + 8], changed[index_end + 8 ..][0..32], .{});
        try std.testing.expectError(error.ConcealedIndex, physicalIndex(allocator, changed, entries, 64));
    }
    try fixture.write(".git/info/grafts", "", 0o644);
    try std.testing.expectError(error.AlternateHistoryForbidden, metadata.recheck());
    try fixture.repository.dir.deleteFile(io, ".git/info/grafts");
    try fixture.write(".git/config", "[include]\npath = /synthetic/not-read\n", 0o644);
    try std.testing.expectError(error.SourceChanged, metadata.recheck());
}

test "source physical symlink closure rejects escapes cycles missing and evidence targets" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = try rt.TestFixture.init(allocator, io);
    defer fixture.deinit();
    try initializeTree(&fixture, "sha1");
    const original = try inspect(&fixture.git, fixture.repository);
    const entries = try parseTree(allocator, try fixture.git.command(fixture.repository, .{ .tree = original.tree }), 40);
    for ([_][]const u8{ "/absolute-not-opened", "../outside-not-opened", ".d/not-opened", "missing", "link" }) |target| {
        try fixture.repository.dir.deleteFile(io, "link");
        try fixture.repository.dir.symLink(io, target, "link", .{});
        for (entries) |*entry| if (std.mem.eql(u8, entry.path, "link")) {
            var hash = try Hash.init(40, "blob", target.len);
            hash.update(target);
            entry.oid = try hash.finish(allocator);
        };
        try std.testing.expectError(if (std.mem.eql(u8, target, "missing")) error.UnreviewedInput else error.UnsafePath, physical(allocator, io, fixture.repository, entries));
    }
}

test "source real Git follows nested symlinks before parent components and rejects lexical false closure" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = try rt.TestFixture.init(allocator, io);
    defer fixture.deinit();
    try initializeTree(&fixture, "sha1");
    try fixture.repository.dir.createDir(io, "inside", .fromMode(0o755));
    try fixture.write("inside/tracked", "synthetic directory marker\n", 0o644);
    try fixture.repository.dir.symLink(io, "../inside", "dir/ref", .{});
    try fixture.repository.dir.symLink(io, "dir/ref/../alpha", "chosen", .{});
    _ = try fixture.setup(&.{ "add", "--all", "--", "." });
    _ = try fixture.setup(&.{ "commit", "--quiet", "-m", "Synthetic nested symlinks" });
    const original = try inspect(&fixture.git, fixture.repository);
    const actual = try fixture.repository.dir.openFile(io, "chosen", .{});
    defer actual.close(io);
    const expected = try fixture.repository.openFile(io, "alpha", .source);
    defer expected.close(io);
    try std.testing.expectEqual(try fs.metadata(expected), try fs.metadata(actual));
    const entries = try parseTree(allocator, try fixture.git.command(fixture.repository, .{ .tree = original.tree }), 40);
    const cases = [_]struct { target: []const u8, err: anyerror }{
        .{ .target = "dir/ref/../../alpha", .err = error.UnsafePath },
        .{ .target = "dir/ref/../.d/hidden", .err = error.UnsafePath },
        .{ .target = ".git/../alpha", .err = error.UnsafePath },
        .{ .target = "dir/ref/..", .err = error.UnsafePath },
        .{ .target = "alpha/../dir/file", .err = error.UnreviewedInput },
        .{ .target = "missing/../alpha", .err = error.UnreviewedInput },
        .{ .target = "alpha/", .err = error.UnreviewedInput },
    };
    for (cases) |case| {
        try fixture.repository.dir.deleteFile(io, "chosen");
        try fixture.repository.dir.symLink(io, case.target, "chosen", .{});
        for (entries) |*entry| if (std.mem.eql(u8, entry.path, "chosen")) {
            var hash = try Hash.init(40, "blob", case.target.len);
            hash.update(case.target);
            entry.oid = try hash.finish(allocator);
        };
        try std.testing.expectError(case.err, physical(allocator, io, fixture.repository, entries));
    }
}

test "source symlink expansion has a fixed hop and pending-path bound" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var entries: [34]Entry = undefined;
    for (entries[0..33], 0..) |*entry, i| entry.* = .{
        .path = try std.fmt.allocPrint(allocator, "link-{d:0>2}", .{i}),
        .mode = "120000",
        .oid = "1" ** 40,
        .target = if (i == 32) "target" else try std.fmt.allocPrint(allocator, "link-{d:0>2}", .{i + 1}),
    };
    entries[33] = .{ .path = "target", .mode = "100644", .oid = "1" ** 40 };
    try std.testing.expectError(error.UnsafePath, resolveLink(allocator, &entries, "link-00"));
    try resolveLink(allocator, &entries, "link-01");
    entries[0].target = "x" ** 4096;
    try std.testing.expectError(error.UnsafePath, resolveLink(allocator, &entries, "link-00/suffix"));
}

test "source synthetic linked metadata is physically bound without following evidence or object symlinks" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = try rt.TestFixture.init(allocator, io);
    defer fixture.deinit();
    try initializeTree(&fixture, "sha1");
    const expected = try inspect(&fixture.git, fixture.repository);
    try fixture.root.dir.createDir(io, "linked", .fromMode(0o755));
    const linked = try fs.Directory.open(allocator, io, try std.fs.path.join(allocator, &.{ fixture.root.path, "linked" }));
    defer linked.close(allocator, io);
    var writer = fixture;
    writer.repository = linked;
    try linked.dir.createDir(io, "dir", .fromMode(0o755));
    for ([_][]const u8{ ".gitignore", "alpha", "dir/file", "dir.c", "executable" }) |name| {
        try writer.write(name, try fixture.repository.read(allocator, io, name, 4096, .source), if (std.mem.eql(u8, name, "executable")) 0o755 else 0o644);
    }
    try linked.dir.symLink(io, "dir/file", "link", .{});
    try fixture.repository.dir.createDir(io, ".git/worktrees", .fromMode(0o755));
    try fixture.repository.dir.createDir(io, ".git/worktrees/synthetic", .fromMode(0o755));
    try fixture.write(".git/worktrees/synthetic/HEAD", try std.fmt.allocPrint(allocator, "{s}\n", .{expected.head}), 0o644);
    try fixture.write(".git/worktrees/synthetic/commondir", "../..\n", 0o644);
    try fixture.write(".git/worktrees/synthetic/gitdir", try std.fmt.allocPrint(allocator, "{s}/.git\n", .{linked.path}), 0o644);
    try fixture.write(".git/worktrees/synthetic/index", try fixture.repository.read(allocator, io, ".git/index", 65536, .source), 0o644);
    const pointer = try std.fmt.allocPrint(allocator, "gitdir: {s}/.git/worktrees/synthetic\n", .{fixture.repository.path});
    try writer.write(".git", pointer, 0o644);
    try require(try inspect(&fixture.git, linked), expected);
    try writer.write(".git", try std.fmt.allocPrint(allocator, "gitdir: {s}/.d/not-opened\n", .{fixture.repository.path}), 0o644);
    try std.testing.expectError(error.UnsafePath, inspect(&fixture.git, linked));
    try writer.write(".git", pointer, 0o644);
    try fixture.repository.dir.symLink(io, "../.d/not-opened", ".git/objects/not-followed", .{});
    try std.testing.expectError(error.InvalidGitMetadata, inspect(&fixture.git, linked));
    try fixture.repository.dir.deleteFile(io, ".git/objects/not-followed");
    try require(try inspect(&fixture.git, linked), expected);
}
