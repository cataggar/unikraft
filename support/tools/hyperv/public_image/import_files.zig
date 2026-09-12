const std = @import("std");
const c = @import("contracts.zig");
const ic = @import("import_contracts.zig");
const p = c.core.private_files;
const f = @import("files.zig");

pub fn directoryIdentity(dir: std.Io.Dir) !ic.DirectoryIdentity {
    const stat = try p.snapshot(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } });
    return .{ .device_major = stat.dev_major, .device_minor = stat.dev_minor, .inode = stat.ino, .uid = stat.uid, .mode = stat.mode };
}
pub fn sameDirectory(left: ic.DirectoryIdentity, right: ic.DirectoryIdentity) bool {
    return left.device_major == right.device_major and left.device_minor == right.device_minor and left.inode == right.inode;
}
pub fn exactFiles(io: std.Io, dir: std.Io.Dir, names: []const []const u8) !void {
    var entries = dir.iterate();
    var count: usize = 0;
    while (try entries.next(io)) |entry| {
        if (entry.kind != .file or count == names.len) return error.InvalidArtifactShape;
        var known = false;
        for (names) |name| if (std.mem.eql(u8, name, entry.name)) {
            known = true;
            break;
        };
        if (!known) return error.InvalidArtifactShape;
        count += 1;
    }
    if (count != names.len) return error.InvalidArtifactShape;
}
pub const Held = struct {
    artifact: c.boot.files.Artifact,
    pub fn close(self: Held, io: std.Io) void {
        self.artifact.file.close(io);
    }
    pub fn open(io: std.Io, dir: std.Io.Dir, name: []const u8, maximum: u64, policy: p.FilePolicy) !Held {
        const file = try (p.FileParent{ .directory = dir, .name = name, .policy = policy }).openFile(io);
        errdefer file.close(io);
        const before = try p.snapshot(file);
        const mode = before.mode & 0o7777;
        if (before.size == 0 or before.size > maximum or before.nlink != 1 or
            (before.uid != 0 and before.uid != std.os.linux.geteuid()) or
            (mode != 0o400 and mode != 0o444 and mode != 0o600 and mode != 0o644)) return error.UnsafeFile;
        return .{ .artifact = .{ .file = file, .before = before, .pin = .{ .size = before.size, .sha256 = try c.boot.files.digest(io, file, before) } } };
    }
    pub fn read(self: Held, a: std.mem.Allocator, io: std.Io, maximum: usize) ![]u8 {
        if (self.artifact.pin.size > maximum) return error.InvalidFileSize;
        const bytes = try a.alloc(u8, @intCast(self.artifact.pin.size));
        errdefer a.free(bytes);
        if (try self.artifact.file.readPositionalAll(io, bytes, 0) != bytes.len or
            !std.mem.eql(u8, &c.hash(bytes), &self.artifact.pin.sha256) or
            !p.sameSnapshot(self.artifact.before, try p.snapshot(self.artifact.file))) return error.ArtifactChanged;
        return bytes;
    }
    pub fn verify(self: Held, io: std.Io, dir: std.Io.Dir, name: []const u8, policy: p.FilePolicy) !void {
        if (!std.mem.eql(u8, &try c.boot.files.digest(io, self.artifact.file, self.artifact.before), &self.artifact.pin.sha256))
            return error.ArtifactChanged;
        const named = try (p.FileParent{ .directory = dir, .name = name, .policy = policy }).openFile(io);
        defer named.close(io);
        if (!p.sameSnapshot(self.artifact.before, try p.snapshot(named))) return error.ArtifactChanged;
    }
    pub fn identity(self: Held, a: std.mem.Allocator) !ic.FileIdentity {
        const s = self.artifact.before;
        return .{
            .digest = .{ .size = s.size, .sha256 = try c.hex(a, self.artifact.pin.sha256) },
            .device_major = s.dev_major,
            .device_minor = s.dev_minor,
            .inode = s.ino,
            .uid = s.uid,
            .mode = s.mode,
            .links = s.nlink,
            .modified_seconds = s.mtime.sec,
            .modified_nanoseconds = s.mtime.nsec,
            .changed_seconds = s.ctime.sec,
            .changed_nanoseconds = s.ctime.nsec,
        };
    }
};

pub fn fileIdentity(a: std.mem.Allocator, io: std.Io, dir: p.Directory, name: []const u8, maximum: u64) !ic.FileIdentity {
    const file = try Held.open(io, dir.dir, name, maximum, .private);
    defer file.close(io);
    return file.identity(a);
}
pub fn lockIdentity(a: std.mem.Allocator, io: std.Io, lock: *p.Locked) !ic.FileIdentity {
    const file = lock.file orelse return error.LockNotHeld;
    const before = try p.snapshot(file);
    const named = try lock.directory.openFile(io, ".writer.lock");
    defer named.close(io);
    if (before.size != 0 or !p.sameSnapshot(before, try p.snapshot(named))) return error.ArtifactChanged;
    return (Held{ .artifact = .{ .file = file, .before = before, .pin = .{ .size = 0, .sha256 = c.hash("") } } }).identity(a);
}

/// Check retained directory ancestry, not just path spellings (including aliases).
pub fn requireOutside(io: std.Io, parent: std.Io.Dir, input: std.Io.Dir) !void {
    const source = try directoryIdentity(input);
    var current = try parent.openDir(io, ".", .{ .follow_symlinks = false });
    defer current.close(io);
    for (0..4096) |_| {
        const here = try directoryIdentity(current);
        if (sameDirectory(here, source)) return error.OutputInsideArtifact;
        const next = try current.openDir(io, "..", .{ .follow_symlinks = false });
        errdefer next.close(io);
        if (sameDirectory(here, try directoryIdentity(next))) {
            next.close(io);
            return;
        }
        current.close(io);
        current = next;
    }
    return error.UnsafePath;
}

pub const Self = struct {
    path: []const u8,
    file: Held,
    pub fn open(a: std.mem.Allocator, io: std.Io) !Self {
        const path = try std.Io.Dir.cwd().realPathFileAlloc(io, "/proc/self/exe", a);
        const recorded = try f.record(a, io, path, c.max_tool, true);
        const parent = try p.FileParent.open(io, path, .artifact);
        defer parent.close(io);
        // Only this fixed kernel link is followed; artifact paths never are.
        const actual = try std.Io.Dir.openFileAbsolute(io, "/proc/self/exe", .{ .mode = .read_only });
        errdefer actual.close(io);
        const before = try p.snapshot(actual);
        if (before.size != recorded.size) return error.ArtifactChanged;
        const held: Held = .{ .artifact = .{ .file = actual, .before = before, .pin = .{ .size = before.size, .sha256 = try c.sha(recorded.sha256) } } };
        try held.verify(io, parent.directory, parent.name, .artifact);
        return .{ .path = path, .file = held };
    }
    pub fn close(self: Self, io: std.Io) void {
        self.file.close(io);
    }
    pub fn verify(self: Self, io: std.Io) !void {
        const parent = try p.FileParent.open(io, self.path, .artifact);
        defer parent.close(io);
        try self.file.verify(io, parent.directory, parent.name, .artifact);
    }
    pub fn producer(self: Self, a: std.mem.Allocator) !ic.Producer {
        return .{ .executable = .{ .size = self.file.artifact.pin.size, .sha256 = try c.hex(a, self.file.artifact.pin.sha256) } };
    }
};
