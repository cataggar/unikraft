// SPDX-License-Identifier: BSD-3-Clause
//! Digest-bound, dedicated root-facade handoff; never inherited environment.
const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");
pub const Sha = c.Sha;
pub const parseDigest = c.sha;

/// Public root-bridge wire contract at 5dbdf050, not an isolation attestation.
pub const MakeRecord = struct {
    bison_data: []const u8,
    m4: []const u8,
    schema: enum { unikraft_native_make_environment_v1 },
    shell: []const u8,
    tmp: []const u8,
    xdg_cache: []const u8,
    xdg_config: []const u8,
    zig_global_cache: []const u8,
    zig_local_cache: []const u8,

    pub fn validate(self: MakeRecord) !void {
        inline for (std.meta.fields(MakeRecord)) |field| {
            if (comptime !std.mem.eql(u8, field.name, "schema")) {
                const path = @field(self, field.name);
                try absolute(path);
                if (path.len > 4095) return error.UnsafePath;
                for (path) |byte| if (!std.ascii.isAlphanumeric(byte) and
                    std.mem.indexOfScalar(u8, "/_.-+", byte) == null) return error.UnsafePath;
            }
        }
    }
};

pub fn loadMake(allocator: std.mem.Allocator, io: std.Io, path: []const u8, sha256: c.Sha) !std.json.Parsed(MakeRecord) {
    try absolute(path);
    const parent = try c.core.private_files.Directory.open(io, std.fs.path.dirname(path).?);
    defer parent.close(io);
    const bytes = try parent.read(io, allocator, std.fs.path.basename(path), 64 * 1024, null);
    defer allocator.free(bytes);
    if (!std.meta.eql(c.digest(bytes), sha256)) return error.HashMismatch;
    const parsed = try c.parse(MakeRecord, allocator, bytes);
    errdefer parsed.deinit();
    try parsed.value.validate();
    inline for (std.meta.fields(MakeRecord)) |field| {
        if (comptime !std.mem.eql(u8, field.name, "schema")) {
            const value = @field(parsed.value, field.name);
            if (comptime std.mem.eql(u8, field.name, "shell") or std.mem.eql(u8, field.name, "m4")) {
                const directory = try fs.Directory.open(allocator, io, std.fs.path.dirname(value).?);
                defer directory.close(allocator, io);
                const file = try directory.openFile(io, std.fs.path.basename(value), .executable);
                file.close(io);
            } else if (comptime std.mem.eql(u8, field.name, "bison_data")) {
                const directory = try fs.Directory.open(allocator, io, value);
                directory.close(allocator, io);
            } else {
                const directory = try c.core.private_files.Directory.open(io, value);
                directory.close(io);
            }
        }
    }
    return parsed;
}

pub const Record = struct {
    schema: enum { @"uk.native-preparation-environment.v1" } = .@"uk.native-preparation-environment.v1",
    /// The producer's explicitly selected scratch directory, not passwd HOME.
    workspace: []const u8,
    bison_pkgdatadir: []const u8,
    m4: []const u8,
    git_exec_path: []const u8,
    trust_bundle: []const u8,

    pub fn validate(self: Record) !void {
        inline for (.{ "workspace", "bison_pkgdatadir", "m4", "git_exec_path", "trust_bundle" }) |field|
            try absolute(@field(self, field));
    }

    /// Internal native namespace/Git policy, not the root Make bridge schema.
    pub fn apply(self: Record, allocator: std.mem.Allocator, map: *std.process.Environ.Map, canonical_home: []const u8) !void {
        try self.validate();
        try absolute(canonical_home);
        try map.put("HOME", canonical_home);
        inline for (.{ "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "ZIG_LOCAL_CACHE_DIR", "ZIG_GLOBAL_CACHE_DIR" }, .{ "tmp", "cache", "config", "zig-local", "zig-global" }) |key, suffix|
            try map.put(key, try std.fs.path.join(allocator, &.{ self.workspace, suffix }));
        inline for (.{
            .{ "GIT_CONFIG_NOSYSTEM", "1" },
            .{ "GIT_CONFIG_GLOBAL", "/dev/null" },
            .{ "GIT_CONFIG_SYSTEM", "/dev/null" },
            .{ "GIT_ATTR_NOSYSTEM", "1" },
            .{ "GIT_NO_REPLACE_OBJECTS", "1" },
            .{ "GIT_OPTIONAL_LOCKS", "0" },
            .{ "GIT_TERMINAL_PROMPT", "0" },
            .{ "GIT_PROTOCOL_FROM_USER", "0" },
            .{ "GIT_ALLOW_PROTOCOL", "" },
            .{ "GIT_NO_LAZY_FETCH", "1" },
            .{ "GIT_PAGER", "" },
            .{ "GIT_EXTERNAL_DIFF", "" },
            .{ "OPENSSL_CONF", "/dev/null" },
        }) |entry| try map.put(entry[0], entry[1]);
        try map.put("GIT_EXEC_PATH", self.git_exec_path);
        try map.put("BISON_PKGDATADIR", self.bison_pkgdatadir);
        try map.put("M4", self.m4);
        try map.put("SSL_CERT_FILE", self.trust_bundle);
        try map.put("GIT_SSL_CAINFO", self.trust_bundle);
        try map.put("SSL_CERT_DIR", try std.fs.path.join(allocator, &.{ self.workspace, "disabled-openssl" }));
        try map.put("GIT_SSL_CAPATH", map.get("SSL_CERT_DIR").?);
        try map.put("OPENSSL_MODULES", map.get("SSL_CERT_DIR").?);
    }

    pub fn create(self: Record, allocator: std.mem.Allocator, canonical_home: []const u8) !std.process.Environ.Map {
        var map = std.process.Environ.Map.init(allocator);
        errdefer map.deinit();
        try map.put("PATH", "/bin");
        try map.put("LC_ALL", "C");
        try map.put("TZ", "UTC");
        try map.put("SHELL", "/bin/sh");
        try map.put("BASH", "/bin/bash");
        try map.put("CONFIG_SHELL", "/bin/sh");
        try self.apply(allocator, &map, canonical_home);
        return map;
    }
};

pub fn absolute(value: []const u8) !void {
    if (value.len < 2 or !std.fs.path.isAbsolute(value)) return error.UnsafePath;
    try c.relative(value[1..]);
}

/// The parent and root facade both use this descriptor-safe, canonical loader.
/// No symlink, unknown field, duplicate key, noncanonical JSON, or ambient fallback.
pub fn load(allocator: std.mem.Allocator, io: std.Io, path: []const u8, sha256: c.Sha) !std.json.Parsed(Record) {
    try absolute(path);
    _ = try c.sha(&sha256);
    const directory = try fs.Directory.open(allocator, io, std.fs.path.dirname(path).?);
    defer directory.close(allocator, io);
    const bytes = try directory.read(allocator, io, std.fs.path.basename(path), 16 * 1024, .private);
    defer allocator.free(bytes);
    if (!std.crypto.timing_safe.eql(c.Sha, c.digest(bytes), sha256)) return error.HashMismatch;
    const parsed = try c.parse(Record, allocator, bytes);
    errdefer parsed.deinit();
    try parsed.value.validate();
    return parsed;
}

pub const Account = struct {
    name: []const u8,
    uid: u32,
    gid: u32,
    home: []const u8,

    /// Deliberately files-only: no NSS plugins, directory service, or host HOME.
    /// The namespace installs just this entry for the facade's getpwuid_r.
    pub fn current(allocator: std.mem.Allocator, io: std.Io) !Account {
        const directory = try fs.Directory.open(allocator, io, "/etc");
        defer directory.close(allocator, io);
        const bytes = try directory.read(allocator, io, "passwd", 1024 * 1024, .source);
        defer allocator.free(bytes);
        var found: ?Account = null;
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        while (lines.next()) |line| {
            var fields = std.mem.splitScalar(u8, line, ':');
            const name = fields.next() orelse continue;
            _ = fields.next() orelse continue;
            const uid = std.fmt.parseInt(u32, fields.next() orelse continue, 10) catch continue;
            if (uid != std.os.linux.geteuid()) continue;
            if (found != null) return error.InvalidAccount;
            const gid = try std.fmt.parseInt(u32, fields.next() orelse return error.InvalidAccount, 10);
            _ = fields.next() orelse return error.InvalidAccount;
            const home = fields.next() orelse return error.InvalidAccount;
            _ = fields.next() orelse return error.InvalidAccount;
            if (fields.next() != null or gid != std.os.linux.getegid()) return error.InvalidAccount;
            try c.core.private_files.basename(name);
            for (name) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '_' and ch != '-') return error.InvalidAccount;
            if (!std.fs.path.isAbsolute(home)) return error.InvalidAccount;
            const resolved = try std.Io.Dir.cwd().realPathFileAlloc(io, home, allocator);
            defer allocator.free(resolved);
            const canonical = try fs.Directory.open(allocator, io, resolved);
            defer canonical.close(allocator, io);
            found = .{ .name = try allocator.dupe(u8, name), .uid = uid, .gid = gid, .home = try allocator.dupe(u8, canonical.path) };
        }
        return found orelse error.InvalidAccount;
    }

    pub fn passwd(self: Account, allocator: std.mem.Allocator) ![]const u8 {
        return std.fmt.allocPrint(allocator, "{s}:x:{d}:{d}::{s}:/bin/sh\n", .{ self.name, self.uid, self.gid, self.home });
    }
};

test "native Make bridge wire exactly matches canonical parent contract" {
    const allocator = std.testing.allocator;
    const record: MakeRecord = .{
        .bison_data = "/native/bison",
        .m4 = "/native/m4",
        .schema = .unikraft_native_make_environment_v1,
        .shell = "/native/bash",
        .tmp = "/private/tmp",
        .xdg_cache = "/private/cache",
        .xdg_config = "/private/config",
        .zig_global_cache = "/private/global",
        .zig_local_cache = "/private/local",
    };
    const bytes = try c.canonical(allocator, record);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings(
        "{\"bison_data\":\"/native/bison\",\"m4\":\"/native/m4\",\"schema\":\"unikraft_native_make_environment_v1\",\"shell\":\"/native/bash\",\"tmp\":\"/private/tmp\",\"xdg_cache\":\"/private/cache\",\"xdg_config\":\"/private/config\",\"zig_global_cache\":\"/private/global\",\"zig_local_cache\":\"/private/local\"}\n",
        bytes,
    );
    const parsed = try c.parse(MakeRecord, allocator, bytes);
    defer parsed.deinit();
    try parsed.value.validate();
    for ([_][]const u8{ "/native/../bash", "/native//bash", "/native/bash ", "/native/bash@", "/native/bash=arg", "/native/bash:other", "/" }) |path| {
        var invalid = record;
        invalid.shell = path;
        try std.testing.expectError(error.UnsafePath, invalid.validate());
    }
    const unknown = try std.fmt.allocPrint(allocator, "{{\"HOME\":\"/other\",{s}", .{bytes[1..]});
    defer allocator.free(unknown);
    try std.testing.expectError(error.UnexpectedFields, c.parse(MakeRecord, allocator, unknown));
}

test "native Make bridge requires private hash-bound file and canonical trusted explicit paths" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    const base = try fixture.dir.realPathFileAlloc(io, ".", allocator);
    var record: MakeRecord = undefined;
    record.schema = .unikraft_native_make_environment_v1;
    inline for (std.meta.fields(MakeRecord)) |field| {
        if (comptime !std.mem.eql(u8, field.name, "schema")) {
            @field(record, field.name) = try std.fs.path.join(allocator, &.{ base, field.name });
            if (comptime std.mem.eql(u8, field.name, "shell") or std.mem.eql(u8, field.name, "m4")) {
                const file = try fixture.dir.createFile(io, field.name, .{ .permissions = .fromMode(0o700) });
                defer file.close(io);
                try file.setPermissions(io, .fromMode(0o700));
                try file.writePositionalAll(io, "public metadata-only fixture, never executed\n", 0);
            } else {
                try fixture.dir.createDir(io, field.name, .fromMode(0o700));
            }
        }
    }
    const bytes = try c.canonical(allocator, record);
    const path = try std.fs.path.join(allocator, &.{ base, "make.json" });
    const file = try fixture.dir.createFile(io, "make.json", .{ .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o600));
    try file.writePositionalAll(io, bytes, 0);
    const parsed = try loadMake(allocator, io, path, c.digest(bytes));
    defer parsed.deinit();
    try std.testing.expectEqualStrings(record.shell, parsed.value.shell);
    try std.testing.expectError(error.HashMismatch, loadMake(allocator, io, path, c.digest("unreviewed")));
    try file.setPermissions(io, .fromMode(0o644));
    try std.testing.expectError(error.UnsafeFile, loadMake(allocator, io, path, c.digest(bytes)));
    try file.setPermissions(io, .fromMode(0o600));
    const cache = try fixture.dir.openDir(io, "xdg_cache", .{ .iterate = true });
    defer cache.close(io);
    try cache.setPermissions(io, .fromMode(0o755));
    try std.testing.expectError(error.UnsafeFile, loadMake(allocator, io, path, c.digest(bytes)));
    try cache.setPermissions(io, .fromMode(0o700));
    try fixture.dir.rename("shell", fixture.dir, "original-shell", io);
    try fixture.dir.symLink(io, "original-shell", "shell", .{});
    try std.testing.expectError(error.UnsafeFile, loadMake(allocator, io, path, c.digest(bytes)));
}
