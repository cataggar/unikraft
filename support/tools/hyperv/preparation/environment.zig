// SPDX-License-Identifier: BSD-3-Clause
//! Digest-bound, dedicated root-facade handoff; never inherited environment.
const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");
pub const Sha = c.Sha;
pub const parseDigest = c.sha;

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

    /// Call only after loading the dedicated FILE/SHA256 pair. The facade must
    /// still derive canonical_home from passwd and retain its ordinary lock.
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
