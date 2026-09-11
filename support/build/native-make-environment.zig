// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const paths = @import("zig-facade-paths.zig");

pub const maximum_bytes = 64 * 1024;

pub const Contract = struct {
    bison_data: []const u8,
    m4: []const u8,
    schema: enum { unikraft_native_make_environment_v1 },
    shell: []const u8,
    tmp: []const u8,
    xdg_cache: []const u8,
    xdg_config: []const u8,
    zig_global_cache: []const u8,
    zig_local_cache: []const u8,

    pub fn validate(self: Contract) !void {
        inline for (std.meta.fields(Contract)) |field| {
            if (comptime !std.mem.eql(u8, field.name, "schema"))
                try commandPath(@field(self, field.name));
        }
    }

    pub fn assignments(self: Contract, allocator: std.mem.Allocator) ![10][]const u8 {
        const mapping = .{
            .{ "SHELL", "shell" },
            .{ "CONFIG_SHELL", "shell" },
            .{ "M4", "m4" },
            .{ "BISON_PKGDATADIR", "bison_data" },
            .{ "TMPDIR", "tmp" },
            .{ "XDG_CACHE_HOME", "xdg_cache" },
            .{ "XDG_CONFIG_HOME", "xdg_config" },
            .{ "ZIG_GLOBAL_CACHE_DIR", "zig_global_cache" },
            .{ "ZIG_LOCAL_CACHE_DIR", "zig_local_cache" },
        };
        var result: [10][]const u8 = undefined;
        var count: usize = 0;
        errdefer for (result[0..count]) |argument| allocator.free(argument);
        result[0] = try allocator.dupe(u8, "UMASK=0077");
        count = 1;
        inline for (mapping, 1..) |entry, index| {
            result[index] = try std.fmt.allocPrint(allocator, "{s}={s}", .{ entry[0], @field(self, entry[1]) });
            count += 1;
        }
        return result;
    }
};

fn commandPath(path: []const u8) !void {
    if (path.len < 2 or path.len > 4095 or path[0] != '/') return error.InvalidNativeMakePath;
    for (path) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '/', '_', '-', '.', '+' => {},
        else => return error.InvalidNativeMakePath,
    };
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or component.len > 255 or
            std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return error.InvalidNativeMakePath;
    }
}

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(Contract) {
    if (bytes.len == 0 or bytes.len > maximum_bytes) return error.InvalidNativeMakeEnvironment;
    var parsed = try std.json.parseFromSlice(Contract, allocator, bytes, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .max_value_len = 4095,
    });
    errdefer parsed.deinit();
    try parsed.value.validate();
    const canonical = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(canonical);
    if (bytes.len != canonical.len + 1 or bytes[bytes.len - 1] != '\n' or
        !std.mem.eql(u8, bytes[0..canonical.len], canonical))
        return error.NoncanonicalNativeMakeEnvironment;
    return parsed;
}

pub fn read(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !std.json.Parsed(Contract) {
    if (comptime builtin.os.tag == .linux) return readLinux(allocator, io, path);
    return error.UnsupportedNativeMakeHost;
}

fn readLinux(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !std.json.Parsed(Contract) {
    const private = @import("../tools/hyperv/private_files.zig");
    try commandPath(path);
    var contents = try private.readSensitiveAbsolute(io, allocator, path, maximum_bytes, null);
    defer contents.deinit();
    var parsed = try parse(allocator, contents.bytes());
    errdefer parsed.deinit();
    inline for (std.meta.fields(Contract)) |field| {
        if (comptime !std.mem.eql(u8, field.name, "schema")) {
            const value = @field(parsed.value, field.name);
            const canonical = try paths.canonicalizeNearestExisting(allocator, io, value);
            defer allocator.free(canonical.path);
            if (!canonical.exists or !std.mem.eql(u8, value, canonical.path))
                return error.InvalidNativeMakePath;
            if (comptime std.mem.eql(u8, field.name, "shell") or std.mem.eql(u8, field.name, "m4")) {
                const file = try private.openAbsolute(io, value, .artifact);
                defer file.close(io);
                const metadata = try private.snapshot(file);
                if (metadata.mode & 0o7022 != 0 or metadata.mode & 0o111 == 0 or
                    (metadata.uid != 0 and metadata.uid != std.os.linux.geteuid()))
                    return error.UnsafeNativeMakeTool;
            } else if (comptime std.mem.eql(u8, field.name, "bison_data")) {
                const directory = try private.openDirectory(io, value, .artifact);
                defer directory.close(io);
            } else {
                const directory = try private.Directory.open(io, value);
                defer directory.close(io);
            }
        }
    }
    return parsed;
}

const fixture: Contract = .{
    .bison_data = "/native/share/bison",
    .m4 = "/native/bin/m4",
    .schema = .unikraft_native_make_environment_v1,
    .shell = "/native/bin/bash",
    .tmp = "/private/scratch/tmp",
    .xdg_cache = "/private/scratch/cache",
    .xdg_config = "/private/scratch/config",
    .zig_global_cache = "/private/scratch/zig-global",
    .zig_local_cache = "/private/scratch/zig-local",
};

test "native Make environment emits only fixed private assignments" {
    const allocator = std.testing.allocator;
    try fixture.validate();
    const arguments = try fixture.assignments(allocator);
    defer for (arguments) |argument| allocator.free(argument);
    const expected = [_][]const u8{
        "UMASK=0077",
        "SHELL=/native/bin/bash",
        "CONFIG_SHELL=/native/bin/bash",
        "M4=/native/bin/m4",
        "BISON_PKGDATADIR=/native/share/bison",
        "TMPDIR=/private/scratch/tmp",
        "XDG_CACHE_HOME=/private/scratch/cache",
        "XDG_CONFIG_HOME=/private/scratch/config",
        "ZIG_GLOBAL_CACHE_DIR=/private/scratch/zig-global",
        "ZIG_LOCAL_CACHE_DIR=/private/scratch/zig-local",
    };
    for (expected, arguments) |want, actual| try std.testing.expectEqualStrings(want, actual);
}

test "native Make environment requires strict canonical complete versioned JSON" {
    const allocator = std.testing.allocator;
    const json = try std.json.Stringify.valueAlloc(allocator, fixture, .{});
    defer allocator.free(json);
    const canonical = try std.fmt.allocPrint(allocator, "{s}\n", .{json});
    defer allocator.free(canonical);
    var parsed = try parse(allocator, canonical);
    defer parsed.deinit();
    try std.testing.expectEqualStrings(fixture.shell, parsed.value.shell);
    try std.testing.expectError(error.NoncanonicalNativeMakeEnvironment, parse(allocator, json));
    try std.testing.expectError(error.MissingField, parse(allocator, "{\"schema\":\"unikraft_native_make_environment_v1\"}\n"));
    for ([_][]const u8{
        "\"HOME\":\"/elsewhere\",",
        "\"LD_PRELOAD\":\"/elsewhere\",",
        "\"umask\":\"0022\",",
        "\"shell\":\"/duplicate\",",
    }) |extra| {
        const invalid = try std.fmt.allocPrint(allocator, "{{{s}{s}\n", .{ extra, json[1..] });
        defer allocator.free(invalid);
        if (std.mem.startsWith(u8, extra, "\"shell\""))
            try std.testing.expectError(error.DuplicateField, parse(allocator, invalid))
        else
            try std.testing.expectError(error.UnknownField, parse(allocator, invalid));
    }
}

test "native Make environment rejects relative ambiguous and command-bearing paths" {
    for ([_][]const u8{
        "",     "relative", "/",     "/a/",   "/a//b", "/a/../b", "/a/./b",
        "/a b", "/a\nb",    "/a\tb", "/a:b",  "/a=b",  "/a$b",    "/a;b",
        "/a`b", "/a'b",     "/a\"b", "/a\\b", "/a%b",  "/a#b",    "/a*b",
    }) |path| {
        var invalid = fixture;
        invalid.shell = path;
        try std.testing.expectError(error.InvalidNativeMakePath, invalid.validate());
    }
}

test "native Make environment reads only private state and validated explicit paths" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    const base = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    var contract = fixture;
    inline for (std.meta.fields(Contract)) |field| {
        if (comptime !std.mem.eql(u8, field.name, "schema")) {
            @field(contract, field.name) = try std.fs.path.join(allocator, &.{ base, field.name });
            if (comptime std.mem.eql(u8, field.name, "shell") or std.mem.eql(u8, field.name, "m4")) {
                const file = try temporary.dir.createFile(io, field.name, .{ .permissions = .fromMode(0o700), .exclusive = true });
                defer file.close(io);
                try file.writePositionalAll(io, "metadata-only fixture, never executed\n", 0);
            } else try temporary.dir.createDir(io, field.name, .fromMode(0o700));
        }
    }
    const json = try std.json.Stringify.valueAlloc(allocator, contract, .{});
    const bytes = try std.fmt.allocPrint(allocator, "{s}\n", .{json});
    const path = try std.fs.path.join(allocator, &.{ base, "environment.json" });
    const file = try temporary.dir.createFile(io, "environment.json", .{ .permissions = .fromMode(0o600), .exclusive = true });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
    var loaded = try read(std.testing.allocator, io, path);
    defer loaded.deinit();
    try std.testing.expectEqualStrings(contract.shell, loaded.value.shell);
    try file.setPermissions(io, .fromMode(0o644));
    try std.testing.expectError(error.UnsafeFile, read(allocator, io, path));
    try file.setPermissions(io, .fromMode(0o600));
    try temporary.dir.symLink(io, "environment.json", "alias.json", .{});
    try std.testing.expectError(error.UnsafeFile, read(allocator, io, try std.fs.path.join(allocator, &.{ base, "alias.json" })));
    const cache = try temporary.dir.openDir(io, "zig_local_cache", .{ .iterate = true });
    defer cache.close(io);
    try cache.setPermissions(io, .fromMode(0o755));
    try std.testing.expectError(error.UnsafeFile, read(allocator, io, path));
    try cache.setPermissions(io, .fromMode(0o700));
    const bison_data = try temporary.dir.openDir(io, "bison_data", .{ .iterate = true });
    defer bison_data.close(io);
    try bison_data.setPermissions(io, .fromMode(0o777));
    try std.testing.expectError(error.UnsafeFile, read(allocator, io, path));
    try bison_data.setPermissions(io, .fromMode(0o700));
    try temporary.dir.rename("shell", temporary.dir, "original-shell", io);
    try temporary.dir.symLink(io, "original-shell", "shell", .{});
    try std.testing.expectError(error.InvalidNativeMakePath, read(allocator, io, path));
}
