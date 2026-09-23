// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

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

pub fn encode(allocator: std.mem.Allocator, contract: Contract) ![]u8 {
    try contract.validate();
    const json = try std.json.Stringify.valueAlloc(allocator, contract, .{});
    defer allocator.free(json);
    return std.fmt.allocPrint(allocator, "{s}\n", .{json});
}

pub fn commandPath(path: []const u8) !void {
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
