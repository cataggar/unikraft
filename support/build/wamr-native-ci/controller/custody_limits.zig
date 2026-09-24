// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub const mib = 1024 * 1024;
pub const tracked_entries = 40_000;
pub const tracked_bytes = 2 * 1024 * mib;
pub const tracked_file = 256 * mib;
pub const ignored_entries = 131_072;
pub const ignored_bytes = 8 * 1024 * mib;
pub const ignored_file = 512 * mib;
pub const ignored_path = 1024;
pub const ignored_depth = 64;
pub const ignored_git_output = 8 * mib;
pub const diagnostic_changes = 64;
pub const diagnostic_ignored = 128;
pub const diagnostic_root = 128;
pub const input_entries = 100_000;
pub const input_bytes = 2 * 1024 * mib;
pub const input_file = 512 * mib;
pub const bison_entries = 512;
pub const bison_bytes = 8 * mib;
pub const dependency_roots = 128;
pub const dependency_entries = 16_384;
pub const dependency_bytes = 256 * mib;
pub const dependency_file = 64 * mib;
pub const wamr_revision = "a53205d77be3b880eb8f8b96679512ba58e2331a";
pub const miz_revision = "669a27982b376311f558e820b69e9a692735b0cd";
pub const miz_package_hash = "miz-0.2.0-Z3lHlD--2gAdGiguNwbjjdjBmv2f8QlAcwHYRw1De0Sx";
pub const miz_url = "git+https://github.com/cataggar/miz.git#" ++ miz_revision;
pub const roles = [_][]const u8{
    ".d",                          ".zig-cache", "support/apps/wamr-aot/.config",
    "support/apps/wamr-aot/build",
};

pub fn addBounded(count: *usize, amount: usize, maximum: usize) !void {
    if (amount > maximum or count.* > maximum - amount) return error.LimitExceeded;
    count.* += amount;
}

pub fn relative(path: []const u8, max_bytes: usize, max_depth: usize) !void {
    if (path.len == 0 or path.len > max_bytes or path[0] == '/' or
        !std.unicode.utf8ValidateSlice(path)) return error.UnsafePath;
    var depth: usize = 0;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..") or
            std.mem.indexOfScalar(u8, part, 0) != null) return error.UnsafePath;
        try addBounded(&depth, 1, max_depth);
    }
}

pub fn outputRole(path: []const u8) !usize {
    try relative(path, ignored_path, ignored_depth);
    for (roles, 0..) |role, index| {
        if (std.mem.eql(u8, path, role) or
            (path.len > role.len and std.mem.startsWith(u8, path, role) and path[role.len] == '/'))
            return index;
    }
    return error.IgnoredOutsideOutput;
}

pub fn packageName(name: []const u8) !void {
    if (name.len == 0 or name.len > 160 or !std.ascii.isAlphanumeric(name[0]))
        return error.UnsafePackageName;
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '.' and byte != '_' and
            byte != '+' and byte != '-') return error.UnsafePackageName;
    }
}
