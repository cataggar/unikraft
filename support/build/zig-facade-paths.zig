const std = @import("std");

pub const marker_name = ".unikraft-zig-build";
pub const marker_contents = "unikraft-zig-build-v1\n";

pub const CanonicalPath = struct {
    path: []const u8,
    exists: bool,
};

pub fn canonicalizeNearestExisting(
    allocator: std.mem.Allocator,
    io: std.Io,
    absolute_path: []const u8,
) !CanonicalPath {
    var probe = absolute_path;
    while (true) {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = std.Io.Dir.realPathFileAbsolute(io, probe, &buffer) catch |err| switch (err) {
            error.FileNotFound => {
                probe = std.fs.path.dirname(probe) orelse return err;
                continue;
            },
            else => return err,
        };
        const canonical = try allocator.dupe(u8, buffer[0..length]);
        if (probe.len == absolute_path.len) {
            return .{ .path = canonical, .exists = true };
        }

        defer allocator.free(canonical);
        const suffix = try std.fs.path.relative(allocator, ".", null, probe, absolute_path);
        defer allocator.free(suffix);
        return .{
            .path = try std.fs.path.resolve(allocator, &.{ canonical, suffix }),
            .exists = false,
        };
    }
}

pub fn isSameOrAncestor(ancestor: []const u8, path: []const u8) bool {
    if (std.mem.eql(u8, ancestor, path)) return true;
    if (!std.mem.startsWith(u8, path, ancestor) or ancestor.len == 0) return false;
    if (std.fs.path.isSep(ancestor[ancestor.len - 1])) return true;
    return path.len > ancestor.len and std.fs.path.isSep(path[ancestor.len]);
}

pub fn isDescendant(parent: []const u8, path: []const u8) bool {
    return !std.mem.eql(u8, parent, path) and isSameOrAncestor(parent, path);
}

pub fn markerPath(allocator: std.mem.Allocator, output: []const u8) ![]const u8 {
    return std.fs.path.join(allocator, &.{ output, marker_name });
}

pub fn hasBuildMarker(
    allocator: std.mem.Allocator,
    io: std.Io,
    output: []const u8,
) bool {
    const marker = markerPath(allocator, output) catch return false;
    defer allocator.free(marker);
    const stat = std.Io.Dir.cwd().statFile(io, marker, .{ .follow_symlinks = false }) catch return false;
    if (stat.kind != .file) return false;
    const contents = std.Io.Dir.cwd().readFileAlloc(
        io,
        marker,
        allocator,
        .limited(marker_contents.len + 1),
    ) catch return false;
    defer allocator.free(contents);
    return std.mem.eql(u8, contents, marker_contents);
}

pub fn makeLockPath(
    allocator: std.mem.Allocator,
    canonical_output: []const u8,
) ![]const u8 {
    const parent = std.fs.path.dirname(canonical_output) orelse return error.InvalidOutputPath;
    const basename = std.fs.path.basename(canonical_output);
    const hash = std.hash.Wyhash.hash(0, canonical_output);
    const lock_name = try std.fmt.allocPrint(
        allocator,
        ".{s}.unikraft-{x}.lock",
        .{ basename, hash },
    );
    defer allocator.free(lock_name);
    return std.fs.path.join(allocator, &.{ parent, lock_name });
}
