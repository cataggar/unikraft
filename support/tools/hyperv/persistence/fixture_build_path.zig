const std = @import("std");

pub fn sourceAbsolute(
    allocator: std.mem.Allocator,
    build_cwd: []const u8,
    owner_root: []const u8,
    sub_path: []const u8,
) ![]u8 {
    if (!std.fs.path.isAbsolute(build_cwd)) return error.InvalidBuildCwd;
    const path = try std.fs.path.resolve(allocator, &.{ build_cwd, owner_root, sub_path });
    errdefer allocator.free(path);
    if (path.len < 2 or path.len > 4096 or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.InvalidCapturePath;
    return path;
}
