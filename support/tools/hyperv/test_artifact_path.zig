//! Zig 0.17 option paths are relative to the maker's cwd, not a test's private cwd.
const std = @import("std");

pub fn resolve(comptime build_cwd: []const u8, comptime path: []const u8) []const u8 {
    @setEvalBranchQuota(10000);
    return comptime resolved: {
        var buffer: [std.fs.max_path_bytes * 2]u8 = undefined;
        var fixed = std.heap.FixedBufferAllocator.init(&buffer);
        const result = std.fs.path.resolve(fixed.allocator(), &.{ build_cwd, path }) catch
            @compileError("fixture artifact path exceeds the native path bound");
        if (!std.fs.path.isAbsolute(result) or result.len >= std.fs.max_path_bytes)
            @compileError("fixture artifact path must be a bounded absolute path");
        const stable = result[0..result.len].*;
        break :resolved &stable;
    };
}
