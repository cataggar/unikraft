// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub fn read(b: *std.Build, path: []const u8) ![]const u8 {
    const contents = std.Io.Dir.cwd().readFileAlloc(
        b.graph.io,
        path,
        b.allocator,
        .limited(64 * 1024 * 1024),
    ) catch |err| {
        b.graph.poisonCache();
        return err;
    };
    b.dependOnFileContents(b.graph.cwdRelativePath(path));
    return contents;
}
