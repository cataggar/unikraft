// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const files = @import("hyperv_core").private_files;

pub fn runtime(io: std.Io, path: []const u8) !files.Directory {
    try files.absoluteFilePath(path);
    if (std.os.linux.geteuid() == 0 or std.os.linux.getuid() != std.os.linux.geteuid())
        return error.InvalidPrincipal;
    return files.Directory.open(io, path);
}
