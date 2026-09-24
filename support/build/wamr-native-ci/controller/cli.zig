// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const files = @import("hyperv_core").private_files;

pub const Action = enum { build, boot, diagnostics, describe };
pub const Command = struct {
    action: Action,
    runtime: ?[]const u8 = null,
    wamr_source: ?[]const u8 = null,
};

pub fn parse(args: []const []const u8) !Command {
    if (args.len < 2) return error.InvalidUsage;
    const action = std.meta.stringToEnum(Action, args[1]) orelse return error.InvalidUsage;
    if (action == .describe) {
        if (args.len != 4 or !std.mem.eql(u8, args[2], "--output") or
            !std.mem.eql(u8, args[3], "json-v1"))
            return error.InvalidUsage;
        return .{ .action = action };
    }
    if (args.len < 4 or args.len > 6 or args.len % 2 != 0) return error.InvalidUsage;
    var result = Command{ .action = action };
    var i: usize = 2;
    while (i < args.len) : (i += 2) {
        const flag = args[i];
        const value = args[i + 1];
        if (std.mem.eql(u8, flag, "--runtime") and result.runtime == null) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.runtime = value;
        } else if (std.mem.eql(u8, flag, "--wamr-source") and
            action == .build and result.wamr_source == null)
        {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.wamr_source = value;
        } else return error.InvalidUsage;
    }
    if (result.runtime == null or (action == .build) != (result.wamr_source != null))
        return error.InvalidUsage;
    return result;
}
