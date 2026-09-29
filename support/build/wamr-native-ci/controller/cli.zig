// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const files = @import("hyperv_core").private_files;

pub const Action = enum { build, boot, diagnostics, describe, records, @"handoff-inspect", @"public-validator-build" };
pub const Command = struct {
    action: Action,
    runtime: ?[]const u8 = null,
    wamr_source: ?[]const u8 = null,
    stage_root: ?[]const u8 = null,
    output: ?[]const u8 = null,
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
    if (action == .records) {
        if (args.len != 6 and args.len != 8) return error.InvalidUsage;
        var result = Command{ .action = action };
        var output = false;
        var transport = false;
        var i: usize = 2;
        while (i < args.len) : (i += 2) {
            const flag = args[i];
            const value = args[i + 1];
            if (std.mem.eql(u8, flag, "--runtime") and result.runtime == null) {
                files.absoluteFilePath(value) catch return error.InvalidUsage;
                result.runtime = value;
            } else if (std.mem.eql(u8, flag, "--stage-root") and result.stage_root == null) {
                files.absoluteFilePath(value) catch return error.InvalidUsage;
                result.stage_root = value;
            } else if (std.mem.eql(u8, flag, "--transport") and !transport and
                std.mem.eql(u8, value, "trusted-inner-zip"))
            {
                transport = true;
            } else if (std.mem.eql(u8, flag, "--output") and !output and
                std.mem.eql(u8, value, "handoff-v1"))
            {
                output = true;
            } else return error.InvalidUsage;
        }
        if (!output or (result.runtime != null) == (result.stage_root != null) or
            transport != (result.stage_root != null))
            return error.InvalidUsage;
        return result;
    }
    if (action == .@"handoff-inspect" or action == .@"public-validator-build") {
        if (args.len != 6) return error.InvalidUsage;
        var result = Command{ .action = action };
        var i: usize = 2;
        while (i < args.len) : (i += 2) {
            const flag = args[i];
            const value = args[i + 1];
            if (std.mem.eql(u8, flag, "--runtime") and result.runtime == null) {
                files.absoluteFilePath(value) catch return error.InvalidUsage;
                result.runtime = value;
            } else if (std.mem.eql(u8, flag, "--output") and result.output == null) {
                files.absoluteFilePath(value) catch return error.InvalidUsage;
                result.output = value;
            } else return error.InvalidUsage;
        }
        if (result.runtime == null or result.output == null) return error.InvalidUsage;
        return result;
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
