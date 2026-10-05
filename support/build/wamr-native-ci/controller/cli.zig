// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const contracts = core.contracts;

pub const Action = enum { build, boot, diagnostics, describe, @"--identity", @"supervisor-source-closure", @"reader-source-closure", records, @"readonly-records", @"local-consumer-custody", @"handoff-inspect", @"handoff-inspect-legacy", @"public-validator-build", @"local-handoff-revalidation", @"supervisor-import-identity", @"import-validator-build", @"import-native-revalidation", @"import-handoff-revalidation" };
pub const Command = struct {
    action: Action,
    runtime: ?[]const u8 = null,
    wamr_source: ?[]const u8 = null,
    stage_root: ?[]const u8 = null,
    output: ?[]const u8 = null,
    supervisor: ?[]const u8 = null,
    git: ?[]const u8 = null,
    validator: ?[]const u8 = null,
    expected_build_start_sha256: ?contracts.Sha256 = null,
    expected_boot_inputs_sha256: ?contracts.Sha256 = null,
};

pub fn parse(args: []const []const u8) !Command {
    if (args.len < 2) return error.InvalidUsage;
    const action = std.meta.stringToEnum(Action, args[1]) orelse return error.InvalidUsage;
    if (action == .@"--identity") {
        if (args.len != 2) return error.InvalidUsage;
        return .{ .action = action };
    }
    if (action == .describe) {
        if (args.len != 4 or !std.mem.eql(u8, args[2], "--output") or
            !std.mem.eql(u8, args[3], "json-v1"))
            return error.InvalidUsage;
        return .{ .action = action };
    }
    if (action == .@"supervisor-source-closure" or action == .@"reader-source-closure") {
        if (args.len != 6) return error.InvalidUsage;
        var result = Command{ .action = action };
        var output = false;
        var i: usize = 2;
        while (i < args.len) : (i += 2) {
            const flag = args[i];
            const value = args[i + 1];
            if (std.mem.eql(u8, flag, "--git") and result.git == null) {
                files.absoluteFilePath(value) catch return error.InvalidUsage;
                result.git = value;
            } else if (std.mem.eql(u8, flag, "--output") and !output and
                std.mem.eql(u8, value, "sha256-v1"))
            {
                output = true;
            } else return error.InvalidUsage;
        }
        if (result.git == null or !output) return error.InvalidUsage;
        return result;
    }
    if (action == .@"local-consumer-custody") {
        if (args.len != 8) return error.InvalidUsage;
        var result = Command{ .action = action };
        var i: usize = 2;
        while (i < args.len) : (i += 2) {
            const flag = args[i];
            const value = args[i + 1];
            if (std.mem.eql(u8, flag, "--runtime") and result.runtime == null) {
                files.absoluteFilePath(value) catch return error.InvalidUsage;
                result.runtime = value;
            } else if (std.mem.eql(u8, flag, "--expected-build-start-sha256") and
                result.expected_build_start_sha256 == null)
            {
                result.expected_build_start_sha256 = contracts.parseSha256(value) catch return error.InvalidUsage;
            } else if (std.mem.eql(u8, flag, "--expected-boot-inputs-sha256") and
                result.expected_boot_inputs_sha256 == null)
            {
                result.expected_boot_inputs_sha256 = contracts.parseSha256(value) catch return error.InvalidUsage;
            } else return error.InvalidUsage;
        }
        if (result.runtime == null or result.expected_build_start_sha256 == null or
            result.expected_boot_inputs_sha256 == null)
            return error.InvalidUsage;
        return result;
    }
    if (action == .records or action == .@"readonly-records") {
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
            } else if (action == .@"readonly-records" and std.mem.eql(u8, flag, "--git") and result.git == null) {
                files.absoluteFilePath(value) catch return error.InvalidUsage;
                result.git = value;
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
            transport != (result.stage_root != null) or
            (action == .@"readonly-records" and result.stage_root != null))
            return error.InvalidUsage;
        return result;
    }
    if (action == .@"supervisor-import-identity" or action == .@"import-handoff-revalidation") {
        if (args.len != (if (action == .@"import-handoff-revalidation") @as(usize, 12) else 10))
            return error.InvalidUsage;
        var result = Command{ .action = action };
        var i: usize = 2;
        while (i < args.len) : (i += 2) {
            const flag = args[i];
            const value = args[i + 1];
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            if (std.mem.eql(u8, flag, "--stage-root") and result.stage_root == null) {
                result.stage_root = value;
            } else if (std.mem.eql(u8, flag, "--supervisor") and result.supervisor == null) {
                result.supervisor = value;
            } else if (std.mem.eql(u8, flag, "--git") and result.git == null) {
                result.git = value;
            } else if (std.mem.eql(u8, flag, "--validator") and
                action == .@"import-handoff-revalidation" and result.validator == null)
            {
                result.validator = value;
            } else if (std.mem.eql(u8, flag, "--output") and result.output == null) {
                result.output = value;
            } else return error.InvalidUsage;
        }
        if (result.stage_root == null or result.supervisor == null or result.git == null or result.output == null or
            (action == .@"import-handoff-revalidation" and result.validator == null))
            return error.InvalidUsage;
        return result;
    }
    if (action == .@"import-validator-build" or action == .@"import-native-revalidation") {
        if (args.len != 6) return error.InvalidUsage;
        var result = Command{ .action = action };
        var i: usize = 2;
        while (i < args.len) : (i += 2) {
            const flag = args[i];
            const value = args[i + 1];
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            if (std.mem.eql(u8, flag, "--stage-root") and result.stage_root == null) {
                result.stage_root = value;
            } else if (std.mem.eql(u8, flag, "--output") and result.output == null) {
                result.output = value;
            } else return error.InvalidUsage;
        }
        if (result.stage_root == null or result.output == null) return error.InvalidUsage;
        return result;
    }
    if (action == .@"handoff-inspect" or action == .@"handoff-inspect-legacy" or action == .@"public-validator-build" or action == .@"local-handoff-revalidation") {
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
