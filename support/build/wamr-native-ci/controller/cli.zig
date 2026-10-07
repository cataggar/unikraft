// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const contracts = core.contracts;

pub const Action = enum { build, boot, diagnostics, describe, @"--identity", @"supervisor-source-closure", @"reader-source-closure", records, @"readonly-records", @"local-consumer-custody", @"handoff-inspect", @"handoff-inspect-legacy", @"public-validator-build", @"local-handoff-revalidation", @"supervisor-import-identity", @"import-validator-build", @"import-native-revalidation", @"import-handoff-revalidation", @"private-export", @"private-validate", @"public-export", @"public-archive", @"verify-public-source-bundle", @"stage-public-source-upload", @"import-public-source-bundle", @"import-public-source-download", candidate, @"candidate-inspect", @"candidate-result" };
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
    archive: ?[]const u8 = null,
    download_root: ?[]const u8 = null,
    container_archive: ?[]const u8 = null,
    validation_output: ?[]const u8 = null,
    source_revision: ?[]const u8 = null,
    source_tree: ?[]const u8 = null,
    run_id: ?[]const u8 = null,
    run_attempt: ?[]const u8 = null,
    inner_digest: ?contracts.Sha256 = null,
    artifact_id: ?[]const u8 = null,
    container_digest: ?contracts.Sha256 = null,
    selected_artifact_id: ?[]const u8 = null,
    selected_container_digest: ?contracts.Sha256 = null,
    bundle: ?[]const u8 = null,
    candidate: ?[]const u8 = null,
    attempt_id: ?[]const u8 = null,
    subscription: ?[]const u8 = null,
    prefix: ?[]const u8 = null,
    serial_first: ?[]const u8 = null,
    serial_second: ?[]const u8 = null,
};

pub fn parse(args: []const []const u8) !Command {
    if (args.len < 2) return error.InvalidUsage;
    const action = std.meta.stringToEnum(Action, args[1]) orelse return error.InvalidUsage;
    if (isCandidate(action)) return parseCandidate(args, action);
    if (isPublic(action)) return parsePublic(args, action);
    if (action == .@"--identity") {
        if (args.len != 2) return error.InvalidUsage;
        return .{ .action = action };
    }
    return parseExisting(args, action);
}

pub fn isCandidate(action: Action) bool {
    return action == .candidate or action == .@"candidate-inspect" or action == .@"candidate-result";
}

fn parseCandidate(args: []const []const u8, action: Action) !Command {
    if (args.len % 2 != 0) return error.InvalidUsage;
    var result: Command = .{ .action = action };
    var i: usize = 2;
    while (i < args.len) : (i += 2) {
        const flag = args[i];
        const value = args[i + 1];
        if (std.mem.eql(u8, flag, "--bundle") and result.bundle == null) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            if (!std.mem.eql(u8, std.fs.path.basename(value), "bundle.json")) return error.InvalidUsage;
            result.bundle = value;
        } else if (std.mem.eql(u8, flag, "--output") and result.output == null and action == .candidate) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.output = value;
        } else if (std.mem.eql(u8, flag, "--candidate") and result.candidate == null and action != .candidate) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.candidate = value;
        } else if (std.mem.eql(u8, flag, "--validation-output") and result.validation_output == null) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.validation_output = value;
        } else if (std.mem.eql(u8, flag, "--git") and result.git == null) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.git = value;
        } else if (std.mem.eql(u8, flag, "--supervisor") and result.supervisor == null) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.supervisor = value;
        } else if (std.mem.eql(u8, flag, "--validator") and result.validator == null) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.validator = value;
        } else if (std.mem.eql(u8, flag, "--attempt-id") and result.attempt_id == null and action == .candidate) {
            _ = contracts.parseUuid(value) catch return error.InvalidUsage;
            result.attempt_id = value;
        } else if (std.mem.eql(u8, flag, "--subscription") and result.subscription == null and action == .candidate) {
            if (value.len == 0 or value.len > 4096) return error.InvalidUsage;
            result.subscription = value;
        } else if (std.mem.eql(u8, flag, "--prefix") and result.prefix == null and action == .candidate) {
            if (value.len == 0 or value.len > 32) return error.InvalidUsage;
            result.prefix = value;
        } else if (std.mem.eql(u8, flag, "--serial-first") and result.serial_first == null and action == .@"candidate-result") {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.serial_first = value;
        } else if (std.mem.eql(u8, flag, "--serial-second") and result.serial_second == null and action == .@"candidate-result") {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.serial_second = value;
        } else return error.InvalidUsage;
    }
    if (result.bundle == null or result.validation_output == null or result.git == null or
        result.supervisor == null or result.validator == null or
        (action == .candidate and result.output == null) or
        (action != .candidate and result.candidate == null) or
        (action == .@"candidate-result" and result.serial_first == null))
        return error.InvalidUsage;
    return result;
}

pub fn isPublic(action: Action) bool {
    return switch (action) {
        .@"public-export", .@"public-archive", .@"verify-public-source-bundle", .@"stage-public-source-upload", .@"import-public-source-bundle", .@"import-public-source-download" => true,
        else => false,
    };
}

fn parsePublic(args: []const []const u8, action: Action) !Command {
    if (args.len % 2 != 0) return error.InvalidUsage;
    var result: Command = .{ .action = action };
    const packing = action == .@"public-export" or action == .@"public-archive";
    const importing = action == .@"import-public-source-bundle" or action == .@"import-public-source-download";
    const download = action == .@"import-public-source-download";
    const reading = action == .@"verify-public-source-bundle" or action == .@"stage-public-source-upload" or action == .@"import-public-source-bundle";
    var i: usize = 2;
    while (i < args.len) : (i += 2) {
        const flag = args[i];
        const value = args[i + 1];
        if (std.mem.eql(u8, flag, "--expected-source") and result.source_revision == null) {
            try sourceIdentity(value);
            result.source_revision = value;
        } else if (std.mem.eql(u8, flag, "--expected-tree") and result.source_tree == null) {
            try sourceIdentity(value);
            result.source_tree = value;
        } else if (std.mem.eql(u8, flag, "--run-id") and result.run_id == null) {
            try identifier(value);
            result.run_id = value;
        } else if (std.mem.eql(u8, flag, "--run-attempt") and result.run_attempt == null) {
            try identifier(value);
            result.run_attempt = value;
        } else if (std.mem.eql(u8, flag, "--expected-archive-sha256") and result.inner_digest == null and !packing) {
            result.inner_digest = contracts.parseSha256(value) catch return error.InvalidUsage;
        } else if (std.mem.eql(u8, flag, "--output") and result.output == null and action != .@"verify-public-source-bundle") {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.output = value;
        } else if (std.mem.eql(u8, flag, "--runtime") and result.runtime == null and action == .@"public-export") {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.runtime = value;
        } else if (std.mem.eql(u8, flag, "--stage-root") and result.stage_root == null and packing) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.stage_root = value;
        } else if (std.mem.eql(u8, flag, "--validation-output") and result.validation_output == null and packing) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.validation_output = value;
        } else if (std.mem.eql(u8, flag, "--archive") and result.archive == null and reading) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.archive = value;
        } else if (std.mem.eql(u8, flag, "--download-root") and result.download_root == null and download) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.download_root = value;
        } else if (std.mem.eql(u8, flag, "--container-archive") and result.container_archive == null and download) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.container_archive = value;
        } else if (std.mem.eql(u8, flag, "--artifact-id") and result.artifact_id == null and download) {
            try identifier(value);
            result.artifact_id = value;
        } else if (std.mem.eql(u8, flag, "--selected-artifact-id") and result.selected_artifact_id == null and download) {
            try identifier(value);
            result.selected_artifact_id = value;
        } else if (std.mem.eql(u8, flag, "--container-digest") and result.container_digest == null and download) {
            result.container_digest = contracts.parseSha256(value) catch return error.InvalidUsage;
        } else if (std.mem.eql(u8, flag, "--selected-container-digest") and result.selected_container_digest == null and download) {
            result.selected_container_digest = contracts.parseSha256(value) catch return error.InvalidUsage;
        } else if (std.mem.eql(u8, flag, "--git") and result.git == null and (packing or importing)) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.git = value;
        } else if (std.mem.eql(u8, flag, "--supervisor") and result.supervisor == null and (packing or importing)) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.supervisor = value;
        } else if (std.mem.eql(u8, flag, "--validator") and result.validator == null and (packing or importing)) {
            files.absoluteFilePath(value) catch return error.InvalidUsage;
            result.validator = value;
        } else return error.InvalidUsage;
    }
    if (result.source_revision == null or result.source_tree == null or result.run_id == null or result.run_attempt == null)
        return error.InvalidUsage;
    if (action != .@"verify-public-source-bundle" and result.output == null) return error.InvalidUsage;
    if ((packing or importing) and (result.git == null or result.supervisor == null or result.validator == null))
        return error.InvalidUsage;
    if (packing and (result.stage_root == null or result.validation_output == null)) return error.InvalidUsage;
    if (action == .@"public-export" and result.runtime == null) return error.InvalidUsage;
    if (reading and result.archive == null) return error.InvalidUsage;
    if (!packing and action != .@"import-public-source-bundle" and result.inner_digest == null) return error.InvalidUsage;
    if (download and (result.download_root == null or result.container_archive == null or
        result.artifact_id == null or result.container_digest == null or
        result.selected_artifact_id == null or result.selected_container_digest == null))
        return error.InvalidUsage;
    return result;
}

fn identifier(value: []const u8) !void {
    if (value.len == 0 or value.len > 20 or value[0] < '1' or value[0] > '9') return error.InvalidUsage;
    for (value) |digit| if (!std.ascii.isDigit(digit)) return error.InvalidUsage;
}
fn sourceIdentity(value: []const u8) !void {
    if (value.len != 40) return error.InvalidUsage;
    for (value) |digit|
        if (!std.ascii.isDigit(digit) and (digit < 'a' or digit > 'f')) return error.InvalidUsage;
}

fn parseExisting(args: []const []const u8, action: Action) !Command {
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
    if (action == .@"supervisor-import-identity" or action == .@"import-handoff-revalidation" or action == .@"private-validate") {
        const validates = action != .@"supervisor-import-identity";
        if (args.len != (if (validates) @as(usize, 12) else 10))
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
                validates and result.validator == null)
            {
                result.validator = value;
            } else if (std.mem.eql(u8, flag, "--output") and result.output == null) {
                result.output = value;
            } else return error.InvalidUsage;
        }
        if (result.stage_root == null or result.supervisor == null or result.git == null or result.output == null or
            (validates and result.validator == null))
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
    if (action == .@"handoff-inspect" or action == .@"handoff-inspect-legacy" or action == .@"public-validator-build" or action == .@"local-handoff-revalidation" or action == .@"private-export") {
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
