// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const c = core.contracts;
const authority = @import("root.zig");
const contracts = authority.contracts;

const golden = @embedFile("goldens/contracts.json");
const scenarios = @embedFile("goldens/python-scenarios.json");

const golden_fields = struct {
    pub const root = [_][]const u8{ "schema", "schema_version", "authority_domain", "canonicalization", "cli", "limits", "policy", "azure_runtime", "schemas", "canonical_records", "uuid_normalization", "uuid_rejection", "generated_ids", "live_success_scenarios", "live_refusal_scenarios", "runtime_bound_scenarios" };
    pub const cli_root = [_][]const u8{ "commands", "exit_contract" };
    pub const command = [_][]const u8{ "options", "required", "optional", "repeated_required", "repeated_optional" };
    pub const exit_contract = [_][]const u8{ "help_exit", "malformed_exit", "refusal_exit", "refusal_stdout", "refusal_stderr", "success_exit", "success_stdout", "validator_probe_streams_public" };
    pub const limits = [_][]const u8{ "runtime_files", "runtime_directories", "runtime_bytes", "runtime_depth", "runtime_file_bytes", "runtime_loader_files", "runtime_manifest_bytes", "approver_min_bytes", "approver_max_bytes", "reference_min_bytes", "reference_max_bytes", "authorization_window_seconds" };
    pub const policy_root = [_][]const u8{ "purpose", "profile", "authority_before_admission", "authority_after_admission", "location", "vm_size", "serial_mode", "runtime_seconds", "cleanup_seconds", "operation_seconds", "poll_seconds", "fixed_vhd_bytes", "fixed_vhd_capacity_bytes", "resources", "retry_count", "substitution", "cleanup", "cost" };
    pub const cost_policy = [_][]const u8{ "unit", "policy", "fixed_overhead_microusd", "vm_hour_microusd", "os_disk_hour_microusd", "estimated_upper_bound", "repository_policy_maximum", "maximum_authorized_minimum", "maximum_authorized_maximum" };
    pub const azure_runtime = [_][]const u8{ "manifest", "commands", "isolation" };
    pub const manifest = [_][]const u8{ "header", "directory", "file", "loader", "parent", "sample" };
    pub const records = [_][]const u8{ "azure_runtime", "plan", "approval_template", "authorization_approved", "authorization_denied", "admission" };
    pub const inventory = [_][]const u8{ "schema", "schema_version", "sources", "source_counts", "count", "scenarios" };
    pub const uuid_normalization = [_][]const u8{ "input", "normalized" };
    pub const uuid_rejection = [_][]const u8{ "field", "input", "refused", "reason", "output_file_appeared" };
    pub const runtime_bound = [_][]const u8{ "name", "limit", "accepted_at_limit", "refused_above_limit", "reason" };
    pub const generated_ids = [_][]const u8{ "attempt_id", "ledger_id" };
    pub const live_refusal = [_][]const u8{ "name", "refused", "exception", "reason", "output_file_appeared", "outputs" };
};

test "Python authority golden is canonical and matches native literal tables" {
    try consumeGolden(golden);
}

fn consumeGolden(bytes: []const u8) !void {
    var document = try contracts.parseCanonical(std.testing.allocator, bytes);
    defer document.deinit();
    const root = try c.exactFields(document.value(), &golden_fields.root);
    try expectLiteral(root, "schema", "uk.wamr.authority-contract-golden");
    try expectInt(root, "schema_version", @as(u8, 1));
    try expectLiteral(root, "authority_domain", "azure-execution");
    try expectLiteral(root, "canonicalization", contracts.canonicalization);
    try expectLimits(root.get("limits") orelse return error.MissingGolden);
    try expectCli(root.get("cli") orelse return error.MissingGolden);
    try expectPolicy(root.get("policy") orelse return error.MissingGolden);
    try expectAzureRuntime(root.get("azure_runtime") orelse return error.MissingGolden);
    try expectSchemas(root.get("schemas") orelse return error.MissingGolden);
    try expectCanonicalRecords(root.get("canonical_records") orelse return error.MissingGolden);
    try expectUuid(root);
    try expectLiveRefusals(root.get("live_refusal_scenarios") orelse return error.MissingGolden);
    try expectRuntimeBounds(root.get("runtime_bound_scenarios") orelse return error.MissingGolden);
}

const Mutation = struct {
    record: ?[]const u8 = null,
    path: []const []const u8,
    value: std.json.Value,
    expected: anyerror,
};

test "native fixture consumer rejects each independent review mutation" {
    const cases = [_]Mutation{
        .{ .path = &.{ "cli", "commands", "plan", "options", "11", "type" }, .value = .{ .bool = false }, .expected = error.ExpectedString },
        .{ .path = &.{ "cli", "commands", "plan", "options", "11", "unknown" }, .value = .null, .expected = error.UnexpectedFields },
        .{ .path = &.{ "schemas", "unknown" }, .value = .null, .expected = error.UnexpectedFields },
        .{ .path = &.{ "azure_runtime", "isolation", "host_loader_fallback" }, .value = .{ .string = "permitted" }, .expected = error.UnexpectedLiteral },
        .{ .record = "authorization_approved", .path = &.{"version"}, .value = .null, .expected = error.ExpectedInteger },
        .{ .record = "authorization_approved", .path = &.{ "azure_runtime", "unknown" }, .value = .null, .expected = error.UnexpectedFields },
    };
    for (cases) |case| try rejectMutations(&.{case}, case.expected);
}

test "native fixture consumer rejects the three combined reviewer fixtures" {
    try rejectMutations(&.{
        .{ .path = &.{ "cli", "commands", "plan", "options", "11", "type" }, .value = .{ .bool = false }, .expected = error.UnexpectedFields },
        .{ .path = &.{ "cli", "commands", "plan", "options", "11", "unknown" }, .value = .null, .expected = error.UnexpectedFields },
    }, error.UnexpectedFields);
    try rejectMutations(&.{
        .{ .path = &.{ "schemas", "unknown" }, .value = .null, .expected = error.UnexpectedLiteral },
        .{ .path = &.{ "azure_runtime", "isolation", "host_loader_fallback" }, .value = .{ .string = "permitted" }, .expected = error.UnexpectedLiteral },
    }, error.UnexpectedLiteral);
    try rejectMutations(&.{
        .{ .record = "authorization_approved", .path = &.{"version"}, .value = .null, .expected = error.ExpectedInteger },
        .{ .record = "authorization_approved", .path = &.{ "azure_runtime", "unknown" }, .value = .null, .expected = error.ExpectedInteger },
    }, error.ExpectedInteger);
}

test "native fixture consumer checks every canonical record version" {
    for (golden_fields.records) |record| {
        try rejectMutations(&.{.{ .record = record, .path = &.{"version"}, .value = .null, .expected = error.ExpectedInteger }}, error.ExpectedInteger);
        try rejectMutations(&.{.{ .record = record, .path = &.{"version"}, .value = .{ .integer = 99 }, .expected = error.UnexpectedInteger }}, error.UnexpectedInteger);
    }
}

test "native fixture consumer rejects scalar coercions and nested shape drift" {
    const cases = [_]Mutation{
        .{ .path = &.{ "cli", "commands", "plan", "options", "0", "required" }, .value = .{ .integer = 1 }, .expected = error.ExpectedBoolean },
        .{ .path = &.{ "cli", "commands", "plan", "options", "0", "required" }, .value = .{ .bool = false }, .expected = error.UnexpectedBoolean },
        .{ .path = &.{ "cli", "commands", "plan", "options", "0", "repeated" }, .value = .{ .string = "false" }, .expected = error.ExpectedBoolean },
        .{ .path = &.{ "cli", "commands", "plan", "options", "0", "repeated" }, .value = .{ .bool = true }, .expected = error.UnexpectedBoolean },
        .{ .path = &.{ "cli", "commands", "plan", "options", "0", "flags" }, .value = .{ .string = "--bundle" }, .expected = error.ExpectedArray },
        .{ .path = &.{ "cli", "commands", "plan", "options", "0", "flags", "0" }, .value = .{ .string = "--unknown" }, .expected = error.UnexpectedOption },
        .{ .path = &.{ "cli", "commands", "plan", "options", "0", "dest" }, .value = .null, .expected = error.ExpectedString },
        .{ .path = &.{ "cli", "commands", "plan", "options", "0", "dest" }, .value = .{ .string = "wrong" }, .expected = error.UnexpectedLiteral },
        .{ .path = &.{ "cli", "commands", "plan", "options", "0", "type" }, .value = .{ .string = "int" }, .expected = error.UnexpectedLiteral },
        .{ .path = &.{ "cli", "commands", "plan", "options", "4", "type" }, .value = .{ .string = "str" }, .expected = error.ExpectedNull },
        .{ .path = &.{ "cli", "commands", "record-authorization", "options", "3", "choices" }, .value = .null, .expected = error.ExpectedArray },
        .{ .path = &.{ "schemas", "plan" }, .value = .{ .bool = false }, .expected = error.ExpectedArray },
        .{ .record = "plan", .path = &.{"created_unix"}, .value = .{ .bool = true }, .expected = error.ExpectedInteger },
        .{ .record = "authorization_approved", .path = &.{"version"}, .value = .{ .string = "2" }, .expected = error.ExpectedInteger },
        .{ .record = "plan", .path = &.{"resources"}, .value = .null, .expected = error.ExpectedObject },
        .{ .record = "plan", .path = &.{ "cleanup", "replacement_resources" }, .value = .{ .integer = 0 }, .expected = error.ExpectedBoolean },
        .{ .record = "plan", .path = &.{ "cleanup", "replacement_resources" }, .value = .{ .bool = true }, .expected = error.UnexpectedBoolean },
        .{ .record = "plan", .path = &.{ "cost", "policy" }, .value = .{ .string = "unknown" }, .expected = error.UnexpectedLiteral },
        .{ .record = "plan", .path = &.{ "candidate", "size" }, .value = .{ .integer = -1 }, .expected = error.IntegerOverflow },
        .{ .record = "plan", .path = &.{ "candidate", "sha256" }, .value = .{ .bool = false }, .expected = error.ExpectedString },
        .{ .record = "plan", .path = &.{ "ledger", "version" }, .value = .null, .expected = error.ExpectedInteger },
        .{ .record = "plan", .path = &.{ "ledger", "schema" }, .value = .{ .string = "unknown" }, .expected = error.UnexpectedLiteral },
        .{ .record = "plan", .path = &.{ "ledger", "directory", "uid" }, .value = .{ .integer = 4294967296 }, .expected = error.IntegerOverflow },
        .{ .record = "azure_runtime", .path = &.{ "loader_dependencies", "0" }, .value = .null, .expected = error.ExpectedObject },
        .{ .record = "azure_runtime", .path = &.{ "observed", "depth" }, .value = .{ .string = "1" }, .expected = error.ExpectedInteger },
        .{ .record = "authorization_approved", .path = &.{ "azure_runtime", "version" }, .value = .{ .integer = 2 }, .expected = error.UnexpectedInteger },
        .{ .record = "authorization_approved", .path = &.{ "azure_runtime", "limits", "bytes" }, .value = .{ .integer = 1 }, .expected = error.UnexpectedInteger },
        .{ .record = "admission", .path = &.{ "approval", "approver" }, .value = .{ .integer = 1 }, .expected = error.ExpectedString },
        .{ .record = "plan", .path = &.{ "resources", "boot_count" }, .value = .{ .integer = 3 }, .expected = error.UnexpectedInteger },
        .{ .record = "authorization_approved", .path = &.{ "azure_runtime", "isolation", "host_loader_fallback" }, .value = .{ .string = "permitted" }, .expected = error.UnexpectedLiteral },
    };
    for (cases) |case| try rejectMutations(&.{case}, case.expected);
    const nested = [_][]const []const u8{
        &.{"candidate"},                                   &.{"run"},
        &.{"identity"},                                    &.{"lineage"},
        &.{"ledger"},                                      &.{ "ledger", "directory" },
        &.{"resources"},                                   &.{"substitution"},
        &.{"cleanup"},                                     &.{"cost"},
        &.{"tools"},                                       &.{"azure_runtime"},
        &.{ "azure_runtime", "manifest" },                 &.{ "azure_runtime", "limits" },
        &.{ "azure_runtime", "observed" },                 &.{ "azure_runtime", "isolation" },
        &.{ "azure_runtime", "loader_dependencies", "0" },
    };
    for (nested) |path| {
        var extended: [4][]const u8 = undefined;
        @memcpy(extended[0..path.len], path);
        extended[path.len] = "unknown";
        const case = Mutation{ .record = "plan", .path = extended[0 .. path.len + 1], .value = .null, .expected = error.UnexpectedFields };
        try rejectMutations(&.{case}, case.expected);
    }
    for ([_][]const u8{ "approval_template", "authorization_approved", "authorization_denied" }) |record| {
        try rejectMutations(&.{.{ .record = record, .path = &.{ "limits", "unknown" }, .value = .null, .expected = error.UnexpectedFields }}, error.UnexpectedFields);
    }
    try rejectMutations(&.{.{ .record = "admission", .path = &.{ "approval", "unknown" }, .value = .null, .expected = error.UnexpectedFields }}, error.UnexpectedFields);
}

fn rejectMutations(mutations: []const Mutation, expected: anyerror) !void {
    var document = try contracts.parseCanonical(std.testing.allocator, golden);
    defer document.deinit();
    const allocator = document.parsed.arena.allocator();
    for (mutations) |mutation| {
        if (mutation.record) |record| {
            const entry = document.parsed.value.object.getPtr("canonical_records").?.object.getPtr(record).?;
            var inner = try contracts.parseCanonical(std.testing.allocator, try c.string(entry.*));
            defer inner.deinit();
            try mutate(&inner.parsed.value, inner.parsed.arena.allocator(), mutation.path, mutation.value);
            entry.* = .{ .string = try inner.canonicalAlloc(allocator) };
        } else {
            try mutate(&document.parsed.value, allocator, mutation.path, mutation.value);
        }
    }
    const bytes = try document.canonicalAlloc(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectError(expected, consumeGolden(bytes));
}

fn mutate(root: *std.json.Value, allocator: std.mem.Allocator, path: []const []const u8, value: std.json.Value) !void {
    var current = root;
    for (path[0 .. path.len - 1]) |part| {
        current = switch (current.*) {
            .object => |*object| object.getPtr(part).?,
            .array => |*items| &items.items[try std.fmt.parseInt(usize, part, 10)],
            else => return error.InvalidMutation,
        };
    }
    const last = path[path.len - 1];
    switch (current.*) {
        .object => |*object| try object.put(allocator, last, value),
        .array => |*items| items.items[try std.fmt.parseInt(usize, last, 10)] = value,
        else => return error.InvalidMutation,
    }
}

test "authority contract helper boundaries are frozen" {
    try std.testing.expectEqual(contracts.policy.estimated_cost_upper_bound_microusd, try contracts.recomputeCost(1, 1, 3600, 1800));
    try std.testing.expectEqual(@as(u64, 7_250_000), try contracts.recomputeCost(1, 1, 60, 1800));
    try std.testing.expect(contracts.validApprovalWindow(1, 3601));
    try std.testing.expect(!contracts.validApprovalWindow(0, 3600));
    try std.testing.expect(!contracts.validApprovalWindow(1, 3602));
    try std.testing.expect(contracts.boundedAuthorityText("operator", 1, 128));
    try std.testing.expect(!contracts.boundedAuthorityText("", 1, 128));
    try std.testing.expect(!contracts.boundedAuthorityText("bad\n", 1, 128));
}

test "Python authority scenario inventory is checked and sorted" {
    var document = try contracts.parseCanonical(std.testing.allocator, scenarios);
    defer document.deinit();
    const root = try c.exactFields(document.value(), &golden_fields.inventory);
    try expectLiteral(root, "schema", "uk.wamr.authority-python-scenario-inventory");
    try expectInt(root, "schema_version", @as(u8, 1));
    try expectInt(root, "count", @as(u16, 184));
    const items = try array(root.get("scenarios") orelse return error.MissingGolden);
    try std.testing.expectEqual(@as(usize, 184), items.len);
    var previous: []const u8 = "";
    for (items) |item| {
        const current = try c.string(item);
        try std.testing.expect(std.mem.lessThan(u8, previous, current));
        previous = current;
    }
}

fn expectLimits(value: std.json.Value) !void {
    const m = try c.exactFields(value, &golden_fields.limits);
    try expectInt(m, "runtime_files", contracts.limits.runtime_files);
    try expectInt(m, "runtime_directories", contracts.limits.runtime_directories);
    try expectInt(m, "runtime_bytes", contracts.limits.runtime_bytes);
    try expectInt(m, "runtime_depth", contracts.limits.runtime_depth);
    try expectInt(m, "runtime_file_bytes", contracts.limits.runtime_file_bytes);
    try expectInt(m, "runtime_loader_files", contracts.limits.runtime_loader_files);
    try expectInt(m, "runtime_manifest_bytes", contracts.limits.runtime_manifest_bytes);
    try expectInt(m, "approver_min_bytes", contracts.limits.approver_min_bytes);
    try expectInt(m, "approver_max_bytes", contracts.limits.approver_max_bytes);
    try expectInt(m, "reference_min_bytes", contracts.limits.reference_min_bytes);
    try expectInt(m, "reference_max_bytes", contracts.limits.reference_max_bytes);
    try expectInt(m, "authorization_window_seconds", contracts.limits.authorization_window_seconds);
}

fn expectCli(value: std.json.Value) !void {
    const root = try c.exactFields(value, &golden_fields.cli_root);
    const commands = try c.exactFields(root.get("commands") orelse return error.MissingGolden, &contracts.cli.commands);
    try expectCommand(commands, "prepare-azure-runtime", &contracts.cli.prepare_required, &contracts.cli.prepare_optional, &contracts.cli.prepare_repeated_required, &contracts.cli.prepare_repeated_optional);
    try expectCommand(commands, "plan", &contracts.cli.plan_required, &contracts.cli.plan_optional, &contracts.cli.plan_repeated_required, &contracts.cli.plan_repeated_optional);
    try expectCommand(commands, "record-authorization", &contracts.cli.authorize_required, &contracts.cli.authorize_optional, &contracts.cli.authorize_repeated_required, &contracts.cli.authorize_repeated_optional);
    try expectCommand(commands, "admit", &contracts.cli.admit_required, &contracts.cli.admit_optional, &contracts.cli.admit_repeated_required, &contracts.cli.admit_repeated_optional);
    const exits = try c.exactFields(root.get("exit_contract") orelse return error.MissingGolden, &golden_fields.exit_contract);
    try expectLiteral(exits, "success_stdout", contracts.success_stdout);
    try expectLiteral(exits, "refusal_stderr", contracts.refusal_stderr);
    try expectLiteral(exits, "refusal_stdout", "");
    try expectExitMap(exits, "help_exit", 0);
    try expectExitMap(exits, "malformed_exit", 2);
    try expectInt(exits, "success_exit", @as(u8, 0));
    try expectInt(exits, "refusal_exit", @as(u8, 1));
    try expectBool(exits, "validator_probe_streams_public", false);
}

fn expectCommand(commands: std.json.ObjectMap, name: []const u8, required: []const []const u8, optional: []const []const u8, repeated_required: []const []const u8, repeated_optional: []const []const u8) !void {
    const m = try c.exactFields(commands.get(name) orelse return error.MissingGolden, &golden_fields.command);
    try expectStringArray(m, "required", required);
    try expectStringArray(m, "optional", optional);
    try expectStringArray(m, "repeated_required", repeated_required);
    try expectStringArray(m, "repeated_optional", repeated_optional);
    const groups = [_][]const []const u8{ required, optional, repeated_required, repeated_optional };
    const options = try array(m.get("options") orelse return error.MissingGolden);
    const count = required.len + optional.len + repeated_required.len + repeated_optional.len;
    if (options.len != count or count > 64) return error.UnexpectedOptions;
    var seen = [_]bool{false} ** 64;
    for (options) |option| {
        const object = try c.exactFields(option, &contracts.cli.option_fields);
        const flags = try array(object.get("flags").?);
        if (flags.len != 1) return error.UnexpectedOptions;
        const flag = try c.string(flags[0]);
        var offset: usize = 0;
        var found = false;
        for (groups, 0..) |group, group_index| {
            for (group, 0..) |expected, index| {
                if (!std.mem.eql(u8, flag, expected)) continue;
                if (seen[offset + index]) return error.DuplicateOption;
                seen[offset + index] = true;
                found = true;
                try expectBool(object, "required", group_index == 0 or group_index == 2);
                try expectBool(object, "repeated", group_index >= 2);
            }
            offset += group.len;
        }
        if (!found) return error.UnexpectedOption;
        const dest = try c.string(object.get("dest").?);
        if (dest.len != flag.len - 2) return error.UnexpectedLiteral;
        for (flag[2..], dest) |letter, actual| {
            if (actual != (if (letter == '-') @as(u8, '_') else letter)) return error.UnexpectedLiteral;
        }
        if (contains(flag, &contracts.cli.integer_flags)) {
            try expectLiteral(object, "type", "int");
        } else if (contains(flag, &contracts.cli.text_flags)) {
            if (object.get("type").? != .null) return error.ExpectedNull;
        } else {
            try expectLiteral(object, "type", "Path");
        }
        try expectStringArray(object, "choices", if (std.mem.eql(u8, flag, "--decision")) &contracts.cli.decision_choices else &.{});
    }
}

fn expectExitMap(map: std.json.ObjectMap, key: []const u8, expected: u8) !void {
    const exits = try c.exactFields(map.get(key) orelse return error.MissingGolden, &contracts.cli.commands);
    for (contracts.cli.commands) |command| try expectInt(exits, command, expected);
}

fn expectResources(value: std.json.Value) !void {
    const resources = try c.exactFields(value, &contracts.schema_fields.resources);
    try expectInt(resources, "vm_count", contracts.policy.resources.vm_count);
    try expectInt(resources, "os_disk_count", contracts.policy.resources.os_disk_count);
    try expectInt(resources, "data_disk_count", contracts.policy.resources.data_disk_count);
    try expectInt(resources, "public_ip_count", contracts.policy.resources.public_ip_count);
    try expectInt(resources, "boot_count", contracts.policy.resources.boot_count);
    try expectInt(resources, "maximum_parallelism", contracts.policy.resources.maximum_parallelism);
    try expectInt(resources, "generation", contracts.policy.resources.generation);
    try expectLiteral(resources, "os_disk_sku", contracts.policy.resources.os_disk_sku);
    try expectInt(resources, "os_disk_capacity_bytes", contracts.policy.resources.os_disk_capacity_bytes);
    try expectLiteral(resources, "network", contracts.policy.resources.network);
}

fn expectSubstitution(value: std.json.Value) !void {
    const substitution = try c.exactFields(value, &contracts.schema_fields.substitution);
    try expectBool(substitution, "source", contracts.policy.substitution.source);
    try expectBool(substitution, "image", contracts.policy.substitution.image);
    try expectBool(substitution, "topology", contracts.policy.substitution.topology);
    try expectBool(substitution, "workload", contracts.policy.substitution.workload);
}

fn expectCleanup(value: std.json.Value) !void {
    const cleanup = try c.exactFields(value, &contracts.schema_fields.cleanup);
    try expectBool(cleanup, "exact_owned_resources_only", contracts.policy.cleanup.exact_owned_resources_only);
    try expectBool(cleanup, "delete_owned_resource_group", contracts.policy.cleanup.delete_owned_resource_group);
    try expectBool(cleanup, "independent_absence_observation", contracts.policy.cleanup.independent_absence_observation);
    try expectBool(cleanup, "replacement_resources", contracts.policy.cleanup.replacement_resources);
}

fn expectPolicy(value: std.json.Value) !void {
    const root = try c.exactFields(value, &golden_fields.policy_root);
    try expectLiteral(root, "purpose", contracts.policy.purpose);
    try expectLiteral(root, "profile", contracts.policy.profile);
    try expectLiteral(root, "authority_before_admission", contracts.policy.not_admitted);
    try expectLiteral(root, "authority_after_admission", contracts.policy.approved);
    try expectLiteral(root, "location", contracts.policy.location);
    try expectLiteral(root, "vm_size", contracts.policy.vm_size);
    try expectLiteral(root, "serial_mode", contracts.policy.serial_mode);
    try expectInt(root, "runtime_seconds", contracts.policy.runtime_seconds);
    try expectInt(root, "cleanup_seconds", contracts.policy.cleanup_seconds);
    try expectInt(root, "operation_seconds", contracts.policy.operation_seconds);
    try expectInt(root, "poll_seconds", contracts.policy.poll_seconds);
    try expectInt(root, "fixed_vhd_bytes", contracts.policy.fixed_vhd_bytes);
    try expectInt(root, "fixed_vhd_capacity_bytes", contracts.policy.fixed_vhd_capacity_bytes);
    try expectInt(root, "retry_count", contracts.policy.retry_count);
    try expectResources(root.get("resources") orelse return error.MissingGolden);
    try expectSubstitution(root.get("substitution") orelse return error.MissingGolden);
    try expectCleanup(root.get("cleanup") orelse return error.MissingGolden);
    const cost = try c.exactFields(root.get("cost") orelse return error.MissingGolden, &golden_fields.cost_policy);
    try expectLiteral(cost, "unit", contracts.policy.cost_unit);
    try expectLiteral(cost, "policy", contracts.policy.cost_policy);
    try expectInt(cost, "fixed_overhead_microusd", contracts.policy.fixed_overhead_microusd);
    try expectInt(cost, "vm_hour_microusd", contracts.policy.vm_hour_microusd);
    try expectInt(cost, "os_disk_hour_microusd", contracts.policy.os_disk_hour_microusd);
    try expectInt(cost, "estimated_upper_bound", contracts.policy.estimated_cost_upper_bound_microusd);
    try expectInt(cost, "repository_policy_maximum", contracts.policy.repository_maximum_cost_microusd);
    try expectInt(cost, "maximum_authorized_minimum", contracts.policy.estimated_cost_upper_bound_microusd);
    try expectInt(cost, "maximum_authorized_maximum", contracts.policy.repository_maximum_cost_microusd);
}

fn expectAzureRuntime(value: std.json.Value) !void {
    const root = try c.exactFields(value, &golden_fields.azure_runtime);
    try expectCommandTable(root.get("commands") orelse return error.MissingGolden);
    try expectIsolation(root.get("isolation") orelse return error.MissingGolden);
    const m = try c.exactFields(root.get("manifest") orelse return error.MissingGolden, &golden_fields.manifest);
    try expectLiteral(m, "header", contracts.manifest.header);
    try expectManifestLine(try c.string(m.get("directory") orelse return error.MissingGolden), "D", null);
    try expectManifestLine(try c.string(m.get("file") orelse return error.MissingGolden), "F", "launcher");
    try expectManifestLine(try c.string(m.get("loader") orelse return error.MissingGolden), "L", contracts.manifest.loader_role);
    try expectManifestLine(try c.string(m.get("parent") orelse return error.MissingGolden), "P", null);
    _ = try c.string(m.get("sample") orelse return error.MissingGolden);
}

fn expectSchemas(value: std.json.Value) !void {
    const domains = comptime blk: {
        const declarations = std.meta.declarations(contracts.schema_fields);
        var names: [declarations.len][]const u8 = undefined;
        for (declarations, 0..) |decl, index| names[index] = decl.name;
        break :blk names;
    };
    const m = try c.exactFields(value, &domains);
    inline for (comptime std.meta.declarations(contracts.schema_fields)) |decl| {
        const expected = &@field(contracts.schema_fields, decl.name);
        const items = try array(m.get(decl.name) orelse return error.MissingGolden);
        try std.testing.expectEqual(expected.len, items.len);
        var previous: []const u8 = "";
        for (items) |item| {
            const name = try c.string(item);
            try std.testing.expect(std.mem.lessThan(u8, previous, name));
            previous = name;
            var found = false;
            for (expected) |field| {
                if (std.mem.eql(u8, name, field)) found = true;
            }
            try std.testing.expect(found);
        }
    }
}

fn expectCanonicalRecords(value: std.json.Value) !void {
    const records = try c.exactFields(value, &golden_fields.records);
    const plan_bytes = try expectRecord(records, "plan", "plan", "uk.wamr.azure-execution-plan", 2);
    const template_bytes = try expectRecord(records, "approval_template", "approval_template", "uk.wamr.azure-execution-approval-template", 2);
    _ = try expectRecord(records, "azure_runtime", "azure_runtime", "uk.wamr.azure-cli-runtime-closure", 1);
    _ = try expectRecord(records, "authorization_approved", "authorization", "uk.wamr.azure-execution-authorization", 2);
    _ = try expectRecord(records, "authorization_denied", "authorization", "uk.wamr.azure-execution-authorization", 2);
    _ = try expectRecord(records, "admission", "admission", "uk.wamr.azure-execution-admission", 2);
    var digest: [32]u8 = undefined;
    core.Sha256.hash(plan_bytes, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    var template = try contracts.parseCanonical(std.testing.allocator, template_bytes);
    defer template.deinit();
    const fields = template.value().object;
    try expectLiteral(fields, "plan_sha256", &hex);
}

fn expectUuid(root: std.json.ObjectMap) !void {
    const items = try array(root.get("uuid_normalization") orelse return error.MissingGolden);
    try std.testing.expectEqual(contracts.uuid.normalization_inputs.len, items.len);
    for (items, 0..) |item, index| {
        const m = try c.exactFields(item, &golden_fields.uuid_normalization);
        try expectLiteral(m, "input", contracts.uuid.normalization_inputs[index]);
        try expectLiteral(m, "normalized", contracts.uuid.normalization_outputs[index]);
    }
    const rejected = try array(root.get("uuid_rejection") orelse return error.MissingGolden);
    try std.testing.expectEqual(contracts.uuid.rejection_fields.len * contracts.uuid.rejection_inputs.len, rejected.len);
    for (contracts.uuid.rejection_fields, 0..) |field, field_index| {
        for (contracts.uuid.rejection_inputs, 0..) |input, input_index| {
            const m = try c.exactFields(rejected[field_index * contracts.uuid.rejection_inputs.len + input_index], &golden_fields.uuid_rejection);
            try expectLiteral(m, "field", field);
            try expectLiteral(m, "input", input);
            try expectBool(m, "refused", true);
            try expectLiteral(m, "reason", "canonical plan UUID required");
            try expectBool(m, "output_file_appeared", false);
        }
    }
    const generated = try c.exactFields(root.get("generated_ids") orelse return error.MissingGolden, &golden_fields.generated_ids);
    try expectLiteral(generated, "attempt_id", contracts.uuid.generated_attempt_id);
    try expectLiteral(generated, "ledger_id", contracts.uuid.generated_ledger_id);
}

fn expectRuntimeBounds(value: std.json.Value) !void {
    const items = try array(value);
    const names = [_][]const u8{ "files", "directories", "bytes", "directory_depth", "file_depth", "scan_files", "scan_directories", "scan_bytes", "scan_depth", "file_bytes", "loader_files", "manifest_bytes" };
    const limits = [_]u64{
        contracts.limits.runtime_files,
        contracts.limits.runtime_directories,
        contracts.limits.runtime_bytes,
        contracts.limits.runtime_depth,
        contracts.limits.runtime_depth,
        contracts.limits.runtime_files,
        contracts.limits.runtime_directories,
        contracts.limits.runtime_bytes,
        contracts.limits.runtime_depth,
        contracts.limits.runtime_file_bytes,
        contracts.limits.runtime_loader_files,
        contracts.limits.runtime_manifest_bytes,
    };
    try std.testing.expectEqual(names.len, items.len);
    for (items, names, limits) |item, name, limit| {
        const m = try c.exactFields(item, &golden_fields.runtime_bound);
        try expectLiteral(m, "name", name);
        try expectInt(m, "limit", limit);
        try expectBool(m, "accepted_at_limit", true);
        try expectBool(m, "refused_above_limit", true);
        _ = try c.string(m.get("reason") orelse return error.MissingGolden);
    }
}

fn expectLiveRefusals(value: std.json.Value) !void {
    const items = try array(value);
    try std.testing.expect(items.len >= 16);
    for (items) |item| {
        const m = try c.exactFields(item, &golden_fields.live_refusal);
        try expectBool(m, "refused", true);
        try expectLiteral(m, "exception", "wamr_native_ci.Refusal");
        try expectBool(m, "output_file_appeared", false);
        _ = try c.string(m.get("name") orelse return error.MissingGolden);
        _ = try c.string(m.get("reason") orelse return error.MissingGolden);
        if ((m.get("outputs") orelse return error.MissingGolden) != .object) return error.ExpectedObject;
    }
}

fn expectRecord(records: std.json.ObjectMap, key: []const u8, comptime domain: []const u8, schema: []const u8, version: u8) ![]const u8 {
    const bytes = try c.string(records.get(key) orelse return error.MissingGolden);
    var document = try contracts.parseCanonical(std.testing.allocator, bytes);
    defer document.deinit();
    try expectRecordObject(domain, document.value());
    const m = document.value().object;
    try expectLiteral(m, "schema", schema);
    try expectInt(m, "version", version);
    if (std.mem.eql(u8, key, "approval_template")) try expectLiteral(m, "decision", "pending");
    if (std.mem.eql(u8, key, "authorization_approved")) try expectLiteral(m, "decision", "approved");
    if (std.mem.eql(u8, key, "authorization_denied")) try expectLiteral(m, "decision", "denied");
    return bytes;
}

fn expectRecordObject(comptime domain: []const u8, value: std.json.Value) anyerror!void {
    @setEvalBranchQuota(20_000);
    if (comptime std.mem.eql(u8, domain, "resources")) return expectResources(value);
    if (comptime std.mem.eql(u8, domain, "substitution")) return expectSubstitution(value);
    if (comptime std.mem.eql(u8, domain, "cleanup")) return expectCleanup(value);
    if (comptime std.mem.eql(u8, domain, "azure_runtime_isolation")) return expectIsolation(value);
    const fields = comptime @field(contracts.schema_fields, domain);
    const m = try c.exactFields(value, &fields);
    inline for (fields) |key| {
        const child = m.get(key).?;
        if (comptime std.mem.eql(u8, domain, "tools") or contains(key, &.{ "candidate", "bundle", "public_bundle", "transport", "qcow2", "os_vhd", "azure_runtime_document", "plan", "authorization", "launcher", "interpreter", "dynamic_loader", "manifest" })) {
            try expectRecordObject("artifact", child);
        } else if (comptime std.mem.eql(u8, key, "azure_runtime")) {
            try expectRecordObject(if (comptime contains(domain, &.{ "approval_template", "authorization" })) "azure_runtime_approval" else "azure_runtime", child);
        } else if (comptime std.mem.eql(u8, key, "limits")) {
            try expectRecordObject(if (comptime contains(domain, &.{ "azure_runtime", "azure_runtime_approval" })) "azure_runtime_limits" else "approval_limits", child);
        } else if (comptime std.mem.eql(u8, key, "observed")) {
            try expectRecordObject("azure_runtime_observed", child);
        } else if (comptime std.mem.eql(u8, key, "isolation")) {
            try expectRecordObject("azure_runtime_isolation", child);
        } else if (comptime std.mem.eql(u8, key, "directory")) {
            try expectRecordObject("ledger_directory", child);
        } else if (comptime std.mem.eql(u8, key, "approval")) {
            try expectRecordObject("admission_approval", child);
        } else if (comptime contains(key, &.{ "ledger", "run", "identity", "lineage", "resources", "substitution", "cleanup", "cost", "tools" })) {
            try expectRecordObject(key, child);
        } else if (comptime std.mem.eql(u8, key, "commands")) {
            try expectCommandTable(child);
        } else if (comptime std.mem.eql(u8, key, "loader_dependencies")) {
            for (try array(child)) |artifact| try expectRecordObject("artifact", artifact);
        } else if (comptime contains(key, &.{ "initialization_required", "ledger_initialization_required" })) {
            if (child != .bool) return error.ExpectedBoolean;
        } else if (comptime std.mem.eql(u8, domain, "ledger_directory") and contains(key, &.{ "device_major", "device_minor", "uid" })) {
            _ = try c.integer(u32, child);
        } else if (comptime std.mem.eql(u8, domain, "ledger_directory") and std.mem.eql(u8, key, "mode")) {
            _ = try c.integer(u16, child);
        } else if (comptime std.mem.eql(u8, key, "version")) {
            _ = try c.integer(u8, child);
        } else if (comptime contains(domain, &.{ "azure_runtime_limits", "azure_runtime_observed", "approval_limits" }) or contains(key, &.{ "size", "created_unix", "runtime_seconds", "cleanup_seconds", "operation_seconds", "poll_seconds", "vhd_bytes", "vhd_capacity_bytes", "retry_count", "estimated_upper_bound", "maximum_authorized", "repository_policy_maximum", "estimated_cost_upper_bound_microusd", "maximum_authorized_cost_microusd", "recorded_unix", "expires_unix", "approved_unix", "inode" })) {
            _ = try c.integer(u64, child);
        } else {
            const text = try c.string(child);
            if (comptime std.mem.eql(u8, key, "sha256") or std.mem.endsWith(u8, key, "_sha256")) _ = try c.parseSha256(text);
            if (comptime contains(key, &.{ "attempt_id", "campaign_id", "ledger_id", "subscription" })) _ = try c.parseUuid(text);
        }
    }
    if (comptime contains(domain, &.{ "azure_runtime", "azure_runtime_approval" })) {
        try expectLiteral(m, "schema", "uk.wamr.azure-cli-runtime-closure");
        try expectInt(m, "version", @as(u8, 1));
        try expectLiteral(m, "canonicalization", contracts.canonicalization);
    } else if (comptime std.mem.eql(u8, domain, "ledger")) {
        try expectLiteral(m, "schema", "uk.wamr.azure-campaign-ledger-binding");
        try expectInt(m, "version", @as(u8, 1));
        try expectLiteral(m, "purpose", contracts.policy.purpose);
    } else if (comptime std.mem.eql(u8, domain, "azure_runtime_limits")) {
        try expectInt(m, "files", contracts.limits.runtime_files);
        try expectInt(m, "directories", contracts.limits.runtime_directories);
        try expectInt(m, "bytes", contracts.limits.runtime_bytes);
        try expectInt(m, "depth", contracts.limits.runtime_depth);
        try expectInt(m, "file_bytes", contracts.limits.runtime_file_bytes);
        try expectInt(m, "loader_files", contracts.limits.runtime_loader_files);
    } else if (comptime std.mem.eql(u8, domain, "azure_runtime_observed")) {
        inline for (contracts.schema_fields.azure_runtime_observed) |key| {
            const maximum = comptime @field(contracts.limits, "runtime_" ++ key);
            if (try c.integer(u64, m.get(key).?) > maximum) return error.RuntimeLimitExceeded;
        }
    } else if (comptime std.mem.eql(u8, domain, "approval_limits")) {
        try expectInt(m, "runtime_seconds", contracts.policy.runtime_seconds);
        try expectInt(m, "cleanup_seconds", contracts.policy.cleanup_seconds);
        try expectInt(m, "operation_seconds", contracts.policy.operation_seconds);
        try expectInt(m, "maximum_parallelism", contracts.policy.resources.maximum_parallelism);
        try expectInt(m, "boot_count", contracts.policy.resources.boot_count);
        try expectInt(m, "retry_count", contracts.policy.retry_count);
    } else if (comptime std.mem.eql(u8, domain, "cost")) {
        try expectLiteral(m, "unit", contracts.policy.cost_unit);
        try expectLiteral(m, "policy", contracts.policy.cost_policy);
        try expectInt(m, "estimated_upper_bound", contracts.policy.estimated_cost_upper_bound_microusd);
        try expectInt(m, "repository_policy_maximum", contracts.policy.repository_maximum_cost_microusd);
        try expectAuthorizedCost(m, "maximum_authorized");
    } else if (comptime contains(domain, &.{ "plan", "admission" })) {
        inline for ([_][]const u8{ "purpose", "profile", "location", "vm_size", "serial_mode" }) |key| {
            try expectLiteral(m, key, @field(contracts.policy, key));
        }
        try expectLiteral(m, "campaign_profile", contracts.policy.profile);
        try expectLiteral(m, "canonicalization", contracts.canonicalization);
        try expectLiteral(m, "authority", if (comptime std.mem.eql(u8, domain, "plan")) contracts.policy.not_admitted else contracts.policy.approved);
        inline for ([_][]const u8{ "runtime_seconds", "cleanup_seconds", "operation_seconds", "poll_seconds", "retry_count" }) |key| {
            try expectInt(m, key, @field(contracts.policy, key));
        }
        try expectInt(m, "vhd_bytes", contracts.policy.fixed_vhd_bytes);
        try expectInt(m, "vhd_capacity_bytes", contracts.policy.fixed_vhd_capacity_bytes);
        if (try c.integer(u64, m.get("created_unix").?) == 0) return error.InvalidCreationTime;
    } else if (comptime contains(domain, &.{ "approval_template", "authorization" })) {
        try expectInt(m, "estimated_cost_upper_bound_microusd", contracts.policy.estimated_cost_upper_bound_microusd);
        try expectAuthorizedCost(m, "maximum_authorized_cost_microusd");
    }
    if (comptime contains(domain, &.{ "authorization", "admission_approval" })) {
        if (!contracts.boundedAuthorityText(try c.string(m.get("approver").?), contracts.limits.approver_min_bytes, contracts.limits.approver_max_bytes)) return error.InvalidApprover;
        if (!contracts.boundedAuthorityText(try c.string(m.get("reference").?), contracts.limits.reference_min_bytes, contracts.limits.reference_max_bytes)) return error.InvalidReference;
        const start = if (comptime std.mem.eql(u8, domain, "authorization")) "recorded_unix" else "approved_unix";
        if (!contracts.validApprovalWindow(try c.integer(u64, m.get(start).?), try c.integer(u64, m.get("expires_unix").?))) return error.InvalidApprovalWindow;
    }
}

fn expectAuthorizedCost(map: std.json.ObjectMap, key: []const u8) !void {
    const amount = try c.integer(u64, map.get(key).?);
    if (amount < contracts.policy.estimated_cost_upper_bound_microusd or amount > contracts.policy.repository_maximum_cost_microusd) return error.InvalidAuthorizedCost;
}

fn expectCommandTable(value: std.json.Value) !void {
    const commands = try array(value);
    try std.testing.expectEqual(contracts.azure_commands.len, commands.len);
    for (commands, contracts.azure_commands) |actual, expected| {
        const words = try array(actual);
        try std.testing.expectEqual(expected.len, words.len);
        for (words, expected) |word, text| try std.testing.expectEqualStrings(text, try c.string(word));
    }
}

fn expectManifestLine(line: []const u8, tag: []const u8, role: ?[]const u8) !void {
    try std.testing.expect(std.mem.endsWith(u8, line, "\n"));
    var fields = std.mem.splitScalar(u8, std.mem.trimEnd(u8, line, "\n"), '\t');
    try std.testing.expectEqualStrings(tag, fields.next() orelse return error.InvalidManifest);
    if (std.mem.eql(u8, tag, "P")) {
        _ = fields.next() orelse return error.InvalidManifest;
        var count: usize = 0;
        while (fields.next()) |_| count += 1;
        try std.testing.expectEqual(@as(usize, 6), count);
        return;
    }
    const actual_role = fields.next() orelse return error.InvalidManifest;
    if (role) |expected| try std.testing.expectEqualStrings(expected, actual_role);
    _ = fields.next() orelse return error.InvalidManifest;
    var count: usize = 0;
    while (fields.next()) |_| count += 1;
    try std.testing.expectEqual(@as(usize, 13), count);
}

fn expectIsolation(value: std.json.Value) !void {
    const m = try c.exactFields(value, &contracts.schema_fields.azure_runtime_isolation);
    inline for (contracts.schema_fields.azure_runtime_isolation) |key| {
        try expectLiteral(m, key, @field(contracts.isolation, key));
    }
}

fn expectStringArray(map: std.json.ObjectMap, key: []const u8, expected: []const []const u8) !void {
    const items = try array(map.get(key) orelse return error.MissingGolden);
    try std.testing.expectEqual(expected.len, items.len);
    for (items, expected) |item, name| try std.testing.expectEqualStrings(name, try c.string(item));
}

fn expectLiteral(map: std.json.ObjectMap, key: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, expected, try c.string(map.get(key) orelse return error.MissingGolden))) return error.UnexpectedLiteral;
}

fn expectInt(map: std.json.ObjectMap, key: []const u8, expected: anytype) !void {
    if (expected != try c.integer(@TypeOf(expected), map.get(key) orelse return error.MissingGolden)) return error.UnexpectedInteger;
}

fn expectBool(map: std.json.ObjectMap, key: []const u8, expected: bool) !void {
    const actual = switch (map.get(key) orelse return error.MissingGolden) {
        .bool => |boolean| boolean,
        else => return error.ExpectedBoolean,
    };
    if (actual != expected) return error.UnexpectedBoolean;
}

fn array(value: std.json.Value) ![]const std.json.Value {
    return switch (value) {
        .array => |items| items.items,
        else => error.ExpectedArray,
    };
}

fn contains(value: []const u8, choices: []const []const u8) bool {
    for (choices) |choice| if (std.mem.eql(u8, value, choice)) return true;
    return false;
}
