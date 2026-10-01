// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const c = core.contracts;
const authority = @import("root.zig");
const contracts = authority.contracts;

const golden = @embedFile("goldens/contracts.json");
const scenarios = @embedFile("goldens/python-scenarios.json");

const golden_fields = struct {
    pub const root = [_][]const u8{ "schema", "schema_version", "authority_domain", "canonicalization", "cli", "limits", "policy", "azure_runtime", "schemas", "canonical_records", "uuid_normalization", "generated_ids", "live_success_scenarios", "live_refusal_scenarios" };
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
    pub const generated_ids = [_][]const u8{ "attempt_id", "ledger_id" };
    pub const live_refusal = [_][]const u8{ "name", "refused", "exception", "reason", "output_file_appeared", "outputs" };
};

test "Python authority golden is canonical and matches native literal tables" {
    var document = try contracts.parseCanonical(std.testing.allocator, golden);
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
    try expectInt(root, "count", @as(u16, 172));
    const items = (root.get("scenarios") orelse return error.MissingGolden).array.items;
    try std.testing.expectEqual(@as(usize, 172), items.len);
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
    try std.testing.expect(!(exits.get("validator_probe_streams_public") orelse return error.MissingGolden).bool);
}

fn expectCommand(commands: std.json.ObjectMap, name: []const u8, required: []const []const u8, optional: []const []const u8, repeated_required: []const []const u8, repeated_optional: []const []const u8) !void {
    const m = try c.exactFields(commands.get(name) orelse return error.MissingGolden, &golden_fields.command);
    try expectStringArray(m, "required", required);
    try expectStringArray(m, "optional", optional);
    try expectStringArray(m, "repeated_required", repeated_required);
    try expectStringArray(m, "repeated_optional", repeated_optional);
    if (std.mem.eql(u8, name, "record-authorization")) {
        const options = (m.get("options") orelse return error.MissingGolden).array.items;
        var found = false;
        for (options) |option| {
            const object = option.object;
            const flags = (object.get("flags") orelse continue).array.items;
            if (flags.len > 0 and std.mem.eql(u8, try c.string(flags[0]), "--decision")) {
                try expectStringArray(object, "choices", &contracts.cli.decision_choices);
                found = true;
            }
        }
        try std.testing.expect(found);
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
    try expectStringObject(root.get("isolation") orelse return error.MissingGolden, &contracts.schema_fields.azure_runtime_isolation);
    const m = try c.exactFields(root.get("manifest") orelse return error.MissingGolden, &golden_fields.manifest);
    try expectLiteral(m, "header", contracts.manifest.header);
    try expectManifestLine(try c.string(m.get("directory") orelse return error.MissingGolden), "D", null);
    try expectManifestLine(try c.string(m.get("file") orelse return error.MissingGolden), "F", "launcher");
    try expectManifestLine(try c.string(m.get("loader") orelse return error.MissingGolden), "L", contracts.manifest.loader_role);
    try expectManifestLine(try c.string(m.get("parent") orelse return error.MissingGolden), "P", null);
}

fn expectSchemas(value: std.json.Value) !void {
    const m = value.object;
    inline for (comptime std.meta.declarations(contracts.schema_fields)) |decl| {
        try expectStringArray(m, decl.name, &@field(contracts.schema_fields, decl.name));
    }
}

fn expectCanonicalRecords(value: std.json.Value) !void {
    const records = try c.exactFields(value, &golden_fields.records);
    const plan_bytes = try expectRecord(records, "plan", &contracts.schema_fields.plan, "uk.wamr.azure-execution-plan");
    const template_bytes = try expectRecord(records, "approval_template", &contracts.schema_fields.approval_template, "uk.wamr.azure-execution-approval-template");
    _ = try expectRecord(records, "azure_runtime", &contracts.schema_fields.azure_runtime, "uk.wamr.azure-cli-runtime-closure");
    _ = try expectRecord(records, "authorization_approved", &contracts.schema_fields.authorization, "uk.wamr.azure-execution-authorization");
    _ = try expectRecord(records, "authorization_denied", &contracts.schema_fields.authorization, "uk.wamr.azure-execution-authorization");
    _ = try expectRecord(records, "admission", &contracts.schema_fields.admission, "uk.wamr.azure-execution-admission");
    var digest: [32]u8 = undefined;
    core.Sha256.hash(plan_bytes, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    var template = try contracts.parseCanonical(std.testing.allocator, template_bytes);
    defer template.deinit();
    const fields = template.value().object;
    try expectLiteral(fields, "plan_sha256", &hex);
}

fn expectUuid(root: std.json.ObjectMap) !void {
    const items = (root.get("uuid_normalization") orelse return error.MissingGolden).array.items;
    try std.testing.expectEqual(contracts.uuid.normalization_inputs.len, items.len);
    for (items, 0..) |item, index| {
        const m = try c.exactFields(item, &golden_fields.uuid_normalization);
        try expectLiteral(m, "input", contracts.uuid.normalization_inputs[index]);
        try expectLiteral(m, "normalized", contracts.uuid.normalization_outputs[index]);
    }
    const generated = try c.exactFields(root.get("generated_ids") orelse return error.MissingGolden, &golden_fields.generated_ids);
    try expectLiteral(generated, "attempt_id", contracts.uuid.generated_attempt_id);
    try expectLiteral(generated, "ledger_id", contracts.uuid.generated_ledger_id);
}

fn expectLiveRefusals(value: std.json.Value) !void {
    const items = value.array.items;
    try std.testing.expect(items.len >= 16);
    for (items) |item| {
        const m = try c.exactFields(item, &golden_fields.live_refusal);
        try expectBool(m, "refused", true);
        try expectLiteral(m, "exception", "wamr_native_ci.Refusal");
        try expectBool(m, "output_file_appeared", false);
        _ = try c.string(m.get("name") orelse return error.MissingGolden);
        _ = try c.string(m.get("reason") orelse return error.MissingGolden);
        _ = (m.get("outputs") orelse return error.MissingGolden).object;
    }
}

fn expectRecord(records: std.json.ObjectMap, key: []const u8, fields: []const []const u8, schema: []const u8) ![]const u8 {
    const bytes = try c.string(records.get(key) orelse return error.MissingGolden);
    var document = try contracts.parseCanonical(std.testing.allocator, bytes);
    defer document.deinit();
    const m = try c.exactFields(document.value(), fields);
    try expectLiteral(m, "schema", schema);
    if (std.mem.eql(u8, key, "authorization_approved")) try expectLiteral(m, "decision", "approved");
    if (std.mem.eql(u8, key, "authorization_denied")) try expectLiteral(m, "decision", "denied");
    return bytes;
}

fn expectCommandTable(value: std.json.Value) !void {
    const commands = value.array.items;
    try std.testing.expectEqual(contracts.azure_commands.len, commands.len);
    for (commands, contracts.azure_commands) |actual, expected| {
        const words = actual.array.items;
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

fn expectStringObject(value: std.json.Value, keys: []const []const u8) !void {
    const m = try c.exactFields(value, keys);
    for (keys) |key| _ = try c.string(m.get(key) orelse return error.MissingGolden);
}

fn expectStringArray(map: std.json.ObjectMap, key: []const u8, expected: []const []const u8) !void {
    const items = (map.get(key) orelse return error.MissingGolden).array.items;
    try std.testing.expectEqual(expected.len, items.len);
    for (items, expected) |item, name| try std.testing.expectEqualStrings(name, try c.string(item));
}

fn expectLiteral(map: std.json.ObjectMap, key: []const u8, expected: []const u8) !void {
    try std.testing.expectEqualStrings(expected, try c.string(map.get(key) orelse return error.MissingGolden));
}

fn expectInt(map: std.json.ObjectMap, key: []const u8, expected: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(expected), expected), try c.integer(@TypeOf(expected), map.get(key) orelse return error.MissingGolden));
}

fn expectBool(map: std.json.ObjectMap, key: []const u8, expected: bool) !void {
    try std.testing.expectEqual(expected, (map.get(key) orelse return error.MissingGolden).bool);
}
