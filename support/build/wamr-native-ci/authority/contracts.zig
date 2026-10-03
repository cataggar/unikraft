// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const c = core.contracts;

pub const canonicalization = "utf8-byte-sorted-keys-compact-lf-v1";
pub const success_stdout = "Compute private contract prepared; no Azure operations.\n";
pub const refusal_stderr = "Compute handoff refused at handoff; original local records are unchanged.\n";
pub const json_limits = c.Limits{ .bytes = 128 * 1024, .depth = 32, .string_bytes = 64 * 1024, .items = 4096, .tokens = 65536 };

pub const limits = struct {
    pub const runtime_files: u32 = 16_384;
    pub const runtime_directories: u32 = 4_096;
    pub const runtime_bytes: u64 = 2 * 1024 * 1024 * 1024;
    pub const runtime_depth: u8 = 32;
    pub const runtime_file_bytes: u64 = 256 * 1024 * 1024;
    pub const runtime_loader_files: u16 = 256;
    pub const runtime_manifest_bytes: u64 = 32 * 1024 * 1024;
    pub const approver_min_bytes: usize = 1;
    pub const approver_max_bytes: usize = 128;
    pub const reference_min_bytes: usize = 1;
    pub const reference_max_bytes: usize = 256;
    pub const authorization_window_seconds: u64 = 3600;
};

pub const policy = struct {
    pub const purpose = "qcow2-derived-vhd-two-boot";
    pub const profile = "qcow2-derived-vhd";
    pub const not_admitted = "not_admitted";
    pub const approved = "approved";
    pub const location = "northeurope";
    pub const vm_size = "Standard_D2s_v5";
    pub const serial_mode = "azure_cumulative";
    pub const runtime_seconds: u32 = 3600;
    pub const cleanup_seconds: u32 = 1800;
    pub const operation_seconds: u32 = 600;
    pub const poll_seconds: u32 = 10;
    pub const fixed_vhd_bytes: u64 = 66 * 1024 * 1024 + 512;
    pub const fixed_vhd_capacity_bytes: u64 = fixed_vhd_bytes - 512;
    pub const retry_count: u8 = 0;
    pub const cost_unit = "micro_usd";
    pub const cost_policy = "northeurope-standard-d2s-v5-conservative-2026-09-v1";
    pub const fixed_overhead_microusd: u64 = 5_000_000;
    pub const vm_hour_microusd: u64 = 2_000_000;
    pub const os_disk_hour_microusd: u64 = 250_000;
    pub const estimated_cost_upper_bound_microusd: u64 = 9_500_000;
    pub const repository_maximum_cost_microusd: u64 = 100_000_000;
    pub const resources = struct {
        pub const vm_count: u8 = 1;
        pub const os_disk_count: u8 = 1;
        pub const data_disk_count: u8 = 0;
        pub const public_ip_count: u8 = 0;
        pub const boot_count: u8 = 2;
        pub const maximum_parallelism: u8 = 1;
        pub const generation: u8 = 2;
        pub const os_disk_sku = "StandardSSD_LRS";
        pub const os_disk_capacity_bytes: u64 = fixed_vhd_capacity_bytes;
        pub const network = "private_no_default_outbound";
    };
    pub const substitution = struct {
        pub const source = false;
        pub const image = false;
        pub const topology = false;
        pub const workload = false;
    };
    pub const cleanup = struct {
        pub const exact_owned_resources_only = true;
        pub const delete_owned_resource_group = true;
        pub const independent_absence_observation = true;
        pub const replacement_resources = false;
    };
};

pub const uuid = struct {
    pub const normalization_inputs = [_][]const u8{
        "00000000000040008000000000000001",
        "{00000000-0000-4000-8000-000000000001}",
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-00000000000A",
        "urn:uuid:00000000-0000-4000-8000-00000000000A",
    };
    pub const normalization_outputs = [_][]const u8{
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-00000000000a",
        "00000000-0000-4000-8000-00000000000a",
    };
    pub const rejection_fields = [_][]const u8{ "attempt_id", "campaign_id", "ledger_id", "subscription" };
    pub const rejection_inputs = [_][]const u8{
        "",
        "0000000000000000000000000000000",
        "gggggggggggggggggggggggggggggggg",
        "00000000-0000-4000-8000-000000000001\n",
        "urn:uuid:not-a-uuid",
    };
    pub const generated_attempt_id = "00000000-0000-4000-8000-000000000101";
    pub const generated_ledger_id = "00000000-0000-4000-8000-000000000102";
};

pub const cli = struct {
    pub const commands = [_][]const u8{ "prepare-azure-runtime", "plan", "record-authorization", "admit" };
    pub const tool_flags = [_][]const u8{ "--azure", "--uploader", "--validator", "--supervisor", "--az-python", "--azure-runtime" };
    pub const prepare_required = [_][]const u8{ "--output", "--azure", "--az-python", "--stdlib", "--validator" };
    pub const prepare_optional = [_][]const u8{};
    pub const prepare_repeated_required = [_][]const u8{"--package-root"};
    pub const prepare_repeated_optional = [_][]const u8{ "--data-root", "--native-dependency" };
    pub const plan_required = [_][]const u8{ "--bundle", "--output", "--approval-template", "--candidate-output", "--campaign-id", "--ledger", "--subscription", "--prefix", "--maximum-authorized-cost-microusd", "--azure", "--uploader", "--validator", "--supervisor", "--az-python", "--azure-runtime" };
    pub const plan_optional = [_][]const u8{ "--attempt-id", "--ledger-id", "--created-unix" };
    pub const plan_repeated_required = [_][]const u8{};
    pub const plan_repeated_optional = [_][]const u8{};
    pub const authorize_required = [_][]const u8{ "--plan", "--template", "--output", "--decision", "--approver", "--reference", "--recorded-unix", "--expires-unix", "--azure", "--uploader", "--validator", "--supervisor", "--az-python", "--azure-runtime" };
    pub const authorize_optional = [_][]const u8{};
    pub const authorize_repeated_required = [_][]const u8{};
    pub const authorize_repeated_optional = [_][]const u8{};
    pub const admit_required = [_][]const u8{ "--plan", "--authorization", "--output", "--azure", "--uploader", "--validator", "--supervisor", "--az-python", "--azure-runtime" };
    pub const admit_optional = [_][]const u8{};
    pub const admit_repeated_required = [_][]const u8{};
    pub const admit_repeated_optional = [_][]const u8{};
    pub const decision_choices = [_][]const u8{ "approved", "denied" };
    pub const option_fields = [_][]const u8{ "flags", "dest", "type", "required", "repeated", "choices" };
    pub const integer_flags = [_][]const u8{ "--maximum-authorized-cost-microusd", "--created-unix", "--recorded-unix", "--expires-unix" };
    pub const text_flags = [_][]const u8{ "--campaign-id", "--subscription", "--prefix", "--attempt-id", "--ledger-id", "--decision", "--approver", "--reference" };
};

pub const isolation = struct {
    pub const python_home = "closure_root";
    pub const module_layout = "flat_python_home_v1";
    pub const extensions = "closure_empty";
    pub const dynamic_extension_install = "disabled";
    pub const user_site = "disabled";
    pub const site_import = "disabled";
    pub const bytecode_writes = "disabled";
    pub const path_environment = "forbidden";
    pub const startup_hooks = "forbidden";
    pub const loader_environment = "retained_readonly_root";
    pub const host_loader_fallback = "forbidden";
    pub const package_restore = "forbidden_after_custody";
};

pub const manifest = struct {
    pub const header = "UK-WAMR-AZURE-RUNTIME-CLOSURE\t1\n";
    pub const record_tags = [_][]const u8{ "D", "F", "L", "P" };
    pub const tree_roles = [_][]const u8{ "runtime", "launcher", "interpreter", "native-extension", "python-module", "fixed-data" };
    pub const loader_role = "loader-dependency";
};

pub const azure_commands = [_][]const []const u8{
    &.{"version"},
    &.{ "group", "exists" },
    &.{ "group", "create" },
    &.{ "group", "show" },
    &.{ "group", "delete" },
    &.{ "disk", "create" },
    &.{ "disk", "show" },
    &.{ "disk", "grant-access" },
    &.{ "disk", "revoke-access" },
    &.{ "deployment", "group", "create" },
    &.{ "vm", "deallocate" },
    &.{ "vm", "start" },
    &.{ "vm", "show" },
    &.{ "vm", "get-instance-view" },
    &.{ "vm", "boot-diagnostics", "get-boot-log" },
    &.{ "resource", "list" },
};

pub const schema_fields = struct {
    pub const artifact = [_][]const u8{ "path", "size", "sha256" };
    pub const azure_runtime = [_][]const u8{ "schema", "version", "canonicalization", "root", "python_version", "extensions", "launcher", "interpreter", "dynamic_loader", "manifest", "limits", "observed", "content_sha256", "metadata_sha256", "parents_sha256", "loader_dependencies", "commands", "isolation" };
    pub const azure_runtime_limits = [_][]const u8{ "files", "directories", "bytes", "depth", "file_bytes", "loader_files" };
    pub const azure_runtime_observed = [_][]const u8{ "files", "directories", "bytes", "depth", "loader_files" };
    pub const azure_runtime_isolation = [_][]const u8{ "python_home", "module_layout", "extensions", "dynamic_extension_install", "user_site", "site_import", "bytecode_writes", "path_environment", "startup_hooks", "loader_environment", "host_loader_fallback", "package_restore" };
    pub const ledger = [_][]const u8{ "schema", "version", "purpose", "campaign_id", "ledger_id", "directory", "initialization_required", "initial_state_sha256", "marker_sha256" };
    pub const ledger_directory = [_][]const u8{ "device_major", "device_minor", "inode", "uid", "mode" };
    pub const run = [_][]const u8{ "repository", "run_attempt", "run_id" };
    pub const identity = [_][]const u8{ "wamr_revision", "wasm_sha256", "cwasm_sha256", "runtime_sha256", "compiler_sha256", "config_sha256" };
    pub const lineage = [_][]const u8{ "accepted_qcow2_sha256", "derived_vhd_sha256", "final_inspection_sha256", "fixed_vhd_derivation_gate_sha256", "fixed_vhd_derivation_sha256", "qcow2_acceptance_sha256", "qcow2_finalization_sha256", "raw_sha256" };
    pub const resources = [_][]const u8{ "vm_count", "os_disk_count", "data_disk_count", "public_ip_count", "boot_count", "maximum_parallelism", "generation", "os_disk_sku", "os_disk_capacity_bytes", "network" };
    pub const substitution = [_][]const u8{ "source", "image", "topology", "workload" };
    pub const cleanup = [_][]const u8{ "exact_owned_resources_only", "delete_owned_resource_group", "independent_absence_observation", "replacement_resources" };
    pub const cost = [_][]const u8{ "unit", "policy", "estimated_upper_bound", "maximum_authorized", "repository_policy_maximum" };
    pub const tools = [_][]const u8{ "azure", "uploader", "validator", "supervisor", "az_python" };
    pub const azure_runtime_approval = [_][]const u8{ "schema", "version", "canonicalization", "document_sha256", "python_version", "manifest", "launcher", "interpreter", "dynamic_loader", "content_sha256", "metadata_sha256", "parents_sha256", "root", "extensions", "limits", "observed", "loader_dependencies", "commands", "isolation" };
    pub const approval_limits = [_][]const u8{ "runtime_seconds", "cleanup_seconds", "operation_seconds", "maximum_parallelism", "boot_count", "retry_count" };
    pub const plan = [_][]const u8{ "schema", "version", "purpose", "profile", "authority", "canonicalization", "created_unix", "attempt_id", "campaign_id", "campaign_profile", "ledger_path", "ledger", "subscription", "location", "prefix", "vm_size", "serial_mode", "runtime_seconds", "cleanup_seconds", "operation_seconds", "poll_seconds", "source_revision", "source_tree", "run", "identity", "lineage", "candidate", "bundle", "public_bundle", "transport", "qcow2", "os_vhd", "vhd_bytes", "vhd_capacity_bytes", "artifact_id", "inner_zip_sha256", "container_digest", "resources", "retry_count", "substitution", "cleanup", "cost", "tools", "azure_runtime_document", "azure_runtime" };
    pub const approval_template = [_][]const u8{ "schema", "version", "decision", "plan_sha256", "attempt_id", "campaign_id", "ledger_id", "ledger_initialization_required", "candidate_sha256", "estimated_cost_upper_bound_microusd", "maximum_authorized_cost_microusd", "limits", "azure_runtime" };
    pub const authorization = [_][]const u8{ "schema", "version", "decision", "plan_sha256", "attempt_id", "campaign_id", "ledger_id", "ledger_initialization_required", "candidate_sha256", "estimated_cost_upper_bound_microusd", "maximum_authorized_cost_microusd", "limits", "azure_runtime", "approver", "reference", "recorded_unix", "expires_unix" };
    pub const admission = [_][]const u8{ "artifact_id", "attempt_id", "azure_runtime", "azure_runtime_document", "bundle", "campaign_id", "campaign_profile", "candidate", "canonicalization", "cleanup", "cleanup_seconds", "container_digest", "cost", "created_unix", "identity", "inner_zip_sha256", "ledger", "ledger_path", "lineage", "location", "operation_seconds", "os_vhd", "poll_seconds", "prefix", "profile", "public_bundle", "purpose", "qcow2", "resources", "retry_count", "run", "runtime_seconds", "serial_mode", "source_revision", "source_tree", "subscription", "substitution", "tools", "transport", "vhd_bytes", "vhd_capacity_bytes", "vm_size", "schema", "version", "authority", "plan", "authorization", "approval" };
    pub const admission_approval = [_][]const u8{ "approver", "reference", "approved_unix", "expires_unix" };
};

pub fn parseCanonical(allocator: std.mem.Allocator, bytes: []const u8) !c.Document {
    var document = try c.Document.parse(allocator, bytes, json_limits);
    errdefer document.deinit();
    try document.requireCanonical(allocator, bytes);
    return document;
}

pub fn recomputeCost(vm_count: u64, os_disk_count: u64, runtime_seconds: u64, cleanup_seconds: u64) !u64 {
    const hours = (try std.math.add(u64, try std.math.add(u64, runtime_seconds, cleanup_seconds), 3599)) / 3600;
    const hourly = try std.math.add(u64, try std.math.mul(u64, vm_count, policy.vm_hour_microusd), try std.math.mul(u64, os_disk_count, policy.os_disk_hour_microusd));
    return std.math.add(u64, policy.fixed_overhead_microusd, try std.math.mul(u64, hours, hourly));
}

pub fn boundedAuthorityText(value: []const u8, minimum: usize, maximum: usize) bool {
    if (value.len < minimum or value.len > maximum) return false;
    for (value) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    return true;
}

pub fn validApprovalWindow(recorded_unix: u64, expires_unix: u64) bool {
    return recorded_unix > 0 and expires_unix > recorded_unix and expires_unix - recorded_unix <= limits.authorization_window_seconds;
}
