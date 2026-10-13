// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
pub const compute = @import("wamr_direct_compute");
pub const runtime = compute.azure_runtime_contract;
pub const Artifact = compute.Artifact;
pub const Plan = compute.Plan;
pub const ApprovalTemplate = compute.ApprovalTemplate;
pub const Authorization = compute.Authorization;
pub const Admission = compute.Admission;
pub const Decision = @TypeOf(@as(Authorization, undefined).decision);
pub const Integer = i128;

pub const ToolPaths = struct {
    azure: []const u8 = "",
    uploader: []const u8 = "",
    validator: []const u8 = "",
    supervisor: []const u8 = "",
    az_python: []const u8 = "",
    azure_runtime: []const u8 = "",
};
pub const PrepareRuntime = struct {
    output: []const u8 = "",
    azure: []const u8 = "",
    az_python: []const u8 = "",
    stdlib: []const u8 = "",
    validator: []const u8 = "",
    package_root: []const []const u8 = &.{},
    data_root: []const []const u8 = &.{},
    native_dependency: []const []const u8 = &.{},
};
pub const PlanCommand = struct {
    bundle: []const u8 = "",
    output: []const u8 = "",
    approval_template: []const u8 = "",
    candidate_output: []const u8 = "",
    campaign_id: []const u8 = "",
    ledger: []const u8 = "",
    subscription: []const u8 = "",
    prefix: []const u8 = "",
    maximum_authorized_cost_microusd: Integer = 0,
    attempt_id: ?[]const u8 = null,
    ledger_id: ?[]const u8 = null,
    created_unix: ?Integer = null,
    tools: ToolPaths = .{},
};
pub const AuthorizationCommand = struct {
    plan: []const u8 = "",
    template: []const u8 = "",
    output: []const u8 = "",
    decision: Decision = .denied,
    approver: []const u8 = "",
    reference: []const u8 = "",
    recorded_unix: Integer = 0,
    expires_unix: Integer = 0,
    tools: ToolPaths = .{},
};
pub const AdmitCommand = struct {
    plan: []const u8 = "",
    authorization: []const u8 = "",
    output: []const u8 = "",
    tools: ToolPaths = .{},
};
pub const Command = union(enum) {
    @"prepare-azure-runtime": PrepareRuntime,
    plan: PlanCommand,
    @"record-authorization": AuthorizationCommand,
    admit: AdmitCommand,
};
pub const Phase = enum { inputs, custody, validation, construction, freshness, publication, final_revalidation };
pub const Exit = enum(u8) { success = 0, refused = 1, malformed = 2 };
pub const Transition = struct {
    command: std.meta.Tag(Command),
    phase: Phase,
    publication: core.private_files.CommitStatus = .not_committed,
    failures: core.diagnostics.Failures = .{},
};
pub const Diagnostic = struct {
    phase: Phase,
    err: anyerror,
    publication: core.private_files.CommitStatus = .not_committed,
    failures: core.diagnostics.Failures = .{},
};
pub fn Outcome(comptime T: type) type {
    return union(enum) { success: T, refused: Diagnostic, poisoned: Diagnostic };
}
pub const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    signal: ?*core.process.SignalCancellation = null,
    publication_deadline: ?core.process.Deadline = null,
};
pub const RuntimeLayout = struct {
    output: []const u8,
    root: []const u8,
    launcher: []const u8,
    interpreter: []const u8,
    extensions: []const u8,
    loader_directory: []const u8,
    startup_config: []const u8,
    python_version: []const u8,
};
pub const LoaderSource = struct {
    file: *core.private_files.RetainedFile,
    executable: bool,
};
/// Borrowed from the probe inventory owner until copied and freshly checked.
pub const LoaderInventory = struct {
    dynamic_loader: *core.private_files.RetainedFile,
    dependencies: []const LoaderSource,
};

/// Borrowed owners remain alive through construction, validation and publication.
pub const PlanInputs = struct {
    candidate: *@import("wamr_handoff").candidate.Finalized,
    created_unix: u64,
    campaign_id: []const u8,
    ledger_path: []const u8,
    ledger: compute.LedgerBinding,
    maximum_authorized_cost_microusd: u64,
    tools: compute.Tools,
    azure_runtime_document: Artifact,
    azure_runtime: runtime.Contract,
};
pub const AuthorizationInputs = struct {
    decision: Decision,
    approver: []const u8,
    reference: []const u8,
    recorded_unix: u64,
    expires_unix: u64,
    now: u64,
};
