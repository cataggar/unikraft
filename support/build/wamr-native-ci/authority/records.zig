// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const contracts = @import("contracts.zig");
const types = @import("types.zig");
const compute = types.compute;
const candidate = @import("wamr_handoff").candidate;
const copy = @import("wamr_handoff").retained_copy;

pub fn parse(comptime T: type, a: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(T) {
    var document = try contracts.parseCanonical(a, bytes);
    defer document.deinit();
    return std.json.parseFromValue(T, a, document.value(), .{ .allocate = .alloc_always });
}
pub fn runtimeBytes(a: std.mem.Allocator, value: types.runtime.Contract) ![]u8 {
    try value.validate();
    return canonical(a, value);
}
pub fn planBytes(a: std.mem.Allocator, value: types.Plan) ![]u8 {
    try value.validate();
    return canonical(a, value);
}
pub fn templateBytes(a: std.mem.Allocator, bound_plan: types.Plan, digest: []const u8, value: types.ApprovalTemplate) ![]u8 {
    try bound_plan.validate();
    _ = try core.contracts.parseSha256(digest);
    try value.validate(bound_plan, digest);
    return canonical(a, value);
}
pub fn authorizationBytes(a: std.mem.Allocator, bound_plan: types.Plan, digest: []const u8, value: types.Authorization, now: u64) ![]u8 {
    try bound_plan.validate();
    _ = try core.contracts.parseSha256(digest);
    try value.validate(bound_plan, digest);
    try decisionCurrent(value, now);
    return canonical(a, value);
}
pub fn admissionBytes(a: std.mem.Allocator, value: types.Admission, now: u64) ![]u8 {
    try value.current(now);
    return canonical(a, value);
}
fn canonical(a: std.mem.Allocator, value: anytype) ![]u8 {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(raw);
    var document = try core.contracts.Document.parse(a, raw, contracts.json_limits);
    defer document.deinit();
    return document.canonicalAlloc(a);
}

pub fn plan(inputs: types.PlanInputs, signal: ?*core.process.SignalCancellation) !types.Plan {
    const metadata = try inputs.candidate.metadata(signal);
    try readerTool(inputs.tools.supervisor, metadata.reader.supervisor, metadata.reader.io, signal);
    try readerTool(inputs.tools.validator, metadata.reader.validator, metadata.reader.io, signal);
    const result = try fromMetadata(inputs, metadata);
    try inputs.candidate.revalidate(signal);
    return result;
}

fn readerTool(actual: types.Artifact, retained: *const core.private_files.RetainedFile, io: std.Io, signal: ?*core.process.SignalCancellation) !void {
    if (!std.mem.eql(u8, actual.path, retained.path) or actual.size != retained.file_snapshot.size)
        return error.ReaderToolMismatch;
    const digest = try copy.hashRetained(io, retained, retained.file_snapshot.size, if (signal) |s| s.flag() else null);
    if (!std.mem.eql(u8, actual.sha256, &digest)) return error.ReaderToolMismatch;
}

fn project(comptime T: type, value: anytype) T {
    var result: T = undefined;
    inline for (std.meta.fields(T)) |field| @field(result, field.name) = @field(value, field.name);
    return result;
}
fn fromMetadata(inputs: types.PlanInputs, metadata: candidate.Metadata) !types.Plan {
    if (metadata.source != .imported_product) return error.ImportedProductRequired;
    const scope = metadata.scope;
    if (scope.version != 2 or scope.authority != .not_admitted or !std.mem.eql(u8, scope.purpose, contracts.policy.profile))
        return error.Version2Required;
    const provenance = metadata.provenance;
    const value: types.Plan = .{
        .schema = "uk.wamr.azure-execution-plan",
        .version = 2,
        .purpose = .@"qcow2-derived-vhd-two-boot",
        .profile = .@"qcow2-derived-vhd",
        .authority = .not_admitted,
        .canonicalization = contracts.canonicalization,
        .created_unix = inputs.created_unix,
        .attempt_id = scope.attempt_id,
        .campaign_id = inputs.campaign_id,
        .campaign_profile = .@"qcow2-derived-vhd",
        .ledger_path = inputs.ledger_path,
        .ledger = inputs.ledger,
        .subscription = scope.subscription,
        .location = scope.location,
        .prefix = scope.prefix,
        .vm_size = scope.vm_size,
        .serial_mode = .azure_cumulative,
        .runtime_seconds = contracts.policy.runtime_seconds,
        .cleanup_seconds = contracts.policy.cleanup_seconds,
        .operation_seconds = contracts.policy.operation_seconds,
        .poll_seconds = contracts.policy.poll_seconds,
        .source_revision = scope.source_revision,
        .source_tree = scope.source_tree,
        .run = project(compute.RunIdentity, provenance.run),
        .identity = project(compute.Identity, scope.identity),
        .lineage = project(compute.Lineage, provenance.lineage),
        .candidate = project(types.Artifact, metadata.candidate),
        .bundle = project(types.Artifact, scope.bundle),
        .public_bundle = project(types.Artifact, provenance.public_bundle),
        .transport = project(types.Artifact, provenance.transport),
        .qcow2 = project(types.Artifact, provenance.qcow2),
        .os_vhd = project(types.Artifact, scope.os_vhd),
        .vhd_bytes = scope.os_vhd.size,
        .vhd_capacity_bytes = contracts.policy.fixed_vhd_capacity_bytes,
        .artifact_id = provenance.artifact_id,
        .inner_zip_sha256 = provenance.inner_zip_sha256,
        .container_digest = provenance.container_digest,
        .resources = .{
            .vm_count = 1,
            .os_disk_count = 1,
            .data_disk_count = 0,
            .public_ip_count = 0,
            .boot_count = 2,
            .maximum_parallelism = 1,
            .generation = 2,
            .os_disk_sku = .StandardSSD_LRS,
            .os_disk_capacity_bytes = contracts.policy.fixed_vhd_capacity_bytes,
            .network = .private_no_default_outbound,
        },
        .retry_count = 0,
        .substitution = .{ .source = false, .image = false, .topology = false, .workload = false },
        .cleanup = .{ .exact_owned_resources_only = true, .delete_owned_resource_group = true, .independent_absence_observation = true, .replacement_resources = false },
        .cost = .{
            .unit = .micro_usd,
            .policy = .@"northeurope-standard-d2s-v5-conservative-2026-09-v1",
            .estimated_upper_bound = try contracts.recomputeCost(1, 1, contracts.policy.runtime_seconds, contracts.policy.cleanup_seconds),
            .maximum_authorized = inputs.maximum_authorized_cost_microusd,
            .repository_policy_maximum = contracts.policy.repository_maximum_cost_microusd,
        },
        .tools = inputs.tools,
        .azure_runtime_document = inputs.azure_runtime_document,
        .azure_runtime = inputs.azure_runtime,
    };
    try value.validate();
    return value;
}

pub fn approvalTemplate(value: types.Plan, digest: []const u8) !types.ApprovalTemplate {
    try value.validate();
    _ = try core.contracts.parseSha256(digest);
    const result: types.ApprovalTemplate = .{
        .schema = "uk.wamr.azure-execution-approval-template",
        .version = 2,
        .decision = .pending,
        .plan_sha256 = digest,
        .attempt_id = value.attempt_id,
        .campaign_id = value.campaign_id,
        .ledger_id = value.ledger.ledger_id,
        .ledger_initialization_required = value.ledger.initialization_required,
        .candidate_sha256 = value.candidate.sha256,
        .estimated_cost_upper_bound_microusd = value.cost.estimated_upper_bound,
        .maximum_authorized_cost_microusd = value.cost.maximum_authorized,
        .limits = value.limits(),
        .azure_runtime = value.runtimeBinding(),
    };
    try result.validate(value, digest);
    return result;
}

/// A current denial is a valid record, but is never an admission.
pub fn decisionCurrent(value: types.Authorization, now: u64) !void {
    if (!contracts.validApprovalWindow(value.recorded_unix, value.expires_unix))
        return error.InvalidApprovalWindow;
    if (now < value.recorded_unix or now >= value.expires_unix) return error.ApprovalExpired;
}
pub fn authorization(value: types.Plan, digest: []const u8, template: types.ApprovalTemplate, inputs: types.AuthorizationInputs) !types.Authorization {
    try value.validate();
    _ = try core.contracts.parseSha256(digest);
    try template.validate(value, digest);
    if (!std.unicode.utf8ValidateSlice(inputs.approver) or !std.unicode.utf8ValidateSlice(inputs.reference))
        return error.InvalidAuthorityField;
    const result: types.Authorization = .{
        .schema = "uk.wamr.azure-execution-authorization",
        .version = 2,
        .decision = inputs.decision,
        .plan_sha256 = template.plan_sha256,
        .attempt_id = template.attempt_id,
        .campaign_id = template.campaign_id,
        .ledger_id = template.ledger_id,
        .ledger_initialization_required = template.ledger_initialization_required,
        .candidate_sha256 = template.candidate_sha256,
        .estimated_cost_upper_bound_microusd = template.estimated_cost_upper_bound_microusd,
        .maximum_authorized_cost_microusd = template.maximum_authorized_cost_microusd,
        .limits = template.limits,
        .azure_runtime = template.azure_runtime,
        .approver = inputs.approver,
        .reference = inputs.reference,
        .recorded_unix = inputs.recorded_unix,
        .expires_unix = inputs.expires_unix,
    };
    try result.validate(value, digest);
    try decisionCurrent(result, inputs.now);
    return result;
}

pub fn admission(value: types.Plan, plan_artifact: types.Artifact, decision: types.Authorization, authorization_artifact: types.Artifact, now: u64) !types.Admission {
    try value.validate();
    try decision.validate(value, plan_artifact.sha256);
    try decision.current(now);
    var result: types.Admission = undefined;
    inline for (std.meta.fields(types.Plan)) |field| {
        if (comptime !std.mem.eql(u8, field.name, "schema") and !std.mem.eql(u8, field.name, "version") and !std.mem.eql(u8, field.name, "authority"))
            @field(result, field.name) = @field(value, field.name);
    }
    result.schema = "uk.wamr.azure-execution-admission";
    result.version = 2;
    result.authority = .approved;
    result.plan = plan_artifact;
    result.authorization = authorization_artifact;
    result.approval = .{ .approver = decision.approver, .reference = decision.reference, .approved_unix = decision.recorded_unix, .expires_unix = decision.expires_unix };
    try result.current(now);
    return result;
}

pub fn unsigned(value: types.Integer) !u64 {
    return std.math.cast(u64, value) orelse error.InvalidInteger;
}
pub fn normalizeUuid(a: std.mem.Allocator, input: []const u8) ![]u8 {
    var text = input;
    if (std.mem.startsWith(u8, text, "urn:uuid:")) text = text[9..];
    if (text.len >= 2 and text[0] == '{' and text[text.len - 1] == '}') text = text[1 .. text.len - 1];
    var digits: [32]u8 = undefined;
    var at: usize = 0;
    for (text) |byte| {
        if (byte == '-') continue;
        if (at >= digits.len or !std.ascii.isHex(byte)) return error.InvalidUuid;
        digits[at] = std.ascii.toLower(byte);
        at += 1;
    }
    if (at != digits.len) return error.InvalidUuid;
    return std.fmt.allocPrint(a, "{s}-{s}-{s}-{s}-{s}", .{ digits[0..8], digits[8..12], digits[12..16], digits[16..20], digits[20..32] });
}
pub fn freshUuid(a: std.mem.Allocator, io: std.Io) ![]u8 {
    var bytes: [16]u8 = undefined;
    io.random(&bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    return normalizeUuid(a, &std.fmt.bytesToHex(bytes, .lower));
}

test "plan projection uses typed provenance without reparsing candidate authority or receipts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bytes = try @import("test_fixtures.zig").goldenRecord(a, "plan");
    var fixture = try parse(types.Plan, a, bytes);
    defer fixture.deinit();
    const value = fixture.value;
    // This exercises only the pure projection, not Finalized construction or
    // imported-product custody. The production entry point accepts an owner.
    const inputs: types.PlanInputs = .{
        .candidate = undefined,
        .created_unix = value.created_unix,
        .campaign_id = value.campaign_id,
        .ledger_path = value.ledger_path,
        .ledger = value.ledger,
        .maximum_authorized_cost_microusd = value.cost.maximum_authorized,
        .tools = value.tools,
        .azure_runtime_document = value.azure_runtime_document,
        .azure_runtime = value.azure_runtime,
    };
    var metadata: candidate.Metadata = .{
        .source = .imported_product,
        .reader = undefined,
        .candidate = project(candidate.Artifact, value.candidate),
        .scope = .{
            .version = 2,
            .purpose = contracts.policy.profile,
            .attempt_id = value.attempt_id,
            .subscription = value.subscription,
            .prefix = value.prefix,
            .source_revision = value.source_revision,
            .source_tree = value.source_tree,
            .identity = project(candidate.Identity, value.identity),
            .os_vhd = project(candidate.Artifact, value.os_vhd),
            .bundle = project(candidate.Artifact, value.bundle),
        },
        .provenance = .{
            .public_bundle = project(candidate.Artifact, value.public_bundle),
            .transport = project(candidate.Artifact, value.transport),
            .qcow2 = project(candidate.Artifact, value.qcow2),
            .run = project(@TypeOf(@as(candidate.Provenance, undefined).run), value.run),
            .lineage = project(@TypeOf(@as(candidate.Provenance, undefined).lineage), value.lineage),
            .artifact_id = value.artifact_id,
            .inner_zip_sha256 = value.inner_zip_sha256,
            .container_digest = value.container_digest,
        },
    };
    try std.testing.expectEqualStrings(bytes, try planBytes(a, try fromMetadata(inputs, metadata)));
    metadata.source = .private_bundle;
    try std.testing.expectError(error.ImportedProductRequired, fromMetadata(inputs, metadata));
    metadata.source = .imported_product;
    metadata.scope.version = 1;
    try std.testing.expectError(error.Version2Required, fromMetadata(inputs, metadata));
}

test "plan reader-tool binding requires the retained path size and fresh digest" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const directory = try std.Io.Dir.openDirAbsolute(io, @import("test_options").fixture_root, .{});
    defer directory.close(io);
    const name = try std.fmt.allocPrint(a, "authority-reader-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    const file = try directory.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    defer directory.deleteFile(io, name) catch @panic("authority reader fixture cleanup failed");
    try file.writeStreamingAll(io, "retained-reader");
    const path = try std.fs.path.join(a, &.{ @import("test_options").fixture_root, name });
    defer a.free(path);
    var retained = try core.private_files.RetainedFile.open(io, path, .private);
    defer retained.close(io);
    const digest = try copy.hashRetained(io, &retained, retained.file_snapshot.size, null);
    const bound: types.Artifact = .{ .path = path, .size = retained.file_snapshot.size, .sha256 = &digest };
    try readerTool(bound, &retained, io, null);
    var changed = bound;
    changed.path = "/different/reader";
    try std.testing.expectError(error.ReaderToolMismatch, readerTool(changed, &retained, io, null));
    changed = bound;
    changed.size += 1;
    try std.testing.expectError(error.ReaderToolMismatch, readerTool(changed, &retained, io, null));
    changed = bound;
    changed.sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try std.testing.expectError(error.ReaderToolMismatch, readerTool(changed, &retained, io, null));
    try file.writePositionalAll(io, "changed", 0);
    try std.testing.expectError(error.FileChanged, readerTool(bound, &retained, io, null));
}
