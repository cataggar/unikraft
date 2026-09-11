const std = @import("std");
const core = @import("hyperv_core");
const host = @import("hyperv_host");
const c = @import("contract.zig");
const p = c.p;

pub const Bundle = struct { receipt: []const u8, logs: []const []const u8 };
pub const Summary = struct {
    kind: c.Kind,
    phase: p.Phase,
    receipt_sha256: p.Hash,
    command_sha256: p.Hash,
    phase_nonce: c.Uuid,
    vm_id: c.Uuid,
    host_boot_id: c.Uuid,
    launches: [4]c.Uuid,
    count: u8,
    host_staged: u64,
    host_control: u64,
    host_evidence: u64,
};

/// The receipt is the merged host's existing wire contract. Boot outcomes and
/// serial verification are reused, rather than replaced by controller PASS flags.
pub fn verify(allocator: std.mem.Allocator, input: *const c.Input, admission: *const p.Admission, command: *const p.Command, bundle: Bundle, public: ?Summary) !Summary {
    var document = try core.contracts.Document.parse(allocator, bundle.receipt, .{ .bytes = p.max_command, .string_bytes = 4096, .items = 2048, .tokens = 16384 });
    defer document.deinit();
    try document.requireCanonical(allocator, bundle.receipt);
    const value = document.value();
    _ = try core.contracts.exactFields(value, &.{
        "schema",         "evidence_kind",   "phase",                                 "run_id",                                "vm_id",                                  "phase_nonce", "host_boot_id",
        "command_sha256", "manifest_sha256", "runner_sha256",                         "image_sha256",                          "host_image_sha256",                      "scope",       "status",
        "boots",          "failures",        "staging_bytes_reserved_before_receipt", "control_bytes_reserved_before_receipt", "evidence_bytes_reserved_before_receipt",
    });
    try text(value, "schema", "uk-hyperv-host-evidence-v1");
    try text(value, "scope", "platform-only");
    try text(value, "status", "PASS");
    try text(value, "evidence_kind", if (input.kind == .production) "qemu_kvm" else "synthetic_child");
    try text(value, "phase", @tagName(command.phase));
    try text(value, "run_id", &input.approved.authority.owner_run);
    try text(value, "vm_id", &p.uuidText(command.vm_id));
    try text(value, "phase_nonce", &p.uuidText(command.phase_nonce));
    try digest(value, "command_sha256", command.verified.digest);
    try digest(value, "manifest_sha256", command.manifest_sha256);
    try digest(value, "runner_sha256", admission.runner_sha256);
    try digest(value, "image_sha256", command.image_sha256);
    try digest(value, "host_image_sha256", admission.host_image_sha256);
    try failures(try p.field(value, "failures"));
    const boots = try p.field(value, "boots");
    const count: usize = if (command.phase == .public) 2 else 4;
    if (boots != .array or boots.array.items.len != count or bundle.logs.len != count) return error.WrongBootCount;
    var result: Summary = .{
        .kind = input.kind,
        .phase = command.phase,
        .receipt_sha256 = p.hash(bundle.receipt),
        .command_sha256 = command.verified.digest,
        .phase_nonce = p.uuidText(command.phase_nonce),
        .vm_id = p.uuidText(command.vm_id),
        .host_boot_id = try uuid(value, "host_boot_id"),
        .launches = [_]c.Uuid{[_]u8{0} ** 36} ** 4,
        .count = @intCast(count),
        .host_staged = try core.contracts.integer(u64, try p.field(value, "staging_bytes_reserved_before_receipt")),
        .host_control = try core.contracts.integer(u64, try p.field(value, "control_bytes_reserved_before_receipt")),
        .host_evidence = try core.contracts.integer(u64, try p.field(value, "evidence_bytes_reserved_before_receipt")),
    };
    const floor = try input.approved.budget.floor();
    const ceiling = try floor.add(input.approved.budget.host_runtime);
    if (result.host_staged < floor.staged or result.host_control < floor.control or
        result.host_staged > ceiling.staged or result.host_control > ceiling.control or result.host_evidence > p.max_evidence)
        return error.InvalidHostAccounting;
    // The host snapshot is explicitly before receipt/counters/remaining records.
    // Its complete host_runtime reservation stays held, not released on a snapshot.
    if (public) |prior| {
        if (command.phase != .private or prior.kind != input.kind or prior.phase != .public or
            !std.mem.eql(u8, &prior.host_boot_id, &result.host_boot_id) or
            result.host_staged < prior.host_staged or result.host_control < prior.host_control or result.host_evidence < prior.host_evidence)
            return error.HostContinuityMismatch;
        const acceptance = command.acceptance orelse return error.MissingPublicAcceptance;
        if (!std.mem.eql(u8, &acceptance.public_command_sha256, &prior.command_sha256) or
            !std.mem.eql(u8, &acceptance.public_evidence_sha256, &prior.receipt_sha256) or
            !std.mem.eql(u8, &p.uuidText(acceptance.host_boot_id), &prior.host_boot_id) or
            !std.mem.eql(u8, &p.uuidText(acceptance.phase_nonce), &prior.phase_nonce))
            return error.PublicAcceptanceMismatch;
    } else if (command.phase != .public) return error.MissingPublicAcceptance;
    var serial_total: u64 = 0;
    for (boots.array.items, bundle.logs, 0..) |boot_value, log, i| {
        const parsed = try std.json.parseFromValue(host.boot.Outcome, allocator, boot_value, .{ .ignore_unknown_fields = false });
        defer parsed.deinit();
        const boot = parsed.value;
        if (boot.evidence_kind != (if (input.kind == .production) host.boot.EvidenceKind.qemu_kvm else .synthetic_child) or
            !boot.passed or boot.index != i + @as(usize, if (command.phase == .public) 0 else 2) or
            boot.legacy_apic != (i % 2 == 1) or !std.mem.eql(u8, &boot.host_boot_id, &result.host_boot_id) or
            boot.serial_bytes == 0 or boot.serial_bytes > p.max_serial or boot.serial_bytes != log.len or
            !std.mem.eql(u8, &boot.serial_sha256, &p.hex(p.hash(log))) or boot.failures.primary != null or
            boot.failures.cleanup != null or boot.failures.recording != null) return error.InvalidBootEvidence;
        _ = try core.contracts.parseUuid(&boot.launch_id);
        try p.validUuid(try core.contracts.parseUuid(&boot.launch_id));
        for (result.launches[0..i]) |prior| if (std.mem.eql(u8, &prior, &boot.launch_id)) return error.DuplicateBoot;
        if (public) |prior| for (prior.launches[0..prior.count]) |launch| {
            if (std.mem.eql(u8, &launch, &boot.launch_id)) return error.DuplicateBoot;
        };
        const image = command.artifact(if (command.phase == .public) .capability_raw else if (i < 2) .raw else .vhd);
        if (!std.mem.eql(u8, &boot.image_sha256, &p.hex(image.sha256))) return error.ImageMismatch;
        try host.serial.validate(allocator, log, command.policy, boot.legacy_apic, command.guarded);
        result.launches[i] = boot.launch_id;
        serial_total += log.len;
    }
    if (serial_total > p.max_evidence or result.host_evidence < serial_total) return error.InvalidHostAccounting;
    return result;
}

fn text(value: std.json.Value, name: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, try core.contracts.string(try p.field(value, name)), expected)) return error.EvidenceMismatch;
}
fn digest(value: std.json.Value, name: []const u8, expected: p.Hash) !void {
    const actual = try core.contracts.parseSha256(try core.contracts.string(try p.field(value, name)));
    if (!std.mem.eql(u8, &actual, &expected)) return error.EvidenceMismatch;
}
fn uuid(value: std.json.Value, name: []const u8) !c.Uuid {
    const result = try core.contracts.parseUuid(try core.contracts.string(try p.field(value, name)));
    try p.validUuid(result);
    return p.uuidText(result);
}
fn failures(value: std.json.Value) !void {
    const fields = try core.contracts.exactFields(value, &.{ "primary", "cleanup", "recording" });
    for (fields.values()) |entry| if (entry != .null) return error.HostFailure;
}
