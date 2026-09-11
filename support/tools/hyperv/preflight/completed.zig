const std = @import("std");
const core = @import("hyperv_core");
const c = @import("contract.zig");
const p = c.p;
const j = @import("journal.zig");
const engine = @import("engine.zig");
const evidence = @import("evidence.zig");

pub const Handoff = struct {
    attempt: c.Uuid,
    run_id: c.Uuid,
    vm_id: c.Uuid,
    host_boot_id: c.Uuid,
    native: c.NativeBinding,
    input_sha256: p.Hash,
    preparation_sha256: p.Hash,
    public_receipt_sha256: p.Hash,
    private_receipt_sha256: p.Hash,
    completion_sha256: p.Hash,
    scope: enum { platform_only } = .platform_only,
    storage: enum { unavailable } = .unavailable,
};

/// Only a trusted native preparation/authority resolver can supply `expected`.
/// Standalone receipts and historical/PREPARED/synthetic state are never accepted.
pub fn load(allocator: std.mem.Allocator, io: std.Io, directory: core.private_files.Directory, expected: *const c.Input) !Handoff {
    if (expected.kind != .production) return error.SyntheticEvidence;
    var lock = try directory.lock(io);
    defer lock.close(io);
    const store = try j.Store.open(allocator, io, &lock, expected);
    const state = store.state;
    if (state.phase != .completed or state.kind != .production or state.completion_sha256 == null or
        state.failures.primary != null or state.failures.cleanup != null or state.failures.recording != null or
        state.public == null or state.private == null or state.public_at == null or state.private_at == null or
        state.public_at.? < state.started_at.? or state.private_at.? < state.public_at.? or
        state.private_at.? >= expected.approved.expires_at or state.observed_at == null or
        state.observed_at.? >= expected.approved.cleanup_expires_at) return error.NotCompleted;
    for (state.actions) |operation| if (operation.status != .complete or operation.proof == null) return error.CleanupUnproved;
    for ([_]c.Action{ .create_group, .deploy_host, .grant_access, .stage_public, .publish_public, .stage_private, .publish_private, .deallocate, .revoke_roles, .revoke_sas, .delete_group }) |action| {
        if (state.actions[@intFromEnum(action)].effect != .accepted) return error.MutationNotCompleted;
    }
    const completion = try directory.read(io, allocator, "completion.json", p.max_command, state.completion_sha256);
    defer allocator.free(completion);
    var verified = try p.verify(allocator, completion, expected.approved.public_key, "uk-hyperv-preflight-completion-v1");
    defer verified.deinit();
    const wanted = .{
        .schema = "uk-hyperv-preflight-completion-v1",
        .kind = expected.kind,
        .attempt = state.attempt,
        .run_id = state.run_id,
        .binding = state.binding,
        .input_sha256 = state.input_sha256,
        .preparation_sha256 = state.preparation_sha256,
        .authority_sha256 = state.authority_sha256,
        .public = state.public.?,
        .private = state.private.?,
        .group_absence = state.actions[@intFromEnum(c.Action.prove_group_absent)].proof.?,
        .scope = "platform-only",
        .storage = "UNAVAILABLE",
    };
    const canonical = try c.canonical(allocator, wanted);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, verified.canonical)) return error.CompletionMismatch;
    const public = try phase(allocator, io, directory, expected, state, .public, null);
    const private = try phase(allocator, io, directory, expected, state, .private, public);
    if (!std.meta.eql(public, state.public.?) or !std.meta.eql(private, state.private.?)) return error.EvidenceMismatch;
    return .{
        .attempt = state.attempt,
        .run_id = state.run_id,
        .vm_id = private.vm_id,
        .host_boot_id = private.host_boot_id,
        .native = state.binding,
        .input_sha256 = state.input_sha256,
        .preparation_sha256 = state.preparation_sha256,
        .public_receipt_sha256 = public.receipt_sha256,
        .private_receipt_sha256 = private.receipt_sha256,
        .completion_sha256 = state.completion_sha256.?,
    };
}
fn phase(a: std.mem.Allocator, io: std.Io, directory: core.private_files.Directory, input: *const c.Input, state: j.State, selected: p.Phase, public: ?evidence.Summary) !evidence.Summary {
    const now = if (selected == .public) state.public_at.? else state.private_at.?;
    var admission = try input.validate(a, now);
    defer admission.deinit();
    const action: c.Action = if (selected == .public) .publish_public else .publish_private;
    const bytes = try directory.read(io, a, engine.commandName(selected), p.max_command, state.actions[@intFromEnum(action)].proof);
    defer a.free(bytes);
    var command = try p.Command.parse(a, bytes, input.approved.public_key, &admission, try input.scope(&admission), try core.contracts.parseUuid(&(state.vm_id orelse return error.MissingHostIdentity)), now);
    defer command.deinit();
    const nonce = if (selected == .public) state.public_nonce else state.private_nonce;
    if (command.phase != selected or !std.mem.eql(u8, &p.uuidText(command.phase_nonce), &nonce)) return error.EvidenceMismatch;
    try @import("commands.zig").matchArtifacts(input, &command);
    const summary = if (selected == .public) state.public.? else state.private.?;
    const receipt = try directory.read(io, a, engine.receiptName(selected), p.max_command, summary.receipt_sha256);
    defer a.free(receipt);
    var logs: [4][]const u8 = undefined;
    var count: usize = 0;
    defer for (logs[0..count]) |log| {
        std.crypto.secureZero(u8, @constCast(log));
        a.free(log);
    };
    for (0..@as(usize, if (selected == .public) 2 else 4)) |i| {
        const name = try std.fmt.allocPrint(a, "boot-{d}.log", .{i + @as(usize, if (selected == .public) 0 else 2)});
        defer a.free(name);
        logs[count] = try directory.read(io, a, name, p.max_serial, null);
        count += 1;
    }
    return evidence.verify(a, input, &admission, &command, .{ .receipt = receipt, .logs = logs[0..count] }, public);
}
