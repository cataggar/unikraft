const std = @import("std");
const core = @import("hyperv_core");
const host = @import("hyperv_host");
const c = @import("contract.zig");
const j = @import("journal.zig");
const engine = @import("engine.zig");
const commands = @import("commands.zig");

pub const Mode = enum { prepare, step, inspect, cleanup, plan, plan_cleanup };
pub const Report = struct {
    schema: []const u8 = "uk-hyperv-preflight-worker-result-v1",
    kind: c.Kind,
    phase: c.Phase = .failed,
    attempt: ?c.Uuid = null,
    more: bool = true,
    deadline_ns: ?u64 = null,
    operation_ms: ?u32 = null,
    failures: core.diagnostics.Failures = .{},
};
/// The integrating CLI owns this resolver. It must consume the preparation
/// lane's real validator and separately verified authority/image/route approvals,
/// and retain independently usable cleanup credentials. No JSON Boolean adapter.
pub const Resolved = struct {
    input: *const c.Input,
    signer: *const commands.Signer,
    backend_context: *anyopaque,
    backendFn: *const fn (*anyopaque, *j.Store) anyerror!engine.Backend,
    now: u64,
    monotonic_ns: u64,
    operator_boot_id: c.Uuid,
};

/// Runs in one owned child, not inside another process supervisor. All operation
/// filesystem writes and HTTP happen here, under its parent's hard deadline.
pub fn execute(comptime kind: c.Kind, a: std.mem.Allocator, io: std.Io, mode: Mode, directory: core.private_files.Directory, resolved: Resolved, cause: ?core.diagnostics.Category) !Report {
    if (resolved.input.kind != kind) return error.EvidenceKindMismatch;
    if (kind == .production) try requireSelf(a, io, resolved.input);
    var lock = try directory.lock(io);
    defer lock.close(io);
    if (mode == .prepare) {
        const store = try j.Store.prepare(a, io, &lock, resolved.input, resolved.now);
        return report(store.state);
    }
    var store = if (mode == .cleanup or mode == .plan_cleanup) try j.Store.openRecovery(a, io, &lock, resolved.input) else try j.Store.open(a, io, &lock, resolved.input);
    if (mode == .inspect) return report(store.state);
    if (mode == .plan or mode == .plan_cleanup) {
        var value = report(store.state);
        const cleanup = mode == .plan_cleanup or store.state.phase == .cleaning;
        const authority_end = if (cleanup) resolved.input.approved.cleanup_expires_at else resolved.input.approved.expires_at;
        const wall_end = if (cleanup) @min(authority_end, store.state.cleanup_until orelse authority_end) else authority_end;
        const seconds = wall_end -| resolved.now;
        const maximum_ms: u64 = if (cleanup) c.cleanup_ms else c.attempt_ms;
        const duration_ms: u64 = @min(try std.math.mul(u64, seconds, 1000), maximum_ms);
        var deadline = try std.math.add(u64, resolved.monotonic_ns, try std.math.mul(u64, duration_ms, std.time.ns_per_ms));
        if (store.state.operator_boot_id) |boot_id| {
            if (std.mem.eql(u8, &boot_id, &resolved.operator_boot_id)) {
                const saved = if (cleanup) store.state.cleanup_deadline_ns else store.state.deadline_ns;
                if (saved) |end| deadline = @min(deadline, end);
            } else if (!cleanup) return error.CleanupOnlyRecovery;
        }
        var next_state = store.state;
        if (cleanup) next_state.phase = .cleaning;
        if (mode == .plan_cleanup and store.state.phase == .failed)
            value.more = engine.next(next_state) != null;
        value.deadline_ns = deadline;
        value.operation_ms = if (engine.next(next_state)) |action| action.timeout() else 5000;
        return value;
    }
    if (cause) |category| {
        store.fail(.primary, .{ .stage = .process_run, .category = category });
        if (store.state.phase != .prepared and !engine.terminal(store.state.phase)) store.state.phase = .cleaning;
        try store.save();
    }
    var machine: engine.Engine = .{
        .store = &store,
        .backend = try resolved.backendFn(resolved.backend_context, &store),
        .signer = resolved.signer,
        .now = resolved.now,
        .monotonic_ns = resolved.monotonic_ns,
        .owner_pid = std.os.linux.getppid(),
        .operator_boot_id = resolved.operator_boot_id,
    };
    machine.step(mode == .cleanup) catch |err| {
        if (err == error.AttemptConsumed or err == error.PreviousOwnerAlive) return err;
        const recording = err == error.RecordingFailed or err == error.RecordingBudgetExceeded or err == error.UnstableRecordSize;
        if (recording) {
            store.fail(.recording, .{ .stage = .state_record, .category = .local_io });
        } else {
            store.fail(if (store.state.phase == .cleaning) .cleanup else .primary, engine.local(err, engine.next(store.state) orelse .prove_group_absent));
        }
        // Leave durable intent authoritative even if neither the main state nor
        // this independently reserved bounded failure record can be persisted.
        if (!engine.terminal(store.state.phase)) store.state.phase = .cleaning;
        const notice = try c.canonical(a, j.FailureRecord{ .attempt = store.state.attempt, .authority_sha256 = store.state.authority_sha256, .failures = store.state.failures });
        defer a.free(notice);
        if (notice.len > c.emergency_bytes) return error.RecordingBudgetExceeded;
        const saved = lock.createImmutable(io, "recording-failure.json", notice) catch |save_err| switch (save_err) {
            error.PathAlreadyExists => return report(store.state),
            else => return save_err,
        };
        try j.durable(saved);
        return report(store.state);
    };
    return report(store.state);
}
pub fn report(state: j.State) Report {
    return .{ .kind = state.kind, .phase = state.phase, .attempt = state.attempt, .more = !engine.terminal(state.phase), .failures = state.failures };
}
fn requireSelf(a: std.mem.Allocator, io: std.Io, input: *const c.Input) !void {
    const executable = try std.Io.Dir.openFileAbsolute(io, "/proc/self/exe", .{ .mode = .read_only });
    defer executable.close(io);
    const size = (try executable.stat(io)).size;
    if (size > c.p.max_control or size > input.approved.budget.producer.control) return error.NativeControlNotAdmitted;
    const digest = try host.files.digest(io, executable, size);
    if (!std.mem.eql(u8, &digest, &input.preparation.binding.operator_binary)) return error.NativeBindingMismatch;
    _ = a;
}
