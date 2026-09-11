const std = @import("std");
const core = @import("hyperv_core");
const host = @import("hyperv_host");
const az = @import("hyperv_azure");
const c = @import("contract.zig");
const p = c.p;
const j = @import("journal.zig");
const cmd = @import("commands.zig");
const ev = @import("evidence.zig");

pub const Proof = struct {
    digest: p.Hash,
    effect: az.transport.Effect,
    vm_id: ?c.Uuid = null,
    disk_id: ?c.Uuid = null,
    principal_id: ?c.Uuid = null,
    keys: ?az.operations.KeySnapshot = null,
};
pub const Backend = struct {
    context: *anyopaque,
    controlFn: *const fn (*anyopaque, c.Action, *const j.State) anyerror!Proof,
    stageFn: *const fn (*anyopaque, p.Phase, *const j.State) anyerror!Proof,
    publishFn: *const fn (*anyopaque, p.Phase, []const u8, *const j.State) anyerror!Proof,
    fetchFn: *const fn (*anyopaque, p.Phase, c.Uuid, *const j.State) anyerror!ev.Bundle,
    releaseFn: *const fn (*anyopaque, ev.Bundle) void,
    failureFn: *const fn (*anyopaque) az.transport.Failure,
};

pub const Engine = struct {
    store: *j.Store,
    backend: Backend,
    signer: *const cmd.Signer,
    now: u64,
    monotonic_ns: u64,
    owner_pid: i32,
    operator_boot_id: c.Uuid,

    /// Exactly one operation per worker, including its intent and state fsyncs.
    /// This function does not spawn; the independent coordinator supervises it.
    pub fn step(self: *Engine, recovery: bool) !void {
        const store = self.store;
        if (recovery) try self.recover() else try self.claim();
        if (terminal(store.state.phase)) return error.AttemptConsumed;
        if (store.state.phase == .running and (self.now >= store.input.approved.expires_at or self.monotonic_ns >= store.state.deadline_ns.?)) {
            store.fail(.primary, .{ .stage = .admission, .category = .timeout });
            store.state.phase = .cleaning;
            try store.save();
        }
        if (store.state.phase == .cleaning) try self.cleanupClock();
        const action = next(store.state) orelse {
            try self.finish();
            return;
        };
        if (action.cleanup() and (self.monotonic_ns >= store.state.cleanup_deadline_ns.? or self.now >= store.state.cleanup_until.?)) {
            store.fail(.cleanup, .{ .stage = .cleanup, .category = .timeout });
            store.state.phase = .failed;
            try store.save();
            return error.CleanupExpired;
        }
        const reservation = try self.reserve(action);
        try store.begin(action, reservation.bytes, reservation.control);
        const outcome = self.perform(action) catch |err| {
            const failure = self.backend.failureFn(self.backend.context);
            const entry = &store.state.actions[@intFromEnum(action)];
            entry.status = if (failure.effect == .rejected) .rejected else .unknown;
            entry.effect = if (action.mutation()) failure.effect else .not_applicable;
            const diagnostic = if (failure.diagnostic.category == .internal) local(err, action) else failure.diagnostic;
            store.fail(if (action.cleanup()) .cleanup else .primary, diagnostic);
            store.state.phase = .cleaning;
            try store.save();
            return;
        };
        if (action == .inspect_host) {
            const vm = outcome.vm_id orelse return error.MissingHostIdentity;
            const disk = outcome.disk_id orelse return error.MissingHostIdentity;
            const principal = outcome.principal_id orelse return error.MissingHostIdentity;
            if (store.state.vm_id) |prior| if (!std.mem.eql(u8, &prior, &vm)) return error.OriginalIdentityMismatch;
            store.state.vm_id = vm;
            store.state.disk_id = disk;
            store.state.principal_id = principal;
        }
        if (outcome.keys) |keys| {
            if (store.state.key_snapshot != null) return error.AttemptConsumed;
            store.state.key_snapshot = keys;
        }
        store.state.actions[@intFromEnum(action)] = .{ .status = .complete, .proof = outcome.digest, .effect = outcome.effect };
        store.state.observed_at = self.now;
        if (action == .read_private) store.state.phase = .cleaning;
        try store.save();
    }

    fn claim(self: *Engine) !void {
        const store = self.store;
        if (store.state.phase == .prepared) {
            if (self.now < store.input.approved.not_before or self.now >= store.input.approved.expires_at) return error.AuthorityExpired;
            store.state.phase = .running;
            store.state.owner_pid = self.owner_pid;
            store.state.operator_boot_id = self.operator_boot_id;
            store.state.started_at = self.now;
            const remaining_ms: u64 = @min(@as(u64, c.attempt_ms), (store.input.approved.expires_at - self.now) * 1000);
            store.state.deadline_ns = try std.math.add(u64, self.monotonic_ns, try std.math.mul(u64, remaining_ms, std.time.ns_per_ms));
            try store.consume();
            try store.save();
        } else if (store.state.owner_pid != self.owner_pid or store.state.operator_boot_id == null or
            !std.mem.eql(u8, &store.state.operator_boot_id.?, &self.operator_boot_id)) return error.CleanupOnlyRecovery;
    }

    fn recover(self: *Engine) !void {
        const store = self.store;
        if ((terminal(store.state.phase) and store.state.phase != .failed) or store.state.phase == .prepared) return error.AttemptConsumed;
        if (store.state.owner_pid.? != self.owner_pid and std.mem.eql(u8, &store.state.operator_boot_id.?, &self.operator_boot_id)) {
            const result = std.os.linux.syscall2(.kill, @intCast(store.state.owner_pid.?), 0);
            if (std.os.linux.errno(result) != .SRCH) return error.PreviousOwnerAlive;
        }
        store.state.phase = .cleaning;
        store.state.owner_pid = self.owner_pid;
        store.fail(.primary, .{ .stage = .process_run, .category = .ambiguous });
        for (&store.state.actions, 0..) |*observation, i| if (observation.status == .intent) {
            observation.status = .unknown;
            observation.effect = if ((@as(c.Action, @enumFromInt(i))).mutation()) .unknown else .not_applicable;
        };
        try store.save();
    }

    fn cleanupClock(self: *Engine) !void {
        const store = self.store;
        if (store.state.cleanup_until == null) {
            if (self.now >= store.input.approved.cleanup_expires_at) return error.CleanupAuthorityExpired;
            store.state.cleanup_until = @min(try std.math.add(u64, self.now, c.cleanup_ms / 1000), store.input.approved.cleanup_expires_at);
            store.state.cleanup_deadline_ns = try std.math.add(u64, self.monotonic_ns, try std.math.mul(u64, store.state.cleanup_until.? - self.now, std.time.ns_per_s));
            try store.save();
        } else if (!std.mem.eql(u8, &store.state.operator_boot_id.?, &self.operator_boot_id)) {
            // The wall-clock ceiling is never renewed after a machine restart.
            if (self.now >= store.state.cleanup_until.?) return error.CleanupExpired;
            store.state.cleanup_deadline_ns = try std.math.add(u64, self.monotonic_ns, try std.math.mul(u64, store.state.cleanup_until.? - self.now, std.time.ns_per_s));
            store.state.operator_boot_id = self.operator_boot_id;
            try store.save();
        }
    }

    fn reserve(self: *Engine, action: c.Action) !struct { bytes: u64, control: bool } {
        var bytes: u64 = 0;
        if (action == .stage_public or action == .stage_private) {
            const phase: p.Phase = if (action == .stage_public) .public else .private;
            for (self.store.input.preparation.files) |file| if (file.phase == phase) {
                bytes = try std.math.add(u64, bytes, file.artifact.size);
            };
            return .{ .bytes = bytes, .control = false };
        }
        if (action == .read_public or action == .read_private)
            return .{ .bytes = 2 * (if (action == .read_public) @as(u64, 2) else 4) * p.max_serial, .control = false };
        // All bounded supervisor output is held from preparation; concrete
        // credential/request files are additionally charged before their writes.
        return .{ .bytes = 0, .control = true };
    }

    fn perform(self: *Engine, action: c.Action) !Proof {
        const store = self.store;
        if (action.cleanup() or action == .metadata or action == .create_group or action == .deploy_host or action == .inspect_host or action == .grant_access)
            return self.backend.controlFn(self.backend.context, action, &store.state);
        if (action == .stage_public or action == .stage_private) {
            if (action == .stage_private) try requirePublic(store.state);
            return self.backend.stageFn(self.backend.context, if (action == .stage_public) .public else .private, &store.state);
        }
        var admission = try store.input.validate(store.allocator, self.now);
        defer admission.deinit();
        const vm = store.state.vm_id orelse return error.MissingHostIdentity;
        if (action == .publish_public or action == .publish_private) {
            const phase: p.Phase = if (action == .publish_public) .public else .private;
            var acceptance: ?[]u8 = null;
            defer if (acceptance) |bytes| store.allocator.free(bytes);
            if (phase == .private) {
                try requirePublic(store.state);
                acceptance = try store.lock.directory.read(store.io, store.allocator, "acceptance.json", p.max_command, store.state.acceptance_sha256);
            }
            const bytes = try self.signer.command(store.allocator, store.input, &admission, phase, vm, if (phase == .public) store.state.public_nonce else store.state.private_nonce, self.now, acceptance);
            defer store.allocator.free(bytes);
            try store.immutable(commandName(phase), bytes, true);
            // Publication is a separate staged copy, not the local control file.
            try store.charge(bytes.len, true);
            try store.save();
            return self.backend.publishFn(self.backend.context, phase, bytes, &store.state);
        }
        const phase: p.Phase = if (action == .read_private) .private else .public;
        const bytes = try store.lock.directory.read(store.io, store.allocator, commandName(phase), p.max_command, null);
        defer store.allocator.free(bytes);
        var command = try p.Command.parse(store.allocator, bytes, store.input.approved.public_key, &admission, try store.input.scope(&admission), try core.contracts.parseUuid(&vm), self.now);
        defer command.deinit();
        if (action == .accept_public) {
            const public = store.state.public orelse return error.MissingPublicEvidence;
            if (store.state.actions[@intFromEnum(c.Action.read_public)].status != .complete) return error.MissingPublicEvidence;
            const acceptance = try self.signer.acceptance(store.allocator, store.input, &command, public.receipt_sha256, public.host_boot_id, self.now);
            defer store.allocator.free(acceptance);
            try store.immutable("acceptance.json", acceptance, true);
            store.state.acceptance_sha256 = p.hash(acceptance);
            return .{ .digest = p.hash(acceptance), .effect = .not_applicable };
        }
        if (action != .read_public and action != .read_private) return error.InvalidOperation;
        // Both downloaded and retained receipt copies are controls. Serial files
        // use the separate two-copy reservation above, including failed reads.
        try store.charge(2 * p.max_command, true);
        try store.save();
        const bundle = try self.backend.fetchFn(self.backend.context, phase, if (phase == .public) store.state.public_nonce else store.state.private_nonce, &store.state);
        defer self.backend.releaseFn(self.backend.context, bundle);
        const summary = try ev.verify(store.allocator, store.input, &admission, &command, bundle, if (phase == .private) store.state.public else null);
        try j.durable(try store.lock.createImmutable(store.io, receiptName(phase), bundle.receipt));
        for (bundle.logs, 0..) |log, i| {
            const name = try std.fmt.allocPrint(store.allocator, "boot-{d}.log", .{i + @as(usize, if (phase == .public) 0 else 2)});
            defer store.allocator.free(name);
            // Both the transport output and retained evidence copy are reserved.
            try j.durable(try store.lock.createImmutable(store.io, name, log));
        }
        if (phase == .public) {
            store.state.public = summary;
            store.state.public_at = self.now;
        } else {
            store.state.private = summary;
            store.state.private_at = self.now;
        }
        return .{ .digest = summary.receipt_sha256, .effect = .not_applicable };
    }

    fn finish(self: *Engine) !void {
        const store = self.store;
        if (store.state.phase != .cleaning) return error.InvalidState;
        var clean = true;
        for (store.state.actions[@intFromEnum(c.Action.deallocate)..]) |observation| {
            if (observation.status != .complete or observation.proof == null) clean = false;
        }
        if (!clean or store.state.failures.cleanup != null or store.state.failures.recording != null) {
            store.state.phase = .failed;
        } else if (store.state.failures.primary != null or store.state.public == null or store.state.private == null) {
            store.state.phase = .cleaned;
        } else {
            const body = .{
                .schema = "uk-hyperv-preflight-completion-v1",
                .kind = store.input.kind,
                .attempt = store.state.attempt,
                .run_id = store.state.run_id,
                .binding = store.state.binding,
                .input_sha256 = store.state.input_sha256,
                .preparation_sha256 = store.state.preparation_sha256,
                .authority_sha256 = store.state.authority_sha256,
                .admitted_at = store.state.admitted_at,
                .public = store.state.public.?,
                .private = store.state.private.?,
                .group_absence = store.state.actions[@intFromEnum(c.Action.prove_group_absent)].proof.?,
                .scope = "platform-only",
                .storage = "UNAVAILABLE",
            };
            const completion = try self.signer.completion(store.allocator, body);
            defer store.allocator.free(completion);
            try store.immutable("completion.json", completion, true);
            store.state.completion_sha256 = p.hash(completion);
            store.state.phase = if (store.input.kind == .production) .completed else .synthetic_completed;
        }
        try store.save();
    }
};

pub fn next(state: j.State) ?c.Action {
    const start: usize = if (state.phase == .cleaning) @intFromEnum(c.Action.deallocate) else 0;
    const end: usize = if (state.phase == .cleaning) c.action_count else @intFromEnum(c.Action.deallocate);
    for (state.actions[start..end], start..) |observation, i| if (observation.status == .fresh) return @enumFromInt(i);
    return null;
}
pub fn terminal(phase: c.Phase) bool {
    return phase == .failed or phase == .cleaned or phase == .completed or phase == .synthetic_completed;
}
pub fn requirePublic(state: j.State) !void {
    const public = state.public orelse return error.PrematurePrivateTransfer;
    if (public.count != 2 or public.phase != .public or public.kind != state.kind or state.acceptance_sha256 == null or
        state.actions[@intFromEnum(c.Action.accept_public)].status != .complete or
        state.actions[@intFromEnum(c.Action.read_public)].status != .complete) return error.PrematurePrivateTransfer;
}
pub fn commandName(phase: p.Phase) []const u8 {
    return if (phase == .public) "public-command.json" else "private-command.json";
}
pub fn receiptName(phase: p.Phase) []const u8 {
    return if (phase == .public) "public-receipt.json" else "private-receipt.json";
}
pub fn local(err: anyerror, action: c.Action) core.diagnostics.Diagnostic {
    return .{ .stage = if (action.cleanup()) .cleanup else .admission, .category = switch (err) {
        error.AuthorityExpired, error.CleanupAuthorityExpired, error.TokenExpired => .authentication,
        error.Deadline, error.CleanupExpired => .timeout,
        error.BudgetExceeded, error.RecordingBudgetExceeded => .output_limit,
        error.RecordingFailed => .local_io,
        else => .integrity,
    } };
}
