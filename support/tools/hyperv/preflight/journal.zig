const std = @import("std");
const core = @import("hyperv_core");
const c = @import("contract.zig");
const evidence = @import("evidence.zig");
const p = c.p;

pub const Status = enum { fresh, intent, complete, rejected, unknown };
pub const Observation = struct {
    status: Status = .fresh,
    effect: @import("hyperv_azure").transport.Effect = .not_started,
    proof: ?p.Hash = null,
};
pub const State = struct {
    schema: []const u8 = "uk-hyperv-preflight-state-v1",
    kind: c.Kind,
    phase: c.Phase = .prepared,
    run_id: c.Uuid,
    binding: c.NativeBinding,
    input_sha256: p.Hash,
    preparation_sha256: p.Hash,
    authority_sha256: p.Hash,
    admitted_at: u64,
    attempt: c.Uuid,
    public_nonce: c.Uuid,
    private_nonce: c.Uuid,
    owner_pid: ?i32 = null,
    operator_boot_id: ?c.Uuid = null,
    deadline_ns: ?u64 = null,
    cleanup_deadline_ns: ?u64 = null,
    cleanup_until: ?u64 = null,
    started_at: ?u64 = null,
    observed_at: ?u64 = null,
    vm_id: ?c.Uuid = null,
    disk_id: ?c.Uuid = null,
    principal_id: ?c.Uuid = null,
    key_snapshot: ?@import("hyperv_azure").operations.KeySnapshot = null,
    public: ?evidence.Summary = null,
    private: ?evidence.Summary = null,
    public_at: ?u64 = null,
    private_at: ?u64 = null,
    acceptance_sha256: ?p.Hash = null,
    completion_sha256: ?p.Hash = null,
    actions: [c.action_count]Observation = [_]Observation{.{}} ** c.action_count,
    spent: c.Debit = .{ .staged = c.emergency_bytes + c.worker_output_reservation, .control = c.emergency_bytes + c.worker_output_reservation },
    failures: core.diagnostics.Failures = .{},

    pub fn validate(self: State, input: *const c.Input) !void {
        if (self.admitted_at < input.approved.not_before or self.admitted_at >= input.approved.expires_at)
            return error.InvalidAdmissionTime;
        if (self.started_at) |started| if (started < self.admitted_at) return error.InvalidAdmissionTime;
        if (self.owner_pid) |pid| if (pid <= 1) return error.InvalidState;
        if (!std.mem.eql(u8, self.schema, "uk-hyperv-preflight-state-v1") or self.kind != input.kind or
            !std.mem.eql(u8, &self.run_id, &input.approved.authority.owner_run) or
            !std.meta.eql(self.binding, input.preparation.binding) or
            !std.mem.eql(u8, &self.input_sha256, &input.preparation.input_manifest_sha256)) return error.NativeBindingMismatch;
        inline for (.{ "attempt", "public_nonce", "private_nonce" }) |field| try p.validUuid(try core.contracts.parseUuid(&@field(self, field)));
        if (std.mem.eql(u8, &self.public_nonce, &self.private_nonce)) return error.InvalidNonce;
        try self.spent.validate();
        if (self.spent.staged > input.approved.budget.controller.staged or self.spent.control > input.approved.budget.controller.control) return error.BudgetExceeded;
        if (self.phase == .prepared and (self.owner_pid != null or self.deadline_ns != null or self.started_at != null)) return error.InvalidState;
        if (self.phase != .prepared and (self.owner_pid == null or self.deadline_ns == null or self.operator_boot_id == null or self.started_at == null)) return error.InvalidState;
        if (self.kind == .synthetic and self.phase == .completed) return error.SyntheticEvidence;
        if (self.public) |value| if (value.count != 2 or value.phase != .public or value.kind != self.kind) return error.InvalidState;
        if (self.private) |value| if (value.count != 4 or value.phase != .private or value.kind != self.kind) return error.InvalidState;
    }
};
pub const Intent = struct {
    schema: []const u8 = "uk-hyperv-preflight-operation-v1",
    attempt: c.Uuid,
    run_id: c.Uuid,
    authority_sha256: p.Hash,
    action: c.Action,
    native: c.NativeBinding,
    reserved: c.Debit,
};
pub const FailureRecord = struct {
    attempt: c.Uuid,
    authority_sha256: p.Hash,
    failures: core.diagnostics.Failures,
};
pub const VmRecord = struct { attempt: c.Uuid, vm_id: c.Uuid };
pub const Store = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    lock: *core.private_files.Locked,
    input: *const c.Input,
    state: State,
    recovery_only: bool = false,

    pub fn prepare(allocator: std.mem.Allocator, io: std.Io, lock: *core.private_files.Locked, input: *const c.Input, now: u64) !Store {
        var admitted = try input.validate(allocator, now);
        defer admitted.deinit();
        const authority = try c.canonical(allocator, input.approved);
        defer allocator.free(authority);
        const preparation = try c.canonical(allocator, input.preparation);
        defer allocator.free(preparation);
        var store: Store = .{ .allocator = allocator, .io = io, .lock = lock, .input = input, .state = .{
            .kind = input.kind,
            .run_id = input.approved.authority.owner_run,
            .binding = input.preparation.binding,
            .input_sha256 = input.preparation.input_manifest_sha256,
            .preparation_sha256 = p.hash(preparation),
            .authority_sha256 = p.hash(authority),
            .admitted_at = now,
            .attempt = randomUuid(io),
            .public_nonce = randomUuid(io),
            .private_nonce = randomUuid(io),
        } };
        try store.charge(authority.len, true);
        const published = lock.createImmutable(io, "admitted-context.json", authority) catch |err| switch (err) {
            error.PathAlreadyExists => return error.AttemptConsumed,
            else => return err,
        };
        try durable(published);
        const bytes = try store.reserveStateCopies(1);
        defer allocator.free(bytes);
        try durable(try lock.createImmutable(io, "state.json", bytes));
        try store.save();
        return store;
    }

    pub fn open(allocator: std.mem.Allocator, io: std.Io, lock: *core.private_files.Locked, input: *const c.Input) !Store {
        return load(allocator, io, lock, input, false);
    }
    pub fn openRecovery(allocator: std.mem.Allocator, io: std.Io, lock: *core.private_files.Locked, input: *const c.Input) !Store {
        return load(allocator, io, lock, input, true);
    }
    fn load(allocator: std.mem.Allocator, io: std.Io, lock: *core.private_files.Locked, input: *const c.Input, recovery: bool) !Store {
        // The recovery checkpoint is committed before the public state. Cleanup
        // never needs to overwrite, follow or trust a damaged state.json path.
        const bytes = try lock.directory.read(io, allocator, if (recovery) "recovery.json" else "state.json", c.max_state, null);
        defer allocator.free(bytes);
        const parsed = try c.parse(State, allocator, bytes);
        defer parsed.deinit();
        var state = parsed.value;
        state.schema = "uk-hyperv-preflight-state-v1";
        try parsed.value.validate(input);
        const preparation = try c.canonical(allocator, input.preparation);
        defer allocator.free(preparation);
        if (!std.mem.eql(u8, &p.hash(preparation), &state.preparation_sha256)) return error.NativeBindingMismatch;
        const expected = try c.canonical(allocator, input.approved);
        defer allocator.free(expected);
        if (!std.mem.eql(u8, &p.hash(expected), &state.authority_sha256)) return error.AuthorityMismatch;
        const admitted = try lock.directory.read(io, allocator, "admitted-context.json", c.max_state, state.authority_sha256);
        defer allocator.free(admitted);
        var store: Store = .{ .allocator = allocator, .io = io, .lock = lock, .input = input, .state = state, .recovery_only = recovery };
        var validated = try store.admission();
        defer validated.deinit();
        const consumed = lock.directory.read(io, allocator, "attempt-consumed.json", c.max_state, null) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        defer if (consumed) |raw| allocator.free(raw);
        if (consumed) |raw| {
            const claim = try c.parse(State, allocator, raw);
            defer claim.deinit();
            try claim.value.validate(input);
            if (claim.value.phase != .running or !std.mem.eql(u8, &claim.value.attempt, &state.attempt) or
                claim.value.admitted_at != state.admitted_at or
                !std.mem.eql(u8, &claim.value.authority_sha256, &state.authority_sha256) or
                !std.mem.eql(u8, &claim.value.preparation_sha256, &state.preparation_sha256)) return error.InvalidIntent;
            if (state.phase == .prepared) {
                store.state = claim.value;
                store.state.schema = "uk-hyperv-preflight-state-v1";
                store.state.phase = .cleaning;
                store.fail(.primary, .{ .stage = .process_run, .category = .ambiguous });
            }
        } else if (state.phase != .prepared) return error.MissingDurableIntent;
        for (&store.state.actions, 0..) |*entry, i| {
            const action: c.Action = @enumFromInt(i);
            const name = try store.intentName(action);
            defer allocator.free(name);
            const file = lock.directory.openFile(io, name) catch |err| switch (err) {
                error.FileNotFound => {
                    if (entry.status != .fresh) return error.MissingDurableIntent;
                    continue;
                },
                else => return err,
            };
            file.close(io);
            const raw = try lock.directory.read(io, allocator, name, 4096, null);
            defer allocator.free(raw);
            const intent = try c.parse(Intent, allocator, raw);
            defer intent.deinit();
            if (!std.meta.eql(intent.value.native, input.preparation.binding) or
                !std.mem.eql(u8, intent.value.schema, "uk-hyperv-preflight-operation-v1") or intent.value.action != action or
                !std.mem.eql(u8, &intent.value.attempt, &state.attempt) or !std.mem.eql(u8, &intent.value.run_id, &state.run_id) or
                !std.mem.eql(u8, &intent.value.authority_sha256, &state.authority_sha256)) return error.InvalidIntent;
            if (entry.status == .fresh or entry.status == .intent) {
                entry.status = .unknown;
                entry.effect = if (action.mutation()) .unknown else .not_applicable;
                store.state.phase = .cleaning;
                store.fail(.primary, .{ .stage = .admission, .category = .ambiguous });
            }
            try intent.value.reserved.validate();
            store.state.spent.staged = @max(store.state.spent.staged, intent.value.reserved.staged);
            store.state.spent.control = @max(store.state.spent.control, intent.value.reserved.control);
        }
        const original_vm = lock.directory.read(io, allocator, "reconciled-vm.json", 4096, null) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        defer if (original_vm) |raw| allocator.free(raw);
        if (original_vm) |raw| {
            const record = try c.parse(VmRecord, allocator, raw);
            defer record.deinit();
            if (!std.mem.eql(u8, &record.value.attempt, &state.attempt)) return error.InvalidIntent;
            try p.validUuid(try core.contracts.parseUuid(&record.value.vm_id));
            if (store.state.vm_id) |id| if (!std.mem.eql(u8, &id, &record.value.vm_id)) return error.OriginalIdentityMismatch;
            store.state.vm_id = record.value.vm_id;
        }
        const notice = lock.directory.read(io, allocator, "recording-failure.json", c.emergency_bytes, null) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        defer if (notice) |raw| allocator.free(raw);
        if (notice) |raw| {
            const failure = try c.parse(FailureRecord, allocator, raw);
            defer failure.deinit();
            if (!std.mem.eql(u8, &failure.value.attempt, &state.attempt) or
                !std.mem.eql(u8, &failure.value.authority_sha256, &state.authority_sha256)) return error.InvalidIntent;
            if (failure.value.failures.primary) |v| store.fail(.primary, v);
            if (failure.value.failures.cleanup) |v| store.fail(.cleanup, v);
            if (failure.value.failures.recording) |v| store.fail(.recording, v);
            if (failure.value.failures.primary == null and failure.value.failures.cleanup == null and failure.value.failures.recording == null)
                return error.InvalidIntent;
            if (store.state.phase == .running or store.state.phase == .completed or store.state.phase == .synthetic_completed)
                store.state.phase = .cleaning;
        }
        try store.state.validate(input);
        return store;
    }

    pub fn save(self: *Store) !void {
        const bytes = try self.reserveStateCopies(if (self.recovery_only) 1 else 2);
        defer self.allocator.free(bytes);
        try durable(self.lock.commit(self.io, "recovery.json", bytes) catch return error.RecordingFailed);
        if (!self.recovery_only) try durable(self.lock.commit(self.io, "state.json", bytes) catch return error.RecordingFailed);
    }
    pub fn admission(self: *const Store) !p.Admission {
        // Historical validation instant is independent of the live execution
        // and cleanup authority clocks, which never renew this admission.
        return self.input.validate(self.allocator, self.state.admitted_at);
    }
    fn reserveStateCopies(self: *Store, count: usize) ![]u8 {
        try self.state.validate(self.input);
        const before = self.state.spent;
        var accounted: usize = 0;
        for (0..6) |_| {
            const bytes = try c.canonical(self.allocator, self.state);
            errdefer self.allocator.free(bytes);
            const copies = count * bytes.len;
            if (bytes.len > c.max_state or copies > self.input.approved.budget.controller.staged - before.staged or
                copies > self.input.approved.budget.controller.control - before.control) return error.RecordingBudgetExceeded;
            if (copies == accounted) return bytes;
            self.allocator.free(bytes);
            accounted = copies;
            self.state.spent = .{ .staged = before.staged + accounted, .control = before.control + accounted };
        }
        return error.UnstableRecordSize;
    }
    pub fn charge(self: *Store, bytes: u64, control: bool) !void {
        const limit = self.input.approved.budget.controller;
        if (bytes > limit.staged - self.state.spent.staged or (control and bytes > limit.control - self.state.spent.control))
            return error.BudgetExceeded;
        self.state.spent.staged += bytes;
        if (control) self.state.spent.control += bytes;
    }
    pub fn immutable(self: *Store, name: []const u8, bytes: []const u8, control: bool) !void {
        try self.charge(bytes.len, control);
        try self.save();
        try durable(try self.lock.createImmutable(self.io, name, bytes));
    }
    pub fn begin(self: *Store, action: c.Action, reserve: u64, control: bool) !void {
        const entry = &self.state.actions[@intFromEnum(action)];
        if (entry.status != .fresh) return error.AttemptConsumed;
        try self.charge(reserve, control);
        try self.charge(4096, true);
        const intent: Intent = .{ .attempt = self.state.attempt, .run_id = self.state.run_id, .authority_sha256 = self.state.authority_sha256, .action = action, .native = self.state.binding, .reserved = self.state.spent };
        const bytes = try c.canonical(self.allocator, intent);
        defer self.allocator.free(bytes);
        const name = try self.intentName(action);
        defer self.allocator.free(name);
        if (bytes.len > 4096) return error.RecordingBudgetExceeded;
        try durable(try self.lock.createImmutable(self.io, name, bytes));
        entry.status = .intent;
        entry.effect = if (action.mutation()) .unknown else .not_applicable;
        try self.save();
    }
    pub fn consume(self: *Store) !void {
        // A complete claim survives interruption before either mutable snapshot.
        // Reserve its bounded maximum before writing the consumption marker.
        try self.charge(16384, true);
        const bytes = try c.canonical(self.allocator, self.state);
        defer self.allocator.free(bytes);
        if (bytes.len > 16384) return error.RecordingBudgetExceeded;
        const result = self.lock.createImmutable(self.io, "attempt-consumed.json", bytes) catch |err| switch (err) {
            error.PathAlreadyExists => return error.AttemptConsumed,
            else => return error.RecordingFailed,
        };
        try durable(result);
    }
    pub fn fail(self: *Store, lane: c.Lane, failure: core.diagnostics.Diagnostic) void {
        self.state.failures.record(switch (lane) {
            .primary => .primary,
            .cleanup => .cleanup,
            .recording => .recording,
        }, failure) catch unreachable;
    }
    fn intentName(self: *Store, action: c.Action) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "intent-{s}.json", .{@tagName(action)});
    }
};

pub fn durable(result: core.private_files.CommitResult) !void {
    if (result.status != .durable or result.failures.primary != null or result.failures.recording != null or result.failures.cleanup != null)
        return error.RecordingFailed;
}
pub fn randomUuid(io: std.Io) c.Uuid {
    var bytes: p.Uuid = undefined;
    io.random(&bytes);
    bytes[6] = (bytes[6] & 15) | 0x40;
    bytes[8] = (bytes[8] & 63) | 0x80;
    return p.uuidText(bytes);
}
