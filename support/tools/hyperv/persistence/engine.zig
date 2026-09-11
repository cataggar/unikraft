const std = @import("std");
const core = @import("hyperv_core");
const contract = @import("contract.zig");
const local = @import("local.zig");
const m = @import("model.zig");
const evidence = @import("evidence.zig");

pub const Reply = struct {
    value: m.Result,
    document: ?local.Document(m.Result) = null,
    pub fn deinit(self: Reply) void {
        if (self.document) |document| document.deinit();
    }
};
/// Injected implementations are trusted in-process adapters. Production uses
/// worker.Supervisor: one directly owned leaf process per typed job.
pub const Driver = struct {
    context: *anyopaque,
    executeFn: *const fn (*anyopaque, m.Job) anyerror!Reply,
    serialFn: *const fn (*anyopaque, std.mem.Allocator, m.Step, m.Serial) anyerror![]u8,
    recoverFn: ?*const fn (*anyopaque, *m.State) anyerror!void = null,
};
const Consumed = struct { input_sha256: local.Hash, nonce: local.Hash, schema_version: u8, deadline_ns: u64 };
pub const Options = struct {
    trusted: contract.TrustedInputs,
    driver: Driver,
    cancellation: ?*const std.atomic.Value(bool) = null,
    record_hook: ?RecordHook = null,
};
pub const RecordHook = struct { context: *anyopaque, call: *const fn (*anyopaque) anyerror!void };
pub const Store = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    lock: *core.private_files.Locked,
    state: m.State,
    /// A test-only in-process durability fault boundary, never a CLI option.
    beforeRecord: ?RecordHook = null,

    pub fn persist(self: *Store) !void {
        try self.state.validate();
        if (self.beforeRecord) |hook| hook.call(hook.context) catch return error.RecordingFailed;
        const bytes = try local.encode(self.allocator, self.state);
        defer self.allocator.free(bytes);
        const result = self.lock.commit(self.io, "state.json", bytes) catch return error.RecordingFailed;
        m.merge(&self.state.failures, result.failures);
        if (result.status != .durable or result.failures.recording != null or result.failures.cleanup != null)
            return error.RecordingFailed;
    }
};

/// Local preparation records metadata only. It neither opens a seed/image nor
/// consumes an attempt, grants authority, creates cloud resources or changes IDs.
pub fn prepare(allocator: std.mem.Allocator, io: std.Io, directory: core.private_files.Directory, input: contract.Contract) !local.Hash {
    try input.validate();
    var lock = try directory.lock(io);
    defer lock.close(io);
    const bytes = try local.encode(allocator, input);
    defer allocator.free(bytes);
    const binding = local.hash(bytes);
    const created = try lock.createImmutable(io, "contract.json", bytes);
    if (created.status != .durable or created.failures.recording != null or created.failures.cleanup != null) return error.RecordingFailed;
    var nonce: [32]u8 = undefined;
    io.random(&nonce);
    const state: m.State = .{ .input_sha256 = binding, .nonce = std.fmt.bytesToHex(nonce, .lower), .control_bytes = input.control_bytes };
    const state_bytes = try local.encode(allocator, state);
    defer allocator.free(state_bytes);
    const prepared = try lock.createImmutable(io, "state.json", state_bytes);
    if (prepared.status != .durable or prepared.failures.recording != null or prepared.failures.cleanup != null) return error.RecordingFailed;
    return binding;
}

pub fn loadState(allocator: std.mem.Allocator, io: std.Io, directory: core.private_files.Directory, binding: local.Hash) !m.State {
    const bytes = try directory.read(io, allocator, "state.json", local.maximum, null);
    defer allocator.free(bytes);
    const parsed = try local.Document(m.State).load(allocator, bytes);
    defer parsed.deinit();
    var state = parsed.value;
    try state.validate();
    state.contract = "uk.hyperv.persistence-state";
    if (!std.mem.eql(u8, &state.input_sha256, &binding)) return error.ContractSubstitution;
    const marker = directory.read(io, allocator, "consumed.json", 1024, null) catch |err| switch (err) {
        error.FileNotFound => if (state.consumed) return error.InvalidConsumption else null,
        else => return err,
    };
    if (marker) |raw| {
        defer allocator.free(raw);
        const consumed = try local.Document(Consumed).load(allocator, raw);
        defer consumed.deinit();
        if (consumed.value.schema_version != 1 or consumed.value.deadline_ns == 0 or
            !std.mem.eql(u8, &consumed.value.input_sha256, &binding) or
            !std.mem.eql(u8, &consumed.value.nonce, &state.nonce) or
            (state.consumed and state.attempt_deadline_ns != consumed.value.deadline_ns)) return error.InvalidConsumption;
        if (!state.consumed) {
            // Crash window after immutable consumption, before the first state
            // publication. Inspect and cleanup must never call this unconsumed.
            state.consumed = true;
            state.phase = .failed;
            state.cleanup_required = true;
            state.attempt_deadline_ns = consumed.value.deadline_ns;
            state.failures.recording = state.failures.recording orelse .{ .stage = .state_record, .category = .ambiguous };
        }
    }
    const input = try contract.load(allocator, io, directory);
    defer input.deinit();
    if (!std.mem.eql(u8, &input.binding, &binding)) return error.ContractSubstitution;
    for ([_]m.Step{ .os_upload, .data_upload }) |step| {
        const record = state.records[@intFromEnum(step)];
        const source = if (step == .os_upload) input.value.guest else input.value.data;
        if (record.page_report) |page| if (page.plan.bytes != source.size) return error.InvalidTransfer;
        if (record.progress == .done) {
            const outcome = record.transfer orelse return error.InvalidTransfer;
            if (outcome.bytes_accepted != source.size or !std.mem.eql(u8, &std.fmt.bytesToHex(outcome.sha256.?, .lower), &source.sha256) or
                !std.mem.eql(u8, &std.fmt.bytesToHex(outcome.footer_sha256.?, .lower), &source.footer_sha256)) return error.InvalidTransfer;
        }
    }
    if (state.boot1) |first| {
        const serial = try directory.read(io, allocator, "boot1.serial", contract.serial_limit, try core.contracts.parseSha256(&first.sha256));
        defer allocator.free(serial);
        if (!std.meta.eql(try evidence.parse(serial, 1, input.value, null), first)) return error.InvalidEvidence;
    }
    if (state.boot2) |second| {
        const serial = try directory.read(io, allocator, "boot2.serial", contract.serial_limit, null);
        defer allocator.free(serial);
        if (!std.meta.eql(try evidence.parse(try evidence.boot2Suffix(serial, state.boot1.?), 2, input.value, state.boot1), second))
            return error.InvalidEvidence;
    }
    return state;
}

pub fn execute(allocator: std.mem.Allocator, io: std.Io, directory: core.private_files.Directory, options: Options, cleanup_only: bool) !m.State {
    const input = try contract.load(allocator, io, directory);
    defer input.deinit();
    var lock = try directory.lock(io);
    defer lock.close(io);
    var store: Store = .{ .allocator = allocator, .io = io, .lock = &lock, .state = try loadState(allocator, io, directory, input.binding), .beforeRecord = options.record_hook };
    if (cleanup_only) {
        try options.trusted.validate(input.value, input.binding, .cleanup);
        if (!store.state.consumed) return error.NoConsumedAttempt;
        for (store.state.records) |record| if (record.progress == .intent) {
            const recover = options.driver.recoverFn orelse return error.ProcessRecoveryRequired;
            try recover(options.driver.context, &store.state);
            break;
        };
        cleanup(&store, input.value, options) catch |err| recordFailure(&store, if (err == error.RecordingFailed) .recording else .cleanup, err);
    } else {
        if (store.state.phase != .prepared or store.state.consumed) return error.AttemptConsumed;
        const prior = directory.openFile(io, "consumed.json") catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (prior) |file| {
            file.close(io);
            return error.AttemptConsumed;
        }
        try options.trusted.validate(input.value, input.binding, .execution);
        const deadline = try core.process.Deadline.afterMilliseconds(input.value.runtime_seconds * 1000);
        store.state.consumed = true;
        store.state.phase = .running;
        store.state.attempt_deadline_ns = deadline.expires_ns;
        const marker = try local.encode(allocator, Consumed{ .input_sha256 = input.binding, .nonce = store.state.nonce, .schema_version = 1, .deadline_ns = deadline.expires_ns });
        defer allocator.free(marker);
        const consumed = try lock.createImmutable(io, "consumed.json", marker);
        m.merge(&store.state.failures, consumed.failures);
        if (consumed.status != .durable or consumed.failures.recording != null or consumed.failures.cleanup != null) {
            recordFailure(&store, .recording, error.RecordingFailed);
            return store.state;
        }
        run(&store, input.value, options) catch |err| recordFailure(&store, if (err == error.RecordingFailed) .recording else .primary, err);
        if (store.state.cleanup_required) cleanup(&store, input.value, options) catch |err| recordFailure(&store, if (err == error.RecordingFailed) .recording else .cleanup, err);
    }
    store.persist() catch |err| recordFailure(&store, .recording, err);
    return store.state;
}

fn run(store: *Store, input: contract.Contract, options: Options) !void {
    try store.persist();
    for (0..m.execution_count) |index| {
        const step: m.Step = @enumFromInt(index);
        try perform(store, input, options, step);
    }
    store.state.phase = .two_boots_verified;
    try store.persist();
}

fn perform(store: *Store, input: contract.Contract, options: Options, step: m.Step) !void {
    if (!store.state.process_cleanup_complete) return error.UnreapedWorker;
    if (!step.cleanup()) {
        if (options.cancellation) |cancel| if (cancel.load(.acquire)) return error.Cancelled;
        if (try core.process.monotonicNanoseconds() >= store.state.attempt_deadline_ns) return error.Deadline;
    }
    try options.trusted.validate(input, store.state.input_sha256, if (step.cleanup()) .cleanup else .execution);
    if (store.state.record(step).progress != .unissued) return error.MutationReplay;
    if (step == .start_boot2 and (store.state.boot1 == null or !store.state.isDone(.observe_deallocated) or store.state.boot_count != 1))
        return error.InvalidRestartIntent;
    if (step == .deploy_boot1) store.state.boot_count = 1;
    if (step == .start_boot2) store.state.boot_count = 2;
    if (step == .os_grant) store.state.os_access_pending = true;
    if (step == .data_grant) store.state.data_access_pending = true;
    if (step.mutation()) store.state.cleanup_required = true;
    store.state.record(step).* = .{ .progress = .intent, .effect = if (step.mutation()) .unknown else .not_applicable };
    // The attempt and every mutating job are durable before a child can start.
    try store.persist();
    const now = try core.process.monotonicNanoseconds();
    const total_deadline = if (step.cleanup()) store.state.cleanup_deadline_ns.? else store.state.attempt_deadline_ns;
    if (now >= total_deadline) return error.Deadline;
    const job: m.Job = .{
        .input = input,
        .input_sha256 = store.state.input_sha256,
        .nonce = store.state.nonce,
        .step = step,
        .originals = store.state.originals,
        .parent_pid = @intCast(std.os.linux.getpid()),
        .deadline_ns = @min(total_deadline, now + @as(u64, input.operation_ms) * std.time.ns_per_ms),
        .authority_lane = if (step.cleanup()) .cleanup else .execution,
        .boot1 = store.state.boot1,
        .creation_intent = .{
            store.state.mayOwn(.os_create),
            store.state.mayOwn(.data_create),
            store.state.mayOwn(.deploy_boot1),
        },
        .network_intent = .{ store.state.mayOwn(.network_nsg), store.state.mayOwn(.network_vnet), store.state.mayOwn(.network_nic) },
        .group_intent = store.state.mayOwn(.group_create),
    };
    var reply = options.driver.executeFn(options.driver.context, job) catch |err| {
        store.state.record(step).progress = .failed;
        return err;
    };
    defer reply.deinit();
    const result = reply.value;
    try result.validate();
    const encoded_job = try local.encode(store.allocator, job);
    defer store.allocator.free(encoded_job);
    if (result.step != step or !std.mem.eql(u8, &result.nonce, &job.nonce) or
        !std.mem.eql(u8, &result.job_sha256, &local.hash(encoded_job))) return error.StaleWorker;
    store.state.record(step).* = .{
        .progress = if (result.complete) .done else .failed,
        .effect = result.effect,
        .transfer = result.transfer,
        .page_report = result.page_report,
        .http_status = result.http_status,
        .service_code = result.service_code,
        .access_metadata = result.access_metadata,
    };
    m.mergeStep(&store.state.failures, result.failures, step);
    store.state.process_cleanup_complete = result.process_cleanup_complete;
    // Private, bound observation survives failed delivery; never relearn a
    // replacement UUID merely because its worker acknowledgment was lost.
    store.state.retainOriginals(step, result.observation.originals) catch |err| {
        store.state.record(step).progress = .failed;
        return err;
    };
    store.state.reconcileUnstartedGrant(step);
    if (!result.complete or !result.process_cleanup_complete) return error.WorkerFailed;
    accept(store, input, options.driver, step, result) catch |err| {
        store.state.record(step).progress = .failed;
        return err;
    };
    try store.persist();
}

fn accept(store: *Store, input: contract.Contract, driver: Driver, step: m.Step, result: m.Result) !void {
    const observation = result.observation;
    switch (step) {
        .os_create => if (store.state.originals.os == null) return error.MissingIdentity,
        .data_create => if (store.state.originals.data == null) return error.MissingIdentity,
        .deploy_boot1 => if (store.state.originals.vm == null) return error.MissingIdentity,
        .os_upload, .data_upload => {
            const actual = result.transfer orelse return error.InvalidTransfer;
            const expected = if (step == .os_upload) input.guest else input.data;
            if (actual.completion != .complete or actual.side_effect != .accepted or actual.bytes_accepted != expected.size or
                actual.bytes_streamed != expected.size or actual.sha256 == null or
                !std.mem.eql(u8, &std.fmt.bytesToHex(actual.sha256.?, .lower), &expected.sha256) or actual.footer_sha256 == null or
                !std.mem.eql(u8, &std.fmt.bytesToHex(actual.footer_sha256.?, .lower), &expected.footer_sha256)) return error.InvalidTransfer;
            if (result.page_report) |page| if (page.plan.bytes != expected.size) return error.InvalidTransfer;
        },
        .observe_boot1, .observe_boot2 => {
            if (!observation.envelope or observation.power != .running or
                !std.meta.eql(observation.originals, store.state.originals)) return error.InvalidEnvelope;
        },
        .observe_deallocated, .observe_final_deallocated => {
            if (!observation.envelope or observation.power != .deallocated or
                !std.meta.eql(observation.originals, store.state.originals)) return error.InvalidEnvelope;
        },
        .serial_boot1, .serial_boot2 => {
            const serial = result.serial orelse return error.EvidenceIncomplete;
            const full = try driver.serialFn(driver.context, store.allocator, step, serial);
            defer store.allocator.free(full);
            if (full.len != serial.bytes or !std.mem.eql(u8, &local.hash(full), &serial.sha256)) return error.SerialSubstitution;
            const second = step == .serial_boot2;
            const segment = if (second) try evidence.boot2Suffix(full, store.state.boot1.?) else full;
            const parsed = try evidence.parse(segment, if (second) 2 else 1, input, if (second) store.state.boot1 else null);
            const saved = try store.lock.createImmutable(store.io, if (second) "boot2.serial" else "boot1.serial", full);
            m.merge(&store.state.failures, saved.failures);
            if (saved.status != .durable or saved.failures.recording != null or saved.failures.cleanup != null) return error.RecordingFailed;
            if (second) store.state.boot2 = parsed else store.state.boot1 = parsed;
        },
        .os_access_closed, .cleanup_os_access => {
            if (!result.access_closed) return error.AccessUnresolved;
            store.state.os_access_pending = false;
        },
        .data_access_closed, .cleanup_data_access => {
            if (!result.access_closed) return error.AccessUnresolved;
            store.state.data_access_pending = false;
        },
        .cleanup_observe => if (observation.group != .absent and !observation.owned_inventory) return error.UnownedResources,
        .cleanup_absence => {
            if (observation.group != .absent or result.http_status != 404 or result.service_code != .ResourceGroupNotFound)
                return error.InvalidAbsence;
            store.state.group_absent = true;
        },
        .cleanup_dispose => {
            if (!result.secrets_disposed) return error.SecretDisposalFailed;
            store.state.secrets_disposed = true;
        },
        else => {},
    }
}

fn cleanup(store: *Store, input: contract.Contract, options: Options) !void {
    try options.trusted.validate(input, store.state.input_sha256, .cleanup);
    if (!store.state.process_cleanup_complete) return error.UnreapedWorker;
    if (store.state.cleanup_deadline_ns == null) {
        store.state.cleanup_deadline_ns = (try core.process.Deadline.afterMilliseconds(input.cleanup_seconds * 1000)).expires_ns;
        try store.persist();
    }
    // Interrupted main jobs are never resumed. Only new cleanup actions and
    // bounded read-only reconciliation are eligible under cleanup authority.
    for (m.execution_count..m.step_count) |index| {
        const step: m.Step = @enumFromInt(index);
        const record = store.state.record(step);
        if (step == .cleanup_dispose and (store.state.os_access_pending or store.state.data_access_pending)) {
            recordFailure(store, .cleanup, error.AccessUnresolved);
            continue;
        }
        if (record.progress == .done or record.progress == .skipped) continue;
        if (record.progress != .unissued) {
            if (step.mutation()) {
                recordFailure(store, .cleanup, error.AmbiguousCleanup);
                continue;
            }
            // The supervisor creates a fresh read-only job, never restarts the
            // consumed child job. Its generation is selected by the driver.
            record.* = .{};
        }
        const skip = switch (step) {
            .cleanup_os_revoke => !store.state.os_access_pending or store.state.originals.os == null or
                store.state.records[@intFromEnum(m.Step.os_revoke)].progress != .unissued,
            .cleanup_data_revoke => !store.state.data_access_pending or store.state.originals.data == null or
                store.state.records[@intFromEnum(m.Step.data_revoke)].progress != .unissued,
            .cleanup_deallocate => store.state.originals.vm == null or store.state.isDone(.observe_final_deallocated) or
                (store.state.isDone(.observe_deallocated) and
                    (store.state.records[@intFromEnum(m.Step.start_boot2)].progress == .unissued or
                        store.state.records[@intFromEnum(m.Step.start_boot2)].effect == .not_started)) or
                store.state.records[@intFromEnum(m.Step.deallocate_boot1)].progress == .intent or
                store.state.records[@intFromEnum(m.Step.deallocate_boot1)].progress == .failed or
                store.state.records[@intFromEnum(m.Step.deallocate_boot2)].progress == .intent or
                store.state.records[@intFromEnum(m.Step.deallocate_boot2)].progress == .failed,
            .cleanup_os_access => !store.state.os_access_pending,
            .cleanup_data_access => !store.state.data_access_pending,
            else => false,
        };
        if (skip) {
            record.progress = .skipped;
            try store.persist();
            continue;
        }
        perform(store, input, options, step) catch |err| {
            recordFailure(store, if (err == error.RecordingFailed) .recording else .cleanup, err);
            if (step == .cleanup_observe or !store.state.process_cleanup_complete) return err;
        };
    }
    if (store.state.group_absent and !store.state.os_access_pending and !store.state.data_access_pending and
        store.state.secrets_disposed and store.state.process_cleanup_complete)
    {
        store.state.cleanup_required = false;
        store.state.phase = .cleaned;
    } else return error.CleanupIncomplete;
}

fn recordFailure(store: *Store, lane: enum { primary, cleanup, recording }, err: anyerror) void {
    const diagnostic: core.diagnostics.Diagnostic = .{
        .stage = if (lane == .recording) .state_record else if (lane == .cleanup) .cleanup else .admission,
        .category = switch (err) {
            error.Deadline => .timeout,
            error.Cancelled => .cancelled,
            error.RecordingFailed => .local_io,
            error.AmbiguousCleanup => .ambiguous,
            error.WorkerFailed, error.UnreapedWorker => .child_failed,
            else => .integrity,
        },
    };
    switch (lane) {
        .primary => if (store.state.failures.primary == null) {
            store.state.failures.primary = diagnostic;
        },
        .cleanup => if (store.state.failures.cleanup == null) {
            store.state.failures.cleanup = diagnostic;
        },
        .recording => if (store.state.failures.recording == null) {
            store.state.failures.recording = diagnostic;
        },
    }
    if (store.state.phase != .cleaned) store.state.phase = .failed;
}
