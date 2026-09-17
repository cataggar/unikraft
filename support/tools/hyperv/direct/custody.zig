// SPDX-License-Identifier: BSD-3-Clause
//! Local, create-only custody. Callers own validation, process statuses and cloud policy.
//! A failed writer is poisoned; retained reservations are never rolled back or resumed.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const direct = @import("main.zig");
const files = core.private_files;
const linux = std.os.linux;

pub const Scope = direct.Scope;
pub const Artifact = direct.Artifact;
pub const SerialMode = direct.SerialMode;
pub const Digest = core.contracts.Sha256;
pub const cli_limit = 8 * 1024 * 1024;
pub const record_limit = 4 * 1024 * 1024;

pub const Phase = enum {
    @"local-admission",
    @"seed-consumed",
    @"group-create-intent",
    @"os-create-intent",
    @"os-grant-intent",
    @"os-native-upload-intent",
    @"os-revoke-intent",
    @"data-create-intent",
    @"data-grant-intent",
    @"data-native-upload-intent",
    @"data-revoke-intent",
    @"boot1-deploy-intent",
    @"boot1-evidence-complete",
    @"deallocate-intent",
    @"boot2-start-intent",
    @"boot2-evidence-complete",
    @"final-deallocate-intent",
    @"persistence-evidence-complete",
    @"cleanup-intent",
    @"cleanup-delete-intent",
};

pub const Event = struct { phase: Phase, reserved_boots: u8 };
pub const Identities = struct {
    vm_id: []const u8,
    vm_uuid: []const u8,
    os_id: []const u8,
    os_uuid: []const u8,
    data_id: []const u8,
    data_uuid: []const u8,

    fn validate(self: Identities) !void {
        inline for (std.meta.fields(Identities)) |field|
            if (@field(self, field.name).len == 0) return error.MissingIdentity;
    }

    fn equal(a: Identities, b: Identities) bool {
        inline for (std.meta.fields(Identities)) |field|
            if (!std.mem.eql(u8, @field(a, field.name), @field(b, field.name))) return false;
        return true;
    }

    fn clone(self: Identities, allocator: std.mem.Allocator) !Identities {
        var result: Identities = undefined;
        inline for (std.meta.fields(Identities)) |field|
            @field(result, field.name) = try allocator.dupe(u8, @field(self, field.name));
        return result;
    }
};

pub const CaptureRecord = struct {
    schema: []const u8 = "uk.hyperv.direct-serial-capture",
    version: u8 = 1,
    boot: u8,
    poll: u8,
    serial_mode: SerialMode,
    serial_sha256: []const u8,
    cli_wrapper_sha256: []const u8,
    scope_sha256: []const u8,
    vm_id: []const u8,
    vm_uuid: []const u8,
    os_id: []const u8,
    os_uuid: []const u8,
    data_id: []const u8,
    data_uuid: []const u8,
    vm_observation_sha256: []const u8,
    original_boot1_sha256: []const u8,
    boot2_admission_sha256: []const u8,
};

pub const AdmissionRecord = struct {
    schema: []const u8 = "uk.hyperv.direct-boot2-admission",
    version: u8 = 1,
    reserved_boots: u8 = 2,
    scope_sha256: []const u8,
    original_boot1_sha256: []const u8,
    boot1_capture_sha256: []const u8,
    vm_id: []const u8,
    vm_uuid: []const u8,
    os_id: []const u8,
    os_uuid: []const u8,
    data_id: []const u8,
    data_uuid: []const u8,
    retained_vm_sha256: []const u8,
    retained_os_sha256: []const u8,
    retained_data_sha256: []const u8,
    deallocated_power_sha256: []const u8,
};

pub const Diagnostics = struct { attempted: bool = false, exit: ?u8 = null, decoded: bool = false };
pub const Freshness = struct { cached_reads: u8, cached_reason: ?[]const u8 };
pub const Outcome = struct {
    phase: Phase,
    primary_exit: u8,
    cleanup_exit: u8,
    reserved_boots: u8,
    persistence_evidence_complete: bool,
    owned_group_absent: bool,
    group_creation_attempted: bool,
    failure_diagnostics: Diagnostics,
    boot2_freshness: Freshness,
    accepted: bool,
};

/// Confirmed caller results, not inferred Azure observations. The final bounded
/// validator must have completed, including on a failed primary lane.
pub const Completion = struct {
    phase: Phase,
    primary_exit: u8,
    cleanup_exit: u8,
    persistence_evidence_complete: bool,
    owned_group_absent: bool,
    group_creation_attempted: bool,
    failure_diagnostics: Diagnostics = .{},
    final_input_exit: ?u8,
};

pub const FinalResult = struct {
    outcome: Outcome,
    recording: files.CommitResult = .{},
    /// Final evidence verification is separate from writing the outcome record.
    evidence_error: ?anyerror = null,
    recording_error: ?anyerror = null,
    cleanup_error: ?anyerror = null,
    exit_code: u8,
};

pub fn requireDurable(result: files.CommitResult) !void {
    switch (result.status) {
        .not_committed => return error.NotCommitted,
        .publication_unknown => return error.PublicationUnknown,
        .visible_not_durable => return error.VisibleNotDurable,
        .durable => {},
    }
    if (result.failures.primary != null or result.failures.cleanup != null or result.failures.recording != null)
        return error.CommitFailed;
}

pub fn encode(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(allocator);
    defer writer.deinit();
    try std.json.Stringify.value(value, .{}, &writer.writer);
    try writer.writer.writeByte('\n');
    return writer.toOwnedSlice();
}

/// Metadata references leave large input scans to the bounded native validator.
/// Paths are borrowed from Scope / explicit argv, and must outlive the reference.
pub const Reference = struct {
    path: []const u8,
    policy: files.FilePolicy,
    metadata: files.Snapshot,
    executable: bool = false,

    pub fn artifact(io: std.Io, item: Artifact, policy: files.FilePolicy) !Reference {
        const reference = try open(io, item.path, policy, false);
        if (reference.metadata.size != item.size) return error.ArtifactChanged;
        return reference;
    }

    pub fn tool(io: std.Io, path: []const u8) !Reference {
        return open(io, path, .artifact, true);
    }

    fn open(io: std.Io, path: []const u8, policy: files.FilePolicy, executable: bool) !Reference {
        const file = try files.openAbsolute(io, path, policy);
        defer file.close(io);
        const metadata = try files.snapshot(file);
        if (executable and metadata.mode & 0o111 == 0) return error.NotExecutable;
        return .{ .path = path, .policy = policy, .metadata = metadata, .executable = executable };
    }

    pub fn verify(self: Reference, io: std.Io) !void {
        const current = try open(io, self.path, self.policy, self.executable);
        if (!files.sameSnapshot(self.metadata, current.metadata)) return error.ReferenceChanged;
    }
};

pub const References = struct {
    artifacts: [5]Reference,
    tools: [3]Reference,

    pub fn capture(io: std.Io, scope: Scope, az: []const u8, uploader: []const u8, validator: []const u8) !References {
        return .{
            .artifacts = .{
                try Reference.artifact(io, scope.os_vhd, .artifact),
                try Reference.artifact(io, scope.seed_raw, .private),
                try Reference.artifact(io, scope.seed_vhd, .private),
                try Reference.artifact(io, scope.manifest, .artifact),
                try Reference.artifact(io, scope.config, .artifact),
            },
            .tools = .{ try Reference.tool(io, az), try Reference.tool(io, uploader), try Reference.tool(io, validator) },
        };
    }

    pub fn verify(self: References, io: std.Io) !void {
        for (self.artifacts) |reference| try reference.verify(io);
        for (self.tools) |reference| try reference.verify(io);
    }
};

pub const FileSnapshot = struct {
    metadata: files.Snapshot,
    sha256: Digest,

    pub fn hex(self: FileSnapshot) [64]u8 {
        return std.fmt.bytesToHex(self.sha256, .lower);
    }

    fn equal(a: FileSnapshot, b: FileSnapshot) bool {
        return files.sameSnapshot(a.metadata, b.metadata) and std.crypto.timing_safe.eql(Digest, a.sha256, b.sha256);
    }
};

pub const CaptureSources = struct {
    serial: FileSnapshot,
    cli_wrapper: FileSnapshot,
    vm_observation: FileSnapshot,
};
pub const Retained = struct {
    vm: FileSnapshot,
    os: FileSnapshot,
    data: FileSnapshot,
    power: FileSnapshot,
};
pub const Boot1 = struct { serial: FileSnapshot, capture: FileSnapshot };
pub const Boot2 = struct { admission: FileSnapshot, retained: Retained };
pub const FreshnessResult = enum { cached, fresh };

pub const TestFault = union(enum) {
    record: files.TestFault,
    directory_sync,
    after_first_reservation,
    after_identity_reservation,
    ledger_sync,
    event_write,
    event_sync,
    raw_file_sync,
    raw_publication,
    raw_directory_sync,
    hash_read,
    hash_after_digest,
    capability_unlink,
    capability_sync,
};

pub const RawTest = struct {
    source_failure: enum { none, read, hash, proof } = .none,
    cleanup_failure: enum { none, delete, directory_sync } = .none,
    named_scratch: ?u64 = null,
    delete_attempts: usize = 0,
    sync_attempts: usize = 0,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: files.Directory,
    writer: files.Locked,
    ledger: files.Directory,
    scope: std.json.Parsed(Scope),
    scope_bytes: core.sensitive.Buffer,
    scope_pin: FileSnapshot,
    phase: Phase = .@"local-admission",
    reserved_boots: u8 = 0,
    consumed: bool = false,
    // Primary refusal is permanent, but is not itself a cleanup failure.
    healthy: bool = true,
    recording_failure: ?anyerror = null,
    cleanup_failure: ?anyerror = null,
    finished: bool = false,
    boot1: ?Boot1 = null,
    boot2: ?Boot2 = null,
    boot2_capture: ?FileSnapshot = null,
    identities: ?Identities = null,
    cached_reads: u8 = 0,
    event_pin: ?FileSnapshot = null,
    event_hash: core.Sha256 = .init(.{}),
    fault: if (builtin.is_test) ?TestFault else void = if (builtin.is_test) null else {},

    /// Only this constructor exists: no opening/resuming an earlier attempt.
    /// On every error after mkdir, the fresh-attempt marker remains in place.
    pub fn create(allocator: std.mem.Allocator, io: std.Io, source_scope: []const u8, fresh_attempt: []const u8, existing_ledger: []const u8) !Store {
        return createImpl(allocator, io, source_scope, fresh_attempt, existing_ledger, null);
    }

    pub fn createFault(allocator: std.mem.Allocator, io: std.Io, source_scope: []const u8, fresh_attempt: []const u8, existing_ledger: []const u8, fault: TestFault) !Store {
        if (!builtin.is_test) @compileError("Fault injection is only available to native tests");
        return createImpl(allocator, io, source_scope, fresh_attempt, existing_ledger, fault);
    }

    fn createImpl(allocator: std.mem.Allocator, io: std.Io, source_scope: []const u8, fresh_attempt: []const u8, existing_ledger: []const u8, fault: ?TestFault) !Store {
        const ledger = try files.Directory.open(io, existing_ledger);
        errdefer ledger.close(io);
        const parent = try files.FileParent.open(io, fresh_attempt, .artifact);
        defer parent.close(io);
        const directory = try createDirectory(io, parent.directory, parent.name, builtin.is_test and fault != null and fault.? == .directory_sync);
        errdefer directory.close(io);
        var writer = try directory.lock(io);
        errdefer writer.close(io);
        var bytes = try files.readSensitiveAbsolute(io, allocator, source_scope, 65536, null);
        errdefer bytes.deinit();
        const scope = try direct.parse(Scope, allocator, bytes.bytes());
        errdefer scope.deinit();
        try scope.value.validate();
        const copied = if (builtin.is_test and fault != null and fault.? == .record)
            try writer.createImmutableFault(io, "scope.json", bytes.bytes(), fault.?.record)
        else
            try writer.createImmutable(io, "scope.json", bytes.bytes());
        try requireDurable(copied);
        const pin = try hashPrivate(io, directory, "scope.json", 65536, fault);
        if (!std.crypto.timing_safe.eql(Digest, pin.sha256, hashBytes(bytes.bytes()))) return error.HashMismatch;
        return .{
            .allocator = allocator,
            .io = io,
            .directory = directory,
            .writer = writer,
            .ledger = ledger,
            .scope = scope,
            .scope_bytes = bytes,
            .scope_pin = pin,
        };
    }

    pub fn close(self: *Store) void {
        self.writer.close(self.io);
        self.directory.close(self.io);
        self.ledger.close(self.io);
        self.scope.deinit();
        self.scope_bytes.deinit();
        self.* = undefined;
    }

    pub fn injectFault(self: *Store, fault: TestFault) void {
        if (!builtin.is_test) @compileError("Fault injection is only available to native tests");
        self.fault = fault;
    }

    fn take(self: *Store, tag: std.meta.Tag(TestFault)) bool {
        if (builtin.is_test) {
            if (self.fault) |fault| {
                if (std.meta.activeTag(fault) == tag) {
                    self.fault = null;
                    return true;
                }
            }
        }
        return false;
    }

    fn ready(self: *Store) !void {
        errdefer self.healthy = false;
        if (self.finished) return error.AlreadyFinished;
        if (!self.healthy) return error.CustodyPoisoned;
        try self.writerReady();
    }

    pub fn recordingFailed(self: *Store, err: anyerror) void {
        self.healthy = false;
        if (self.recording_failure == null) self.recording_failure = err;
    }

    /// Cleanup uses only the original admitted descriptors and in-memory
    /// identities; revalidating this writer never reloads scope or clears refusal.
    fn writerReady(self: *Store) !void {
        if (self.finished) return error.AlreadyFinished;
        errdefer |err| self.recordingFailed(err);
        try validatePrivateDirectory(self.directory.dir);
        const held = self.writer.file orelse return error.LockNotHeld;
        try validatePrivate(held, false);
        const named = try self.directory.openFile(self.io, ".writer.lock");
        defer named.close(self.io);
        if (!files.sameSnapshot(try files.snapshot(held), try files.snapshot(named)))
            return error.WriterLockChanged;
    }

    fn verifyEvents(self: *Store) !void {
        if (self.event_pin) |pin| {
            try self.verifyFile("events.jsonl", pin, record_limit);
        } else {
            const unexpected = self.directory.openFile(self.io, "events.jsonl") catch |err| switch (err) {
                error.FileNotFound => return,
                else => return err,
            };
            unexpected.close(self.io);
            return error.PathAlreadyExists;
        }
    }

    /// Each mkdir and parent entry is synced separately. Never remove a claim,
    /// even when a later name collides or consumed.json cannot become durable.
    pub fn consume(self: *Store) !void {
        try self.ready();
        errdefer self.healthy = false;
        if (self.consumed) return error.PathAlreadyExists;
        try self.verifyScope();
        self.reserveSeed() catch |err| {
            if (err != error.PathAlreadyExists) self.recordingFailed(err);
            return err;
        };
        try self.verifyScope();
        self.consumed = true;
    }

    fn reserveSeed(self: *Store) !void {
        try validatePrivateDirectory(self.ledger.dir);
        var ledger_writer = try self.ledger.lock(self.io);
        defer ledger_writer.close(self.io);
        const s = self.scope.value;
        var buffer: [128]u8 = undefined;
        const attempt_name = try std.fmt.bufPrint(&buffer, "attempt-{s}", .{s.attempt_id});
        const attempt = try createDirectory(self.io, self.ledger.dir, attempt_name, self.take(.directory_sync));
        attempt.close(self.io);
        if (self.take(.after_first_reservation)) return error.Injected;
        const identity_name = try std.fmt.bufPrint(&buffer, "{s}-{s}", .{ s.run_id, s.disk_id });
        const identity = try createDirectory(self.io, self.ledger.dir, identity_name, false);
        defer identity.close(self.io);
        if (self.take(.after_identity_reservation)) return error.Injected;
        const digest_name = try std.fmt.bufPrint(&buffer, "sha256-{s}", .{s.seed_vhd.sha256});
        const digest = try createDirectory(self.io, self.ledger.dir, digest_name, false);
        digest.close(self.io);
        var identity_writer = try identity.lock(self.io);
        defer identity_writer.close(self.io);
        try requireDurable(try self.immutable(&identity_writer, "consumed.json", self.scope_bytes.bytes()));
        if (self.take(.ledger_sync)) return error.Injected;
        try syncDirectory(self.io, self.ledger.dir);
    }

    /// Gate primary effects, in addition to the caller's approval/budget gates.
    pub fn requireConsumed(self: *Store) !void {
        try self.ready();
        if (!self.consumed) return error.SeedNotConsumed;
        try self.verifyScope();
    }

    pub fn reserveBoot1(self: *Store) !void {
        try self.requireConsumed();
        if (self.reserved_boots != 0) return error.BootAlreadyReserved;
        self.reserved_boots = 1;
    }

    /// Only cleanup intent phases can append after primary refusal, and only
    /// through independently revalidated directory, lock and event custody.
    pub fn event(self: *Store, phase: Phase) !void {
        switch (phase) {
            .@"cleanup-intent", .@"cleanup-delete-intent" => try self.writerReady(),
            else => try self.ready(),
        }
        // The failing phase is observable even if its event append fails.
        self.phase = phase;
        errdefer |err| self.recordingFailed(err);
        const bytes = try encode(self.allocator, Event{ .phase = phase, .reserved_boots = self.reserved_boots });
        defer self.allocator.free(bytes);
        var expected_hash = self.event_hash;
        expected_hash.update(bytes);
        var offset: u64 = 0;
        try self.verifyEvents();
        if (self.event_pin) |pin| {
            offset = pin.metadata.size;
        }
        const file = try openEvent(self.directory, self.event_pin == null);
        defer file.close(self.io);
        try validatePrivate(file, false);
        if (self.event_pin) |pin| if (!files.sameSnapshot(pin.metadata, try files.snapshot(file))) return error.FileChanged;
        if (offset + bytes.len > record_limit) return error.FileTooLarge;
        if (self.take(.event_write)) {
            try file.writePositionalAll(self.io, bytes[0 .. bytes.len / 2], offset);
            return error.Injected;
        }
        try file.writePositionalAll(self.io, bytes, offset);
        if (self.take(.event_sync)) return error.Injected;
        try file.sync(self.io);
        try syncDirectory(self.io, self.directory.dir);
        const pin = try self.pinFile("events.jsonl", record_limit);
        var finalized_hash = expected_hash;
        if (!std.crypto.timing_safe.eql(Digest, pin.sha256, finalized_hash.finalResult())) return error.HashMismatch;
        self.event_hash = expected_hash;
        self.event_pin = pin;
    }

    /// Snapshot candidate, wrapper and observed VM before the bounded validator.
    /// Capture verifies these same bytes again, and never decodes/trims serial.
    pub fn captureSources(self: *Store, boot: u8, poll: u8) !CaptureSources {
        try validateCaptureIndex(boot, poll);
        var name: [80]u8 = undefined;
        const serial = try self.pinFile(try std.fmt.bufPrint(&name, "boot{d}-candidate.log", .{boot}), cli_limit);
        const wrapper = try self.pinFile(try std.fmt.bufPrint(&name, "boot{d}-serial-{d}.json", .{ boot, poll }), cli_limit);
        const vm = try self.pinFile(try std.fmt.bufPrint(&name, "boot{d}-vm.json", .{boot}), cli_limit);
        return .{ .serial = serial, .cli_wrapper = wrapper, .vm_observation = vm };
    }

    pub fn capture(self: *Store, boot: u8, poll: u8, ids: Identities, sources: CaptureSources, validator_exit: u8) !void {
        try self.ready();
        errdefer self.healthy = false;
        try validateCaptureIndex(boot, poll);
        if (validator_exit != 0) return error.SerialNotValidated;
        if (!self.consumed or self.reserved_boots != boot) return error.BootNotReserved;
        try ids.validate();
        try self.verifyScope();
        if (boot == 1) {
            if (self.boot1 != null) return error.PathAlreadyExists;
        } else {
            try self.verifyBoot2Admission();
            if (!Identities.equal(ids, self.identities.?)) return error.IdentityChanged;
            if (self.boot2_capture != null) return error.PathAlreadyExists;
        }
        var name: [80]u8 = undefined;
        try self.verifyFile(try std.fmt.bufPrint(&name, "boot{d}-serial-{d}.json", .{ boot, poll }), sources.cli_wrapper, cli_limit);
        try self.verifyFile(try std.fmt.bufPrint(&name, "boot{d}-vm.json", .{boot}), sources.vm_observation, cli_limit);
        var candidate_name: [80]u8 = undefined;
        const candidate = try std.fmt.bufPrint(&candidate_name, "boot{d}-candidate.log", .{boot});
        var log_name: [80]u8 = undefined;
        const log = try std.fmt.bufPrint(&log_name, "boot{d}.log", .{boot});
        const raw = try self.publishRaw(candidate, log, sources.serial);
        const serial_sha = raw.hex();
        const wrapper_sha = sources.cli_wrapper.hex();
        const scope_sha = self.scope_pin.hex();
        const vm_sha = sources.vm_observation.hex();
        const first_sha = if (boot == 1) raw.hex() else self.boot1.?.serial.hex();
        const admission_sha = if (self.boot2) |admission| admission.admission.hex() else [_]u8{0} ** 64;
        const capture_record: CaptureRecord = .{
            .boot = boot,
            .poll = poll,
            .serial_mode = self.scope.value.serial_mode,
            .serial_sha256 = &serial_sha,
            .cli_wrapper_sha256 = &wrapper_sha,
            .scope_sha256 = &scope_sha,
            .vm_id = ids.vm_id,
            .vm_uuid = ids.vm_uuid,
            .os_id = ids.os_id,
            .os_uuid = ids.os_uuid,
            .data_id = ids.data_id,
            .data_uuid = ids.data_uuid,
            .vm_observation_sha256 = &vm_sha,
            .original_boot1_sha256 = &first_sha,
            .boot2_admission_sha256 = if (boot == 2) &admission_sha else "",
        };
        const record_name = try std.fmt.bufPrint(&name, "boot{d}-capture.json", .{boot});
        const pin = try self.record(record_name, capture_record);
        if (boot == 1) {
            self.identities = try ids.clone(self.scope.arena.allocator());
            self.boot1 = .{ .serial = raw, .capture = pin };
        } else self.boot2_capture = pin;
    }

    pub fn retainedSnapshots(self: *Store) !Retained {
        return .{
            .vm = try self.pinFile("retained-vm.json", cli_limit),
            .os = try self.pinFile("retained-os.json", cli_limit),
            .data = try self.pinFile("retained-data.json", cli_limit),
            .power = try self.pinFile("retained-power.json", cli_limit),
        };
    }

    /// Caller has confirmed retained observations, bounded input validation and
    /// unexpired approval. Reserving boot 2 precedes recording, even on failure.
    pub fn admitBoot2(self: *Store, ids: Identities, retained: Retained) !void {
        try self.ready();
        errdefer self.healthy = false;
        if (self.reserved_boots != 1 or self.boot2 != null) return error.BootAlreadyReserved;
        self.reserved_boots = 2;
        try self.verifyBoot1();
        if (!Identities.equal(ids, self.identities.?)) return error.IdentityChanged;
        try self.verifyRetained(retained);
        const scope_sha = self.scope_pin.hex();
        const first_sha = self.boot1.?.serial.hex();
        const capture_sha = self.boot1.?.capture.hex();
        const vm_sha = retained.vm.hex();
        const os_sha = retained.os.hex();
        const data_sha = retained.data.hex();
        const power_sha = retained.power.hex();
        const record_value: AdmissionRecord = .{
            .scope_sha256 = &scope_sha,
            .original_boot1_sha256 = &first_sha,
            .boot1_capture_sha256 = &capture_sha,
            .vm_id = ids.vm_id,
            .vm_uuid = ids.vm_uuid,
            .os_id = ids.os_id,
            .os_uuid = ids.os_uuid,
            .data_id = ids.data_id,
            .data_uuid = ids.data_uuid,
            .retained_vm_sha256 = &vm_sha,
            .retained_os_sha256 = &os_sha,
            .retained_data_sha256 = &data_sha,
            .deallocated_power_sha256 = &power_sha,
        };
        const admission = try self.record("boot2-admission.json", record_value);
        self.boot2 = .{ .admission = admission, .retained = retained };
    }

    pub fn verifyScope(self: *Store) !void {
        try self.verifyFile("scope.json", self.scope_pin, 65536);
    }

    pub fn verifyBoot1(self: *Store) !void {
        const first = self.boot1 orelse return error.MissingBoot1;
        try self.verifyFile("boot1.log", first.serial, cli_limit);
        try self.verifyFile("boot1-capture.json", first.capture, record_limit);
        try self.verifyScope();
    }

    /// Must succeed immediately before the sole VM start and each Boot2 poll.
    pub fn verifyBoot2Admission(self: *Store) !void {
        try self.ready();
        try self.verifyBoot1();
        const second = self.boot2 orelse return error.MissingAdmission;
        try self.verifyFile("boot2-admission.json", second.admission, record_limit);
        try self.verifyRetained(second.retained);
    }

    fn verifyRetained(self: *Store, retained: Retained) !void {
        try self.verifyFile("retained-vm.json", retained.vm, cli_limit);
        try self.verifyFile("retained-os.json", retained.os, cli_limit);
        try self.verifyFile("retained-data.json", retained.data, cli_limit);
        try self.verifyFile("retained-power.json", retained.power, cli_limit);
    }

    pub fn freshness(self: *Store, candidate: FileSnapshot) !FreshnessResult {
        try self.verifyBoot2Admission();
        try self.verifyFile("boot2-candidate.log", candidate, cli_limit);
        if (std.crypto.timing_safe.eql(Digest, candidate.sha256, self.boot1.?.serial.sha256)) {
            if (self.cached_reads >= 60) return error.PollLimit;
            self.cached_reads += 1;
            return .cached;
        }
        return .fresh;
    }

    pub fn pinFile(self: *Store, name: []const u8, maximum: usize) !FileSnapshot {
        errdefer self.healthy = false;
        const fault: ?TestFault = if (self.take(.hash_read)) .hash_read else if (self.take(.hash_after_digest)) .hash_after_digest else null;
        return hashPrivate(self.io, self.directory, name, maximum, fault);
    }

    pub fn verifyFile(self: *Store, name: []const u8, pin: FileSnapshot, maximum: usize) !void {
        errdefer self.healthy = false;
        const current = try self.pinFile(name, maximum);
        if (!FileSnapshot.equal(pin, current)) return error.FileChanged;
    }

    fn record(self: *Store, name: []const u8, value: anytype) !FileSnapshot {
        errdefer |err| self.recordingFailed(err);
        const bytes = try encode(self.allocator, value);
        defer self.allocator.free(bytes);
        try requireDurable(try self.immutable(&self.writer, name, bytes));
        const pin = try self.pinFile(name, record_limit);
        if (!std.crypto.timing_safe.eql(Digest, pin.sha256, hashBytes(bytes))) return error.HashMismatch;
        return pin;
    }

    fn immutable(self: *Store, writer: *files.Locked, name: []const u8, bytes: []const u8) !files.CommitResult {
        errdefer |err| self.recordingFailed(err);
        const result = try self.immutableResult(writer, name, bytes);
        requireDurable(result) catch |err| self.recordingFailed(err);
        return result;
    }

    fn immutableResult(self: *Store, writer: *files.Locked, name: []const u8, bytes: []const u8) !files.CommitResult {
        if (builtin.is_test) {
            if (self.fault) |fault| if (fault == .record) {
                self.fault = null;
                return writer.createImmutableFault(self.io, name, bytes, fault.record);
            };
        }
        return writer.createImmutable(self.io, name, bytes);
    }

    /// Large CLI/serial records use streaming create-only publication, not the
    /// small-record helper. Disks are references, never copied by this API.
    pub fn publishRaw(self: *Store, source: []const u8, destination: []const u8, expected: FileSnapshot) !FileSnapshot {
        return self.publishRawImpl(source, destination, expected, null);
    }

    pub fn publishRawFault(self: *Store, source: []const u8, destination: []const u8, expected: FileSnapshot, fault: *RawTest) !FileSnapshot {
        if (!builtin.is_test) @compileError("Fault injection is only available to native tests");
        return self.publishRawImpl(source, destination, expected, fault);
    }

    fn publishRawImpl(self: *Store, source: []const u8, destination: []const u8, expected: FileSnapshot, fault: ?*RawTest) !FileSnapshot {
        try self.ready();
        errdefer self.healthy = false;
        try files.basename(destination);
        if (destination[0] == '.' or std.mem.startsWith(u8, source, "failure-")) return error.InvalidEvidenceName;
        if (expected.metadata.size > cli_limit) return error.FileTooLarge;
        try self.verifyFile(source, expected, cli_limit);
        const file = try self.directory.openFile(self.io, source);
        defer file.close(self.io);
        if (!files.sameSnapshot(expected.metadata, try files.snapshot(file))) return error.FileChanged;
        var atomic = self.directory.dir.createFileAtomic(self.io, destination, .{
            .permissions = .fromMode(0o600),
            // Tests disable O_TMPFILE. Publication still exclusively uses link(),
            // never replace(), exactly as on a filesystem with named fallback.
            .replace = builtin.is_test and fault != null,
        }) catch |err| {
            self.recordingFailed(err);
            return err;
        };
        defer self.releaseRaw(&atomic, fault);
        validatePrivate(atomic.file, true) catch |err| {
            self.recordingFailed(err);
            return err;
        };
        if (builtin.is_test) {
            if (fault) |test_fault| {
                if (!atomic.file_exists) return error.NamedTemporaryRequired;
                const name = std.fmt.hex(atomic.file_basename_hex);
                const named = try (files.Directory{ .dir = atomic.dir }).openFile(self.io, &name);
                defer named.close(self.io);
                if (!files.sameSnapshot(try files.snapshot(atomic.file), try files.snapshot(named)))
                    return error.FileChanged;
                test_fault.named_scratch = atomic.file_basename_hex;
            }
        }
        var buffer: [65536]u8 = undefined;
        var sha = core.Sha256.init(.{});
        var offset: u64 = 0;
        while (offset < expected.metadata.size) {
            if (builtin.is_test and fault != null and fault.?.source_failure == .read)
                return error.InjectedReadFailure;
            const length: usize = @intCast(@min(buffer.len, expected.metadata.size - offset));
            if (try file.readPositionalAll(self.io, buffer[0..length], offset) != length) return error.FileChanged;
            sha.update(buffer[0..length]);
            atomic.file.writePositionalAll(self.io, buffer[0..length], offset) catch |err| {
                self.recordingFailed(err);
                return err;
            };
            offset += length;
        }
        const digest = sha.finalResult();
        if (builtin.is_test and fault != null and fault.?.source_failure == .hash)
            return error.InjectedHashFailure;
        if (!std.crypto.timing_safe.eql(Digest, digest, expected.sha256)) return error.HashMismatch;
        if (builtin.is_test) {
            if (fault != null and fault.?.source_failure == .proof) {
                const changed = try self.directory.dir.createFile(self.io, source, .{ .truncate = false, .permissions = .fromMode(0o600) });
                defer changed.close(self.io);
                try changed.writePositionalAll(self.io, "\x00", 0);
                try changed.sync(self.io);
            }
        }
        try self.verifyFile(source, expected, cli_limit);
        return self.commitRaw(&atomic, destination, expected.sha256);
    }

    fn releaseRaw(self: *Store, atomic: *std.Io.File.Atomic, fault: ?*RawTest) void {
        defer atomic.deinit(self.io);
        if (!atomic.file_exists) return;
        const name = std.fmt.hex(atomic.file_basename_hex);
        // This path owns the one unlink attempt, including an uncertain failure.
        // deinit may close descriptors, but must not silently retry the deletion.
        atomic.file_exists = false;
        self.removeRawScratch(atomic.dir, &name, fault) catch |err| {
            self.healthy = false;
            if (self.cleanup_failure == null) self.cleanup_failure = err;
        };
    }

    fn removeRawScratch(self: *Store, directory: std.Io.Dir, name: []const u8, fault: ?*RawTest) !void {
        if (builtin.is_test) {
            if (fault) |test_fault| {
                test_fault.delete_attempts += 1;
                if (test_fault.cleanup_failure == .delete) return error.InjectedScratchDeleteFailure;
            }
        }
        try directory.deleteFile(self.io, name);
        if (builtin.is_test) {
            if (fault) |test_fault| {
                test_fault.sync_attempts += 1;
                if (test_fault.cleanup_failure == .directory_sync) return error.InjectedScratchSyncFailure;
            }
        }
        try syncDirectory(self.io, directory);
    }

    fn commitRaw(self: *Store, atomic: *std.Io.File.Atomic, destination: []const u8, expected: Digest) !FileSnapshot {
        errdefer |err| self.recordingFailed(err);
        if (self.take(.raw_file_sync)) return error.NotCommitted;
        try atomic.file.sync(self.io);
        if (self.take(.raw_publication)) return error.PublicationUnknown;
        try atomic.link(self.io);
        if (self.take(.raw_directory_sync)) return error.VisibleNotDurable;
        try syncDirectory(self.io, self.directory.dir);
        const pin = try self.pinFile(destination, cli_limit);
        if (!std.crypto.timing_safe.eql(Digest, pin.sha256, expected)) return error.HashMismatch;
        return pin;
    }

    /// All independent deletions are attempted. Refusal of an unsafe entry is a
    /// cleanup failure, not permission to follow it or erase .writer.lock.
    pub fn removeCapabilities(self: *Store) !void {
        var first_error: ?anyerror = null;
        for ([_][]const u8{ "upload-os", "upload-data" }) |name| {
            const child = openChild(self.io, self.directory, name) catch |err| {
                if (err != error.FileNotFound and first_error == null) first_error = err;
                continue;
            };
            defer child.close(self.io);
            self.removeOne(child, "sas.txt") catch |err| {
                if (first_error == null) first_error = err;
            };
        }
        for ([_][]const u8{ "grant-os.json", "grant-os.stderr", "grant-data.json", "grant-data.stderr" }) |name| {
            self.removeOne(self.directory, name) catch |err| {
                if (first_error == null) first_error = err;
            };
        }
        if (self.take(.capability_sync)) {
            if (first_error == null) first_error = error.Injected;
        } else syncDirectory(self.io, self.directory.dir) catch |err| {
            if (first_error == null) first_error = err;
        };
        if (first_error) |err| {
            if (self.cleanup_failure == null) self.cleanup_failure = err;
            return err;
        }
    }

    fn removeOne(self: *Store, directory: files.Directory, name: []const u8) !void {
        const file = directory.openFile(self.io, name) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        file.close(self.io);
        if (self.take(.capability_unlink)) return error.Injected;
        try directory.dir.deleteFile(self.io, name);
        try syncDirectory(self.io, directory.dir);
        const unexpected = directory.openFile(self.io, name) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        unexpected.close(self.io);
        return error.CapabilityRemains;
    }

    /// Never throws away the primary exit status. Even a visible outcome saying
    /// accepted cannot make exit_code zero without successful durable recording.
    pub fn finish(self: *Store, completion: Completion) FinalResult {
        var outcome: Outcome = .{
            .phase = completion.phase,
            .primary_exit = completion.primary_exit,
            .cleanup_exit = completion.cleanup_exit,
            .reserved_boots = self.reserved_boots,
            .persistence_evidence_complete = completion.persistence_evidence_complete,
            .owned_group_absent = completion.owned_group_absent,
            .group_creation_attempted = completion.group_creation_attempted,
            .failure_diagnostics = completion.failure_diagnostics,
            .boot2_freshness = .{
                .cached_reads = self.cached_reads,
                .cached_reason = if (self.cached_reads > 0) "identical-pinned-boot1" else null,
            },
            .accepted = false,
        };
        var result: FinalResult = .{ .outcome = outcome, .exit_code = if (completion.primary_exit != 0) completion.primary_exit else 1 };
        if (self.finished) {
            result.recording_error = error.AlreadyFinished;
            return result;
        }
        self.removeCapabilities() catch |err| {
            result.cleanup_error = err;
            outcome.cleanup_exit = 1;
        };
        if (completion.final_input_exit == null or completion.final_input_exit.? != 0) outcome.cleanup_exit = 1;
        const writer_ready = if (self.writerReady()) |_| true else |_| false;
        if (writer_ready) self.verifyEvents() catch |err| self.recordingFailed(err);
        if (outcome.persistence_evidence_complete) {
            self.verifyCompleted() catch |err| {
                result.evidence_error = err;
            };
        }
        result.recording_error = self.recording_failure;
        result.cleanup_error = self.cleanup_failure;
        if (result.recording_error != null or result.cleanup_error != null) outcome.cleanup_exit = 1;
        outcome.accepted = outcome.primary_exit == 0 and outcome.cleanup_exit == 0 and
            outcome.persistence_evidence_complete and outcome.owned_group_absent and
            self.healthy and result.evidence_error == null;
        result.outcome = outcome;
        self.finished = true;
        if (!writer_ready) return result;
        const bytes = encode(self.allocator, outcome) catch |err| {
            result.recording_error = err;
            return result;
        };
        defer self.allocator.free(bytes);
        result.recording = self.immutable(&self.writer, "outcome.json", bytes) catch |err| {
            result.recording_error = err;
            return result;
        };
        requireDurable(result.recording) catch |err| {
            result.recording_error = err;
            return result;
        };
        const recorded = self.pinFile("outcome.json", record_limit) catch |err| {
            result.recording_error = err;
            return result;
        };
        if (!std.crypto.timing_safe.eql(Digest, recorded.sha256, hashBytes(bytes))) {
            result.recording_error = error.HashMismatch;
            return result;
        }
        if (outcome.accepted and result.recording_error == null) result.exit_code = 0;
        return result;
    }

    fn verifyCompleted(self: *Store) !void {
        try self.ready();
        if (!self.consumed or self.reserved_boots != 2) return error.EvidenceIncomplete;
        try self.verifyBoot2Admission();
        const capture_pin = self.boot2_capture orelse return error.EvidenceIncomplete;
        try self.verifyFile("boot2-capture.json", capture_pin, record_limit);
        var bytes = try self.directory.readSensitive(self.io, self.allocator, "boot2-capture.json", record_limit, capture_pin.sha256);
        defer bytes.deinit();
        const record_value = try direct.parse(CaptureRecord, self.allocator, bytes.bytes());
        defer record_value.deinit();
        const serial = try self.pinFile("boot2.log", cli_limit);
        if (!std.crypto.timing_safe.eql(Digest, serial.sha256, try core.contracts.parseSha256(record_value.value.serial_sha256)))
            return error.HashMismatch;
    }
};

fn hashBytes(bytes: []const u8) Digest {
    var digest: Digest = undefined;
    core.Sha256.hash(bytes, &digest, .{});
    return digest;
}

fn hashPrivate(io: std.Io, directory: files.Directory, name: []const u8, maximum: usize, fault: ?TestFault) !FileSnapshot {
    if (maximum == 0 or maximum > cli_limit) return error.InvalidLimit;
    const file = try directory.openFile(io, name);
    defer file.close(io);
    const before = try files.snapshot(file);
    if (before.size > maximum) return error.FileTooLarge;
    var sha = core.Sha256.init(.{});
    var buffer: [65536]u8 = undefined;
    var offset: u64 = 0;
    while (offset < before.size) {
        if (builtin.is_test and fault != null and fault.? == .hash_read) return error.InjectedReadFailure;
        const length: usize = @intCast(@min(buffer.len, before.size - offset));
        if (try file.readPositionalAll(io, buffer[0..length], offset) != length) return error.FileChanged;
        sha.update(buffer[0..length]);
        offset += length;
    }
    const digest = sha.finalResult();
    // A plausible digest accompanied by any failed read/hash is not evidence.
    if (builtin.is_test and fault != null and fault.? == .hash_after_digest) return error.InjectedHashFailure;
    if (!files.sameSnapshot(before, try files.snapshot(file))) return error.FileChanged;
    const named = try directory.openFile(io, name);
    defer named.close(io);
    if (!files.sameSnapshot(before, try files.snapshot(named))) return error.FileChanged;
    return .{ .metadata = before, .sha256 = digest };
}

fn syncDirectory(io: std.Io, dir: std.Io.Dir) !void {
    const file: std.Io.File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
    try file.sync(io);
}

fn validatePrivate(file: std.Io.File, allow_unlinked: bool) !void {
    const metadata = try files.snapshot(file);
    if (metadata.mode & linux.S.IFMT != linux.S.IFREG or metadata.mode & 0o7777 != 0o600 or
        metadata.uid != linux.geteuid() or (metadata.nlink != 1 and !(allow_unlinked and metadata.nlink == 0)))
        return error.UnsafeFile;
}

fn openChild(io: std.Io, parent: files.Directory, name: []const u8) !files.Directory {
    try files.basename(name);
    const child = try parent.dir.openDir(io, name, .{ .follow_symlinks = false, .iterate = true });
    errdefer child.close(io);
    try validatePrivateDirectory(child);
    return .{ .dir = child };
}

fn validatePrivateDirectory(child: std.Io.Dir) !void {
    const metadata = try files.snapshot(.{ .handle = child.handle, .flags = .{ .nonblocking = false } });
    if (metadata.mode & linux.S.IFMT != linux.S.IFDIR or metadata.mode & 0o7777 != 0o700 or metadata.uid != linux.geteuid())
        return error.UnsafeFile;
}

fn createDirectory(io: std.Io, parent: std.Io.Dir, name: []const u8, fail_sync: bool) !files.Directory {
    try files.basename(name);
    try parent.createDir(io, name, .fromMode(0o700));
    // No errdefer unlink: creation itself permanently consumes this name.
    const child = try openChild(io, .{ .dir = parent }, name);
    errdefer child.close(io);
    if (fail_sync) return error.Injected;
    try syncDirectory(io, child.dir);
    try syncDirectory(io, parent);
    return child;
}

fn validateCaptureIndex(boot: u8, poll: u8) !void {
    if ((boot != 1 and boot != 2) or poll == 0 or poll > 60) return error.InvalidCaptureIndex;
}

fn openEvent(directory: files.Directory, exclusive: bool) !std.Io.File {
    while (true) {
        const result = linux.openat(directory.dir.handle, "events.jsonl", .{
            .ACCMODE = .RDWR,
            .CREAT = true,
            .EXCL = exclusive,
            .NOFOLLOW = true,
            .NONBLOCK = true,
            .CLOEXEC = true,
        }, 0o600);
        switch (linux.errno(result)) {
            .SUCCESS => return .{ .handle = @intCast(result), .flags = .{ .nonblocking = true } },
            .INTR => continue,
            .EXIST => return error.PathAlreadyExists,
            .LOOP, .ISDIR, .NOTDIR, .ACCES, .PERM => return error.UnsafeFile,
            else => return error.FileOpenFailed,
        }
    }
}
