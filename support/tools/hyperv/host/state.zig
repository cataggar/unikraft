const std = @import("std");
const core = @import("hyperv_core");
const p = @import("protocol.zig");
const files = @import("files.zig");
pub const Stage = enum { empty, public_intent, public_done, private_intent, done, failed };
pub const Publication = enum { not_started, rejected, unknown, complete };

pub const Record = struct {
    version: u8,
    run_id: p.Uuid,
    vm_id: p.Uuid,
    host_boot_id: p.Uuid,
    stage: Stage,
    public_nonce: ?p.Uuid,
    private_nonce: ?p.Uuid,
    public_command_sha256: ?p.Hash,
    public_evidence_sha256: ?p.Hash,
    infrastructure_sha256: ?p.Hash,
    boots_attempted: u8,
    boots_passed: u8,
    staging_bytes: u64,
    control_bytes: u64,
    evidence_bytes: u64,
    deadline_ns: u64,
    wire_calls: u16,
    wire_inflight: bool,
    publication: Publication,
    failures: core.diagnostics.Failures,

    pub fn initial(run: p.Uuid, vm: p.Uuid, boot: p.Uuid, image_bytes: u64, control: u64) !Record {
        if (image_bytes < control or image_bytes > p.max_staging - 4096 or control > p.max_control - 4096) return error.InvalidBudget;
        try p.validUuid(run);
        try p.validUuid(vm);
        try p.validUuid(boot);
        return .{ .version = 1, .run_id = run, .vm_id = vm, .host_boot_id = boot, .stage = .empty, .public_nonce = null, .private_nonce = null, .public_command_sha256 = null, .public_evidence_sha256 = null, .infrastructure_sha256 = null, .boots_attempted = 0, .boots_passed = 0, .staging_bytes = image_bytes + 4096, .control_bytes = control + 4096, .evidence_bytes = 0, .deadline_ns = (try core.process.Deadline.afterMilliseconds(p.attempt_ms)).expires_ns, .wire_calls = 0, .wire_inflight = false, .publication = .not_started, .failures = .{} };
    }

    pub fn validate(self: Record) !void {
        if (self.version != 1 or self.boots_attempted > 6 or self.boots_passed > self.boots_attempted or self.control_bytes > p.max_control or self.staging_bytes > p.max_staging or self.evidence_bytes > p.max_evidence or self.deadline_ns == 0 or self.wire_calls > 256) return error.InvalidState;
        try p.validUuid(self.run_id);
        try p.validUuid(self.vm_id);
        try p.validUuid(self.host_boot_id);
        for ([_]?core.diagnostics.Diagnostic{ self.failures.primary, self.failures.cleanup, self.failures.recording }) |failure| if (failure) |diagnostic| try diagnostic.validate();
        const failed = self.failures.primary != null or self.failures.cleanup != null or self.failures.recording != null;
        if (self.stage == .empty and (self.boots_attempted != 0 or self.public_nonce != null or self.private_nonce != null or self.public_command_sha256 != null or self.public_evidence_sha256 != null or self.infrastructure_sha256 != null or failed)) return error.InvalidState;
        if (self.stage == .public_intent and (self.boots_attempted > 2 or self.private_nonce != null or self.public_evidence_sha256 != null)) return error.InvalidState;
        if (self.stage == .public_done and (self.boots_passed != 2 or self.boots_attempted != 2 or self.public_evidence_sha256 == null or self.publication != .complete)) return error.InvalidState;
        if (self.stage == .public_done and (self.private_nonce != null or failed)) return error.InvalidState;
        if (self.stage == .done and (self.boots_passed != 6 or self.boots_attempted != 6 or self.publication != .complete)) return error.InvalidState;
        if (self.stage == .done and failed) return error.InvalidState;
        if ((self.stage == .private_intent or self.stage == .done) and (self.private_nonce == null or self.public_evidence_sha256 == null)) return error.InvalidState;
        if (self.stage == .private_intent and (self.boots_attempted < 2 or self.boots_passed < 2)) return error.InvalidState;
        if (self.stage != .empty and self.stage != .failed and (self.public_nonce == null or self.public_command_sha256 == null or self.infrastructure_sha256 == null)) return error.InvalidState;
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: *core.private_files.Locked,
    record: Record,

    pub fn open(allocator: std.mem.Allocator, io: std.Io, locked: *core.private_files.Locked, initial: Record) !Store {
        const bytes = locked.directory.read(io, allocator, "state.json", 16384, null) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        var record = initial;
        if (bytes) |data| {
            defer allocator.free(data);
            var doc = try core.contracts.Document.parse(allocator, data, .{});
            defer doc.deinit();
            try doc.requireCanonical(allocator, data);
            const parsed = try std.json.parseFromSlice(Record, allocator, data, .{ .ignore_unknown_fields = false });
            defer parsed.deinit();
            record = parsed.value;
            try record.validate();
            if (!std.mem.eql(u8, &record.run_id, &initial.run_id) or !std.mem.eql(u8, &record.vm_id, &initial.vm_id) or !std.mem.eql(u8, &record.host_boot_id, &initial.host_boot_id)) return error.AttemptBindingChanged;
            if (record.stage == .public_intent or record.stage == .private_intent or record.wire_inflight) return error.InterruptedIntent;
        }
        var self: Store = .{ .allocator = allocator, .io = io, .locked = locked, .record = record };
        if (bytes == null) try self.save();
        return self;
    }

    pub fn encode(self: *Store, value: anytype) ![]u8 {
        const bytes = try std.json.Stringify.valueAlloc(self.allocator, value, .{});
        defer self.allocator.free(bytes);
        var doc = try core.contracts.Document.parse(self.allocator, bytes, .{ .bytes = p.max_command, .items = 2048, .tokens = 16384 });
        defer doc.deinit();
        return doc.canonicalAlloc(self.allocator);
    }

    pub fn save(self: *Store) !void {
        try self.record.validate();
        const staging = self.record.staging_bytes;
        const control = self.record.control_bytes;
        var accounted: usize = 0;
        for (0..4) |_| {
            const bytes = try self.encode(self.record);
            defer self.allocator.free(bytes);
            if (bytes.len > 4096 or bytes.len > p.max_staging - staging or bytes.len > p.max_control - control) return error.RecordingBudgetExceeded;
            if (bytes.len == accounted) {
                const result = try self.locked.commit(self.io, "state.json", bytes);
                if (!files.isDurable(result)) return error.StateNotDurable;
                return;
            }
            // Charge every atomic state version, including its own byte counters.
            accounted = bytes.len;
            self.record.staging_bytes = staging + accounted;
            self.record.control_bytes = control + accounted;
        }
        return error.RecordingBudgetExceeded;
    }

    pub fn immutable(self: *Store, name: []const u8, bytes: []const u8) !void {
        const result = try self.locked.createImmutable(self.io, name, bytes);
        if (!files.isDurable(result)) return error.StateNotDurable;
    }

    pub fn reserve(self: *Store, amount: u64, control: bool, evidence: bool) !void {
        if (amount > p.max_staging - self.record.staging_bytes) return error.StagingBudgetExceeded;
        if (control and amount > p.max_control - self.record.control_bytes) return error.ControlAllowanceExceeded;
        if (evidence and amount > p.max_evidence - self.record.evidence_bytes) return error.EvidenceBudgetExceeded;
        self.record.staging_bytes += amount;
        if (control) self.record.control_bytes += amount;
        if (evidence) self.record.evidence_bytes += amount;
        try self.save();
    }

    pub fn begin(self: *Store, command: *const p.Command, command_bytes: []const u8) !void {
        if (!std.mem.eql(u8, &self.record.run_id, &command.scope.run_id) or !std.mem.eql(u8, &self.record.vm_id, &command.vm_id)) return error.ScopeMismatch;
        if (command.phase == .public) {
            if (self.record.stage != .empty or self.record.boots_attempted != 0) return error.DuplicatePhase;
        } else {
            if (self.record.stage != .public_done or self.record.boots_attempted != 2 or self.record.boots_passed != 2) return error.PrematurePrivatePhase;
            const acceptance = command.acceptance orelse return error.MissingAcceptance;
            if (!std.mem.eql(u8, &acceptance.phase_nonce, &self.record.public_nonce.?) or
                !std.mem.eql(u8, &acceptance.public_command_sha256, &self.record.public_command_sha256.?) or
                !std.mem.eql(u8, &acceptance.public_evidence_sha256, &self.record.public_evidence_sha256.?) or
                !std.mem.eql(u8, &acceptance.host_boot_id, &self.record.host_boot_id) or
                !std.mem.eql(u8, &command.infrastructure_sha256, &self.record.infrastructure_sha256.?) or
                std.mem.eql(u8, &command.phase_nonce, &self.record.public_nonce.?)) return error.AcceptanceMismatch;
        }
        try self.reserve(command_bytes.len, true, false);
        // The create-only marker remains authoritative even if state publication
        // or the process fails immediately afterward.
        try self.immutable(if (command.phase == .public) "public-intent.json" else "private-intent.json", command_bytes);
        if (command.phase == .public) {
            self.record.public_nonce = command.phase_nonce;
            self.record.public_command_sha256 = command.verified.digest;
            self.record.infrastructure_sha256 = command.infrastructure_sha256;
            self.record.stage = .public_intent;
        } else {
            self.record.private_nonce = command.phase_nonce;
            self.record.stage = .private_intent;
        }
        self.record.publication = .not_started;
        try self.save();
    }

    pub fn bootIntent(self: *Store, phase: p.Phase) !u8 {
        const expected: Stage = if (phase == .public) .public_intent else .private_intent;
        const lower: u8 = if (phase == .public) 0 else 2;
        const upper: u8 = if (phase == .public) 2 else 6;
        if (self.record.stage != expected or self.record.boots_attempted < lower or self.record.boots_attempted >= upper or self.record.boots_passed != self.record.boots_attempted) return error.BootLimit;
        const index = self.record.boots_attempted;
        self.record.boots_attempted += 1;
        try self.save();
        return index;
    }

    pub fn bootPassed(self: *Store) !void {
        if ((self.record.stage != .public_intent and self.record.stage != .private_intent) or self.record.boots_attempted != self.record.boots_passed + 1) return error.InvalidState;
        self.record.boots_passed += 1;
        try self.save();
    }

    pub fn complete(self: *Store, phase: p.Phase, evidence_sha256: p.Hash) !void {
        const expected: u8 = if (phase == .public) 2 else 6;
        if (self.record.stage != @as(Stage, if (phase == .public) .public_intent else .private_intent) or
            self.record.boots_attempted != expected or self.record.boots_passed != expected or self.record.publication != .complete or
            self.record.failures.primary != null or self.record.failures.cleanup != null or self.record.failures.recording != null) return error.IncompleteEvidence;
        if (phase == .public) self.record.public_evidence_sha256 = evidence_sha256;
        self.record.stage = if (phase == .public) .public_done else .done;
        try self.save();
    }

    pub fn fail(self: *Store, failures: core.diagnostics.Failures) void {
        if (self.record.failures.primary == null) self.record.failures.primary = failures.primary;
        if (self.record.failures.cleanup == null) self.record.failures.cleanup = failures.cleanup;
        if (self.record.failures.recording == null) self.record.failures.recording = failures.recording;
        if (self.record.failures.primary == null and self.record.failures.cleanup == null and self.record.failures.recording == null) self.record.failures.primary = .{ .stage = .host_phase, .category = .internal };
        self.record.stage = .failed;
        self.save() catch {
            self.record.failures.recording = .{ .stage = .state_record, .category = .local_io };
            const bytes = self.encode(self.record.failures) catch return;
            defer self.allocator.free(bytes);
            self.immutable("recording-failure.json", bytes) catch return;
        };
    }
};
