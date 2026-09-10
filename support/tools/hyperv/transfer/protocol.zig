const std = @import("std");
const core = @import("hyperv_core");
const c = core.contracts;
const d = @import("diagnostic.zig");
const job = @import("job.zig");
const client = @import("client.zig");
const request = @import("request.zig");

pub const maximum_result = 8192;
pub const Phase = enum {
    /// No event: default counters, no Outcome, admission-derived certainty.
    prepared,
    /// One pending request and no head/Outcome. A pending mutation is unknown,
    /// including zero-byte writes; a pending read retains prior write certainty.
    in_flight,
    /// No pending request/Outcome. A head settles its mutation, a missing head
    /// remains unknown, and a proven pre-transport rollback removes the attempt.
    observed,
    /// No pending request and a counter-consistent Outcome. Local verification
    /// may fail after all writes were confirmed; completion is not certainty.
    finished,
};

pub const Progress = struct {
    /// Declared write-ahead payloads, rolled back only before transport entry.
    bytes_attempted: u64 = 0,
    /// Declared payloads covered by observed 2xx mutation heads, not reader bytes.
    bytes_confirmed: u64 = 0,
    mutations_attempted: u64 = 0,
    mutations_confirmed: u64 = 0,
    pending: bool = false,
    pending_bytes: u64 = 0,
    pending_mutation: bool = false,
    previous_effect: d.Certainty = .not_started,
    requests_attempted: u64 = 0,
    responses_observed: u64 = 0,
    stage: d.Stage = .contract,
    status: ?u16 = null,

    pub fn parse(value: std.json.Value) !Progress {
        const o = try c.exactFields(value, &.{
            "bytes_attempted",    "bytes_confirmed",    "mutations_attempted", "mutations_confirmed",
            "pending",            "pending_bytes",      "pending_mutation",    "previous_effect",
            "requests_attempted", "responses_observed", "stage",               "status",
        });
        const status = o.get("status").?;
        return .{
            .bytes_attempted = try c.integer(u64, o.get("bytes_attempted").?),
            .bytes_confirmed = try c.integer(u64, o.get("bytes_confirmed").?),
            .mutations_attempted = try c.integer(u64, o.get("mutations_attempted").?),
            .mutations_confirmed = try c.integer(u64, o.get("mutations_confirmed").?),
            .pending = try boolean(o.get("pending").?),
            .pending_bytes = try c.integer(u64, o.get("pending_bytes").?),
            .pending_mutation = try boolean(o.get("pending_mutation").?),
            .previous_effect = try c.enumeration(d.Certainty, o.get("previous_effect").?),
            .requests_attempted = try c.integer(u64, o.get("requests_attempted").?),
            .responses_observed = try c.integer(u64, o.get("responses_observed").?),
            .stage = try c.enumeration(d.Stage, o.get("stage").?),
            .status = if (status == .null) null else try c.integer(u16, status),
        };
    }

    pub fn validate(self: Progress, kind: job.Kind, plan: job.Plan) !void {
        try plan.validate(kind);
        if (self.requests_attempted > plan.requests or self.responses_observed > self.requests_attempted or
            self.mutations_attempted > plan.mutations or self.mutations_confirmed > self.mutations_attempted or
            self.bytes_attempted > plan.bytes or self.bytes_confirmed > self.bytes_attempted or
            (!self.pending and (self.pending_bytes != 0 or self.pending_mutation))) return error.InvalidReport;
        if (self.stage == .contract) {
            if (!std.meta.eql(self, Progress{})) return error.InvalidReport;
            return;
        }
        const mutation = try mutationStage(self.stage);
        const missing = self.requests_attempted - self.responses_observed;
        if (missing > 1 or (self.pending and (missing != 1 or self.status != null or self.pending_mutation != mutation)))
            return error.InvalidReport;
        if (self.status) |status| if (status < 100 or status > 599) return error.InvalidReport;
        if (self.status != null and (missing != 0 or self.requests_attempted == 0)) return error.InvalidReport;
        const counted = self.status != null or missing == 1;
        const confirmed = self.status != null and self.status.? >= 200 and self.status.? < 300;
        const current_mutation: u64 = @intFromBool(counted and mutation);
        const current_confirmation: u64 = @intFromBool(counted and mutation and confirmed);
        if (self.mutations_attempted < current_mutation or
            self.mutations_confirmed != self.mutations_attempted - current_mutation + current_confirmation)
            return error.InvalidReport;
        if ((self.mutations_attempted == 0 and self.bytes_attempted != 0) or
            (self.mutations_confirmed == 0 and self.bytes_confirmed != 0) or
            (self.mutations_attempted == self.mutations_confirmed and self.bytes_attempted != self.bytes_confirmed) or
            (self.mutations_attempted == plan.mutations and self.bytes_attempted != plan.bytes))
            return error.InvalidReport;
        if (self.pending and self.pending_bytes != self.bytes_attempted - self.bytes_confirmed)
            return error.InvalidReport;
        const before_requests = self.requests_attempted - @as(u64, @intFromBool(counted));
        const before_mutations = self.mutations_attempted - current_mutation;
        if (before_requests >= plan.requests or
            self.previous_effect != prefixEffect(plan, before_mutations)) return error.InvalidReport;
        switch (kind) {
            .blob => if (plan.mutations == 0) {
                if (self.stage != .download_open or self.mutations_attempted != 0) return error.InvalidReport;
            } else {
                if ((self.stage != .container_create and self.stage != .block_put) or
                    self.requests_attempted != self.mutations_attempted or
                    self.bytes_attempted > self.mutations_attempted * @as(u64, request.maximum_file) or
                    self.bytes_confirmed > self.mutations_confirmed * @as(u64, request.maximum_file))
                    return error.InvalidReport;
                if (self.stage == .container_create and (before_requests != 0 or self.bytes_attempted != 0))
                    return error.InvalidReport;
            },
            .pages => {
                if (self.bytes_attempted != @min(self.mutations_attempted * client.page_chunk_size, plan.bytes) or
                    self.bytes_confirmed != @min(self.mutations_confirmed * client.page_chunk_size, plan.bytes))
                    return error.InvalidReport;
                switch (self.stage) {
                    .page_put => if (self.requests_attempted != self.mutations_attempted) return error.InvalidReport,
                    .footer_readback => if (self.mutations_confirmed != plan.mutations or before_requests != plan.mutations)
                        return error.InvalidReport,
                    else => return error.InvalidReport,
                }
            },
        }
    }

    /// Only the last serial operation may lack a head or be rejected. Counts
    /// identify mutations even when their declared payload is zero bytes.
    pub fn certainty(self: Progress, plan: job.Plan) d.Certainty {
        if (plan.mutations == 0) return .not_applicable;
        if (self.pending_mutation or self.mutations_attempted > self.mutations_confirmed) {
            if (self.status == null) return .unknown;
            return if (self.mutations_confirmed == 0) .rejected else .incomplete;
        }
        return prefixEffect(plan, self.mutations_confirmed);
    }

    pub fn checkpointPhase(self: Progress) Phase {
        return if (self.pending) .in_flight else if (self.stage == .contract) .prepared else .observed;
    }
};

fn mutationStage(stage: d.Stage) !bool {
    return switch (stage) {
        .container_create, .block_put, .page_put => true,
        .download_open, .footer_readback => false,
        else => error.InvalidReport,
    };
}

fn prefixEffect(plan: job.Plan, confirmed: u64) d.Certainty {
    if (plan.mutations == 0) return .not_applicable;
    if (confirmed == 0) return .not_started;
    return if (confirmed == plan.mutations) .accepted else .incomplete;
}

pub const Report = struct {
    /// Trusted admission context, never decoded from or emitted in the report.
    admitted_plan: ?job.Plan = null,
    attempt_id: ?[32]u8 = null,
    delivery_complete: bool = false,
    failures: core.diagnostics.Failures = .{},
    job_sha256: ?[32]u8 = null,
    kind: ?job.Kind = null,
    outcome: ?d.Outcome = null,
    phase: Phase = .prepared,
    process_cleanup_complete: ?bool = null,
    progress: ?Progress = null,
    side_effect: d.Certainty = .not_started,

    pub fn initial(intent: Intent) Report {
        return .{
            .admitted_plan = intent.plan,
            .attempt_id = intent.attempt_id,
            .job_sha256 = intent.job_sha256,
            .kind = intent.kind,
            .progress = .{},
            .side_effect = prefixEffect(intent.plan, 0),
        };
    }

    pub fn succeeded(self: Report) bool {
        self.validate() catch return false;
        return self.delivery_complete and self.process_cleanup_complete == true and
            self.failures.primary == null and self.failures.cleanup == null and self.failures.recording == null and
            self.outcome != null and self.outcome.?.completion == .complete;
    }

    pub fn write(self: Report, writer: *std.Io.Writer) !void {
        try self.validate();
        try writer.writeAll("{\"attempt_id\":");
        try d.writeHash(self.attempt_id, writer);
        try writer.writeAll(",\"contract\":\"uk.hyperv.transfer-report\",\"delivery_complete\":");
        try std.json.Stringify.value(self.delivery_complete, .{}, writer);
        try writer.writeAll(",\"failures\":");
        try self.failures.writeValue(writer);
        try writer.writeAll(",\"job_sha256\":");
        try d.writeHash(self.job_sha256, writer);
        try writer.writeAll(",\"kind\":");
        try std.json.Stringify.value(self.kind, .{}, writer);
        try writer.writeAll(",\"outcome\":");
        if (self.outcome) |outcome| try outcome.writeValue(writer) else try writer.writeAll("null");
        try writer.print(",\"phase\":\"{s}\",\"process_cleanup_complete\":", .{@tagName(self.phase)});
        try std.json.Stringify.value(self.process_cleanup_complete, .{}, writer);
        try writer.writeAll(",\"progress\":");
        try std.json.Stringify.value(self.progress, .{}, writer);
        try writer.print(",\"schema_version\":1,\"side_effect\":\"{s}\"}}\n", .{@tagName(self.side_effect)});
    }

    pub fn parse(allocator: std.mem.Allocator, raw: []const u8, intent: Intent) !Report {
        return read(allocator, raw, intent, false);
    }

    /// Recovery may salvage independently valid progress and typed failures,
    /// never an inconsistent Outcome or an unsupported certainty claim.
    pub fn recover(allocator: std.mem.Allocator, raw: []const u8, intent: Intent) !Report {
        return read(allocator, raw, intent, true);
    }

    fn read(allocator: std.mem.Allocator, raw: []const u8, intent: Intent, recovery: bool) !Report {
        try intent.plan.validate(intent.kind);
        const document = try c.SensitiveDocument.parse(allocator, raw, .{ .bytes = maximum_result });
        defer document.deinit();
        try document.requireCanonical(raw);
        const o = try c.exactFields(document.value(), &.{
            "attempt_id", "contract",                 "delivery_complete", "failures",       "job_sha256",  "kind", "outcome",
            "phase",      "process_cleanup_complete", "progress",          "schema_version", "side_effect",
        });
        if (!std.mem.eql(u8, try c.string(o.get("contract").?), "uk.hyperv.transfer-report") or
            try c.integer(u32, o.get("schema_version").?) != 1) return error.InvalidReport;
        const observed = (try d.parseHash(o.get("job_sha256").?)) orelse return error.BindingMismatch;
        const attempt = (try d.parseHash(o.get("attempt_id").?)) orelse return error.BindingMismatch;
        if (!std.mem.eql(u8, &intent.job_sha256, &observed) or !std.mem.eql(u8, &intent.attempt_id, &attempt))
            return error.BindingMismatch;
        if (try c.enumeration(job.Kind, o.get("kind").?) != intent.kind) return error.BindingMismatch;
        if (recovery and o.get("process_cleanup_complete").? != .null) return error.InvalidReport;
        var result = Report.initial(intent);
        result.progress = null;
        result.failures = try core.diagnostics.Failures.parse(o.get("failures").?);
        result.readBody(o) catch |err| {
            if (!recovery) return err;
            result.rejectRecord();
            return result;
        };
        result.validate() catch |err| {
            if (!recovery) return err;
            result.rejectRecord();
        };
        return result;
    }

    fn readBody(self: *Report, o: std.json.ObjectMap) !void {
        const progress = o.get("progress").?;
        const cleanup = o.get("process_cleanup_complete").?;
        const outcome = o.get("outcome").?;
        self.progress = if (progress == .null) null else try Progress.parse(progress);
        self.delivery_complete = try boolean(o.get("delivery_complete").?);
        self.phase = try c.enumeration(Phase, o.get("phase").?);
        self.process_cleanup_complete = if (cleanup == .null) null else try boolean(cleanup);
        self.side_effect = try c.enumeration(d.Certainty, o.get("side_effect").?);
        self.outcome = if (outcome == .null) null else try d.Outcome.parse(outcome);
    }

    pub fn validate(self: Report) !void {
        if (self.delivery_complete and (self.phase != .finished or self.outcome == null)) return error.InvalidReport;
        if ((self.phase == .finished) != (self.outcome != null)) return error.InvalidReport;
        if (self.outcome) |value| {
            try value.validate();
            if (self.side_effect != value.side_effect) return error.InvalidReport;
            const failures = try value.failureSummary();
            if ((failures.primary != null and self.failures.primary == null) or
                (failures.cleanup != null and self.failures.cleanup == null) or
                (failures.recording != null and self.failures.recording == null)) return error.InvalidReport;
        }
        const plan = self.admitted_plan orelse {
            if (self.attempt_id != null or self.job_sha256 != null or self.kind != null or self.progress != null or
                (self.side_effect != .not_started and self.side_effect != .unknown)) return error.InvalidReport;
            try self.validateUnavailable();
            return;
        };
        if (self.attempt_id == null or self.job_sha256 == null) return error.InvalidReport;
        const kind = self.kind orelse return error.InvalidReport;
        try plan.validate(kind);
        const p = self.progress orelse {
            if (self.side_effect != (if (plan.mutations == 0) d.Certainty.not_applicable else .unknown))
                return error.InvalidReport;
            try self.validateUnavailable();
            return;
        };
        try p.validate(kind, plan);
        if (self.side_effect != p.certainty(plan) or
            (self.phase == .finished and p.pending) or
            (self.phase != .finished and self.phase != p.checkpointPhase())) return error.InvalidReport;
        if (self.outcome) |value| {
            // Accepted counters describe the same heads in both models. Reader
            // bytes may be short or include one failed overflow probe. Download
            // bytes count output-file writes, never page-footer readback.
            const probe: u64 = @intFromBool(kind == .blob and p.mutations_attempted > 0 and value.completion == .failed);
            if (value.bytes_accepted != p.bytes_confirmed or value.bytes_streamed > p.bytes_attempted + probe or
                value.bytes_downloaded > plan.download_bytes or
                ((kind == .pages or plan.mutations > 0 or p.requests_attempted == 0) and value.bytes_downloaded != 0) or
                (value.diagnostic.status != null and value.diagnostic.status != p.status)) return error.InvalidReport;
            if (value.completion == .complete) {
                if (p.requests_attempted != plan.requests or p.responses_observed != plan.requests or
                    p.mutations_confirmed != plan.mutations or p.bytes_confirmed != plan.bytes or
                    value.bytes_streamed != p.bytes_attempted)
                    return error.InvalidReport;
                if (value.side_effect != (if (plan.mutations == 0) d.Certainty.not_applicable else .accepted))
                    return error.InvalidReport;
                const terminal_status: u16 = switch (kind) {
                    .pages => 206,
                    .blob => if (plan.mutations == 0) 200 else 201,
                };
                if (value.diagnostic.status != terminal_status or p.status != terminal_status)
                    return error.InvalidReport;
            }
        }
    }

    fn validateUnavailable(self: Report) !void {
        if (self.phase != .prepared and self.phase != .finished) return error.InvalidReport;
        if (self.failures.primary == null and self.failures.cleanup == null and self.failures.recording == null)
            return error.InvalidReport;
        if (self.outcome) |value| {
            if (value.completion != .failed or value.diagnostic.status != null or value.bytes_accepted != 0 or
                value.bytes_streamed != 0 or value.bytes_downloaded != 0) return error.InvalidReport;
        }
    }

    fn rejectRecord(self: *Report) void {
        if (self.outcome) |value| {
            if (value.failureSummary()) |failures| self.merge(failures) else |_| self.primary(.invalid_response);
        }
        self.outcome = null;
        self.delivery_complete = false;
        self.phase = .prepared;
        const plan = self.admitted_plan.?;
        self.side_effect = if (plan.mutations == 0) .not_applicable else .unknown;
        if (self.progress) |p| {
            if (p.validate(self.kind.?, plan)) |_| {
                self.side_effect = p.certainty(plan);
                self.phase = p.checkpointPhase();
            } else |_| self.progress = null;
        }
        self.failures.record(.recording, .{ .stage = .state_record, .category = .invalid_response }) catch unreachable;
    }

    pub fn retain(self: *Report, observed: Report) void {
        const prior = self.failures;
        self.* = observed;
        self.failures = prior;
        self.merge(observed.failures);
    }

    pub fn merge(self: *Report, failures: core.diagnostics.Failures) void {
        if (failures.primary) |value| self.failures.record(.primary, value) catch unreachable;
        if (failures.cleanup) |value| self.failures.record(.cleanup, value) catch unreachable;
        if (failures.recording) |value| self.failures.record(.recording, value) catch unreachable;
    }

    pub fn primary(self: *Report, category: core.diagnostics.Category) void {
        self.failures.record(.primary, .{ .stage = .transfer_worker, .category = category }) catch unreachable;
    }
};

pub const Intent = struct {
    attempt_id: [32]u8,
    deadline_ns: u64,
    job_sha256: [32]u8,
    kind: job.Kind,
    parent_pid: u32,
    plan: job.Plan,
    request_sha256: [32]u8,
    sas_sha256: [32]u8,

    pub fn write(self: Intent, writer: *std.Io.Writer) !void {
        try self.plan.validate(self.kind);
        try writer.writeAll("{\"attempt_id\":");
        try d.writeHash(self.attempt_id, writer);
        try writer.print(",\"contract\":\"uk.hyperv.transfer-intent\",\"deadline_ns\":{d},\"job_sha256\":", .{self.deadline_ns});
        try d.writeHash(self.job_sha256, writer);
        try writer.print(",\"kind\":\"{s}\",\"parent_pid\":{d},\"plan\":", .{ @tagName(self.kind), self.parent_pid });
        try std.json.Stringify.value(self.plan, .{}, writer);
        try writer.writeAll(",\"request_sha256\":");
        try d.writeHash(self.request_sha256, writer);
        try writer.writeAll(",\"sas_sha256\":");
        try d.writeHash(self.sas_sha256, writer);
        try writer.writeAll(",\"schema_version\":1}\n");
    }

    pub fn load(allocator: std.mem.Allocator, io: std.Io, directory: core.private_files.Directory) !Intent {
        var raw = try directory.readSensitive(io, allocator, job.intent_name, 2048, null);
        defer raw.deinit();
        const document = try c.SensitiveDocument.parse(allocator, raw.bytes(), .{ .bytes = 2048, .string_bytes = 2048 });
        defer document.deinit();
        try document.requireCanonical(raw.bytes());
        const o = try c.exactFields(document.value(), &.{ "attempt_id", "contract", "schema_version", "deadline_ns", "job_sha256", "request_sha256", "sas_sha256", "parent_pid", "kind", "plan" });
        if (!std.mem.eql(u8, try c.string(o.get("contract").?), "uk.hyperv.transfer-intent") or
            try c.integer(u32, o.get("schema_version").?) != 1) return error.InvalidJob;
        const result: Intent = .{
            .attempt_id = try c.parseSha256(try c.string(o.get("attempt_id").?)),
            .deadline_ns = try c.integer(u64, o.get("deadline_ns").?),
            .job_sha256 = try c.parseSha256(try c.string(o.get("job_sha256").?)),
            .kind = try c.enumeration(job.Kind, o.get("kind").?),
            .plan = try job.Plan.parse(o.get("plan").?),
            .request_sha256 = try c.parseSha256(try c.string(o.get("request_sha256").?)),
            .sas_sha256 = try c.parseSha256(try c.string(o.get("sas_sha256").?)),
            .parent_pid = try c.integer(u32, o.get("parent_pid").?),
        };
        try result.plan.validate(result.kind);
        return result;
    }
};

fn boolean(value: std.json.Value) !bool {
    return if (value == .bool) value.bool else error.ExpectedBoolean;
}

pub const Journal = struct {
    io: std.Io,
    lock: *core.private_files.Locked,
    plan: job.Plan,
    report: Report,
    failed: bool = false,
    begin_failed: bool = false,

    pub fn observer(self: *Journal) client.Observer {
        return .{ .context = self, .notifyFn = notify };
    }

    fn notify(context: *anyopaque, event: client.Event) !void {
        const self: *Journal = @ptrCast(@alignCast(context));
        if (self.failed) return error.RecordingFailed;
        try self.update(event);
        self.persist() catch |err| {
            self.begin_failed = event == .begin;
            return err;
        };
    }

    fn update(self: *Journal, event: client.Event) !void {
        if (self.report.admitted_plan == null or !std.meta.eql(self.report.admitted_plan.?, self.plan))
            return error.InvalidProgress;
        var next = self.report;
        try next.validate();
        // Work on a copy: a rejected transition must not leave half-updated
        // counters that could later be published as a checkpoint.
        var progress = next.progress orelse return error.InvalidProgress;
        const current = &progress;
        switch (event) {
            .begin => |value| {
                if (current.pending or next.phase == .finished or current.requests_attempted != current.responses_observed or
                    current.mutations_attempted != current.mutations_confirmed or
                    value.mutation != try mutationStage(value.stage) or
                    (!value.mutation and value.bytes != 0) or value.bytes > self.plan.bytes - current.bytes_attempted)
                    return error.InvalidProgress;
                if (current.status) |status| {
                    const expected: u16 = switch (current.stage) {
                        .download_open => 200,
                        .footer_readback => 206,
                        else => 201,
                    };
                    if (status != expected) return error.InvalidProgress;
                }
                current.previous_effect = next.side_effect;
                current.pending = true;
                current.pending_mutation = value.mutation;
                current.pending_bytes = if (value.mutation) value.bytes else 0;
                current.stage = value.stage;
                current.status = null;
                current.requests_attempted += 1;
                if (value.mutation) {
                    current.mutations_attempted += 1;
                    current.bytes_attempted += value.bytes;
                }
                next.phase = .in_flight;
            },
            .end => |value| {
                if (!current.pending or (!value.transport_started and value.status != null)) return error.InvalidProgress;
                if (!value.transport_started) {
                    current.requests_attempted -= 1;
                    if (current.pending_mutation) {
                        current.mutations_attempted -= 1;
                        current.bytes_attempted -= current.pending_bytes;
                    }
                } else if (value.status) |status| {
                    current.responses_observed += 1;
                    if (current.pending_mutation) {
                        if (status >= 200 and status < 300) {
                            current.mutations_confirmed += 1;
                            current.bytes_confirmed += current.pending_bytes;
                        }
                    }
                }
                current.status = value.status;
                current.pending = false;
                current.pending_bytes = 0;
                current.pending_mutation = false;
                next.phase = .observed;
            },
        }
        try current.validate(next.kind.?, self.plan);
        next.progress = current.*;
        next.side_effect = current.certainty(self.plan);
        try next.validate();
        self.report = next;
    }

    pub fn persist(self: *Journal) !void {
        if (self.failed) return error.RecordingFailed;
        var buffer: [maximum_result]u8 = undefined;
        defer std.crypto.secureZero(u8, &buffer);
        var writer = std.Io.Writer.fixed(&buffer);
        self.report.write(&writer) catch {
            self.failed = true;
            self.report.failures.record(.recording, .{ .stage = .state_record, .category = .invalid_response }) catch unreachable;
            return error.RecordingFailed;
        };
        const result = self.lock.commit(self.io, job.state_name, writer.buffered()) catch {
            self.failed = true;
            self.report.failures.record(.recording, .{ .stage = .state_record, .category = .local_io }) catch unreachable;
            return error.RecordingFailed;
        };
        self.report.merge(result.failures);
        if (result.status != .durable or result.failures.cleanup != null or result.failures.recording != null) {
            self.failed = true;
            self.report.failures.record(.recording, .{ .stage = .state_record, .category = .local_io }) catch unreachable;
            return error.RecordingFailed;
        }
    }

    pub fn finish(self: *Journal, outcome: d.Outcome) Report {
        if (self.begin_failed) self.update(.{ .end = .{ .transport_started = false, .status = null } }) catch {
            self.report.primary(.internal);
        };
        var normalized = outcome;
        if (self.report.progress) |p| {
            const effect = p.certainty(self.plan);
            // Client outcomes describe issued operations; the journal knows
            // remaining admitted mutations and read-only pre-transport failures.
            if ((effect == .incomplete and normalized.side_effect == .accepted) or
                (self.plan.mutations == 0 and normalized.side_effect == .not_started))
                normalized.side_effect = effect;
        }
        self.report.outcome = normalized;
        self.report.side_effect = normalized.side_effect;
        self.report.phase = .finished;
        self.report.delivery_complete = true;
        self.report.merge(normalized.failureSummary() catch {
            self.report.primary(.invalid_response);
            self.report.rejectRecord();
            return self.report;
        });
        self.report.validate() catch self.report.rejectRecord();
        if (!self.failed) self.persist() catch {
            self.report.failures.record(.recording, .{ .stage = .state_record, .category = .local_io }) catch unreachable;
        };
        return self.report;
    }
};
