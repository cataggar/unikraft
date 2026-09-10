const std = @import("std");
const core = @import("hyperv_core");
const c = core.contracts;
const d = @import("diagnostic.zig");
const job = @import("job.zig");
const client = @import("client.zig");

pub const maximum_result = 8192;
pub const Phase = enum { prepared, in_flight, observed, finished };

pub const Progress = struct {
    bytes_attempted: u64 = 0,
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

    pub fn validate(self: Progress, plan: job.Plan) !void {
        if (self.requests_attempted > plan.requests or self.responses_observed > self.requests_attempted or
            self.mutations_attempted > plan.mutations or self.mutations_confirmed > self.mutations_attempted or
            self.bytes_attempted > plan.bytes or self.bytes_confirmed > self.bytes_attempted or
            (self.pending and self.requests_attempted == 0) or
            (!self.pending and (self.pending_bytes != 0 or self.pending_mutation))) return error.InvalidReport;
        if (self.status) |status| if (status < 100 or status > 599) return error.InvalidReport;
    }
};

pub const Report = struct {
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

    pub fn succeeded(self: Report) bool {
        return self.delivery_complete and self.process_cleanup_complete == true and
            self.failures.primary == null and self.failures.cleanup == null and self.failures.recording == null and
            self.outcome != null and self.outcome.?.completion == .complete;
    }

    pub fn write(self: Report, writer: *std.Io.Writer) !void {
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
        const plan = intent.plan;
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
        const outcome = o.get("outcome").?;
        const progress = o.get("progress").?;
        const cleanup = o.get("process_cleanup_complete").?;
        const result: Report = .{
            .attempt_id = attempt,
            .delivery_complete = try boolean(o.get("delivery_complete").?),
            .failures = try core.diagnostics.Failures.parse(o.get("failures").?),
            .job_sha256 = observed,
            .kind = try c.enumeration(job.Kind, o.get("kind").?),
            .outcome = if (outcome == .null) null else try d.Outcome.parse(outcome),
            .phase = try c.enumeration(Phase, o.get("phase").?),
            .process_cleanup_complete = if (cleanup == .null) null else try boolean(cleanup),
            .progress = if (progress == .null) null else try Progress.parse(progress),
            .side_effect = try c.enumeration(d.Certainty, o.get("side_effect").?),
        };
        if (result.kind != intent.kind) return error.BindingMismatch;
        if (result.progress) |value| try value.validate(plan);
        if (result.delivery_complete and (result.phase != .finished or result.outcome == null)) return error.InvalidReport;
        if (result.outcome) |value| {
            if (result.phase != .finished or result.side_effect != value.side_effect or
                value.bytes_accepted > plan.bytes or value.bytes_streamed > plan.bytes + plan.requests or
                value.bytes_downloaded > plan.download_bytes) return error.InvalidReport;
            const failures = try value.failureSummary();
            if ((failures.primary != null and result.failures.primary == null) or
                (failures.cleanup != null and result.failures.cleanup == null) or
                (failures.recording != null and result.failures.recording == null)) return error.InvalidReport;
            if (value.completion == .complete) {
                const p = result.progress orelse return error.InvalidReport;
                if (p.pending or p.requests_attempted != plan.requests or p.responses_observed != plan.requests or
                    p.mutations_confirmed != plan.mutations or p.bytes_confirmed != plan.bytes)
                    return error.InvalidReport;
                if (value.side_effect != (if (plan.mutations == 0) d.Certainty.not_applicable else .accepted))
                    return error.InvalidReport;
                const terminal_status: u16 = switch (intent.kind) {
                    .pages => 206,
                    .blob => if (plan.mutations == 0) 200 else 201,
                };
                if (value.diagnostic.status != terminal_status or p.status != terminal_status)
                    return error.InvalidReport;
            }
        }
        return result;
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
        return .{
            .attempt_id = try c.parseSha256(try c.string(o.get("attempt_id").?)),
            .deadline_ns = try c.integer(u64, o.get("deadline_ns").?),
            .job_sha256 = try c.parseSha256(try c.string(o.get("job_sha256").?)),
            .kind = try c.enumeration(job.Kind, o.get("kind").?),
            .plan = try job.Plan.parse(o.get("plan").?),
            .request_sha256 = try c.parseSha256(try c.string(o.get("request_sha256").?)),
            .sas_sha256 = try c.parseSha256(try c.string(o.get("sas_sha256").?)),
            .parent_pid = try c.integer(u32, o.get("parent_pid").?),
        };
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
        const p = &self.report.progress.?;
        switch (event) {
            .begin => |value| {
                if (p.pending) return error.InvalidProgress;
                p.previous_effect = self.report.side_effect;
                p.pending = true;
                p.pending_mutation = value.mutation;
                p.pending_bytes = if (value.mutation) value.bytes else 0;
                p.stage = value.stage;
                p.status = null;
                p.requests_attempted += 1;
                if (value.mutation) {
                    p.mutations_attempted += 1;
                    p.bytes_attempted += value.bytes;
                    self.report.side_effect = .unknown;
                }
                self.report.phase = .in_flight;
            },
            .end => |value| {
                if (!p.pending) return error.InvalidProgress;
                if (!value.transport_started) {
                    p.requests_attempted -= 1;
                    if (p.pending_mutation) {
                        p.mutations_attempted -= 1;
                        p.bytes_attempted -= p.pending_bytes;
                    }
                    self.report.side_effect = p.previous_effect;
                } else if (value.status) |status| {
                    p.responses_observed += 1;
                    if (p.pending_mutation) {
                        if (status >= 200 and status < 300) {
                            p.mutations_confirmed += 1;
                            p.bytes_confirmed += p.pending_bytes;
                            self.report.side_effect = if (p.mutations_confirmed == self.plan.mutations) .accepted else .incomplete;
                        } else self.report.side_effect = if (p.mutations_confirmed == 0) .rejected else .incomplete;
                    }
                }
                p.status = value.status;
                p.pending = false;
                p.pending_bytes = 0;
                p.pending_mutation = false;
                self.report.phase = .observed;
            },
        }
        try p.validate(self.plan);
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
        self.report.outcome = outcome;
        self.report.side_effect = outcome.side_effect;
        self.report.phase = .finished;
        self.report.delivery_complete = true;
        self.report.merge(outcome.failureSummary() catch {
            self.report.primary(.invalid_response);
            return self.report;
        });
        if (!self.failed) self.persist() catch {
            self.report.failures.record(.recording, .{ .stage = .state_record, .category = .local_io }) catch unreachable;
        };
        return self.report;
    }
};
