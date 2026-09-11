const std = @import("std");
const core = @import("hyperv_core");
const transfer = @import("hyperv_transfer");
const contract = @import("contract.zig");
const local = @import("local.zig");
const evidence = @import("evidence.zig");

pub const Step = enum {
    group_create,
    os_create,
    os_grant,
    os_upload,
    os_revoke,
    os_access_closed,
    data_create,
    data_grant,
    data_upload,
    data_revoke,
    data_access_closed,
    network_nsg,
    network_vnet,
    network_nic,
    deploy_boot1,
    observe_boot1,
    serial_boot1,
    deallocate_boot1,
    observe_deallocated,
    start_boot2,
    observe_boot2,
    serial_boot2,
    deallocate_boot2,
    observe_final_deallocated,
    cleanup_observe,
    cleanup_os_revoke,
    cleanup_data_revoke,
    cleanup_deallocate,
    cleanup_delete,
    cleanup_absence,
    cleanup_os_access,
    cleanup_data_access,
    cleanup_dispose,

    pub fn mutation(self: Step) bool {
        return switch (self) {
            .os_access_closed, .data_access_closed, .observe_boot1, .serial_boot1, .observe_deallocated, .observe_boot2, .serial_boot2, .observe_final_deallocated, .cleanup_observe, .cleanup_absence, .cleanup_os_access, .cleanup_data_access, .cleanup_dispose => false,
            else => true,
        };
    }
    pub fn cleanup(self: Step) bool {
        return @intFromEnum(self) >= @intFromEnum(Step.cleanup_observe);
    }
    pub fn upload(self: Step) bool {
        return self == .os_upload or self == .data_upload;
    }
};
pub const step_count = std.meta.fields(Step).len;
pub const execution_count = @intFromEnum(Step.cleanup_observe);
pub const Presence = enum { unknown, present, absent };
pub const Power = enum { unknown, running, deallocated };
pub const Uuid = [36]u8;
pub const Originals = struct { os: ?Uuid = null, data: ?Uuid = null, vm: ?Uuid = null };
pub const Observation = struct {
    group: Presence = .unknown,
    originals: Originals = .{},
    power: Power = .unknown,
    owned_inventory: bool = false,
    envelope: bool = false,
};
pub const Serial = struct { name: []const u8, bytes: u32, sha256: local.Hash };
/// Storage adapter only: the merged transfer Report remains the authority for
/// all checkpoint/Outcome/certainty relationships.
pub const PageReport = struct {
    plan: transfer.job.Plan,
    nonce: local.Hash,
    job_sha256: local.Hash,
    phase: transfer.worker.protocol.Phase,
    progress: ?transfer.worker.protocol.Progress,
    outcome: ?transfer.Outcome,
    effect: transfer.diagnostic.Certainty,
    failures: core.diagnostics.Failures,
    delivery_complete: bool,
    process_cleanup_complete: ?bool,

    pub fn capture(report: transfer.worker.protocol.Report) !PageReport {
        try report.validate();
        return .{
            .plan = report.admitted_plan orelse return error.MissingPlan,
            .nonce = std.fmt.bytesToHex(report.attempt_id orelse return error.MissingBinding, .lower),
            .job_sha256 = std.fmt.bytesToHex(report.job_sha256 orelse return error.MissingBinding, .lower),
            .phase = report.phase,
            .progress = report.progress,
            .outcome = report.outcome,
            .effect = report.side_effect,
            .failures = report.failures,
            .delivery_complete = report.delivery_complete,
            .process_cleanup_complete = report.process_cleanup_complete,
        };
    }
    pub fn restore(self: PageReport) !transfer.worker.protocol.Report {
        const report: transfer.worker.protocol.Report = .{
            .admitted_plan = self.plan,
            .attempt_id = try core.contracts.parseSha256(&self.nonce),
            .job_sha256 = try core.contracts.parseSha256(&self.job_sha256),
            .kind = .pages,
            .phase = self.phase,
            .progress = self.progress,
            .outcome = self.outcome,
            .side_effect = self.effect,
            .failures = self.failures,
            .delivery_complete = self.delivery_complete,
            .process_cleanup_complete = self.process_cleanup_complete,
        };
        try report.validate();
        return report;
    }
};
pub const Result = struct {
    contract: []const u8 = "uk.hyperv.persistence-result",
    schema_version: u8 = 1,
    job_sha256: local.Hash,
    nonce: local.Hash,
    step: Step,
    complete: bool = false,
    effect: transfer.diagnostic.Certainty,
    failures: core.diagnostics.Failures = .{},
    observation: Observation = .{},
    transfer: ?transfer.Outcome = null,
    page_report: ?PageReport = null,
    serial: ?Serial = null,
    access_closed: bool = false,
    secrets_disposed: bool = false,
    process_cleanup_complete: bool = true,
    http_status: ?u16 = null,
    service_code: core.diagnostics.ServiceCode = .unavailable,
    access_metadata: ?transfer.diagnostic.Metadata = null,

    pub fn validate(self: Result) !void {
        if (!std.mem.eql(u8, self.contract, "uk.hyperv.persistence-result") or self.schema_version != 1) return error.UnknownSchema;
        try local.hex(&self.job_sha256, true);
        try local.hex(&self.nonce, true);
        try originalsValid(self.observation.originals);
        try (core.diagnostics.Diagnostic{ .stage = .arm, .category = .unavailable, .http_status = self.http_status, .service_code = self.service_code }).validate();
        if (self.complete and self.step == .cleanup_absence and (self.observation.group != .absent or
            self.http_status != 404 or self.service_code != .ResourceGroupNotFound)) return error.InvalidAbsence;
        if (self.observation.group == .absent and
            (self.step != .cleanup_observe and self.step != .cleanup_absence or
                self.http_status != 404 or self.service_code != .ResourceGroupNotFound)) return error.InvalidAbsence;
        if (self.access_metadata) |metadata| try metadata.validate();
        if (self.access_closed and (self.http_status != 403 or self.service_code != .AuthenticationFailed or
            self.access_metadata == null or self.access_metadata.?.state != .known or
            self.access_metadata.?.code != .AuthenticationFailed)) return error.InvalidAccessProof;
        if (self.step.mutation()) {
            if (self.effect == .not_applicable) return error.InvalidEffect;
        } else if (self.effect != .not_applicable) return error.InvalidEffect;
        if (self.transfer) |outcome| {
            try outcome.validate();
            if (!self.step.upload() or self.page_report == null or outcome.side_effect != self.effect or
                (self.complete and outcome.completion != .complete)) return error.InvalidTransfer;
        } else if (self.step.upload() and self.complete) return error.InvalidTransfer;
        if (self.page_report) |page| {
            _ = try page.restore();
            if (!self.step.upload() or !std.mem.eql(u8, &page.nonce, &self.nonce) or
                !std.mem.eql(u8, &page.job_sha256, &self.job_sha256) or page.effect != self.effect or
                !std.meta.eql(page.outcome, self.transfer))
                return error.InvalidTransfer;
        }
        if (self.serial) |serial| {
            if (self.step != .serial_boot1 and self.step != .serial_boot2) return error.InvalidSerialResult;
            if (!std.mem.eql(u8, serial.name, "serial.bin") or serial.bytes == 0 or serial.bytes > contract.serial_limit)
                return error.InvalidSerialResult;
            try local.hex(&serial.sha256, true);
        }
        if (self.complete and (self.failures.primary != null or self.failures.cleanup != null or self.failures.recording != null or
            !self.process_cleanup_complete or (self.step.mutation() and self.effect != .accepted and
            !(self.step == .cleanup_delete and self.effect == .not_started))))
            return error.ContradictoryResult;
    }
};
pub const Job = struct {
    contract: []const u8 = "uk.hyperv.persistence-job",
    schema_version: u8 = 1,
    input: contract.Contract,
    input_sha256: local.Hash,
    nonce: local.Hash,
    step: Step,
    originals: Originals,
    parent_pid: u32,
    deadline_ns: u64,
    authority_lane: contract.TrustedInputs.Lane,
    boot1: ?evidence.Evidence,
    creation_intent: [3]bool,
    network_intent: [3]bool,
    group_intent: bool,

    pub fn validate(self: Job) !void {
        if (!std.mem.eql(u8, self.contract, "uk.hyperv.persistence-job") or self.schema_version != 1 or self.parent_pid == 0 or
            self.deadline_ns == 0 or self.step.cleanup() != (self.authority_lane == .cleanup)) return error.InvalidJob;
        try self.input.validate();
        try local.hex(&self.input_sha256, true);
        try local.hex(&self.nonce, true);
        try originalsValid(self.originals);
    }
};
pub const Progress = enum { unissued, intent, done, failed, skipped };
pub const Record = struct {
    progress: Progress = .unissued,
    effect: transfer.diagnostic.Certainty = .not_started,
    transfer: ?transfer.Outcome = null,
    page_report: ?PageReport = null,
    http_status: ?u16 = null,
    service_code: core.diagnostics.ServiceCode = .unavailable,
    access_metadata: ?transfer.diagnostic.Metadata = null,
};
pub const Phase = enum { prepared, running, failed, two_boots_verified, cleaned };
pub const State = struct {
    contract: []const u8 = "uk.hyperv.persistence-state",
    schema_version: u8 = 1,
    input_sha256: local.Hash,
    nonce: local.Hash,
    consumed: bool = false,
    phase: Phase = .prepared,
    cleanup_required: bool = false,
    attempt_deadline_ns: u64 = 0,
    cleanup_deadline_ns: ?u64 = null,
    boot_count: u8 = 0,
    originals: Originals = .{},
    records: [step_count]Record = [_]Record{.{}} ** step_count,
    boot1: ?evidence.Evidence = null,
    boot2: ?evidence.Evidence = null,
    failures: core.diagnostics.Failures = .{},
    os_access_pending: bool = false,
    data_access_pending: bool = false,
    group_absent: bool = false,
    secrets_disposed: bool = false,
    process_cleanup_complete: bool = true,
    control_bytes: u64 = 0,

    pub fn record(self: *State, step: Step) *Record {
        return &self.records[@intFromEnum(step)];
    }
    pub fn isDone(self: State, step: Step) bool {
        return self.records[@intFromEnum(step)].progress == .done;
    }
    pub fn mayOwn(self: State, step: Step) bool {
        return switch (self.records[@intFromEnum(step)].effect) {
            .accepted, .unknown, .incomplete => true,
            else => false,
        };
    }
    pub fn retainOriginals(self: *State, step: Step, observed: Originals) !void {
        var originals = self.originals;
        inline for (.{ "os", "data", "vm" }) |field| {
            if (@field(observed, field)) |uuid| {
                const slot = &@field(originals, field);
                if (slot.*) |known| {
                    if (!std.mem.eql(u8, &known, &uuid)) return error.IdentityDrift;
                } else {
                    const creation: Step = comptime if (std.mem.eql(u8, field, "os")) .os_create else if (std.mem.eql(u8, field, "data")) .data_create else .deploy_boot1;
                    if ((step != creation and step != .cleanup_observe) or !self.mayOwn(creation)) return error.UnadmittedIdentity;
                    slot.* = uuid;
                }
            }
        }
        try originalsValid(originals);
        self.originals = originals;
    }
    pub fn reconcileUnstartedGrant(self: *State, step: Step) void {
        const record_ = self.records[@intFromEnum(step)];
        if (record_.effect != .not_started or record_.progress != .failed) return;
        if (step == .os_grant) self.os_access_pending = false;
        if (step == .data_grant) self.data_access_pending = false;
    }
    pub fn validate(self: State) !void {
        if (!std.mem.eql(u8, self.contract, "uk.hyperv.persistence-state") or self.schema_version != 1) return error.UnknownSchema;
        try local.hex(&self.input_sha256, true);
        try local.hex(&self.nonce, true);
        try originalsValid(self.originals);
        if (self.boot_count > 2 or self.control_bytes > contract.control_limit) return error.InvalidState;
        const first_intent = self.records[@intFromEnum(Step.deploy_boot1)].progress != .unissued;
        const second_intent = self.records[@intFromEnum(Step.start_boot2)].progress != .unissued;
        if (self.boot_count != @as(u8, if (second_intent) 2 else if (first_intent) 1 else 0)) return error.InvalidBootCount;
        if (!self.consumed and (self.phase != .prepared or self.cleanup_required or self.boot_count != 0 or self.attempt_deadline_ns != 0))
            return error.InvalidConsumption;
        if (!self.consumed and (!std.meta.eql(self.originals, Originals{}) or self.boot1 != null or self.boot2 != null or
            self.cleanup_deadline_ns != null or self.os_access_pending or self.data_access_pending or
            self.group_absent or self.secrets_disposed or !self.process_cleanup_complete)) return error.InvalidConsumption;
        if (self.consumed and (self.phase == .prepared or self.attempt_deadline_ns == 0)) return error.InvalidConsumption;
        if (second_intent and (self.boot1 == null or !self.isDone(.observe_deallocated) or self.originals.vm == null))
            return error.InvalidRestartIntent;
        if ((self.originals.os != null and !self.mayOwn(.os_create)) or
            (self.originals.data != null and !self.mayOwn(.data_create)) or
            (self.originals.vm != null and !self.mayOwn(.deploy_boot1))) return error.UnadmittedIdentity;
        if (self.boot1) |first| {
            if (first.boot != 1 or first.writes != 5 or first.flushes != 3 or first.bytes == 0 or !self.isDone(.serial_boot1))
                return error.InvalidEvidence;
        }
        if (self.boot2) |second| {
            const first = self.boot1 orelse return error.InvalidEvidence;
            if (second.boot != 2 or second.writes != 0 or second.flushes != 0 or second.bytes == 0 or
                !std.meta.eql(second.identity, first.identity) or !second_intent or !self.isDone(.serial_boot2)) return error.InvalidEvidence;
        }
        for (self.records, 0..) |record_, index| {
            const step: Step = @enumFromInt(index);
            try (core.diagnostics.Diagnostic{ .stage = .arm, .category = .unavailable, .http_status = record_.http_status, .service_code = record_.service_code }).validate();
            if (record_.access_metadata) |metadata| try metadata.validate();
            if (record_.progress == .unissued or record_.progress == .intent or record_.progress == .skipped) {
                if (record_.page_report != null or record_.http_status != null or record_.service_code != .unavailable or
                    record_.access_metadata != null) return error.InvalidProgress;
            }
            if (index > 0 and index < execution_count and record_.progress != .unissued and self.records[index - 1].progress != .done)
                return error.InvalidExecutionOrder;
            switch (record_.progress) {
                .unissued => if (record_.effect != .not_started or record_.transfer != null) return error.InvalidProgress,
                .intent => if (record_.effect != (if (step.mutation()) transfer.diagnostic.Certainty.unknown else .not_applicable) or record_.transfer != null)
                    return error.InvalidProgress,
                .skipped => if (!step.cleanup() or record_.effect != .not_started or record_.transfer != null) return error.InvalidProgress,
                .done, .failed => {
                    if (step.mutation() == (record_.effect == .not_applicable)) return error.InvalidProgress;
                    if (record_.transfer) |outcome| {
                        try outcome.validate();
                        if (!step.upload() or record_.page_report == null or outcome.side_effect != record_.effect) return error.InvalidProgress;
                        if (record_.progress == .done and (outcome.completion != .complete or outcome.side_effect != .accepted or
                            outcome.bytes_accepted == 0 or outcome.bytes_accepted != outcome.bytes_streamed or
                            outcome.sha256 == null or outcome.footer_sha256 == null)) return error.InvalidTransfer;
                    }
                    if (step.upload() and record_.progress == .done and record_.transfer == null) return error.InvalidTransfer;
                    if (record_.progress == .done and step.mutation() and record_.effect != .accepted and
                        !(step == .cleanup_delete and record_.effect == .not_started)) return error.InvalidEffect;
                    if (record_.progress == .done and (step == .os_access_closed or step == .data_access_closed or
                        step == .cleanup_os_access or step == .cleanup_data_access) and
                        (record_.http_status != 403 or record_.service_code != .AuthenticationFailed or
                            record_.access_metadata == null or record_.access_metadata.?.state != .known or
                            record_.access_metadata.?.code != .AuthenticationFailed)) return error.InvalidAccessProof;
                    if (self.isDone(.serial_boot1) != (self.boot1 != null) or self.isDone(.serial_boot2) != (self.boot2 != null))
                        return error.InvalidEvidence;
                    if (self.group_absent and (!self.isDone(.cleanup_absence) or
                        self.records[@intFromEnum(Step.cleanup_absence)].http_status != 404 or
                        self.records[@intFromEnum(Step.cleanup_absence)].service_code != .ResourceGroupNotFound)) return error.InvalidAbsence;
                    if (self.secrets_disposed and !self.isDone(.cleanup_dispose)) return error.InvalidCleanup;
                    if (!self.os_access_pending and self.records[@intFromEnum(Step.os_grant)].progress != .unissued and
                        self.records[@intFromEnum(Step.os_grant)].effect != .not_started and
                        !self.isDone(.os_access_closed) and !self.isDone(.cleanup_os_access)) return error.InvalidAccessProof;
                    if (!self.data_access_pending and self.records[@intFromEnum(Step.data_grant)].progress != .unissued and
                        self.records[@intFromEnum(Step.data_grant)].effect != .not_started and
                        !self.isDone(.data_access_closed) and !self.isDone(.cleanup_data_access)) return error.InvalidAccessProof;
                    if (record_.page_report) |page| {
                        _ = try page.restore();
                        if (!step.upload() or page.effect != record_.effect or !std.mem.eql(u8, &page.nonce, &self.nonce) or
                            !std.meta.eql(page.outcome, record_.transfer))
                            return error.InvalidProgress;
                    }
                },
            }
            if (!self.consumed and record_.progress != .unissued) return error.InvalidConsumption;
        }
        if (self.phase == .two_boots_verified and (self.boot2 == null or !self.isDone(.observe_final_deallocated)))
            return error.InvalidEvidence;
        if (self.phase == .cleaned and (!self.group_absent or self.os_access_pending or self.data_access_pending or
            !self.secrets_disposed or !self.process_cleanup_complete or self.cleanup_required)) return error.InvalidCleanup;
    }

    pub fn succeeded(self: State) bool {
        self.validate() catch return false;
        for (self.records[0..execution_count]) |record_| if (record_.progress != .done) return false;
        return self.phase == .cleaned and self.boot2 != null and self.failures.primary == null and
            self.failures.cleanup == null and self.failures.recording == null;
    }
};

pub fn originalsValid(originals: Originals) !void {
    const azure = @import("hyperv_azure");
    const values = [_]?Uuid{ originals.os, originals.data, originals.vm };
    for (values, 0..) |value, index| if (value) |uuid| {
        _ = try azure.scope.uuid(&uuid);
        for (values[0..index]) |prior| if (prior) |other| if (std.mem.eql(u8, &uuid, &other)) return error.IdentityCollision;
    };
}

pub fn merge(target: *core.diagnostics.Failures, source: core.diagnostics.Failures) void {
    if (target.primary == null) target.primary = source.primary;
    if (target.cleanup == null) target.cleanup = source.cleanup;
    if (target.recording == null) target.recording = source.recording;
}
pub fn mergeStep(target: *core.diagnostics.Failures, source: core.diagnostics.Failures, step: Step) void {
    var lanes = source;
    if (step.cleanup()) {
        lanes.cleanup = lanes.cleanup orelse lanes.primary;
        lanes.primary = null;
    }
    merge(target, lanes);
}
