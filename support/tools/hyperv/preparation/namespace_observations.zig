//! Closed synthetic stage records. No namespace status or admission consumer.
const std = @import("std");
const c = @import("contracts.zig");
const measurement = @import("synthetic_measurement");

pub const Fixture = enum {
    timeout,
    git_policy,
    git_unborn,
    git_modified,
    git_timeout,

    pub fn fromMode(input: []const u8) !Fixture {
        inline for (std.meta.fields(Fixture)) |field| {
            const fixture: Fixture = @enumFromInt(field.value);
            if (std.mem.eql(u8, input, fixture.mode())) return fixture;
        }
        return error.InvalidFixtureObservationMode;
    }

    pub fn mode(self: Fixture) []const u8 {
        return switch (self) {
            .timeout => "timeout",
            .git_policy => "git-policy",
            .git_unborn => "git-unborn",
            .git_modified => "git-modified",
            .git_timeout => "git-timeout",
        };
    }

    pub fn timesOut(self: Fixture) bool {
        return self == .timeout or self == .git_timeout;
    }

    pub fn logPrefix(self: Fixture) []const u8 {
        return if (self == .git_timeout) "Namespace Git timeout observations: " else "Namespace fixture observations: ";
    }
};

pub const ClockScope = enum { outer_helper, inner_payload };
pub const Stage = enum {
    setup_started,
    helper_copy,
    helper_copied,
    helper_recorded,
    payload_copy,
    payload_copied,
    payload_recorded,
    dynamic_copy,
    dynamic_copied,
    dynamic_recorded,
    incomplete_validated,
    git_runtime_copy,
    runtime_ready,
    context_ready,
    git_setup,
    git_setup_ready,
    sandbox_record,
    sandbox_ready,
    binding_reopen,
    binding_reopened,
    binding_validated,
    make_policy_refusal,
    make_policy_refused,
    git_policy_refusal,
    git_policy_refused,
    missing_policy_enter,
    missing_policy_refused,
    alias_enter,
    alias_refused,
    missing_helper_enter,
    missing_helper_refused,
    missing_git_enter,
    missing_git_refused,
    namespace_enter,
    inner_payload_entry,
    detached_setup,
    detached_forked,
    detached_ready,
    inside_ready,
    policy_ready,
    stripped_head,
    stripped_head_ready,
    stripped_index,
    stripped_index_ready,
    poisoned_head,
    poisoned_head_ready,
    poisoned_index,
    poisoned_index_ready,
    blocked_probe,
    blocked_spawned,
    write_observed,
    blocked_checked,
    timeout_ready,
    blocked_reaped,
    invalid_commands,
    invalid_commands_ready,
    inner_complete,
    namespace_return,

    pub fn clockScope(self: Stage) ClockScope {
        return if (@intFromEnum(self) <= @intFromEnum(Stage.namespace_enter) or self == .namespace_return)
            .outer_helper
        else
            .inner_payload;
    }

    pub fn appliesTo(self: Stage, fixture: Fixture) bool {
        return switch (self) {
            .dynamic_copy,
            .dynamic_copied,
            .dynamic_recorded,
            .incomplete_validated,
            .detached_setup,
            .detached_forked,
            .detached_ready,
            => fixture == .timeout,
            .helper_copy,
            .helper_copied,
            .helper_recorded,
            .git_runtime_copy,
            .git_setup,
            .git_setup_ready,
            .inside_ready,
            .policy_ready,
            => fixture != .timeout,
            .binding_reopen,
            .binding_reopened,
            .binding_validated,
            .make_policy_refusal,
            .make_policy_refused,
            .git_policy_refusal,
            .git_policy_refused,
            .missing_policy_enter,
            .missing_policy_refused,
            .alias_enter,
            .alias_refused,
            .missing_helper_enter,
            .missing_helper_refused,
            .missing_git_enter,
            .missing_git_refused,
            .stripped_head,
            .stripped_head_ready,
            .stripped_index,
            .stripped_index_ready,
            .poisoned_head,
            .poisoned_head_ready,
            .poisoned_index,
            .poisoned_index_ready,
            .invalid_commands,
            .invalid_commands_ready,
            .inner_complete,
            => !fixture.timesOut(),
            .blocked_probe, .blocked_spawned, .write_observed, .blocked_checked => fixture != .timeout and fixture != .git_unborn,
            .timeout_ready => fixture.timesOut(),
            .blocked_reaped => fixture == .git_policy or fixture == .git_modified,
            else => true,
        };
    }
};
pub const stage_count = std.meta.fields(Stage).len;
pub const record_bytes = 512;
pub const total_record_bytes = stage_count * record_bytes;
pub const log_bytes = stage_count * (record_bytes + 128) + 256;

pub fn fileName(stage: Stage) [:0]const u8 {
    return switch (stage) {
        inline else => |value| "stage-" ++ @tagName(value),
    };
}

pub const Record = struct {
    schema: enum { hyperv_preparation_namespace_stage_v2 } = .hyperv_preparation_namespace_stage_v2,
    authority: enum { none } = .none,
    fixture: Fixture,
    stage: Stage,
    clock_scope: ClockScope,
    self_executable_bytes: u64,
    sample: measurement.Sample,

    pub fn observe(io: std.Io, fixture: Fixture, stage: Stage) !Record {
        if (!stage.appliesTo(fixture)) return error.InvalidFixtureObservationPhase;
        const size = try measurement.selfExecutableBytes(io);
        return .{
            .fixture = fixture,
            .stage = stage,
            .clock_scope = stage.clockScope(),
            .self_executable_bytes = size,
            .sample = try measurement.capture(),
        };
    }

    pub fn encode(self: Record, allocator: std.mem.Allocator) ![record_bytes]u8 {
        if (!self.stage.appliesTo(self.fixture)) return error.InvalidFixtureObservationPhase;
        if (self.clock_scope != self.stage.clockScope() or self.self_executable_bytes == 0)
            return error.InvalidFixtureObservation;
        const json = try c.canonical(allocator, self);
        defer allocator.free(json);
        if (json.len > record_bytes) return error.FixtureObservationTooLarge;
        var result = [_]u8{0} ** record_bytes;
        @memcpy(result[0..json.len], json);
        return result;
    }
};

pub const State = enum { observed, missing, not_applicable, partial, invalid, oversized, unavailable, invalid_order };
pub const Observation = struct {
    stage: Stage,
    state: State,
    record: ?Record = null,
};

pub fn decode(allocator: std.mem.Allocator, fixture: Fixture, stage: Stage, bytes: []const u8) !Observation {
    var result: Observation = .{ .stage = stage, .state = .invalid };
    if (bytes.len < record_bytes) {
        result.state = .partial;
        return result;
    }
    if (bytes.len > record_bytes) {
        result.state = .oversized;
        return result;
    }
    const parsed = c.parse(Record, allocator, std.mem.trimEnd(u8, bytes, "\x00")) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return result,
    };
    defer parsed.deinit();
    const record = parsed.value;
    const canonical = record.encode(allocator) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return result,
    };
    if (record.fixture != fixture or record.stage != stage or !std.mem.eql(u8, bytes, &canonical)) return result;
    return .{ .stage = stage, .state = .observed, .record = record };
}

pub const Collection = struct {
    fixture: Fixture,
    observations: [stage_count]Observation,

    pub fn init(fixture: Fixture) Collection {
        var result: Collection = .{ .fixture = fixture, .observations = undefined };
        for (std.enums.values(Stage), 0..) |stage, index| {
            result.observations[index] = .{
                .stage = stage,
                .state = if (stage.appliesTo(fixture)) .missing else .not_applicable,
            };
        }
        return result;
    }

    pub fn checkOrder(self: *Collection) void {
        var last_wall: ?u64 = null;
        var last_cpu: [2]?u64 = .{ null, null };
        for (&self.observations) |*observation| {
            const record = observation.record orelse continue;
            if (record.fixture != self.fixture or record.stage != observation.stage or
                record.clock_scope != record.stage.clockScope() or !record.stage.appliesTo(self.fixture))
            {
                observation.state = .invalid;
                observation.record = null;
                continue;
            }
            const scope = @intFromEnum(record.clock_scope);
            if ((last_wall != null and record.sample.monotonic_ns < last_wall.?) or
                (last_cpu[scope] != null and record.sample.process_cpu_ns < last_cpu[scope].?))
            {
                observation.state = .invalid_order;
                observation.record = null;
                continue;
            }
            last_wall = record.sample.monotonic_ns;
            last_cpu[scope] = record.sample.process_cpu_ns;
        }
    }

    pub fn log(self: Collection, allocator: std.mem.Allocator, buffer: *[log_bytes]u8) ![]const u8 {
        const json = try c.canonical(allocator, .{
            .schema = "hyperv_preparation_namespace_observations_v2",
            .authority = "none",
            .fixture = self.fixture,
            .observations = self.observations,
        });
        defer allocator.free(json);
        return std.fmt.bufPrint(buffer, "{s}{s}", .{ self.fixture.logPrefix(), json });
    }
};
