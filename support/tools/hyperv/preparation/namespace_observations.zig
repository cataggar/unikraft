//! Closed synthetic stage records. No namespace status or admission consumer.
const std = @import("std");
const c = @import("contracts.zig");
const measurement = @import("synthetic_measurement");

pub const ClockScope = enum { outer_helper, inner_payload };
pub const Stage = enum {
    setup_started,
    runtime_ready,
    namespace_enter,
    inner_payload_entry,
    inside_ready,
    policy_ready,
    blocked_probe,
    write_observed,

    pub fn clockScope(self: Stage) ClockScope {
        return switch (self) {
            .setup_started, .runtime_ready, .namespace_enter => .outer_helper,
            else => .inner_payload,
        };
    }
};
pub const stage_count = std.meta.fields(Stage).len;
pub const record_bytes = 512;
pub const total_record_bytes = stage_count * record_bytes;
pub const log_bytes = 6144;

pub fn fileName(comptime stage: Stage) [:0]const u8 {
    return "stage-" ++ @tagName(stage);
}

pub const Record = struct {
    schema: enum { hyperv_preparation_namespace_stage_v1 } = .hyperv_preparation_namespace_stage_v1,
    authority: enum { none } = .none,
    stage: Stage,
    clock_scope: ClockScope,
    self_executable_bytes: u64,
    sample: measurement.Sample,

    pub fn observe(io: std.Io, stage: Stage) !Record {
        const size = try measurement.selfExecutableBytes(io);
        return .{
            .stage = stage,
            .clock_scope = stage.clockScope(),
            .self_executable_bytes = size,
            .sample = try measurement.capture(),
        };
    }

    pub fn encode(self: Record, allocator: std.mem.Allocator) ![record_bytes]u8 {
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

pub const State = enum { observed, missing, partial, invalid, oversized, unavailable, invalid_order };
pub const Observation = struct {
    stage: Stage,
    state: State,
    record: ?Record = null,
};

pub fn decode(allocator: std.mem.Allocator, stage: Stage, bytes: []const u8) !Observation {
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
    if (record.stage != stage or !std.mem.eql(u8, bytes, &canonical)) return result;
    return .{ .stage = stage, .state = .observed, .record = record };
}

pub const Collection = struct {
    observations: [stage_count]Observation = initial: {
        var result: [stage_count]Observation = undefined;
        for (std.meta.fields(Stage), 0..) |field, index|
            result[index] = .{ .stage = @enumFromInt(field.value), .state = .missing };
        break :initial result;
    },

    pub fn checkOrder(self: *Collection) void {
        var last_wall: ?u64 = null;
        var last_cpu: [2]?u64 = .{ null, null };
        for (&self.observations) |*observation| {
            const record = observation.record orelse continue;
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
            .schema = "hyperv_preparation_namespace_observations_v1",
            .authority = "none",
            .observations = self.observations,
        });
        defer allocator.free(json);
        return std.fmt.bufPrint(buffer, "Namespace Git timeout observations: {s}", .{json});
    }
};
