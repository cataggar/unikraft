//! Bounded fixture observations, not launch, cleanup, or authority evidence.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const measurement = @import("synthetic_measurement");
const linux = std.os.linux;

comptime {
    if (!builtin.is_test and !(@hasDecl(@import("root"), "host_timing_fixture") and @import("root").host_timing_fixture))
        @compileError("Host timing requires a synthetic fixture root");
}

pub const Fixture = enum { hard_deadline, success, setup_refusal, expired, launch_failure, observer_refusal };
pub const Stage = enum {
    call_enter,
    request_encoded,
    reservation_ready,
    state_ready,
    operation_ready,
    job_ready,
    process_call,
    process_return,
    call_success,
    call_error,
    child_entry,
};
pub const Scope = enum { parent, child };
pub const Fault = enum { clock_failed, invalid, overflow, process_changed, reused, io_failed };
pub const ChildStatus = enum { not_called, cleanup_unconfirmed, missing, invalid, overflow, io_failed, entry };
pub const Cleanup = enum { not_called, unconfirmed, incomplete, complete };
pub const slot_bytes = 1024;
pub const parent_slots = 9;
pub const max_bytes = (parent_slots + 2) * slot_bytes;
pub const aggregate_bytes = @typeInfo(Fixture).@"enum".fields.len * max_bytes;
pub const child_name = "synthetic-host-child-entry-v1";

pub const Record = struct {
    schema: enum { synthetic_host_timing_v1 } = .synthetic_host_timing_v1,
    authority: enum { none } = .none,
    scope: Scope,
    stage: Stage,
    sequence: u8,
    cleanup_complete: ?bool = null,
    sample: measurement.Sample,

    fn validate(self: Record) !void {
        if ((self.stage == .child_entry) != (self.scope == .child) or
            (self.stage == .process_return) != (self.cleanup_complete != null) or
            (self.scope == .child and self.sequence != 0) or
            (self.scope == .parent and self.sequence >= parent_slots))
            return error.InvalidHostTiming;
    }

    pub fn encode(self: Record) ![slot_bytes]u8 {
        try self.validate();
        return encodeSlot(self);
    }
};

pub fn encodeSlot(value: anytype) ![slot_bytes]u8 {
    var bytes = [_]u8{0} ** slot_bytes;
    var out: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(value, .{}, &out);
    try out.writeByte('\n');
    return bytes;
}

pub fn decodeRecord(a: std.mem.Allocator, bytes: []const u8) !Record {
    if (bytes.len != slot_bytes) return error.InvalidHostTiming;
    const parsed = std.json.parseFromSlice(Record, a, std.mem.trimEnd(u8, bytes, "\x00"), .{ .ignore_unknown_fields = false }) catch |err|
        return if (err == error.OutOfMemory) err else error.InvalidHostTiming;
    defer parsed.deinit();
    if (!std.mem.eql(u8, bytes, &try parsed.value.encode())) return error.InvalidHostTiming;
    return parsed.value;
}

pub const Records = struct {
    values: [parent_slots]Record = undefined,
    count: usize = 0,

    pub fn push(self: *Records, record: Record) !void {
        if (self.count == parent_slots) return error.HostTimingOverflow;
        try record.validate();
        if (record.scope != .parent or record.sequence != self.count) return error.InvalidHostTiming;
        if (self.count == 0) {
            if (record.stage != .call_enter) return error.InvalidHostTiming;
        } else {
            const previous = self.values[self.count - 1];
            if (previous.stage == .call_success or previous.stage == .call_error) return error.InvalidHostTiming;
            if (record.stage != .call_error) {
                const expected: Stage = switch (previous.stage) {
                    .call_enter => .request_encoded,
                    .request_encoded => if (record.stage == .state_ready) .state_ready else .reservation_ready,
                    .reservation_ready => .state_ready,
                    .state_ready => .operation_ready,
                    .operation_ready => .job_ready,
                    .job_ready => .process_call,
                    .process_call => .process_return,
                    .process_return => .call_success,
                    else => return error.InvalidHostTiming,
                };
                if (record.stage != expected) return error.InvalidHostTiming;
            }
            if (record.sample.monotonic_ns < previous.sample.monotonic_ns or
                record.sample.process_cpu_ns < previous.sample.process_cpu_ns or
                record.sample.backend != previous.sample.backend or record.sample.arch != previous.sample.arch or
                record.sample.optimize != previous.sample.optimize or record.sample.aarch64_sha2 != previous.sample.aarch64_sha2 or
                record.sample.x86_sha != previous.sample.x86_sha or record.sample.x86_avx2 != previous.sample.x86_avx2)
                return error.InvalidHostTiming;
        }
        self.values[self.count] = record;
        self.count += 1;
    }
};

pub const Summary = struct {
    schema: enum { synthetic_host_timing_summary_v1 } = .synthetic_host_timing_summary_v1,
    authority: enum { none } = .none,
    fixture: Fixture,
    parent_records: usize,
    parent_fault: ?Fault,
    cleanup: Cleanup,
    child: ChildStatus,
    deadline_ns: u64,
    fixture_bytes: ?u64,
};

threadlocal var active: ?*Parent = null;

pub const Parent = struct {
    fixture: Fixture,
    fixture_bytes: ?u64,
    pid: linux.pid_t,
    records: Records = .{},
    fault: ?Fault = null,
    cleanup: Cleanup = .not_called,
    deadline_ns: u64 = 0,

    pub fn init(fixture: Fixture, fixture_bytes: ?u64) Parent {
        return .{ .fixture = fixture, .fixture_bytes = fixture_bytes, .pid = linux.getpid() };
    }

    pub fn start(self: *Parent) void {
        if (active != null or self.records.count != 0) {
            self.fault = .reused;
            return;
        }
        active = self;
    }

    pub fn stop(self: *Parent) void {
        if (active == self) active = null;
    }

    pub fn mark(self: *Parent, stage: Stage, cleanup_complete: ?bool) void {
        if (linux.getpid() != self.pid) {
            self.fault = .process_changed;
            return;
        }
        // Cleanup knowledge must survive clock/format faults. A pre-call
        // observation never means spawn succeeded.
        if (stage == .process_call) self.cleanup = .unconfirmed;
        if (stage == .process_return) self.cleanup = if (cleanup_complete == true) .complete else .incomplete;
        if (self.fault != null) return;
        const sample = measurement.capture() catch {
            self.fault = .clock_failed;
            return;
        };
        self.records.push(.{
            .scope = .parent,
            .stage = stage,
            .sequence = @intCast(self.records.count),
            .cleanup_complete = cleanup_complete,
            .sample = sample,
        }) catch |err| {
            self.fault = if (err == error.HostTimingOverflow) .overflow else .invalid;
        };
    }

    pub fn collect(self: *Parent, a: std.mem.Allocator, io: std.Io, operation_path: ?[]const u8) Report {
        var report: Report = .{
            .summary = .{
                .fixture = self.fixture,
                .parent_records = self.records.count,
                .parent_fault = self.fault,
                .cleanup = self.cleanup,
                .child = .not_called,
                .deadline_ns = self.deadline_ns,
                .fixture_bytes = self.fixture_bytes,
            },
            .parent = self.records,
        };
        if (self.cleanup == .not_called) return report;
        if (self.cleanup != .complete) {
            report.summary.child = .cleanup_unconfirmed;
            return report;
        }
        const path = operation_path orelse {
            report.summary.child = .missing;
            return report;
        };
        report.child = readChild(a, io, path) catch |err| {
            report.summary.child = switch (err) {
                error.FileNotFound => .missing,
                error.HostTimingOverflow => .overflow,
                error.InvalidHostTiming => .invalid,
                else => .io_failed,
            };
            return report;
        };
        report.summary.child = .entry;
        return report;
    }

    // Called by a fixture defer, after the unchanged assertions on either
    // success or failure, but before its operation directory can be removed.
    pub fn retain(self: *Parent, a: std.mem.Allocator, io: std.Io, root_path: []const u8, operation_path: ?[]const u8) void {
        self.stop();
        const report = self.collect(a, io, operation_path);
        report.emit(io);
        report.write(io, root_path) catch {
            std.debug.print("Host timing retention fault: io_failed\n", .{});
        };
    }
};

pub fn begin(deadline_ns: u64) void {
    const parent = active orelse return;
    parent.deadline_ns = deadline_ns;
    parent.mark(.call_enter, null);
}

pub fn mark(stage: Stage) void {
    if (active) |parent| parent.mark(stage, null);
}

pub fn returned(cleanup_complete: bool) void {
    if (active) |parent| parent.mark(.process_return, cleanup_complete);
}

fn readChild(a: std.mem.Allocator, io: std.Io, path: []const u8) !Record {
    const directory = try core.private_files.Directory.open(io, path);
    defer directory.close(io);
    const file = try directory.openFile(io, child_name);
    defer file.close(io);
    const before = try core.private_files.snapshot(file);
    if (before.size > slot_bytes) return error.HostTimingOverflow;
    if (before.size != slot_bytes) return error.InvalidHostTiming;
    var bytes: [slot_bytes + 1]u8 = undefined;
    const count = try file.readPositionalAll(io, &bytes, 0);
    if (count != slot_bytes or !core.private_files.sameSnapshot(before, try core.private_files.snapshot(file)))
        return error.InvalidHostTiming;
    const record = try decodeRecord(a, bytes[0..count]);
    if (record.scope != .child) return error.InvalidHostTiming;
    return record;
}

pub const Child = struct {
    record: ?Record,

    pub fn capture() Child {
        const sample = measurement.capture() catch return .{ .record = null };
        return .{ .record = .{ .scope = .child, .stage = .child_entry, .sequence = 0, .sample = sample } };
    }

    pub fn write(self: Child, io: std.Io) void {
        self.writeChecked(io) catch {
            std.debug.print("Host timing child fault: unavailable\n", .{});
        };
    }

    fn writeChecked(self: Child, io: std.Io) !void {
        const record = self.record orelse return error.HostTimingClockUnavailable;
        const directory = try core.private_files.Directory.openWorkerCwd(io);
        defer directory.close(io);
        const file = try directory.dir.createFile(io, child_name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writeStreamingAll(io, &try record.encode());
    }
};

pub const Report = struct {
    summary: Summary,
    parent: Records,
    child: ?Record = null,

    pub fn encode(self: Report, buffer: *[max_bytes]u8) ![]const u8 {
        if (self.parent.count > parent_slots or self.summary.parent_records != self.parent.count) return error.InvalidHostTiming;
        var out: std.Io.Writer = .fixed(buffer);
        for (self.parent.values[0..self.parent.count]) |record| try line(&out, record);
        if (self.child) |record| try line(&out, record);
        try line(&out, self.summary);
        return out.buffered();
    }

    fn line(out: *std.Io.Writer, value: anytype) !void {
        const slot = try encodeSlot(value);
        try out.writeAll(std.mem.trimEnd(u8, &slot, "\x00"));
    }

    pub fn emit(self: Report, io: std.Io) void {
        var buffer: [max_bytes]u8 = undefined;
        const bytes = self.encode(&buffer) catch {
            std.debug.print("Host timing retention fault: invalid\n", .{});
            return;
        };
        std.Io.File.stderr().writeStreamingAll(io, bytes) catch {
            std.debug.print("Host timing stderr unavailable\n", .{});
        };
    }

    pub fn write(self: Report, io: std.Io, root_path: []const u8) !void {
        const root = try core.private_files.Directory.open(io, root_path);
        defer root.close(io);
        var name: [96]u8 = undefined;
        const path = try std.fmt.bufPrint(&name, "synthetic-host-timing-{s}-v1.jsonl", .{@tagName(self.summary.fixture)});
        var buffer: [max_bytes]u8 = undefined;
        const bytes = try self.encode(&buffer);
        const file = try root.dir.createFile(io, path, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
    }
};
