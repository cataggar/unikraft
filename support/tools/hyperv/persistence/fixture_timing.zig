//! Bounded synthetic observations, never admission, effect, or reaping evidence.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const measurement = @import("synthetic_measurement");
const worker = @import("worker.zig");
const m = @import("model.zig");
const f = @import("fixture_support.zig");
const local = @import("local.zig");
const linux = std.os.linux;

pub const Stage = worker.Observer.Stage;
pub const file_name = "synthetic-persistence-timing-v1";
pub const slot_size = 1024;
pub const parent_slots = @intFromEnum(Stage.child_entry);
pub const child_slots = @typeInfo(Stage).@"enum".fields.len - parent_slots;
pub const max_bytes = (1 + child_slots) * slot_size;
pub const max_jobs = 8 * m.step_count + 1;
pub const log_prefix = "persistence_timing ";
pub const report_bytes = (parent_slots + child_slots) * (slot_size + log_prefix.len) + slot_size;
pub const collector_log_bytes = max_jobs * report_bytes + slot_size;
pub const Status = enum { ok, empty, prefix, partial_slot, complete, invalid, overflow, clock_failed, io_failed, missing, not_started, cleanup_unconfirmed };

pub const Header = struct {
    schema_version: u8 = 1,
    scope: enum { synthetic_timing_only } = .synthetic_timing_only,
    authority: enum { none } = .none,
    identity: worker.Observer.Identity,
    worker_bytes: u64,
    mode: f.Mode,
    sequence: u16,

    fn validate(self: Header) !void {
        if (self.schema_version != 1 or self.worker_bytes == 0 or self.worker_bytes > 32 * 1024 * 1024 or
            self.sequence == 0 or self.sequence > max_jobs or self.identity.deadline_ns == 0 or
            self.identity.parent_pid == 0 or self.identity.operation_ms == 0 or self.identity.operation_ms > 600000)
            return error.InvalidDiagnostic;
        try local.hex(&self.identity.nonce, true);
        try local.hex(&self.identity.input_sha256, true);
    }

    pub fn encode(self: Header) ![slot_size]u8 {
        try self.validate();
        return encodeSlot(self);
    }
};

pub const Record = struct {
    schema_version: u8 = 1,
    scope: enum { synthetic_timing_only } = .synthetic_timing_only,
    authority: enum { none } = .none,
    stage: Stage,
    mode: f.Mode,
    sequence: u16,
    step: m.Step,
    worker_bytes: u64,
    deadline_ns: u64,
    operation_ms: u32,
    cleanup_complete: ?bool = null,
    sample: measurement.Sample,

    pub fn observe(header: Header, stage: Stage, cleanup_complete: ?bool) !Record {
        return sampled(header, stage, cleanup_complete, try measurement.capture());
    }

    fn sampled(header: Header, stage: Stage, cleanup_complete: ?bool, sample: measurement.Sample) Record {
        return .{
            .stage = stage,
            .mode = header.mode,
            .sequence = header.sequence,
            .step = header.identity.step,
            .worker_bytes = header.worker_bytes,
            .deadline_ns = header.identity.deadline_ns,
            .operation_ms = header.identity.operation_ms,
            .cleanup_complete = cleanup_complete,
            .sample = sample,
        };
    }

    fn validate(self: Record) !void {
        if (self.schema_version != 1 or self.worker_bytes == 0 or self.worker_bytes > 32 * 1024 * 1024 or
            self.sequence == 0 or self.sequence > max_jobs or self.deadline_ns == 0 or
            self.operation_ms == 0 or self.operation_ms > 600000 or
            (self.stage == .process_return) != (self.cleanup_complete != null)) return error.InvalidDiagnostic;
    }

    pub fn encode(self: Record) ![slot_size]u8 {
        try self.validate();
        return encodeSlot(self);
    }
};

fn encodeSlot(value: anytype) ![slot_size]u8 {
    var slot = [_]u8{0} ** slot_size;
    var out: std.Io.Writer = .fixed(&slot);
    try std.json.Stringify.value(value, .{}, &out);
    try out.writeByte('\n');
    return slot;
}

fn parseSlot(comptime T: type, allocator: std.mem.Allocator, slot: []const u8) !T {
    if (slot.len != slot_size) return error.InvalidDiagnostic;
    const parsed = try std.json.parseFromSlice(T, allocator, std.mem.trimEnd(u8, slot, "\x00"), .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    const canonical = try encodeSlot(parsed.value);
    if (!std.mem.eql(u8, &canonical, slot)) return error.InvalidDiagnostic;
    return parsed.value;
}

pub const Records = struct {
    values: [@max(parent_slots, child_slots)]Record = undefined,
    count: usize = 0,
    child: bool = false,
    status: Status = .ok,

    pub fn push(self: *Records, record: Record) !void {
        if (self.count == (if (self.child) child_slots else parent_slots)) return error.DiagnosticOverflow;
        try record.validate();
        const stage = @intFromEnum(record.stage);
        if ((stage >= parent_slots) != self.child or
            (self.count == 0 and record.stage != (if (self.child) Stage.child_entry else .parent_begin)))
            return error.InvalidDiagnostic;
        if (self.count != 0) {
            const previous = self.values[self.count - 1];
            if (stage <= @intFromEnum(previous.stage) or record.sequence != previous.sequence or record.mode != previous.mode or
                record.step != previous.step or record.worker_bytes != previous.worker_bytes or record.deadline_ns != previous.deadline_ns or
                record.operation_ms != previous.operation_ms or record.sample.monotonic_ns < previous.sample.monotonic_ns or
                record.sample.process_cpu_ns < previous.sample.process_cpu_ns or
                record.sample.backend != previous.sample.backend or record.sample.arch != previous.sample.arch or
                record.sample.optimize != previous.sample.optimize or record.sample.aarch64_sha2 != previous.sample.aarch64_sha2 or
                record.sample.x86_sha != previous.sample.x86_sha or record.sample.x86_avx2 != previous.sample.x86_avx2)
                return error.InvalidDiagnostic;
        }
        self.values[self.count] = record;
        self.count += 1;
    }

    fn mark(self: *Records, header: Header, event: worker.Observer.Event) void {
        if (self.status != .ok) return;
        const record = Record.observe(header, event.stage, event.cleanup_complete) catch {
            self.status = .clock_failed;
            return;
        };
        self.push(record) catch |err| {
            self.status = if (err == error.DiagnosticOverflow) .overflow else .invalid;
        };
    }
};

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8, expected: Header) !Records {
    try expected.validate();
    if (bytes.len > max_bytes) return error.DiagnosticOverflow;
    if (bytes.len < slot_size) return error.InvalidDiagnostic;
    const header = parseSlot(Header, allocator, bytes[0..slot_size]) catch return error.InvalidDiagnostic;
    header.validate() catch return error.InvalidDiagnostic;
    if (!std.meta.eql(header, expected)) return error.InvalidDiagnostic;
    var records: Records = .{ .child = true };
    records.status = if (bytes.len == slot_size) .empty else if (bytes.len % slot_size != 0) .partial_slot else .prefix;
    for (1..bytes.len / slot_size) |index| {
        const record = parseSlot(Record, allocator, bytes[index * slot_size ..][0..slot_size]) catch {
            records.status = .invalid;
            break;
        };
        if (record.mode != header.mode or record.sequence != header.sequence or record.step != header.identity.step or
            record.worker_bytes != header.worker_bytes or record.deadline_ns != header.identity.deadline_ns or
            record.operation_ms != header.identity.operation_ms)
        {
            records.status = .invalid;
            break;
        }
        records.push(record) catch {
            records.status = .invalid;
            break;
        };
    }
    if (records.status != .invalid and records.count != 0 and records.values[records.count - 1].stage == .child_end)
        records.status = if (bytes.len % slot_size == 0) .complete else .invalid;
    return records;
}

pub const Sidecar = struct {
    file: std.Io.File,
    header: Header,

    pub fn create(io: std.Io, directory: core.private_files.Directory, header: Header) !Sidecar {
        try header.validate();
        const file = try directory.dir.createFile(io, file_name, .{ .exclusive = true, .read = true, .permissions = .fromMode(0o600) });
        errdefer file.close(io);
        try file.writePositionalAll(io, &try header.encode(), 0);
        return .{ .file = file, .header = header };
    }

    // Retain the parent's descriptor, compare the pathname's current identity,
    // and only then read a bounded, stable snapshot after actual process cleanup.
    pub fn read(self: Sidecar, allocator: std.mem.Allocator, io: std.Io, directory: core.private_files.Directory, cleanup_complete: bool) !Records {
        if (!cleanup_complete) return error.DiagnosticCleanupUnconfirmed;
        const named = try directory.openFile(io, file_name);
        defer named.close(io);
        const before = try core.private_files.snapshot(self.file);
        if (!core.private_files.sameSnapshot(before, try core.private_files.snapshot(named))) return error.InvalidDiagnostic;
        if (before.size > max_bytes) return error.DiagnosticOverflow;
        var bytes: [max_bytes + 1]u8 = undefined;
        const count = try self.file.readPositionalAll(io, &bytes, 0);
        if (count != before.size or !core.private_files.sameSnapshot(before, try core.private_files.snapshot(self.file)))
            return error.InvalidDiagnostic;
        return decode(allocator, bytes[0..count], self.header);
    }

    pub fn close(self: Sidecar, io: std.Io) void {
        self.file.close(io);
    }
};

pub const Child = struct {
    io: std.Io,
    sidecar: ?Sidecar = null,
    records: Records = .{ .child = true },

    pub fn start(io: std.Io) Child {
        if (!builtin.is_test and !(@hasDecl(@import("root"), "persistence_timing_fixture") and @import("root").persistence_timing_fixture))
            @compileError("Timing is restricted to synthetic fixture roots");
        var self: Child = .{ .io = io };
        // Capture entry before opening/parsing the private diagnostic sidecar.
        const sample = measurement.capture() catch {
            self.records.status = .clock_failed;
            return self;
        };
        self.sidecar = open(io) catch {
            self.records.status = .io_failed;
            return self;
        };
        self.append(Record.sampled(self.sidecar.?.header, .child_entry, null, sample));
        return self;
    }

    fn open(io: std.Io) !Sidecar {
        const directory = try core.private_files.Directory.openWorkerCwd(io);
        defer directory.close(io);
        const checked = try directory.openFile(io, file_name);
        defer checked.close(io);
        const before = try core.private_files.snapshot(checked);
        if (before.size != slot_size) return error.InvalidDiagnostic;
        var bytes: [slot_size]u8 = undefined;
        if (try checked.readPositionalAll(io, &bytes, 0) != slot_size) return error.InvalidDiagnostic;
        const header = try parseSlot(Header, std.heap.page_allocator, &bytes);
        try header.validate();
        if (header.identity.parent_pid != linux.getppid()) return error.InvalidDiagnostic;
        const fd = linux.openat(directory.dir.handle, file_name, .{ .ACCMODE = .WRONLY, .CLOEXEC = true, .NOFOLLOW = true, .NONBLOCK = true }, 0);
        if (linux.errno(fd) != .SUCCESS) return error.DiagnosticOpenFailed;
        const file: std.Io.File = .{ .handle = @intCast(fd), .flags = .{ .nonblocking = true } };
        errdefer file.close(io);
        if (!core.private_files.sameSnapshot(before, try core.private_files.snapshot(file))) return error.InvalidDiagnostic;
        return .{ .file = file, .header = header };
    }

    pub fn observer(self: *Child) worker.Observer {
        return .{ .context = self, .call = receive };
    }

    fn receive(context: *anyopaque, event: worker.Observer.Event) void {
        const self: *Child = @ptrCast(@alignCast(context));
        if (self.records.status != .ok) return;
        const sidecar = self.sidecar orelse {
            self.records.status = .io_failed;
            return;
        };
        if (event.stage == .child_job_validated and
            (event.identity == null or !std.meta.eql(event.identity.?, sidecar.header.identity)))
        {
            self.records.status = .invalid;
            return;
        }
        const record = Record.observe(sidecar.header, event.stage, event.cleanup_complete) catch {
            self.records.status = .clock_failed;
            return;
        };
        self.append(record);
    }

    fn append(self: *Child, record: Record) void {
        self.records.push(record) catch |err| {
            self.records.status = if (err == error.DiagnosticOverflow) .overflow else .invalid;
            return;
        };
        const slot = record.encode() catch {
            self.records.status = .invalid;
            return;
        };
        // One positional slot write, no fsync, stdout, inherited FD, or ack use.
        self.sidecar.?.file.writePositionalAll(self.io, &slot, self.records.count * slot_size) catch {
            self.records.status = .io_failed;
        };
    }

    pub fn close(self: *Child) void {
        if (self.sidecar) |sidecar| sidecar.close(self.io);
    }
};

pub const Parent = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    mode: f.Mode,
    enabled: bool = false,
    emit_log: bool = true,
    sequence: u16 = 0,
    header: ?Header = null,
    records: Records = .{},
    child_records: Records = .{ .child = true, .status = .not_started },
    sidecar: ?Sidecar = null,
    directory: ?core.private_files.Directory = null,
    overflow_reported: bool = false,

    pub fn observer(self: *Parent) ?worker.Observer {
        if (!builtin.is_test) @compileError("Parent timing is fixture-only");
        return if (self.enabled) .{ .context = self, .call = receive } else null;
    }

    fn receive(context: *anyopaque, event: worker.Observer.Event) void {
        const self: *Parent = @ptrCast(@alignCast(context));
        if (event.stage == .parent_begin) {
            if (self.sequence == max_jobs) {
                if (!self.overflow_reported and self.emit_log)
                    std.debug.print("persistence_timing scope=synthetic_timing_only authority=none status=overflow\n", .{});
                self.overflow_reported = true;
                return;
            }
            self.sequence += 1;
            self.records = .{};
            self.child_records = .{ .child = true, .status = .not_started };
            self.header = if (event.identity) |identity| .{ .identity = identity, .worker_bytes = event.worker_bytes, .mode = self.mode, .sequence = self.sequence } else null;
        }
        if (self.overflow_reported) return;
        const header = self.header orelse {
            self.records.status = .invalid;
            return;
        };
        self.records.mark(header, event);
        switch (event.stage) {
            .provision_begin => {
                self.directory = event.directory;
                if (self.directory) |directory| {
                    self.sidecar = Sidecar.create(self.io, directory, header) catch {
                        self.child_records.status = .io_failed;
                        return;
                    };
                    self.child_records.status = .cleanup_unconfirmed;
                } else self.child_records.status = .invalid;
            },
            .process_return => {
                if (event.cleanup_complete == true) {
                    if (self.sidecar) |sidecar| {
                        self.child_records = sidecar.read(self.allocator, self.io, self.directory.?, true) catch |err| {
                            self.child_records.status = switch (err) {
                                error.DiagnosticOverflow => .overflow,
                                error.InvalidDiagnostic => .invalid,
                                error.FileNotFound => .missing,
                                else => .io_failed,
                            };
                            return;
                        };
                    }
                } else self.child_records.status = .cleanup_unconfirmed;
            },
            .parent_end => {
                if (self.sidecar) |sidecar| sidecar.close(self.io);
                self.sidecar = null;
                self.directory = null;
                if (self.emit_log) self.report();
            },
            else => {},
        }
    }

    pub fn encodeReport(self: *const Parent, buffer: *[report_bytes]u8) ![]const u8 {
        if (self.records.count > parent_slots or self.child_records.count > child_slots)
            return error.DiagnosticOverflow;
        var out: std.Io.Writer = .fixed(buffer);
        for (self.records.values[0..self.records.count]) |record| try writeRecord(&out, record);
        for (self.child_records.values[0..self.child_records.count]) |record| try writeRecord(&out, record);
        try out.print("persistence_timing scope=synthetic_timing_only authority=none mode={s} sequence={d} parent_status={s} child_status={s} parent_records={d} child_records={d}\n", .{
            @tagName(self.mode), self.sequence, @tagName(self.records.status), @tagName(self.child_records.status), self.records.count, self.child_records.count,
        });
        return out.buffered();
    }

    fn report(self: *const Parent) void {
        var buffer: [report_bytes]u8 = undefined;
        const bytes = self.encodeReport(&buffer) catch |err| {
            std.debug.print("persistence_timing scope=synthetic_timing_only authority=none status={s}\n", .{
                if (err == error.DiagnosticOverflow or err == error.WriteFailed) @as([]const u8, "overflow") else "invalid",
            });
            return;
        };
        std.debug.print("{s}", .{bytes});
    }
};

fn writeRecord(out: *std.Io.Writer, record: Record) !void {
    const slot = try record.encode();
    try out.writeAll(log_prefix);
    try out.writeAll(std.mem.trimEnd(u8, &slot, "\x00"));
}

pub const Selection = struct {
    enabled: bool,
    before: ?measurement.Sample = null,

    pub fn begin(enabled: bool) Selection {
        var self: Selection = .{ .enabled = enabled };
        if (enabled) self.before = measurement.capture() catch {
            std.debug.print("persistence_timing scope=synthetic_timing_only authority=none stage=selection_begin status=clock_failed\n", .{});
            return self;
        };
        return self;
    }

    pub fn end(self: Selection, bytes: u64) void {
        if (!self.enabled) return;
        const after = measurement.capture() catch {
            std.debug.print("persistence_timing scope=synthetic_timing_only authority=none stage=selection_end status=clock_failed\n", .{});
            return;
        };
        for ([_]?measurement.Sample{ self.before, after }, 0..) |maybe, index| {
            if (maybe) |sample| {
                var buffer: [slot_size]u8 = undefined;
                var out: std.Io.Writer = .fixed(&buffer);
                std.json.Stringify.value(.{ .schema_version = @as(u8, 1), .scope = "synthetic_timing_only", .authority = "none", .stage = if (index == 0) @as([]const u8, "selection_begin") else "selection_end", .worker_bytes = bytes, .sample = sample }, .{}, &out) catch {
                    std.debug.print("persistence_timing scope=synthetic_timing_only authority=none stage=selection_end status=overflow\n", .{});
                    return;
                };
                std.debug.print("persistence_timing {s}\n", .{out.buffered()});
            }
        }
    }
};

pub fn recoverySnapshot(enabled: bool, stage: enum { recovery_initial, recovery_rewritten, recovery_validated }, state: m.State) void {
    if (!enabled) return;
    // Only the exact local validation preconditions, not bodies or effect proof.
    std.debug.print("persistence_timing scope=synthetic_timing_only authority=none stage={s} phase={s} os_pending={} os_grant_obligation={} os_access_done={} cleanup_os_access_done={} data_pending={} data_grant_obligation={} data_access_done={} cleanup_data_access_done={} data_upload_progress={s}\n", .{
        @tagName(stage),                                                                                                                            @tagName(state.phase),                                                                                                                          state.os_access_pending,
        state.records[@intFromEnum(m.Step.os_grant)].progress != .unissued and state.records[@intFromEnum(m.Step.os_grant)].effect != .not_started, state.isDone(.os_access_closed),                                                                                                                state.isDone(.cleanup_os_access),
        state.data_access_pending,                                                                                                                  state.records[@intFromEnum(m.Step.data_grant)].progress != .unissued and state.records[@intFromEnum(m.Step.data_grant)].effect != .not_started, state.isDone(.data_access_closed),
        state.isDone(.cleanup_data_access),                                                                                                         @tagName(state.records[@intFromEnum(m.Step.data_upload)].progress),
    });
}
