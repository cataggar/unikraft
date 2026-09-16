//! Synthetic final-entry observations; never a namespace status or approval.
const std = @import("std");
const builtin = @import("builtin");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const outer = @import("namespace_observations.zig");
const measurement = @import("synthetic_measurement");
const linux = std.os.linux;

comptime {
    if ((!builtin.is_test and !@hasDecl(@import("root"), "namespace_fixture_observer")) or !builtin.single_threaded)
        @compileError("Internal observations require the dedicated single-threaded fixture root");
}

pub const slots = 96;
pub const record_bytes = 512;
pub const log_bytes = slots * record_bytes + 1024;
pub const Context = enum { isolation, runtime_0, runtime_1, runtime_2 };
pub const Phase = enum {
    isolation_begin,
    inventory_begin,
    inventory_end,
    loader_begin,
    loader_end,
    executable_record_begin,
    executable_record_end,
    executable_read_begin,
    executable_read_end,
    executable_hash_end,
    executable_elf_end,
    libraries_begin,
    libraries_end,
    origin_begin,
    origin_end,
    validation_end,
    isolation_end,
    mounts_begin,
    mounts_end,
    runtime_begin,
    runtime_mount_begin,
    runtime_mount_end,
    mounts_finalize_begin,
    mounts_finalize_end,
    namespace_setup_begin,
    returned_error,
};
pub const Fault = enum { invalid_sequence, record_unavailable, process_changed, reuse };
pub const fault_name = "internal-entry-fault";

pub fn fileName(index: usize, buffer: *[32]u8) ![]const u8 {
    if (index >= slots) return error.InternalObservationLimit;
    return std.fmt.bufPrint(buffer, "internal-entry-{d:0>2}", .{index});
}

pub const Record = struct {
    schema: enum { namespace_internal_v1 } = .namespace_internal_v1,
    authority: enum { none } = .none,
    fixture: outer.Fixture,
    sequence: u8,
    context: Context,
    phase: Phase,
    clock_scope: enum { outer_helper } = .outer_helper,
    self_bytes: u64,
    sample: measurement.Sample,

    pub fn encode(self: Record, a: std.mem.Allocator) ![record_bytes]u8 {
        if (self.sequence >= slots or self.self_bytes == 0) return error.InvalidInternalObservation;
        const json = try c.canonical(a, self);
        defer a.free(json);
        if (json.len > record_bytes) return error.InternalObservationLimit;
        var bytes = [_]u8{0} ** record_bytes;
        @memcpy(bytes[0..json.len], json);
        return bytes;
    }
};

pub const Order = struct {
    previous: ?Phase = null,
    context: Context = .isolation,
    runtime_count: usize = 0,
    terminal: bool = false,

    pub fn advance(self: *Order, context: Context, phase: Phase) !void {
        if (self.terminal) return error.InvalidInternalSequence;
        if (phase == .returned_error) {
            if (self.previous == null or context != self.context) return error.InvalidInternalSequence;
            self.previous = phase;
            self.terminal = true;
            return;
        }
        if (phase == .runtime_begin) {
            if (self.previous != .mounts_end and self.previous != .runtime_mount_end)
                return error.InvalidInternalSequence;
            if (self.runtime_count >= 3 or @intFromEnum(context) != self.runtime_count + 1)
                return error.InvalidInternalSequence;
            self.runtime_count += 1;
            self.context = context;
        } else {
            if (context != self.context) return error.InvalidInternalSequence;
            const expected: Phase = if (self.previous) |previous| switch (previous) {
                .isolation_begin, .runtime_begin => .inventory_begin,
                .inventory_begin => .inventory_end,
                .inventory_end => .loader_begin,
                .loader_begin => .loader_end,
                .loader_end => .executable_record_begin,
                .executable_record_begin => .executable_record_end,
                .executable_record_end => .executable_read_begin,
                .executable_read_begin => .executable_read_end,
                .executable_read_end => .executable_hash_end,
                .executable_hash_end => .executable_elf_end,
                .executable_elf_end => .libraries_begin,
                .libraries_begin => .libraries_end,
                .libraries_end => .origin_begin,
                .origin_begin => .origin_end,
                .origin_end => .validation_end,
                .validation_end => if (context == .isolation) .isolation_end else .runtime_mount_begin,
                .isolation_end => .mounts_begin,
                .mounts_begin => .mounts_end,
                .runtime_mount_begin => .runtime_mount_end,
                .runtime_mount_end => .mounts_finalize_begin,
                .mounts_finalize_begin => .mounts_finalize_end,
                .mounts_finalize_end => .namespace_setup_begin,
                else => return error.InvalidInternalSequence,
            } else .isolation_begin;
            if (phase != expected) return error.InvalidInternalSequence;
        }
        self.previous = phase;
        self.terminal = phase == .namespace_setup_begin;
    }
};

const Capture = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: std.Io.Dir,
    fixture: outer.Fixture,
    pid: linux.pid_t,
    order: Order = .{},
    sequence: usize = 0,
};
var capture: ?Capture = null;
var last_fault: ?Fault = null;

// Borrow only the fixture's existing scratch descriptor. Every new file
// descriptor is closed inside its write, before validation resumes.
pub fn start(a: std.mem.Allocator, io: std.Io, directory: std.Io.Dir, fixture: ?outer.Fixture) void {
    if (capture != null) {
        fail(.reuse);
        return;
    }
    last_fault = null;
    if (fixture) |selected| capture = .{
        .allocator = a,
        .io = io,
        .directory = directory,
        .fixture = selected,
        .pid = linux.getpid(),
    };
}

pub fn stop() void {
    capture = null;
}

pub fn fault() ?Fault {
    return last_fault;
}

fn put(value: Capture, name: []const u8, bytes: []const u8) !void {
    const file = try value.directory.createFile(value.io, name, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(value.io);
    try file.writeStreamingAll(value.io, bytes);
}

fn fail(reason: Fault) void {
    last_fault = reason;
    if (capture) |value| {
        // Diagnostic failure never replaces or preempts an integrity error.
        // Retention also reports missing/invalid records if this write fails.
        put(value, fault_name, @tagName(reason)) catch {
            std.debug.print("Namespace internal observation fault unavailable\n", .{});
        };
    }
    capture = null;
    std.debug.print("Namespace internal observation fault: {s}\n", .{@tagName(reason)});
}

pub fn mark(phase: Phase) void {
    const value = &(capture orelse return);
    if (linux.getpid() != value.pid) {
        fail(.process_changed);
        return;
    }
    var next = value.order;
    next.advance(next.context, phase) catch {
        fail(.invalid_sequence);
        return;
    };
    write(next, phase);
}

pub fn runtimeBegin() void {
    const value = capture orelse return;
    const index = value.order.runtime_count;
    if (index >= 3) {
        fail(.invalid_sequence);
        return;
    }
    var next = value.order;
    next.advance(@enumFromInt(index + 1), .runtime_begin) catch {
        fail(.invalid_sequence);
        return;
    };
    write(next, .runtime_begin);
}

fn write(next: Order, phase: Phase) void {
    const value = capture orelse return;
    if (linux.getpid() != value.pid) {
        fail(.process_changed);
        return;
    }
    observe(value, next, phase) catch {
        fail(.record_unavailable);
        return;
    };
    capture.?.sequence += 1;
    capture.?.order = next;
    // Stop before userNamespace and every fork. There are no post-fork CPU
    // samples, inherited observer descriptors, or synthetic completion claims.
    if (next.terminal) capture = null;
}

fn observe(value: Capture, next: Order, phase: Phase) !void {
    var name: [32]u8 = undefined;
    const path = try fileName(value.sequence, &name);
    const record: Record = .{
        .fixture = value.fixture,
        .sequence = @intCast(value.sequence),
        .context = next.context,
        .phase = phase,
        .self_bytes = try measurement.selfExecutableBytes(value.io),
        .sample = try measurement.capture(),
    };
    try put(value, path, &try record.encode(value.allocator));
}

pub const Tail = enum { prefix, partial, invalid, oversized, unavailable, gap };
pub const Collection = struct {
    schema: enum { namespace_internal_collection_v1 } = .namespace_internal_collection_v1,
    authority: enum { none } = .none,
    fixture: outer.Fixture,
    tail: Tail = .prefix,
    observer_fault: ?Fault = null,
    fault_unavailable: bool = false,
    records: [slots]Record = undefined,
    count: usize = 0,

    pub fn log(self: *const Collection, a: std.mem.Allocator, buffer: *[log_bytes]u8) ![]const u8 {
        const json = try c.canonical(a, .{
            .schema = self.schema,
            .authority = self.authority,
            .fixture = self.fixture,
            .tail = self.tail,
            .observer_fault = self.observer_fault,
            .fault_unavailable = self.fault_unavailable,
            .records = self.records[0..self.count],
        });
        defer a.free(json);
        return std.fmt.bufPrint(buffer, "Namespace internal observations: {s}", .{json});
    }
};

pub fn decode(a: std.mem.Allocator, bytes: []const u8) !Record {
    if (bytes.len != record_bytes) return error.InvalidInternalObservation;
    const parsed = try c.parse(Record, a, std.mem.trimEnd(u8, bytes, "\x00"));
    defer parsed.deinit();
    if (!std.mem.eql(u8, bytes, &try parsed.value.encode(a))) return error.InvalidInternalObservation;
    return parsed.value;
}

pub fn read(a: std.mem.Allocator, io: std.Io, directory: fs.Directory, fixture: outer.Fixture) !Collection {
    var result: Collection = .{ .fixture = fixture };
    var order: Order = .{};
    var missing = false;
    for (0..slots) |index| {
        var name: [32]u8 = undefined;
        const bytes = directory.read(a, io, try fileName(index, &name), record_bytes, .private) catch |err| {
            if (err == error.FileNotFound) {
                missing = true;
                continue;
            }
            result.tail = if (err == error.FileTooLarge) .oversized else .unavailable;
            break;
        };
        defer a.free(bytes);
        if (missing) {
            result.tail = .gap;
            break;
        }
        if (bytes.len < record_bytes) {
            result.tail = .partial;
            break;
        }
        const record = decode(a, bytes) catch {
            result.tail = .invalid;
            break;
        };
        if (record.fixture != fixture or record.sequence != index or
            (index != 0 and (record.self_bytes != result.records[0].self_bytes or
                record.sample.monotonic_ns < result.records[index - 1].sample.monotonic_ns or
                record.sample.process_cpu_ns < result.records[index - 1].sample.process_cpu_ns)))
        {
            result.tail = .invalid;
            break;
        }
        order.advance(record.context, record.phase) catch {
            result.tail = .invalid;
            break;
        };
        result.records[result.count] = record;
        result.count += 1;
    }
    const failure = directory.read(a, io, fault_name, 64, .private) catch |err| failure: {
        if (err != error.FileNotFound) result.fault_unavailable = true;
        break :failure null;
    };
    if (failure) |bytes| {
        defer a.free(bytes);
        result.observer_fault = std.meta.stringToEnum(Fault, bytes);
        if (result.observer_fault == null) result.fault_unavailable = true;
    }
    return result;
}

test "namespace observations internal writer activation disarming and process guard are bounded" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const path = try temporary.dir.realPathFileAlloc(io, ".", a);
    defer a.free(path);
    const directory: fs.Directory = .{ .dir = temporary.dir, .path = path };
    defer stop();
    start(a, io, temporary.dir, null);
    mark(.isolation_begin);
    try std.testing.expectEqual(@as(usize, 0), (try read(a, io, directory, .timeout)).count);
    start(a, io, temporary.dir, .timeout);
    mark(.isolation_begin);
    inline for (@typeInfo(Phase).@"enum".fields[@intFromEnum(Phase.inventory_begin) .. @intFromEnum(Phase.validation_end) + 1]) |field|
        mark(@enumFromInt(field.value));
    mark(.isolation_end);
    mark(.mounts_begin);
    mark(.mounts_end);
    runtimeBegin();
    inline for (@typeInfo(Phase).@"enum".fields[@intFromEnum(Phase.inventory_begin) .. @intFromEnum(Phase.validation_end) + 1]) |field|
        mark(@enumFromInt(field.value));
    mark(.runtime_mount_begin);
    mark(.runtime_mount_end);
    mark(.mounts_finalize_begin);
    mark(.mounts_finalize_end);
    mark(.namespace_setup_begin);
    try std.testing.expect(capture == null and fault() == null);
    const complete_prefix = try read(a, io, directory, .timeout);
    try std.testing.expectEqual(Phase.namespace_setup_begin, complete_prefix.records[complete_prefix.count - 1].phase);
    mark(.returned_error);
    runtimeBegin();
    try std.testing.expectEqual(complete_prefix.count, (try read(a, io, directory, .timeout)).count);
    start(a, io, temporary.dir, .timeout);
    capture.?.pid += 1;
    mark(.isolation_begin);
    try std.testing.expect(capture == null);
    try std.testing.expectEqual(Fault.process_changed, fault().?);
    const refused = try read(a, io, directory, .timeout);
    try std.testing.expectEqual(complete_prefix.count, refused.count);
    try std.testing.expectEqual(Fault.process_changed, refused.observer_fault.?);
}
