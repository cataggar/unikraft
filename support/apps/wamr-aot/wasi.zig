// SPDX-License-Identifier: BSD-3-Clause
//! Optional C bridge to the pinned allocation-free minimal WASI context.
//! A single fresh, bounded CoreMark invocation, not a benchmark producer.
const std = @import("std");
const runtime = @import("wamr-aot");
const wasi = runtime.benchmark.wasi;

const RealtimeCaps = extern struct {
    version: u32,
    source: u32,
    resolution_ns: u64,
    efi_accuracy_pptrillion: u32,
    reserved: u32,
    sample_span_ns: u64,
};

extern fn hyperv_clock_realtime(*RealtimeCaps, *u64) c_int;
const RealtimeRead = *const fn (*RealtimeCaps, *u64) callconv(.c) c_int;

const Output = extern struct {
    stdout_bytes: [4096]u8,
    stderr_bytes: [4096]u8,
    stdout_length: usize,
    stderr_length: usize,
    output_error: u32,
    pending_stdout: u32,
    pending_stderr: u32,
    unsupported_clock: u32,
    realtime_supported: u32,
    realtime_caps: RealtimeCaps,
};

comptime {
    std.debug.assert(@sizeOf(RealtimeCaps) == 32);
    std.debug.assert(@offsetOf(Output, "realtime_caps") == 8232);
}

const State = struct {
    context: wasi.Context,
    config: *const runtime.Config,
    output: *Output,
    realtime_read: RealtimeRead,
};

fn validRealtime(caps: RealtimeCaps, ns: u64) bool {
    return caps.version == 1 and caps.source == 1 and
        caps.reserved == 0 and caps.resolution_ns >= 100 and
        caps.resolution_ns != std.math.maxInt(u64) and
        caps.efi_accuracy_pptrillion != 0 and
        caps.efi_accuracy_pptrillion != std.math.maxInt(u32) and
        caps.sample_span_ns != std.math.maxInt(u64) and
        ns != 0 and ns != std.math.maxInt(u64);
}

fn bindClock(s: *State) void {
    s.output.realtime_supported = 0;
    s.output.realtime_caps = std.mem.zeroes(RealtimeCaps);
    var caps = std.mem.zeroes(RealtimeCaps);
    var ns: u64 = 0;
    if (s.realtime_read(&caps, &ns) == 0 and validRealtime(caps, ns)) {
        s.output.realtime_supported = 1;
        s.output.realtime_caps = caps;
    }
    s.context.clock = .{
        .userdata = s,
        .read = clock,
        .resolution_ns = .{ s.output.realtime_caps.resolution_ns, 100, 0, 0 },
    };
}

fn noteClockRequest(s: *State, id: u32) void {
    if (id >= 4 or s.context.clock.?.resolution_ns[id] == 0)
        s.output.unsupported_clock = 1;
}

fn write(raw: ?*anyopaque, fd: u32, bytes: []const u8) wasi.WriteResult {
    const s: *State = @ptrCast(@alignCast(raw.?));
    const buffer = if (fd == 1) &s.output.stdout_bytes else &s.output.stderr_bytes;
    const length = if (fd == 1) &s.output.stdout_length else &s.output.stderr_length;
    const count = @min(bytes.len, buffer.len - length.*);
    @memcpy(buffer[length.*..][0..count], bytes[0..count]);
    length.* += count;
    if (count != bytes.len) {
        s.output.output_error = @intFromEnum(wasi.Errno.nospc);
        return .{ .written = count, .errno = .nospc };
    }
    return .{ .written = count };
}

fn clock(raw: ?*anyopaque, id: wasi.ClockId, precision: u64) wasi.ClockResult {
    _ = precision;
    const s: *State = @ptrCast(@alignCast(raw.?));
    var ns: u64 = 0;
    if (id == .realtime) {
        if (s.output.realtime_supported == 0) return .{ .failure = .notsup };
        var caps = std.mem.zeroes(RealtimeCaps);
        if (s.realtime_read(&caps, &ns) != 0 or !validRealtime(caps, ns) or
            !std.meta.eql(caps, s.output.realtime_caps))
        {
            s.output.realtime_supported = 0;
            s.output.unsupported_clock = 1;
            return .{ .failure = .overflow };
        }
        return .{ .timestamp_ns = ns };
    }
    if (id != .monotonic) return .{ .failure = .notsup };
    if (s.config.monotonic_ns(s.config.context, &ns) != 0 or ns == std.math.maxInt(u64)) {
        s.output.unsupported_clock = 1;
        return .{ .failure = .overflow };
    }
    return .{ .timestamp_ns = ns };
}

fn Thunk(comptime index: usize) type {
    const spec = wasi.imports[index];
    return struct {
        fn call(raw: ?*anyopaque, host: *runtime.aot.HostContext, arguments: [*]const runtime.CValue, count: usize, results: [*]runtime.CValue, capacity: usize) callconv(.c) u32 {
            const s: *State = @ptrCast(@alignCast(raw.?));
            if (count != spec.params.len or capacity != spec.results.len) return 2;
            var bits: [spec.params.len]u64 = undefined;
            inline for (spec.params, 0..) |kind, i| {
                if (arguments[i].kind != kind) return 2;
                bits[i] = arguments[i].bits;
            }
            if (comptime std.mem.eql(u8, spec.name, "clock_time_get")) {
                noteClockRequest(s, @truncate(bits[0]));
            }
            const outcome = s.context.dispatch(host.memory(), @enumFromInt(index), &bits) catch return 2;
            switch (outcome) {
                .returned => |errno| {
                    if (comptime spec.results.len != 1) return 2;
                    results[0] = .{ .kind = 0x7f, .bits = @intFromEnum(errno) };
                },
                .exited => |code| host.terminate(code),
            }
            return 0;
        }
    };
}

export fn wamr_wasi_check(config: *const runtime.Config, bytes: [*]const u8, length: usize, output: *Output) runtime.Result {
    output.* = std.mem.zeroes(Output);
    var state: State = .{
        .context = wasi.Context.init(.{
            .args = &.{ "coremark", "0", "0", "0", "100", "0" },
            .environment = &.{},
            .output = null,
            .clock = null,
        }) catch unreachable,
        .config = config,
        .output = output,
        .realtime_read = hyperv_clock_realtime,
    };
    state.context.output = .{ .userdata = &state, .write = write };
    bindClock(&state);
    var imports: [wasi.imports.len]runtime.CImport = undefined;
    inline for (wasi.imports, 0..) |spec, i| {
        imports[i] = .{
            .module = spec.namespace.ptr,
            .module_len = spec.namespace.len,
            .name = spec.name.ptr,
            .name_len = spec.name.len,
            .params = spec.params.ptr,
            .param_count = spec.params.len,
            .results = spec.results.ptr,
            .result_count = spec.results.len,
            .context = &state,
            .callback = Thunk(i).call,
        };
    }
    var handle: ?*runtime.Handle = null;
    var result = runtime.wamr_aot_load(config, bytes, length, &imports, imports.len, &handle);
    if (handle) |instance| {
        defer runtime.wamr_aot_destroy(instance);
        if (result.kind == 0) result = runtime.wamr_aot_start(instance);
        if (result.kind == 0) result = runtime.wamr_aot_call(instance, "_start", 6, null, 0, null, 0);
    }
    if (state.context.pendingWriteError(1)) |errno| output.pending_stdout = @intFromEnum(errno);
    if (state.context.pendingWriteError(2)) |errno| output.pending_stderr = @intFromEnum(errno);
    return result;
}

// Hosted synthetic provider only. It is never linked into an EFI archive.
const TestClock = struct {
    var ns: u64 = 1709210096123456789;
    var status: c_int = 0;
    var caps: RealtimeCaps = undefined;

    fn reset() void {
        ns = 1709210096123456789;
        status = 0;
        caps = .{
            .version = 1,
            .source = 1,
            .resolution_ns = 1000000000,
            .efi_accuracy_pptrillion = 50000000,
            .reserved = 0,
            .sample_span_ns = 500,
        };
    }

    fn read(out: *RealtimeCaps, value: *u64) callconv(.c) c_int {
        if (status != 0) return status;
        out.* = caps;
        value.* = ns;
        return 0;
    }

    fn monotonic(_: ?*anyopaque, value: *u64) callconv(.c) c_int {
        value.* = ns;
        return status;
    }
};

comptime {
    if (@import("builtin").is_test)
        @export(&TestClock.read, .{ .name = "hyperv_clock_realtime" });
}

test "qualified realtime clock bridge writes actual WASI ID0 nanoseconds" {
    TestClock.reset();
    var output = std.mem.zeroes(Output);
    var config: runtime.Config = undefined;
    config.context = null;
    config.monotonic_ns = TestClock.monotonic;
    var state: State = .{
        .context = try wasi.Context.init(.{
            .args = &.{},
            .environment = &.{},
            .output = null,
            .clock = null,
        }),
        .config = &config,
        .output = &output,
        .realtime_read = hyperv_clock_realtime,
    };
    bindClock(&state);
    try std.testing.expectEqual(@as(u32, 1), output.realtime_supported);
    try std.testing.expectEqual(@as(u64, 1000000000), state.context.clock.?.resolution_ns[0]);
    var memory: [16]u8 = @splat(0xa5);
    noteClockRequest(&state, 0);
    try std.testing.expectEqual(wasi.Errno.success, state.context.clockTimeGet(&memory, 0, 1, 4));
    try std.testing.expectEqual(TestClock.ns, std.mem.readInt(u64, memory[4..12], .little));
    try std.testing.expectEqual(@as(u32, 0), output.unsupported_clock);
    try std.testing.expectEqual(wasi.Errno.fault, state.context.clockTimeGet(&memory, 0, 1, 12));
    try std.testing.expectEqual(wasi.Errno.success, state.context.clockTimeGet(&memory, 1, 1, 0));
    try std.testing.expectEqual(@as(u64, 100), state.context.clock.?.resolution_ns[1]);
    for (2..4) |id| {
        noteClockRequest(&state, @intCast(id));
        try std.testing.expectEqual(wasi.Errno.notsup, state.context.clockTimeGet(&memory, @intCast(id), 0, 0));
    }
    try std.testing.expectEqual(@as(u32, 1), output.unsupported_clock);
    output.unsupported_clock = 0;
    TestClock.ns = std.math.maxInt(u64);
    try std.testing.expectEqual(wasi.Errno.overflow, state.context.clockTimeGet(&memory, 1, 1, 0));
    try std.testing.expectEqual(@as(u32, 1), output.unsupported_clock);
}

test "unqualified failed zero sentinel and changed clocks never write success" {
    var output = std.mem.zeroes(Output);
    var state: State = .{
        .context = try wasi.Context.init(.{
            .args = &.{},
            .environment = &.{},
            .output = null,
            .clock = null,
        }),
        .config = undefined,
        .output = &output,
        .realtime_read = hyperv_clock_realtime,
    };
    for (0..12) |case| {
        TestClock.reset();
        switch (case) {
            0 => TestClock.status = -1,
            1 => TestClock.ns = 0,
            2 => TestClock.ns = std.math.maxInt(u64),
            3 => TestClock.caps.version = 2,
            4 => TestClock.caps.source = 0,
            5 => TestClock.caps.resolution_ns = 0,
            6 => TestClock.caps.resolution_ns = std.math.maxInt(u64),
            7 => TestClock.caps.efi_accuracy_pptrillion = 0,
            8 => TestClock.caps.sample_span_ns = std.math.maxInt(u64),
            9 => TestClock.caps.reserved = 1,
            10 => TestClock.caps.efi_accuracy_pptrillion = std.math.maxInt(u32),
            11 => TestClock.caps.resolution_ns = 1,
            else => unreachable,
        }
        bindClock(&state);
        try std.testing.expectEqual(@as(u32, 0), output.realtime_supported);
        var memory: [8]u8 = @splat(0xa5);
        noteClockRequest(&state, 0);
        try std.testing.expectEqual(wasi.Errno.notsup, state.context.clockTimeGet(&memory, 0, 0, 0));
        try std.testing.expectEqualSlices(u8, &@as([8]u8, @splat(0xa5)), &memory);
        try std.testing.expectEqual(@as(u32, 1), output.unsupported_clock);
    }
    for (0..4) |case| {
        TestClock.reset();
        bindClock(&state);
        switch (case) {
            0 => TestClock.status = -1,
            1 => TestClock.ns = 0,
            2 => TestClock.ns = std.math.maxInt(u64),
            3 => TestClock.caps.resolution_ns = 100,
            else => unreachable,
        }
        var memory: [8]u8 = @splat(0xa5);
        try std.testing.expectEqual(wasi.Errno.overflow, state.context.clockTimeGet(&memory, 0, 0, 0));
        try std.testing.expectEqualSlices(u8, &@as([8]u8, @splat(0xa5)), &memory);
        try std.testing.expectEqual(@as(u32, 0), output.realtime_supported);
        try std.testing.expectEqual(@as(u32, 1), output.unsupported_clock);
    }
}
