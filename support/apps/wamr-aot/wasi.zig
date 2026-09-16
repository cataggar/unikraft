// SPDX-License-Identifier: BSD-3-Clause
//! Optional C bridge to the pinned allocation-free minimal WASI context.
//! A single fresh, bounded CoreMark invocation, not a benchmark producer.
const std = @import("std");
const runtime = @import("wamr-native");
const wasi = @import("minimal-wasi");

const Output = extern struct {
    stdout_bytes: [4096]u8,
    stderr_bytes: [4096]u8,
    stdout_length: usize,
    stderr_length: usize,
    output_error: u32,
    pending_stdout: u32,
    pending_stderr: u32,
    unsupported_clock: u32,
};

const State = struct {
    context: wasi.Context,
    config: *const runtime.Config,
    output: *Output,
};

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
    if (id != .monotonic) return .{ .failure = .notsup };
    var ns: u64 = 0;
    if (s.config.monotonic_ns(s.config.context, &ns) != 0)
        return .{ .failure = .overflow };
    if (ns == std.math.maxInt(u64)) return .{ .failure = .overflow };
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
                if (bits[0] != 1) s.output.unsupported_clock = 1;
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
    };
    state.context.output = .{ .userdata = &state, .write = write };
    // Hyper-V values are nanoseconds; reference-source resolution is 100 ns.
    // No qualified EFI epoch or process/thread CPU clock is available here.
    state.context.clock = .{ .userdata = &state, .read = clock, .resolution_ns = .{ 0, 100, 0, 0 } };
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
