// SPDX-License-Identifier: BSD-3-Clause
//! Correctness exercise of the producer's real Session, not a v2 receipt.
const std = @import("std");
const native = @import("wamr-aot");
const bench = native.benchmark;
const runner = native.runner;
const fixture = @import("workload-artifacts");
const services = @import("native-services.zig");
const c = services.c;
const Platform = services.Services(native.aot);

export fn wamr_workload_run(config: *const c.wamr_aot_config, facts: *const c.struct_wamr_workload_facts, mode: c_uint) c_int {
    if (mode != 0) return 1;
    run(config, facts) catch return 1;
    return 0;
}

fn clock(raw: ?*anyopaque, id: bench.wasi.ClockId, _: u64) bench.wasi.ClockResult {
    const platform: *Platform = @ptrCast(@alignCast(raw.?));
    if (id != .monotonic) return .{ .failure = .notsup };
    return .{ .timestamp_ns = platform.platform().monotonicNs() catch return .{ .failure = .overflow } };
}

fn exercise(platform: *Platform, writer: *std.Io.Writer, name: []const u8, wasm: []const u8, bytes: []const u8) !void {
    var wasm_hash: [64]u8 = undefined;
    var aot_hash: [64]u8 = undefined;
    const wasm_identity = bench.Identity.fromBytes(wasm, &wasm_hash);
    const aot_identity = bench.Identity.fromBytes(bytes, &aot_hash);
    var progress: runner.Session.Progress = .{};
    const created = runner.Session.createCaptured(platform.allocator(), platform.platform(), bytes, &.{name}, &.{}, .{ .userdata = platform, .read = clock, .resolution_ns = .{ 0, 100, 0, 0 } }, &progress, .{ .output_limit = 4096, .setup_evidence = writer });
    // Preserve actual module-start evidence even when subsequent setup fails.
    if (writer.end != 0) services.transmit(writer) catch |err| {
        if (created) |session| session.deinit() else |_| {}
        return err;
    };
    const session = try created;
    defer session.deinit();
    try services.writeJson(writer, "WAMR_NATIVE_SNAPSHOT_SETUP=", .{
        .version = 1,
        .correctness_only = true,
        .workload = name,
        .wasm = wasm_identity,
        .aot = aot_identity,
        .execution_lifecycle = runner.execution_lifecycle,
        .phases_ns = progress,
        .pages = platform.pages(),
    });
    const instance = session.instance.?;
    for (0..4) |index| {
        if (index != 0) {
            const reset = session.resetTimed();
            try services.writeJson(writer, "WAMR_NATIVE_SNAPSHOT_RESET=", .{
                .workload = name,
                .index = index,
                .reset = reset,
                .same_instance = instance == session.instance.?,
                .pages = platform.pages(),
            });
            if (reset.outcome != .completed or reset.elapsed_ticks == null)
                return error.ResetFailed;
            if (std.mem.eql(u8, name, "memory") and instance.memory()[1025] != 0)
                return error.SnapshotContentsNotRestored;
        }
        const invocation = try session.invoke("_start");
        try runner.writeInvocationEvidence(writer, name, index, invocation);
        try services.transmit(writer);
        if (!invocation.succeeded() or invocation.stdout.len != 0 or invocation.stderr.len != 0)
            return error.InvocationFailed;
        if (std.mem.eql(u8, name, "memory") and instance.memory()[1025] != 1)
            return error.MemoryResultMismatch;
    }
}

fn run(config: *const c.wamr_aot_config, facts: *const c.struct_wamr_workload_facts) !void {
    var platform: Platform = .{ .config = config };
    var storage: [16384]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    const result = blk: {
        exercise(&platform, &writer, "compute", fixture.compute_wasm, fixture.compute_aot) catch |err| break :blk err;
        exercise(&platform, &writer, "memory", fixture.memory_wasm, fixture.memory_aot) catch |err| break :blk err;
        break :blk {};
    };
    try services.factsRecord(&writer, facts, "snapshot", platform.observations());
    try result;
}
