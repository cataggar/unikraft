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

export fn wamr_workload_bench(
    config: *const c.wamr_aot_config,
    facts: *const c.struct_wamr_workload_facts,
    envelope_ptr: [*]const u8,
    envelope_len: usize,
) c_int {
    runBenchEnvelope(config, facts, envelope_ptr[0..envelope_len]) catch return 1;
    return 0;
}

/// Binds a Unikraft `wamr_aot_config` (`Services`) to `@import("wamr-aot").benchmark.Options`
/// and runs the v2 freestanding guest benchmark producer when supplied with an
/// independently admitted request and deployment envelope.
pub fn runBenchmark(config: *const c.wamr_aot_config, options: bench.Options) !void {
    var platform: Platform = .{ .config = config };
    var bound = options;
    bound.allocator = platform.allocator();
    bound.native = platform.platform();
    bound.clock = platform.benchmarkClock(bench);
    bound.pages = platform.benchmarkPages(bench);
    try bench.run(bound);
}

const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(self: *Cursor, n: usize) ![]const u8 {
        if (n > self.bytes.len -| self.pos) return error.InvalidEnvelope;
        const out = self.bytes[self.pos .. self.pos + n];
        self.pos += n;
        return out;
    }

    fn takeU32(self: *Cursor) !u32 {
        const b = try self.take(4);
        return std.mem.readInt(u32, b[0..4], .little);
    }

    fn takeU64(self: *Cursor) !u64 {
        const b = try self.take(8);
        return std.mem.readInt(u64, b[0..8], .little);
    }

    fn takeFramed(self: *Cursor) ![]const u8 {
        const len = try self.takeU32();
        return self.take(len);
    }
};

fn writeStream(bytes: []const u8) !void {
    if (bytes.len == 0) return;
    if (c.wamr_workload_write_stream(bytes.ptr, bytes.len) != 0) return error.SerialWriteFailed;
}

fn writeMarkerLine(prefix: []const u8, token: []const u8) !void {
    try writeStream(prefix);
    try writeStream(token);
    try writeStream("\n");
}

fn runBenchEnvelope(
    config: *const c.wamr_aot_config,
    facts: *const c.struct_wamr_workload_facts,
    envelope: []const u8,
) !void {
    var cur: Cursor = .{ .bytes = envelope };
    const magic = try cur.take(12);
    if (!std.mem.eql(u8, magic, "WAMRBENCHV2\n")) return error.InvalidEnvelope;

    const configured_vm_ram_bytes = try cur.takeU64();
    const runtime_bytes = try cur.takeU64();
    const compiler_bytes = try cur.takeU64();
    const image_bytes = try cur.takeU64();
    const image_sha256 = try cur.take(64);
    const tracked_diff_sha256 = try cur.take(64);
    const compiler_version = try cur.takeFramed();
    const target_abi = try cur.takeFramed();
    const azure_sku = try cur.takeFramed();
    const azure_region = try cur.takeFramed();
    const receipt_json = try cur.takeFramed();

    const workload_count = try cur.takeU32();
    if (workload_count == 0 or workload_count > 8) return error.InvalidEnvelope;
    var workloads: [8]bench.Workload = undefined;
    for (0..workload_count) |idx| {
        workloads[idx] = .{
            .name = try cur.takeFramed(),
            .wasm = try cur.takeFramed(),
            .aot_bytes = try cur.takeFramed(),
        };
    }

    const request_count = try cur.takeU32();
    if (request_count == 0 or request_count > 256) return error.InvalidEnvelope;

    const source: bench.Source = .{
        .commit = std.mem.span(facts.revision),
        .tree_sha256 = std.mem.span(facts.source_tree_sha256),
        .tracked_diff_sha256 = tracked_diff_sha256,
    };
    const build: bench.Build = .{
        .source = source,
        .runtime = .{
            .sha256 = std.mem.span(facts.runtime_sha256),
            .bytes = runtime_bytes,
        },
        .compiler = .{
            .binary = .{
                .sha256 = std.mem.span(facts.compiler_sha256),
                .bytes = compiler_bytes,
            },
            .source = source,
            .version = compiler_version,
        },
        .target_abi = target_abi,
        .memory_policy = .{
            .allocator_by_phase = .{
                .load = "unikraft-uk_alloc-page-backed",
                .instantiate = "unikraft-uk_alloc-page-backed",
                .first = "wasm-linear-memory-in-place",
                .steady = "snapshot-restore-in-place",
            },
            .page_policy = .{
                .reservation = "uk_paging_page_map-4k",
                .commitment = "eager-physical-frame-alloc",
                .release = "uk_paging_page_unmap-and-frame-free",
            },
        },
    };
    const deployment: bench.Deployment = .{
        .receipt_json = receipt_json,
        .image = .{
            .sha256 = image_sha256,
            .bytes = image_bytes,
        },
        .azure_sku = azure_sku,
        .azure_region = azure_region,
        .configured_vm_ram_bytes = configured_vm_ram_bytes,
        .qualification = .independently_qualified_hardware,
    };

    var brand_buf: [48]u8 = undefined;
    const cpu_model = services.cpuidBrandToken(&brand_buf);
    var outer_platform: Platform = .{ .config = config };

    for (0..request_count) |_| {
        const run_id = try cur.takeFramed();
        const config_sha256 = try cur.take(64);
        const request_json = try cur.takeFramed();

        {
            const scratch = try outer_platform.allocator().alloc(u8, 768 * 1024);
            defer outer_platform.allocator().free(scratch);
            const workspace = scratch[0 .. 512 * 1024];
            const result_buf = scratch[512 * 1024 .. 640 * 1024];
            const evidence_buf = scratch[640 * 1024 .. 768 * 1024];
            var result_writer = std.Io.Writer.fixed(result_buf);
            var evidence_writer = std.Io.Writer.fixed(evidence_buf);

            try writeMarkerLine("WAMR_BENCH_RUN_BEGIN=", run_id);
            try runBenchmark(config, .{
                .request_json = request_json,
                .config_sha256 = config_sha256,
                .build = build,
                .deployment = deployment,
                .workloads = workloads[0..workload_count],
                .cpu = .{ .model = cpu_model, .active_count = 1 },
                .native = undefined,
                .clock = undefined,
                .pages = undefined,
                .allocator = undefined,
                .workspace = workspace,
                .result = &result_writer,
                .evidence = &evidence_writer,
            });
            try writeStream(evidence_writer.buffered());
            try writeStream(result_writer.buffered());
            try writeMarkerLine("WAMR_BENCH_RUN_END=", run_id);
        }
        const observed = outer_platform.pages();
        if (observed.reserved_bytes != 0 or observed.frame_bytes != 0 or
            observed.accessible_bytes != 0 or observed.allocation_bytes != 0)
            return error.ResourceLeak;
    }
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
