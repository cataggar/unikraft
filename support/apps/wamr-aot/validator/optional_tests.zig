// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const validator = @import("wamr_log_validator");
const core = @import("hyperv_core");
const t = std.testing;
const a = t.allocator;

const cases = .{
    .{ validator.optional.Mode.snapshot, @embedFile("optional-fixtures/snapshot.log"), @embedFile("optional-fixtures/snapshot.identity.json") },
    .{ validator.optional.Mode.aot, @embedFile("optional-fixtures/aot.log"), @embedFile("optional-fixtures/aot.identity.json") },
    .{ validator.optional.Mode.fast, @embedFile("optional-fixtures/fast.log"), @embedFile("optional-fixtures/fast.identity.json") },
    .{ validator.optional.Mode.full, @embedFile("optional-fixtures/full.log"), @embedFile("optional-fixtures/full.identity.json") },
};

fn check(mode: validator.optional.Mode, raw: []const u8, source: []const u8) !validator.optional.Result {
    var identity = try validator.records.OptionalIdentity.parse(a, source);
    defer identity.deinit();
    return validator.optional.checkSerial(a, raw, identity, mode);
}

fn refuse(mode: validator.optional.Mode, raw: []const u8, source: []const u8) !void {
    if (check(mode, raw, source)) |_| return error.UnsafeOptionalRecordAccepted else |_| {}
}

fn mutate(source: []const u8, before: []const u8, after: []const u8) ![]u8 {
    try t.expect(std.mem.indexOf(u8, source, before) != null);
    return std.mem.replaceOwned(u8, a, source, before, after);
}

test "snapshot and all three pinned sampler modes preserve raw hashes and normalized framing" {
    inline for (cases) |fixture| {
        const mode, const raw, const source = fixture;
        const result = try check(mode, raw, source);
        try t.expectEqual(raw.len, result.raw_serial_bytes);
        var digest: [32]u8 = undefined;
        core.Sha256.hash(raw, &digest, .{});
        try t.expectEqualSlices(u8, &digest, &result.raw_serial_sha256);
        const framed = try mutate(raw, "\n", "\x1b[0m\r\n\x00");
        defer a.free(framed);
        const framed_result = try check(mode, framed, source);
        try t.expectEqual(framed.len, framed_result.raw_serial_bytes);
        try t.expect(!std.mem.eql(u8, &digest, &framed_result.raw_serial_sha256));
        try t.expectEqualSlices(u8, raw, fixture[1]);
    }
}

test "optional lifecycle, strict sampler keys, integer types and identity refuse mutations" {
    inline for (cases) |fixture| {
        const mode, const raw, const source = fixture;
        for ([_]struct { before: []const u8, after: []const u8 }{
            .{ .before = "\"correctness_only\": true", .after = "\"correctness_only\": false" },
            .{ .before = "\"correctness_only\": true", .after = "\"correctness_only\": 1" },
            .{ .before = "\"version\": 1", .after = "\"version\": 1.0" },
            .{ .before = "\"memory_coverage\": \"code-and-linear-pages-only\"", .after = "\"memory_coverage\": \"whole-guest\"" },
            .{ .before = "\"frame_bytes\": 0", .after = "\"frame_bytes\": 4096" },
            .{ .before = "\"observation_count\": 20", .after = "\"observation_count\": 0" },
            .{ .before = "\"method\": \"hyperv-reference-monotonic\"", .after = "\"method\": \"other\"" },
            .{ .before = "\"correctness_only\": true", .after = "\"correctness_only\": true,\"correctness_only\": true" },
            .{ .before = "\"correctness_only\": true", .after = "\"correctness_only\": true,\"correctness_\\u006fnly\": true" },
        }) |change| {
            const bad = try mutate(raw, change.before, change.after);
            defer a.free(bad);
            try refuse(mode, bad, source);
        }
        for ([_][]const u8{
            raw[0 .. raw.len - 1],
            raw[0 .. raw.len - 2],
            "WAMR_NATIVE_WORKLOAD_BUILD={}\n",
            "WAMR_NATIVE_WORKLOAD_FAILED\n",
            "Unikraft Crash\n",
            "UK_HYPERV_PLATFORM_READY\n",
            "WAMR_BENCH_RESULT={}\n",
            "\xff\n",
            "\xe2\x80\xa8\n",
            "\x1b[0\x00m\n",
        }) |bad| {
            const extended = try std.mem.concat(a, u8, &.{ raw, bad });
            defer a.free(extended);
            try refuse(mode, extended, source);
        }
        const changed = try mutate(source, "\"source_tree_sha256\": \"bbbb", "\"source_tree_sha256\": \"cbbb");
        defer a.free(changed);
        try refuse(mode, raw, changed);
    }
    const snapshot = cases[0][1];
    const snapshot_identity = cases[0][2];
    for ([_]struct { before: []const u8, after: []const u8 }{
        .{ .before = "\"same_instance\": true", .after = "\"same_instance\": false" },
        .{ .before = "\"outcome\": \"returned\"", .after = "\"outcome\": \"trap\"" },
        .{ .before = "\"ticks\": null", .after = "\"ticks\": 0" },
        .{ .before = "\"stdout_base64\": \"\"", .after = "\"stdout_base64\": \"AA==\"" },
        .{ .before = "\"reset_scope\": [", .after = "\"reset_scope\": [\"extra\"," },
        .{ .before = "\"elapsed_ticks\": 100", .after = "\"elapsed_ticks\": null" },
        .{ .before = "\"load_ticks\": 100", .after = "\"load_ticks\": true" },
        .{ .before = "\"phase\": \"module-start\"", .after = "\"phase\": \"compute\"" },
        .{ .before = "\"wasm\": {\"sha256\": \"", .after = "\"wasm\": {\"sha256\": \"f" },
        .{ .before = "\"index\": 0", .after = "\"index\": true" },
    }) |change| {
        const bad = try mutate(snapshot, change.before, change.after);
        defer a.free(bad);
        try refuse(.snapshot, bad, snapshot_identity);
    }
    inline for (cases) |fixture| {
        const mode, const raw, const source = fixture;
        if (mode == .snapshot) continue;
        for ([_]struct { before: []const u8, after: []const u8 }{
            .{ .before = "\"expected\": 2241491208", .after = "\"expected\": 0" },
            .{ .before = "\"schema_version\": 1", .after = "\"schema_version\": true" },
            .{ .before = "\"linear_committed_bytes\": 131072", .after = "\"linear_committed_bytes\": 65536" },
            .{ .before = "\"heap_peak_bytes\": 8192", .after = "\"heap_peak_bytes\": 16777217" },
            .{ .before = "\"caller_live_after_teardown\": 0", .after = "\"caller_live_after_teardown\": 1" },
            .{ .before = "\"request_sha256\": \"", .after = "\"request_sha256\": \"f" },
            .{ .before = "\"growth_previous_pages\": 2", .after = "\"growth_previous_pages\": 3" },
            .{ .before = "\"linear_reserved_bytes\": 524288", .after = "\"linear_reserved_bytes\": 589824" },
            .{ .before = "\"compiler_polls\": 100", .after = "\"compiler_polls\": 100001" },
            .{ .before = "\"compiler_phases_ns\": {\"parse\": 10", .after = "\"compiler_phases_ns\": {\"parse\": 100" },
            .{ .before = "\"compiler_retained_bytes\": 4096", .after = "\"compiler_retained_bytes\": 65537" },
            .{ .before = "\"compiler_peak_bytes\": 65536", .after = "\"compiler_peak_bytes\": 67108865" },
            .{ .before = "\"memory_after\": {\"heap_live_bytes\": 4096", .after = "\"memory_after\": {\"heap_live_bytes\": 9000" },
            .{ .before = "\"compiler_embedded\": ", .after = "\"compiler_embedded\": null,\"unused\": " },
            .{ .before = "\"failure\": null", .after = "\"failure\": \"failed\"" },
            .{ .before = "\"compiler_peak_bytes\": ", .after = "\"compiler_peak_bytes\": -1,\"unused\": " },
        }) |change| {
            if (mode == .aot and std.mem.indexOf(u8, raw, change.before) == null) continue;
            const bad = try mutate(raw, change.before, change.after);
            defer a.free(bad);
            try refuse(mode, bad, source);
        }
    }
}

test "producer extension fields remain accepted only on required-subset records" {
    const extension = try mutate(cases[0][1], "WAMR_NATIVE_WORKLOAD_BUILD={\"version\": 1", "WAMR_NATIVE_WORKLOAD_BUILD={\"producer_extension\": {\"v2\": 2}, \"version\": 1");
    defer a.free(extension);
    _ = try check(.snapshot, extension, cases[0][2]);
    const bad = try mutate(cases[1][1], "WAMR_JIT_SAMPLE={\"schema_version\": 1", "WAMR_JIT_SAMPLE={\"producer_extension\": 1, \"schema_version\": 1");
    defer a.free(bad);
    try refuse(.aot, bad, cases[1][2]);
    try refuse(.snapshot, "", cases[0][2]);
    const oversized = try a.alloc(u8, 2 * 1024 * 1024 + 1);
    defer a.free(oversized);
    @memset(oversized, 'x');
    try refuse(.snapshot, oversized, cases[0][2]);
}

test "snapshot event order and deterministic single-byte fault property" {
    const raw = cases[0][1];
    const source = cases[0][2];
    const first = std.mem.indexOf(u8, raw, "WAMR_NATIVE_INVOCATION=") orelse unreachable;
    const reordered = try mutate(raw, "WAMR_NATIVE_INVOCATION=", "WAMR_NATIVE_SNAPSHOT_SETUP=");
    defer a.free(reordered);
    try refuse(.snapshot, reordered, source);
    var rng = std.Random.DefaultPrng.init(18803);
    for (0..128) |_| {
        const changed = try a.dupe(u8, raw);
        defer a.free(changed);
        const at = rng.random().intRangeLessThan(usize, first, raw.len - 22);
        changed[at] = 0x7f;
        try refuse(.snapshot, changed, source);
    }
    const noise = try mutate(raw, "WAMR_NATIVE_SNAPSHOT_SETUP=", "interleaved noise\nWAMR_NATIVE_SNAPSHOT_SETUP=");
    defer a.free(noise);
    try refuse(.snapshot, noise, source);
}
