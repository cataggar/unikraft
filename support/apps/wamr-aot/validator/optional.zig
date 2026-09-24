// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const c = core.contracts;
const serial = @import("local_boot_serial");
const r = @import("records.zig");
const sampler = @import("sampler.zig");

pub const Mode = enum { snapshot, aot, fast, full };
pub const Result = struct {
    raw_serial_bytes: usize,
    raw_serial_sha256: [32]u8,
};

const Entry = enum { invocation, setup, reset, build, sample, completed };
const prefixes = [_][]const u8{
    "WAMR_NATIVE_INVOCATION",     "WAMR_NATIVE_SNAPSHOT_SETUP",
    "WAMR_NATIVE_SNAPSHOT_RESET", "WAMR_NATIVE_WORKLOAD_BUILD",
    "WAMR_JIT_SAMPLE",
};
const forbidden = [_][]const u8{
    "Unikraft Crash",     "Assertion failure",           "Exception Type",           "HYPERV_ACCEPTANCE",
    "UK_HYPERV_IO_READY", "UK_HYPERV_NETWORK_APP_READY", "UK_HYPERV_PLATFORM_READY",
};
const domains = [_][]const u8{
    "globals",                  "invocation-output",          "linear-memory-access-protection",
    "linear-memory-contents",   "linear-memory-logical-size", "passive-segment-drop-state",
    "table-entries-signatures", "wasi-context",
};
const excludes = [_][]const u8{
    "allocator-backing", "image", "native-stack", "page-tables", "other-kernel-allocations",
};
const snapshot_order = [_]Entry{
    .invocation, .setup,      .invocation, .reset,      .invocation, .reset,     .invocation,
    .reset,      .invocation, .invocation, .setup,      .invocation, .reset,     .invocation,
    .reset,      .invocation, .reset,      .invocation, .build,      .completed,
};
const sampler_order = [_]Entry{ .sample, .build, .completed };

fn integer(fields: std.json.ObjectMap, key: []const u8, minimum: u64) !u64 {
    const value = try c.integer(u64, try r.get(fields, key));
    if (value < minimum) return error.InvalidObservation;
    return value;
}

fn empty(value: std.json.Value) !void {
    const array = switch (value) {
        .array => |v| v.items,
        else => return error.ExpectedArray,
    };
    if (array.len != 0) return error.InvalidObservation;
}

fn strings(value: std.json.Value, expected: []const []const u8) !void {
    const array = switch (value) {
        .array => |v| v.items,
        else => return error.ExpectedArray,
    };
    if (array.len != expected.len) return error.InvalidObservation;
    for (array, expected) |item, name| try r.equal(try c.string(item), name);
}

fn nullField(fields: std.json.ObjectMap, key: []const u8) !void {
    if (try r.get(fields, key) != .null) return error.InvalidObservation;
}

fn falseField(fields: std.json.ObjectMap, key: []const u8) !void {
    if (try r.boolean(try r.get(fields, key))) return error.InvalidObservation;
}

fn build(value: std.json.Value, identity: r.OptionalIdentity) !void {
    const fields = try r.object(value);
    try r.intEquals(fields, "version", 1);
    try r.trueField(fields, "correctness_only");
    try r.stringEquals(fields, "variant", identity.variant);
    try r.stringEquals(fields, "wamr_revision", identity.revision);
    try r.stringEquals(fields, "source_tree_sha256", identity.source_tree);
    try r.stringEquals(fields, "runtime_sha256", try identity.file("libwamr-aot.a"));
    try r.stringEquals(fields, "compiler_sha256", try identity.file("wamrc"));
    const clock = try c.exactFields(try r.get(fields, "clock"), &.{ "method", "resolution_ns" });
    try r.stringEquals(clock, "method", "hyperv-reference-monotonic");
    try r.intEquals(clock, "resolution_ns", 100);
    try r.stringEquals(fields, "memory_method", "native-vma-owned-4k-data-frames-including-none");
    try r.stringEquals(fields, "memory_coverage", "code-and-linear-pages-only");
    try r.stringEquals(fields, "sampling", "callback-boundaries-observed-max-not-peak");
    try r.stringEquals(fields, "allocator_quantity", "caller-and-adapter-requested-bytes-not-backing");
    try strings(try r.get(fields, "excludes"), &excludes);
    const memory = try r.object(try r.get(fields, "memory"));
    const teardown = try c.exactFields(try r.get(memory, "after_teardown"), &.{
        "reserved_bytes", "frame_bytes", "accessible_bytes", "allocation_bytes",
    });
    inline for (.{ "reserved_bytes", "frame_bytes", "accessible_bytes", "allocation_bytes" }) |field|
        try r.intEquals(teardown, field, 0);
    inline for (.{ "observed_max_frame_bytes", "observed_max_reserved_bytes", "observed_max_allocation_bytes", "observation_count" }) |field|
        _ = try integer(memory, field, 1);
}

fn invocation(value: std.json.Value, ordinal: usize) !void {
    const fields = try r.object(value);
    try r.intEquals(fields, "schema_version", 1);
    try r.stringEquals(fields, "kind", "wamr-native-invocation-evidence");
    try r.stringEquals(fields, "outcome", "returned");
    try nullField(fields, "exit_code");
    try nullField(fields, "timing_error");
    try nullField(fields, "diagnostic");
    try falseField(fields, "output_failure");
    try r.trueField(fields, "stdout_complete");
    try r.trueField(fields, "stderr_complete");
    try empty(try r.get(fields, "measurement_errors"));
    try r.stringEquals(fields, "stdout_base64", "");
    try r.stringEquals(fields, "stderr_base64", "");

    const local = ordinal % 5;
    const phase = if (local == 0) "module-start" else if (ordinal < 5) "compute" else "memory";
    try r.stringEquals(fields, "phase", phase);
    try r.intEquals(fields, "index", if (local == 0) 0 else local - 1);
    if (local == 0) try nullField(fields, "ticks") else _ = try integer(fields, "ticks", 0);
}

fn setup(value: std.json.Value, identity: r.OptionalIdentity, name: []const u8) !void {
    const fields = try r.object(value);
    try r.intEquals(fields, "version", 1);
    try r.trueField(fields, "correctness_only");
    try r.stringEquals(fields, "workload", name);
    const wasm = try r.object(try r.get(fields, "wasm"));
    const aot = try r.object(try r.get(fields, "aot"));
    const wasm_name = if (std.mem.eql(u8, name, "compute")) "compute.wasm" else "memory.wasm";
    const aot_name = if (std.mem.eql(u8, name, "compute")) "compute.cwasm" else "memory.cwasm";
    try r.stringEquals(wasm, "sha256", try identity.file(wasm_name));
    try r.stringEquals(aot, "sha256", try identity.file(aot_name));
    _ = try integer(wasm, "bytes", 1);
    _ = try integer(aot, "bytes", 1);
    const lifecycle = try c.exactFields(try r.get(fields, "execution_lifecycle"), &.{
        "mode", "reset_policy", "reset_before", "reset_timing", "reset_scope",
    });
    try r.stringEquals(lifecycle, "mode", "snapshot-replay");
    try r.stringEquals(lifecycle, "reset_policy", "restore-post-start-snapshot");
    try r.stringEquals(lifecycle, "reset_before", "each-steady-invocation");
    try r.stringEquals(lifecycle, "reset_timing", "excluded-from-invocation");
    try strings(try r.get(lifecycle, "reset_scope"), &domains);
    const phases = try c.exactFields(try r.get(fields, "phases_ns"), &.{
        "load_ticks", "instantiate_ticks", "lifecycle_setup_ticks",
    });
    inline for (.{ "load_ticks", "instantiate_ticks", "lifecycle_setup_ticks" }) |field|
        _ = try integer(phases, field, 0);
    _ = try integer(try r.object(try r.get(fields, "pages")), "frame_bytes", 1);
}

fn reset(value: std.json.Value, name: []const u8, index: usize) !void {
    const fields = try r.object(value);
    try r.stringEquals(fields, "workload", name);
    try r.intEquals(fields, "index", index);
    try r.trueField(fields, "same_instance");
    const state = try r.object(try r.get(fields, "reset"));
    try r.stringEquals(state, "outcome", "completed");
    try nullField(state, "diagnostic");
    try nullField(state, "timing_error");
    _ = try integer(state, "elapsed_ticks", 0);
}

fn requestHash(mode: Mode) [64]u8 {
    const request = switch (mode) {
        .aot => "wamr-native-correctness-only-v1\naot\n",
        .fast => "wamr-native-correctness-only-v1\nfast\n",
        .full => "wamr-native-correctness-only-v1\nfull\n",
        .snapshot => unreachable,
    };
    var digest: [32]u8 = undefined;
    core.Sha256.hash(request, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn checkSerial(allocator: std.mem.Allocator, raw: []const u8, identity: r.OptionalIdentity, mode: Mode) !Result {
    if (raw.len == 0 or raw.len > 2 * 1024 * 1024) return error.SerialLimit;
    const text = try serial.normalizeWithOptions(allocator, raw, .optional);
    defer allocator.free(text);
    if (text.len == 0 or text[text.len - 1] != '\n') return error.TruncatedSerial;
    for (forbidden) |bad|
        if (std.mem.indexOf(u8, text, bad) != null) return error.ForbiddenMarker;
    const snapshot = mode == .snapshot;
    if (snapshot != std.mem.eql(u8, identity.variant, "snapshot")) return error.WrongMode;
    if (!snapshot) {
        const jit = std.mem.eql(u8, identity.variant, "jit");
        if (!jit and !std.mem.eql(u8, identity.variant, "sample-aot")) return error.WrongMode;
        if (jit != (mode != .aot)) return error.WrongMode;
        if (jit) {
            if (identity.jit_mode == null or !std.mem.eql(u8, identity.jit_mode.?, @tagName(mode)))
                return error.WrongMode;
        } else if (identity.jit_mode != null) return error.WrongMode;
    }
    const order = if (snapshot) &snapshot_order else &sampler_order;
    var seen: usize = 0;
    var calls: usize = 0;
    var setups: usize = 0;
    var resets: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "WAMR_") == null) {
            if (seen > 0 and seen < order.len and std.mem.trim(u8, line, " \t").len != 0)
                return error.TranscriptNoise;
            continue;
        }
        if (!std.mem.startsWith(u8, line, "WAMR_") or
            std.mem.count(u8, line, "WAMR_") != 1)
            return error.UnanchoredRecord;
        if (line.len + 1 > 16384 or seen >= order.len) return error.InvalidRecord;
        if (std.mem.startsWith(u8, line, "WAMR_NATIVE_WORKLOAD_CHECK_OK ")) {
            if (order[seen] != .completed) return error.ReorderedRecord;
            const marker: []const u8 = switch (mode) {
                .snapshot => "WAMR_NATIVE_WORKLOAD_CHECK_OK variant=1 mode=0 teardown=0",
                .aot => "WAMR_NATIVE_WORKLOAD_CHECK_OK variant=3 mode=0 teardown=0",
                .fast => "WAMR_NATIVE_WORKLOAD_CHECK_OK variant=2 mode=1 teardown=0",
                .full => "WAMR_NATIVE_WORKLOAD_CHECK_OK variant=2 mode=2 teardown=0",
            };
            try r.equal(line, marker);
            seen += 1;
            continue;
        }
        const separator = std.mem.indexOfScalar(u8, line, '=') orelse return error.InvalidRecord;
        const name = line[0..separator];
        const kind: Entry = if (std.mem.eql(u8, name, prefixes[0])) .invocation else if (std.mem.eql(u8, name, prefixes[1])) .setup else if (std.mem.eql(u8, name, prefixes[2])) .reset else if (std.mem.eql(u8, name, prefixes[3])) .build else if (std.mem.eql(u8, name, prefixes[4])) .sample else return error.InvalidRecord;
        if (kind != order[seen] or (kind == .sample and line.len + 1 > 8192))
            return error.ReorderedRecord;
        var document = try r.parseDocument(allocator, line[separator + 1 ..]);
        defer document.deinit();
        switch (kind) {
            .invocation => {
                try invocation(document.value(), calls);
                calls += 1;
            },
            .setup => {
                try setup(document.value(), identity, if (setups == 0) "compute" else "memory");
                setups += 1;
            },
            .reset => {
                try reset(document.value(), if (resets < 3) "compute" else "memory", resets % 3 + 1);
                resets += 1;
            },
            .build => try build(document.value(), identity),
            .sample => {
                const fields = try r.object(document.value());
                const request = requestHash(mode);
                const sample_mode: sampler.Mode = switch (mode) {
                    .aot => .aot,
                    .fast => .fast,
                    .full => .full,
                    .snapshot => unreachable,
                };
                try sampler.validate(document.value(), sample_mode, &request);
                try r.stringEquals(fields, "wasm_sha256", try identity.file("matched.wasm"));
                if (mode == .aot) try r.stringEquals(fields, "cwasm_sha256", try identity.file("matched.cwasm"));
            },
            .completed => unreachable,
        }
        seen += 1;
    }
    if (seen != order.len) return error.IncompleteTranscript;
    var digest: [32]u8 = undefined;
    core.Sha256.hash(raw, &digest, .{});
    return .{ .raw_serial_bytes = raw.len, .raw_serial_sha256 = digest };
}
