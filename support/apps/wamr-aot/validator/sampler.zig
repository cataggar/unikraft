// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const c = @import("hyperv_core").contracts;
const r = @import("records.zig");

// scripts/native_jit_benchmark.py::validate_sample at
// a53205d77be3b880eb8f8b96679512ba58e2331a (not its receipt/measurement policy).
pub const SAMPLE_KEYS = [_][]const u8{
    "schema_version",          "kind",                "qualification",           "request_sha256",        "mode",
    "compiler_embedded",       "wasm_sha256",         "wasm_bytes",              "cwasm_sha256",          "cwasm_bytes",
    "workload",                "expected",            "lifecycle",               "clock_resolution_ns",   "compile_ns",
    "compiler_phases_ns",      "compiler_peak_bytes", "compiler_retained_bytes", "compiler_polls",        "load_ns",
    "instantiate_ns",          "start_ns",            "growth_ns",               "growth_previous_pages", "fuel_per_invocation",
    "invocations",             "memory_before",       "memory_after",            "caller_peak_bytes",     "caller_live_after_teardown",
    "reserved_after_teardown", "failure_stage",       "failure",
};
pub const MEMORY_KEYS = [_][]const u8{
    "heap_live_bytes",       "heap_peak_bytes",        "code_bytes", "code_reserved_bytes",
    "linear_reserved_bytes", "linear_committed_bytes",
};

pub const Mode = enum { aot, fast, full };
pub const expected_value: u64 = 2241491208;

fn number(fields: std.json.ObjectMap, name: []const u8, minimum: u64) !u64 {
    const value = try c.integer(u64, try r.get(fields, name));
    if (value < minimum) return error.InvalidObservation;
    return value;
}

fn isNull(value: std.json.Value) bool {
    return value == .null;
}

fn digest(fields: std.json.ObjectMap, name: []const u8) !void {
    _ = try c.parseSha256(try c.string(try r.get(fields, name)));
}

fn memory(value: std.json.Value) !std.json.ObjectMap {
    const fields = try c.exactFields(value, &MEMORY_KEYS);
    for (MEMORY_KEYS) |name| _ = try number(fields, name, 1);
    const live = try number(fields, "heap_live_bytes", 1);
    const peak = try number(fields, "heap_peak_bytes", 1);
    const code = try number(fields, "code_bytes", 1);
    const reserved = try number(fields, "code_reserved_bytes", 1);
    const linear = try number(fields, "linear_reserved_bytes", 1);
    if (live > peak or peak > 16 * 1024 * 1024 or code > 4 * 1024 * 1024 or
        @as(u128, reserved) + linear > 8 * 1024 * 1024)
        return error.SamplerMemoryCap;
    return fields;
}

pub fn validate(value: std.json.Value, mode: Mode, request_sha256: []const u8) !void {
    const fields = try c.exactFields(value, &SAMPLE_KEYS);
    try r.intEquals(fields, "schema_version", 1);
    try r.stringEquals(fields, "kind", "wamr-native-jit-sample");
    try r.stringEquals(fields, "qualification", "requires-independent-image-and-deployment-evidence");
    try r.stringEquals(fields, "request_sha256", request_sha256);
    try r.stringEquals(fields, "mode", @tagName(mode));
    if (try r.boolean(try r.get(fields, "compiler_embedded")) != (mode != .aot))
        return error.CompilerIdentity;
    if (!isNull(try r.get(fields, "failure")) or !isNull(try r.get(fields, "failure_stage")))
        return error.SamplerFailure;
    try r.stringEquals(fields, "workload", "volatile-compute-memory-2000");
    try r.intEquals(fields, "expected", expected_value);
    try r.stringEquals(fields, "lifecycle", "same-instance-workload-initializes-memory-in-timed-call");
    try digest(fields, "wasm_sha256");
    try digest(fields, "cwasm_sha256");
    inline for (.{ "wasm_bytes", "cwasm_bytes", "clock_resolution_ns", "caller_peak_bytes" }) |name|
        _ = try number(fields, name, 1);
    inline for (.{ "load_ns", "instantiate_ns", "start_ns", "growth_ns" }) |name|
        _ = try number(fields, name, 0);
    try r.intEquals(fields, "growth_previous_pages", 2);
    try r.intEquals(fields, "caller_live_after_teardown", 0);
    try r.intEquals(fields, "reserved_after_teardown", 0);

    const invocations = switch (try r.get(fields, "invocations")) {
        .array => |array| array.items,
        else => return error.InvalidInvocations,
    };
    if (invocations.len != 4) return error.InvalidInvocations;
    for (invocations) |call| {
        const invocation = try c.exactFields(call, &.{ "ns", "outcome", "value", "diagnostic" });
        _ = try number(invocation, "ns", 0);
        try r.stringEquals(invocation, "outcome", "returned");
        try r.intEquals(invocation, "value", expected_value);
        if (!isNull(try r.get(invocation, "diagnostic"))) return error.InvalidInvocation;
    }
    const before = try memory(try r.get(fields, "memory_before"));
    const after = try memory(try r.get(fields, "memory_after"));
    try r.intEquals(before, "linear_committed_bytes", 2 * 65536);
    try r.intEquals(after, "linear_committed_bytes", 3 * 65536);
    try r.intEquals(before, "linear_reserved_bytes", 8 * 65536);
    try r.intEquals(after, "linear_reserved_bytes", 8 * 65536);

    if (mode == .aot) {
        if (!isNull(try r.get(fields, "compile_ns")) or
            !isNull(try r.get(fields, "compiler_phases_ns")) or
            !isNull(try r.get(fields, "fuel_per_invocation")))
            return error.CompilerInAot;
        inline for (.{ "compiler_peak_bytes", "compiler_retained_bytes", "compiler_polls" }) |name|
            try r.intEquals(fields, name, 0);
    } else {
        const compile_ns = try number(fields, "compile_ns", 0);
        const phases = try c.exactFields(try r.get(fields, "compiler_phases_ns"), &.{
            "parse", "lower", "optimize", "codegen", "emit",
        });
        var total: u128 = 0;
        inline for (.{ "parse", "lower", "optimize", "codegen", "emit" }) |name|
            total += try number(phases, name, 0);
        if (total > compile_ns) return error.InvalidCompilerPhases;
        const peak = try number(fields, "compiler_peak_bytes", 1);
        const retained = try number(fields, "compiler_retained_bytes", 1);
        const polls = try number(fields, "compiler_polls", 1);
        if (retained > peak or peak > 64 * 1024 * 1024 or polls > 100000)
            return error.CompilerCap;
        try r.intEquals(fields, "fuel_per_invocation", 100000);
    }
}
