// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const c = @import("hyperv_core").contracts;
const serial = @import("local_boot_serial");
const records = @import("records.zig");
const coremark = @import("coremark.zig");

pub const marker = "WAMR_NATIVE_AOT_OK answer=42 teardown=0";
pub const prefix = "WAMR_NATIVE_COMPUTE=";
pub const wasi_prefix = "WAMR_NATIVE_WASI=";
pub const legacy_marker = "Using legacy xAPIC MMIO";

pub const Result = struct {
    version: u8,
    workload: enum { tiny },
    wamr_revision: []const u8,
    wasm_sha256: []const u8,
    cwasm_sha256: []const u8,
    runtime_sha256: []const u8,
    platform_status: i32,
    checks: u32,
    answer: i32,
    terminal: u32,
    detail: u32,
    reserved_bytes: u64,
    frame_bytes: u64,
    accessible_bytes: u64,
    allocation_bytes: u64,
    system_page_table_bytes: u64,
    error_name: []const u8,
};

pub const Scope = enum { app, direct };
pub const LegacyApic = enum { ignored, required, forbidden };
pub const Options = struct {
    scope: Scope = .app,
    legacy_apic: LegacyApic = .ignored,
};

const forbidden = [_][]const u8{
    "HYPERV_ACCEPTANCE",        "UK_HYPERV_IO_READY",   "UK_HYPERV_NETWORK_APP_READY",
    "UK_HYPERV_PLATFORM_READY", "WAMR_NATIVE_AOT_FAIL", "Unikraft Crash",
    "Assertion failure",        "Exception Type",
};

pub fn checkSerial(allocator: std.mem.Allocator, raw: []const u8, identity: records.Identity, options: Options) !Result {
    if (raw.len == 0) return error.EvidenceIncomplete;
    const text = try serial.normalizeWithOptions(allocator, raw, .tiny);
    defer allocator.free(text);

    for (forbidden) |bad|
        if (std.mem.indexOf(u8, text, bad) != null) return error.ForbiddenMarker;
    if ((options.scope == .direct or !identity.minimal_wasi) and
        std.mem.indexOf(u8, text, wasi_prefix) != null) return error.ForbiddenMarker;
    switch (options.legacy_apic) {
        .ignored => {},
        .required => if (std.mem.count(u8, text, legacy_marker) != 1) return error.LegacyApicMismatch,
        .forbidden => if (std.mem.indexOf(u8, text, legacy_marker) != null) return error.LegacyApicMismatch,
    }
    if (std.mem.count(u8, text, marker) > 1) return error.InvalidCompletion;

    var lines = std.mem.splitScalar(u8, text, '\n');
    var starts: usize = 0;
    var wasi_count: usize = 0;
    var record: ?Result = null;
    var complete = false;
    var returned = false;
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "Calling main(") != null) {
            if (starts != 0 or wasi_count != 0 or record != null or complete or returned)
                return error.DuplicateStart;
            starts += 1;
        }
        if (std.mem.indexOf(u8, line, wasi_prefix) != null) {
            if (!std.mem.startsWith(u8, line, wasi_prefix) or starts != 1 or
                complete or returned or wasi_count >= 2 or
                options.scope == .direct or !identity.minimal_wasi)
                return error.InvalidWasiRecord;
            var doc = try records.parseDocument(allocator, line[wasi_prefix.len..]);
            defer doc.deinit();
            const name = if (wasi_count == 0) "coremark" else "coremark-nofp";
            try coremark.validateRecord(allocator, doc.value(), name, if (wasi_count == 0) identity.coremark_wasm else identity.nofp_wasm, if (wasi_count == 0) identity.coremark_cwasm else identity.nofp_cwasm);
            wasi_count += 1;
        }
        if (std.mem.indexOf(u8, line, prefix) != null) {
            if (!std.mem.startsWith(u8, line, prefix) or starts != 1 or record != null or complete or returned)
                return error.InvalidComputeRecord;
            var doc = try records.parseDocument(allocator, line[prefix.len..]);
            defer doc.deinit();
            record = try parseResult(doc.value(), identity);
        }
        if (std.mem.indexOf(u8, line, marker) != null) {
            if (!std.mem.eql(u8, line, marker) or complete or record == null or returned)
                return error.InvalidCompletion;
            complete = true;
        }
        if (std.mem.indexOf(u8, line, "main returned") != null) {
            if (!complete or returned) return error.InvalidMainReturn;
            returned = true;
        }
    }
    if (!returned or record == null or (identity.minimal_wasi and wasi_count != 2))
        return error.EvidenceIncomplete;
    // Local-boot owns the milestone and terminal grammar; no second boot parser.
    try serial.validateEnvelope(allocator, text, marker, 0, &.{}, &.{});
    return record.?;
}

fn parseResult(value: std.json.Value, identity: records.Identity) !Result {
    const fields = try c.exactFields(value, &.{
        "version",      "workload",         "wamr_revision",    "wasm_sha256",
        "cwasm_sha256", "runtime_sha256",   "platform_status",  "checks",
        "answer",       "terminal",         "detail",           "reserved_bytes",
        "frame_bytes",  "accessible_bytes", "allocation_bytes", "system_page_table_bytes",
        "error_name",
    });
    try records.intEquals(fields, "version", 1);
    try records.stringEquals(fields, "workload", "tiny");
    try records.stringEquals(fields, "wamr_revision", identity.wamr_revision);
    try records.stringEquals(fields, "wasm_sha256", identity.tiny_wasm);
    try records.stringEquals(fields, "cwasm_sha256", identity.tiny_cwasm);
    try records.stringEquals(fields, "runtime_sha256", identity.runtime);
    try records.intEquals(fields, "platform_status", 0);
    try records.intEquals(fields, "checks", 2);
    try records.intEquals(fields, "answer", 42);
    try records.intEquals(fields, "terminal", 1);
    try records.intEquals(fields, "detail", 2);
    inline for (.{ "reserved_bytes", "frame_bytes", "accessible_bytes", "allocation_bytes" }) |field|
        try records.intEquals(fields, field, 0);
    try records.stringEquals(fields, "error_name", "");
    const table_bytes = try c.integer(u64, try records.get(fields, "system_page_table_bytes"));
    if (table_bytes == 0 or table_bytes > 256 * 1024 * 1024 or table_bytes % 4096 != 0)
        return error.InvalidPageTable;
    return .{
        .version = 1,
        .workload = .tiny,
        .wamr_revision = identity.wamr_revision,
        .wasm_sha256 = identity.tiny_wasm,
        .cwasm_sha256 = identity.tiny_cwasm,
        .runtime_sha256 = identity.runtime,
        .platform_status = 0,
        .checks = 2,
        .answer = 42,
        .terminal = 1,
        .detail = 2,
        .reserved_bytes = 0,
        .frame_bytes = 0,
        .accessible_bytes = 0,
        .allocation_bytes = 0,
        .system_page_table_bytes = table_bytes,
        .error_name = "",
    };
}
