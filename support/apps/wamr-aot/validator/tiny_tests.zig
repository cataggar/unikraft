// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const validator = @import("wamr_log_validator");
const fixtures = @import("fixtures.zig");
const t = std.testing;
const a = t.allocator;
extern fn check_coremark([*]const u8, usize) c_int;

fn refused(raw: []const u8, identity: validator.records.Identity, options: validator.tiny.Options) !void {
    if (validator.tiny.checkSerial(a, raw, identity, options)) |_| return error.UnsafeInputAccepted else |_| {}
}

fn rejectedOutput(output: []const u8) !void {
    try t.expectEqual(@as(c_int, 0), check_coremark(output.ptr, output.len));
    if (validator.coremark.validateOutput(output)) |_| return error.InvalidCoreMarkAccepted else |_| {}
}

test "independent C oracle agrees on exact indexed CoreMark fields and formatting" {
    for ([_][]const u8{
        fixtures.stdout,
        try std.mem.replaceOwned(u8, a, fixtures.stdout, "\n", "\r\n"),
        try std.mem.replaceOwned(u8, a, fixtures.stdout, " : ", "\t:\t"),
    }, 0..) |output, index| {
        defer if (index != 0) a.free(output);
        try t.expectEqual(@as(c_int, 1), check_coremark(output.ptr, output.len));
        try validator.coremark.validateOutput(output);
    }
    for ([_]struct { original: []const u8, replacement: []const u8 }{
        .{ .original = "Iterations       : 100", .replacement = "Iterations       : 1000" },
        .{ .original = "0xe714", .replacement = "0xdead" },
        .{ .original = "[0]crclist", .replacement = "crclist" },
        .{ .original = "[0]crcmatrix", .replacement = "crcmatrix" },
        .{ .original = "[0]crcstate", .replacement = "crcstate" },
        .{ .original = "[0]crcfinal", .replacement = "crcfinal" },
        .{ .original = "[0]crclist", .replacement = "[1]crclist" },
        .{ .original = "seedcrc", .replacement = "othercrc" },
        .{ .original = "Errors detected\n", .replacement = "" },
        .{ .original = "for a valid result!", .replacement = "for a valid result! extra" },
        .{ .original = "0xe714", .replacement = "0xe714\x00" },
    }) |mutation| {
        const output = try std.mem.replaceOwned(u8, a, fixtures.stdout, mutation.original, mutation.replacement);
        defer a.free(output);
        try rejectedOutput(output);
    }
    for ([_][]const u8{
        "[0]crclist : 0xe714\n",                       "seedcrc : 0xe9f5\n",     "Errors detected\n",
        "ERROR! list crc 0xdead - should be 0xe714\n", "ERROR! other failure\n", "unrecognized output\n",
        "\x00\n",                                      "\xff\n",                 "[1]crclist : 0xe714\n",
    }) |extra| {
        const output = try std.mem.concat(a, u8, &.{ fixtures.stdout, extra });
        defer a.free(output);
        try rejectedOutput(output);
    }
    try rejectedOutput(fixtures.stdout[0 .. fixtures.stdout.len - 1]);
    try rejectedOutput("");
}

test "prepared identity requires typed pins, refuses duplicate nested keys and oversized input" {
    var parsed = try validator.records.PreparedIdentity.parse(a, fixtures.identity_json);
    defer parsed.deinit();
    try t.expectEqualStrings(fixtures.identity.coremark_wasm, parsed.value.coremark_wasm);
    try t.expectEqual(true, parsed.value.minimal_wasi);
    const extension = try std.mem.replaceOwned(u8, a, fixtures.identity_json, "\"files\":{", "\"additional\":42,\"files\":{");
    defer a.free(extension);
    var accepted = try validator.records.PreparedIdentity.parse(a, extension);
    accepted.deinit();
    for ([_]struct { original: []const u8, replacement: []const u8 }{
        .{ .original = "\"minimal_wasi\":true", .replacement = "\"minimal_wasi\":1" },
        .{ .original = "\"minimal_wasi\":true", .replacement = "\"minimal_wasi\":\"true\"" },
        .{ .original = "\"tiny.wasm\":", .replacement = "\"tiny.wasm\":\"0\",\"tiny.wasm\":" },
        .{ .original = "\"files\":{", .replacement = "\"files\":{},\"fi\\u006ces\":{" },
        .{ .original = "\"coremark.wasm\":", .replacement = "\"coremark.wasm\":false,\"unused\":" },
        .{ .original = "\"tiny.cwasm\":\"111", .replacement = "\"tiny.cwasm\":\"FFF" },
    }) |mutation| {
        const source = try std.mem.replaceOwned(u8, a, fixtures.identity_json, mutation.original, mutation.replacement);
        defer a.free(source);
        if (validator.records.PreparedIdentity.parse(a, source)) |result| {
            var unexpected = result;
            unexpected.deinit();
            return error.InvalidIdentityAccepted;
        } else |_| {}
    }
    try t.expectError(error.InputTooLarge, validator.records.PreparedIdentity.parse(a, " " ** (64 * 1024 + 1)));
}

test "shared tiny parser accepts app CoreMark, direct tiny, and normalized boot framing" {
    const raw = try fixtures.serial(a, true);
    defer a.free(raw);
    const result = try validator.tiny.checkSerial(a, raw, fixtures.identity, .{});
    try t.expectEqual(@as(u64, 4096), result.system_page_table_bytes);
    try t.expectEqualStrings(fixtures.identity.tiny_wasm, result.wasm_sha256);
    try refused(raw, fixtures.identity, .{ .scope = .direct });
    var tiny_identity = fixtures.identity;
    tiny_identity.minimal_wasi = false;
    const direct_raw = try fixtures.serial(a, false);
    defer a.free(direct_raw);
    _ = try validator.tiny.checkSerial(a, direct_raw, tiny_identity, .{ .scope = .direct });
    _ = try validator.tiny.checkSerial(a, direct_raw, tiny_identity, .{});
    const framed = try std.mem.replaceOwned(u8, a, direct_raw, "\n", "\x1b[0m\r\n\x00");
    defer a.free(framed);
    _ = try validator.tiny.checkSerial(a, framed, tiny_identity, .{ .scope = .direct });
    const legacy = try std.mem.replaceOwned(u8, a, direct_raw, "Powered by\n", "Powered by\nUsing legacy xAPIC MMIO\n");
    defer a.free(legacy);
    _ = try validator.tiny.checkSerial(a, legacy, tiny_identity, .{ .legacy_apic = .required });
    try refused(legacy, tiny_identity, .{ .legacy_apic = .forbidden });
    try refused(direct_raw, tiny_identity, .{ .legacy_apic = .required });
    const duplicate_legacy = try std.mem.replaceOwned(u8, a, legacy, "Using legacy xAPIC MMIO\n", "Using legacy xAPIC MMIO\nUsing legacy xAPIC MMIO\n");
    defer a.free(duplicate_legacy);
    try refused(duplicate_legacy, tiny_identity, .{ .legacy_apic = .required });
}

test "exact tiny fields and envelope refuse bad types, bytes and ordering" {
    const raw = try fixtures.serial(a, false);
    defer a.free(raw);
    var identity = fixtures.identity;
    identity.minimal_wasi = false;
    for ([_]struct { before: []const u8, after: []const u8 }{
        .{ .before = "\"answer\":42", .after = "\"answer\":43" },
        .{ .before = "\"checks\":2", .after = "\"checks\":true" },
        .{ .before = "\"version\":1", .after = "\"version\":1.0" },
        .{ .before = "\"detail\":2", .after = "\"detail\":0" },
        .{ .before = "\"frame_bytes\":0", .after = "\"frame_bytes\":4096" },
        .{ .before = "\"allocation_bytes\":0", .after = "\"allocation_bytes\":1" },
        .{ .before = "\"system_page_table_bytes\":4096", .after = "\"system_page_table_bytes\":3" },
        .{ .before = "\"platform_status\":0", .after = "\"platform_status\":-12" },
        .{ .before = "\"error_name\":\"\"", .after = "\"error_name\":\"error\"" },
        .{ .before = "\"runtime_sha256\":\"222", .after = "\"runtime_sha256\":\"999" },
        .{ .before = "\"version\":1", .after = "\"version\":1,\"version\":1" },
        .{ .before = "\"version\":1", .after = "\"version\":1,\"ver\\u0073ion\":1" },
        .{ .before = "\"answer\":42", .after = "\"answer\":42,\"unexpected\":0" },
        .{ .before = "WAMR_NATIVE_COMPUTE=", .after = "noise WAMR_NATIVE_COMPUTE=" },
        .{ .before = "WAMR_NATIVE_AOT_OK", .after = "noise WAMR_NATIVE_AOT_OK" },
        .{ .before = "main returned 0", .after = "main returned -1" },
        .{ .before = "Calling main(", .after = "not calling main(" },
        .{ .before = "Hyper-V SynIC:", .after = "missing SynIC" },
    }) |mutation| {
        const bad = try std.mem.replaceOwned(u8, a, raw, mutation.before, mutation.after);
        defer a.free(bad);
        try refused(bad, identity, .{});
    }
    for ([_][]const u8{
        "WAMR_NATIVE_WASI={}\n",                   "WAMR_NATIVE_AOT_FAIL", "HYPERV_ACCEPTANCE",
        "Unikraft Crash",                          "WAMR_NATIVE_COMPUTE=", "Calling main(",
        "WAMR_NATIVE_AOT_OK answer=42 teardown=0",
    }) |extra| {
        const bad = try std.mem.concat(a, u8, &.{ raw, extra });
        defer a.free(bad);
        try refused(bad, identity, .{ .scope = .direct });
    }
    try t.expectError(error.EvidenceIncomplete, validator.tiny.checkSerial(a, "", identity, .{ .scope = .direct }));
    try t.expectError(error.EvidenceIncomplete, validator.tiny.checkSerial(a, "Calling main(0, 0)\n", identity, .{ .scope = .direct }));
    try refused("x" ** (4 * 1024 * 1024), identity, .{});
    const record_at = std.mem.indexOf(u8, raw, validator.tiny.prefix).?;
    const end = std.mem.indexOfPos(u8, raw, record_at, "\n").? + 1;
    const marker_at = std.mem.indexOf(u8, raw, validator.tiny.marker).?;
    const wrong_order = try std.mem.concat(a, u8, &.{
        raw[0..record_at],   raw[marker_at .. marker_at + validator.tiny.marker.len + 1],
        raw[record_at..end], raw[marker_at + validator.tiny.marker.len + 1 ..],
    });
    defer a.free(wrong_order);
    try refused(wrong_order, identity, .{});
}

test "two CoreMarks require independent bytes, zero output errors and exact terminal" {
    const raw = try fixtures.serial(a, true);
    defer a.free(raw);
    for ([_]struct { before: []const u8, after: []const u8 }{
        .{ .before = "\"crc_ok\":true", .after = "\"crc_ok\":false" },
        .{ .before = "\"terminal\":2", .after = "\"terminal\":1" },
        .{ .before = "\"terminal\":2", .after = "\"terminal\":2,\"detail\":4294967295" },
        .{ .before = "\"detail\":0", .after = "\"detail\":4294967295" },
        .{ .before = "\"realtime_supported\":true", .after = "\"realtime_supported\":false" },
        .{ .before = "\"output_error\":0", .after = "\"output_error\":1" },
        .{ .before = "\"pending_stdout\":0", .after = "\"pending_stdout\":1" },
        .{ .before = "\"unsupported_clock\":0", .after = "\"unsupported_clock\":1" },
        .{ .before = "\"stderr_base64\":\"\"", .after = "\"stderr_base64\":\"RVJST1IhCg==\"" },
        .{ .before = "\"stdout_base64\":\"", .after = "\"stdout_base64\":\"@@" },
        .{ .before = "\"workload\":\"coremark\"", .after = "\"workload\":\"coremark-nofp\"" },
        .{ .before = "\"wasm_sha256\":\"333", .after = "\"wasm_sha256\":\"999" },
        .{ .before = "\"version\":1", .after = "\"version\":1,\"version\":1" },
        .{ .before = "\"output_error\":0", .after = "\"output_error\":false" },
    }) |mutation| {
        const bad = try std.mem.replaceOwned(u8, a, raw, mutation.before, mutation.after);
        defer a.free(bad);
        refused(bad, fixtures.identity, .{}) catch |err| {
            std.debug.print("unexpected CoreMark acceptance after {s} => {s}\n", .{ mutation.before, mutation.after });
            return err;
        };
    }
    const wrong = try std.mem.replaceOwned(u8, a, fixtures.stdout, "0xe714", "0xdead");
    defer a.free(wrong);
    const encoded = try a.alloc(u8, std.base64.standard.Encoder.calcSize(wrong.len));
    defer a.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, wrong);
    const original = try a.alloc(u8, std.base64.standard.Encoder.calcSize(fixtures.stdout.len));
    defer a.free(original);
    _ = std.base64.standard.Encoder.encode(original, fixtures.stdout);
    const bad_output = try std.mem.replaceOwned(u8, a, raw, original, encoded);
    defer a.free(bad_output);
    try refused(bad_output, fixtures.identity, .{});
    const empty_output = try std.mem.replaceOwned(u8, a, raw, original, "");
    defer a.free(empty_output);
    try refused(empty_output, fixtures.identity, .{});
    const wasi_first = std.mem.indexOf(u8, raw, validator.tiny.wasi_prefix).?;
    const wasi_second = std.mem.indexOfPos(u8, raw, wasi_first + 1, validator.tiny.wasi_prefix).?;
    const second_end = std.mem.indexOfPos(u8, raw, wasi_second, "\n").? + 1;
    const missing_wasi = try std.mem.concat(a, u8, &.{ raw[0..wasi_first], raw[wasi_second..] });
    defer a.free(missing_wasi);
    try refused(missing_wasi, fixtures.identity, .{});
    const reversed_wasi = try std.mem.concat(a, u8, &.{
        raw[0..wasi_first], raw[wasi_second..second_end], raw[wasi_first..wasi_second], raw[second_end..],
    });
    defer a.free(reversed_wasi);
    try refused(reversed_wasi, fixtures.identity, .{});
    const compute_at = std.mem.indexOfPos(u8, raw, second_end, validator.tiny.prefix).?;
    const compute_end = std.mem.indexOfPos(u8, raw, compute_at, "\n").? + 1;
    const later_wasi = try std.mem.concat(a, u8, &.{
        raw[0..wasi_first], raw[compute_at..compute_end], raw[wasi_first..compute_at], raw[compute_end..],
    });
    defer a.free(later_wasi);
    _ = try validator.tiny.checkSerial(a, later_wasi, fixtures.identity, .{});
    const extended = try std.mem.replaceOwned(u8, a, raw, "\"correctness_only\":true,", "\"correctness_only\":true,\"realtime_capability_version\":1,");
    defer a.free(extended);
    _ = try validator.tiny.checkSerial(a, extended, fixtures.identity, .{});
    const too_long = try a.alloc(u8, 4097);
    defer a.free(too_long);
    @memset(too_long, 'x');
    const oversized = try a.alloc(u8, std.base64.standard.Encoder.calcSize(too_long.len));
    defer a.free(oversized);
    _ = std.base64.standard.Encoder.encode(oversized, too_long);
    const invalid_size = try std.mem.replaceOwned(u8, a, raw, original, oversized);
    defer a.free(invalid_size);
    try refused(invalid_size, fixtures.identity, .{});
}

test "seeded mutations of required keys cannot become alternate valid records" {
    const raw = try fixtures.serial(a, false);
    defer a.free(raw);
    var identity = fixtures.identity;
    identity.minimal_wasi = false;
    var prng: std.Random.DefaultPrng = .init(188);
    const fields = [_][]const u8{
        "\"version\"",     "\"checks\"",           "\"terminal\"",         "\"answer\"",                  "\"reserved_bytes\"",
        "\"frame_bytes\"", "\"accessible_bytes\"", "\"allocation_bytes\"", "\"system_page_table_bytes\"", "\"runtime_sha256\"",
        "\"wasm_sha256\"",
    };
    for (0..192) |_| {
        const key = fields[prng.random().uintLessThan(usize, fields.len)];
        const mutated = try a.dupe(u8, raw);
        defer a.free(mutated);
        const at = std.mem.indexOf(u8, mutated, key).? + 1;
        mutated[at] = if (mutated[at] == 'X') 'Y' else 'X';
        try refused(mutated, identity, .{});
    }
}
