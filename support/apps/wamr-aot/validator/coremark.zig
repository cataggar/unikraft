// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const c = @import("hyperv_core").contracts;
const records = @import("records.zig");
const base64 = @import("base64.zig");

const required = [_]struct { key: []const u8, value: []const u8 }{
    .{ .key = "Iterations", .value = "100" },
    .{ .key = "seedcrc", .value = "0xe9f5" },
    .{ .key = "[0]crclist", .value = "0xe714" },
    .{ .key = "[0]crcmatrix", .value = "0x1fd7" },
    .{ .key = "[0]crcstate", .value = "0x8e3a" },
    .{ .key = "[0]crcfinal", .value = "0x988c" },
};
const metadata = [_][]const u8{
    "CoreMark Size",    "Total ticks",    "Total time (secs)", "Iterations/Sec",
    "Compiler version", "Compiler flags", "Memory location",
};
const markers = [_][]const u8{
    "2K performance run parameters for coremark.",
    "ERROR! Must execute for at least 10 secs for a valid result!",
    "Errors detected",
};

pub fn validateOutput(output: []const u8) !void {
    if (output.len == 0 or output[output.len - 1] != '\n') return error.IncompleteCoreMark;
    var fields_seen: u16 = 0;
    var markers_seen: u8 = 0;
    var lines = std.mem.splitScalar(u8, output[0 .. output.len - 1], '\n');
    while (lines.next()) |raw| {
        for (raw) |byte| {
            if (!((byte >= 32 and byte <= 126) or byte == '\t' or byte == '\r'))
                return error.InvalidCoreMarkOutput;
        }
        const without_cr = if (std.mem.endsWith(u8, raw, "\r")) raw[0 .. raw.len - 1] else raw;
        const line = std.mem.trim(u8, without_cr, " \t");
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const key = std.mem.trim(u8, line[0..colon], " \t");
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            for (required, 0..) |field, index| {
                if (std.mem.eql(u8, key, field.key)) {
                    if (fields_seen & (@as(u16, 1) << @intCast(index)) != 0 or
                        !std.mem.eql(u8, value, field.value)) return error.InvalidCoreMarkField;
                    fields_seen |= @as(u16, 1) << @intCast(index);
                    break;
                }
            } else {
                for (metadata, 0..) |field, index| {
                    if (std.mem.eql(u8, key, field)) {
                        const bit = @as(u16, 1) << @intCast(index + required.len);
                        if (fields_seen & bit != 0) return error.InvalidCoreMarkField;
                        fields_seen |= bit;
                        break;
                    }
                } else return error.InvalidCoreMarkField;
            }
        } else {
            for (markers, 0..) |marker, index| {
                if (std.mem.eql(u8, line, marker)) {
                    const bit = @as(u8, 1) << @intCast(index);
                    if (markers_seen & bit != 0) return error.InvalidCoreMarkOutput;
                    markers_seen |= bit;
                    break;
                }
            } else return error.InvalidCoreMarkOutput;
        }
    }
    if (fields_seen & 0x3f != 0x3f or markers_seen != 0x7)
        return error.IncompleteCoreMark;
}

pub fn validateRecord(allocator: std.mem.Allocator, value: std.json.Value, name: []const u8, wasm: []const u8, cwasm: []const u8) !void {
    const fields = try records.object(value);
    try records.intEquals(fields, "version", 1);
    try records.trueField(fields, "correctness_only");
    try records.stringEquals(fields, "workload", name);
    try records.stringEquals(fields, "wasm_sha256", wasm);
    try records.stringEquals(fields, "cwasm_sha256", cwasm);
    const terminal = try c.integer(u32, try records.get(fields, "terminal"));
    const detail = try c.integer(u32, try records.get(fields, "detail"));
    if (terminal != 0 and terminal != 2 or terminal == 2 and detail != 0)
        return error.CoreMarkTermination;
    try records.trueField(fields, "crc_ok");
    try records.trueField(fields, "realtime_supported");
    inline for (.{ "output_error", "pending_stdout", "pending_stderr", "unsupported_clock" }) |field|
        try records.intEquals(fields, field, 0);
    const stdout = try base64.decode(allocator, try c.string(try records.get(fields, "stdout_base64")), 4096);
    defer allocator.free(stdout);
    const stderr = try base64.decode(allocator, try c.string(try records.get(fields, "stderr_base64")), 4096);
    defer allocator.free(stderr);
    if (stderr.len != 0) return error.CoreMarkStderr;
    try validateOutput(stdout);
}
