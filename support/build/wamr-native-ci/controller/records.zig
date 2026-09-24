// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const contracts = core.contracts;
const Sha256 = core.Sha256;
const profile = @import("profile.zig");

pub const max_record_bytes = 4 * 1024 * 1024;
const required_common = [_][]const u8{
    "build-start.json", "build.json", "boot-inputs.json", "package.json",
};
const required_v2 = [_][]const u8{
    "qcow2-finalization-intent.json", "qcow2-finalization.json",
    "qcow2-acceptance.json",          "fixed-vhd-derivation-intent.json",
    "fixed-vhd-derivation-gate.json", "fixed-vhd-derivation.json",
    "final-inspection.json",
};
const public_stages = [_][]const u8{
    "adapter",      "local-boot-tool", "fixtures", "prepare", "config",
    "native-image", "package",         "inspect",
};

pub const Result = struct {
    set: profile.CompatibleRecordSet,
    records: std.json.ObjectMap,
};

pub const AcceptedResult = struct {
    document: contracts.Document,
    value: Result,

    pub fn deinit(self: *AcceptedResult) void {
        self.document.deinit();
        self.* = undefined;
    }
};

pub fn parseCanonicalResult(allocator: std.mem.Allocator, bytes: []const u8) !AcceptedResult {
    const document = try contracts.Document.parse(allocator, bytes, .{
        .bytes = max_record_bytes,
        .depth = 32,
        .items = 4096,
        .tokens = 65536,
    });
    errdefer document.deinit();
    try document.requireCanonical(allocator, bytes);
    return .{ .document = document, .value = try readResult(document.value()) };
}

/// The same canonical encoder as the shared contracts, including its terminal LF.
pub fn canonicalAlloc(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    const document = try contracts.Document.parse(allocator, raw, .{
        .bytes = max_record_bytes,
        .depth = 32,
        .items = 4096,
        .tokens = 65536,
    });
    defer document.deinit();
    return document.canonicalAlloc(allocator);
}

/// Python's record_digest hashes compact sorted-key JSON without the file LF.
pub fn identity(allocator: std.mem.Allocator, raw: []const u8) !contracts.Sha256 {
    const encoded = try canonicalAlloc(allocator, raw);
    defer allocator.free(encoded);
    var hash: contracts.Sha256 = undefined;
    Sha256.hash(encoded[0 .. encoded.len - 1], &hash, .{});
    return hash;
}

pub fn fileIdentity(bytes: []const u8) contracts.Sha256 {
    var hash: contracts.Sha256 = undefined;
    Sha256.hash(bytes, &hash, .{});
    return hash;
}

pub fn readResult(value: std.json.Value) !Result {
    const object = switch (value) {
        .object => |map| map,
        else => return error.InvalidResult,
    };
    const version = try contracts.integer(u32, object.get("schema_version") orelse return error.InvalidResult);
    const set = try profile.recordSet(version, if (object.get("profile")) |v| try contracts.string(v) else null);
    _ = try contracts.exactFields(value, if (set == .tiny_v1_legacy)
        &.{ "schema_version", "scope", "passed", "hardware_acceptance", "cloud_authority", "benchmark", "workload", "modes", "records" }
    else
        &.{ "schema_version", "profile", "scope", "passed", "hardware_acceptance", "cloud_authority", "benchmark", "workload", "modes", "records" });
    try literal(object, "scope", "local_native_compute_only");
    try literal(object, "hardware_acceptance", "not_established");
    try literal(object, "cloud_authority", "not_admitted");
    try literal(object, "benchmark", "not_measured");
    try literal(object, "workload", "tiny");
    if (object.get("passed").? != .bool or !object.get("passed").?.bool)
        return error.InvalidResult;
    const list = switch (object.get("modes").?) {
        .array => |array| array.items,
        else => return error.InvalidModes,
    };
    const expected_modes = profile.modes(set);
    if (list.len != expected_modes.len) return error.InvalidModes;
    for (list, expected_modes) |mode, expected| {
        if (!std.mem.eql(u8, try contracts.string(mode), @tagName(expected)))
            return error.InvalidModes;
    }
    const records = switch (object.get("records").?) {
        .object => |map| map,
        else => return error.InvalidRecords,
    };
    if (records.count() < 8 or records.count() > 64 or records.contains("result.json"))
        return error.InvalidRecords;
    for (records.keys(), records.values()) |name, digest| {
        if (!allowedName(set, name)) return error.InvalidRecordName;
        _ = try contracts.parseSha256(try contracts.string(digest));
    }
    for (required_common) |name| if (!records.contains(name)) return error.MissingRecord;
    for (expected_modes) |mode| {
        var buf: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&buf, "{s}-compute.json", .{@tagName(mode)});
        if (!records.contains(name)) return error.MissingRecord;
    }
    if (set == .tiny_v2_qcow2_derived_vhd)
        for (required_v2) |name| {
            if (!records.contains(name)) return error.MissingRecord;
        };
    return .{ .set = set, .records = records };
}

pub fn verifyRecord(result: Result, name: []const u8, bytes: []const u8) !void {
    const digest = try contracts.parseSha256(try contracts.string(result.records.get(name) orelse
        return error.MissingRecord));
    const actual = fileIdentity(bytes);
    if (!std.crypto.timing_safe.eql(contracts.Sha256, digest, actual))
        return error.RecordChanged;
}

fn literal(object: std.json.ObjectMap, key: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, try contracts.string(object.get(key) orelse return error.InvalidResult), expected))
        return error.InvalidResult;
}

fn allowedName(set: profile.CompatibleRecordSet, name: []const u8) bool {
    for (required_common) |expected| if (std.mem.eql(u8, name, expected)) return true;
    if (set == .tiny_v2_qcow2_derived_vhd)
        for (required_v2) |expected| {
            if (std.mem.eql(u8, name, expected)) return true;
        };
    for (profile.modes(set)) |mode| {
        var buf: [64]u8 = undefined;
        const expected = std.fmt.bufPrint(&buf, "{s}-compute.json", .{@tagName(mode)}) catch unreachable;
        if (std.mem.eql(u8, name, expected) or
            std.mem.eql(u8, name, std.fmt.bufPrint(&buf, "command-{s}.json", .{@tagName(mode)}) catch unreachable))
            return true;
    }
    for (public_stages) |stage| {
        var buf: [64]u8 = undefined;
        const expected = std.fmt.bufPrint(&buf, "command-{s}.json", .{stage}) catch unreachable;
        if (std.mem.eql(u8, name, expected)) return true;
    }
    if (set == .tiny_v2_qcow2_derived_vhd) {
        if (std.mem.eql(u8, name, "command-finalize-qcow2.json") or
            std.mem.eql(u8, name, "command-derive-fixed-vhd.json"))
            return true;
    }
    return false;
}
