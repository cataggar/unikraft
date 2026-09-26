// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const ci = @import("wamr_controller");
const contracts = @import("hyperv_core").contracts;

const v1 = @embedFile("fixtures/differential/accepted-v1.json");
const v2 = @embedFile("fixtures/differential/accepted-v2.json");
const empty_evidence = "{}\n";

fn parsed(bytes: []const u8) !ci.records.AcceptedResult {
    return ci.records.parseCanonicalResult(std.testing.allocator, bytes);
}

fn mutate(source: []const u8, old: []const u8, new: []const u8) ![]u8 {
    try std.testing.expect(std.mem.indexOf(u8, source, old) != null);
    return std.mem.replaceOwned(u8, std.testing.allocator, source, old, new);
}

test "frozen v1 read-only and v2 complete acceptance records" {
    for ([_]struct {
        bytes: []const u8,
        set: ci.profile.CompatibleRecordSet,
        names: usize,
    }{
        .{ .bytes = v1, .set = .tiny_v1_legacy, .names = 8 },
        .{ .bytes = v2, .set = .tiny_v2_qcow2_derived_vhd, .names = 33 },
    }) |fixture| {
        var result = try parsed(fixture.bytes);
        defer result.deinit();
        try std.testing.expectEqual(fixture.set, result.value.set);
        try std.testing.expectEqual(fixture.names, result.value.records.count());
        for (result.value.records.keys()) |name|
            try ci.records.verifyRecord(result.value, name, empty_evidence);
        try std.testing.expectError(error.MissingRecord, ci.records.verifyRecord(result.value, "result.json", empty_evidence));
        try std.testing.expectError(error.RecordChanged, ci.records.verifyRecord(result.value, "build.json", "{}"));
    }
    try std.testing.expectEqual(ci.profile.CompatibleRecordSet.tiny_v2_qcow2_derived_vhd, ci.profile.productionSet(.tiny_exact_v2));
    try std.testing.expectError(error.UnsupportedRecordSet, ci.profile.recordSet(1, "qcow2-derived-vhd"));
    try std.testing.expectError(error.UnsupportedRecordSet, ci.profile.recordSet(2, "coremark"));
}

test "golden parser refuses missing stages, rehashed fields and downgrades" {
    const a = std.testing.allocator;
    for ([_]struct { source: []const u8, old: []const u8, new: []const u8 }{
        .{ .source = v2, .old = ",\"command-config.json\":\"ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356", .new = "" },
        .{ .source = v2, .old = "\"profile\":\"qcow2-derived-vhd\"", .new = "\"profile\":\"coremark\"" },
        .{ .source = v1, .old = "\"schema_version\":1", .new = "\"schema_version\":2" },
        .{ .source = v2, .old = "\"passed\":true", .new = "\"passed\":1" },
        .{ .source = v2, .old = "\"hardware_acceptance\":\"not_established\"", .new = "\"hardware_acceptance\":\"established\"" },
        .{ .source = v2, .old = "\"modes\":[\"raw-x2apic\",\"raw-legacy-apic\"", .new = "\"modes\":[\"raw-legacy-apic\",\"raw-x2apic\"" },
        .{ .source = v2, .old = "\"build.json\":", .new = "\"../build.json\":" },
    }) |change| {
        const raw = try mutate(change.source, change.old, change.new);
        defer a.free(raw);
        if (parsed(raw)) |accepted| {
            var result = accepted;
            result.deinit();
            return error.ExpectedRefusal;
        } else |_| {}
    }
    const bad = try mutate(v2, "\"build.json\":\"ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356\"", "\"build.json\":\"0000000000000000000000000000000000000000000000000000000000000000\"");
    defer a.free(bad);
    var forged = try parsed(bad);
    defer forged.deinit();
    try std.testing.expectError(error.RecordChanged, ci.records.verifyRecord(forged.value, "build.json", empty_evidence));
}

test "canonical JSON refuses duplicate keys and overflow, binds LF separately" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.DuplicateField, ci.records.canonicalAlloc(a, "{\"x\":1,\"x\":1}"));
    try std.testing.expectError(error.IntegerOverflow, ci.records.canonicalAlloc(a, "{\"x\":18446744073709551616}"));
    try std.testing.expectError(error.NonCanonical, parsed(v2[0 .. v2.len - 1]));
    const record_digest = try ci.records.identity(a, "{\"z\":1,\"a\":2}");
    const file_digest = ci.records.fileIdentity("{\"a\":2,\"z\":1}\n");
    try std.testing.expect(!std.mem.eql(u8, &record_digest, &file_digest));
    const expected = try contracts.parseSha256("ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356");
    const actual = ci.records.fileIdentity(empty_evidence);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}
