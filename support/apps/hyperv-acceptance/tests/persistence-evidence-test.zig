// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const evidence = @import("evidence");
const t = std.testing;
const a = t.allocator;

const input: evidence.EvidenceInput = .{
    .run_id = "00112233445566778899aabbccddeeff".*,
    .disk_id = "102132435465768798a9bacbdcedfe0f".*,
    .sectors = 8388608,
    .lun = 7,
};
const start = "HYPERV_PERSISTENCE START PASS run=00112233445566778899aabbccddeeff address=0:0:7 sectors=8388608 sector_size=512\n";
const identity = "UK_HYPERV_PERSISTENCE_IDENTITY:1:2:00112233445566778899aabbccddeeff:102132435465768798a9bacbdcedfe0f:02000000000000000000000000000000:4:5:7:8388608:512:1:1:3:0:02\n";
const final = "HYPERV_PERSISTENCE FINAL PASS rc=0\nmain returned 0\n";
const first = start ++
    "HYPERV_PERSISTENCE SELECT PASS id=0 controller=1 state=0\n" ++ identity ++
    "HYPERV_PERSISTENCE BOOT1_WRITE PASS run=00112233445566778899aabbccddeeff\n" ++
    "UK_HYPERV_PERSISTENCE_IO:1:1:00112233445566778899aabbccddeeff:5:3:receipt-verified\n" ++
    "UK_HYPERV_PERSISTENCE_BOOT1_COMPLETE:00112233445566778899aabbccddeeff\n" ++ final;
const second = start ++
    "HYPERV_PERSISTENCE SELECT PASS id=0 controller=1 state=2\n" ++ identity ++
    "HYPERV_PERSISTENCE BOOT2_READ PASS run=00112233445566778899aabbccddeeff\n" ++
    "UK_HYPERV_PERSISTENCE_IO:1:2:00112233445566778899aabbccddeeff:0:0:receipt-verified\n" ++
    "UK_HYPERV_PERSISTENCE_BOOT2_COMPLETE:00112233445566778899aabbccddeeff\n" ++ final;

test "typed workload input accepts the unchanged two boot serial contract" {
    const boot1 = try evidence.parseWorkload(first, 1, input, null);
    const boot2 = try evidence.parseWorkload(second, 2, input, boot1);
    try t.expectEqual(@as(u8, 5), boot1.writes);
    try t.expectEqual(@as(u8, 3), boot1.flushes);
    try t.expectEqual(@as(u8, 0), boot2.writes);
    try t.expectEqual(@as(u8, 0), boot2.flushes);
    try t.expectEqualDeep(boot1.identity, boot2.identity);
    try t.expectEqual(@as(u8, 4), boot1.identity.path);
    try t.expectEqual(@as(u8, 5), boot1.identity.target);
}

test "accumulated prefix and separately attributed fresh capture retain identical evidence" {
    const boot1 = try evidence.parseWorkload(first, 1, input, null);
    const suffix = try evidence.boot2Suffix(first ++ second, boot1);
    try t.expectEqualStrings(second, suffix);
    const accumulated = try evidence.parseWorkload(suffix, 2, input, boot1);
    const fresh = try evidence.parseWorkload(second, 2, input, boot1);
    try t.expectEqualDeep(accumulated, fresh);
    try t.expectError(error.SerialPrefixChanged, evidence.boot2Suffix(second ++ first, boot1));
    try t.expectError(error.EvidenceIncomplete, evidence.boot2Suffix(first, boot1));
}

test "workload parser refuses invalid phase transitions without granting another boot" {
    const boot1 = try evidence.parseWorkload(first, 1, input, null);
    const boot2 = try evidence.parseWorkload(second, 2, input, boot1);
    try t.expectError(error.InvalidBoot, evidence.parseWorkload(second, 2, input, null));
    try t.expectError(error.InvalidBoot, evidence.parseWorkload(first, 1, input, boot1));
    try t.expectError(error.InvalidBoot, evidence.parseWorkload(second, 2, input, boot2));
    try t.expectError(error.InvalidBoot, evidence.parseWorkload(second, 3, input, boot1));
    try t.expectError(error.SerialPrefixChanged, evidence.boot2Suffix(first ++ second, boot2));
}

test "workload parser refuses malformed missing duplicate truncated and failed evidence" {
    try t.expectError(error.EvidenceIncomplete, evidence.parseWorkload(first[0 .. first.len - 1], 1, input, null));
    try t.expectError(error.InvalidEvidenceOrder, evidence.parseWorkload(first ++ first, 1, input, null));
    try t.expectError(error.InvalidEvidenceOrder, evidence.parseWorkload(final, 1, input, null));
    const changes = [_]struct { from: []const u8, to: []const u8 }{
        .{ .from = ":5:3:receipt-verified", .to = ":5:2:receipt-verified" },
        .{ .from = "receipt-verified", .to = "receipt-written" },
        .{ .from = "address=0:0:7", .to = "address=0:0:8" },
        .{ .from = "sectors=8388608", .to = "sectors=8388607" },
        .{ .from = ":8388608:512:", .to = ":8388608:4096:" },
        .{ .from = "BOOT1_WRITE PASS", .to = "BOOT1_WRITE FAIL" },
        .{ .from = "FINAL PASS rc=0", .to = "FINAL FAIL rc=-5" },
        .{ .from = "main returned 0", .to = "main returned 1" },
        .{ .from = "BOOT1_COMPLETE", .to = "BOOT2_COMPLETE" },
        .{ .from = "UK_HYPERV_PERSISTENCE_IO:", .to = "UK_HYPERV_PERSISTENCE_UNKNOWN:" },
        .{ .from = "02000000000000000000000000000000", .to = "00000000000000000000000000000000" },
    };
    for (changes) |change| {
        const bad = try std.mem.replaceOwned(u8, a, first, change.from, change.to);
        defer a.free(bad);
        if (evidence.parseWorkload(bad, 1, input, null)) |_| return error.AcceptedInvalidEvidence else |_| {}
    }
}

test "workload parser refuses identity drift and any Boot2 workload mutation ledger" {
    const boot1 = try evidence.parseWorkload(first, 1, input, null);
    const changes = [_]struct { from: []const u8, to: []const u8 }{
        .{ .from = "02000000000000000000000000000000", .to = "03000000000000000000000000000000" },
        .{ .from = ":4:5:7:", .to = ":4:6:7:" },
        .{ .from = ":1:1:3:0:02", .to = ":1:1:3:0:03" },
        .{ .from = ":0:0:receipt-verified", .to = ":1:0:receipt-verified" },
        .{ .from = ":0:0:receipt-verified", .to = ":0:1:receipt-verified" },
    };
    for (changes) |change| {
        const bad = try std.mem.replaceOwned(u8, a, second, change.from, change.to);
        defer a.free(bad);
        if (evidence.parseWorkload(bad, 2, input, boot1)) |_| return error.AcceptedInvalidEvidence else |_| {}
    }
    try t.expectError(error.WrongBootState, evidence.parseWorkload(first, 2, input, boot1));
    var wrong = input;
    wrong.run_id[0] = '1';
    try t.expectError(error.WrongIdentity, evidence.parseWorkload(first, 1, wrong, null));
    wrong = input;
    wrong.disk_id[0] = '2';
    try t.expectError(error.WrongIdentity, evidence.parseWorkload(first, 1, wrong, null));
    wrong = input;
    wrong.sectors += 1;
    try t.expectError(error.WrongGeometry, evidence.parseWorkload(first, 1, wrong, null));
}
