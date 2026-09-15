// SPDX-License-Identifier: BSD-3-Clause
// This executable has no file, process, network, or credential operations.
const std = @import("std");
const validation = @import("main.zig");
const prep = @import("preparation");
const evidence = @import("evidence");

fn expect(ok: bool) !void {
    if (!ok) return error.FixtureFailed;
}

const serial_input: evidence.EvidenceInput = .{
    .run_id = "11111111111111111111111111111111".*,
    .disk_id = "22222222222222222222222222222222".*,
    .sectors = 8388608,
    .lun = 7,
};

fn serialLog(comptime boot: u8) []const u8 {
    return "UK_HYPERV_PLATFORM_READY\n" ++
        "HYPERV_PERSISTENCE START PASS run=11111111111111111111111111111111 address=0:0:7 sectors=8388608 sector_size=512\n" ++
        "HYPERV_PERSISTENCE SELECT PASS id=1 controller=1 state=" ++ (if (boot == 1) "0" else "2") ++ "\n" ++
        "UK_HYPERV_PERSISTENCE_IDENTITY:1:2:11111111111111111111111111111111:22222222222222222222222222222222:33333333333333333333333333333333:0:0:7:8388608:512:16:1:3:0:44444444444444444444444444444444\n" ++
        "HYPERV_PERSISTENCE " ++ (if (boot == 1) "BOOT1_WRITE" else "BOOT2_READ") ++ " PASS run=11111111111111111111111111111111\n" ++
        "UK_HYPERV_PERSISTENCE_IO:1:" ++ (if (boot == 1) "1:11111111111111111111111111111111:5:3:" else "2:11111111111111111111111111111111:0:0:") ++ "receipt-verified\n" ++
        "UK_HYPERV_PERSISTENCE_BOOT" ++ (if (boot == 1) "1" else "2") ++ "_COMPLETE:11111111111111111111111111111111\n" ++
        "HYPERV_PERSISTENCE FINAL PASS rc=0\nmain returned 0\n";
}

fn serialCheck(mode: validation.SerialMode, first: []const u8, full: ?[]const u8) !void {
    const boot1 = try validation.serialFirst(first, mode, serial_input);
    if (full) |second| try validation.serialSecond(second, mode, serial_input, boot1);
}

fn serialError(expected: anyerror, mode: validation.SerialMode, first: []const u8, full: ?[]const u8) !void {
    if (serialCheck(mode, first, full)) |_| return error.AcceptedInvalidSerial else |err| try expect(err == expected);
}

fn serialFixtures(a: std.mem.Allocator) !void {
    const first = comptime serialLog(1);
    const second = comptime serialLog(2);
    const padding = "\x00" ** 464;
    const padded = first ++ padding;
    const platform = "UK_HYPERV_PLATFORM_READY\n";
    inline for (.{ validation.SerialMode.per_boot, .cumulative, .azure_cumulative }) |mode| {
        const boot1 = try validation.serialFirst(padded, mode, serial_input);
        const prefix = if (mode == .azure_cumulative) first else padded;
        var sha: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(prefix, &sha, .{});
        try expect(boot1.boot == 1 and boot1.writes == 5 and boot1.flushes == 3 and
            boot1.bytes == prefix.len and std.mem.eql(u8, &boot1.sha256, &std.fmt.bytesToHex(sha, .lower)));
        try serialCheck(mode, padded, if (mode == .per_boot) second else padded ++ second);
        try serialCheck(mode, padded, if (mode == .per_boot) second ++ padding else padded ++ second ++ padding);
        try serialError(error.EvidenceIncomplete, mode, "", null);
        try serialError(error.EvidenceIncomplete, mode, padding, null);
        try serialError(error.EvidenceIncomplete, mode, platform ++ padding, null);
        try serialError(error.PlatformNotReady, mode, first[platform.len..] ++ padding, null);
        try serialError(error.EvidenceIncomplete, mode, first ++ " \x00", null);
        try serialError(error.EvidenceIncomplete, mode, first ++ "\x1b\x00", null);
        try serialError(error.EvidenceIncomplete, mode, padded, "");
        try serialError(if (mode == .per_boot) error.WrongBootState else error.EvidenceIncomplete, mode, padded, padded);
    }
    // No opt-in fallback: overwritten padding is rejected in both old modes.
    try serialError(error.WrongBootState, .per_boot, padded, first ++ second);
    try serialError(error.SerialPrefixChanged, .cumulative, padded, first ++ second);
    try serialError(error.SerialPrefixChanged, .cumulative, padded, first);
    try serialError(error.SerialPrefixChanged, .cumulative, padded, first ++ "\x00");
    try serialCheck(.azure_cumulative, padded, first ++ second);
    try serialCheck(.azure_cumulative, padded, first ++ second ++ padding);
    try serialCheck(.azure_cumulative, first, first ++ second);
    inline for (.{ first, first ++ "\x00", padded, padded ++ padding }) |unchanged|
        try serialError(error.EvidenceIncomplete, .azure_cumulative, padded, unchanged);
    try serialError(error.SerialPrefixChanged, .azure_cumulative, padded, first[0 .. first.len - 1]);
    try serialError(error.SerialPrefixChanged, .azure_cumulative, padded, second);
    try serialError(error.SerialPrefixChanged, .azure_cumulative, padded, "X" ++ first[1..] ++ second);
    try serialError(error.WrongBootState, .azure_cumulative, padded, first ++ first);
    try serialError(error.EvidenceIncomplete, .azure_cumulative, padded, first ++ platform ++ padding);
    try serialError(error.PlatformNotReady, .azure_cumulative, padded, first ++ second[platform.len..]);
    try serialError(error.GuestFailure, .azure_cumulative, padded, first ++ "UK_HYPERV_ACCEPTANCE_FAIL:fixture\n" ++ second);
    try serialError(error.GuestFailure, .azure_cumulative, padded, first ++ second ++ "Unikraft Crash\n");

    // Interior NULs, whitespace and ANSI bytes remain in the exact hash gate.
    const decorated = "\x00banner\x00 \t\x1b[0m\n" ++ first ++ "\x1b[0m";
    try serialCheck(.azure_cumulative, decorated ++ padding, decorated ++ second);
    const decorated_first = try validation.serialFirst(decorated ++ padding, .azure_cumulative, serial_input);
    try expect(decorated_first.bytes == decorated.len);
    inline for (.{ "\x00", " ", "\t", "\x1b[0m" }) |removed| {
        const drift = try std.mem.replaceOwned(u8, a, decorated, removed, "");
        defer a.free(drift);
        const full = try std.mem.concat(a, u8, &.{ drift, second });
        defer a.free(full);
        try serialError(error.SerialPrefixChanged, .azure_cumulative, decorated ++ padding, full);
    }
    try serialError(error.SerialPrefixChanged, .azure_cumulative, first ++ "\x1b[0m" ++ padding, first ++ second);

    const mutations = .{
        .{ "44444444444444444444444444444444", "55555555555555555555555555555555", error.IdentityDrift },
        .{ "22222222222222222222222222222222", "66666666666666666666666666666666", error.WrongIdentity },
        .{ ":0:0:receipt-verified", ":1:0:receipt-verified", error.WrongIoLedger },
        .{ ":0:0:receipt-verified", ":0:1:receipt-verified", error.WrongIoLedger },
        .{ "FINAL PASS rc=0", "FINAL FAIL rc=1", error.GuestFailure },
        .{ "main returned 0", "main returned 1", error.GuestFailure },
    };
    inline for (mutations) |mutation| {
        const changed = try std.mem.replaceOwned(u8, a, second, mutation[0], mutation[1]);
        defer a.free(changed);
        const full = try std.mem.concat(a, u8, &.{ first, changed, padding });
        defer a.free(full);
        try serialError(mutation[2], .azure_cumulative, padded, full);
    }
    const oversized = try a.alloc(u8, 4 * 1024 * 1024 + 1);
    defer a.free(oversized);
    @memset(oversized, 0);
    @memcpy(oversized[0..first.len], first);
    try serialError(error.InvalidSerialLength, .azure_cumulative, oversized, null);
    try serialError(error.SerialPrefixChanged, .azure_cumulative, padded, oversized);
}

pub fn main() !void {
    const parameters: prep.seed.Parameters = .{
        .run_id = "11111111111111111111111111111111".*,
        .disk_id = "22222222222222222222222222222222".*,
        .sectors = 8388608,
        .lun = 7,
    };
    const record = try prep.seed.encodeSector(parameters);
    var prefix: [8192]u8 = @splat(0);
    @memcpy(prefix[4096..4608], &record);
    @memcpy(prefix[4608..5120], &record);
    try validation.seedChunk(&prefix, 0, parameters);
    prefix[8191] = 1;
    if (validation.seedChunk(&prefix, 0, parameters)) |_| return error.AcceptedDirtySeed else |err| try expect(err == error.SeedNotPristine);
    prefix[8191] = 0;
    prefix[4096] = 'X';
    if (validation.seedChunk(&prefix, 0, parameters)) |_| return error.AcceptedWrongSeed else |err| try expect(err == error.InvalidSeedMagic);
    const a = std.heap.page_allocator;
    try serialFixtures(a);
    const manifest = try std.fmt.allocPrint(a,
        \\{{"version":2,"run_id":"{s}","disk_id":"{s}","sectors":8388608,"sector_size":512,
        \\"identity_policy":"seed-enrollment-v2","identity_policy_version":2,"path":null,"target":null,
        \\"lun":7,"seed_lbas":[8,9],"intent_lba":16,"receipt_lba":17,"extent_lba":32,"extent_sectors":16,"manifest_crc32":{d}}}
    , .{ &parameters.run_id, &parameters.disk_id, std.mem.readInt(u32, record[508..512], .little) });
    defer a.free(manifest);
    try validation.inspectManifest(a, manifest, parameters);
    var changed = parameters;
    changed.disk_id[0] = '3';
    if (validation.inspectManifest(a, manifest, changed)) |_| return error.AcceptedWrongManifest else |err| try expect(err == error.ManifestMismatch);
    const Simple = struct { version: u8 };
    if (validation.parse(Simple, a, "{\"version\":1,\"version\":2}")) |parsed| {
        parsed.deinit();
        return error.AcceptedDuplicate;
    } else |_| {}
    if (validation.parse(Simple, a, "{\"version\":1,\"unknown\":2}")) |parsed| {
        parsed.deinit();
        return error.AcceptedUnknown;
    } else |_| {}
    inline for (.{ "{\"version\":\"1\"}", "{\"version\":true}", "{\"version\":1.5}" }) |bad| {
        if (validation.parse(Simple, a, bad)) |parsed| {
            parsed.deinit();
            return error.AcceptedWrongIntegerType;
        } else |_| {}
    }
    const legacy_guard = try prep.config.render(a, parameters.guard());
    defer a.free(legacy_guard);
    const guard = try std.mem.replaceOwned(u8, a, legacy_guard, "CONFIG_LIBSTORVSC_MAX_LUNS=8", "CONFIG_LIBSTORVSC_MAX_LUNS=2");
    defer a.free(guard);
    try prep.config.validatePurpose(a, legacy_guard, parameters.guard(), .persistence);
    if (prep.config.validateDirectPersistence(a, legacy_guard, parameters.guard())) |_| return error.AcceptedLegacyDirectPool else |err| try expect(err == error.InvalidGuardProfile);
    if (prep.config.validatePurpose(a, guard, parameters.guard(), .persistence)) |_| return error.RelaxedLegacyPool else |err| try expect(err == error.InvalidGuardProfile);
    const config = try std.mem.concat(a, u8, &.{ "CONFIG_ARCH_X86_64=y\nCONFIG_PLAT_HYPERV=y\nCONFIG_UKPLAT_CPU_MAXCOUNT=1\n", guard });
    defer a.free(config);
    try validation.inspectConfig(a, config, parameters);
    if (validation.inspectConfig(a, guard, parameters)) |_| return error.AcceptedUnknownPlatform else |err| try expect(err == error.WrongPlatform);
    if (validation.inspectConfig(a, config, changed)) |_| return error.AcceptedWrongConfigIdentity else |err| try expect(err == error.IdentityChanged);
    const no_discovery = try std.mem.replaceOwned(u8, a, config, "CONFIG_LIBSTORVSC_LUN_DISCOVERY=y", "CONFIG_LIBSTORVSC_LUN_DISCOVERY=n");
    defer a.free(no_discovery);
    if (validation.inspectConfig(a, no_discovery, parameters)) |_| return error.AcceptedMissingDiscovery else |err| try expect(err == error.InvalidGuardProfile);
    var tail: [512]u8 = @splat(0);
    @memcpy(tail[0..8], "conectix");
    std.mem.writeInt(u32, tail[8..12], 2, .big);
    std.mem.writeInt(u32, tail[12..16], 0x10000, .big);
    std.mem.writeInt(u64, tail[16..24], std.math.maxInt(u64), .big);
    std.mem.writeInt(u64, tail[40..48], 4294967296, .big);
    std.mem.writeInt(u64, tail[48..56], 4294967296, .big);
    std.mem.writeInt(u32, tail[60..64], 2, .big);
    _ = try std.fmt.hexToBytes(tail[68..84], &parameters.disk_id);
    var sum: u32 = 0;
    for (tail) |byte| sum += byte;
    std.mem.writeInt(u32, tail[64..68], ~sum, .big);
    try validation.footer(&tail, 4294967296, &parameters.disk_id);
    if (validation.footer(&tail, 4294967808, &parameters.disk_id)) |_| return error.AcceptedWrongSize else |err| try expect(err == error.InvalidFooter);
    if (validation.footer(&tail, 4294967296, &changed.disk_id)) |_| return error.AcceptedWrongFooterId else |err| try expect(err == error.WrongDiskIdentity);
    tail[32] = 1;
    if (validation.footer(&tail, 4294967296, &parameters.disk_id)) |_| return error.AcceptedBadChecksum else |err| try expect(err == error.InvalidFooterChecksum);
}
