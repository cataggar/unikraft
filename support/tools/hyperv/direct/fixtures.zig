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
    const padding = &@as([464:0]u8, @splat('\x00'));
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
    const manifest = try a.print(
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

    const metadata_bytes =
        "unikraft-native-config-metadata-v1\n" ++
        "symbol\tAPPHYPERVACCEPTANCE\tbool\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE\tbool\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_NETWORK_APPLICATION\tbool\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID\tstring\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_DISK_ID\tstring\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_SECTORS\tint\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_SECTOR_SIZE\tint\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY\tint\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_LUN\tint\n" ++
        "symbol\tLIBSTORVSC\tbool\n" ++
        "symbol\tLIBSTORVSC_LUN_DISCOVERY\tbool\n" ++
        "symbol\tLIBSTORVSC_GUARDED_IO\tbool\n" ++
        "symbol\tLIBSTORVSC_MAX_DEVICES\tint\n" ++
        "symbol\tLIBSTORVSC_MAX_LUNS\tint\n" ++
        "symbol\tARCH_X86_64\tbool\n" ++
        "symbol\tPLAT_HYPERV\tbool\n" ++
        "symbol\tUKPLAT_CPU_MAXCOUNT\tint\n";
    var metadata = try prep.config.Metadata.parse(a, metadata_bytes);
    defer metadata.deinit();
    try validation.inspectConfigWithMetadata(a, config, parameters, &metadata);
    const undeclared_cfg = try std.mem.concat(a, u8, &.{ config, "CONFIG_UNDECLARED_DIRECT_SYMBOL=y\n" });
    defer a.free(undeclared_cfg);
    if (validation.inspectConfigWithMetadata(a, undeclared_cfg, parameters, &metadata)) |_| return error.AcceptedUndeclaredSymbol else |err| try expect(err == error.IncompleteMetadata);
    const legacy_full_cfg = try std.mem.concat(a, u8, &.{ "CONFIG_ARCH_X86_64=y\nCONFIG_PLAT_HYPERV=y\nCONFIG_UKPLAT_CPU_MAXCOUNT=1\n", legacy_guard });
    defer a.free(legacy_full_cfg);
    if (validation.inspectConfigWithMetadata(a, legacy_full_cfg, parameters, &metadata)) |_| return error.AcceptedLegacyMaxLuns else |err| try expect(err == error.InvalidGuardProfile);

    const os_vhd_sha = prep.contracts.digest("os-vhd");
    const seed_raw_sha = prep.contracts.digest("seed-raw");
    const seed_vhd_sha = prep.contracts.digest("seed-vhd");
    const manifest_sha = prep.contracts.digest("manifest");
    const solved_cfg_sha = prep.contracts.digest("solved-config");
    const other_sha = prep.contracts.digest("other-artifact");
    const valid_scope: validation.Scope = .{
        .schema = "uk.hyperv.direct-two-boot",
        .version = 1,
        .approval = .{
            .destructive_data_disk = true,
            .direct_specialized_gen2 = true,
            .two_boots_only = true,
            .cleanup_owned_group = true,
            .original_seed_reviewed = true,
            .guarded_native_image_reviewed = true,
            .expires_unix = 1900000000,
        },
        .attempt_id = "11111111-2222-3333-4444-555555555555",
        .subscription = "66666666-7777-8888-9999-aaaaaaaaaaaa",
        .location = "eastus2",
        .prefix = "ukhvdirect",
        .vm_size = "Standard_D2s_v5",
        .run_id = &parameters.run_id,
        .disk_id = &parameters.disk_id,
        .controller = .SCSI,
        .lun = 7,
        .sectors = 8388608,
        .sector_size = 512,
        .serial_mode = .azure_cumulative,
        .runtime_seconds = 600,
        .cleanup_seconds = 300,
        .operation_seconds = 120,
        .poll_seconds = 5,
        .os_vhd = .{ .path = "/private/acceptance.vhd", .size = 64 * 1024 * 1024 + 512, .sha256 = &os_vhd_sha },
        .seed_raw = .{ .path = "/private/original.raw", .size = 4294967296, .sha256 = &seed_raw_sha },
        .seed_vhd = .{ .path = "/private/original.vhd", .size = 4294967808, .sha256 = &seed_vhd_sha },
        .manifest = .{ .path = "/private/original.json", .size = 512, .sha256 = &manifest_sha },
        .config = .{ .path = "/private/solved.config", .size = 4096, .sha256 = &solved_cfg_sha },
    };
    const valid_bundle: prep.production_local.DirectPersistenceBundle = .{
        .guard = parameters.guard(),
        .commitments = .{
            .scheme = .reviewed_provenance_projection_v1,
            .guarded_producer_sha256 = prep.contracts.digest("provenance"),
            .producer_executable_sha256 = prep.contracts.digest("producer"),
            .engine_executable_sha256 = prep.contracts.digest("engine"),
            .packaged_receipt_sha256 = prep.contracts.digest("packaged-receipt"),
            .selection_sha256 = prep.contracts.digest("selection"),
            .input_sha256 = prep.contracts.digest("input"),
            .solved_config_sha256 = solved_cfg_sha,
            .raw_sha256 = prep.contracts.digest("os-raw"),
            .vhd_sha256 = os_vhd_sha,
        },
        .os_vhd = .{ .path = "acceptance.vhd", .size = valid_scope.os_vhd.size, .sha256 = os_vhd_sha, .mode = 0o600 },
        .seed_raw = .{ .path = "original.raw", .size = valid_scope.seed_raw.size, .sha256 = seed_raw_sha, .mode = 0o600 },
        .seed_vhd = .{ .path = "original.vhd", .size = valid_scope.seed_vhd.size, .sha256 = seed_vhd_sha, .mode = 0o600 },
        .manifest = .{ .path = "original.json", .size = valid_scope.manifest.size, .sha256 = manifest_sha, .mode = 0o600 },
        .original_config = .{ .path = "original.config", .size = 512, .sha256 = prep.contracts.digest("original-config"), .mode = 0o600 },
        .derived_config = .{ .path = "direct.config", .size = 540, .sha256 = prep.contracts.digest("derived-config"), .mode = 0o600 },
        .solved_config = .{ .path = "workspace.config", .size = valid_scope.config.size, .sha256 = solved_cfg_sha, .mode = 0o600 },
        .original_production_sha256 = prep.contracts.digest("original-production"),
        .derivation_sha256 = prep.contracts.digest("derivation"),
    };
    try validation.requirePreparedBundle(valid_scope, valid_bundle);
    {
        var bad_bundle = valid_bundle;
        bad_bundle.guard.run_id = "abababababababababababababababab".*;
        if (validation.requirePreparedBundle(valid_scope, bad_bundle)) |_| return error.AcceptedWrongBundleGuard else |err| try expect(err == error.IdentityChanged);
    }
    {
        var bad_scope = valid_scope;
        bad_scope.os_vhd.size += 1024 * 1024;
        if (validation.requirePreparedBundle(bad_scope, valid_bundle)) |_| return error.AcceptedWrongOsVhdSize else |err| try expect(err == error.InvalidArtifact);
    }
    {
        var bad_scope = valid_scope;
        bad_scope.os_vhd.sha256 = &other_sha;
        if (validation.requirePreparedBundle(bad_scope, valid_bundle)) |_| return error.AcceptedWrongOsVhdSha else |err| try expect(err == error.HashMismatch);
    }
    {
        var bad_bundle = valid_bundle;
        bad_bundle.seed_raw.size -= 512;
        if (validation.requirePreparedBundle(valid_scope, bad_bundle)) |_| return error.AcceptedWrongSeedRawSize else |err| try expect(err == error.InvalidArtifact);
    }
    {
        var bad_scope = valid_scope;
        bad_scope.seed_raw.sha256 = &other_sha;
        if (validation.requirePreparedBundle(bad_scope, valid_bundle)) |_| return error.AcceptedWrongSeedRawSha else |err| try expect(err == error.HashMismatch);
    }
    {
        var bad_bundle = valid_bundle;
        bad_bundle.seed_vhd.size += 512;
        if (validation.requirePreparedBundle(valid_scope, bad_bundle)) |_| return error.AcceptedWrongSeedVhdSize else |err| try expect(err == error.InvalidArtifact);
    }
    {
        var bad_scope = valid_scope;
        bad_scope.seed_vhd.sha256 = &other_sha;
        if (validation.requirePreparedBundle(bad_scope, valid_bundle)) |_| return error.AcceptedWrongSeedVhdSha else |err| try expect(err == error.HashMismatch);
    }
    {
        var bad_scope = valid_scope;
        bad_scope.manifest.size += 1;
        if (validation.requirePreparedBundle(bad_scope, valid_bundle)) |_| return error.AcceptedWrongManifestSize else |err| try expect(err == error.InvalidArtifact);
    }
    {
        var bad_scope = valid_scope;
        bad_scope.manifest.sha256 = &other_sha;
        if (validation.requirePreparedBundle(bad_scope, valid_bundle)) |_| return error.AcceptedWrongManifestSha else |err| try expect(err == error.HashMismatch);
    }
    {
        var bad_scope = valid_scope;
        bad_scope.config.size += 1;
        if (validation.requirePreparedBundle(bad_scope, valid_bundle)) |_| return error.AcceptedWrongConfigSize else |err| try expect(err == error.InvalidArtifact);
    }
    {
        var bad_scope = valid_scope;
        bad_scope.config.sha256 = &other_sha;
        if (validation.requirePreparedBundle(bad_scope, valid_bundle)) |_| return error.AcceptedWrongConfigSha else |err| try expect(err == error.HashMismatch);
    }
    {
        var bad_scope = valid_scope;
        bad_scope.config.path = bad_scope.manifest.path;
        if (validation.requirePreparedBundle(bad_scope, valid_bundle)) |_| return error.AcceptedDuplicateArtifactPath else |err| try expect(err == error.InvalidArtifact);
    }
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
