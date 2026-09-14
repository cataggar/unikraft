// SPDX-License-Identifier: BSD-3-Clause
// This executable has no file, process, network, or credential operations.
const std = @import("std");
const validation = @import("main.zig");
const prep = @import("preparation");

fn expect(ok: bool) !void {
    if (!ok) return error.FixtureFailed;
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
