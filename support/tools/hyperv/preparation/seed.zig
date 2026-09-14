// SPDX-License-Identifier: BSD-3-Clause
//! Small synthetic pristine seeds only. Sector admission is independently usable
//! by a future descriptor-streaming importer; no original-disk renderer exists.
const std = @import("std");
const contracts = @import("contracts.zig");
const configuration = @import("config.zig");
const miz_vhd = @import("miz").vhd;

pub const sector_size: usize = 512;
pub const Sector = [sector_size]u8;
pub const seed_lbas = [2]u64{ 8, 9 };
pub const intent_lba: u64 = 16;
pub const receipt_lba: u64 = 17;
pub const extent_lba: u64 = 32;
pub const extent_sectors: u32 = 16;
pub const min_sectors: u64 = 49;
pub const max_synthetic_sectors: u64 = 4096;
pub const footer_creator: [4]u8 = "ukn1".*;
pub const manifest_schema = "unikraft.hyperv.synthetic-storage-seed.native";

pub const Parameters = struct {
    run_id: contracts.Identity,
    disk_id: contracts.Identity,
    sectors: u64,
    lun: u8,

    pub fn guard(self: Parameters) configuration.Guard {
        return .{ .run_id = self.run_id, .disk_id = self.disk_id, .sectors = self.sectors, .lun = self.lun };
    }
};

pub const Products = struct {
    raw: []u8,
    vhd: []u8,
    config: []u8,
    manifest: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Products) void {
        self.allocator.free(self.raw);
        self.allocator.free(self.vhd);
        self.allocator.free(self.config);
        self.allocator.free(self.manifest);
        self.* = undefined;
    }
};

pub const Artifact = struct { size: u64, sha256: []const u8 };
pub const Manifest = struct {
    schema: []const u8,
    schema_version: u32,
    scope: enum { synthetic_only },
    run_id: []const u8,
    disk_id: []const u8,
    sectors: u64,
    sector_size: u32,
    identity_policy: []const u8,
    identity_policy_version: u32,
    lun: u8,
    seed_lbas: [2]u64,
    intent_lba: u64,
    receipt_lba: u64,
    extent_lba: u64,
    extent_sectors: u32,
    manifest_crc32: u32,
    raw: Artifact,
    vhd: Artifact,
    config: Artifact,
    producer: struct {
        implementation: enum { native_zig_v1 },
        compiler_version: []const u8,
        miz_revision: []const u8,
        footer_creator: []const u8,
    },
};

fn validateParameters(parameters: Parameters) !void {
    try configuration.validateGuard(parameters.guard());
}

fn validateSynthetic(parameters: Parameters) !void {
    try validateParameters(parameters);
    if (parameters.sectors > max_synthetic_sectors) return error.SyntheticLimitExceeded;
}

fn binaryIdentity(identity: contracts.Identity) ![16]u8 {
    _ = try contracts.identity(&identity);
    var bytes: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &identity);
    return bytes;
}

fn zero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

fn sectorCrc(bytes: *const Sector) u32 {
    var checked = bytes.*;
    @memset(checked[508..512], 0);
    return std.hash.crc.Crc32IsoHdlc.hash(&checked);
}

/// Encodes one 512-byte record, not a disk. General guarded geometry is accepted
/// here so large-seed admission need not allocate or regenerate its raw payload.
pub fn encodeSector(parameters: Parameters) !Sector {
    try validateParameters(parameters);
    var sector: Sector = @splat(0);
    sector[0..8].* = "UKPSEED2".*;
    std.mem.writeInt(u16, sector[8..10], 2, .little);
    std.mem.writeInt(u16, sector[10..12], 128, .little);
    std.mem.writeInt(u32, sector[12..16], sector_size, .little);
    sector[16..32].* = try binaryIdentity(parameters.run_id);
    sector[32..48].* = try binaryIdentity(parameters.disk_id);
    std.mem.writeInt(u64, sector[48..56], parameters.sectors, .little);
    std.mem.writeInt(u32, sector[56..60], sector_size, .little);
    std.mem.writeInt(u32, sector[60..64], 2, .little);
    std.mem.writeInt(u64, sector[64..72], seed_lbas[0], .little);
    std.mem.writeInt(u64, sector[72..80], seed_lbas[1], .little);
    std.mem.writeInt(u64, sector[80..88], intent_lba, .little);
    std.mem.writeInt(u64, sector[88..96], receipt_lba, .little);
    std.mem.writeInt(u64, sector[96..104], extent_lba, .little);
    std.mem.writeInt(u32, sector[104..108], extent_sectors, .little);
    sector[108] = 2;
    sector[110] = parameters.lun;
    std.mem.writeInt(u32, sector[508..512], sectorCrc(&sector), .little);
    return sector;
}

/// Checks every fixed field, reserved byte, CRC, nonnil ID and geometry. This
/// validates a record only, not pristine regions, disk custody, or boot evidence.
pub fn decodeSector(bytes: []const u8) !Parameters {
    if (bytes.len != sector_size) return error.InvalidSectorLength;
    const sector = bytes[0..sector_size];
    if (!std.mem.eql(u8, sector[0..8], "UKPSEED2")) return error.InvalidSeedMagic;
    if (std.mem.readInt(u16, sector[8..10], .little) != 2 or
        std.mem.readInt(u16, sector[10..12], .little) != 128 or
        std.mem.readInt(u32, sector[12..16], .little) != sector_size or
        std.mem.readInt(u32, sector[56..60], .little) != sector_size or
        std.mem.readInt(u32, sector[60..64], .little) != 2 or
        std.mem.readInt(u64, sector[64..72], .little) != seed_lbas[0] or
        std.mem.readInt(u64, sector[72..80], .little) != seed_lbas[1] or
        std.mem.readInt(u64, sector[80..88], .little) != intent_lba or
        std.mem.readInt(u64, sector[88..96], .little) != receipt_lba or
        std.mem.readInt(u64, sector[96..104], .little) != extent_lba or
        std.mem.readInt(u32, sector[104..108], .little) != extent_sectors or
        sector[108] != 2)
        return error.InvalidSeedLayout;
    if (sector[109] != 0 or sector[111] != 0 or !zero(sector[112..508]))
        return error.NonzeroReserved;
    if (std.mem.readInt(u32, sector[508..512], .little) != sectorCrc(sector))
        return error.BadSeedChecksum;
    const parameters: Parameters = .{
        .run_id = std.fmt.bytesToHex(sector[16..32].*, .lower),
        .disk_id = std.fmt.bytesToHex(sector[32..48].*, .lower),
        .sectors = std.mem.readInt(u64, sector[48..56], .little),
        .lun = sector[110],
    };
    try validateParameters(parameters);
    return parameters;
}

pub fn validateSector(bytes: []const u8, expected: Parameters) !void {
    try validateParameters(expected);
    if (!contracts.same(try decodeSector(bytes), expected)) return error.IdentityChanged;
}

fn fixedFooter(parameters: Parameters) !miz_vhd.Footer {
    try validateParameters(parameters);
    var footer = miz_vhd.Footer.forFixedDisk(
        parameters.sectors * sector_size,
        try binaryIdentity(parameters.disk_id),
        miz_vhd.timestamp_base,
    );
    footer.creator_application = footer_creator;
    return footer;
}

/// Strictly admits this native deterministic footer, not historical creators.
pub fn validateFooter(bytes: []const u8, expected: Parameters) !void {
    if (bytes.len != miz_vhd.footer_size) return error.InvalidFooterLength;
    const footer = try miz_vhd.Footer.decode(bytes[0..miz_vhd.footer_size]);
    const wanted = try fixedFooter(expected);
    const encoded = wanted.encode();
    if (!contracts.same(footer, wanted) or !std.mem.eql(u8, bytes, &encoded))
        return error.InvalidFooter;
}

/// Buffer-based validation deliberately shares the small synthetic limit.
/// All bytes outside the two seed records must still be pristine zeroes.
pub fn validateBytes(raw: []const u8, vhd: []const u8, expected: Parameters) !void {
    try validateSynthetic(expected);
    const size: usize = @intCast(expected.sectors * sector_size);
    if (raw.len != size or vhd.len != size + sector_size) return error.InvalidImageLength;
    if (!std.mem.eql(u8, raw, vhd[0..size])) return error.RawPrefixMismatch;
    const first = raw[8 * sector_size .. 9 * sector_size];
    const second = raw[9 * sector_size .. 10 * sector_size];
    if (!std.mem.eql(u8, first, second)) return error.SeedCopiesDiffer;
    try validateSector(first, expected);
    try validateSector(second, expected);
    if (!zero(raw[0 .. 8 * sector_size]) or !zero(raw[10 * sector_size ..]))
        return error.NonzeroPristineRegion;
    try validateFooter(vhd[size..], expected);
}

pub fn render(allocator: std.mem.Allocator, parameters: Parameters) !Products {
    try validateSynthetic(parameters);
    const size: usize = @intCast(parameters.sectors * sector_size);
    const sector = try encodeSector(parameters);
    const raw = try allocator.alloc(u8, size);
    errdefer allocator.free(raw);
    @memset(raw, 0);
    @memcpy(raw[8 * sector_size .. 9 * sector_size], &sector);
    @memcpy(raw[9 * sector_size .. 10 * sector_size], &sector);
    const vhd = try allocator.alloc(u8, size + sector_size);
    errdefer allocator.free(vhd);
    @memcpy(vhd[0..size], raw);
    const footer = (try fixedFooter(parameters)).encode();
    @memcpy(vhd[size..], &footer);
    const config = try configuration.render(allocator, parameters.guard());
    errdefer allocator.free(config);
    const manifest = try renderManifest(allocator, raw, vhd, config, parameters);
    errdefer allocator.free(manifest);
    try validateBytes(raw, vhd, parameters);
    return .{ .raw = raw, .vhd = vhd, .config = config, .manifest = manifest, .allocator = allocator };
}

/// Validate all four native products, including exact canonical manifest/hash
/// bindings. This is synthetic preparation validation, never an acceptance result.
pub fn validateProducts(allocator: std.mem.Allocator, products: Products, expected: Parameters) !void {
    try validateBytes(products.raw, products.vhd, expected);
    try configuration.validate(allocator, products.config, expected.guard());
    const parsed = try contracts.parse(Manifest, allocator, products.manifest);
    defer parsed.deinit();
    const wanted = try renderManifest(allocator, products.raw, products.vhd, products.config, expected);
    defer allocator.free(wanted);
    if (!std.mem.eql(u8, products.manifest, wanted)) return error.ManifestMismatch;
}

fn renderManifest(
    allocator: std.mem.Allocator,
    raw: []const u8,
    vhd: []const u8,
    config: []const u8,
    parameters: Parameters,
) ![]u8 {
    const raw_sha = contracts.digest(raw);
    const vhd_sha = contracts.digest(vhd);
    const config_sha = contracts.digest(config);
    const sector = try encodeSector(parameters);
    const manifest: Manifest = .{
        .schema = manifest_schema,
        .schema_version = 1,
        .scope = .synthetic_only,
        .run_id = &parameters.run_id,
        .disk_id = &parameters.disk_id,
        .sectors = parameters.sectors,
        .sector_size = sector_size,
        .identity_policy = "seed-enrollment-v2",
        .identity_policy_version = 2,
        .lun = parameters.lun,
        .seed_lbas = seed_lbas,
        .intent_lba = intent_lba,
        .receipt_lba = receipt_lba,
        .extent_lba = extent_lba,
        .extent_sectors = extent_sectors,
        .manifest_crc32 = std.mem.readInt(u32, sector[508..512], .little),
        .raw = .{ .size = raw.len, .sha256 = &raw_sha },
        .vhd = .{ .size = vhd.len, .sha256 = &vhd_sha },
        .config = .{ .size = config.len, .sha256 = &config_sha },
        .producer = .{
            .implementation = .native_zig_v1,
            .compiler_version = contracts.compiler_version,
            .miz_revision = contracts.miz_revision,
            .footer_creator = &footer_creator,
        },
    };
    return contracts.canonical(allocator, manifest);
}

const fixture: Parameters = .{
    .run_id = "00112233445566778899aabbccddeeff".*,
    .disk_id = "102132435465768798a9bacbdcedfe0f".*,
    .sectors = 291,
    .lun = 7,
};

fn referenceCrc(bytes: []const u8) u32 {
    var crc: u32 = 0xffffffff;
    for (bytes) |byte| {
        crc ^= byte;
        for (0..8) |_| crc = if (crc & 1 != 0) (crc >> 1) ^ 0xedb88320 else crc >> 1;
    }
    return ~crc;
}

fn repairTestCrc(sector: *Sector) void {
    @memset(sector[508..512], 0);
    std.mem.writeInt(u32, sector[508..512], referenceCrc(sector), .little);
}

fn repairTestFooter(footer: *Sector) void {
    @memset(footer[64..68], 0);
    var sum: u32 = 0;
    for (footer) |byte| sum += byte;
    std.mem.writeInt(u32, footer[64..68], ~sum, .big);
}

test "native seed wire layout and IEEE CRC match independently specified bytes" {
    const sector = try encodeSector(fixture);
    const header =
        "UKPSEED2" ++ "\x02\x00\x80\x00\x00\x02\x00\x00" ++
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff" ++
        "\x10\x21\x32\x43\x54\x65\x76\x87\x98\xa9\xba\xcb\xdc\xed\xfe\x0f" ++
        "\x23\x01\x00\x00\x00\x00\x00\x00" ++
        "\x00\x02\x00\x00\x02\x00\x00\x00" ++
        "\x08\x00\x00\x00\x00\x00\x00\x00" ++
        "\x09\x00\x00\x00\x00\x00\x00\x00" ++
        "\x10\x00\x00\x00\x00\x00\x00\x00" ++
        "\x11\x00\x00\x00\x00\x00\x00\x00" ++
        "\x20\x00\x00\x00\x00\x00\x00\x00" ++
        "\x10\x00\x00\x00\x02\x00\x07\x00";
    try std.testing.expectEqual(@as(usize, 112), header.len);
    try std.testing.expectEqualSlices(u8, header, sector[0..112]);
    try std.testing.expect(zero(sector[112..508]));
    var checked = sector;
    @memset(checked[508..512], 0);
    try std.testing.expectEqual(referenceCrc(&checked), std.mem.readInt(u32, sector[508..512], .little));
    try std.testing.expectEqual(@as(u32, 0xcbf43926), referenceCrc("123456789"));
    try std.testing.expectEqualDeep(fixture, try decodeSector(&sector));
}

test "native seed rejects every reserved byte even with a repaired checksum" {
    const original = try encodeSector(fixture);
    for ([_]usize{ 109, 111 }) |offset| {
        var sector = original;
        sector[offset] = 1;
        repairTestCrc(&sector);
        try std.testing.expectError(error.NonzeroReserved, decodeSector(&sector));
    }
    for (112..508) |offset| {
        var sector = original;
        sector[offset] = 1;
        repairTestCrc(&sector);
        try std.testing.expectError(error.NonzeroReserved, decodeSector(&sector));
    }
}

test "native seed rejects layout downgrade byte order CRC and identity mutations" {
    const original = try encodeSector(fixture);
    for ([_]usize{ 8, 9, 10, 11, 12, 13, 14, 15, 56, 60, 64, 72, 80, 88, 96, 104, 108 }) |offset| {
        var sector = original;
        sector[offset] ^= 1;
        repairTestCrc(&sector);
        try std.testing.expectError(error.InvalidSeedLayout, decodeSector(&sector));
    }
    var sector = original;
    sector[7] = '1';
    repairTestCrc(&sector);
    try std.testing.expectError(error.InvalidSeedMagic, decodeSector(&sector));
    sector = original;
    sector[508] ^= 1;
    try std.testing.expectError(error.BadSeedChecksum, decodeSector(&sector));
    sector = original;
    std.mem.reverse(u8, sector[48..56]);
    repairTestCrc(&sector);
    try std.testing.expectError(error.InvalidGuard, decodeSector(&sector));
    for ([_]usize{ 16, 32, 48, 110 }) |offset| {
        sector = original;
        sector[offset] ^= 1;
        repairTestCrc(&sector);
        try std.testing.expectError(error.IdentityChanged, validateSector(&sector, fixture));
    }
    for ([_]usize{ 16, 32 }) |offset| {
        sector = original;
        @memset(sector[offset..][0..16], 0);
        repairTestCrc(&sector);
        try std.testing.expectError(error.InvalidIdentity, decodeSector(&sector));
    }
    try std.testing.expectError(error.InvalidSectorLength, decodeSector(original[0..511]));
}

test "native fixed footer uses miz geometry codec and native creator binding" {
    const footer = (try fixedFooter(fixture)).encode();
    try validateFooter(&footer, fixture);
    try std.testing.expectEqualStrings("conectix", footer[0..8]);
    try std.testing.expectEqualStrings("ukn1", footer[28..32]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 4, 4, 17 }, footer[56..60]);
    try std.testing.expectEqual(@as(u64, 291 * 512), std.mem.readInt(u64, footer[40..48], .big));
    try std.testing.expectEqual(@as(u64, 291 * 512), std.mem.readInt(u64, footer[48..56], .big));
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, footer[60..64], .big));
    const disk_id = try binaryIdentity(fixture.disk_id);
    try std.testing.expectEqualSlices(u8, &disk_id, footer[68..84]);
    var checked = footer;
    repairTestFooter(&checked);
    try std.testing.expectEqualSlices(u8, &footer, &checked);
    checked[64] ^= 1;
    try std.testing.expectError(error.BadChecksum, validateFooter(&checked, fixture));
    checked = footer;
    checked[0] ^= 1;
    repairTestFooter(&checked);
    try std.testing.expectError(error.BadCookie, validateFooter(&checked, fixture));
    for ([_]usize{ 8, 12, 16, 24, 28, 32, 36, 40, 48, 56, 57, 58, 59, 60, 68, 84, 85, 511 }) |offset| {
        checked = footer;
        checked[offset] ^= 1;
        repairTestFooter(&checked);
        try std.testing.expectError(error.InvalidFooter, validateFooter(&checked, fixture));
    }
    checked = footer;
    std.mem.reverse(u8, checked[40..48]);
    repairTestFooter(&checked);
    try std.testing.expectError(error.InvalidFooter, validateFooter(&checked, fixture));
    try std.testing.expectError(error.InvalidFooterLength, validateFooter(footer[0..511], fixture));
}

test "native synthetic products are deterministic canonical and fully bound" {
    const a = std.testing.allocator;
    var first = try render(a, fixture);
    defer first.deinit();
    var second = try render(a, fixture);
    defer second.deinit();
    try validateProducts(a, first, fixture);
    try std.testing.expectEqualSlices(u8, first.raw, second.raw);
    try std.testing.expectEqualSlices(u8, first.vhd, second.vhd);
    try std.testing.expectEqualStrings(first.config, second.config);
    try std.testing.expectEqualStrings(first.manifest, second.manifest);
    try std.testing.expectEqual(@as(usize, 291 * 512), first.raw.len);
    try std.testing.expectEqual(first.raw.len + 512, first.vhd.len);
    const parsed = try contracts.parse(Manifest, a, first.manifest);
    defer parsed.deinit();
    try std.testing.expectEqualStrings(manifest_schema, parsed.value.schema);
    try std.testing.expectEqual(@as(u32, 1), parsed.value.schema_version);
    try std.testing.expectEqualStrings(&fixture.run_id, parsed.value.run_id);
    try std.testing.expectEqualStrings(&fixture.disk_id, parsed.value.disk_id);
    const raw_sha = contracts.digest(first.raw);
    const vhd_sha = contracts.digest(first.vhd);
    const config_sha = contracts.digest(first.config);
    try std.testing.expectEqualStrings(&raw_sha, parsed.value.raw.sha256);
    try std.testing.expectEqualStrings(&vhd_sha, parsed.value.vhd.sha256);
    try std.testing.expectEqualStrings(&config_sha, parsed.value.config.sha256);
    try std.testing.expectEqualDeep([2]u64{ 8, 9 }, parsed.value.seed_lbas);
    const crc = std.mem.readInt(u32, first.raw[8 * sector_size + 508 ..][0..4], .little);
    try std.testing.expectEqual(crc, parsed.value.manifest_crc32);
    const binding = std.mem.indexOf(u8, first.manifest, parsed.value.raw.sha256).?;
    first.manifest[binding] = if (first.manifest[binding] == '0') '1' else '0';
    try std.testing.expectError(error.ManifestMismatch, validateProducts(a, first, fixture));
}

test "native raw admission rejects mismatched copies prefix lengths and nonpristine regions" {
    const a = std.testing.allocator;
    var products = try render(a, fixture);
    defer products.deinit();
    try std.testing.expectError(error.InvalidImageLength, validateBytes(products.raw[0 .. products.raw.len - 1], products.vhd, fixture));
    try std.testing.expectError(error.InvalidImageLength, validateBytes(products.raw, products.vhd[0 .. products.vhd.len - 1], fixture));
    products.vhd[0] = 1;
    try std.testing.expectError(error.RawPrefixMismatch, validateBytes(products.raw, products.vhd, fixture));
    products.vhd[0] = 0;
    const mismatch = 9 * sector_size + 16;
    products.raw[mismatch] ^= 1;
    products.vhd[mismatch] ^= 1;
    try std.testing.expectError(error.SeedCopiesDiffer, validateBytes(products.raw, products.vhd, fixture));
    products.raw[mismatch] ^= 1;
    products.vhd[mismatch] ^= 1;
    for ([_]usize{ 0, 7 * 512, 10 * 512, 16 * 512, 17 * 512, 32 * 512, 48 * 512 - 1, 291 * 512 - 1 }) |offset| {
        products.raw[offset] = 1;
        products.vhd[offset] = 1;
        try std.testing.expectError(error.NonzeroPristineRegion, validateBytes(products.raw, products.vhd, fixture));
        products.raw[offset] = 0;
        products.vhd[offset] = 0;
    }
    const footer_checksum = products.raw.len + 64;
    products.vhd[footer_checksum] ^= 1;
    try std.testing.expectError(error.BadChecksum, validateBytes(products.raw, products.vhd, fixture));
    products.vhd[footer_checksum] ^= 1;
    try validateBytes(products.raw, products.vhd, fixture);
}

test "native seed renderer is bounded and cannot regenerate acceptance geometry" {
    const a = std.testing.allocator;
    var parameters = fixture;
    parameters.sectors = min_sectors;
    parameters.lun = 0;
    var products = try render(a, parameters);
    defer products.deinit();
    try validateProducts(a, products, parameters);
    parameters.sectors = max_synthetic_sectors;
    try validateSynthetic(parameters);
    for ([_]u64{ 0, 48, configuration.max_sectors + 1, std.math.maxInt(u64) }) |sectors| {
        parameters.sectors = sectors;
        try std.testing.expectError(error.InvalidGuard, render(a, parameters));
    }
    for ([_]u64{ max_synthetic_sectors + 1, configuration.persistence_sectors }) |sectors| {
        parameters.sectors = sectors;
        try std.testing.expectError(error.SyntheticLimitExceeded, render(a, parameters));
        try std.testing.expectError(error.SyntheticLimitExceeded, validateBytes(&.{}, &.{}, parameters));
    }
    // Only a sector-sized synthetic record is used to exercise streaming APIs.
    const sector = try encodeSector(parameters);
    try validateSector(&sector, parameters);
    parameters = fixture;
    parameters.lun = 8;
    try std.testing.expectError(error.InvalidGuard, render(a, parameters));
    parameters = fixture;
    parameters.run_id = @splat('0');
    try std.testing.expectError(error.InvalidIdentity, render(a, parameters));
    parameters = fixture;
    parameters.disk_id[10] = 'A';
    try std.testing.expectError(error.InvalidIdentity, render(a, parameters));
}
