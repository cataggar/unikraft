// SPDX-License-Identifier: BSD-3-Clause
//! Guarded-v2 configuration admission, not a Kconfig solver or boot receipt.
const std = @import("std");
const kconfig = @import("native_kconfig");
const contracts = @import("contracts.zig");

pub const Metadata = kconfig.Metadata;
pub const Purpose = contracts.Purpose;
pub const format = "unikraft-hyperv-guarded-config-native-v1";
pub const min_sectors: u64 = 49;
pub const max_sectors: u64 = @as(u64, std.math.maxInt(i64)) / 512;
pub const persistence_sectors: u64 = 8388608;
pub const config_cap: usize = 1024 * 1024;

pub const Guard = struct {
    run_id: contracts.Identity,
    disk_id: contracts.Identity,
    sectors: u64,
    lun: u8,
    sector_size: u32 = 512,
    identity_policy: u32 = 2,
};

const prefix = "APPHYPERVACCEPTANCE_PERSISTENCE";
const enabled_symbols = [_][]const u8{
    prefix,
    "LIBSTORVSC",
    "LIBSTORVSC_LUN_DISCOVERY",
    "LIBSTORVSC_GUARDED_IO",
};

// Types are from the public acceptance and StorVSC Config.uk files. Additional
// solved symbols need caller-supplied metadata when their numbers are ambiguous.
const symbols = [_]kconfig.SymbolMetadata{
    .{ .name = "APPHYPERVACCEPTANCE", .symbol_type = .boolean },
    .{ .name = "APPHYPERVACCEPTANCE_WORKLOAD", .symbol_type = .boolean },
    .{ .name = "APPHYPERVACCEPTANCE_NETWORK_APPLICATION", .symbol_type = .boolean },
    .{ .name = "APPHYPERVACCEPTANCE_PEER_IPV4", .symbol_type = .string },
    .{ .name = "APPHYPERVACCEPTANCE_PEER_TCP_PORT", .symbol_type = .integer },
    .{ .name = "APPHYPERVACCEPTANCE_PEER_UDP_PORT", .symbol_type = .integer },
    .{ .name = "APPHYPERVACCEPTANCE_NONCE", .symbol_type = .string },
    .{ .name = prefix, .symbol_type = .boolean },
    .{ .name = prefix ++ "_RUN_ID", .symbol_type = .string },
    .{ .name = prefix ++ "_DISK_ID", .symbol_type = .string },
    .{ .name = prefix ++ "_SECTORS", .symbol_type = .integer },
    .{ .name = prefix ++ "_SECTOR_SIZE", .symbol_type = .integer },
    .{ .name = prefix ++ "_IDENTITY_POLICY", .symbol_type = .integer },
    .{ .name = prefix ++ "_PATH", .symbol_type = .integer },
    .{ .name = prefix ++ "_TARGET", .symbol_type = .integer },
    .{ .name = prefix ++ "_LUN", .symbol_type = .integer },
    .{ .name = "LIBSTORVSC", .symbol_type = .boolean },
    .{ .name = "LIBSTORVSC_MAX_DEVICES", .symbol_type = .integer },
    .{ .name = "LIBSTORVSC_LUN_DISCOVERY", .symbol_type = .boolean },
    .{ .name = "LIBSTORVSC_GUARDED_IO", .symbol_type = .boolean },
    .{ .name = "LIBSTORVSC_MAX_LUNS", .symbol_type = .integer },
    .{ .name = "LIBSTORVSC_MAX_QUEUES", .symbol_type = .integer },
    .{ .name = "LIBSTORVSC_QUEUE_DEPTH", .symbol_type = .integer },
    .{ .name = "LIBSTORVSC_MAX_TRANSFER_PAGES", .symbol_type = .integer },
    .{ .name = "LIBSTORVSC_TX_RING_PAGES", .symbol_type = .integer },
    .{ .name = "LIBSTORVSC_RX_RING_PAGES", .symbol_type = .integer },
    .{ .name = "LIBSTORVSC_CONTROL_TIMEOUT_MS", .symbol_type = .integer },
    .{ .name = "LIBSTORVSC_REQUEST_TIMEOUT_MS", .symbol_type = .integer },
};

pub fn validateGuard(guard: Guard) !void {
    _ = try contracts.identity(&guard.run_id);
    _ = try contracts.identity(&guard.disk_id);
    if (guard.sectors < min_sectors or guard.sectors > max_sectors or
        guard.lun > 7 or guard.sector_size != 512 or guard.identity_policy != 2)
        return error.InvalidGuard;
}

/// The persistence gate checks geometry only; it does not authenticate original
/// seed custody, authorize a write, or establish a completed platform handoff.
pub fn validateGuardPurpose(guard: Guard, purpose: Purpose) !void {
    try validateGuard(guard);
    switch (purpose) {
        .synthetic, .platform_preflight => {},
        .persistence => if (guard.sectors != persistence_sectors or guard.lun != 7)
            return error.WrongPurposeGeometry,
    }
}

pub fn render(allocator: std.mem.Allocator, guard: Guard) ![]u8 {
    try validateGuard(guard);
    const bytes = try std.fmt.allocPrint(allocator,
        \\# {s}
        \\CONFIG_APPHYPERVACCEPTANCE=y
        \\CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE=y
        \\CONFIG_LIBSTORVSC=y
        \\CONFIG_LIBSTORVSC_LUN_DISCOVERY=y
        \\CONFIG_LIBSTORVSC_GUARDED_IO=y
        \\CONFIG_LIBSTORVSC_MAX_DEVICES=2
        \\CONFIG_LIBSTORVSC_MAX_LUNS=8
        \\# CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION is not set
        \\CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID="{s}"
        \\CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_DISK_ID="{s}"
        \\CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTORS={d}
        \\CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTOR_SIZE=512
        \\CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY=2
        \\CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_LUN={d}
        \\
    , .{ format, &guard.run_id, &guard.disk_id, guard.sectors, guard.lun });
    errdefer allocator.free(bytes);
    try validate(allocator, bytes, guard);
    return bytes;
}

pub fn guardedIdentity(allocator: std.mem.Allocator, bytes: []const u8) !Guard {
    return guardedIdentityWithMetadata(allocator, bytes, null);
}

/// Full solved metadata can resolve unrelated integer/hex symbols, but cannot
/// change the authoritative types or extend the guarded symbol allowlist.
pub fn guardedIdentityWithMetadata(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    metadata: ?*const Metadata,
) !Guard {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var document = try parseDocument(arena.allocator(), bytes, metadata);
    defer document.deinit();
    return documentGuard(&document);
}

pub fn validate(allocator: std.mem.Allocator, bytes: []const u8, expected: Guard) !void {
    return validateWithMetadata(allocator, bytes, expected, null);
}

pub fn validateWithMetadata(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: Guard,
    metadata: ?*const Metadata,
) !void {
    try validateGuard(expected);
    const actual = try guardedIdentityWithMetadata(allocator, bytes, metadata);
    if (!contracts.same(actual, expected)) return error.IdentityChanged;
}

pub fn validatePurpose(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: Guard,
    purpose: Purpose,
) !void {
    try validateGuardPurpose(expected, purpose);
    try validate(allocator, bytes, expected);
}

/// Re-emit all parsed options, including unrelated ones, without changing guard
/// identity. Comments/blank lines are not retained by the native document parser.
pub fn normalize(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: Guard,
) ![]u8 {
    return normalizeWithMetadata(allocator, bytes, expected, null);
}

pub fn normalizeWithMetadata(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: Guard,
    metadata: ?*const Metadata,
) ![]u8 {
    try validateGuard(expected);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var document = try parseDocument(arena.allocator(), bytes, metadata);
    defer document.deinit();
    if (!contracts.same(try documentGuard(&document), expected)) return error.IdentityChanged;
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const writer = &output.writer;
    try writer.print("# {s}\n", .{format});
    for (document.entries.items) |entry| {
        switch (entry.value) {
            .unset => try writer.print("# CONFIG_{s} is not set\n", .{entry.name}),
            .tristate => |value| try writer.print("CONFIG_{s}={s}\n", .{ entry.name, @tagName(value) }),
            .integer => |number| try writer.print("CONFIG_{s}={s}\n", .{ entry.name, number.text }),
            .hex => |number| try writer.print("CONFIG_{s}={s}\n", .{ entry.name, number.text }),
            .string => |value| {
                try writer.print("CONFIG_{s}=\"", .{entry.name});
                for (value) |byte| {
                    if (byte == '"' or byte == '\\') try writer.writeByte('\\');
                    try writer.writeByte(byte);
                }
                try writer.writeAll("\"\n");
            },
        }
    }
    const result = try output.toOwnedSlice();
    errdefer allocator.free(result);
    try validateWithMetadata(allocator, result, expected, metadata);
    return result;
}

fn dangerous(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "APPHYPERVACCEPTANCE") or
        std.mem.startsWith(u8, name, "LIBSTORVSC");
}

fn known(name: []const u8) bool {
    for (symbols) |symbol| if (std.mem.eql(u8, symbol.name, name)) return true;
    return false;
}

fn parseDocument(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    extra: ?*const Metadata,
) !kconfig.Document {
    if (bytes.len > config_cap) return error.ConfigTooLarge;
    if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidConfig;
    for (bytes) |byte| {
        if ((byte < 0x20 and byte != '\n' and byte != '\r' and byte != '\t') or byte == 0x7f)
            return error.InvalidConfig;
    }
    var metadata = Metadata.init(allocator);
    defer metadata.deinit();
    for (symbols) |symbol| try metadata.addSymbol(symbol.name, symbol.symbol_type);
    if (extra) |types| {
        for (types.symbols.items) |symbol| {
            if (dangerous(symbol.name) and !known(symbol.name)) return error.UnknownDangerousOverride;
            if (metadata.typeOf(symbol.name)) |actual| {
                if (actual != symbol.symbol_type) return error.ConflictingMetadata;
            } else try metadata.addSymbol(symbol.name, symbol.symbol_type);
        }
    }
    var diagnostic: kconfig.Diagnostic = .{};
    return kconfig.parseWithMetadata(allocator, bytes, &metadata, &diagnostic);
}

fn integer(document: *const kconfig.Document, name: []const u8) !u64 {
    const entry = document.get(name) orelse return error.MissingRequired;
    if (entry.value != .integer) return error.InvalidGuardValue;
    const number = entry.value.integer;
    if (number.text.len == 0 or (number.text.len > 1 and number.text[0] == '0'))
        return error.InvalidGuardValue;
    for (number.text) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidGuardValue;
    return std.math.cast(u64, number.value) orelse error.InvalidGuardValue;
}

fn identity(document: *const kconfig.Document, name: []const u8) !contracts.Identity {
    const value = try document.getString(name) orelse return error.MissingRequired;
    return contracts.identity(value);
}

fn documentGuard(document: *const kconfig.Document) !Guard {
    for (document.entries.items) |entry| {
        if (dangerous(entry.name) and !known(entry.name)) return error.UnknownDangerousOverride;
    }
    if (document.get(prefix ++ "_PATH") != null or document.get(prefix ++ "_TARGET") != null)
        return error.ForbiddenV2Address;
    for (enabled_symbols) |name| {
        const enabled = try document.getBool(name) orelse return error.MissingRequired;
        if (!enabled) return error.InvalidGuardProfile;
    }
    if (try document.getBool("APPHYPERVACCEPTANCE")) |enabled| {
        if (!enabled) return error.InvalidGuardProfile;
    }
    // Kconfig may omit this disabled choice member when its dependencies are off.
    if ((try document.getBool("APPHYPERVACCEPTANCE_NETWORK_APPLICATION")) orelse false)
        return error.InvalidGuardProfile;
    if (try integer(document, "LIBSTORVSC_MAX_DEVICES") != 2 or
        try integer(document, "LIBSTORVSC_MAX_LUNS") != 8)
        return error.InvalidGuardProfile;
    const guard: Guard = .{
        .run_id = try identity(document, prefix ++ "_RUN_ID"),
        .disk_id = try identity(document, prefix ++ "_DISK_ID"),
        .sectors = try integer(document, prefix ++ "_SECTORS"),
        .sector_size = std.math.cast(u32, try integer(document, prefix ++ "_SECTOR_SIZE")) orelse return error.InvalidGuard,
        .identity_policy = std.math.cast(u32, try integer(document, prefix ++ "_IDENTITY_POLICY")) orelse return error.InvalidGuard,
        .lun = std.math.cast(u8, try integer(document, prefix ++ "_LUN")) orelse return error.InvalidGuard,
    };
    try validateGuard(guard);
    return guard;
}

const fixture: Guard = .{
    .run_id = "00112233445566778899aabbccddeeff".*,
    .disk_id = "102132435465768798a9bacbdcedfe0f".*,
    .sectors = 291,
    .lun = 7,
};

fn replaceTest(allocator: std.mem.Allocator, bytes: []const u8, old: []const u8, new: []const u8) ![]u8 {
    const start = std.mem.indexOf(u8, bytes, old) orelse return error.TestUnexpectedResult;
    return std.fmt.allocPrint(allocator, "{s}{s}{s}", .{ bytes[0..start], new, bytes[start + old.len ..] });
}

test "native guarded config renders deterministically and validates before and after normalization" {
    const a = std.testing.allocator;
    const first = try render(a, fixture);
    defer a.free(first);
    const second = try render(a, fixture);
    defer a.free(second);
    try std.testing.expectEqualStrings(first, second);
    try std.testing.expect(std.mem.startsWith(u8, first, "# " ++ format ++ "\n"));
    try std.testing.expectEqualDeep(fixture, try guardedIdentity(a, first));
    const normalized = try normalize(a, first, fixture);
    defer a.free(normalized);
    try std.testing.expectEqualStrings(first, normalized);
    try validatePurpose(a, normalized, fixture, .synthetic);
    try validatePurpose(a, normalized, fixture, .platform_preflight);
    try std.testing.expectError(error.WrongPurposeGeometry, validatePurpose(a, normalized, fixture, .persistence));
}

test "native document preserves unrelated typed options and requires metadata for ambiguous numbers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const base = try render(a, fixture);
    const unrelated =
        \\CONFIG_OTHER_BOOL=y
        \\CONFIG_OTHER_MODULE=m
        \\# CONFIG_OTHER_UNSET is not set
        \\CONFIG_OTHER_HEX=0x12ab
        \\CONFIG_OTHER_SIGNED=-17
        \\CONFIG_OTHER_TEXT="a\\b\"c"
        \\CONFIG_LIBSTORVSC_QUEUE_DEPTH=32
        \\
    ;
    const input = try std.fmt.allocPrint(a, "{s}{s}", .{ base, unrelated });
    const normalized = try normalize(a, input, fixture);
    try std.testing.expect(std.mem.endsWith(u8, normalized, unrelated));
    const ambiguous = try std.fmt.allocPrint(a, "{s}CONFIG_OTHER_NUMBER=123\n", .{input});
    try std.testing.expectError(error.InvalidConfig, validate(a, ambiguous, fixture));
    var metadata = Metadata.init(a);
    defer metadata.deinit();
    try metadata.addSymbol("OTHER_NUMBER", .integer);
    try validateWithMetadata(a, ambiguous, fixture, &metadata);
    const full = try normalizeWithMetadata(a, ambiguous, fixture, &metadata);
    try std.testing.expect(std.mem.endsWith(u8, full, "CONFIG_OTHER_NUMBER=123\n"));
    try std.testing.expectEqualDeep(fixture, try guardedIdentityWithMetadata(a, full, &metadata));
    try metadata.addSymbol(prefix ++ "_SECTORS", .string);
    try std.testing.expectError(error.ConflictingMetadata, validateWithMetadata(a, ambiguous, fixture, &metadata));
}

test "native config rejects duplicate conflicting missing and malformed required entries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const base = try render(a, fixture);
    for ([_][]const u8{
        "CONFIG_LIBSTORVSC=y\n",
        "CONFIG_LIBSTORVSC=n\n",
        "# CONFIG_LIBSTORVSC is not set\n",
        "CONFIG_LIBSTORVSC_MAX_LUNS=8\n",
        "CONFIG_OTHER=y\nCONFIG_OTHER=y\n",
    }) |extra| {
        const bytes = try std.fmt.allocPrint(a, "{s}{s}", .{ base, extra });
        try std.testing.expectError(error.InvalidConfig, validate(a, bytes, fixture));
    }
    for ([_][]const u8{
        prefix,
        "LIBSTORVSC",
        "LIBSTORVSC_GUARDED_IO",
        "LIBSTORVSC_LUN_DISCOVERY",
        "LIBSTORVSC_MAX_DEVICES",
        "LIBSTORVSC_MAX_LUNS",
        prefix ++ "_RUN_ID",
        prefix ++ "_DISK_ID",
        prefix ++ "_SECTORS",
        prefix ++ "_SECTOR_SIZE",
        prefix ++ "_IDENTITY_POLICY",
        prefix ++ "_LUN",
    }) |name| {
        const search = try std.fmt.allocPrint(a, "CONFIG_{s}=", .{name});
        const start = std.mem.indexOf(u8, base, search).?;
        const end = start + std.mem.indexOfScalar(u8, base[start..], '\n').? + 1;
        const missing = try replaceTest(a, base, base[start..end], "");
        try std.testing.expectError(error.MissingRequired, validate(a, missing, fixture));
    }
    for ([_][]const u8{ "\"8\"", "y", "8oops", "9223372036854775808", "" }) |value| {
        const replacement = try std.fmt.allocPrint(a, "CONFIG_LIBSTORVSC_MAX_LUNS={s}\n", .{value});
        const bytes = try replaceTest(a, base, "CONFIG_LIBSTORVSC_MAX_LUNS=8\n", replacement);
        try std.testing.expectError(error.InvalidConfig, validate(a, bytes, fixture));
    }
    for ([_][]const u8{ "08", "+8", "-8", "0_8" }) |value| {
        const replacement = try std.fmt.allocPrint(a, "CONFIG_LIBSTORVSC_MAX_LUNS={s}\n", .{value});
        const bytes = try replaceTest(a, base, "CONFIG_LIBSTORVSC_MAX_LUNS=8\n", replacement);
        try std.testing.expectError(error.InvalidGuardValue, validate(a, bytes, fixture));
    }
}

test "native config rejects profile changes v1 addresses and unknown guarded overrides" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const base = try render(a, fixture);
    for (enabled_symbols) |name| {
        const old = try std.fmt.allocPrint(a, "CONFIG_{s}=y\n", .{name});
        const new = try std.fmt.allocPrint(a, "# CONFIG_{s} is not set\n", .{name});
        try std.testing.expectError(error.InvalidGuardProfile, validate(a, try replaceTest(a, base, old, new), fixture));
    }
    const network = try replaceTest(a, base, "# CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION is not set\n", "CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION=y\n");
    try std.testing.expectError(error.InvalidGuardProfile, validate(a, network, fixture));
    for ([_][]const u8{ "PATH", "TARGET" }) |name| {
        const bytes = try std.fmt.allocPrint(a, "{s}CONFIG_{s}_{s}=0\n", .{ base, prefix, name });
        try std.testing.expectError(error.ForbiddenV2Address, validate(a, bytes, fixture));
    }
    for ([_][]const u8{
        "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_FORCE=y\n",
        "CONFIG_LIBSTORVSC_GUARDED_IO_BYPASS=n\n",
        "# CONFIG_LIBSTORVSC_UNKNOWN is not set\n",
    }) |extra| {
        const bytes = try std.fmt.allocPrint(a, "{s}{s}", .{ base, extra });
        try std.testing.expectError(error.UnknownDangerousOverride, validate(a, bytes, fixture));
    }
    var metadata = Metadata.init(a);
    defer metadata.deinit();
    try metadata.addSymbol("LIBSTORVSC_GUARDED_IO_BYPASS", .boolean);
    try std.testing.expectError(error.UnknownDangerousOverride, validateWithMetadata(a, base, fixture, &metadata));
}

test "native config never replaces caller identities and rejects invalid IDs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bytes = try render(a, fixture);
    var changes = [_]Guard{fixture} ** 4;
    changes[0].run_id[0] = '1';
    changes[1].disk_id[0] = '2';
    changes[2].sectors += 1;
    changes[3].lun = 0;
    for (changes) |changed| {
        try std.testing.expectError(error.IdentityChanged, validate(a, bytes, changed));
        try std.testing.expectError(error.IdentityChanged, normalize(a, bytes, changed));
    }
    for ([_][]const u8{
        "00000000000000000000000000000000",
        "00112233445566778899AABBCCDDEEFF",
        "00112233445566778899aabbccddeefg",
        "00112233445566778899aabbccddeef",
    }) |invalid| {
        const changed = try replaceTest(a, bytes, &fixture.run_id, invalid);
        try std.testing.expectError(error.InvalidIdentity, validate(a, changed, fixture));
    }
    const unterminated = try replaceTest(a, bytes, "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID=\"", "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID=");
    try std.testing.expectError(error.InvalidConfig, validate(a, unterminated, fixture));
}

test "native config purpose and numeric limits are explicit without allocating disks" {
    const a = std.testing.allocator;
    var guard = fixture;
    guard.sectors = persistence_sectors;
    const bytes = try render(a, guard);
    defer a.free(bytes);
    try validatePurpose(a, bytes, guard, .persistence);
    guard.lun = 6;
    try std.testing.expectError(error.WrongPurposeGeometry, validateGuardPurpose(guard, .persistence));
    guard = fixture;
    guard.sectors = min_sectors;
    guard.lun = 0;
    try validateGuardPurpose(guard, .synthetic);
    guard.sectors = max_sectors;
    try validateGuard(guard);
    guard.sectors += 1;
    try std.testing.expectError(error.InvalidGuard, render(a, guard));
    guard.sectors = 48;
    try std.testing.expectError(error.InvalidGuard, render(a, guard));
    guard = fixture;
    guard.lun = 8;
    try std.testing.expectError(error.InvalidGuard, render(a, guard));
    guard = fixture;
    guard.sector_size = 4096;
    try std.testing.expectError(error.InvalidGuard, render(a, guard));
    guard = fixture;
    guard.identity_policy = 1;
    try std.testing.expectError(error.InvalidGuard, render(a, guard));
}

test "native config bounds and malformed byte input fail closed" {
    const a = std.testing.allocator;
    const large = try a.alloc(u8, config_cap + 1);
    defer a.free(large);
    @memset(large, '\n');
    try std.testing.expectError(error.ConfigTooLarge, guardedIdentity(a, large));
    for ([_][]const u8{ "# bad\x00\n", "# bad\xff\n", " CONFIG_FOO=y\n", "CONFIG_FOO\n" }) |bytes| {
        try std.testing.expectError(error.InvalidConfig, guardedIdentity(a, bytes));
    }
}
