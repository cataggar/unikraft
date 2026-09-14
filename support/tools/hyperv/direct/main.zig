// SPDX-License-Identifier: BSD-3-Clause
//! Read-only admission/serial/private-JSON checks. No network or mutations.
const std = @import("std");
const core = @import("hyperv_core");
const prep = @import("preparation");
const evidence = @import("evidence");
const c = core.contracts;
const files = core.private_files;

pub const Artifact = struct { path: []const u8, size: u64, sha256: []const u8 };
pub const Scope = struct {
    schema: []const u8,
    version: u8,
    approval: struct {
        destructive_data_disk: bool,
        direct_specialized_gen2: bool,
        two_boots_only: bool,
        cleanup_owned_group: bool,
        original_seed_reviewed: bool,
        guarded_native_image_reviewed: bool,
        expires_unix: u64,
    },
    attempt_id: []const u8,
    subscription: []const u8,
    location: []const u8,
    prefix: []const u8,
    vm_size: []const u8,
    run_id: []const u8,
    disk_id: []const u8,
    controller: enum { SCSI },
    lun: u8,
    sectors: u64,
    sector_size: u16,
    serial_mode: enum { cumulative, per_boot },
    runtime_seconds: u32,
    cleanup_seconds: u32,
    operation_seconds: u32,
    poll_seconds: u32,
    os_vhd: Artifact,
    seed_raw: Artifact,
    seed_vhd: Artifact,
    manifest: Artifact,
    config: Artifact,

    pub fn validate(self: Scope) !void {
        if (!std.mem.eql(u8, self.schema, "uk.hyperv.direct-two-boot") or self.version != 1)
            return error.InvalidScope;
        inline for (.{ "destructive_data_disk", "direct_specialized_gen2", "two_boots_only", "cleanup_owned_group", "original_seed_reviewed", "guarded_native_image_reviewed" }) |field|
            if (!@field(self.approval, field)) return error.NotAuthorized;
        try uuid(self.attempt_id);
        try uuid(self.subscription);
        if (self.prefix.len < 6 or self.prefix.len > 32) return error.InvalidPrefix;
        for (self.prefix) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-') return error.InvalidPrefix;
        if (self.location.len < 2 or self.location.len > 32) return error.InvalidLocation;
        for (self.location) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte)) return error.InvalidLocation;
        if (!std.mem.eql(u8, self.vm_size, "Standard_D2s_v5") and
            !std.mem.eql(u8, self.vm_size, "Standard_D2as_v5") and
            !std.mem.eql(u8, self.vm_size, "Standard_B2s")) return error.InvalidSize;
        _ = try prep.contracts.identity(self.run_id);
        _ = try prep.contracts.identity(self.disk_id);
        if (std.mem.eql(u8, self.run_id, self.disk_id)) return error.IdentityCollision;
        if (self.sectors != 8388608 or self.sector_size != 512 or self.lun != 7)
            return error.InvalidGeometry;
        if (self.runtime_seconds < 60 or self.runtime_seconds > 3600 or
            self.cleanup_seconds < 60 or self.cleanup_seconds > 1800 or
            self.operation_seconds < 10 or self.operation_seconds > 600 or
            self.poll_seconds < 1 or self.poll_seconds > 30) return error.InvalidBudget;
        inline for (.{ "os_vhd", "seed_raw", "seed_vhd", "manifest", "config" }) |name| {
            const item = @field(self, name);
            try files.absoluteFilePath(item.path);
            _ = try c.parseSha256(item.sha256);
            if (item.size == 0) return error.InvalidArtifact;
        }
        if (self.seed_raw.size != 4294967296 or self.seed_vhd.size != 4294967808 or
            self.os_vhd.size < 1049088 or self.os_vhd.size > 268435968 or
            (self.os_vhd.size - 512) % 1048576 != 0 or
            self.manifest.size > 65536 or self.config.size > 1048576) return error.InvalidArtifact;
    }

    pub fn parameters(self: Scope) !prep.seed.Parameters {
        return .{
            .run_id = try prep.contracts.identity(self.run_id),
            .disk_id = try prep.contracts.identity(self.disk_id),
            .sectors = self.sectors,
            .lun = self.lun,
        };
    }
};

fn uuid(text: []const u8) !void {
    if (text.len != 36) return error.InvalidUuid;
    var nonzero = false;
    for (text, 0..) |byte, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (byte != '-') return error.InvalidUuid;
        } else {
            if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidUuid;
            nonzero = nonzero or byte != '0';
        }
    }
    if (!nonzero) return error.InvalidUuid;
}

pub fn parse(comptime T: type, allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(T) {
    const document = try c.Document.parse(allocator, bytes, .{ .bytes = 1024 * 1024, .items = 4096 });
    defer document.deinit();
    try shape(T, document.value());
    return std.json.parseFromValue(T, allocator, document.value(), .{ .allocate = .alloc_always, .ignore_unknown_fields = false });
}

fn shape(comptime T: type, value: std.json.Value) anyerror!void {
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            var names: [info.fields.len][]const u8 = undefined;
            inline for (info.fields, 0..) |field, i| names[i] = field.name;
            const object = try c.exactFields(value, &names);
            inline for (info.fields) |field| try shape(field.type, object.get(field.name).?);
        },
        .optional => |info| if (value != .null) {
            try shape(info.child, value);
        },
        .array => |info| {
            if (value != .array or value.array.items.len != info.len) return error.InvalidArray;
            for (value.array.items) |item| try shape(info.child, item);
        },
        .pointer => _ = try c.string(value),
        .int => _ = try c.integer(T, value),
        .bool => if (value != .bool) {
            return error.ExpectedBoolean;
        },
        .@"enum" => _ = try c.enumeration(T, value),
        else => @compileError("unsupported direct scope field"),
    }
}

pub fn loadScope(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !std.json.Parsed(Scope) {
    var bytes = try files.readSensitiveAbsolute(io, allocator, path, 65536, null);
    defer bytes.deinit();
    const scope = try parse(Scope, allocator, bytes.bytes());
    errdefer scope.deinit();
    try scope.value.validate();
    return scope;
}

fn readArtifact(allocator: std.mem.Allocator, io: std.Io, item: Artifact) ![]u8 {
    const file = try files.openAbsolute(io, item.path, .artifact);
    defer file.close(io);
    const before = try files.snapshot(file);
    if (before.size != item.size or item.size > 1048576) return error.InvalidArtifact;
    const bytes = try allocator.alloc(u8, @intCast(item.size));
    errdefer allocator.free(bytes);
    if (try file.readPositionalAll(io, bytes, 0) != bytes.len or !files.sameSnapshot(before, try files.snapshot(file)))
        return error.ArtifactChanged;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    if (!std.mem.eql(u8, &hash, &try c.parseSha256(item.sha256))) return error.HashMismatch;
    return bytes;
}

pub fn footer(bytes: *const [512]u8, logical_size: u64, disk_id: ?[]const u8) !void {
    if (!std.mem.eql(u8, bytes[0..8], "conectix") or
        std.mem.readInt(u32, bytes[8..12], .big) != 2 or
        std.mem.readInt(u32, bytes[12..16], .big) != 0x10000 or
        std.mem.readInt(u64, bytes[16..24], .big) != std.math.maxInt(u64) or
        std.mem.readInt(u64, bytes[40..48], .big) != logical_size or
        std.mem.readInt(u64, bytes[48..56], .big) != logical_size or
        std.mem.readInt(u32, bytes[60..64], .big) != 2 or bytes[84] != 0)
        return error.InvalidFooter;
    var sum: u32 = 0;
    for (bytes, 0..) |byte, i| if (i < 64 or i >= 68) {
        sum +%= byte;
    };
    if (~sum != std.mem.readInt(u32, bytes[64..68], .big)) return error.InvalidFooterChecksum;
    for (bytes[85..]) |byte| if (byte != 0) return error.InvalidFooter;
    if (disk_id) |id| {
        const found = std.fmt.bytesToHex(bytes[68..84].*, .lower);
        if (!std.mem.eql(u8, &found, id)) return error.WrongDiskIdentity;
    }
}

pub fn seedChunk(bytes: []const u8, offset: u64, parameters: prep.seed.Parameters) !void {
    for (bytes, 0..) |byte, i| {
        const at = offset + i;
        if (at < 4096 or at >= 5120) {
            if (byte != 0) return error.SeedNotPristine;
        }
    }
    inline for (.{ @as(u64, 4096), @as(u64, 4608) }) |at| {
        if (offset <= at and offset + bytes.len >= at + 512)
            try prep.seed.validateSector(bytes[@intCast(at - offset)..][0..512], parameters);
    }
}

fn inspectDisk(io: std.Io, item: Artifact, parameters: ?prep.seed.Parameters, vhd: bool) !void {
    const file = try files.openAbsolute(io, item.path, if (parameters != null) .private else .artifact);
    defer file.close(io);
    const before = try files.snapshot(file);
    if (before.size != item.size) return error.WrongDiskSize;
    const logical = item.size - @as(u64, if (vhd) 512 else 0);
    var buffer: [1024 * 1024]u8 = undefined;
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    var offset: u64 = 0;
    while (offset < logical) {
        const length: usize = @intCast(@min(logical - offset, buffer.len));
        if (try file.readPositionalAll(io, buffer[0..length], offset) != length) return error.ArtifactChanged;
        if (parameters) |expected| try seedChunk(buffer[0..length], offset, expected);
        sha.update(buffer[0..length]);
        offset += length;
    }
    if (vhd) {
        var tail: [512]u8 = undefined;
        if (try file.readPositionalAll(io, &tail, logical) != tail.len) return error.ArtifactChanged;
        try footer(&tail, logical, if (parameters) |expected| &expected.disk_id else null);
        sha.update(&tail);
    }
    if (!std.mem.eql(u8, &sha.finalResult(), &try c.parseSha256(item.sha256)) or
        !files.sameSnapshot(before, try files.snapshot(file))) return error.ArtifactChanged;
}

pub fn inspectManifest(allocator: std.mem.Allocator, bytes: []const u8, parameters: prep.seed.Parameters) !void {
    const Manifest = struct {
        version: u8,
        run_id: []const u8,
        disk_id: []const u8,
        sectors: u64,
        sector_size: u16,
        identity_policy: []const u8,
        identity_policy_version: u8,
        path: ?u8,
        target: ?u8,
        lun: u8,
        seed_lbas: [2]u64,
        intent_lba: u64,
        receipt_lba: u64,
        extent_lba: u64,
        extent_sectors: u32,
        manifest_crc32: u32,
    };
    const parsed = try parse(Manifest, allocator, bytes);
    defer parsed.deinit();
    const m = parsed.value;
    const sector = try prep.seed.encodeSector(parameters);
    if (m.version != 2 or m.identity_policy_version != 2 or !std.mem.eql(u8, m.identity_policy, "seed-enrollment-v2") or
        !std.mem.eql(u8, m.run_id, &parameters.run_id) or !std.mem.eql(u8, m.disk_id, &parameters.disk_id) or
        m.sectors != parameters.sectors or m.sector_size != 512 or m.lun != 7 or m.path != null or m.target != null or
        !std.meta.eql(m.seed_lbas, [2]u64{ 8, 9 }) or m.intent_lba != 16 or m.receipt_lba != 17 or
        m.extent_lba != 32 or m.extent_sectors != 16 or m.manifest_crc32 != std.mem.readInt(u32, sector[508..512], .little))
        return error.ManifestMismatch;
}

pub fn inspectConfig(allocator: std.mem.Allocator, bytes: []const u8, parameters: prep.seed.Parameters) !void {
    // The complete solved file is hash-bound; project only the authoritative
    // guard symbols to avoid guessing unrelated Kconfig integer/hex metadata.
    var projected: std.Io.Writer.Allocating = .init(allocator);
    defer projected.deinit();
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var platform: u8 = 0;
    var arch: u8 = 0;
    var cpus: u8 = 0;
    while (lines.next()) |line| {
        if (std.mem.eql(u8, line, "CONFIG_PLAT_KVM=y") or std.mem.eql(u8, line, "CONFIG_PLAT_XEN=y"))
            return error.WrongPlatform;
        if (std.mem.startsWith(u8, line, "CONFIG_PLAT_HYPERV=")) {
            if (!std.mem.eql(u8, line, "CONFIG_PLAT_HYPERV=y") or platform != 0) return error.WrongPlatform;
            platform += 1;
        }
        if (std.mem.startsWith(u8, line, "CONFIG_ARCH_X86_64=")) {
            if (!std.mem.eql(u8, line, "CONFIG_ARCH_X86_64=y") or arch != 0) return error.WrongPlatform;
            arch += 1;
        }
        if (std.mem.startsWith(u8, line, "CONFIG_UKPLAT_CPU_MAXCOUNT=")) {
            if (!std.mem.eql(u8, line, "CONFIG_UKPLAT_CPU_MAXCOUNT=1") or cpus != 0) return error.WrongPlatform;
            cpus += 1;
        }
        if (std.mem.indexOf(u8, line, "CONFIG_APPHYPERVACCEPTANCE") != null or
            std.mem.indexOf(u8, line, "CONFIG_LIBSTORVSC") != null)
            try projected.writer.print("{s}\n", .{line});
    }
    if (platform != 1 or arch != 1 or cpus != 1) return error.WrongPlatform;
    try prep.config.validateDirectPersistence(allocator, projected.written(), parameters.guard());
}

pub fn inspect(allocator: std.mem.Allocator, io: std.Io, scope: Scope) !void {
    const parameters = try scope.parameters();
    const manifest = try readArtifact(allocator, io, scope.manifest);
    defer allocator.free(manifest);
    try inspectManifest(allocator, manifest, parameters);
    const config = try readArtifact(allocator, io, scope.config);
    defer allocator.free(config);
    try inspectConfig(allocator, config, parameters);
    try inspectDisk(io, scope.seed_raw, parameters, false);
    try inspectDisk(io, scope.seed_vhd, parameters, true);
    try inspectDisk(io, scope.os_vhd, null, true);
}

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        // No raw serial, paths, ARM response, or credential may reach diagnostics.
        if (err == error.EvidenceIncomplete) std.process.exit(2);
        var writer = std.Io.File.stderr().writer(init.io, &.{});
        writer.interface.print("direct validation failed: {s}\n", .{@errorName(err)}) catch {};
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len < 3) return error.InvalidCommand;
    const scope = try loadScope(a, init.io, args[2]);
    defer scope.deinit();
    if (args.len == 3 and std.mem.eql(u8, args[1], "scope")) return;
    if (args.len == 4 and std.mem.eql(u8, args[1], "ledger")) {
        const directory = try files.Directory.open(init.io, args[3]);
        directory.close(init.io);
        return;
    }
    if (args.len == 4 and std.mem.eql(u8, args[1], "json")) {
        var bytes = try files.readSensitiveAbsolute(init.io, a, args[3], 65536, null);
        defer bytes.deinit();
        const document = try c.SensitiveDocument.parse(a, bytes.bytes(), .{ .bytes = 65536 });
        defer document.deinit();
        return;
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "inputs")) return inspect(a, init.io, scope.value);
    if ((args.len == 4 or args.len == 5) and std.mem.eql(u8, args[1], "serial")) {
        var first = try files.readSensitiveAbsolute(init.io, a, args[3], 4 * 1024 * 1024, null);
        defer first.deinit();
        if (first.bytes().len == 0) return error.EvidenceIncomplete;
        const parameters = try scope.value.parameters();
        const input: evidence.EvidenceInput = .{ .run_id = parameters.run_id, .disk_id = parameters.disk_id, .sectors = parameters.sectors, .lun = parameters.lun };
        const boot1 = try evidence.parseWorkload(first.bytes(), 1, input, null);
        if (std.mem.indexOf(u8, first.bytes(), "UK_HYPERV_PLATFORM_READY") == null) return error.PlatformNotReady;
        if (args.len == 5) {
            var full = try files.readSensitiveAbsolute(init.io, a, args[4], 4 * 1024 * 1024, null);
            defer full.deinit();
            if (full.bytes().len == 0) return error.EvidenceIncomplete;
            const second = if (scope.value.serial_mode == .cumulative) try evidence.boot2Suffix(full.bytes(), boot1) else full.bytes();
            _ = try evidence.parseWorkload(second, 2, input, boot1);
            if (std.mem.indexOf(u8, second, "UK_HYPERV_PLATFORM_READY") == null) return error.PlatformNotReady;
        }
        return;
    }
    return error.InvalidCommand;
}
