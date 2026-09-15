// SPDX-License-Identifier: BSD-3-Clause
//! Fresh local ORIGINAL seeds, not ledger admission or image/boot provenance.
const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const config = @import("config.zig");
const seed = @import("seed.zig");
const private = c.core.private_files;

pub const logical_size: u64 = config.persistence_sectors * seed.sector_size;
pub const record_name = "production.json";
pub const schema = "unikraft.hyperv.original-seed.production.native";
pub const started =
    "{\"authority\":\"not_admitted\",\"scope\":\"local_original_seed_production_only\",\"state\":\"started_not_acceptance\"}";
const names = [_][]const u8{
    "original.raw", "original.vhd", "original.json", "original.config",
};

/// The legacy strict version-2 input schema deliberately has no producer fields.
pub const Manifest = struct {
    version: u8,
    run_id: c.Identity,
    disk_id: c.Identity,
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

pub const Record = struct {
    schema: []const u8 = schema,
    schema_version: u8 = 1,
    scope: enum { local_original_seed_production_only } = .local_original_seed_production_only,
    authority: enum { not_admitted } = .not_admitted,
    provenance: enum { producer_self_report_not_authenticated } = .producer_self_report_not_authenticated,
    identity_generation: enum { os_csprng_fresh } = .os_csprng_fresh,
    configuration: enum { original_seed_fragment_unsolved } = .original_seed_fragment_unsolved,
    guard: config.Guard,
    raw: c.File,
    vhd: c.File,
    manifest: c.File,
    original_config: c.File,
    producer: struct {
        implementation: enum { native_original_seed_v1 } = .native_original_seed_v1,
        compiler_version: []const u8 = c.compiler_version,
        miz_revision: []const u8 = c.miz_revision,
        footer_creator: []const u8 = &seed.footer_creator,
    } = .{},
};

fn validateParameters(parameters: seed.Parameters) !void {
    try config.validateGuardPurpose(parameters.guard(), .persistence);
    if (std.mem.eql(u8, &parameters.run_id, &parameters.disk_id)) return error.IdentityCollision;
}

fn freshParameters(io: std.Io) !seed.Parameters {
    var entropy: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &entropy);
    // Unlike Io.random, randomSecure never falls back to a weaker entropy source.
    try io.randomSecure(&entropy);
    const parameters: seed.Parameters = .{
        .run_id = std.fmt.bytesToHex(entropy[0..16].*, .lower),
        .disk_id = std.fmt.bytesToHex(entropy[16..32].*, .lower),
        .sectors = config.persistence_sectors,
        .lun = 7,
    };
    try validateParameters(parameters);
    return parameters;
}

fn renderManifest(allocator: std.mem.Allocator, parameters: seed.Parameters) ![]u8 {
    try validateParameters(parameters);
    const sector = try seed.encodeSector(parameters);
    return c.canonical(allocator, Manifest{
        .version = 2,
        .run_id = parameters.run_id,
        .disk_id = parameters.disk_id,
        .sectors = parameters.sectors,
        .sector_size = seed.sector_size,
        .identity_policy = "seed-enrollment-v2",
        .identity_policy_version = 2,
        .path = null,
        .target = null,
        .lun = parameters.lun,
        .seed_lbas = seed.seed_lbas,
        .intent_lba = seed.intent_lba,
        .receipt_lba = seed.receipt_lba,
        .extent_lba = seed.extent_lba,
        .extent_sectors = seed.extent_sectors,
        .manifest_crc32 = std.mem.readInt(u32, sector[508..512], .little),
    });
}

fn syncDirectory(io: std.Io, directory: std.Io.Dir) !void {
    try (std.Io.File{ .handle = directory.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

fn publish(
    io: std.Io,
    lock: *private.Locked,
    name: []const u8,
    bytes: []const u8,
    failures: *c.Failure,
) !void {
    try fs.requireLock(io, lock);
    const result = try fs.publish(lock, io, name, bytes);
    if (result.failures.recording) |value| try failures.record(.recording, value);
    if (result.failures.cleanup) |value| try failures.record(.cleanup, value);
    if (result.status != .durable or result.failures.recording != null or result.failures.cleanup != null)
        return error.PublicationIncomplete;
    try fs.requireLock(io, lock);
}

fn writeAll(io: std.Io, file: std.Io.File, bytes: []const u8, offset: u64) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const count = try file.writePositional(io, &.{bytes[written..]}, offset + written);
        if (count == 0) return error.NoProgress;
        written += count;
    }
}

/// Internal streaming primitive. Only create() selects production parameters;
/// small native tests exercise the same I/O without producing original records.
fn writeDisk(io: std.Io, lock: *private.Locked, name: []const u8, parameters: seed.Parameters, vhd: bool) !void {
    try fs.requireLock(io, lock);
    try private.basename(name);
    const sector = try seed.encodeSector(parameters);
    const footer = (try seed.fixedFooter(parameters)).encode();
    const size = parameters.sectors * seed.sector_size;
    const file = try lock.directory.dir.createFile(io, name, .{
        .exclusive = true,
        .read = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(io);
    // Exclusive new regular files have zero-filled holes; no existing disk is
    // opened, truncated, copied, relabelled, or adopted.
    try file.setLength(io, size + @as(u64, if (vhd) seed.sector_size else 0));
    for (seed.seed_lbas) |lba| try writeAll(io, file, &sector, lba * seed.sector_size);
    if (vhd) try writeAll(io, file, &footer, size);
    try file.sync(io);
    const pinned = try Pinned.open(io, lock.directory, name);
    defer pinned.close(io);
    if (!std.meta.eql(try fs.metadata(file), pinned.before)) return error.SourceChanged;
    try pinned.unchanged(io, lock.directory);
    try syncDirectory(io, lock.directory.dir);
    try fs.requireLock(io, lock);
}

const Pinned = struct {
    name: []const u8,
    file: std.Io.File,
    before: fs.Metadata,

    fn open(io: std.Io, directory: private.Directory, name: []const u8) !Pinned {
        const file = try directory.openFile(io, name);
        errdefer file.close(io);
        return .{ .name = name, .file = file, .before = try fs.metadata(file) };
    }
    fn close(self: Pinned, io: std.Io) void {
        self.file.close(io);
    }
    fn unchanged(self: Pinned, io: std.Io, directory: private.Directory) !void {
        const named = try directory.openFile(io, self.name);
        defer named.close(io);
        if (!std.meta.eql(self.before, try fs.metadata(self.file)) or
            !std.meta.eql(self.before, try fs.metadata(named))) return error.SourceChanged;
    }
    fn binding(self: Pinned, sha: c.Sha) c.File {
        return .{ .path = self.name, .size = self.before.size, .mode = self.before.mode & 0o7777, .sha256 = sha };
    }
    fn read(self: Pinned, allocator: std.mem.Allocator, io: std.Io, maximum: usize) ![]u8 {
        if (self.before.size > maximum) return error.FileTooLarge;
        const bytes = try allocator.alloc(u8, @as(usize, @intCast(self.before.size)) + 1);
        errdefer allocator.free(bytes);
        if (try self.file.readPositionalAll(io, bytes, 0) != self.before.size) return error.SourceChanged;
        return bytes;
    }
};

fn pristine(bytes: []const u8, offset: u64) !void {
    const first = seed.seed_lbas[0] * seed.sector_size;
    const end = (seed.seed_lbas[1] + 1) * seed.sector_size;
    if (offset < first and !std.mem.allEqual(u8, bytes[0..@min(bytes.len, first - offset)], 0))
        return error.NonzeroPristineRegion;
    if (offset + bytes.len > end and !std.mem.allEqual(u8, bytes[@intCast(end -| offset)..], 0))
        return error.NonzeroPristineRegion;
}

fn scan(io: std.Io, raw: Pinned, vhd: Pinned, parameters: seed.Parameters) ![2]c.File {
    try config.validateGuard(parameters.guard());
    const size = parameters.sectors * seed.sector_size;
    if (raw.before.size != size or vhd.before.size != size + seed.sector_size) return error.InvalidImageLength;
    for (seed.seed_lbas) |lba| {
        var sector: seed.Sector = undefined;
        if (try raw.file.readPositionalAll(io, &sector, lba * seed.sector_size) != sector.len) return error.SourceChanged;
        try seed.validateSector(&sector, parameters);
    }
    var raw_hash = std.crypto.hash.sha2.Sha256.init(.{});
    var vhd_hash = std.crypto.hash.sha2.Sha256.init(.{});
    var left: [64 * 1024]u8 = undefined;
    var right: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        const length: usize = @intCast(@min(left.len, size - offset));
        if (try raw.file.readPositionalAll(io, left[0..length], offset) != length or
            try vhd.file.readPositionalAll(io, right[0..length], offset) != length) return error.SourceChanged;
        if (!std.mem.eql(u8, left[0..length], right[0..length])) return error.RawPrefixMismatch;
        try pristine(left[0..length], offset);
        raw_hash.update(left[0..length]);
        vhd_hash.update(right[0..length]);
        offset += length;
    }
    var footer: seed.Sector = undefined;
    if (try vhd.file.readPositionalAll(io, &footer, size) != footer.len) return error.SourceChanged;
    try seed.validateFooter(&footer, parameters);
    vhd_hash.update(&footer);
    if (try raw.file.readPositionalAll(io, left[0..1], size) != 0 or
        try vhd.file.readPositionalAll(io, right[0..1], size + seed.sector_size) != 0) return error.SourceChanged;
    return .{
        raw.binding(std.fmt.bytesToHex(raw_hash.finalResult(), .lower)),
        vhd.binding(std.fmt.bytesToHex(vhd_hash.finalResult(), .lower)),
    };
}

fn measure(allocator: std.mem.Allocator, io: std.Io, directory: private.Directory, parameters: seed.Parameters) !Record {
    try validateParameters(parameters);
    var pinned: [names.len]Pinned = undefined;
    var opened: usize = 0;
    defer for (pinned[0..opened]) |file| file.close(io);
    for (names, 0..) |name, i| {
        pinned[i] = try Pinned.open(io, directory, name);
        opened += 1;
    }
    const manifest = try renderManifest(allocator, parameters);
    defer allocator.free(manifest);
    const fragment = try config.render(allocator, parameters.guard());
    defer allocator.free(fragment);
    var controls: [2]c.File = undefined;
    for ([_][]const u8{ manifest, fragment }, 0..) |wanted, i| {
        const file = pinned[i + 2];
        const bytes = try file.read(allocator, io, config.config_cap);
        defer allocator.free(bytes);
        if (!std.mem.eql(u8, bytes[0..@intCast(file.before.size)], wanted)) return error.SourceChanged;
        if (i == 1) try config.validatePurpose(allocator, wanted, parameters.guard(), .persistence);
        controls[i] = file.binding(try fs.hashFile(io, file.file, file.before.size));
    }
    const disks = try scan(io, pinned[0], pinned[1], parameters);
    for (pinned) |file| try file.unchanged(io, directory);
    return .{
        .guard = parameters.guard(),
        .raw = disks[0],
        .vhd = disks[1],
        .manifest = controls[0],
        .original_config = controls[1],
    };
}

fn inventory(io: std.Io, directory: private.Directory, final: bool) !void {
    var count: usize = 0;
    var iterator = directory.dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .file) return error.UnexpectedOutput;
        var known = std.mem.eql(u8, entry.name, ".writer.lock") or
            std.mem.eql(u8, entry.name, "production.started.json") or
            (final and std.mem.eql(u8, entry.name, record_name));
        for (names) |name| known = known or std.mem.eql(u8, entry.name, name);
        if (!known) return error.UnexpectedOutput;
        count += 1;
    }
    if (count != names.len + 2 + @as(usize, if (final) 1 else 0)) return error.IncompleteOutput;
}

/// Complete local byte/metadata inspection, never admission. The expected hash
/// binds the producer's self-report; it does not authenticate that producer.
pub fn inspect(allocator: std.mem.Allocator, io: std.Io, directory: private.Directory, expected: c.Sha) !Record {
    const record = try Pinned.open(io, directory, record_name);
    defer record.close(io);
    const storage = try record.read(allocator, io, 64 * 1024);
    defer allocator.free(storage);
    const bytes = storage[0..@intCast(record.before.size)];
    if (!std.mem.eql(u8, &c.digest(bytes), &expected)) return error.HashMismatch;
    const parsed = try c.parse(Record, allocator, bytes);
    defer parsed.deinit();
    const guard = parsed.value.guard;
    try config.validateGuardPurpose(guard, .persistence);
    const measured = try measure(allocator, io, directory, .{
        .run_id = guard.run_id,
        .disk_id = guard.disk_id,
        .sectors = guard.sectors,
        .lun = guard.lun,
    });
    const wanted = try c.canonical(allocator, measured);
    defer allocator.free(wanted);
    if (!std.mem.eql(u8, bytes, wanted)) return error.ProductionRecordMismatch;
    const marker = try directory.read(io, allocator, "production.started.json", 1024, try c.core.contracts.parseSha256(&c.digest(started)));
    defer allocator.free(marker);
    try inventory(io, directory, true);
    try record.unchanged(io, directory);
    return measured;
}

fn custody(io: std.Io, parent: *private.Locked, child: *private.Locked, parent_path: []const u8, child_path: []const u8) !void {
    try fs.requireLock(io, parent);
    try fs.requireLock(io, child);
    const again_parent = try fs.openPrivate(io, parent_path);
    defer again_parent.close(io);
    const again_child = try fs.openPrivate(io, child_path);
    defer again_child.close(io);
    try fs.requireDirectoryIdentity(
        .{ .dir = parent.directory.dir, .path = parent_path },
        .{ .dir = again_parent.dir, .path = parent_path },
    );
    try fs.requireDirectoryIdentity(
        .{ .dir = child.directory.dir, .path = child_path },
        .{ .dir = again_child.dir, .path = child_path },
    );
}

/// The only production constructor: no identities, sizes, footer input, or RNG
/// controls are accepted. Errors preserve the fresh child for private diagnosis;
/// a child without a valid production record is incomplete and cannot be retried.
pub fn create(allocator: std.mem.Allocator, io: std.Io, parent_path: []const u8, name: []const u8, failures: *c.Failure) !c.Sha {
    try private.basename(name);
    try c.relative(name);
    if (name[0] == '.') return error.UnsafePath;
    const parent = try fs.openPrivate(io, parent_path);
    defer parent.close(io);
    var parent_lock = try parent.lock(io);
    defer parent_lock.close(io);
    const child_path = try std.fs.path.join(allocator, &.{ parent_path, name });
    defer allocator.free(child_path);
    try fs.requireLock(io, &parent_lock);
    try parent.dir.createDir(io, name, .fromMode(0o700));
    try syncDirectory(io, parent.dir);
    const child = try fs.openPrivate(io, child_path);
    defer child.close(io);
    var lock = try child.lock(io);
    defer lock.close(io);
    try custody(io, &parent_lock, &lock, parent_path, child_path);
    try publish(io, &lock, "production.started.json", started, failures);
    const parameters = try freshParameters(io);
    const manifest = try renderManifest(allocator, parameters);
    defer allocator.free(manifest);
    const fragment = try config.render(allocator, parameters.guard());
    defer allocator.free(fragment);
    try writeDisk(io, &lock, names[0], parameters, false);
    try writeDisk(io, &lock, names[1], parameters, true);
    try publish(io, &lock, names[2], manifest, failures);
    try publish(io, &lock, names[3], fragment, failures);
    try inventory(io, child, false);
    const record = try measure(allocator, io, child, parameters);
    const bytes = try c.canonical(allocator, record);
    defer allocator.free(bytes);
    const sha = c.digest(bytes);
    try custody(io, &parent_lock, &lock, parent_path, child_path);
    try publish(io, &lock, record_name, bytes, failures);
    try syncDirectory(io, parent.dir);
    _ = try inspect(allocator, io, child, sha);
    try custody(io, &parent_lock, &lock, parent_path, child_path);
    return sha;
}

pub const Test = if (@import("builtin").is_test) struct {
    pub const parameters = freshParameters;
    pub const manifest = renderManifest;
    pub const disk = writeDisk;
    pub const publishBytes = publish;

    pub fn inspectDisks(io: std.Io, directory: private.Directory, parameters_: seed.Parameters) ![2]c.File {
        const raw = try Pinned.open(io, directory, names[0]);
        defer raw.close(io);
        const vhd = try Pinned.open(io, directory, names[1]);
        defer vhd.close(io);
        const result = try scan(io, raw, vhd, parameters_);
        try raw.unchanged(io, directory);
        try vhd.unchanged(io, directory);
        return result;
    }
} else struct {};
