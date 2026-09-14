const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const miz = @import("miz").efi_application_image;
const private = c.core.private_files;

pub const raw_name = "acceptance.raw";
pub const vhd_name = "acceptance.vhd";
pub const esp_bytes: u64 = 64 * 1024 * 1024;
pub const esp_offset: u64 = 1024 * 1024;
pub const vhd_bytes: u64 = c.image_bytes + 512;
pub const maximum_efi_bytes = esp_bytes;
const stage_name = ".package-stage";

pub const Identities = struct {
    /// Hex encodes miz's on-disk GPT GUID byte order, not display-order UUIDs.
    disk_guid_le: c.Identity,
    esp_partition_guid_le: c.Identity,
    esp_volume_id: u32,
};

pub const Geometry = struct {
    virtual_size: u64,
    sector_size: u32,
    esp_offset_bytes: u64,
    esp_length_bytes: u64,
};

pub const PackageReport = struct {
    schema: enum { miz_efi_application_package_v1 },
    miz_revision: []const u8,
    architecture: miz.Architecture,
    generation: enum { gen1, gen2 },
    boot_path: []const u8,
    efi: c.File,
    raw: c.File,
    vhd: c.File,
    identities: Identities,
    geometry: Geometry,
    raw_vhd_prefix_sha256: c.Sha,
};

/// A failure may leave unreceipted final artifacts. Neither a primary failure
/// nor a cleanup failure is success, and cleanup never erases the primary.
pub const Result = struct {
    report: ?PackageReport = null,
    primary: ?anyerror = null,
    cleanup: ?anyerror = null,

    pub fn succeeded(self: Result) bool {
        return self.report != null and self.primary == null and self.cleanup == null;
    }
};

fn requireEfi(efi: c.File) !void {
    try c.relative(efi.path);
    _ = try c.sha(&efi.sha256);
    if (efi.size == 0 or efi.size > maximum_efi_bytes or efi.mode & 0o7022 != 0 or
        efi.mode & ~@as(u16, 0o7777) != 0)
        return error.InvalidEfiRecord;
}

fn requireOutput(file: c.File, name: []const u8, size: u64) !void {
    _ = try c.sha(&file.sha256);
    if (!std.mem.eql(u8, file.path, name) or file.mode != 0o600 or file.size != size)
        return error.InvalidPackageRecord;
}

/// Shape/consistency checks only. Use validate for admission of stored receipts;
/// a serialized receipt is not proof that native image validation took place.
pub fn validateReport(report: PackageReport) !void {
    try requireEfi(report.efi);
    try requireOutput(report.raw, raw_name, c.image_bytes);
    try requireOutput(report.vhd, vhd_name, vhd_bytes);
    if (!std.mem.eql(u8, report.miz_revision, c.miz_revision)) return error.MizRevisionMismatch;
    if (report.architecture != .x86_64 or report.generation != .gen2 or
        !std.mem.eql(u8, report.boot_path, miz.fallback_x86_64))
        return error.PackageBootMismatch;
    if (report.geometry.virtual_size != c.image_bytes or report.geometry.sector_size != 512 or
        report.geometry.esp_offset_bytes != esp_offset or report.geometry.esp_length_bytes != esp_bytes)
        return error.PackageGeometryMismatch;
    _ = try c.identity(&report.identities.disk_guid_le);
    _ = try c.identity(&report.identities.esp_partition_guid_le);
    if (std.mem.eql(u8, &report.identities.disk_guid_le, &report.identities.esp_partition_guid_le) or
        report.identities.esp_volume_id == 0)
        return error.PackageIdentityMismatch;
    _ = try c.sha(&report.raw_vhd_prefix_sha256);
    if (!std.crypto.timing_safe.eql(c.Sha, report.raw.sha256, report.raw_vhd_prefix_sha256))
        return error.RawVhdMismatch;
}

fn fromValidation(
    efi: c.File,
    raw: c.File,
    vhd: c.File,
    checked: miz.ValidationReport,
    prefix_sha256: c.Sha,
) !PackageReport {
    const input_sha256 = try binarySha(efi.sha256);
    if (checked.architecture != .x86_64 or !std.mem.eql(u8, checked.boot_path, miz.fallback_x86_64) or
        checked.boot_file_size != efi.size or
        !std.crypto.timing_safe.eql([32]u8, checked.boot_file_sha256, input_sha256))
        return error.PackageBootMismatch;
    if (checked.virtual_size != c.image_bytes or checked.file_size != vhd_bytes or
        checked.esp_offset_bytes != esp_offset or checked.esp_length_bytes != esp_bytes)
        return error.PackageGeometryMismatch;
    const report: PackageReport = .{
        .schema = .miz_efi_application_package_v1,
        .miz_revision = c.miz_revision,
        .architecture = checked.architecture,
        .generation = .gen2,
        .boot_path = miz.fallback_x86_64,
        .efi = efi,
        .raw = raw,
        .vhd = vhd,
        .identities = .{
            .disk_guid_le = std.fmt.bytesToHex(checked.disk_guid, .lower),
            .esp_partition_guid_le = std.fmt.bytesToHex(checked.esp_partition_guid, .lower),
            .esp_volume_id = checked.esp_volume_id,
        },
        .geometry = .{
            .virtual_size = checked.virtual_size,
            .sector_size = 512,
            .esp_offset_bytes = checked.esp_offset_bytes,
            .esp_length_bytes = checked.esp_length_bytes,
        },
        .raw_vhd_prefix_sha256 = prefix_sha256,
    };
    try validateReport(report);
    return report;
}

fn requireBuild(built: miz.Report, report: PackageReport, comptime format: @FieldType(miz.Report, "output_format")) !void {
    if (built.output_format != format or built.architecture != report.architecture or
        !std.mem.eql(u8, built.boot_path, report.boot_path) or built.input_size != report.efi.size or
        !std.crypto.timing_safe.eql([32]u8, built.input_sha256, try binarySha(report.efi.sha256)))
        return error.PackageBootMismatch;
    if (built.virtual_size != report.geometry.virtual_size or
        built.esp_offset_bytes != report.geometry.esp_offset_bytes or
        built.esp_length_bytes != report.geometry.esp_length_bytes)
        return error.PackageGeometryMismatch;
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(built.disk_guid, .lower), &report.identities.disk_guid_le) or
        !std.mem.eql(u8, &std.fmt.bytesToHex(built.esp_partition_guid, .lower), &report.identities.esp_partition_guid_le) or
        built.esp_volume_id != report.identities.esp_volume_id)
        return error.PackageIdentityMismatch;
}

/// Pure comparison of the two actual native build reports and the independent
/// native fixed-VHD validation. Strings in the returned receipt are borrowed.
pub fn fromNative(
    efi: c.File,
    raw: c.File,
    vhd: c.File,
    raw_build: miz.Report,
    vhd_build: miz.Report,
    checked: miz.ValidationReport,
    prefix_sha256: c.Sha,
) !PackageReport {
    const report = try fromValidation(efi, raw, vhd, checked, prefix_sha256);
    try requireBuild(raw_build, report, .raw);
    try requireBuild(vhd_build, report, .vhd);
    return report;
}

fn binarySha(sha256: c.Sha) ![32]u8 {
    _ = try c.sha(&sha256);
    var result: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, &sha256);
    return result;
}

fn directoryFile(dir: std.Io.Dir) std.Io.File {
    return .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
}

fn requirePrivateDirectory(dir: std.Io.Dir) !void {
    const value = try fs.metadata(directoryFile(dir));
    if (value.mode & std.os.linux.S.IFMT != std.os.linux.S.IFDIR or value.mode & 0o7777 != 0o700 or
        value.uid != std.os.linux.geteuid())
        return error.UnsafeFile;
}

fn requireLock(io: std.Io, lock: *private.Locked) !void {
    try fs.requireLock(io, lock);
}

fn requireAbsent(io: std.Io, dir: std.Io.Dir, name: []const u8) !void {
    const file = dir.openFile(io, name, .{ .path_only = true, .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    file.close(io);
    return error.PathAlreadyExists;
}

fn descriptorRecord(allocator: std.mem.Allocator, io: std.Io, file: std.Io.File, name: []const u8, maximum: u64) !c.File {
    const before = try fs.metadata(file);
    if (before.size == 0 or before.size > maximum) return error.FileTooLarge;
    const sha256 = try fs.hashFile(io, file, before.size);
    if (!std.meta.eql(before, try fs.metadata(file))) return error.SourceChanged;
    return .{ .path = try allocator.dupe(u8, name), .sha256 = sha256, .size = before.size, .mode = before.mode & 0o7777 };
}

fn requireInputUnchanged(io: std.Io, input: fs.Directory, file: std.Io.File, before: fs.Metadata, expected: c.File) !void {
    if (!std.meta.eql(before, try fs.metadata(file))) return error.SourceChanged;
    if (!std.crypto.timing_safe.eql(c.Sha, try fs.hashFile(io, file, before.size), expected.sha256))
        return error.SourceChanged;
    if (!std.meta.eql(before, try fs.metadata(file))) return error.SourceChanged;
    const named = try input.openFile(io, expected.path, .artifact);
    defer named.close(io);
    if (!std.meta.eql(before, try fs.metadata(named))) return error.SourceChanged;
}

fn normalize(io: std.Io, dir: std.Io.Dir, name: []const u8) !void {
    const directory: fs.Directory = .{ .dir = dir, .path = "" };
    const file = try directory.openFile(io, name, .artifact);
    defer file.close(io);
    const metadata = try fs.metadata(file);
    if (metadata.uid != std.os.linux.geteuid() or metadata.links != 1) return error.UnsafeFile;
    try file.setPermissions(io, .fromMode(0o600));
    try file.sync(io);
}

fn prefixHash(io: std.Io, file: std.Io.File) !c.Sha {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var offset: u64 = 0;
    while (offset < c.image_bytes) {
        const slice = buffer[0..@min(buffer.len, c.image_bytes - offset)];
        if (try file.readPositionalAll(io, slice, offset) != slice.len) return error.SourceChanged;
        hash.update(slice);
        offset += slice.len;
    }
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}

fn observe(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: private.Directory,
    efi: c.File,
) !PackageReport {
    try requirePrivateDirectory(directory.dir);
    const raw = try directory.openFile(io, raw_name);
    defer raw.close(io);
    const vhd = try directory.openFile(io, vhd_name);
    defer vhd.close(io);
    const raw_before = try fs.metadata(raw);
    const vhd_before = try fs.metadata(vhd);
    if (raw_before.size != c.image_bytes or vhd_before.size != vhd_bytes) return error.PackageGeometryMismatch;
    const raw_record = try descriptorRecord(allocator, io, raw, raw_name, c.image_bytes);
    const vhd_record = try descriptorRecord(allocator, io, vhd, vhd_name, vhd_bytes);
    const prefix_sha256 = try prefixHash(io, vhd);
    if (!std.crypto.timing_safe.eql(c.Sha, raw_record.sha256, prefix_sha256)) return error.RawVhdMismatch;
    var vhd_path_buffer: [64]u8 = undefined;
    const checked = try miz.validateFixedVhd(allocator, io, .{
        .path = try std.fmt.bufPrint(&vhd_path_buffer, "/proc/self/fd/{d}", .{vhd.handle}),
        .architecture = .x86_64,
        .expected_efi_sha256 = try binarySha(efi.sha256),
        .expected_virtual_size = c.image_bytes,
        .max_efi_size = maximum_efi_bytes,
    });
    if (!std.meta.eql(raw_before, try fs.metadata(raw)) or !std.meta.eql(vhd_before, try fs.metadata(vhd)))
        return error.SourceChanged;
    const raw_named = try directory.openFile(io, raw_name);
    defer raw_named.close(io);
    const vhd_named = try directory.openFile(io, vhd_name);
    defer vhd_named.close(io);
    if (!std.meta.eql(raw_before, try fs.metadata(raw_named)) or !std.meta.eql(vhd_before, try fs.metadata(vhd_named)))
        return error.SourceChanged;
    // Native validation proves Gen2/GPT/FAT/PE and deterministic VHD metadata.
    // Equality of the complete raw digest and the VHD prefix transfers that
    // same disk validation to raw without introducing another format parser.
    return fromValidation(efi, raw_record, vhd_record, checked, prefix_sha256);
}

fn requireSameReport(actual: PackageReport, expected: PackageReport) !void {
    try validateReport(expected);
    try fs.requireFile(actual.efi, expected.efi);
    try fs.requireFile(actual.raw, expected.raw);
    try fs.requireFile(actual.vhd, expected.vhd);
    if (!std.meta.eql(actual.identities, expected.identities)) return error.PackageIdentityMismatch;
    if (!std.meta.eql(actual.geometry, expected.geometry)) return error.PackageGeometryMismatch;
    if (!std.crypto.timing_safe.eql(c.Sha, actual.raw_vhd_prefix_sha256, expected.raw_vhd_prefix_sha256))
        return error.RawVhdMismatch;
}

/// Read-only revalidation uses the receipt only as expectations; all artifact
/// hashes/sizes and the native fixed-VHD report are recomputed from checked fds.
/// Allocations and returned strings may be arena-scoped.
pub fn validate(
    allocator: std.mem.Allocator,
    io: std.Io,
    output: private.Directory,
    input: fs.Directory,
    expected: PackageReport,
) !PackageReport {
    try validateReport(expected);
    const file = try input.openFile(io, expected.efi.path, .artifact);
    defer file.close(io);
    const before = try fs.metadata(file);
    const efi = try descriptorRecord(allocator, io, file, expected.efi.path, maximum_efi_bytes);
    try fs.requireFile(efi, expected.efi);
    const actual = try observe(allocator, io, output, efi);
    try requireSameReport(actual, expected);
    try requireInputUnchanged(io, input, file, before, expected.efi);
    return actual;
}

fn noteCleanup(result: *Result, err: anyerror) void {
    if (result.cleanup == null) result.cleanup = err;
    result.report = null;
}

fn cleanupStage(io: std.Io, parent: std.Io.Dir, stage: ?std.Io.Dir, result: *Result) void {
    if (stage) |dir| {
        defer dir.close(io);
        var iterator = dir.iterate();
        while (true) {
            const entry = iterator.next(io) catch |err| {
                noteCleanup(result, err);
                break;
            } orelse break;
            if (entry.kind != .file) {
                noteCleanup(result, error.UnexpectedPackageStageEntry);
                continue;
            }
            dir.deleteFile(io, entry.name) catch |err| noteCleanup(result, err);
        }
        directoryFile(dir).sync(io) catch |err| noteCleanup(result, err);
        const named = parent.openDir(io, stage_name, .{ .follow_symlinks = false }) catch |err| {
            noteCleanup(result, err);
            return;
        };
        defer named.close(io);
        const held_metadata = fs.metadata(directoryFile(dir)) catch |err| {
            noteCleanup(result, err);
            return;
        };
        const named_metadata = fs.metadata(directoryFile(named)) catch |err| {
            noteCleanup(result, err);
            return;
        };
        if (held_metadata.device != named_metadata.device or held_metadata.inode != named_metadata.inode) {
            noteCleanup(result, error.SourceChanged);
            return;
        }
    }
    parent.deleteDir(io, stage_name) catch |err| noteCleanup(result, err);
    directoryFile(parent).sync(io) catch |err| noteCleanup(result, err);
}

/// Calls the pinned native miz library, never a subprocess. The lock borrows a
/// caller-validated 0700 directory. Names and geometry cannot be caller-chosen.
/// Both miz's atomic files and our exclusively reserved stage stay beneath that
/// directory. A returned receipt implies 0600 files, no-replace publication,
/// file/directory fsync, stable input, and successful cleanup.
pub fn package(
    allocator: std.mem.Allocator,
    io: std.Io,
    lock: *private.Locked,
    input: fs.Directory,
    expected_efi: c.File,
) Result {
    var result: Result = .{};
    packageImpl(allocator, io, lock, input, expected_efi, &result) catch |err| {
        result.primary = err;
        result.report = null;
    };
    return result;
}

fn packageImpl(
    allocator: std.mem.Allocator,
    io: std.Io,
    lock: *private.Locked,
    input: fs.Directory,
    expected_efi: c.File,
    result: *Result,
) !void {
    try requireLock(io, lock);
    try requireEfi(expected_efi);
    const input_file = try input.openFile(io, expected_efi.path, .artifact);
    defer input_file.close(io);
    const before = try fs.metadata(input_file);
    const efi = try descriptorRecord(allocator, io, input_file, expected_efi.path, maximum_efi_bytes);
    try fs.requireFile(efi, expected_efi);
    try requireInputUnchanged(io, input, input_file, before, expected_efi);
    try requireAbsent(io, lock.directory.dir, raw_name);
    try requireAbsent(io, lock.directory.dir, vhd_name);

    try lock.directory.dir.createDir(io, stage_name, .fromMode(0o700));
    var stage: ?std.Io.Dir = null;
    defer cleanupStage(io, lock.directory.dir, stage, result);
    stage = try lock.directory.dir.openDir(io, stage_name, .{ .follow_symlinks = false, .iterate = true });
    const stage_dir = stage.?;
    try requirePrivateDirectory(stage_dir);
    try directoryFile(lock.directory.dir).sync(io);
    var input_path_buffer: [64]u8 = undefined;
    const input_path = try std.fmt.bufPrint(&input_path_buffer, "/proc/self/fd/{d}", .{input_file.handle});
    var raw_path_buffer: [96]u8 = undefined;
    var vhd_path_buffer: [96]u8 = undefined;
    const raw_build = try miz.build(allocator, io, .{
        .efi_path = input_path,
        .output_path = try std.fmt.bufPrint(&raw_path_buffer, "/proc/self/fd/{d}/{s}", .{ stage_dir.handle, raw_name }),
        .output_format = .raw,
        .architecture = .x86_64,
        .esp_size = esp_bytes,
        .disk_size = null,
        .max_efi_size = maximum_efi_bytes,
    });
    try requireInputUnchanged(io, input, input_file, before, expected_efi);
    const vhd_build = try miz.build(allocator, io, .{
        .efi_path = input_path,
        .output_path = try std.fmt.bufPrint(&vhd_path_buffer, "/proc/self/fd/{d}/{s}", .{ stage_dir.handle, vhd_name }),
        .output_format = .vhd,
        .architecture = .x86_64,
        .esp_size = esp_bytes,
        .disk_size = null,
        .max_efi_size = maximum_efi_bytes,
    });
    try requireInputUnchanged(io, input, input_file, before, expected_efi);
    try normalize(io, stage_dir, raw_name);
    try normalize(io, stage_dir, vhd_name);
    const staged = try observe(allocator, io, .{ .dir = stage_dir }, efi);
    try requireBuild(raw_build, staged, .raw);
    try requireBuild(vhd_build, staged, .vhd);
    try directoryFile(stage_dir).sync(io);
    try requireLock(io, lock);
    try stage_dir.renamePreserve(raw_name, lock.directory.dir, raw_name, io);
    try stage_dir.renamePreserve(vhd_name, lock.directory.dir, vhd_name, io);
    try directoryFile(stage_dir).sync(io);
    try directoryFile(lock.directory.dir).sync(io);
    const published = try observe(allocator, io, lock.directory, efi);
    try requireSameReport(published, staged);
    try requireInputUnchanged(io, input, input_file, before, expected_efi);
    try requireLock(io, lock);
    result.report = published;
}

fn syntheticEfi() [512]u8 {
    var bytes = [_]u8{0} ** 512;
    bytes[0..2].* = "MZ".*;
    std.mem.writeInt(u32, bytes[0x3c..0x40], 0x80, .little);
    bytes[0x80..0x84].* = "PE\x00\x00".*;
    std.mem.writeInt(u16, bytes[0x84..0x86], 0x8664, .little);
    std.mem.writeInt(u16, bytes[0x86..0x88], 1, .little);
    std.mem.writeInt(u16, bytes[0x94..0x96], 0xf0, .little);
    std.mem.writeInt(u16, bytes[0x98..0x9a], 0x20b, .little);
    std.mem.writeInt(u16, bytes[0xdc..0xde], 10, .little);
    return bytes;
}

const NativeFixture = struct {
    efi: c.File,
    raw: c.File,
    vhd: c.File,
    raw_build: miz.Report,
    vhd_build: miz.Report,
    checked: miz.ValidationReport,
    prefix: c.Sha,

    fn report(self: NativeFixture) !PackageReport {
        return fromNative(self.efi, self.raw, self.vhd, self.raw_build, self.vhd_build, self.checked, self.prefix);
    }
};

fn nativeFixture() !NativeFixture {
    const efi: c.File = .{ .path = "synthetic.efi", .sha256 = c.digest(&syntheticEfi()), .size = 512, .mode = 0o600 };
    const raw: c.File = .{ .path = raw_name, .sha256 = c.digest("synthetic raw digest fixture"), .size = c.image_bytes, .mode = 0o600 };
    const raw_build: miz.Report = .{
        .output_format = .raw,
        .architecture = .x86_64,
        .boot_path = miz.fallback_x86_64,
        .input_size = efi.size,
        .input_sha256 = try binarySha(efi.sha256),
        .virtual_size = c.image_bytes,
        .esp_offset_bytes = esp_offset,
        .esp_length_bytes = esp_bytes,
        .disk_guid = [_]u8{1} ** 16,
        .esp_partition_guid = [_]u8{2} ** 16,
        .esp_volume_id = 3,
    };
    var vhd_build = raw_build;
    vhd_build.output_format = .vhd;
    return .{
        .efi = efi,
        .raw = raw,
        .vhd = .{ .path = vhd_name, .sha256 = c.digest("synthetic vhd digest fixture"), .size = vhd_bytes, .mode = 0o600 },
        .raw_build = raw_build,
        .vhd_build = vhd_build,
        .checked = .{
            .architecture = raw_build.architecture,
            .boot_path = raw_build.boot_path,
            .boot_file_size = efi.size,
            .boot_file_sha256 = raw_build.input_sha256,
            .virtual_size = c.image_bytes,
            .file_size = vhd_bytes,
            .disk_guid = raw_build.disk_guid,
            .esp_partition_guid = raw_build.esp_partition_guid,
            .esp_offset_bytes = esp_offset,
            .esp_length_bytes = esp_bytes,
            .esp_volume_id = raw_build.esp_volume_id,
        },
        .prefix = raw.sha256,
    };
}

test "package native report checks reject geometry boot identity and prefix mismatches" {
    const fixture = try nativeFixture();
    _ = try fixture.report();
    var changed = fixture;
    changed.raw_build.output_format = .vhd;
    try std.testing.expectError(error.PackageBootMismatch, changed.report());
    changed = fixture;
    changed.raw_build.virtual_size += 512;
    try std.testing.expectError(error.PackageGeometryMismatch, changed.report());
    changed = fixture;
    changed.vhd_build.esp_length_bytes -= 512;
    try std.testing.expectError(error.PackageGeometryMismatch, changed.report());
    changed = fixture;
    changed.checked.file_size -= 512;
    try std.testing.expectError(error.PackageGeometryMismatch, changed.report());
    changed = fixture;
    changed.checked.architecture = .aarch64;
    try std.testing.expectError(error.PackageBootMismatch, changed.report());
    changed = fixture;
    changed.checked.boot_file_size += 1;
    try std.testing.expectError(error.PackageBootMismatch, changed.report());
    changed = fixture;
    changed.checked.boot_file_sha256[0] ^= 1;
    try std.testing.expectError(error.PackageBootMismatch, changed.report());
    changed = fixture;
    changed.checked.boot_path = miz.fallback_aarch64;
    try std.testing.expectError(error.PackageBootMismatch, changed.report());
    changed = fixture;
    changed.raw_build.disk_guid[0] ^= 1;
    try std.testing.expectError(error.PackageIdentityMismatch, changed.report());
    changed = fixture;
    changed.vhd_build.esp_partition_guid[0] ^= 1;
    try std.testing.expectError(error.PackageIdentityMismatch, changed.report());
    changed = fixture;
    changed.checked.esp_volume_id += 1;
    try std.testing.expectError(error.PackageIdentityMismatch, changed.report());
    changed = fixture;
    changed.prefix = c.digest("different prefix");
    try std.testing.expectError(error.RawVhdMismatch, changed.report());
}

test "package receipt rejects pin generation filenames modes sizes and zero identities" {
    const report = try (try nativeFixture()).report();
    var changed = report;
    changed.miz_revision = "unreviewed";
    try std.testing.expectError(error.MizRevisionMismatch, validateReport(changed));
    changed = report;
    changed.generation = .gen1;
    try std.testing.expectError(error.PackageBootMismatch, validateReport(changed));
    changed = report;
    changed.raw.path = "arbitrary.raw";
    try std.testing.expectError(error.InvalidPackageRecord, validateReport(changed));
    changed = report;
    changed.vhd.mode = 0o644;
    try std.testing.expectError(error.InvalidPackageRecord, validateReport(changed));
    changed = report;
    changed.vhd.size -= 1;
    try std.testing.expectError(error.InvalidPackageRecord, validateReport(changed));
    changed = report;
    changed.identities.disk_guid_le = [_]u8{'0'} ** 32;
    try std.testing.expectError(error.InvalidIdentity, validateReport(changed));
    changed = report;
    changed.identities.esp_volume_id = 0;
    try std.testing.expectError(error.PackageIdentityMismatch, validateReport(changed));
}

test "package real native miz synthetic PE roundtrip is private immutable and revalidated" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    try fixture.dir.createDir(io, "output", .fromMode(0o700));
    const output = try fixture.dir.openDir(io, "output", .{ .follow_symlinks = false, .iterate = true });
    defer output.close(io);
    const private_output: private.Directory = .{ .dir = output };
    var lock = try private_output.lock(io);
    defer lock.close(io);
    const source = try fixture.dir.createFile(io, "synthetic.efi", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer source.close(io);
    try source.writePositionalAll(io, &syntheticEfi(), 0);
    try source.sync(io);
    const input: fs.Directory = .{ .dir = fixture.dir, .path = "" };
    const expected = try input.record(allocator, io, "synthetic.efi", 512, .private);
    const result = package(allocator, io, &lock, input, expected);
    if (result.primary) |err| return err;
    if (result.cleanup) |err| return err;
    try std.testing.expect(result.succeeded());
    const report = result.report.?;
    try std.testing.expectEqual(c.image_bytes, report.raw.size);
    try std.testing.expectEqual(vhd_bytes, report.vhd.size);
    try requireAbsent(io, output, stage_name);
    _ = try validate(allocator, io, private_output, input, report);
    const canonical = try c.canonical(allocator, report);
    const parsed = try c.parse(PackageReport, allocator, canonical);
    defer parsed.deinit();
    try requireSameReport(parsed.value, report);
    const repeated = package(allocator, io, &lock, input, expected);
    try std.testing.expectEqual(error.PathAlreadyExists, repeated.primary.?);
    try std.testing.expect(!repeated.succeeded() and repeated.report == null and repeated.cleanup == null);
    const raw = try output.openFile(io, raw_name, .{ .mode = .read_write, .follow_symlinks = false });
    defer raw.close(io);
    try raw.writePositionalAll(io, &.{0xff}, 4096);
    try raw.sync(io);
    try std.testing.expectError(error.RawVhdMismatch, validate(allocator, io, private_output, input, report));
}

test "package malformed synthetic PE leaves no success or stage and preserves existing outputs" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    const directory: private.Directory = .{ .dir = fixture.dir };
    var lock = try directory.lock(io);
    defer lock.close(io);
    const source = try fixture.dir.createFile(io, "invalid.efi", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer source.close(io);
    try source.writePositionalAll(io, "not a PE image", 0);
    try source.sync(io);
    const input: fs.Directory = .{ .dir = fixture.dir, .path = "" };
    const expected = try input.record(allocator, io, "invalid.efi", 512, .private);
    const failed = package(allocator, io, &lock, input, expected);
    try std.testing.expectEqual(error.InvalidEfiImage, failed.primary.?);
    try std.testing.expect(failed.cleanup == null and failed.report == null and !failed.succeeded());
    try requireAbsent(io, fixture.dir, stage_name);
    try requireAbsent(io, fixture.dir, raw_name);
    try requireAbsent(io, fixture.dir, vhd_name);
    const sentinel = try fixture.dir.createFile(io, vhd_name, .{ .read = true, .exclusive = true, .permissions = .fromMode(0o600) });
    defer sentinel.close(io);
    try sentinel.writePositionalAll(io, "existing", 0);
    const blocked = package(allocator, io, &lock, input, expected);
    try std.testing.expectEqual(error.PathAlreadyExists, blocked.primary.?);
    try std.testing.expectEqual(c.digest("existing"), try fs.hashFile(io, sentinel, 8));
    lock.close(io);
    const unlocked = package(allocator, io, &lock, input, expected);
    try std.testing.expectEqual(error.LockNotHeld, unlocked.primary.?);
}

test "package cleanup lane never hides a primary failure or permits success" {
    var result: Result = .{ .report = try (try nativeFixture()).report(), .primary = error.InvalidEfiImage };
    noteCleanup(&result, error.AccessDenied);
    try std.testing.expectEqual(error.InvalidEfiImage, result.primary.?);
    try std.testing.expectEqual(error.AccessDenied, result.cleanup.?);
    try std.testing.expect(result.report == null and !result.succeeded());
    noteCleanup(&result, error.FileNotFound);
    try std.testing.expectEqual(error.AccessDenied, result.cleanup.?);
}
