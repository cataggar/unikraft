const std = @import("std");
const c = @import("contracts.zig");
const f = @import("files.zig");
const p = c.core.private_files;
const miz = @import("miz").efi_application_image;
pub const Packaging = struct {
    @"schema-version": u8 = 1,
    contract: []const u8 = "miz.efi-application-image",
    valid: bool = true,
    format: []const u8 = "vhd",
    subformat: []const u8 = "fixed",
    generation: u8 = 2,
    @"virtual-size": u64 = c.raw_bytes,
    @"file-size": u64 = c.vhd_bytes,
    architecture: []const u8 = "x86_64",
    @"boot-path": []const u8 = "EFI/BOOT/BOOTX64.EFI",
    @"boot-file-sha256": []const u8,
    @"esp-offset": u64 = c.mib,
    @"esp-length": u64 = c.esp_bytes,
};
pub const Report = struct { efi: c.File, raw: c.File, vhd: c.File, packaging: Packaging };
pub const Digest = struct { size: u64, sha256: []const u8 };
pub const Inspection = struct {
    schema_version: u8 = 1,
    miz_revision: []const u8 = c.miz_revision,
    efi: Digest,
    raw: Digest,
    vhd: Digest,
    footer_sha256: []const u8,
    disk_guid: []const u8,
    esp_partition_guid: []const u8,
    esp_volume_id: u32,
    packaging: Packaging,
};
pub const ExpectedImage = struct { efi: c.Hash, raw: c.Hash, vhd: c.Hash };

/// Descriptor-bound, read-only inspection; no raw image/EFI sidecar or guest
/// execution is needed to verify the exact fixed-VHD packaging contract.
pub fn inspectVhd(a: std.mem.Allocator, io: std.Io, file: std.Io.File, expected: ExpectedImage) !Inspection {
    const before = try p.snapshot(file);
    if (before.size != c.vhd_bytes) return error.InvalidGeometry;
    _ = try c.boot.vhd.validate(io, file);
    var buffer: [32768]u8 = undefined;
    var raw_hash = std.crypto.hash.sha2.Sha256.init(.{});
    var vhd_hash = std.crypto.hash.sha2.Sha256.init(.{});
    var offset: u64 = 0;
    while (offset < before.size) {
        const count: usize = @intCast(@min(buffer.len, before.size - offset));
        if (try file.readPositionalAll(io, buffer[0..count], offset) != count) return error.ArtifactChanged;
        vhd_hash.update(buffer[0..count]);
        if (offset < c.raw_bytes) raw_hash.update(buffer[0..@intCast(@min(count, c.raw_bytes - offset))]);
        offset += count;
    }
    if (try file.readPositionalAll(io, buffer[0..1], offset) != 0 or
        !p.sameSnapshot(before, try p.snapshot(file))) return error.ArtifactChanged;
    const raw_digest = raw_hash.finalResult();
    const vhd_digest = vhd_hash.finalResult();
    if (!std.mem.eql(u8, &raw_digest, &expected.raw) or !std.mem.eql(u8, &vhd_digest, &expected.vhd)) return error.PayloadMismatch;
    var footer: [512]u8 = undefined;
    if (try file.readPositionalAll(io, &footer, c.raw_bytes) != footer.len) return error.ArtifactChanged;
    const fd_path = try std.fmt.allocPrint(a, "/proc/self/fd/{d}", .{file.handle});
    defer a.free(fd_path);
    const verified = try miz.validateFixedVhd(a, io, .{
        .path = fd_path,
        .architecture = .x86_64,
        .expected_efi_sha256 = expected.efi,
        .expected_virtual_size = c.raw_bytes,
        .max_efi_size = c.max_efi,
    });
    if (verified.architecture != .x86_64 or !std.mem.eql(u8, verified.boot_path, miz.fallback_x86_64) or
        verified.boot_file_size == 0 or verified.boot_file_size > c.max_efi or
        verified.virtual_size != c.raw_bytes or verified.file_size != c.vhd_bytes or
        verified.esp_offset_bytes != c.mib or verified.esp_length_bytes != c.esp_bytes or
        !std.mem.eql(u8, &verified.boot_file_sha256, &expected.efi) or
        !std.mem.eql(u8, &try c.boot.files.digest(io, file, before), &expected.vhd)) return error.InvalidPackage;
    const efi_sha = try c.hex(a, verified.boot_file_sha256);
    return .{
        .efi = .{ .size = verified.boot_file_size, .sha256 = efi_sha },
        .raw = .{ .size = c.raw_bytes, .sha256 = try c.hex(a, raw_digest) },
        .vhd = .{ .size = c.vhd_bytes, .sha256 = try c.hex(a, vhd_digest) },
        .footer_sha256 = try c.hex(a, c.hash(&footer)),
        .disk_guid = try a.dupe(u8, &std.fmt.bytesToHex(verified.disk_guid, .lower)),
        .esp_partition_guid = try a.dupe(u8, &std.fmt.bytesToHex(verified.esp_partition_guid, .lower)),
        .esp_volume_id = verified.esp_volume_id,
        .packaging = .{ .@"boot-file-sha256" = efi_sha },
    };
}

pub fn observe(a: std.mem.Allocator, io: std.Io, root: p.Directory, efi: c.File) !Report {
    const private_raw = try root.openFile(io, "unikraft.raw");
    defer private_raw.close(io);
    var path_buffer: [4096]u8 = undefined;
    const root_path = path_buffer[0..try root.dir.realPath(io, &path_buffer)];
    const raw = try f.record(a, io, try f.path(a, root_path, "unikraft.raw"), c.raw_bytes, false);
    const vhd = try f.record(a, io, try f.path(a, root_path, "unikraft.vhd"), c.vhd_bytes, false);
    if (raw.size != c.raw_bytes or vhd.size != c.vhd_bytes) return error.InvalidGeometry;
    const file = try root.openFile(io, "unikraft.vhd");
    defer file.close(io);
    const verified = try inspectVhd(a, io, file, .{ .efi = try c.sha(efi.sha256), .raw = try c.sha(raw.sha256), .vhd = try c.sha(vhd.sha256) });
    if (verified.efi.size != efi.size) return error.InvalidPackage;
    try f.verify(a, io, raw, c.raw_bytes, false);
    try f.verify(a, io, vhd, c.vhd_bytes, false);
    return .{ .efi = efi, .raw = raw, .vhd = vhd, .packaging = verified.packaging };
}
pub fn build(a: std.mem.Allocator, io: std.Io, root: p.Directory, efi: c.File) !Report {
    try f.verify(a, io, efi, c.max_efi, false);
    try f.copy(io, efi, root, "BOOTX64.EFI");
    const source = try root.openFile(io, "BOOTX64.EFI");
    defer source.close(io);
    try root.dir.createDir(io, "package-stage", .fromMode(0o700));
    const stage_dir = try root.dir.openDir(io, "package-stage", .{ .follow_symlinks = false, .iterate = true });
    defer stage_dir.close(io);
    try f.sync(io, root.dir);
    const source_path = try std.fmt.allocPrint(a, "/proc/self/fd/{d}", .{source.handle});
    for ([_]struct { name: []const u8, format: @FieldType(miz.Options, "output_format") }{
        .{ .name = "unikraft.raw", .format = .raw }, .{ .name = "unikraft.vhd", .format = .vhd },
    }) |item| {
        const report = try miz.build(a, io, .{ .efi_path = source_path, .output_path = try std.fmt.allocPrint(a, "/proc/self/fd/{d}/{s}", .{ stage_dir.handle, item.name }), .output_format = item.format, .architecture = .x86_64, .esp_size = c.esp_bytes, .max_efi_size = c.max_efi });
        if (report.output_format != item.format or report.architecture != .x86_64 or report.input_size != efi.size or
            !std.mem.eql(u8, &report.input_sha256, &try c.sha(efi.sha256)) or report.virtual_size != c.raw_bytes or
            report.esp_offset_bytes != c.mib or report.esp_length_bytes != c.esp_bytes) return error.InvalidPackage;
        const output = try stage_dir.openFile(io, item.name, .{ .mode = .read_write, .allow_directory = false });
        defer output.close(io);
        try output.setPermissions(io, .fromMode(0o600));
        try output.sync(io);
    }
    _ = try observe(a, io, .{ .dir = stage_dir }, efi);
    try f.sync(io, stage_dir);
    for ([_][]const u8{ "unikraft.raw", "unikraft.vhd" }) |name|
        try stage_dir.renamePreserve(name, root.dir, name, io);
    try f.sync(io, stage_dir);
    try f.sync(io, root.dir);
    try f.verify(a, io, efi, c.max_efi, false);
    return observe(a, io, root, efi);
}
