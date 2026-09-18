const std = @import("std");
const core = @import("hyperv_core");
const miz = @import("miz");
const c = @import("config.zig");
const linux = std.os.linux;
pub const Sha256 = core.Sha256;

pub const Pin = struct { size: u64, sha256: [32]u8 };
pub const Artifact = struct {
    file: std.Io.File,
    before: core.private_files.Snapshot,
    pin: Pin,
};
pub const Set = struct {
    items: [4]Artifact,

    pub fn open(io: std.Io, config: c.Config) !Set {
        var result: Set = undefined;
        var count: usize = 0;
        errdefer for (result.items[0..count]) |item| item.file.close(io);
        for (config.paths(), 0..) |path, i| {
            const file = try core.private_files.openAbsolute(io, path, .artifact);
            errdefer file.close(io);
            const before = try core.private_files.snapshot(file);
            const maximum: u64 = switch (i) {
                0 => config.source.maximumPhysicalSize(),
                1 => c.max_firmware,
                2 => c.max_vars,
                3 => c.max_qemu,
                else => unreachable,
            };
            if (before.size == 0 or before.size > maximum or before.mode & 0o022 != 0) return error.InvalidArtifact;
            if (i == 0 and config.source.kind == .fixed_vhd) _ = try @import("vhd.zig").validate(io, file);
            if (i == 0 and config.source.kind == .qcow2) try validateQcow2(io, file, before);
            if (i == 3) {
                if (before.mode & 0o111 == 0 or before.mode & 0o6000 != 0) return error.InvalidExecutable;
                var magic: [4]u8 = undefined;
                if (try file.readPositionalAll(io, &magic, 0) != 4 or !std.mem.eql(u8, &magic, "\x7fELF")) return error.InvalidExecutable;
            }
            result.items[i] = .{ .file = file, .before = before, .pin = .{ .size = before.size, .sha256 = try digest(io, file, before) } };
            count += 1;
        }
        return result;
    }

    pub fn pins(self: Set) [4]Pin {
        var result: [4]Pin = undefined;
        for (self.items, &result) |item, *pin| pin.* = item.pin;
        return result;
    }

    pub fn verify(self: Set, io: std.Io, config: c.Config) !void {
        for (self.items, config.paths()) |item, path| {
            if (!std.mem.eql(u8, &try digest(io, item.file, item.before), &item.pin.sha256)) return error.ArtifactChanged;
            const current = try core.private_files.openAbsolute(io, path, .artifact);
            defer current.close(io);
            if (!core.private_files.sameSnapshot(item.before, try core.private_files.snapshot(current))) return error.ArtifactChanged;
        }
    }

    pub fn close(self: Set, io: std.Io) void {
        for (self.items) |item| item.file.close(io);
    }
};

pub fn digest(io: std.Io, file: std.Io.File, before: core.private_files.Snapshot) ![32]u8 {
    if (!core.private_files.sameSnapshot(before, try core.private_files.snapshot(file))) return error.ArtifactChanged;
    var sha = Sha256.init(.{});
    var buffer: [32 * 1024]u8 = undefined;
    var position: u64 = 0;
    while (position < before.size) {
        const length: usize = @intCast(@min(buffer.len, before.size - position));
        if (try file.readPositionalAll(io, buffer[0..length], position) != length) return error.ArtifactChanged;
        sha.update(buffer[0..length]);
        position += length;
    }
    if (try file.readPositionalAll(io, buffer[0..1], position) != 0 or
        !core.private_files.sameSnapshot(before, try core.private_files.snapshot(file))) return error.ArtifactChanged;
    return sha.finalResult();
}

pub fn copy(io: std.Io, artifact: Artifact, directory: std.Io.Dir, name: []const u8) !void {
    const output = try directory.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer output.close(io);
    var buffer: [32 * 1024]u8 = undefined;
    var position: u64 = 0;
    var sha = Sha256.init(.{});
    while (position < artifact.pin.size) {
        const length: usize = @intCast(@min(buffer.len, artifact.pin.size - position));
        if (try artifact.file.readPositionalAll(io, buffer[0..length], position) != length) return error.ArtifactChanged;
        sha.update(buffer[0..length]);
        try output.writePositionalAll(io, buffer[0..length], position);
        position += length;
    }
    if (!std.mem.eql(u8, &sha.finalResult(), &artifact.pin.sha256) or
        !core.private_files.sameSnapshot(artifact.before, try core.private_files.snapshot(artifact.file))) return error.ArtifactChanged;
    try output.sync(io);
    try sync(io, directory);
}

pub fn sync(io: std.Io, directory: std.Io.Dir) !void {
    try (std.Io.File{ .handle = directory.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

pub fn durable(result: core.private_files.CommitResult) !void {
    if (result.status != .durable or result.failures.primary != null or result.failures.cleanup != null or result.failures.recording != null)
        return error.RecordingFailed;
}

pub fn cleanup(io: std.Io, work: core.private_files.Directory, image: bool) !void {
    var failed = false;
    for ([_][]const u8{ "OVMF_CODE.fd", "OVMF_VARS.fd" }) |name|
        remove(io, work.dir, name) catch {
            failed = true;
        };
    if (image) removeEsp(io, work.dir) catch {
        failed = true;
    };
    sync(io, work.dir) catch {
        failed = true;
    };
    if (failed) return error.CleanupFailed;
}

fn remove(io: std.Io, directory: std.Io.Dir, name: []const u8) !void {
    directory.deleteFile(io, name) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}
fn removeEsp(io: std.Io, work: std.Io.Dir) !void {
    const esp = work.openDir(io, "esp", .{ .follow_symlinks = false, .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer esp.close(io);
    const efi = esp.openDir(io, "EFI", .{ .follow_symlinks = false, .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return work.deleteDir(io, "esp"),
        else => return err,
    };
    defer efi.close(io);
    if (efi.openDir(io, "BOOT", .{ .follow_symlinks = false, .iterate = true })) |boot| {
        defer boot.close(io);
        try remove(io, boot, "BOOTX64.EFI");
        try efi.deleteDir(io, "BOOT");
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    try esp.deleteDir(io, "EFI");
    try work.deleteDir(io, "esp");
}

pub fn inheritedReadOnly(file: std.Io.File) !linux.fd_t {
    // Keep only this O_RDONLY artifact descriptor across the one QEMU exec.
    const flags = linux.fcntl(file.handle, linux.F.GETFL, 0);
    if (linux.errno(flags) != .SUCCESS or flags & 3 != 0) return error.DescriptorFailed;
    const fd = linux.fcntl(file.handle, linux.F.DUPFD, 64);
    if (linux.errno(fd) != .SUCCESS) return error.DescriptorFailed;
    return @intCast(fd);
}

fn validationDuplicate(file: std.Io.File) !std.Io.File {
    const flags = linux.fcntl(file.handle, linux.F.GETFL, 0);
    if (linux.errno(flags) != .SUCCESS or flags & 3 != 0) return error.DescriptorFailed;
    const fd = linux.fcntl(file.handle, linux.F.DUPFD_CLOEXEC, 64);
    if (linux.errno(fd) != .SUCCESS) return error.DescriptorFailed;
    return .{ .handle = @intCast(fd), .flags = .{ .nonblocking = false } };
}

pub fn validateQcow2(
    io: std.Io,
    retained: std.Io.File,
    retained_snapshot: core.private_files.Snapshot,
) !void {
    var duplicate = try validationDuplicate(retained);
    var transferred = false;
    defer if (!transferred) duplicate.close(io);
    var image = miz.Image.openStandaloneQcow2File(io, duplicate) catch |err| switch (err) {
        error.BackingFileNotSupported, error.ExternalDataFileNotSupported => return err,
        else => return error.InvalidQcow2,
    };
    transferred = true;
    defer image.close(io);

    const info = image.qcow2 orelse return error.InvalidQcow2Profile;
    if (image.format != .qcow2 or info.file_size != retained_snapshot.size or
        info.virtual_size == 0 or info.virtual_size > c.max_virtual or info.virtual_size % 512 != 0 or
        info.version != 3 or info.cluster_bits != miz.qcow2.default_cluster_bits or
        info.cluster_size != 64 * 1024 or info.header_length != 112 or
        info.l2_entries != 8192)
    {
        return error.InvalidQcow2Profile;
    }
    const guest_clusters = std.math.divCeil(u64, info.virtual_size, info.cluster_size) catch
        return error.InvalidQcow2Profile;
    const expected_l1_size = std.math.divCeil(u64, guest_clusters, info.l2_entries) catch
        return error.InvalidQcow2Profile;
    if (info.l1_size != @max(1, expected_l1_size) or
        info.active_l1_table_offset != info.l1_table_offset or
        info.refcount_order != miz.qcow2.default_refcount_order or
        info.refcount_table_clusters != 1 or info.refcount_table_capacity_blocks != 8192 or
        info.refcount_block_count != 1 or
        info.incompatible_features != miz.qcow2.incompatible_compression or
        info.compression_type != 1 or info.crypt_method != 0 or
        info.snapshot_count != 0 or info.snapshots_offset != 0 or
        info.source_path_len != 0 or info.data_file_len != 0 or info.data_file_size != 0 or
        info.backing_file_len != 0 or info.backing_depth != 0)
    {
        return error.InvalidQcow2Profile;
    }

    miz.qcow2.check(image.file, io, info) catch return error.InvalidQcow2;
    var buffer: [64 * 1024]u8 = undefined;
    var position: u64 = 0;
    while (position < info.virtual_size) {
        const length: usize = @intCast(@min(buffer.len, info.virtual_size - position));
        const read = image.pread(io, buffer[0..length], position) catch return error.InvalidQcow2;
        if (read != length) return error.InvalidQcow2;
        position += length;
    }
    if (!core.private_files.sameSnapshot(retained_snapshot, try core.private_files.snapshot(retained)))
        return error.ArtifactChanged;
}
