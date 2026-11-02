// SPDX-License-Identifier: BSD-3-Clause
//! Local original-to-direct configuration derivation, not solving or admission.
const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const config = @import("config.zig");
const original = @import("original_seed.zig");
const private = c.core.private_files;

pub const config_name = "direct.config";
pub const record_name = "derivation.json";
pub const started_name = "derivation.started.json";
pub const started =
    "{\"authority\":\"not_admitted\",\"scope\":\"local_direct_configuration_only\",\"state\":\"started_not_acceptance\"}";

pub const Record = struct {
    schema: enum { hyperv_direct_configuration_derivation_native_v1 } = .hyperv_direct_configuration_derivation_native_v1,
    purpose: enum { guarded_v2_direct_persistence } = .guarded_v2_direct_persistence,
    scope: enum { local_direct_configuration_only } = .local_direct_configuration_only,
    authority: enum { not_admitted } = .not_admitted,
    configuration: enum { unsolved_fragment } = .unsolved_fragment,
    not_evidence_of: enum { solved_approval_source_authentication_build_boot_device_or_cloud_acceptance } = .solved_approval_source_authentication_build_boot_device_or_cloud_acceptance,
    guard: config.Guard,
    original: struct {
        production_record: c.File,
        manifest: c.File,
        config: c.File,
        raw: c.File,
        vhd: c.File,
    },
    derived_config: c.File,
};

const source_names = [_][]const u8{
    "original.raw",       "original.vhd",            "original.json", "original.config",
    original.record_name, "production.started.json",
};

const Held = struct {
    file: std.Io.File,
    before: fs.Metadata,

    fn open(io: std.Io, directory: private.Directory, name: []const u8) !Held {
        const file = try directory.openFile(io, name);
        errdefer file.close(io);
        return .{ .file = file, .before = try fs.metadata(file) };
    }
    fn verify(self: Held, io: std.Io, directory: private.Directory, name: []const u8) !void {
        const named = try directory.openFile(io, name);
        defer named.close(io);
        if (!std.meta.eql(self.before, try fs.metadata(self.file)) or
            !std.meta.eql(self.before, try fs.metadata(named))) return error.SourceChanged;
    }
};

fn directoryMetadata(directory: private.Directory) !fs.Metadata {
    return fs.metadata(.{ .handle = directory.dir.handle, .flags = .{ .nonblocking = false } });
}

/// All original descriptors and the already-existing writer lock remain held.
/// No file, lock, journal or directory is created inside the original seed.
const Source = struct {
    path: []const u8,
    directory: private.Directory,
    before: fs.Metadata,
    lock: private.Locked,
    lock_before: fs.Metadata,
    files: [source_names.len]Held,

    pub fn open(io: std.Io, path: []const u8) !Source {
        const directory = try fs.openPrivate(io, path);
        errdefer directory.close(io);
        const before = try directoryMetadata(directory);
        const file = try directory.openFile(io, ".writer.lock");
        errdefer file.close(io);
        const lock_before = try fs.metadata(file);
        if (!try file.tryLock(io, .exclusive)) return error.WouldBlock;
        var files: [source_names.len]Held = undefined;
        var opened: usize = 0;
        errdefer for (files[0..opened]) |held| held.file.close(io);
        for (source_names, 0..) |name, i| {
            files[i] = try Held.open(io, directory, name);
            opened += 1;
        }
        var result: Source = .{
            .path = path,
            .directory = directory,
            .before = before,
            .lock = .{ .directory = directory, .file = file },
            .lock_before = lock_before,
            .files = files,
        };
        try result.verify(io);
        return result;
    }
    pub fn close(self: *Source, io: std.Io) void {
        for (self.files) |held| held.file.close(io);
        self.lock.close(io);
        self.directory.close(io);
    }
    pub fn verify(self: *Source, io: std.Io) !void {
        try fs.requireLock(io, &self.lock);
        if (!std.meta.eql(self.lock_before, try fs.metadata(self.lock.file.?)) or
            !std.meta.eql(self.before, try directoryMetadata(self.directory))) return error.SourceChanged;
        for (self.files, source_names) |held, name| try held.verify(io, self.directory, name);
        const named = try fs.openPrivate(io, self.path);
        defer named.close(io);
        if (!std.meta.eql(self.before, try directoryMetadata(named))) return error.SourceChanged;
    }
    fn inspect(self: *Source, allocator: std.mem.Allocator, io: std.Io, expected: c.Sha) !original.Record {
        try self.verify(io);
        const result = try original.inspect(allocator, io, self.directory, expected);
        try self.verify(io);
        return result;
    }
    fn productionBinding(self: Source, expected: c.Sha) c.File {
        return .{ .path = original.record_name, .sha256 = expected, .size = self.files[4].before.size, .mode = 0o600 };
    }
};

fn syncDirectory(io: std.Io, directory: std.Io.Dir) !void {
    try (std.Io.File{ .handle = directory.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

fn publish(io: std.Io, lock: *private.Locked, name: []const u8, bytes: []const u8, failures: *c.Failure) !void {
    try fs.requireLock(io, lock);
    const result = try fs.publish(lock, io, name, bytes);
    if (result.failures.recording) |value| try failures.record(.recording, value);
    if (result.failures.cleanup) |value| try failures.record(.cleanup, value);
    if (result.status != .durable or result.failures.recording != null or result.failures.cleanup != null)
        return error.PublicationIncomplete;
    try fs.requireLock(io, lock);
}

fn requireAbsent(io: std.Io, parent: private.Directory, name: []const u8) !void {
    _ = parent.dir.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    return error.PathAlreadyExists;
}

fn custody(io: std.Io, lock: *private.Locked, path: []const u8) !void {
    try fs.requireLock(io, lock);
    const named = try fs.openPrivate(io, path);
    defer named.close(io);
    try fs.requireDirectoryIdentity(
        .{ .dir = lock.directory.dir, .path = path },
        .{ .dir = named.dir, .path = path },
    );
}

fn requireOutside(source: Source, parent: private.Directory, path: []const u8) !void {
    if (std.mem.startsWith(u8, path, source.path) and
        (path.len == source.path.len or path[source.path.len] == '/')) return error.OutputInsideOriginal;
    const metadata = try directoryMetadata(parent);
    if (metadata.device == source.before.device and metadata.inode == source.before.inode)
        return error.OutputInsideOriginal;
}

fn recordFor(source: original.Record, production: c.File, fragment: []const u8) Record {
    return .{
        .guard = source.guard,
        .original = .{
            .production_record = production,
            .manifest = source.manifest,
            .config = source.original_config,
            .raw = source.raw,
            .vhd = source.vhd,
        },
        .derived_config = .{ .path = config_name, .sha256 = c.digest(fragment), .size = fragment.len, .mode = 0o600 },
    };
}

fn validateOutput(allocator: std.mem.Allocator, io: std.Io, directory: private.Directory, expected: Record, final: bool) !void {
    const view: fs.Directory = .{ .dir = directory.dir, .path = "" };
    const bytes = try view.read(allocator, io, config_name, config.config_cap, .private);
    defer allocator.free(bytes);
    if (bytes.len != expected.derived_config.size or
        !std.meta.eql(c.digest(bytes), expected.derived_config.sha256)) return error.HashMismatch;
    try config.validateDirectPersistence(allocator, bytes, expected.guard);
    const marker = try view.read(allocator, io, started_name, 1024, .private);
    defer allocator.free(marker);
    if (!std.mem.eql(u8, marker, started)) return error.HashMismatch;
    if (final) {
        const record = try view.read(allocator, io, record_name, 65536, .private);
        defer allocator.free(record);
        const wanted = try c.canonical(allocator, expected);
        defer allocator.free(wanted);
        if (!std.mem.eql(u8, record, wanted)) return error.DerivationRecordMismatch;
    }
    var entries = directory.dir.iterate();
    var count: usize = 0;
    while (try entries.next(io)) |entry| {
        if (entry.kind != .file or !(std.mem.eql(u8, entry.name, ".writer.lock") or
            std.mem.eql(u8, entry.name, started_name) or std.mem.eql(u8, entry.name, config_name) or
            (final and std.mem.eql(u8, entry.name, record_name)))) return error.UnexpectedOutput;
        count += 1;
    }
    if (count != @as(usize, if (final) 4 else 3)) return error.IncompleteOutput;
}

/// Validates original bytes twice, publishes only a fresh unsolved fragment.
/// No identity generation, solver/compiler, subprocess, or approval is involved.
pub fn create(
    allocator: std.mem.Allocator,
    io: std.Io,
    original_path: []const u8,
    expected_production: c.Sha,
    parent_path: []const u8,
    name: []const u8,
    failures: *c.Failure,
) !c.Sha {
    _ = try c.sha(&expected_production);
    try private.basename(name);
    try c.relative(name);
    if (name[0] == '.') return error.UnsafePath;
    var source = try Source.open(io, original_path);
    defer source.close(io);
    const parent = try fs.openPrivate(io, parent_path);
    defer parent.close(io);
    try requireOutside(source, parent, parent_path);
    var parent_lock = try parent.lock(io);
    defer parent_lock.close(io);
    try requireAbsent(io, parent, name);
    const measured = try source.inspect(allocator, io, expected_production);
    const fragment = try config.renderDirectPersistence(allocator, measured.guard);
    defer allocator.free(fragment);
    const record = recordFor(measured, source.productionBinding(expected_production), fragment);
    const child_path = try std.fs.path.join(allocator, &.{ parent_path, name });
    defer allocator.free(child_path);
    try custody(io, &parent_lock, parent_path);
    try source.verify(io);
    try parent.dir.createDir(io, name, .fromMode(0o700));
    try syncDirectory(io, parent.dir);
    const child = try fs.openPrivate(io, child_path);
    defer child.close(io);
    var lock = try child.lock(io);
    defer lock.close(io);
    try custody(io, &lock, child_path);
    try publish(io, &lock, started_name, started, failures);
    try publish(io, &lock, config_name, fragment, failures);
    try validateOutput(allocator, io, child, record, false);
    _ = try source.inspect(allocator, io, expected_production);
    try custody(io, &parent_lock, parent_path);
    try custody(io, &lock, child_path);
    const bytes = try c.canonical(allocator, record);
    defer allocator.free(bytes);
    try publish(io, &lock, record_name, bytes, failures);
    try syncDirectory(io, parent.dir);
    try validateOutput(allocator, io, child, record, true);
    try source.verify(io);
    try custody(io, &parent_lock, parent_path);
    try custody(io, &lock, child_path);
    return c.digest(bytes);
}

pub const Test = if (@import("builtin").is_test) struct {
    pub const HeldSource = Source;
    pub const publishBytes = publish;
    pub const absent = requireAbsent;
    pub const outside = requireOutside;
    pub const validateFiles = validateOutput;
    pub const shapeRecord = recordFor;
} else struct {};
