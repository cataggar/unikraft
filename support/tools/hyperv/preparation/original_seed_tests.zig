// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const prep = @import("preparation");
const direct = @import("direct_validation");
const original = prep.original_seed;
const c = prep.contracts;
const private = c.core.private_files;
const io = std.testing.io;
const a = std.testing.allocator;

const Fixture = struct {
    tmp: std.testing.TmpDir,
    path: [:0]u8,
    directory: private.Directory,

    fn init() !Fixture {
        var tmp = std.testing.tmpDir(.{ .iterate = true });
        errdefer tmp.cleanup();
        try tmp.dir.setPermissions(io, .fromMode(0o700));
        const path = try tmp.dir.realPathFileAlloc(io, ".", a);
        errdefer a.free(path);
        return .{ .tmp = tmp, .path = path, .directory = try prep.files.openPrivate(io, path) };
    }
    fn deinit(self: *Fixture) void {
        self.directory.close(io);
        a.free(self.path);
        self.tmp.cleanup();
    }
};

fn absent(directory: private.Directory, name: []const u8) !void {
    const file = directory.openFile(io, name) catch |err| {
        try std.testing.expectEqual(error.FileNotFound, err);
        return;
    };
    file.close(io);
    return error.UnexpectedFile;
}

fn refuse(value: anytype) !void {
    if (value) |_| return error.ExpectedRefusal else |_| {}
}

fn zeroEntropy(_: ?*anyopaque, bytes: []u8) std.Io.RandomSecureError!void {
    @memset(bytes, 0);
}
fn equalEntropy(_: ?*anyopaque, bytes: []u8) std.Io.RandomSecureError!void {
    @memset(bytes, 0x55);
}

test "original seed OS entropy produces fresh distinct typed identities without caller IDs" {
    var identities: [32]c.Identity = undefined;
    for (0..16) |i| {
        const parameters = try original.Test.parameters(io);
        try prep.config.validateGuardPurpose(parameters.guard(), .persistence);
        identities[i * 2] = try c.identity(&parameters.run_id);
        identities[i * 2 + 1] = try c.identity(&parameters.disk_id);
    }
    for (identities, 0..) |id, i|
        for (identities[0..i]) |previous|
            try std.testing.expect(!std.mem.eql(u8, &id, &previous));
}

test "original seed entropy errors zero and identity collisions fail closed" {
    var vtable = io.vtable.*;
    const injected: std.Io = .{ .userdata = io.userdata, .vtable = &vtable };
    vtable.randomSecure = std.Io.failingRandomSecure;
    try std.testing.expectError(error.EntropyUnavailable, original.Test.parameters(injected));
    vtable.randomSecure = zeroEntropy;
    try std.testing.expectError(error.InvalidIdentity, original.Test.parameters(injected));
    vtable.randomSecure = equalEntropy;
    try std.testing.expectError(error.IdentityCollision, original.Test.parameters(injected));
    vtable.randomSecure = std.Io.failingRandomSecure;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var failures: c.Failure = .{};
    try std.testing.expectError(error.EntropyUnavailable, original.create(a, injected, fixture.path, "entropy-failed", &failures));
    const child_path = try std.fs.path.join(a, &.{ fixture.path, "entropy-failed" });
    defer a.free(child_path);
    const child = try prep.files.openPrivate(io, child_path);
    defer child.close(io);
    try absent(child, original.record_name);
    try absent(child, "original.raw");
    const marker = try child.read(io, a, "production.started.json", 1024, null);
    defer a.free(marker);
    try std.testing.expectEqualStrings(original.started, marker);
    try std.testing.expectError(error.PathAlreadyExists, original.create(a, io, fixture.path, "entropy-failed", &failures));
}

test "original manifest remains strict direct version two and original config is not a solved direct image" {
    const parameters = try original.Test.parameters(io);
    const manifest = try original.Test.manifest(a, parameters);
    defer a.free(manifest);
    try direct.inspectManifest(a, manifest, parameters);
    const parsed = try c.parse(original.Manifest, a, manifest);
    defer parsed.deinit();
    try std.testing.expectEqual(parameters.run_id, parsed.value.run_id);
    try std.testing.expectEqual(parameters.disk_id, parsed.value.disk_id);
    var other = parameters;
    other.disk_id = other.run_id;
    try std.testing.expectError(error.IdentityCollision, original.Test.manifest(a, other));
    other = parameters;
    other.sectors = 49;
    try std.testing.expectError(error.WrongPurposeGeometry, original.Test.manifest(a, other));
    const fragment = try prep.config.render(a, parameters.guard());
    defer a.free(fragment);
    try prep.config.validatePurpose(a, fragment, parameters.guard(), .persistence);
    try std.testing.expectError(error.InvalidGuardProfile, prep.config.validateDirectPersistence(a, fragment, parameters.guard()));
    try std.testing.expectError(error.WrongPlatform, direct.inspectConfig(a, fragment, parameters));
    const footer = (try prep.seed.fixedFooter(parameters)).encode();
    try direct.footer(&footer, original.logical_size, &parameters.disk_id);
    try prep.seed.validateFooter(&footer, parameters);
    try std.testing.expectEqualStrings(&parameters.disk_id, &std.fmt.bytesToHex(footer[68..84].*, .lower));
}

fn fixtureDisks(fixture: Fixture, sectors: u64) !prep.seed.Parameters {
    var parameters = try original.Test.parameters(io);
    parameters.sectors = sectors;
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    try original.Test.disk(io, &lock, "original.raw", parameters, false);
    try original.Test.disk(io, &lock, "original.vhd", parameters, true);
    try absent(fixture.directory, original.record_name);
    return parameters;
}

test "original generic sparse streaming matches complete native bytes hashes and pristine layout at bounded geometry" {
    for ([_]u64{ 49, 257, 4096 }) |sectors| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        const parameters = try fixtureDisks(fixture, sectors);
        var reference = try prep.seed.render(a, parameters);
        defer reference.deinit();
        const measured = try original.Test.inspectDisks(io, fixture.directory, parameters);
        for ([_][]const u8{ reference.raw, reference.vhd }, measured) |expected, binding| {
            try std.testing.expectEqual(c.digest(expected), binding.sha256);
            try std.testing.expectEqual(expected.len, binding.size);
            try std.testing.expectEqual(@as(u16, 0o600), binding.mode);
            const file = try fixture.directory.openFile(io, binding.path);
            defer file.close(io);
            try std.testing.expectEqual(binding.sha256, try prep.files.hashFile(io, file, binding.size));
        }
        try prep.seed.validateBytes(reference.raw, reference.vhd, parameters);
        try direct.seedChunk(reference.raw, 0, parameters);
        try direct.footer(reference.vhd[reference.raw.len..][0..512], reference.raw.len, &parameters.disk_id);
    }
}

test "original streaming refuses workload bytes prefix drift seed copy changes truncation and footer changes" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const parameters = try fixtureDisks(fixture, 257);
    const raw = try fixture.directory.dir.openFile(io, "original.raw", .{ .mode = .read_write });
    defer raw.close(io);
    const vhd = try fixture.directory.dir.openFile(io, "original.vhd", .{ .mode = .read_write });
    defer vhd.close(io);
    for ([_]u64{ 0, 16 * 512, 17 * 512, 32 * 512, 48 * 512, 65536 + 3, 257 * 512 - 1 }) |offset| {
        try raw.writePositionalAll(io, &.{1}, offset);
        try std.testing.expectError(error.RawPrefixMismatch, original.Test.inspectDisks(io, fixture.directory, parameters));
        try vhd.writePositionalAll(io, &.{1}, offset);
        try std.testing.expectError(error.NonzeroPristineRegion, original.Test.inspectDisks(io, fixture.directory, parameters));
        try raw.writePositionalAll(io, &.{0}, offset);
        try vhd.writePositionalAll(io, &.{0}, offset);
    }
    const sector = try prep.seed.encodeSector(parameters);
    try raw.writePositionalAll(io, &.{0}, 9 * 512);
    try std.testing.expectError(error.InvalidSeedMagic, original.Test.inspectDisks(io, fixture.directory, parameters));
    try raw.writePositionalAll(io, &sector, 9 * 512);
    const footer = (try prep.seed.fixedFooter(parameters)).encode();
    for ([_]usize{ 40, 56, 64, 68, 84, 85, 511 }) |offset| {
        try vhd.writePositionalAll(io, &.{footer[offset] ^ 1}, parameters.sectors * 512 + offset);
        try refuse(original.Test.inspectDisks(io, fixture.directory, parameters));
        try vhd.writePositionalAll(io, &footer, parameters.sectors * 512);
    }
    try raw.setLength(io, parameters.sectors * 512 - 1);
    try std.testing.expectError(error.InvalidImageLength, original.Test.inspectDisks(io, fixture.directory, parameters));
    try raw.setLength(io, parameters.sectors * 512);
    try vhd.setLength(io, parameters.sectors * 512 + 513);
    try std.testing.expectError(error.InvalidImageLength, original.Test.inspectDisks(io, fixture.directory, parameters));
    try vhd.setLength(io, parameters.sectors * 512 + 512);
    _ = try original.Test.inspectDisks(io, fixture.directory, parameters);
}

test "original create refuses existing directories files symlinks unsafe parents and path components" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.directory.dir.createDir(io, "exists", .fromMode(0o700));
    const file = try fixture.directory.dir.createFile(io, "file", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    file.close(io);
    try fixture.directory.dir.symLink(io, "exists", "link", .{ .is_directory = true });
    try fixture.directory.dir.symLink(io, "missing", "dangling", .{ .is_directory = true });
    var failures: c.Failure = .{};
    for ([_][]const u8{ "exists", "file", "link", "dangling" }) |name|
        try std.testing.expectError(error.PathAlreadyExists, original.create(a, io, fixture.path, name, &failures));
    for ([_][]const u8{ "", ".", "..", ".hidden", "../escape", "a/b", "a\\b", "bad\nname" }) |name|
        try std.testing.expectError(error.UnsafePath, original.create(a, io, fixture.path, name, &failures));
    try std.testing.expectError(error.UnsafePath, original.create(a, io, "relative", "new", &failures));
    try fixture.directory.dir.setPermissions(io, .fromMode(0o755));
    try std.testing.expectError(error.UnsafeFile, original.create(a, io, fixture.path, "new", &failures));
    try fixture.directory.dir.setPermissions(io, .fromMode(0o700));
    const linked_parent = try std.fs.path.join(a, &.{ fixture.path, "link" });
    defer a.free(linked_parent);
    try refuse(original.create(a, io, linked_parent, "new", &failures));
    const existing = try fixture.directory.dir.openDir(io, "exists", .{ .iterate = true });
    defer existing.close(io);
    var iterator = existing.iterate();
    try std.testing.expectEqual(null, try iterator.next(io));
}

test "original private files reject hardlinks modes missing records and replaced locks" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const parameters = try fixtureDisks(fixture, 49);
    var first_lock = try fixture.directory.lock(io);
    try std.testing.expectError(error.PathAlreadyExists, original.Test.disk(io, &first_lock, "original.raw", parameters, false));
    first_lock.close(io);
    const raw = try fixture.directory.dir.openFile(io, "original.raw", .{ .mode = .read_write });
    defer raw.close(io);
    try raw.setPermissions(io, .fromMode(0o644));
    try std.testing.expectError(error.UnsafeFile, original.Test.inspectDisks(io, fixture.directory, parameters));
    try raw.setPermissions(io, .fromMode(0o600));
    const linux = std.os.linux;
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.linkat(
        fixture.directory.dir.handle,
        "original.raw",
        fixture.directory.dir.handle,
        "alias",
        0,
    )));
    try std.testing.expectError(error.UnsafeFile, original.Test.inspectDisks(io, fixture.directory, parameters));
    try fixture.directory.dir.deleteFile(io, "alias");
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    try std.testing.expectError(error.WouldBlock, fixture.directory.lock(io));
    try fixture.directory.dir.rename(".writer.lock", fixture.directory.dir, "old-lock", io);
    var replacement = try fixture.directory.lock(io);
    defer replacement.close(io);
    try std.testing.expectError(error.LockNotHeld, original.Test.disk(io, &lock, "never.raw", parameters, false));
    try absent(fixture.directory, "never.raw");
    try std.testing.expectError(error.FileNotFound, original.inspect(a, io, fixture.directory, c.digest("absent")));
}

fn shortWrite(userdata: ?*anyopaque, file: std.Io.File, header: []const u8, data: []const []const u8, splat: usize, offset: u64) std.Io.File.WritePositionalError!usize {
    _ = header;
    _ = splat;
    return io.vtable.fileWritePositional(userdata, file, &.{}, &.{data[0][0..@min(7, data[0].len)]}, 1, offset);
}
fn noWrite(_: ?*anyopaque, _: std.Io.File, _: []const u8, _: []const []const u8, _: usize, _: u64) std.Io.File.WritePositionalError!usize {
    return 0;
}
fn noFileSync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
    const stat = file.stat(io) catch return error.InputOutput;
    if (stat.kind == .file) return error.InputOutput;
    return io.vtable.fileSync(userdata, file);
}
fn noDirSync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
    const stat = file.stat(io) catch return error.InputOutput;
    if (stat.kind == .directory) return error.InputOutput;
    return io.vtable.fileSync(userdata, file);
}
fn noLength(_: ?*anyopaque, _: std.Io.File, _: u64) std.Io.File.SetLengthError!void {
    return error.InputOutput;
}
fn noRead(_: ?*anyopaque, _: std.Io.File, _: []const []u8, _: u64) std.Io.File.ReadPositionalError!usize {
    return 0;
}

test "original full production boundary preserves incomplete output on sparse allocation and parent sync errors" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var vtable = io.vtable.*;
    const injected: std.Io = .{ .userdata = io.userdata, .vtable = &vtable };
    vtable.fileSetLength = noLength;
    var failures: c.Failure = .{};
    try std.testing.expectError(error.InputOutput, original.create(a, injected, fixture.path, "length-failed", &failures));
    const child_path = try std.fs.path.join(a, &.{ fixture.path, "length-failed" });
    defer a.free(child_path);
    const child = try prep.files.openPrivate(io, child_path);
    defer child.close(io);
    try absent(child, original.record_name);
    const partial = try child.openFile(io, "original.raw");
    defer partial.close(io);
    try std.testing.expectEqual(@as(u64, 0), (try partial.stat(io)).size);
    try std.testing.expectError(error.PathAlreadyExists, original.create(a, io, fixture.path, "length-failed", &failures));
    vtable.fileSetLength = io.vtable.fileSetLength;
    vtable.fileSync = noDirSync;
    try std.testing.expectError(error.InputOutput, original.create(a, injected, fixture.path, "sync-failed", &failures));
    try absent(fixture.directory, "sync-failed");
}

test "original streaming refuses premature EOF even when metadata still reports the expected length" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const parameters = try fixtureDisks(fixture, 49);
    var vtable = io.vtable.*;
    vtable.fileReadPositional = noRead;
    try std.testing.expectError(error.SourceChanged, original.Test.inspectDisks(.{
        .userdata = io.userdata,
        .vtable = &vtable,
    }, fixture.directory, parameters));
}

test "original streaming rejects descriptor drift after the complete hash pass" {
    const Drift = struct {
        var writable: ?std.Io.File = null;

        fn read(userdata: ?*anyopaque, file: std.Io.File, data: []const []u8, offset: u64) std.Io.File.ReadPositionalError!usize {
            const count = try io.vtable.fileReadPositional(userdata, file, data, offset);
            if (offset == 49 * 512 and data[0].len == 1) {
                if (writable) |target| {
                    writable = null;
                    target.writePositionalAll(io, &.{1}, 17 * 512) catch return error.InputOutput;
                }
            }
            return count;
        }
    };
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const parameters = try fixtureDisks(fixture, 49);
    const raw = try fixture.directory.dir.openFile(io, "original.raw", .{ .mode = .read_write });
    defer raw.close(io);
    Drift.writable = raw;
    defer Drift.writable = null;
    var vtable = io.vtable.*;
    vtable.fileReadPositional = Drift.read;
    try std.testing.expectError(error.SourceChanged, original.Test.inspectDisks(.{
        .userdata = io.userdata,
        .vtable = &vtable,
    }, fixture.directory, parameters));
    try std.testing.expectEqual(null, Drift.writable);
}

test "original record inspection requires an independent digest and refuses wrong production geometry" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var parameters = try original.Test.parameters(io);
    parameters.sectors = 49;
    const dummy: c.File = .{ .path = "fixture", .sha256 = c.digest("fixture"), .size = 1, .mode = 0o600 };
    const record: original.Record = .{
        .guard = parameters.guard(),
        .raw = dummy,
        .vhd = dummy,
        .manifest = dummy,
        .original_config = dummy,
    };
    const bytes = try c.canonical(a, record);
    defer a.free(bytes);
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    var failures: c.Failure = .{};
    try original.Test.publishBytes(io, &lock, original.record_name, bytes, &failures);
    try std.testing.expectError(error.HashMismatch, original.inspect(a, io, fixture.directory, c.digest("not the producer record")));
    try std.testing.expectError(error.WrongPurposeGeometry, original.inspect(a, io, fixture.directory, c.digest(bytes)));
    try absent(fixture.directory, "original.raw");
}

test "original streaming completes short writes but rejects zero progress and disk sync failures" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var parameters = try original.Test.parameters(io);
    parameters.sectors = 49;
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    var vtable = io.vtable.*;
    const injected: std.Io = .{ .userdata = io.userdata, .vtable = &vtable };
    vtable.fileWritePositional = shortWrite;
    try original.Test.disk(injected, &lock, "original.raw", parameters, false);
    try original.Test.disk(injected, &lock, "original.vhd", parameters, true);
    _ = try original.Test.inspectDisks(io, fixture.directory, parameters);
    vtable.fileWritePositional = noWrite;
    try std.testing.expectError(error.NoProgress, original.Test.disk(injected, &lock, "partial.raw", parameters, false));
    vtable.fileWritePositional = io.vtable.fileWritePositional;
    vtable.fileSync = noFileSync;
    try std.testing.expectError(error.InputOutput, original.Test.disk(injected, &lock, "unsynced.raw", parameters, false));
    try absent(fixture.directory, original.record_name);
}

test "original immutable publication reports file and directory sync failure without durable success" {
    for ([_]bool{ false, true }) |directory_sync| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var lock = try fixture.directory.lock(io);
        defer lock.close(io);
        var vtable = io.vtable.*;
        vtable.fileSync = if (directory_sync) noDirSync else noFileSync;
        const injected: std.Io = .{ .userdata = io.userdata, .vtable = &vtable };
        var failures: c.Failure = .{};
        try std.testing.expectError(error.PublicationIncomplete, original.Test.publishBytes(injected, &lock, "fixture.json", "{}", &failures));
        try std.testing.expect(failures.recording != null);
        if (directory_sync) {
            const visible = try fixture.directory.read(io, a, "fixture.json", 8, null);
            defer a.free(visible);
            try std.testing.expectEqualStrings("{}", visible);
        } else try absent(fixture.directory, "fixture.json");
        try absent(fixture.directory, original.record_name);
    }
}

test "original core publication collision ambiguity and cleanup faults retain distinct failure lanes" {
    for ([_]private.TestFault{ .before_file_sync, .before_rename, .publication, .after_rename, .cleanup }) |fault| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var lock = try fixture.directory.lock(io);
        defer lock.close(io);
        // Replace-style publication uses a named staging file even on kernels
        // with O_TMPFILE, making the shared cleanup-failure seam observable.
        const result = if (fault == .cleanup)
            try lock.commitFault(io, "fixture.json", "{}", fault)
        else
            try lock.createImmutableFault(io, "fixture.json", "{}", fault);
        try std.testing.expect(result.status != .durable);
        try std.testing.expect(result.failures.recording != null);
        if (fault == .cleanup) try std.testing.expect(result.failures.cleanup != null);
        if (fault == .publication) try std.testing.expectEqual(private.CommitStatus.publication_unknown, result.status);
        if (fault == .after_rename) {
            try std.testing.expectEqual(private.CommitStatus.visible_not_durable, result.status);
            try std.testing.expectError(error.PathAlreadyExists, prep.files.publish(&lock, io, "fixture.json", "changed"));
        }
        try absent(fixture.directory, original.record_name);
    }
}
