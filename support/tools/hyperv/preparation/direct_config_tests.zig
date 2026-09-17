// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const prep = @import("preparation");
const config = prep.config;
const dc = prep.direct_config;
const c = prep.contracts;
const private = c.core.private_files;
const a = std.testing.allocator;
const io = std.testing.io;

const guard: config.Guard = .{
    .run_id = "00112233445566778899aabbccddeeff".*,
    .disk_id = "102132435465768798a9bacbdcedfe0f".*,
    .sectors = 8388608,
    .lun = 7,
};
const metadata_text =
    "unikraft-native-config-metadata-v1\n" ++
    "symbol\tUKPLAT_CPU_MAXCOUNT\tint\n" ++
    "symbol\tAPPHYPERVACCEPTANCE\tbool\n" ++
    "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE\tbool\n" ++
    "symbol\tLIBSTORVSC\tbool\n" ++
    "symbol\tLIBSTORVSC_LUN_DISCOVERY\tbool\n" ++
    "symbol\tLIBSTORVSC_GUARDED_IO\tbool\n" ++
    "symbol\tLIBSTORVSC_MAX_DEVICES\tint\n" ++
    "symbol\tLIBSTORVSC_MAX_LUNS\tint\n" ++
    "symbol\tAPPHYPERVACCEPTANCE_NETWORK_APPLICATION\tbool\n" ++
    "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID\tstring\n" ++
    "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_DISK_ID\tstring\n" ++
    "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_SECTORS\tint\n" ++
    "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_SECTOR_SIZE\tint\n" ++
    "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY\tint\n" ++
    "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_LUN\tint\n";

fn replaced(bytes: []const u8, from: []const u8, to: []const u8) ![]u8 {
    const offset = std.mem.indexOf(u8, bytes, from) orelse return error.MissingFixtureText;
    return std.fmt.allocPrint(a, "{s}{s}{s}", .{ bytes[0..offset], to, bytes[offset + from.len ..] });
}
fn refused(value: anytype) !void {
    if (value) |_| return error.ExpectedRefusal else |_| {}
}

test "direct fragment is distinct unsolved CPU1 config and never changes the original domain" {
    const original = try config.render(a, guard);
    defer a.free(original);
    const saved = c.digest(original);
    const fragment = try config.renderDirectPersistence(a, guard);
    defer a.free(fragment);
    try std.testing.expect(std.mem.startsWith(u8, fragment, "# " ++ config.direct_format ++ "\nCONFIG_UKPLAT_CPU_MAXCOUNT=1\n"));
    try std.testing.expect(std.mem.indexOf(u8, fragment, "CONFIG_LIBSTORVSC_MAX_LUNS=2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, original, "CONFIG_LIBSTORVSC_MAX_LUNS=8\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, original, "UKPLAT_CPU_MAXCOUNT") == null);
    try std.testing.expect(!std.meta.eql(saved, c.digest(fragment)));
    try std.testing.expectEqual(saved, c.digest(original));
    try config.validatePurpose(a, original, guard, .persistence);
    try config.validateDirectPersistence(a, fragment, guard);
    try std.testing.expectError(error.InvalidGuardProfile, config.validateDirectPersistence(a, original, guard));
    try refused(config.validate(a, fragment, guard));
    try std.testing.expectError(error.WrongPlatform, @import("direct_validation").inspectConfig(a, fragment, .{
        .run_id = guard.run_id,
        .disk_id = guard.disk_id,
        .sectors = guard.sectors,
        .lun = guard.lun,
    }));
    var metadata = try config.Metadata.parse(a, metadata_text);
    defer metadata.deinit();
    try config.validateDirectPersistenceWithMetadata(a, fragment, guard, &metadata);
}

test "direct metadata types all supplied candidate settings without claiming a solver or approval" {
    const fragment = try config.renderDirectPersistence(a, guard);
    defer a.free(fragment);
    const candidate = try std.fmt.allocPrint(a, "{s}CONFIG_UNRELATED=10\nCONFIG_ARCH_X86_64=y\nCONFIG_PLAT_HYPERV=y\n", .{fragment});
    defer a.free(candidate);
    var metadata = try config.Metadata.parse(a, metadata_text);
    defer metadata.deinit();
    try metadata.addSymbol("UNRELATED", .hex);
    try metadata.addSymbol("ARCH_X86_64", .boolean);
    try metadata.addSymbol("PLAT_HYPERV", .boolean);
    try config.validateDirectPersistenceWithMetadata(a, candidate, guard, &metadata);
    try refused(config.validateDirectPersistence(a, candidate, guard));
    const missing = try std.fmt.allocPrint(a, "{s}CONFIG_UNDECLARED=y\n", .{candidate});
    defer a.free(missing);
    try std.testing.expectError(error.IncompleteMetadata, config.validateDirectPersistenceWithMetadata(a, missing, guard, &metadata));
    var empty = config.Metadata.init(a);
    defer empty.deinit();
    try std.testing.expectError(error.IncompleteMetadata, config.validateDirectPersistenceWithMetadata(a, fragment, guard, &empty));
}

test "direct metadata conflicts duplicates unknown guarded declarations and missing CPU fail" {
    const fragment = try config.renderDirectPersistence(a, guard);
    defer a.free(fragment);
    for ([_][]const u8{ "LIBSTORVSC_MAX_LUNS", "UKPLAT_CPU_MAXCOUNT", "APPHYPERVACCEPTANCE_PERSISTENCE_LUN" }) |name| {
        const from = try std.fmt.allocPrint(a, "symbol\t{s}\tint", .{name});
        defer a.free(from);
        const to = try std.fmt.allocPrint(a, "symbol\t{s}\thex", .{name});
        defer a.free(to);
        const changed = try replaced(metadata_text, from, to);
        defer a.free(changed);
        var metadata = try config.Metadata.parse(a, changed);
        defer metadata.deinit();
        try std.testing.expectError(error.ConflictingMetadata, config.validateDirectPersistenceWithMetadata(a, fragment, guard, &metadata));
    }
    var metadata = try config.Metadata.parse(a, metadata_text);
    defer metadata.deinit();
    try metadata.addSymbol("LIBSTORVSC_UNREVIEWED_OVERRIDE", .boolean);
    try std.testing.expectError(error.UnknownDangerousOverride, config.validateDirectPersistenceWithMetadata(a, fragment, guard, &metadata));
    const duplicate = metadata_text ++ "symbol\tUKPLAT_CPU_MAXCOUNT\tint\n";
    try std.testing.expectError(error.DuplicateMetadata, config.Metadata.parse(a, duplicate));
    try std.testing.expectError(error.InvalidMetadata, config.Metadata.parse(a, "not native metadata"));
    const without_cpu = try replaced(fragment, "CONFIG_UKPLAT_CPU_MAXCOUNT=1\n", "");
    defer a.free(without_cpu);
    var complete = try config.Metadata.parse(a, metadata_text);
    defer complete.deinit();
    try std.testing.expectError(error.MissingRequired, config.validateDirectPersistenceWithMetadata(a, without_cpu, guard, &complete));
    // The preexisting fragment validator did not require a CPU setting.
    try config.validateDirectPersistence(a, without_cpu, guard);
}

test "direct renderer and validators reject stale geometry identities policy and guarded overrides" {
    const fragment = try config.renderDirectPersistence(a, guard);
    defer a.free(fragment);
    var metadata = try config.Metadata.parse(a, metadata_text);
    defer metadata.deinit();
    for ([_][2][]const u8{
        .{ "MAX_LUNS=2", "MAX_LUNS=8" },
        .{ "MAX_DEVICES=2", "MAX_DEVICES=3" },
        .{ "CPU_MAXCOUNT=1", "CPU_MAXCOUNT=2" },
        .{ "PERSISTENCE=y", "PERSISTENCE=n" },
        .{ "LUN_DISCOVERY=y", "LUN_DISCOVERY=n" },
        .{ "GUARDED_IO=y", "GUARDED_IO=n" },
        .{ "IDENTITY_POLICY=2", "IDENTITY_POLICY=1" },
        .{ "LUN=7", "LUN=6" },
        .{ "SECTORS=8388608", "SECTORS=49" },
        .{ "SECTOR_SIZE=512", "SECTOR_SIZE=4096" },
        .{ &guard.run_id, "abcdef0123456789abcdef0123456789" },
        .{ &guard.disk_id, "00000000000000000000000000000000" },
        .{ "# CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION is not set", "CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION=y" },
    }) |mutation| {
        const changed = try replaced(fragment, mutation[0], mutation[1]);
        defer a.free(changed);
        try refused(config.validateDirectPersistence(a, changed, guard));
        try refused(config.validateDirectPersistenceWithMetadata(a, changed, guard, &metadata));
    }
    for ([_][]const u8{
        "CONFIG_LIBSTORVSC_MAX_LUNS=2\n",
        "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_PATH=0\n",
        "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_TARGET=0\n",
        "CONFIG_APPHYPERVACCEPTANCE_DANGEROUS=y\n",
    }) |extra| {
        const changed = try std.fmt.allocPrint(a, "{s}{s}", .{ fragment, extra });
        defer a.free(changed);
        try refused(config.validateDirectPersistenceWithMetadata(a, changed, guard, &metadata));
    }
    var changed = guard;
    changed.sectors = 49;
    try std.testing.expectError(error.WrongPurposeGeometry, config.renderDirectPersistence(a, changed));
    changed = guard;
    changed.disk_id = changed.run_id;
    try std.testing.expectError(error.IdentityCollision, config.renderDirectPersistence(a, changed));
    try std.testing.expectError(error.IdentityCollision, config.validateDirectPersistenceWithMetadata(a, fragment, changed, &metadata));
}

const Fixture = struct {
    temporary: std.testing.TmpDir,
    path: [:0]u8,
    directory: private.Directory,

    fn init() !Fixture {
        var temporary = std.testing.tmpDir(.{ .iterate = true });
        errdefer temporary.cleanup();
        try temporary.dir.setPermissions(io, .fromMode(0o700));
        const path = try temporary.dir.realPathFileAlloc(io, ".", a);
        errdefer a.free(path);
        return .{ .temporary = temporary, .path = path, .directory = try prep.files.openPrivate(io, path) };
    }
    fn deinit(self: *Fixture) void {
        self.directory.close(io);
        a.free(self.path);
        self.temporary.cleanup();
    }
    fn put(self: Fixture, name: []const u8, bytes: []const u8) !void {
        const file = try self.directory.dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writePositionalAll(io, bytes, 0);
    }
    // Descriptor/refusal fixtures only, never accepted original seeds.
    fn fakeSource(self: Fixture) !void {
        var lock = try self.directory.lock(io);
        defer lock.close(io);
        for ([_][]const u8{ "original.raw", "original.vhd", "original.json", "original.config", "production.json", "production.started.json" }) |name|
            try self.put(name, "invalid original fixture");
    }
};

test "direct source custody never creates a missing original lock and rejects substitution" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.expectError(error.FileNotFound, dc.Test.HeldSource.open(io, fixture.path));
    try dc.Test.absent(io, fixture.directory, ".writer.lock");
    try fixture.fakeSource();
    var source = try dc.Test.HeldSource.open(io, fixture.path);
    defer source.close(io);
    try std.testing.expectError(error.WouldBlock, dc.Test.HeldSource.open(io, fixture.path));
    try source.verify(io);
    try fixture.directory.dir.rename("original.config", fixture.directory.dir, "old.config", io);
    try fixture.put("original.config", "invalid original fixture");
    try std.testing.expectError(error.SourceChanged, source.verify(io));
}

test "direct command refuses wrong hash and existing or unsafe outputs before full-size inspection" {
    var source = try Fixture.init();
    defer source.deinit();
    try source.fakeSource();
    var output = try Fixture.init();
    defer output.deinit();
    var failures: c.Failure = .{};
    try std.testing.expectError(error.HashMismatch, dc.create(a, io, source.path, c.digest("wrong expected hash"), output.path, "wrong-hash", &failures));
    try dc.Test.absent(io, output.directory, "wrong-hash");
    try output.directory.dir.createDir(io, "exists", .fromMode(0o700));
    try output.put("file", "untouched");
    try output.directory.dir.symLink(io, "missing", "dangling", .{ .is_directory = true });
    for ([_][]const u8{ "exists", "file", "dangling" }) |name|
        try std.testing.expectError(error.PathAlreadyExists, dc.create(a, io, source.path, c.digest("fixture"), output.path, name, &failures));
    for ([_][]const u8{ "", ".", "..", ".hidden", "a/b", "a\\b", "a\nb" }) |name|
        try std.testing.expectError(error.UnsafePath, dc.create(a, io, source.path, c.digest("fixture"), output.path, name, &failures));
    try std.testing.expectError(error.OutputInsideOriginal, dc.create(a, io, source.path, c.digest("fixture"), source.path, "never", &failures));
    try dc.Test.absent(io, source.directory, "never");
    try output.directory.dir.setPermissions(io, .fromMode(0o755));
    try std.testing.expectError(error.UnsafeFile, dc.create(a, io, source.path, c.digest("fixture"), output.path, "never", &failures));
    try output.directory.dir.setPermissions(io, .fromMode(0o700));
    try std.testing.expectError(error.UnsafePath, dc.create(a, io, source.path, c.digest("fixture"), "relative", "never", &failures));
}

test "direct source custody rejects unsafe modes hardlinks and symlinks without adopting originals" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.fakeSource();
    const raw = try fixture.directory.dir.openFile(io, "original.raw", .{ .mode = .read_write });
    defer raw.close(io);
    try raw.setPermissions(io, .fromMode(0o644));
    try std.testing.expectError(error.UnsafeFile, dc.Test.HeldSource.open(io, fixture.path));
    try raw.setPermissions(io, .fromMode(0o600));
    const linux = std.os.linux;
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.linkat(fixture.directory.dir.handle, "original.raw", fixture.directory.dir.handle, "alias", 0)));
    try std.testing.expectError(error.UnsafeFile, dc.Test.HeldSource.open(io, fixture.path));
    try fixture.directory.dir.deleteFile(io, "alias");
    try fixture.directory.dir.rename("original.raw", fixture.directory.dir, "saved.raw", io);
    try fixture.directory.dir.symLink(io, "saved.raw", "original.raw", .{});
    try refused(dc.Test.HeldSource.open(io, fixture.path));
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

test "direct publication file and directory sync failures never supply a durable derivation" {
    for ([_]bool{ false, true }) |directory_sync| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var lock = try fixture.directory.lock(io);
        defer lock.close(io);
        var vtable = io.vtable.*;
        vtable.fileSync = if (directory_sync) noDirSync else noFileSync;
        var failures: c.Failure = .{};
        try std.testing.expectError(error.PublicationIncomplete, dc.Test.publishBytes(
            .{ .userdata = io.userdata, .vtable = &vtable },
            &lock,
            dc.record_name,
            "{}",
            &failures,
        ));
        try std.testing.expect(failures.recording != null);
        if (!directory_sync) try dc.Test.absent(io, fixture.directory, dc.record_name);
        try dc.Test.absent(io, fixture.directory, dc.config_name);
    }
}

test "direct output validation binds separate shape-only controls and refuses drift or partial history" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const fragment = try config.renderDirectPersistence(a, guard);
    defer a.free(fragment);
    const production: c.File = .{ .path = "production.json", .size = 3, .mode = 0o600, .sha256 = c.digest("{}\n") };
    const dummy: c.File = .{ .path = "shape-only", .size = 1, .mode = 0o600, .sha256 = c.digest("unvalidated fixture") };
    const source: prep.original_seed.Record = .{ .guard = guard, .raw = dummy, .vhd = dummy, .manifest = dummy, .original_config = dummy };
    const record = dc.Test.shapeRecord(source, production, fragment);
    try std.testing.expectEqual(production.sha256, record.original.production_record.sha256);
    try std.testing.expectEqual(guard, record.guard);
    try std.testing.expect(!std.meta.eql(record.original.config.sha256, record.derived_config.sha256));
    const bytes = try c.canonical(a, record);
    defer a.free(bytes);
    const parsed = try c.parse(dc.Record, a, bytes);
    defer parsed.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    var failures: c.Failure = .{};
    try dc.Test.publishBytes(io, &lock, dc.started_name, dc.started, &failures);
    try dc.Test.publishBytes(io, &lock, dc.config_name, fragment, &failures);
    try dc.Test.validateFiles(a, io, fixture.directory, record, false);
    try std.testing.expectError(error.FileNotFound, dc.Test.validateFiles(a, io, fixture.directory, record, true));
    try dc.Test.publishBytes(io, &lock, dc.record_name, bytes, &failures);
    try dc.Test.validateFiles(a, io, fixture.directory, record, true);
    try std.testing.expectError(error.PathAlreadyExists, dc.Test.publishBytes(io, &lock, dc.record_name, "changed", &failures));
    const changed = try fixture.directory.dir.openFile(io, dc.config_name, .{ .mode = .read_write });
    defer changed.close(io);
    try changed.writePositionalAll(io, "!", 0);
    try std.testing.expectError(error.HashMismatch, dc.Test.validateFiles(a, io, fixture.directory, record, true));
}
