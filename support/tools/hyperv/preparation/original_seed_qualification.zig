// SPDX-License-Identifier: BSD-3-Clause
//! Explicit large OFFLINE qualification. Not installed, and never an authority.
const std = @import("std");
const prep = @import("preparation");
const direct = @import("direct_validation");
const c = prep.contracts;
const private = c.core.private_files;
const process = c.core.process;

const Output = struct {
    scope: enum { local_original_seed_production_only },
    authority: enum { not_admitted },
    not_evidence_of: enum { build_local_boot_device_or_cloud_acceptance },
    state: enum { validated_local_files },
    production_record_sha256: []const u8,
};

fn command(allocator: std.mem.Allocator, io: std.Io, cwd: std.Io.Dir, root: []const u8) !process.Result {
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    return process.run(allocator, io, .{
        .argv = &.{ @import("test_options").preparation_cli, "original-seed", root, "seed" },
        .environment = &environment,
        .cwd = cwd,
        .deadline = try process.Deadline.afterMilliseconds(20 * 60 * 1000),
        .stdout_limit = 8192,
        .stderr_limit = 8192,
    });
}

fn exited(result: process.Result, expected: u8) !void {
    if (result.failures.primary) |failure| {
        if (expected == 0 or failure.stage != .process_run or failure.category != .child_failed)
            return error.UnexpectedCliFailure;
    }
    if (result.failures.cleanup != null or result.failures.recording != null or
        !result.cleanup_complete or result.termination == null or result.termination.? != .exited or
        result.termination.?.exited != expected) return error.UnexpectedCliResult;
}

fn sync(io: std.Io, directory: std.Io.Dir) !void {
    try (std.Io.File{ .handle = directory.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

fn publish(io: std.Io, lock: *private.Locked, name: []const u8, bytes: []const u8) !void {
    const result = try prep.files.publish(lock, io, name, bytes);
    if (result.status != .durable or result.failures.recording != null or result.failures.cleanup != null)
        return error.QualificationRecordIncomplete;
}

/// Separate descriptor reader using the existing production direct contracts.
/// No fake Scope/approval is fabricated to reach these read-only checks.
fn independent(allocator: std.mem.Allocator, io: std.Io, directory: private.Directory, record: prep.original_seed.Record) !void {
    if (!std.mem.eql(u8, record.schema, prep.original_seed.schema) or record.schema_version != 1 or
        !std.mem.eql(u8, record.producer.compiler_version, c.compiler_version) or
        !std.mem.eql(u8, record.producer.miz_revision, c.miz_revision) or
        !std.mem.eql(u8, record.producer.footer_creator, &prep.seed.footer_creator)) return error.WrongProductionContract;
    for ([_]c.File{ record.raw, record.vhd, record.manifest, record.original_config }, [_][]const u8{
        "original.raw", "original.vhd", "original.json", "original.config",
    }) |file, name| {
        if (!std.mem.eql(u8, file.path, name) or file.mode != 0o600) return error.WrongArtifactBinding;
    }
    const guard = record.guard;
    try prep.config.validateGuardPurpose(guard, .persistence);
    if (std.mem.eql(u8, &guard.run_id, &guard.disk_id)) return error.IdentityCollision;
    const parameters: prep.seed.Parameters = .{ .run_id = guard.run_id, .disk_id = guard.disk_id, .sectors = guard.sectors, .lun = guard.lun };
    const manifest = try directory.read(io, allocator, "original.json", 65536, try c.core.contracts.parseSha256(&record.manifest.sha256));
    defer allocator.free(manifest);
    if (manifest.len != record.manifest.size) return error.WrongControlSize;
    try direct.inspectManifest(allocator, manifest, parameters);
    const fragment = try directory.read(io, allocator, "original.config", prep.config.config_cap, try c.core.contracts.parseSha256(&record.original_config.sha256));
    defer allocator.free(fragment);
    if (fragment.len != record.original_config.size) return error.WrongControlSize;
    try prep.config.validatePurpose(allocator, fragment, guard, .persistence);
    if (prep.config.validateDirectPersistence(allocator, fragment, guard)) |_| {
        return error.OriginalSilentlyRewrittenAsDirect;
    } else |err| if (err != error.InvalidGuardProfile) return err;
    const raw = try directory.openFile(io, "original.raw");
    defer raw.close(io);
    const vhd = try directory.openFile(io, "original.vhd");
    defer vhd.close(io);
    const before_raw = try private.snapshot(raw);
    const before_vhd = try private.snapshot(vhd);
    if (before_raw.size != prep.original_seed.logical_size or before_raw.size != record.raw.size or
        before_vhd.size != prep.original_seed.logical_size + 512 or before_vhd.size != record.vhd.size)
        return error.WrongDiskSize;
    var left: [1024 * 1024]u8 = undefined;
    var right: [1024 * 1024]u8 = undefined;
    var raw_sha = std.crypto.hash.sha2.Sha256.init(.{});
    var vhd_sha = std.crypto.hash.sha2.Sha256.init(.{});
    var offset: u64 = 0;
    while (offset < prep.original_seed.logical_size) {
        if (try raw.readPositionalAll(io, &left, offset) != left.len or
            try vhd.readPositionalAll(io, &right, offset) != right.len) return error.ShortDiskRead;
        try direct.seedChunk(&left, offset, parameters);
        try direct.seedChunk(&right, offset, parameters);
        if (!std.mem.eql(u8, &left, &right)) return error.PrefixMismatch;
        raw_sha.update(&left);
        vhd_sha.update(&right);
        offset += left.len;
    }
    var footer: [512]u8 = undefined;
    if (try vhd.readPositionalAll(io, &footer, offset) != footer.len) return error.ShortFooterRead;
    try direct.footer(&footer, offset, &parameters.disk_id);
    try prep.seed.validateFooter(&footer, parameters);
    vhd_sha.update(&footer);
    if (try raw.readPositionalAll(io, left[0..1], offset) != 0 or
        try vhd.readPositionalAll(io, right[0..1], offset + 512) != 0) return error.TrailingDiskBytes;
    if (!std.mem.eql(u8, &record.raw.sha256, &std.fmt.bytesToHex(raw_sha.finalResult(), .lower)) or
        !std.mem.eql(u8, &record.vhd.sha256, &std.fmt.bytesToHex(vhd_sha.finalResult(), .lower))) return error.HashMismatch;
    const named_raw = try directory.openFile(io, "original.raw");
    defer named_raw.close(io);
    const named_vhd = try directory.openFile(io, "original.vhd");
    defer named_vhd.close(io);
    if (!private.sameSnapshot(before_raw, try private.snapshot(raw)) or
        !private.sameSnapshot(before_raw, try private.snapshot(named_raw)) or
        !private.sameSnapshot(before_vhd, try private.snapshot(vhd)) or
        !private.sameSnapshot(before_vhd, try private.snapshot(named_vhd))) return error.ArtifactChanged;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 2) return error.ExpectedFreshQualificationRoot;
    try private.absoluteFilePath(args[1]);
    const parent = try prep.files.openPrivate(init.io, std.fs.path.dirname(args[1]).?);
    defer parent.close(init.io);
    try parent.dir.createDir(init.io, std.fs.path.basename(args[1]), .fromMode(0o700));
    try sync(init.io, parent.dir);
    const root = try prep.files.openPrivate(init.io, args[1]);
    defer root.close(init.io);
    try process.initialize();
    const start = try process.monotonicNanoseconds();
    var generated = try command(allocator, init.io, root.dir, args[1]);
    defer generated.deinit(allocator);
    try exited(generated, 0);
    const produced = try process.monotonicNanoseconds();
    const output = try direct.parse(Output, allocator, std.mem.trimEnd(u8, generated.stdout, "\n"));
    defer output.deinit();
    const record_sha = try c.sha(output.value.production_record_sha256);
    var repeated = try command(allocator, init.io, root.dir, args[1]);
    defer repeated.deinit(allocator);
    try exited(repeated, 1);
    if (repeated.stdout.len != 0) return error.RefusalReportedSuccess;
    const child_path = try std.fs.path.join(allocator, &.{ args[1], "seed" });
    const child = try prep.files.openPrivate(init.io, child_path);
    defer child.close(init.io);
    var child_lock = try child.lock(init.io);
    defer child_lock.close(init.io);
    const bytes = try child.read(init.io, allocator, prep.original_seed.record_name, 65536, try c.core.contracts.parseSha256(&record_sha));
    const parsed = try c.parse(prep.original_seed.Record, allocator, bytes);
    defer parsed.deinit();
    try independent(allocator, init.io, child, parsed.value);
    try prep.files.requireLock(init.io, &child_lock);
    const end = try process.monotonicNanoseconds();
    const cli_path = @import("test_options").preparation_cli;
    const cli = try private.openAbsolute(init.io, cli_path, .artifact);
    defer cli.close(init.io);
    const cli_before = try private.snapshot(cli);
    const cli_sha = try prep.files.hashFile(init.io, cli, cli_before.size);
    if (!private.sameSnapshot(cli_before, try private.snapshot(cli))) return error.ExecutableChanged;
    const report = try c.canonical(allocator, .{
        .schema = "unikraft.hyperv.original-seed.offline-qualification.native",
        .version = @as(u8, 1),
        .authority = "not_admitted",
        .host_arch = @tagName(@import("builtin").cpu.arch),
        .optimization = @tagName(@import("builtin").mode),
        .compiler_version = c.compiler_version,
        .full_size_creations = @as(u8, 1),
        .preexisting_refusals = @as(u8, 1),
        .independent_full_bytes_read = prep.original_seed.logical_size * 2 + 512,
        .producer_complete_disk_passes = @as(u8, 2),
        .creation_milliseconds = (produced - start) / std.time.ns_per_ms,
        .independent_validation_and_refusal_milliseconds = (end - produced) / std.time.ns_per_ms,
        .cli_sha256 = cli_sha,
        .production_record_sha256 = record_sha,
        .products = parsed.value,
        .scope = "local_original_seed_files_only_no_build_boot_device_or_cloud_acceptance",
    });
    var lock = try root.lock(init.io);
    defer lock.close(init.io);
    try publish(init.io, &lock, "creation.stdout.json", generated.stdout);
    try publish(init.io, &lock, "qualification.json", report);
    try sync(init.io, parent.dir);
    var stdout = std.Io.File.stdout().writer(init.io, &.{});
    try stdout.interface.print("original-seed offline qualification: 1 full 4-GiB creation, 1 preexisting refusal, {d} independently validated bytes; authority=not_admitted; report_sha256={s}\n", .{
        prep.original_seed.logical_size * 2 + 512, c.digest(report),
    });
}
