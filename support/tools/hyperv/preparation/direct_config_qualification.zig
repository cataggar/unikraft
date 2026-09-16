// SPDX-License-Identifier: BSD-3-Clause
//! Explicit fresh full-size CLI qualification; never installed or admitted.
const std = @import("std");
const prep = @import("preparation");
const direct = @import("direct_validation");
const dc = prep.direct_config;
const c = prep.contracts;
const private = c.core.private_files;
const process = c.core.process;

const OriginalOutput = struct {
    scope: enum { local_original_seed_production_only },
    authority: enum { not_admitted },
    not_evidence_of: enum { build_local_boot_device_or_cloud_acceptance },
    state: enum { validated_local_files },
    production_record_sha256: []const u8,
};
const DerivedOutput = struct {
    scope: enum { local_direct_configuration_only },
    authority: enum { not_admitted },
    configuration: enum { unsolved_fragment },
    not_evidence_of: enum { solved_approval_source_authentication_build_boot_device_or_cloud_acceptance },
    derivation_sha256: []const u8,
};
const original_names = [_][]const u8{
    "original.raw",    "original.vhd",            "original.json", "original.config",
    "production.json", "production.started.json", ".writer.lock",
};

fn command(a: std.mem.Allocator, io: std.Io, cwd: std.Io.Dir, tail: []const []const u8, expected: u8) !process.Result {
    const argv = try a.alloc([]const u8, tail.len + 1);
    defer a.free(argv);
    argv[0] = @import("test_options").preparation_cli;
    @memcpy(argv[1..], tail);
    var environment = std.process.Environ.Map.init(a);
    defer environment.deinit();
    var result = try process.run(a, io, .{
        .argv = argv,
        .environment = &environment,
        .cwd = cwd,
        .deadline = try process.Deadline.afterMilliseconds(20 * 60 * 1000),
        .stdout_limit = 8192,
        .stderr_limit = 8192,
    });
    errdefer result.deinit(a);
    if (result.failures.primary) |failure| {
        if (expected == 0 or failure.stage != .process_run or failure.category != .child_failed) return error.UnexpectedCliFailure;
    }
    if (result.failures.cleanup != null or result.failures.recording != null or !result.cleanup_complete or
        result.termination == null or result.termination.? != .exited or result.termination.?.exited != expected)
        return error.UnexpectedCliResult;
    if (expected != 0 and result.stdout.len != 0) return error.RefusalReportedSuccess;
    return result;
}
fn publish(io: std.Io, lock: *private.Locked, name: []const u8, bytes: []const u8) !void {
    const result = try prep.files.publish(lock, io, name, bytes);
    if (result.status != .durable or result.failures.recording != null or result.failures.cleanup != null)
        return error.QualificationRecordIncomplete;
}
fn sync(io: std.Io, dir: std.Io.Dir) !void {
    try (std.Io.File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}
fn snapshots(io: std.Io, directory: private.Directory) ![original_names.len]prep.files.Metadata {
    var result: [original_names.len]prep.files.Metadata = undefined;
    for (original_names, &result) |name, *value| {
        const file = try directory.openFile(io, name);
        defer file.close(io);
        value.* = try prep.files.metadata(file);
    }
    return result;
}
fn absent(io: std.Io, directory: private.Directory, name: []const u8) !void {
    _ = directory.dir.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    return error.UnexpectedOutput;
}

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 2) return error.ExpectedFreshQualificationRoot;
    try private.absoluteFilePath(args[1]);
    const parent = try prep.files.openPrivate(io, std.fs.path.dirname(args[1]).?);
    defer parent.close(io);
    try parent.dir.createDir(io, std.fs.path.basename(args[1]), .fromMode(0o700));
    try sync(io, parent.dir);
    const root = try prep.files.openPrivate(io, args[1]);
    defer root.close(io);
    try process.initialize();
    const start = try process.monotonicNanoseconds();
    var generated = try command(a, io, root.dir, &.{ "original-seed", args[1], "seed" }, 0);
    defer generated.deinit(a);
    const original_end = try process.monotonicNanoseconds();
    const output = try direct.parse(OriginalOutput, a, std.mem.trimEnd(u8, generated.stdout, "\n"));
    defer output.deinit();
    const production_sha = try c.sha(output.value.production_record_sha256);
    const seed_path = try std.fs.path.join(a, &.{ args[1], "seed" });
    const seed_dir = try prep.files.openPrivate(io, seed_path);
    defer seed_dir.close(io);
    const before = try snapshots(io, seed_dir);
    const original_bytes = try seed_dir.read(io, a, "production.json", 65536, try c.core.contracts.parseSha256(&production_sha));
    const original = try c.parse(prep.original_seed.Record, a, original_bytes);
    defer original.deinit();

    var derived = try command(a, io, root.dir, &.{ "direct-config", seed_path, &production_sha, args[1], "derived" }, 0);
    defer derived.deinit(a);
    const derived_end = try process.monotonicNanoseconds();
    const derived_output = try direct.parse(DerivedOutput, a, std.mem.trimEnd(u8, derived.stdout, "\n"));
    defer derived_output.deinit();
    const derivation_sha = try c.sha(derived_output.value.derivation_sha256);
    const derived_path = try std.fs.path.join(a, &.{ args[1], "derived" });
    const derived_dir = try prep.files.openPrivate(io, derived_path);
    defer derived_dir.close(io);
    const record_bytes = try derived_dir.read(io, a, dc.record_name, 65536, try c.core.contracts.parseSha256(&derivation_sha));
    const record = try c.parse(dc.Record, a, record_bytes);
    defer record.deinit();
    const fragment = try derived_dir.read(io, a, dc.config_name, prep.config.config_cap, try c.core.contracts.parseSha256(&record.value.derived_config.sha256));
    const wanted_fragment = try prep.config.renderDirectPersistence(a, original.value.guard);
    if (!std.mem.eql(u8, fragment, wanted_fragment)) return error.WrongDirectFragment;
    try prep.config.validateDirectPersistence(a, fragment, original.value.guard);
    const wanted: dc.Record = .{
        .guard = original.value.guard,
        .original = .{
            .production_record = .{ .path = "production.json", .size = original_bytes.len, .mode = 0o600, .sha256 = production_sha },
            .manifest = original.value.manifest,
            .config = original.value.original_config,
            .raw = original.value.raw,
            .vhd = original.value.vhd,
        },
        .derived_config = .{ .path = "direct.config", .size = fragment.len, .mode = 0o600, .sha256 = c.digest(fragment) },
    };
    if (!std.mem.eql(u8, record_bytes, try c.canonical(a, wanted))) return error.WrongDerivationBinding;
    if (std.meta.eql(record.value.original.config.sha256, record.value.derived_config.sha256)) return error.ConflatedConfigurationDomains;

    var wrong_sha = production_sha;
    wrong_sha[0] = if (wrong_sha[0] == '0') '1' else '0';
    const unsafe_path = try std.fs.path.join(a, &.{ args[1], "unsafe" });
    try root.dir.createDir(io, "unsafe", .fromMode(0o700));
    const unsafe = try root.dir.openDir(io, "unsafe", .{ .follow_symlinks = false, .iterate = true });
    defer unsafe.close(io);
    try unsafe.setPermissions(io, .fromMode(0o755));
    const refusals = [_][]const []const u8{
        &.{ "direct-config", seed_path, &wrong_sha, args[1], "wrong-hash" },
        &.{ "direct-config", seed_path, &production_sha, args[1], "derived" },
        &.{ "direct-config", seed_path, &production_sha, unsafe_path, "never" },
        &.{ "direct-config", seed_path, &production_sha, seed_path, "never" },
        &.{ "direct-config", seed_path, &production_sha, args[1], "extra", "--fixture" },
    };
    for (refusals) |tail| {
        var refused = try command(a, io, root.dir, tail, 1);
        defer refused.deinit(a);
    }
    try unsafe.setPermissions(io, .fromMode(0o700));
    try absent(io, root, "wrong-hash");
    try absent(io, root, "extra");
    try absent(io, .{ .dir = unsafe }, "never");
    try absent(io, seed_dir, "never");
    try @import("original_seed_qualification.zig").independent(a, io, seed_dir, original.value);
    if (!std.meta.eql(before, try snapshots(io, seed_dir))) return error.OriginalMetadataChanged;
    const end = try process.monotonicNanoseconds();
    const cli = try private.openAbsolute(io, @import("test_options").preparation_cli, .artifact);
    defer cli.close(io);
    const cli_before = try private.snapshot(cli);
    const cli_sha = try prep.files.hashFile(io, cli, cli_before.size);
    if (!private.sameSnapshot(cli_before, try private.snapshot(cli))) return error.ExecutableChanged;
    const report = try c.canonical(a, .{
        .schema = "unikraft.hyperv.direct-config.offline-qualification.native",
        .version = @as(u8, 1),
        .scope = "local_unsolved_configuration_only",
        .authority = "not_admitted",
        .host_arch = @tagName(@import("builtin").cpu.arch),
        .optimization = @tagName(@import("builtin").mode),
        .cli_sha256 = cli_sha,
        .full_size_creations = @as(u8, 1),
        .derivations = @as(u8, 1),
        .cli_refusals = refusals.len,
        .original_files_unchanged = true,
        .original_producer_complete_disk_passes = @as(u8, 2),
        .derivation_complete_disk_passes = @as(u8, 2),
        .independent_full_bytes_read = prep.original_seed.logical_size * 2 + 512,
        .original_creation_milliseconds = (original_end - start) / std.time.ns_per_ms,
        .derivation_milliseconds = (derived_end - original_end) / std.time.ns_per_ms,
        .independent_validation_and_refusal_milliseconds = (end - derived_end) / std.time.ns_per_ms,
        .production_record_sha256 = production_sha,
        .derivation_record_sha256 = derivation_sha,
        .derivation = record.value,
    });
    var lock = try root.lock(io);
    defer lock.close(io);
    try publish(io, &lock, "creation.stdout.json", generated.stdout);
    try publish(io, &lock, "derivation.stdout.json", derived.stdout);
    try publish(io, &lock, "qualification.json", report);
    try sync(io, parent.dir);
    var stdout = std.Io.File.stdout().writer(io, &.{});
    try stdout.interface.print("direct-config offline qualification: 1 full-size original, 1 unsolved derivation, {d} refusals, original files unchanged; authority=not_admitted; report_sha256={s}\n", .{
        refusals.len, c.digest(report),
    });
}
