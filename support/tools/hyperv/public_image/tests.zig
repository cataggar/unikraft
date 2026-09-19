const std = @import("std");
const image = @import("public_image");
const c = image.contracts;
const t = std.testing;
const a = t.allocator;
const io = t.io;
const options = @import("test_options");
const serial_fixture = @import("fixture.zig");
const config_text = "CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION=y\n" ++
    "CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4=\"10.77.0.20\"\nCONFIG_APPHYPERVACCEPTANCE_PEER_TCP_PORT=42001\n" ++
    "CONFIG_APPHYPERVACCEPTANCE_PEER_UDP_PORT=42002\nCONFIG_APPHYPERVACCEPTANCE_NONCE=\"0123456789abcdef\"\n";
const source: c.Source = .{
    .repository = "cataggar/unikraft",
    .repository_id = 123,
    .workflow_ref = "cataggar/unikraft/.github/workflows/integration.yaml@refs/heads/main",
    .run_id = 456,
    .run_attempt = 1,
    .head_sha = "0123456789abcdef0123456789abcdef01234567",
};
fn efi() [512]u8 {
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
const Fixture = struct {
    arena: *std.heap.ArenaAllocator,
    root: image.core.private_files.Directory,
    dir: image.core.private_files.Directory,
    name: []const u8,
    path: []const u8,
    cli: []const u8,
    input: c.Input,
    fn init(mode: u8, network: bool) !Fixture {
        try image.core.process.initialize();
        const arena = try a.create(std.heap.ArenaAllocator);
        arena.* = .init(a);
        const alloc = arena.allocator();
        const root_path = options.test_root orelse return error.MissingFixtureRoot;
        const root = try image.core.private_files.Directory.open(io, root_path);
        var nonce: [8]u8 = undefined;
        io.random(&nonce);
        const name = try std.fmt.allocPrint(alloc, "public,case-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
        const path = try image.files.path(alloc, root_path, name);
        const dir = try image.files.create(io, path);
        try dir.dir.writeFile(io, .{ .sub_path = "public,image.efi", .data = &efi(), .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) } });
        try dir.dir.writeFile(io, .{ .sub_path = "code,template.fd", .data = "synthetic firmware", .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) } });
        try dir.dir.writeFile(io, .{ .sub_path = "vars,template.fd", .data = &.{ 0xa5, mode }, .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) } });
        if (network) try dir.dir.writeFile(io, .{ .sub_path = "solved.config", .data = config_text, .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) } });
        return .{
            .arena = arena,
            .root = root,
            .dir = dir,
            .name = name,
            .path = path,
            .cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, alloc),
            .input = .{
                .efi = try image.files.path(alloc, path, "public,image.efi"),
                .state_dir = try image.files.path(alloc, path, "state"),
                .qemu = try std.Io.Dir.cwd().realPathFileAlloc(io, options.fixture, alloc),
                .ovmf_code = try image.files.path(alloc, path, "code,template.fd"),
                .ovmf_vars = try image.files.path(alloc, path, "vars,template.fd"),
                .solved_config = if (network) try image.files.path(alloc, path, "solved.config") else null,
                .timeout_ms = 10_000,
            },
        };
    }
    fn deinit(self: Fixture) void {
        self.dir.close(io);
        self.root.dir.deleteTree(io, self.name) catch @panic("owned synthetic fixture cleanup failed");
        self.root.close(io);
        self.arena.deinit();
        a.destroy(self.arena);
    }
    fn prepare(self: Fixture) !c.State {
        return image.engine.prepare(self.arena.allocator(), io, self.input, .{ .self_executable = self.cli });
    }
    fn stateDir(self: Fixture) !image.core.private_files.Directory {
        return image.core.private_files.Directory.open(io, self.input.state_dir);
    }
};

fn finalizeDirect(
    alloc: std.mem.Allocator,
    root: image.core.private_files.Directory,
    options_value: image.compute_artifacts.FinalizeOptions,
) !image.compute_artifacts.FinalizationRecord {
    var attempt = try image.compute_artifacts.reserveAttempt(io, root, .qcow2);
    defer attempt.close(io);
    const record = image.compute_artifacts.finalizeQcow2(
        alloc,
        io,
        root,
        attempt.evidence,
        options_value,
    ) catch |err| {
        _ = attempt.rollback(io, root);
        return err;
    };
    _ = try image.compute_artifacts.verifyFinalizedQcow2(
        alloc,
        io,
        root,
        &attempt,
        options_value,
    );
    if (!attempt.cleanupStage(io, root)) return error.AttemptCleanupFailed;
    return record;
}

fn deriveDirect(
    alloc: std.mem.Allocator,
    root: image.core.private_files.Directory,
    options_value: image.compute_artifacts.DeriveOptions,
) !image.compute_artifacts.DerivationRecord {
    var attempt = try image.compute_artifacts.reserveAttempt(io, root, .vhd);
    defer attempt.close(io);
    const record = image.compute_artifacts.deriveFixedVhd(
        alloc,
        io,
        root,
        attempt.evidence,
        options_value,
    ) catch |err| {
        _ = attempt.rollback(io, root);
        return err;
    };
    _ = try image.compute_artifacts.verifyDerivedFixedVhd(
        alloc,
        io,
        root,
        &attempt,
        options_value,
    );
    if (!attempt.cleanupStage(io, root)) return error.AttemptCleanupFailed;
    return record;
}

fn expectMissingName(directory: image.core.private_files.Directory, name: []const u8) !void {
    if (directory.dir.statFile(io, name, .{ .follow_symlinks = false })) |_| {
        return error.UnexpectedOutput;
    } else |err| if (err != error.FileNotFound) return err;
}

fn rewritePrivateFile(
    directory: image.core.private_files.Directory,
    name: []const u8,
    bytes: []const u8,
) !void {
    const file = try directory.dir.openFile(io, name, .{
        .mode = .read_write,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer file.close(io);
    try file.setLength(io, 0);
    try file.writePositionalAll(io, bytes, 0);
    try file.setLength(io, bytes.len);
    try file.sync(io);
    try image.files.sync(io, directory.dir);
}

test "compute attempts reserve every publication slot and clean only retained identities" {
    const fixture = try Fixture.init(0, false);
    defer fixture.deinit();
    const alloc = fixture.arena.allocator();
    const cases = [_]struct {
        kind: image.compute_artifacts.AttemptKind,
        stage: []const u8,
        output: []const u8,
        record: []const u8,
    }{
        .{
            .kind = .qcow2,
            .stage = image.compute_artifacts.qcow2_stage_name,
            .output = image.compute_artifacts.qcow2_name,
            .record = image.compute_artifacts.qcow2_record_name,
        },
        .{
            .kind = .vhd,
            .stage = image.compute_artifacts.vhd_stage_name,
            .output = image.compute_artifacts.vhd_name,
            .record = image.compute_artifacts.vhd_record_name,
        },
    };
    for (cases, 0..) |case, case_index| {
        for ([_]enum { stage, output, record }{ .stage, .output, .record }, 0..) |target, target_index| {
            const state_path = try image.files.path(
                alloc,
                fixture.path,
                try std.fmt.allocPrint(alloc, "collision-{d}-{d}", .{ case_index, target_index }),
            );
            const state = try image.files.create(io, state_path);
            defer state.close(io);
            switch (target) {
                .stage => {
                    try state.dir.createDir(io, case.stage, .fromMode(0o700));
                    const collision = try state.dir.openDir(io, case.stage, .{
                        .follow_symlinks = false,
                    });
                    defer collision.close(io);
                    try collision.writeFile(io, .{
                        .sub_path = "sentinel",
                        .data = "stage collision",
                        .flags = .{
                            .exclusive = true,
                            .permissions = .fromMode(0o600),
                        },
                    });
                },
                .output, .record => {
                    const name = if (target == .output) case.output else case.record;
                    try state.dir.writeFile(io, .{
                        .sub_path = name,
                        .data = "publication collision",
                        .flags = .{
                            .exclusive = true,
                            .permissions = .fromMode(0o600),
                        },
                    });
                },
            }
            try t.expectError(
                error.PathAlreadyExists,
                image.compute_artifacts.reserveAttempt(io, state, case.kind),
            );
            switch (target) {
                .stage => {
                    const collision = try state.dir.openDir(io, case.stage, .{
                        .follow_symlinks = false,
                    });
                    defer collision.close(io);
                    try t.expectEqualStrings(
                        "stage collision",
                        try (image.core.private_files.Directory{ .dir = collision }).read(
                            io,
                            alloc,
                            "sentinel",
                            64,
                            null,
                        ),
                    );
                },
                .output, .record => {
                    const name = if (target == .output) case.output else case.record;
                    try t.expectEqualStrings(
                        "publication collision",
                        try state.read(io, alloc, name, 64, null),
                    );
                },
            }
        }
    }

    const retry_path = try image.files.path(alloc, fixture.path, "crash-retry");
    const retry_state = try image.files.create(io, retry_path);
    defer retry_state.close(io);
    var abandoned = try image.compute_artifacts.reserveAttempt(io, retry_state, .qcow2);
    abandoned.close(io);
    try t.expectError(
        error.PathAlreadyExists,
        image.compute_artifacts.reserveAttempt(io, retry_state, .qcow2),
    );
    try t.expectEqual(@as(u64, 0), (try retry_state.dir.statFile(
        io,
        image.compute_artifacts.qcow2_name,
        .{ .follow_symlinks = false },
    )).size);

    const replacement_path = try image.files.path(alloc, fixture.path, "replacement");
    const replacement_state = try image.files.create(io, replacement_path);
    defer replacement_state.close(io);
    var replaced = try image.compute_artifacts.reserveAttempt(io, replacement_state, .vhd);
    defer replaced.close(io);
    try replacement_state.dir.rename(
        image.compute_artifacts.vhd_name,
        replacement_state.dir,
        "owned-output",
        io,
    );
    try replacement_state.dir.writeFile(io, .{
        .sub_path = image.compute_artifacts.vhd_name,
        .data = "replacement output",
        .flags = .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        },
    });
    const replacement_cleanup = replaced.rollback(io, replacement_state);
    try t.expect(!replacement_cleanup.output_complete);
    try t.expectEqualStrings(
        "replacement output",
        try replacement_state.read(io, alloc, image.compute_artifacts.vhd_name, 64, null),
    );
    try expectMissingName(replacement_state, image.compute_artifacts.vhd_record_name);

    const moved_path = try image.files.path(alloc, fixture.path, "moved-reservation");
    const moved_state = try image.files.create(io, moved_path);
    defer moved_state.close(io);
    var moved = try image.compute_artifacts.reserveAttempt(io, moved_state, .vhd);
    defer moved.close(io);
    try moved_state.dir.rename(
        image.compute_artifacts.vhd_record_name,
        moved_state.dir,
        "moved-record",
        io,
    );
    const moved_cleanup = moved.rollback(io, moved_state);
    try t.expect(!moved_cleanup.record_complete);
    try t.expect(moved_cleanup.stage_complete and moved_cleanup.output_complete);
    try t.expectEqual(@as(u64, 0), (try moved_state.dir.statFile(
        io,
        "moved-record",
        .{ .follow_symlinks = false },
    )).size);

    const record_replacement_path = try image.files.path(
        alloc,
        fixture.path,
        "record-replacement",
    );
    const record_replacement_state = try image.files.create(io, record_replacement_path);
    defer record_replacement_state.close(io);
    var record_replaced = try image.compute_artifacts.reserveAttempt(
        io,
        record_replacement_state,
        .qcow2,
    );
    defer record_replaced.close(io);
    try record_replacement_state.dir.rename(
        image.compute_artifacts.qcow2_record_name,
        record_replacement_state.dir,
        "owned-record",
        io,
    );
    try record_replacement_state.dir.writeFile(io, .{
        .sub_path = image.compute_artifacts.qcow2_record_name,
        .data = "replacement record",
        .flags = .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        },
    });
    const record_replacement_cleanup = record_replaced.rollback(
        io,
        record_replacement_state,
    );
    try t.expect(!record_replacement_cleanup.record_complete);
    try t.expectEqualStrings(
        "replacement record",
        try record_replacement_state.read(
            io,
            alloc,
            image.compute_artifacts.qcow2_record_name,
            64,
            null,
        ),
    );
    try expectMissingName(record_replacement_state, image.compute_artifacts.qcow2_name);

    const stage_replacement_path = try image.files.path(
        alloc,
        fixture.path,
        "stage-replacement",
    );
    const stage_replacement_state = try image.files.create(io, stage_replacement_path);
    defer stage_replacement_state.close(io);
    var stage_replaced = try image.compute_artifacts.reserveAttempt(
        io,
        stage_replacement_state,
        .vhd,
    );
    defer stage_replaced.close(io);
    try stage_replacement_state.dir.rename(
        image.compute_artifacts.vhd_stage_name,
        stage_replacement_state.dir,
        "owned-stage",
        io,
    );
    try stage_replacement_state.dir.createDir(
        io,
        image.compute_artifacts.vhd_stage_name,
        .fromMode(0o700),
    );
    const replacement_stage = try stage_replacement_state.dir.openDir(
        io,
        image.compute_artifacts.vhd_stage_name,
        .{ .follow_symlinks = false },
    );
    defer replacement_stage.close(io);
    try replacement_stage.writeFile(io, .{
        .sub_path = "sentinel",
        .data = "replacement stage",
        .flags = .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        },
    });
    const stage_replacement_cleanup = stage_replaced.rollback(
        io,
        stage_replacement_state,
    );
    try t.expect(!stage_replacement_cleanup.stage_complete);
    try t.expect(stage_replacement_cleanup.output_complete);
    try t.expect(stage_replacement_cleanup.record_complete);
    try t.expectEqualStrings(
        "replacement stage",
        try (image.core.private_files.Directory{ .dir = replacement_stage }).read(
            io,
            alloc,
            "sentinel",
            64,
            null,
        ),
    );

    const cleanup_path = try image.files.path(alloc, fixture.path, "cleanup-failure");
    const cleanup_state = try image.files.create(io, cleanup_path);
    defer cleanup_state.close(io);
    var blocked = try image.compute_artifacts.reserveAttempt(io, cleanup_state, .qcow2);
    defer blocked.close(io);
    try blocked.stage.writeFile(io, .{
        .sub_path = "unexpected",
        .data = "retained failure evidence",
        .flags = .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        },
    });
    const blocked_cleanup = blocked.rollback(io, cleanup_state);
    try t.expect(!blocked_cleanup.stage_complete);
    try t.expect(blocked_cleanup.output_complete and blocked_cleanup.record_complete);
    const retained_stage = try cleanup_state.dir.openDir(
        io,
        image.compute_artifacts.qcow2_stage_name,
        .{ .follow_symlinks = false },
    );
    defer retained_stage.close(io);
    try t.expectEqualStrings(
        "retained failure evidence",
        try (image.core.private_files.Directory{ .dir = retained_stage }).read(
            io,
            alloc,
            "unexpected",
            64,
            null,
        ),
    );
}

test "native miz creates exact raw GPT fixed VHD genuine four-mode wire and durable exact export" {
    const f = try Fixture.init(16, false);
    defer f.deinit();
    const alloc = f.arena.allocator();
    const state = try f.prepare();
    if (state.phase != .prepared) std.debug.print("synthetic failure: packaged={} boots={any} failures={any}\n", .{
        state.package != null,
        .{ state.boots[0] != null, state.boots[1] != null, state.boots[2] != null, state.boots[3] != null },
        state.failures,
    });
    try t.expectEqual(c.Phase.prepared, state.phase);
    try t.expectEqual(@as(u64, c.raw_bytes), state.package.?.raw.size);
    try t.expectEqual(@as(u64, c.vhd_bytes), state.package.?.vhd.size);
    const root = try f.stateDir();
    defer root.close(io);
    var lock = try root.lock(io);
    defer lock.close(io);
    const loaded = try image.engine.load(alloc, io, &lock, f.cli);
    try t.expectEqual(c.Phase.prepared, loaded.phase);
    const target = try image.files.path(alloc, f.path, "export");
    const published = image.manifest.publish(alloc, io, &lock, f.cli, target, source);
    try t.expect(image.engine.clean(published.failures));
    try t.expect(published.sha256 != null);
    const exported = try image.core.private_files.Directory.open(io, target);
    defer exported.close(io);
    const bytes = try exported.read(io, alloc, image.manifest.name, c.max_record, published.sha256);
    const manifest = try image.manifest.validate(alloc, bytes, source, try c.sha(state.inputs.producer.sha256));
    try t.expectEqual(@as(u8, 4), manifest.controller_revision);
    const exported_disk = try image.files.record(alloc, io, try image.files.path(alloc, target, "unikraft.vhd"), c.vhd_bytes, false);
    try t.expectEqualStrings(state.package.?.vhd.sha256, exported_disk.sha256);
    try t.expectEqual(state.package.?.vhd.size, exported_disk.size);
    var incorrect = manifest;
    incorrect.controller_revision = 3;
    try t.expectError(error.UnsupportedController, image.manifest.validate(alloc, try c.encode(alloc, incorrect), source, try c.sha(state.inputs.producer.sha256)));
    incorrect = manifest;
    incorrect.artifacts.vhd.size -= 512;
    try t.expectError(error.InvalidManifest, image.manifest.validate(alloc, try c.encode(alloc, incorrect), source, try c.sha(state.inputs.producer.sha256)));
    incorrect = manifest;
    incorrect.source.run_attempt += 1;
    try t.expectError(error.RecordMismatch, image.manifest.validate(alloc, try c.encode(alloc, incorrect), source, try c.sha(state.inputs.producer.sha256)));
    incorrect = manifest;
    incorrect.packaging.@"virtual-size" += 512;
    try t.expectError(error.RecordMismatch, image.manifest.validate(alloc, try c.encode(alloc, incorrect), source, try c.sha(state.inputs.producer.sha256)));
    var entries = exported.dir.iterate();
    var count: usize = 0;
    while (try entries.next(io)) |entry| {
        try t.expect(std.mem.eql(u8, entry.name, "unikraft.vhd") or std.mem.eql(u8, entry.name, image.manifest.name));
        count += 1;
    }
    try t.expectEqual(@as(usize, 2), count);
    try t.expect(image.manifest.publish(alloc, io, &lock, f.cli, target, source).sha256 == null);
    try t.expectError(error.PathAlreadyExists, f.prepare());
}
test "direct native package structurally validates synthetic PE raw and fixed VHD" {
    const f = try Fixture.init(0, false);
    defer f.deinit();
    const alloc = f.arena.allocator();
    const root = try image.files.create(io, f.input.state_dir);
    defer root.close(io);
    const input = try image.files.record(alloc, io, f.input.efi, c.max_efi, false);
    const report = try image.package.build(alloc, io, root, input);
    try t.expectEqual(@as(u64, c.vhd_bytes), report.vhd.size);
    try image.files.cleanupStage(io, root, "package-stage");
}
test "compute-only raw to native zstd QCOW2 to digest-bound fixed VHD" {
    const fixture = try Fixture.init(0, false);
    defer fixture.deinit();
    const alloc = fixture.arena.allocator();
    const root = try image.files.create(io, fixture.input.state_dir);
    defer root.close(io);
    const efi_input = try image.files.record(alloc, io, fixture.input.efi, c.max_efi, false);
    const packaged = try image.package.build(alloc, io, root, efi_input);
    try image.files.cleanupStage(io, root, "package-stage");
    const producer = try image.files.record(alloc, io, fixture.cli, c.max_tool, true);
    const limits: image.compute_artifacts.Limits = .{
        .max_input_bytes = c.raw_bytes,
        .max_output_bytes = c.vhd_bytes,
        .max_virtual_bytes = c.raw_bytes,
        .max_partition_array_bytes = 1024 * 1024,
        .max_metadata_bytes = 128 * 1024,
        .max_metadata_work = 8194,
        .max_work_bytes = 4 * c.raw_bytes,
        .max_memory_bytes = 512 * 1024 * 1024,
    };
    const raw_path = try image.files.path(alloc, fixture.input.state_dir, "unikraft.raw");
    const raw = try image.compute_artifacts.bindExpected(
        alloc,
        io,
        raw_path,
        packaged.raw.size,
        packaged.raw.sha256,
        limits.max_input_bytes,
    );
    const finalize_options: image.compute_artifacts.FinalizeOptions = .{
        .source = raw,
        .expected_virtual_bytes = packaged.raw.size,
        .expected_workload_sha256 = try c.sha(efi_input.sha256),
        .expected_workload_bytes = efi_input.size,
        .limits = limits,
        .producer = producer,
        .config_sha256 = c.hash("native compute finalization fixture"),
    };
    const refusal_path = try image.files.path(alloc, fixture.path, "worker-refusal");
    const refusal_state = try image.files.create(io, refusal_path);
    defer refusal_state.close(io);
    var refused_attempt = try image.compute_artifacts.reserveAttempt(io, refusal_state, .qcow2);
    defer refused_attempt.close(io);
    try refusal_state.dir.rename(
        image.compute_artifacts.qcow2_name,
        refusal_state.dir,
        "owned-output",
        io,
    );
    try refusal_state.dir.writeFile(io, .{
        .sub_path = image.compute_artifacts.qcow2_name,
        .data = "substituted reservation",
        .flags = .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        },
    });
    try t.expectError(
        error.AttemptOwnershipChanged,
        image.compute_artifacts.finalizeQcow2(
            alloc,
            io,
            refusal_state,
            refused_attempt.evidence,
            finalize_options,
        ),
    );
    const refusal_cleanup = refused_attempt.rollback(io, refusal_state);
    try t.expect(!refusal_cleanup.output_complete);
    try t.expectEqualStrings(
        "substituted reservation",
        try refusal_state.read(io, alloc, image.compute_artifacts.qcow2_name, 64, null),
    );

    const finalized = try finalizeDirect(alloc, root, finalize_options);
    try t.expectEqual(@as(u64, c.raw_bytes), finalized.output.virtual_bytes);
    try t.expect(finalized.output.file_bytes < finalized.output.virtual_bytes);
    try t.expectEqualStrings(packaged.raw.sha256, finalized.source_sha256);
    try t.expectEqualStrings(efi_input.sha256, finalized.identity.workload_sha256);
    const stored_finalization = try image.compute_artifacts.readFinalizationRecord(
        alloc,
        try root.read(io, alloc, image.compute_artifacts.qcow2_record_name, c.max_record, null),
    );
    try image.files.same(alloc, finalized, stored_finalization);

    const verification_path = try image.files.path(alloc, fixture.path, "parent-verification");
    const verification_state = try image.files.create(io, verification_path);
    defer verification_state.close(io);
    var verification_attempt = try image.compute_artifacts.reserveAttempt(io, verification_state, .qcow2);
    defer verification_attempt.close(io);
    _ = try image.compute_artifacts.finalizeQcow2(
        alloc,
        io,
        verification_state,
        verification_attempt.evidence,
        finalize_options,
    );
    const original_record = try verification_state.read(
        io,
        alloc,
        image.compute_artifacts.qcow2_record_name,
        c.max_record,
        null,
    );
    const canonical = try image.compute_artifacts.readFinalizationRecord(alloc, original_record);
    var mutations = [_]image.compute_artifacts.FinalizationRecord{
        canonical,
        canonical,
        canonical,
        canonical,
    };
    mutations[0].output.allocated = .{ .state = .unavailable, .bytes = null };
    mutations[1].identity.workload_sha256 = "0" ** 64;
    mutations[2].provenance.config_sha256 = "0" ** 64;
    mutations[3].output.sha256 = "0" ** 64;
    for (mutations) |mutation| {
        try rewritePrivateFile(
            verification_state,
            image.compute_artifacts.qcow2_record_name,
            try c.encode(alloc, mutation),
        );
        if (image.compute_artifacts.verifyFinalizedQcow2(
            alloc,
            io,
            verification_state,
            &verification_attempt,
            finalize_options,
        )) |_| return error.AcceptedTamperedFinalization else |_| {}
    }
    try rewritePrivateFile(
        verification_state,
        image.compute_artifacts.qcow2_record_name,
        original_record,
    );
    const verification_output = try verification_state.dir.openFile(
        io,
        image.compute_artifacts.qcow2_name,
        .{
            .mode = .read_write,
            .allow_directory = false,
            .follow_symlinks = false,
        },
    );
    var original_header_byte: [1]u8 = undefined;
    _ = try verification_output.readPositionalAll(io, &original_header_byte, 105);
    try verification_output.writePositionalAll(io, &.{original_header_byte[0] ^ 1}, 105);
    try verification_output.sync(io);
    const changed_snapshot = try image.boot.files.snapshot(verification_output);
    var coherently_rehashed = canonical;
    coherently_rehashed.output.sha256 = try c.hex(
        alloc,
        try image.boot.files.digest(io, verification_output, changed_snapshot),
    );
    verification_output.close(io);
    try rewritePrivateFile(
        verification_state,
        image.compute_artifacts.qcow2_record_name,
        try c.encode(alloc, coherently_rehashed),
    );
    if (image.compute_artifacts.verifyFinalizedQcow2(
        alloc,
        io,
        verification_state,
        &verification_attempt,
        finalize_options,
    )) |_| return error.AcceptedRehashedQcow2Tamper else |_| {}
    try rewritePrivateFile(
        verification_state,
        image.compute_artifacts.qcow2_record_name,
        original_record,
    );
    const restore_output = try verification_state.dir.openFile(
        io,
        image.compute_artifacts.qcow2_name,
        .{
            .mode = .read_write,
            .allow_directory = false,
            .follow_symlinks = false,
        },
    );
    try restore_output.writePositionalAll(io, &original_header_byte, 105);
    try restore_output.sync(io);
    restore_output.close(io);
    try verification_state.dir.rename(
        image.compute_artifacts.qcow2_name,
        verification_state.dir,
        "retained-qcow2",
        io,
    );
    const retained_qcow2_path = try image.files.path(
        alloc,
        verification_path,
        "retained-qcow2",
    );
    const retained_qcow2 = try image.files.record(
        alloc,
        io,
        retained_qcow2_path,
        limits.max_output_bytes,
        false,
    );
    try image.files.copy(
        io,
        retained_qcow2,
        verification_state,
        image.compute_artifacts.qcow2_name,
    );
    try t.expectError(
        error.AttemptOwnershipChanged,
        image.compute_artifacts.verifyFinalizedQcow2(
            alloc,
            io,
            verification_state,
            &verification_attempt,
            finalize_options,
        ),
    );

    const qcow2_path = try image.files.path(alloc, fixture.input.state_dir, image.compute_artifacts.qcow2_name);
    const qcow2 = try image.compute_artifacts.bindExpected(
        alloc,
        io,
        qcow2_path,
        finalized.output.file_bytes,
        finalized.output.sha256,
        limits.max_input_bytes,
    );
    const derive_options: image.compute_artifacts.DeriveOptions = .{
        .source = qcow2,
        .expected_capacity_bytes = finalized.output.virtual_bytes,
        .limits = limits,
        .producer = producer,
        .config_sha256 = c.hash("native compute fixed vhd fixture"),
    };
    const vhd_refusal_path = try image.files.path(alloc, fixture.path, "vhd-worker-refusal");
    const vhd_refusal_state = try image.files.create(io, vhd_refusal_path);
    defer vhd_refusal_state.close(io);
    var vhd_refused_attempt = try image.compute_artifacts.reserveAttempt(
        io,
        vhd_refusal_state,
        .vhd,
    );
    defer vhd_refused_attempt.close(io);
    try vhd_refusal_state.dir.rename(
        image.compute_artifacts.vhd_name,
        vhd_refusal_state.dir,
        "owned-output",
        io,
    );
    try vhd_refusal_state.dir.writeFile(io, .{
        .sub_path = image.compute_artifacts.vhd_name,
        .data = "substituted reservation",
        .flags = .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        },
    });
    try t.expectError(
        error.AttemptOwnershipChanged,
        image.compute_artifacts.deriveFixedVhd(
            alloc,
            io,
            vhd_refusal_state,
            vhd_refused_attempt.evidence,
            derive_options,
        ),
    );
    const vhd_refusal_cleanup = vhd_refused_attempt.rollback(io, vhd_refusal_state);
    try t.expect(!vhd_refusal_cleanup.output_complete);
    try t.expectEqualStrings(
        "substituted reservation",
        try vhd_refusal_state.read(
            io,
            alloc,
            image.compute_artifacts.vhd_name,
            64,
            null,
        ),
    );

    const derived = try deriveDirect(alloc, root, derive_options);
    try t.expectEqualStrings(finalized.output.sha256, derived.accepted_qcow2.sha256);
    try t.expectEqualStrings(finalized.source_sha256, derived.accepted_qcow2_decoded_sha256);
    try t.expectEqual(@as(u64, c.vhd_bytes), derived.output.file_bytes);
    try t.expect(!derived.relocation.was_relocated);
    try image.files.same(alloc, finalized.identity, derived.output_identity);
    const stored_derivation = try image.compute_artifacts.readDerivationRecord(
        alloc,
        try root.read(io, alloc, image.compute_artifacts.vhd_record_name, c.max_record, null),
    );
    try image.files.same(alloc, derived, stored_derivation);
    var bad_derivation = derived;
    bad_derivation.footer.checksum +%= 1;
    try t.expectError(
        error.InvalidFooter,
        image.compute_artifacts.readDerivationRecord(
            alloc,
            try c.encode(alloc, bad_derivation),
        ),
    );
    bad_derivation = derived;
    bad_derivation.output_identity.workload_sha256 = "0" ** 64;
    try t.expectError(
        error.InvalidRecord,
        image.compute_artifacts.readDerivationRecord(
            alloc,
            try c.encode(alloc, bad_derivation),
        ),
    );

    var wrong: [64]u8 = undefined;
    @memcpy(&wrong, finalized.output.sha256);
    wrong[0] = if (wrong[0] == '0') '1' else '0';
    try t.expectError(
        error.ArtifactChanged,
        image.compute_artifacts.bindExpected(
            alloc,
            io,
            qcow2_path,
            finalized.output.file_bytes,
            &wrong,
            limits.max_input_bytes,
        ),
    );
    try t.expectError(
        error.PathAlreadyExists,
        finalizeDirect(alloc, root, .{
            .source = raw,
            .expected_virtual_bytes = packaged.raw.size,
            .expected_workload_sha256 = try c.sha(efi_input.sha256),
            .expected_workload_bytes = efi_input.size,
            .limits = limits,
            .producer = producer,
            .config_sha256 = c.hash("collision"),
        }),
    );
    const tampered = try std.mem.replaceOwned(
        u8,
        alloc,
        try root.read(io, alloc, image.compute_artifacts.qcow2_record_name, c.max_record, null),
        "\"status\":\"succeeded\"",
        "\"status\":\"refused\"",
    );
    try t.expectError(
        error.InvalidRecord,
        image.compute_artifacts.readFinalizationRecord(alloc, tampered),
    );
}
test "fixed VHD derivation permits only documented GPT relocation deltas" {
    const fixture = try Fixture.init(0, false);
    defer fixture.deinit();
    const alloc = fixture.arena.allocator();
    const root = try image.files.create(io, fixture.input.state_dir);
    defer root.close(io);
    const efi_input = try image.files.record(alloc, io, fixture.input.efi, c.max_efi, false);
    _ = try image.package.build(alloc, io, root, efi_input);
    try image.files.cleanupStage(io, root, "package-stage");
    const raw_path = try image.files.path(alloc, fixture.input.state_dir, "unikraft.raw");
    var raw_image = try image.boot.miz.Image.openPathReadOnly(io, raw_path);
    defer raw_image.close(io);
    var raw_gpt = try image.boot.miz.gpt.readVerifiedGpt(
        raw_image,
        io,
        alloc,
        1024 * 1024,
    );
    defer raw_gpt.deinit(alloc);

    const source_capacity = c.raw_bytes + 512;
    const expanded_path = try image.files.path(alloc, fixture.input.state_dir, "expanded.qcow2");
    var expanded = try image.boot.miz.Image.create(
        io,
        expanded_path,
        .qcow2,
        source_capacity,
        .{},
    );
    _ = try image.boot.miz.copyAll(io, raw_image, &expanded, alloc);
    const source_relocation = try image.boot.miz.gpt.relocateBackup(
        &expanded,
        io,
        alloc,
        raw_gpt,
    );
    try t.expect(source_relocation.was_relocated);
    expanded.close(io);

    const expanded_file = try image.files.record(
        alloc,
        io,
        expanded_path,
        68 * c.mib,
        false,
    );
    const accepted_path = try image.files.path(alloc, fixture.input.state_dir, "accepted-relocated.qcow2");
    const accepted = try image.boot.miz.artifact_pipeline.finalizeQcow2(alloc, io, .{
        .input_path = expanded_path,
        .expected_input_sha256 = try c.sha(expanded_file.sha256),
        .max_input_size = 68 * c.mib,
        .source_format = .qcow2,
        .expected_virtual_size = source_capacity,
        .max_virtual_size = 68 * c.mib,
        .output_path = accepted_path,
        .max_output_size = 68 * c.mib,
        .compression = .zstd,
        .cluster_size = 64 * 1024,
    });
    const producer = try image.files.record(alloc, io, fixture.cli, c.max_tool, true);
    const limits: image.compute_artifacts.Limits = .{
        .max_input_bytes = 68 * c.mib,
        .max_output_bytes = 68 * c.mib,
        .max_virtual_bytes = 68 * c.mib,
        .max_partition_array_bytes = 1024 * 1024,
        .max_metadata_bytes = 128 * 1024,
        .max_metadata_work = 8194,
        .max_work_bytes = 4 * source_capacity,
        .max_memory_bytes = 512 * 1024 * 1024,
    };
    const pinned = try image.compute_artifacts.bindExpected(
        alloc,
        io,
        accepted_path,
        accepted.artifact.size,
        try c.hex(alloc, accepted.artifact.sha256),
        limits.max_input_bytes,
    );
    const derive_options: image.compute_artifacts.DeriveOptions = .{
        .source = pinned,
        .expected_capacity_bytes = source_capacity,
        .limits = limits,
        .producer = producer,
        .config_sha256 = c.hash("relocation fixture"),
    };
    var attempt = try image.compute_artifacts.reserveAttempt(io, root, .vhd);
    defer attempt.close(io);
    const derived = try image.compute_artifacts.deriveFixedVhd(
        alloc,
        io,
        root,
        attempt.evidence,
        derive_options,
    );
    _ = try image.compute_artifacts.verifyDerivedFixedVhd(
        alloc,
        io,
        root,
        &attempt,
        derive_options,
    );
    try t.expect(attempt.cleanupStage(io, root));
    try t.expect(derived.relocation.was_relocated);
    try t.expectEqual(@as(u64, 67 * c.mib), derived.output.virtual_bytes);
    try t.expectEqualStrings(
        derived.source_identity.partition_contents_sha256,
        derived.output_identity.partition_contents_sha256,
    );
    try t.expectEqualStrings(
        "protective-mbr,primary-gpt,relocated-backup-gpt,zero-padding",
        derived.relocation.allowed_differences,
    );
    const original_record = try root.read(
        io,
        alloc,
        image.compute_artifacts.vhd_record_name,
        c.max_record,
        null,
    );
    const canonical = try image.compute_artifacts.readDerivationRecord(alloc, original_record);
    var record_mutations = [_]image.compute_artifacts.DerivationRecord{
        canonical,
        canonical,
        canonical,
        canonical,
        canonical,
    };
    record_mutations[0].accepted_qcow2_decoded_sha256 = "0" ** 64;
    record_mutations[1].accepted_qcow2.allocated = .{ .state = .unavailable, .bytes = null };
    record_mutations[2].source_identity.workload_sha256 = "0" ** 64;
    record_mutations[2].output_identity.workload_sha256 = "0" ** 64;
    record_mutations[3].output.allocated = .{ .state = .unavailable, .bytes = null };
    record_mutations[4].provenance.config_sha256 = "0" ** 64;
    for (record_mutations) |mutation| {
        try rewritePrivateFile(
            root,
            image.compute_artifacts.vhd_record_name,
            try c.encode(alloc, mutation),
        );
        if (image.compute_artifacts.verifyDerivedFixedVhd(
            alloc,
            io,
            root,
            &attempt,
            derive_options,
        )) |_| return error.AcceptedTamperedDerivation else |_| {}
    }
    try rewritePrivateFile(root, image.compute_artifacts.vhd_record_name, original_record);

    const old_backup_offset = derived.relocation.old_backup_lba * 512;
    const mutation_offsets = [_]u64{
        0,
        0x1b8,
        0x1bc,
        2 * 512 + 48,
        512 + image.boot.miz.gpt.header_size,
        old_backup_offset + 100,
        derived.output.virtual_bytes + 85,
    };
    {
        const output = try root.dir.openFile(io, image.compute_artifacts.vhd_name, .{
            .mode = .read_write,
            .allow_directory = false,
            .follow_symlinks = false,
        });
        defer output.close(io);
        for (mutation_offsets) |mutation_offset| {
            var original: [1]u8 = undefined;
            if (try output.readPositionalAll(io, &original, mutation_offset) != 1)
                return error.InvalidFixture;
            try output.writePositionalAll(io, &.{original[0] ^ 1}, mutation_offset);
            try output.sync(io);
            const changed_snapshot = try image.boot.files.snapshot(output);
            var rehashed = canonical;
            rehashed.output.sha256 = try c.hex(
                alloc,
                try image.boot.files.digest(io, output, changed_snapshot),
            );
            try rewritePrivateFile(
                root,
                image.compute_artifacts.vhd_record_name,
                try c.encode(alloc, rehashed),
            );
            if (image.compute_artifacts.verifyDerivedFixedVhd(
                alloc,
                io,
                root,
                &attempt,
                derive_options,
            )) |_| return error.AcceptedRehashedVhdTamper else |_| {}
            try output.writePositionalAll(io, &original, mutation_offset);
            try output.sync(io);
            try rewritePrivateFile(root, image.compute_artifacts.vhd_record_name, original_record);
        }
    }
    try root.dir.rename(
        image.compute_artifacts.vhd_name,
        root.dir,
        "retained-vhd",
        io,
    );
    const retained_vhd_path = try image.files.path(
        alloc,
        fixture.input.state_dir,
        "retained-vhd",
    );
    const retained_vhd = try image.files.record(
        alloc,
        io,
        retained_vhd_path,
        limits.max_output_bytes,
        false,
    );
    try image.files.copy(io, retained_vhd, root, image.compute_artifacts.vhd_name);
    try t.expectError(
        error.AttemptOwnershipChanged,
        image.compute_artifacts.verifyDerivedFixedVhd(
            alloc,
            io,
            root,
            &attempt,
            derive_options,
        ),
    );
}
test "compute primitives refuse changed custody malformed identity and unsupported QCOW2" {
    const fixture = try Fixture.init(0, false);
    defer fixture.deinit();
    const alloc = fixture.arena.allocator();
    const package_root = try image.files.create(io, fixture.input.state_dir);
    defer package_root.close(io);
    const efi_input = try image.files.record(alloc, io, fixture.input.efi, c.max_efi, false);
    const packaged = try image.package.build(alloc, io, package_root, efi_input);
    try image.files.cleanupStage(io, package_root, "package-stage");
    const producer = try image.files.record(alloc, io, fixture.cli, c.max_tool, true);
    const limits: image.compute_artifacts.Limits = .{
        .max_input_bytes = c.raw_bytes,
        .max_output_bytes = c.vhd_bytes,
        .max_virtual_bytes = c.raw_bytes,
        .max_partition_array_bytes = 1024 * 1024,
        .max_metadata_bytes = 128 * 1024,
        .max_metadata_work = 8194,
        .max_work_bytes = 4 * c.raw_bytes,
        .max_memory_bytes = 512 * 1024 * 1024,
    };
    const raw_path = try image.files.path(alloc, fixture.input.state_dir, "unikraft.raw");
    try t.expectError(
        error.ArtifactChanged,
        image.compute_artifacts.bindExpected(
            alloc,
            io,
            raw_path,
            packaged.raw.size - 512,
            packaged.raw.sha256,
            limits.max_input_bytes,
        ),
    );

    try image.files.copy(io, packaged.raw, fixture.dir, "substituted.raw");
    const substituted_path = try image.files.path(alloc, fixture.path, "substituted.raw");
    const substituted = try image.compute_artifacts.bindExpected(
        alloc,
        io,
        substituted_path,
        packaged.raw.size,
        packaged.raw.sha256,
        limits.max_input_bytes,
    );
    try fixture.dir.dir.rename("substituted.raw", fixture.dir.dir, "substituted.old", io);
    const old_path = try image.files.path(alloc, fixture.path, "substituted.old");
    const old_record = try image.files.record(alloc, io, old_path, c.raw_bytes, false);
    try image.files.copy(io, old_record, fixture.dir, "substituted.raw");
    try t.expectError(
        error.ArtifactChanged,
        image.compute_artifacts.verifyPinned(io, substituted, limits.max_input_bytes),
    );

    try image.files.copy(io, packaged.raw, fixture.dir, "malformed.raw");
    const malformed_file = try fixture.dir.dir.openFile(io, "malformed.raw", .{ .mode = .read_write });
    try malformed_file.writePositionalAll(io, "NOT GPT!", 512);
    malformed_file.close(io);
    const malformed_path = try image.files.path(alloc, fixture.path, "malformed.raw");
    const malformed_record = try image.files.record(alloc, io, malformed_path, c.raw_bytes, false);
    const malformed = try image.compute_artifacts.bindExpected(
        alloc,
        io,
        malformed_path,
        malformed_record.size,
        malformed_record.sha256,
        limits.max_input_bytes,
    );
    const malformed_state_path = try image.files.path(alloc, fixture.path, "malformed-state");
    const malformed_state = try image.files.create(io, malformed_state_path);
    defer malformed_state.close(io);
    if (finalizeDirect(alloc, malformed_state, .{
        .source = malformed,
        .expected_virtual_bytes = malformed_record.size,
        .expected_workload_sha256 = try c.sha(efi_input.sha256),
        .expected_workload_bytes = efi_input.size,
        .limits = limits,
        .producer = producer,
        .config_sha256 = c.hash("malformed"),
    })) |_| return error.AcceptedMalformedDisk else |_| {}
    const symlink_state_path = try image.files.path(alloc, fixture.path, "symlink-state");
    const symlink_state = try image.files.create(io, symlink_state_path);
    defer symlink_state.close(io);
    try symlink_state.dir.symLink(io, "/does/not/exist", image.compute_artifacts.qcow2_name, .{});
    const raw = try image.compute_artifacts.bindExpected(
        alloc,
        io,
        raw_path,
        packaged.raw.size,
        packaged.raw.sha256,
        limits.max_input_bytes,
    );
    if (finalizeDirect(alloc, symlink_state, .{
        .source = raw,
        .expected_virtual_bytes = packaged.raw.size,
        .expected_workload_sha256 = try c.sha(efi_input.sha256),
        .expected_workload_bytes = efi_input.size,
        .limits = limits,
        .producer = producer,
        .config_sha256 = c.hash("symlink"),
    })) |_| return error.AcceptedOutputSymlink else |_| {}

    const good_state_path = try image.files.path(alloc, fixture.path, "good-state");
    const good_state = try image.files.create(io, good_state_path);
    defer good_state.close(io);
    const finalized = try finalizeDirect(alloc, good_state, .{
        .source = raw,
        .expected_virtual_bytes = packaged.raw.size,
        .expected_workload_sha256 = try c.sha(efi_input.sha256),
        .expected_workload_bytes = efi_input.size,
        .limits = limits,
        .producer = producer,
        .config_sha256 = c.hash("good"),
    });
    const good_qcow_path = try image.files.path(alloc, good_state_path, image.compute_artifacts.qcow2_name);
    const good_qcow = try image.files.record(
        alloc,
        io,
        good_qcow_path,
        limits.max_input_bytes,
        false,
    );
    try image.files.copy(io, good_qcow, fixture.dir, "unsupported.qcow2");
    const unsupported_file = try fixture.dir.dir.openFile(io, "unsupported.qcow2", .{ .mode = .read_write });
    try unsupported_file.writePositionalAll(io, &[_]u8{0}, 104);
    unsupported_file.close(io);
    const unsupported_path = try image.files.path(alloc, fixture.path, "unsupported.qcow2");
    const unsupported_record = try image.files.record(
        alloc,
        io,
        unsupported_path,
        limits.max_input_bytes,
        false,
    );
    const unsupported = try image.compute_artifacts.bindExpected(
        alloc,
        io,
        unsupported_path,
        unsupported_record.size,
        unsupported_record.sha256,
        limits.max_input_bytes,
    );
    const derive_state_path = try image.files.path(alloc, fixture.path, "unsupported-state");
    const derive_state = try image.files.create(io, derive_state_path);
    defer derive_state.close(io);
    if (deriveDirect(alloc, derive_state, .{
        .source = unsupported,
        .expected_capacity_bytes = finalized.output.virtual_bytes,
        .limits = limits,
        .producer = producer,
        .config_sha256 = c.hash("unsupported"),
    })) |_| return error.AcceptedUnsupportedQcow2 else |_| {}
}
test "native input and private evidence permissions and malformed PE refuse" {
    const f = try Fixture.init(0, false);
    defer f.deinit();
    const file = try f.dir.dir.openFile(io, "public,image.efi", .{ .mode = .read_write });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o666));
    if (f.prepare()) |_| return error.AcceptedWritableImage else |_| {}
    try file.setPermissions(io, .fromMode(0o644));
    try file.writePositionalAll(io, "BAD", 0);
    const state = try f.prepare();
    try t.expectEqual(c.Phase.failed, state.phase);
    try t.expect(state.package == null);
    const root = try f.stateDir();
    defer root.close(io);
    const state_file = try root.openFile(io, "state.json");
    defer state_file.close(io);
    try state_file.setPermissions(io, .fromMode(0o644));
    if (root.read(io, f.arena.allocator(), "state.json", c.max_record, null)) |_| return error.AcceptedPublicState else |_| {}
}
test "native solved-config transcript and all four public network configuration-only boots" {
    const f = try Fixture.init(16, true);
    defer f.deinit();
    const state = try f.prepare();
    try t.expectEqual(c.Phase.prepared, state.phase);
    const config = (try image.network.parse(state.acceptance)).?;
    try t.expectEqual(@as(u32, 1760), config.transcript.tcp_bytes);
    try t.expectEqual(@as(u32, 3408), config.transcript.udp_bytes);
    const root = try f.stateDir();
    defer root.close(io);
    var lock = try root.lock(io);
    defer lock.close(io);
    _ = try image.engine.load(f.arena.allocator(), io, &lock, f.cli);
}
test "public serial rejects colliding return APIC mismatch live IO and duplicate network config" {
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const raw = try image.network.raw(alloc);
    const config: image.boot.config.Config = .{ .source = .{ .kind = .raw_disk, .path = "/public/raw" }, .qemu = "/public/qemu", .ovmf_code = "/public/code", .ovmf_vars = "/public/vars", .work_dir = "/public/work", .expect = c.platform_marker, .expect_main_return = 2 };
    const good = serial_fixture.prefix ++ serial_fixture.application ++ serial_fixture.terminal;
    try image.network.serial(alloc, good, config, raw);
    for ([_][]const u8{ "main returned 20", "main returned 0", "main returned 2 trailing", "spoof main returned 2" }) |replacement| {
        const bad = try std.mem.replaceOwned(u8, alloc, good, serial_fixture.terminal, replacement);
        if (image.network.serial(alloc, bad, config, raw)) |_| return error.AcceptedBadSerial else |_| {}
    }
    for ([_][]const u8{ "UK_HYPERV_IO_READY", "UK_HYPERV_NETWORK_APP_READY", c.legacy_marker, "HYPERV_ACCEPTANCE NETWORK_APP_FINAL PASS" }) |extra| {
        const bad = try std.fmt.allocPrint(alloc, "{s}{s}\n", .{ good, extra });
        if (image.network.serial(alloc, bad, config, raw)) |_| return error.AcceptedBadSerial else |_| {}
    }
    const net = try image.network.fromConfig(alloc, config_text);
    const marker = try image.network.marker(alloc, (try image.network.parse(net)).?);
    const network_good = try std.fmt.allocPrint(alloc, "{s}{s}{s}\n{s}", .{ serial_fixture.prefix, serial_fixture.application, marker, serial_fixture.terminal });
    try image.network.serial(alloc, network_good, config, net);
    for ([_][]const u8{
        try std.fmt.allocPrint(alloc, "{s}{s}\n", .{ good, marker }),
        try std.fmt.allocPrint(alloc, "{s}{s}{s}\n{s}\n{s}", .{ serial_fixture.prefix, serial_fixture.application, marker, marker, serial_fixture.terminal }),
        try std.mem.replaceOwned(u8, alloc, network_good, "nonce=0123456789abcdef", "nonce=1123456789abcdef"),
        good,
    }) |bad| if (image.network.serial(alloc, bad, config, net)) |_| return error.AcceptedBadNetwork else |_| {};
}

test "pinned QAPI vpc opening accepts generic format and rejects creation size controls" {
    const opening =
        \\{"driver":"vpc","node-name":"fixture-disk","read-only":true,"file":{"driver":"file","filename":"/proc/self/fd/64","read-only":true}}
    ;
    try serial_fixture.checkVpcOpening(a, opening);
    for ([_][]const u8{
        "\"force-size\":true",
        "\"force_size_calc\":\"current_size\"",
        "\"force-size-calc\":\"current_size\"",
        "\"size\":69206016",
        "\"offset\":0",
        "\"subformat\":\"fixed\"",
    }) |creation_field| {
        const invalid = try std.fmt.allocPrint(a, "{{{s},{s}", .{ creation_field, opening[1..] });
        defer a.free(invalid);
        try t.expectError(error.UnknownField, serial_fixture.checkVpcOpening(a, invalid));
    }
}

const late_platform = serial_fixture.prefix ++ serial_fixture.prefixed_application ++ serial_fixture.terminal ++ c.platform_marker ++ "\n";
const early_platform = serial_fixture.prefix ++ c.platform_marker ++ "\n" ++ serial_fixture.prefixed_application ++ serial_fixture.terminal;
const duplicate_platform = serial_fixture.prefix ++ serial_fixture.application ++ c.platform_marker ++ "\n" ++ serial_fixture.terminal;

test "exact platform marker is unique between application start and anchored return" {
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const config: image.boot.config.Config = .{
        .source = .{ .kind = .raw_disk, .path = "/public/raw" },
        .qemu = "/public/qemu",
        .ovmf_code = "/public/code",
        .ovmf_vars = "/public/vars",
        .work_dir = "/public/work",
        .expect = c.platform_marker,
        .expect_main_return = 2,
    };
    const raw = try image.network.raw(alloc);
    // The shared substring policy alone admits the late exact line.
    try image.boot.serial.validate(alloc, late_platform, config);
    try t.expectError(error.InvalidPublicSerial, image.network.serial(alloc, late_platform, config, raw));
    try t.expectError(error.ReorderedMilestone, image.network.serial(alloc, early_platform, config, raw));
    try t.expectError(error.InvalidPublicSerial, image.network.serial(alloc, duplicate_platform, config, raw));
    try t.expectError(error.InvalidPublicSerial, image.network.serial(alloc, serial_fixture.prefix ++ serial_fixture.prefixed_application ++ serial_fixture.terminal, config, raw));
    const good = serial_fixture.prefix ++ serial_fixture.prefixed_application ++ c.platform_marker ++ "\n" ++ serial_fixture.terminal;
    try image.network.serial(alloc, good, config, raw);
    const decorated = try std.mem.replaceOwned(u8, alloc, good, "\n" ++ c.platform_marker ++ "\n", "\n\x1b[32m" ++ c.platform_marker ++ "\x1b[0m\x00\r\n");
    try image.network.serial(alloc, decorated, config, raw);
    const network = try image.network.fromConfig(alloc, config_text);
    const marker = try image.network.marker(alloc, (try image.network.parse(network)).?);
    const configured = try std.fmt.allocPrint(alloc, "{s}{s}\n{s}", .{ good[0 .. good.len - serial_fixture.terminal.len], marker, serial_fixture.terminal });
    try image.network.serial(alloc, configured, config, network);
    const late_with_config = try std.fmt.allocPrint(alloc, "{s}{s}{s}\n{s}{s}\n", .{ serial_fixture.prefix, serial_fixture.prefixed_application, marker, serial_fixture.terminal, c.platform_marker });
    try t.expectError(error.InvalidPublicSerial, image.network.serial(alloc, late_with_config, config, network));
}

test "source provenance exact canonical integers repository workflow revision job and hashes" {
    try source.validate();
    for ([_][]const u8{
        "",                                                                 "other/repo/.github/workflows/a.yaml@refs/heads/main",
        "cataggar/unikraft/.github/workflows/.yaml@refs/heads/main",        "cataggar/unikraft/.github/workflows/a.yaml@main",
        "cataggar/unikraft/.github/workflows/a.yaml@refs/heads/../main",    "cataggar/unikraft/.github/workflows/a.yaml@refs/",
        "cataggar/unikraft/.github/workflows/a.yaml@refs/heads/main@extra",
    }) |workflow| {
        var bad = source;
        bad.workflow_ref = workflow;
        try t.expectError(error.InvalidSource, bad.validate());
    }
    for ([_][]const u8{ "", "x/y/z", "https://example.test/repo", "x/\nrepo" }) |repository| {
        var bad = source;
        bad.repository = repository;
        try t.expectError(error.InvalidSource, bad.validate());
    }
    var bad = source;
    bad.job = "other-job";
    try t.expectError(error.InvalidSource, bad.validate());
    bad = source;
    bad.run_attempt = 0;
    try t.expectError(error.InvalidSource, bad.validate());
    bad = source;
    bad.head_sha = "A" ** 40;
    try t.expectError(error.InvalidSource, bad.validate());
}
test "solved config missing duplicate typed noncanonical network settings refuse" {
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    for ([_][]const u8{
        "",                                                                                 config_text ++ "CONFIG_APPHYPERVACCEPTANCE_PEER_TCP_PORT=42001\n",
        try std.mem.replaceOwned(u8, alloc, config_text, "10.77.0.20", "8.8.8.8"),          try std.mem.replaceOwned(u8, alloc, config_text, "10.77.0.20", "010.77.0.20"),
        try std.mem.replaceOwned(u8, alloc, config_text, "=42001", "=42002"),               try std.mem.replaceOwned(u8, alloc, config_text, "=42001", "=\"42001\""),
        try std.mem.replaceOwned(u8, alloc, config_text, "=42001", "=0"),                   try std.mem.replaceOwned(u8, alloc, config_text, "=42001", "=65536"),
        try std.mem.replaceOwned(u8, alloc, config_text, "APPLICATION=y", "APPLICATION=n"), try std.mem.replaceOwned(u8, alloc, config_text, "0123456789abcdef", "short"),
    }) |bad| if (image.network.fromConfig(alloc, bad)) |_| return error.AcceptedBadConfig else |_| {};
    const with_other = config_text ++ "CONFIG_UNRELATED_INTEGER=12345\nCONFIG_UNRELATED_HEX=deadbeef\n";
    const accepted = try image.network.fromConfig(alloc, with_other);
    try t.expectEqualStrings(try c.hex(alloc, c.hash(with_other)), (try image.network.parse(accepted)).?.solved_config_sha256);
    const upper = try std.mem.replaceOwned(u8, alloc, config_text, "abcdef", "ABCDEF");
    try t.expectEqualStrings("0123456789abcdef", (try image.network.parse(try image.network.fromConfig(alloc, upper))).?.nonce);
}
test "native partial matrix nonzero bad markers input mutation and independent failure evidence" {
    for ([_]u8{ 1, 2, 3, 6, 7, 9, 10, 11, 12, 13, 14, 15 }) |mode| {
        const f = try Fixture.init(mode, mode == 12);
        defer f.deinit();
        const state = try f.prepare();
        try t.expectEqual(c.Phase.failed, state.phase);
        try t.expect(!image.engine.clean(state.failures));
        if (mode == 6) {
            try t.expect(state.failures.cleanup != null);
            try t.expect(state.failures.primary == null);
        }
        if (mode == 7) try t.expect(state.failures.recording != null);
        if (mode == 9) try t.expectEqual(image.core.diagnostics.Category.integrity, state.failures.primary.?.category);
        if (mode == 1) {
            try t.expect(state.boots[0] != null and state.boots[1] != null and state.boots[2] == null and state.boots[3] == null);
        } else try t.expect(state.boots[0] == null);
        const root = try f.stateDir();
        defer root.close(io);
        var lock = try root.lock(io);
        defer lock.close(io);
        try t.expectError(error.NotPrepared, image.engine.load(f.arena.allocator(), io, &lock, f.cli));
        const log = try root.read(io, f.arena.allocator(), "local-raw-x2apic-serial.log", image.boot.config.max_serial, null);
        try t.expect(log.len > 0 and std.mem.indexOf(u8, log, "synthetic stderr retained") != null);
        try t.expectError(error.PathAlreadyExists, f.prepare());
    }
}
test "native hard deadline output limit cancellation and descendant group cleanup" {
    for ([_]u8{ 4, 5, 8 }) |mode| {
        var f = try Fixture.init(mode, false);
        defer f.deinit();
        f.input.timeout_ms = 3000;
        const state = try f.prepare();
        if (mode == 8) {
            try t.expectEqual(c.Phase.prepared, state.phase);
            for (0..4) |index| {
                const work = try image.core.private_files.Directory.open(io, (try image.engine.bootConfig(f.arena.allocator(), state, index)).work_dir);
                defer work.close(io);
                const pid_text = try work.read(io, f.arena.allocator(), "descendant.pid", 16, null);
                const pid = try std.fmt.parseInt(u32, pid_text, 10);
                try t.expectEqual(std.os.linux.E.SRCH, std.os.linux.errno(std.os.linux.syscall2(.kill, pid, 0)));
            }
        } else {
            try t.expectEqual(c.Phase.failed, state.phase);
            if (mode == 4) try t.expectEqual(image.core.diagnostics.Category.timeout, state.failures.primary.?.category);
            const root = try f.stateDir();
            defer root.close(io);
            const bytes = try root.read(io, f.arena.allocator(), "local-raw-x2apic-serial.log", image.boot.config.max_serial, null);
            try t.expect(bytes.len > 0 and bytes.len <= image.boot.config.max_serial);
            if (mode == 5) {
                const work = try image.core.private_files.Directory.open(io, (try image.engine.bootConfig(f.arena.allocator(), state, 0)).work_dir);
                defer work.close(io);
                const report = try image.boot.runner.Report.decode(f.arena.allocator(), try work.read(io, f.arena.allocator(), "report.json", c.max_record, null));
                try t.expect(report.serial_limit_reached and report.serial_bytes == image.boot.config.max_serial);
            }
        }
    }
    const f = try Fixture.init(0, false);
    defer f.deinit();
    var cancel = std.atomic.Value(bool).init(true);
    const cancelled = try image.engine.prepare(f.arena.allocator(), io, f.input, .{ .self_executable = f.cli, .cancel = &cancel });
    try t.expectEqual(c.Phase.failed, cancelled.phase);
    try t.expectEqual(image.core.diagnostics.Category.cancelled, cancelled.failures.primary.?.category);
    try t.expect(cancelled.package == null);
}
test "physical loader rejects incomplete tampered matrix requests logs packages and source bytes" {
    const f = try Fixture.init(0, false);
    defer f.deinit();
    const alloc = f.arena.allocator();
    const state = try f.prepare();
    try t.expectEqual(c.Phase.prepared, state.phase);
    const root = try f.stateDir();
    defer root.close(io);
    var lock = try root.lock(io);
    defer lock.close(io);
    var changed = state;
    changed.phase = .preparing;
    try image.files.durable(try lock.commit(io, "state.json", try c.encode(alloc, changed)));
    try t.expectError(error.NotPrepared, image.engine.load(alloc, io, &lock, f.cli));
    changed = state;
    changed.boots[3] = null;
    try image.files.durable(try lock.commit(io, "state.json", try c.encode(alloc, changed)));
    try t.expectError(error.IncompleteMatrix, image.engine.load(alloc, io, &lock, f.cli));
    try image.files.durable(try lock.commit(io, "state.json", try c.encode(alloc, state)));
    for ([_][]const u8{ "BOOTX64.EFI", "unikraft.raw", "unikraft.vhd" }) |name| {
        const file = try root.openFile(io, name);
        defer file.close(io);
        try file.setPermissions(io, .fromMode(0o644));
        if (image.engine.load(alloc, io, &lock, f.cli)) |_| return error.AcceptedPublicPreparedFile else |_| {}
        try file.setPermissions(io, .fromMode(0o600));
    }
    for ([_][]const u8{ "prepare.json", "packaging.json", "package-report.json", "local-raw-x2apic-serial.log", "BOOTX64.EFI", "unikraft.raw", "unikraft.vhd" }) |name| {
        const file = try root.dir.openFile(io, name, .{ .mode = .read_write });
        defer file.close(io);
        const pos: u64 = if (std.mem.eql(u8, name, "unikraft.vhd")) c.vhd_bytes - 1 else 0;
        var original: [1]u8 = undefined;
        _ = try file.readPositionalAll(io, &original, pos);
        try file.writePositionalAll(io, &.{original[0] ^ 1}, pos);
        if (image.engine.load(alloc, io, &lock, f.cli)) |_| return error.AcceptedTamperedEvidence else |_| {}
        try file.writePositionalAll(io, &original, pos);
    }
    const work = try image.core.private_files.Directory.open(io, (try image.engine.bootConfig(alloc, state, 2)).work_dir);
    defer work.close(io);
    for ([_][]const u8{ "request.json", "report.json", image.boot.config.log_name }) |name| {
        const file = try work.dir.openFile(io, name, .{ .mode = .read_write });
        defer file.close(io);
        var byte: [1]u8 = undefined;
        _ = try file.readPositionalAll(io, &byte, 0);
        try file.writePositionalAll(io, &.{byte[0] ^ 1}, 0);
        if (image.engine.load(alloc, io, &lock, f.cli)) |_| return error.AcceptedTamperedEvidence else |_| {}
        try file.writePositionalAll(io, &byte, 0);
    }
    _ = try image.engine.load(alloc, io, &lock, f.cli);
    const valid = try c.encode(alloc, state);
    const duplicate = try std.fmt.allocPrint(alloc, "{{\"phase\":\"prepared\",{s}", .{valid[1..]});
    try image.files.durable(try lock.commit(io, "state.json", duplicate));
    if (image.engine.load(alloc, io, &lock, f.cli)) |_| return error.AcceptedDuplicate else |_| {}
    const azure = try std.fmt.allocPrint(alloc, "{{\"resource_group\":\"not-authorized\",{s}", .{valid[1..]});
    try image.files.durable(try lock.commit(io, "state.json", azure));
    if (image.engine.load(alloc, io, &lock, f.cli)) |_| return error.AcceptedUnknownFields else |_| {}
}
test "export reload rejects misplaced exact markers even with coherent synthetic hashes" {
    const f = try Fixture.init(16, false);
    defer f.deinit();
    const alloc = f.arena.allocator();
    const state = try f.prepare();
    try t.expectEqual(c.Phase.prepared, state.phase);
    const root = try f.stateDir();
    defer root.close(io);
    var lock = try root.lock(io);
    defer lock.close(io);
    const work = try image.core.private_files.Directory.open(io, (try image.engine.bootConfig(alloc, state, 0)).work_dir);
    defer work.close(io);
    const original_log = try work.read(io, alloc, image.boot.config.log_name, image.boot.config.max_serial, null);
    const original_report = try work.read(io, alloc, "report.json", c.max_record, null);
    const target = try image.files.path(alloc, f.path, "checked-export");
    for ([_]struct { bytes: []const u8, failure: anyerror }{
        .{ .bytes = late_platform, .failure = error.InvalidPublicSerial },
        .{ .bytes = early_platform, .failure = error.ReorderedMilestone },
        .{ .bytes = duplicate_platform, .failure = error.InvalidPublicSerial },
    }) |invalid| {
        // Keep all stored public hashes coherent so failure must come from
        // actual serial semantics, not an earlier digest-mismatch shortcut.
        var report = try image.boot.runner.Report.decode(alloc, original_report);
        report.serial_bytes = invalid.bytes.len;
        report.serial_sha256 = c.hash(invalid.bytes);
        try t.expect(report.succeeded());
        const report_bytes = try report.encode(alloc);
        try rewriteFixture(work, image.boot.config.log_name, invalid.bytes);
        try rewriteFixture(work, "report.json", report_bytes);
        try rewriteFixture(root, "local-raw-x2apic-serial.log", invalid.bytes);
        var altered = state;
        altered.boots[0].?.report_sha256 = try c.hex(alloc, c.hash(report_bytes));
        altered.boots[0].?.serial_sha256 = try c.hex(alloc, c.hash(invalid.bytes));
        altered.boots[0].?.serial_bytes = invalid.bytes.len;
        try image.files.durable(try lock.commit(io, "state.json", try c.encode(alloc, altered)));
        try t.expectError(invalid.failure, image.engine.load(alloc, io, &lock, f.cli));
        const refused = image.manifest.publish(alloc, io, &lock, f.cli, target, source);
        try t.expect(refused.sha256 == null and refused.failures.primary != null);
        try t.expectError(error.FileNotFound, image.core.private_files.Directory.open(io, target));
    }
    try rewriteFixture(work, image.boot.config.log_name, original_log);
    try rewriteFixture(work, "report.json", original_report);
    try rewriteFixture(root, "local-raw-x2apic-serial.log", original_log);
    try image.files.durable(try lock.commit(io, "state.json", try c.encode(alloc, state)));
    _ = try image.engine.load(alloc, io, &lock, f.cli);
    try t.expect(image.manifest.publish(alloc, io, &lock, f.cli, target, source).sha256 != null);
}
fn rewriteFixture(dir: image.core.private_files.Directory, name: []const u8, bytes: []const u8) !void {
    try dir.dir.writeFile(io, .{ .sub_path = name, .data = bytes, .flags = .{ .permissions = .fromMode(0o600) } });
}
fn command(f: Fixture, args: []const []const u8) !std.process.RunResult {
    var environment: std.process.Environ.Map = .init(f.arena.allocator());
    defer environment.deinit();
    try environment.put("TMPDIR", f.path);
    try environment.put("PUBLIC_SENTINEL_NOT_FOR_QEMU", "synthetic");
    return std.process.run(f.arena.allocator(), io, .{ .argv = args, .cwd = .{ .dir = f.dir.dir }, .environ_map = &environment, .stdout_limit = .limited(c.max_record), .stderr_limit = .limited(c.max_record) });
}
test "actual native CLI prepare matrix exact export digest and refusal boundaries" {
    const f = try Fixture.init(0, false);
    defer f.deinit();
    const alloc = f.arena.allocator();
    const prepare_args = [_][]const u8{ f.cli, "prepare", "--efi", f.input.efi, "--qemu", f.input.qemu, "--ovmf-code", f.input.ovmf_code, "--ovmf-vars", f.input.ovmf_vars, "--state-dir", f.input.state_dir, "--timeout", "10" };
    for ([_][]const []const u8{ &.{ "--timeout", "0" }, &.{ "--timeout", "NaN" }, &.{ "--miz", "/unused" }, &.{ "--fixture-mode", "success" }, &.{ "--state-dir", f.input.state_dir }, &.{ "--cpus", "2" } }) |extra| {
        const failed = try command(f, try std.mem.concat(alloc, []const u8, &.{ &prepare_args, extra }));
        try t.expect(failed.term == .exited and failed.term.exited != 0 and failed.stdout.len == 0);
        try t.expect(std.mem.indexOf(u8, failed.stderr, f.input.efi) == null);
    }
    const prepared = try command(f, &prepare_args);
    try t.expect(prepared.term == .exited and prepared.term.exited == 0);
    const matrix = try command(f, &.{ f.cli, "validate-matrix", "--state-dir", f.input.state_dir });
    try t.expect(matrix.term == .exited and matrix.term.exited == 0);
    const target = try image.files.path(alloc, f.path, "artifact");
    const exported = try command(f, &.{ f.cli, "export-prepared", "--state-dir", f.input.state_dir, "--artifact-dir", target, "--source-repository", source.repository, "--source-repository-id", "123", "--source-workflow-ref", source.workflow_ref, "--source-job", source.job, "--source-run-id", "456", "--source-run-attempt", "1", "--source-head-sha", source.head_sha });
    try t.expect(exported.term == .exited and exported.term.exited == 0 and exported.stderr.len == 0);
    try t.expectEqual(@as(usize, 65), exported.stdout.len);
    const digest = try c.sha(exported.stdout[0..64]);
    try t.expectEqual(@as(u8, '\n'), exported.stdout[64]);
    const output = try image.core.private_files.Directory.open(io, target);
    defer output.close(io);
    _ = try output.read(io, alloc, image.manifest.name, c.max_record, digest);
    const root = try f.stateDir();
    defer root.close(io);
    var lock = try root.lock(io);
    defer lock.close(io);
    const locked = try command(f, &.{ f.cli, "validate-matrix", "--state-dir", f.input.state_dir });
    try t.expect(locked.term == .exited and locked.term.exited != 0);
}
