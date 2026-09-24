const std = @import("std");
const image = @import("public_image");
const controller = @import("wamr_controller");
const c = image.contracts;
const t = std.testing;
const a = t.allocator;
const io = t.io;
const options = @import("test_options");
const Value = std.json.Value;

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
    parent: image.core.private_files.Directory,
    directory: image.core.private_files.Directory,
    name: []const u8,
    path: []const u8,
    state_path: []const u8,
    cli: []const u8,

    fn init() !Fixture {
        const root_path = options.test_root orelse return error.MissingTestRoot;
        const arena = try a.create(std.heap.ArenaAllocator);
        errdefer a.destroy(arena);
        arena.* = .init(a);
        errdefer arena.deinit();
        const alloc = arena.allocator();
        const parent = try image.core.private_files.Directory.open(io, root_path);
        errdefer parent.close(io);
        var nonce: [8]u8 = undefined;
        io.random(&nonce);
        const name = try std.fmt.allocPrint(alloc, "wamr-compute-{s}", .{
            std.fmt.bytesToHex(nonce, .lower),
        });
        const path = try image.files.path(alloc, root_path, name);
        const directory = try image.files.create(io, path);
        errdefer directory.close(io);
        const state_path = try image.files.path(alloc, path, "state");
        const state = try image.files.create(io, state_path);
        state.close(io);
        try directory.dir.writeFile(io, .{
            .sub_path = "workload.efi",
            .data = &efi(),
            .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) },
        });
        return .{
            .arena = arena,
            .parent = parent,
            .directory = directory,
            .name = name,
            .path = path,
            .state_path = state_path,
            .cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, alloc),
        };
    }

    fn deinit(self: Fixture) void {
        self.directory.close(io);
        self.parent.dir.deleteTree(io, self.name) catch @panic("compute fixture cleanup failed");
        self.parent.close(io);
        self.arena.deinit();
        a.destroy(self.arena);
    }
};

test "supervised compute workers finalize exact raw and derive from exact QCOW2" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const alloc = fixture.arena.allocator();
    const state = try image.core.private_files.Directory.open(io, fixture.state_path);
    defer state.close(io);
    const efi_path = try image.files.path(alloc, fixture.path, "workload.efi");
    const efi_input = try image.files.record(alloc, io, efi_path, c.max_efi, false);
    const packaged = try image.package.build(alloc, io, state, efi_input);
    try image.files.cleanupStage(io, state, "package-stage");
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
    const raw_path = try image.files.path(alloc, fixture.state_path, "unikraft.raw");
    const finalize_intent: image.compute_artifacts.FinalizeIntent = .{
        .source_path = raw_path,
        .expected_source_sha256 = packaged.raw.sha256,
        .expected_source_bytes = packaged.raw.size,
        .expected_virtual_bytes = packaged.raw.size,
        .expected_workload_sha256 = efi_input.sha256,
        .expected_workload_bytes = efi_input.size,
        .timeout_ms = 120_000,
        .limits = limits,
    };
    const finalize_path = try image.files.path(alloc, fixture.path, "finalize.json");
    try writeIntent(fixture.directory, "finalize.json", try c.encode(alloc, finalize_intent));
    const result = try run(fixture, &.{ fixture.cli, "finalize-qcow2", finalize_path, fixture.state_path });
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);
    try t.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    const finalized = try image.compute_artifacts.readFinalizationRecord(alloc, result.stdout);
    try t.expectEqualStrings(packaged.raw.sha256, finalized.source_sha256);
    try t.expectEqualStrings(efi_input.sha256, finalized.identity.workload_sha256);
    try t.expect((try state.read(io, alloc, "qcow2-launched", 1, null)).len == 0);
    try t.expect(std.mem.indexOf(
        u8,
        try state.read(io, alloc, "qcow2-supervision.json", c.max_record, null),
        "\"outcome\":\"succeeded\"",
    ) != null);

    const qcow2_path = try image.files.path(alloc, fixture.state_path, image.compute_artifacts.qcow2_name);
    const derive_intent: image.compute_artifacts.DeriveIntent = .{
        .source_path = qcow2_path,
        .accepted_qcow2_sha256 = finalized.output.sha256,
        .expected_source_bytes = finalized.output.file_bytes,
        .expected_capacity_bytes = finalized.output.virtual_bytes,
        .timeout_ms = 120_000,
        .limits = limits,
    };
    const derive_path = try image.files.path(alloc, fixture.path, "derive.json");
    try writeIntent(fixture.directory, "derive.json", try c.encode(alloc, derive_intent));
    const derived_result = try run(fixture, &.{ fixture.cli, "derive-fixed-vhd", derive_path, fixture.state_path });
    defer alloc.free(derived_result.stdout);
    defer alloc.free(derived_result.stderr);
    try t.expectEqual(std.process.Child.Term{ .exited = 0 }, derived_result.term);
    const derived = try image.compute_artifacts.readDerivationRecord(alloc, derived_result.stdout);
    try t.expectEqualStrings(finalized.output.sha256, derived.accepted_qcow2.sha256);
    try t.expectEqualStrings(finalized.source_sha256, derived.accepted_qcow2_decoded_sha256);
    try t.expectEqual(@as(u64, c.vhd_bytes), derived.output.file_bytes);
    try t.expect((try state.read(io, alloc, "vhd-launched", 1, null)).len == 0);
    try t.expect(std.mem.indexOf(
        u8,
        try state.read(io, alloc, "vhd-supervision.json", c.max_record, null),
        "\"outcome\":\"succeeded\"",
    ) != null);
}

test "deadline refusal removes partial compute outputs and retains typed supervision" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const alloc = fixture.arena.allocator();
    const state = try image.core.private_files.Directory.open(io, fixture.state_path);
    defer state.close(io);
    const efi_path = try image.files.path(alloc, fixture.path, "workload.efi");
    const efi_input = try image.files.record(alloc, io, efi_path, c.max_efi, false);
    const packaged = try image.package.build(alloc, io, state, efi_input);
    try image.files.cleanupStage(io, state, "package-stage");
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
    const raw_path = try image.files.path(alloc, fixture.state_path, "unikraft.raw");
    const intent: image.compute_artifacts.FinalizeIntent = .{
        .source_path = raw_path,
        .expected_source_sha256 = packaged.raw.sha256,
        .expected_source_bytes = packaged.raw.size,
        .expected_virtual_bytes = packaged.raw.size,
        .expected_workload_sha256 = efi_input.sha256,
        .expected_workload_bytes = efi_input.size,
        .timeout_ms = 1,
        .limits = limits,
    };
    const intent_path = try image.files.path(alloc, fixture.path, "deadline.json");
    try writeIntent(fixture.directory, "deadline.json", try c.encode(alloc, intent));
    const result = try run(fixture, &.{ fixture.cli, "finalize-qcow2", intent_path, fixture.state_path });
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);
    try t.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
    try expectMissing(state, image.compute_artifacts.qcow2_name);
    try expectMissing(state, image.compute_artifacts.qcow2_record_name);
    try t.expect(std.mem.indexOf(
        u8,
        try state.read(io, alloc, "qcow2-supervision.json", c.max_record, null),
        "\"outcome\":\"refused\"",
    ) != null);

    const vhd_fixture = try Fixture.init();
    defer vhd_fixture.deinit();
    const vhd_alloc = vhd_fixture.arena.allocator();
    const vhd_state = try image.core.private_files.Directory.open(io, vhd_fixture.state_path);
    defer vhd_state.close(io);
    const vhd_efi_path = try image.files.path(vhd_alloc, vhd_fixture.path, "workload.efi");
    const vhd_efi = try image.files.record(vhd_alloc, io, vhd_efi_path, c.max_efi, false);
    const vhd_packaged = try image.package.build(vhd_alloc, io, vhd_state, vhd_efi);
    try image.files.cleanupStage(io, vhd_state, "package-stage");
    const vhd_raw_path = try image.files.path(vhd_alloc, vhd_fixture.state_path, "unikraft.raw");
    const finalize_intent: image.compute_artifacts.FinalizeIntent = .{
        .source_path = vhd_raw_path,
        .expected_source_sha256 = vhd_packaged.raw.sha256,
        .expected_source_bytes = vhd_packaged.raw.size,
        .expected_virtual_bytes = vhd_packaged.raw.size,
        .expected_workload_sha256 = vhd_efi.sha256,
        .expected_workload_bytes = vhd_efi.size,
        .timeout_ms = 120_000,
        .limits = limits,
    };
    const finalize_path = try image.files.path(vhd_alloc, vhd_fixture.path, "vhd-finalize.json");
    try writeIntent(
        vhd_fixture.directory,
        "vhd-finalize.json",
        try c.encode(vhd_alloc, finalize_intent),
    );
    const finalized_result = try run(vhd_fixture, &.{
        vhd_fixture.cli,
        "finalize-qcow2",
        finalize_path,
        vhd_fixture.state_path,
    });
    defer vhd_alloc.free(finalized_result.stdout);
    defer vhd_alloc.free(finalized_result.stderr);
    try t.expectEqual(std.process.Child.Term{ .exited = 0 }, finalized_result.term);
    const finalized = try image.compute_artifacts.readFinalizationRecord(
        vhd_alloc,
        finalized_result.stdout,
    );
    const qcow2_path = try image.files.path(
        vhd_alloc,
        vhd_fixture.state_path,
        image.compute_artifacts.qcow2_name,
    );
    const derive_intent: image.compute_artifacts.DeriveIntent = .{
        .source_path = qcow2_path,
        .accepted_qcow2_sha256 = finalized.output.sha256,
        .expected_source_bytes = finalized.output.file_bytes,
        .expected_capacity_bytes = finalized.output.virtual_bytes,
        .timeout_ms = 1,
        .limits = limits,
    };
    const derive_path = try image.files.path(vhd_alloc, vhd_fixture.path, "deadline-vhd.json");
    try writeIntent(
        vhd_fixture.directory,
        "deadline-vhd.json",
        try c.encode(vhd_alloc, derive_intent),
    );
    const derived_result = try run(vhd_fixture, &.{
        vhd_fixture.cli,
        "derive-fixed-vhd",
        derive_path,
        vhd_fixture.state_path,
    });
    defer vhd_alloc.free(derived_result.stdout);
    defer vhd_alloc.free(derived_result.stderr);
    try t.expectEqual(std.process.Child.Term{ .exited = 1 }, derived_result.term);
    try expectMissing(vhd_state, image.compute_artifacts.vhd_name);
    try expectMissing(vhd_state, image.compute_artifacts.vhd_record_name);
    try t.expect(std.mem.indexOf(
        u8,
        try vhd_state.read(io, vhd_alloc, "vhd-supervision.json", c.max_record, null),
        "\"outcome\":\"refused\"",
    ) != null);
}

test "real image chain validates six synthetic boot reports and withholds result after mutation" {
    try syntheticChain(.mutated);
}

test "real image chain publishes canonical synthetic six-mode result last" {
    try syntheticChain(.complete);
}

const ChainCase = enum { mutated, complete };

fn syntheticChain(comptime case: ChainCase) !void {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const alloc = fixture.arena.allocator();
    const compute = fixture.directory.dir;
    try compute.createDir(io, "package", .fromMode(0o700));
    try compute.createDir(io, "evidence", .fromMode(0o700));
    const package_path = try image.files.path(alloc, fixture.path, "package");
    const evidence_path = try image.files.path(alloc, fixture.path, "evidence");
    const package_dir = try image.core.private_files.Directory.open(io, package_path);
    defer package_dir.close(io);
    const evidence_dir = try image.core.private_files.Directory.open(io, evidence_path);
    defer evidence_dir.close(io);
    const efi_path = try image.files.path(alloc, fixture.path, "workload.efi");
    const identity_path = try image.files.path(alloc, fixture.path, "identity.json");
    const code_path = try image.files.path(alloc, fixture.path, "code.fd");
    const vars_path = try image.files.path(alloc, fixture.path, "vars.fd");
    try writePrivate(fixture.directory, "code.fd", "synthetic firmware code");
    try writePrivate(fixture.directory, "vars.fd", "synthetic firmware vars");
    const identity = .{
        .wamr_revision = "f" ** 40,
        .minimal_wasi = false,
        .files = .{
            .@"tiny.wasm" = "0" ** 64,
            .@"tiny.cwasm" = "1" ** 64,
            .@"libwamr-aot.a" = "2" ** 64,
        },
    };
    try writePrivate(fixture.directory, "identity.json", try c.encode(alloc, identity));
    const validator_cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.validator_cli, alloc);
    var signal = try controller.build_pipeline.installCancellation();
    defer signal.deinit();
    var build_context: controller.build_pipeline.Context = .{
        .allocator = alloc, .io = io, .environ = undefined, .runtime = fixture.path,
        .repository = fixture.path, .wamr = "", .compute = fixture.path,
        .git = undefined, .tools = undefined,
        .roots = .{
            .source_root = fixture.path, .work = fixture.path, .runtime = fixture.path,
            .zig = fixture.cli, .producer = fixture.cli, .fixture_runner = fixture.cli,
            .supervisor = fixture.cli, .package_tool = fixture.cli, .validator = validator_cli,
            .supervisor_fixture = fixture.cli, .tools = [_][]const u8{fixture.cli} ** controller.input_custody.host_tools.len,
            .efi = efi_path, .local_boot_tool = fixture.cli, .qemu = fixture.cli,
            .ovmf_code = code_path, .ovmf_vars = vars_path, .identity = identity_path,
        },
        .signal = &signal,
        .source = .{
            .revision = "f" ** 40, .tree = "f" ** 40,
            .custody = .{
                .object_format = "sha1", .files = 0, .directories = 0, .bytes = 0,
                .content_sha256 = [_]u8{'0'} ** 64, .physical_sha256 = [_]u8{'0'} ** 64,
            },
        },
    };
    var context: controller.boot_pipeline.Context = .{
        .build_context = &build_context,
        .pinned = std.StringHashMap(controller.custody_files.File).init(alloc),
    };
    defer context.pinned.deinit();
    const gate = controller.boot_pipeline.testing;
    try gate.publish(&context, "build-start.json", .null);
    if (case == .complete) {
        for ([_][]const u8{
            "adapter", "local-boot-tool", "fixtures", "prepare", "config", "native-image",
        }) |name| try publishFixtureOnlyCommandRecord(&context, name);
    }
    try gate.publish(&context, "build.json", .null);
    const package_file = try controller.custody_files.readFile(io, fixture.cli, 64 * 1024 * 1024, false);
    try gate.publish(&context, "boot-inputs.json", try fixtureValue(alloc, .{
        .files = .{ .package_tool = .{ .sha256 = package_file.sha256 } },
    }));

    const packaged_run = try run(fixture, &.{ fixture.cli, "package", efi_path, package_path });
    try t.expectEqual(std.process.Child.Term{ .exited = 0 }, packaged_run.term);
    try t.expectEqual(@as(usize, 0), packaged_run.stderr.len);
    try gate.recordPackageResult(&context, try fixtureJson(alloc, packaged_run.stdout));
    if (case == .complete) try publishFixtureOnlyCommandRecord(&context, "package");
    try expectMissing(evidence_dir, "result.json");

    for (0..2) |index| {
        try syntheticBoot(fixture, &context, index, validator_cli);
        if (case == .complete) try publishFixtureOnlyCommandRecord(&context, @tagName(controller.profile.production_modes[index]));
    }
    try expectMissing(package_dir, image.compute_artifacts.qcow2_name);
    try gate.qcow2Intent(&context);
    const finalized_run = try run(fixture, &.{
        fixture.cli, "finalize-qcow2",
        try image.files.path(alloc, evidence_path, "qcow2-finalization-intent.json"), package_path,
    });
    try t.expectEqual(std.process.Child.Term{ .exited = 0 }, finalized_run.term);
    try t.expectEqual(@as(usize, 0), finalized_run.stderr.len);
    try gate.qcow2Finalization(&context, try fixtureJson(alloc, finalized_run.stdout));
    if (case == .complete) try publishFixtureOnlyCommandRecord(&context, "finalize-qcow2");
    try t.expectError(error.MissingBoot, gate.qcow2Acceptance(&context));
    try expectMissing(evidence_dir, "qcow2-acceptance.json");
    for (2..4) |index| {
        try syntheticBoot(fixture, &context, index, validator_cli);
        if (case == .complete) try publishFixtureOnlyCommandRecord(&context, @tagName(controller.profile.production_modes[index]));
    }
    try gate.qcow2Acceptance(&context);
    try expectMissing(package_dir, image.compute_artifacts.vhd_name);
    try gate.vhdIntent(&context);
    try gate.vhdGate(&context);
    const derived_run = try run(fixture, &.{
        fixture.cli, "derive-fixed-vhd",
        try image.files.path(alloc, evidence_path, "fixed-vhd-derivation-intent.json"), package_path,
    });
    try t.expectEqual(std.process.Child.Term{ .exited = 0 }, derived_run.term);
    try t.expectEqual(@as(usize, 0), derived_run.stderr.len);
    try gate.vhdDerivation(&context, try fixtureJson(alloc, derived_run.stdout));
    if (case == .complete) try publishFixtureOnlyCommandRecord(&context, "derive-fixed-vhd");
    try t.expectError(error.MissingBoot, gate.inspect(&context));
    try expectMissing(evidence_dir, "final-inspection.json");
    for (4..6) |index| {
        try syntheticBoot(fixture, &context, index, validator_cli);
        if (case == .complete) try publishFixtureOnlyCommandRecord(&context, @tagName(controller.profile.production_modes[index]));
    }
    const inspected_run = try run(fixture, &.{ fixture.cli, "inspect", efi_path, package_path });
    try t.expectEqual(std.process.Child.Term{ .exited = 0 }, inspected_run.term);
    try t.expectEqual(@as(usize, 0), inspected_run.stderr.len);
    try t.expectEqualStrings(packaged_run.stdout, inspected_run.stdout);
    if (case == .complete) try publishFixtureOnlyCommandRecord(&context, "inspect");
    try gate.inspect(&context);
    try expectMissing(evidence_dir, "result.json");
    if (case == .complete) {
        const inspection = try fixtureJson(alloc, try evidence_dir.read(
            io, alloc, "final-inspection.json", controller.records.max_record_bytes, null));
        const modes = inspection.object.get("modes").?.array.items;
        const boots = inspection.object.get("boots").?.object;
        try t.expectEqual(controller.profile.production_modes.len, modes.len);
        try t.expectEqual(controller.profile.production_modes.len, boots.count());
        for (controller.profile.production_modes, 0..) |mode, index| {
            try t.expectEqualStrings(@tagName(mode), modes[index].string);
            try t.expect(boots.contains(@tagName(mode)));
        }
        _ = try gate.resultAfterInspection(&context);
        const raw = try evidence_dir.read(io, alloc, "result.json", controller.records.max_record_bytes, null);
        var accepted = try controller.records.parseCanonicalResult(alloc, raw);
        defer accepted.deinit();
        try t.expectEqual(controller.profile.CompatibleRecordSet.tiny_v2_qcow2_derived_vhd, accepted.value.set);
        try t.expectEqual(@as(usize, 34), context.pinned.count());
        try t.expect(context.pinned.contains("result.json"));
        try t.expectEqual(@as(usize, 33), accepted.value.records.count());
        try t.expect(!accepted.value.records.contains("result.json"));
        var fixture_commands: usize = 0;
        for (accepted.value.records.keys(), accepted.value.records.values()) |name, digest| {
            const pinned = context.pinned.get(name) orelse return error.MissingRecord;
            const bytes = try evidence_dir.read(io, alloc, name, controller.records.max_record_bytes, null);
            const actual = std.fmt.bytesToHex(controller.records.fileIdentity(bytes), .lower);
            try t.expectEqualStrings(&actual, digest.string);
            try t.expectEqualStrings(&pinned.sha256, digest.string);
            try controller.records.verifyRecord(accepted.value, name, bytes);
            if (std.mem.startsWith(u8, name, "command-")) {
                const command = try fixtureJson(alloc, bytes);
                try t.expectEqualStrings("synthetic_fixture_not_command_proof",
                    command.object.get("scope").?.string);
                try t.expectEqualStrings(name["command-".len .. name.len - ".json".len],
                    command.object.get("stage").?.string);
                fixture_commands += 1;
            }
        }
        try t.expectEqual(@as(usize, 16), fixture_commands);
        var entries = evidence_dir.dir.iterate();
        var observed: usize = 0;
        while (try entries.next(io)) |entry| {
            try t.expect(std.mem.eql(u8, entry.name, "result.json") or
                accepted.value.records.contains(entry.name));
            observed += 1;
        }
        try t.expectEqual(accepted.value.records.count() + 1, observed);
        return;
    }
    try writePrivate(evidence_dir, "unlisted.json", "{}\n");
    try t.expectError(error.UnexpectedEvidence, gate.resultAfterInspection(&context));
    try expectMissing(evidence_dir, "result.json");
    try evidence_dir.dir.deleteFile(io, "unlisted.json");
    const last_slot = try image.core.private_files.Directory.open(io,
        try image.files.path(alloc, fixture.path, "boot-vpc-legacy-apic"));
    defer last_slot.close(io);
    const serial = try last_slot.dir.openFile(io, "hyperv-efi-boot.log", .{ .mode = .read_write });
    var original: [1]u8 = undefined;
    try t.expectEqual(@as(usize, 1), try serial.readPositionalAll(io, &original, 0));
    try serial.writePositionalAll(io, "!", 0);
    serial.close(io);
    try t.expectError(error.SerialChanged, gate.resultAfterInspection(&context));
    try expectMissing(evidence_dir, "result.json");
    const restore = try last_slot.dir.openFile(io, "hyperv-efi-boot.log", .{ .mode = .read_write });
    try restore.writePositionalAll(io, &original, 0);
    restore.close(io);
    const inspection = try package_dir.dir.openFile(io, image.compute_artifacts.vhd_name, .{ .mode = .read_write });
    try inspection.writePositionalAll(io, &.{0x42}, 100);
    inspection.close(io);
    try t.expectError(error.ArtifactChanged, gate.resultAfterInspection(&context));
    try expectMissing(evidence_dir, "result.json");
}

fn publishFixtureOnlyCommandRecord(ctx: *controller.boot_pipeline.Context, stage: []const u8) !void {
    const allocator = ctx.build_context.allocator;
    const name = try std.fmt.allocPrint(allocator, "command-{s}.json", .{stage});
    try controller.boot_pipeline.testing.publish(ctx, name, try fixtureValue(allocator, .{
        .scope = "synthetic_fixture_not_command_proof", .stage = stage,
    }));
}

fn fixtureJson(allocator: std.mem.Allocator, raw: []const u8) !Value {
    return std.json.parseFromSliceLeaky(Value, allocator, raw, .{
        .duplicate_field_behavior = .@"error", .parse_numbers = false, .allocate = .alloc_always,
    });
}

fn fixtureValue(allocator: std.mem.Allocator, value: anytype) !Value {
    return fixtureJson(allocator, try std.json.Stringify.valueAlloc(allocator, value, .{}));
}

fn writePrivate(directory: image.core.private_files.Directory, name: []const u8, bytes: []const u8) !void {
    try directory.dir.writeFile(io, .{
        .sub_path = name, .data = bytes,
        .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) },
    });
}

fn syntheticBoot(fixture: Fixture, ctx: *controller.boot_pipeline.Context, index: usize, validator: []const u8) !void {
    const alloc = fixture.arena.allocator();
    const mode = controller.profile.production_modes[index];
    const slot_name = try std.fmt.allocPrint(alloc, "boot-{s}", .{@tagName(mode)});
    try fixture.directory.dir.createDir(io, slot_name, .fromMode(0o700));
    const slot_path = try image.files.path(alloc, fixture.path, slot_name);
    const slot = try image.core.private_files.Directory.open(io, slot_path);
    defer slot.close(io);
    const config = try controller.boot_pipeline.testing.config(ctx, index);
    const source_path = try image.files.path(alloc, fixture.path,
        try std.fmt.allocPrint(alloc, "package/{s}", .{controller.command_plan.bootImage(mode)}));
    var pins = Value{ .array = std.array_list.Managed(Value).init(alloc) };
    for ([_][]const u8{ source_path, ctx.build_context.roots.ovmf_code,
        ctx.build_context.roots.ovmf_vars, ctx.build_context.roots.qemu }) |path_name|
        try pins.array.append(try controller.boot_pipeline.testing.pin(ctx, path_name));
    try writePrivate(slot, "request.json", try controller.records.canonicalAlloc(alloc,
        try std.json.Stringify.valueAlloc(alloc, .{
            .schema_version = @as(u8, 2), .supervisor_pid = @as(u32, 1),
            .config = config, .pins = pins,
        }, .{})));
    try writePrivate(slot, "launched", "");
    const computation = try std.json.Stringify.valueAlloc(alloc, .{
        .version = 1, .workload = "tiny", .wamr_revision = "f" ** 40,
        .wasm_sha256 = "0" ** 64, .cwasm_sha256 = "1" ** 64,
        .runtime_sha256 = "2" ** 64, .platform_status = 0, .checks = 2,
        .answer = 42, .terminal = 1, .detail = 2, .reserved_bytes = 0,
        .frame_bytes = 0, .accessible_bytes = 0, .allocation_bytes = 0,
        .error_name = "", .system_page_table_bytes = 4096,
    }, .{});
    const serial = try std.fmt.allocPrint(alloc,
        "{s}Hyper-V Hv#1 hypercall page enabled\nHyper-V SynIC:\nPowered by\n" ++
            "Calling main(0, 0)\nWAMR_NATIVE_COMPUTE={s}\n" ++
            "WAMR_NATIVE_AOT_OK answer=42 teardown=0\nmain returned 0\n",
        .{ if (mode.legacyApic()) "Using legacy xAPIC MMIO\n" else "", computation });
    try writePrivate(slot, "hyperv-efi-boot.log", serial);
    const digest = std.fmt.bytesToHex(controller.records.fileIdentity(serial), .lower);
    try writePrivate(slot, "report.json", try controller.records.canonicalAlloc(alloc,
        try std.json.Stringify.valueAlloc(alloc, .{
            .schema_version = @as(u8, 1), .scope = "public_local_qemu_only",
            .acceptance = "not_established", .passed = true, .consumed = true,
            .cleanup_complete = true, .input_unchanged = true, .serial_valid = true,
            .serial_limit_reached = false, .serial_bytes = serial.len,
            .serial_sha256 = digest, .termination = .{ .exited = 0 },
            .failures = .{ .primary = @as(?u8, null), .cleanup = @as(?u8, null),
                .recording = @as(?u8, null) },
        }, .{})));
    const stage: controller.command_plan.Stage = if (mode.legacyApic())
        .@"log-validator-legacy"
    else
        .@"log-validator-x2apic";
    const environment = try controller.command_plan.environment(alloc, stage);
    defer controller.command_plan.freeEnvironment(alloc, environment);
    try t.expectEqual(@as(usize, 0), environment.len);
    ctx.build_context.roots.serial = try image.files.path(alloc, slot_path, "hyperv-efi-boot.log");
    try t.expectEqualStrings(validator, ctx.build_context.roots.validator);
    const outcome = try controller.command_adapter.execute(alloc, io, .{
        .roots = ctx.build_context.roots, .stage = stage,
        .private_dir = slot.dir, .evidence_dir = slot.dir,
        .cancel = ctx.build_context.signal.flag(),
        .capture_stdout = true, .private_record = true,
    });
    try t.expect(outcome.accepted and !outcome.poisoned);
    try t.expectEqual(@as(usize, 0), outcome.stderr_bytes);
    const name = try std.fmt.allocPrint(alloc, "command-{s}.json", .{@tagName(stage)});
    const record_path = try image.files.path(alloc, slot_path, name);
    _ = try controller.custody_files.readFile(io, record_path, controller.records.max_record_bytes, true);
    const command = try fixtureJson(alloc, try slot.read(io, alloc, name, controller.records.max_record_bytes, null));
    const request = command.object.get("supervisor").?.object.get("request").?;
    try t.expectEqual(@as(usize, 0), request.object.get("environment").?.array.items.len);
    try t.expectEqual(@as(usize, 0), request.object.get("retained_executables").?.array.items.len);
    const validated = try controller.boot_pipeline.parseValidator(alloc, outcome.stdout, serial.len, &digest);
    try controller.boot_pipeline.testing.recordBoot(ctx, index, validated.object.get("compute").?);
}

fn writeIntent(directory: image.core.private_files.Directory, name: []const u8, bytes: []const u8) !void {
    try directory.dir.writeFile(io, .{
        .sub_path = name,
        .data = bytes,
        .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) },
    });
    try image.files.sync(io, directory.dir);
}

fn run(fixture: Fixture, args: []const []const u8) !std.process.RunResult {
    return std.process.run(fixture.arena.allocator(), io, .{
        .argv = args,
        .cwd = .{ .dir = fixture.directory.dir },
        .stdout_limit = .limited(c.max_record),
        .stderr_limit = .limited(c.max_record),
    });
}

fn expectMissing(directory: image.core.private_files.Directory, name: []const u8) !void {
    if (directory.dir.openFile(io, name, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    })) |file| {
        file.close(io);
        return error.UnexpectedOutput;
    } else |err| if (err != error.FileNotFound) return err;
}
