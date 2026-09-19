const std = @import("std");
const image = @import("public_image");
const c = image.contracts;
const t = std.testing;
const a = t.allocator;
const io = t.io;
const options = @import("test_options");

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
