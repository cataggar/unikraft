// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const controller = @import("wamr_controller");
const handoff = @import("wamr_handoff");
const files = core.private_files;
const archive = handoff.public_archive;
const products = handoff.public_products;
const candidate = handoff.candidate;
const zip = handoff.zip;
const copy = handoff.retained_copy;
const options = @import("test_options");

const Workspace = struct {
    a: std.mem.Allocator,
    io: std.Io,
    parent: std.Io.Dir,
    root: std.Io.Dir,
    name: []const u8,
    path: []const u8,

    fn init(a: std.mem.Allocator, io: std.Io, label: []const u8) !Workspace {
        const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{});
        errdefer parent.close(io);
        const name = try a.print("handoff-composition-{s}-{d}", .{ label, std.os.linux.getpid() });
        try parent.createDir(io, name, .fromMode(0o700));
        const root = try parent.openDir(io, name, .{ .iterate = true });
        return .{ .a = a, .io = io, .parent = parent, .root = root, .name = name, .path = try std.fs.path.join(a, &.{ options.fixture_root, name }) };
    }
    fn deinit(self: Workspace) void {
        self.root.close(self.io);
        self.parent.deleteTree(self.io, self.name) catch @panic("composition fixture cleanup failed");
        self.parent.close(self.io);
    }
    fn join(self: Workspace, name: []const u8) ![]const u8 {
        return std.fs.path.join(self.a, &.{ self.path, name });
    }
    fn relative(self: Workspace, path: []const u8) []const u8 {
        std.debug.assert(std.mem.startsWith(u8, path, self.path) and path[self.path.len] == '/');
        return path[self.path.len + 1 ..];
    }
    fn put(self: Workspace, name: []const u8, bytes: []const u8) !void {
        const file = try self.root.createFile(self.io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(self.io);
        try file.writePositionalAll(self.io, bytes, 0);
        try file.sync(self.io);
    }
    fn read(self: Workspace, name: []const u8) ![]const u8 {
        return self.root.readFileAlloc(self.io, name, self.a, .limited(handoff.layout.max_serial_bytes));
    }
    fn absent(self: Workspace, name: []const u8) !void {
        try std.testing.expectError(error.FileNotFound, self.root.openFile(self.io, name, .{}));
    }
    fn digest(self: Workspace, name: []const u8) ![64]u8 {
        var file = try files.RetainedFile.open(self.io, try self.join(name), .private);
        defer file.close(self.io);
        return copy.hashRetained(self.io, &file, handoff.layout.max_total_bytes, null);
    }
};

fn canonical(a: std.mem.Allocator, value: anytype) ![]const u8 {
    return controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, value, .{}));
}

fn fileCrc(io: std.Io, file: std.Io.File, size: u64) !u32 {
    var crc = std.hash.Crc32.init();
    var buffer: [64 * 1024]u8 = undefined;
    var at: u64 = 0;
    while (at < size) {
        const want: usize = @intCast(@min(buffer.len, size - at));
        try std.testing.expectEqual(want, try file.readPositionalAll(io, buffer[0..want], at));
        crc.update(buffer[0..want]);
        at += want;
    }
    return crc.final();
}

// The bytes come from the existing complete owner fixture, not ZIP goldens or
// a synthetic AcceptedRun. Only the public CI producer path remains unqualified.
fn writeArchive(work: Workspace, name: []const u8, stage: []const u8, metadata: *const archive.Metadata, altered_serial: ?[]const u8) ![32]u8 {
    const a = work.a;
    const count = metadata.selected.len;
    const sources = try a.alloc(std.Io.File, count);
    var opened: usize = 0;
    defer for (sources[0..opened]) |file| file.close(work.io);
    const readers = try a.alloc(std.Io.File.Reader, count);
    const entries = try a.alloc(zip.Entry, count + 2);
    var serial_reader: std.Io.Reader = undefined;
    for (metadata.selected, 0..) |member, index| {
        if (altered_serial != null and std.mem.eql(u8, member.name, "boots/raw-x2apic/serial")) {
            serial_reader = .fixed(altered_serial.?);
            entries[index] = sliceEntry(member.name, altered_serial.?, &serial_reader);
            continue;
        }
        sources[opened] = try std.Io.Dir.cwd().openFile(work.io, try std.fs.path.join(a, &.{ stage, member.name }), .{});
        const file = sources[opened];
        opened += 1;
        readers[index] = file.reader(work.io, &.{});
        entries[index] = .{
            .name = member.name,
            .reader = &readers[index].interface,
            .size = member.size,
            .crc32 = try fileCrc(work.io, file, member.size),
            .sha256 = member.sha256,
            .limit = member.limit,
        };
    }
    var bundle_reader: std.Io.Reader = .fixed(metadata.bundle);
    var manifest_reader: std.Io.Reader = .fixed(metadata.manifest);
    entries[count] = sliceEntry("bundle.json", metadata.bundle, &bundle_reader);
    entries[count + 1] = sliceEntry("public-source.json", metadata.manifest, &manifest_reader);
    const output = try work.root.createFile(work.io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer output.close(work.io);
    var buffer: [64 * 1024]u8 = undefined;
    var writer = output.writer(work.io, &buffer);
    var digest: [32]u8 = undefined;
    try zip.writeArchive(&writer.interface, entries, &digest);
    try writer.flush();
    try output.sync(work.io);
    return digest;
}

fn sliceEntry(name: []const u8, bytes: []const u8, reader: *std.Io.Reader) zip.Entry {
    return .{ .name = name, .reader = reader, .size = bytes.len, .crc32 = zip.crc32(bytes), .sha256 = zip.sha256(bytes), .limit = handoff.layout.max_json_bytes };
}

pub fn historical(
    a: std.mem.Allocator,
    io: std.Io,
    accepted: *controller.accepted_run.AcceptedRun,
    stage: []const u8,
    repository: []const u8,
    tools: controller.import_validator_build.LocalTools,
) !void {
    const work = try Workspace.init(a, io, "historical");
    defer work.deinit();
    const context: archive.Context = .{
        .repository = "cataggar/unikraft",
        .run_id = "1",
        .run_attempt = "1",
        .source_revision = accepted.source.revision,
        .source_tree = accepted.source.tree,
        .wamr_revision = controller.custody_limits.historical_wamr_revision,
    };
    const root_bound = try std.Io.Dir.cwd().readFileAlloc(io, try std.fs.path.join(a, &.{ stage, "bundle.json" }), a, .limited(handoff.layout.max_json_bytes));
    var metadata = try archive.Metadata.fromRootBound(a, root_bound, stage, context);
    defer metadata.deinit();
    const digest = try writeArchive(work, "input.zip", stage, &metadata, null);
    const input_digest = try work.digest("input.zip");
    const input: products.Input = .{ .historical_archive = .{
        .path = try work.join("input.zip"),
        .context = context,
        .digest = .{ .bytes = digest },
    } };
    const Fault = enum { foreign_output, materialization, copy_sync, native_identity, native_command, publication_unknown, publication_sync, final_collision, final_revalidation };
    for (std.enums.values(Fault)) |fault| {
        var step_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer step_arena.deinit();
        const step_a = step_arena.allocator();
        const name = @tagName(fault);
        const output = try work.join(name);
        if (fault == .foreign_output) {
            try work.root.createDir(io, name, .fromMode(0o700));
            try work.put("foreign_output/foreign", "foreign output\n");
        }
        var local_tools = tools;
        if (fault == .native_identity) local_tools.validator = options.command_fixture;
        const result = products.Test.importBundle(.{
            .allocator = std.testing.allocator,
            .io = io,
            .repository = repository,
            .input = input,
            .output = output,
            .tools = local_tools,
        }, .{
            .materialization_collision = fault == .materialization,
            .copy = if (fault == .copy_sync) .before_file_sync else .none,
            .publication = switch (fault) {
                .publication_unknown => .publication,
                .publication_sync => .after_rename,
                else => null,
            },
            .publication_collision = fault == .final_collision,
            .native_command_refusal = fault == .native_command,
            .change_before_final_revalidation = fault == .final_revalidation,
        });
        std.debug.print("historical composition {s}: {any}\n", .{ name, result });
        if (result == .success) {
            result.success.deinit();
            return error.FaultAccepted;
        }
        try std.testing.expectEqual(fault == .foreign_output, result == .refused);
        const diagnostic = if (result == .refused) result.refused else result.poisoned;
        try std.testing.expectEqual(switch (fault) {
            .foreign_output => products.Phase.reserved,
            .materialization => .materialized,
            .copy_sync => .copied,
            .native_identity, .native_command => .native_validation,
            .final_revalidation => .final_revalidation,
            else => .publication,
        }, diagnostic.phase);
        try std.testing.expectEqual(switch (fault) {
            .foreign_output, .materialization => error.OutputExists,
            .native_identity => error.InvalidValidator,
            .native_command => error.StageRefused,
            .final_collision => error.PathAlreadyExists,
            .final_revalidation => error.FileChanged,
            else => error.AmbiguousWrite,
        }, diagnostic.err);
        try std.testing.expectEqual(switch (fault) {
            .publication_unknown => files.CommitStatus.publication_unknown,
            .publication_sync => .visible_not_durable,
            .final_revalidation => .durable,
            else => .not_committed,
        }, diagnostic.publication);
        try std.testing.expectEqualSlices(u8, &input_digest, &try work.digest("input.zip"));
        if (fault == .foreign_output)
            try std.testing.expectEqualStrings("foreign output\n", try work.read("foreign_output/foreign"))
        else if (fault == .materialization)
            try std.testing.expectEqualStrings("foreign materialization\n", try work.read("materialization/private/materialized/foreign"))
        else {
            const directory = try files.Directory.open(io, try std.fs.path.join(step_a, &.{ output, "private/materialized" }));
            directory.close(io);
        }
        if (fault == .final_collision)
            try std.testing.expectEqualStrings("foreign final bundle\n", try work.read("final_collision/bundle.json"))
        else if (fault != .publication_sync and fault != .final_revalidation)
            try work.absent(try step_a.print("{s}/bundle.json", .{name}));
        if (fault == .copy_sync) {
            const copied = try work.root.openFile(io, try step_a.print("{s}/{s}", .{ name, metadata.selected[0].name }), .{});
            defer copied.close(io);
            try std.testing.expectEqual(metadata.selected[0].size, (try copied.stat(io)).size);
        }
        if (fault == .native_command) {
            const record = try work.read("native_command/private/native-validation/evidence/command-import-historical-native-revalidation.json");
            var document = try handoff.contracts.parseCanonical(step_a, record);
            defer document.deinit();
            try std.testing.expectEqual(@as(i32, 1), try core.contracts.integer(i32, document.value().object.get("exit_code").?));
            const changed = try work.read("native_command/candidate-bundle.json");
            try std.testing.expectEqual(@as(u8, '!'), changed[0]);
            const log = try work.root.openFile(io, "native_command/private/native-validation/private/import-historical-native-revalidation.log", .{});
            defer log.close(io);
            try std.testing.expect((try log.stat(io)).size > 0);
        }
    }
    {
        const imported = products.importBundle(.{ .allocator = std.testing.allocator, .io = io, .repository = repository, .input = input, .output = try work.join("success"), .tools = tools });
        if (imported != .success) std.debug.print("historical import: {any}\n", .{imported});
        try std.testing.expect(imported == .success);
        const owner = imported.success;
        defer owner.deinit();
        try owner.revalidate(null);
        const finalized = candidate.create(.{
            .allocator = std.testing.allocator,
            .io = io,
            .source = .{ .imported_product = owner },
            .output = try work.join("historical-candidate.json"),
            .validation_output = try work.join("historical-candidate-validation"),
            .settings = .{ .attempt_id = "00000000-0000-4000-8000-000000000001" },
        });
        if (finalized != .success) std.debug.print("historical candidate: {any}\n", .{finalized});
        try std.testing.expect(finalized == .success);
        defer finalized.success.deinit();
        _ = try finalized.success.result(try std.fs.path.join(a, &.{ owner.bundle.?.evidence.root, "boots/raw-x2apic/serial" }), null, null);
        try reopenHistoricalCandidate(work, owner);
    }
    try rehashedPayload(work, stage, repository, tools, context, &metadata);
}

fn reopenHistoricalCandidate(work: Workspace, owner: *products.ImportedProduct) !void {
    const reopened = candidate.open(.{
        .allocator = std.testing.allocator,
        .io = work.io,
        .source = .{ .imported_product = owner },
        .output = try work.join("historical-candidate.json"),
        .validation_output = try work.join("historical-candidate-open-validation"),
    });
    if (reopened != .success) std.debug.print("historical candidate open: {any}\n", .{reopened});
    try std.testing.expect(reopened == .success);
    defer reopened.success.deinit();
    const inspect = try reopened.success.inspect(null);
    try std.testing.expectEqual(@as(u8, 1), inspect.version);
    try std.testing.expectEqual(.not_admitted, inspect.authority);
    try std.testing.expectError(error.Version2Required, reopened.success.metadata(null));
    _ = try reopened.success.result(try std.fs.path.join(work.a, &.{ owner.bundle.?.evidence.root, "boots/raw-x2apic/serial" }), null, null);

    var tampered_doc = try handoff.contracts.parseCanonical(work.a, try work.read("historical-candidate.json"));
    defer tampered_doc.deinit();
    const bundle_ref = tampered_doc.value().object.get("bundle").?.object;
    bundle_ref.getPtr("sha256").?.* = .{ .string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
    const tampered_bytes = try canonical(work.a, tampered_doc.value());
    try work.put("historical-candidate-tampered.json", tampered_bytes);
    const tampered = candidate.open(.{
        .allocator = std.testing.allocator,
        .io = work.io,
        .source = .{ .imported_product = owner },
        .output = try work.join("historical-candidate-tampered.json"),
        .validation_output = try work.join("historical-candidate-tampered-validation"),
    });
    if (tampered == .success) {
        tampered.success.deinit();
        return error.TamperedCandidateAccepted;
    }
    try std.testing.expect(tampered == .poisoned);
    try std.testing.expectEqual(candidate.Phase.publication, tampered.poisoned.phase);
    try std.testing.expectEqual(error.CandidateBindingChanged, tampered.poisoned.err);
    try std.testing.expectEqual(files.CommitStatus.not_committed, tampered.poisoned.publication);
    try std.testing.expectEqualStrings(tampered_bytes, try work.read("historical-candidate-tampered.json"));
}

fn rehashedPayload(work: Workspace, stage: []const u8, repository: []const u8, tools: controller.import_validator_build.LocalTools, context: archive.Context, metadata: *archive.Metadata) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var changed = metadata.*;
    var bundle = try handoff.contracts.parseCanonical(a, metadata.bundle);
    defer bundle.deinit();
    var manifest = try handoff.contracts.parseCanonical(a, metadata.manifest);
    defer manifest.deinit();
    const original = try std.Io.Dir.cwd().readFileAlloc(work.io, try std.fs.path.join(a, &.{ stage, "boots/raw-x2apic/serial" }), a, .limited(handoff.layout.max_serial_bytes));
    const altered = try std.mem.concat(a, u8, &.{ original, "tampered\n" });
    const member = bundle.value().object.get("boots").?.array.items[0].object.get("serial").?;
    const transport_member = manifest.value().object.get("members").?.object.get("boots/raw-x2apic/serial").?;
    for ([_]std.json.Value{ member, transport_member }) |value| {
        value.object.getPtr("size").?.* = .{ .integer = @intCast(altered.len) };
        value.object.getPtr("sha256").?.* = .{ .string = try a.dupe(u8, &std.fmt.bytesToHex(zip.sha256(altered), .lower)) };
    }
    changed.bundle = try canonical(a, bundle.value());
    changed.manifest = try canonical(a, manifest.value());
    const digest = try writeArchive(work, "rehashed-payload.zip", stage, &changed, altered);
    var verified = try archive.Archive.open(std.testing.allocator, work.io, try work.join("rehashed-payload.zip"), context, digest, null);
    defer verified.deinit(work.io);
    const before = try work.digest("rehashed-payload.zip");
    const result = products.importBundle(.{
        .allocator = std.testing.allocator,
        .io = work.io,
        .repository = repository,
        .input = .{ .historical_archive = .{ .path = try work.join("rehashed-payload.zip"), .context = context, .digest = .{ .bytes = digest } } },
        .output = try work.join("rehashed-payload"),
        .tools = tools,
    });
    std.debug.print("fully rehashed historical payload: {any}\n", .{result});
    if (result == .success) {
        result.success.deinit();
        return error.RehashedPayloadAccepted;
    }
    try std.testing.expect(result == .poisoned);
    try std.testing.expectEqual(products.Phase.materialized, result.poisoned.phase);
    try std.testing.expectEqual(error.SerialChanged, result.poisoned.err);
    try std.testing.expectEqual(files.CommitStatus.not_committed, result.poisoned.publication);
    try work.absent("rehashed-payload/bundle.json");
    try std.testing.expectEqualSlices(u8, &before, &try work.digest("rehashed-payload.zip"));
}

pub fn local(a: std.mem.Allocator, io: std.Io, stage: []const u8, repository: []const u8, tools: controller.import_validator_build.LocalTools) !void {
    const work = try Workspace.init(a, io, "local-private");
    defer work.deinit();
    const directory = try files.Directory.open(io, stage);
    defer directory.close(io);
    var bundle = try controller.accepted_run.PrivateBundle.open(std.testing.allocator, io, &directory, stage, repository, tools, null);
    defer bundle.deinit();
    const receipt = try localReceipt(work, &bundle);
    const manifest_before = try copy.hashRetained(io, &bundle.manifest, handoff.layout.max_json_bytes, null);
    const Fault = enum { admission_collision, candidate_collision, admission_sync, publication_unknown, publication_sync, cancellation, final_revalidation };
    for (if (options.handoff_composition_group == .retention) &.{} else std.enums.values(Fault)) |fault| {
        var step_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer step_arena.deinit();
        const step_a = step_arena.allocator();
        const name = @tagName(fault);
        const output = try work.join(try step_a.print("{s}.json", .{name}));
        const admission = try step_a.print("{s}.admission.json", .{output});
        if (fault == .admission_collision or fault == .candidate_collision)
            try work.put(work.relative(if (fault == .admission_collision) admission else output), "foreign candidate product\n");
        var signal = try core.process.SignalCancellation.install();
        defer signal.deinit();
        const result = candidate.Test.create(.{
            .allocator = std.testing.allocator,
            .io = io,
            .source = .{ .private_bundle = &bundle },
            .output = output,
            .validation_output = try work.join(try step_a.print("{s}-validation", .{name})),
            .settings = .{ .attempt_id = "00000000-0000-4000-8000-000000000001" },
            .signal = &signal,
        }, .{
            .admission = if (fault == .admission_sync) .after_rename else null,
            .publication = switch (fault) {
                .publication_unknown => .publication,
                .publication_sync => .after_rename,
                else => null,
            },
            .cancel_after_admission = fault == .cancellation,
            .change_before_final_revalidation = fault == .final_revalidation,
        });
        std.debug.print("local private candidate composition {s}: {any}\n", .{ name, result });
        if (result == .success) {
            result.success.deinit();
            return error.CandidateFaultAccepted;
        }
        try std.testing.expect(result == .poisoned);
        try std.testing.expectEqual(switch (fault) {
            .admission_collision, .admission_sync, .cancellation => candidate.Phase.admission,
            .final_revalidation => .final_revalidation,
            else => .publication,
        }, result.poisoned.phase);
        try std.testing.expectEqual(switch (fault) {
            .admission_collision, .candidate_collision => error.PathAlreadyExists,
            .cancellation => error.Cancelled,
            .final_revalidation => error.FileChanged,
            else => error.PublicationUncertain,
        }, result.poisoned.err);
        try std.testing.expectEqual(switch (fault) {
            .publication_unknown => files.CommitStatus.publication_unknown,
            .publication_sync => .visible_not_durable,
            .final_revalidation => .durable,
            else => .not_committed,
        }, result.poisoned.publication);
        @constCast(signal.flag()).store(false, .release);
        try bundle.revalidate(null);
        try std.testing.expectEqualSlices(u8, &manifest_before, &try copy.hashRetained(io, &bundle.manifest, handoff.layout.max_json_bytes, null));
        if (fault == .admission_collision or fault == .candidate_collision)
            try std.testing.expectEqualStrings("foreign candidate product\n", try work.read(work.relative(if (fault == .admission_collision) admission else output)));
        if (fault != .admission_collision) {
            var document = try handoff.contracts.parseCanonical(step_a, try work.read(work.relative(admission)));
            defer document.deinit();
            try handoff.contracts.validateDirectComputeAdmissionV2(document.value());
        }
        if (fault != .candidate_collision and fault != .publication_sync and fault != .final_revalidation)
            try work.absent(work.relative(output));
    }
    const finalized = candidate.create(.{
        .allocator = std.testing.allocator,
        .io = io,
        .source = .{ .private_bundle = &bundle },
        .output = try work.join("candidate.json"),
        .validation_output = try work.join("success-validation"),
        .settings = .{ .attempt_id = "00000000-0000-4000-8000-000000000001" },
    });
    if (finalized != .success) std.debug.print("local private candidate: {any}\n", .{finalized});
    try std.testing.expect(finalized == .success);
    defer finalized.success.deinit();
    try std.testing.expect((try finalized.success.inspect(null)).authority == .not_admitted);
    if (options.handoff_composition_group != .retention)
        try serialCases(work, finalized.success, stage);
    if (options.handoff_composition_group == .faults) return;
    try privateLineage(work, &bundle, repository, tools);
    try cliCollision(work, stage, repository, tools);
    try exactDownloadAndReopen(work, receipt, &bundle, repository, tools);
    try changedInputs(work, finalized.success, &bundle, repository, tools);
}

const LocalReceipt = struct {
    context: archive.Context,
    inner: [32]u8,
    container: [32]u8,
};

fn localReceipt(work: Workspace, bundle: *controller.accepted_run.PrivateBundle) !LocalReceipt {
    var bytes = try files.readSensitiveFile(work.io, work.a, bundle.manifest.file, handoff.layout.max_json_bytes, .private);
    defer bytes.deinit();
    var document = try handoff.contracts.parseCanonical(work.a, bytes.bytes());
    defer document.deinit();
    const value = document.value().object;
    const run = value.get("run").?.object;
    const context: archive.Context = .{
        .repository = try work.a.dupe(u8, run.get("repository").?.string),
        .run_id = try work.a.dupe(u8, run.get("run_id").?.string),
        .run_attempt = try work.a.dupe(u8, run.get("run_attempt").?.string),
        .source_revision = bundle.evidence.source.revision,
        .source_tree = bundle.evidence.source.tree,
        .wamr_revision = controller.custody_limits.historical_wamr_revision,
    };
    var metadata = try archive.Metadata.fromRootBound(work.a, bytes.bytes(), bundle.evidence.root, context);
    defer metadata.deinit();
    const inner = try writeArchive(work, "local-inner.zip", bundle.evidence.root, &metadata, null);
    const source = try work.root.openFile(work.io, "local-inner.zip", .{});
    defer source.close(work.io);
    var reader = source.reader(work.io, &.{});
    const entry: zip.Entry = .{
        .name = handoff.public_transport.filename,
        .reader = &reader.interface,
        .size = (try source.stat(work.io)).size,
        .crc32 = try fileCrc(work.io, source, (try source.stat(work.io)).size),
        .sha256 = inner,
        .limit = handoff.layout.max_total_bytes,
    };
    const container = try work.root.createFile(work.io, "local-container.zip", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer container.close(work.io);
    var buffer: [64 * 1024]u8 = undefined;
    var writer = container.writer(work.io, &buffer);
    var container_digest: [32]u8 = undefined;
    try zip.writeArchive(&writer.interface, &.{entry}, &container_digest);
    try writer.flush();
    try container.sync(work.io);
    // A private fixture receipt is not a public CI producer or Download owner.
    // Candidate observation remains not_admitted, with a private_bundle source.
    const receipt = try canonical(work.a, .{
        .schema = "uk.wamr.public-source-transport",
        .version = @as(u8, 2),
        .artifact_id = "1",
        .repository = context.repository,
        .run_id = context.run_id,
        .run_attempt = context.run_attempt,
        .source_revision = context.source_revision,
        .source_tree = context.source_tree,
        .inner_zip_sha256 = std.fmt.bytesToHex(inner, .lower),
        .container_digest = std.fmt.bytesToHex(container_digest, .lower),
    });
    const file = try std.Io.Dir.cwd().createFile(work.io, try std.fs.path.join(work.a, &.{ bundle.evidence.root, "transport.json" }), .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(work.io);
    try file.writePositionalAll(work.io, receipt, 0);
    try file.sync(work.io);
    return .{
        .context = context,
        .inner = inner,
        .container = container_digest,
    };
}

fn exactDownloadAndReopen(
    work: Workspace,
    receipt: LocalReceipt,
    bundle: *controller.accepted_run.PrivateBundle,
    repository: []const u8,
    tools: controller.import_validator_build.LocalTools,
) !void {
    {
        const reopened = candidate.open(.{
            .allocator = std.testing.allocator,
            .io = work.io,
            .source = .{ .private_bundle = bundle },
            .output = try work.join("candidate.json"),
            .validation_output = try work.join("reopen-private-validation"),
        });
        if (reopened != .success) std.debug.print("reopen private candidate: {any}\n", .{reopened});
        try std.testing.expect(reopened == .success);
        defer reopened.success.deinit();
        const inspect = try reopened.success.inspect(null);
        try std.testing.expectEqual(@as(u8, 2), inspect.version);
        try std.testing.expectEqual(.not_admitted, inspect.authority);
        const meta = try reopened.success.metadata(null);
        try std.testing.expectEqual(.private_bundle, meta.source);
        try std.testing.expectEqual(@as(u8, 2), meta.scope.version);
        try std.testing.expectEqualStrings("1", meta.provenance.artifact_id);
    }

    const artifact_id = try handoff.public_transport.ArtifactId.parse("1");
    const upload: handoff.public_transport.UploadMetadata = .{
        .context = receipt.context,
        .artifact_id = artifact_id,
        .container_digest = .{ .bytes = receipt.container },
    };
    const expected: handoff.public_transport.Expected = .{
        .upload = upload,
        .inner_digest = .{ .bytes = receipt.inner },
    };
    const retained = handoff.public_transport.actions_container.retainDownload(.{
        .allocator = std.testing.allocator,
        .io = work.io,
        .container_path = try work.join("local-container.zip"),
        .output_path = try work.join("local-download"),
        .expected = expected,
        .selection = .{ .upload = upload },
    });
    if (retained != .success) std.debug.print("retain local download: {any}\n", .{retained});
    try std.testing.expect(retained == .success);
    var retained_download = retained.success;
    defer retained_download.deinit(work.io);
    try retained_download.revalidate(work.io, null);

    const imported = products.importBundle(.{
        .allocator = std.testing.allocator,
        .io = work.io,
        .repository = repository,
        .input = .{ .exact_download = .{
            .path = try work.join("local-download"),
            .container_path = try work.join("local-container.zip"),
            .expected = expected,
            .selection = .{ .upload = upload },
        } },
        .output = try work.join("local-imported"),
        .tools = tools,
    });
    if (imported != .success) std.debug.print("exact download import: {any}\n", .{imported});
    try std.testing.expect(imported == .success);
    const owner = imported.success;
    defer owner.deinit();
    try owner.revalidate(null);

    const created = candidate.create(.{
        .allocator = std.testing.allocator,
        .io = work.io,
        .source = .{ .imported_product = owner },
        .output = try work.join("imported-candidate.json"),
        .validation_output = try work.join("imported-candidate-validation"),
        .settings = .{ .attempt_id = "00000000-0000-4000-8000-000000000001" },
    });
    if (created != .success) std.debug.print("imported v2 candidate create: {any}\n", .{created});
    try std.testing.expect(created == .success);
    defer created.success.deinit();
    const created_meta = try created.success.metadata(null);
    try std.testing.expectEqual(.imported_product, created_meta.source);
    try std.testing.expectEqual(@as(u8, 2), created_meta.scope.version);
    try std.testing.expectEqualStrings("1", created_meta.provenance.artifact_id);

    const reopened = candidate.open(.{
        .allocator = std.testing.allocator,
        .io = work.io,
        .source = .{ .imported_product = owner },
        .output = try work.join("imported-candidate.json"),
        .validation_output = try work.join("imported-candidate-open-validation"),
    });
    if (reopened != .success) std.debug.print("imported v2 candidate open: {any}\n", .{reopened});
    try std.testing.expect(reopened == .success);
    defer reopened.success.deinit();
    const reopened_inspect = try reopened.success.inspect(null);
    try std.testing.expectEqual(@as(u8, 2), reopened_inspect.version);
    try std.testing.expectEqual(.not_admitted, reopened_inspect.authority);
    const reopened_meta = try reopened.success.metadata(null);
    try std.testing.expectEqual(.imported_product, reopened_meta.source);
    try std.testing.expectEqual(@as(u8, 2), reopened_meta.scope.version);
    try std.testing.expectEqualStrings("1", reopened_meta.provenance.artifact_id);
    _ = try reopened.success.result(try std.fs.path.join(work.a, &.{ owner.bundle.?.evidence.root, "boots/raw-x2apic/serial" }), null, null);

    // Tampering with the admission sidecar before candidate.open poisons at .admission.
    {
        var admission_doc = try handoff.contracts.parseCanonical(work.a, try work.read("imported-candidate.json.admission.json"));
        defer admission_doc.deinit();
        const public_bundle = admission_doc.value().object.get("public_bundle").?.object;
        public_bundle.getPtr("size").?.* = .{ .integer = public_bundle.get("size").?.integer + 1 };
        const tampered_admission = try canonical(work.a, admission_doc.value());
        try work.put("tampered-admission.json.admission.json", tampered_admission);

        var candidate_doc = try handoff.contracts.parseCanonical(work.a, try work.read("imported-candidate.json"));
        defer candidate_doc.deinit();
        const bundle_ref = candidate_doc.value().object.get("bundle").?.object;
        bundle_ref.getPtr("path").?.* = .{ .string = try work.join("tampered-admission.json.admission.json") };
        const candidate_bytes = try canonical(work.a, candidate_doc.value());
        try work.put("tampered-admission.json", candidate_bytes);

        const bad_admission = candidate.open(.{
            .allocator = std.testing.allocator,
            .io = work.io,
            .source = .{ .imported_product = owner },
            .output = try work.join("tampered-admission.json"),
            .validation_output = try work.join("tampered-admission-validation"),
        });
        if (bad_admission == .success) {
            bad_admission.success.deinit();
            return error.TamperedAdmissionAccepted;
        }
        try std.testing.expect(bad_admission == .poisoned);
        try std.testing.expectEqual(candidate.Phase.admission, bad_admission.poisoned.phase);
        try std.testing.expectEqual(error.CandidateBindingChanged, bad_admission.poisoned.err);
        try std.testing.expectEqual(files.CommitStatus.not_committed, bad_admission.poisoned.publication);
        try std.testing.expectEqualStrings(tampered_admission, try work.read("tampered-admission.json.admission.json"));
    }

    // Tampering with the candidate record while preserving the valid admission sidecar poisons at .publication.
    {
        const admission_bytes = try work.read("imported-candidate.json.admission.json");
        try work.put("tampered-candidate.json.admission.json", admission_bytes);

        var candidate_doc = try handoff.contracts.parseCanonical(work.a, try work.read("imported-candidate.json"));
        defer candidate_doc.deinit();
        const bundle_ref = candidate_doc.value().object.get("bundle").?.object;
        bundle_ref.getPtr("path").?.* = .{ .string = try work.join("tampered-candidate.json.admission.json") };
        const vhd_ref = candidate_doc.value().object.get("os_vhd").?.object;
        vhd_ref.getPtr("sha256").?.* = .{ .string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
        const tampered_candidate = try canonical(work.a, candidate_doc.value());
        try work.put("tampered-candidate.json", tampered_candidate);

        const bad_candidate = candidate.open(.{
            .allocator = std.testing.allocator,
            .io = work.io,
            .source = .{ .imported_product = owner },
            .output = try work.join("tampered-candidate.json"),
            .validation_output = try work.join("tampered-candidate-validation"),
        });
        if (bad_candidate == .success) {
            bad_candidate.success.deinit();
            return error.TamperedCandidateAccepted;
        }
        try std.testing.expect(bad_candidate == .poisoned);
        try std.testing.expectEqual(candidate.Phase.publication, bad_candidate.poisoned.phase);
        try std.testing.expectEqual(error.CandidateBindingChanged, bad_candidate.poisoned.err);
        try std.testing.expectEqual(files.CommitStatus.not_committed, bad_candidate.poisoned.publication);
        try std.testing.expectEqualStrings(tampered_candidate, try work.read("tampered-candidate.json"));
    }
}

fn overwrite(io: std.Io, path: []const u8, bytes: []const u8) !void {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write, .follow_symlinks = false });
    defer file.close(io);
    try file.setLength(io, bytes.len);
    try file.writePositionalAll(io, bytes, 0);
    try file.sync(io);
}

fn rehashRecord(work: Workspace, stage: []const u8, manifest: std.json.Value, filename: []const u8, role: []const u8, record: std.json.Value) ![]const u8 {
    const bytes = try canonical(work.a, record);
    const digest = try work.a.dupe(u8, &std.fmt.bytesToHex(zip.sha256(bytes), .lower));
    const evidence = try std.fs.path.join(work.a, &.{ stage, "evidence", filename });
    const artifact = try std.fs.path.join(work.a, &.{ stage, "artifacts", role });
    try overwrite(work.io, evidence, bytes);
    try overwrite(work.io, artifact, bytes);
    for ([_][]const u8{ "artifacts", "evidence" }) |key| {
        for (manifest.object.get(key).?.array.items) |item| {
            const path = item.object.get("path").?.string;
            if (std.mem.eql(u8, path, artifact) or std.mem.eql(u8, path, evidence)) {
                item.object.getPtr("size").?.* = .{ .integer = @intCast(bytes.len) };
                item.object.getPtr("sha256").?.* = .{ .string = digest };
            }
        }
    }
    return digest;
}

fn privateLineage(work: Workspace, source: *controller.accepted_run.PrivateBundle, repository: []const u8, tools: controller.import_validator_build.LocalTools) !void {
    var raw = try files.readSensitiveFile(work.io, work.a, source.manifest.file, handoff.layout.max_json_bytes, .private);
    defer raw.deinit();
    var document = try handoff.contracts.parseCanonical(work.a, raw.bytes());
    defer document.deinit();
    const value = document.value().object;
    const run = value.get("run").?.object;
    var metadata = try archive.Metadata.fromRootBound(work.a, raw.bytes(), source.evidence.root, .{
        .repository = run.get("repository").?.string,
        .run_id = run.get("run_id").?.string,
        .run_attempt = run.get("run_attempt").?.string,
        .source_revision = source.evidence.source.revision,
        .source_tree = source.evidence.source.tree,
        .wamr_revision = controller.custody_limits.historical_wamr_revision,
    });
    defer metadata.deinit();
    try work.root.createDir(work.io, "lineage-stage", .fromMode(0o700));
    const stage = try work.join("lineage-stage");
    const directory = try files.Directory.open(work.io, stage);
    defer directory.close(work.io);
    var budget: copy.Budget = .{};
    for (metadata.selected) |member| {
        var input = try files.RetainedFile.open(work.io, try std.fs.path.join(work.a, &.{ source.evidence.root, member.name }), .private);
        defer input.close(work.io);
        const copied = try copy.copyRetained(work.a, work.io, &input, directory.dir, stage, member.name, member.limit, &budget, .{});
        try std.testing.expectEqualSlices(u8, &std.fmt.bytesToHex(member.sha256, .lower), &copied.sha256);
    }
    const original = try metadata.rootBoundBundle(work.a, stage);
    try work.put("lineage-stage/bundle.json", original);
    {
        var accepted = try controller.accepted_run.PrivateBundle.open(std.testing.allocator, work.io, &directory, stage, repository, tools, null);
        defer accepted.deinit();
        try accepted.revalidate(null);
    }
    var manifest = try handoff.contracts.parseCanonical(work.a, original);
    defer manifest.deinit();
    var acceptance = try handoff.contracts.parseCanonical(work.a, try work.read("lineage-stage/evidence/qcow2-acceptance.json"));
    defer acceptance.deinit();
    acceptance.value().object.get("accepted_qcow2").?.object.getPtr("sha256").?.* =
        .{ .string = "0000000000000000000000000000000000000000000000000000000000000000" };
    const acceptance_hash = try rehashRecord(work, stage, manifest.value(), "qcow2-acceptance.json", "qcow2_acceptance", acceptance.value());
    var gate = try handoff.contracts.parseCanonical(work.a, try work.read("lineage-stage/evidence/fixed-vhd-derivation-gate.json"));
    defer gate.deinit();
    gate.value().object.getPtr("qcow2_acceptance_sha256").?.* = .{ .string = acceptance_hash };
    const gate_hash = try rehashRecord(work, stage, manifest.value(), "fixed-vhd-derivation-gate.json", "fixed_vhd_derivation_gate", gate.value());
    var inspection = try handoff.contracts.parseCanonical(work.a, try work.read("lineage-stage/evidence/final-inspection.json"));
    defer inspection.deinit();
    const inspection_records = inspection.value().object.get("records").?.object;
    inspection_records.getPtr("qcow2-acceptance.json").?.* = .{ .string = acceptance_hash };
    inspection_records.getPtr("fixed-vhd-derivation-gate.json").?.* = .{ .string = gate_hash };
    const inspection_hash = try rehashRecord(work, stage, manifest.value(), "final-inspection.json", "final_inspection", inspection.value());
    var result = try handoff.contracts.parseCanonical(work.a, try work.read("lineage-stage/artifacts/local_result"));
    defer result.deinit();
    const records = result.value().object.get("records").?.object;
    records.getPtr("qcow2-acceptance.json").?.* = .{ .string = acceptance_hash };
    records.getPtr("fixed-vhd-derivation-gate.json").?.* = .{ .string = gate_hash };
    records.getPtr("final-inspection.json").?.* = .{ .string = inspection_hash };
    const result_bytes = try canonical(work.a, result.value());
    try overwrite(work.io, try work.join("lineage-stage/artifacts/local_result"), result_bytes);
    for (manifest.value().object.get("artifacts").?.array.items) |item| {
        if (std.mem.eql(u8, std.fs.path.basename(item.object.get("path").?.string), "local_result")) {
            item.object.getPtr("size").?.* = .{ .integer = @intCast(result_bytes.len) };
            item.object.getPtr("sha256").?.* = .{ .string = try work.a.dupe(u8, &std.fmt.bytesToHex(zip.sha256(result_bytes), .lower)) };
        }
    }
    const lineage = manifest.value().object.get("lineage").?.object;
    lineage.getPtr("qcow2_acceptance_sha256").?.* = .{ .string = acceptance_hash };
    lineage.getPtr("fixed_vhd_derivation_gate_sha256").?.* = .{ .string = gate_hash };
    lineage.getPtr("final_inspection_sha256").?.* = .{ .string = inspection_hash };
    const rehashed = try canonical(work.a, manifest.value());
    try overwrite(work.io, try work.join("lineage-stage/bundle.json"), rehashed);
    var envelope = try handoff.contracts.parseCanonical(work.a, rehashed);
    defer envelope.deinit();
    _ = try handoff.contracts.validateLocalImageHandoffWithRoot(envelope.value(), stage);
    // The native image-output hash comparison preserves EvidenceChanged.
    try std.testing.expectError(error.EvidenceChanged, controller.accepted_run.PrivateBundle.open(std.testing.allocator, work.io, &directory, stage, repository, tools, null));
    try std.testing.expectEqualStrings(rehashed, try work.read("lineage-stage/bundle.json"));
    try source.revalidate(null);
}

fn serialCases(work: Workspace, owner: *candidate.Finalized, stage: []const u8) !void {
    const serial = try std.Io.Dir.cwd().readFileAlloc(work.io, try std.fs.path.join(work.a, &.{ stage, "boots/raw-x2apic/serial" }), work.a, .limited(handoff.layout.max_serial_bytes));
    try work.put("first", serial);
    try work.put("padded-first", try std.mem.concat(work.a, u8, &.{ serial, "\x00\x00" }));
    try work.put("second", try std.mem.concat(work.a, u8, &.{ serial, serial, "\x00\x00" }));
    try work.put("unchanged", serial);
    try work.put("empty", "");
    try work.put("incomplete", "Calling main(0, 0)\n");
    try work.put("changed-prefix", try std.mem.concat(work.a, u8, &.{ "changed\n", serial }));
    const overflow = try work.root.createFile(work.io, "overflow", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    try overflow.setLength(work.io, handoff.layout.max_serial_bytes + 1);
    overflow.close(work.io);
    _ = try owner.result(try work.join("first"), null, null);
    _ = try owner.result(try work.join("padded-first"), try work.join("second"), null);
    for ([_]struct { first: []const u8, second: ?[]const u8 = null, err: anyerror }{
        .{ .first = "empty", .err = error.EvidenceIncomplete },
        .{ .first = "incomplete", .err = error.EvidenceIncomplete },
        .{ .first = "first", .second = "empty", .err = error.WrongSerialPrefix },
        .{ .first = "first", .second = "changed-prefix", .err = error.WrongSerialPrefix },
        .{ .first = "first", .second = "unchanged", .err = error.EvidenceIncomplete },
        .{ .first = "overflow", .err = error.UnsafeSource },
        .{ .first = "first", .second = "overflow", .err = error.UnsafeSource },
    }) |case| {
        std.debug.print("private serial refusal {s}/{s}: {s}\n", .{ case.first, case.second orelse "-", @errorName(case.err) });
        try std.testing.expectError(case.err, owner.result(try work.join(case.first), if (case.second) |second| try work.join(second) else null, null));
    }
    inline for (.{ .change_first, .replace_first, .change_second, .replace_second }) |fault| {
        const first = try work.a.print("{s}-first", .{@tagName(fault)});
        const second = try work.a.print("{s}-second", .{@tagName(fault)});
        try work.put(first, serial);
        try work.put(second, try std.mem.concat(work.a, u8, &.{ serial, serial }));
        try std.testing.expectError(error.FileChanged, candidate.Test.result(owner, try work.join(first), try work.join(second), null, fault));
        if (fault == .replace_first or fault == .replace_second) {
            const saved = try work.a.print("{s}.retained-original", .{if (fault == .replace_first) first else second});
            try std.testing.expectEqualStrings(if (fault == .replace_first) serial else try std.mem.concat(work.a, u8, &.{ serial, serial }), try work.read(saved));
        }
        try owner.revalidate(null);
    }
}

fn createCandidate(work: Workspace, name: []const u8, bundle: *controller.accepted_run.PrivateBundle) !*candidate.Finalized {
    const result = candidate.create(.{
        .allocator = std.testing.allocator,
        .io = work.io,
        .source = .{ .private_bundle = bundle },
        .output = try work.join(try work.a.print("{s}/candidate.json", .{name})),
        .validation_output = try work.join(try work.a.print("{s}-validation", .{name})),
        .settings = .{ .attempt_id = "00000000-0000-4000-8000-000000000001" },
    });
    if (result != .success) std.debug.print("changed input candidate {s}: {any}\n", .{ name, result });
    try std.testing.expect(result == .success);
    return result.success;
}

fn cliCollision(work: Workspace, stage: []const u8, repository: []const u8, tools: controller.import_validator_build.LocalTools) !void {
    try work.put("cli-collision.json", "foreign CLI candidate\n");
    const output = try work.join("cli-collision.json");
    const result = try std.process.run(work.a, work.io, .{
        .argv = &.{
            options.host_controller_cli, "candidate",     "--bundle",            try std.fs.path.join(work.a, &.{ stage, "bundle.json" }),
            "--output",                  output,          "--validation-output", try work.join("cli-collision-validation"),
            "--git",                     tools.git,       "--supervisor",        options.host_controller_cli,
            "--validator",               tools.validator, "--attempt-id",        "00000000-0000-4000-8000-000000000001",
        },
        .cwd = .{ .path = repository },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
    try std.testing.expectEqualStrings("", result.stdout);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "candidate/publication; cause: PathAlreadyExists; publication: not_committed") != null);
    try std.testing.expectEqualStrings("foreign CLI candidate\n", try work.read("cli-collision.json"));
    var admission = try handoff.contracts.parseCanonical(work.a, try work.read("cli-collision.json.admission.json"));
    defer admission.deinit();
    try handoff.contracts.validateDirectComputeAdmissionV2(admission.value());
}

fn changedInputs(work: Workspace, owner: *candidate.Finalized, bundle: *controller.accepted_run.PrivateBundle, repository: []const u8, tools: controller.import_validator_build.LocalTools) !void {
    const artifact = try owner.artifact(null);
    try work.root.renamePreserve("candidate.json", work.root, "saved-candidate.json", work.io);
    try work.put("candidate.json", try work.read("saved-candidate.json"));
    try std.testing.expectError(error.FileChanged, owner.revalidate(null));
    try std.testing.expectEqualStrings(try work.read("saved-candidate.json"), try work.read("candidate.json"));
    try std.testing.expectEqualStrings(artifact.path, try work.join("candidate.json"));
    {
        try work.root.createDir(work.io, "changed-parent", .fromMode(0o700));
        const parent_owner = try createCandidate(work, "changed-parent", bundle);
        defer parent_owner.deinit();
        try work.root.renamePreserve("changed-parent", work.root, "retained-parent", work.io);
        try work.root.createDir(work.io, "changed-parent", .fromMode(0o700));
        inline for (.{ "candidate.json", "candidate.json.admission.json" }) |name| {
            const retained = try work.read("retained-parent/" ++ name);
            try work.put("changed-parent/" ++ name, retained);
        }
        try std.testing.expectError(error.FileChanged, parent_owner.revalidate(null));
        try std.testing.expectEqualStrings(try work.read("retained-parent/candidate.json"), try work.read("changed-parent/candidate.json"));
        try bundle.revalidate(null);
    }
    {
        try work.root.createDir(work.io, "changed-executable", .fromMode(0o700));
        const executable_owner = try createCandidate(work, "changed-executable", bundle);
        defer executable_owner.deinit();
        const saved = try work.a.print("{s}.composition-original", .{tools.git});
        try std.Io.Dir.cwd().renamePreserve(tools.git, .cwd(), saved, work.io);
        const bytes = try std.Io.Dir.cwd().readFileAlloc(work.io, saved, work.a, .limited(64 * 1024 * 1024));
        const replacement = try std.Io.Dir.cwd().createFile(work.io, tools.git, .{ .exclusive = true, .permissions = .fromMode(0o700) });
        defer replacement.close(work.io);
        try replacement.writePositionalAll(work.io, bytes, 0);
        try replacement.sync(work.io);
        try std.testing.expectError(error.FileChanged, executable_owner.revalidate(null));
        try std.testing.expectEqualStrings(bytes, try std.Io.Dir.cwd().readFileAlloc(work.io, tools.git, work.a, .limited(64 * 1024 * 1024)));
    }
    const directory = try files.Directory.open(work.io, bundle.evidence.root);
    defer directory.close(work.io);
    var fresh_source = try controller.accepted_run.PrivateBundle.open(std.testing.allocator, work.io, &directory, bundle.evidence.root, repository, tools, null);
    defer fresh_source.deinit();
    try work.root.createDir(work.io, "changed-source", .fromMode(0o700));
    const source_owner = try createCandidate(work, "changed-source", &fresh_source);
    defer source_owner.deinit();
    const manifest = try std.Io.Dir.cwd().openFile(work.io, fresh_source.manifest.path, .{ .mode = .read_write, .follow_symlinks = false });
    defer manifest.close(work.io);
    try manifest.writePositionalAll(work.io, "!", 0);
    try manifest.sync(work.io);
    try std.testing.expectError(error.FileChanged, fresh_source.revalidate(null));
    try std.testing.expectError(error.FileChanged, source_owner.revalidate(null));
}
