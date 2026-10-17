// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const controller = @import("wamr_controller");
const handoff = @import("wamr_handoff");
const authority = @import("wamr_authority");
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
        try cliHistoricalBundleAndCandidate(work, repository, tools, context, input_digest);
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

    {
        var parsed_plan = try authority.cli.parse(work.a, &.{
            "plan",
            "--bundle",                           try work.join("success/bundle.json"),
            "--output",                           try work.join("historical-refused-plan.json"),
            "--approval-template",                try work.join("historical-refused-template.json"),
            "--candidate-output",                 try work.join("historical-candidate.json"),
            "--campaign-id",                      "00000000-0000-4000-8000-000000000010",
            "--ledger",                           try work.join("historical-refused-ledger"),
            "--subscription",                     "00000000-0000-4000-8000-000000000004",
            "--prefix",                           "ukwamr",
            "--maximum-authorized-cost-microusd", "15000000",
            "--attempt-id",                       "00000000-0000-4000-8000-000000000001",
            "--ledger-id",                        "00000000-0000-4000-8000-000000000020",
            "--azure-runtime",                    try work.join("historical-candidate.json"),
            "--azure",                            options.command_fixture,
            "--uploader",                         options.command_fixture,
            "--validator",                        options.command_fixture,
            "--supervisor",                       options.host_controller_cli,
            "--az-python",                        options.python_executable,
        });
        defer parsed_plan.deinit();
        const v1_plan = authority.handlers.run(
            .{
                .retained = .{ .allocator = std.testing.allocator, .io = work.io },
                .live_finalized = reopened.success,
            },
            parsed_plan.result.command,
        );
        try std.testing.expect(v1_plan.plan == .refused);
        try std.testing.expectEqual(authority.types.Phase.custody, v1_plan.plan.refused.phase);
        try std.testing.expectEqual(error.Version2Required, v1_plan.plan.refused.err);
        try std.testing.expectEqual(authority.plan.Publications{}, v1_plan.plan.refused.outputs);
        try work.absent("historical-refused-plan.json");
        try work.absent("historical-refused-template.json");
    }

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

fn cliHistoricalBundleAndCandidate(
    work: Workspace,
    repository: []const u8,
    tools: controller.import_validator_build.LocalTools,
    context: archive.Context,
    input_digest: [64]u8,
) !void {
    const input_archive = try work.join("input.zip");
    const import_pinned_res = try std.process.run(work.a, work.io, .{
        .argv = &.{
            options.host_controller_cli,  "import-public-source-bundle",
            "--archive",                  input_archive,
            "--output",                   try work.join("cli-historical-imported"),
            "--git",                      tools.git,
            "--supervisor",               options.host_controller_cli,
            "--validator",                tools.validator,
            "--expected-source",          context.source_revision,
            "--expected-tree",            context.source_tree,
            "--run-id",                   context.run_id,
            "--run-attempt",              context.run_attempt,
            "--expected-archive-sha256",  input_digest[0..],
        },
        .cwd = .{ .path = repository },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, import_pinned_res.term);
    try std.testing.expectEqualStrings("Public source handoff imported; authority=not_admitted.\n", import_pinned_res.stdout);
    try std.testing.expectEqualStrings("", import_pinned_res.stderr);

    const import_unpinned_res = try std.process.run(work.a, work.io, .{
        .argv = &.{
            options.host_controller_cli, "import-public-source-bundle",
            "--archive",                 input_archive,
            "--output",                  try work.join("cli-historical-imported-unpinned"),
            "--git",                     tools.git,
            "--supervisor",              options.host_controller_cli,
            "--validator",               tools.validator,
            "--expected-source",         context.source_revision,
            "--expected-tree",           context.source_tree,
            "--run-id",                  context.run_id,
            "--run-attempt",             context.run_attempt,
        },
        .cwd = .{ .path = repository },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, import_unpinned_res.term);
    try std.testing.expectEqualStrings("Public source handoff imported; authority=not_admitted.\n", import_unpinned_res.stdout);
    try std.testing.expectEqualStrings("", import_unpinned_res.stderr);
    try std.testing.expectEqualSlices(u8, &try work.digest("success/portable-bundle.json"), &try work.digest("cli-historical-imported/portable-bundle.json"));
    try std.testing.expectEqualSlices(u8, &try work.digest("cli-historical-imported/portable-bundle.json"), &try work.digest("cli-historical-imported-unpinned/portable-bundle.json"));
    try std.testing.expectEqualSlices(u8, &try work.digest("success/public-source.json"), &try work.digest("cli-historical-imported/public-source.json"));
    try std.testing.expectEqualSlices(u8, &try work.digest("cli-historical-imported/public-source.json"), &try work.digest("cli-historical-imported-unpinned/public-source.json"));

    const bundle_path = try work.join("cli-historical-imported/bundle.json");
    const candidate_path = try work.join("cli-historical-candidate.json");
    const create_res = try std.process.run(work.a, work.io, .{
        .argv = &.{
            options.host_controller_cli, "candidate",
            "--bundle",                  bundle_path,
            "--output",                  candidate_path,
            "--validation-output",       try work.join("cli-historical-candidate-validation"),
            "--git",                     tools.git,
            "--supervisor",              options.host_controller_cli,
            "--validator",               tools.validator,
            "--attempt-id",              "00000000-0000-4000-8000-000000000099",
        },
        .cwd = .{ .path = repository },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, create_res.term);
    try std.testing.expectEqualStrings("Compute candidate created; authority=not_admitted.\n", create_res.stdout);
    try std.testing.expectEqualStrings("", create_res.stderr);

    const inspect_res = try std.process.run(work.a, work.io, .{
        .argv = &.{
            options.host_controller_cli, "candidate-inspect",
            "--bundle",                  bundle_path,
            "--candidate",               candidate_path,
            "--validation-output",       try work.join("cli-historical-candidate-inspect-validation"),
            "--git",                     tools.git,
            "--supervisor",              options.host_controller_cli,
            "--validator",               tools.validator,
        },
        .cwd = .{ .path = repository },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, inspect_res.term);
    try std.testing.expectEqualStrings("Compute candidate revalidated; authority=not_admitted.\n", inspect_res.stdout);
    try std.testing.expectEqualStrings("", inspect_res.stderr);

    const wrong_bundle_res = try std.process.run(work.a, work.io, .{
        .argv = &.{
            options.host_controller_cli, "candidate-inspect",
            "--bundle",                  try work.join("success/bundle.json"),
            "--candidate",               candidate_path,
            "--validation-output",       try work.join("cli-historical-candidate-wrong-bundle-validation"),
            "--git",                     tools.git,
            "--supervisor",              options.host_controller_cli,
            "--validator",               tools.validator,
        },
        .cwd = .{ .path = repository },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(8192),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, wrong_bundle_res.term);
    try std.testing.expectEqualStrings("", wrong_bundle_res.stdout);
    try std.testing.expect(std.mem.indexOf(u8, wrong_bundle_res.stderr, "CandidateBindingChanged") != null);

    const result_res = try std.process.run(work.a, work.io, .{
        .argv = &.{
            options.host_controller_cli, "candidate-result",
            "--bundle",                  bundle_path,
            "--candidate",               candidate_path,
            "--validation-output",       try work.join("cli-historical-candidate-result-validation"),
            "--git",                     tools.git,
            "--supervisor",              options.host_controller_cli,
            "--validator",               tools.validator,
            "--serial-first",            try work.join("cli-historical-imported/boots/raw-x2apic/serial"),
        },
        .cwd = .{ .path = repository },
        .stdout_limit = .limited(16384),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result_res.term);
    try std.testing.expectEqualStrings("", result_res.stderr);
    const parsed_result = try std.json.parseFromSlice(controller.tiny.Result, work.a, std.mem.trim(u8, result_res.stdout, "\n"), .{ .allocate = .alloc_always });
    try std.testing.expectEqual(@as(i32, 42), parsed_result.value.answer);
    try std.testing.expectEqual(@as(u32, 2), parsed_result.value.checks);
    try std.testing.expectEqual(@as(i32, 0), parsed_result.value.platform_status);
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
    try cliPublicAndCandidateComposition(work, receipt, stage, repository, tools);
    try exactDownloadAndReopen(work, receipt, &bundle, finalized.success, repository, tools);
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
    private_candidate: *candidate.Finalized,
    repository: []const u8,
    tools: controller.import_validator_build.LocalTools,
) !void {
    {
        const private_reopened = candidate.open(.{
            .allocator = std.testing.allocator,
            .io = work.io,
            .source = .{ .private_bundle = bundle },
            .output = try work.join("candidate.json"),
            .validation_output = try work.join("reopen-private-validation"),
        });
        if (private_reopened != .success) std.debug.print("reopen private candidate: {any}\n", .{private_reopened});
        try std.testing.expect(private_reopened == .success);
        defer private_reopened.success.deinit();
        const private_inspect = try private_reopened.success.inspect(null);
        try std.testing.expectEqual(@as(u8, 2), private_inspect.version);
        try std.testing.expectEqual(.not_admitted, private_inspect.authority);
        const private_meta = try private_reopened.success.metadata(null);
        try std.testing.expectEqual(.private_bundle, private_meta.source);
        try std.testing.expectEqual(@as(u8, 2), private_meta.scope.version);
        try std.testing.expectEqualStrings("1", private_meta.provenance.artifact_id);
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
    {
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
    }

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

    try liveImportedAuthorityComposition(work, owner, private_candidate, created.success, tools);

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

fn writeModeFile(io: std.Io, directory: std.Io.Dir, name: []const u8, bytes: []const u8, mode: u32) !void {
    const file = try directory.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    if (std.os.linux.errno(std.os.linux.fchmod(file.handle, mode)) != .SUCCESS) return error.FixtureMode;
    try file.sync(io);
}

fn makeDirectoryRemovable(io: std.Io, directory: std.Io.Dir) !void {
    if (std.os.linux.errno(std.os.linux.fchmod(directory.handle, 0o700)) != .SUCCESS) return error.FixtureMode;
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const child = try directory.openDir(io, entry.name, .{ .iterate = true, .follow_symlinks = false });
        defer child.close(io);
        try makeDirectoryRemovable(io, child);
    }
}

fn liveImportedAuthorityComposition(
    work: Workspace,
    owner: *products.ImportedProduct,
    private_candidate: *candidate.Finalized,
    created_candidate: *candidate.Finalized,
    tools: controller.import_validator_build.LocalTools,
) !void {
    try work.root.createDir(work.io, "authority-work", .fromMode(0o700));
    const authority_dir = try work.root.openDir(work.io, "authority-work", .{ .iterate = true, .follow_symlinks = false });
    defer {
        makeDirectoryRemovable(work.io, authority_dir) catch @panic("authority composition cleanup failed");
        authority_dir.close(work.io);
    }
    for ([_][]const u8{ "runtime-source", "ledger", "records" }) |component|
        try authority_dir.createDir(work.io, component, .fromMode(0o700));

    const ctx: authority.types.Context = .{
        .allocator = std.testing.allocator,
        .io = work.io,
    };
    const tool_paths: authority.types.ToolPaths = blk: {
        const source_dir = try authority_dir.openDir(work.io, "runtime-source", .{ .iterate = true, .follow_symlinks = false });
        defer source_dir.close(work.io);
        for ([_][]const u8{ "python3.11", "packages", "data" }) |component|
            try source_dir.createDir(work.io, component, .fromMode(0o700));
        const loader_source_path = try work.join("authority-work/runtime-source/ld-linux-x86-64.so.2");
        const loader_elf = try syntheticElf(.{ .soname = "ld-linux-x86-64.so.2" });
        const interpreter_elf = try syntheticElf(.{
            .interp = loader_source_path,
            .needed = &.{"libalpha.so"},
        });
        const alpha_elf = try syntheticElf(.{
            .needed = &.{"libbeta.so"},
            .soname = "libalpha.so",
        });
        const beta_elf = try syntheticElf(.{
            .soname = "libbeta.so",
        });
        const ext_elf = try syntheticElf(.{
            .needed = &.{"libbeta.so"},
        });
        try writeModeFile(work.io, source_dir, "launcher", "#!/bin/sh\nexit 0\n", 0o500);
        try writeModeFile(work.io, source_dir, "python", &interpreter_elf, 0o500);
        try writeModeFile(work.io, source_dir, "ld-linux-x86-64.so.2", &loader_elf, 0o500);
        try writeModeFile(work.io, source_dir, "libalpha.so", &alpha_elf, 0o400);
        try writeModeFile(work.io, source_dir, "libbeta.so", &beta_elf, 0o400);
        try writeModeFile(work.io, source_dir, "uploader", "synthetic-uploader\n", 0o500);
        {
            const stdlib = try source_dir.openDir(work.io, "python3.11", .{ .iterate = true });
            defer stdlib.close(work.io);
            try stdlib.createDir(work.io, "encodings", .fromMode(0o700));
            try writeModeFile(work.io, stdlib, "os.py", "synthetic-os\n", 0o600);
            try writeModeFile(work.io, stdlib, "_ext.so", &ext_elf, 0o400);
            const encodings = try stdlib.openDir(work.io, "encodings", .{});
            defer encodings.close(work.io);
            try writeModeFile(work.io, encodings, "__init__.py", "synthetic-encodings\n", 0o600);
        }
        {
            const packages = try source_dir.openDir(work.io, "packages", .{ .iterate = true });
            defer packages.close(work.io);
            try packages.createDir(work.io, "azure", .fromMode(0o700));
            const azure = try packages.openDir(work.io, "azure", .{});
            defer azure.close(work.io);
            try writeModeFile(work.io, azure, "__init__.py", "synthetic-azure\n", 0o600);
        }
        {
            const data = try source_dir.openDir(work.io, "data", .{});
            defer data.close(work.io);
            try writeModeFile(work.io, data, "fixed.txt", "synthetic-data\n", 0o600);
        }

        var interpreter = try files.RetainedFile.open(work.io, try work.join("authority-work/runtime-source/python"), .tool);
        defer interpreter.close(work.io);
        var loader = try files.RetainedFile.open(work.io, loader_source_path, .artifact);
        defer loader.close(work.io);
        var alpha = try files.RetainedFile.open(work.io, try work.join("authority-work/runtime-source/libalpha.so"), .artifact);
        defer alpha.close(work.io);
        var beta = try files.RetainedFile.open(work.io, try work.join("authority-work/runtime-source/libbeta.so"), .artifact);
        defer beta.close(work.io);
        var ext = try files.RetainedFile.open(work.io, try work.join("authority-work/runtime-source/python3.11/_ext.so"), .artifact);
        defer ext.close(work.io);
        const runtime_output_path = try work.join("authority-work/azure-runtime");
        const launcher_source_path = try work.join("authority-work/runtime-source/launcher");
        const python_source_path = try work.join("authority-work/runtime-source/python");
        const stdlib_root = try work.join("authority-work/runtime-source/python3.11");
        const package_root = try work.join("authority-work/runtime-source/packages");
        const data_root = try work.join("authority-work/runtime-source/data");
        const discovery: authority.runtime_probes.DiscoveryInput = .{
            .interpreter = &interpreter,
            .dynamic_loader = &loader,
            .native_roots = &.{&ext},
            .candidates = &.{ &alpha, &beta },
        };

        var parsed_prepare = try authority.cli.parse(std.testing.allocator, &.{
            "prepare-azure-runtime",
            try std.fmt.allocPrint(work.a, "--output={s}", .{runtime_output_path}),
            try std.fmt.allocPrint(work.a, "--azure={s}", .{launcher_source_path}),
            try std.fmt.allocPrint(work.a, "--az-python={s}", .{python_source_path}),
            try std.fmt.allocPrint(work.a, "--stdlib={s}", .{stdlib_root}),
            try std.fmt.allocPrint(work.a, "--validator={s}", .{tools.validator}),
            try std.fmt.allocPrint(work.a, "--package-root={s}", .{package_root}),
            try std.fmt.allocPrint(work.a, "--data-root={s}", .{data_root}),
        });
        defer parsed_prepare.deinit();

        const prepare_outcome = authority.handlers.run(
            .{ .retained = ctx, .discovery = discovery },
            parsed_prepare.result.command,
        ).prepare;
        const prepare_diag = switch (prepare_outcome) {
            .poisoned => |failure| failure,
            .refused => return error.UnexpectedEarlyPrepareRefusal,
            .success => |prepared| {
                prepared.deinit();
                return error.SyntheticRuntimeAccepted;
            },
        };
        try std.testing.expectEqual(authority.types.Phase.validation, prepare_diag.phase);
        try std.testing.expectEqual(files.CommitStatus.durable, prepare_diag.publications.copy);
        try std.testing.expectEqual(files.CommitStatus.durable, prepare_diag.publications.manifest);
        try std.testing.expectEqual(files.CommitStatus.durable, prepare_diag.publications.pending);
        try std.testing.expectEqual(files.CommitStatus.not_committed, prepare_diag.publications.validation);
        try std.testing.expectEqual(files.CommitStatus.not_committed, prepare_diag.publications.output);
        try std.testing.expectEqual(files.CommitStatus.durable, prepare_diag.publications.failure);
        try std.testing.expect(prepare_diag.recording_error == null);
        try std.testing.expectEqual(core.diagnostics.Stage.process_run, prepare_diag.failures.primary.?.stage);
        try std.testing.expectEqual(core.diagnostics.Category.child_failed, prepare_diag.failures.primary.?.category);
        try std.testing.expect(prepare_diag.helper_cleanup_complete);
        try std.testing.expect(prepare_diag.native_validation != null);
        try std.testing.expectEqual(core.process.CommandPrimary{ .exited = 0 }, prepare_diag.native_validation.?.primary);
        try std.testing.expect(prepare_diag.native_validation.?.cleanup_complete);
        try std.testing.expect(prepare_diag.probes != null);
        try std.testing.expectEqual(@as(u8, 0), prepare_diag.probes.?.completed_steps);

        const duplicate_prepare = authority.handlers.run(
            .{ .retained = ctx, .discovery = discovery },
            parsed_prepare.result.command,
        ).prepare;
        try std.testing.expect(duplicate_prepare == .refused);
        try std.testing.expectEqual(error.PathAlreadyExists, duplicate_prepare.refused.err);
        try std.testing.expectEqual(files.CommitStatus.not_committed, duplicate_prepare.refused.publications.copy);

        const runtime_output = try authority_dir.openDir(work.io, "azure-runtime", .{});
        defer runtime_output.close(work.io);
        const pending_bytes = try work.read("authority-work/azure-runtime/azure-runtime.pending.json");
        var parsed_contract = try authority.records.parse(authority.types.runtime.Contract, std.testing.allocator, pending_bytes);
        defer parsed_contract.deinit();
        try std.testing.expectEqual(@as(usize, 3), parsed_contract.value.loader_dependencies.len);
        try std.testing.expectEqual(@as(u16, 3), parsed_contract.value.observed.loader_files);
        try writeModeFile(work.io, runtime_output, "azure-runtime.json", pending_bytes, 0o600);
        break :blk .{
            .azure_runtime = try work.join("authority-work/azure-runtime/azure-runtime.json"),
            .azure = try work.a.dupe(u8, parsed_contract.value.launcher.path),
            .uploader = try work.join("authority-work/runtime-source/uploader"),
            .validator = tools.validator,
            .supervisor = tools.supervisor,
            .az_python = try work.a.dupe(u8, parsed_contract.value.interpreter.path),
        };
    };

    const created_meta = try created_candidate.metadata(null);
    const base_plan: authority.types.PlanCommand = .{
        .bundle = created_meta.provenance.public_bundle.path,
        .output = try work.join("authority-work/records/plan.json"),
        .approval_template = try work.join("authority-work/records/template.json"),
        .candidate_output = created_meta.candidate.path,
        .campaign_id = "00000000-0000-4000-8000-000000000010",
        .ledger = try work.join("authority-work/ledger"),
        .subscription = created_meta.scope.subscription,
        .prefix = created_meta.scope.prefix,
        .maximum_authorized_cost_microusd = 15_000_000,
        .attempt_id = created_meta.scope.attempt_id,
        .ledger_id = "00000000-0000-4000-8000-000000000020",
        .tools = tool_paths,
    };

    // A private_bundle candidate is refused before any plan or template publication.
    {
        const private_plan = authority.handlers.run(
            .{ .retained = ctx, .live_finalized = private_candidate },
            .{ .plan = base_plan },
        );
        try std.testing.expect(private_plan == .plan);
        try std.testing.expect(private_plan.plan == .refused);
        try std.testing.expectEqual(error.ImportedProductRequired, private_plan.plan.refused.err);
        try std.testing.expectEqual(authority.plan.Publications{}, private_plan.plan.refused.outputs);
        try work.absent("authority-work/records/plan.json");
        try work.absent("authority-work/records/template.json");
    }

    // Mismatched bundle, candidate_output, or attempt_id is refused on the live imported owner.
    {
        var wrong_bundle = base_plan;
        wrong_bundle.bundle = try work.join("candidate.json");
        const refused_bundle = authority.handlers.run(
            .{ .retained = ctx, .live_finalized = created_candidate },
            .{ .plan = wrong_bundle },
        );
        try std.testing.expect(refused_bundle.plan == .refused);
        try std.testing.expectEqual(error.WrongCandidate, refused_bundle.plan.refused.err);
        try std.testing.expectEqual(authority.plan.Publications{}, refused_bundle.plan.refused.outputs);

        var wrong_candidate = base_plan;
        wrong_candidate.candidate_output = try work.join("candidate.json");
        const refused_candidate = authority.handlers.run(
            .{ .retained = ctx, .live_finalized = created_candidate },
            .{ .plan = wrong_candidate },
        );
        try std.testing.expect(refused_candidate.plan == .refused);
        try std.testing.expectEqual(error.WrongCandidate, refused_candidate.plan.refused.err);
        try std.testing.expectEqual(authority.plan.Publications{}, refused_candidate.plan.refused.outputs);

        var wrong_attempt = base_plan;
        wrong_attempt.attempt_id = "00000000-0000-4000-8000-000000000099";
        const refused_attempt = authority.handlers.run(
            .{ .retained = ctx, .live_finalized = created_candidate },
            .{ .plan = wrong_attempt },
        );
        try std.testing.expect(refused_attempt.plan == .refused);
        try std.testing.expectEqual(error.WrongCandidate, refused_attempt.plan.refused.err);
        try std.testing.expectEqual(authority.plan.Publications{}, refused_attempt.plan.refused.outputs);

        var wrong_cost = base_plan;
        wrong_cost.maximum_authorized_cost_microusd = 500_000;
        const refused_cost = authority.handlers.run(
            .{ .retained = ctx, .live_finalized = created_candidate },
            .{ .plan = wrong_cost },
        );
        try std.testing.expect(refused_cost.plan == .refused);
        try std.testing.expectEqual(error.InvalidCost, refused_cost.plan.refused.err);
        try std.testing.expectEqual(authority.plan.Publications{}, refused_cost.plan.refused.outputs);
    }

    // Positive live imported-owner plan -> authorization -> admission composition via CLI parser + handlers.
    {
        const runtime_res = try std.process.run(work.a, work.io, .{
            .argv = &.{ tools.validator, "azure-runtime", tool_paths.azure_runtime },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        if (runtime_res.term != .exited or runtime_res.term.exited != 0)
            std.debug.print("direct validator azure-runtime stderr: {s}\n", .{runtime_res.stderr});
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, runtime_res.term);
        try std.testing.expectEqualStrings("", runtime_res.stderr);
    }

    const plan_commitments = blk: {
        var parsed_plan = try authority.cli.parse(work.a, &.{
            "plan",
            "--bundle",                           created_meta.provenance.public_bundle.path,
            "--output",                           try work.join("authority-work/records/plan.json"),
            "--approval-template",                try work.join("authority-work/records/template.json"),
            "--candidate-output",                 created_meta.candidate.path,
            "--campaign-id",                      "00000000-0000-4000-8000-000000000010",
            "--ledger",                           try work.join("authority-work/ledger"),
            "--subscription",                     created_meta.scope.subscription,
            "--prefix",                           created_meta.scope.prefix,
            "--maximum-authorized-cost-microusd", "15000000",
            "--attempt-id",                       created_meta.scope.attempt_id,
            "--ledger-id",                        "00000000-0000-4000-8000-000000000020",
            "--azure-runtime",                    tool_paths.azure_runtime,
            "--azure",                            tool_paths.azure,
            "--uploader",                         tool_paths.uploader,
            "--validator",                        tool_paths.validator,
            "--supervisor",                       tool_paths.supervisor,
            "--az-python",                        tool_paths.az_python,
        });
        defer parsed_plan.deinit();
        const planned = authority.handlers.run(
            .{ .retained = ctx, .live_finalized = created_candidate },
            parsed_plan.result.command,
        );
        if (planned.plan != .success) std.debug.print("live imported plan: {any}\n", .{planned});
        try std.testing.expect(planned.plan == .success);
        const prepared = planned.plan.success;
        defer prepared.deinit();
        try prepared.revalidate();
        const plan_res = try prepared.result();
        try std.testing.expectEqual(.not_admitted, plan_res.plan.authority);
        try std.testing.expectEqual(.pending, plan_res.template.decision);
        try std.testing.expectEqualStrings("1", plan_res.plan.artifact_id);
        break :blk .{
            .plan_artifact = authority.types.Artifact{
                .path = try work.a.dupe(u8, plan_res.plan_artifact.path),
                .size = plan_res.plan_artifact.size,
                .sha256 = try work.a.dupe(u8, plan_res.plan_artifact.sha256),
            },
            .template_artifact = authority.types.Artifact{
                .path = try work.a.dupe(u8, plan_res.template_artifact.path),
                .size = plan_res.template_artifact.size,
                .sha256 = try work.a.dupe(u8, plan_res.template_artifact.sha256),
            },
            .created_unix = plan_res.plan.created_unix,
        };
    };
    {
        const plan_res = try std.process.run(work.a, work.io, .{
            .argv = &.{ tools.validator, "plan", plan_commitments.plan_artifact.path, plan_commitments.template_artifact.path },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        if (plan_res.term != .exited or plan_res.term.exited != 0)
            std.debug.print("direct validator plan stderr: {s}\n", .{plan_res.stderr});
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, plan_res.term);
        try std.testing.expectEqualStrings("", plan_res.stderr);

        // Create-only durability: re-running plan against existing output paths is refused without mutating published records.
        const original_plan_bytes = try work.read("authority-work/records/plan.json");
        const original_template_bytes = try work.read("authority-work/records/template.json");
        const duplicate_plan = authority.handlers.run(
            .{ .retained = ctx, .live_finalized = created_candidate },
            .{ .plan = base_plan },
        );
        try std.testing.expect(duplicate_plan.plan == .refused);
        try std.testing.expectEqual(error.PathAlreadyExists, duplicate_plan.plan.refused.err);
        try std.testing.expectEqual(authority.plan.Publications{}, duplicate_plan.plan.refused.outputs);
        try std.testing.expectEqualStrings(original_plan_bytes, try work.read("authority-work/records/plan.json"));
        try std.testing.expectEqualStrings(original_template_bytes, try work.read("authority-work/records/template.json"));
    }

    const now_unix: u64 = @intCast(std.Io.Clock.real.now(work.io).toSeconds());
    const recorded_unix = @max(now_unix, plan_commitments.created_unix);
    const recorded_unix_str = try work.a.print("{d}", .{recorded_unix});
    const expires_unix_str = try work.a.print("{d}", .{recorded_unix + 1800});

    const denied_artifact: authority.types.Artifact = blk: {
        var parsed_denied = try authority.cli.parse(work.a, &.{
            "record-authorization",
            "--plan",          plan_commitments.plan_artifact.path,
            "--template",      plan_commitments.template_artifact.path,
            "--output",        try work.join("authority-work/records/authorization-denied.json"),
            "--decision",      "denied",
            "--approver",      "operator@example.invalid",
            "--reference",     "CHG-189-DENY",
            "--recorded-unix", recorded_unix_str,
            "--expires-unix",  expires_unix_str,
            "--azure-runtime", tool_paths.azure_runtime,
            "--azure",         tool_paths.azure,
            "--uploader",      tool_paths.uploader,
            "--validator",     tool_paths.validator,
            "--supervisor",    tool_paths.supervisor,
            "--az-python",     tool_paths.az_python,
        });
        defer parsed_denied.deinit();
        const denied_outcome = authority.handlers.run(.{ .retained = ctx }, parsed_denied.result.command);
        if (denied_outcome.authorization != .success) std.debug.print("live denied authorization: {any}\n", .{denied_outcome});
        try std.testing.expect(denied_outcome.authorization == .success);
        const denied_recorded = denied_outcome.authorization.success;
        defer denied_recorded.deinit();
        try denied_recorded.revalidate();
        const raw = denied_recorded.artifact();
        break :blk .{
            .path = try work.a.dupe(u8, raw.path),
            .size = raw.size,
            .sha256 = try work.a.dupe(u8, raw.sha256),
        };
    };

    const approved_artifact: authority.types.Artifact = blk: {
        var parsed_approved = try authority.cli.parse(work.a, &.{
            "record-authorization",
            "--plan",          plan_commitments.plan_artifact.path,
            "--template",      plan_commitments.template_artifact.path,
            "--output",        try work.join("authority-work/records/authorization.json"),
            "--decision",      "approved",
            "--approver",      "operator@example.invalid",
            "--reference",     "CHG-189-APPROVE",
            "--recorded-unix", recorded_unix_str,
            "--expires-unix",  expires_unix_str,
            "--azure-runtime", tool_paths.azure_runtime,
            "--azure",         tool_paths.azure,
            "--uploader",      tool_paths.uploader,
            "--validator",     tool_paths.validator,
            "--supervisor",    tool_paths.supervisor,
            "--az-python",     tool_paths.az_python,
        });
        defer parsed_approved.deinit();
        const approved_outcome = authority.handlers.run(.{ .retained = ctx }, parsed_approved.result.command);
        if (approved_outcome.authorization != .success) std.debug.print("live approved authorization: {any}\n", .{approved_outcome});
        try std.testing.expect(approved_outcome.authorization == .success);
        const approved_recorded = approved_outcome.authorization.success;
        defer approved_recorded.deinit();
        try approved_recorded.revalidate();
        const raw = approved_recorded.artifact();
        break :blk .{
            .path = try work.a.dupe(u8, raw.path),
            .size = raw.size,
            .sha256 = try work.a.dupe(u8, raw.sha256),
        };
    };
    {
        // Create-only durability and approval window / authority-field boundary refusals for record-authorization.
        const original_auth_bytes = try work.read("authority-work/records/authorization.json");
        const base_auth_cmd: authority.types.AuthorizationCommand = .{
            .plan = plan_commitments.plan_artifact.path,
            .template = plan_commitments.template_artifact.path,
            .output = approved_artifact.path,
            .decision = .approved,
            .approver = "operator@example.invalid",
            .reference = "CHG-189-APPROVE",
            .recorded_unix = recorded_unix,
            .expires_unix = recorded_unix + 1800,
            .tools = tool_paths,
        };
        const duplicate_auth = authority.handlers.run(.{ .retained = ctx }, .{ .@"record-authorization" = base_auth_cmd });
        try std.testing.expect(duplicate_auth.authorization == .refused);
        try std.testing.expectEqual(error.PathAlreadyExists, duplicate_auth.authorization.refused.err);
        try std.testing.expectEqual(files.CommitStatus.not_committed, duplicate_auth.authorization.refused.publication);
        try std.testing.expectEqualStrings(original_auth_bytes, try work.read("authority-work/records/authorization.json"));

        const bad_auth_output = try work.join("authority-work/records/authorization-bad.json");
        var zero_window = base_auth_cmd;
        zero_window.output = bad_auth_output;
        zero_window.expires_unix = recorded_unix;
        const zero_window_res = authority.handlers.run(.{ .retained = ctx }, .{ .@"record-authorization" = zero_window });
        try std.testing.expect(zero_window_res.authorization == .refused);
        try std.testing.expectEqual(error.InvalidApprovalWindow, zero_window_res.authorization.refused.err);

        var oversized_window = base_auth_cmd;
        oversized_window.output = bad_auth_output;
        oversized_window.expires_unix = recorded_unix + 3601;
        const oversized_window_res = authority.handlers.run(.{ .retained = ctx }, .{ .@"record-authorization" = oversized_window });
        try std.testing.expect(oversized_window_res.authorization == .refused);
        try std.testing.expectEqual(error.InvalidApprovalWindow, oversized_window_res.authorization.refused.err);

        var future_recorded = base_auth_cmd;
        future_recorded.output = bad_auth_output;
        future_recorded.recorded_unix = recorded_unix + 600;
        future_recorded.expires_unix = recorded_unix + 1800;
        const future_recorded_res = authority.handlers.run(.{ .retained = ctx }, .{ .@"record-authorization" = future_recorded });
        try std.testing.expect(future_recorded_res.authorization == .refused);
        try std.testing.expectEqual(error.ApprovalExpired, future_recorded_res.authorization.refused.err);

        var control_approver = base_auth_cmd;
        control_approver.output = bad_auth_output;
        control_approver.approver = "operator\n@example.invalid";
        const control_approver_res = authority.handlers.run(.{ .retained = ctx }, .{ .@"record-authorization" = control_approver });
        try std.testing.expect(control_approver_res.authorization == .refused);
        try std.testing.expectEqual(error.InvalidAuthorityField, control_approver_res.authorization.refused.err);

        var empty_reference = base_auth_cmd;
        empty_reference.output = bad_auth_output;
        empty_reference.reference = "";
        const empty_reference_res = authority.handlers.run(.{ .retained = ctx }, .{ .@"record-authorization" = empty_reference });
        try std.testing.expect(empty_reference_res.authorization == .refused);
        try std.testing.expectEqual(error.InvalidAuthorityField, empty_reference_res.authorization.refused.err);
        try work.absent("authority-work/records/authorization-bad.json");

        const denied_res = try std.process.run(work.a, work.io, .{
            .argv = &.{ tools.validator, "authorization", plan_commitments.plan_artifact.path, denied_artifact.path },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        if (denied_res.term != .exited or denied_res.term.exited != 0)
            std.debug.print("direct validator denied authorization stderr: {s}\n", .{denied_res.stderr});
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, denied_res.term);
        try std.testing.expectEqualStrings("", denied_res.stderr);

        const template_as_auth_res = try std.process.run(work.a, work.io, .{
            .argv = &.{ tools.validator, "authorization", plan_commitments.plan_artifact.path, plan_commitments.template_artifact.path },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, template_as_auth_res.term);
        try std.testing.expectEqualStrings("", template_as_auth_res.stdout);
        try std.testing.expect(template_as_auth_res.stderr.len > 0);

        const approved_res = try std.process.run(work.a, work.io, .{
            .argv = &.{ tools.validator, "authorization", plan_commitments.plan_artifact.path, approved_artifact.path },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        if (approved_res.term != .exited or approved_res.term.exited != 0)
            std.debug.print("direct validator authorization stderr: {s}\n", .{approved_res.stderr});
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, approved_res.term);
        try std.testing.expectEqualStrings("", approved_res.stderr);
    }

    // Denied authorization and private_bundle candidate are refused by admission.run.
    {
        const denied_admit = authority.handlers.run(
            .{
                .retained = ctx,
                .live_finalized = created_candidate,
                .plan_commitment = plan_commitments.plan_artifact,
                .authorization_commitment = denied_artifact,
            },
            .{ .admit = .{
                .plan = plan_commitments.plan_artifact.path,
                .authorization = denied_artifact.path,
                .output = try work.join("authority-work/records/admission-denied.json"),
                .tools = tool_paths,
            } },
        );
        try std.testing.expect(denied_admit.admission == .refused);
        try std.testing.expectEqual(error.NotAuthorized, denied_admit.admission.refused.err);
        try std.testing.expectEqual(files.CommitStatus.not_committed, denied_admit.admission.refused.publication);
        try work.absent("authority-work/records/admission-denied.json");

        const private_admit = authority.handlers.run(
            .{
                .retained = ctx,
                .live_finalized = private_candidate,
                .plan_commitment = plan_commitments.plan_artifact,
                .authorization_commitment = approved_artifact,
            },
            .{ .admit = .{
                .plan = plan_commitments.plan_artifact.path,
                .authorization = approved_artifact.path,
                .output = try work.join("authority-work/records/admission-private.json"),
                .tools = tool_paths,
            } },
        );
        try std.testing.expect(private_admit.admission == .refused);
        try std.testing.expectEqual(error.ImportedProductRequired, private_admit.admission.refused.err);
        try std.testing.expectEqual(files.CommitStatus.not_committed, private_admit.admission.refused.publication);
        try work.absent("authority-work/records/admission-private.json");
    }

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
    const serial_path = try std.fs.path.join(work.a, &.{ owner.bundle.?.evidence.root, "boots/raw-x2apic/serial" });
    _ = try reopened.success.result(serial_path, null, null);

    {
        var parsed_admit = try authority.cli.parse(work.a, &.{
            "admit",
            "--plan",          plan_commitments.plan_artifact.path,
            "--authorization", approved_artifact.path,
            "--output",        try work.join("authority-work/records/admission.json"),
            "--azure-runtime", tool_paths.azure_runtime,
            "--azure",         tool_paths.azure,
            "--uploader",      tool_paths.uploader,
            "--validator",     tool_paths.validator,
            "--supervisor",    tool_paths.supervisor,
            "--az-python",     tool_paths.az_python,
        });
        defer parsed_admit.deinit();
        const admitted_outcome = authority.handlers.run(
            .{
                .retained = ctx,
                .live_finalized = reopened.success,
                .plan_commitment = plan_commitments.plan_artifact,
                .authorization_commitment = approved_artifact,
            },
            parsed_admit.result.command,
        );
        if (admitted_outcome.admission != .success) std.debug.print("live imported admission: {any}\n", .{admitted_outcome});
        try std.testing.expect(admitted_outcome.admission == .success);
        const admitted = admitted_outcome.admission.success;
        defer admitted.deinit();
        try admitted.revalidate();
        const admission_artifact = try admitted.artifact();
        try std.testing.expect(admission_artifact.size > 0);
        const admission_bytes = try work.read("authority-work/records/admission.json");
        try std.testing.expectEqualStrings(admission_bytes, try work.read("authority-work/records/admission.json.validation.json"));

        // Create-only durability: re-running admit against existing output path is refused without mutating published admission.
        const duplicate_admit = authority.handlers.run(
            .{
                .retained = ctx,
                .live_finalized = reopened.success,
                .plan_commitment = plan_commitments.plan_artifact,
                .authorization_commitment = approved_artifact,
            },
            parsed_admit.result.command,
        );
        try std.testing.expect(duplicate_admit.admission == .refused);
        try std.testing.expectEqual(error.PathAlreadyExists, duplicate_admit.admission.refused.err);
        try std.testing.expectEqual(files.CommitStatus.not_committed, duplicate_admit.admission.refused.publication);
        try std.testing.expectEqualStrings(admission_bytes, try work.read("authority-work/records/admission.json"));
        try admitted.revalidate();

        for ([_][]const []const u8{
            &.{ tools.validator, "admission", admission_artifact.path },
            &.{ tools.validator, "stored-scope", admission_artifact.path },
            &.{ tools.validator, "inputs", admission_artifact.path },
            &.{ tools.validator, "ledger", admission_artifact.path, try work.join("authority-work/ledger") },
            &.{ tools.validator, "ledger-proposal", try work.join("authority-work/ledger"), "00000000-0000-4000-8000-000000000010", "00000000-0000-4000-8000-000000000020" },
            &.{ tools.validator, "serial", admission_artifact.path, serial_path },
        }) |argv| {
            const val_res = try std.process.run(work.a, work.io, .{
                .argv = argv,
                .stdout_limit = .limited(16 * 1024),
                .stderr_limit = .limited(4096),
            });
            if (val_res.term != .exited or val_res.term.exited != 0)
                std.debug.print("direct validator {s} stderr: {s}\n", .{ argv[1], val_res.stderr });
            try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, val_res.term);
            try std.testing.expectEqualStrings("", val_res.stderr);
        }

        // Post-admission tamper detection: mismatched ledger path, mutating a bound tool, mutating the uninitialized
        // ledger, or mutating the staged runtime is refused by Admitted.revalidate() and uk-wamr-direct-validate.
        {
            const wrong_ledger_res = try std.process.run(work.a, work.io, .{
                .argv = &.{ tools.validator, "ledger", admission_artifact.path, try work.join("authority-work/records") },
                .stdout_limit = .limited(4096),
                .stderr_limit = .limited(4096),
            });
            try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, wrong_ledger_res.term);
            try std.testing.expectEqualStrings("", wrong_ledger_res.stdout);
            try std.testing.expect(wrong_ledger_res.stderr.len > 0);
        }
        {
            const source_dir = try authority_dir.openDir(work.io, "runtime-source", .{});
            defer source_dir.close(work.io);
            if (std.os.linux.errno(std.os.linux.fchmodat(source_dir.handle, "uploader", 0o700)) != .SUCCESS)
                return error.FixtureMode;
            const uploader = try source_dir.openFile(work.io, "uploader", .{ .mode = .read_write, .follow_symlinks = false });
            defer uploader.close(work.io);
            try uploader.writePositionalAll(work.io, "tampered-uploader!\n", 0);
            if (std.os.linux.errno(std.os.linux.fchmod(uploader.handle, 0o500)) != .SUCCESS)
                return error.FixtureMode;
            try uploader.sync(work.io);
            try std.testing.expectError(error.ArtifactChanged, admitted.revalidate());
            const plan_tamper_res = try std.process.run(work.a, work.io, .{
                .argv = &.{ tools.validator, "plan", plan_commitments.plan_artifact.path, plan_commitments.template_artifact.path },
                .stdout_limit = .limited(4096),
                .stderr_limit = .limited(4096),
            });
            try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, plan_tamper_res.term);
            try std.testing.expectEqualStrings("", plan_tamper_res.stdout);
            try std.testing.expect(plan_tamper_res.stderr.len > 0);
        }
        {
            const ledger_dir = try authority_dir.openDir(work.io, "ledger", .{});
            defer ledger_dir.close(work.io);
            try writeModeFile(work.io, ledger_dir, "stray.json", "{}", 0o600);
            try std.testing.expectError(error.WrongLedgerIdentity, admitted.revalidate());
            const ledger_tamper_res = try std.process.run(work.a, work.io, .{
                .argv = &.{ tools.validator, "admission", admission_artifact.path },
                .stdout_limit = .limited(4096),
                .stderr_limit = .limited(4096),
            });
            try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, ledger_tamper_res.term);
            try std.testing.expectEqualStrings("", ledger_tamper_res.stdout);
            try std.testing.expect(ledger_tamper_res.stderr.len > 0);
        }
        {
            const runtime_dir = try authority_dir.openDir(work.io, "azure-runtime", .{});
            defer runtime_dir.close(work.io);
            const manifest_file = try runtime_dir.openFile(work.io, "azure-runtime.manifest", .{ .mode = .read_write, .follow_symlinks = false });
            defer manifest_file.close(work.io);
            try manifest_file.writePositionalAll(work.io, "{\"tampered\":true}\n", 0);
            try manifest_file.sync(work.io);
            const runtime_tamper_res = try std.process.run(work.a, work.io, .{
                .argv = &.{ tools.validator, "azure-runtime", try work.join("authority-work/azure-runtime/azure-runtime.json") },
                .stdout_limit = .limited(4096),
                .stderr_limit = .limited(4096),
            });
            try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, runtime_tamper_res.term);
            try std.testing.expectEqualStrings("", runtime_tamper_res.stdout);
            try std.testing.expect(runtime_tamper_res.stderr.len > 0);
        }
    }
}

const SyntheticElf = struct {
    interp: ?[]const u8 = null,
    needed: []const []const u8 = &.{},
    soname: ?[]const u8 = null,
};

fn writeElfInt(comptime T: type, bytes: []u8, offset: usize, value: T) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, .little);
}

fn writeElfProgram(bytes: []u8, index: usize, kind: std.elf.PT, offset: u64, size: u64, flags: u32) void {
    const at = 64 + index * 56;
    writeElfInt(u32, bytes, at, @intFromEnum(kind));
    writeElfInt(u32, bytes, at + 4, flags);
    writeElfInt(u64, bytes, at + 8, offset);
    writeElfInt(u64, bytes, at + 16, 0x400000 + offset);
    writeElfInt(u64, bytes, at + 32, size);
    writeElfInt(u64, bytes, at + 40, size);
    writeElfInt(u64, bytes, at + 48, if (kind == .LOAD) 0x1000 else 8);
}

fn writeElfDynamicEntry(bytes: []u8, index: usize, tag: i64, value: u64) void {
    writeElfInt(i64, bytes, 0x200 + index * 16, tag);
    writeElfInt(u64, bytes, 0x208 + index * 16, value);
}

fn syntheticElf(config: SyntheticElf) ![2048]u8 {
    var bytes: [2048]u8 = @splat(0);
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    writeElfInt(u16, &bytes, 16, 3);
    writeElfInt(u16, &bytes, 18, @intFromEnum(std.elf.EM.X86_64));
    writeElfInt(u32, &bytes, 20, 1);
    writeElfInt(u64, &bytes, 24, 0x400080);
    writeElfInt(u64, &bytes, 32, 64);
    writeElfInt(u16, &bytes, 52, 64);
    writeElfInt(u16, &bytes, 54, 56);
    writeElfInt(u16, &bytes, 56, if (config.interp != null) 3 else 2);
    writeElfProgram(&bytes, 0, .LOAD, 0, bytes.len, std.elf.PF_R | std.elf.PF_X);
    writeElfProgram(&bytes, 1, .DYNAMIC, 0x200, 96, std.elf.PF_R);
    if (config.interp) |interp| {
        if (interp.len >= 256) return error.InvalidSynthetic;
        @memcpy(bytes[0x100..][0..interp.len], interp);
        writeElfProgram(&bytes, 2, .INTERP, 0x100, interp.len + 1, std.elf.PF_R);
    }
    var cursor: usize = 1;
    var entry: usize = 2;
    for (config.needed) |name| {
        @memcpy(bytes[0x380 + cursor ..][0..name.len], name);
        writeElfDynamicEntry(&bytes, entry, std.elf.DT_NEEDED, cursor);
        cursor += name.len + 1;
        entry += 1;
    }
    if (config.soname) |name| {
        @memcpy(bytes[0x380 + cursor ..][0..name.len], name);
        writeElfDynamicEntry(&bytes, entry, std.elf.DT_SONAME, cursor);
        cursor += name.len + 1;
        entry += 1;
    }
    if (entry >= 6) return error.InvalidSynthetic;
    writeElfDynamicEntry(&bytes, 0, std.elf.DT_STRTAB, 0x400380);
    writeElfDynamicEntry(&bytes, 1, std.elf.DT_STRSZ, cursor);
    return bytes;
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

fn cliPublicAndCandidateComposition(
    work: Workspace,
    receipt: LocalReceipt,
    stage: []const u8,
    repository: []const u8,
    tools: controller.import_validator_build.LocalTools,
) !void {
    const inner_hex = std.fmt.bytesToHex(receipt.inner, .lower);
    const container_hex = std.fmt.bytesToHex(receipt.container, .lower);
    const inner_archive = try work.join("local-inner.zip");
    const container_archive = try work.join("local-container.zip");

    // 1. CLI private-validate on the exported private bundle.
    {
        const res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli, "private-validate",
                "--stage-root",              stage,
                "--git",                     tools.git,
                "--supervisor",              options.host_controller_cli,
                "--validator",               tools.validator,
                "--output",                  try work.join("cli-private-validation"),
            },
            .cwd = .{ .path = repository },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        if (res.term != .exited or res.term.exited != 0)
            std.debug.print("cli private-validate stderr: {s}\n", .{res.stderr});
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, res.term);
        try std.testing.expectEqualStrings("Compute handoff revalidated; authority=not_admitted.\n", res.stdout);
        try std.testing.expectEqualStrings("", res.stderr);
    }

    // 2. CLI verify-public-source-bundle and stage-public-source-upload.
    {
        const expected_stdout = try work.a.print("Public source archive SHA-256: {s}\n", .{inner_hex[0..]});
        const verify_res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli,  "verify-public-source-bundle",
                "--archive",                  inner_archive,
                "--expected-source",          receipt.context.source_revision,
                "--expected-tree",            receipt.context.source_tree,
                "--run-id",                   receipt.context.run_id,
                "--run-attempt",              receipt.context.run_attempt,
                "--expected-archive-sha256",  inner_hex[0..],
            },
            .cwd = .{ .path = repository },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, verify_res.term);
        try std.testing.expectEqualStrings(expected_stdout, verify_res.stdout);
        try std.testing.expectEqualStrings("", verify_res.stderr);

        const stage_res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli,  "stage-public-source-upload",
                "--archive",                  inner_archive,
                "--output",                   try work.join("cli-staged-upload"),
                "--expected-source",          receipt.context.source_revision,
                "--expected-tree",            receipt.context.source_tree,
                "--run-id",                   receipt.context.run_id,
                "--run-attempt",              receipt.context.run_attempt,
                "--expected-archive-sha256",  inner_hex[0..],
            },
            .cwd = .{ .path = repository },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, stage_res.term);
        try std.testing.expectEqualStrings(expected_stdout, stage_res.stdout);
        try std.testing.expectEqualStrings("", stage_res.stderr);
        try std.testing.expectEqualSlices(u8, &inner_hex, &try work.digest("cli-staged-upload/tiny-aot-public-source.zip"));

        const staged_upload_archive = try work.join("cli-staged-upload/tiny-aot-public-source.zip");
        const uid = std.os.linux.geteuid();
        const gid = std.os.linux.getegid();
        const uid_text = try work.a.print("{d}", .{uid});
        const gid_text = try work.a.print("{d}", .{gid});
        const seal_cli_res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli,  "seal-public-source-upload",
                "--archive",                  staged_upload_archive,
                "--output",                   try work.join("cli-refused-sealed-upload"),
                "--source-uid",               uid_text,
                "--source-gid",               gid_text,
                "--upload-gid",               gid_text,
                "--expected-source",          receipt.context.source_revision,
                "--expected-tree",            receipt.context.source_tree,
                "--run-id",                   receipt.context.run_id,
                "--run-attempt",              receipt.context.run_attempt,
                "--expected-archive-sha256",  inner_hex[0..],
            },
            .cwd = .{ .path = repository },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, seal_cli_res.term);
        try std.testing.expectEqualStrings("", seal_cli_res.stdout);
        try std.testing.expect(std.mem.indexOf(u8, seal_cli_res.stderr, "seal-public-source-upload/inputs; cause: PrivilegeRequired; publication: not_committed") != null);
        try work.absent("cli-refused-sealed-upload");

        const wrong_owner_sealed = handoff.public_transport.publication.sealUploadForTest(.{
            .allocator = work.a,
            .io = work.io,
            .source_path = staged_upload_archive,
            .source_uid = uid + 1,
            .source_gid = gid,
            .upload_gid = gid,
            .output_path = try work.join("cli-wrong-owner-sealed-upload"),
            .context = receipt.context,
            .inner_digest = .{ .bytes = receipt.inner },
        });
        try std.testing.expectEqual(handoff.public_transport.publication.Outcome{
            .refused = .{ .phase = .inputs, .err = error.UnsafeSource, .publication = .not_committed },
        }, wrong_owner_sealed);
        try work.absent("cli-wrong-owner-sealed-upload");

        const sealed_dir_path = try work.join("cli-sealed-upload");
        defer if (work.root.openDir(work.io, "cli-sealed-upload", .{ .iterate = true, .follow_symlinks = false })) |dir| {
            defer dir.close(work.io);
            makeDirectoryRemovable(work.io, dir) catch {};
        } else |_| {};
        const sealed_outcome = handoff.public_transport.publication.sealUploadForTest(.{
            .allocator = work.a,
            .io = work.io,
            .source_path = staged_upload_archive,
            .source_uid = uid,
            .source_gid = gid,
            .upload_gid = gid,
            .output_path = sealed_dir_path,
            .context = receipt.context,
            .inner_digest = .{ .bytes = receipt.inner },
        });
        try std.testing.expect(sealed_outcome == .success);
        var sealed = sealed_outcome.success;
        defer sealed.deinit(work.io);
        try sealed.revalidate(work.io, null);
        try std.testing.expectEqualSlices(u8, &receipt.inner, &sealed.digest);
        try std.testing.expectEqual(@as(u32, 0o440), sealed.output.snapshot.mode & 0o7777);
        try std.testing.expectEqual(@as(u32, 0o550), sealed.output.snapshots[sealed.output.count - 1].mode & 0o7777);
        try std.testing.expectError(error.UnsafeFile, files.RetainedFile.open(work.io, try work.join("cli-sealed-upload/tiny-aot-public-source.zip"), .private));

        var ci_env: std.process.Environ.Map = .init(work.a);
        defer ci_env.deinit();
        try ci_env.put("GITHUB_ACTIONS", "true");
        try ci_env.put("GITHUB_REPOSITORY", receipt.context.repository);
        try ci_env.put("GITHUB_JOB", "wamr-native-compute");
        try ci_env.put("GITHUB_EVENT_NAME", "pull_request");
        try ci_env.put("GITHUB_REPOSITORY_VISIBILITY", "public");
        try ci_env.put("GITHUB_WORKSPACE", repository);
        try ci_env.put("GITHUB_SHA", receipt.context.source_revision);
        try ci_env.put("GITHUB_WORKFLOW_REF", "cataggar/unikraft/.github/workflows/wamr-native-compute.yaml@refs/heads/zig16");
        try ci_env.put("GITHUB_RUN_ID", receipt.context.run_id);
        try ci_env.put("GITHUB_RUN_ATTEMPT", receipt.context.run_attempt);

        const archive_mismatch_res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli, "public-archive",
                "--stage-root",              stage,
                "--validation-output",       try work.join("cli-public-archive-mismatch-validation"),
                "--output",                  try work.join("cli-public-archive-mismatch"),
                "--git",                     tools.git,
                "--supervisor",              options.host_controller_cli,
                "--validator",               tools.validator,
                "--expected-source",         receipt.context.source_revision,
                "--expected-tree",           "0000000000000000000000000000000000000000",
                "--run-id",                  receipt.context.run_id,
                "--run-attempt",             receipt.context.run_attempt,
            },
            .cwd = .{ .path = repository },
            .environ_map = &ci_env,
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, archive_mismatch_res.term);
        try std.testing.expectEqualStrings("", archive_mismatch_res.stdout);
        try std.testing.expect(std.mem.indexOf(u8, archive_mismatch_res.stderr, "public-archive/inputs; cause: ContextMismatch; publication: not_committed") != null);
        try work.absent("cli-public-archive-mismatch-validation");
        try work.absent("cli-public-archive-mismatch");

        const archive_scope_res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli, "public-archive",
                "--stage-root",              stage,
                "--validation-output",       try work.join("cli-public-archive-scope-validation"),
                "--output",                  try work.join("cli-public-archive-scope"),
                "--git",                     tools.git,
                "--supervisor",              options.host_controller_cli,
                "--validator",               tools.validator,
                "--expected-source",         receipt.context.source_revision,
                "--expected-tree",           receipt.context.source_tree,
                "--run-id",                  receipt.context.run_id,
                "--run-attempt",             receipt.context.run_attempt,
            },
            .cwd = .{ .path = repository },
            .environ_map = &ci_env,
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, archive_scope_res.term);
        try std.testing.expectEqualStrings("", archive_scope_res.stdout);
        try std.testing.expect(std.mem.indexOf(u8, archive_scope_res.stderr, "public-archive/archive; cause: InvalidPublicScope; publication: not_committed") != null);
        try std.testing.expect((try work.read("cli-public-archive-scope-validation/evidence/command-import-native-revalidation.json")).len > 0);
        try work.absent("cli-public-archive-scope");

        const bundle_digest_res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli,  "import-public-source-bundle",
                "--archive",                  inner_archive,
                "--output",                   try work.join("cli-refused-bundle-digest"),
                "--git",                      tools.git,
                "--supervisor",               options.host_controller_cli,
                "--validator",                tools.validator,
                "--expected-source",          receipt.context.source_revision,
                "--expected-tree",            receipt.context.source_tree,
                "--run-id",                   receipt.context.run_id,
                "--run-attempt",              receipt.context.run_attempt,
                "--expected-archive-sha256",  "0000000000000000000000000000000000000000000000000000000000000000",
            },
            .cwd = .{ .path = repository },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, bundle_digest_res.term);
        try std.testing.expectEqualStrings("", bundle_digest_res.stdout);
        try std.testing.expect(std.mem.indexOf(u8, bundle_digest_res.stderr, "import-public-source-bundle/inputs; cause: DigestMismatch; publication: not_committed") != null);
        try work.absent("cli-refused-bundle-digest");

        const bundle_v2_res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli,  "import-public-source-bundle",
                "--archive",                  inner_archive,
                "--output",                   try work.join("cli-refused-bundle-v2"),
                "--git",                      tools.git,
                "--supervisor",               options.host_controller_cli,
                "--validator",                tools.validator,
                "--expected-source",          receipt.context.source_revision,
                "--expected-tree",            receipt.context.source_tree,
                "--run-id",                   receipt.context.run_id,
                "--run-attempt",              receipt.context.run_attempt,
                "--expected-archive-sha256",  inner_hex[0..],
            },
            .cwd = .{ .path = repository },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, bundle_v2_res.term);
        try std.testing.expectEqualStrings("", bundle_v2_res.stdout);
        try std.testing.expect(std.mem.indexOf(u8, bundle_v2_res.stderr, "import-public-source-bundle/inputs; cause: ExactDownloadRequired; publication: not_committed") != null);
        try work.absent("cli-refused-bundle-v2");
    }

    // 3. CLI retain-public-source-download (mismatched selection refused; matching selection retained).
    {
        const mismatch_res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli,   "retain-public-source-download",
                "--container-archive",         container_archive,
                "--output",                    try work.join("cli-refused-download"),
                "--expected-source",           receipt.context.source_revision,
                "--expected-tree",             receipt.context.source_tree,
                "--run-id",                    receipt.context.run_id,
                "--run-attempt",               receipt.context.run_attempt,
                "--expected-archive-sha256",   inner_hex[0..],
                "--artifact-id",               "1",
                "--container-digest",          container_hex[0..],
                "--selected-artifact-id",      "2",
                "--selected-container-digest", container_hex[0..],
                "--selected-source",           receipt.context.source_revision,
                "--selected-tree",             receipt.context.source_tree,
                "--selected-run-id",           receipt.context.run_id,
                "--selected-run-attempt",      receipt.context.run_attempt,
            },
            .cwd = .{ .path = repository },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, mismatch_res.term);
        try std.testing.expectEqualStrings("", mismatch_res.stdout);
        try std.testing.expect(std.mem.indexOf(u8, mismatch_res.stderr, "retain-public-source-download/inputs") != null);
        try work.absent("cli-refused-download/tiny-aot-public-source.zip");

        const retain_res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli,   "retain-public-source-download",
                "--container-archive",         container_archive,
                "--output",                    try work.join("cli-retained-download"),
                "--expected-source",           receipt.context.source_revision,
                "--expected-tree",             receipt.context.source_tree,
                "--run-id",                    receipt.context.run_id,
                "--run-attempt",               receipt.context.run_attempt,
                "--expected-archive-sha256",   inner_hex[0..],
                "--artifact-id",               "1",
                "--container-digest",          container_hex[0..],
                "--selected-artifact-id",      "1",
                "--selected-container-digest", container_hex[0..],
                "--selected-source",           receipt.context.source_revision,
                "--selected-tree",             receipt.context.source_tree,
                "--selected-run-id",           receipt.context.run_id,
                "--selected-run-attempt",      receipt.context.run_attempt,
            },
            .cwd = .{ .path = repository },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, retain_res.term);
        try std.testing.expectEqualStrings("Raw public source container retained and inner ZIP verified; authority=not_admitted.\n", retain_res.stdout);
        try std.testing.expectEqualStrings("", retain_res.stderr);
        try std.testing.expectEqualSlices(u8, &inner_hex, &try work.digest("cli-retained-download/tiny-aot-public-source.zip"));
    }

    // 4. CLI import-public-source-download -> candidate -> candidate-inspect -> candidate-result.
    const cli_imported = try work.join("cli-imported");
    {
        const import_res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli,   "import-public-source-download",
                "--download-root",             try work.join("cli-retained-download"),
                "--container-archive",         container_archive,
                "--output",                    cli_imported,
                "--git",                       tools.git,
                "--supervisor",                options.host_controller_cli,
                "--validator",                 tools.validator,
                "--expected-source",           receipt.context.source_revision,
                "--expected-tree",             receipt.context.source_tree,
                "--run-id",                    receipt.context.run_id,
                "--run-attempt",               receipt.context.run_attempt,
                "--expected-archive-sha256",   inner_hex[0..],
                "--artifact-id",               "1",
                "--container-digest",          container_hex[0..],
                "--selected-artifact-id",      "1",
                "--selected-container-digest", container_hex[0..],
                "--selected-source",           receipt.context.source_revision,
                "--selected-tree",             receipt.context.source_tree,
                "--selected-run-id",           receipt.context.run_id,
                "--selected-run-attempt",      receipt.context.run_attempt,
            },
            .cwd = .{ .path = repository },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        if (import_res.term != .exited or import_res.term.exited != 0)
            std.debug.print("cli import-public-source-download stderr: {s}\n", .{import_res.stderr});
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, import_res.term);
        try std.testing.expectEqualStrings("Public source handoff imported; authority=not_admitted.\n", import_res.stdout);
        try std.testing.expectEqualStrings("", import_res.stderr);
    }

    const cli_bundle = try std.fs.path.join(work.a, &.{ cli_imported, "bundle.json" });
    const cli_candidate = try work.join("cli-imported-candidate.json");
    {
        const create_res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli, "candidate",
                "--bundle",                  cli_bundle,
                "--output",                  cli_candidate,
                "--validation-output",       try work.join("cli-imported-candidate-validation"),
                "--git",                     tools.git,
                "--supervisor",              options.host_controller_cli,
                "--validator",               tools.validator,
                "--attempt-id",              "00000000-0000-4000-8000-000000000001",
            },
            .cwd = .{ .path = repository },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        if (create_res.term != .exited or create_res.term.exited != 0)
            std.debug.print("cli candidate stderr: {s}\n", .{create_res.stderr});
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, create_res.term);
        try std.testing.expectEqualStrings("Compute candidate created; authority=not_admitted.\n", create_res.stdout);
        try std.testing.expectEqualStrings("", create_res.stderr);
        var admission = try handoff.contracts.parseCanonical(work.a, try work.read("cli-imported-candidate.json.admission.json"));
        defer admission.deinit();
        try handoff.contracts.validateDirectComputeAdmissionV2(admission.value());

        const inspect_res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli, "candidate-inspect",
                "--bundle",                  cli_bundle,
                "--candidate",               cli_candidate,
                "--validation-output",       try work.join("cli-imported-inspect-validation"),
                "--git",                     tools.git,
                "--supervisor",              options.host_controller_cli,
                "--validator",               tools.validator,
            },
            .cwd = .{ .path = repository },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        if (inspect_res.term != .exited or inspect_res.term.exited != 0)
            std.debug.print("cli candidate-inspect stderr: {s}\n", .{inspect_res.stderr});
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, inspect_res.term);
        try std.testing.expectEqualStrings("Compute candidate revalidated; authority=not_admitted.\n", inspect_res.stdout);
        try std.testing.expectEqualStrings("", inspect_res.stderr);
    }

    {
        const serial = try std.Io.Dir.cwd().readFileAlloc(work.io, try std.fs.path.join(work.a, &.{ cli_imported, "boots/raw-x2apic/serial" }), work.a, .limited(handoff.layout.max_serial_bytes));
        try work.put("cli-serial-first", serial);
        try work.put("cli-serial-second", try std.mem.concat(work.a, u8, &.{ serial, serial, "\x00\x00" }));
        try work.put("cli-serial-incomplete", "Calling main(0, 0)\n");

        const result_res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli, "candidate-result",
                "--bundle",                  cli_bundle,
                "--candidate",               cli_candidate,
                "--validation-output",       try work.join("cli-imported-result-validation"),
                "--git",                     tools.git,
                "--supervisor",              options.host_controller_cli,
                "--validator",               tools.validator,
                "--serial-first",            try work.join("cli-serial-first"),
                "--serial-second",           try work.join("cli-serial-second"),
            },
            .cwd = .{ .path = repository },
            .stdout_limit = .limited(16384),
            .stderr_limit = .limited(4096),
        });
        if (result_res.term != .exited or result_res.term.exited != 0)
            std.debug.print("cli candidate-result stderr: {s}\n", .{result_res.stderr});
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result_res.term);
        try std.testing.expectEqualStrings("", result_res.stderr);
        const parsed_result = try std.json.parseFromSlice(controller.tiny.Result, work.a, std.mem.trim(u8, result_res.stdout, "\n"), .{ .allocate = .alloc_always });
        try std.testing.expectEqual(@as(i32, 42), parsed_result.value.answer);
        try std.testing.expectEqual(@as(u32, 2), parsed_result.value.checks);
        try std.testing.expectEqual(@as(i32, 0), parsed_result.value.platform_status);

        const incomplete_res = try std.process.run(work.a, work.io, .{
            .argv = &.{
                options.host_controller_cli, "candidate-result",
                "--bundle",                  cli_bundle,
                "--candidate",               cli_candidate,
                "--validation-output",       try work.join("cli-imported-incomplete-validation"),
                "--git",                     tools.git,
                "--supervisor",              options.host_controller_cli,
                "--validator",               tools.validator,
                "--serial-first",            try work.join("cli-serial-incomplete"),
            },
            .cwd = .{ .path = repository },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 2 }, incomplete_res.term);
        try std.testing.expectEqualStrings("", incomplete_res.stdout);
        try std.testing.expect(std.mem.indexOf(u8, incomplete_res.stderr, "candidate-result/serial; cause: EvidenceIncomplete; authority=not_admitted.") != null);
    }
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
