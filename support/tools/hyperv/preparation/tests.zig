const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const rt = @import("runtime.zig");
const provenance = @import("provenance.zig");
const receipts = @import("receipts.zig");
const inputs = @import("inputs.zig");
const producer = @import("producer.zig");
const packaging = @import("package.zig");
const budget = @import("budget.zig");
const admission = @import("admission.zig");
const private = c.core.private_files;

fn cli(allocator: std.mem.Allocator, cwd: std.Io.Dir, arguments: []const []const u8) !c.core.process.Result {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, @import("test_options").preparation_cli);
    try argv.appendSlice(allocator, arguments);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try c.core.process.initialize();
    return c.core.process.run(allocator, std.testing.io, .{
        .argv = argv.items,
        .environment = &environment,
        .cwd = cwd,
        .deadline = try c.core.process.Deadline.afterMilliseconds(30000),
        .stdout_limit = 8192,
        .stderr_limit = 8192,
    });
}

test "real standalone CLI generates only synthetic seed outputs and inspects bounded receipt bindings" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    const path = try fixture.dir.realPathFileAlloc(io, ".", allocator);
    const parameters: @import("seed.zig").Parameters = .{
        .run_id = "11111111111111111111111111111111".*,
        .disk_id = "22222222222222222222222222222222".*,
        .sectors = 49,
        .lun = 7,
    };
    try writeFixture(fixture.dir, "request.json", try c.canonical(allocator, parameters), 0o600);
    var generated = try cli(allocator, fixture.dir, &.{ "synthetic-seed", path, "request.json" });
    defer generated.deinit(allocator);
    try std.testing.expect(generated.termination != null and generated.termination.? == .exited);
    try std.testing.expectEqual(@as(u8, 0), generated.termination.?.exited);
    try std.testing.expectEqualStrings("{\"scope\":\"synthetic_only\",\"state\":\"prepared\"}\n", generated.stdout);
    const directory: fs.Directory = .{ .dir = fixture.dir, .path = path };
    const raw = try directory.read(allocator, io, "synthetic.raw", 32 * 1024, .private);
    const vhd = try directory.read(allocator, io, "synthetic.vhd", 32 * 1024, .private);
    try @import("seed.zig").validateBytes(raw, vhd, parameters);
    var repeat = try cli(allocator, fixture.dir, &.{ "synthetic-seed", path, "request.json" });
    defer repeat.deinit(allocator);
    try std.testing.expect(repeat.termination.?.exited != 0);
    try std.testing.expectEqualStrings(raw, try directory.read(allocator, io, "synthetic.raw", 32 * 1024, .private));
    const receipt = try c.canonical(allocator, try shapePrepared(allocator));
    try writeFixture(fixture.dir, "shape-only.receipt.json", receipt, 0o600);
    var inspected = try cli(allocator, fixture.dir, &.{ "inspect-receipt", path, "shape-only.receipt.json", &c.digest(receipt) });
    defer inspected.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), inspected.termination.?.exited);
    try std.testing.expectEqualStrings(
        "{\"authority\":\"not_admitted\",\"inspection\":\"shape_and_binding_only\",\"phase\":\"prepared\"}\n",
        inspected.stdout,
    );
    var substituted = try cli(allocator, fixture.dir, &.{ "inspect-receipt", path, "shape-only.receipt.json", &c.digest("substituted") });
    defer substituted.deinit(allocator);
    try std.testing.expect(substituted.termination.?.exited != 0);
}

test "typed canonical byte strings round trip" {
    const value: c.File = .{ .path = "public.fixture", .sha256 = c.digest("fixture"), .size = 7, .mode = 0o600 };
    const bytes = try c.canonical(std.testing.allocator, value);
    defer std.testing.allocator.free(bytes);
    const parsed = try c.parse(c.File, std.testing.allocator, bytes);
    defer parsed.deinit();
    try @import("files.zig").requireFile(parsed.value, value);
}

test "native context entry points compile without executing blocked workflows" {
    inline for (.{
        receipts.Context.verify,
        receipts.Context.prepared,
        receipts.Context.runProducer,
        receipts.Context.package,
        receipts.Context.publish,
        inputs.generate,
        provenance.verify,
        provenance.requireCurrentExecutable,
        producer.execute,
        fs.copyImmutable,
        admission.load,
        admission.verifyExecution,
    }) |entry| {
        var pointer: *const @TypeOf(entry) = &entry;
        std.mem.doNotOptimizeAway(&pointer);
    }
}

fn shapeFile(path: []const u8, size: u64) c.File {
    return .{ .path = path, .size = size, .mode = 0o600, .sha256 = c.digest(path) };
}

fn shapeSource() c.Source {
    return .{
        .scheme = .git_physical_native_v1,
        .head = "1111111111111111111111111111111111111111",
        .tree = "2222222222222222222222222222222222222222",
        .tree_sha256 = c.digest("public synthetic Git tree SHAPE only"),
        .physical = .{ .sha256 = c.digest("public synthetic physical SHAPE only"), .files = 3, .bytes = 128 },
    };
}

fn shapeTool(role: rt.Role, executable: ?c.File) rt.Tool {
    return .{
        .role = role,
        .origin = if (role == .dependencies) @import("origin_fixture.zig").shapePackage() else if (role == .preparation or role == .git or role == .m4) @import("origin_fixture.zig").local() else @import("origin_fixture.zig").shapeDistribution(),
        .target = if (executable == null) .data else .aarch64_linux,
        .tree = .{ .sha256 = c.digest("public synthetic runtime SHAPE only"), .files = 1, .bytes = 128 },
        .executable = executable,
        .loader = null,
        .libraries = &.{},
    };
}

// These records exercise SHAPE and cryptographic linking only. They are never
// execution, source-approval, image-validation, or completed-handoff fixtures.
fn shapePrepared(allocator: std.mem.Allocator) !receipts.Receipt {
    const selected_source = shapeSource();
    var compiler = shapeTool(.zig, shapeFile("bin/zig", 128));
    compiler.executable.?.mode = 0o755;
    var native = shapeTool(.preparation, shapeFile("bin/prepare", 128));
    native.executable.?.mode = 0o755;
    native.origin.payload.local_build.source_physical_sha256 = selected_source.physical.sha256;
    native.origin.payload.local_build.compiler_executable_sha256 = compiler.executable.?.sha256;
    var git = shapeTool(.git, shapeFile("bin/git", 128));
    git.executable.?.mode = 0o755;
    const dependencies = try allocator.alloc(provenance.Dependency, 1);
    dependencies[0] = .{
        .name = "miz_source",
        .package_hash = provenance.miz_package_hash,
        .content = shapeTool(.dependencies, null),
    };
    const review: provenance.Record = .{
        .schema = .hyperv_native_producer_provenance_v2,
        .source = selected_source,
        .host_target = .aarch64_linux,
        .guest_target = .x86_64_freestanding_none,
        .compiler_version = c.compiler_version,
        .producer = native,
        .compiler = compiler,
        .git = git,
        .dependencies = dependencies,
        .trust = shapeTool(.trust, null),
    };
    return .{
        .schema = .hyperv_artifact_preparation_native_v2,
        .phase = .prepared,
        .purpose = .synthetic,
        .run_id = try c.identity("11111111111111111111111111111111"),
        .guard = .{
            .run_id = try c.identity("11111111111111111111111111111111"),
            .disk_id = try c.identity("22222222222222222222222222222222"),
            .sectors = 49,
            .lun = 0,
        },
        .source_before = selected_source,
        .source_after = selected_source,
        .provenance = review,
        .reviewed_provenance_sha256 = c.digest(try c.canonical(allocator, review)),
        .config_before = shapeFile("guarded.config", 128),
        .config_after = shapeFile("guarded.config", 128),
        .parent_sha256 = null,
        .execution = null,
        .efi = null,
        .packaging = null,
        .authority = .not_admitted,
    };
}

fn shapeLink(allocator: std.mem.Allocator, receipt: receipts.Receipt) !receipts.Link {
    return .{ .receipt = receipt, .sha256 = c.digest(try c.canonical(allocator, receipt)) };
}

fn shapeChain(allocator: std.mem.Allocator) ![4]receipts.Link {
    var result: [4]receipts.Link = undefined;
    result[0] = try shapeLink(allocator, try shapePrepared(allocator));
    for ([_]c.Phase{ .configured, .built, .packaged }, 1..) |phase, i| {
        var receipt = result[i - 1].receipt;
        receipt.phase = phase;
        receipt.parent_sha256 = result[i - 1].sha256;
        receipt.config_before = result[i - 1].receipt.config_after;
        receipt.execution = if (phase == .packaged) null else .{
            .step = if (phase == .configured) .configure else .build,
            .exit_code = 0,
            .cleanup_complete = true,
            .admitted_binding_sha256 = c.digest("SHAPE only; not native execution approval"),
        };
        if (phase == .configured) receipt.config_after.sha256 = c.digest("SHAPE solved config");
        if (phase == .built) receipt.efi = shapeFile("synthetic.efi", 512);
        if (phase == .packaged) {
            const raw = shapeFile(packaging.raw_name, c.image_bytes);
            receipt.packaging = .{
                .schema = .miz_efi_application_package_v1,
                .miz_revision = c.miz_revision,
                .architecture = .x86_64,
                .generation = .gen2,
                .boot_path = @import("miz").efi_application_image.fallback_x86_64,
                .efi = receipt.efi.?,
                .raw = raw,
                .vhd = shapeFile(packaging.vhd_name, packaging.vhd_bytes),
                .identities = .{
                    .disk_guid_le = try c.identity("33333333333333333333333333333333"),
                    .esp_partition_guid_le = try c.identity("44444444444444444444444444444444"),
                    .esp_volume_id = 1,
                },
                .geometry = .{
                    .virtual_size = c.image_bytes,
                    .sector_size = 512,
                    .esp_offset_bytes = packaging.esp_offset,
                    .esp_length_bytes = packaging.esp_bytes,
                },
                .raw_vhd_prefix_sha256 = raw.sha256,
            };
        }
        result[i] = try shapeLink(allocator, receipt);
    }
    return result;
}

fn replaceOnce(allocator: std.mem.Allocator, bytes: []const u8, from: []const u8, to: []const u8) ![]u8 {
    const offset = std.mem.indexOf(u8, bytes, from) orelse return error.MissingFixtureField;
    return std.mem.concat(allocator, u8, &.{ bytes[0..offset], to, bytes[offset + from.len ..] });
}

test "typed native contracts reject duplicate missing unknown float noncanonical and version fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const value = shapeFile("public.fixture", 7);
    const bytes = try c.canonical(allocator, value);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "\"sha256\":\"") != null);
    try std.testing.expectError(error.DuplicateField, c.parse(c.File, allocator, try replaceOnce(allocator, bytes, "\"mode\":384", "\"mode\":384,\"mode\":384")));
    try std.testing.expectError(error.UnexpectedFields, c.parse(c.File, allocator, try replaceOnce(allocator, bytes, "\"mode\":384,", "")));
    try std.testing.expectError(error.UnexpectedFields, c.parse(c.File, allocator, try replaceOnce(allocator, bytes, "}\n", ",\"unknown\":false}\n")));
    for ([_][]const u8{ "7.0", "7e0", "7E+0", "-0" }) |number|
        try std.testing.expectError(error.ExpectedInteger, c.parse(c.File, allocator, try replaceOnce(allocator, bytes, "\"size\":7", try std.fmt.allocPrint(allocator, "\"size\":{s}", .{number}))));
    try std.testing.expectError(error.IntegerOverflow, c.parse(c.File, allocator, try replaceOnce(allocator, bytes, "\"size\":7", "\"size\":18446744073709551616")));
    try std.testing.expectError(error.IntegerOverflow, c.parse(c.File, allocator, try replaceOnce(allocator, bytes, "\"size\":7", "\"size\":-1")));
    try std.testing.expectError(error.ExpectedInteger, c.parse(c.File, allocator, try replaceOnce(allocator, bytes, "\"size\":7", "\"size\":\"7\"")));
    try std.testing.expectError(error.NonCanonical, c.parse(c.File, allocator, bytes[0 .. bytes.len - 1]));
    try std.testing.expectError(error.NonCanonical, c.parse(c.File, allocator, try std.mem.concat(allocator, u8, &.{ " ", bytes })));
    const receipt = try c.canonical(allocator, try shapePrepared(allocator));
    for ([_]struct { from: []const u8, to: []const u8 }{
        .{ .from = "hyperv_artifact_preparation_native_v2", .to = "hyperv_artifact_preparation_native_v1" },
        .{ .from = "hyperv_native_producer_provenance_v2", .to = "hyperv_native_producer_provenance_v1" },
        .{ .from = "\"phase\":\"prepared\"", .to = "\"phase\":\"completed\"" },
        .{ .from = "\"phase\":\"prepared\"", .to = "\"phase\":\"accepted\"" },
        .{ .from = "\"authority\":\"not_admitted\"", .to = "\"authority\":\"accepted\"" },
    }) |change| {
        const bad = try replaceOnce(allocator, receipt, change.from, change.to);
        try std.testing.expectError(error.InvalidEnum, receipts.parse(allocator, bad, c.digest(bad)));
    }
    const shortened = try replaceOnce(allocator, bytes, &value.sha256, "abcd");
    try std.testing.expectError(error.InvalidLength, c.parse(c.File, allocator, shortened));
}

test "SHAPE ONLY receipt chains retain four local phases exact canonical parents and immutable fresh links" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const chain = try shapeChain(allocator);
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    try directory.dir.setPermissions(io, .fromMode(0o700));
    var lock = try (private.Directory{ .dir = directory.dir }).lock(io);
    defer lock.close(io);
    const names = [_][]const u8{ "prepared.receipt.json", "configured.receipt.json", "built.receipt.json", "packaged.receipt.json" };
    for (chain, names, 0..) |link, name, i| {
        const bytes = try c.canonical(allocator, link.receipt);
        const result = try fs.publish(&lock, io, name, bytes);
        try std.testing.expectEqual(.durable, result.status);
        try std.testing.expect(result.failures.primary == null and result.failures.cleanup == null and result.failures.recording == null);
        const stored = try lock.directory.read(io, allocator, name, 1024 * 1024, null);
        const parsed = try receipts.parse(allocator, stored, link.sha256);
        defer parsed.deinit();
        try std.testing.expectEqual(link.receipt.phase, parsed.value.phase);
        try std.testing.expectEqual(.not_admitted, parsed.value.authority);
        const encoded = try c.canonical(allocator, parsed.value);
        try std.testing.expectEqualStrings(bytes, encoded);
        if (i != 0) try receipts.requireParent(allocator, parsed.value, chain[i - 1]);
        try std.testing.expectError(error.PathAlreadyExists, fs.publish(&lock, io, name, bytes));
        try std.testing.expectError(error.HashMismatch, receipts.parse(allocator, stored, c.digest("not this receipt")));
    }
}

test "SHAPE ONLY receipt phases reject replay skipped parents changed identities config and source" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const chain = try shapeChain(allocator);
    for (chain[1..], 1..) |link, i| {
        var changed = link.receipt;
        changed.parent_sha256 = c.digest("different parent");
        try std.testing.expectError(error.ReceiptSubstitution, receipts.requireParent(allocator, changed, chain[i - 1]));
        var forged_parent = chain[i - 1];
        forged_parent.sha256 = changed.parent_sha256.?;
        try std.testing.expectError(error.ReceiptSubstitution, receipts.requireParent(allocator, changed, forged_parent));
        changed = link.receipt;
        changed.run_id = try c.identity("55555555555555555555555555555555");
        changed.guard.run_id = changed.run_id;
        try std.testing.expectError(error.ReceiptSubstitution, receipts.requireParent(allocator, changed, chain[i - 1]));
        changed = link.receipt;
        changed.guard.disk_id = try c.identity("66666666666666666666666666666666");
        try std.testing.expectError(error.ReceiptSubstitution, receipts.requireParent(allocator, changed, chain[i - 1]));
        changed = link.receipt;
        changed.config_before.sha256 = c.digest("substituted config");
        if (changed.phase != .configured) changed.config_after = changed.config_before;
        try std.testing.expectError(error.HashMismatch, receipts.requireParent(allocator, changed, chain[i - 1]));
        changed = link.receipt;
        changed.source_after.tree_sha256 = c.digest("mutated source");
        try std.testing.expectError(error.UnreviewedInput, receipts.validate(changed));
    }
    var replay = chain[1].receipt;
    replay.parent_sha256 = chain[1].sha256;
    replay.config_before = chain[1].receipt.config_after;
    try std.testing.expectError(error.InvalidPhase, receipts.requireParent(allocator, replay, chain[1]));
    var skipped = chain[2].receipt;
    skipped.config_before = chain[0].receipt.config_after;
    skipped.config_after = skipped.config_before;
    skipped.parent_sha256 = chain[0].sha256;
    try std.testing.expectError(error.InvalidPhase, receipts.requireParent(allocator, skipped, chain[0]));
    var changed = chain[0].receipt;
    changed.parent_sha256 = chain[0].sha256;
    try std.testing.expectError(error.InvalidPhase, receipts.validate(changed));
    changed = chain[0].receipt;
    changed.efi = shapeFile("unbuilt.efi", 512);
    try std.testing.expectError(error.InvalidPhase, receipts.validate(changed));
    changed = chain[3].receipt;
    changed.efi.?.sha256 = c.digest("different built EFI");
    changed.packaging.?.efi = changed.efi.?;
    try std.testing.expectError(error.HashMismatch, receipts.requireParent(allocator, changed, chain[2]));
}

test "SHAPE ONLY receipts cannot claim phases from nonzero failed or incomplete producer execution" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const chain = try shapeChain(allocator);
    for (chain[1..3]) |link| {
        var changed = link.receipt;
        changed.execution.?.exit_code = 1;
        try std.testing.expectError(error.IncompleteExecution, receipts.validate(changed));
        changed = link.receipt;
        changed.execution.?.cleanup_complete = false;
        try std.testing.expectError(error.IncompleteExecution, receipts.validate(changed));
        changed = link.receipt;
        changed.execution.?.step = .inspect;
        try std.testing.expectError(error.InvalidPhase, receipts.validate(changed));
        changed = link.receipt;
        changed.execution = null;
        try std.testing.expectError(error.InvalidPhase, receipts.validate(changed));
        const bytes = try c.canonical(allocator, link.receipt);
        const forged = try replaceOnce(allocator, bytes, "\"exit_code\":0", "\"exit_code\":0,\"failures\":{\"primary\":\"failed\"}");
        try std.testing.expectError(error.UnexpectedFields, receipts.parse(allocator, forged, c.digest(forged)));
    }
    var changed = chain[3].receipt;
    changed.execution = chain[2].receipt.execution;
    try std.testing.expectError(error.InvalidPhase, receipts.validate(changed));
}

test "SHAPE ONLY reviewed provenance rejects substitution of every producer compiler target runtime dependency and trust binding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const chain = try shapeChain(allocator);
    const original = chain[1].receipt;
    for (0..8) |kind| {
        var changed = original;
        switch (kind) {
            0 => changed.provenance.producer.tree.sha256 = c.digest("substitute producer"),
            1 => changed.provenance.compiler.tree.sha256 = c.digest("substitute compiler runtime"),
            2 => changed.provenance.git.tree.sha256 = c.digest("substitute git"),
            3 => changed.provenance.trust.tree.sha256 = c.digest("substitute trust"),
            4 => {
                const deps = try allocator.dupe(provenance.Dependency, original.provenance.dependencies);
                deps[0].content.tree.sha256 = c.digest("substitute dependency bytes");
                changed.provenance.dependencies = deps;
            },
            5 => changed.provenance.producer.origin.payload.local_build.source_revision = "3" ** 40,
            6 => changed.provenance.git.origin.payload.local_build.compiler_executable_sha256 = c.digest("substitute runtime producer"),
            7 => changed.provenance.trust.origin.payload.distribution.evidence_set_sha256 = c.digest("substitute trust source"),
            else => unreachable,
        }
        const bytes = try c.canonical(allocator, changed);
        try std.testing.expectError(error.UnreviewedInput, receipts.parse(allocator, bytes, c.digest(bytes)));
        try std.testing.expectError(error.UnreviewedInput, receipts.requireParent(allocator, changed, chain[0]));
        changed.reviewed_provenance_sha256 = c.digest(try c.canonical(allocator, changed.provenance));
        try std.testing.expectError(if (kind == 5) error.UnreviewedInput else error.ReceiptSubstitution, receipts.requireParent(allocator, changed, chain[0]));
    }
    var changed = original.provenance;
    changed.compiler_version = "0.16.1";
    try std.testing.expectError(error.CompilerMismatch, provenance.validate(changed));
    changed = original.provenance;
    changed.host_target = .x86_64_linux;
    try std.testing.expectError(error.CompilerMismatch, provenance.validate(changed));
    changed = original.provenance;
    changed.compiler.target = .x86_64_linux;
    try std.testing.expectError(error.CompilerMismatch, provenance.validate(changed));
    changed = original.provenance;
    changed.dependencies = &.{};
    try std.testing.expectError(error.IncompleteProvenance, provenance.validate(changed));
    changed = original.provenance;
    changed.dependencies = try std.mem.concat(allocator, provenance.Dependency, &.{ original.provenance.dependencies, original.provenance.dependencies });
    try std.testing.expectError(error.InvalidProvenance, provenance.validate(changed));
    changed = original.provenance;
    changed.producer.origin.payload.local_build.compiler_executable_sha256 = c.digest("unrelated compiler");
    try std.testing.expectError(error.UnreviewedInput, provenance.validate(changed));
}

test "SHAPE ONLY provenance rejects malformed runtime hashes paths modes and cross host Git" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const original = (try shapePrepared(arena.allocator())).provenance;
    var changed = original;
    changed.git.target = .x86_64_linux;
    try std.testing.expectError(error.CompilerMismatch, provenance.validate(changed));
    changed = original;
    changed.trust.tree.sha256[0] = 'g';
    try std.testing.expectError(error.InvalidSha256, provenance.validate(changed));
    changed = original;
    changed.trust.origin.payload.distribution.evidence_set_sha256[0] = 'A';
    try std.testing.expectError(error.InvalidSha256, provenance.validate(changed));
    changed = original;
    changed.compiler.executable.?.path = "../outside";
    try std.testing.expectError(error.UnsafePath, provenance.validate(changed));
    changed = original;
    changed.compiler.executable.?.mode = 0o666;
    try std.testing.expectError(error.InvalidRuntime, provenance.validate(changed));
    changed = original;
    changed.trust.executable = original.compiler.executable;
    try std.testing.expectError(error.InvalidRuntime, provenance.validate(changed));
    changed = original;
    changed.producer.tree.bytes = 0;
    try std.testing.expectError(error.InvalidRuntime, provenance.validate(changed));
}

fn shapePlan(allocator: std.mem.Allocator, packaged: receipts.Link) !inputs.Plan {
    const assets = try allocator.alloc(inputs.Asset, 27);
    const roles = [_]budget.Role{
        .raw,            .boot_disk,        .qemu,                .qemu_support,  .firmware_code, .firmware_vars,
        .native_control, .producer_control, .publication_control, .baked_control,
    };
    const names = [_][]const u8{
        "acceptance.raw",   "capability.raw", "bin/qemu",         "share/support.bin",       "firmware-code.fd",
        "firmware-vars.fd", "native-control", "producer-control", "capability-receipt.json", "baked-control",
    };
    const sizes = [_]u64{ c.image_bytes, c.image_bytes, 4096, 512, 1024 * 1024, 256 * 1024, 1024, 512, 1024, 512 };
    for (roles, names, sizes, 0..) |role, name, size, i| assets[i] = .{
        .id = @tagName(role),
        .role = role,
        .source = shapeFile(name, size),
        .destination = name,
        .placement = if (role == .baked_control) .baked else .staged,
    };
    assets[0].source = packaged.receipt.packaging.?.raw;
    assets[2].source.mode = 0o755;
    assets[7].source = packaged.receipt.provenance.producer.executable.?;
    assets[10] = .{
        .id = "private-vhd",
        .role = .vhd,
        .source = packaged.receipt.packaging.?.vhd,
        .destination = "private.vhd",
        .placement = .staged,
    };
    assets[11] = .{
        .id = "solved-metadata",
        .role = .publication_control,
        .source = shapeFile("native-config/metadata.tsv", 256),
        .destination = "metadata.tsv",
        .placement = .staged,
    };
    for (assets[12..18], 0..) |*item, i| item.* = .{
        .id = try std.fmt.allocPrint(allocator, "vars-copy-{d}", .{i}),
        .role = .firmware_working_copy,
        .source = assets[5].source,
        .destination = try std.fmt.allocPrint(allocator, "firmware/vars-{d}.fd", .{i}),
        .placement = .future_copy,
    };
    var qemu = shapeTool(.qemu, assets[2].source);
    qemu.target = .x86_64_linux;
    qemu.tree.files = 2;
    qemu.tree.bytes = assets[2].source.size + assets[3].source.size;
    const chain = try shapeChain(allocator);
    var publication: @FieldType(inputs.Plan, "publication") = undefined;
    for (&publication.receipts, chain, [_][]const u8{ "prepared.receipt.json", "configured.receipt.json", "built.receipt.json", "packaged.receipt.json" }) |*record, link, name|
        record.* = .{ .path = name, .sha256 = link.sha256, .size = (try c.canonical(allocator, link.receipt)).len, .mode = 0o600 };
    for (&publication.executions, [_][]const u8{ "configured.binding.json", "built.binding.json" }, 0..) |*record, name, i| {
        record.* = shapeFile(name, 128);
        record.sha256 = chain[i + 1].receipt.execution.?.admitted_binding_sha256;
    }
    for (&publication.inspections, [_][]const u8{ "configured.inspection.binding.json", "built.inspection.binding.json" }) |*record, name|
        record.* = shapeFile(name, 128);
    const controls = publication.receipts ++ publication.executions ++ publication.inspections ++ [_]c.File{packaged.receipt.config_after};
    for (assets[18..], controls) |*item, record| item.* = .{
        .id = record.path,
        .role = .publication_control,
        .source = record,
        .destination = record.path,
        .placement = .staged,
    };
    return .{
        .schema = .hyperv_native_input_selection_v3,
        .packaged_receipt_sha256 = packaged.sha256,
        .solved_metadata = assets[11].source,
        .publication = publication,
        .capability_source = shapeSource(),
        .capability_receipt = assets[8].source,
        .qemu = qemu,
        .firmware_origins = .{
            .code = .{ .asset_id = assets[4].id, .directory = .{ .path = "/shape/firmware", .device = 1, .inode = 1, .mode = 0o40700, .uid = 1000 }, .physical_sha256 = c.digest("shape"), .tool = shapeTool(.firmware, null), .member = assets[4].source },
            .vars = .{ .asset_id = assets[5].id, .directory = .{ .path = "/shape/firmware", .device = 1, .inode = 1, .mode = 0o40700, .uid = 1000 }, .physical_sha256 = c.digest("shape"), .tool = shapeTool(.firmware, null), .member = assets[5].source },
        },
        .assets = assets,
    };
}

test "SHAPE ONLY generation ledger charges six firmware copies all controls evidence and publication headroom" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const packaged = (try shapeChain(allocator))[3];
    const plan = try shapePlan(allocator, packaged);
    const entries = try inputs.ledger(std.testing.allocator, plan, packaged);
    defer std.testing.allocator.free(entries);
    try std.testing.expectEqual(@as(usize, 29), entries.len);
    var copies: usize = 0;
    var firmware_bytes: u64 = 0;
    for (entries) |entry| if (entry.role == .firmware_working_copy) {
        copies += 1;
        firmware_bytes += entry.source.?.size;
        try fs.requireFile(entry.source.?, plan.assets[5].source);
    };
    try std.testing.expectEqual(@as(usize, 6), copies);
    try std.testing.expectEqual(@as(u64, 6 * 256 * 1024), firmware_bytes);
    try std.testing.expectEqual(.publication_reservation, entries[entries.len - 2].role);
    var actual_controls: u64 = 0;
    for (plan.assets) |item| if (item.role.isControl()) {
        actual_controls += item.source.size;
    };
    try std.testing.expectEqual(c.control_cap - actual_controls, entries[entries.len - 2].reserved);
    try std.testing.expect(entries[entries.len - 2].source == null);
    try std.testing.expectEqual(.evidence, entries[entries.len - 1].role);
    try std.testing.expectEqual(@as(u64, 8 * 1024 * 1024), entries[entries.len - 1].reserved);
    const totals = try budget.compute(entries);
    try std.testing.expectEqual(c.control_cap, totals.control);
    try std.testing.expectEqual(3 * c.image_bytes + 512 + 4096 + 512 + 1024 * 1024 + 7 * 256 * 1024 + actual_controls, totals.used);
    try std.testing.expectEqual(c.total_cap, totals.used + totals.reserved + totals.total_remaining);
    const selected_sha = c.digest(try c.canonical(allocator, plan));
    const document: inputs.Input = .{
        .schema = .hyperv_native_prepared_input_v3,
        .state = .prepared,
        .authority = .not_admitted,
        .receipt = packaged.receipt,
        .reviewed_selection_sha256 = selected_sha,
        .selection = plan,
        .ledger = entries,
        .budget = totals,
    };
    try inputs.validate(std.testing.allocator, document, selected_sha);
    const bytes = try c.canonical(allocator, document);
    try std.testing.expect(bytes.len < entries[entries.len - 2].reserved);
    const parsed = try c.parse(inputs.Input, allocator, bytes);
    defer parsed.deinit();
    try inputs.validate(std.testing.allocator, parsed.value, selected_sha);
    for ([_][]const u8{ "completed", "accepted", "configured" }) |state| {
        const bad = try replaceOnce(allocator, bytes, "\"state\":\"prepared\"", try std.fmt.allocPrint(allocator, "\"state\":\"{s}\"", .{state}));
        try std.testing.expectError(error.InvalidEnum, c.parse(inputs.Input, allocator, bad));
    }
    var changed = document;
    changed.budget.used -= 1;
    try std.testing.expectError(error.BudgetSubstitution, inputs.validate(std.testing.allocator, changed, selected_sha));
    changed = document;
    changed.ledger = entries[1..];
    try std.testing.expectError(error.LedgerClosureMismatch, inputs.validate(std.testing.allocator, changed, selected_sha));
    changed = document;
    changed.reviewed_selection_sha256 = c.digest("unreviewed selection");
    try std.testing.expectError(error.UnreviewedInput, inputs.validate(std.testing.allocator, changed, selected_sha));
}

test "SHAPE ONLY eight MiB policy does not silently adopt a former two MiB prepared ledger" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const chain = try shapeChain(allocator);
    const current = try shapeInput(allocator, chain);
    try inputs.validate(allocator, current, current.reviewed_selection_sha256);
    var previous = current;
    const entries = try allocator.dupe(budget.Entry, current.ledger);
    var found = false;
    for (entries) |*entry| {
        if (entry.role != .publication_reservation or !std.mem.eql(u8, entry.id, "remaining-controls")) continue;
        try std.testing.expect(entry.reserved > 8388608 - 2097152);
        entry.reserved -= 8388608 - 2097152;
        found = true;
    }
    try std.testing.expect(found);
    previous.ledger = entries;
    previous.budget = try budget.compute(entries);
    try std.testing.expectEqual(@as(u64, 2097152), previous.budget.control);
    try std.testing.expectError(error.LedgerClosureMismatch, inputs.validate(allocator, previous, previous.reviewed_selection_sha256));
    try inputs.validate(allocator, current, current.reviewed_selection_sha256);
}

test "SHAPE ONLY generation rejects missing controls partial QEMU duplicate paths and forged package links" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const packaged = (try shapeChain(allocator))[3];
    const plan = try shapePlan(allocator, packaged);
    for ([_]usize{ 6, 7, 8, 9 }) |missing| {
        var changed = plan;
        const assets = try allocator.dupe(inputs.Asset, plan.assets);
        assets[missing].role = .qemu_support;
        assets[missing].placement = .staged;
        changed.assets = assets;
        try std.testing.expectError(error.MissingControls, inputs.ledger(std.testing.allocator, changed, packaged));
    }
    var changed = plan;
    changed.assets = plan.assets[0..17];
    try std.testing.expectError(error.InvalidSelection, inputs.ledger(allocator, changed, packaged));
    var assets = try allocator.dupe(inputs.Asset, plan.assets);
    changed = plan;
    changed.assets = assets;
    assets[13].destination = assets[12].destination;
    try std.testing.expectError(error.DuplicateLedgerArtifact, inputs.ledger(allocator, changed, packaged));
    @memcpy(assets, plan.assets);
    assets[13].id = assets[12].id;
    try std.testing.expectError(error.DuplicateLedgerId, inputs.ledger(allocator, changed, packaged));
    @memcpy(assets, plan.assets);
    assets[3].source = assets[2].source;
    try std.testing.expectError(error.IncompleteRuntime, inputs.ledger(allocator, changed, packaged));
    @memcpy(assets, plan.assets);
    assets[3].role = .publication_control;
    try std.testing.expectError(error.IncompleteRuntime, inputs.ledger(allocator, changed, packaged));
    @memcpy(assets, plan.assets);
    assets[12].source.sha256 = c.digest("different variable firmware");
    try std.testing.expectError(error.HashMismatch, inputs.ledger(allocator, changed, packaged));
    @memcpy(assets, plan.assets);
    assets[12].placement = .staged;
    try std.testing.expectError(error.InvalidSelection, inputs.ledger(allocator, changed, packaged));
    @memcpy(assets, plan.assets);
    assets[6].source.size = c.control_cap;
    try std.testing.expectError(error.ControlLimitExceeded, inputs.ledger(allocator, changed, packaged));
    @memcpy(assets, plan.assets);
    assets[1].source.size = c.total_cap;
    try std.testing.expectError(error.LimitExceeded, inputs.ledger(allocator, changed, packaged));
    @memcpy(assets, plan.assets);
    for ([_][]const u8{ "input.json", ".writer.lock", "../outside", "/outside" }) |path| {
        assets[6].destination = path;
        try std.testing.expectError(error.UnsafePath, inputs.ledger(allocator, changed, packaged));
    }
    changed = plan;
    var forged = packaged;
    forged.sha256 = c.digest("invented package link");
    changed.packaged_receipt_sha256 = forged.sha256;
    try std.testing.expectError(error.ReceiptSubstitution, inputs.ledger(allocator, changed, forged));
    changed = plan;
    changed.qemu.target = .aarch64_linux;
    try std.testing.expectError(error.InvalidSelection, inputs.ledger(allocator, changed, packaged));
    changed = plan;
    changed.qemu.loader = shapeFile("lib/missing-loader", 128);
    try std.testing.expectError(error.IncompleteRuntime, inputs.ledger(allocator, changed, packaged));
}

fn shapeInput(allocator: std.mem.Allocator, chain: [4]receipts.Link) !inputs.Input {
    const plan = try shapePlan(allocator, chain[3]);
    const entries = try inputs.ledger(allocator, plan, chain[3]);
    return .{
        .schema = .hyperv_native_prepared_input_v3,
        .state = .prepared,
        .authority = .not_admitted,
        .receipt = chain[3].receipt,
        .reviewed_selection_sha256 = c.digest(try c.canonical(allocator, plan)),
        .selection = plan,
        .ledger = entries,
        .budget = try budget.compute(entries),
    };
}

fn shapeReview(allocator: std.mem.Allocator, chain: [4]receipts.Link, input: inputs.Input) !admission.Review {
    var result: admission.Review = .{
        .input_sha256 = c.digest(try c.canonical(allocator, input)),
        .selection_sha256 = input.reviewed_selection_sha256,
        .provenance_sha256 = input.receipt.reviewed_provenance_sha256,
        .capability_provenance_sha256 = c.digest("independent capability review SHAPE ONLY"),
        .receipt_sha256 = undefined,
        .execution_sha256 = .{ chain[1].receipt.execution.?.admitted_binding_sha256, chain[2].receipt.execution.?.admitted_binding_sha256 },
        .engine_runtime_sha256 = c.digest("independent engine runtime SHAPE ONLY"),
        .engine_executable_sha256 = c.digest("different engine executable SHAPE ONLY"),
    };
    for (chain, &result.receipt_sha256) |link, *hash| hash.* = link.sha256;
    return result;
}

test "entry chain requires independent selection provenance receipt and execution commitments" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const chain = try shapeChain(a);
    const input = try shapeInput(a, chain);
    const review = try shapeReview(a, chain, input);
    try admission.requireChain(a, chain, input, review);
    var bad = review;
    bad.selection_sha256 = c.digest("other selection");
    try std.testing.expectError(error.UnreviewedInput, admission.requireChain(a, chain, input, bad));
    bad = review;
    bad.provenance_sha256 = c.digest("other review");
    try std.testing.expectError(error.ReceiptSubstitution, admission.requireChain(a, chain, input, bad));
    for (0..4) |i| {
        bad = review;
        bad.receipt_sha256[i] = c.digest("substituted receipt");
        try std.testing.expectError(error.ReceiptSubstitution, admission.requireChain(a, chain, input, bad));
    }
    for (0..2) |i| {
        bad = review;
        bad.execution_sha256[i] = c.digest("self-approved execution");
        try std.testing.expectError(error.UnreviewedInput, admission.requireChain(a, chain, input, bad));
    }
    const projection = try admission.project(input, review);
    try std.testing.expectEqual(review.provenance_sha256, projection.guarded_producer_sha256);
    try std.testing.expectEqual(review.engine_executable_sha256, projection.engine_executable_sha256);
    try std.testing.expect(!std.meta.eql(projection.guarded_producer_sha256, projection.producer_executable_sha256));
    try std.testing.expectEqual(@as(usize, 32), (try admission.rawHash(review.input_sha256)).len);
    const storage = try admission.storageIdentity(input.receipt.run_id);
    try std.testing.expectEqual(@as(u8, 0x11), storage.bytes[0]);
    try std.testing.expectError(error.InvalidSha256, admission.rawHash(("G" ** 64).*));
    const encoded = try c.canonical(a, input);
    const legacy = try replaceOnce(a, encoded, "hyperv_native_prepared_input_v3", "hyperv_native_prepared_input_v2");
    try std.testing.expectError(error.InvalidEnum, c.parse(inputs.PreparedInputV3, a, legacy));
}

test "read-only staged entry rejects leftover directories changed bytes modes links and forged input" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    const path = try fixture.dir.realPathFileAlloc(io, ".", a);
    const directory = try fs.openPrivate(io, path);
    defer directory.close(io);
    var lock = try directory.lock(io);
    defer lock.close(io);
    try fixture.dir.createDir(io, "qemu", .fromMode(0o700));
    try writeFixture(fixture.dir, "qemu/public.bin", "public synthetic", 0o600);
    try writeFixture(fixture.dir, "input.json", "{}\n", 0o600);
    const measured: fs.Directory = .{ .dir = fixture.dir, .path = path };
    const asset = inputs.Asset{
        .id = "public",
        .role = .qemu_support,
        .source = try measured.record(a, io, "qemu/public.bin", 100, .private),
        .destination = "qemu/public.bin",
        .placement = .staged,
    };
    const input = try measured.record(a, io, "input.json", 100, .private);
    _ = try inputs.requireStagedClosure(a, io, &lock, &.{asset}, input);
    try fixture.dir.createDir(io, "unaccounted-empty", .fromMode(0o700));
    try std.testing.expectError(error.InvalidSelection, inputs.requireStagedClosure(a, io, &lock, &.{asset}, input));
    try fixture.dir.deleteDir(io, "unaccounted-empty");
    try writeFixture(fixture.dir, "qemu/public.bin", "public substitute", 0o600);
    try std.testing.expectError(error.HashMismatch, inputs.requireStagedClosure(a, io, &lock, &.{asset}, input));
    try writeFixture(fixture.dir, "qemu/public.bin", "public synthetic", 0o644);
    try std.testing.expectError(error.UnsafeFile, inputs.requireStagedClosure(a, io, &lock, &.{asset}, input));
    try writeFixture(fixture.dir, "qemu/public.bin", "public synthetic", 0o600);
    try writeFixture(fixture.dir, "input.json", "{\"forged\":true}\n", 0o600);
    try std.testing.expectError(error.HashMismatch, inputs.requireStagedClosure(a, io, &lock, &.{asset}, input));
    try writeFixture(fixture.dir, "input.json", "{}\n", 0o600);
    try fixture.dir.symLink(io, "qemu/public.bin", "unaccounted-link", .{});
    try std.testing.expectError(error.UnsafeFile, inputs.requireStagedClosure(a, io, &lock, &.{asset}, input));
}

test "current engine identity is physically bound without weakening producer self verification" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    const directory: fs.Directory = .{ .dir = fixture.dir, .path = try fixture.dir.realPathFileAlloc(io, ".", a) };
    const self = try std.Io.Dir.openFileAbsolute(io, "/proc/self/exe", .{});
    defer self.close(io);
    const info = try fs.metadata(self);
    if (info.size > 128 * 1024 * 1024) return error.LimitExceeded;
    const bytes = try a.alloc(u8, @intCast(info.size));
    try std.testing.expectEqual(bytes.len, try self.readPositionalAll(io, bytes, 0));
    try writeFixture(fixture.dir, "engine", bytes, info.mode & 0o7777);
    const record = try directory.record(a, io, "engine", bytes.len, .executable);
    var tool = shapeTool(.preparation, record);
    tool.target = if (@import("builtin").cpu.arch == .aarch64) .aarch64_linux else .x86_64_linux;
    tool.tree = (try fs.inventory(a, io, directory, 4, 128 * 1024 * 1024)).tree;
    const bound: rt.Bound = .{ .directory = directory, .contract = tool };
    const chain = try shapeChain(a);
    var review = try shapeReview(a, chain, try shapeInput(a, chain));
    review.engine_executable_sha256 = record.sha256;
    review.engine_runtime_sha256 = c.digest(try c.canonical(a, tool));
    try std.testing.expectError(error.UnreviewedInput, admission.requireEngine(a, io, bound, review));
    const actual_path = try std.Io.Dir.cwd().realPathFileAlloc(io, "/proc/self/exe", a);
    const actual_directory = try fs.Directory.open(a, io, std.fs.path.dirname(actual_path).?);
    defer actual_directory.close(a, io);
    var actual_tool = tool;
    actual_tool.executable = try actual_directory.record(a, io, std.fs.path.basename(actual_path), 128 * 1024 * 1024, .executable);
    actual_tool.tree = (try fs.inventory(a, io, actual_directory, 16, 512 * 1024 * 1024)).tree;
    var actual_review = review;
    actual_review.engine_runtime_sha256 = c.digest(try c.canonical(a, actual_tool));
    try admission.requireEngine(a, io, .{ .directory = actual_directory, .contract = actual_tool }, actual_review);
    try std.testing.expectError(error.UnreviewedInput, provenance.requireCurrentExecutable(io, chain[0].receipt.provenance));
    var bad = review;
    bad.engine_executable_sha256 = c.digest("another executable");
    try std.testing.expectError(error.UnreviewedInput, admission.requireEngine(a, io, bound, bad));
    bad = review;
    bad.engine_runtime_sha256 = c.digest("another review");
    try std.testing.expectError(error.UnreviewedInput, admission.requireEngine(a, io, bound, bad));
    try writeFixture(fixture.dir, "engine", "substituted", info.mode & 0o7777);
    try std.testing.expectError(error.HashMismatch, admission.requireEngine(a, io, bound, review));
}

test "reservation permutation cannot borrow evidence allowance and identical copies need distinct control bindings" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const chain = try shapeChain(a);
    var plan = try shapePlan(a, chain[3]);
    const entries = try inputs.ledger(a, plan, chain[3]);
    const allowance = try inputs.publicationAllowance(entries);
    std.mem.swap(budget.Entry, &entries[entries.len - 1], &entries[entries.len - 2]);
    try std.testing.expectEqual(allowance, try inputs.publicationAllowance(entries));
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    try fixture.dir.createDir(io, "producer", .fromMode(0o700));
    try fixture.dir.createDir(io, "engine", .fromMode(0o700));
    const path = try fixture.dir.realPathFileAlloc(io, ".", a);
    const producer_dir = try fs.Directory.open(a, io, try std.fs.path.join(a, &.{ path, "producer" }));
    defer producer_dir.close(a, io);
    const engine_dir = try fs.Directory.open(a, io, try std.fs.path.join(a, &.{ path, "engine" }));
    defer engine_dir.close(a, io);
    try writeFixture(producer_dir.dir, "control", "identical public controls", 0o700);
    try writeFixture(engine_dir.dir, "control", "identical public controls", 0o700);
    const record = try producer_dir.record(a, io, "control", 128, .executable);
    const assets = [_]inputs.Asset{
        .{ .id = "producer", .role = .producer_control, .source = record, .destination = "producer", .placement = .staged },
        .{ .id = "engine", .role = .native_control, .source = record, .destination = "engine", .placement = .staged },
    };
    const bindings = [_]inputs.Binding{ .{ .id = "producer", .directory = producer_dir }, .{ .id = "engine", .directory = engine_dir } };
    var required: rt.Bound = .{ .directory = engine_dir, .contract = shapeTool(.preparation, record) };
    required.contract.tree = (try fs.inventory(a, io, engine_dir, 4, 1024)).tree;
    plan.assets = assets[0..1];
    try std.testing.expectError(error.MissingControlBinding, inputs.requireControlBinding(a, io, plan, &bindings, required));
    plan.assets = &assets;
    try inputs.requireControlBinding(a, io, plan, &bindings, required);
    plan.assets = assets[0..1];
    try inputs.requireControlBinding(a, io, plan, &bindings, .{ .directory = producer_dir, .contract = required.contract });
}

test "physical control accounting requires every runtime file without library support or copy exemptions" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    try fixture.dir.createDir(io, "runtime", .fromMode(0o700));
    try fixture.dir.createDir(io, "copy", .fromMode(0o700));
    const path = try fixture.dir.realPathFileAlloc(io, ".", a);
    const directory = try fs.Directory.open(a, io, try std.fs.path.join(a, &.{ path, "runtime" }));
    defer directory.close(a, io);
    const copy = try fs.Directory.open(a, io, try std.fs.path.join(a, &.{ path, "copy" }));
    defer copy.close(a, io);
    // These are physical accounting fixtures, not claimed ELF executables.
    const names = [_][]const u8{ "control", "loader", "library", "support" };
    const modes = [_]u16{ 0o700, 0o700, 0o600, 0o600 };
    var records: [4]c.File = undefined;
    var assets: [4]inputs.Asset = undefined;
    var bindings: [4]inputs.Binding = undefined;
    for (names, modes, 0..) |name, mode, i| {
        try writeFixture(directory.dir, name, name, mode);
        try writeFixture(copy.dir, name, name, mode);
        records[i] = try directory.record(a, io, name, 128, .artifact);
        assets[i] = .{ .id = name, .role = .native_control, .source = records[i], .destination = name, .placement = .staged };
        bindings[i] = .{ .id = name, .directory = directory };
    }
    var tool = shapeTool(.preparation, records[0]);
    tool.loader = records[1];
    tool.libraries = records[2..3];
    tool.tree = (try fs.inventory(a, io, directory, 8, 1024)).tree;
    const required: rt.Bound = .{ .directory = directory, .contract = tool };
    const chain = try shapeChain(a);
    var plan = try shapePlan(a, chain[3]);
    plan.assets = &assets;
    try inputs.requireControlBinding(a, io, plan, &bindings, required);
    for (0..assets.len) |i| {
        assets[i].role = .qemu_support;
        try std.testing.expectError(error.MissingControlBinding, inputs.requireControlBinding(a, io, plan, &bindings, required));
        assets[i].role = .native_control;
        bindings[i].directory = copy;
        try std.testing.expectError(error.MissingControlBinding, inputs.requireControlBinding(a, io, plan, &bindings, required));
        bindings[i].directory = directory;
    }
    plan.assets = assets[0..3];
    try std.testing.expectError(error.MissingControlBinding, inputs.requireControlBinding(a, io, plan, &bindings, required));
    plan.assets = &assets;
    try writeFixture(directory.dir, "support", "changed", 0o600);
    try std.testing.expectError(error.HashMismatch, inputs.requireControlBinding(a, io, plan, &bindings, required));
    var oversized = required;
    oversized.contract.tree.bytes = c.control_cap + 1;
    try std.testing.expectError(error.ControlLimitExceeded, inputs.requireControlBinding(a, io, plan, &bindings, oversized));
}

test "merged native proof root builder and CLI are physically bound without running a root build" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const reference = try fs.Directory.open(a, io, @import("test_options").proof_fixture);
    defer reference.close(a, io);
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    try fixture.dir.createDirPath(io, "support/build");
    const directory: fs.Directory = .{ .dir = fixture.dir, .path = try fixture.dir.realPathFileAlloc(io, ".", a) };
    const names = [_][]const u8{ "build.zig", "support/build/hyperv-proof-build.zig", "support/build/hyperv-proof-tool.zig" };
    var contents: [3][]const u8 = undefined;
    var records: [3]c.File = undefined;
    for (names, 0..) |name, i| {
        contents[i] = try reference.read(a, io, name, 1024 * 1024, .source);
        try writeFixture(fixture.dir, name, contents[i], 0o600);
        records[i] = try directory.record(a, io, name, 1024 * 1024, .source);
    }
    // Only selection/physical-file fixtures: no source review or execution
    // admission is conferred by this synthetic Source record.
    const observed = (try shapeChain(a))[0].receipt.source_before;
    const proof: producer.NativeProof = .{
        .schema = .hyperv_native_elf_proofs_v2,
        .source_sha256 = observed.tree_sha256,
        .root_build = records[0],
        .builder = records[1],
        .tool = records[2],
        .modes = .{ .smp, .irq, .drivers },
    };
    try producer.requireNativeProofFiles(a, io, directory, observed, proof);
    const encoded = try c.canonical(a, proof);
    const parsed = try c.parse(producer.NativeProof, a, encoded);
    defer parsed.deinit();
    const legacy = try replaceOnce(a, encoded, "hyperv_native_elf_proofs_v2", "hyperv_native_elf_proofs_v1");
    try std.testing.expectError(error.InvalidEnum, c.parse(producer.NativeProof, a, legacy));

    const mutations = [_]struct { index: usize, old: []const u8, new: []const u8 }{
        .{ .index = 0, .old = "gate.step.dependOn(&driver_check.step);", .new = "// gate.step.dependOn(&driver_check.step);" },
        .{ .index = 0, .old = "hyperv_proof_build.tool(b, b.path(\".\"))", .new = "hyperv_proof_build.tool(b, b.path(\"substituted\"))" },
        .{ .index = 0, .old = "check.addArgs(&.{ \"smp\", \"--image\" });", .new = "check.addArgs(&.{ \"drivers\", \"--image\" });" },
        .{ .index = 1, .old = "\"support/build/hyperv-proof-tool.zig\", b.graph.host, .ReleaseSafe", .new = "\"support/build/hyperv-proof-tool.zig\", b.graph.host, .Debug" },
        .{ .index = 1, .old = "drivers/hyperv/vmbus/vmbus_protocol.zig", .new = "drivers/hyperv/vmbus/unselected.zig" },
        .{ .index = 2, .old = "try proofs.drivers(model, required.items, diagnostic);", .new = "// try proofs.drivers(model, required.items, diagnostic);" },
    };
    for (mutations) |mutation| {
        const changed = try replaceOnce(a, contents[mutation.index], mutation.old, mutation.new);
        try writeFixture(fixture.dir, names[mutation.index], changed, 0o600);
        try std.testing.expectError(if (mutation.index == 0) error.UnreviewedInput else error.HashMismatch, producer.requireNativeProofFiles(a, io, directory, observed, proof));
        const record = try directory.record(a, io, names[mutation.index], 1024 * 1024, .source);
        var changed_proof = proof;
        switch (mutation.index) {
            0 => changed_proof.root_build = record,
            1 => changed_proof.builder = record,
            2 => changed_proof.tool = record,
            else => unreachable,
        }
        try std.testing.expectError(error.DependencyUnavailable, producer.requireNativeProofFiles(a, io, directory, observed, changed_proof));
        try writeFixture(fixture.dir, names[mutation.index], contents[mutation.index], 0o600);
    }
    try fixture.dir.deleteFile(io, names[2]);
    try fixture.dir.symLink(io, "hyperv-proof-build.zig", names[2], .{});
    try std.testing.expectError(error.UnsafeFile, producer.requireNativeProofFiles(a, io, directory, observed, proof));
}

test "read-only entry never creates missing state or adopts v1 partial staging or a held writer" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    const path = try fixture.dir.realPathFileAlloc(io, ".", a);
    const directory: fs.Directory = .{ .dir = fixture.dir, .path = path };
    const state = try fs.openPrivate(io, path);
    defer state.close(io);
    const tool: rt.Bound = .{ .directory = directory, .contract = shapeTool(.preparation, null) };
    const deadline = try c.core.process.Deadline.afterMilliseconds(30000);
    var git: rt.Git = .{
        .allocator = a,
        .io = io,
        .runtime = tool,
        .environment = .{ .scratch = path, .path = path },
        .deadline = deadline,
    };
    const produced: admission.ProducerSource = .{
        .repository = directory,
        .git = &git,
        .provenance_bindings = .{ .repository = directory, .producer = directory, .compiler = directory, .git = directory, .dependencies = &.{}, .trust = directory },
    };
    const bindings: admission.Bindings = .{
        .staging = state,
        .receipts = directory,
        .producer_source = produced,
        .capability_source = produced,
        .config = directory,
        .packaged = state,
        .efi = directory,
        .assets = &.{},
        .qemu = directory,
        .engine = tool,
    };
    const chain = try shapeChain(a);
    const input = try shapeInput(a, chain);
    var review = try shapeReview(a, chain, input);
    try std.testing.expectError(error.FileNotFound, admission.load(a, io, review, bindings, deadline));
    try std.testing.expectError(error.FileNotFound, directory.openFile(io, ".writer.lock", .private));
    var lock = try state.lock(io);
    try std.testing.expectError(error.WouldBlock, admission.load(a, io, review, bindings, deadline));
    lock.close(io);
    const encoded = try c.canonical(a, input);
    const legacy = try replaceOnce(a, encoded, "hyperv_native_prepared_input_v3", "hyperv_native_prepared_input_v2");
    review.input_sha256 = c.digest(legacy);
    try writeFixture(fixture.dir, "input.json", legacy, 0o600);
    try std.testing.expectError(error.InvalidEnum, admission.load(a, io, review, bindings, deadline));
    review.input_sha256 = c.digest(encoded);
    try writeFixture(fixture.dir, "input.json", encoded, 0o600);
    for (chain, [_][]const u8{ "prepared.receipt.json", "configured.receipt.json", "built.receipt.json", "packaged.receipt.json" }) |link, name|
        try writeFixture(fixture.dir, name, try c.canonical(a, link.receipt), 0o600);
    try std.testing.expectError(error.InvalidSelection, admission.load(a, io, review, bindings, deadline));
    try std.testing.expectError(error.DeadlineExceeded, admission.load(a, io, review, bindings, .{ .expires_ns = 0 }));
    try std.testing.expectEqualStrings(encoded, try directory.read(a, io, "input.json", 1024 * 1024, .private));
    try std.testing.expect(git.failures.primary == null and git.failures.cleanup == null);
}

test "authoritative metadata entry rejects incomplete invented and wrong platform declarations" {
    const cfg = @import("config.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const guard = (try shapePrepared(a)).guard;
    const solved = try std.fmt.allocPrint(a, "{s}CONFIG_ARCH_X86_64=y\nCONFIG_PLAT_HYPERV=y\n", .{try cfg.render(a, guard)});
    const metadata =
        "unikraft-native-config-metadata-v1\n" ++
        "symbol\tAPPHYPERVACCEPTANCE\tbool\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE\tbool\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_NETWORK_APPLICATION\tbool\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID\tstring\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_DISK_ID\tstring\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_SECTORS\tint\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_SECTOR_SIZE\tint\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY\tint\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_LUN\tint\n" ++
        "symbol\tLIBSTORVSC\tbool\n" ++
        "symbol\tLIBSTORVSC_LUN_DISCOVERY\tbool\n" ++
        "symbol\tLIBSTORVSC_GUARDED_IO\tbool\n" ++
        "symbol\tLIBSTORVSC_MAX_DEVICES\tint\n" ++
        "symbol\tLIBSTORVSC_MAX_LUNS\tint\n" ++
        "symbol\tARCH_X86_64\tbool\nsymbol\tPLAT_HYPERV\tbool\n";
    try inputs.validateAuthoritativeConfig(a, solved, metadata, guard);
    try std.testing.expectError(error.InvalidConfig, inputs.validateAuthoritativeConfig(a, solved, "unikraft-native-config-metadata-v1\n", guard));
    const wrong = try replaceOnce(a, solved, "CONFIG_PLAT_HYPERV=y", "# CONFIG_PLAT_HYPERV is not set");
    try std.testing.expectError(error.InvalidSelection, inputs.validateAuthoritativeConfig(a, wrong, metadata, guard));
    const unknown = try std.fmt.allocPrint(a, "{s}CONFIG_UNREVIEWED_FLAG=y\n", .{solved});
    try std.testing.expectError(error.IncompleteMetadata, inputs.validateAuthoritativeConfig(a, unknown, metadata, guard));
    const bad_types = try replaceOnce(a, metadata, "APPHYPERVACCEPTANCE_PERSISTENCE_SECTORS\tint", "APPHYPERVACCEPTANCE_PERSISTENCE_SECTORS\thex");
    try std.testing.expectError(error.ConflictingMetadata, inputs.validateAuthoritativeConfig(a, solved, bad_types, guard));
}

test "producer v3 policy documents bind Make Git trust caches and physical control files" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    const path = try fixture.dir.realPathFileAlloc(io, ".", a);
    const directory: fs.Directory = .{ .dir = fixture.dir, .path = path };
    for ([_][]const u8{ "tmp", "cache", "config", "zig-local", "zig-global", "disabled-git-exec", "disabled-openssl" }) |name|
        try fixture.dir.createDir(io, name, .fromMode(0o700));
    try writeFixture(fixture.dir, "m4", "public metadata-only fixture", 0o700);
    try writeFixture(fixture.dir, "bash", "public metadata-only fixture", 0o700);
    const m4 = shapeTool(.m4, try directory.record(a, io, "m4", 128, .executable));
    const bash = shapeTool(.preparation, try directory.record(a, io, "bash", 128, .executable));
    var git = shapeTool(.git, shapeFile("bin/git", 128));
    git.loader = shapeFile("lib/loader", 128);
    git.libraries = &.{shapeFile("lib/library.so", 128)};
    var selected: producer.Inputs = .{
        .repository = directory,
        .observed_source = shapeSource(),
        .workspace = .{ .directory = directory, .output = directory, .scratch = directory, .config = shapeFile("guarded.config", 128) },
        .tools = .{
            .native = &.{ .{ .name = .m4, .bound = .{ .directory = directory, .contract = m4 } }, .{ .name = .bash, .bound = .{ .directory = directory, .contract = bash } } },
            .git = .{ .directory = directory, .contract = git },
            .packages = .{ .directory = directory, .contract = shapeTool(.dependencies, null) },
            .bison_data = .{ .directory = directory, .contract = shapeTool(.bison_data, null) },
            .trust = .{ .directory = directory, .contract = shapeTool(.trust, null) },
            .trust_bundle = shapeFile("trust.pem", 128),
        },
        .native_execution = null,
        .native_proof = null,
        .isolation = .{
            .helper = .{ .directory = directory, .contract = bash },
            .git_metadata = &.{},
            .account = .{ .name = "synthetic", .uid = std.os.linux.geteuid(), .gid = std.os.linux.getegid(), .home = path },
            .facade_runtime = directory,
            .facade_lock = try @import("namespace.zig").Identity.directory(directory),
            .environment = shapeFile("environment.json", 1),
            .make_environment = shapeFile("make.json", 1),
            .git_policy = shapeFile("git.json", 1),
        },
    };
    // Data-construction fixture only: no fake tools are executed or admitted.
    const description = try producer.describe(a, selected);
    const environment = try producer.bindingEnvironment(a, description);
    const make = try producer.bindingMakeEnvironment(a, description);
    const policy = try producer.bindingGitPolicy(a, description);
    inline for (.{ "environment", "make_environment", "git_policy" }, .{ environment, make, policy }) |name, value| {
        const record: c.File = if (comptime std.mem.eql(u8, name, "environment"))
            selected.isolation.?.environment
        else
            @field(selected.isolation.?, name).?;
        try writeFixture(fixture.dir, record.path, try c.canonical(a, value), 0o600);
        @field(selected.isolation.?, name) = try directory.record(a, io, record.path, 256 * 1024, .private);
    }
    var binding = try producer.describe(a, selected);
    try producer.validatePolicyFiles(a, io, binding);
    const encoded = try c.canonical(a, binding);
    const old = try replaceOnce(a, encoded, "hyperv_local_native_producer_binding_v4", "hyperv_local_native_producer_binding_v3");
    try std.testing.expectError(error.InvalidEnum, c.parse(producer.Binding, a, old));
    var substituted_make = make;
    substituted_make.tmp = make.xdg_cache;
    try writeFixture(fixture.dir, "make.json", try c.canonical(a, substituted_make), 0o600);
    binding.isolation.?.make_environment = try directory.record(a, io, "make.json", 64 * 1024, .private);
    try std.testing.expectError(error.UnreviewedInput, producer.validatePolicyFiles(a, io, binding));
    try writeFixture(fixture.dir, "make.json", try c.canonical(a, make), 0o600);
    binding = try producer.describe(a, selected);
    var substituted_git = policy;
    substituted_git.runtime.origin.payload.local_build.source_physical_sha256 = c.digest("different Git source");
    try writeFixture(fixture.dir, "git.json", try c.canonical(a, substituted_git), 0o600);
    binding.isolation.?.git_policy = try directory.record(a, io, "git.json", 256 * 1024, .private);
    try std.testing.expectError(error.UnreviewedInput, producer.validatePolicyFiles(a, io, binding));
    try std.testing.expectEqualStrings(environment.workspace, make.tmp[0 .. make.tmp.len - "/tmp".len]);
}

test "input v2 requires a charged distinct private VHD and rejects v1 wire shapes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const packaged = (try shapeChain(allocator))[3];
    var plan = try shapePlan(allocator, packaged);
    const assets = try allocator.dupe(inputs.Asset, plan.assets);
    plan.assets = assets;
    const original = assets[10];
    for ([_]budget.Role{ .boot_disk, .raw, .qemu_support }) |role| {
        assets[10].role = role;
        try std.testing.expectError(error.InvalidSelection, inputs.ledger(allocator, plan, packaged));
    }
    assets[10] = original;
    assets[10].placement = .baked;
    try std.testing.expectError(error.InvalidSelection, inputs.ledger(allocator, plan, packaged));
    assets[10] = original;
    assets[10].source.size = 1;
    try std.testing.expectError(error.HashMismatch, inputs.ledger(allocator, plan, packaged));
    assets[10] = original;
    const bytes = try c.canonical(allocator, plan);
    const legacy = try replaceOnce(allocator, bytes, "hyperv_native_input_selection_v3", "hyperv_native_input_selection_v2");
    try std.testing.expectError(error.InvalidEnum, c.parse(inputs.SelectionV3, allocator, legacy));
    const entries = try inputs.ledger(allocator, plan, packaged);
    var charged: u64 = 0;
    for (entries) |entry| if (entry.role == .vhd) {
        charged += entry.source.?.size;
    };
    try std.testing.expectEqual(c.image_bytes + 512, charged);
    plan.solved_metadata.path = "invented-symbol-types.tsv";
    try std.testing.expectError(error.InvalidMetadata, inputs.ledger(allocator, plan, packaged));
}

fn writeFixture(directory: std.Io.Dir, path: []const u8, bytes: []const u8, mode: u16) !void {
    const io = std.testing.io;
    const file = try directory.createFile(io, path, .{ .permissions = .fromMode(mode) });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(mode));
    try file.writePositionalAll(io, bytes, 0);
    try file.sync(io);
}

fn expectAbsent(directory: std.Io.Dir, path: []const u8) !void {
    if (directory.openFile(std.testing.io, path, .{ .path_only = true, .follow_symlinks = false })) |file| {
        file.close(std.testing.io);
        return error.TestUnexpectedFile;
    } else |err| try std.testing.expectEqual(error.FileNotFound, err);
}

test "physical native file records reject mutation size mode path symlink and private hardlink substitution" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    const directory: fs.Directory = .{ .dir = fixture.dir, .path = try fixture.dir.realPathFileAlloc(io, ".", allocator) };
    const reopened = try fs.Directory.open(allocator, io, directory.path);
    defer reopened.close(allocator, io);
    try writeFixture(directory.dir, "public.bin", "public synthetic bytes", 0o600);
    const original = try directory.record(allocator, io, "public.bin", 128, .private);
    try fs.requireFile(try reopened.record(allocator, io, "public.bin", 128, .private), original);
    try std.testing.expectEqualStrings("public synthetic bytes", try directory.read(allocator, io, "public.bin", 128, .private));
    try std.testing.expectError(error.FileTooLarge, directory.read(allocator, io, "public.bin", 1, .private));
    try std.testing.expectError(error.FileTooLarge, directory.record(allocator, io, "public.bin", 1, .private));
    for ([_][]const u8{ "../public.bin", "/public.bin", "dir/../public.bin", "dir//public.bin", "dir/./public.bin", "public.bin/", "public bin", "public\\bin" }) |path|
        try std.testing.expectError(error.UnsafePath, directory.openFile(io, path, .artifact));
    try directory.dir.symLink(io, "public.bin", "alias", .{});
    try std.testing.expectError(error.UnsafeFile, directory.openFile(io, "alias", .artifact));
    try directory.dir.createDir(io, "nested", .fromMode(0o700));
    try directory.dir.symLink(io, "nested", "directory-alias", .{ .is_directory = true });
    try std.testing.expectError(error.NotDir, directory.openFile(io, "directory-alias/public.bin", .artifact));
    try std.testing.expectEqual(.SUCCESS, std.os.linux.errno(std.os.linux.linkat(directory.dir.handle, "public.bin", directory.dir.handle, "hard", 0)));
    try std.testing.expectError(error.UnsafeFile, directory.openFile(io, "public.bin", .private));
    try fs.requireFile(try directory.record(allocator, io, "public.bin", 128, .artifact), original);
    try directory.dir.deleteFile(io, "hard");
    try writeFixture(directory.dir, "public.bin", "public synthetic bytex", 0o600);
    try std.testing.expectError(error.HashMismatch, fs.requireFile(try directory.record(allocator, io, "public.bin", 128, .private), original));
    try writeFixture(directory.dir, "public.bin", "public synthetic bytes", 0o644);
    try std.testing.expectError(error.UnsafeFile, directory.openFile(io, "public.bin", .private));
    try std.testing.expectError(error.HashMismatch, fs.requireFile(try directory.record(allocator, io, "public.bin", 128, .artifact), original));
    try writeFixture(directory.dir, "public.bin", "public synthetic bytes", 0o622);
    try std.testing.expectError(error.UnsafeFile, directory.openFile(io, "public.bin", .artifact));
    try writeFixture(directory.dir, "public.bin", "public synthetic bytes", 0o600);
    try std.testing.expectError(error.UnsafeFile, directory.openFile(io, "public.bin", .executable));
    try directory.dir.setPermissions(io, .fromMode(0o722));
    try std.testing.expectError(error.UnsafeFile, fs.Directory.open(allocator, io, directory.path));
    try std.testing.expectError(error.UnsafeFile, directory.openFile(io, "public.bin", .artifact));
    try directory.dir.setPermissions(io, .fromMode(0o700));
}

test "native inventory hashes empty directory paths modes and file bytes with descriptor relative nofollow" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    const directory: fs.Directory = .{ .dir = fixture.dir, .path = "" };
    try writeFixture(directory.dir, "public.bin", "synthetic", 0o644);
    const original = try fs.inventory(allocator, io, directory, 8, 128);
    try std.testing.expectEqual(@as(u32, 1), original.tree.files);
    try std.testing.expectEqual(@as(u64, 9), original.tree.bytes);
    try directory.dir.createDir(io, "empty", .fromMode(0o700));
    const with_empty = try fs.inventory(allocator, io, directory, 8, 128);
    try std.testing.expectEqual(original.tree.files, with_empty.tree.files);
    try std.testing.expectError(error.HashMismatch, fs.requireTree(with_empty.tree, original.tree));
    const empty = try directory.dir.openDir(io, "empty", .{ .follow_symlinks = false, .iterate = true });
    defer empty.close(io);
    try empty.setPermissions(io, .fromMode(0o755));
    const mode_changed = try fs.inventory(allocator, io, directory, 8, 128);
    try std.testing.expectError(error.HashMismatch, fs.requireTree(mode_changed.tree, with_empty.tree));
    try empty.setPermissions(io, .fromMode(0o700));
    try fs.requireTree((try fs.inventory(allocator, io, directory, 8, 128)).tree, with_empty.tree);
    try writeFixture(directory.dir, "public.bin", "synthetix", 0o644);
    try std.testing.expectError(error.HashMismatch, fs.requireTree((try fs.inventory(allocator, io, directory, 8, 128)).tree, with_empty.tree));
    try std.testing.expectError(error.FileTooLarge, fs.inventory(allocator, io, directory, 8, 8));
    try std.testing.expectError(error.LimitExceeded, fs.inventory(allocator, io, directory, 0, 128));
    try directory.dir.symLink(io, "empty", "alias", .{ .is_directory = true });
    try std.testing.expectError(error.UnsafeFile, fs.inventory(allocator, io, directory, 8, 128));
}

test "native bounded immutable copy streams public bytes privately durably without overwriting or mutating original" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    try fixture.dir.createDir(io, "output", .fromMode(0o700));
    const output = try fixture.dir.openDir(io, "output", .{ .follow_symlinks = false, .iterate = true });
    defer output.close(io);
    var lock = try (private.Directory{ .dir = output }).lock(io);
    defer lock.close(io);
    const source: fs.Directory = .{ .dir = fixture.dir, .path = "" };
    const payload = try allocator.alloc(u8, 2 * 64 * 1024 + 13);
    for (payload, 0..) |*byte, i| byte.* = @intCast(i % 251);
    try writeFixture(source.dir, "public.bin", payload, 0o644);
    const original = try source.record(allocator, io, "public.bin", c.total_cap, .artifact);
    const deadline = try c.core.process.Deadline.afterMilliseconds(10000);
    const result = try fs.copyImmutable(allocator, io, &lock, source, original, "artifacts/native.bin", deadline);
    try std.testing.expectEqual(.durable, result.status);
    try std.testing.expect(result.failures.primary == null and result.failures.cleanup == null and result.failures.recording == null);
    const target: fs.Directory = .{ .dir = output, .path = "" };
    const stored = try target.record(allocator, io, "artifacts/native.bin", c.total_cap, .private);
    try std.testing.expectEqualSlices(u8, &original.sha256, &stored.sha256);
    try std.testing.expectEqual(original.size, stored.size);
    try std.testing.expectEqual(@as(u16, 0o600), stored.mode);
    try std.testing.expect(!std.mem.eql(u8, stored.path, original.path));
    try std.testing.expectEqualSlices(u8, payload, try target.read(allocator, io, stored.path, payload.len, .private));
    try fs.requireFile(try source.record(allocator, io, "public.bin", c.total_cap, .artifact), original);
    const repeated = try fs.copyImmutable(allocator, io, &lock, source, original, stored.path, deadline);
    try std.testing.expect(repeated.status != .durable and repeated.failures.primary != null and repeated.failures.cleanup == null);
    try fs.requireFile(try target.record(allocator, io, stored.path, c.total_cap, .private), stored);
    const artifacts = try output.openDir(io, "artifacts", .{ .iterate = true });
    defer artifacts.close(io);
    try std.testing.expectEqual(@as(u16, 0o700), (try fs.metadata(.{ .handle = artifacts.handle, .flags = .{ .nonblocking = false } })).mode & 0o7777);
    var iterator = artifacts.iterate();
    var count: usize = 0;
    while (try iterator.next(io)) |entry| {
        try std.testing.expectEqualStrings("native.bin", entry.name);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), count);
}

test "native immutable copy rejects escaped symlink parents stale hashes deadlines size caps and missing lock with cleanup" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    try fixture.dir.createDir(io, "output", .fromMode(0o700));
    const output = try fixture.dir.openDir(io, "output", .{ .iterate = true, .follow_symlinks = false });
    defer output.close(io);
    var lock = try (private.Directory{ .dir = output }).lock(io);
    defer lock.close(io);
    const source: fs.Directory = .{ .dir = fixture.dir, .path = "" };
    try writeFixture(source.dir, "public.bin", "synthetic bytes", 0o644);
    const original = try source.record(allocator, io, "public.bin", 128, .artifact);
    const deadline = try c.core.process.Deadline.afterMilliseconds(10000);
    for ([_][]const u8{ "../escape", "a/../../escape", "/escape", ".writer.lock", "a//escape", "a/./escape" }) |path|
        try std.testing.expectError(error.UnsafePath, fs.copyImmutable(allocator, io, &lock, source, original, path, deadline));
    try output.symLink(io, "..", "escape", .{ .is_directory = true });
    try std.testing.expectError(error.NotDir, fs.copyImmutable(allocator, io, &lock, source, original, "escape/no-write", deadline));
    try expectAbsent(source.dir, "no-write");
    try output.deleteFile(io, "escape");
    try output.createDir(io, "public-parent", .fromMode(0o755));
    {
        const public_parent = try output.openDir(io, "public-parent", .{ .follow_symlinks = false, .iterate = true });
        defer public_parent.close(io);
        try public_parent.setPermissions(io, .fromMode(0o755));
    }
    try std.testing.expectError(error.UnsafeFile, fs.copyImmutable(allocator, io, &lock, source, original, "public-parent/no-write", deadline));
    try expectAbsent(output, "public-parent/no-write");
    try output.deleteDir(io, "public-parent");
    const expired = try fs.copyImmutable(allocator, io, &lock, source, original, "must-not-create/expired.bin", .{ .expires_ns = 0 });
    try std.testing.expectEqual(.not_committed, expired.status);
    try std.testing.expectEqual(.timeout, expired.failures.primary.?.category);
    try std.testing.expect(expired.failures.cleanup == null and expired.failures.recording == null);
    try expectAbsent(output, "must-not-create");
    var stale = original;
    stale.sha256 = c.digest("not these physical bytes");
    const mismatched = try fs.copyImmutable(allocator, io, &lock, source, stale, "stale.bin", deadline);
    try std.testing.expectEqual(.not_committed, mismatched.status);
    try std.testing.expectEqual(.integrity, mismatched.failures.primary.?.category);
    try std.testing.expect(mismatched.failures.cleanup == null);
    try expectAbsent(output, "stale.bin");
    stale = original;
    stale.size = c.total_cap + 1;
    try std.testing.expectError(error.FileTooLarge, fs.copyImmutable(allocator, io, &lock, source, stale, "huge.bin", deadline));
    stale = original;
    stale.size += 1;
    try std.testing.expectError(error.SourceChanged, fs.copyImmutable(allocator, io, &lock, source, stale, "long.bin", deadline));
    var iterator = output.iterate();
    while (try iterator.next(io)) |entry| try std.testing.expectEqualStrings(".writer.lock", entry.name);
    lock.close(io);
    try std.testing.expectError(error.LockNotHeld, fs.copyImmutable(allocator, io, &lock, source, original, "unlocked.bin", deadline));
    try expectAbsent(output, "unlocked.bin");
}

test "native publication fsync recording and cleanup fault lanes never imply durable success" {
    const io = std.testing.io;
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    var lock = try (private.Directory{ .dir = fixture.dir }).lock(io);
    defer lock.close(io);
    const before = try lock.commitFault(io, "before.json", "{}\n", .before_file_sync);
    try std.testing.expectEqual(.not_committed, before.status);
    try std.testing.expect(before.failures.recording != null and before.failures.cleanup == null);
    try expectAbsent(fixture.dir, "before.json");
    const after = try lock.commitFault(io, "after.json", "{}\n", .after_rename);
    try std.testing.expectEqual(.visible_not_durable, after.status);
    try std.testing.expect(after.failures.recording != null and after.failures.cleanup == null);
    const cleanup = try lock.commitFault(io, "cleanup.json", "{}\n", .cleanup);
    try std.testing.expectEqual(.not_committed, cleanup.status);
    try std.testing.expect(cleanup.failures.recording != null and cleanup.failures.cleanup != null);
    try expectAbsent(fixture.dir, "cleanup.json");
}

test "native producer rejects legacy proof text as unavailable before any child can run" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    const directory: fs.Directory = .{ .dir = fixture.dir, .path = try fixture.dir.realPathFileAlloc(io, ".", allocator) };
    // Public parser text only; never interpreted or executed by a child.
    try writeFixture(directory.dir, "build.zig",
        \\fn finishNativeImages() void {
        \\    _ = "support/build/tests/hyperv-smp-link-test.py";
        \\}
    , 0o644);
    const bound: rt.Bound = .{ .directory = directory, .contract = shapeTool(.preparation, null) };
    const selected: producer.Inputs = .{
        .repository = directory,
        .observed_source = shapeSource(),
        .workspace = .{ .directory = directory, .output = directory, .scratch = directory, .config = shapeFile("not-opened.config", 1) },
        .tools = .{
            .path = directory,
            .native = &.{},
            .git = bound,
            .packages = bound,
            .bison_data = bound,
            .trust = bound,
            .trust_bundle = shapeFile("not-opened-trust", 1),
        },
        .native_execution = null,
        .native_proof = null,
    };
    var outcome = try producer.execute(allocator, io, .build, selected, .{
        .source = selected.observed_source,
        .binding_sha256 = c.digest("not an approval"),
    }, try c.core.process.Deadline.afterMilliseconds(1000));
    defer outcome.deinit(allocator);
    try std.testing.expect(!outcome.succeeded());
    try std.testing.expect(outcome.child.termination == null and outcome.child.stdout.len == 0 and outcome.child.storage.len == 0);
    try std.testing.expectEqual(.admission, outcome.child.failures.primary.?.stage);
    try std.testing.expectEqual(.unavailable, outcome.child.failures.primary.?.category);
    try std.testing.expect(outcome.child.cleanup_complete and outcome.child.failures.cleanup == null and outcome.child.failures.recording == null);
}

test "SHAPE ONLY context rejects foreign receipt bindings before physical verification execution or publication" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const chain = try shapeChain(allocator);
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    const directory: fs.Directory = .{ .dir = fixture.dir, .path = try fixture.dir.realPathFileAlloc(io, ".", allocator) };
    var lock = try (private.Directory{ .dir = fixture.dir }).lock(io);
    defer lock.close(io);
    const bound: rt.Bound = .{ .directory = directory, .contract = shapeTool(.git, null) };
    var git: rt.Git = .{
        .allocator = allocator,
        .io = io,
        .runtime = bound,
        .environment = .{ .scratch = directory.path, .path = directory.path },
        .deadline = try c.core.process.Deadline.afterMilliseconds(1000),
    };
    var context: receipts.Context = .{
        .allocator = allocator,
        .io = io,
        .git = &git,
        .repository = directory,
        .review = chain[0].receipt.provenance,
        .reviewed_provenance_sha256 = chain[0].receipt.reviewed_provenance_sha256,
        .bindings = .{ .repository = directory, .producer = directory, .compiler = directory, .git = directory, .dependencies = &.{}, .trust = directory },
        .guard = chain[0].receipt.guard,
        .purpose = .synthetic,
    };
    try context.requireReceiptBinding(chain[0].receipt);
    context.guard.disk_id = try c.identity("77777777777777777777777777777777");
    for (chain) |link| try std.testing.expectError(error.ReceiptSubstitution, context.requireReceiptBinding(link.receipt));
    const selected: producer.Inputs = .{
        .repository = directory,
        .observed_source = shapeSource(),
        .workspace = .{ .directory = directory, .output = directory, .scratch = directory, .config = chain[0].receipt.config_after },
        .tools = .{
            .path = directory,
            .native = &.{},
            .git = bound,
            .packages = bound,
            .bison_data = bound,
            .trust = bound,
            .trust_bundle = shapeFile("not-opened-trust", 1),
        },
        .native_execution = null,
        .native_proof = null,
    };
    try std.testing.expectError(error.ReceiptSubstitution, context.runProducer(chain[0], selected, c.digest("not approval"), c.digest("not inspection approval")));
    try std.testing.expectError(error.ReceiptSubstitution, context.package(chain[2], &lock, directory));
    try std.testing.expectError(error.ReceiptSubstitution, context.publish(&lock, chain[0].receipt));
    const plan = try shapePlan(allocator, chain[3]);
    try std.testing.expectError(error.ReceiptSubstitution, inputs.generate(
        &context,
        &lock,
        chain[3],
        lock.directory,
        directory,
        plan,
        c.digest("not approval"),
        &.{},
        directory,
    ));
    context.guard = chain[0].receipt.guard;
    context.reviewed_provenance_sha256 = c.digest("other reviewed producer");
    try std.testing.expectError(error.ReceiptSubstitution, context.publish(&lock, chain[0].receipt));
    context.reviewed_provenance_sha256 = chain[0].receipt.reviewed_provenance_sha256;
    git.runtime.contract = context.review.git;
    try context.requireGitBinding();
    git.runtime.contract.origin.payload.local_build.compiler_executable_sha256 = c.digest("different executed Git");
    try std.testing.expectError(error.UnreviewedInput, context.requireGitBinding());
    git.runtime.contract = context.review.git;
    var other = std.testing.tmpDir(.{ .iterate = true });
    defer other.cleanup();
    const other_directory: fs.Directory = .{ .dir = other.dir, .path = try other.dir.realPathFileAlloc(io, ".", allocator) };
    git.runtime.directory = other_directory;
    try std.testing.expectError(error.UnreviewedInput, context.requireGitBinding());
    git.runtime.directory = directory;
    var different_checkout = selected;
    different_checkout.repository = other_directory;
    try std.testing.expectError(error.UnreviewedInput, context.requireProducerBinding(different_checkout));
    var different_compiler = selected;
    different_compiler.tools.git = git.runtime;
    different_compiler.tools.trust = .{ .directory = directory, .contract = context.review.trust };
    var compiler = context.review.compiler;
    compiler.executable.?.sha256 = c.digest("different executed compiler");
    const aliases = [_]producer.Native{.{ .name = .zig, .bound = .{ .directory = directory, .contract = compiler } }};
    different_compiler.tools.native = &aliases;
    try std.testing.expectError(error.UnreviewedInput, context.requireProducerBinding(different_compiler));
    var forged = chain[0];
    forged.sha256 = c.digest("forged receipt link");
    try std.testing.expectError(error.ReceiptSubstitution, context.runProducer(forged, selected, c.digest("not approval"), c.digest("not inspection approval")));
    var iterator = fixture.dir.iterate();
    while (try iterator.next(io)) |entry| try std.testing.expectEqualStrings(".writer.lock", entry.name);
    try std.testing.expect(context.failures.primary == null and git.failures.primary == null);
}

test "input generation refuses unrelated staging bytes empty directories and failed operation leftovers" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    const directory = try fs.openPrivate(io, try fixture.dir.realPathFileAlloc(io, ".", arena.allocator()));
    defer directory.close(io);
    var lock = try directory.lock(io);
    defer lock.close(io);
    try inputs.requireFresh(io, &lock);
    try writeFixture(fixture.dir, "unreceipted.raw", "public synthetic interrupted copy", 0o600);
    try std.testing.expectError(error.StagingNotFresh, inputs.requireFresh(io, &lock));
    try fixture.dir.deleteFile(io, "unreceipted.raw");
    try fixture.dir.createDir(io, "unplanned", .fromMode(0o700));
    try std.testing.expectError(error.StagingNotFresh, inputs.requireFresh(io, &lock));
    try fixture.dir.deleteDir(io, "unplanned");
    try inputs.requireFresh(io, &lock);
}

fn measuredTool(allocator: std.mem.Allocator, directory: fs.Directory, role: rt.Role, executable: ?[]const u8) !rt.Tool {
    var tool = shapeTool(role, if (executable) |path| try directory.record(allocator, std.testing.io, path, 64 * 1024 * 1024, .executable) else null);
    tool.tree = (try fs.inventory(allocator, std.testing.io, directory, 16, 128 * 1024 * 1024)).tree;
    if (role == .zig or role == .trust) {
        const synthetic = try @import("origin_fixture.zig").distribution(allocator, std.testing.io, directory);
        tool.origin = synthetic.origin;
        tool.evidence = synthetic.evidence;
    } else if (role == .dependencies) {
        const packages = try allocator.dupe(rt.origin.Package, tool.origin.payload.zig_packages.packages);
        packages[0].selected_tree = tool.tree;
        const parent = try fs.Directory.open(allocator, std.testing.io, try std.fs.path.join(allocator, &.{ std.fs.path.dirname(directory.path).?, "repository" }));
        defer parent.close(allocator, std.testing.io);
        packages[0].declaration.directory = try rt.origin.Identity.directory(parent);
        packages[0].declaration.directory.path = try allocator.dupe(u8, parent.path);
        packages[0].declaration.file = try parent.record(allocator, std.testing.io, "build.zig.zon", 4096, .artifact);
        tool.origin.payload.zig_packages.packages = packages;
    }
    return tool;
}

test "native provenance binding fixtures reject changed physical runtimes dependencies and trust without source approval" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = try rt.TestFixture.init(allocator, io);
    defer fixture.deinit();
    for ([_][]const u8{ "native-fixture", provenance.miz_package_hash, "trust-fixture" }) |name|
        try fixture.root.dir.createDir(io, name, .fromMode(0o700));
    const native = try fs.Directory.open(allocator, io, try std.fs.path.join(allocator, &.{ fixture.root.path, "native-fixture" }));
    defer native.close(allocator, io);
    const dependency = try fs.Directory.open(allocator, io, try std.fs.path.join(allocator, &.{ fixture.root.path, provenance.miz_package_hash }));
    defer dependency.close(allocator, io);
    const trust = try fs.Directory.open(allocator, io, try std.fs.path.join(allocator, &.{ fixture.root.path, "trust-fixture" }));
    defer trust.close(allocator, io);
    const compiled_path = @import("test_options").process_fixture;
    const compiled = try fs.Directory.open(allocator, io, std.fs.path.dirname(compiled_path).?);
    defer compiled.close(allocator, io);
    const executable = try compiled.read(allocator, io, std.fs.path.basename(compiled_path), 64 * 1024 * 1024, .executable);
    try writeFixture(native.dir, "fixture", executable, 0o755);
    try writeFixture(dependency.dir, "fixture.zig", "pub const synthetic = true;\n", 0o644);
    try writeFixture(trust.dir, "fixture.txt", "public synthetic trust fixture; not a CA bundle\n", 0o644);
    try writeFixture(fixture.repository.dir, "build.zig.zon", ".{ .dependencies = .{ .miz_source = .{ .url = \"git+https://github.com/cataggar/miz.git#" ++ c.miz_revision ++ "\", .hash = \"" ++ provenance.miz_package_hash ++ "\" } } }\n", 0o644);
    var record = (try shapePrepared(allocator)).provenance;
    // The measured static fixture is not the preparation CLI or a compiler;
    // these field bindings test rejection only, never approval or execution.
    record.compiler = try measuredTool(allocator, native, .zig, "fixture");
    record.producer = try measuredTool(allocator, native, .preparation, "fixture");
    record.producer.origin.payload.local_build.source_physical_sha256 = record.source.physical.sha256;
    record.producer.origin.payload.local_build.compiler_executable_sha256 = record.compiler.executable.?.sha256;
    record.git = fixture.git.runtime.contract;
    record.trust = try measuredTool(allocator, trust, .trust, null);
    const dependencies = try allocator.dupe(provenance.Dependency, record.dependencies);
    dependencies[0].content = try measuredTool(allocator, dependency, .dependencies, null);
    record.dependencies = dependencies;
    const bound_dependencies = [_]provenance.Dependencies{.{ .name = "miz_source", .directory = dependency }};
    const bindings: provenance.Bindings = .{
        .repository = fixture.repository,
        .producer = native,
        .compiler = native,
        .git = fixture.git.runtime.directory,
        .dependencies = &bound_dependencies,
        .trust = trust,
    };
    const expected = c.digest(try c.canonical(allocator, record));
    try std.testing.expectError(error.UnreviewedInput, provenance.verify(allocator, io, record, bindings, c.digest("not independently reviewed")));
    try std.testing.expectError(error.UnreviewedInput, provenance.requireCurrentExecutable(io, record));
    const file = try native.dir.openFile(io, "fixture", .{ .mode = .read_write });
    defer file.close(io);
    try file.writePositionalAll(io, "X", 0);
    try std.testing.expectError(error.HashMismatch, provenance.verify(allocator, io, record, bindings, expected));
    try file.writePositionalAll(io, executable[0..1], 0);
    try writeFixture(trust.dir, "extra.txt", "unexpected public trust bytes", 0o644);
    try std.testing.expectError(error.HashMismatch, provenance.verify(allocator, io, record, bindings, expected));
    try trust.dir.deleteFile(io, "extra.txt");
    try writeFixture(dependency.dir, "fixture.zig", "pub const synthetic = false;\n", 0o644);
    try std.testing.expectError(error.HashMismatch, provenance.verify(allocator, io, record, bindings, expected));
    var missing = bindings;
    missing.dependencies = &.{};
    try std.testing.expectError(error.IncompleteProvenance, provenance.verify(allocator, io, record, missing, expected));
    var wrong_name = bound_dependencies;
    wrong_name[0].name = "not_miz_source";
    missing = bindings;
    missing.dependencies = &wrong_name;
    try std.testing.expectError(error.IncompleteProvenance, provenance.verify(allocator, io, record, missing, expected));
}
