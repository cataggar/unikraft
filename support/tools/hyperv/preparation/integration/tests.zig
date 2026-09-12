const std = @import("std");
const runtime_material = @import("runtime_material.zig");
const x = @import("common.zig");
const main = @import("main.zig");
const material = @import("material.zig");
const selection = @import("selection.zig");
const t = std.testing;
const a = t.allocator;
const hash = "1" ** 64;

test "integration driver runtime measurement is explicit and bootstrap cannot borrow a post Bundle review" {
    const parsed = try main.arguments(&.{ "driver", "runtime-material", "/private/work" });
    try t.expect(parsed.command == .runtime_material);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var fixture = t.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(t.io, .fromMode(0o700));
    for ([_][]const u8{ "requests", "controls", "reviews" }) |name|
        try fixture.dir.createDir(t.io, name, .fromMode(0o700));
    var world: x.World = .{ .allocator = arena.allocator(), .io = t.io, .deadline = try x.c.core.process.Deadline.afterMilliseconds(30000) };
    defer world.deinit();
    const workspace = try world.open(try fixture.dir.realPathFileAlloc(t.io, ".", world.allocator));
    const requests = try world.child(workspace, "requests");
    // Invalid spec is deliberately never inspected: separate runtime permission
    // must be read before constructing or invoking a supplied runtime.
    try write(requests.dir, "bootstrap.json", "{}\n", 0o600);
    const reviews = try world.child(workspace, "reviews");
    try write(reviews.dir, "prepare.json", try x.c.canonical(world.allocator, review(.prepare)), 0o600);
    try t.expectError(error.FileNotFound, material.bootstrap(&world, workspace));
    try t.expectError(error.FileNotFound, workspace.dir.openDir(t.io, "scratch", .{}));
    try t.expectError(error.FileNotFound, workspace.dir.openFile(t.io, "run.config", .{}));
    try t.expectError(error.FileNotFound, runtime_material.approve(&world, workspace));
    // The later Bundle cannot be used to jump directly into producer/importer.
    // The missing runtime review is checked before any Bundle field is read.
    try t.expectError(error.FileNotFound, runtime_material.requireBundle(&world, workspace, undefined));
}

test "integration driver runtime review binds complete roles physical identities evidence policies and witnesses" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const allocator = arena.allocator();
    const identity: x.p.origin.Identity = .{ .path = "/synthetic/runtime", .device = 1, .inode = 2, .mode = 0o40700, .uid = 1000 };
    const file: x.c.File = .{ .path = "synthetic", .sha256 = hash.*, .size = 1, .mode = 0o600 };
    const tree: x.c.Tree = .{ .sha256 = hash.*, .files = 1, .bytes = 1 };
    const policy: x.p.origin.Policy = .{
        .artifact_id = "synthetic",
        .authority = .{ .publisher_https_sha256 = .{ .publisher = "synthetic.invalid", .repository = "fixture" } },
        .authentication_sha256 = hash.*,
        .realization_verification_sha256 = &.{hash.*},
    };
    const evidence = [_]x.p.origin.Binding{.{
        .directory = identity,
        .set = .{ .tree = tree, .catalog = file },
        .physical_sha256 = hash.*,
        .policy = &.{policy},
    }};
    const tool: runtime_material.MeasuredTool = .{
        .directory = identity,
        .physical_sha256 = hash.*,
        .tool = .{ .path = identity.path, .contract = .{
            .role = .preparation,
            .target = .aarch64_linux,
            .origin = x.p.origin_fixture.shapeDistribution(),
            .tree = tree,
            .executable = file,
            .loader = null,
            .libraries = &.{},
            .evidence = &evidence,
        } },
    };
    const measured: runtime_material.Material = .{
        .schema = .hyperv_native_runtime_material_v1,
        .authority = .not_admitted,
        .spec = file,
        .spec_physical = .{ .device = 1, .inode = 1, .size = 1, .mode = 0o100600, .uid = 1000, .links = 1, .modified_ns = 0, .changed_ns = 0 },
        .repository = identity,
        .actor = .{ .role = .preparation, .target = .aarch64_linux, .directory = identity, .tree = tree, .physical_sha256 = hash.*, .executable = file, .helper = file },
        .native = &.{.{ .name = .zig, .measured = tool }},
        .git = tool,
        .packages = tool,
        .bison_data = tool,
        .trust = tool,
        .dependencies = &.{},
    };
    const expected: runtime_material.Review = .{
        .schema = .hyperv_native_runtime_review_v1,
        .material_sha256 = try x.p.origin.hash(allocator, measured),
        .authentication = .existing_publisher_assurance,
        .realization = .declared_prefix_relocation,
        .evidence = &.{.{ .evidence_set_sha256 = try x.p.origin.hash(allocator, evidence[0].set), .policy = &.{policy} }},
    };
    try runtime_material.requireReview(allocator, measured, expected);
    for (0..6) |i| {
        var changed = measured;
        switch (i) {
            0 => changed.git.physical_sha256 = x.c.digest("different physical files"),
            1 => changed.git.directory.inode += 1,
            2 => changed.git.tool.contract.role = .zig,
            3 => changed.git.tool.contract.target = .x86_64_linux,
            4 => changed.git.tool.contract.executable.?.sha256 = x.c.digest("different executable"),
            5 => changed.spec_physical.inode += 1,
            else => unreachable,
        }
        try t.expectError(error.UnreviewedInput, runtime_material.requireReview(allocator, changed, expected));
    }
    var absent = expected;
    absent.evidence = &.{};
    try t.expectError(error.WrongAuthority, runtime_material.requireReview(allocator, measured, absent));
    var required = policy;
    required.authority = .{ .pinned_key_signature = .{ .publisher = "synthetic.invalid", .repository = "fixture", .key_id = "independent-required-key" } };
    absent.evidence = &.{.{ .evidence_set_sha256 = expected.evidence[0].evidence_set_sha256, .policy = &.{required} }};
    try t.expectError(error.UnreviewedInput, runtime_material.requireReview(allocator, measured, absent));
    const bytes = try x.c.canonical(allocator, expected);
    const roundtrip = try x.c.parse(runtime_material.Review, allocator, bytes);
    try runtime_material.requireReview(allocator, measured, roundtrip.value);
}

fn review(phase: x.Phase) x.Review {
    return .{
        .schema = .hyperv_native_integration_review_v1,
        .phase = phase,
        .material_sha256 = hash.*,
        .provenance_sha256 = hash.*,
        .parent_sha256 = if (phase == .prepare) null else hash.*,
        .execution_sha256 = if (phase == .configure or phase == .build) hash.* else null,
        .inspection_sha256 = if (phase == .configure or phase == .build) hash.* else null,
        .selection_sha256 = if (phase == .generate) hash.* else null,
        .capability_provenance_sha256 = if (phase == .generate) hash.* else null,
    };
}

test "integration driver fixed commands and independent expected config" {
    const cases = [_][]const []const u8{
        &.{ "driver", "material", "/private/work" },
        &.{ "driver", "stage", "/private/work", "configure", "expected.config" },
        &.{ "driver", "stage", "/private/work", "build" },
        &.{ "driver", "producer", "/private/work", "prepare" },
        &.{ "driver", "producer", "/private/work", "configure" },
        &.{ "driver", "producer", "/private/work", "build" },
        &.{ "driver", "producer", "/private/work", "package" },
        &.{ "driver", "producer", "/private/work", "generate" },
        &.{ "driver", "selection", "/private/work" },
        &.{ "driver", "importer", "/private/work" },
        &.{ "driver", "measure", "/private/work", "configure" },
        &.{ "driver", "measure", "/private/work", "importer" },
    };
    for (cases) |args| _ = try main.arguments(args);
    try t.expectError(error.InspectionExpectationRequired, main.arguments(&.{ "driver", "stage", "/private/work", "configure" }));
}

test "integration driver rejects arbitrary commands paths and extra arguments" {
    const cases = [_][]const []const u8{
        &.{"driver"},
        &.{ "driver", "shell", "/private/work" },
        &.{ "driver", "material", "relative" },
        &.{ "driver", "producer", "/private/work", "completed" },
        &.{ "driver", "producer", "/private/work", "build", "--unsafe" },
        &.{ "driver", "stage", "/private/work", "build", "unexpected.config" },
        &.{ "driver", "stage", "/private/work", "configure", "../escape" },
        &.{ "driver", "importer", "/private/work", "self-approve" },
        &.{ "driver", "measure", "/private/work", "approve" },
    };
    for (cases) |args| {
        if (main.arguments(args)) |_| return error.TestExpectedError else |_| {}
    }
}

test "integration driver review requires every phase-specific commitment" {
    inline for (std.meta.tags(x.Phase)) |phase| {
        const valid = review(phase);
        try valid.validate(phase);
        var bad = valid;
        bad.phase = if (phase == .prepare) .build else .prepare;
        try t.expectError(error.WrongPhase, bad.validate(phase));
        inline for (.{ "parent_sha256", "execution_sha256", "inspection_sha256", "selection_sha256", "capability_provenance_sha256" }) |name| {
            bad = valid;
            @field(bad, name) = if (@field(valid, name) == null) hash.* else null;
            try t.expectError(error.InvalidReview, bad.validate(phase));
        }
    }
}

test "integration driver canonical exact review rejects duplicate and unknown fields" {
    const encoded = try x.c.canonical(a, review(.configure));
    defer a.free(encoded);
    const decoded = try x.c.parse(x.Review, a, encoded);
    defer decoded.deinit();
    try decoded.value.validate(.configure);
    const duplicate = try std.fmt.allocPrint(a, "{{\"phase\":\"configure\",{s}", .{encoded[1..]});
    defer a.free(duplicate);
    if (x.c.parse(x.Review, a, duplicate)) |value| {
        value.deinit();
        return error.TestExpectedError;
    } else |_| {}
    const unknown = try std.fmt.allocPrint(a, "{{\"arbitrary\":false,{s}", .{encoded[1..]});
    defer a.free(unknown);
    if (x.c.parse(x.Review, a, unknown)) |value| {
        value.deinit();
        return error.TestExpectedError;
    } else |_| {}
}

test "integration driver expectation preserves destination not future physical identity" {
    const current: x.c.File = .{ .path = "run.config", .mode = 0o600, .size = 19, .sha256 = "2".* ** 64 };
    const expected: x.c.File = .{ .path = "reviewed.config", .mode = 0o600, .size = 123, .sha256 = hash.* };
    const result = try x.inspectionConfig(current, expected);
    try t.expectEqualStrings("run.config", result.path);
    try t.expectEqual(expected.size, result.size);
    try t.expectEqualStrings(&expected.sha256, &result.sha256);
    var bad = expected;
    bad.mode = 0o644;
    try t.expectError(error.InvalidInspectionExpectation, x.inspectionConfig(current, bad));
    bad = expected;
    bad.size = 0;
    try t.expectError(error.InvalidInspectionExpectation, x.inspectionConfig(current, bad));
    bad.size = x.p.config.config_cap + 1;
    try t.expectError(error.InvalidInspectionExpectation, x.inspectionConfig(current, bad));
}

test "integration driver import approval remains independently typed" {
    const value: selection.ImportReview = .{
        .schema = .hyperv_native_integration_import_review_v1,
        .material_sha256 = hash.*,
        .review = .{
            .input_sha256 = hash.*,
            .selection_sha256 = hash.*,
            .provenance_sha256 = hash.*,
            .capability_provenance_sha256 = hash.*,
            .receipt_sha256 = .{ hash.*, hash.*, hash.*, hash.* },
            .execution_sha256 = .{ hash.*, hash.* },
            .engine_runtime_sha256 = hash.*,
            .engine_executable_sha256 = hash.*,
        },
    };
    const encoded = try x.c.canonical(a, value);
    defer a.free(encoded);
    const decoded = try x.c.parse(selection.ImportReview, a, encoded);
    defer decoded.deinit();
    try t.expectEqualStrings(&hash.*, &decoded.value.review.engine_runtime_sha256);
    try t.expectEqual(@as(u64, 8388608), x.c.control_cap);
    try t.expectEqual(@as(u64, 268435456), x.c.total_cap);
}

fn write(directory: std.Io.Dir, path: []const u8, bytes: []const u8, mode: u16) !void {
    const file = try directory.createFile(t.io, path, .{ .permissions = .fromMode(mode), .exclusive = true });
    defer file.close(t.io);
    try file.setPermissions(t.io, .fromMode(mode));
    try file.writePositionalAll(t.io, bytes, 0);
    try file.sync(t.io);
}

test "integration driver private material requires an independent matching hash" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var fixture = t.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(t.io, .fromMode(0o700));
    var world: x.World = .{ .allocator = arena.allocator(), .io = t.io, .deadline = try x.c.core.process.Deadline.afterMilliseconds(30000) };
    defer world.deinit();
    const directory = try world.open(try fixture.dir.realPathFileAlloc(t.io, ".", world.allocator));
    const state = try world.state(directory);
    var lock = try state.lock(t.io);
    defer lock.close(t.io);
    const file = try world.publish(&lock, "review.json", review(.build));
    _ = try world.read(x.Review, directory, file.path, file.sha256);
    try t.expectError(error.UnreviewedInput, world.read(x.Review, directory, file.path, hash.*));
    const held = try directory.openFile(t.io, file.path, .private);
    defer held.close(t.io);
    try held.setPermissions(t.io, .fromMode(0o644));
    try t.expectError(error.UnsafeFile, world.read(x.Review, directory, file.path, file.sha256));
}

test "integration driver immutable attempt refuses replay without changing material" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var fixture = t.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(t.io, .fromMode(0o700));
    var world: x.World = .{ .allocator = arena.allocator(), .io = t.io, .deadline = try x.c.core.process.Deadline.afterMilliseconds(30000) };
    defer world.deinit();
    const directory = try world.open(try fixture.dir.realPathFileAlloc(t.io, ".", world.allocator));
    try main.attempt(&world, directory, .configure, hash.*, hash.*);
    const before = try directory.record(world.allocator, t.io, "attempt-configure.json", 4096, .private);
    try t.expectError(error.PathAlreadyExists, main.attempt(&world, directory, .configure, "2".* ** 64, hash.*));
    const after = try directory.record(world.allocator, t.io, "attempt-configure.json", 4096, .private);
    try x.fs.requireFile(before, after);
}

test "integration driver actual actor identity rejects identical physical copies" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var fixture = t.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(t.io, .fromMode(0o700));
    var world: x.World = .{ .allocator = arena.allocator(), .io = t.io, .deadline = try x.c.core.process.Deadline.afterMilliseconds(30000) };
    defer world.deinit();
    const path = try std.Io.Dir.cwd().realPathFileAlloc(t.io, "/proc/self/exe", world.allocator);
    const directory = try world.open(std.fs.path.dirname(path).?);
    const executable = try directory.record(world.allocator, t.io, std.fs.path.basename(path), 64 * 1024 * 1024, .executable);
    var bound: x.rt.Bound = .{ .directory = directory, .contract = .{
        .role = .preparation,
        .target = if (@import("builtin").cpu.arch == .aarch64) .aarch64_linux else .x86_64_linux,
        .origin = x.p.origin_fixture.local(),
        .tree = .{ .files = 1, .bytes = executable.size, .sha256 = hash.* },
        .executable = executable,
        .loader = null,
        .libraries = &.{},
    } };
    try world.requireActor(bound);
    const bytes = try directory.read(world.allocator, t.io, executable.path, 64 * 1024 * 1024, .executable);
    try write(fixture.dir, "actor-copy", bytes, executable.mode);
    bound.directory = try world.open(try fixture.dir.realPathFileAlloc(t.io, ".", world.allocator));
    bound.contract.executable = try bound.directory.record(world.allocator, t.io, "actor-copy", 64 * 1024 * 1024, .executable);
    try t.expectEqualStrings(&executable.sha256, &bound.contract.executable.?.sha256);
    try t.expectError(error.WrongPhysicalActor, world.requireActor(bound));
}

test "integration driver reservation charges every post-selection file and manifest" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var fixture = t.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(t.io, .fromMode(0o700));
    try fixture.dir.createDir(t.io, "reserved-controls", .fromMode(0o700));
    try fixture.dir.createDir(t.io, "staging", .fromMode(0o700));
    var world: x.World = .{ .allocator = arena.allocator(), .io = t.io, .deadline = try x.c.core.process.Deadline.afterMilliseconds(30000) };
    defer world.deinit();
    const directory = try world.open(try fixture.dir.realPathFileAlloc(t.io, ".", world.allocator));
    const reserved = try world.child(directory, "reserved-controls");
    const staged = try world.child(directory, "staging");
    for ([_][]const u8{ "selection.json", "generate.json", "attempt-generate.json", "import.json" }) |name|
        try write(reserved.dir, name, "123", 0o600);
    try write(staged.dir, "input.json", "1234", 0o600);
    var entries = [_]x.p.budget.Entry{.{
        .id = "remaining-controls",
        .role = .publication_reservation,
        .artifact = "controls/future",
        .source = null,
        .reserved = 16,
    }};
    try selection.reservedBudget(&world, directory, &entries);
    entries[0].reserved = 15;
    try t.expectError(error.ControlLimitExceeded, selection.reservedBudget(&world, directory, &entries));
    entries[0].reserved = 16;
    try write(reserved.dir, "unaccounted.json", "x", 0o600);
    try t.expectError(error.UnexpectedControlFile, selection.reservedBudget(&world, directory, &entries));
}

test "integration driver rejects historical-size geometry and non-synthetic LUN" {
    var guard: x.p.config.Guard = .{ .run_id = "1".* ** 32, .disk_id = "2".* ** 32, .sectors = 49, .lun = 0 };
    try x.synthetic(guard);
    guard.sectors = 4096;
    try x.synthetic(guard);
    guard.sectors = 8388608;
    try t.expectError(error.NonSyntheticInput, x.synthetic(guard));
    guard.sectors = 49;
    guard.lun = 7;
    try t.expectError(error.NonSyntheticInput, x.synthetic(guard));
}

test "integration driver detects unselected control publications without mutating them" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var fixture = t.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(t.io, .fromMode(0o700));
    for ([_][]const u8{ "requests", "reviews", "controls", "receipts" }) |name|
        try fixture.dir.createDir(t.io, name, .fromMode(0o700));
    var world: x.World = .{ .allocator = arena.allocator(), .io = t.io, .deadline = try x.c.core.process.Deadline.afterMilliseconds(30000) };
    defer world.deinit();
    const directory = try world.open(try fixture.dir.realPathFileAlloc(t.io, ".", world.allocator));
    const requests = try world.child(directory, "requests");
    try write(requests.dir, "request.json", "{}\n", 0o600);
    const record = try requests.record(world.allocator, t.io, "request.json", 1024, .private);
    const selected = [_]x.p.inputs.Asset{.{
        .id = "request",
        .role = .publication_control,
        .source = record,
        .destination = "controls/request.json",
        .placement = .staged,
    }};
    const bound = [_]x.p.inputs.Binding{.{ .id = "request", .directory = requests }};
    try selection.requireControlInventory(&world, directory, &selected, &bound);
    try write(requests.dir, "later.json", "{}\n", 0o600);
    const before = try x.fs.inventory(world.allocator, t.io, requests, 8, 1024);
    try t.expectError(error.UnexpectedControlFile, selection.requireControlInventory(&world, directory, &selected, &bound));
    try x.fs.requireTree(before.tree, (try x.fs.inventory(world.allocator, t.io, requests, 8, 1024)).tree);
}

test "integration driver binds receipt phase to the selected pipeline stage" {
    inline for (std.meta.tags(x.c.Phase)) |expected| {
        inline for (std.meta.tags(x.c.Phase)) |actual| {
            if (actual == expected)
                try x.requireReceiptPhase(actual, expected)
            else
                try t.expectError(error.InvalidPhase, x.requireReceiptPhase(actual, expected));
        }
    }
}

test "integration driver rejects data-only and absent compiler or engine executables" {
    var tool: x.rt.Tool = .{
        .role = .preparation,
        .target = .aarch64_linux,
        .origin = x.p.origin_fixture.local(),
        .tree = .{ .files = 1, .bytes = 1, .sha256 = hash.* },
        .executable = .{ .path = "bin/actor", .size = 1, .sha256 = hash.*, .mode = 0o700 },
        .loader = null,
        .libraries = &.{},
    };
    _ = try x.runtimeExecutable(tool, .preparation);
    try t.expectError(error.InvalidRuntime, x.runtimeExecutable(tool, .zig));
    tool.role = .zig;
    _ = try x.runtimeExecutable(tool, .zig);
    try t.expectError(error.InvalidRuntime, x.runtimeExecutable(tool, .preparation));
    tool.executable = null;
    try t.expectError(error.InvalidRuntime, x.runtimeExecutable(tool, .zig));
    tool.role = .preparation;
    try t.expectError(error.InvalidRuntime, x.runtimeExecutable(tool, .preparation));
    tool.target = .data;
    try t.expectError(error.InvalidRuntime, x.runtimeExecutable(tool, .preparation));
}

// Valid contract/hash only. No corresponding source or executable material is
// installed, so these negative intake fixtures cannot run a real producer.
fn configuredReceiptFixture(allocator: std.mem.Allocator) !x.p.receipts.Link {
    const source: x.c.Source = .{
        .scheme = .git_physical_native_v1,
        .head = "1" ** 40,
        .tree = "2" ** 40,
        .tree_sha256 = hash.*,
        .physical = .{ .sha256 = hash.*, .files = 1, .bytes = 1 },
    };
    const executable: x.rt.Tool = .{
        .role = .preparation,
        .target = if (@import("builtin").cpu.arch == .aarch64) .aarch64_linux else .x86_64_linux,
        .origin = .{ .payload = .{ .local_build = .{ .source_revision = "1" ** 40, .source_physical_sha256 = hash.*, .compiler_executable_sha256 = hash.* } } },
        .tree = .{ .files = 1, .bytes = 1, .sha256 = hash.* },
        .executable = .{ .path = "bin/fixture", .size = 1, .mode = 0o700, .sha256 = hash.* },
        .loader = null,
        .libraries = &.{},
    };
    var compiler = executable;
    compiler.role = .zig;
    compiler.origin = x.p.origin_fixture.shapeDistribution();
    var git = executable;
    git.role = .git;
    var trust = executable;
    trust.role = .trust;
    trust.target = .data;
    trust.executable = null;
    trust.origin = x.p.origin_fixture.shapeDistribution();
    var dependency = trust;
    dependency.role = .dependencies;
    dependency.origin = x.p.origin_fixture.shapePackage();
    const dependencies = try allocator.alloc(x.p.provenance.Dependency, 1);
    dependencies[0] = .{ .name = "miz_source", .package_hash = x.p.provenance.miz_package_hash, .content = dependency };
    const provenance: x.p.provenance.Record = .{
        .schema = .hyperv_native_producer_provenance_v2,
        .source = source,
        .host_target = if (@import("builtin").cpu.arch == .aarch64) .aarch64_linux else .x86_64_linux,
        .guest_target = .x86_64_freestanding_none,
        .compiler_version = x.c.compiler_version,
        .producer = executable,
        .compiler = compiler,
        .git = git,
        .trust = trust,
        .dependencies = dependencies,
    };
    const config: x.c.File = .{ .path = "run.config", .size = 1, .mode = 0o600, .sha256 = hash.* };
    const receipt: x.p.receipts.Receipt = .{
        .schema = .hyperv_artifact_preparation_native_v2,
        .phase = .configured,
        .purpose = .synthetic,
        .run_id = "1".* ** 32,
        .guard = .{ .run_id = "1".* ** 32, .disk_id = "2".* ** 32, .sectors = 49, .lun = 0 },
        .source_before = source,
        .source_after = source,
        .provenance = provenance,
        .reviewed_provenance_sha256 = x.c.digest(try x.c.canonical(allocator, provenance)),
        .config_before = config,
        .config_after = config,
        .parent_sha256 = hash.*,
        .execution = .{ .step = .configure, .exit_code = 0, .cleanup_complete = true, .admitted_binding_sha256 = hash.* },
        .efi = null,
        .packaging = null,
        .authority = .not_admitted,
    };
    const link: x.p.receipts.Link = .{ .receipt = receipt, .sha256 = x.c.digest(try x.c.canonical(allocator, receipt)) };
    try x.p.receipts.requireLink(allocator, link);
    return link;
}

test "integration driver checks internal phase of a valid matching-hash private receipt" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var fixture = t.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(t.io, .fromMode(0o700));
    var world: x.World = .{ .allocator = arena.allocator(), .io = t.io, .deadline = try x.c.core.process.Deadline.afterMilliseconds(30000) };
    defer world.deinit();
    const directory = try world.open(try fixture.dir.realPathFileAlloc(t.io, ".", world.allocator));
    const link = try configuredReceiptFixture(world.allocator);
    const bytes = try x.c.canonical(world.allocator, link.receipt);
    try write(directory.dir, "prepared.receipt.json", bytes, 0o600);
    try write(directory.dir, "configured.receipt.json", bytes, 0o600);
    const before = try x.fs.inventory(world.allocator, t.io, directory, 8, x.maximum_document);
    try t.expectError(error.InvalidPhase, world.receipt(directory, .prepared, link.sha256));
    const accepted = try world.receipt(directory, .configured, link.sha256);
    try t.expectEqual(x.c.Phase.configured, accepted.receipt.phase);
    try t.expectEqualStrings(&link.sha256, &accepted.sha256);
    try t.expectError(error.UnreviewedInput, world.receipt(directory, .configured, x.c.digest("independently mismatching fixture hash")));
    try x.fs.requireTree(before.tree, (try x.fs.inventory(world.allocator, t.io, directory, 8, x.maximum_document)).tree);
}

test "integration driver wrong-phase receipt stops real intake paths before attempts or execution" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var fixture = t.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(t.io, .fromMode(0o700));
    for ([_][]const u8{ "receipts", "reviews", "controls" }) |name|
        try fixture.dir.createDir(t.io, name, .fromMode(0o700));
    var world: x.World = .{ .allocator = arena.allocator(), .io = t.io, .deadline = try x.c.core.process.Deadline.afterMilliseconds(30000) };
    defer world.deinit();
    const directory = try world.open(try fixture.dir.realPathFileAlloc(t.io, ".", world.allocator));
    const receipts = try world.child(directory, "receipts");
    const reviews = try world.child(directory, "reviews");
    const link = try configuredReceiptFixture(world.allocator);
    const bytes = try x.c.canonical(world.allocator, link.receipt);
    try write(receipts.dir, "prepared.receipt.json", bytes, 0o600);
    try write(receipts.dir, "packaged.receipt.json", bytes, 0o600);
    var approved = review(.configure);
    approved.parent_sha256 = link.sha256;
    approved.provenance_sha256 = link.receipt.reviewed_provenance_sha256;
    try approved.validate(.configure);
    try write(reviews.dir, "configure.json", try x.c.canonical(world.allocator, approved), 0o600);
    const before = try x.fs.inventory(world.allocator, t.io, directory, 16, x.maximum_document);
    try t.expectError(error.InvalidPhase, material.stage(&world, directory, .configure, "expected.config"));
    try x.fs.requireTree(before.tree, (try x.fs.inventory(world.allocator, t.io, directory, 16, x.maximum_document)).tree);
    try t.expectError(error.InvalidPhase, main.run(&world, .{ .workspace = directory.path, .command = .{ .producer = .configure } }));
    try x.fs.requireTree(before.tree, (try x.fs.inventory(world.allocator, t.io, directory, 16, x.maximum_document)).tree);
    try t.expect(link.receipt.packaging == null);
    try t.expectError(error.InvalidPhase, selection.create(&world, directory));
    try x.fs.requireTree(before.tree, (try x.fs.inventory(world.allocator, t.io, directory, 16, x.maximum_document)).tree);
    const controls = try world.child(directory, "controls");
    try t.expectEqual(@as(u32, 0), (try x.fs.inventory(world.allocator, t.io, controls, 8, x.maximum_document)).tree.files);
}
