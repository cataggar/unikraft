const std = @import("std");
const x = @import("common.zig");
const main = @import("main.zig");
const selection = @import("selection.zig");
const t = std.testing;
const a = t.allocator;
const hash = "1" ** 64;

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
        .origin = .{ .scheme = .git, .revision = "synthetic", .source_sha256 = hash.*, .producer_sha256 = hash.* },
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
