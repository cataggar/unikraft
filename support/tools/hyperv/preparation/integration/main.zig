const std = @import("std");
const x = @import("common.zig");
const material = @import("material.zig");
const selection = @import("selection.zig");
const p = x.p;
const c = x.c;
const fs = x.fs;

pub const Command = union(enum) {
    runtime_material,
    material,
    stage: struct { phase: @FieldType(x.Stage, "phase"), expected: ?[]const u8 },
    producer: x.Phase,
    selection,
    importer,
    measure: enum { prepare, configure, build, package, generate, importer },
};

pub const Arguments = struct { workspace: []const u8, command: Command };

pub fn arguments(args: []const []const u8) !Arguments {
    if (args.len < 3 or args.len > 5) return error.InvalidArguments;
    try p.environment.absolute(args[2]);
    if (std.mem.eql(u8, args[1], "runtime-material") and args.len == 3)
        return .{ .workspace = args[2], .command = .runtime_material };
    if (std.mem.eql(u8, args[1], "material") and args.len == 3)
        return .{ .workspace = args[2], .command = .material };
    if (std.mem.eql(u8, args[1], "selection") and args.len == 3)
        return .{ .workspace = args[2], .command = .selection };
    if (std.mem.eql(u8, args[1], "importer") and args.len == 3)
        return .{ .workspace = args[2], .command = .importer };
    if (std.mem.eql(u8, args[1], "measure") and args.len == 4)
        return .{ .workspace = args[2], .command = .{ .measure = std.meta.stringToEnum(@FieldType(Command, "measure"), args[3]) orelse return error.InvalidArguments } };
    if (std.mem.eql(u8, args[1], "producer") and args.len == 4)
        return .{ .workspace = args[2], .command = .{ .producer = std.meta.stringToEnum(x.Phase, args[3]) orelse return error.InvalidArguments } };
    if (std.mem.eql(u8, args[1], "stage") and args.len >= 4) {
        const phase = std.meta.stringToEnum(@FieldType(x.Stage, "phase"), args[3]) orelse return error.InvalidArguments;
        if (phase == .configure) {
            if (args.len != 5) return error.InspectionExpectationRequired;
            try c.core.private_files.basename(args[4]);
        } else if (args.len != 4) return error.InvalidArguments;
        return .{ .workspace = args[2], .command = .{ .stage = .{ .phase = phase, .expected = if (args.len == 5) args[4] else null } } };
    }
    return error.InvalidArguments;
}

pub fn attempt(world: *x.World, directory: fs.Directory, phase: x.Phase, review_sha256: x.Sha, material_sha256: x.Sha) !void {
    const state = try world.state(directory);
    var lock = try state.lock(world.io);
    defer lock.close(world.io);
    _ = try world.publish(&lock, try std.fmt.allocPrint(world.allocator, "attempt-{s}.json", .{@tagName(phase)}), .{
        .schema = "hyperv_native_integration_attempt_v1",
        .phase = phase,
        .review_sha256 = review_sha256,
        .material_sha256 = material_sha256,
        .replay = "forbidden",
    });
}

fn producer(world: *x.World, workspace: fs.Directory, phase: x.Phase) !x.Sha {
    const state = try world.state(workspace);
    const reviews = try world.child(workspace, if (phase == .generate) "reserved-controls" else "reviews");
    const reviewed = try world.read(x.Review, reviews, try std.fmt.allocPrint(world.allocator, "{s}.json", .{@tagName(phase)}), null);
    const review = reviewed.value;
    try review.validate(phase);
    const receipts = try world.child(workspace, "receipts");
    const parent_phase: c.Phase = switch (phase) {
        .prepare, .configure => .prepared,
        .build => .configured,
        .package => .built,
        .generate => .packaged,
    };
    const parent = if (phase != .prepare) try world.receipt(receipts, parent_phase, review.parent_sha256.?) else null;
    var workspace_lock = try state.lock(world.io);
    defer workspace_lock.close(world.io);
    const controls = try world.child(workspace, "controls");
    var stage: ?x.Stage = null;
    var selected: ?selection.Material = null;
    const bootstrap_sha = switch (phase) {
        .prepare, .package => review.material_sha256,
        .configure, .build => blk: {
            stage = (try world.read(x.Stage, controls, try std.fmt.allocPrint(world.allocator, "{s}.json", .{@tagName(phase)}), review.material_sha256)).value;
            if (!std.mem.eql(u8, @tagName(stage.?.phase), @tagName(phase)) or
                !std.meta.eql(stage.?.parent_sha256, review.parent_sha256.?) or
                !std.meta.eql(try p.producer.bindingDigest(world.allocator, stage.?.execution), review.execution_sha256.?) or
                !std.meta.eql(try p.producer.bindingDigest(world.allocator, stage.?.inspection), review.inspection_sha256.?))
                return error.UnreviewedInput;
            try stage.?.execution.workspace.require(try x.ns.Identity.directory(workspace));
            break :blk stage.?.bootstrap_sha256;
        },
        .generate => blk: {
            selected = (try world.read(selection.Material, reviews, "selection.json", review.material_sha256)).value;
            if (!std.meta.eql(c.digest(try c.canonical(world.allocator, selected.?.plan)), review.selection_sha256.?))
                return error.UnreviewedInput;
            break :blk selected.?.bootstrap_sha256;
        },
    };
    const root = (try material.bundle(world, workspace, bootstrap_sha)).value;
    if (stage) |selected_stage| {
        try @import("runtime_material.zig").requireExecution(world, root.binding, selected_stage.execution);
        try @import("runtime_material.zig").requireExecution(world, root.binding, selected_stage.inspection);
    }
    var context = try world.context(root, review.provenance_sha256);
    defer world.merge(context.failures) catch unreachable;
    defer world.merge(context.git.failures) catch unreachable;
    _ = try context.verify();
    const receipt_state = try world.state(receipts);
    var receipt_lock = try receipt_state.lock(world.io);
    defer receipt_lock.close(world.io);
    if (phase == .generate) {
        const inputs = selected.?;
        const asset_bindings = try selection.bindings(world, inputs);
        try selection.requireControlInventory(world, workspace, inputs.plan.assets, asset_bindings);
        const capability = try p.inputs.loadCapability(world.allocator, world.io, inputs.plan, asset_bindings);
        const capability_source = try selection.source(world, inputs.capability_source, capability.value.provenance);
        defer world.merge(capability_source.git.failures) catch unreachable;
        try p.provenance.verify(world.allocator, world.io, capability.value.provenance, capability_source.provenance_bindings, review.capability_provenance_sha256.?);
        try p.source.require(try p.source.inspect(capability_source.git, capability_source.repository), capability.value.provenance.source);
        try attempt(world, reviews, phase, reviewed.sha256, review.material_sha256);
        const staging = try world.state(try world.child(workspace, "staging"));
        var staging_lock = try staging.lock(world.io);
        defer staging_lock.close(world.io);
        const result = try p.inputs.generate(&context, &staging_lock, parent.?, try world.state(try world.child(workspace, "package")), try world.child(workspace, "output"), inputs.plan, review.selection_sha256.?, asset_bindings, try world.open(inputs.qemu_directory));
        try selection.reservedBudget(world, workspace, result.ledger);
        return c.digest(try c.canonical(world.allocator, result));
    }
    try attempt(world, controls, phase, reviewed.sha256, review.material_sha256);
    const receipt = switch (phase) {
        .prepare => blk: {
            var metadata = try world.metadata(root);
            defer if (metadata) |*value| value.deinit();
            break :blk try context.prepared(workspace, root.binding.config, if (metadata) |*value| value else null);
        },
        .configure, .build => blk: {
            const inputs = try world.inputs(stage.?.execution);
            _ = try context.publishBinding(&receipt_lock, if (phase == .configure) .configured else .built, inputs, review.execution_sha256.?);
            const result = try context.runProducer(parent.?, inputs, review.execution_sha256.?, review.inspection_sha256.?);
            var inspection = inputs;
            inspection.workspace.config = result.config_after;
            _ = try context.publishBinding(&receipt_lock, if (phase == .configure) .configured_inspection else .built_inspection, inspection, review.inspection_sha256.?);
            break :blk result;
        },
        .package => blk: {
            const directory = try world.state(try world.child(workspace, "package"));
            var lock = try directory.lock(world.io);
            defer lock.close(world.io);
            break :blk try context.package(parent.?, &lock, try world.child(workspace, "output"));
        },
        .generate => unreachable,
    };
    return (try context.publish(&receipt_lock, receipt)).sha256;
}

fn importer(world: *x.World, workspace: fs.Directory) !p.admission.Commitments {
    const reserved = try world.child(workspace, "reserved-controls");
    const review = (try world.read(selection.ImportReview, reserved, "import.json", null)).value;
    const selected = (try world.read(selection.Material, reserved, "selection.json", review.material_sha256)).value;
    const root = (try material.bundle(world, workspace, selected.bootstrap_sha256)).value;
    if (!std.meta.eql(c.digest(try c.canonical(world.allocator, selected.plan)), review.review.selection_sha256) or
        !std.meta.eql(c.digest(try c.canonical(world.allocator, root.provenance)), review.review.provenance_sha256))
        return error.UnreviewedInput;
    const assets = try selection.bindings(world, selected);
    try selection.requireControlInventory(world, workspace, selected.plan.assets, assets);
    const capability = try p.inputs.loadCapability(world.allocator, world.io, selected.plan, assets);
    const producing = try selection.source(world, root.locations, root.provenance);
    const public = try selection.source(world, selected.capability_source, capability.value.provenance);
    defer world.merge(producing.git.failures) catch unreachable;
    defer world.merge(public.git.failures) catch unreachable;
    var loaded = try p.admission.load(world.allocator, world.io, review.review, .{
        .staging = try world.state(try world.child(workspace, "staging")),
        .receipts = try world.child(workspace, "receipts"),
        .producer_source = producing,
        .capability_source = public,
        .config = workspace,
        .packaged = try world.state(try world.child(workspace, "package")),
        .efi = try world.child(workspace, "output"),
        .assets = assets,
        .qemu = try world.open(selected.qemu_directory),
        .engine = .{ .directory = try world.open(selected.engine.path), .contract = selected.engine.contract },
    }, world.deadline);
    defer loaded.deinit();
    try x.synthetic(loaded.input.receipt.guard);
    if (loaded.input.receipt.purpose != .synthetic) return error.NonSyntheticInput;
    try selection.reservedBudget(world, workspace, loaded.input.ledger);
    return loaded.commitments;
}

pub fn main(init: std.process.Init.Minimal) void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const allocator = arena.allocator();
    var world: x.World = .{
        .allocator = allocator,
        .io = threaded.io(),
        .deadline = c.core.process.Deadline.afterMilliseconds(30 * 60 * 1000) catch |err| fail(.{}, err),
    };
    defer world.deinit();
    const args = init.args.toSlice(allocator) catch |err| fail(.{}, err);
    const command = arguments(args) catch |err| fail(.{}, err);
    c.core.process.initialize() catch |err| fail(.{}, err);
    run(&world, command) catch |err| fail(world.failures, err);
}

pub fn run(world: *x.World, command: Arguments) !void {
    const workspace = try world.open(command.workspace);
    _ = try world.state(workspace);
    if (command.command == .measure) {
        try measure(world, workspace, command.command.measure);
        return;
    }
    if (command.command == .importer) {
        const commitments = try importer(world, workspace);
        const output = try c.canonical(world.allocator, .{
            .schema = "hyperv_native_integration_result_v1",
            .state = "loaded_prepared",
            .authority = "not_admitted",
            .projection_use = "pending_parent_review",
            .commitments = commitments,
        });
        try std.Io.File.stdout().writeStreamingAll(world.io, output);
        return;
    }
    const hash = switch (command.command) {
        .runtime_material => (try @import("runtime_material.zig").publish(world, workspace)).sha256,
        .material => (try material.bootstrap(world, workspace)).sha256,
        .stage => |stage| (try material.stage(world, workspace, stage.phase, stage.expected)).sha256,
        .producer => |phase| try producer(world, workspace, phase),
        .selection => (try selection.create(world, workspace)).sha256,
        .importer, .measure => unreachable,
    };
    try std.Io.File.stdout().writeStreamingAll(world.io, try c.canonical(world.allocator, .{
        .schema = "hyperv_native_integration_result_v1",
        .operation = @tagName(command.command),
        .authority = "not_admitted",
        .sha256 = hash,
    }));
}

fn measure(world: *x.World, workspace: fs.Directory, phase: @FieldType(Command, "measure")) !void {
    const bootstrap = try material.bundle(world, workspace, null);
    const receipts = try world.child(workspace, "receipts");
    const provenance_sha256 = c.digest(try c.canonical(world.allocator, bootstrap.value.provenance));
    const fields = switch (phase) {
        .prepare, .package => try c.canonical(world.allocator, .{
            .material_sha256 = bootstrap.sha256,
            .provenance_sha256 = provenance_sha256,
            .parent_sha256 = if (phase == .package)
                (try world.read(p.receipts.Receipt, receipts, "built.receipt.json", null)).sha256
            else
                @as(?x.Sha, null),
        }),
        .configure, .build => blk: {
            const record = try world.read(x.Stage, try world.child(workspace, "controls"), try std.fmt.allocPrint(world.allocator, "{s}.json", .{@tagName(phase)}), null);
            break :blk try c.canonical(world.allocator, .{
                .material_sha256 = record.sha256,
                .provenance_sha256 = provenance_sha256,
                .parent_sha256 = record.value.parent_sha256,
                .execution_sha256 = try p.producer.bindingDigest(world.allocator, record.value.execution),
                .inspection_sha256 = try p.producer.bindingDigest(world.allocator, record.value.inspection),
            });
        },
        .generate, .importer => blk: {
            const record = try world.read(selection.Material, try world.child(workspace, "reserved-controls"), "selection.json", null);
            const selected = record.value;
            const engine_executable = try x.runtimeExecutable(selected.engine.contract, .preparation);
            const assets = try selection.bindings(world, selected);
            const capability = try p.inputs.loadCapability(world.allocator, world.io, selected.plan, assets);
            var hashes: [4]x.Sha = undefined;
            for (selected.plan.publication.receipts, &hashes) |file, *hash| hash.* = file.sha256;
            break :blk try c.canonical(world.allocator, .{
                .material_sha256 = record.sha256,
                .provenance_sha256 = provenance_sha256,
                .selection_sha256 = c.digest(try c.canonical(world.allocator, selected.plan)),
                .capability_provenance_sha256 = c.digest(try c.canonical(world.allocator, capability.value.provenance)),
                .parent_sha256 = selected.plan.packaged_receipt_sha256,
                .receipt_sha256 = hashes,
                .execution_sha256 = [2]x.Sha{ selected.plan.publication.executions[0].sha256, selected.plan.publication.executions[1].sha256 },
                .engine_runtime_sha256 = c.digest(try c.canonical(world.allocator, selected.engine.contract)),
                .engine_executable_sha256 = engine_executable.sha256,
                .input_sha256 = if (phase == .importer)
                    (try world.read(p.inputs.Input, try world.child(workspace, "staging"), "input.json", null)).sha256
                else
                    @as(?x.Sha, null),
            });
        },
    };
    const document = try std.json.parseFromSlice(std.json.Value, world.allocator, fields, .{});
    try std.Io.File.stdout().writeStreamingAll(world.io, try c.canonical(world.allocator, .{
        .schema = "hyperv_native_integration_measurement_v1",
        .authority = "not_admitted",
        .phase = phase,
        .measured = document.value,
    }));
}

fn fail(previous: c.Failure, err: anyerror) noreturn {
    var failures = previous;
    if (failures.primary == null) failures.primary = c.failure(err).primary;
    const gate: enum { postsolve_expectation_required, pinned_x86_qemu_required, baked_inventory_required, physical_actor_mismatch, core_refusal } = switch (err) {
        error.InspectionExpectationRequired => .postsolve_expectation_required,
        error.RequiredX86Qemu => .pinned_x86_qemu_required,
        error.MissingBakedControlInventory => .baked_inventory_required,
        error.WrongPhysicalActor => .physical_actor_mismatch,
        else => .core_refusal,
    };
    var buffer: [2048]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    std.json.Stringify.value(.{ .schema = "hyperv_native_integration_failure_v1", .gate = gate, .failures = failures }, .{}, &writer) catch std.os.linux.exit_group(1);
    writer.writeByte('\n') catch std.os.linux.exit_group(1);
    const bytes = writer.buffered();
    _ = std.os.linux.write(2, bytes.ptr, bytes.len);
    std.os.linux.exit_group(1);
}
