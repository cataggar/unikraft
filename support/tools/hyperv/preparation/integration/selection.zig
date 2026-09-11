const std = @import("std");
const x = @import("common.zig");
const material = @import("material.zig");
const p = x.p;
const c = x.c;
const fs = x.fs;

pub const FileSpec = struct { directory: []const u8, path: []const u8 };
pub const Spec = struct {
    schema: enum { hyperv_native_integration_selection_spec_v1 },
    qemu: x.ToolSpec,
    firmware_code: FileSpec,
    firmware_vars: FileSpec,
    capability_receipt: FileSpec,
    capability_images: []const u8,
    capability_source: x.Locations,
    engine: ?x.ToolSpec,
    baked_controls: []const FileSpec,
    extra_controls: []const FileSpec,
};
pub const Material = struct {
    schema: enum { hyperv_native_integration_selection_material_v1 },
    authority: enum { not_admitted },
    bootstrap_sha256: x.Sha,
    plan: p.inputs.Plan,
    bindings: []const struct { id: []const u8, directory: []const u8 },
    qemu_directory: []const u8,
    capability_source: x.Locations,
    engine: x.ns.Tool,
};
pub const ImportReview = struct {
    schema: enum { hyperv_native_integration_import_review_v1 },
    material_sha256: x.Sha,
    review: p.admission.Review,
};

const Builder = struct {
    world: *x.World,
    assets: std.ArrayList(p.inputs.Asset) = .empty,
    bindings: std.ArrayList(p.inputs.Binding) = .empty,

    fn add(self: *Builder, directory: fs.Directory, file: c.File, role: p.budget.Role, destination: []const u8, placement: @FieldType(p.inputs.Asset, "placement")) !void {
        if (self.assets.items.len >= 240) return error.LimitExceeded;
        const id = try std.fmt.allocPrint(self.world.allocator, "asset-{d}", .{self.assets.items.len});
        try self.assets.append(self.world.allocator, .{ .id = id, .role = role, .source = file, .destination = destination, .placement = placement });
        try self.bindings.append(self.world.allocator, .{ .id = id, .directory = directory });
    }
    fn addFile(self: *Builder, spec: FileSpec, role: p.budget.Role, destination: []const u8) !c.File {
        const directory = try self.world.open(spec.directory);
        const file = try directory.record(self.world.allocator, self.world.io, spec.path, c.total_cap, .artifact);
        try self.add(directory, file, role, destination, if (role == .baked_control) .baked else .staged);
        return file;
    }
    fn controlDirectory(self: *Builder, directory: fs.Directory, prefix: []const u8) !void {
        _ = try self.world.state(directory);
        const inventory = try fs.inventory(self.world.allocator, self.world.io, directory, 240, c.control_cap);
        for (inventory.entries) |file| {
            const held = try directory.openFile(self.world.io, file.path, .private);
            held.close(self.world.io);
            if (std.mem.eql(u8, file.path, ".writer.lock") and file.size == 0) continue;
            try self.add(directory, file, .publication_control, try std.fs.path.join(self.world.allocator, &.{ prefix, file.path }), .staged);
        }
    }
    fn runtime(self: *Builder, bound: x.rt.Bound, prefix: []const u8, producer: bool) !void {
        try bound.validate(self.world.allocator, self.world.io);
        const inventory = try fs.inventory(self.world.allocator, self.world.io, bound.directory, 240, c.control_cap);
        for (inventory.entries) |file| {
            const held = try bound.directory.openFile(self.world.io, file.path, .artifact);
            defer held.close(self.world.io);
            const identity = try fs.metadata(held);
            var covered = false;
            for (self.assets.items, self.bindings.items) |item, binding| {
                if (!item.role.isControl() or item.placement != .staged or
                    !std.mem.eql(u8, item.source.path, file.path) or !std.meta.eql(item.source.sha256, file.sha256)) continue;
                const other = try binding.directory.openFile(self.world.io, item.source.path, .artifact);
                defer other.close(self.world.io);
                covered = covered or std.meta.eql(identity, try fs.metadata(other));
            }
            if (!covered) try self.add(bound.directory, file, if (producer and std.mem.eql(u8, file.path, bound.contract.executable.?.path)) .producer_control else .native_control, try std.fs.path.join(self.world.allocator, &.{ prefix, file.path }), .staged);
        }
    }
};

pub fn create(world: *x.World, workspace: fs.Directory) !c.File {
    const workspace_state = try world.state(workspace);
    const receipts = try world.child(workspace, "receipts");
    const packaged = try world.read(p.receipts.Receipt, receipts, "packaged.receipt.json", null);
    try x.requireReceiptPhase(packaged.value.phase, .packaged);
    try p.receipts.validate(packaged.value);
    try x.synthetic(packaged.value.guard);
    var workspace_lock = try workspace_state.lock(world.io);
    defer workspace_lock.close(world.io);
    const root = try material.bundle(world, workspace, null);
    const requests = try world.child(workspace, "requests");
    const spec = (try world.read(Spec, requests, "selection.json", null)).value;
    if (spec.qemu.role != .qemu or spec.qemu.target != .x86_64_linux) return error.RequiredX86Qemu;
    if (spec.baked_controls.len == 0) return error.MissingBakedControlInventory;
    if (spec.baked_controls.len + spec.extra_controls.len > 128) return error.LimitExceeded;
    if (!std.mem.eql(u8, spec.capability_receipt.path, "capability.receipt.json")) return error.InvalidCapabilityName;
    const package_directory = try world.child(workspace, "package");
    const output = try world.child(workspace, "output");
    _ = try p.package.validate(world.allocator, world.io, try world.state(package_directory), output, packaged.value.packaging.?);
    var builder: Builder = .{ .world = world };
    const report = packaged.value.packaging.?;
    try builder.add(package_directory, report.raw, .raw, "images/acceptance.raw", .staged);
    try builder.add(package_directory, report.vhd, .vhd, "images/acceptance.vhd", .staged);
    const capability_directory = try world.open(spec.capability_receipt.directory);
    const capability = try world.read(p.inputs.Capability, capability_directory, spec.capability_receipt.path, null);
    try p.provenance.validate(capability.value.provenance);
    const capability_file = try builder.addFile(spec.capability_receipt, .publication_control, "controls/capability.receipt.json");
    const images = try world.open(spec.capability_images);
    try fs.requireFile(try images.record(world.allocator, world.io, capability.value.image.path, c.total_cap, .artifact), capability.value.image);
    try builder.add(images, capability.value.image, .boot_disk, "images/capability.raw", .staged);
    _ = try builder.addFile(spec.firmware_code, .firmware_code, "firmware/code.fd");
    const vars = try builder.addFile(spec.firmware_vars, .firmware_vars, "firmware/vars.fd");
    for (0..p.inputs.firmware_copy_count) |i|
        try builder.add(try world.open(spec.firmware_vars.directory), vars, .firmware_working_copy, try std.fmt.allocPrint(world.allocator, "firmware/working-{d}.fd", .{i}), .future_copy);
    const qemu = try world.tool(spec.qemu);
    const qemu_files = try fs.inventory(world.allocator, world.io, qemu.directory, 240, c.total_cap);
    for (qemu_files.entries) |file|
        try builder.add(qemu.directory, file, if (std.mem.eql(u8, file.path, qemu.contract.executable.?.path)) .qemu else .qemu_support, try std.fs.path.join(world.allocator, &.{ "qemu", file.path }), .staged);
    const actor: x.rt.Bound = .{ .directory = try world.open(root.value.locations.producer), .contract = root.value.provenance.producer };
    try world.requireActor(actor);
    try builder.runtime(actor, "controls/actor", true);
    const helper = root.value.binding.isolation.?.helper;
    try builder.runtime(.{ .directory = try world.open(helper.path), .contract = helper.contract }, "controls/namespace", false);
    const engine = if (spec.engine) |selected| try world.tool(selected) else actor;
    _ = try x.runtimeExecutable(engine.contract, .preparation);
    try builder.runtime(engine, "controls/engine", false);
    for ([_][]const u8{ "requests", "reviews", "controls" }) |name|
        try builder.controlDirectory(try world.child(workspace, name), try std.fs.path.join(world.allocator, &.{ "controls", name }));
    try builder.controlDirectory(receipts, "controls/receipts");
    for ([_][]const u8{ "run.config", "namespace-environment.json", "make-environment.json", "git-policy.json" }) |name|
        _ = try builder.addFile(.{ .directory = workspace.path, .path = name }, .publication_control, try std.fs.path.join(world.allocator, &.{ "controls", name }));
    const metadata = try builder.addFile(.{ .directory = output.path, .path = "native-config/metadata.tsv" }, .publication_control, "controls/metadata.tsv");
    for (spec.baked_controls, 0..) |file, i|
        _ = try builder.addFile(file, .baked_control, try std.fmt.allocPrint(world.allocator, "baked/control-{d}", .{i}));
    for (spec.extra_controls, 0..) |file, i|
        _ = try builder.addFile(file, .publication_control, try std.fmt.allocPrint(world.allocator, "controls/extra-{d}", .{i}));
    var plan: p.inputs.Plan = .{
        .schema = .hyperv_native_input_selection_v2,
        .packaged_receipt_sha256 = packaged.sha256,
        .solved_metadata = metadata,
        .publication = undefined,
        .capability_source = capability.value.provenance.source,
        .capability_receipt = capability_file,
        .qemu = qemu.contract,
        .assets = builder.assets.items,
    };
    for ([_][]const u8{ "prepared", "configured", "built", "packaged" }, &plan.publication.receipts) |name, *record|
        record.* = try receipts.record(world.allocator, world.io, try std.fmt.allocPrint(world.allocator, "{s}.receipt.json", .{name}), x.maximum_document, .private);
    for ([_][]const u8{ "configured", "built" }, &plan.publication.executions, &plan.publication.inspections) |name, *execution, *inspection| {
        execution.* = try receipts.record(world.allocator, world.io, try std.fmt.allocPrint(world.allocator, "{s}.binding.json", .{name}), x.maximum_document, .private);
        inspection.* = try receipts.record(world.allocator, world.io, try std.fmt.allocPrint(world.allocator, "{s}.inspection.binding.json", .{name}), x.maximum_document, .private);
    }
    _ = try p.inputs.ledger(world.allocator, plan, .{ .receipt = packaged.value, .sha256 = packaged.sha256 });
    try p.inputs.validateSolvedConfig(world.allocator, world.io, plan, builder.bindings.items, workspace, packaged.value);
    try p.inputs.checkQemuClosure(world.allocator, world.io, plan, qemu.directory);
    const locations = try world.allocator.alloc(std.meta.Child(@FieldType(Material, "bindings")), builder.bindings.items.len);
    for (builder.bindings.items, locations) |binding, *location|
        location.* = .{ .id = binding.id, .directory = binding.directory.path };
    const result: Material = .{
        .schema = .hyperv_native_integration_selection_material_v1,
        .authority = .not_admitted,
        .bootstrap_sha256 = root.sha256,
        .plan = plan,
        .bindings = locations,
        .qemu_directory = qemu.directory.path,
        .capability_source = spec.capability_source,
        .engine = .{ .path = engine.directory.path, .contract = engine.contract },
    };
    const state = try world.state(try world.child(workspace, "reserved-controls"));
    var lock = try state.lock(world.io);
    defer lock.close(world.io);
    return world.publish(&lock, "selection.json", result);
}

pub fn bindings(world: *x.World, selected: Material) ![]p.inputs.Binding {
    if (selected.bindings.len != selected.plan.assets.len or selected.bindings.len > 240) return error.InvalidSelection;
    const result = try world.allocator.alloc(p.inputs.Binding, selected.bindings.len);
    for (selected.bindings, result) |item, *binding|
        binding.* = .{ .id = item.id, .directory = try world.open(item.directory) };
    return result;
}

pub fn source(world: *x.World, locations: x.Locations, provenance: p.provenance.Record) !p.admission.ProducerSource {
    const bound = try world.provenanceBindings(locations);
    return .{
        .repository = try world.open(locations.repository),
        .provenance_bindings = bound,
        .git = try world.git(.{ .directory = bound.git, .contract = provenance.git }, locations.git_scratch),
    };
}

pub fn requireControlInventory(world: *x.World, workspace: fs.Directory, selected: []const p.inputs.Asset, assets: []const p.inputs.Binding) !void {
    if (selected.len != assets.len) return error.InvalidSelection;
    for ([_][]const u8{ "requests", "reviews", "controls", "receipts" }) |name| {
        const directory = try world.child(workspace, name);
        _ = try world.state(directory);
        const inventory = try fs.inventory(world.allocator, world.io, directory, 240, c.control_cap);
        for (inventory.entries) |file| {
            const held = try directory.openFile(world.io, file.path, .private);
            defer held.close(world.io);
            if (std.mem.eql(u8, file.path, ".writer.lock") and file.size == 0) continue;
            var found = false;
            for (selected) |item| {
                const directory_binding = try p.inputs.binding(assets, item.id);
                if (item.role != .publication_control or !std.mem.eql(u8, item.source.path, file.path) or
                    !std.mem.eql(u8, directory_binding.path, directory.path)) continue;
                try fs.requireFile(file, item.source);
                found = true;
            }
            if (!found) return error.UnexpectedControlFile;
        }
    }
}

/// These fixed, post-selection publications consume the existing reservation,
/// never an uncharged exception or a self-referential manifest entry.
pub fn reservedBudget(world: *x.World, workspace: fs.Directory, ledger: []const p.budget.Entry) !void {
    const directory = try world.child(workspace, "reserved-controls");
    _ = try world.state(directory);
    const inventory = try fs.inventory(world.allocator, world.io, directory, 8, c.control_cap);
    var bytes: u64 = 0;
    for (inventory.entries) |file| {
        const held = try directory.openFile(world.io, file.path, .private);
        held.close(world.io);
        if (std.mem.eql(u8, file.path, ".writer.lock") and file.size == 0) continue;
        var allowed = false;
        for ([_][]const u8{ "selection.json", "generate.json", "attempt-generate.json", "import.json" }) |name|
            allowed = allowed or std.mem.eql(u8, file.path, name);
        if (!allowed) return error.UnexpectedControlFile;
        bytes = try std.math.add(u64, bytes, file.size);
    }
    const staging = try world.child(workspace, "staging");
    const file = try staging.record(world.allocator, world.io, "input.json", x.maximum_document, .private);
    bytes = try std.math.add(u64, bytes, file.size);
    if (bytes > try p.inputs.publicationAllowance(ledger)) return error.ControlLimitExceeded;
}
