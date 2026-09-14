//! Pure held-file measurement precedes the first supplied Git/loader/tool.
const std = @import("std");
const x = @import("common.zig");
const o = x.rt.origin;
pub const MeasuredTool = struct {
    tool: x.ns.Tool,
    directory: o.Identity,
    physical_sha256: x.Sha,
};
pub const Material = struct {
    schema: enum { hyperv_native_runtime_material_v1 },
    authority: enum { not_admitted },
    spec: x.c.File,
    spec_physical: x.fs.Metadata,
    repository: o.Identity,
    actor: struct {
        role: enum { preparation },
        target: enum { aarch64_linux, x86_64_linux },
        directory: o.Identity,
        tree: x.c.Tree,
        physical_sha256: x.Sha,
        executable: x.c.File,
        helper: x.c.File,
    },
    native: []const struct { name: x.p.producer.Alias, measured: MeasuredTool },
    git: MeasuredTool,
    packages: MeasuredTool,
    bison_data: MeasuredTool,
    trust: MeasuredTool,
    dependencies: []const struct { name: []const u8, measured: MeasuredTool },
};
pub const Review = struct {
    schema: enum { hyperv_native_runtime_review_v1 },
    material_sha256: x.Sha,
    authentication: enum { existing_publisher_assurance },
    realization: enum { declared_prefix_relocation },
    evidence: []const struct { evidence_set_sha256: x.Sha, policy: []const o.Policy },
};

fn measured(world: *x.World, spec: x.ToolSpec) !MeasuredTool {
    const bound = try world.tool(spec);
    return .{
        .tool = .{ .path = bound.directory.path, .contract = bound.contract },
        .directory = try o.Identity.directory(bound.directory),
        .physical_sha256 = try x.fs.physicalDigest(world.allocator, world.io, bound.directory),
    };
}
pub fn measure(world: *x.World, workspace: x.fs.Directory) !Material {
    const requests = try world.child(workspace, "requests");
    const parsed = try world.read(x.Spec, requests, "bootstrap.json", null);
    const spec = parsed.value;
    try x.synthetic(spec.guard);
    if (spec.native.len > std.meta.fields(x.p.producer.Alias).len or spec.dependencies.len > 128) return error.LimitExceeded;
    const native = try world.allocator.alloc(std.meta.Child(@FieldType(Material, "native")), spec.native.len);
    for (spec.native, native, 0..) |item, *output, i| {
        for (spec.native[0..i]) |previous| if (previous.name == item.name) return error.InvalidRuntime;
        output.* = .{ .name = item.name, .measured = try measured(world, item.tool) };
    }
    const dependencies = try world.allocator.alloc(std.meta.Child(@FieldType(Material, "dependencies")), spec.dependencies.len);
    for (spec.dependencies, dependencies) |item, *output| {
        try x.c.core.private_files.basename(item.package_hash);
        output.* = .{ .name = item.name, .measured = try measured(world, .{
            .directory = try std.fs.path.join(world.allocator, &.{ spec.packages.directory, item.package_hash }),
            .role = .dependencies,
            .target = .data,
            .executable = null,
            .loader = null,
            .libraries = &.{},
            .origin = item.origin,
        }) };
    }
    const dependency_roots = try world.allocator.alloc(x.p.provenance.Dependencies, dependencies.len);
    const dependency_records = try world.allocator.alloc(x.p.provenance.Dependency, dependencies.len);
    for (dependencies, spec.dependencies, dependency_roots, dependency_records) |item, selected_dependency, *root, *record| {
        root.* = .{ .name = item.name, .directory = try world.open(item.measured.directory.path) };
        record.* = .{ .name = item.name, .package_hash = selected_dependency.package_hash, .content = item.measured.tool.contract };
    }
    const repository_root = try world.open(spec.repository);
    try x.p.provenance.requireDeclarationRoots(spec.packages.origin, repository_root, dependency_roots);
    for (dependencies) |item| try x.p.provenance.requireDeclarationRoots(item.measured.tool.contract.origin, repository_root, dependency_roots);
    const actor = try world.open(spec.actor_directory);
    const executable = try actor.record(world.allocator, world.io, "uk-hyperv-prepare-integration", 1024 * 1024 * 1024, .executable);
    const actual = try std.Io.Dir.openFileAbsolute(world.io, "/proc/self/exe", .{});
    defer actual.close(world.io);
    const selected = try actor.openFile(world.io, executable.path, .executable);
    defer selected.close(world.io);
    if (!std.meta.eql(try x.fs.metadata(actual), try x.fs.metadata(selected))) return error.WrongPhysicalActor;
    const spec_file = try requests.openFile(world.io, "bootstrap.json", .private);
    defer spec_file.close(world.io);
    const result: Material = .{
        .schema = .hyperv_native_runtime_material_v1,
        .authority = .not_admitted,
        .spec = try requests.record(world.allocator, world.io, "bootstrap.json", x.maximum_document, .private),
        .spec_physical = try x.fs.metadata(spec_file),
        .repository = try o.Identity.directory(try world.open(spec.repository)),
        .actor = .{
            .role = .preparation,
            .target = if (@import("builtin").cpu.arch == .aarch64) .aarch64_linux else if (@import("builtin").cpu.arch == .x86_64) .x86_64_linux else return error.InvalidRuntime,
            .directory = try o.Identity.directory(actor),
            .tree = (try x.fs.inventory(world.allocator, world.io, actor, 100000, 4 * 1024 * 1024 * 1024)).tree,
            .physical_sha256 = try x.fs.physicalDigest(world.allocator, world.io, actor),
            .executable = executable,
            .helper = try actor.record(world.allocator, world.io, "preparation-namespace", 1024 * 1024 * 1024, .executable),
        },
        .native = native,
        .git = try measured(world, spec.git),
        .packages = try measured(world, spec.packages),
        .bison_data = try measured(world, spec.bison_data),
        .trust = try measured(world, spec.trust),
        .dependencies = dependencies,
    };
    try x.p.provenance.requirePackages(world.allocator, result.packages.tool.contract, dependency_records);
    var roots: std.ArrayList([]const u8) = .empty;
    try roots.appendSlice(world.allocator, &.{ result.repository.path, result.actor.directory.path, result.git.directory.path, result.packages.directory.path, result.bison_data.directory.path, result.trust.directory.path });
    for (native) |item| try roots.append(world.allocator, item.measured.directory.path);
    for (dependencies) |item| try roots.append(world.allocator, item.measured.directory.path);
    for (native) |item| try o.requireSeparate(item.measured.tool.contract.evidence, roots.items);
    inline for (.{ "git", "packages", "bison_data", "trust" }) |field|
        try o.requireSeparate(@field(result, field).tool.contract.evidence, roots.items);
    return result;
}

fn requirePolicy(allocator: std.mem.Allocator, tool: x.rt.Tool, review: Review, used: []bool) !void {
    for (tool.evidence) |binding| {
        var found = false;
        for (review.evidence, 0..) |expected, i| {
            if (!std.meta.eql(expected.evidence_set_sha256, try o.hash(allocator, binding.set))) continue;
            if (found or !std.meta.eql(try o.hash(allocator, expected.policy), try o.hash(allocator, binding.policy)))
                return error.UnreviewedInput;
            found = true;
            used[i] = true;
        }
        if (!found) return error.WrongAuthority;
    }
}
pub fn requireReview(allocator: std.mem.Allocator, material: Material, review: Review) !void {
    _ = try x.c.sha(&review.material_sha256);
    if (!std.meta.eql(try o.hash(allocator, material), review.material_sha256)) return error.UnreviewedInput;
    if (review.evidence.len > 128) return error.LimitExceeded;
    const used = try allocator.alloc(bool, review.evidence.len);
    defer allocator.free(used);
    @memset(used, false);
    for (material.native) |item| try requirePolicy(allocator, item.measured.tool.contract, review, used);
    for (material.dependencies) |item| try requirePolicy(allocator, item.measured.tool.contract, review, used);
    inline for (.{ "git", "packages", "bison_data", "trust" }) |field|
        try requirePolicy(allocator, @field(material, field).tool.contract, review, used);
    for (used) |seen| if (!seen) return error.WrongAuthority;
}
pub fn publish(world: *x.World, workspace: x.fs.Directory) !x.c.File {
    const state = try world.state(workspace);
    var lock = try state.lock(world.io);
    defer lock.close(world.io);
    // Only output directories are created; all runtime acquisition is external.
    for ([_][]const u8{ "controls", "reviews" }) |name|
        workspace.dir.createDir(world.io, name, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    const value = try measure(world, workspace);
    const controls = try world.state(try world.child(workspace, "controls"));
    var output = try controls.lock(world.io);
    defer output.close(world.io);
    return world.publish(&output, "runtime.json", value);
}
pub fn approve(world: *x.World, workspace: x.fs.Directory) !void {
    // Read the independent review FIRST: no post-Bundle substitute or expected
    // hash calculated here can grant permission to execute supplied material.
    const review = (try world.read(Review, try world.child(workspace, "reviews"), "runtime.json", null)).value;
    const retained = (try world.read(Material, try world.child(workspace, "controls"), "runtime.json", review.material_sha256)).value;
    try requireReview(world.allocator, retained, review);
    const current = try measure(world, workspace);
    try requireReview(world.allocator, current, review);
}

fn revalidate(world: *x.World, selected: MeasuredTool) !void {
    const directory = try world.open(selected.tool.path);
    try selected.directory.require(try o.Identity.directory(directory));
    if (!std.mem.eql(u8, selected.directory.path, selected.tool.path) or
        !std.meta.eql(selected.physical_sha256, try x.fs.physicalDigest(world.allocator, world.io, directory)))
        return error.SourceChanged;
    try (x.rt.Bound{ .directory = directory, .contract = selected.tool.contract }).validate(world.allocator, world.io);
}
fn sameTool(world: *x.World, selected: x.ns.Tool, expected: MeasuredTool) !void {
    if (!std.meta.eql(try o.hash(world.allocator, selected), try o.hash(world.allocator, expected.tool)))
        return error.UnreviewedInput;
    try revalidate(world, expected);
}

/// A hand-supplied Bundle plus a later provenance review is not permission
/// to skip the earlier runtime boundary. This also runs before importer Git.
/// The original actor is remeasured, not confused with a separately reviewed
/// importing engine whose current-inode check remains in admission.requireEngine.
pub fn requireBundle(world: *x.World, workspace: x.fs.Directory, bundle: x.Bundle) !void {
    const review = (try world.read(Review, try world.child(workspace, "reviews"), "runtime.json", null)).value;
    const selected = (try world.read(Material, try world.child(workspace, "controls"), "runtime.json", review.material_sha256)).value;
    try requireReview(world.allocator, selected, review);
    const requests = try world.child(workspace, "requests");
    try x.fs.requireFile(try requests.record(world.allocator, world.io, "bootstrap.json", x.maximum_document, .private), selected.spec);
    const spec = try requests.openFile(world.io, "bootstrap.json", .private);
    defer spec.close(world.io);
    if (!std.meta.eql(try x.fs.metadata(spec), selected.spec_physical)) return error.SourceChanged;
    try selected.repository.require(try o.Identity.directory(try world.open(bundle.locations.repository)));
    try sameTool(world, .{ .path = bundle.locations.git, .contract = bundle.provenance.git }, selected.git);
    try sameTool(world, .{ .path = bundle.locations.trust, .contract = bundle.provenance.trust }, selected.trust);
    inline for (.{ "git", "packages", "bison_data", "trust" }) |field|
        try sameTool(world, @field(bundle.binding, field), @field(selected, field));
    if (bundle.binding.native.len != selected.native.len or bundle.provenance.dependencies.len != selected.dependencies.len or
        bundle.locations.dependencies.len != selected.dependencies.len) return error.UnreviewedInput;
    var compiler = false;
    for (selected.native) |expected| {
        var found = false;
        for (bundle.binding.native) |native| if (native.name == expected.name) {
            if (found) return error.UnreviewedInput;
            found = true;
            try sameTool(world, native.tool, expected.measured);
        };
        if (!found) return error.UnreviewedInput;
        if (expected.name == .zig) {
            if (compiler) return error.UnreviewedInput;
            compiler = true;
            try sameTool(world, .{ .path = bundle.locations.compiler, .contract = bundle.provenance.compiler }, expected.measured);
        }
    }
    if (!compiler) return error.MissingCompiler;
    for (selected.dependencies) |expected| {
        var found = false;
        var location: ?[]const u8 = null;
        for (bundle.locations.dependencies) |item| if (std.mem.eql(u8, item.name, expected.name)) {
            if (location != null) return error.UnreviewedInput;
            location = item.directory;
        };
        for (bundle.provenance.dependencies) |dependency| if (std.mem.eql(u8, dependency.name, expected.name)) {
            if (found) return error.UnreviewedInput;
            found = true;
            try sameTool(world, .{ .path = location orelse return error.UnreviewedInput, .contract = dependency.content }, expected.measured);
        };
        if (!found) return error.UnreviewedInput;
    }
    const actor = try world.open(bundle.locations.producer);
    try selected.actor.directory.require(try o.Identity.directory(actor));
    if (!std.meta.eql(selected.actor.physical_sha256, try x.fs.physicalDigest(world.allocator, world.io, actor)))
        return error.SourceChanged;
    try x.fs.requireTree(bundle.provenance.producer.tree, selected.actor.tree);
    try x.fs.requireFile(bundle.provenance.producer.executable orelse return error.InvalidRuntime, selected.actor.executable);
    const helper = (bundle.binding.isolation orelse return error.InvalidRuntime).helper;
    if (!std.mem.eql(u8, helper.path, actor.path)) return error.UnreviewedInput;
    try x.fs.requireTree(helper.contract.tree, selected.actor.tree);
    try x.fs.requireFile(helper.contract.executable orelse return error.InvalidRuntime, selected.actor.helper);
}

/// Later phase review may change config expectations, not silently exchange
/// the bootstrap-approved runtime or its independent authority requirements.
pub fn requireExecution(world: *x.World, bootstrap: x.p.producer.Binding, execution: x.p.producer.Binding) !void {
    inline for (.{ "native", "git", "packages", "bison_data", "trust", "trust_bundle" }) |field|
        if (!std.meta.eql(try o.hash(world.allocator, @field(bootstrap, field)), try o.hash(world.allocator, @field(execution, field))))
            return error.UnreviewedInput;
    const original_helper = (bootstrap.isolation orelse return error.InvalidRuntime).helper;
    const helper = (execution.isolation orelse return error.InvalidRuntime).helper;
    if (!std.meta.eql(try o.hash(world.allocator, original_helper), try o.hash(world.allocator, helper)))
        return error.UnreviewedInput;
}
