const std = @import("std");
const x = @import("common.zig");
const p = x.p;
const c = x.c;
const fs = x.fs;
const rt = x.rt;

pub fn bundle(world: *x.World, workspace: fs.Directory, expected: ?x.Sha) !struct { value: x.Bundle, sha256: x.Sha } {
    const result = try world.read(x.Bundle, try world.child(workspace, "controls"), "bootstrap.json", expected);
    try x.synthetic(result.value.guard);
    try p.provenance.validate(result.value.provenance);
    try p.producer.validateBindingStructure(world.allocator, result.value.binding);
    try p.source.require(result.value.binding.source, result.value.provenance.source);
    try result.value.binding.workspace.require(try x.ns.Identity.directory(workspace));
    return .{ .value = result.value, .sha256 = result.sha256 };
}

fn actor(world: *x.World, directory: []const u8, executable: []const u8, source: c.Source, compiler: rt.Bound) !rt.Bound {
    const compiler_executable = try x.runtimeExecutable(compiler.contract, .zig);
    return world.tool(.{
        .directory = directory,
        .executable = executable,
        .loader = null,
        .libraries = &.{},
        .role = .preparation,
        .target = compiler.contract.target,
        .origin = .{ .scheme = .git, .revision = source.head, .source_sha256 = source.physical.sha256, .producer_sha256 = compiler_executable.sha256 },
    });
}

pub fn bootstrap(world: *x.World, workspace: fs.Directory) !c.File {
    const state = try world.state(workspace);
    var lock = try state.lock(world.io);
    defer lock.close(world.io);
    const requests = try world.child(workspace, "requests");
    _ = try world.state(requests);
    const spec = (try world.read(x.Spec, requests, "bootstrap.json", null)).value;
    try x.synthetic(spec.guard);
    if (spec.initial_config) |name| try c.core.private_files.basename(name);
    if (spec.initial_metadata) |name| try c.core.private_files.basename(name);
    if (spec.initial_config == null and spec.initial_metadata != null) return error.InvalidArguments;
    if (spec.native.len > std.meta.fields(p.producer.Alias).len or spec.dependencies.len > 128)
        return error.LimitExceeded;
    const repository = try world.open(spec.repository);
    const prefix = try std.fs.path.join(world.allocator, &.{ repository.path, ".d/zig-migration-preparation/" });
    if (!std.mem.startsWith(u8, workspace.path, prefix)) return error.UnsafePath;
    for ([_][]const u8{ "controls", "reviews", "reserved-controls", "output", "scratch", "receipts", "package", "staging" }) |name|
        try workspace.dir.createDir(world.io, name, .fromMode(0o700));
    const scratch = try world.child(workspace, "scratch");
    for ([_][]const u8{ "home", "tmp", "cache", "config", "zig-local", "zig-global", "disabled-git-exec", "disabled-openssl" }) |name|
        try scratch.dir.createDir(world.io, name, .fromMode(0o700));
    const initial = if (spec.initial_config) |name|
        try requests.read(world.allocator, world.io, name, p.config.config_cap, .private)
    else
        try p.config.render(world.allocator, spec.guard);
    const initial_metadata = if (spec.initial_metadata) |name|
        try requests.record(world.allocator, world.io, name, p.config.config_cap, .private)
    else
        null;
    var metadata = if (initial_metadata) |record|
        try p.config.Metadata.parse(world.allocator, try requests.read(world.allocator, world.io, record.path, p.config.config_cap, .private))
    else
        null;
    defer if (metadata) |*value| value.deinit();
    try p.config.validateWithMetadata(world.allocator, initial, spec.guard, if (metadata) |*value| value else null);
    const copied = try fs.publish(&lock, world.io, "run.config", initial);
    try world.merge(copied.failures);
    if (copied.status != .durable or copied.failures.primary != null or copied.failures.cleanup != null or copied.failures.recording != null)
        return error.PublicationIncomplete;
    const config = try workspace.record(world.allocator, world.io, "run.config", p.config.config_cap, .private);
    const natives = try world.allocator.alloc(p.producer.Native, spec.native.len);
    var compiler: ?rt.Bound = null;
    for (spec.native, natives) |item, *native| {
        native.* = .{ .name = item.name, .bound = try world.tool(item.tool) };
        if (item.name == .zig) {
            if (compiler != null) return error.InvalidRuntime;
            compiler = native.bound;
        }
    }
    const zig = compiler orelse return error.MissingCompiler;
    const git_runtime = try world.tool(spec.git);
    const git = try world.git(git_runtime, scratch.path);
    const source = p.source.inspect(git, repository) catch |err| {
        try world.merge(git.failures);
        return err;
    };
    const self = try actor(world, spec.actor_directory, "uk-hyperv-prepare-integration", source, zig);
    try world.requireActor(self);
    const helper = try actor(world, spec.actor_directory, "preparation-namespace", source, zig);
    const packages = try world.tool(spec.packages);
    const trust = try world.tool(spec.trust);
    const bison = try world.tool(spec.bison_data);
    const dependencies = try world.allocator.alloc(p.provenance.Dependency, spec.dependencies.len);
    const locations = try world.allocator.alloc(std.meta.Child(@FieldType(x.Locations, "dependencies")), spec.dependencies.len);
    for (spec.dependencies, dependencies, locations) |item, *dependency, *location| {
        try c.core.private_files.basename(item.name);
        try c.core.private_files.basename(item.package_hash);
        const directory = try world.child(packages.directory, item.package_hash);
        dependency.* = .{
            .name = item.name,
            .package_hash = item.package_hash,
            .content = (try world.tool(.{
                .directory = directory.path,
                .role = .dependencies,
                .target = .data,
                .executable = null,
                .loader = null,
                .libraries = &.{},
                .origin = item.origin,
            })).contract,
        };
        location.* = .{ .name = item.name, .directory = directory.path };
    }
    const provenance: p.provenance.Record = .{
        .schema = .hyperv_native_producer_provenance_v1,
        .source = source,
        .host_target = switch (self.contract.target) {
            .aarch64_linux => .aarch64_linux,
            .x86_64_linux => .x86_64_linux,
            .data => return error.InvalidRuntime,
        },
        .guest_target = .x86_64_freestanding_none,
        .compiler_version = c.compiler_version,
        .producer = self.contract,
        .compiler = zig.contract,
        .git = git_runtime.contract,
        .dependencies = dependencies,
        .trust = trust.contract,
    };
    try p.provenance.validate(provenance);
    var git_metadata: std.ArrayList(x.ns.GitTree) = .empty;
    for ([_]rt.GitCommand{ .common_directory, .git_directory }) |operation| {
        const bytes = git.command(repository, operation) catch |err| {
            try world.merge(git.failures);
            return err;
        };
        const path = std.mem.trimEnd(u8, bytes, "\n");
        var seen = false;
        for (git_metadata.items) |item| seen = seen or std.mem.eql(u8, item.directory.path, path);
        if (!seen) {
            const directory = try world.open(path);
            try git_metadata.append(world.allocator, .{
                .directory = directory,
                .tree = (try fs.inventory(world.allocator, world.io, directory, 100000, 4 * 1024 * 1024 * 1024)).tree,
            });
        }
    }
    const facade = try world.open(spec.facade_runtime);
    const facade_lock = try facade.openFile(world.io, "build.lock", .private);
    defer facade_lock.close(world.io);
    var inputs: p.producer.Inputs = .{
        .repository = repository,
        .observed_source = source,
        .workspace = .{ .directory = workspace, .config = config, .output = try world.child(workspace, "output"), .scratch = scratch },
        .tools = .{
            .native = natives,
            .git = git_runtime,
            .packages = packages,
            .bison_data = bison,
            .trust = trust,
            .trust_bundle = try trust.directory.record(world.allocator, world.io, spec.trust_bundle, 1024 * 1024, .artifact),
        },
        .native_execution = .{
            .schema = .closed_native_facade_runtime_v1,
            .source_sha256 = source.tree_sha256,
            .root_build = try repository.record(world.allocator, world.io, "build.zig", 1024 * 1024, .source),
            .facade = try repository.record(world.allocator, world.io, "support/build/zig-facade-runner.zig", 1024 * 1024, .source),
            .makefile = try repository.record(world.allocator, world.io, "Makefile", 1024 * 1024, .source),
            .make_default_shell = "/bin/sh",
            .compiler_version = c.compiler_version,
            .git_entry_source = try repository.record(world.allocator, world.io, "support/tools/hyperv/preparation/git_entry.zig", 1024 * 1024, .source),
        },
        .native_proof = .{
            .schema = .hyperv_native_elf_proofs_v2,
            .source_sha256 = source.tree_sha256,
            .root_build = try repository.record(world.allocator, world.io, "build.zig", 1024 * 1024, .source),
            .builder = try repository.record(world.allocator, world.io, "support/build/hyperv-proof-build.zig", 1024 * 1024, .source),
            .tool = try repository.record(world.allocator, world.io, "support/build/hyperv-proof-tool.zig", 1024 * 1024, .source),
            .modes = .{ .smp, .irq, .drivers },
        },
        .isolation = .{
            .helper = helper,
            .git_metadata = git_metadata.items,
            .account = try p.environment.Account.current(world.allocator, world.io),
            .facade_runtime = facade,
            .facade_lock = try x.ns.Identity.of(try std.fs.path.join(world.allocator, &.{ facade.path, "build.lock" }), facade_lock),
            // This construction-only field is replaced before validation or publication.
            .environment = config,
        },
    };
    const draft = try p.producer.describe(world.allocator, inputs);
    inputs.isolation.?.environment = try world.publish(&lock, "namespace-environment.json", try p.producer.bindingEnvironment(world.allocator, draft));
    inputs.isolation.?.make_environment = try world.publish(&lock, "make-environment.json", try p.producer.bindingMakeEnvironment(world.allocator, draft));
    inputs.isolation.?.git_policy = try world.publish(&lock, "git-policy.json", try p.producer.bindingGitPolicy(world.allocator, draft));
    const binding = try p.producer.describe(world.allocator, inputs);
    try p.producer.validateBindingStructure(world.allocator, binding);
    try p.producer.validatePolicyFiles(world.allocator, world.io, binding);
    try x.ns.validate(world.allocator, world.io, inputs.isolation.?, repository, workspace);
    try p.producer.requireNativeProofFiles(world.allocator, world.io, repository, source, inputs.native_proof);
    const output: x.Bundle = .{
        .schema = .hyperv_native_integration_material_v1,
        .authority = .not_admitted,
        .guard = spec.guard,
        .provenance = provenance,
        .initial_metadata = initial_metadata,
        .binding = binding,
        .locations = .{
            .repository = repository.path,
            .producer = self.directory.path,
            .compiler = zig.directory.path,
            .git = git_runtime.directory.path,
            .trust = trust.directory.path,
            .dependencies = locations,
            .git_scratch = scratch.path,
        },
    };
    const controls = try world.state(try world.child(workspace, "controls"));
    var controls_lock = try controls.lock(world.io);
    defer controls_lock.close(world.io);
    return world.publish(&controls_lock, "bootstrap.json", output);
}

pub fn stage(world: *x.World, workspace: fs.Directory, phase: @FieldType(x.Stage, "phase"), expected_config: ?[]const u8) !c.File {
    const workspace_state = try world.state(workspace);
    const receipts = try world.child(workspace, "receipts");
    const parent_phase: c.Phase = if (phase == .configure) .prepared else .configured;
    const parent_name = try std.fmt.allocPrint(world.allocator, "{s}.receipt.json", .{@tagName(parent_phase)});
    const parent = try world.read(p.receipts.Receipt, receipts, parent_name, null);
    try x.requireReceiptPhase(parent.value.phase, parent_phase);
    try p.receipts.validate(parent.value);
    try x.synthetic(parent.value.guard);
    var workspace_lock = try workspace_state.lock(world.io);
    defer workspace_lock.close(world.io);
    const base = try bundle(world, workspace, null);
    var execution = base.value.binding;
    execution.config = try workspace.record(world.allocator, world.io, execution.config.path, p.config.config_cap, .private);
    try fs.requireFile(execution.config, parent.value.config_after);
    const expected = if (phase == .configure) blk: {
        const name = expected_config orelse return error.InspectionExpectationRequired;
        const requests = try world.child(workspace, "requests");
        break :blk try requests.record(world.allocator, world.io, name, p.config.config_cap, .private);
    } else blk: {
        if (expected_config != null) return error.InvalidArguments;
        break :blk execution.config;
    };
    const value: x.Stage = .{
        .schema = .hyperv_native_integration_stage_v1,
        .authority = .not_admitted,
        .phase = phase,
        .bootstrap_sha256 = base.sha256,
        .parent_sha256 = parent.sha256,
        .execution = execution,
        .inspection = try x.inspectionBinding(execution, expected),
        .inspection_basis = if (phase == .configure) .externally_supplied_expected_config else .unchanged_built_config,
    };
    const state = try world.state(try world.child(workspace, "controls"));
    var lock = try state.lock(world.io);
    defer lock.close(world.io);
    return world.publish(&lock, try std.fmt.allocPrint(world.allocator, "{s}.json", .{@tagName(phase)}), value);
}
