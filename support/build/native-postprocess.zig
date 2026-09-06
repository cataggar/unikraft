// SPDX-License-Identifier: BSD-3-Clause

//! Planning and execution of ordered platform post-processing declarations.
//!
//! Every mutation produces a fresh tracked build output. This preserves the
//! declaration's in-place semantics without allowing a later command to modify
//! an earlier step's cached output.

const std = @import("std");
const api = @import("component-api.zig");

pub const Error = error{
    OutOfMemory,
    DuplicateBinding,
    DuplicateOutput,
    InvalidBinding,
    InvalidReference,
    MalformedTransformation,
    UnsupportedArchitecture,
    UnsupportedTransformation,
    MissingTool,
};

pub const Binding = struct {
    reference: api.ArtifactReference,
    logical_path: []const u8,
    role: api.ArtifactRole = .intermediate,
};

pub const PlanOptions = struct {
    architecture: api.Architecture,
    bootinfo_names: bool = false,
};

pub const ToolKind = enum {
    strip,
    objcopy,
    objdump,
    nm,
    readelf,
};

pub const Helper = enum {
    uk_reloc,
    bootinfo,
    multiboot,
    efi,
    linux_header,
    compile_database,
};

pub const Argument = union(enum) {
    literal: []const u8,
    directory: []const u8,
    input: usize,
    output: usize,
    tool: ToolKind,
    helper: Helper,
};

pub const OperationKind = enum {
    uk_reloc,
    strip,
    bootinfo,
    multiboot,
    efi,
    objcopy_binary,
    linux_header,
    compile_database,
};

pub const ArtifactSource = union(enum) {
    binding: usize,
    operation: usize,
};

pub const Artifact = struct {
    source: ArtifactSource,
    transformation: ?[]const u8,
    name: ?[]const u8,
    logical_path: []const u8,
    role: api.ArtifactRole,
    mutation: bool,
};

pub const Operation = struct {
    transformation: []const u8,
    kind: OperationKind,
    inputs: []const usize,
    outputs: []const usize,
    arguments: []const Argument,
};

pub const Plan = struct {
    backing_allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    artifacts: []const Artifact,
    operations: []const Operation,
    binding_count: usize,

    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub fn planSelectedPlatform(
    allocator: std.mem.Allocator,
    graph: api.FinalizedGraph,
    config: api.ConfigQuery,
    bindings: []const Binding,
) Error!Plan {
    return planPlatform(allocator, graph.selectedPlatform().*, config, bindings, .{
        .architecture = graph.target.architecture,
        .bootinfo_names = config.isEnabled("CONFIG_UKPLAT_MEMRNAME"),
    });
}

pub fn planPlatform(
    allocator: std.mem.Allocator,
    platform: api.Platform,
    config: api.ConfigQuery,
    bindings: []const Binding,
    options: PlanOptions,
) Error!Plan {
    const arena = allocator.create(std.heap.ArenaAllocator) catch return error.OutOfMemory;
    errdefer allocator.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();

    var artifacts = std.array_list.Managed(Artifact).init(owned);
    var operations = std.array_list.Managed(Operation).init(owned);

    for (bindings, 0..) |binding, index| {
        if (binding.logical_path.len == 0) return error.InvalidBinding;
        for (bindings[0..index]) |previous| {
            if (referenceEql(previous.reference, binding.reference)) {
                return error.DuplicateBinding;
            }
        }
        artifacts.append(.{
            .source = .{ .binding = index },
            .transformation = null,
            .name = null,
            .logical_path = try owned.dupe(u8, binding.logical_path),
            .role = binding.role,
            .mutation = false,
        }) catch return error.OutOfMemory;
    }

    for (platform.post_process, 0..) |transformation, transformation_index| {
        if (transformation.name.len == 0) return error.MalformedTransformation;
        for (platform.post_process[0..transformation_index]) |previous| {
            if (std.mem.eql(u8, previous.name, transformation.name)) {
                return error.MalformedTransformation;
            }
        }
        if (!transformation.condition.matches(config)) continue;
        for (transformation.effects, 0..) |effect, effect_index| {
            const name = effectName(effect);
            for (transformation.effects[0..effect_index]) |previous| {
                if (std.mem.eql(u8, effectName(previous), name)) {
                    return error.MalformedTransformation;
                }
            }
        }

        const kind = operationKind(transformation.kind) orelse
            return error.UnsupportedTransformation;
        const input_count = 1 + transformation.additional_inputs.len;
        const inputs = owned.alloc(usize, input_count) catch return error.OutOfMemory;
        inputs[0] = resolveReference(
            platform.name,
            transformation.input,
            bindings,
            artifacts.items,
        ) orelse return error.InvalidReference;
        for (transformation.additional_inputs, 0..) |reference, index| {
            inputs[index + 1] = resolveReference(
                platform.name,
                reference,
                bindings,
                artifacts.items,
            ) orelse return error.InvalidReference;
        }

        try validateShape(kind, transformation, inputs.len);

        const operation_index = operations.items.len;
        const outputs = owned.alloc(usize, transformation.effects.len) catch
            return error.OutOfMemory;
        for (transformation.effects, 0..) |effect, effect_index| {
            const artifact = switch (effect) {
                .create => |created| blk: {
                    if (created.name.len == 0 or created.path.len == 0) {
                        return error.MalformedTransformation;
                    }
                    for (artifacts.items) |existing| {
                        if (std.mem.eql(u8, existing.logical_path, created.path)) {
                            return error.DuplicateOutput;
                        }
                    }
                    break :blk Artifact{
                        .source = .{ .operation = operation_index },
                        .transformation = try owned.dupe(u8, transformation.name),
                        .name = try owned.dupe(u8, created.name),
                        .logical_path = try owned.dupe(u8, created.path),
                        .role = created.role,
                        .mutation = false,
                    };
                },
                .mutate_input => |mutated| blk: {
                    if (mutated.name.len == 0 or mutated.input_index >= inputs.len) {
                        return error.MalformedTransformation;
                    }
                    const mutated_input = artifacts.items[inputs[mutated.input_index]];
                    break :blk Artifact{
                        .source = .{ .operation = operation_index },
                        .transformation = try owned.dupe(u8, transformation.name),
                        .name = try owned.dupe(u8, mutated.name),
                        .logical_path = try owned.dupe(u8, mutated_input.logical_path),
                        .role = mutated.role,
                        .mutation = true,
                    };
                },
            };
            outputs[effect_index] = artifacts.items.len;
            artifacts.append(artifact) catch return error.OutOfMemory;
        }

        const arguments = try makeArguments(
            owned,
            kind,
            options,
            transformation.flags,
            inputs,
            outputs,
            artifacts.items,
        );
        operations.append(.{
            .transformation = try owned.dupe(u8, transformation.name),
            .kind = kind,
            .inputs = inputs,
            .outputs = outputs,
            .arguments = arguments,
        }) catch return error.OutOfMemory;
    }

    return .{
        .backing_allocator = allocator,
        .arena = arena,
        .artifacts = artifacts.toOwnedSlice() catch return error.OutOfMemory,
        .operations = operations.toOwnedSlice() catch return error.OutOfMemory,
        .binding_count = bindings.len,
    };
}

fn operationKind(kind: api.PostProcessKind) ?OperationKind {
    return switch (kind) {
        .uk_reloc => .uk_reloc,
        .strip => .strip,
        .bootinfo => .bootinfo,
        .multiboot => .multiboot,
        .efi => .efi,
        .objcopy_binary => .objcopy_binary,
        .linux_header => .linux_header,
        .compile_database => .compile_database,
        else => null,
    };
}

fn effectName(effect: api.PostProcessEffect) []const u8 {
    return switch (effect) {
        .create => |created| created.name,
        .mutate_input => |mutated| mutated.name,
    };
}

fn validateShape(
    kind: OperationKind,
    transformation: api.PostProcessTransformation,
    input_count: usize,
) Error!void {
    var creates: usize = 0;
    var mutations: usize = 0;
    var primary_mutations: usize = 0;
    for (transformation.effects) |effect| {
        switch (effect) {
            .create => creates += 1,
            .mutate_input => |mutated| {
                mutations += 1;
                if (mutated.input_index == 0) primary_mutations += 1;
                if (mutated.input_index >= input_count) return error.MalformedTransformation;
            },
        }
    }

    const valid = switch (kind) {
        .uk_reloc => input_count == 1 and creates == 1 and
            mutations == 1 and primary_mutations == 1,
        .strip => input_count == 1 and creates == 1 and mutations == 0,
        .bootinfo => input_count == 1 and creates == 1 and
            mutations == 1 and primary_mutations == 1,
        .multiboot, .objcopy_binary => input_count == 1 and
            creates == 0 and mutations == 1 and primary_mutations == 1,
        .efi => input_count == 2 and creates == 0 and
            mutations == 1 and primary_mutations == 1,
        .linux_header => input_count == 2 and creates == 0 and
            mutations == 1 and primary_mutations == 1,
        .compile_database => input_count == 1 and creates == 1 and mutations == 0,
    };
    if (!valid) return error.MalformedTransformation;
}

fn makeArguments(
    allocator: std.mem.Allocator,
    kind: OperationKind,
    options: PlanOptions,
    flags: []const []const u8,
    inputs: []const usize,
    outputs: []const usize,
    artifacts: []const Artifact,
) Error![]const Argument {
    var args = std.array_list.Managed(Argument).init(allocator);
    switch (kind) {
        .uk_reloc => {
            const created = findOutput(outputs, artifacts, false) orelse
                return error.MalformedTransformation;
            const mutated = findOutput(outputs, artifacts, true) orelse
                return error.MalformedTransformation;
            try appendArgs(&args, &.{
                .{ .literal = "uk-reloc" },
                .{ .literal = "--script" },
                .{ .helper = .uk_reloc },
                .{ .literal = "--nm" },
                .{ .tool = .nm },
                .{ .literal = "--readelf" },
                .{ .tool = .readelf },
                .{ .literal = "--objcopy" },
                .{ .tool = .objcopy },
                .{ .input = inputs[0] },
                .{ .output = created },
                .{ .output = mutated },
            });
        },
        .strip => {
            try appendArgs(&args, &.{
                .{ .literal = "strip" },
                .{ .literal = "--tool" },
                .{ .tool = .strip },
            });
            for (flags) |section| {
                try appendArgs(&args, &.{
                    .{ .literal = "--remove-section" },
                    .{ .literal = section },
                });
            }
            try appendArgs(&args, &.{
                .{ .input = inputs[0] },
                .{ .output = outputs[0] },
            });
        },
        .bootinfo => {
            const created = findOutput(outputs, artifacts, false) orelse
                return error.MalformedTransformation;
            const mutated = findOutput(outputs, artifacts, true) orelse
                return error.MalformedTransformation;
            const architecture = switch (options.architecture) {
                .x86_64 => "x86_64",
                .arm64 => "arm64",
                else => return error.UnsupportedArchitecture,
            };
            try appendArgs(&args, &.{
                .{ .literal = "bootinfo" },
                .{ .literal = "--script" },
                .{ .helper = .bootinfo },
                .{ .literal = "--objdump" },
                .{ .tool = .objdump },
                .{ .literal = "--objcopy" },
                .{ .tool = .objcopy },
                .{ .literal = "--arch" },
                .{ .literal = architecture },
            });
            if (options.bootinfo_names) {
                args.append(.{ .literal = "--names" }) catch return error.OutOfMemory;
            }
            try appendArgs(&args, &.{
                .{ .input = inputs[0] },
                .{ .output = created },
                .{ .output = mutated },
            });
        },
        .multiboot => {
            try appendArgs(&args, &.{
                .{ .literal = "multiboot" },
                .{ .literal = "--script" },
                .{ .helper = .multiboot },
                .{ .input = inputs[0] },
                .{ .output = outputs[0] },
            });
        },
        .efi => {
            try appendArgs(&args, &.{
                .{ .literal = "efi" },
                .{ .literal = "--script" },
                .{ .helper = .efi },
                .{ .literal = "--nm" },
                .{ .tool = .nm },
                .{ .literal = "--readelf" },
                .{ .tool = .readelf },
                .{ .input = inputs[0] },
                .{ .input = inputs[1] },
                .{ .output = outputs[0] },
            });
        },
        .objcopy_binary => {
            try appendArgs(&args, &.{
                .{ .literal = "objcopy-binary" },
                .{ .literal = "--tool" },
                .{ .tool = .objcopy },
                .{ .input = inputs[0] },
                .{ .output = outputs[0] },
            });
        },
        .linux_header => {
            try appendArgs(&args, &.{
                .{ .literal = "linux-header" },
                .{ .literal = "--script" },
                .{ .helper = .linux_header },
                .{ .literal = "--nm" },
                .{ .tool = .nm },
                .{ .input = inputs[0] },
                .{ .input = inputs[1] },
                .{ .output = outputs[0] },
            });
        },
        .compile_database => {
            const output = artifacts[outputs[0]];
            try appendArgs(&args, &.{
                .{ .literal = "compile-database" },
                .{ .literal = "--script" },
                .{ .helper = .compile_database },
                .{ .literal = "--search-root" },
                .{ .directory = std.fs.path.dirname(output.logical_path) orelse "." },
                .{ .input = inputs[0] },
                .{ .output = outputs[0] },
            });
        },
    }
    return args.toOwnedSlice() catch return error.OutOfMemory;
}

fn appendArgs(
    list: *std.array_list.Managed(Argument),
    values: []const Argument,
) Error!void {
    list.appendSlice(values) catch return error.OutOfMemory;
}

fn findOutput(
    outputs: []const usize,
    artifacts: []const Artifact,
    mutation: bool,
) ?usize {
    for (outputs) |artifact_index| {
        if (artifacts[artifact_index].mutation == mutation) return artifact_index;
    }
    return null;
}

fn resolveReference(
    platform_name: []const u8,
    reference: api.ArtifactReference,
    bindings: []const Binding,
    artifacts: []const Artifact,
) ?usize {
    switch (reference) {
        .post_process_output => |wanted| {
            if (!std.mem.eql(u8, wanted.platform, platform_name)) return null;
            for (artifacts, 0..) |artifact, index| {
                const transformation = artifact.transformation orelse continue;
                const name = artifact.name orelse continue;
                if (std.mem.eql(u8, transformation, wanted.transformation) and
                    std.mem.eql(u8, name, wanted.output))
                {
                    return index;
                }
            }
            return null;
        },
        else => {
            for (bindings, 0..) |binding, index| {
                if (referenceEql(binding.reference, reference)) return index;
            }
            return null;
        },
    }
}

fn referenceEql(a: api.ArtifactReference, b: api.ArtifactReference) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .path => |item| std.mem.eql(u8, item, b.path),
        .generated_output => |item| std.mem.eql(u8, item, b.generated_output),
        .component_output => |item| std.mem.eql(u8, item.component, b.component_output.component) and
            std.mem.eql(u8, item.path, b.component_output.path),
        .library_partial_output => |item| std.mem.eql(u8, item, b.library_partial_output),
        .library_final_object => |item| std.mem.eql(u8, item, b.library_final_object),
        .stage_output => |item| std.mem.eql(u8, item.platform, b.stage_output.platform) and
            std.mem.eql(u8, item.stage, b.stage_output.stage),
        .post_process_output => |item| std.mem.eql(u8, item.platform, b.post_process_output.platform) and
            std.mem.eql(u8, item.transformation, b.post_process_output.transformation) and
            std.mem.eql(u8, item.output, b.post_process_output.output),
    };
}

pub const ToolCommands = struct {
    python_executable: []const u8 = "python3",
    python_command: ?[]const u8 = null,
    strip: []const u8,
    objcopy: []const u8,
    objdump: ?[]const u8,
    nm: []const u8,
    readelf: []const u8 = "llvm-readelf",
};

pub const ExecutorPaths = struct {
    runner: std.Build.LazyPath,
    uk_reloc: std.Build.LazyPath,
    bootinfo: std.Build.LazyPath,
    multiboot: std.Build.LazyPath,
    efi: std.Build.LazyPath,
    linux_header: std.Build.LazyPath,
    compile_database: std.Build.LazyPath,
    elf_tools: std.Build.LazyPath,
};

pub const TrackedOutput = struct {
    transformation: []const u8,
    name: []const u8,
    logical_path: []const u8,
    role: api.ArtifactRole,
    mutation: bool,
    path: std.Build.LazyPath,
};

pub const Execution = struct {
    outputs: []const TrackedOutput,

    pub fn latestOutput(self: Execution, logical_path: []const u8) ?TrackedOutput {
        var index = self.outputs.len;
        while (index != 0) {
            index -= 1;
            const output = self.outputs[index];
            if (std.mem.eql(u8, output.logical_path, logical_path)) return output;
        }
        return null;
    }

    pub fn publicationPath(
        self: Execution,
        logical_path: []const u8,
        fallback: std.Build.LazyPath,
    ) std.Build.LazyPath {
        const output = self.latestOutput(logical_path) orelse return fallback;
        return output.path;
    }
};

pub fn execute(
    b: *std.Build,
    plan: Plan,
    binding_paths: []const std.Build.LazyPath,
    tools: ToolCommands,
    paths: ExecutorPaths,
) Error!Execution {
    if (binding_paths.len != plan.binding_count) return error.InvalidBinding;

    const resolved = b.allocator.alloc(?std.Build.LazyPath, plan.artifacts.len) catch
        return error.OutOfMemory;
    @memset(resolved, null);
    for (binding_paths, 0..) |path, index| resolved[index] = path;

    for (plan.operations) |operation| {
        const run = b.addSystemCommand(&.{tools.python_executable});
        run.setEnvironmentVariable(
            "PYTHON",
            tools.python_command orelse tools.python_executable,
        );
        run.addFileArg(paths.runner);
        if (operation.kind == .uk_reloc or operation.kind == .bootinfo or
            operation.kind == .efi or
            operation.kind == .linux_header)
        {
            run.addFileInput(paths.elf_tools);
        }

        for (operation.arguments) |argument| {
            switch (argument) {
                .literal => |item| run.addArg(item),
                .directory => |path| run.addDirectoryArg(.{ .cwd_relative = path }),
                .input => |artifact_index| {
                    run.addFileArg(resolved[artifact_index] orelse
                        return error.InvalidReference);
                },
                .output => |artifact_index| {
                    const basename = std.fs.path.basename(
                        plan.artifacts[artifact_index].logical_path,
                    );
                    resolved[artifact_index] = run.addOutputFileArg(basename);
                },
                .tool => |tool| run.addArg(try toolCommand(tools, tool)),
                .helper => |helper| run.addFileArg(switch (helper) {
                    .uk_reloc => paths.uk_reloc,
                    .bootinfo => paths.bootinfo,
                    .multiboot => paths.multiboot,
                    .efi => paths.efi,
                    .linux_header => paths.linux_header,
                    .compile_database => paths.compile_database,
                }),
            }
        }
        for (operation.outputs) |artifact_index| {
            if (resolved[artifact_index] == null) return error.MalformedTransformation;
        }
    }

    var outputs = std.array_list.Managed(TrackedOutput).init(b.allocator);
    for (plan.artifacts[plan.binding_count..], plan.binding_count..) |artifact, index| {
        outputs.append(.{
            .transformation = b.dupe(artifact.transformation.?),
            .name = b.dupe(artifact.name.?),
            .logical_path = b.dupe(artifact.logical_path),
            .role = artifact.role,
            .mutation = artifact.mutation,
            .path = resolved[index].?,
        }) catch return error.OutOfMemory;
    }
    return .{ .outputs = outputs.toOwnedSlice() catch return error.OutOfMemory };
}

fn toolCommand(tools: ToolCommands, tool: ToolKind) Error![]const u8 {
    return switch (tool) {
        .strip => tools.strip,
        .objcopy => tools.objcopy,
        .objdump => tools.objdump orelse return error.MissingTool,
        .nm => tools.nm,
        .readelf => tools.readelf,
    };
}

fn enabled(_: ?*const anyopaque, name: []const u8) bool {
    return std.mem.eql(u8, name, "CONFIG_ENABLED");
}

fn value(_: ?*const anyopaque, name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, name, "CONFIG_UK_ARCH")) return "arm64";
    return null;
}

const test_config = api.ConfigQuery{
    .is_enabled_fn = enabled,
    .value_fn = value,
};

test "all native postprocess declarations compile" {
    std.testing.refAllDecls(@This());
}

test "publication selects the latest mutated artifact instead of final-link output" {
    const raw = std.Build.LazyPath{ .cwd_relative = "/cache/raw-final-link.dbg" };
    const relocated = std.Build.LazyPath{ .cwd_relative = "/cache/relocated.dbg" };
    const execution = Execution{ .outputs = &.{.{
        .transformation = "uk-reloc",
        .name = "debug",
        .logical_path = "/build/hyperv.dbg",
        .role = .debug,
        .mutation = true,
        .path = relocated,
    }} };

    const selected = execution.publicationPath("/build/hyperv.dbg", raw);
    try std.testing.expect(selected == .cwd_relative);
    try std.testing.expectEqualStrings("/cache/relocated.dbg", selected.cwd_relative);
    try std.testing.expect(!std.mem.eql(u8, selected.cwd_relative, raw.cwd_relative));
}

test "x86 plan preserves side output and mutation chain order" {
    const stage = api.ArtifactReference{ .stage_output = .{
        .platform = "kvm",
        .stage = "final-link",
    } };
    const platform = api.Platform{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .post_process = &.{
            .{
                .name = "strip",
                .kind = .strip,
                .input = stage,
                .effects = &.{.{ .create = .{
                    .name = "image",
                    .path = "/build dir/app qemu",
                    .role = .image,
                } }},
            },
            .{
                .name = "bootinfo",
                .kind = .bootinfo,
                .input = .{ .post_process_output = .{
                    .platform = "kvm",
                    .transformation = "strip",
                    .output = "image",
                } },
                .effects = &.{
                    .{ .create = .{
                        .name = "bootinfo",
                        .path = "/build dir/app qemu.bootinfo",
                        .role = .side,
                    } },
                    .{ .mutate_input = .{ .name = "image", .role = .image } },
                },
            },
            .{
                .name = "multiboot",
                .kind = .multiboot,
                .input = .{ .post_process_output = .{
                    .platform = "kvm",
                    .transformation = "bootinfo",
                    .output = "image",
                } },
                .effects = &.{.{ .mutate_input = .{
                    .name = "image",
                    .role = .image,
                } }},
            },
        },
    };
    var plan = try planPlatform(std.testing.allocator, platform, test_config, &.{.{
        .reference = stage,
        .logical_path = "/build dir/app qemu.dbg",
        .role = .debug,
    }}, .{ .architecture = .x86_64 });
    defer plan.deinit();

    try std.testing.expectEqual(@as(usize, 3), plan.operations.len);
    try std.testing.expectEqual(OperationKind.strip, plan.operations[0].kind);
    try std.testing.expectEqual(OperationKind.bootinfo, plan.operations[1].kind);
    try std.testing.expectEqual(OperationKind.multiboot, plan.operations[2].kind);
    try std.testing.expectEqual(plan.operations[0].outputs[0], plan.operations[1].inputs[0]);
    try std.testing.expectEqual(plan.operations[1].outputs[1], plan.operations[2].inputs[0]);
    try std.testing.expectEqualStrings(
        "/build dir/app qemu.bootinfo",
        plan.artifacts[plan.operations[1].outputs[0]].logical_path,
    );
    try std.testing.expect(plan.artifacts[plan.operations[1].outputs[1]].mutation);

    const bootinfo_args = plan.operations[1].arguments;
    try std.testing.expect(bootinfo_args[0] == .literal);
    try std.testing.expectEqualStrings("bootinfo", bootinfo_args[0].literal);
    try std.testing.expect(bootinfo_args[2] == .helper);
    try std.testing.expect(bootinfo_args[4] == .tool);
    try std.testing.expect(bootinfo_args[9] == .input);
    try std.testing.expect(bootinfo_args[10] == .output);
    try std.testing.expect(bootinfo_args[11] == .output);
}

test "arm64 plan orders binary conversion before Linux header and ELF dependency" {
    const stage = api.ArtifactReference{ .stage_output = .{
        .platform = "kvm",
        .stage = "final-link",
    } };
    const platform = api.Platform{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .post_process = &.{
            .{
                .name = "strip",
                .kind = .strip,
                .input = stage,
                .effects = &.{.{ .create = .{
                    .name = "image",
                    .path = "/out/app",
                    .role = .image,
                } }},
            },
            .{
                .name = "linux-binary",
                .kind = .objcopy_binary,
                .input = .{ .post_process_output = .{
                    .platform = "kvm",
                    .transformation = "strip",
                    .output = "image",
                } },
                .effects = &.{.{ .mutate_input = .{
                    .name = "image",
                    .role = .image,
                } }},
            },
            .{
                .name = "linux-header",
                .kind = .linux_header,
                .input = .{ .post_process_output = .{
                    .platform = "kvm",
                    .transformation = "linux-binary",
                    .output = "image",
                } },
                .additional_inputs = &.{stage},
                .effects = &.{.{ .mutate_input = .{
                    .name = "image",
                    .role = .image,
                } }},
            },
        },
    };
    var plan = try planPlatform(std.testing.allocator, platform, test_config, &.{.{
        .reference = stage,
        .logical_path = "/out/app.dbg",
        .role = .debug,
    }}, .{ .architecture = .arm64 });
    defer plan.deinit();

    try std.testing.expectEqual(OperationKind.objcopy_binary, plan.operations[1].kind);
    try std.testing.expectEqual(OperationKind.linux_header, plan.operations[2].kind);
    try std.testing.expectEqual(plan.operations[1].outputs[0], plan.operations[2].inputs[0]);
    try std.testing.expectEqual(@as(usize, 0), plan.operations[2].inputs[1]);
    const args = plan.operations[2].arguments;
    try std.testing.expect(args[5] == .input);
    try std.testing.expectEqual(plan.operations[2].inputs[0], args[5].input);
    try std.testing.expect(args[6] == .input);
    try std.testing.expectEqual(@as(usize, 0), args[6].input);
    try std.testing.expect(args[7] == .output);
}

test "EFI plan populates relocation data before strip and EFI conversion" {
    const stage = api.ArtifactReference{ .stage_output = .{
        .platform = "hyperv",
        .stage = "final-link",
    } };
    const platform = api.Platform{
        .name = "hyperv",
        .origin = .{ .internal = .platform },
        .post_process = &.{
            .{
                .name = "uk-reloc",
                .kind = .uk_reloc,
                .input = stage,
                .effects = &.{
                    .{ .create = .{
                        .name = "relocations",
                        .path = "/out/hyperv.efi.dbg.uk_reloc.bin",
                        .role = .side,
                    } },
                    .{ .mutate_input = .{
                        .name = "debug",
                        .role = .debug,
                    } },
                },
            },
            .{
                .name = "strip",
                .kind = .strip,
                .input = .{ .post_process_output = .{
                    .platform = "hyperv",
                    .transformation = "uk-reloc",
                    .output = "debug",
                } },
                .flags = &.{ ".dynamic", ".dynsym", ".dynstr", ".rela.dyn" },
                .effects = &.{.{ .create = .{
                    .name = "image",
                    .path = "/out/hyperv.efi",
                    .role = .image,
                } }},
            },
            .{
                .name = "efi",
                .kind = .efi,
                .input = .{ .post_process_output = .{
                    .platform = "hyperv",
                    .transformation = "strip",
                    .output = "image",
                } },
                .additional_inputs = &.{.{ .post_process_output = .{
                    .platform = "hyperv",
                    .transformation = "uk-reloc",
                    .output = "debug",
                } }},
                .effects = &.{.{ .mutate_input = .{
                    .name = "image",
                    .role = .image,
                } }},
            },
        },
    };
    var plan = try planPlatform(std.testing.allocator, platform, test_config, &.{.{
        .reference = stage,
        .logical_path = "/out/hyperv.efi.dbg",
        .role = .debug,
    }}, .{ .architecture = .x86_64 });
    defer plan.deinit();

    try std.testing.expectEqual(OperationKind.uk_reloc, plan.operations[0].kind);
    try std.testing.expectEqual(OperationKind.strip, plan.operations[1].kind);
    try std.testing.expectEqual(OperationKind.efi, plan.operations[2].kind);
    try std.testing.expectEqual(plan.operations[0].outputs[1], plan.operations[1].inputs[0]);
    try std.testing.expectEqual(plan.operations[1].outputs[0], plan.operations[2].inputs[0]);
    try std.testing.expectEqual(plan.operations[0].outputs[1], plan.operations[2].inputs[1]);
    try std.testing.expectEqualStrings("--remove-section", plan.operations[1].arguments[3].literal);
    try std.testing.expectEqualStrings(".dynamic", plan.operations[1].arguments[4].literal);
    try std.testing.expect(plan.operations[0].arguments[2] == .helper);
    try std.testing.expectEqual(Helper.uk_reloc, plan.operations[0].arguments[2].helper);
    try std.testing.expect(plan.operations[2].arguments[2] == .helper);
    try std.testing.expectEqual(Helper.efi, plan.operations[2].arguments[2].helper);
}

test "planner rejects missing references, collisions, and unsupported active kinds" {
    const missing = api.Platform{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .post_process = &.{.{
            .name = "strip",
            .kind = .strip,
            .input = .{ .path = "/missing.dbg" },
            .effects = &.{.{ .create = .{
                .name = "image",
                .path = "/out/app",
                .role = .image,
            } }},
        }},
    };
    try std.testing.expectError(
        error.InvalidReference,
        planPlatform(std.testing.allocator, missing, test_config, &.{}, .{
            .architecture = .x86_64,
        }),
    );

    const source = api.ArtifactReference{ .path = "/in.dbg" };
    const collision = api.Platform{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .post_process = &.{
            .{
                .name = "first",
                .kind = .strip,
                .input = source,
                .effects = &.{.{ .create = .{
                    .name = "image",
                    .path = "/out/app",
                    .role = .image,
                } }},
            },
            .{
                .name = "second",
                .kind = .strip,
                .input = source,
                .effects = &.{.{ .create = .{
                    .name = "image",
                    .path = "/out/app",
                    .role = .image,
                } }},
            },
        },
    };
    try std.testing.expectError(
        error.DuplicateOutput,
        planPlatform(std.testing.allocator, collision, test_config, &.{.{
            .reference = source,
            .logical_path = "/in.dbg",
        }}, .{ .architecture = .x86_64 }),
    );

    const unsupported = api.Platform{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .post_process = &.{.{
            .name = "gzip",
            .kind = .gzip,
            .input = source,
            .effects = &.{.{ .create = .{
                .name = "gzip",
                .path = "/out/app.gz",
                .role = .image,
            } }},
        }},
    };
    try std.testing.expectError(
        error.UnsupportedTransformation,
        planPlatform(std.testing.allocator, unsupported, test_config, &.{.{
            .reference = source,
            .logical_path = "/in.dbg",
        }}, .{ .architecture = .x86_64 }),
    );
}

test "production native profiles plan through compile database generation" {
    const native_graph = @import("native-image-graph.zig");
    inline for (.{
        native_graph.Profile.@"qemu-x86_64",
        native_graph.Profile.@"qemu-arm64",
        native_graph.Profile.@"hyperv-x86_64-efi",
    }) |profile| {
        var registered = try native_graph.RegisteredGraph.init(std.testing.allocator, .{
            .roots = .{
                .base = "/src/unikraft",
                .app = "/src/app",
                .output = "/build output",
                .config = "/build output/.config",
            },
            .profile = profile,
        });
        defer registered.deinit();

        const platform = registered.graph.selectedPlatform();
        var final_output: ?[]const u8 = null;
        for (platform.link_stages) |stage| {
            if (std.mem.eql(u8, stage.name, "final-link")) {
                final_output = stage.output;
                break;
            }
        }
        var plan = try planSelectedPlatform(
            std.testing.allocator,
            registered.graph,
            test_config,
            &.{.{
                .reference = .{ .stage_output = .{
                    .platform = platform.name,
                    .stage = "final-link",
                } },
                .logical_path = final_output orelse return error.TestUnexpectedResult,
                .role = .debug,
            }},
        );
        defer plan.deinit();

        const expected_operations: usize = if (profile == .@"qemu-x86_64") 4 else 5;
        try std.testing.expectEqual(expected_operations, plan.operations.len);
        if (profile == .@"hyperv-x86_64-efi") {
            try std.testing.expectEqual(OperationKind.uk_reloc, plan.operations[0].kind);
            try std.testing.expectEqual(OperationKind.strip, plan.operations[1].kind);
            try std.testing.expectEqual(
                plan.operations[0].outputs[1],
                plan.operations[1].inputs[0],
            );
        }
        const compile_database = plan.operations[plan.operations.len - 1];
        try std.testing.expectEqual(OperationKind.compile_database, compile_database.kind);
        try std.testing.expectEqual(
            plan.operations[plan.operations.len - 2].outputs[0],
            compile_database.inputs[0],
        );
        try std.testing.expectEqualStrings(
            "/build output/compile_commands.json",
            plan.artifacts[compile_database.outputs[0]].logical_path,
        );
        try std.testing.expectEqual(
            api.ArtifactRole.auxiliary,
            plan.artifacts[compile_database.outputs[0]].role,
        );
        try std.testing.expect(!plan.artifacts[compile_database.outputs[0]].mutation);
        try std.testing.expect(compile_database.arguments[2] == .helper);
        try std.testing.expectEqual(
            Helper.compile_database,
            compile_database.arguments[2].helper,
        );
        try std.testing.expect(compile_database.arguments[4] == .directory);
        try std.testing.expectEqualStrings(
            "/build output",
            compile_database.arguments[4].directory,
        );
    }
}
