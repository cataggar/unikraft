// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");
const component = @import("component-api.zig");

pub const PlanError = error{
    OutOfMemory,
    MissingLinkerScript,
    UnsupportedCompilerDriver,
    UnsupportedFinalLinkFlag,
    UnsupportedMergeStage,
    UnresolvedArtifact,
};

pub const Argument = union(enum) {
    literal: []const u8,
    artifact: component.ArtifactReference,
    merged_linker_script,
};

pub const Dependency = struct {
    artifact: component.ArtifactReference,
    path: []const u8,
};

pub const Plan = struct {
    stage_name: []const u8,
    output: []const u8,
    command: []const u8,
    arguments: []const Argument,
    linker_scripts: []const Dependency,
    dependencies: []const Dependency,
};

pub fn planSelected(
    allocator: std.mem.Allocator,
    graph: component.FinalizedGraph,
) PlanError![]Plan {
    if (graph.toolchain.compiler.kind != .zig_cc) {
        return error.UnsupportedCompilerDriver;
    }
    const platform = graph.selectedPlatform();
    var plans = std.array_list.Managed(Plan).init(allocator);
    errdefer {
        for (plans.items) |plan| deinitPlan(allocator, plan);
        plans.deinit();
    }

    for (platform.link_stages, 0..) |stage, stage_index| {
        if (!graph.linkStageIsActive(stage_index) or stage.transformation != .final_link) {
            continue;
        }
        try plans.append(try planStage(allocator, graph, stage));
    }
    return plans.toOwnedSlice();
}

pub fn deinitPlans(allocator: std.mem.Allocator, plans: []Plan) void {
    for (plans) |plan| deinitPlan(allocator, plan);
    allocator.free(plans);
}

fn deinitPlan(allocator: std.mem.Allocator, plan: Plan) void {
    allocator.free(plan.arguments);
    allocator.free(plan.linker_scripts);
    allocator.free(plan.dependencies);
}

fn planStage(
    allocator: std.mem.Allocator,
    graph: component.FinalizedGraph,
    stage: component.LinkStage,
) PlanError!Plan {
    var arguments = std.array_list.Managed(Argument).init(allocator);
    errdefer arguments.deinit();
    var scripts = std.array_list.Managed(Dependency).init(allocator);
    errdefer scripts.deinit();
    var dependencies = std.array_list.Managed(Dependency).init(allocator);
    errdefer dependencies.deinit();

    try arguments.append(.{ .literal = "-target" });
    try arguments.append(.{ .literal = graph.toolchain.target_triple });
    try arguments.insert(0, .{ .literal = "cc" });

    var emitted_script = false;
    for (stage.sequence) |item| {
        switch (item) {
            .literal_flag => |flag| {
                if (isForbiddenDriverFlag(flag)) return error.UnsupportedFinalLinkFlag;
                try arguments.append(.{ .literal = flag });
            },
            .tool_mode_flag => |flag| {
                const driver_flag = flag.driver orelse
                    return error.UnsupportedFinalLinkFlag;
                if (isForbiddenDriverFlag(driver_flag)) {
                    return error.UnsupportedFinalLinkFlag;
                }
                try arguments.append(.{ .literal = driver_flag });
            },
            .group_start => try arguments.append(.{ .literal = "-Wl,--start-group" }),
            .group_end => try arguments.append(.{ .literal = "-Wl,--end-group" }),
            .library_argument => |library| {
                if (isForbiddenDriverFlag(library)) return error.UnsupportedFinalLinkFlag;
                try arguments.append(.{ .literal = library });
            },
            .artifact => |link_artifact| {
                const path = resolveArtifactPath(graph, link_artifact.artifact) orelse
                    return error.UnresolvedArtifact;
                if (link_artifact.kind == .linker_script) {
                    try scripts.append(.{
                        .artifact = link_artifact.artifact,
                        .path = path,
                    });
                    if (!emitted_script) {
                        try arguments.append(.merged_linker_script);
                        emitted_script = true;
                    }
                } else if (link_artifact.kind == .custom_link_dependency) {
                    try dependencies.append(.{
                        .artifact = link_artifact.artifact,
                        .path = path,
                    });
                } else {
                    try arguments.append(.{ .artifact = link_artifact.artifact });
                }
            },
        }
    }
    if (!emitted_script) return error.MissingLinkerScript;
    try arguments.append(.{ .literal = "-o" });
    try arguments.append(.{ .literal = stage.output });

    const owned_arguments = try arguments.toOwnedSlice();
    errdefer allocator.free(owned_arguments);
    const owned_scripts = try scripts.toOwnedSlice();
    errdefer allocator.free(owned_scripts);
    const owned_dependencies = try dependencies.toOwnedSlice();

    return .{
        .stage_name = stage.name,
        .output = stage.output,
        .command = graph.toolchain.compiler.tool.command,
        .arguments = owned_arguments,
        .linker_scripts = owned_scripts,
        .dependencies = owned_dependencies,
    };
}

fn isForbiddenDriverFlag(flag: []const u8) bool {
    return std.mem.eql(u8, flag, "-dT") or
        std.mem.startsWith(u8, flag, "-T") or
        std.mem.indexOf(u8, flag, "--default-script") != null or
        std.mem.indexOf(u8, flag, "--script") != null or
        std.mem.indexOf(u8, flag, "-Wl,-dT") != null or
        std.mem.indexOf(u8, flag, "-Wl,--default-script") != null or
        std.mem.indexOf(u8, flag, "-Wl,-T") != null or
        std.mem.startsWith(u8, flag, "-Wl,-m");
}

fn resolveArtifactPath(
    graph: component.FinalizedGraph,
    reference: component.ArtifactReference,
) ?[]const u8 {
    return switch (reference) {
        .path, .generated_output => |path| path,
        .component_output => |output| output.path,
        .library_partial_output => |name| blk: {
            for (graph.libraries) |library| {
                if (std.mem.eql(u8, library.name, name)) {
                    break :blk if (library.object_pipeline) |pipeline|
                        pipeline.partial_link_output
                    else
                        null;
                }
            }
            break :blk null;
        },
        .library_final_object => |name| blk: {
            for (graph.libraries) |library| {
                if (std.mem.eql(u8, library.name, name)) {
                    break :blk if (library.object_pipeline) |pipeline|
                        pipeline.transform.output
                    else
                        null;
                }
            }
            break :blk null;
        },
        .stage_output => |output| blk: {
            for (graph.platforms) |platform| {
                if (!std.mem.eql(u8, platform.name, output.platform)) continue;
                for (platform.link_stages) |stage| {
                    if (std.mem.eql(u8, stage.name, output.stage)) break :blk stage.output;
                }
            }
            break :blk null;
        },
        .post_process_output => null,
    };
}

pub const ArtifactResolver = struct {
    context: ?*const anyopaque = null,
    resolve_fn: *const fn (
        ?*const anyopaque,
        component.ArtifactReference,
        []const u8,
    ) std.Build.LazyPath,

    pub fn resolve(
        self: ArtifactResolver,
        reference: component.ArtifactReference,
        fallback_path: []const u8,
    ) std.Build.LazyPath {
        return self.resolve_fn(self.context, reference, fallback_path);
    }

    pub fn cwdRelative() ArtifactResolver {
        return .{ .resolve_fn = cwdRelativeResolve };
    }
};

fn cwdRelativeResolve(
    _: ?*const anyopaque,
    _: component.ArtifactReference,
    fallback_path: []const u8,
) std.Build.LazyPath {
    return .{ .cwd_relative = fallback_path };
}

pub const Executed = struct {
    stage_name: []const u8,
    merged_linker_script: std.Build.LazyPath,
    output: std.Build.LazyPath,
    step: *std.Build.Step.Run,
};

const MergedStage = struct {
    name: []const u8,
    output: std.Build.LazyPath,
};

pub const Executor = struct {
    b: *std.Build,
    merger: *std.Build.Step.Compile,
    resolver: ArtifactResolver,
    prerequisite: ?*std.Build.Step,

    pub fn init(b: *std.Build, resolver: ArtifactResolver) Executor {
        return initWithPrerequisite(b, resolver, null);
    }

    pub fn initWithPrerequisite(
        b: *std.Build,
        resolver: ArtifactResolver,
        prerequisite: ?*std.Build.Step,
    ) Executor {
        const merger = b.addExecutable(.{
            .name = "unikraft-linker-script",
            .root_module = b.createModule(.{
                .root_source_file = b.path("support/build/linker-script.zig"),
                .target = b.graph.host,
                .optimize = .ReleaseSafe,
            }),
        });
        return .{
            .b = b,
            .merger = merger,
            .resolver = resolver,
            .prerequisite = prerequisite,
        };
    }

    pub fn addSelected(
        self: Executor,
        graph: component.FinalizedGraph,
    ) PlanError![]Executed {
        const plans = try planSelected(self.b.allocator, graph);
        defer deinitPlans(self.b.allocator, plans);
        const merged_stages = try self.addMergeStages(graph);
        const executed = try self.b.allocator.alloc(Executed, plans.len);
        errdefer self.b.allocator.free(executed);

        for (plans, 0..) |plan, index| {
            const merged = self.resolveMergedScript(
                graph,
                plan,
                merged_stages,
            );

            const link = self.b.addSystemCommand(&.{plan.command});
            if (self.prerequisite) |prerequisite| {
                link.step.dependOn(prerequisite);
            }
            var output: ?std.Build.LazyPath = null;
            for (plan.arguments, 0..) |argument, argument_index| {
                switch (argument) {
                    .literal => |literal| {
                        if (argument_index + 1 == plan.arguments.len) {
                            output = link.addOutputFileArg(std.fs.path.basename(plan.output));
                        } else {
                            link.addArg(literal);
                        }
                    },
                    .merged_linker_script => link.addPrefixedFileArg("-Wl,-T,", merged),
                    .artifact => |artifact| {
                        const path = resolveArtifactPath(graph, artifact) orelse
                            return error.UnresolvedArtifact;
                        link.addFileArg(self.resolver.resolve(artifact, path));
                    },
                }
            }
            for (plan.dependencies) |dependency| {
                link.addFileInput(self.resolver.resolve(
                    dependency.artifact,
                    dependency.path,
                ));
            }
            executed[index] = .{
                .stage_name = plan.stage_name,
                .merged_linker_script = merged,
                .output = output orelse unreachable,
                .step = link,
            };
        }
        return executed;
    }

    fn addMergeStages(
        self: Executor,
        graph: component.FinalizedGraph,
    ) PlanError![]const MergedStage {
        const platform = graph.selectedPlatform();
        var merged_stages = std.array_list.Managed(MergedStage).init(self.b.allocator);
        for (platform.link_stages, 0..) |stage, stage_index| {
            if (!graph.linkStageIsActive(stage_index)) continue;
            const custom = switch (stage.transformation) {
                .custom => |name| name,
                else => continue,
            };
            if (!std.mem.eql(u8, custom, "merge-linker-scripts")) continue;

            const merge = self.b.addRunArtifact(self.merger);
            if (self.prerequisite) |prerequisite| {
                merge.step.dependOn(prerequisite);
            }
            merge.setName(self.b.fmt("merge linker scripts for {s}", .{stage.name}));
            const output = merge.addOutputFileArg(std.fs.path.basename(stage.output));
            if (stage.sequence.len == 0) return error.MissingLinkerScript;
            for (stage.sequence) |item| {
                const artifact = switch (item) {
                    .artifact => |artifact| artifact,
                    else => return error.UnsupportedMergeStage,
                };
                if (artifact.kind != .linker_script) return error.UnsupportedMergeStage;
                const path = resolveArtifactPath(graph, artifact.artifact) orelse
                    return error.UnresolvedArtifact;
                merge.addFileArg(self.resolver.resolve(artifact.artifact, path));
            }
            try merged_stages.append(.{
                .name = stage.name,
                .output = output,
            });
        }
        return merged_stages.toOwnedSlice();
    }

    fn resolveMergedScript(
        self: Executor,
        graph: component.FinalizedGraph,
        plan: Plan,
        merged_stages: []const MergedStage,
    ) std.Build.LazyPath {
        if (plan.linker_scripts.len == 1) {
            switch (plan.linker_scripts[0].artifact) {
                .stage_output => |stage_output| {
                    if (std.mem.eql(
                        u8,
                        stage_output.platform,
                        graph.selectedPlatform().name,
                    )) {
                        for (merged_stages) |merged_stage| {
                            if (std.mem.eql(u8, merged_stage.name, stage_output.stage)) {
                                return merged_stage.output;
                            }
                        }
                    }
                },
                else => {},
            }
        }

        const merge = self.b.addRunArtifact(self.merger);
        if (self.prerequisite) |prerequisite| {
            merge.step.dependOn(prerequisite);
        }
        const merged = merge.addOutputFileArg(self.b.fmt(
            "{s}-{s}-combined.lds",
            .{ graph.selectedPlatform().name, plan.stage_name },
        ));
        for (plan.linker_scripts) |script| {
            merge.addFileArg(self.resolver.resolve(script.artifact, script.path));
        }
        return merged;
    }
};

fn fixtureGraph() component.FinalizedGraph {
    const libraries = &.{component.Library{
        .name = "libcore",
        .origin = .{ .internal = .core },
        .layout = .{ .ordinary = .{ .build_subdir = "libcore" } },
        .object_pipeline = .{
            .partial_link_output = "build dir/libcore.ld.o",
            .partial_link_sequence = &.{},
            .transform = .{
                .input = .{ .library_partial_output = "libcore" },
                .output = "build dir/libcore.o",
            },
        },
    }};
    const platforms = &.{component.Platform{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .link_stages = &.{
            .{
                .name = "partial",
                .transformation = .partial_link,
                .output = "build dir/partial.o",
            },
            .{
                .name = "final",
                .transformation = .final_link,
                .output = "build dir/image.dbg",
                .sequence = &.{
                    .{ .literal_flag = "-nostdlib" },
                    .{ .artifact = .{
                        .kind = .object,
                        .artifact = .{ .library_final_object = "libcore" },
                    } },
                    .group_start,
                    .{ .artifact = .{
                        .kind = .archive,
                        .artifact = .{ .generated_output = "build dir/generated archive.a" },
                    } },
                    .group_end,
                    .{ .library_argument = "-lgcc" },
                    .{ .artifact = .{
                        .kind = .custom_link_dependency,
                        .artifact = .{ .generated_output = "build dir/link dependency" },
                    } },
                    .{ .artifact = .{
                        .kind = .linker_script,
                        .artifact = .{ .path = "scripts dir/primary.lds" },
                    } },
                    .{ .artifact = .{
                        .kind = .linker_script,
                        .artifact = .{ .generated_output = "scripts dir/extra one.lds" },
                    } },
                    .{ .artifact = .{
                        .kind = .intermediate,
                        .artifact = .{ .stage_output = .{
                            .platform = "kvm",
                            .stage = "partial",
                        } },
                    } },
                },
            },
        },
    }};
    return .{
        .roots = .{
            .base = ".",
            .app = ".",
            .output = "build dir",
            .config = ".config",
        },
        .target = .{
            .architecture = .x86_64,
            .family = .x86,
            .abi = "none",
            .triple = "x86_64-freestanding-none",
        },
        .toolchain = .{
            .target_triple = "x86_64-freestanding-none",
            .compiler = .{
                .tool = .{ .command = "zig" },
                .kind = .zig_cc,
            },
            .partial_linker = .{
                .tool = .{ .command = "ld.lld" },
                .kind = .lld,
                .mode = .raw,
            },
            .final_linker = .{
                .tool = .{ .command = "ld.lld" },
                .kind = .lld,
            },
            .binutils = .{
                .ar = .{ .command = "ar" },
                .objcopy = .{ .command = "objcopy" },
                .strip = .{ .command = "strip" },
                .nm = .{ .command = "nm" },
            },
        },
        .global_flags = .{},
        .global_includes = &.{},
        .libraries = libraries,
        .active_libraries = &.{true},
        .platforms = platforms,
        .registrations = &.{},
        .selected_platform_index = 0,
        .active_link_stages = &.{ true, true },
    };
}

test "planner preserves final-link order and typed generated artifacts" {
    const plans = try planSelected(std.testing.allocator, fixtureGraph());
    defer deinitPlans(std.testing.allocator, plans);
    try std.testing.expectEqual(@as(usize, 1), plans.len);
    const plan = plans[0];
    try std.testing.expectEqualStrings("zig", plan.command);
    try std.testing.expectEqual(@as(usize, 2), plan.linker_scripts.len);
    try std.testing.expectEqualStrings("scripts dir/primary.lds", plan.linker_scripts[0].path);
    try std.testing.expect(plan.linker_scripts[1].artifact == .generated_output);
    try std.testing.expectEqual(@as(usize, 1), plan.dependencies.len);
    try std.testing.expect(plan.dependencies[0].artifact == .generated_output);

    try expectLiteral(plan.arguments[0], "cc");
    try expectLiteral(plan.arguments[1], "-target");
    try expectLiteral(plan.arguments[2], "x86_64-freestanding-none");
    try expectLiteral(plan.arguments[3], "-nostdlib");
    try std.testing.expect(plan.arguments[4] == .artifact);
    try expectLiteral(plan.arguments[5], "-Wl,--start-group");
    try std.testing.expect(plan.arguments[6] == .artifact);
    try expectLiteral(plan.arguments[7], "-Wl,--end-group");
    try expectLiteral(plan.arguments[8], "-lgcc");
    try std.testing.expect(plan.arguments[9] == .merged_linker_script);
    try std.testing.expect(plan.arguments[10] == .artifact);
    try expectLiteral(plan.arguments[11], "-o");
    try expectLiteral(plan.arguments[12], "build dir/image.dbg");

    var merged_count: usize = 0;
    for (plan.arguments) |argument| {
        switch (argument) {
            .merged_linker_script => merged_count += 1,
            .literal => |literal| try std.testing.expect(!isForbiddenDriverFlag(literal)),
            .artifact => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 1), merged_count);
}

test "planner rejects driver-incompatible linker script and emulation flags" {
    var graph = fixtureGraph();
    var stages = [_]component.LinkStage{.{
        .name = "bad",
        .transformation = .final_link,
        .output = "bad",
        .sequence = &.{
            .{ .literal_flag = "-Wl,-m,elf_x86_64" },
            .{ .artifact = .{
                .kind = .linker_script,
                .artifact = .{ .path = "primary.lds" },
            } },
        },
    }};
    var platforms = [_]component.Platform{graph.platforms[0]};
    platforms[0].link_stages = &stages;
    graph.platforms = &platforms;
    try std.testing.expectError(
        error.UnsupportedFinalLinkFlag,
        planSelected(std.testing.allocator, graph),
    );
}

test "planner rejects attached linker emulation flags" {
    var graph = fixtureGraph();
    var stages = [_]component.LinkStage{.{
        .name = "bad",
        .transformation = .final_link,
        .output = "bad",
        .sequence = &.{
            .{ .literal_flag = "-Wl,-melf_x86_64" },
            .{ .artifact = .{
                .kind = .linker_script,
                .artifact = .{ .path = "primary.lds" },
            } },
        },
    }};
    var platforms = [_]component.Platform{graph.platforms[0]};
    platforms[0].link_stages = &stages;
    graph.platforms = &platforms;
    try std.testing.expectError(
        error.UnsupportedFinalLinkFlag,
        planSelected(std.testing.allocator, graph),
    );
}

test "planner rejects raw-only final-link flags" {
    var graph = fixtureGraph();
    var stages = [_]component.LinkStage{.{
        .name = "bad",
        .transformation = .final_link,
        .output = "bad",
        .sequence = &.{
            .{ .tool_mode_flag = .{ .driver = null, .raw = "-r" } },
            .{ .artifact = .{
                .kind = .linker_script,
                .artifact = .{ .path = "primary.lds" },
            } },
        },
    }};
    var platforms = [_]component.Platform{graph.platforms[0]};
    platforms[0].link_stages = &stages;
    graph.platforms = &platforms;
    try std.testing.expectError(
        error.UnsupportedFinalLinkFlag,
        planSelected(std.testing.allocator, graph),
    );
}

test "planner requires a modeled linker script" {
    var graph = fixtureGraph();
    var stages = [_]component.LinkStage{.{
        .name = "bad",
        .transformation = .final_link,
        .output = "bad",
        .sequence = &.{.{ .artifact = .{
            .kind = .object,
            .artifact = .{ .path = "input.o" },
        } }},
    }};
    var platforms = [_]component.Platform{graph.platforms[0]};
    platforms[0].link_stages = &stages;
    graph.platforms = &platforms;
    try std.testing.expectError(
        error.MissingLinkerScript,
        planSelected(std.testing.allocator, graph),
    );
}

test "planner requires the Zig compiler driver" {
    var graph = fixtureGraph();
    graph.toolchain.compiler.kind = .clang;
    try std.testing.expectError(
        error.UnsupportedCompilerDriver,
        planSelected(std.testing.allocator, graph),
    );
}

fn expectLiteral(argument: Argument, expected: []const u8) !void {
    try std.testing.expect(argument == .literal);
    try std.testing.expectEqualStrings(expected, argument.literal);
}

test "executor build wiring is analyzed" {
    var never_zero: u8 = 0;
    if (@intFromPtr(&never_zero) == 0) {
        const b: *std.Build = undefined;
        const executor = Executor.init(b, ArtifactResolver.cwdRelative());
        _ = try executor.addSelected(fixtureGraph());
    }
}
