// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");
const component = @import("component-api.zig");

pub const PlanError = error{
    OutOfMemory,
    UnsupportedToolchain,
};

pub const ExecuteError = PlanError || error{
    CyclicLibraryPipeline,
    MissingArtifactBinding,
    MissingLibraryOutput,
    UnsupportedArtifactReference,
};

pub const PlannedArgument = union(enum) {
    literal: []const u8,
    artifact: component.ArtifactReference,
    symbol_file: SymbolFile,
    output,

    pub const SymbolFile = struct {
        prefix: []const u8,
        path: []const u8,
    };
};

pub const LibraryPlan = struct {
    library_index: usize,
    component_name: []const u8,
    partial_output: []const u8,
    partial_arguments: []const PlannedArgument,
    final_output: []const u8,
    transform_arguments: []const PlannedArgument,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    libraries: []const LibraryPlan,

    pub fn deinit(self: Plan) void {
        for (self.libraries) |library| {
            self.allocator.free(library.partial_arguments);
            self.allocator.free(library.transform_arguments);
        }
        self.allocator.free(self.libraries);
    }
};

pub fn plan(allocator: std.mem.Allocator, graph: component.FinalizedGraph) PlanError!Plan {
    if (graph.toolchain.compiler.kind != .zig_cc) return error.UnsupportedToolchain;

    var libraries = std.array_list.Managed(LibraryPlan).init(allocator);
    errdefer {
        for (libraries.items) |library| {
            allocator.free(library.partial_arguments);
            allocator.free(library.transform_arguments);
        }
        libraries.deinit();
    }

    for (graph.libraries, 0..) |library, library_index| {
        if (!graph.libraryIsActive(library_index)) continue;
        const pipeline = library.object_pipeline orelse continue;

        var partial = std.array_list.Managed(PlannedArgument).init(allocator);
        errdefer partial.deinit();
        try partial.appendSlice(&.{
            .{ .literal = "cc" },
            .{ .literal = "-target" },
            .{ .literal = graph.toolchain.target_triple },
            .{ .literal = "-nostdlib" },
            .{ .literal = "-r" },
        });
        for (pipeline.partial_link_sequence) |item| {
            switch (item) {
                .artifact => |artifact| try partial.append(.{ .artifact = artifact.artifact }),
                .literal_flag => |flag| try partial.append(.{ .literal = flag }),
                .tool_mode_flag => |flag| if (flag.forMode(.driver)) |value| {
                    try partial.append(.{ .literal = value });
                },
                .group_start => try partial.append(.{ .literal = "-Wl,--start-group" }),
                .group_end => try partial.append(.{ .literal = "-Wl,--end-group" }),
                .library_argument => |argument| try partial.append(.{ .literal = argument }),
            }
        }
        try partial.append(.{ .literal = "-o" });
        try partial.append(.output);

        var transform = std.array_list.Managed(PlannedArgument).init(allocator);
        errdefer transform.deinit();
        for (pipeline.transform.sequence) |item| {
            switch (item) {
                .literal_flag => |flag| try transform.append(.{ .literal = flag }),
                .symbol_file => |symbol| try transform.append(.{ .symbol_file = .{
                    .prefix = switch (symbol.action) {
                        .keep_global => "--keep-global-symbols=",
                        .localize => "--localize-symbols=",
                    },
                    .path = symbol.symbols_file,
                } }),
            }
        }
        try transform.append(.{ .artifact = pipeline.transform.input });
        try transform.append(.output);

        try libraries.append(.{
            .library_index = library_index,
            .component_name = library.name,
            .partial_output = pipeline.partial_link_output,
            .partial_arguments = try partial.toOwnedSlice(),
            .final_output = pipeline.transform.output,
            .transform_arguments = try transform.toOwnedSlice(),
        });
    }

    return .{
        .allocator = allocator,
        .libraries = try libraries.toOwnedSlice(),
    };
}

pub const PathBinding = struct {
    logical_path: []const u8,
    lazy_path: std.Build.LazyPath,
};

pub const Options = struct {
    path_bindings: []const PathBinding = &.{},
    validator_executable: ?*std.Build.Step.Compile = null,
};

pub const LibraryOutput = struct {
    component_name: []const u8,
    declared_partial_output: []const u8,
    partial_output: std.Build.LazyPath,
    declared_final_output: []const u8,
    final_object: std.Build.LazyPath,
    partial_link_step: *std.Build.Step.Run,
    common_validation_step: *std.Build.Step.Run,
    objcopy_step: *std.Build.Step.Run,
};

pub const Execution = struct {
    libraries: []const LibraryOutput,

    pub fn finalObject(self: Execution, component_name: []const u8) ?std.Build.LazyPath {
        for (self.libraries) |library| {
            if (std.mem.eql(u8, library.component_name, component_name)) {
                return library.final_object;
            }
        }
        return null;
    }
};

const Materializer = struct {
    b: *std.Build,
    graph: component.FinalizedGraph,
    plans: []const LibraryPlan,
    bindings: []const PathBinding,
    validator: *std.Build.Step.Compile,
    states: []State,
    outputs: []?LibraryOutput,

    const State = enum {
        pending,
        materializing,
        done,
    };

    fn materialize(self: *Materializer, plan_index: usize) ExecuteError!LibraryOutput {
        switch (self.states[plan_index]) {
            .done => return self.outputs[plan_index].?,
            .materializing => return error.CyclicLibraryPipeline,
            .pending => self.states[plan_index] = .materializing,
        }
        errdefer self.states[plan_index] = .pending;

        const library_plan = self.plans[plan_index];
        const zig = self.graph.toolchain.compiler.tool.command;
        const partial = self.b.addSystemCommand(&.{zig});
        partial.setName(self.b.fmt("partial link library {s}", .{library_plan.component_name}));
        var partial_output: ?std.Build.LazyPath = null;
        for (library_plan.partial_arguments) |argument| {
            switch (argument) {
                .literal => |value| partial.addArg(value),
                .artifact => |reference| partial.addFileArg(try self.resolveArtifact(reference)),
                .symbol_file => unreachable,
                .output => {
                    std.debug.assert(partial_output == null);
                    partial_output = partial.addOutputFileArg(std.fs.path.basename(
                        library_plan.partial_output,
                    ));
                },
            }
        }
        const linked_object = partial_output orelse unreachable;

        const validate = self.b.addRunArtifact(self.validator);
        validate.setName(self.b.fmt(
            "reject COMMON symbols in library {s}",
            .{library_plan.component_name},
        ));
        validate.addArg(library_plan.component_name);
        validate.addFileArg(linked_object);
        const validation_stamp = validate.addOutputFileArg(self.b.fmt(
            "{s}.no-common",
            .{std.fs.path.basename(library_plan.partial_output)},
        ));

        const objcopy = self.b.addSystemCommand(&.{
            self.graph.toolchain.binutils.objcopy.command,
        });
        objcopy.setName(self.b.fmt("localize symbols in library {s}", .{
            library_plan.component_name,
        }));
        var final_output: ?std.Build.LazyPath = null;
        for (library_plan.transform_arguments) |argument| {
            switch (argument) {
                .literal => |value| objcopy.addArg(value),
                .artifact => |reference| objcopy.addFileArg(
                    if (reference == .library_partial_output and
                        std.mem.eql(
                            u8,
                            reference.library_partial_output,
                            library_plan.component_name,
                        ))
                        linked_object
                    else
                        try self.resolveArtifact(reference),
                ),
                .symbol_file => |symbol| objcopy.addPrefixedFileArg(
                    symbol.prefix,
                    self.resolvePath(symbol.path),
                ),
                .output => {
                    std.debug.assert(final_output == null);
                    final_output = objcopy.addOutputFileArg(std.fs.path.basename(
                        library_plan.final_output,
                    ));
                },
            }
        }
        validation_stamp.addStepDependencies(&objcopy.step);

        const result: LibraryOutput = .{
            .component_name = library_plan.component_name,
            .declared_partial_output = library_plan.partial_output,
            .partial_output = linked_object,
            .declared_final_output = library_plan.final_output,
            .final_object = final_output orelse unreachable,
            .partial_link_step = partial,
            .common_validation_step = validate,
            .objcopy_step = objcopy,
        };
        self.outputs[plan_index] = result;
        self.states[plan_index] = .done;
        return result;
    }

    fn resolveArtifact(
        self: *Materializer,
        reference: component.ArtifactReference,
    ) ExecuteError!std.Build.LazyPath {
        return switch (reference) {
            .path => |path| self.resolvePath(path),
            .generated_output => |path| self.findBinding(path) orelse
                error.MissingArtifactBinding,
            .component_output => |output| self.findBinding(output.path) orelse
                error.MissingArtifactBinding,
            .library_partial_output => |name| self.resolveLibraryOutput(name, false),
            .library_final_object => |name| self.resolveLibraryOutput(name, true),
            .stage_output, .post_process_output => error.UnsupportedArtifactReference,
        };
    }

    fn resolveLibraryOutput(
        self: *Materializer,
        name: []const u8,
        final: bool,
    ) ExecuteError!std.Build.LazyPath {
        for (self.plans, 0..) |library_plan, index| {
            if (!std.mem.eql(u8, library_plan.component_name, name)) continue;
            const output = try self.materialize(index);
            return if (final) output.final_object else output.partial_output;
        }
        return error.MissingLibraryOutput;
    }

    fn resolvePath(self: Materializer, path: []const u8) std.Build.LazyPath {
        return self.findBinding(path) orelse .{ .cwd_relative = path };
    }

    fn findBinding(self: Materializer, path: []const u8) ?std.Build.LazyPath {
        for (self.bindings) |binding| {
            if (std.mem.eql(u8, binding.logical_path, path)) return binding.lazy_path;
        }
        return null;
    }
};

pub fn execute(
    b: *std.Build,
    graph: component.FinalizedGraph,
    options: Options,
) ExecuteError!Execution {
    const pipeline_plan = try plan(b.allocator, graph);
    const validator = options.validator_executable orelse b.addExecutable(.{
        .name = "unikraft-elf-common-validator",
        .root_module = b.createModule(.{
            .root_source_file = b.path("support/build/elf-common-validator.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    const states = try b.allocator.alloc(Materializer.State, pipeline_plan.libraries.len);
    @memset(states, .pending);
    const outputs = try b.allocator.alloc(?LibraryOutput, pipeline_plan.libraries.len);
    @memset(outputs, null);

    var materializer: Materializer = .{
        .b = b,
        .graph = graph,
        .plans = pipeline_plan.libraries,
        .bindings = options.path_bindings,
        .validator = validator,
        .states = states,
        .outputs = outputs,
    };
    for (pipeline_plan.libraries, 0..) |_, index| {
        _ = try materializer.materialize(index);
    }

    const result = try b.allocator.alloc(LibraryOutput, pipeline_plan.libraries.len);
    for (result, outputs) |*destination, output| destination.* = output.?;
    return .{ .libraries = result };
}

fn syntheticGraph(
    libraries: []const component.Library,
    active_libraries: []const bool,
) component.FinalizedGraph {
    return .{
        .roots = .{
            .base = "/repo",
            .app = "/app",
            .output = "/app/build",
            .config = "/app/build/.config",
        },
        .target = .{
            .architecture = .x86_64,
            .family = .x86,
            .abi = "none",
            .triple = "x86_64-unknown-none",
        },
        .toolchain = .{
            .target_triple = "x86_64-unknown-none",
            .compiler = .{
                .tool = .{ .command = "zig" },
                .kind = .zig_cc,
            },
            .partial_linker = .{
                .tool = .{ .command = "zig" },
                .kind = .compiler_driver,
                .mode = .driver,
            },
            .final_linker = .{
                .tool = .{ .command = "zig" },
                .kind = .compiler_driver,
            },
            .binutils = .{
                .ar = .{ .command = "llvm-ar" },
                .objcopy = .{ .command = "llvm-objcopy" },
                .strip = .{ .command = "llvm-strip" },
                .nm = .{ .command = "llvm-nm" },
            },
        },
        .global_flags = .{},
        .global_includes = &.{},
        .libraries = libraries,
        .active_libraries = active_libraries,
        .platforms = &.{.{
            .name = "test",
            .origin = .{ .internal = .platform },
        }},
        .registrations = &.{},
        .selected_platform_index = 0,
        .active_link_stages = &.{},
    };
}

test "planner preserves partial-link ordering groups and paths with spaces" {
    const libraries = [_]component.Library{.{
        .name = "lib ordered",
        .origin = .{ .internal = .library },
        .layout = .{ .ordinary = .{ .build_subdir = "lib ordered" } },
        .object_pipeline = .{
            .partial_link_output = "/build dir/lib ordered.ld.o",
            .partial_link_sequence = &.{
                .{ .artifact = .{
                    .kind = .object,
                    .artifact = .{ .path = "/objects/first object.o" },
                } },
                .group_start,
                .{ .artifact = .{
                    .kind = .archive,
                    .artifact = .{ .path = "/archives/lib one.a" },
                } },
                .{ .tool_mode_flag = .{
                    .driver = "-Wl,--gc-sections",
                    .raw = "--gc-sections",
                } },
                .group_end,
                .{ .literal_flag = "--literal" },
                .{ .library_argument = "-lgcc" },
            },
            .transform = .{
                .input = .{ .library_partial_output = "lib ordered" },
                .output = "/build dir/lib ordered.o",
            },
        },
    }};
    var pipeline_plan = try plan(
        std.testing.allocator,
        syntheticGraph(&libraries, &.{true}),
    );
    defer pipeline_plan.deinit();

    const args = pipeline_plan.libraries[0].partial_arguments;
    try std.testing.expectEqual(@as(usize, 14), args.len);
    try std.testing.expectEqualStrings("cc", args[0].literal);
    try std.testing.expectEqualStrings("-target", args[1].literal);
    try std.testing.expectEqualStrings("x86_64-unknown-none", args[2].literal);
    try std.testing.expectEqualStrings("-nostdlib", args[3].literal);
    try std.testing.expectEqualStrings("-r", args[4].literal);
    try std.testing.expectEqualStrings("/objects/first object.o", args[5].artifact.path);
    try std.testing.expectEqualStrings("-Wl,--start-group", args[6].literal);
    try std.testing.expectEqualStrings("/archives/lib one.a", args[7].artifact.path);
    try std.testing.expectEqualStrings("-Wl,--gc-sections", args[8].literal);
    try std.testing.expectEqualStrings("-Wl,--end-group", args[9].literal);
    try std.testing.expectEqualStrings("--literal", args[10].literal);
    try std.testing.expectEqualStrings("-lgcc", args[11].literal);
    try std.testing.expectEqualStrings("-o", args[12].literal);
    try std.testing.expect(args[13] == .output);
}

test "planner retains generated and dependent typed artifacts" {
    const libraries = [_]component.Library{
        .{
            .name = "dependency",
            .origin = .{ .internal = .library },
            .layout = .{ .ordinary = .{ .build_subdir = "dependency" } },
            .object_pipeline = .{
                .partial_link_output = "/build/dependency.ld.o",
                .partial_link_sequence = &.{},
                .transform = .{
                    .input = .{ .library_partial_output = "dependency" },
                    .output = "/build/dependency.o",
                },
            },
        },
        .{
            .name = "consumer",
            .origin = .{ .internal = .library },
            .layout = .{ .ordinary = .{ .build_subdir = "consumer" } },
            .object_pipeline = .{
                .partial_link_output = "/build/consumer.ld.o",
                .partial_link_sequence = &.{
                    .{ .artifact = .{
                        .kind = .object,
                        .artifact = .{ .generated_output = "/build/generated.o" },
                    } },
                    .{ .artifact = .{
                        .kind = .object,
                        .artifact = .{ .library_final_object = "dependency" },
                    } },
                },
                .transform = .{
                    .input = .{ .library_partial_output = "consumer" },
                    .output = "/build/consumer.o",
                },
            },
        },
    };
    var pipeline_plan = try plan(
        std.testing.allocator,
        syntheticGraph(&libraries, &.{ true, true }),
    );
    defer pipeline_plan.deinit();

    const consumer_args = pipeline_plan.libraries[1].partial_arguments;
    try std.testing.expect(consumer_args[5].artifact == .generated_output);
    try std.testing.expectEqualStrings(
        "/build/generated.o",
        consumer_args[5].artifact.generated_output,
    );
    try std.testing.expect(consumer_args[6].artifact == .library_final_object);
    try std.testing.expectEqualStrings(
        "dependency",
        consumer_args[6].artifact.library_final_object,
    );
}

test "planner emits ordered objcopy symbol localization" {
    const libraries = [_]component.Library{.{
        .name = "symbols",
        .origin = .{ .internal = .library },
        .layout = .{ .ordinary = .{ .build_subdir = "symbols" } },
        .object_pipeline = .{
            .partial_link_output = "/build/symbols.ld.o",
            .partial_link_sequence = &.{},
            .transform = .{
                .input = .{ .library_partial_output = "symbols" },
                .output = "/build/symbols.o",
                .sequence = &.{
                    .{ .symbol_file = .{
                        .action = .keep_global,
                        .symbols_file = "/symbols/exports list",
                        .provenance = .library_local,
                    } },
                    .{ .literal_flag = "--wildcard" },
                    .{ .symbol_file = .{
                        .action = .localize,
                        .symbols_file = "/symbols/locals list",
                        .provenance = .library_local,
                    } },
                },
            },
        },
    }};
    var pipeline_plan = try plan(
        std.testing.allocator,
        syntheticGraph(&libraries, &.{true}),
    );
    defer pipeline_plan.deinit();

    const args = pipeline_plan.libraries[0].transform_arguments;
    try std.testing.expectEqual(@as(usize, 5), args.len);
    try std.testing.expectEqualStrings("--keep-global-symbols=", args[0].symbol_file.prefix);
    try std.testing.expectEqualStrings("/symbols/exports list", args[0].symbol_file.path);
    try std.testing.expectEqualStrings("--wildcard", args[1].literal);
    try std.testing.expectEqualStrings("--localize-symbols=", args[2].symbol_file.prefix);
    try std.testing.expect(args[3].artifact == .library_partial_output);
    try std.testing.expect(args[4] == .output);
}

test "planner accepts empty inputs and empty archive groups" {
    const libraries = [_]component.Library{.{
        .name = "empty",
        .origin = .{ .internal = .library },
        .layout = .{ .ordinary = .{ .build_subdir = "empty" } },
        .object_pipeline = .{
            .partial_link_output = "/build/empty.ld.o",
            .partial_link_sequence = &.{ .group_start, .group_end },
            .transform = .{
                .input = .{ .library_partial_output = "empty" },
                .output = "/build/empty.o",
            },
        },
    }};
    var pipeline_plan = try plan(
        std.testing.allocator,
        syntheticGraph(&libraries, &.{true}),
    );
    defer pipeline_plan.deinit();

    const args = pipeline_plan.libraries[0].partial_arguments;
    try std.testing.expectEqualStrings("-Wl,--start-group", args[5].literal);
    try std.testing.expectEqualStrings("-Wl,--end-group", args[6].literal);
    try std.testing.expectEqualStrings("-o", args[7].literal);
    try std.testing.expect(args[8] == .output);
}

test "planner excludes inactive libraries and rejects non-Zig drivers" {
    const libraries = [_]component.Library{.{
        .name = "inactive",
        .origin = .{ .internal = .library },
        .layout = .{ .ordinary = .{ .build_subdir = "inactive" } },
        .object_pipeline = .{
            .partial_link_output = "/build/inactive.ld.o",
            .partial_link_sequence = &.{},
            .transform = .{
                .input = .{ .library_partial_output = "inactive" },
                .output = "/build/inactive.o",
            },
        },
    }};
    var graph = syntheticGraph(&libraries, &.{false});
    var pipeline_plan = try plan(std.testing.allocator, graph);
    defer pipeline_plan.deinit();
    try std.testing.expectEqual(@as(usize, 0), pipeline_plan.libraries.len);

    graph.toolchain.compiler.kind = .clang;
    try std.testing.expectError(
        error.UnsupportedToolchain,
        plan(std.testing.allocator, graph),
    );
}
