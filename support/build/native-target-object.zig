// SPDX-License-Identifier: BSD-3-Clause

//! Native compilation of target-side Zig objects registered in the component graph.

const std = @import("std");
const component = @import("component-api.zig");

pub const Error = error{
    OutOfMemory,
    UnsupportedTarget,
    MissingDependencyBinding,
};

pub const PathBinding = struct {
    logical_path: []const u8,
    lazy_path: std.Build.LazyPath,
};

pub const ObjectPlan = struct {
    component_name: []const u8,
    object: component.TargetZigObject,
    optimize: std.builtin.OptimizeMode,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    objects: []const ObjectPlan,

    pub fn deinit(self: Plan) void {
        self.allocator.free(self.objects);
    }
};

pub fn plan(
    allocator: std.mem.Allocator,
    graph: component.FinalizedGraph,
    default_optimize: std.builtin.OptimizeMode,
) Error!Plan {
    var objects = std.array_list.Managed(ObjectPlan).init(allocator);
    errdefer objects.deinit();
    for (graph.libraries, 0..) |library, library_index| {
        if (!graph.libraryIsActive(library_index)) continue;
        for (library.target_zig_objects) |object| {
            if (!object.condition.matches(graph.config)) continue;
            objects.append(.{
                .component_name = library.name,
                .object = object,
                .optimize = object.optimize orelse default_optimize,
            }) catch return error.OutOfMemory;
        }
    }
    if (objects.items.len != 0 and
        !std.mem.eql(u8, graph.target.triple, "x86_64-freestanding-none"))
    {
        return error.UnsupportedTarget;
    }
    return .{
        .allocator = allocator,
        .objects = objects.toOwnedSlice() catch return error.OutOfMemory,
    };
}

pub const Options = struct {
    optimize: std.builtin.OptimizeMode,
    path_bindings: []const PathBinding = &.{},
};

pub const Output = struct {
    component_name: []const u8,
    object_name: []const u8,
    logical_path: []const u8,
    object: *std.Build.Step.Compile,
    lazy_path: std.Build.LazyPath,
};

pub const Execution = struct {
    outputs: []const Output,

    pub fn pathBindings(self: Execution, allocator: std.mem.Allocator) ![]const PathBinding {
        const bindings = try allocator.alloc(PathBinding, self.outputs.len);
        for (self.outputs, bindings) |output, *binding| {
            binding.* = .{
                .logical_path = output.logical_path,
                .lazy_path = output.lazy_path,
            };
        }
        return bindings;
    }
};

pub fn execute(
    b: *std.Build,
    graph: component.FinalizedGraph,
    options: Options,
) Error!Execution {
    const object_plan = try plan(b.allocator, graph, options.optimize);
    if (object_plan.objects.len == 0) return .{ .outputs = &.{} };
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
    });
    const outputs = b.allocator.alloc(Output, object_plan.objects.len) catch
        return error.OutOfMemory;

    for (object_plan.objects, outputs) |planned, *output| {
        const target_module = b.createModule(.{
            .root_source_file = .{ .cwd_relative = planned.object.root_source_file },
            .target = target,
            .optimize = planned.optimize,
            .link_libc = false,
            .single_threaded = true,
            .unwind_tables = .none,
            .stack_protector = false,
            .stack_check = false,
            .red_zone = false,
            .pic = planned.object.pic,
            .omit_frame_pointer = planned.object.omit_frame_pointer,
            .error_tracing = false,
        });
        try addIncludes(target_module, graph.global_includes, options.path_bindings);
        try addIncludes(target_module, planned.object.includes, options.path_bindings);
        for (planned.object.c_macros) |macro| {
            target_module.addCMacro(macro.name, macro.value);
        }

        const wrapper_source = b.addWriteFiles().add(b.fmt("{s}-{s}.zig", .{ planned.component_name, planned.object.name }),
            \\const std = @import("std");
            \\pub const panic = std.debug.no_panic;
            \\comptime { _ = @import("target"); }
            \\
        );
        const module = b.createModule(.{
            .root_source_file = wrapper_source,
            .target = target,
            .optimize = planned.optimize,
            .imports = &.{.{ .name = "target", .module = target_module }},
            .link_libc = false,
            .single_threaded = true,
            .unwind_tables = .none,
            .stack_protector = false,
            .stack_check = false,
            .red_zone = false,
            .pic = planned.object.pic,
            .omit_frame_pointer = planned.object.omit_frame_pointer,
            .error_tracing = false,
        });
        const object = b.addObject(.{
            .name = b.fmt("{s}-{s}", .{ planned.component_name, planned.object.name }),
            .root_module = module,
            .use_llvm = true,
        });
        for (planned.object.dependencies) |dependency| {
            const binding = findBinding(options.path_bindings, dependency) orelse
                return error.MissingDependencyBinding;
            binding.addStepDependencies(&object.step);
        }
        output.* = .{
            .component_name = planned.component_name,
            .object_name = planned.object.name,
            .logical_path = planned.object.output,
            .object = object,
            .lazy_path = object.getEmittedBin(),
        };
    }
    return .{ .outputs = outputs };
}

pub fn addFixtureValidation(b: *std.Build) Error!*std.Build.Step {
    const generated = b.addWriteFiles();
    const config_header = generated.add(
        "include/uk/bits/config.h",
        "#define CONFIG_ISSUE34_VALUE 34\n",
    );
    const fixture_source = b.pathFromRoot(
        "support/build/tests/target-zig-object/fixture.zig",
    );
    const fixture_include = b.pathFromRoot(
        "support/build/tests/target-zig-object/include",
    );
    const logical_header = "/fixture/generated/include/uk/bits/config.h";
    const logical_include = "/fixture/generated/include";
    const graph = testGraph(&.{.{
        .name = "fixture",
        .root_source_file = fixture_source,
        .output = "/fixture/fixture.o",
        .includes = &.{
            .{ .path = logical_include, .languages = &.{.zig} },
            .{ .path = fixture_include, .languages = &.{.zig} },
        },
        .dependencies = &.{logical_header},
    }});
    const compiled = try execute(b, graph, .{
        .optimize = .ReleaseSafe,
        .path_bindings = &.{.{
            .logical_path = logical_header,
            .lazy_path = config_header,
        }},
    });
    const link = b.addSystemCommand(&.{
        "zig",
        "cc",
        "-target",
        "x86_64-freestanding-none",
        "-nostdlib",
        "-r",
    });
    link.addFileArg(compiled.outputs[0].lazy_path);
    link.addArg("-o");
    const linked = link.addOutputFileArg("issue34-target-zig-linked.o");

    const verify = b.addSystemCommand(&.{
        "python3",
        "support/build/tests/target-zig-object/verify.py",
        "--readelf",
        "llvm-readelf",
        "--nm",
        "llvm-nm",
    });
    verify.addFileArg(linked);
    return &verify.step;
}

fn addIncludes(
    module: *std.Build.Module,
    includes: []const component.Include,
    bindings: []const PathBinding,
) Error!void {
    for (includes) |include| {
        if (!includeApplies(include)) continue;
        const path = boundDirectory(include.path, bindings) orelse
            std.Build.LazyPath{ .cwd_relative = include.path };
        switch (include.kind) {
            .normal => module.addIncludePath(path),
            .system => module.addSystemIncludePath(path),
            .quote => module.addSystemIncludePath(path),
        }
    }
}

fn includeApplies(include: component.Include) bool {
    if (include.languages.len == 0) return true;
    for (include.languages) |language| {
        if (language == .zig) return true;
    }
    return false;
}

fn boundDirectory(path: []const u8, bindings: []const PathBinding) ?std.Build.LazyPath {
    for (bindings) |binding| {
        if (std.mem.eql(u8, path, binding.logical_path)) return binding.lazy_path;
        if (!std.mem.startsWith(u8, binding.logical_path, path) or
            binding.logical_path.len <= path.len or
            binding.logical_path[path.len] != std.fs.path.sep)
        {
            continue;
        }
        var result = binding.lazy_path;
        var remainder = std.mem.tokenizeScalar(
            u8,
            binding.logical_path[path.len + 1 ..],
            std.fs.path.sep,
        );
        while (remainder.next() != null) result = result.dirname();
        return result;
    }
    return null;
}

fn findBinding(bindings: []const PathBinding, logical_path: []const u8) ?std.Build.LazyPath {
    for (bindings) |binding| {
        if (std.mem.eql(u8, binding.logical_path, logical_path)) return binding.lazy_path;
    }
    return null;
}

fn alwaysDisabled(_: ?*const anyopaque, _: []const u8) bool {
    return false;
}

fn noValue(_: ?*const anyopaque, _: []const u8) ?[]const u8 {
    return null;
}

fn testGraph(objects: []const component.TargetZigObject) component.FinalizedGraph {
    return .{
        .roots = .{
            .base = "/src/unikraft",
            .app = "/src/app",
            .output = "/build",
            .config = "/build/.config",
        },
        .target = .{
            .architecture = .x86_64,
            .family = .x86,
            .abi = "none",
            .triple = "x86_64-freestanding-none",
        },
        .toolchain = undefined,
        .global_flags = .{},
        .global_includes = &.{},
        .config = .{
            .is_enabled_fn = alwaysDisabled,
            .value_fn = noValue,
        },
        .libraries = &.{.{
            .name = "libfixture",
            .origin = .{ .internal = .library },
            .layout = .{ .ordinary = .{ .build_subdir = "libfixture" } },
            .target_zig_objects = objects,
        }},
        .active_libraries = &.{true},
        .platforms = &.{.{
            .name = "fixture",
            .origin = .{ .internal = .platform },
        }},
        .registrations = &.{},
        .selected_platform_index = 0,
        .active_link_stages = &.{},
    };
}

test "planner retains target object optimization and generated dependencies" {
    const graph = testGraph(&.{.{
        .name = "probe",
        .root_source_file = "/src/probe.zig",
        .output = "/build/probe.o",
        .optimize = .ReleaseSafe,
        .includes = &.{.{
            .path = "/build/include",
            .languages = &.{.zig},
        }},
        .dependencies = &.{"/build/include/uk/bits/config.h"},
    }});
    const object_plan = try plan(std.testing.allocator, graph, .Debug);
    defer object_plan.deinit();

    try std.testing.expectEqual(@as(usize, 1), object_plan.objects.len);
    try std.testing.expectEqual(std.builtin.OptimizeMode.ReleaseSafe, object_plan.objects[0].optimize);
    try std.testing.expectEqualStrings(
        "/build/include/uk/bits/config.h",
        object_plan.objects[0].object.dependencies[0],
    );
}

test "planner rejects non-x86_64 freestanding target" {
    var graph = testGraph(&.{.{
        .name = "probe",
        .root_source_file = "/src/probe.zig",
        .output = "/build/probe.o",
    }});
    graph.target.triple = "aarch64-freestanding-none";
    try std.testing.expectError(
        error.UnsupportedTarget,
        plan(std.testing.allocator, graph, .Debug),
    );
}
