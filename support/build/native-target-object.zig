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
    optimize: std.lang.Optimize,
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
    default_optimize: std.lang.Optimize,
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
    optimize: std.lang.Optimize,
    path_bindings: []const PathBinding = &.{},
    strip: bool = false,
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

pub fn targetQuery(isr: bool) std.Target.Query {
    return .{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
        .cpu_features_add = if (isr)
            std.Target.x86.featureSet(&.{.soft_float})
        else
            .empty,
        .cpu_features_sub = if (isr)
            std.Target.x86.featureSet(&.{ .x87, .mmx, .sse, .sse2, .avx, .avx2 })
        else
            .empty,
    };
}

test "ISR Zig target excludes unsaved x86 registers" {
    const target = try std.zig.system.resolveTargetQuery(std.testing.io, targetQuery(true));
    try std.testing.expect(target.cpu.features.isEnabled(@backingInt(std.Target.x86.Feature.soft_float)));
    inline for (.{ .x87, .mmx, .sse, .sse2, .avx, .avx2 }) |feature| {
        try std.testing.expect(!target.cpu.features.isEnabled(@backingInt(@field(std.Target.x86.Feature, @tagName(feature)))));
    }
}

pub fn execute(
    b: *std.Build,
    graph: component.FinalizedGraph,
    options: Options,
) Error!Execution {
    const object_plan = try plan(b.allocator, graph, options.optimize);
    if (object_plan.objects.len == 0) return .{ .outputs = &.{} };
    const outputs = b.allocator.alloc(Output, object_plan.objects.len) catch
        return error.OutOfMemory;

    for (object_plan.objects, outputs) |planned, *output| {
        const target = b.resolveTargetQuery(targetQuery(planned.object.isr));
        const target_module = b.createModule(.{
            .root_source_file = b.graph.cwdRelativePath(planned.object.root_source_file),
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
            .strip = if (options.strip) true else null,
        });
        try addIncludes(target_module, graph.global_includes, options.path_bindings);
        try addIncludes(target_module, planned.object.includes, options.path_bindings);
        for (planned.object.c_macros) |macro| {
            target_module.addCMacro(macro.name, macro.value);
        }
        if (planned.object.c_translation) |translation| {
            const translate_c = @import("translate-c");
            const dependency = b.dependency("translate-c", .{
                .target = b.graph.host,
                .optimize = .safe,
            });
            var source: std.Io.Writer.Allocating = .init(b.allocator);
            for (translation.headers) |header| {
                source.writer.print("#include <{s}>\n", .{header}) catch
                    return error.OutOfMemory;
            }
            const header = b.addWriteFiles().add(
                b.fmt("{s}-{s}-translate.h", .{ planned.component_name, planned.object.name }),
                source.written(),
            );
            const translated = translate_c.Translator.init(dependency, .{
                .name = b.fmt("{s}-{s}-config", .{ planned.component_name, planned.object.name }),
                .c_source_file = header,
                .target = target,
                .optimize = planned.optimize,
                .link_libc = false,
            });
            translated.mod.single_threaded = true;
            translated.mod.unwind_tables = .none;
            translated.mod.stack_protector = false;
            translated.mod.stack_check = false;
            translated.mod.red_zone = false;
            translated.mod.pic = planned.object.pic;
            translated.mod.omit_frame_pointer = planned.object.omit_frame_pointer;
            translated.mod.error_tracing = false;
            translated.mod.strip = if (options.strip) true else null;
            addTranslationIncludes(&translated, graph.global_includes, options.path_bindings);
            addTranslationIncludes(&translated, planned.object.includes, options.path_bindings);
            for (planned.object.c_macros) |macro| {
                translated.defineCMacro(macro.name, macro.value);
            }
            for (planned.object.dependencies) |dependency_path| {
                const binding = findBinding(options.path_bindings, dependency_path) orelse
                    return error.MissingDependencyBinding;
                translated.run.addFileInput(binding);
            }
            target_module.addImport(translation.import_name, translated.mod);
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
            .strip = if (options.strip) true else null,
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
        "#define CONFIG_ISSUE34_VALUE 34\n#define CONFIG_OPTIMIZE_PIE 1\n",
    );
    const fixture_source = b.root.joinString(
        b.allocator,
        "support/build/tests/target-zig-object/fixture.zig",
    ) catch @panic("OOM");
    const fixture_include = b.root.joinString(
        b.allocator,
        "support/build/tests/target-zig-object/include",
    ) catch @panic("OOM");
    const logical_header = "/fixture/generated/include/uk/bits/config.h";
    const logical_include = "/fixture/generated/include";
    const fixture_objects = [_]component.TargetZigObject{ .{
        .name = "fixture",
        .root_source_file = fixture_source,
        .output = "/fixture/fixture.o",
        .includes = &.{
            .{ .path = logical_include, .languages = &.{.zig} },
            .{ .path = fixture_include, .languages = &.{.zig} },
        },
        .dependencies = &.{logical_header},
        .c_translation = .{
            .headers = &.{ "uk/bits/config.h", "issue34-fixture.h" },
        },
        .c_macros = &.{.{ .name = "ISSUE34_OBJECT_VALUE", .value = "5" }},
    }, .{
        .name = "native-profile",
        .root_source_file = b.root.joinString(b.allocator, "support/build/target/native-profile.zig") catch @panic("OOM"),
        .output = "/fixture/native-profile.o",
        .includes = &.{.{ .path = logical_include, .languages = &.{.zig} }},
        .dependencies = &.{logical_header},
        .c_translation = .{ .headers = &.{"uk/bits/config.h"} },
    } };
    const library = b.allocator.create([1]component.Library) catch return error.OutOfMemory;
    const graph = testGraph(&fixture_objects, library);
    const compiled = try execute(b, graph, .{
        .optimize = .safe,
        .path_bindings = &.{.{
            .logical_path = logical_header,
            .lazy_path = config_header,
        }},
    });
    const stripped = try execute(b, graph, .{
        .optimize = .safe,
        .path_bindings = &.{.{
            .logical_path = logical_header,
            .lazy_path = config_header,
        }},
        .strip = true,
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
    const verify_stripped = b.addSystemCommand(&.{
        "python3",
        "support/build/tests/target-zig-object/verify.py",
        "--readelf",
        "llvm-readelf",
        "--nm",
        "llvm-nm",
        "--expect-stripped",
    });
    verify_stripped.addFileArg(stripped.outputs[0].lazy_path);
    verify.step.dependOn(&verify_stripped.step);
    if (b.graph.host.result.cpu.arch == .x86_64 and b.graph.host.result.os.tag == .linux) {
        const abi = b.addExecutable(.{
            .name = "issue34-target-zig-abi",
            .root_module = b.createModule(.{
                .target = b.graph.host,
                .optimize = .safe,
                .link_libc = true,
            }),
        });
        abi.root_module.addCSourceFile(.{
            .file = b.path("support/build/tests/target-zig-object/abi.c"),
            .flags = &.{"-std=c11"},
        });
        abi.root_module.addIncludePath(config_header.dirname().dirname().dirname());
        abi.root_module.addIncludePath(b.path("support/build/tests/target-zig-object/include"));
        abi.root_module.addCMacro("ISSUE34_OBJECT_VALUE", "5");
        abi.root_module.addObject(compiled.outputs[0].object);
        abi.root_module.addObject(compiled.outputs[1].object);
        verify.step.dependOn(&b.addRunArtifact(abi).step);
    }
    return &verify.step;
}

fn addTranslationIncludes(
    translated: anytype,
    includes: []const component.Include,
    bindings: []const PathBinding,
) void {
    for (includes) |include| {
        if (!includeApplies(include)) continue;
        const path = boundDirectory(include.path, bindings) orelse
            translated.mod.owner.graph.cwdRelativePath(include.path);
        switch (include.kind) {
            .normal => translated.addIncludePath(path),
            .system, .quote => translated.addSystemIncludePath(path),
        }
    }
}

fn addIncludes(
    module: *std.Build.Module,
    includes: []const component.Include,
    bindings: []const PathBinding,
) Error!void {
    for (includes) |include| {
        if (!includeApplies(include)) continue;
        const path = boundDirectory(include.path, bindings) orelse
            module.owner.graph.cwdRelativePath(include.path);
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

fn testGraph(
    objects: []const component.TargetZigObject,
    libraries: *[1]component.Library,
) component.FinalizedGraph {
    libraries.* = .{.{
        .name = "libfixture",
        .origin = .{ .internal = .library },
        .layout = .{ .ordinary = .{ .build_subdir = "libfixture" } },
        .target_zig_objects = objects,
    }};
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
        .libraries = libraries,
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
    var libraries: [1]component.Library = undefined;
    const graph = testGraph(&.{.{
        .name = "probe",
        .root_source_file = "/src/probe.zig",
        .output = "/build/probe.o",
        .optimize = .safe,
        .includes = &.{.{
            .path = "/build/include",
            .languages = &.{.zig},
        }},
        .dependencies = &.{"/build/include/uk/bits/config.h"},
        .c_translation = .{ .headers = &.{"uk/bits/config.h"} },
    }}, &libraries);
    const object_plan = try plan(std.testing.allocator, graph, .debug);
    defer object_plan.deinit();

    try std.testing.expectEqual(@as(usize, 1), object_plan.objects.len);
    try std.testing.expectEqual(std.lang.Optimize.safe, object_plan.objects[0].optimize);
    try std.testing.expectEqualStrings(
        "/build/include/uk/bits/config.h",
        object_plan.objects[0].object.dependencies[0],
    );
    try std.testing.expectEqualStrings(
        "uk/bits/config.h",
        object_plan.objects[0].object.c_translation.?.headers[0],
    );
}

test "planner rejects non-x86_64 freestanding target" {
    var libraries: [1]component.Library = undefined;
    var graph = testGraph(&.{.{
        .name = "probe",
        .root_source_file = "/src/probe.zig",
        .output = "/build/probe.o",
    }}, &libraries);
    graph.target.triple = "aarch64-freestanding-none";
    try std.testing.expectError(
        error.UnsupportedTarget,
        plan(std.testing.allocator, graph, .debug),
    );
}
