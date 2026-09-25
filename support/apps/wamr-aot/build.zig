// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const core = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/core.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../../tools/hyperv/sha256_clear_upper.S"));
    const native_make_environment = b.createModule(.{
        .root_source_file = b.path("../../build/native-make-environment-contract.zig"),
        .target = target,
        .optimize = optimize,
    });
    const facade_paths = b.createModule(.{
        .root_source_file = b.path("../../build/zig-facade-paths.zig"),
        .target = target,
        .optimize = optimize,
    });
    const preparation_files = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/preparation/files.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "facade_paths", .module = facade_paths },
        },
    });
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "hyperv_core", .module = core },
        .{ .name = "facade_paths", .module = facade_paths },
        .{ .name = "preparation_files", .module = preparation_files },
        .{ .name = "native_make_environment", .module = native_make_environment },
    };
    const module = b.addModule("wamr_aot_build", .{
        .root_source_file = b.path("build-tool-contract.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    });
    const executable = b.addExecutable(.{
        .name = "uk-wamr-aot-build",
        .root_module = b.createModule(.{
            .root_source_file = b.path("build-tool-main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = optimize != .Debug,
            .imports = &.{.{ .name = "wamr_aot_build", .module = module }},
        }),
    });
    b.installArtifact(executable);

    const process_fixture = b.addExecutable(.{
        .name = "wamr-aot-build-process-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/build_tool_process_fixture.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const prepare_fixture = b.addExecutable(.{
        .name = "wamr-aot-build-prepare-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/build_tool_prepare_fixture.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const image_fixture = b.addExecutable(.{
        .name = "wamr-aot-build-image-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/build_tool_image_fixture.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const options = b.addOptions();
    options.addOptionPath("cli", executable.getEmittedBin());
    options.addOptionPath("process_fixture", process_fixture.getEmittedBin());
    options.addOptionPath("prepare_fixture", prepare_fixture.getEmittedBin());
    options.addOptionPath("image_fixture", image_fixture.getEmittedBin());
    options.addOption(
        []const u8,
        "zig_lib_dir",
        b.graph.zig_lib_directory.path.?,
    );
    options.addOption([]const u8, "git_executable", b.findProgram(&.{"git"}, &.{}) catch
        @panic("native Git archive fixture requires Git"));
    options.addOption(
        []const u8,
        "repository_root",
        std.fs.path.resolve(
            b.allocator,
            &.{ b.build_root.path.?, "../../.." },
        ) catch @panic("cannot resolve repository root"),
    );

    const unit_tests = b.addTest(.{
        .filters = b.option(
            []const []const u8,
            "test-filter",
            "Run matching native WAMR build foundation tests; repeat to select groups",
        ) orelse &.{},
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/build_tool_tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "wamr_aot_build", .module = module },
                .{ .name = "hyperv_core", .module = core },
            },
        }),
    });
    unit_tests.root_module.link_libc = true;
    unit_tests.root_module.addCSourceFile(.{
        .file = b.path("tests/workload-mode.c"),
        .flags = &.{ "-std=c11", "-Wall", "-Wextra", "-Werror" },
    });
    unit_tests.root_module.addOptions("test_options", options);
    const unit_run = b.addRunArtifact(unit_tests);
    const test_cwd = if (std.mem.eql(u8, b.build_root.path.?, "."))
        "."
    else
        b.pathFromRoot("../../..");
    unit_run.setCwd(.{ .cwd_relative = test_cwd });
    const unit_step = b.step("test-unit", "Run native WAMR build helper unit and fault fixtures");
    unit_step.dependOn(&unit_run.step);

    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/build_tool_integration.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "wamr_aot_build", .module = module }},
        }),
    });
    integration_tests.root_module.addOptions("test_options", options);
    const integration_run = b.addRunArtifact(integration_tests);
    integration_run.setCwd(.{ .cwd_relative = test_cwd });
    const integration_step = b.step("test-integration", "Run native WAMR build executable and supervisor fixtures");
    integration_step.dependOn(&integration_run.step);

    const all = b.step("test", "Run native WAMR producer golden, fault, and integration tests");
    all.dependOn(unit_step);
    all.dependOn(integration_step);
}
