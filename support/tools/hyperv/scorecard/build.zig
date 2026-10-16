// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const core = b.createModule(.{
        .root_source_file = b.path("../core.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../sha256_clear_upper.S"));

    const native_image_data = b.createModule(.{
        .root_source_file = b.path("../../../build/native-image-data.zig"),
        .target = target,
        .optimize = optimize,
    });

    const module = b.addModule("hyperv_scorecard", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "native_image_data", .module = native_image_data },
        },
    });

    const cli = b.addExecutable(.{
        .name = "uk-hyperv-scorecard",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "scorecard", .module = module }},
        }),
    });
    b.installArtifact(cli);

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "scorecard", .module = module }},
        }),
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run footprint and reproducible-build scorecard unit tests");
    test_step.dependOn(&run_tests.step);
}
