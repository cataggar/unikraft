// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const core = b.createModule(.{
        .root_source_file = b.path("../../../tools/hyperv/core.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    if (b.graph.host.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../../../tools/hyperv/sha256_clear_upper.S"));
    const closure = b.createModule(.{
        .root_source_file = b.path("../../../controller_source_closure.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const controller = b.createModule(.{
        .root_source_file = b.path("../controller/root.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "controller_source_closure", .module = closure },
        },
    });
    const suite = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("differential_records.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "wamr_controller", .module = controller },
                .{ .name = "hyperv_core", .module = core },
            },
        }),
    });
    b.step("test", "Run frozen v1/v2 native parser goldens")
        .dependOn(&b.addRunArtifact(suite).step);
    const host = b.addExecutable(.{
        .name = "uk-wamr-native-ci-host-differential",
        .root_module = b.createModule(.{
            .root_source_file = b.path("../controller/main.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "wamr_controller", .module = controller }},
        }),
    });
    b.installArtifact(host);
}
