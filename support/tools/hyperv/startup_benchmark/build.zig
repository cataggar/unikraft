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

    const module = b.addModule("hyperv_startup_benchmark", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    });

    const cli = b.addExecutable(.{
        .name = "uk-hyperv-startup-benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "startup_benchmark", .module = module }},
        }),
    });
    b.installArtifact(cli);

    const linux_server = b.addExecutable(.{
        .name = "startup-test-http-server",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    linux_server.root_module.addCSourceFiles(.{
        .files = &.{
            "../http_benchmark/linux_http_server.c",
            "../../../apps/hyperv-acceptance/http_protocol.c",
        },
        .flags = &.{ "-std=c11", "-Wall", "-Wextra", "-Werror" },
    });

    const options = b.addOptions();
    options.addOptionPath("http_server", linux_server.getEmittedBin());

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "startup_benchmark", .module = module }},
        }),
    });
    tests.root_module.addOptions("test_options", options);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run Azure start-to-service and guest boot timing unit tests");
    test_step.dependOn(&run_tests.step);
}
