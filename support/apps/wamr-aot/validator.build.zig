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
    const serial = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/local_boot/serial.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    });
    const validator = b.addModule("wamr_log_validator", .{
        .root_source_file = b.path("validator/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "local_boot_serial", .module = serial },
        },
    });
    const cli = b.addExecutable(.{ .name = "uk-wamr-log-validate", .root_module = b.createModule(.{
        .root_source_file = b.path("validator/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "wamr_log_validator", .module = validator }},
    }) });
    b.installArtifact(cli);
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("validator/tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "wamr_log_validator", .module = validator },
            .{ .name = "hyperv_core", .module = core },
        },
    }) });
    tests.root_module.addCSourceFile(.{
        .file = b.path("tests/coremark-output.c"),
        .flags = &.{ "-std=c11", "-Wall", "-Wextra", "-Werror" },
    });
    tests.root_module.link_libc = true;
    const native_tests = b.addRunArtifact(tests);
    const production = b.addExecutable(.{ .name = "wamr-validator-compile-only", .root_module = b.createModule(.{
        .root_source_file = b.path("validator/production_compile.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "wamr_log_validator", .module = validator }},
    }) });
    const test_step = b.step("test", "Run native WAMR validator primitive tests");
    test_step.dependOn(&native_tests.step);
    test_step.dependOn(&production.step);
    const cli_tests = b.addSystemCommand(&.{ "python3", "-B" });
    cli_tests.addFileArg(b.path("validator/cli_test.py"));
    cli_tests.addFileArg(cli.getEmittedBin());
    test_step.dependOn(&cli_tests.step);
}
