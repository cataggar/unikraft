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
    const fixture = b.addExecutable(.{ .name = "wamr-normalization-reference-fixture", .root_module = b.createModule(.{
        .root_source_file = b.path("validator/reference_fixture.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "wamr_log_validator", .module = validator }},
    }) });
    const differential = b.addSystemCommand(&.{ "python3", "-B" });
    differential.addFileArg(b.path("validator/reference_test.py"));
    differential.addFileArg(fixture.getEmittedBin());
    const reference_tests = b.step("test-differential", "Compare normalization and base64 against retained Python references");
    reference_tests.dependOn(test_step);
    reference_tests.dependOn(&differential.step);
    const cli_differential = b.addSystemCommand(&.{ "python3", "-B" });
    cli_differential.addFileArg(b.path("validator/cli_test.py"));
    cli_differential.addFileArg(cli.getEmittedBin());
    cli_differential.addArg("--differential");
    reference_tests.dependOn(&cli_differential.step);
    const tiny_fixture = b.addExecutable(.{ .name = "wamr-tiny-reference-fixture", .root_module = b.createModule(.{
        .root_source_file = b.path("validator/tiny_reference_fixture.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "wamr_log_validator", .module = validator },
            .{ .name = "hyperv_core", .module = core },
        },
    }) });
    const tiny_differential = b.addSystemCommand(&.{ "python3", "-B" });
    tiny_differential.addFileArg(b.path("validator/tiny_reference_test.py"));
    tiny_differential.addFileArg(tiny_fixture.getEmittedBin());
    reference_tests.dependOn(&tiny_differential.step);
    const optional_fixture = b.addExecutable(.{ .name = "wamr-optional-reference-fixture", .root_module = b.createModule(.{
        .root_source_file = b.path("validator/optional_reference_fixture.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "wamr_log_validator", .module = validator }},
    }) });
    const optional_differential = b.addSystemCommand(&.{ "python3", "-B" });
    optional_differential.addFileArg(b.path("validator/optional_reference_test.py"));
    optional_differential.addFileArg(optional_fixture.getEmittedBin());
    reference_tests.dependOn(&optional_differential.step);
}
