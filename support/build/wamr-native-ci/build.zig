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
    const supervisor_fixture = b.addExecutable(.{
        .name = "wamr-ci-supervisor-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("../../tools/hyperv/direct/runtime_fixture.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "hyperv_core", .module = core }},
        }),
    });
    b.installArtifact(supervisor_fixture);

    const image = b.dependency("public_image", .{ .target = target, .optimize = optimize }).module("hyperv_public_image");
    const root = b.createModule(.{
        .root_source_file = b.path("package.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "public_image", .module = image }},
    });
    const cli = b.addExecutable(.{ .name = "wamr-ci-package", .root_module = root });
    b.installArtifact(cli);
    const tests = b.addTest(.{ .root_module = root });
    const unit_tests = b.addRunArtifact(tests);
    const unit_step = b.step("test-unit", "Test the compute packaging adapter command boundary");
    unit_step.dependOn(&unit_tests.step);
    const options = b.addOptions();
    options.addOptionPath("cli", cli.getEmittedBin());
    options.addOption(
        ?[]const u8,
        "test_root",
        b.option([]const u8, "test-root", "Existing absolute private compute fixture directory"),
    );
    const pipeline_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("pipeline_tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "public_image", .module = image }},
    }) });
    pipeline_tests.root_module.addOptions("test_options", options);
    const pipeline_run = b.addRunArtifact(pipeline_tests);
    const pipeline_step = b.step("test-pipeline", "Run the real private raw-to-QCOW2-to-VHD pipeline fixtures");
    pipeline_step.dependOn(&pipeline_run.step);
    const test_step = b.step("test", "Run unit and required private compute pipeline fixtures");
    test_step.dependOn(&unit_tests.step);
    test_step.dependOn(&pipeline_run.step);
}
