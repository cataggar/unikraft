const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = target, .optimize = optimize });
    const module = b.addModule("hyperv_local_boot", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    });
    const cli = b.addExecutable(.{
        .name = "uk-hyperv-local-boot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "local_boot", .module = module }},
        }),
    });
    b.installArtifact(cli);
    const fixture = b.addExecutable(.{
        .name = "local-boot-qemu-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("fixture.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "local_boot", .module = module }},
        }),
    });
    const options = b.addOptions();
    options.addOptionPath("cli", cli.getEmittedBin());
    options.addOptionPath("fixture", fixture.getEmittedBin());
    options.addOption(?[]const u8, "test_root", b.option([]const u8, "test-root", "Existing absolute 0700 native fixture directory"));
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "local_boot", .module = module }},
    }) });
    tests.root_module.addOptions("test_options", options);
    b.step("test", "Run public synthetic local-boot fixtures, never a real guest").dependOn(&b.addRunArtifact(tests).step);
}
