const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency = b.dependency("preparation", .{ .target = target, .optimize = optimize });
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "preparation", .module = dependency.module("hyperv_preparation") },
    };
    const executable = b.addExecutable(.{
        .name = "uk-hyperv-prepare-integration",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .link_libc = false,
            .strip = optimize != .Debug,
            .imports = imports,
        }),
    });
    b.installArtifact(executable);
    b.installArtifact(dependency.artifact("preparation-namespace"));
    const tests = b.addTest(.{
        .filters = &.{"integration driver"},
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = imports,
        }),
    });
    const run = b.addRunArtifact(tests);
    run.setCwd(.{ .cwd_relative = b.cache_root.path.? });
    b.step("test", "Run non-executing integration argument/material fixtures").dependOn(&run.step);
}
