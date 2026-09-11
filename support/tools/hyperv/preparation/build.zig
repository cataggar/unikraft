const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const miz = b.dependency("miz_source", .{ .target = target, .optimize = optimize });
    const core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = target, .optimize = optimize });
    const elf = b.createModule(.{ .root_source_file = b.path("../../../build/postprocess-elf.zig"), .target = target, .optimize = optimize });
    const kconfig = b.createModule(.{ .root_source_file = b.path("../../../build/kconfig.zig"), .target = target, .optimize = optimize });
    const paths = b.createModule(.{ .root_source_file = b.path("../../../build/zig-facade-paths.zig"), .target = target, .optimize = optimize });
    const miz_module = b.createModule(.{ .root_source_file = miz.path("packages/miz/src/root.zig"), .target = target, .optimize = optimize });
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "hyperv_core", .module = core },
        .{ .name = "producer_elf", .module = elf },
        .{ .name = "native_kconfig", .module = kconfig },
        .{ .name = "facade_paths", .module = paths },
        .{ .name = "miz", .module = miz_module },
    };
    const module = b.addModule("hyperv_preparation", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    });
    const executable = b.addExecutable(.{
        .name = "uk-hyperv-prepare",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = optimize != .Debug,
            .imports = &.{.{ .name = "preparation", .module = module }},
        }),
    });
    b.installArtifact(executable);
    const helper = b.addExecutable(.{
        .name = "preparation-namespace",
        .root_module = b.createModule(.{
            .root_source_file = b.path("namespace_main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = optimize != .Debug,
            .single_threaded = true,
            .link_libc = false,
            .imports = imports,
        }),
    });
    b.installArtifact(helper);
    const fixture = b.addExecutable(.{
        .name = "preparation-process-fixture",
        .root_module = b.createModule(.{ .root_source_file = b.path("process_fixture.zig"), .target = target, .optimize = optimize }),
    });
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    }) });
    const options = b.addOptions();
    options.addOptionPath("process_fixture", fixture.getEmittedBin());
    options.addOptionPath("preparation_cli", executable.getEmittedBin());
    tests.root_module.addOptions("test_options", options);
    const run = b.addRunArtifact(tests);
    run.setCwd(.{ .cwd_relative = b.cache_root.path.? });
    b.step("test", "Run native synthetic preparation and provenance fixtures").dependOn(&run.step);
}
