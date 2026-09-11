// Standalone focused fixtures; no root build or dependency resolution.
const std = @import("std");

pub fn build(b: *std.Build) void {
    b.cache_root.path = b.cache_root.handle.realPathFileAlloc(b.graph.io, ".", b.allocator) catch
        @panic("cannot canonicalize the selected fixture cache");
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const workspace = b.option([]const u8, "workspace", "Explicit resume-producer validation subtree") orelse
        @panic("-Dworkspace is required");
    const core = b.createModule(.{ .root_source_file = b.path("../../core.zig"), .target = target, .optimize = optimize });
    const elf = b.createModule(.{ .root_source_file = b.path("../../../../build/postprocess-elf.zig"), .target = target, .optimize = optimize });
    const paths = b.createModule(.{ .root_source_file = b.path("../../../../build/zig-facade-paths.zig"), .target = target, .optimize = optimize });
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "hyperv_core", .module = core },
        .{ .name = "producer_elf", .module = elf },
        .{ .name = "facade_paths", .module = paths },
    };
    const helper = b.addExecutable(.{
        .name = "preparation-namespace",
        .root_module = b.createModule(.{
            .root_source_file = b.path("../namespace_main.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = imports,
        }),
    });
    b.installArtifact(helper);
    const options = b.addOptions();
    options.addOption([]const u8, "workspace", workspace);
    const fixture = b.addExecutable(.{
        .name = "preparation-namespace-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("../namespace_tests.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = imports,
        }),
    });
    fixture.root_module.addOptions("fixture_options", options);
    b.installArtifact(fixture);
    const child = b.addExecutable(.{
        .name = "preparation-process-fixture",
        .root_module = b.createModule(.{ .root_source_file = b.path("../process_fixture.zig"), .target = target, .optimize = optimize }),
    });
    const test_options = b.addOptions();
    test_options.addOptionPath("namespace_helper", helper.getEmittedBin());
    test_options.addOptionPath("namespace_fixture", fixture.getEmittedBin());
    test_options.addOptionPath("process_fixture", child.getEmittedBin());
    const tests = b.addTest(.{
        .filters = &.{ "namespace", "producer exact", "producer rejects", "producer vetoes", "producer native proof", "producer outcome" },
        .root_module = b.createModule(.{
            .root_source_file = b.path("../namespace_tests.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = imports,
        }),
    });
    tests.root_module.addOptions("fixture_options", options);
    tests.root_module.addOptions("test_options", test_options);
    const run = b.addRunArtifact(tests);
    run.setCwd(.{ .cwd_relative = workspace });
    b.step("test", "Run small native namespace and typed producer fixtures").dependOn(&run.step);
}
