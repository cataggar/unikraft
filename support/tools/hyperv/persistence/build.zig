const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_root = b.option([]const u8, "test-root", "Existing private absolute fixture directory");
    const sdk = b.dependency("azure_sdk_core", .{ .target = target, .optimize = optimize }).module("azure_sdk_core");
    const storage = b.dependency("azure_sdk_storage_common", .{ .target = target, .optimize = optimize }).module("azure_sdk_storage_common");
    const core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = target, .optimize = optimize });
    const azure = b.createModule(.{
        .root_source_file = b.path("../azure/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "azure_sdk_core", .module = sdk }, .{ .name = "hyperv_core", .module = core } },
    });
    const transfer = b.createModule(.{
        .root_source_file = b.path("../transfer/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "azure_sdk_core", .module = sdk },               .{ .name = "hyperv_core", .module = core },
            .{ .name = "azure_sdk_storage_common", .module = storage },
        },
    });
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "hyperv_core", .module = core },         .{ .name = "hyperv_azure", .module = azure },
        .{ .name = "hyperv_transfer", .module = transfer }, .{ .name = "azure_sdk_core", .module = sdk },
    };
    const module = b.addModule("hyperv_persistence", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    });
    const cli = b.addExecutable(.{
        .name = "uk-hyperv-persistence-engine",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{ .{ .name = "hyperv_persistence", .module = module }, .{ .name = "hyperv_core", .module = core } },
        }),
    });
    b.installArtifact(cli);
    const test_options = b.addOptions();
    test_options.addOption(?[]const u8, "test_root", test_root);
    test_options.addOptionPath("cli", cli.getEmittedBin());
    const worker_fixture = b.addExecutable(.{
        .name = "hyperv-persistence-worker-fixture",
        .root_module = b.createModule(.{ .root_source_file = b.path("worker_fixture.zig"), .target = target, .optimize = optimize, .imports = imports }),
    });
    test_options.addOptionPath("worker", worker_fixture.getEmittedBin());
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    }) });
    tests.root_module.addOptions("test_options", test_options);
    const run = b.addRunArtifact(tests);
    b.step("test", "Run offline persistence engine fixtures").dependOn(&run.step);
    const arm_tests = b.addTest(.{ .root_module = azure });
    b.step("test-arm", "Run the affected shared ARM fixtures").dependOn(&b.addRunArtifact(arm_tests).step);
    b.installArtifact(b.addLibrary(.{ .name = "hyperv-persistence", .root_module = module, .linkage = .static }));
}
