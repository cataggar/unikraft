const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.dependency("azure_sdk_core", .{ .target = target, .optimize = optimize });
    const storage = b.dependency("azure_sdk_storage_common", .{ .target = target, .optimize = optimize });
    const shared = b.createModule(.{
        .root_source_file = b.path("../core.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (target.result.cpu.arch == .x86_64)
        shared.addAssemblyFile(b.path("../sha256_clear_upper.S"));
    const module = b.addModule("hyperv_transfer", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = shared },
            .{ .name = "azure_sdk_core", .module = core.module("azure_sdk_core") },
            .{ .name = "azure_sdk_storage_common", .module = storage.module("azure_sdk_storage_common") },
        },
    });
    const library = b.addLibrary(.{ .name = "hyperv-transfer", .root_module = module, .linkage = .static });
    b.installArtifact(library);
    const tests = b.addTest(.{ .root_module = module });
    const run = b.addRunArtifact(tests);
    const fixture_root = b.option([]const u8, "fixture-root", "Explicit private /d directory for synthetic fixtures");
    const options = b.addOptions();
    options.addOption(?[]const u8, "test_root", fixture_root);
    module.addOptions("test_options", options);
    if (fixture_root) |path|
        run.setCwd(.{ .cwd_relative = path });
    b.step("test", "Run synthetic offline transfer fixtures").dependOn(&run.step);
}
