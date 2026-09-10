const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const sdk = b.dependency("azure_sdk_core", .{ .target = target, .optimize = optimize });
    const foundation = b.createModule(.{ .root_source_file = b.path("../root.zig"), .target = target, .optimize = optimize });
    const module = b.addModule("hyperv_azure", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "azure_sdk_core", .module = sdk.module("azure_sdk_core") },
            .{ .name = "hyperv_core", .module = foundation },
        },
    });
    b.installArtifact(b.addLibrary(.{ .name = "hyperv-azure", .root_module = module, .linkage = .static }));
    const tests = b.addTest(.{ .root_module = module });
    b.step("test", "Run offline native ARM/auth fixtures").dependOn(&b.addRunArtifact(tests).step);
}
