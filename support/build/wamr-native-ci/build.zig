const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const image = b.dependency("public_image", .{ .target = target, .optimize = optimize }).module("hyperv_public_image");
    const root = b.createModule(.{
        .root_source_file = b.path("package.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "public_image", .module = image }},
    });
    b.installArtifact(b.addExecutable(.{ .name = "wamr-ci-package", .root_module = root }));
    const tests = b.addTest(.{ .root_module = root });
    b.step("test", "Test the compute packaging adapter command boundary").dependOn(&b.addRunArtifact(tests).step);
}
