const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const fixture_optimize = b.option(std.builtin.OptimizeMode, "fixture-optimize", "Native synthetic child optimization (default: ReleaseSafe)") orelse .ReleaseSafe;
    const module = addModule(b, target, optimize, "hyperv_operator_guard");
    const executable = b.addExecutable(.{ .name = "uk-hyperv-operator-guard", .root_module = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "operator_guard", .module = module }},
    }) });
    b.installArtifact(executable);
    const cross = b.addExecutable(.{ .name = "operator-guard-target-fixture", .root_module = b.createModule(.{
        .root_source_file = b.path("fixture.zig"),
        .target = target,
        .optimize = optimize,
        .strip = true,
        .imports = &.{.{ .name = "operator_guard", .module = addModule(b, target, optimize, null) }},
    }) });
    b.step("compile-guard", "Build the complete bound guard fixture for the selected Linux target").dependOn(&b.addInstallArtifact(cross, .{}).step);
    const fixture = b.addExecutable(.{ .name = "operator-guard-fixture", .root_module = b.createModule(.{
        .root_source_file = b.path("fixture.zig"),
        .target = b.graph.host,
        .optimize = fixture_optimize,
        .strip = true,
        .imports = &.{.{ .name = "operator_guard", .module = addModule(b, b.graph.host, fixture_optimize, null) }},
    }) });
    b.step("install-fixture", "Install only the native synthetic custody fixture").dependOn(&b.addInstallArtifact(fixture, .{}).step);
    const options = b.addOptions();
    if (b.option([]const u8, "fixture-executable", "Existing absolute synthetic fixture executable for profile-scoped CI")) |path| {
        if (!std.fs.path.isAbsolute(path)) @panic("fixture-executable must be absolute");
        options.addOption([]const u8, "fixture", path);
    } else {
        options.addOptionPath("fixture", fixture.getEmittedBin());
    }
    options.addOption(?[]const u8, "test_root", b.option([]const u8, "test-root", "Existing private absolute native fixture directory"));
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "operator_guard", .module = addModule(b, b.graph.host, optimize, null) }},
    }), .filters = if (b.option([]const u8, "test-filter", "Native fixture filter")) |filter| &.{filter} else &.{} });
    tests.root_module.addOptions("test_options", options);
    b.step("test", "Run native kernel custody and sealed recovery fixtures").dependOn(&b.addRunArtifact(tests).step);
}

fn addModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, name: ?[]const u8) *std.Build.Module {
    const core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = target, .optimize = optimize });
    const options: std.Build.Module.CreateOptions = .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    };
    return if (name) |public_name| b.addModule(public_name, options) else b.createModule(options);
}
