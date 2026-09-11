const std = @import("std");

fn module(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = target, .optimize = optimize });
    const sdk = b.dependency("azure_sdk_core", .{ .target = target, .optimize = optimize }).module("azure_sdk_core");
    const storage = b.dependency("azure_sdk_storage_common", .{ .target = target, .optimize = optimize }).module("azure_sdk_storage_common");
    const shared: []const std.Build.Module.Import = &.{
        std.Build.Module.Import{ .name = "hyperv_core", .module = core },
        .{ .name = "azure_sdk_core", .module = sdk },
    };
    const azure = b.createModule(.{ .root_source_file = b.path("../azure/root.zig"), .target = target, .optimize = optimize, .imports = shared });
    const host = b.createModule(.{ .root_source_file = b.path("../host/root.zig"), .target = target, .optimize = optimize, .imports = shared });
    const transfer = b.createModule(.{ .root_source_file = b.path("../transfer/root.zig"), .target = target, .optimize = optimize, .imports = &.{
        .{ .name = "hyperv_core", .module = core },                 .{ .name = "azure_sdk_core", .module = sdk },
        .{ .name = "azure_sdk_storage_common", .module = storage },
    } });
    return b.createModule(.{ .root_source_file = b.path("root.zig"), .target = target, .optimize = optimize, .imports = &.{
        .{ .name = "hyperv_core", .module = core },   .{ .name = "hyperv_azure", .module = azure },
        .{ .name = "hyperv_host", .module = host },   .{ .name = "hyperv_transfer", .module = transfer },
        .{ .name = "azure_sdk_core", .module = sdk },
    } });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const engine = module(b, target, optimize);
    b.modules.put(b.allocator, b.dupe("hyperv_preflight"), engine) catch @panic("out of memory");
    const cli = b.addExecutable(.{ .name = "uk-hyperv-preflight-worker", .root_module = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = optimize != .Debug,
        .imports = &.{.{ .name = "preflight", .module = engine }},
    }) });
    b.installArtifact(cli);
    const native = module(b, b.graph.host, optimize);
    const fixture = b.addExecutable(.{ .name = "preflight-child-fixture", .root_module = b.createModule(.{
        .root_source_file = b.path("fixture_main.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "preflight", .module = native }},
    }) });
    const native_cli = b.addExecutable(.{ .name = "preflight-cli-fixture", .root_module = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "preflight", .module = native }},
    }) });
    const options = b.addOptions();
    options.addOption(?[]const u8, "test_root", b.option([]const u8, "test-root", "Existing absolute private fixture root"));
    options.addOptionPath("child", fixture.getEmittedBin());
    options.addOptionPath("cli", native_cli.getEmittedBin());
    const tests = b.addTest(.{ .filters = if (b.option([]const u8, "test-filter", "Native fixture filter")) |filter| &.{filter} else &.{}, .root_module = b.createModule(.{
        .root_source_file = b.path("tests.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "preflight", .module = native }},
    }) });
    tests.root_module.addOptions("test_options", options);
    b.step("test", "Run offline preflight engine, adapter and supervised child fixtures").dependOn(&b.addRunArtifact(tests).step);
}
