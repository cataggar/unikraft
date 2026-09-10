const std = @import("std");

fn module(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const sdk = b.dependency("azure_sdk_core", .{ .target = target, .optimize = optimize });
    return b.createModule(.{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = b.createModule(.{
                .root_source_file = b.path("../root.zig"),
                .target = target,
                .optimize = optimize,
            }) },
            .{ .name = "azure_sdk_core", .module = sdk.module("azure_sdk_core") },
        },
    });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const host = module(b, target, optimize);
    b.modules.put(b.allocator, b.dupe("hyperv_host"), host) catch @panic("OOM");
    const options = b.addOptions();
    options.addOption(?[]const u8, "image_trust_key", b.option([]const u8, "image-trust-key", "Image-build Ed25519 public key (64 lowercase hex); never a runtime option"));
    const exe = b.addExecutable(.{
        .name = "uk-hyperv-host",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = optimize != .Debug,
            .imports = &.{.{ .name = "host", .module = host }},
        }),
    });
    exe.root_module.addOptions("image_options", options);
    b.installArtifact(exe);
    b.installFile("uk-hyperv-host.service", "share/uk-hyperv-host/uk-hyperv-host.service");

    const fixture = b.addExecutable(.{
        .name = "host-child-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("child_fixture.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "host", .module = module(b, b.graph.host, optimize) }},
        }),
    });
    const test_options = b.addOptions();
    test_options.addOption(?[]const u8, "test_root", b.option([]const u8, "test-root", "Existing absolute 0700 fixture directory"));
    test_options.addOptionPath("child_fixture", fixture.getEmittedBin());
    const tests = b.addTest(.{
        .filters = if (b.option([]const u8, "test-filter", "Run only matching native fixture names")) |filter| &.{filter} else &.{},
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "host", .module = module(b, b.graph.host, optimize) }},
        }),
    });
    tests.root_module.addOptions("test_options", test_options);
    tests.root_module.addImport("azure_sdk_core", b.dependency("azure_sdk_core", .{ .target = b.graph.host, .optimize = optimize }).module("azure_sdk_core"));
    const run = b.addRunArtifact(tests);
    b.step("test", "Run offline signed-protocol, wire and supervised boot fixtures").dependOn(&run.step);
}
