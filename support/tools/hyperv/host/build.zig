const std = @import("std");

fn module(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const sdk = b.dependency("azure_sdk_core", .{ .target = target, .optimize = optimize });
    const host = b.createModule(.{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = b.createModule(.{
                .root_source_file = b.path("../core.zig"),
                .target = target,
                .optimize = optimize,
            }) },
            .{ .name = "azure_sdk_core", .module = sdk.module("azure_sdk_core") },
        },
    });
    configureHost(b, host, null);
    return host;
}

fn configureHost(b: *std.Build, host: *std.Build.Module, timing: ?*std.Build.Module) void {
    const options = b.addOptions();
    options.addOption(bool, "timing", timing != null);
    host.addOptions("host_options", options);
    if (timing) |observer| host.addImport("host_timing", observer);
}

fn child(b: *std.Build, optimize: std.builtin.OptimizeMode, native: *std.Build.Module, timing: ?*std.Build.Module, success: bool) *std.Build.Step.Compile {
    const fixture = b.addExecutable(.{
        .name = if (success) "host-wire-success-fixture" else "host-child-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("child_fixture.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "host", .module = native }},
        }),
    });
    const options = b.addOptions();
    options.addOption(bool, "timing", timing != null);
    options.addOption(bool, "wire_success", success);
    fixture.root_module.addOptions("fixture_options", options);
    if (timing) |observer| fixture.root_module.addImport("host_timing", observer);
    return fixture;
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

    const timing_enabled = b.option(bool, "host-timing", "Enable bounded synthetic host observations (never production)") orelse false;
    const native = module(b, b.graph.host, optimize);
    const timing = if (timing_enabled) b.createModule(.{
        .root_source_file = b.path("fixture_timing.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = native.import_table.get("hyperv_core").? },
            .{ .name = "synthetic_measurement", .module = b.createModule(.{ .root_source_file = b.path("../synthetic_measurement.zig"), .target = b.graph.host, .optimize = optimize }) },
        },
    }) else null;
    configureHost(b, native, timing);
    const fixture = child(b, optimize, native, timing, false);
    const test_options = b.addOptions();
    test_options.addOption(bool, "host_timing", timing_enabled);
    test_options.addOption(?[]const u8, "test_root", b.option([]const u8, "test-root", "Existing absolute 0700 fixture directory"));
    test_options.addOptionPath("child_fixture", fixture.getEmittedBin());
    if (timing_enabled) test_options.addOptionPath("wire_success_fixture", child(b, optimize, native, timing, true).getEmittedBin());
    const tests = b.addTest(.{
        .filters = if (b.option([]const u8, "test-filter", "Run only matching native fixture names")) |filter| &.{filter} else &.{},
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "host", .module = native }},
        }),
    });
    tests.root_module.addOptions("test_options", test_options);
    if (timing) |observer| tests.root_module.addImport("host_timing", observer);
    tests.root_module.addImport("azure_sdk_core", b.dependency("azure_sdk_core", .{ .target = b.graph.host, .optimize = optimize }).module("azure_sdk_core"));
    const run = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run offline signed-protocol, wire and supervised boot fixtures");
    test_step.dependOn(&run.step);
    if (timing_enabled) {
        const observations = b.addTest(.{
            .filters = &.{ "host timing", "native wire child hard deadline" },
            .root_module = tests.root_module,
        });
        b.step("test-observations", "Run bounded native host observation and original deadline fixtures").dependOn(&b.addRunArtifact(observations).step);
    }

    // Independent default-root compilation: neither observer nor measurement
    // exists in this import graph, even when the fixture option is enabled.
    const exclusion = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("timing_exclusion_tests.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "host", .module = module(b, b.graph.host, optimize) }},
    }) });
    const exclude_run = b.addRunArtifact(exclusion);
    b.step("test-exclusion", "Compile and exercise production host without observer dependencies").dependOn(&exclude_run.step);
    test_step.dependOn(&exclude_run.step);
}
