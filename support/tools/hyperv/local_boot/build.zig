const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = target, .optimize = optimize });
    const measurement = b.createModule(.{
        .root_source_file = b.path("../synthetic_measurement.zig"),
        .target = target,
        .optimize = optimize,
    });
    const diagnostics = b.createModule(.{
        .root_source_file = b.path("synthetic_diagnostics.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "synthetic_measurement", .module = measurement },
        },
    });
    const module = b.addModule("hyperv_local_boot", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    });
    const synthetic_module = b.createModule(.{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "synthetic_diagnostics", .module = diagnostics },
        },
    });
    const cli = b.addExecutable(.{
        .name = "uk-hyperv-local-boot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "local_boot", .module = module }},
        }),
    });
    b.installArtifact(cli);
    const fixture = b.addExecutable(.{
        .name = "local-boot-qemu-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("fixture.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "local_boot", .module = module }},
        }),
    });
    const diagnostic_cli = b.addExecutable(.{
        .name = "local-boot-cli-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("synthetic_cli.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "local_boot", .module = synthetic_module }},
        }),
    });
    const diagnostic_fixture = b.addExecutable(.{
        .name = "local-boot-qemu-diagnostic-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("synthetic_qemu.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "local_boot", .module = synthetic_module },
                .{ .name = "synthetic_diagnostics", .module = diagnostics },
            },
        }),
    });
    const options = b.addOptions();
    options.addOptionPath("cli", diagnostic_cli.getEmittedBin());
    options.addOptionPath("fixture", diagnostic_fixture.getEmittedBin());
    options.addOptionPath("production_cli", cli.getEmittedBin());
    options.addOptionPath("plain_fixture", fixture.getEmittedBin());
    options.addOption(?[]const u8, "test_root", b.option([]const u8, "test-root", "Existing absolute 0700 native fixture directory"));
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "local_boot", .module = synthetic_module },
            .{ .name = "synthetic_diagnostics", .module = diagnostics },
        },
    }) });
    tests.root_module.addOptions("test_options", options);
    b.step("test", "Run public synthetic local-boot fixtures, never a real guest").dependOn(&b.addRunArtifact(tests).step);
}
