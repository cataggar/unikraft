// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const foundation = @import("authority.build.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.createModule(.{ .root_source_file = b.path("../../tools/hyperv/core.zig"), .target = target, .optimize = optimize });
    if (target.result.cpu.arch == .x86_64) core.addAssemblyFile(b.path("../../tools/hyperv/sha256_clear_upper.S"));
    const serial = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/local_boot/serial.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    });
    const validator = b.createModule(.{
        .root_source_file = b.path("../../apps/wamr-aot/validator/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "hyperv_core", .module = core }, .{ .name = "local_boot_serial", .module = serial } },
    });
    const direct = b.addExecutable(.{
        .name = "authority-plan-direct-validator",
        .root_module = b.createModule(.{
            .root_source_file = b.path("../../tools/hyperv/direct/compute_main.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
            .imports = &.{
                .{ .name = "hyperv_core", .module = core },
                .{ .name = "local_serial", .module = serial },
                .{ .name = "wamr_log_validator", .module = validator },
            },
        }),
    });
    const writer = b.addExecutable(.{
        .name = "authority-plan-validator-identity",
        .root_module = b.createModule(.{ .root_source_file = b.path("build.zig"), .target = b.graph.host, .optimize = .ReleaseSafe }),
    });
    const identity_run = b.addRunArtifact(writer);
    identity_run.addFileArg(direct.getEmittedBin());
    const identity = b.createModule(.{
        .root_source_file = b.addWriteFiles().addCopyFile(identity_run.captureStdOut(.{}), "plan-validator-identity.zig"),
        .target = target,
        .optimize = optimize,
    });
    const controller = b.createModule(.{
        .root_source_file = b.path("controller/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "wamr_log_validator", .module = validator },
            .{ .name = "import_validator_identity", .module = identity },
            .{ .name = "controller_source_closure", .module = b.createModule(.{
                .root_source_file = b.path("../../controller_source_closure.zig"),
                .target = target,
                .optimize = optimize,
            }) },
            .{ .name = "handoff_contracts", .module = b.createModule(.{
                .root_source_file = b.path("handoff/contracts.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "hyperv_core", .module = core }},
            }) },
        },
    });
    const handoff = b.createModule(.{
        .root_source_file = b.path("handoff/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "hyperv_core", .module = core }, .{ .name = "wamr_controller", .module = controller } },
    });
    const fixture_root = b.option([]const u8, "test-root", "Existing private absolute plan fixture root") orelse @panic("-Dtest-root is required");
    const options = foundation.testOptions(b, target, optimize, fixture_root);
    const options_module = options.createModule();
    handoff.addImport("test_options", options_module);
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("authority/plan_tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "test_options", .module = options_module }, .{ .name = "wamr_controller", .module = controller } },
    }) });
    foundation.addImports(b, tests.root_module, target, optimize, core, serial, validator, handoff);
    const object = b.addObject(.{
        .name = "authority-plan-source-check",
        .root_module = b.createModule(.{ .root_source_file = b.path("authority/plan_source_check.zig"), .target = target, .optimize = optimize }),
    });
    foundation.addImports(b, object.root_module, target, optimize, core, serial, validator, handoff);
    const run = b.addRunArtifact(tests);
    const step = b.step("test", "Run plan library refusals, constructors, transactions and non-test source object");
    step.dependOn(&run.step);
    step.dependOn(&object.step);
}
