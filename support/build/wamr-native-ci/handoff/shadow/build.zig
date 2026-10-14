// SPDX-License-Identifier: BSD-3-Clause
//! Dependency-free test witness; deliberately outside production installation.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.createModule(.{
        .root_source_file = b.path("../../../../tools/hyperv/core.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../../../../tools/hyperv/sha256_clear_upper.S"));
    const serial = b.createModule(.{
        .root_source_file = b.path("../../../../tools/hyperv/local_boot/serial.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    });
    const tiny = b.createModule(.{
        .root_source_file = b.path("../../../../apps/wamr-aot/validator/tiny.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "local_boot_serial", .module = serial },
        },
    });
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "hyperv_core", .module = core },
        .{ .name = "wamr_tiny_contract", .module = tiny },
    };
    const exe = b.addExecutable(.{
        .name = "wamr-handoff-shadow-compare",
        .root_module = b.createModule(.{
            .root_source_file = b.path("../shadow_main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = imports,
        }),
    });
    b.installArtifact(exe);
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("../shadow_compare.zig"),
            .target = target,
            .optimize = optimize,
            .imports = imports,
        }),
    });
    const native_run = b.addRunArtifact(tests);
    const python = b.addSystemCommand(&.{ "python3", "-B" });
    python.addFileArg(b.path("../../tests/test_handoff_shadow.py"));
    python.addArg("--comparator");
    python.addArtifactArg(exe);
    if (b.option([]const u8, "publication-cli", "Canonical path to the actual integrated publication CLI module")) |path| {
        if (!std.fs.path.isAbsolute(path)) @panic("-Dpublication-cli must be absolute");
        const publication_cli = b.createModule(.{
            .root_source_file = .{ .cwd_relative = path },
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "hyperv_core", .module = core }},
        });
        const parser = b.addExecutable(.{
            .name = "wamr-handoff-shadow-parse",
            .root_module = b.createModule(.{
                .root_source_file = b.path("../shadow_cli_main.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "publication_cli", .module = publication_cli }},
            }),
        });
        python.addArg("--publication-parser");
        python.addArtifactArg(parser);
    }
    python.addArg("--scratch");
    const scratch = b.option([]const u8, "test-root", "Existing external owner-private scratch root") orelse @panic("-Dtest-root is required");
    if (!std.fs.path.isAbsolute(scratch)) @panic("-Dtest-root must be absolute");
    python.addArg(scratch);
    const step = b.step("test-shadow", "Run synthetic comparator and bounded-driver refusal tests (not live parity)");
    step.dependOn(&native_run.step);
    step.dependOn(&python.step);
}
