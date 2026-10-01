// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.createModule(.{ .root_source_file = b.path("../../tools/hyperv/core.zig"), .target = target, .optimize = optimize });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../../tools/hyperv/sha256_clear_upper.S"));
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("authority/tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    }) });
    const run = b.addRunArtifact(tests);
    const python = b.addSystemCommand(&.{ "python3", "-B" });
    python.addFileArg(b.path("tests/test_authority_contract_goldens.py"));
    const step = b.step("test", "Run native and Python authority contract goldens");
    step.dependOn(&run.step);
    step.dependOn(&python.step);
}
