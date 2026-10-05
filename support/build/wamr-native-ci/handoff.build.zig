// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/core.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../../tools/hyperv/sha256_clear_upper.S"));
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
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "local_boot_serial", .module = serial },
        },
    });
    const source_closure = b.createModule(.{
        .root_source_file = b.path("../../controller_source_closure.zig"),
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
            .{ .name = "controller_source_closure", .module = source_closure },
        },
    });
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("handoff/tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "hyperv_core", .module = core },
                .{ .name = "wamr_controller", .module = controller },
            },
        }),
    });
    const options = b.addOptions();
    options.addOptionPath("fixture_root", .cache_root);
    options.addOptionPath("python_oracle", b.path("tests/test_handoff_contract_goldens.py"));
    options.addOptionPath("accepted_result_fixture", b.path("tests/fixtures/differential/accepted-v2.json"));
    tests.root_module.addOptions("test_options", options);
    const run = b.addRunArtifact(tests);
    const python = b.addSystemCommand(&.{"env"});
    python.addPrefixedDirectoryArg("WAMR_HANDOFF_GOLDEN_ROOT=", .cache_root);
    python.addArgs(&.{ "python3", "-B" });
    python.addFileArg(b.path("tests/test_handoff_contract_goldens.py"));
    const step = b.step("test", "Run native and Python handoff contract goldens");
    step.dependOn(&run.step);
    step.dependOn(&python.step);
}
