// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = target, .optimize = optimize });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../sha256_clear_upper.S"));
    const kconfig = b.createModule(.{ .root_source_file = b.path("../../../build/kconfig.zig"), .target = target, .optimize = optimize });
    const preparation = b.createModule(.{
        .root_source_file = b.path("../preparation/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "hyperv_core", .module = core }, .{ .name = "native_kconfig", .module = kconfig } },
    });
    const persistence = b.createModule(.{
        .root_source_file = b.path("../persistence/evidence.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    });
    const local_serial = b.createModule(.{
        .root_source_file = b.path("../local_boot/serial.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    });
    const wamr_validator = b.createModule(.{
        .root_source_file = b.path("../../../apps/wamr-aot/validator/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "local_boot_serial", .module = local_serial },
        },
    });
    const log_cli = b.addExecutable(.{ .name = "uk-wamr-log-validate", .root_module = b.createModule(.{
        .root_source_file = b.path("../../../apps/wamr-aot/validator/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "wamr_log_validator", .module = wamr_validator },
            .{ .name = "hyperv_core", .module = core },
        },
    }) });
    b.installArtifact(log_cli);
    const imports = [_]std.Build.Module.Import{
        .{ .name = "hyperv_core", .module = core },
        .{ .name = "preparation", .module = preparation },
        .{ .name = "evidence", .module = persistence },
        .{ .name = "local_serial", .module = local_serial },
        .{ .name = "wamr_log_validator", .module = wamr_validator },
    };
    const validator = b.addExecutable(.{
        .name = "uk-hyperv-direct-validate",
        .root_module = b.createModule(.{ .root_source_file = b.path("main.zig"), .target = target, .optimize = optimize, .imports = &imports }),
    });
    b.installArtifact(validator);
    const fixtures = b.addExecutable(.{
        .name = "hyperv-direct-validation-fixtures",
        .root_module = b.createModule(.{ .root_source_file = b.path("fixtures.zig"), .target = target, .optimize = optimize, .imports = &imports }),
    });
    const test_step = b.step("test", "Run native read-only direct validation fixtures (no cloud or disks)");
    test_step.dependOn(&b.addRunArtifact(fixtures).step);
    const compute_runtime_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("compute.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &imports,
    }) });
    const compute_runtime_run = b.addRunArtifact(compute_runtime_tests);
    b.step("test-compute-runtime", "Check current and frozen historical handoff runtime identities").dependOn(&compute_runtime_run.step);
    test_step.dependOn(&compute_runtime_run.step);
    const log_cli_tests = b.addSystemCommand(&.{ "python3", "-B" });
    log_cli_tests.addFileArg2(b.path("../../../apps/wamr-aot/validator/cli_test.py"), .{ .make_absolute = true });
    log_cli_tests.addFileArg2(log_cli.getEmittedBin(), .{ .make_absolute = true });
    test_step.dependOn(&log_cli_tests.step);

    const fixture_tools = b.step("fixture-tools", "Install isolated native lifecycle fixture tools (no controller)");
    const fake = b.addExecutable(.{
        .name = "hyperv-direct-fixture-cli",
        .root_module = b.createModule(.{ .root_source_file = b.path("fixture_cli.zig"), .target = target, .optimize = optimize, .strip = true, .imports = &imports }),
    });
    const lifecycle = b.addExecutable(.{
        .name = "hyperv-direct-lifecycle-fixtures",
        .root_module = b.createModule(.{ .root_source_file = b.path("lifecycle_fixtures.zig"), .target = target, .optimize = optimize, .imports = &imports }),
    });
    inline for (.{ fake, lifecycle }) |tool| {
        fixture_tools.dependOn(&b.addInstallArtifact(tool, .{}).step);
    }

    const test_options = b.addOptions();
    test_options.addOption(?[]const u8, "test_root", b.option([]const u8, "test-root", "Existing private absolute native fixture directory"));
    const foundation = b.step("test-foundation", "Run native direct observation, custody and runtime fixtures");
    inline for (.{ "observation", "custody" }) |name| {
        const tests = b.addTest(.{ .root_module = b.createModule(.{
            .root_source_file = b.path(name ++ "_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &imports,
        }) });
        tests.root_module.addOptions("test_options", test_options);
        const run = b.addRunArtifact(tests);
        b.step("test-" ++ name, "Run native direct " ++ name ++ " fixtures").dependOn(&run.step);
        foundation.dependOn(&run.step);
    }

    const runtime_fixture = b.addExecutable(.{
        .name = "hyperv-direct-runtime-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("runtime_fixture.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .imports = &.{.{ .name = "hyperv_core", .module = core }},
        }),
    });
    test_options.addOptionPath("runtime_fixture", runtime_fixture.getEmittedBin());
    const test_support = b.createModule(.{
        .root_source_file = b.path("../process_private_test_support.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    });
    test_support.addOptions("test_options", test_options);
    const transfer_job = b.createModule(.{
        .root_source_file = b.path("../transfer/job.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    });
    const runtime_imports = imports ++ [_]std.Build.Module.Import{
        .{ .name = "transfer_job", .module = transfer_job },
        .{ .name = "process_test_support", .module = test_support },
    };
    const compile = b.addObject(.{
        .name = "hyperv-direct-foundation-compile",
        .root_module = b.createModule(.{
            .root_source_file = b.path("foundation_compile.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &runtime_imports,
        }),
    });
    b.step("check-foundation", "Compile production direct foundation interfaces without running them").dependOn(&compile.step);
    foundation.dependOn(&compile.step);
    const runtime_tests = b.step("test-runtime", "Run private process and direct runtime fixtures");
    inline for (.{
        "../process_command_tests.zig",
        "../process_command_gate_tests.zig",
        "../process_command_gate_poison_tests.zig",
        "../process_command_post_release_fault_tests.zig",
        "../process_command_post_release_poison_tests.zig",
        "../process_private_tests.zig",
        "runtime_tests.zig",
        "../process_command_leader_track_fault_tests.zig",
        "../process_command_poison_tests.zig",
        "../process_command_parent_fault_tests.zig",
        "../process_command_signal_fault_tests.zig",
        "../process_private_poison_tests.zig",
        "../process_private_completion_poison_tests.zig",
    }) |source| {
        const tests = b.addTest(.{ .root_module = b.createModule(.{
            .root_source_file = b.path(source),
            .target = target,
            .optimize = optimize,
            .imports = &runtime_imports,
        }) });
        tests.root_module.addOptions("test_options", test_options);
        runtime_tests.dependOn(&b.addRunArtifact(tests).step);
    }
    foundation.dependOn(runtime_tests);

    const controller_imports = imports ++ [_]std.Build.Module.Import{
        .{ .name = "transfer_job", .module = transfer_job },
    };
    const controller = b.addExecutable(.{
        .name = "uk-hyperv-direct-two-boot",
        .root_module = controllerModule(b, "controller_main.zig", target, optimize, &controller_imports),
    });
    b.installArtifact(controller);
    const compute_validator = b.addExecutable(.{
        .name = "uk-wamr-direct-validate",
        .root_module = b.createModule(.{
            .root_source_file = b.path("compute_main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = optimize != .debug,
            .imports = &imports,
        }),
    });
    b.installArtifact(compute_validator);
    const compute_controller = b.addExecutable(.{
        .name = "uk-wamr-direct-compute",
        .root_module = controllerModule(b, "compute_controller_main.zig", target, optimize, &controller_imports),
    });
    b.installArtifact(compute_controller);
    const compute_fixture_tools = b.step("compute-fixture-tools", "Install explicitly isolated WAMR fake backend and controller (no cloud)");
    compute_fixture_tools.dependOn(&b.addInstallArtifact(runtime_fixture, .{}).step);
    inline for (.{
        .{ "wamr-direct-fixture-cli", "compute_fixture_cli.zig" },
        .{ "wamr-direct-controller-fixture", "compute_controller_fixture.zig" },
        .{ "wamr-direct-authorization-controller-fixture", "compute_authorization_controller_fixture.zig" },
    }) |entry| {
        const tool = b.addExecutable(.{
            .name = entry[0],
            .root_module = controllerModule(b, entry[1], target, optimize, &controller_imports),
        });
        compute_fixture_tools.dependOn(&b.addInstallArtifact(tool, .{}).step);
    }
    const controller_fixture = b.addExecutable(.{
        .name = "hyperv-direct-controller-fixture",
        .root_module = controllerModule(b, "controller_fixture_main.zig", target, optimize, &controller_imports),
    });
    controller_fixture.root_module.strip = true;
    const lifecycle_validator = b.addExecutable(.{
        .name = "uk-hyperv-direct-validate",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .imports = &imports,
        }),
    });
    const controller_tests = b.addTest(.{
        .root_module = controllerModule(b, "controller_tests.zig", target, optimize, &runtime_imports),
    });
    controller_tests.root_module.addOptions("test_options", test_options);
    b.step("test-controller", "Run native controller policy and private IO fixtures").dependOn(&b.addRunArtifact(controller_tests).step);

    const lifecycle_root = b.option([]const u8, "lifecycle-root", "Fresh nonexistent absolute native lifecycle fixture root");
    const lifecycle_cases = b.option([]const u8, "lifecycle-cases", "Comma-separated native lifecycle case selectors");
    const native_lifecycle = b.step("test-lifecycle-native", "Run the complete native lifecycle with isolated fake resources");
    if (lifecycle_root) |root| {
        if (!std.fs.path.isAbsolute(root)) {
            native_lifecycle.dependOn(&b.addFail("Lifecycle fixture root must be absolute").step);
        } else {
            const run = b.addRunArtifact(lifecycle);
            run.has_side_effects = true;
            run.addArgs(&.{ "--root", root });
            for ([_]*std.Build.Step.Compile{ controller_fixture, fake, lifecycle_validator }, [_][]const u8{ "--controller", "--fake", "--validator" }) |program, flag| {
                run.addArg(flag);
                run.addFileArg2(program.getEmittedBin(), .{ .make_absolute = true });
            }
            if (lifecycle_cases) |cases| run.addArgs(&.{ "--case", cases });
            native_lifecycle.dependOn(&run.step);
        }
    } else {
        native_lifecycle.dependOn(&b.addFail("test-lifecycle-native requires -Dlifecycle-root=FRESH_ABSOLUTE_PATH").step);
    }
}

fn controllerModule(
    b: *std.Build,
    source: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    imports: []const std.Build.Module.Import,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path(source),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    });
    module.addAnonymousImport("direct_arm_template", .{
        .root_source_file = b.path(if (std.mem.startsWith(u8, source, "compute_")) "../../../azure/wamr-direct-compute.json" else "../../../azure/hyperv-direct-two-boot.json"),
    });
    return module;
}
