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
    const imports = [_]std.Build.Module.Import{
        .{ .name = "hyperv_core", .module = core },
        .{ .name = "preparation", .module = preparation },
        .{ .name = "evidence", .module = persistence },
        .{ .name = "local_serial", .module = b.createModule(.{
            .root_source_file = b.path("../local_boot/serial.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "hyperv_core", .module = core }},
        }) },
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
    b.step("test", "Run native read-only direct validation fixtures (no cloud or disks)").dependOn(&b.addRunArtifact(fixtures).step);

    const fixture_tools = b.step("fixture-tools", "Install isolated native lifecycle fixture tools (no controller)");
    const fake = b.addExecutable(.{
        .name = "hyperv-direct-fixture-cli",
        .root_module = b.createModule(.{ .root_source_file = b.path("fixture_cli.zig"), .target = target, .optimize = optimize, .imports = &imports }),
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
        "../process_private_tests.zig",
        "runtime_tests.zig",
        "../process_command_poison_tests.zig",
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
        .root_module = b.createModule(.{ .root_source_file = b.path("compute_main.zig"), .target = target, .optimize = optimize, .imports = &imports }),
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
            NativeLifecycleArgs.add(b, run, .{ controller_fixture, fake, validator });
            if (lifecycle_cases) |cases| run.addArgs(&.{ "--case", cases });
            native_lifecycle.dependOn(&run.step);
        }
    } else {
        native_lifecycle.dependOn(&b.addFail("test-lifecycle-native requires -Dlifecycle-root=FRESH_ABSOLUTE_PATH").step);
    }
}

const NativeLifecycleArgs = struct {
    step: std.Build.Step,
    run: *std.Build.Step.Run,
    programs: [3]*std.Build.Step.Compile,

    fn add(b: *std.Build, run: *std.Build.Step.Run, programs: [3]*std.Build.Step.Compile) void {
        const args = b.allocator.create(NativeLifecycleArgs) catch @panic("OOM");
        args.* = .{
            .step = std.Build.Step.init(.{
                .id = .custom,
                .name = "Resolve absolute native fixture program paths",
                .owner = b,
                .makeFn = make,
            }),
            .run = run,
            .programs = programs,
        };
        for (programs) |program| program.getEmittedBin().addStepDependencies(&args.step);
        run.step.dependOn(&args.step);
    }

    fn make(step: *std.Build.Step, _: std.Build.Step.MakeOptions) !void {
        const args: *NativeLifecycleArgs = @fieldParentPtr("step", step);
        const b = step.owner;
        // Run.addFileArg intentionally relativizes paths; the fixture CLI requires absolute inputs.
        for (args.programs, [_][]const u8{ "--controller", "--fake", "--validator" }) |program, flag| {
            const path = try program.getEmittedBin().getPath4(b, step);
            args.run.addArgs(&.{ flag, b.pathResolve(&.{ b.graph.cache.cwd, path.root_dir.path orelse ".", path.sub_path }) });
        }
    }
};

fn controllerModule(
    b: *std.Build,
    source: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
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
