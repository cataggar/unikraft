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
    const log_validator = b.createModule(.{
        .root_source_file = b.path("../../apps/wamr-aot/validator/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "local_boot_serial", .module = serial },
        },
    });
    const log_cli = b.addExecutable(.{ .name = "uk-wamr-log-validate", .root_module = b.createModule(.{
        .root_source_file = b.path("../../apps/wamr-aot/validator/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "wamr_log_validator", .module = log_validator }},
    }) });
    b.installArtifact(log_cli);
    const supervisor_fixture = b.addExecutable(.{
        .name = "wamr-ci-supervisor-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("../../tools/hyperv/direct/runtime_fixture.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "hyperv_core", .module = core }},
        }),
    });
    b.installArtifact(supervisor_fixture);

    const image = b.dependency("public_image", .{ .target = target, .optimize = optimize }).module("hyperv_public_image");
    const wamr_aot_build = b.dependency("wamr_aot_build", .{
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(wamr_aot_build.artifact("uk-wamr-aot-build"));
    const root = b.createModule(.{
        .root_source_file = b.path("package.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "public_image", .module = image }},
    });
    const cli = b.addExecutable(.{ .name = "wamr-ci-package", .root_module = root });
    b.installArtifact(cli);
    const source_closure_module = b.createModule(.{
        .root_source_file = b.path("../../controller_source_closure.zig"),
        .target = target,
        .optimize = optimize,
    });
    const controller_module = b.addModule("wamr_controller", .{
        .root_source_file = b.path("controller/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "controller_source_closure", .module = source_closure_module },
        },
    });
    const controller_cli = b.addExecutable(.{
        .name = "uk-wamr-native-ci",
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "wamr_controller", .module = controller_module }},
        }),
    });
    b.installArtifact(controller_cli);
    const controller_runtime = b.option(
        []const u8,
        "controller-runtime",
        "Existing absolute owner-only runtime directory for create-only controller install",
    ) orelse "";
    const controller_options = b.addOptions();
    controller_options.addOption([]const u8, "repository_root", std.fs.path.resolve(b.allocator, &.{ b.graph.cache.cwd, b.build_root.path orelse ".", "../../.." }) catch
        @panic("cannot resolve source root"));
    const host_core = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/core.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    if (b.graph.host.result.cpu.arch == .x86_64)
        host_core.addAssemblyFile(b.path("../../tools/hyperv/sha256_clear_upper.S"));
    const host_closure = b.createModule(.{
        .root_source_file = b.path("../../controller_source_closure.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const host_controller = b.createModule(.{
        .root_source_file = b.path("controller/root.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = host_core },
            .{ .name = "controller_source_closure", .module = host_closure },
        },
    });
    const host_cli = b.addExecutable(.{
        .name = "uk-wamr-native-ci-host-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/main.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "wamr_controller", .module = host_controller }},
        }),
    });
    const host_cli_run = b.addRunArtifact(host_cli);
    if (b.args) |args| host_cli_run.addArgs(args);
    b.step("run-controller-fixture", "Run host controller CLI for bounded CLI fixtures")
        .dependOn(&host_cli_run.step);
    const installer = b.addExecutable(.{
        .name = "uk-wamr-native-ci-install",
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/install.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "hyperv_core", .module = host_core },
                .{ .name = "wamr_controller", .module = host_controller },
            },
        }),
    });
    const install_run = b.addRunArtifact(installer);
    install_run.addArg(controller_runtime);
    install_run.addArg(b.graph.cache.cwd);
    install_run.addFileArg(controller_cli.getEmittedBin());
    b.step("install-controller", "Create-only portable controller install in the private runtime")
        .dependOn(&install_run.step);
    const controller_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "wamr_controller", .module = host_controller },
                .{ .name = "hyperv_core", .module = host_core },
            },
        }),
    });
    controller_tests.root_module.addOptions("test_options", controller_options);
    const controller_run = b.addRunArtifact(controller_tests);
    b.step("test-controller", "Run controller foundation unit, golden, and fault fixtures")
        .dependOn(&controller_run.step);
    const tests = b.addTest(.{ .root_module = root });
    const unit_tests = b.addRunArtifact(tests);
    const unit_step = b.step("test-unit", "Test the compute packaging adapter command boundary");
    unit_step.dependOn(&unit_tests.step);
    const cli_tests = b.addSystemCommand(&.{ "python3", "-B" });
    cli_tests.addFileArg(b.path("../../apps/wamr-aot/validator/cli_test.py"));
    cli_tests.addFileArg(log_cli.getEmittedBin());
    unit_step.dependOn(&cli_tests.step);
    const options = b.addOptions();
    options.addOptionPath("cli", cli.getEmittedBin());
    options.addOption(
        ?[]const u8,
        "test_root",
        b.option([]const u8, "test-root", "Existing absolute private compute fixture directory"),
    );
    const pipeline_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("pipeline_tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "public_image", .module = image }},
    }) });
    pipeline_tests.root_module.addOptions("test_options", options);
    const pipeline_run = b.addRunArtifact(pipeline_tests);
    const pipeline_step = b.step("test-pipeline", "Run the real private raw-to-QCOW2-to-VHD pipeline fixtures");
    pipeline_step.dependOn(&pipeline_run.step);
    const test_step = b.step("test", "Run unit and required private compute pipeline fixtures");
    test_step.dependOn(&unit_tests.step);
    test_step.dependOn(&pipeline_run.step);
    test_step.dependOn(&controller_run.step);
}
