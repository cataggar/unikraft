const std = @import("std");
const controller_target = @import("controller/target.zig");
const authority_build = @import("authority.build.zig");

fn handoffContracts(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize, core: *std.Build.Module) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("handoff/contracts.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    });
}

fn handoffModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize, core: *std.Build.Module, controller: *std.Build.Module) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("handoff/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "wamr_controller", .module = controller },
        },
    });
}

fn wamrAotBuild(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize) *std.Build.Dependency {
    return b.dependency("wamr_aot_build", .{ .target = target, .optimize = optimize });
}

pub fn build(b: *std.Build) void {
    const repository_root = std.Io.Dir.cwd().realPathFileAlloc(
        b.graph.io,
        b.root.joinString(b.allocator, "../../..") catch @panic("OOM"),
        b.allocator,
    ) catch |err| std.debug.panic("resolve controller repository root: {s}", .{@errorName(err)});
    const requested_target = b.standardTargetOptionsQueryOnly(.{});
    const target = b.resolveTargetQuery(requested_target);
    const optimize = b.standardOptimizeOption(.{});
    const portable_query = controller_target.portableQuery();
    const portable_target = b.resolveTargetQuery(portable_query);
    const identity_writer = b.addExecutable(.{
        .name = "wamr-validator-identity",
        .root_module = b.createModule(.{
            .root_source_file = b.path("build.zig"),
            .target = b.graph.host,
            .optimize = .safe,
        }),
    });
    const portable_direct = b.dependency("direct_validator", .{
        .target = portable_target,
        .optimize = .safe,
    }).artifact("uk-wamr-direct-validate");
    const portable_identity = validatorIdentity(b, identity_writer, portable_direct, portable_target);
    const host_direct = b.dependency("direct_validator", .{
        .target = b.graph.host,
        .optimize = .safe,
    }).artifact("uk-wamr-direct-validate");
    const host_identity = validatorIdentity(b, identity_writer, host_direct, b.graph.host);
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
        .strip = optimize != .debug,
        .imports = &.{
            .{ .name = "wamr_log_validator", .module = log_validator },
            .{ .name = "hyperv_core", .module = core },
        },
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
    const wamr_aot_build = wamrAotBuild(b, target, optimize);
    const aot_build_cli = wamr_aot_build.artifact("uk-wamr-aot-build");
    b.installArtifact(aot_build_cli);
    const package_options = b.addOptions();
    package_options.addOption([]const u8, "miz_revision", "66ea6701cf0e1b6d31e5f30fade00b7a546d4b44");
    const root = b.createModule(.{
        .root_source_file = b.path("package.zig"),
        .target = target,
        .optimize = optimize,
        .strip = optimize != .debug,
        .imports = &.{
            .{ .name = "public_image", .module = image },
            .{ .name = "package_options", .module = package_options.createModule() },
        },
    });
    const cli = b.addExecutable(.{ .name = "wamr-ci-package", .root_module = root });
    b.installArtifact(cli);
    const portable_core = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/core.zig"),
        .target = portable_target,
        .optimize = optimize,
    });
    portable_core.addAssemblyFile(b.path("../../tools/hyperv/sha256_clear_upper.S"));
    const portable_serial = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/local_boot/serial.zig"),
        .target = portable_target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = portable_core }},
    });
    const portable_validator = b.createModule(.{
        .root_source_file = b.path("../../apps/wamr-aot/validator/root.zig"),
        .target = portable_target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = portable_core },
            .{ .name = "local_boot_serial", .module = portable_serial },
        },
    });
    const source_closure_module = sourceClosureModule(b, portable_target, optimize);
    const controller_module = b.addModule("wamr_controller", .{
        .root_source_file = b.path("controller/root.zig"),
        .target = portable_target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = portable_core },
            .{ .name = "wamr_log_validator", .module = portable_validator },
            .{ .name = "controller_source_closure", .module = source_closure_module },
            .{ .name = "import_validator_identity", .module = portable_identity },
            .{ .name = "handoff_contracts", .module = handoffContracts(b, portable_target, optimize, portable_core) },
        },
    });
    const controller_cli = b.addExecutable(.{
        .name = "uk-wamr-native-ci",
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/portable_main.zig"),
            .target = portable_target,
            .optimize = optimize,
            .strip = optimize != .debug,
            .imports = &.{
                .{ .name = "wamr_controller", .module = controller_module },
                .{ .name = "wamr_handoff", .module = handoffModule(b, portable_target, optimize, portable_core, controller_module) },
            },
        }),
    });
    b.installArtifact(controller_cli);
    const native_fixtures = b.addExecutable(.{
        .name = "wamr-native-ci-fixtures",
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/fixture_runner.zig"),
            .target = portable_target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "wamr_controller", .module = controller_module },
                .{ .name = "hyperv_core", .module = portable_core },
            },
        }),
    });
    b.installArtifact(native_fixtures);
    const controller_runtime = b.option(
        []const u8,
        "controller-runtime",
        "Existing absolute owner-only runtime directory for create-only controller install",
    ) orelse "";
    const controller_options = b.addOptions();
    const CompositionGroup = enum { all, faults, retention, local_qualify };
    controller_options.addOption(CompositionGroup, "handoff_composition_group", b.option(CompositionGroup, "handoff-composition-group", "Select a focused real-owner handoff composition group") orelse .all);
    controller_options.addOption([]const u8, "local_fixture_source", b.option([]const u8, "local-fixture-source", "Select one complete historical local fixture revision for diagnosis") orelse "");
    controller_options.addOptionPathDirectory("repository_root", b.graph.cwdRelativePath(repository_root));
    controller_options.addOption([]const u8, "zig_executable", b.graph.zig_exe);
    controller_options.addOptionPath("git_executable", b.findProgramLazy(.{ .names = &.{"git"} }));
    controller_options.addOptionPath("python_executable", b.findProgramLazy(.{ .names = &.{"python3"} }));
    const miz_dep = b.dependency("public_image", .{ .target = target, .optimize = optimize }).builder.dependency("miz_source", .{ .target = target, .optimize = optimize });
    const miz_package_abs = std.Io.Dir.cwd().realPathFileAlloc(
        b.graph.io,
        miz_dep.builder.root.joinString(b.allocator, ".") catch @panic("OOM"),
        b.allocator,
    ) catch @panic("cannot resolve miz package root");
    controller_options.addOption([]const u8, "miz_package", miz_package_abs);
    const explicit_controller_fixture_root = b.option([]const u8, "controller-fixture-root", "Existing absolute owner-private source fixture root");
    const env_cache_fixture_root: ?[]const u8 = if (b.graph.environ_map.get("ZIG_LOCAL_CACHE_DIR")) |cache_dir| blk: {
        const cwd = std.Io.Dir.cwd().realPathFileAlloc(b.graph.io, ".", b.allocator) catch @panic("OOM");
        break :blk std.fs.path.resolve(b.allocator, &.{ cwd, cache_dir }) catch @panic("OOM");
    } else null;
    if (explicit_controller_fixture_root) |custom_fixture_root| {
        if (!std.fs.path.isAbsolute(custom_fixture_root)) @panic("controller-fixture-root must be absolute");
        controller_options.addOption([]const u8, "fixture_root", custom_fixture_root);
    } else if (env_cache_fixture_root) |cache_root| {
        controller_options.addOption([]const u8, "fixture_root", cache_root);
    } else
        controller_options.addOptionPathUntracked("fixture_root", .cache_root);
    const host_core = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/core.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    if (b.graph.host.result.cpu.arch == .x86_64)
        host_core.addAssemblyFile(b.path("../../tools/hyperv/sha256_clear_upper.S"));
    const host_closure = sourceClosureModule(b, b.graph.host, optimize);
    for ([_]bool{ false, true }) |native_owner| {
        const supervisor_options = b.addOptions();
        supervisor_options.addOption(bool, "native_source_owner", native_owner);
        supervisor_options.addOption([]const u8, "source_closure_sha256", &@as([64]u8, @splat('a')));
        const supervisor = b.addExecutable(.{
            .name = if (native_owner) "wamr-ci-native-supervisor-host-test" else "wamr-ci-historical-supervisor-host-test",
            .root_module = b.createModule(.{
                .root_source_file = b.path("supervisor.zig"),
                .target = b.graph.host,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "hyperv_core", .module = host_core },
                    .{ .name = "build_options", .module = supervisor_options.createModule() },
                    .{ .name = "supervisor_source_closure", .module = host_closure },
                },
            }),
        });
        controller_options.addOptionPath(if (native_owner) "native_standalone_supervisor" else "historical_standalone_supervisor", supervisor.getEmittedBin());
    }
    const host_serial = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/local_boot/serial.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = host_core }},
    });
    const host_validator = b.createModule(.{
        .root_source_file = b.path("../../apps/wamr-aot/validator/root.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = host_core },
            .{ .name = "local_boot_serial", .module = host_serial },
        },
    });
    const historical_package_options = b.addOptions();
    historical_package_options.addOption([]const u8, "miz_revision", "669a27982b376311f558e820b69e9a692735b0cd");
    const host_package = b.addExecutable(.{
        .name = "wamr-ci-package-host-local-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("package.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "public_image", .module = b.dependency("public_image", .{ .target = b.graph.host, .optimize = optimize }).module("hyperv_public_image") },
                .{ .name = "package_options", .module = historical_package_options.createModule() },
            },
        }),
    });
    controller_options.addOptionPath("host_package_cli", host_package.getEmittedBin());
    const host_log_cli = b.addExecutable(.{
        .name = "uk-wamr-log-validate-host-local-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("../../apps/wamr-aot/validator/main.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "wamr_log_validator", .module = host_validator },
                .{ .name = "hyperv_core", .module = host_core },
            },
        }),
    });
    controller_options.addOptionPath("host_log_validator", host_log_cli.getEmittedBin());
    controller_options.addOptionPath("host_aot_build", wamrAotBuild(b, b.graph.host, optimize).artifact("uk-wamr-aot-build").getEmittedBin());
    const host_controller = b.createModule(.{
        .root_source_file = b.path("controller/root.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = host_core },
            .{ .name = "wamr_log_validator", .module = host_validator },
            .{ .name = "controller_source_closure", .module = host_closure },
            .{ .name = "import_validator_identity", .module = host_identity },
            .{ .name = "handoff_contracts", .module = handoffContracts(b, b.graph.host, optimize, host_core) },
        },
    });
    const host_cli = b.addExecutable(.{
        .name = "uk-wamr-native-ci-host-fixture",
        .use_llvm = true,
        .use_lld = if (optimize == .debug) true else null,
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/main.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .strip = true,
            .imports = &.{
                .{ .name = "wamr_controller", .module = host_controller },
                .{ .name = "wamr_handoff", .module = handoffModule(b, b.graph.host, optimize, host_core, host_controller) },
            },
        }),
    });
    // Producer import requires an installable safe supervisor.
    // Keep the selected profile for the other CLI fixtures and test modules.
    const host_import_cli = if (optimize == .safe) host_cli else blk: {
        const import_core = b.createModule(.{
            .root_source_file = b.path("../../tools/hyperv/core.zig"),
            .target = b.graph.host,
            .optimize = .safe,
        });
        if (b.graph.host.result.cpu.arch == .x86_64)
            import_core.addAssemblyFile(b.path("../../tools/hyperv/sha256_clear_upper.S"));
        const import_serial = b.createModule(.{
            .root_source_file = b.path("../../tools/hyperv/local_boot/serial.zig"),
            .target = b.graph.host,
            .optimize = .safe,
            .imports = &.{.{ .name = "hyperv_core", .module = import_core }},
        });
        const import_validator = b.createModule(.{
            .root_source_file = b.path("../../apps/wamr-aot/validator/root.zig"),
            .target = b.graph.host,
            .optimize = .safe,
            .imports = &.{
                .{ .name = "hyperv_core", .module = import_core },
                .{ .name = "local_boot_serial", .module = import_serial },
            },
        });
        const import_controller = b.createModule(.{
            .root_source_file = b.path("controller/root.zig"),
            .target = b.graph.host,
            .optimize = .safe,
            .imports = &.{
                .{ .name = "hyperv_core", .module = import_core },
                .{ .name = "wamr_log_validator", .module = import_validator },
                .{ .name = "controller_source_closure", .module = sourceClosureModule(b, b.graph.host, .safe) },
                .{ .name = "import_validator_identity", .module = host_identity },
                .{ .name = "handoff_contracts", .module = handoffContracts(b, b.graph.host, .safe, import_core) },
            },
        });
        break :blk b.addExecutable(.{
            .name = "uk-wamr-native-ci-host-import-fixture",
            .use_llvm = true,
            .root_module = b.createModule(.{
                .root_source_file = b.path("controller/main.zig"),
                .target = b.graph.host,
                .optimize = .safe,
                .strip = true,
                .imports = &.{
                    .{ .name = "wamr_controller", .module = import_controller },
                    .{ .name = "wamr_handoff", .module = handoffModule(b, b.graph.host, .safe, import_core, import_controller) },
                },
            }),
        });
    };
    const host_cli_run = b.addRunArtifact(host_cli);
    host_cli_run.addPassthruArgs();
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
    install_run.addDirectoryArg(b.graph.cwdRelativePath("."));
    install_run.addFileArg(controller_cli.getEmittedBin());
    const install_step = b.step("install-controller", "Create-only portable controller install in the private runtime");
    if (controller_target.permitsInstall(requested_target, optimize))
        install_step.dependOn(&install_run.step)
    else
        install_step.dependOn(&b.addFail(
            "install-controller requires -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v2 -Doptimize=safe",
        ).step);
    const controller_tests = b.addTest(.{
        .filters = b.option([]const []const u8, "test-filter", "Select bounded controller fixtures") orelse &.{},
        .test_runner = .{ .path = b.path("controller/composition_runner.zig"), .mode = .server },
        .use_llvm = true,
        .use_lld = if (optimize == .debug) true else null,
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            // This runner is itself a pinned supervisor, bounded to 64 MiB.
            .strip = true,
            .imports = &.{
                .{ .name = "wamr_controller", .module = host_controller },
                .{ .name = "hyperv_core", .module = host_core },
            },
        }),
    });
    controller_tests.root_module.addOptions("test_options", controller_options);
    const composition_module = b.createModule(.{
        .root_source_file = b.path("handoff/composition_tests.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "wamr_controller", .module = host_controller },
            .{ .name = "hyperv_core", .module = host_core },
            .{ .name = "wamr_handoff", .module = handoffModule(b, b.graph.host, optimize, host_core, host_controller) },
        },
    });
    const controller_test_options = controller_tests.root_module.import_table.get("test_options").?;
    composition_module.addImport("test_options", controller_test_options);
    controller_tests.root_module.addImport("handoff_composition_tests", composition_module);
    const zig_real_exe = std.Io.Dir.cwd().realPathFileAlloc(b.graph.io, b.graph.zig_exe, b.allocator) catch
        @panic("cannot resolve zig executable path");
    const default_test_runner = b.createModule(.{
        .root_source_file = b.graph.cwdRelativePath(b.pathJoin(&.{ std.fs.path.dirname(zig_real_exe).?, "lib/compiler/test_runner.zig" })),
        .target = b.graph.host,
        .optimize = optimize,
    });
    controller_tests.root_module.addImport("default_test_runner", default_test_runner);
    controller_tests.root_module.addImport("wamr_handoff", composition_module.import_table.get("wamr_handoff").?);
    controller_options.addOptionPath("host_controller_cli", host_cli.getEmittedBin());
    controller_options.addOptionPath("host_import_controller_cli", host_import_cli.getEmittedBin());
    controller_options.addOptionPath("import_validator", host_direct.getEmittedBin());
    controller_options.addOptionPath("native_validator_cli", host_direct.getEmittedBin());
    const fixture_host = b.addExecutable(.{
        .name = "wamr-native-ci-fixtures-host-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/fixture_runner.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "wamr_controller", .module = host_controller },
                .{ .name = "hyperv_core", .module = host_core },
            },
        }),
    });
    controller_options.addOptionPath("fixture_runner", fixture_host.getEmittedBin());
    const command_fixture = b.addExecutable(.{
        .name = "wamr-ci-controller-test-command",
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/test_command.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    controller_options.addOptionPath("command_fixture", command_fixture.getEmittedBin());
    const descendant_core = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/core.zig"),
        .target = b.graph.host,
        .optimize = .safe,
    });
    if (b.graph.host.result.cpu.arch == .x86_64)
        descendant_core.addAssemblyFile(b.path("../../tools/hyperv/sha256_clear_upper.S"));
    const descendant_fixture = b.addExecutable(.{
        .name = "wamr-ci-controller-descendant-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("../../tools/hyperv/direct/runtime_fixture.zig"),
            .target = b.graph.host,
            .optimize = .safe,
            .imports = &.{.{ .name = "hyperv_core", .module = descendant_core }},
        }),
    });
    controller_options.addOptionPath("descendant_fixture", descendant_fixture.getEmittedBin());
    const local_worker = b.addExecutable(.{
        .name = "wamr-ci-local-acceptance-worker",
        .use_llvm = if (optimize == .safe) true else null,
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/local_acceptance_worker.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .strip = true,
            .imports = &.{
                .{ .name = "wamr_controller", .module = host_controller },
                .{ .name = "hyperv_core", .module = host_core },
            },
        }),
    });
    local_worker.root_module.addOptions("test_options", controller_options);
    const local_worker_options = b.addOptions();
    local_worker_options.addOptionPath("executable", local_worker.getEmittedBin());
    controller_tests.root_module.addOptions("local_worker_options", local_worker_options);
    const composition_tests = b.addTest(.{
        .filters = &.{"handoff composition"},
        .test_runner = .{ .path = b.path("controller/composition_runner.zig"), .mode = .server },
        .use_llvm = if (optimize == .safe) true else null,
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .strip = true,
            .imports = &.{
                .{ .name = "wamr_controller", .module = host_controller },
                .{ .name = "hyperv_core", .module = host_core },
                .{ .name = "handoff_composition_tests", .module = composition_module },
                .{ .name = "wamr_handoff", .module = composition_module.import_table.get("wamr_handoff").? },
                .{ .name = "default_test_runner", .module = default_test_runner },
            },
        }),
    });
    composition_tests.root_module.addImport("test_options", controller_test_options);
    composition_tests.root_module.addOptions("local_worker_options", local_worker_options);
    b.step("build-handoff-composition", "Build the exact retained native composition fixture runner")
        .dependOn(&composition_tests.step);
    const composition_run = b.addSystemCommand(&.{"/usr/bin/env"});
    composition_run.addFileArg(composition_tests.getEmittedBin());
    b.step("test-handoff-composition", "Run retained native import/candidate composition faults without live qualification")
        .dependOn(&composition_run.step);
    const noop_fixture = b.addExecutable(.{
        .name = "wamr-ci-noop-test-command",
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/noop_fixture.zig"),
            .target = b.graph.host,
            .optimize = .safe,
            .strip = true,
        }),
    });
    controller_options.addOptionPath("noop_fixture", noop_fixture.getEmittedBin());
    const controller_run = b.addRunArtifact(controller_tests);
    const controller_direct = b.addSystemCommand(&.{"/usr/bin/env"});
    controller_direct.addFileArg(controller_tests.getEmittedBin());
    controller_direct.addPassthruArgs();
    b.step("test-controller-direct", "Run host controller tests with direct failure output")
        .dependOn(&controller_direct.step);
    const install_target_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/install_target_tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    install_target_tests.root_module.addOptions("test_options", controller_options);
    const install_target_run = b.addRunArtifact(install_target_tests);
    install_target_run.step.dependOn(&controller_run.step);
    const controller_step = b.step("test-controller", "Run controller foundation unit, golden, and fault fixtures");
    controller_step.dependOn(&install_target_run.step);
    const source_limits_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/source_custody_limits_tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "hyperv_core", .module = host_core },
                .{ .name = "controller_source_closure", .module = host_closure },
            },
        }),
    });
    const source_limits_options = b.addOptions();
    source_limits_options.addOptionPathDirectory("repository_root", b.graph.cwdRelativePath(repository_root));
    if (explicit_controller_fixture_root) |custom_fixture_root| {
        source_limits_options.addOption([]const u8, "fixture_root", custom_fixture_root);
    } else if (env_cache_fixture_root) |cache_root| {
        source_limits_options.addOption([]const u8, "fixture_root", b.pathJoin(&.{ cache_root, "source-limits-work" }));
    } else
        source_limits_options.addOptionPathUntracked("fixture_root", std.Build.LazyPath.cache_root.path(b, "source-limits-work"));
    source_limits_tests.root_module.addOptions("test_options", source_limits_options);
    const source_limits_run = b.addRunArtifact(source_limits_tests);
    b.step("test-controller-limits", "Run native source-custody production boundary fixtures")
        .dependOn(&source_limits_run.step);
    controller_step.dependOn(&source_limits_run.step);
    const fault_parity_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/fault_parity_tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "wamr_controller", .module = host_controller },
                .{ .name = "hyperv_core", .module = host_core },
            },
        }),
    });
    fault_parity_tests.root_module.addOptions("test_options", controller_options);
    controller_run.step.dependOn(&fault_parity_tests.step);
    const fault_parity_run = b.addRunArtifact(fault_parity_tests);
    fault_parity_run.step.dependOn(&controller_run.step);
    b.step("test-controller-fault-parity", "Run native physical custody parity faults")
        .dependOn(&fault_parity_run.step);
    controller_step.dependOn(&fault_parity_run.step);
    const record_goldens = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/differential_records.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "wamr_controller", .module = host_controller },
                .{ .name = "hyperv_core", .module = host_core },
            },
        }),
    });
    const record_goldens_run = b.addRunArtifact(record_goldens);
    b.step("test-differential-records", "Run frozen v1/v2 native record goldens")
        .dependOn(&record_goldens_run.step);
    controller_step.dependOn(&record_goldens_run.step);
    const handoff_contracts = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("handoff/tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "hyperv_core", .module = host_core },
                .{ .name = "wamr_controller", .module = host_controller },
            },
        }),
    });
    const handoff_options = b.addOptions();
    handoff_options.addOptionPathUntracked("fixture_root", .cache_root);
    handoff_options.addOptionPath("python_oracle", b.graph.cwdRelativePath(b.fmt(
        "{s}/support/build/wamr-native-ci/tests/test_handoff_contract_goldens.py",
        .{repository_root},
    )));
    handoff_options.addOptionPath("accepted_result_fixture", b.graph.cwdRelativePath(b.fmt(
        "{s}/support/build/wamr-native-ci/tests/fixtures/differential/accepted-v2.json",
        .{repository_root},
    )));
    handoff_contracts.root_module.addOptions("test_options", handoff_options);
    const handoff_contracts_run = b.addRunArtifact(handoff_contracts);
    const handoff_python_goldens = b.addSystemCommand(&.{"env"});
    handoff_python_goldens.addPrefixedDirectoryArg("WAMR_HANDOFF_GOLDEN_ROOT=", .cache_root);
    handoff_python_goldens.addArgs(&.{ "python3", "-B" });
    handoff_python_goldens.addFileArg(b.path("tests/test_handoff_contract_goldens.py"));
    const handoff_step = b.step("test-handoff-contracts", "Run native/Python handoff contract goldens");
    handoff_step.dependOn(&handoff_contracts_run.step);
    handoff_step.dependOn(&handoff_python_goldens.step);
    controller_step.dependOn(&handoff_contracts_run.step);
    controller_step.dependOn(&handoff_python_goldens.step);
    const authority_contracts = b.addTest(.{
        .filters = b.option([]const []const u8, "authority-test-filter", "Select bounded authority fixtures") orelse &.{},
        .root_module = b.createModule(.{
            .root_source_file = b.path("authority/library_tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "hyperv_core", .module = host_core }},
        }),
    });
    const authority_handoff = handoffModule(b, b.graph.host, optimize, host_core, host_controller);
    const authority_options = authority_build.testOptions(b, b.graph.host, optimize, std.Build.LazyPath.cache_root.path(b, "authority-contract-work"));
    const authority_options_module = authority_options.createModule();
    authority_handoff.addImport("test_options", authority_options_module);
    authority_contracts.root_module.addImport("test_options", authority_options_module);
    authority_build.addImports(b, authority_contracts.root_module, b.graph.host, optimize, host_core, host_serial, host_validator, authority_handoff);
    const authority_module = b.addModule("wamr_authority", .{
        .root_source_file = b.path("authority/root.zig"),
        .target = portable_target,
        .optimize = optimize,
    });
    authority_build.addImports(b, authority_module, portable_target, optimize, portable_core, portable_serial, portable_validator, handoffModule(b, portable_target, optimize, portable_core, controller_module));
    const authority_source_check = authority_build.sourceCheck(b, portable_target, optimize, authority_module);
    const authority_contracts_run = b.addRunArtifact(authority_contracts);
    source_limits_run.step.dependOn(&authority_source_check.step);
    authority_contracts_run.step.dependOn(&authority_source_check.step);
    const authority_direct = b.addSystemCommand(&.{"/usr/bin/env"});
    authority_direct.addFileArg(authority_contracts.getEmittedBin());
    b.step("test-authority-direct", "Run authority fixtures with direct failure output").dependOn(&authority_direct.step);
    const authority_python_goldens = b.addSystemCommand(&.{"env"});
    authority_python_goldens.addPrefixedDirectoryArg("WAMR_AUTHORITY_CONTRACT_SCRATCH=", std.Build.LazyPath.cache_root.path(b, "authority-contract-work"));
    authority_python_goldens.addArgs(&.{ "python3", "-B" });
    authority_python_goldens.addFileArg(b.path("tests/test_authority_contract_goldens.py"));
    const authority_step = b.step("test-authority-contracts", "Run native/Python authority contract goldens");
    authority_step.dependOn(&authority_contracts_run.step);
    authority_step.dependOn(&authority_source_check.step);
    authority_step.dependOn(&authority_python_goldens.step);
    const authority_libraries_step = b.step("test-authority-libraries", "Run complete source-only authority library composition");
    authority_libraries_step.dependOn(&authority_contracts_run.step);
    authority_libraries_step.dependOn(&authority_source_check.step);
    authority_libraries_step.dependOn(&authority_python_goldens.step);
    controller_step.dependOn(&authority_contracts_run.step);
    controller_step.dependOn(&authority_source_check.step);
    controller_step.dependOn(&authority_python_goldens.step);
    // Parallel goldens must not create ancestors of recorded controller tools.
    const contract_fixture_dirs = b.addSystemCommand(&.{ "mkdir", "-p", "-m", "0700", "--" });
    contract_fixture_dirs.has_side_effects = true;
    for ([_][]const u8{ "tmp", "h", "o", "z", "handoff-export-tests", "handoff-python-goldens", "authority-contract-work", "install-target-work", "source-limits-work" }) |name|
        contract_fixture_dirs.addDirectoryArg2(std.Build.LazyPath.cache_root.path(b, name), .{ .make_absolute = true });
    if (explicit_controller_fixture_root == null) {
        if (env_cache_fixture_root) |cache_root|
            contract_fixture_dirs.addArg(b.pathJoin(&.{ cache_root, "source-limits-work" }));
    }
    for ([_]*std.Build.Step{
        &controller_run.step,
        &controller_direct.step,
        &source_limits_run.step,
        &handoff_contracts_run.step,
        &handoff_python_goldens.step,
        &authority_contracts_run.step,
        &authority_python_goldens.step,
        &install_target_run.step,
    }) |step| step.dependOn(&contract_fixture_dirs.step);
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
    options.addOptionPath("validator_cli", log_cli.getEmittedBin());
    options.addOption(
        ?[]const u8,
        "test_root",
        b.option([]const u8, "test-root", "Existing absolute private compute fixture directory"),
    );
    const proof_closure = sourceClosureModule(b, target, optimize);
    const proof_serial = b.createModule(.{
        .root_source_file = b.path("controller/public_image_serial.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "local_boot", .module = image.import_table.get("local_boot").? }},
    });
    const proof_validator = b.createModule(.{
        .root_source_file = b.path("../../apps/wamr-aot/validator/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = image.import_table.get("hyperv_core").? },
            .{ .name = "local_boot_serial", .module = proof_serial },
        },
    });
    const proof_controller = b.createModule(.{
        .root_source_file = b.path("controller/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = image.import_table.get("hyperv_core").? },
            .{ .name = "wamr_log_validator", .module = proof_validator },
            .{ .name = "controller_source_closure", .module = proof_closure },
            .{ .name = "handoff_contracts", .module = handoffContracts(b, target, optimize, image.import_table.get("hyperv_core").?) },
            .{ .name = "import_validator_identity", .module = validatorIdentity(b, identity_writer, b.dependency("direct_validator", .{
                .target = target,
                .optimize = .safe,
            }).artifact("uk-wamr-direct-validate"), target) },
        },
    });
    const pipeline_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("pipeline_tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "public_image", .module = image },
            .{ .name = "wamr_controller", .module = proof_controller },
        },
    }) });
    pipeline_tests.root_module.addOptions("test_options", options);
    const pipeline_run = b.addRunArtifact(pipeline_tests);
    const pipeline_step = b.step("test-pipeline", "Run the real private raw-to-QCOW2-to-VHD pipeline fixtures");
    pipeline_step.dependOn(&pipeline_run.step);
    const fixture_build = b.step("build-controller-fixtures", "Compile controller and package-boot fixture binaries without running them");
    for ([_]*std.Build.Step.Compile{
        log_cli,
        supervisor_fixture,
        aot_build_cli,
        cli,
        controller_cli,
        native_fixtures,
        controller_tests,
        source_limits_tests,
        fault_parity_tests,
        install_target_tests,
        record_goldens,
        handoff_contracts,
        authority_contracts,
        authority_source_check,
        tests,
        pipeline_tests,
    }) |artifact| {
        fixture_build.dependOn(&artifact.step);
        controller_run.step.dependOn(&artifact.step);
        controller_direct.step.dependOn(&artifact.step);
    }
    const test_step = b.step("test", "Run unit and required private compute pipeline fixtures");
    test_step.dependOn(&unit_tests.step);
    test_step.dependOn(&pipeline_run.step);
    test_step.dependOn(&controller_run.step);
    test_step.dependOn(&source_limits_run.step);
    test_step.dependOn(&fault_parity_run.step);
    test_step.dependOn(&record_goldens_run.step);
    test_step.dependOn(&handoff_contracts_run.step);
    test_step.dependOn(&handoff_python_goldens.step);
    test_step.dependOn(&authority_contracts_run.step);
    test_step.dependOn(&authority_source_check.step);
    test_step.dependOn(&authority_python_goldens.step);
    for (b.graph.configure_dependencies.items) |*dep| switch (dep.lazy_path) {
        .src_path => |sp| if (sp.owner != b) {
            dep.lazy_path = b.graph.cwdRelativePath(
                sp.owner.root.joinString(b.allocator, sp.sub_path) catch @panic("OOM"),
            );
        },
        else => {},
    };
}

fn sourceClosureModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
) *std.Build.Module {
    const source_file = b.path("../../controller_source_closure.zig");
    b.dependOnFileContents(source_file);
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        b.graph.io,
        b.root.joinString(b.allocator, "../../controller_source_closure.zig") catch @panic("OOM"),
        b.allocator,
        .limited(1024 * 1024),
    ) catch |err| std.debug.panic("read controller source closure: {s}", .{@errorName(err)});
    const text = b.allocator.dupeSentinel(u8, bytes, 0) catch @panic("OOM");
    const module = b.createModule(.{
        .root_source_file = source_file,
        .target = target,
        .optimize = optimize,
    });

    // Zig 0.17 interns nested build-root files separately from this module's
    // root. Bind their existing embed names to explicit source dependencies.
    var tokenizer = std.zig.Tokenizer.init(text);
    while (true) {
        const token = tokenizer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid)
            @panic("invalid controller source inventory");
        if (token.tag != .builtin or
            !std.mem.eql(u8, text[token.loc.start..token.loc.end], "@embedFile"))
            continue;
        if (tokenizer.next().tag != .l_paren)
            @panic("invalid controller source embed");
        const literal = tokenizer.next();
        if (literal.tag != .string_literal or tokenizer.next().tag != .r_paren)
            @panic("controller source embeds must name literal files");
        const name = std.zig.string_literal.parseAlloc(b.allocator, text[literal.loc.start..literal.loc.end]) catch
            @panic("invalid controller source embed name");
        if (module.import_table.contains(name))
            continue;
        module.addImport(name, b.createModule(.{
            .root_source_file = b.path(b.fmt("../../{s}", .{name})),
            .target = target,
            .optimize = optimize,
        }));
    }
    return module;
}

fn validatorIdentity(
    b: *std.Build,
    writer: *std.Build.Step.Compile,
    validator: *std.Build.Step.Compile,
    target: std.Build.ResolvedTarget,
) *std.Build.Module {
    const run = b.addRunArtifact(writer);
    run.addFileArg(validator.getEmittedBin());
    const generated = b.addWriteFiles().addCopyFile(run.captureStdOut(.{}), "validator-identity.zig");
    return b.createModule(.{
        .root_source_file = generated,
        .target = target,
        .optimize = .safe,
    });
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidUsage;
    const file = try std.Io.Dir.cwd().openFile(init.io, args[1], .{ .follow_symlinks = false });
    defer file.close(init.io);
    const before = try file.stat(init.io);
    if (before.size > 64 * 1024 * 1024) return error.ArtifactLimit;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < before.size) {
        const count = try file.readPositionalAll(init.io, buffer[0..@intCast(@min(buffer.len, before.size - offset))], offset);
        if (count == 0) return error.ArtifactChanged;
        hash.update(buffer[0..count]);
        offset += count;
    }
    const after = try file.stat(init.io);
    if (before.size != after.size or !std.meta.eql(before.mtime, after.mtime))
        return error.ArtifactChanged;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &.{});
    try stdout.interface.print("pub const sha256 = \"{s}\";\n", .{std.fmt.bytesToHex(hash.finalResult(), .lower)});
}
