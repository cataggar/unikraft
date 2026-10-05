const std = @import("std");
const controller_target = @import("controller/target.zig");

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
    const wamr_aot_build = b.dependency("wamr_aot_build", .{
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(wamr_aot_build.artifact("uk-wamr-aot-build"));
    const root = b.createModule(.{
        .root_source_file = b.path("package.zig"),
        .target = target,
        .optimize = optimize,
        .strip = optimize != .debug,
        .imports = &.{.{ .name = "public_image", .module = image }},
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
        },
    });
    const controller_cli = b.addExecutable(.{
        .name = "uk-wamr-native-ci",
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/portable_main.zig"),
            .target = portable_target,
            .optimize = optimize,
            .imports = &.{.{ .name = "wamr_controller", .module = controller_module }},
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
    controller_options.addOptionPathDirectory("repository_root", b.graph.cwdRelativePath(repository_root));
    controller_options.addOption([]const u8, "zig_executable", b.graph.zig_exe);
    controller_options.addOptionPath("git_executable", b.findProgramLazy(.{ .names = &.{"git"} }));
    controller_options.addOptionPath("python_executable", b.findProgramLazy(.{ .names = &.{"python3"} }));
    controller_options.addOptionPathUntracked("fixture_root", .cache_root);
    const host_core = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/core.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    if (b.graph.host.result.cpu.arch == .x86_64)
        host_core.addAssemblyFile(b.path("../../tools/hyperv/sha256_clear_upper.S"));
    const host_closure = sourceClosureModule(b, b.graph.host, optimize);
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
    const host_controller = b.createModule(.{
        .root_source_file = b.path("controller/root.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = host_core },
            .{ .name = "wamr_log_validator", .module = host_validator },
            .{ .name = "controller_source_closure", .module = host_closure },
            .{ .name = "import_validator_identity", .module = host_identity },
        },
    });
    const host_cli = b.addExecutable(.{
        .name = "uk-wamr-native-ci-host-fixture",
        .use_llvm = if (optimize == .debug) true else null,
        .use_lld = if (optimize == .debug) true else null,
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/main.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .strip = true,
            .imports = &.{.{ .name = "wamr_controller", .module = host_controller }},
        }),
    });
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
        .root_module = b.createModule(.{
            .root_source_file = b.path("controller/tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .strip = true,
            .imports = &.{
                .{ .name = "wamr_controller", .module = host_controller },
                .{ .name = "hyperv_core", .module = host_core },
            },
        }),
    });
    controller_tests.root_module.addOptions("test_options", controller_options);
    controller_options.addOptionPath("host_controller_cli", host_cli.getEmittedBin());
    controller_options.addOptionPath("import_validator", host_direct.getEmittedBin());
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
    source_limits_tests.root_module.addOptions("test_options", controller_options);
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
        .root_module = b.createModule(.{
            .root_source_file = b.path("authority/tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "hyperv_core", .module = host_core }},
        }),
    });
    const authority_contracts_run = b.addRunArtifact(authority_contracts);
    const authority_python_goldens = b.addSystemCommand(&.{ "python3", "-B" });
    authority_python_goldens.addFileArg(b.path("tests/test_authority_contract_goldens.py"));
    const authority_step = b.step("test-authority-contracts", "Run native/Python authority contract goldens");
    authority_step.dependOn(&authority_contracts_run.step);
    authority_step.dependOn(&authority_python_goldens.step);
    controller_step.dependOn(&authority_contracts_run.step);
    controller_step.dependOn(&authority_python_goldens.step);
    const tests = b.addTest(.{ .root_module = root });
    const unit_tests = b.addRunArtifact(tests);
    const unit_step = b.step("test-unit", "Test the compute packaging adapter command boundary");
    unit_step.dependOn(&unit_tests.step);
    unit_step.dependOn(&controller_run.step);
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
    test_step.dependOn(&authority_python_goldens.step);
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
            @panic("duplicate controller source embed");
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
