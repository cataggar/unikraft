const builtin = @import("builtin");
const std = @import("std");
const build_context = @import("support/build/build-context.zig");
const facade_paths = @import("support/build/zig-facade-paths.zig");
const native_qemu_graph = @import("support/build/native-qemu-graph.zig");

const supported_zig = std.SemanticVersion{ .major = 0, .minor = 16, .patch = 0 };

comptime {
    if (builtin.zig_version.order(supported_zig) != .eq) {
        @compileError("the Unikraft build facade requires Zig 0.16.0");
    }
}

const Verbosity = enum {
    @"0",
    @"1",
    @"2",
};

const PartialLinkerType = enum {
    driver,
    raw,
};

const MakeOptions = struct {
    command: []const u8,
    app: []const u8,
    output: []const u8,
    config: ?[]const u8,
    image_name: ?[]const u8,
    external_libraries: ?[]const u8,
    external_platforms: ?[]const u8,
    exclusions: ?[]const u8,
    verbosity: ?Verbosity,
    cross_compile: ?[]const u8,
    compiler: ?[]const u8,
    linker: ?[]const u8,
    partial_linker: ?[]const u8,
    partial_linker_type: ?PartialLinkerType,
    compiler_targeted: ?bool,
    host_cc: ?[]const u8,
    host_cxx: ?[]const u8,
    host_cflags: ?[]const u8,
    forwarded: []const []const u8,
};

const Target = struct {
    name: []const u8,
    make_target: []const u8,
    description: []const u8,
};

const targets = [_]Target{
    .{ .name = "all", .make_target = "all", .description = "Build everything (GNU Make backend)" },
    .{ .name = "images", .make_target = "images", .description = "Build kernel images" },
    .{ .name = "libs", .make_target = "libs", .description = "Build libraries and their objects" },
    .{ .name = "objs", .make_target = "objs", .description = "Build objects only" },
    .{ .name = "preprocess", .make_target = "preprocess", .description = "Run preprocessing steps" },
    .{ .name = "prepare", .make_target = "prepare", .description = "Run preparation steps" },
    .{ .name = "fetch", .make_target = "fetch", .description = "Fetch, extract, and patch remote code" },
    .{ .name = "menuconfig", .make_target = "menuconfig", .description = "Open the interactive configuration menu" },
    .{ .name = "defconfig", .make_target = "defconfig", .description = "Create a configuration using defaults" },
    .{ .name = "oldconfig", .make_target = "oldconfig", .description = "Resolve new configuration symbols interactively" },
    .{ .name = "olddefconfig", .make_target = "olddefconfig", .description = "Resolve new configuration symbols using defaults" },
    .{ .name = "syncconfig", .make_target = "syncconfig", .description = "Synchronize configuration and dependencies" },
    .{ .name = "savedefconfig", .make_target = "savedefconfig", .description = "Save a minimal default configuration" },
    .{ .name = "clean-libs", .make_target = "clean-libs", .description = "Remove configured library build products" },
    .{ .name = "clean", .make_target = "clean", .description = "Remove configured build products" },
    .{ .name = "properclean", .make_target = "properclean", .description = "Remove the build output directory" },
    .{ .name = "distclean", .make_target = "distclean", .description = "Remove build output and configuration" },
};

pub fn build(b: *std.Build) void {
    const root_lexical = b.pathFromRoot(".");
    const root_result = facade_paths.canonicalizeNearestExisting(
        b.allocator,
        b.graph.io,
        root_lexical,
    ) catch |err| {
        addFailedTargets(b, b.fmt("unable to canonicalize the Unikraft repository '{s}': {s}", .{
            root_lexical,
            @errorName(err),
        }));
        return;
    };
    const root = root_result.path;
    const app_option = b.option([]const u8, "app", "Application directory (Make A=)");
    if (app_option) |value| {
        if (firstUnsafePathByte(value, false)) |byte| {
            addFailedTargets(b, b.fmt(
                "invalid A value: byte 0x{x:0>2} is outside the facade's conservative Make-safe character allowlist",
                .{byte},
            ));
            return;
        }
    }
    const output_option = b.option([]const u8, "output", "Build output directory (Make O=)");
    var validation_message: ?[]const u8 = null;
    if (output_option) |value| {
        if (firstUnsafePathByte(value, false)) |byte| {
            validation_message = b.fmt(
                "invalid O value: byte 0x{x:0>2} is outside the facade's conservative Make-safe character allowlist",
                .{byte},
            );
        }
        validateOutputValue(value) catch {
            validation_message = "invalid -Doutput: the value is empty; omit it to use <app>/build or provide a dedicated build directory";
        };
    }
    const config_option = b.option([]const u8, "config", "Configuration file (Make C=)");
    const image_name_option = b.option([]const u8, "image-name", "Image/application name override (Make N=)");
    const external_library_options = b.option(
        []const []const u8,
        "external-lib",
        "External library path; may be repeated (Make L=)",
    ) orelse &.{};
    const external_platform_options = b.option(
        []const []const u8,
        "external-platform",
        "External platform path; may be repeated (Make P=)",
    ) orelse &.{};
    const exclusion_options = b.option(
        []const []const u8,
        "exclude",
        "Excluded component path; may be repeated (Make E=)",
    ) orelse &.{};
    const context = build_context.Context.init(b.allocator, b.graph.io, .{
        .base = root,
        .application = app_option,
        .output = output_option,
        .prefix = b.option([]const u8, "prefix", "Native build installation/header prefix (defaults to output)"),
        .config = config_option,
        .external_libraries = external_library_options,
        .external_platforms = external_platform_options,
        .exclusions = exclusion_options,
        .image_name = image_name_option,
    }, null) catch |err| {
        addFailedTargets(b, b.fmt("unable to create canonical Unikraft build context: {s}", .{
            @errorName(err),
        }));
        return;
    };
    const app = context.application;
    const output = context.output;
    const output_result = facade_paths.CanonicalPath{
        .path = context.output,
        .exists = context.output_exists,
    };

    const options = MakeOptions{
        .command = b.option([]const u8, "make-command", "GNU Make executable (default: make)") orelse "make",
        .app = app,
        .output = output,
        .config = if (config_option != null) context.config else null,
        .image_name = image_name_option,
        .external_libraries = joinPathList(b.allocator, context.external_libraries),
        .external_platforms = joinPathList(b.allocator, context.external_platforms),
        .exclusions = joinPathList(b.allocator, context.exclusions),
        .verbosity = b.option(Verbosity, "verbose", "Make verbosity: 0, 1, or 2 (Make V=)"),
        .cross_compile = b.option([]const u8, "cross-compile", "Cross-toolchain prefix (Make CROSS_COMPILE=)"),
        .compiler = b.option([]const u8, "compiler", "C compiler command (Make COMPILER=)"),
        .linker = b.option([]const u8, "linker", "Final linker driver command (Make LINKER=)"),
        .partial_linker = b.option([]const u8, "partial-linker", "Relocatable linker command (Make PARTIAL_LINKER=)"),
        .partial_linker_type = b.option(PartialLinkerType, "partial-linker-type", "Relocatable linker interface: driver or raw"),
        .compiler_targeted = b.option(bool, "compiler-targeted", "Compiler command already selects its target"),
        .host_cc = b.option([]const u8, "host-cc", "Host C compiler command (Make HOSTCC=)"),
        .host_cxx = b.option([]const u8, "host-cxx", "Host C++ compiler command (Make HOSTCXX=)"),
        .host_cflags = b.option([]const u8, "host-cflags", "Host compiler flags (Make HOSTCFLAGS=)"),
        .forwarded = b.option([]const []const u8, "make-arg", "Allowlisted NAME=VALUE tool/flag assignment; may be repeated") orelse &.{},
    };

    if (validation_message == null) {
        validation_message = validatePaths(b, root, options, output_result);
    }

    var invalid_assignment: ?[]const u8 = null;
    for (options.forwarded) |assignment| {
        validateForwardedAssignment(assignment) catch {
            invalid_assignment = assignment;
            break;
        };
    }

    if (validation_message) |message| {
        addFailedTargets(b, message);
        return;
    }

    if (invalid_assignment != null) {
        addFailedTargets(b, b.fmt(
            "invalid -Dmake-arg: NAME must be an allowlisted toolchain, flag, or backend assignment and VALUE may contain only conservative Make-safe command characters; use dedicated facade options for paths and configuration",
            .{},
        ));
        return;
    }

    const native_graph = registerNativeQemuGraph(b, context);
    if (native_graph) |registered| {
        std.debug.assert(std.mem.eql(
            u8,
            registered.graph.selectedPlatform().name,
            "kvm",
        ));
    }

    const make_runner = b.addExecutable(.{
        .name = "unikraft-zig-make",
        .root_module = b.createModule(.{
            .root_source_file = b.path("support/build/zig-facade-runner.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .link_libc = true,
        }),
    });
    const native_config_tool = b.addExecutable(.{
        .name = "unikraft-native-config",
        .root_module = b.createModule(.{
            .root_source_file = b.path("support/build/native-config-tool.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    const metadata_path = std.fs.path.join(
        b.allocator,
        &.{ context.output, "native-config", "metadata.tsv" },
    ) catch @panic("out of memory");
    const export_config_metadata = b.addSystemCommand(&.{
        "python3",
        "support/build/native-config-metadata.py",
        "--base",
        context.base,
        "--app",
        context.application,
        "--output",
        context.output,
        "--config",
        context.config,
        "--metadata",
        metadata_path,
    });
    export_config_metadata.setCwd(.{ .cwd_relative = root });
    export_config_metadata.setEnvironmentVariable("PYTHONDONTWRITEBYTECODE", "1");
    if (image_name_option) |image_name| {
        export_config_metadata.addArgs(&.{ "--image-name", image_name });
    }
    for (context.external_libraries) |path| {
        export_config_metadata.addArgs(&.{ "--external-library", path });
    }
    for (context.external_platforms) |path| {
        export_config_metadata.addArgs(&.{ "--external-platform", path });
    }
    for (context.exclusions) |path| {
        export_config_metadata.addArgs(&.{ "--exclude", path });
    }
    const inspect_config = b.addRunArtifact(native_config_tool);
    inspect_config.addArgs(&.{ "inspect", context.config, metadata_path });
    inspect_config.setCwd(.{ .cwd_relative = root });
    inspect_config.step.dependOn(&export_config_metadata.step);
    const inspect_config_step = b.step(
        "config-inspect",
        "Parse configuration and print the native architecture/platform selection",
    );
    inspect_config_step.dependOn(&inspect_config.step);

    const validate_config = b.addRunArtifact(native_config_tool);
    validate_config.addArgs(&.{ "validate", context.config, metadata_path });
    validate_config.setCwd(.{ .cwd_relative = root });
    validate_config.step.dependOn(&export_config_metadata.step);
    const validate_config_step = b.step(
        "config-validate",
        "Validate typed configuration values and target selection without solving Kconfig",
    );
    validate_config_step.dependOn(&validate_config.step);

    const header_path = context.headerPath() catch @panic("out of memory");
    const generate_config_header = b.addRunArtifact(native_config_tool);
    generate_config_header.addArgs(&.{ "header", context.config, metadata_path, header_path });
    generate_config_header.setCwd(.{ .cwd_relative = root });
    generate_config_header.step.dependOn(&export_config_metadata.step);
    const generate_config_header_step = b.step(
        "config-header",
        "Generate include/uk/bits/config.h directly from an existing solved .config",
    );
    generate_config_header_step.dependOn(&generate_config_header.step);

    for (targets) |target| {
        const step = b.step(target.name, target.description);
        if (isDestructiveTarget(target.name)) {
            const fail = b.addFail(b.fmt(
                "Zig facade step '{s}' is intentionally refused: GNU Make re-resolves mutable A/O/C paths before deletion, and this compatibility facade cannot provide descriptor-relative cleanup portably; verify paths and use GNU Make or manual cleanup explicitly",
                .{target.name},
            ));
            step.dependOn(&fail.step);
        } else {
            const run = addMakeCommand(
                b,
                make_runner,
                output,
                root,
                target.make_target,
                options,
            );
            step.dependOn(&run.step);
        }
        if (std.mem.eql(u8, target.name, "all")) {
            b.default_step = step;
        }
    }

    const facade_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("build.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run_facade_tests = b.addRunArtifact(facade_tests);
    run_facade_tests.setCwd(.{ .cwd_relative = b.cache_root.path orelse ".zig-cache" });
    const runner_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("support/build/zig-facade-runner.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
            .link_libc = true,
        }),
    });
    const run_runner_tests = b.addRunArtifact(runner_tests);
    run_runner_tests.setCwd(.{ .cwd_relative = b.cache_root.path orelse ".zig-cache" });
    const native_config_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("support/build/native-config-tests.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run_native_config_tests = b.addRunArtifact(native_config_tests);
    run_native_config_tests.setCwd(.{ .cwd_relative = b.cache_root.path orelse ".zig-cache" });
    const context_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("support/build/build-context.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run_context_tests = b.addRunArtifact(context_tests);
    run_context_tests.setCwd(.{ .cwd_relative = b.cache_root.path orelse ".zig-cache" });
    const native_library_link_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("support/build/native-library-link.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run_native_library_link_tests = b.addRunArtifact(native_library_link_tests);
    run_native_library_link_tests.setCwd(.{ .cwd_relative = b.cache_root.path orelse ".zig-cache" });
    const elf_common_validator_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("support/build/elf-common-validator.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run_elf_common_validator_tests = b.addRunArtifact(elf_common_validator_tests);
    run_elf_common_validator_tests.setCwd(.{ .cwd_relative = b.cache_root.path orelse ".zig-cache" });
    const linker_script_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("support/build/linker-script.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run_linker_script_tests = b.addRunArtifact(linker_script_tests);
    run_linker_script_tests.setCwd(.{ .cwd_relative = b.cache_root.path orelse ".zig-cache" });
    const final_link_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("support/build/final-link.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run_final_link_tests = b.addRunArtifact(final_link_tests);
    run_final_link_tests.setCwd(.{ .cwd_relative = b.cache_root.path orelse ".zig-cache" });
    const native_qemu_graph_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("support/build/native-qemu-graph.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run_native_qemu_graph_tests = b.addRunArtifact(native_qemu_graph_tests);
    run_native_qemu_graph_tests.setCwd(.{ .cwd_relative = b.cache_root.path orelse ".zig-cache" });
    const native_postprocess_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("support/build/native-postprocess.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run_native_postprocess_tests = b.addRunArtifact(native_postprocess_tests);
    run_native_postprocess_tests.setCwd(.{ .cwd_relative = b.cache_root.path orelse ".zig-cache" });
    const test_step = b.step(
        "test",
        "Test facade, native configuration, native linking, QEMU graphs, and post-processing",
    );
    test_step.dependOn(&run_facade_tests.step);
    test_step.dependOn(&run_runner_tests.step);
    test_step.dependOn(&run_native_config_tests.step);
    test_step.dependOn(&run_context_tests.step);
    test_step.dependOn(&run_native_library_link_tests.step);
    test_step.dependOn(&run_elf_common_validator_tests.step);
    test_step.dependOn(&run_native_qemu_graph_tests.step);
    test_step.dependOn(&run_linker_script_tests.step);
    test_step.dependOn(&run_final_link_tests.step);
    test_step.dependOn(&run_native_postprocess_tests.step);
    const integration_output = resolvePath(
        b.allocator,
        root,
        b.cache_root.path orelse ".zig-cache",
    );
    const native_postprocess_integration = b.addSystemCommand(&.{
        "python3",
        "support/build/tests/native-postprocess-test.py",
        "--work-dir",
        integration_output,
        "--base",
        root,
    });
    native_postprocess_integration.setCwd(.{ .cwd_relative = root });
    native_postprocess_integration.setEnvironmentVariable("PYTHONDONTWRITEBYTECODE", "1");
    test_step.dependOn(&native_postprocess_integration.step);
    const acme_integration_output = std.fs.path.join(
        b.allocator,
        &.{ integration_output, "native-config-acme" },
    ) catch @panic("out of memory");
    const integration_metadata = std.fs.path.join(
        b.allocator,
        &.{ acme_integration_output, "metadata.tsv" },
    ) catch @panic("out of memory");
    const acme_config = resolvePath(
        b.allocator,
        root,
        "support/build/tests/native-config/x86_64-acme.config",
    );
    const acme_platform = resolvePath(
        b.allocator,
        root,
        "support/build/tests/native-config/external-platform/provider",
    );
    const export_integration_metadata = b.addSystemCommand(&.{
        "python3",
        "support/build/native-config-metadata.py",
        "--base",
        root,
        "--app",
        root,
        "--output",
        acme_integration_output,
        "--config",
        acme_config,
        "--metadata",
        integration_metadata,
        "--external-platform",
        acme_platform,
    });
    export_integration_metadata.setCwd(.{ .cwd_relative = root });
    export_integration_metadata.setEnvironmentVariable("PYTHONDONTWRITEBYTECODE", "1");
    const inspect_acme_config = b.addRunArtifact(native_config_tool);
    inspect_acme_config.addArgs(&.{ "inspect", acme_config, integration_metadata });
    inspect_acme_config.setCwd(.{ .cwd_relative = root });
    inspect_acme_config.step.dependOn(&export_integration_metadata.step);
    test_step.dependOn(&inspect_acme_config.step);
    const validate_acme_config = b.addRunArtifact(native_config_tool);
    validate_acme_config.addArgs(&.{ "validate", acme_config, integration_metadata });
    validate_acme_config.setCwd(.{ .cwd_relative = root });
    validate_acme_config.step.dependOn(&export_integration_metadata.step);
    test_step.dependOn(&validate_acme_config.step);
    const fixture_app = resolvePath(
        b.allocator,
        root,
        "support/build/tests/native-config/fixture-app",
    );
    const fixture_library = resolvePath(
        b.allocator,
        root,
        "support/build/tests/native-config/external-library/libfixture",
    );
    const x86_config = resolvePath(
        b.allocator,
        root,
        "support/build/tests/native-config/x86_64-kvm.config",
    );
    const x86_expected_header = resolvePath(
        b.allocator,
        root,
        "support/build/tests/native-config/x86_64-kvm.h",
    );
    const x86_integration_output = std.fs.path.join(
        b.allocator,
        &.{ integration_output, "native-config-x86" },
    ) catch @panic("out of memory");
    const x86_metadata = std.fs.path.join(
        b.allocator,
        &.{ x86_integration_output, "metadata.tsv" },
    ) catch @panic("out of memory");
    const x86_generated_header = std.fs.path.join(
        b.allocator,
        &.{ x86_integration_output, "config.h" },
    ) catch @panic("out of memory");
    const export_x86_metadata = b.addSystemCommand(&.{
        "python3",
        "support/build/native-config-metadata.py",
        "--base",
        root,
        "--app",
        fixture_app,
        "--output",
        x86_integration_output,
        "--config",
        x86_config,
        "--metadata",
        x86_metadata,
        "--external-library",
        fixture_library,
    });
    export_x86_metadata.setCwd(.{ .cwd_relative = root });
    export_x86_metadata.setEnvironmentVariable("PYTHONDONTWRITEBYTECODE", "1");
    const generate_x86_header = b.addRunArtifact(native_config_tool);
    generate_x86_header.addArgs(&.{ "header", x86_config, x86_metadata, x86_generated_header });
    generate_x86_header.setCwd(.{ .cwd_relative = root });
    generate_x86_header.step.dependOn(&export_x86_metadata.step);
    const compare_x86_header = b.addSystemCommand(&.{
        "cmp",
        x86_expected_header,
        x86_generated_header,
    });
    compare_x86_header.step.dependOn(&generate_x86_header.step);
    test_step.dependOn(&compare_x86_header.step);
    const version_integration_output = std.fs.path.join(
        b.allocator,
        &.{ integration_output, "native-config-version-test" },
    ) catch @panic("out of memory");
    const version_work_dir = std.fs.path.join(
        b.allocator,
        &.{ version_integration_output, "cases" },
    ) catch @panic("out of memory");
    const prepare_version_fragment = b.addSystemCommand(&.{
        "python3",
        "support/build/tests/native-config/version-metadata-test.py",
        "--base",
        root,
        "--work-dir",
        version_work_dir,
        "--prepare-output",
        version_integration_output,
    });
    prepare_version_fragment.setCwd(.{ .cwd_relative = root });
    prepare_version_fragment.setEnvironmentVariable("PYTHONDONTWRITEBYTECODE", "1");
    const version_config = resolvePath(
        b.allocator,
        root,
        "support/build/tests/native-config/version-metadata.config",
    );
    const version_library = resolvePath(
        b.allocator,
        root,
        "support/build/tests/native-config/versioned-library",
    );
    const version_expected_header = resolvePath(
        b.allocator,
        root,
        "support/build/tests/native-config/version-metadata.h",
    );
    const version_metadata = std.fs.path.join(
        b.allocator,
        &.{ version_integration_output, "metadata.tsv" },
    ) catch @panic("out of memory");
    const version_generated_header = std.fs.path.join(
        b.allocator,
        &.{ version_integration_output, "config.h" },
    ) catch @panic("out of memory");
    const export_version_metadata = b.addSystemCommand(&.{
        "python3",
        "support/build/native-config-metadata.py",
        "--base",
        root,
        "--app",
        root,
        "--output",
        version_integration_output,
        "--config",
        version_config,
        "--metadata",
        version_metadata,
        "--external-library",
        version_library,
    });
    export_version_metadata.setCwd(.{ .cwd_relative = root });
    export_version_metadata.setEnvironmentVariable("PYTHONDONTWRITEBYTECODE", "1");
    export_version_metadata.step.dependOn(&prepare_version_fragment.step);
    const generate_version_header = b.addRunArtifact(native_config_tool);
    generate_version_header.addArgs(&.{
        "header",
        version_config,
        version_metadata,
        version_generated_header,
    });
    generate_version_header.setCwd(.{ .cwd_relative = root });
    generate_version_header.step.dependOn(&export_version_metadata.step);
    const compare_version_header = b.addSystemCommand(&.{
        "cmp",
        version_expected_header,
        version_generated_header,
    });
    compare_version_header.step.dependOn(&generate_version_header.step);
    test_step.dependOn(&compare_version_header.step);
    const runner_link_targets = [_]struct {
        name: []const u8,
        query: std.Target.Query,
    }{
        .{
            .name = "x86_64-macos",
            .query = .{ .cpu_arch = .x86_64, .os_tag = .macos },
        },
        .{
            .name = "aarch64-macos",
            .query = .{ .cpu_arch = .aarch64, .os_tag = .macos },
        },
        .{
            .name = "x86_64-openbsd",
            .query = .{ .cpu_arch = .x86_64, .os_tag = .openbsd },
        },
    };
    for (runner_link_targets) |link_target| {
        const runner_link_test = b.addExecutable(.{
            .name = b.fmt("unikraft-zig-make-{s}", .{link_target.name}),
            .root_module = b.createModule(.{
                .root_source_file = b.path("support/build/zig-facade-runner.zig"),
                .target = b.resolveTargetQuery(link_target.query),
                .optimize = .ReleaseSafe,
                .link_libc = true,
            }),
        });
        test_step.dependOn(&runner_link_test.step);
    }
}

fn registerNativeQemuGraph(
    b: *std.Build,
    context: build_context.Context,
) ?*native_qemu_graph.RegisteredGraph {
    const step = b.step(
        "native-link-graph",
        "Register the native hello-world QEMU link graph without executing it",
    );
    const profile_name = b.option(
        []const u8,
        "native-qemu-graph",
        "Registered native graph: qemu-x86_64 or qemu-arm64",
    ) orelse {
        const fail = b.addFail(
            "native-link-graph requires -Dnative-qemu-graph=qemu-x86_64 or qemu-arm64",
        );
        step.dependOn(&fail.step);
        return null;
    };
    const profile = native_qemu_graph.parseProfile(profile_name) catch {
        step.dependOn(&b.addFail(b.fmt(
            "unsupported native QEMU graph '{s}'; registered graphs are qemu-x86_64 and qemu-arm64",
            .{profile_name},
        )).step);
        return null;
    };

    const registration = b.allocator.create(native_qemu_graph.RegisteredGraph) catch {
        step.dependOn(&b.addFail("unable to allocate the native QEMU graph").step);
        return null;
    };
    registration.* = native_qemu_graph.RegisteredGraph.init(b.allocator, .{
        .roots = .{
            .base = context.base,
            .app = context.application,
            .output = context.output,
            .config = context.config,
        },
        .profile = profile,
    }) catch |err| {
        step.dependOn(&b.addFail(b.fmt(
            "unable to register native QEMU graph '{s}': {s}",
            .{ @tagName(profile), @errorName(err) },
        )).step);
        return null;
    };

    return registration;
}

fn addFailedTargets(b: *std.Build, message: []const u8) void {
    const fail = b.addFail(message);
    for (targets) |target| {
        const step = b.step(target.name, target.description);
        step.dependOn(&fail.step);
        if (std.mem.eql(u8, target.name, "all")) {
            b.default_step = step;
        }
    }
    const native_targets = [_]struct {
        name: []const u8,
        description: []const u8,
    }{
        .{
            .name = "config-inspect",
            .description = "Parse configuration and print the native architecture/platform selection",
        },
        .{
            .name = "config-validate",
            .description = "Validate typed configuration values and target selection without solving Kconfig",
        },
        .{
            .name = "config-header",
            .description = "Generate include/uk/bits/config.h directly from an existing solved .config",
        },
        .{
            .name = "native-link-graph",
            .description = "Register the native hello-world QEMU link graph without executing it",
        },
    };
    for (native_targets) |target| {
        b.step(target.name, target.description).dependOn(&fail.step);
    }
}

fn resolveOptionalPath(
    b: *std.Build,
    root: []const u8,
    name: []const u8,
    description: []const u8,
) ?[]const u8 {
    const value = b.option([]const u8, name, description) orelse return null;
    return resolvePath(b.allocator, root, value);
}

fn resolvePath(allocator: std.mem.Allocator, root: []const u8, path: []const u8) []const u8 {
    return std.fs.path.resolve(allocator, &.{ root, path }) catch @panic("out of memory");
}

fn resolvePathList(
    allocator: std.mem.Allocator,
    root: []const u8,
    paths: ?[]const []const u8,
) ?[]const u8 {
    const values = paths orelse return null;
    if (values.len == 0) return null;

    var resolved = std.array_list.Managed([]const u8).init(allocator);
    defer resolved.deinit();
    defer for (resolved.items) |path| allocator.free(path);
    for (values) |path| {
        resolved.append(resolvePath(allocator, root, path)) catch @panic("out of memory");
    }

    return std.mem.join(allocator, ":", resolved.items) catch @panic("out of memory");
}

fn joinPathList(
    allocator: std.mem.Allocator,
    paths: []const []const u8,
) ?[]const u8 {
    if (paths.len == 0) return null;
    return std.mem.join(allocator, ":", paths) catch @panic("out of memory");
}

fn canonicalizeMakePaths(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: *MakeOptions,
) !void {
    options.app = (try facade_paths.canonicalizeNearestExisting(
        allocator,
        io,
        options.app,
    )).path;
    if (options.config) |config| {
        options.config = (try facade_paths.canonicalizeNearestExisting(
            allocator,
            io,
            config,
        )).path;
    }
    options.external_libraries = try canonicalizePathList(
        allocator,
        io,
        options.external_libraries,
    );
    options.external_platforms = try canonicalizePathList(
        allocator,
        io,
        options.external_platforms,
    );
    options.exclusions = try canonicalizePathList(
        allocator,
        io,
        options.exclusions,
    );
}

fn canonicalizePathList(
    allocator: std.mem.Allocator,
    io: std.Io,
    value: ?[]const u8,
) !?[]const u8 {
    const paths = value orelse return null;
    var canonical = std.array_list.Managed([]const u8).init(allocator);
    defer canonical.deinit();
    var iterator = std.mem.splitScalar(u8, paths, ':');
    while (iterator.next()) |path| {
        try canonical.append((try facade_paths.canonicalizeNearestExisting(
            allocator,
            io,
            path,
        )).path);
    }
    return try std.mem.join(allocator, ":", canonical.items);
}

fn isDestructiveTarget(name: []const u8) bool {
    return std.mem.eql(u8, name, "clean-libs") or
        std.mem.eql(u8, name, "clean") or
        std.mem.eql(u8, name, "properclean") or
        std.mem.eql(u8, name, "distclean");
}

fn validatePaths(
    b: *std.Build,
    repository: []const u8,
    options: MakeOptions,
    output: facade_paths.CanonicalPath,
) ?[]const u8 {
    if (findUnsafeValue(options)) |value| {
        return b.fmt(
            "invalid {s} value: byte 0x{x:0>2} is outside the facade's conservative Make-safe character allowlist",
            .{ value.name, value.byte },
        );
    }

    validateOutputTarget(
        b.allocator,
        b.graph.io,
        repository,
        options.app,
        output,
    ) catch |err| {
        const protected_name = switch (err) {
            error.ProtectsRepository => "Unikraft repository",
            error.ProtectsApplication => "application",
            error.ExistingSourceDirectory => "existing source directory",
            error.ExistingUndedicatedDirectory => "existing directory without a Unikraft build marker",
            error.NotDirectory => "non-directory path",
            else => return b.fmt(
                "unable to validate canonical output '{s}': {s}",
                .{ output.path, @errorName(err) },
            ),
        };
        return b.fmt(
            "unsafe -Doutput '{s}': canonical target is an {s} and properclean deletes it recursively; use a new dedicated path such as '{s}{s}build'",
            .{ options.output, protected_name, options.app, std.fs.path.sep_str },
        );
    };
    return null;
}

const UnsafeValue = struct {
    name: []const u8,
    byte: u8,
};

fn findUnsafeValue(options: MakeOptions) ?UnsafeValue {
    const paths = [_]struct {
        name: []const u8,
        value: ?[]const u8,
        allow_colon: bool,
    }{
        .{ .name = "A", .value = options.app, .allow_colon = false },
        .{ .name = "O", .value = options.output, .allow_colon = false },
        .{ .name = "C", .value = options.config, .allow_colon = false },
        .{ .name = "L", .value = options.external_libraries, .allow_colon = true },
        .{ .name = "P", .value = options.external_platforms, .allow_colon = true },
        .{ .name = "E", .value = options.exclusions, .allow_colon = true },
    };
    for (paths) |path| {
        const value = path.value orelse continue;
        if (firstUnsafePathByte(value, path.allow_colon)) |byte| {
            return .{ .name = path.name, .byte = byte };
        }
    }

    if (options.image_name) |value| {
        if (firstUnsafeNameByte(value)) |byte| {
            return .{ .name = "N", .byte = byte };
        }
    }
    if (firstUnsafePathByte(options.command, false)) |byte| {
        return .{ .name = "make-command", .byte = byte };
    }

    const commands = [_]struct {
        name: []const u8,
        value: ?[]const u8,
    }{
        .{ .name = "CROSS_COMPILE", .value = options.cross_compile },
        .{ .name = "COMPILER", .value = options.compiler },
        .{ .name = "LINKER", .value = options.linker },
        .{ .name = "PARTIAL_LINKER", .value = options.partial_linker },
        .{ .name = "HOSTCC", .value = options.host_cc },
        .{ .name = "HOSTCXX", .value = options.host_cxx },
        .{ .name = "HOSTCFLAGS", .value = options.host_cflags },
    };
    for (commands) |command| {
        const value = command.value orelse continue;
        if (firstUnsafeCommandByte(value)) |byte| {
            return .{ .name = command.name, .byte = byte };
        }
    }
    return null;
}

fn firstUnsafePathByte(value: []const u8, allow_colon: bool) ?u8 {
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        if (std.mem.indexOfScalar(u8, "/._-+@", byte) != null) continue;
        if (allow_colon and byte == ':') continue;
        return byte;
    }
    return null;
}

fn firstUnsafeNameByte(value: []const u8) ?u8 {
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        if (std.mem.indexOfScalar(u8, "._-+@", byte) != null) continue;
        return byte;
    }
    return null;
}

fn firstUnsafeCommandByte(value: []const u8) ?u8 {
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte) or byte == ' ') continue;
        if (std.mem.indexOfScalar(u8, "/._-+@:,=", byte) != null) continue;
        return byte;
    }
    return null;
}

fn validateOutputValue(value: []const u8) error{EmptyOutput}!void {
    if (value.len == 0) return error.EmptyOutput;
}

fn validateOutputTarget(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    app: []const u8,
    output: facade_paths.CanonicalPath,
) !void {
    if (facade_paths.isSameOrAncestor(output.path, repository)) return error.ProtectsRepository;
    if (facade_paths.isSameOrAncestor(output.path, app)) return error.ProtectsApplication;
    if (!output.exists) return;

    const stat = try std.Io.Dir.cwd().statFile(io, output.path, .{});
    if (stat.kind != .directory) return error.NotDirectory;

    const app_build_lexical = try std.fs.path.join(allocator, &.{ app, "build" });
    defer allocator.free(app_build_lexical);
    const app_build = try facade_paths.canonicalizeNearestExisting(
        allocator,
        io,
        app_build_lexical,
    );
    defer allocator.free(app_build.path);
    const repository_build_lexical = try std.fs.path.join(allocator, &.{ repository, "build" });
    defer allocator.free(repository_build_lexical);
    const repository_build = try facade_paths.canonicalizeNearestExisting(
        allocator,
        io,
        repository_build_lexical,
    );
    defer allocator.free(repository_build.path);

    const is_dedicated =
        (std.mem.eql(u8, app_build.path, app_build_lexical) and
            facade_paths.isSameOrAncestor(app_build.path, output.path)) or
        (std.mem.eql(u8, repository_build.path, repository_build_lexical) and
            facade_paths.isSameOrAncestor(repository_build.path, output.path)) or
        facade_paths.hasBuildMarker(allocator, io, output.path);
    if (is_dedicated) return;

    if (facade_paths.isDescendant(repository, output.path) or
        facade_paths.isDescendant(app, output.path))
    {
        return error.ExistingSourceDirectory;
    }
    return error.ExistingUndedicatedDirectory;
}

fn validateDistcleanConfig(
    b: *std.Build,
    app: []const u8,
    config: []const u8,
) ?[]const u8 {
    const safe = distcleanConfigIsSafe(
        b.allocator,
        b.graph.io,
        app,
        config,
    ) catch |err| {
        return b.fmt(
            "distclean refused: unable to canonicalize configuration deletion targets for '{s}': {s}",
            .{ config, @errorName(err) },
        );
    };
    if (!safe) {
        return b.fmt(
            "distclean refused: configuration '{s}' or its metadata resolves outside application '{s}'; use an in-application -Dconfig path or remove it manually",
            .{ config, app },
        );
    }
    return null;
}

fn distcleanConfigIsSafe(
    allocator: std.mem.Allocator,
    io: std.Io,
    app: []const u8,
    config: []const u8,
) !bool {
    const config_dir = std.fs.path.dirname(config) orelse {
        return false;
    };
    const config_basename = std.fs.path.basename(config);
    const deletion_targets = [_][]const u8{
        config,
        try std.fmt.allocPrint(allocator, "{s}.old", .{config}),
        try std.fmt.allocPrint(allocator, "{s}{s}.{s}.tmp", .{ config_dir, std.fs.path.sep_str, config_basename }),
        try std.fmt.allocPrint(allocator, "{s}{s}.auto.deps", .{ config_dir, std.fs.path.sep_str }),
    };
    defer {
        for (deletion_targets[1..]) |target| allocator.free(target);
    }
    for (deletion_targets) |target| {
        const canonical = facade_paths.canonicalizeNearestExisting(
            allocator,
            io,
            target,
        ) catch |err| return err;
        defer allocator.free(canonical.path);
        if (!facade_paths.isDescendant(app, canonical.path)) {
            return false;
        }
    }
    return true;
}

fn addMakeCommand(
    b: *std.Build,
    make_runner: *std.Build.Step.Compile,
    output: []const u8,
    root: []const u8,
    target: []const u8,
    options: MakeOptions,
) *std.Build.Step.Run {
    const argv = makeArguments(b.allocator, target, options);
    const run = b.addRunArtifact(make_runner);
    run.addArg(output);
    run.addArgs(argv);
    run.setCwd(.{ .cwd_relative = root });
    return run;
}

fn makeArguments(
    allocator: std.mem.Allocator,
    target: []const u8,
    options: MakeOptions,
) []const []const u8 {
    var argv = std.array_list.Managed([]const u8).init(allocator);
    argv.append(options.command) catch @panic("out of memory");
    argv.append("--no-print-directory") catch @panic("out of memory");
    argv.append(target) catch @panic("out of memory");

    appendAssignment(allocator, &argv, "A", options.app);
    appendAssignment(allocator, &argv, "O", options.output);
    appendOptionalAssignment(allocator, &argv, "C", options.config);
    appendOptionalAssignment(allocator, &argv, "N", options.image_name);
    appendOptionalAssignment(allocator, &argv, "L", options.external_libraries);
    appendOptionalAssignment(allocator, &argv, "P", options.external_platforms);
    appendOptionalAssignment(allocator, &argv, "E", options.exclusions);

    if (options.verbosity) |value| {
        appendAssignment(allocator, &argv, "V", @tagName(value));
    }
    appendOptionalAssignment(allocator, &argv, "CROSS_COMPILE", options.cross_compile);
    appendOptionalAssignment(allocator, &argv, "COMPILER", options.compiler);
    appendOptionalAssignment(allocator, &argv, "LINKER", options.linker);
    appendOptionalAssignment(allocator, &argv, "PARTIAL_LINKER", options.partial_linker);
    if (options.partial_linker_type) |value| {
        appendAssignment(allocator, &argv, "PARTIAL_LINKER_TYPE", @tagName(value));
    }
    if (options.compiler_targeted) |value| {
        appendAssignment(allocator, &argv, "COMPILER_TARGETED", if (value) "y" else "n");
    }
    appendOptionalAssignment(allocator, &argv, "HOSTCC", options.host_cc);
    appendOptionalAssignment(allocator, &argv, "HOSTCXX", options.host_cxx);
    appendOptionalAssignment(allocator, &argv, "HOSTCFLAGS", options.host_cflags);

    for (options.forwarded) |assignment| {
        argv.append(assignment) catch @panic("out of memory");
    }
    return argv.toOwnedSlice() catch @panic("out of memory");
}

fn appendOptionalAssignment(
    allocator: std.mem.Allocator,
    argv: *std.array_list.Managed([]const u8),
    name: []const u8,
    value: ?[]const u8,
) void {
    appendAssignment(allocator, argv, name, value orelse return);
}

fn appendAssignment(
    allocator: std.mem.Allocator,
    argv: *std.array_list.Managed([]const u8),
    name: []const u8,
    value: []const u8,
) void {
    argv.append(std.fmt.allocPrint(allocator, "{s}={s}", .{ name, value }) catch @panic("out of memory")) catch
        @panic("out of memory");
}

fn validateForwardedAssignment(assignment: []const u8) error{InvalidAssignment}!void {
    const separator = std.mem.indexOfScalar(u8, assignment, '=') orelse return error.InvalidAssignment;
    const name = assignment[0..separator];
    if (name.len == 0 or !isMakeNameStart(name[0])) return error.InvalidAssignment;
    for (name[1..]) |character| {
        if (!isMakeNameContinue(character)) return error.InvalidAssignment;
    }
    if (!isAllowedAssignment(name)) return error.InvalidAssignment;
    if (firstUnsafeCommandByte(assignment[separator + 1 ..]) != null) return error.InvalidAssignment;
}

fn isMakeNameStart(character: u8) bool {
    return std.ascii.isAlphabetic(character) or character == '_';
}

fn isMakeNameContinue(character: u8) bool {
    return isMakeNameStart(character) or std.ascii.isDigit(character);
}

fn isAllowedAssignment(name: []const u8) bool {
    const allowed = [_][]const u8{
        "ARCH",
        "LLVM_TARGET_ARCH",
        "AR",
        "RANLIB",
        "NM",
        "READELF",
        "STRIP",
        "OBJCOPY",
        "OBJDUMP",
        "DTC",
        "HOSTAR",
        "HOSTAS",
        "HOSTCPP",
        "HOSTLD",
        "HOSTLN",
        "HOSTNM",
        "HOSTOBJCOPY",
        "HOSTRANLIB",
        "UK_ASFLAGS",
        "UK_CFLAGS",
        "UK_CXXFLAGS",
        "UK_GOCFLAGS",
        "UK_LDFLAGS",
    };
    for (allowed) |candidate| {
        if (std.mem.eql(u8, name, candidate)) return true;
    }
    return false;
}

test "Make assignments remain single arguments" {
    const options = MakeOptions{
        .command = "gmake",
        .app = "/workspace/app",
        .output = "/workspace/output",
        .config = "/workspace/configs/test",
        .image_name = "hello",
        .external_libraries = "/workspace/lib-one:/workspace/lib-two",
        .external_platforms = null,
        .exclusions = null,
        .verbosity = .@"2",
        .cross_compile = null,
        .compiler = "zig cc -target x86_64-freestanding-none",
        .linker = null,
        .partial_linker = "zig ld.lld",
        .partial_linker_type = .raw,
        .compiler_targeted = true,
        .host_cc = "zig cc",
        .host_cxx = "zig c++",
        .host_cflags = "-fno-sanitize=null",
        .forwarded = &.{"AR=zig ar"},
    };
    const actual = makeArguments(std.testing.allocator, "images", options);
    defer {
        for (actual[3 .. actual.len - 1]) |argument| std.testing.allocator.free(argument);
        std.testing.allocator.free(actual);
    }

    const expected = [_][]const u8{
        "gmake",
        "--no-print-directory",
        "images",
        "A=/workspace/app",
        "O=/workspace/output",
        "C=/workspace/configs/test",
        "N=hello",
        "L=/workspace/lib-one:/workspace/lib-two",
        "V=2",
        "COMPILER=zig cc -target x86_64-freestanding-none",
        "PARTIAL_LINKER=zig ld.lld",
        "PARTIAL_LINKER_TYPE=raw",
        "COMPILER_TARGETED=y",
        "HOSTCC=zig cc",
        "HOSTCXX=zig c++",
        "HOSTCFLAGS=-fno-sanitize=null",
        "AR=zig ar",
    };
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |expected_argument, actual_argument| {
        try std.testing.expectEqualStrings(expected_argument, actual_argument);
    }
}

test "output path rejects repository and application deletion hazards" {
    const repository = "/workspace/unikraft";
    const app = "/workspace/apps/hello";

    try std.testing.expectError(
        error.ProtectsRepository,
        validateOutputTarget(
            std.testing.allocator,
            std.testing.io,
            repository,
            app,
            .{ .path = repository, .exists = true },
        ),
    );
    try std.testing.expectError(
        error.ProtectsRepository,
        validateOutputTarget(
            std.testing.allocator,
            std.testing.io,
            repository,
            app,
            .{ .path = "/workspace", .exists = true },
        ),
    );
    try std.testing.expectError(
        error.ProtectsApplication,
        validateOutputTarget(
            std.testing.allocator,
            std.testing.io,
            repository,
            app,
            .{ .path = app, .exists = true },
        ),
    );
    try std.testing.expectError(
        error.ProtectsApplication,
        validateOutputTarget(
            std.testing.allocator,
            std.testing.io,
            repository,
            app,
            .{ .path = "/workspace/apps", .exists = true },
        ),
    );

    try validateOutputTarget(
        std.testing.allocator,
        std.testing.io,
        repository,
        app,
        .{ .path = "/workspace/build", .exists = false },
    );
    try validateOutputTarget(
        std.testing.allocator,
        std.testing.io,
        repository,
        app,
        .{ .path = "/workspace/unikraft/build", .exists = false },
    );
    try validateOutputTarget(
        std.testing.allocator,
        std.testing.io,
        repository,
        app,
        .{ .path = "/workspace/apps/hello/build", .exists = false },
    );
}

test "missing output defaults to a safe app build directory" {
    const app = "/workspace/apps/hello";
    const output = resolvePath(std.testing.allocator, app, "build");
    defer std.testing.allocator.free(output);

    try std.testing.expectEqualStrings("/workspace/apps/hello/build", output);
    try validateOutputTarget(
        std.testing.allocator,
        std.testing.io,
        "/workspace/unikraft",
        app,
        .{ .path = output, .exists = false },
    );
}

test "dot and parent output values resolve to protected paths" {
    const repository = "/workspace/unikraft";
    const app = "/workspace/apps/hello";
    const dot = resolvePath(std.testing.allocator, repository, ".");
    defer std.testing.allocator.free(dot);
    const parent = resolvePath(std.testing.allocator, repository, "..");
    defer std.testing.allocator.free(parent);

    try std.testing.expectError(
        error.ProtectsRepository,
        validateOutputTarget(
            std.testing.allocator,
            std.testing.io,
            repository,
            app,
            .{ .path = dot, .exists = true },
        ),
    );
    try std.testing.expectError(
        error.ProtectsRepository,
        validateOutputTarget(
            std.testing.allocator,
            std.testing.io,
            repository,
            app,
            .{ .path = parent, .exists = true },
        ),
    );
}

test "canonical output rejects source directories and symlink aliases" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDirPath(std.testing.io, "repo/lib");
    try temporary.dir.createDirPath(std.testing.io, "repo/build");
    try temporary.dir.createDirPath(std.testing.io, "app");
    try temporary.dir.createDirPath(std.testing.io, "external");
    try temporary.dir.symLink(std.testing.io, "repo/lib", "source-alias", .{ .is_directory = true });
    try temporary.dir.symLink(std.testing.io, "../repo/lib", "app/build", .{ .is_directory = true });

    const root = try testDirPath(std.testing.allocator, temporary.dir);
    defer std.testing.allocator.free(root);
    const repository = try std.fs.path.join(std.testing.allocator, &.{ root, "repo" });
    defer std.testing.allocator.free(repository);
    const app = try std.fs.path.join(std.testing.allocator, &.{ root, "app" });
    defer std.testing.allocator.free(app);

    const source_lexical = try std.fs.path.join(std.testing.allocator, &.{ repository, "lib" });
    defer std.testing.allocator.free(source_lexical);
    const source = try facade_paths.canonicalizeNearestExisting(
        std.testing.allocator,
        std.testing.io,
        source_lexical,
    );
    defer std.testing.allocator.free(source.path);
    try std.testing.expectError(
        error.ExistingSourceDirectory,
        validateOutputTarget(std.testing.allocator, std.testing.io, repository, app, source),
    );

    const alias_lexical = try std.fs.path.join(std.testing.allocator, &.{ root, "source-alias" });
    defer std.testing.allocator.free(alias_lexical);
    const alias = try facade_paths.canonicalizeNearestExisting(
        std.testing.allocator,
        std.testing.io,
        alias_lexical,
    );
    defer std.testing.allocator.free(alias.path);
    try std.testing.expectEqualStrings(source.path, alias.path);
    try std.testing.expectError(
        error.ExistingSourceDirectory,
        validateOutputTarget(std.testing.allocator, std.testing.io, repository, app, alias),
    );

    const app_build_alias_lexical = try std.fs.path.join(std.testing.allocator, &.{ app, "build" });
    defer std.testing.allocator.free(app_build_alias_lexical);
    const app_build_alias = try facade_paths.canonicalizeNearestExisting(
        std.testing.allocator,
        std.testing.io,
        app_build_alias_lexical,
    );
    defer std.testing.allocator.free(app_build_alias.path);
    try std.testing.expectError(
        error.ExistingSourceDirectory,
        validateOutputTarget(std.testing.allocator, std.testing.io, repository, app, app_build_alias),
    );

    const build_lexical = try std.fs.path.join(std.testing.allocator, &.{ repository, "build" });
    defer std.testing.allocator.free(build_lexical);
    const build_output = try facade_paths.canonicalizeNearestExisting(
        std.testing.allocator,
        std.testing.io,
        build_lexical,
    );
    defer std.testing.allocator.free(build_output.path);
    try validateOutputTarget(
        std.testing.allocator,
        std.testing.io,
        repository,
        app,
        build_output,
    );

    const external_lexical = try std.fs.path.join(std.testing.allocator, &.{ root, "external" });
    defer std.testing.allocator.free(external_lexical);
    const external = try facade_paths.canonicalizeNearestExisting(
        std.testing.allocator,
        std.testing.io,
        external_lexical,
    );
    defer std.testing.allocator.free(external.path);
    try std.testing.expectError(
        error.ExistingUndedicatedDirectory,
        validateOutputTarget(std.testing.allocator, std.testing.io, repository, app, external),
    );
}

test "canonicalization follows symlinks through nearest existing ancestor" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDirPath(std.testing.io, "real");
    try temporary.dir.symLink(std.testing.io, "real", "alias", .{ .is_directory = true });

    const root = try testDirPath(std.testing.allocator, temporary.dir);
    defer std.testing.allocator.free(root);
    const requested = try std.fs.path.join(std.testing.allocator, &.{ root, "alias/missing/build" });
    defer std.testing.allocator.free(requested);
    const expected = try std.fs.path.join(std.testing.allocator, &.{ root, "real/missing/build" });
    defer std.testing.allocator.free(expected);
    const canonical = try facade_paths.canonicalizeNearestExisting(
        std.testing.allocator,
        std.testing.io,
        requested,
    );
    defer std.testing.allocator.free(canonical.path);

    try std.testing.expect(!canonical.exists);
    try std.testing.expectEqualStrings(expected, canonical.path);
}

test "Make path normalization preserves the single canonical output result" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDirPath(std.testing.io, "app");

    const root = try testDirPath(std.testing.allocator, temporary.dir);
    defer std.testing.allocator.free(root);
    const requested = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "app/build" },
    );
    defer std.testing.allocator.free(requested);
    const canonical = try facade_paths.canonicalizeNearestExisting(
        std.testing.allocator,
        std.testing.io,
        requested,
    );
    defer std.testing.allocator.free(canonical.path);
    try std.testing.expect(!canonical.exists);

    var options = testingMakeOptions();
    const app_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ root, "app" },
    );
    defer std.testing.allocator.free(app_path);
    options.app = app_path;
    options.output = canonical.path;
    options.config = null;
    options.external_libraries = null;
    options.external_platforms = null;
    options.exclusions = null;
    const output_pointer = options.output.ptr;

    try canonicalizeMakePaths(std.testing.allocator, std.testing.io, &options);
    defer std.testing.allocator.free(options.app);
    try std.testing.expectEqual(output_pointer, options.output.ptr);
    try std.testing.expectEqualStrings(canonical.path, options.output);
}

test "distclean configuration targets stay inside the canonical app tree" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDirPath(std.testing.io, "app");
    try temporary.dir.createDirPath(std.testing.io, "external");
    try temporary.dir.writeFile(std.testing.io, .{
        .sub_path = "external/config",
        .data = "CONFIG_TEST=y\n",
    });

    const root = try testDirPath(std.testing.allocator, temporary.dir);
    defer std.testing.allocator.free(root);
    const app = try std.fs.path.join(std.testing.allocator, &.{ root, "app" });
    defer std.testing.allocator.free(app);
    const normal_config = try std.fs.path.join(std.testing.allocator, &.{ app, ".config" });
    defer std.testing.allocator.free(normal_config);
    try std.testing.expect(try distcleanConfigIsSafe(
        std.testing.allocator,
        std.testing.io,
        app,
        normal_config,
    ));

    const external_config = try std.fs.path.join(std.testing.allocator, &.{ root, "external/config" });
    defer std.testing.allocator.free(external_config);
    try std.testing.expect(!try distcleanConfigIsSafe(
        std.testing.allocator,
        std.testing.io,
        app,
        external_config,
    ));
    try std.testing.expect(!try distcleanConfigIsSafe(
        std.testing.allocator,
        std.testing.io,
        app,
        "/etc/passwd",
    ));

    try temporary.dir.symLink(std.testing.io, "/etc/passwd", "app/.config", .{});
    try std.testing.expect(!try distcleanConfigIsSafe(
        std.testing.allocator,
        std.testing.io,
        app,
        normal_config,
    ));

    try temporary.dir.deleteFile(std.testing.io, "app/.config");
    try temporary.dir.writeFile(std.testing.io, .{
        .sub_path = "app/.config",
        .data = "CONFIG_TEST=y\n",
    });
    try temporary.dir.symLink(std.testing.io, "/etc/passwd", "app/.config.old", .{});
    try std.testing.expect(!try distcleanConfigIsSafe(
        std.testing.allocator,
        std.testing.io,
        app,
        normal_config,
    ));
}

test "empty output and unsafe facade values are rejected" {
    try std.testing.expectError(error.EmptyOutput, validateOutputValue(""));
    try validateOutputValue("/workspace/apps/hello/build");

    const Field = enum { app, output, config, libraries, platforms, exclusions };
    const cases = [_]struct {
        field: Field,
        make_name: []const u8,
    }{
        .{ .field = .app, .make_name = "A" },
        .{ .field = .output, .make_name = "O" },
        .{ .field = .config, .make_name = "C" },
        .{ .field = .libraries, .make_name = "L" },
        .{ .field = .platforms, .make_name = "P" },
        .{ .field = .exclusions, .make_name = "E" },
    };
    for (cases) |case| {
        var options = testingMakeOptions();
        switch (case.field) {
            .app => options.app = "/workspace/app path",
            .output => options.output = "/workspace/output path",
            .config => options.config = "/workspace/config path",
            .libraries => options.external_libraries = "/workspace/library path",
            .platforms => options.external_platforms = "/workspace/platform path",
            .exclusions => options.exclusions = "/workspace/excluded path",
        }
        const invalid = findUnsafeValue(options).?;
        try std.testing.expectEqualStrings(case.make_name, invalid.name);
    }
    try std.testing.expect(findUnsafeValue(testingMakeOptions()) == null);

    var image_options = testingMakeOptions();
    image_options.image_name = "image#comment";
    try std.testing.expectEqualStrings("N", findUnsafeValue(image_options).?.name);

    var command_options = testingMakeOptions();
    command_options.command = "make;true";
    try std.testing.expectEqualStrings("make-command", findUnsafeValue(command_options).?.name);

    const CommandField = enum {
        cross_compile,
        compiler,
        linker,
        partial_linker,
        host_cc,
        host_cxx,
        host_cflags,
    };
    const command_cases = [_]struct {
        field: CommandField,
        make_name: []const u8,
    }{
        .{ .field = .cross_compile, .make_name = "CROSS_COMPILE" },
        .{ .field = .compiler, .make_name = "COMPILER" },
        .{ .field = .linker, .make_name = "LINKER" },
        .{ .field = .partial_linker, .make_name = "PARTIAL_LINKER" },
        .{ .field = .host_cc, .make_name = "HOSTCC" },
        .{ .field = .host_cxx, .make_name = "HOSTCXX" },
        .{ .field = .host_cflags, .make_name = "HOSTCFLAGS" },
    };
    for (command_cases) |case| {
        var options = testingMakeOptions();
        switch (case.field) {
            .cross_compile => options.cross_compile = "tool;true",
            .compiler => options.compiler = "tool;true",
            .linker => options.linker = "tool;true",
            .partial_linker => options.partial_linker = "tool;true",
            .host_cc => options.host_cc = "tool;true",
            .host_cxx => options.host_cxx = "tool;true",
            .host_cflags => options.host_cflags = "flag;true",
        }
        try std.testing.expectEqualStrings(case.make_name, findUnsafeValue(options).?.name);
    }
}

test "Make and shell metacharacters are rejected conservatively" {
    const unsafe_values = [_][]const u8{
        "/d/victim;true",
        "/d/victim$(true)",
        "/d/victim`true`",
        "/d/victim*",
        "/d/victim#comment",
        "/d/victim%pattern",
        "/d/victim\"quoted",
        "/d/victim'quoted",
        "/d/victim\\escaped",
        "/d/victim\nnext",
        "/d/victim&next",
        "/d/victim|next",
        "/d/victim<next",
        "/d/victim>next",
    };
    for (unsafe_values) |value| {
        try std.testing.expect(firstUnsafePathByte(value, false) != null);
        try std.testing.expect(firstUnsafeCommandByte(value) != null);
    }

    try std.testing.expect(firstUnsafePathByte("/d/safe-_.+@/name", false) == null);
    try std.testing.expect(firstUnsafePathByte("/d/lib-one:/d/lib_two", true) == null);
    try std.testing.expect(firstUnsafeNameByte("safe-_.+@name") == null);
    try std.testing.expect(firstUnsafeCommandByte("zig cc -target x86_64-freestanding-none") == null);
}

test "path lists resolve from the repository root" {
    const actual = resolvePathList(
        std.testing.allocator,
        "/workspace/unikraft",
        &.{ "libs/lib-one", "/opt/platform" },
    ).?;
    defer std.testing.allocator.free(actual);

    try std.testing.expectEqualStrings(
        "/workspace/unikraft/libs/lib-one:/opt/platform",
        actual,
    );
}

test "forwarded Make assignments require allowlisted names" {
    try validateForwardedAssignment("AR=zig ar");
    try validateForwardedAssignment("UK_CFLAGS=-std=gnu17");
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("not-an-assignment"));
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("-j=8"));
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("A=../app"));
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("BUILD_DIR=/etc"));
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("_O=/"));
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("UK_CONFIG=/etc/passwd"));
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("CONFIG_DIR=/etc"));
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("C=/etc/passwd"));
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("UK_CLEAN=/"));
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("UK_LDEPS=/etc/passwd"));
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("AR=zig ar;true"));
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("UK_CFLAGS=$(shell true)"));
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("UK_LDFLAGS=-Wl,*"));
}

fn testingMakeOptions() MakeOptions {
    return .{
        .command = "make",
        .app = "/workspace/apps/hello",
        .output = "/workspace/apps/hello/build",
        .config = "/workspace/apps/hello/.config",
        .image_name = null,
        .external_libraries = "/workspace/libs",
        .external_platforms = "/workspace/platforms",
        .exclusions = "/workspace/excluded",
        .verbosity = null,
        .cross_compile = null,
        .compiler = null,
        .linker = null,
        .partial_linker = null,
        .partial_linker_type = null,
        .compiler_targeted = null,
        .host_cc = null,
        .host_cxx = null,
        .host_cflags = null,
        .forwarded = &.{},
    };
}

fn testDirPath(allocator: std.mem.Allocator, directory: std.Io.Dir) ![]u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try directory.realPath(std.testing.io, &buffer);
    return allocator.dupe(u8, buffer[0..length]);
}
