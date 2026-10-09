// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub fn addImports(b: *std.Build, module: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, core: *std.Build.Module, serial: *std.Build.Module, validator: *std.Build.Module, handoff: *std.Build.Module) void {
    module.addImport("hyperv_core", core);
    module.addImport("wamr_handoff", handoff);
    module.addImport("wamr_controller", handoff.import_table.get("wamr_controller").?);
    module.addImport("producer_elf", b.createModule(.{
        .root_source_file = b.path("../postprocess-elf.zig"),
        .target = target,
        .optimize = optimize,
    }));
    module.addImport("wamr_direct_compute", b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/direct/compute.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "local_serial", .module = serial },
            .{ .name = "wamr_log_validator", .module = validator },
        },
    }));
}

pub fn testOptions(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, fixture_root: []const u8) *std.Build.Step.Options {
    if (!std.fs.path.isAbsolute(fixture_root)) @panic("authority fixture root must be absolute");
    const fixture = b.addExecutable(.{
        .name = "authority-process-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("../../tools/hyperv/process_fixture.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const options = b.addOptions();
    options.addOption([]const u8, "fixture_root", fixture_root);
    options.addOptionPath("process_fixture", fixture.getEmittedBin());
    const probe_fixture = b.addExecutable(.{
        .name = "authority-runtime-probe-fault-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("authority/runtime_probes_fixture.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    options.addOptionPath("probe_fixture", probe_fixture.getEmittedBin());
    options.addOptionPath("validator", b.dependency("direct_validator", .{ .target = target, .optimize = .ReleaseSafe }).artifact("uk-wamr-direct-validate").getEmittedBin());
    const image = b.dependency("public_image", .{ .target = target, .optimize = optimize }).module("hyperv_public_image");
    const package = b.addExecutable(.{
        .name = "authorization-image-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("package.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "public_image", .module = image }},
        }),
    });
    options.addOptionPath("authorization_package", package.getEmittedBin());
    options.addOptionPath("authorization_fixture", b.path("authority/authorization_fixture.py"));
    return options;
}

pub fn sourceCheck(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, authority: *std.Build.Module) *std.Build.Step.Compile {
    const generated = b.addWriteFiles();
    const source = generated.add("authority-source-check.zig",
        \\const authority = @import("wamr_authority");
        \\export fn authoritySourceCheck(inputs: *const authority.types.PlanInputs, transaction: *authority.transaction.Transaction, barrier: *const authority.transaction.Barrier, bytes: [*]const u8, len: usize) u16 {
        \\    _ = authority.records.plan(inputs.*, null) catch |err| return @intFromError(err);
        \\    return switch (transaction.publish(bytes[0..len], barrier.*)) {
        \\        .success => 0,
        \\        .refused, .poisoned => |failure| @intFromError(failure.err),
        \\    };
        \\}
        \\export fn authorityHandlers(ctx: *const authority.handlers.Context, command: *const authority.types.Command) u16 {
        \\    return switch (authority.handlers.run(ctx.*, command.*)) {
        \\        .prepare => |outcome| switch (outcome) {
        \\            .success => |owner| result: { defer owner.deinit(); _ = owner.result() catch |err| break :result @intFromError(err); break :result 0; },
        \\            .refused, .poisoned => |failure| @intFromError(failure.err),
        \\        },
        \\        .plan => |outcome| switch (outcome) {
        \\            .success => |owner| result: { defer owner.deinit(); _ = owner.result() catch |err| break :result @intFromError(err); break :result 0; },
        \\            .refused, .poisoned => |failure| @intFromError(failure.err),
        \\        },
        \\        .authorization => |outcome| switch (outcome) {
        \\            .success => |owner| result: { defer owner.deinit(); owner.revalidate() catch |err| break :result @intFromError(err); _ = owner.value(); _ = owner.artifact(); break :result 0; },
        \\            .refused, .poisoned => |failure| @intFromError(failure.err),
        \\        },
        \\        .admission => |outcome| switch (outcome) {
        \\            .success => |owner| result: { defer owner.deinit(); _ = owner.artifact() catch |err| break :result @intFromError(err); break :result 0; },
        \\            .refused, .poisoned => |failure| @intFromError(failure.err),
        \\        },
        \\    };
        \\}
    );
    return b.addObject(.{
        .name = "authority-source-check",
        .root_module = b.createModule(.{
            .root_source_file = source,
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "wamr_authority", .module = authority }},
        }),
    });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.createModule(.{ .root_source_file = b.path("../../tools/hyperv/core.zig"), .target = target, .optimize = optimize });
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
    const identity_writer = b.addExecutable(.{
        .name = "authority-validator-identity",
        .root_module = b.createModule(.{ .root_source_file = b.path("build.zig"), .target = b.graph.host, .optimize = .ReleaseSafe }),
    });
    const identity_run = b.addRunArtifact(identity_writer);
    identity_run.addFileArg(b.dependency("direct_validator", .{ .target = target, .optimize = .ReleaseSafe }).artifact("uk-wamr-direct-validate").getEmittedBin());
    const identity = b.createModule(.{
        .root_source_file = b.addWriteFiles().addCopyFile(identity_run.captureStdOut(.{}), "authority-validator-identity.zig"),
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
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "wamr_controller", .module = controller },
        },
    });
    const filter = b.option([]const u8, "test-filter", "Run matching authority source tests");
    const filters = b.option([]const []const u8, "authority-test-filter", "Select bounded authority fixtures") orelse
        if (filter) |value| &.{value} else &.{};
    const tests = b.addTest(.{ .filters = filters, .root_module = b.createModule(.{
        .root_source_file = b.path("authority/library_tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    }) });
    addImports(b, tests.root_module, target, optimize, core, serial, validator, handoff);
    const fixture_root = b.option([]const u8, "test-root", "Existing private absolute authority fixture root") orelse std.fs.path.resolve(b.allocator, &.{ b.graph.cache.cwd, b.cache_root.path orelse "." }) catch @panic("cannot resolve authority fixture root");
    const options = testOptions(b, target, optimize, fixture_root);
    const options_module = options.createModule();
    tests.root_module.addImport("test_options", options_module);
    handoff.addImport("test_options", options_module);
    const run = b.addRunArtifact(tests);
    const authority = b.createModule(.{ .root_source_file = b.path("authority/root.zig"), .target = target, .optimize = optimize });
    addImports(b, authority, target, optimize, core, serial, validator, handoff);
    const source_check = sourceCheck(b, target, optimize, authority);
    const native_step = b.step("test-native", "Run native authority contracts and foundations");
    native_step.dependOn(&run.step);
    native_step.dependOn(&source_check.step);
    b.step("source-check", "Compile all real authority source library operations").dependOn(&source_check.step);
    const direct = b.addSystemCommand(&.{"/usr/bin/env"});
    direct.addFileArg(tests.getEmittedBin());
    const direct_step = b.step("test-native-direct", "Run native authority fixtures with direct failure output");
    direct_step.dependOn(&direct.step);
    direct_step.dependOn(&source_check.step);
    const python = b.addSystemCommand(&.{ "python3", "-B" });
    python.addFileArg(b.path("tests/test_authority_contract_goldens.py"));
    const step = b.step("test", "Run native authority foundations and Python contract goldens");
    step.dependOn(&run.step);
    step.dependOn(&source_check.step);
    step.dependOn(&python.step);
}
