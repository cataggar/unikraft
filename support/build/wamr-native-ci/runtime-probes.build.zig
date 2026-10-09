// SPDX-License-Identifier: BSD-3-Clause
//! Focused source tests only. No executable is installed and no peer module is
//! required. The integrating authority build must provide producer_elf as well
//! as the existing authority imports.
const std = @import("std");
const foundation = @import("authority.build.zig");

fn imports(b: *std.Build, module: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, options: ?*std.Build.Module) void {
    const core = b.createModule(.{ .root_source_file = b.path("../../tools/hyperv/core.zig"), .target = target, .optimize = optimize });
    if (target.result.cpu.arch == .x86_64) core.addAssemblyFile(b.path("../../tools/hyperv/sha256_clear_upper.S"));
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
    const controller = b.createModule(.{
        .root_source_file = b.path("controller/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "wamr_log_validator", .module = validator },
            .{ .name = "controller_source_closure", .module = b.createModule(.{ .root_source_file = b.path("../../controller_source_closure.zig"), .target = target, .optimize = optimize }) },
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
    foundation.addImports(b, module, target, optimize, core, serial, validator, handoff);
    module.addImport("producer_elf", b.createModule(.{ .root_source_file = b.path("../postprocess-elf.zig"), .target = target, .optimize = optimize }));
    if (options) |value| {
        module.addImport("test_options", value);
        handoff.addImport("test_options", value);
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const fixture_root = b.option([]const u8, "test-root", "Existing private absolute source-only fixture root") orelse @panic("-Dtest-root is required");
    if (!std.fs.path.isAbsolute(fixture_root)) @panic("fixture root must be absolute");
    const fixture = b.addExecutable(.{
        .name = "authority-runtime-probe-fault-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("authority/runtime_probes_fixture.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const options = b.addOptions();
    options.addOption([]const u8, "fixture_root", fixture_root);
    options.addOptionPath("process_fixture", fixture.getEmittedBin());
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("authority/runtime_probes_tests.zig"),
        .target = target,
        .optimize = optimize,
    }) });
    const options_module = options.createModule();
    imports(b, tests.root_module, target, optimize, options_module);
    const run = b.addRunArtifact(tests);
    const x86 = b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu });
    const source = b.createModule(.{ .root_source_file = b.path("authority/runtime_probes.zig"), .target = x86, .optimize = optimize });
    imports(b, source, x86, optimize, null);
    const generated = b.addWriteFiles();
    const check_source = generated.add("runtime-probes-source-check.zig",
        \\const p = @import("runtime_probes");
        \\export fn checkDiscovery(ctx: *const p.Context, input: *const p.DiscoveryInput) u16 {
        \\    var result = p.discover(ctx.*, input.*) catch |err| return @intFromError(err);
        \\    result.deinit();
        \\    return 0;
        \\}
        \\export fn checkCopied(ctx: *const p.Context, input: *const p.CopiedInput) u16 {
        \\    _ = p.inspectCopied(ctx.*, input.*) catch |err| return @intFromError(err);
        \\    const sealed = p.sealCopied(ctx.*, input.*) catch |err| return @intFromError(err);
        \\    sealed.close(ctx.io);
        \\    return 0;
        \\}
        \\export fn checkSealed(ctx: *const p.Context, input: *const p.SealedInput) u16 {
        \\    return switch (p.runSealed(ctx.*, input.*)) {
        \\        .complete => 0,
        \\        .refused => |failure| @intFromError(failure.cause),
        \\    };
        \\}
    );
    const source_check = b.addObject(.{ .name = "authority-runtime-probes-source-check", .root_module = b.createModule(.{
        .root_source_file = check_source,
        .target = x86,
        .optimize = optimize,
        .imports = &.{.{ .name = "runtime_probes", .module = source }},
    }) });
    const step = b.step("test", "Run native source-only runtime ELF/probe tests");
    step.dependOn(&run.step);
    step.dependOn(&source_check.step);
    b.step("source-check", "Typecheck complete x86_64 source paths without running a runtime").dependOn(&source_check.step);
}
