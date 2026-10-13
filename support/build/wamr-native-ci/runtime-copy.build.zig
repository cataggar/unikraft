// SPDX-License-Identifier: BSD-3-Clause
//! Standalone source-only COPY qualification; no installed command.
const std = @import("std");
const foundation = @import("authority.build.zig");
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
        .imports = &.{ .{ .name = "hyperv_core", .module = core }, .{ .name = "local_boot_serial", .module = serial } },
    });
    const controller = b.createModule(.{
        .root_source_file = b.path("controller/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "wamr_log_validator", .module = validator },
            .{ .name = "controller_source_closure", .module = b.createModule(.{ .root_source_file = b.path("../../controller_source_closure.zig"), .target = target, .optimize = optimize }) },
            .{ .name = "handoff_contracts", .module = b.createModule(.{ .root_source_file = b.path("handoff/contracts.zig"), .target = target, .optimize = optimize, .imports = &.{.{ .name = "hyperv_core", .module = core }} }) },
        },
    });
    const handoff = b.createModule(.{
        .root_source_file = b.path("handoff/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "hyperv_core", .module = core }, .{ .name = "wamr_controller", .module = controller } },
    });
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("authority/runtime_copy_tests.zig"),
        .target = target,
        .optimize = optimize,
    }) });
    foundation.addImports(b, tests.root_module, target, optimize, core, serial, validator, handoff);
    const options = b.addOptions();
    options.addOption([]const u8, "fixture_root", b.option([]const u8, "test-root", "Private synthetic fixtures") orelse @panic("test-root required"));
    options.addOption(bool, "oracle_keep_first", b.option(bool, "oracle-keep-first", "Retain synthetic COPY output for Python oracle") orelse false);
    tests.root_module.addImport("test_options", options.createModule());
    const run = b.addRunArtifact(tests);
    const production = b.createModule(.{ .root_source_file = b.path("authority/runtime_copy.zig"), .target = target, .optimize = optimize });
    foundation.addImports(b, production, target, optimize, core, serial, validator, handoff);
    const generated = b.addWriteFiles();
    const source = generated.add("runtime-copy-source-check.zig",
        \\const copy = @import("runtime_copy");
        \\const parameters = @typeInfo(@TypeOf(copy.Stage.init)).@"fn".params;
        \\export fn copyCheck(ctx: *const parameters[0].type.?, request: *const parameters[1].type.?, inventory: *const parameters[2].type.?) u16 {
        \\    var stage = copy.Stage.init(ctx.*, request.*, inventory.*) catch |err| return @intFromError(err);
        \\    defer stage.deinit();
        \\    return switch (stage.copyStage()) {
        \\        .staged => 0,
        \\        .refused, .poisoned => |failure| @intFromError(failure.err),
        \\    };
        \\}
        \\const binding = @typeInfo(@TypeOf(copy.ManifestInputs.bindManifest)).@"fn".params;
        \\export fn bindCheck(stage: *copy.Stage, manifest: binding[2].type.?) u16 {
        \\    _ = stage.root() catch |err| return @intFromError(err);
        \\    _ = stage.layout() catch |err| return @intFromError(err);
        \\    stage.barrier().revalidate() catch |err| return @intFromError(err);
        \\    const inputs = stage.manifestInputs() catch |err| return @intFromError(err);
        \\    _ = inputs.bindManifest(stage.ctx, manifest) catch |err| return @intFromError(err);
        \\    return 0;
        \\}
    );
    const check = b.addObject(.{ .name = "runtime-copy-source-check", .root_module = b.createModule(.{
        .root_source_file = source,
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "runtime_copy", .module = production }},
    }) });
    const step = b.step("test", "Run source-only synthetic runtime COPY tests");
    step.dependOn(&run.step);
    step.dependOn(&check.step);
    b.step("check-source", "Compile the non-test library API without installing or running it").dependOn(&check.step);
}
