// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const foundation = @import("authority.build.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
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
    const module = b.createModule(.{ .root_source_file = b.path("authority/authorization.zig"), .target = target, .optimize = optimize });
    foundation.addImports(b, module, target, optimize, core, serial, validator, handoff);
    const root = b.option([]const u8, "test-root", "Existing private absolute fixture root") orelse @panic("-Dtest-root is required");
    const options_step = foundation.testOptions(b, target, optimize, root);
    const options = options_step.createModule();
    module.addImport("test_options", options);
    handoff.addImport("test_options", options);
    const test_module = b.createModule(.{ .root_source_file = b.path("authority/authorization_tests.zig"), .target = target, .optimize = optimize });
    foundation.addImports(b, test_module, target, optimize, core, serial, validator, handoff);
    test_module.addImport("test_options", options);
    const tests = b.addTest(.{ .root_module = test_module });
    const run = b.addRunArtifact(tests);
    // Use the handler's own types to avoid duplicate Zig module identities.
    const source = b.addWriteFiles().add("authorization-source-root.zig",
        \\const authorization = @import("authorization");
        \\export fn authorizationSourceCheck(ctx: *const authorization.Context, command: *const authorization.Command) u16 {
        \\    return switch (authorization.run(ctx.*, command.*)) {
        \\        .success => |owner| result: { owner.deinit(); break :result 0; },
        \\        .refused, .poisoned => |failure| @intFromError(failure.err),
        \\    };
        \\}
    );
    const check = b.addObject(.{
        .name = "authorization-source-check",
        .root_module = b.createModule(.{
            .root_source_file = source,
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "authorization", .module = module }},
        }),
    });
    const step = b.step("test", "Test source authorization recording without an installed command");
    step.dependOn(&run.step);
    step.dependOn(&check.step);
}
