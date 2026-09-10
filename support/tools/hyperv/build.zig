const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_root = b.option([]const u8, "test-root", "Existing private absolute directory for native filesystem fixtures");
    const core = b.addModule("hyperv_core", .{
        .root_source_file = b.path("core.zig"),
        .target = target,
        .optimize = optimize,
    });
    const transfer = b.addModule("hyperv_transfer", transferOptions(b, core, target, optimize));
    const aggregate = b.addModule("hyperv", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "hyperv_transfer", .module = transfer },
        },
    });
    const cli = b.addExecutable(.{
        .name = "uk-hyperv",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "hyperv", .module = aggregate }},
        }),
    });
    b.installArtifact(cli);

    const fixture = b.addExecutable(.{
        .name = "hyperv-process-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("process_fixture.zig"),
            .target = b.graph.host,
        }),
    });
    const options = b.addOptions();
    options.addOption(?[]const u8, "test_root", test_root);
    options.addOptionPath("process_fixture", fixture.getEmittedBin());
    const host_core = b.createModule(.{
        .root_source_file = b.path("core.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "hyperv", .module = host_core }},
        }),
    });
    tests.root_module.addOptions("test_options", options);
    const run_tests = b.addRunArtifact(tests);
    const core_step = b.step("test-core", "Run shared native core fixtures");
    core_step.dependOn(&run_tests.step);
    const host_transfer = b.createModule(transferOptions(b, host_core, b.graph.host, optimize));
    const transfer_tests = b.addTest(.{ .root_module = host_transfer });
    const transfer_run = b.addRunArtifact(transfer_tests);
    transfer_run.setCwd(.{ .cwd_relative = test_root orelse b.pathFromRoot("../../../.d/zig-migration-transfer-core/fixtures") });
    const transfer_step = b.step("test-transfer", "Run offline streaming transfer fixtures");
    transfer_step.dependOn(&transfer_run.step);
    const host_aggregate = b.createModule(.{
        .root_source_file = b.path("root.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = host_core },
            .{ .name = "hyperv_transfer", .module = host_transfer },
        },
    });
    const host_cli = b.addExecutable(.{
        .name = "hyperv-cli-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "hyperv", .module = host_aggregate }},
        }),
    });
    const worker_fixture = b.addExecutable(.{
        .name = "hyperv-transfer-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("transfer/worker_fixture.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "hyperv", .module = host_aggregate },
                .{ .name = "azure_sdk_core", .module = b.dependency("azure_sdk_core", .{ .target = b.graph.host, .optimize = optimize }).module("azure_sdk_core") },
            },
        }),
    });
    const worker_options = b.addOptions();
    worker_options.addOption(?[]const u8, "test_root", test_root);
    worker_options.addOptionPath("worker_fixture", worker_fixture.getEmittedBin());
    worker_options.addOptionPath("cli", host_cli.getEmittedBin());
    const worker_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("transfer/worker_tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "hyperv", .module = host_aggregate }},
        }),
    });
    worker_tests.root_module.addOptions("test_options", worker_options);
    const worker_step = b.step("test-worker", "Run restricted native child transfer and supervisor fixtures");
    worker_step.dependOn(&b.addRunArtifact(worker_tests).step);
    const all = b.step("test", "Run native core, transfer and supervised worker fixtures");
    all.dependOn(core_step);
    all.dependOn(transfer_step);
    all.dependOn(worker_step);
}

fn transferOptions(b: *std.Build, core: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) std.Build.Module.CreateOptions {
    const sdk = b.dependency("azure_sdk_core", .{ .target = target, .optimize = optimize });
    const storage = b.dependency("azure_sdk_storage_common", .{ .target = target, .optimize = optimize });
    return .{
        .root_source_file = b.path("transfer/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = b.allocator.dupe(std.Build.Module.Import, &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "azure_sdk_core", .module = sdk.module("azure_sdk_core") },
            .{ .name = "azure_sdk_storage_common", .module = storage.module("azure_sdk_storage_common") },
        }) catch @panic("out of memory"),
    };
}
