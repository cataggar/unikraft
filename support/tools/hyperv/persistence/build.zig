const std = @import("std");
pub fn build(b: *std.Build) void {
    b.cache_root.path = b.cache_root.handle.realPathFileAlloc(b.graph.io, ".", b.allocator) catch
        @panic("cannot canonicalize the selected fixture cache");
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_root = b.option([]const u8, "test-root", "Existing private absolute fixture directory");
    const timing = b.option(bool, "persistence-timing", "Synthetic timing only (inside unchanged deadlines; never installed)") orelse false;
    const filter = b.option([]const u8, "test-filter", "Run only matching native fixture names");
    const strip_debug = b.option(bool, "strip-fixture-debug", "QUALIFICATION ONLY: verify a debug-stripped synthetic persistence worker copy") orelse false;
    const file_relayout = b.option(bool, "fixture-file-relayout", "QUALIFICATION ONLY: explicitly verify file-offset-only ELF relayout") orelse false;
    if (file_relayout and !strip_debug) @panic("fixture-file-relayout requires strip-fixture-debug=true");
    const layout_policy = if (file_relayout) "file_offset_relayout" else "identical_program_headers";
    const objcopy = b.option([]const u8, "fixture-objcopy", "Explicit absolute pinned native llvm-objcopy for QUALIFICATION ONLY");
    if (strip_debug and objcopy == null) @panic("strip-fixture-debug=true requires -Dfixture-objcopy=ABS");
    if (objcopy) |path| {
        if (!strip_debug) @panic("fixture-objcopy requires strip-fixture-debug=true");
        if (!std.fs.path.isAbsolute(path)) @panic("fixture-objcopy must be absolute");
    }
    const strip_report = b.option([]const u8, "strip-fixture-report", "Optional private create-only absolute persistence worker qualification report");
    if (strip_report) |path| {
        if (!strip_debug) @panic("strip-fixture-report requires strip-fixture-debug=true");
        if (!std.fs.path.isAbsolute(path)) @panic("strip-fixture-report must be absolute");
    }
    const sdk = b.dependency("azure_sdk_core", .{ .target = target, .optimize = optimize }).module("azure_sdk_core");
    const storage = b.dependency("azure_sdk_storage_common", .{ .target = target, .optimize = optimize }).module("azure_sdk_storage_common");
    const core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = target, .optimize = optimize });
    const azure = b.createModule(.{
        .root_source_file = b.path("../azure/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "azure_sdk_core", .module = sdk }, .{ .name = "hyperv_core", .module = core } },
    });
    const transfer = b.createModule(.{
        .root_source_file = b.path("../transfer/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "azure_sdk_core", .module = sdk },               .{ .name = "hyperv_core", .module = core },
            .{ .name = "azure_sdk_storage_common", .module = storage },
        },
    });
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "hyperv_core", .module = core },         .{ .name = "hyperv_azure", .module = azure },
        .{ .name = "hyperv_transfer", .module = transfer }, .{ .name = "azure_sdk_core", .module = sdk },
    };
    const module = b.addModule("hyperv_persistence", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    });
    const cli = b.addExecutable(.{
        .name = "uk-hyperv-persistence-engine",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{ .{ .name = "hyperv_persistence", .module = module }, .{ .name = "hyperv_core", .module = core } },
        }),
    });
    b.installArtifact(cli);
    const test_options = b.addOptions();
    test_options.addOption(bool, "persistence_timing", timing);
    test_options.addOption(?[]const u8, "test_root", test_root);
    test_options.addOptionPath("cli", cli.getEmittedBin());
    const worker_fixture = b.addExecutable(.{
        .name = "hyperv-persistence-worker-fixture",
        .root_module = b.createModule(.{ .root_source_file = b.path("worker_fixture.zig"), .target = target, .optimize = optimize, .imports = imports }),
    });
    const measurement = b.createModule(.{ .root_source_file = b.path("../synthetic_measurement.zig"), .target = target, .optimize = optimize });
    worker_fixture.root_module.addImport("synthetic_measurement", measurement);
    const fixture_options = b.addOptions();
    fixture_options.addOption(bool, "persistence_timing", timing);
    worker_fixture.root_module.addOptions("fixture_options", fixture_options);
    const raw_worker = worker_fixture.getEmittedBin();
    const selected_worker = if (strip_debug) stripped: {
        const strip = b.addSystemCommand(&.{ objcopy.?, "--strip-debug" });
        strip.addFileInput(.{ .cwd_relative = objcopy.? });
        strip.addFileArg(raw_worker);
        break :stripped strip.addOutputFileArg("hyperv-persistence-worker-fixture");
    } else raw_worker;
    test_options.addOptionPath("worker", selected_worker);
    const gate_core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = b.graph.host, .optimize = .ReleaseSafe });
    const gate_elf = b.createModule(.{ .root_source_file = b.path("../../../build/postprocess-elf.zig"), .target = b.graph.host, .optimize = .ReleaseSafe });
    const equivalence = b.createModule(.{
        .root_source_file = b.path("../preparation/namespace/fixture_debug_equivalence.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
        .imports = &.{ .{ .name = "hyperv_core", .module = gate_core }, .{ .name = "producer_elf", .module = gate_elf } },
    });
    const qualification = b.createModule(.{
        .root_source_file = b.path("fixture_strip.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
        .imports = &.{.{ .name = "equivalence", .module = equivalence }},
    });
    const verifier = b.addExecutable(.{
        .name = "persistence-fixture-strip-verifier",
        .root_module = b.createModule(.{
            .root_source_file = b.path("fixture_strip_verifier.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .imports = &.{.{ .name = "qualification", .module = qualification }},
        }),
    });
    const check: ?*std.Build.Step.Run = if (strip_debug) checked: {
        const verify = b.addRunArtifact(verifier);
        // Cached candidates and an omitted report still require fresh reads.
        verify.has_side_effects = true;
        verify.addFileArg(raw_worker);
        verify.addFileArg(selected_worker);
        verify.addArgs(&.{ "--layout-policy", layout_policy });
        if (strip_report) |path| verify.addArgs(&.{ "--report", path });
        verify.expectExitCode(0);
        break :checked verify;
    } else null;
    const qualify = b.step("qualify-fixture", "Qualify only the non-installed synthetic persistence worker");
    if (check) |verify| qualify.dependOn(&verify.step) else qualify.dependOn(&b.addFail("qualify-fixture requires strip-fixture-debug=true").step);
    const gate_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("../preparation/namespace/fixture_debug_equivalence_tests.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "equivalence", .module = equivalence }},
    }) });
    const run_gate_tests = b.addRunArtifact(gate_tests);
    run_gate_tests.setCwd(.{ .cwd_relative = test_root orelse b.cache_root.path.? });
    const gate_test_step = b.step("test-strip-equivalence", "Run the existing 13 shared ELF and private-file qualification cases");
    gate_test_step.dependOn(&run_gate_tests.step);
    const proof_options = b.addOptions();
    proof_options.addOptionPath("raw", raw_worker);
    proof_options.addOptionPath("candidate", selected_worker);
    proof_options.addOption(bool, "qualified", strip_debug);
    proof_options.addOption(bool, "file_relayout", file_relayout);
    const proof_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("fixture_strip_tests.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "qualification", .module = qualification }},
    }) });
    proof_tests.root_module.addOptions("strip_options", proof_options);
    const run_proof_tests = b.addRunArtifact(proof_tests);
    run_proof_tests.setCwd(.{ .cwd_relative = test_root orelse b.cache_root.path.? });
    const proof_test_step = b.step("test-strip-proof", "Test the single persistence-worker proof and explicit verifier options");
    proof_test_step.dependOn(&run_proof_tests.step);
    const tests = b.addTest(.{ .filters = if (filter) |value| &.{value} else &.{}, .root_module = b.createModule(.{
        .root_source_file = b.path("tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    }) });
    tests.root_module.addOptions("test_options", test_options);
    tests.root_module.addImport("synthetic_measurement", measurement);
    const run = b.addRunArtifact(tests);
    b.step("test", "Run offline persistence engine fixtures").dependOn(&run.step);
    const arm_tests = b.addTest(.{ .root_module = azure });
    const arm_run = b.addRunArtifact(arm_tests);
    b.step("test-arm", "Run the affected shared ARM fixtures").dependOn(&arm_run.step);
    if (check) |verify| {
        for ([_]*std.Build.Step{ &run.step, &arm_run.step, &run_gate_tests.step, &run_proof_tests.step, b.getInstallStep() }) |step|
            step.dependOn(&verify.step);
    }
    b.installArtifact(b.addLibrary(.{ .name = "hyperv-persistence", .root_module = module, .linkage = .static }));
}
