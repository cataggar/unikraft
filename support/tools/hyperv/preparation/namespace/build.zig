// Standalone focused fixtures; no root build or dependency resolution.
const std = @import("std");

pub fn build(b: *std.Build) void {
    b.cache_root.path = b.cache_root.handle.realPathFileAlloc(b.graph.io, ".", b.allocator) catch
        @panic("cannot canonicalize the selected fixture cache");
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const workspace = b.option([]const u8, "workspace", "Explicit preparation validation subtree") orelse
        @panic("-Dworkspace is required");
    const exclusion = exclusionTests(b, target, optimize, workspace);
    if (b.option(bool, "observations-only", "Build only unprivileged synthetic namespace observation tests; no namespace fixture/helper") orelse false) {
        const observations = observationTests(b, target, optimize, workspace);
        observations.step.dependOn(&exclusion.step);
        return;
    }
    const git_executable = b.option([]const u8, "git-executable", "Explicit public native Git fixture executable") orelse
        @panic("-Dgit-executable is required");
    const git_loader = b.option([]const u8, "git-loader", "Explicit public native Git fixture ELF interpreter") orelse
        @panic("-Dgit-loader is required");
    const git_libraries = b.option([]const []const u8, "git-library", "Explicit public Git fixture library; repeat for the complete closure") orelse
        @panic("-Dgit-library is required");
    const filter = b.option([]const u8, "test-filter", "Run only matching standalone fixtures");
    const fixture_path = b.option([]const u8, "fixture-executable", "Existing absolute synthetic namespace fixture for TESTS ONLY");
    if (fixture_path) |path| if (!std.fs.path.isAbsolute(path)) @panic("fixture-executable must be absolute");
    const ci_report = b.option([]const u8, "ci-report", "Private absolute baseline report for TESTS ONLY");
    if (ci_report) |path| if (!std.fs.path.isAbsolute(path)) @panic("ci-report must be absolute");
    const strip_debug = b.option(bool, "strip-fixture-debug", "QUALIFICATION ONLY: verify post-compilation debug stripping of synthetic fixture copies") orelse false;
    const file_relayout = b.option(bool, "fixture-file-relayout", "QUALIFICATION ONLY: explicitly verify file-offset-only ELF relayout") orelse false;
    if (file_relayout and !strip_debug) @panic("fixture-file-relayout requires strip-fixture-debug=true");
    const layout_policy = if (file_relayout) "file_offset_relayout" else "identical_program_headers";
    const fixture_objcopy = b.option([]const u8, "fixture-objcopy", "Explicit absolute pinned native llvm-objcopy for QUALIFICATION ONLY");
    if (strip_debug and fixture_objcopy == null) @panic("strip-fixture-debug=true requires -Dfixture-objcopy=ABS");
    if (fixture_objcopy) |path| {
        if (!strip_debug) @panic("fixture-objcopy requires strip-fixture-debug=true");
        if (!std.fs.path.isAbsolute(path)) @panic("fixture-objcopy must be absolute");
    }
    const strip_report = b.option([]const u8, "strip-fixture-report", "Optional private create-only absolute equivalence report for QUALIFICATION ONLY");
    if (strip_report) |path| {
        if (!strip_debug) @panic("strip-fixture-report requires strip-fixture-debug=true");
        if (!std.fs.path.isAbsolute(path)) @panic("strip-fixture-report must be absolute");
    }
    const core = b.createModule(.{ .root_source_file = b.path("../../core.zig"), .target = target, .optimize = optimize });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../../sha256_clear_upper.S"));
    const measurement = b.createModule(.{
        .root_source_file = b.path("../../synthetic_measurement.zig"),
        .target = target,
        .optimize = optimize,
    });
    const elf = b.createModule(.{ .root_source_file = b.path("../../../../build/postprocess-elf.zig"), .target = target, .optimize = optimize });
    const paths = b.createModule(.{ .root_source_file = b.path("../../../../build/zig-facade-paths.zig"), .target = target, .optimize = optimize });
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "hyperv_core", .module = core },
        .{ .name = "producer_elf", .module = elf },
        .{ .name = "facade_paths", .module = paths },
    };
    const gate_core = b.createModule(.{ .root_source_file = b.path("../../core.zig"), .target = b.graph.host, .optimize = .ReleaseSafe });
    if (b.graph.host.result.cpu.arch == .x86_64)
        gate_core.addAssemblyFile(b.path("../../sha256_clear_upper.S"));
    const gate_elf = b.createModule(.{ .root_source_file = b.path("../../../../build/postprocess-elf.zig"), .target = b.graph.host, .optimize = .ReleaseSafe });
    const equivalence = b.createModule(.{
        .root_source_file = b.path("fixture_debug_equivalence.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
        .imports = &.{ .{ .name = "hyperv_core", .module = gate_core }, .{ .name = "producer_elf", .module = gate_elf } },
    });
    const verifier = b.addExecutable(.{
        .name = "fixture-debug-equivalence",
        .root_module = b.createModule(.{
            .root_source_file = b.path("fixture_debug_verifier.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .imports = &.{.{ .name = "equivalence", .module = equivalence }},
        }),
    });
    const gate_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("fixture_debug_equivalence_tests.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "equivalence", .module = equivalence }},
    }) });
    gate_tests.step.dependOn(&verifier.step);
    const run_gate_tests = b.addRunArtifact(gate_tests);
    run_gate_tests.setCwd(.{ .cwd_relative = workspace });
    b.step("test-strip-equivalence", "Test qualification-only ELF preservation and private file gates").dependOn(&run_gate_tests.step);
    const sample_raw = b.option([]const u8, "relayout-sample-raw", "Explicit read-only x64 regression data, never executed");
    const sample_candidate = b.option([]const u8, "relayout-sample-candidate", "Explicit read-only x64 regression candidate data, never executed");
    const sample_report = b.option([]const u8, "relayout-sample-report", "Optional private create-only report for the data-only regression");
    if ((sample_raw == null) != (sample_candidate == null) or (sample_report != null and sample_raw == null))
        @panic("relayout sample requires both raw and candidate data paths");
    for ([_]?[]const u8{ sample_raw, sample_candidate, sample_report }) |path| {
        if (path) |value| if (!std.fs.path.isAbsolute(value)) @panic("relayout sample paths must be absolute");
    }
    if (sample_raw) |raw_path| {
        const sample_options = b.addOptions();
        sample_options.addOption([]const u8, "raw", raw_path);
        sample_options.addOption([]const u8, "candidate", sample_candidate.?);
        sample_options.addOption(?[]const u8, "report", sample_report);
        const sample_tests = b.addTest(.{ .root_module = b.createModule(.{
            .root_source_file = b.path("fixture_debug_relayout_sample_tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "equivalence", .module = equivalence }},
        }) });
        sample_tests.root_module.addOptions("sample_options", sample_options);
        const run_sample = b.addRunArtifact(sample_tests);
        run_sample.has_side_effects = true;
        run_sample.addFileInput(.{ .cwd_relative = raw_path });
        run_sample.addFileInput(.{ .cwd_relative = sample_candidate.? });
        run_sample.setCwd(.{ .cwd_relative = workspace });
        b.step("test-strip-sample", "Compare the copied x64 regression data without executing it").dependOn(&run_sample.step);
    }
    const helper = b.addExecutable(.{
        .name = "preparation-namespace",
        .root_module = b.createModule(.{
            .root_source_file = b.path("../namespace_main.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = imports,
        }),
    });
    b.installArtifact(helper);
    const selected_helper = if (strip_debug) strippedCopy(b, fixture_objcopy.?, helper.getEmittedBin(), "preparation-namespace") else helper.getEmittedBin();
    const helper_gate: ?*std.Build.Step.Run = if (strip_debug) gate: {
        const check = b.addRunArtifact(verifier);
        check.has_side_effects = true;
        check.addArg("pair");
        check.addFileArg(helper.getEmittedBin());
        check.addFileArg(selected_helper);
        check.addArgs(&.{ "--layout-policy", layout_policy });
        check.expectExitCode(0);
        break :gate check;
    } else null;
    const options = b.addOptions();
    options.addOption([]const u8, "workspace", workspace);
    options.addOption([]const u8, "git_executable", git_executable);
    options.addOption([]const u8, "git_loader", git_loader);
    options.addOption([]const []const u8, "git_libraries", git_libraries);
    options.addOptionPath("namespace_helper", selected_helper);
    const fixture = b.addExecutable(.{
        .name = "preparation-namespace-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("../namespace_tests.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = imports,
        }),
    });
    fixture.root_module.addOptions("fixture_options", options);
    fixture.root_module.addImport("synthetic_measurement", measurement);
    if (helper_gate) |check| fixture.step.dependOn(&check.step);
    const selected_fixture = if (strip_debug) strippedCopy(b, fixture_objcopy.?, fixture.getEmittedBin(), "preparation-namespace-fixture") else fixture.getEmittedBin();
    const suite_gate: ?*std.Build.Step.Run = if (strip_debug) gate: {
        const check = b.addRunArtifact(verifier);
        // A path/options cache hit never substitutes for reading all current
        // raw, candidate and external-copy bytes on this invocation.
        check.has_side_effects = true;
        check.addArg("suite");
        check.addFileArg(helper.getEmittedBin());
        check.addFileArg(selected_helper);
        check.addFileArg(fixture.getEmittedBin());
        check.addFileArg(selected_fixture);
        check.addArgs(&.{ "--layout-policy", layout_policy });
        if (fixture_path) |path| {
            check.addArg("--external");
            check.addFileArg(.{ .cwd_relative = path });
        }
        if (strip_report) |path| check.addArgs(&.{ "--report", path });
        check.expectExitCode(0);
        break :gate check;
    } else null;
    const install_fixture: *std.Build.Step = if (strip_debug)
        &b.addInstallFileWithDir(selected_fixture, .bin, "preparation-namespace-fixture").step
    else
        &b.addInstallArtifact(fixture, .{}).step;
    if (suite_gate) |check| install_fixture.dependOn(&check.step);
    b.getInstallStep().dependOn(install_fixture);
    b.step("install-fixture", "Install only the native synthetic namespace fixture").dependOn(install_fixture);
    const child = b.addExecutable(.{
        .name = "preparation-process-fixture",
        .root_module = b.createModule(.{ .root_source_file = b.path("../process_fixture.zig"), .target = target, .optimize = optimize }),
    });
    const test_options = b.addOptions();
    const internal_probe = internalProbe(b, target, optimize, workspace);
    test_options.addOptionPath("internal_probe", internal_probe.getEmittedBin());
    test_options.addOptionPath("namespace_helper", selected_helper);
    if (fixture_path) |path|
        test_options.addOption([]const u8, "namespace_fixture", path)
    else
        test_options.addOptionPath("namespace_fixture", selected_fixture);
    test_options.addOption(?[]const u8, "ci_report", ci_report);
    test_options.addOption(bool, "strip_fixture_debug", strip_debug);
    test_options.addOptionPath("process_fixture", child.getEmittedBin());
    const tests = b.addTest(.{
        .filters = if (filter) |selected| &.{selected} else &.{ "namespace", "producer exact", "producer rejects", "producer vetoes", "producer native proof", "producer outcome" },
        .root_module = b.createModule(.{
            .root_source_file = b.path("../namespace_tests.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = imports,
        }),
    });
    tests.root_module.addOptions("fixture_options", options);
    tests.root_module.addOptions("test_options", test_options);
    tests.root_module.addImport("synthetic_measurement", measurement);
    const run = b.addRunArtifact(tests);
    run.step.dependOn(&exclusion.step);
    if (suite_gate) |check| run.step.dependOn(&check.step);
    run.setCwd(.{ .cwd_relative = workspace });
    b.step("test", "Run small native namespace and typed producer fixtures").dependOn(&run.step);
}

fn observationTests(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, workspace: []const u8) *std.Build.Step.Run {
    const core = b.createModule(.{ .root_source_file = b.path("../../core.zig"), .target = target, .optimize = optimize });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../../sha256_clear_upper.S"));
    const elf = b.createModule(.{ .root_source_file = b.path("../../../../build/postprocess-elf.zig"), .target = target, .optimize = optimize });
    const paths = b.createModule(.{ .root_source_file = b.path("../../../../build/zig-facade-paths.zig"), .target = target, .optimize = optimize });
    const measurement = b.createModule(.{ .root_source_file = b.path("../../synthetic_measurement.zig"), .target = target, .optimize = optimize });
    const tests = b.addTest(.{
        .filters = &.{"namespace observations "},
        .root_module = b.createModule(.{
            .root_source_file = b.path("../namespace_tests.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = &.{
                .{ .name = "hyperv_core", .module = core },
                .{ .name = "producer_elf", .module = elf },
                .{ .name = "facade_paths", .module = paths },
                .{ .name = "synthetic_measurement", .module = measurement },
            },
        }),
    });
    const options = b.addOptions();
    options.addOption([]const u8, "workspace", workspace);
    tests.root_module.addOptions("fixture_options", options);
    const test_options = b.addOptions();
    test_options.addOptionPath("internal_probe", internalProbe(b, target, optimize, workspace).getEmittedBin());
    tests.root_module.addOptions("test_options", test_options);
    const run = b.addRunArtifact(tests);
    run.setCwd(.{ .cwd_relative = workspace });
    b.step("test-observations", "Run only bounded observation format, phase, refusal and failure-retention tests").dependOn(&run.step);
    return run;
}

fn exclusionTests(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, workspace: []const u8) *std.Build.Step.Run {
    const core = b.createModule(.{ .root_source_file = b.path("../../core.zig"), .target = target, .optimize = optimize });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../../sha256_clear_upper.S"));
    const elf = b.createModule(.{ .root_source_file = b.path("../../../../build/postprocess-elf.zig"), .target = target, .optimize = optimize });
    const paths = b.createModule(.{ .root_source_file = b.path("../../../../build/zig-facade-paths.zig"), .target = target, .optimize = optimize });
    // Deliberately no synthetic_measurement or observer import in this root.
    const tests = b.addTest(.{ .filters = &.{"production root compiles"}, .root_module = b.createModule(.{
        .root_source_file = b.path("../namespace_observer_exclusion_tests.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = true,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "producer_elf", .module = elf },
            .{ .name = "facade_paths", .module = paths },
        },
    }) });
    const run = b.addRunArtifact(tests);
    run.setCwd(.{ .cwd_relative = workspace });
    b.step("test-observer-exclusion", "Compile hook-free shared roots and exercise only pre-IO refusals").dependOn(&run.step);
    return run;
}

fn internalProbe(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, workspace: []const u8) *std.Build.Step.Compile {
    const core = b.createModule(.{ .root_source_file = b.path("../../core.zig"), .target = target, .optimize = optimize });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../../sha256_clear_upper.S"));
    const elf = b.createModule(.{ .root_source_file = b.path("../../../../build/postprocess-elf.zig"), .target = target, .optimize = optimize });
    const paths = b.createModule(.{ .root_source_file = b.path("../../../../build/zig-facade-paths.zig"), .target = target, .optimize = optimize });
    const measurement = b.createModule(.{ .root_source_file = b.path("../../synthetic_measurement.zig"), .target = target, .optimize = optimize });
    const probe = b.addExecutable(.{ .name = "namespace-observer-probe", .root_module = b.createModule(.{
        .root_source_file = b.path("../namespace_observer_probe.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = true,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "producer_elf", .module = elf },
            .{ .name = "facade_paths", .module = paths },
            .{ .name = "synthetic_measurement", .module = measurement },
        },
    }) });
    const options = b.addOptions();
    options.addOption([]const u8, "workspace", workspace);
    probe.root_module.addOptions("fixture_options", options);
    return probe;
}

fn strippedCopy(b: *std.Build, objcopy: []const u8, raw: std.Build.LazyPath, basename: []const u8) std.Build.LazyPath {
    const strip = b.addSystemCommand(&.{ objcopy, "--strip-debug" });
    // The executable's contents, not only its argv spelling, key this output.
    strip.addFileInput(.{ .cwd_relative = objcopy });
    strip.addFileArg(raw);
    return strip.addOutputFileArg(basename);
}
