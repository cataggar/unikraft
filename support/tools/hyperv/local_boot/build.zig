const std = @import("std");

pub fn build(b: *std.Build) void {
    b.cache_root.path = b.cache_root.handle.realPathFileAlloc(b.graph.io, ".", b.allocator) catch
        @panic("cannot canonicalize the selected fixture cache");
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_root = b.option([]const u8, "test-root", "Existing absolute 0700 native fixture directory");
    const miz = b.dependency("miz_source", .{ .target = target, .optimize = optimize }).module("miz");
    const strip_debug = b.option(bool, "strip-fixture-debug", "TESTS ONLY: gate debug-stripped copies of the two uninstalled synthetic QEMU fixtures") orelse false;
    const objcopy = b.option([]const u8, "fixture-objcopy", "Explicit absolute pinned native llvm-objcopy for TESTS ONLY");
    if (strip_debug and objcopy == null) @panic("strip-fixture-debug=true requires -Dfixture-objcopy=ABS");
    if (objcopy) |path| {
        if (!strip_debug) @panic("fixture-objcopy requires strip-fixture-debug=true");
        if (!std.fs.path.isAbsolute(path)) @panic("fixture-objcopy must be absolute");
    }
    const strip_report = b.option([]const u8, "strip-fixture-report", "Optional private create-only absolute synthetic QEMU equivalence report");
    if (strip_report) |path| {
        if (!strip_debug) @panic("strip-fixture-report requires strip-fixture-debug=true");
        if (!std.fs.path.isAbsolute(path)) @panic("strip-fixture-report must be absolute");
    }
    const core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = target, .optimize = optimize });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../sha256_clear_upper.S"));
    const measurement = b.createModule(.{
        .root_source_file = b.path("../synthetic_measurement.zig"),
        .target = target,
        .optimize = optimize,
    });
    const diagnostics = b.createModule(.{
        .root_source_file = b.path("synthetic_diagnostics.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "synthetic_measurement", .module = measurement },
        },
    });
    const module = b.addModule("hyperv_local_boot", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "miz", .module = miz },
        },
    });
    const synthetic_module = b.createModule(.{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "miz", .module = miz },
            .{ .name = "synthetic_diagnostics", .module = diagnostics },
        },
    });
    const cli = b.addExecutable(.{
        .name = "uk-hyperv-local-boot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = optimize != .Debug,
            .imports = &.{.{ .name = "local_boot", .module = module }},
        }),
    });
    b.installArtifact(cli);
    const fixture = b.addExecutable(.{
        .name = "local-boot-qemu-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("fixture.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "local_boot", .module = module }},
        }),
    });
    const diagnostic_cli = b.addExecutable(.{
        .name = "local-boot-cli-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("synthetic_cli.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "local_boot", .module = synthetic_module }},
        }),
    });
    const diagnostic_fixture = b.addExecutable(.{
        .name = "local-boot-qemu-diagnostic-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("synthetic_qemu.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "local_boot", .module = synthetic_module },
                .{ .name = "synthetic_diagnostics", .module = diagnostics },
            },
        }),
    });
    const raw_plain = fixture.getEmittedBin();
    const raw_diagnostic = diagnostic_fixture.getEmittedBin();
    const selected_plain = if (strip_debug) strippedCopy(b, objcopy.?, raw_plain, "local-boot-qemu-fixture") else raw_plain;
    const selected_diagnostic = if (strip_debug) strippedCopy(b, objcopy.?, raw_diagnostic, "local-boot-qemu-diagnostic-fixture") else raw_diagnostic;
    const gate_core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = b.graph.host, .optimize = .ReleaseSafe });
    if (b.graph.host.result.cpu.arch == .x86_64)
        gate_core.addAssemblyFile(b.path("../sha256_clear_upper.S"));
    const gate_elf = b.createModule(.{ .root_source_file = b.path("../../../build/postprocess-elf.zig"), .target = b.graph.host, .optimize = .ReleaseSafe });
    const equivalence = b.createModule(.{
        .root_source_file = b.path("../preparation/namespace/fixture_debug_equivalence.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
        .imports = &.{ .{ .name = "hyperv_core", .module = gate_core }, .{ .name = "producer_elf", .module = gate_elf } },
    });
    const verifier = b.addExecutable(.{
        .name = "local-boot-fixture-debug-equivalence",
        .root_module = b.createModule(.{
            .root_source_file = b.path("../preparation/namespace/fixture_debug_verifier.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .imports = &.{.{ .name = "equivalence", .module = equivalence }},
        }),
    });
    const gate = b.step("qualify-fixtures", "Verify both current uninstalled synthetic QEMU copies before any fixture execution");
    if (strip_debug) {
        for ([_]std.Build.LazyPath{ raw_plain, raw_diagnostic }, [_]std.Build.LazyPath{ selected_plain, selected_diagnostic }) |raw, candidate| {
            const check = b.addRunArtifact(verifier);
            // Never let a cached candidate substitute for reading this pair.
            check.has_side_effects = true;
            check.addArg("pair");
            check.addFileArg(raw);
            check.addFileArg(candidate);
            check.addArgs(&.{ "--layout-policy", "file_offset_relayout" });
            check.expectExitCode(0);
            gate.dependOn(&check.step);
        }
    } else gate.dependOn(&b.addFail("qualify-fixtures requires strip-fixture-debug=true").step);
    const gate_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("../preparation/namespace/fixture_debug_equivalence_tests.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "equivalence", .module = equivalence }},
    }) });
    const run_gate_tests = b.addRunArtifact(gate_tests);
    run_gate_tests.setCwd(.{ .cwd_relative = test_root orelse b.cache_root.path.? });
    b.step("test-strip-equivalence", "Reuse native ELF, relayout and private-file refusal fixtures").dependOn(&run_gate_tests.step);
    const proof_options = b.addOptions();
    proof_options.addOption(bool, "stripped", strip_debug);
    proof_options.addOptionPath("raw_plain", raw_plain);
    proof_options.addOptionPath("plain", selected_plain);
    proof_options.addOptionPath("raw_diagnostic", raw_diagnostic);
    proof_options.addOptionPath("diagnostic", selected_diagnostic);
    proof_options.addOptionPath("verifier", verifier.getEmittedBin());
    proof_options.addOption(?[]const u8, "report", strip_report);
    const proof_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("fixture_strip_tests.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "equivalence", .module = equivalence }},
    }) });
    proof_tests.root_module.addOptions("strip_options", proof_options);
    const run_proof_tests = b.addRunArtifact(proof_tests);
    run_proof_tests.has_side_effects = true;
    run_proof_tests.setCwd(.{ .cwd_relative = test_root orelse b.cache_root.path.? });
    if (strip_debug) run_proof_tests.step.dependOn(gate);
    b.step("test-strip-proof", "Verify selected synthetic pairs, preserved raw files and verifier refusals").dependOn(&run_proof_tests.step);
    const options = b.addOptions();
    options.addOptionPath("cli", diagnostic_cli.getEmittedBin());
    options.addOptionPath("fixture", selected_diagnostic);
    options.addOptionPath("production_cli", cli.getEmittedBin());
    options.addOptionPath("plain_fixture", selected_plain);
    options.addOption(?[]const u8, "test_root", test_root);
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "local_boot", .module = synthetic_module },
            .{ .name = "synthetic_diagnostics", .module = diagnostics },
        },
    }) });
    tests.root_module.addOptions("test_options", options);
    const run = b.addRunArtifact(tests);
    if (strip_debug) {
        run.step.dependOn(gate);
        run.step.dependOn(&run_proof_tests.step);
        run_proof_tests.step.dependOn(&run_gate_tests.step);
    }
    b.step("test", "Run public synthetic local-boot fixtures, never a real guest").dependOn(&run.step);
    const hash_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("../sha256_tests.zig"),
        .target = target,
        .optimize = optimize,
    }) });
    if (target.result.cpu.arch == .x86_64)
        hash_tests.root_module.addAssemblyFile(b.path("../sha256_clear_upper.S"));
    const run_hash_tests = b.addRunArtifact(hash_tests);
    b.step("test-sha256", "Check full-byte standard SHA equivalence and streaming boundaries").dependOn(&run_hash_tests.step);
    run.step.dependOn(&run_hash_tests.step);
}

fn strippedCopy(b: *std.Build, objcopy: []const u8, raw: std.Build.LazyPath, basename: []const u8) std.Build.LazyPath {
    const strip = b.addSystemCommand(&.{ objcopy, "--strip-debug" });
    strip.addFileInput(.{ .cwd_relative = objcopy });
    strip.addFileArg(raw);
    return strip.addOutputFileArg(basename);
}
