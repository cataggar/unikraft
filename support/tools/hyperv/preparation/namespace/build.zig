// Standalone focused fixtures; no root build or dependency resolution.
const std = @import("std");

pub fn build(b: *std.Build) void {
    b.cache_root.path = b.cache_root.handle.realPathFileAlloc(b.graph.io, ".", b.allocator) catch
        @panic("cannot canonicalize the selected fixture cache");
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const workspace = b.option([]const u8, "workspace", "Explicit preparation validation subtree") orelse
        @panic("-Dworkspace is required");
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
    const core = b.createModule(.{ .root_source_file = b.path("../../core.zig"), .target = target, .optimize = optimize });
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
    const options = b.addOptions();
    options.addOption([]const u8, "workspace", workspace);
    options.addOption([]const u8, "git_executable", git_executable);
    options.addOption([]const u8, "git_loader", git_loader);
    options.addOption([]const []const u8, "git_libraries", git_libraries);
    options.addOptionPath("namespace_helper", helper.getEmittedBin());
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
    b.installArtifact(fixture);
    b.step("install-fixture", "Install only the native synthetic namespace fixture").dependOn(&b.addInstallArtifact(fixture, .{}).step);
    const child = b.addExecutable(.{
        .name = "preparation-process-fixture",
        .root_module = b.createModule(.{ .root_source_file = b.path("../process_fixture.zig"), .target = target, .optimize = optimize }),
    });
    const test_options = b.addOptions();
    test_options.addOptionPath("namespace_helper", helper.getEmittedBin());
    if (fixture_path) |path|
        test_options.addOption([]const u8, "namespace_fixture", path)
    else
        test_options.addOptionPath("namespace_fixture", fixture.getEmittedBin());
    test_options.addOption(?[]const u8, "ci_report", ci_report);
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
    run.setCwd(.{ .cwd_relative = workspace });
    b.step("test", "Run small native namespace and typed producer fixtures").dependOn(&run.step);
}
