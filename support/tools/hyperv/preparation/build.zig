const std = @import("std");

pub fn build(b: *std.Build) void {
    b.cache_root.path = b.cache_root.handle.realPathFileAlloc(b.graph.io, ".", b.allocator) catch
        @panic("cannot canonicalize the selected preparation cache");
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const miz = b.dependency("miz_source", .{ .target = target, .optimize = optimize });
    const core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = target, .optimize = optimize });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../sha256_clear_upper.S"));
    const elf = b.createModule(.{ .root_source_file = b.path("../../../build/postprocess-elf.zig"), .target = target, .optimize = optimize });
    const kconfig = b.createModule(.{ .root_source_file = b.path("../../../build/kconfig.zig"), .target = target, .optimize = optimize });
    const paths = b.createModule(.{ .root_source_file = b.path("../../../build/zig-facade-paths.zig"), .target = target, .optimize = optimize });
    const miz_module = b.createModule(.{ .root_source_file = miz.path("packages/miz/src/root.zig"), .target = target, .optimize = optimize });
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "hyperv_core", .module = core },
        .{ .name = "producer_elf", .module = elf },
        .{ .name = "native_kconfig", .module = kconfig },
        .{ .name = "facade_paths", .module = paths },
        .{ .name = "miz", .module = miz_module },
    };
    const module = b.addModule("hyperv_preparation", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    });
    const executable = b.addExecutable(.{
        .name = "uk-hyperv-prepare",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = optimize != .Debug,
            .imports = &.{.{ .name = "preparation", .module = module }},
        }),
    });
    b.installArtifact(executable);
    const helper = b.addExecutable(.{
        .name = "preparation-namespace",
        .root_module = b.createModule(.{
            .root_source_file = b.path("namespace_main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = optimize != .Debug,
            .single_threaded = true,
            .link_libc = false,
            .imports = imports,
        }),
    });
    b.installArtifact(helper);
    const fixture = b.addExecutable(.{
        .name = "preparation-process-fixture",
        .root_module = b.createModule(.{ .root_source_file = b.path("process_fixture.zig"), .target = target, .optimize = optimize }),
    });
    const tests = b.addTest(.{ .filters = b.option([]const []const u8, "test-filter", "Run matching native tests; repeat to select multiple groups") orelse &.{}, .root_module = b.createModule(.{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    }) });
    const options = b.addOptions();
    options.addOption([]const u8, "proof_fixture", b.option([]const u8, "proof-fixture", "Explicit directory containing reviewed native proof source fixtures") orelse
        (std.fs.path.resolve(b.allocator, &.{ b.build_root.path.?, "../../../.." }) catch @panic("cannot resolve proof fixture root")));
    options.addOption(?[]const u8, "git_executable", b.option([]const u8, "git-executable", "Explicit public native Git fixture executable"));
    options.addOption(?[]const u8, "git_loader", b.option([]const u8, "git-loader", "Explicit public native Git fixture ELF interpreter"));
    options.addOption(?[]const []const u8, "git_libraries", b.option([]const []const u8, "git-library", "Explicit public Git fixture library; repeat for the complete closure"));
    options.addOptionPath("process_fixture", fixture.getEmittedBin());
    options.addOptionPath("preparation_cli", executable.getEmittedBin());
    tests.root_module.addOptions("test_options", options);
    const run = b.addRunArtifact(tests);
    run.setCwd(.{ .cwd_relative = b.cache_root.path.? });
    const test_step = b.step("test", "Run native synthetic preparation and provenance fixtures");
    test_step.dependOn(&run.step);

    // Direct readers are qualification-only dependencies. The producer never
    // imports a controller, approval schema, or the direct build graph.
    const evidence = b.createModule(.{
        .root_source_file = b.path("../persistence/evidence.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    });
    const direct = b.createModule(.{
        .root_source_file = b.path("../direct/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "preparation", .module = module },
            .{ .name = "evidence", .module = evidence },
        },
    });
    const seed_imports: []const std.Build.Module.Import = &.{
        .{ .name = "preparation", .module = module },
        .{ .name = "direct_validation", .module = direct },
    };
    const seed_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("original_seed_tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = seed_imports,
    }) });
    seed_tests.root_module.addOptions("test_options", options);
    const seed_run = b.addRunArtifact(seed_tests);
    seed_run.setCwd(.{ .cwd_relative = b.cache_root.path.? });
    const seed_step = b.step("test-original-seed", "Run bounded original-seed native fixtures (no full-size disks)");
    seed_step.dependOn(&seed_run.step);
    test_step.dependOn(seed_step);

    const qualify = b.step("qualify-original-seed", "Explicit full 4-GiB local seed creation and independent direct-reader validation");
    if (b.option([]const u8, "original-seed-root", "Fresh nonexistent absolute private full-size qualification directory")) |root| {
        if (!std.fs.path.isAbsolute(root)) {
            qualify.dependOn(&b.addFail("original-seed-root must be an absolute fresh directory").step);
        } else {
            const qualification = b.addExecutable(.{
                .name = "original-seed-qualification",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("original_seed_qualification.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = seed_imports,
                }),
            });
            qualification.root_module.addOptions("test_options", options);
            const qualify_run = b.addRunArtifact(qualification);
            qualify_run.has_side_effects = true;
            qualify_run.addArg(root);
            qualify.dependOn(&qualify_run.step);
        }
    } else {
        qualify.dependOn(&b.addFail("qualify-original-seed requires -Doriginal-seed-root=FRESH_ABSOLUTE_PATH").step);
    }
}
