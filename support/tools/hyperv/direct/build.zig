// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = target, .optimize = optimize });
    const kconfig = b.createModule(.{ .root_source_file = b.path("../../../build/kconfig.zig"), .target = target, .optimize = optimize });
    const preparation = b.createModule(.{
        .root_source_file = b.path("../preparation/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "hyperv_core", .module = core }, .{ .name = "native_kconfig", .module = kconfig } },
    });
    const persistence = b.createModule(.{
        .root_source_file = b.path("../persistence/evidence.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    });
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "hyperv_core", .module = core },
        .{ .name = "preparation", .module = preparation },
        .{ .name = "evidence", .module = persistence },
    };
    b.installArtifact(b.addExecutable(.{
        .name = "uk-hyperv-direct-validate",
        .root_module = b.createModule(.{ .root_source_file = b.path("main.zig"), .target = target, .optimize = optimize, .imports = imports }),
    }));
    const fixtures = b.addExecutable(.{
        .name = "hyperv-direct-validation-fixtures",
        .root_module = b.createModule(.{ .root_source_file = b.path("fixtures.zig"), .target = target, .optimize = optimize, .imports = imports }),
    });
    b.step("test", "Run native read-only direct validation fixtures (no cloud or disks)").dependOn(&b.addRunArtifact(fixtures).step);

    const test_options = b.addOptions();
    test_options.addOption(?[]const u8, "test_root", b.option([]const u8, "test-root", "Existing private absolute native fixture directory"));
    const foundation = b.step("test-foundation", "Run native direct observation and custody fixtures");
    inline for (.{ "observation", "custody" }) |name| {
        const tests = b.addTest(.{ .root_module = b.createModule(.{
            .root_source_file = b.path(name ++ "_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = imports,
        }) });
        tests.root_module.addOptions("test_options", test_options);
        const run = b.addRunArtifact(tests);
        b.step("test-" ++ name, "Run native direct " ++ name ++ " fixtures").dependOn(&run.step);
        foundation.dependOn(&run.step);
    }
}
