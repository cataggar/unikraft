const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.addModule("hyperv", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const cli = b.addExecutable(.{
        .name = "uk-hyperv",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "hyperv", .module = core }},
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
    options.addOption(?[]const u8, "test_root", b.option([]const u8, "test-root", "Existing private absolute directory for native filesystem fixtures"));
    options.addOptionPath("process_fixture", fixture.getEmittedBin());
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "hyperv", .module = b.createModule(.{
                .root_source_file = b.path("root.zig"),
                .target = b.graph.host,
                .optimize = optimize,
            }) }},
        }),
    });
    tests.root_module.addOptions("test_options", options);
    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run bounded contracts, private files, and process supervision tests").dependOn(&run_tests.step);
}
