const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filters = b.option([]const []const u8, "test-filter", "Run only tests matching these filters") orelse &.{};
    const source = b.dependency("miz_source", .{ .target = target, .optimize = optimize });
    const core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = target, .optimize = optimize });
    const local = b.createModule(.{ .root_source_file = b.path("../local_boot/root.zig"), .target = target, .optimize = optimize, .imports = &.{.{ .name = "hyperv_core", .module = core }} });
    const kconfig = b.createModule(.{ .root_source_file = b.path("../../../build/kconfig.zig"), .target = target, .optimize = optimize });
    const elf = b.createModule(.{ .root_source_file = b.path("../../../build/postprocess-elf.zig"), .target = target, .optimize = optimize });
    const miz = b.createModule(.{ .root_source_file = source.path("packages/miz/src/root.zig"), .target = target, .optimize = optimize });
    const peer = b.build_root.handle.readFileAlloc(b.graph.io, "../../../scripts/hyperv-network-peer.py", b.allocator, .limited(4 * 1024 * 1024)) catch @panic("public peer source unavailable");
    var peer_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(peer, &peer_hash, .{});
    const pins = b.addOptions();
    pins.addOption([32]u8, "peer_sha256", peer_hash);
    const module = b.addModule("hyperv_public_image", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },       .{ .name = "local_boot", .module = local },
            .{ .name = "native_kconfig", .module = kconfig }, .{ .name = "native_elf", .module = elf },
            .{ .name = "miz", .module = miz },
        },
    });
    module.addOptions("producer_pins", pins);
    const cli = b.addExecutable(.{ .name = "uk-hyperv-public-image", .root_module = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "public_image", .module = module }},
    }) });
    b.installArtifact(cli);
    const fixture = b.addExecutable(.{ .name = "public-image-qemu-fixture", .root_module = b.createModule(.{
        .root_source_file = b.path("fixture.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "public_image", .module = module }},
    }) });
    const options = b.addOptions();
    options.addOptionPath("cli", cli.getEmittedBin());
    options.addOptionPath("fixture", fixture.getEmittedBin());
    options.addOption(?[]const u8, "test_root", b.option([]const u8, "test-root", "Existing absolute private fixture directory"));
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "public_image", .module = module }},
    }), .filters = filters });
    tests.root_module.addOptions("test_options", options);
    b.step("test", "Test native public packaging/export without real guest boots").dependOn(&b.addRunArtifact(tests).step);
    const import_options = b.addOptions();
    import_options.addOptionPath("cli", cli.getEmittedBin());
    import_options.addOption(?[]const u8, "test_root", b.option([]const u8, "import-test-root", "Existing private native import fixture directory"));
    const import_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("import_tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "public_image", .module = module }},
    }), .filters = filters });
    import_tests.root_module.addOptions("test_options", import_options);
    b.step("test-import", "Test physical native import and reload without guests or networking").dependOn(&b.addRunArtifact(import_tests).step);
    const measurement = b.createModule(.{
        .root_source_file = b.path("../synthetic_measurement.zig"),
        .target = target,
        .optimize = optimize,
    });
    const cost_probe = b.addExecutable(.{
        .name = "public-image-cost-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cost_probe.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "public_image", .module = module },
                .{ .name = "synthetic_measurement", .module = measurement },
            },
        }),
    });
    if (target.result.cpu.arch == .x86_64)
        cost_probe.root_module.addAssemblyFile(b.path("cost_clear_upper.S"));
    cost_probe.root_module.addOptions("test_options", options);
    b.step("build-cost-probe", "Compile the uninstalled synthetic cost probe without running it").dependOn(&cost_probe.step);
    b.step("diagnose-cost", "Measure actual synthetic package and independent boot hashes without a guest").dependOn(&b.addRunArtifact(cost_probe).step);
}
