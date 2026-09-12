const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
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
    }) });
    tests.root_module.addOptions("test_options", options);
    b.step("test", "Test native public packaging/export without real guest boots").dependOn(&b.addRunArtifact(tests).step);
}
