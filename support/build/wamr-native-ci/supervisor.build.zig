// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const native_owner = b.option(bool, "native-source-owner", "Use the compiled native standalone source owner, not a historical identity") orelse false;
    const source_closure = b.option(
        []const u8,
        "source-closure-sha256",
        "Exact supervised source content closure",
    );
    if (native_owner and source_closure != null)
        @panic("native-source-owner cannot accept a substituted source-closure-sha256");
    if (!native_owner and source_closure == null)
        @panic("source-closure-sha256 is required");
    const historical_closure = source_closure orelse "";
    if (!native_owner and historical_closure.len != 64)
        @panic("source-closure-sha256 must be lowercase SHA-256");
    for (historical_closure) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            @panic("source-closure-sha256 must be lowercase SHA-256");
    }
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "source_closure_sha256", historical_closure);
    build_options.addOption(bool, "native_source_owner", native_owner);
    const core = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/core.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../../tools/hyperv/sha256_clear_upper.S"));
    const source = b.createModule(.{
        .root_source_file = b.path("../../controller_source_closure.zig"),
        .target = target,
        .optimize = optimize,
    });
    const supervisor = b.addExecutable(.{
        .name = "wamr-ci-supervisor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("supervisor.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .imports = &.{
                .{ .name = "build_options", .module = build_options.createModule() },
                .{ .name = "hyperv_core", .module = core },
                .{ .name = "supervisor_source_closure", .module = source },
            },
        }),
    });
    b.installArtifact(supervisor);
}
