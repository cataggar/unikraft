// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

fn pic(module: *std.Build.Module) void {
    module.pic = true;
    for (module.import_table.values()) |child| pic(child);
}

pub fn build(b: *std.Build) void {
    const variant = b.option(enum { snapshot, jit, @"sample-aot" }, "variant", "Explicit optional workload image") orelse
        @panic("variant is required");
    const target = b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .freestanding, .abi = .none });
    const sdk = b.dependency("wamr", .{
        .profile = @as([]const u8, if (variant == .snapshot) "unikraft-aot" else "unikraft-jit"),
        .target = target,
        .optimize = std.builtin.OptimizeMode.ReleaseSafe,
    });
    const root = b.createModule(.{
        .root_source_file = b.path(if (variant == .snapshot) "snapshot.zig" else "sampler.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .single_threaded = true,
        .red_zone = false,
        .stack_check = false,
        .stack_protector = false,
        .unwind_tables = .none,
        .error_tracing = false,
        .link_libc = false,
        .pic = true,
    });
    root.addIncludePath(b.path("."));
    root.addIncludePath(b.path("../artifacts"));
    root.addAnonymousImport("workload-artifacts", .{
        .root_source_file = b.path("artifacts.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
    });
    if (variant == .snapshot) {
        root.addImport("wamr-aot", sdk.module("wamr-aot"));
    } else {
        root.addImport("sampler", sdk.module(if (variant == .jit) "wamr-jit" else "wamr-jit-aot-sample"));
        root.addImport("wamr-jit-workload", sdk.module("wamr-jit-workload"));
        const wasm = sdk.module("wamr-jit-workload").root_source_file.?.dirname().path(b, "matched.wasm");
        b.getInstallStep().dependOn(&b.addInstallFile(wasm, "matched.wasm").step);
    }
    pic(root);
    const library = b.addLibrary(.{ .name = "wamr-aot", .linkage = .static, .root_module = root });
    library.bundle_compiler_rt = false;
    b.installArtifact(library);
}
