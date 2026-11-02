// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const Translator = @import("translate_c").Translator;

fn pic(module: *std.Build.Module) void {
    module.pic = true;
    for (module.import_table.values()) |child| pic(child);
}

pub fn build(b: *std.Build) void {
    const variant = b.option(enum { tiny, snapshot, jit, @"sample-aot" }, "variant", "Explicit workload image") orelse
        @panic("variant is required");
    const coremark = b.option(bool, "coremark", "Original CoreMarks and qualified WASI clock bridge") orelse false;
    if (coremark and variant != .tiny) @panic("CoreMarks belong to the tiny image");
    const target = b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .freestanding, .abi = .none });
    const sdk = b.dependency("wamr", .{
        .profile = @as([]const u8, if (variant == .snapshot or variant == .tiny) "unikraft-aot" else "unikraft-jit"),
        .target = target,
        .optimize = std.lang.Optimize.safe,
    });
    const root = if (variant == .tiny and !coremark) sdk.module("wamr-aot") else b.createModule(.{
        .root_source_file = b.path(if (variant == .tiny) "wasi.zig" else if (variant == .snapshot) "snapshot.zig" else "sampler.zig"),
        .target = target,
        .optimize = .safe,
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
    if (variant != .tiny or coremark) {
        const translated: Translator = .init(b.dependency("translate_c", .{}), .{
            .name = "workloads_c",
            .c_source_file = b.path("workloads.h"),
            .target = target,
            .optimize = .safe,
            .link_libc = false,
        });
        translated.addIncludePath(b.path("."));
        translated.addIncludePath(b.path("../artifacts"));
        translated.mod.single_threaded = true;
        translated.mod.red_zone = false;
        translated.mod.stack_check = false;
        translated.mod.stack_protector = false;
        translated.mod.unwind_tables = .none;
        translated.mod.error_tracing = false;
        root.addImport("workloads_c", translated.mod);
    }
    if (variant != .tiny) root.addAnonymousImport("workload-artifacts", .{
        .root_source_file = b.path("artifacts.zig"),
        .target = target,
        .optimize = .safe,
    });
    if (variant == .snapshot or coremark) {
        root.addImport("wamr-aot", sdk.module("wamr-aot"));
    } else if (variant != .tiny) {
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
