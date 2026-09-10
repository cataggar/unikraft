// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

fn module(b: *std.Build, root: std.Build.LazyPath, source: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const result = b.createModule(.{
        .root_source_file = root.path(b, source),
        .target = target,
        .optimize = optimize,
        .pic = true,
    });
    result.addImport("vmbus_protocol", b.createModule(.{
        .root_source_file = root.path(b, "drivers/hyperv/vmbus/vmbus_protocol.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
    }));
    return result;
}

pub fn tool(b: *std.Build, root: std.Build.LazyPath) *std.Build.Step.Compile {
    return b.addExecutable(.{
        .name = "hyperv-image-proof",
        .root_module = module(b, root, "support/build/hyperv-proof-tool.zig", b.graph.host, .ReleaseSafe),
    });
}

pub fn tests(b: *std.Build, root: std.Build.LazyPath) *std.Build.Step {
    const step = b.step("test-hyperv-image-proofs", "Run native Hyper-V linked-image proofs and refusal fixtures; no guest execution");
    const proof_tool = tool(b, root);
    const unit = b.addTest(.{ .root_module = module(b, root, "support/build/hyperv-proof-tests.zig", b.graph.host, .Debug) });
    step.dependOn(&b.addRunArtifact(unit).step);
    const install = b.step("build-hyperv-image-proofs", "Build/install the native Hyper-V linked-image proof CLI only");
    install.dependOn(&b.addInstallArtifact(proof_tool, .{}).step);
    const nm = b.option([]const u8, "proof-nm", "Native NM command for image proof fixtures") orelse "llvm-nm";
    const objdump = b.option([]const u8, "proof-objdump", "Native objdump command for image proof fixtures") orelse "llvm-objdump";
    const fixture_runner = b.addExecutable(.{
        .name = "hyperv-proof-fixtures",
        .root_module = module(b, root, "support/build/hyperv-proof-fixtures.zig", b.graph.host, .Debug),
    });
    const config = b.addWriteFiles();
    _ = config.add("uk/bits/config.h", "/* Native, freestanding proof fixture configuration. */\n");
    for ([_]struct { name: []const u8, cpus: u32, fixed: bool, paging: bool, pie: bool = true, direct_scheduler: bool = false, object_scheduler: bool = false }{
        .{ .name = "fixed", .cpus = 4, .fixed = true, .paging = true },
        .{ .name = "fixed-object", .cpus = 4, .fixed = true, .paging = true, .object_scheduler = true },
        .{ .name = "fixed-static", .cpus = 4, .fixed = true, .paging = true, .pie = false, .direct_scheduler = true },
        .{ .name = "fixed-no-paging", .cpus = 4, .fixed = true, .paging = false },
        .{ .name = "multi-nonfixed", .cpus = 4, .fixed = false, .paging = false },
        .{ .name = "single", .cpus = 1, .fixed = false, .paging = false },
    }) |options| {
        const target = b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .freestanding, .abi = .none });
        const fixture_module = module(b, root, "support/build/tests/hyperv-proof-fixture.zig", target, .ReleaseSmall);
        fixture_module.strip = false;
        const object = b.addObject(.{ .name = b.fmt("proof-zig-{s}", .{options.name}), .root_module = fixture_module });
        const executable = b.addExecutable(.{
            .name = b.fmt("proof-image-{s}", .{options.name}),
            .root_module = b.createModule(.{ .target = target, .optimize = .ReleaseSmall, .strip = false }),
        });
        executable.root_module.addObject(object);
        executable.root_module.addIncludePath(config.getDirectory());
        executable.root_module.addIncludePath(root.path(b, "drivers/hyperv/vmbus/include"));
        executable.root_module.addIncludePath(root.path(b, "support/build/tests/vmbus-host-include"));
        executable.root_module.addIncludePath(root.path(b, "include"));
        executable.root_module.addIncludePath(root.path(b, "arch/x86/x86_64/include"));
        executable.root_module.addCSourceFile(.{
            .file = root.path(b, "support/build/tests/hyperv-proof-fixture.c"),
            .flags = &.{
                "-std=gnu11",                                                                 "-ffreestanding",                                               "-fno-builtin",                                               "-fno-stack-protector",                                                       if (options.pie) "-fno-optimize-sibling-calls" else "-foptimize-sibling-calls",
                "-ffunction-sections",                                                        "-fdata-sections",                                              "-mno-sse",                                                   "-mno-mmx",                                                                   "-mno-red-zone",
                b.fmt("-DPROOF_MAX_CPUS={d}", .{options.cpus}),                               b.fmt("-DPROOF_FIXED_SMP={d}", .{@intFromBool(options.fixed)}), b.fmt("-DPROOF_PAGING={d}", .{@intFromBool(options.paging)}), b.fmt("-DPROOF_DIRECT_SCHED={d}", .{@intFromBool(options.direct_scheduler)}), "-fpatchable-function-entry=2",
                b.fmt("-DPROOF_OBJECT_SCHED={d}", .{@intFromBool(options.object_scheduler)}),
            },
        });
        executable.setLinkerScript(root.path(b, "support/build/tests/hyperv-proof-fixture.lds"));
        executable.entry = .{ .symbol_name = "_start" };
        executable.link_gc_sections = true;
        executable.pie = options.pie;
        const run = b.addRunArtifact(fixture_runner);
        run.addArtifactArg(proof_tool);
        run.addFileArg(executable.getEmittedBin());
        run.addFileArg(object.getEmittedBin());
        run.addArgs(&.{ nm, objdump, options.name, b.fmt("{d}", .{options.cpus}) });
        _ = run.addOutputDirectoryArg(b.fmt("proof-fixtures-{s}", .{options.name}));
        step.dependOn(&run.step);
    }
    return step;
}
