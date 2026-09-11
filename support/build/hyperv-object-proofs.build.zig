// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub const Setup = struct {
    tool: *std.Build.Step.Compile,
    process: *std.Build.Module,
    optimize: std.builtin.OptimizeMode,
    nm: []const u8,
    readelf: []const u8,
    objcopy: []const u8,

    pub fn create(b: *std.Build, optimize: std.builtin.OptimizeMode) Setup {
        const process = b.createModule(.{
            .root_source_file = b.path("support/tools/hyperv/process.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        });
        const tool = b.addExecutable(.{
            .name = "hyperv-object-proofs",
            .root_module = b.createModule(.{
                .root_source_file = b.path("support/build/hyperv-object-proofs.zig"),
                .target = b.graph.host,
                .optimize = optimize,
                .imports = &.{.{ .name = "hyperv_process", .module = process }},
            }),
        });
        const install = b.addInstallArtifact(tool, .{});
        b.step("hyperv-object-proofs", "Install the native Hyper-V relocatable-object verifier").dependOn(&install.step);
        return .{
            .tool = tool,
            .process = process,
            .optimize = optimize,
            .nm = b.option([]const u8, "hyperv-object-nm", "Native object verifier nm executable") orelse "llvm-nm",
            .readelf = b.option([]const u8, "hyperv-object-readelf", "Native object verifier readelf executable") orelse "llvm-readelf",
            .objcopy = b.option([]const u8, "hyperv-object-objcopy", "Native object negative-fixture objcopy executable") orelse "llvm-objcopy",
        };
    }

    pub fn fixtures(self: Setup, b: *std.Build, step: *std.Build.Step, objects: [5]std.Build.LazyPath, mappings: [2]std.Build.LazyPath) void {
        const module_options: std.Build.Module.CreateOptions = .{
            .root_source_file = b.path("support/build/hyperv-object-tests.zig"),
            .target = b.graph.host,
            .optimize = self.optimize,
            .imports = &.{.{ .name = "hyperv_process", .module = self.process }},
        };
        const unit = b.addTest(.{ .root_module = b.createModule(module_options) });
        const run_unit = b.addRunArtifact(unit);
        run_unit.setCwd(.{ .cwd_relative = b.cache_root.path orelse ".zig-cache" });
        step.dependOn(&run_unit.step);
        const fixture = b.addExecutable(.{
            .name = "hyperv-object-fixtures",
            .root_module = b.createModule(module_options),
        });
        const fake = b.addExecutable(.{
            .name = "hyperv-object-tool-fixture",
            .root_module = b.createModule(.{
                .root_source_file = b.path("support/build/hyperv-object-tool-fixture.zig"),
                .target = b.graph.host,
                .optimize = self.optimize,
            }),
        });
        const undefined_object = b.addObject(.{
            .name = "hyperv-object-undefined",
            .root_module = b.createModule(.{
                .target = b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .freestanding, .abi = .none }),
                .optimize = .ReleaseFast,
                .link_libc = false,
                .stack_protector = false,
            }),
        });
        undefined_object.root_module.addCSourceFile(.{
            .file = b.path("support/build/tests/hyperv-object-undefined.c"),
            .flags = &.{ "-std=c11", "-ffreestanding" },
        });
        const run = b.addRunArtifact(fixture);
        run.addArtifactArg(self.tool);
        run.addArtifactArg(fake);
        run.addArgs(&.{ self.nm, self.readelf, self.objcopy, b.graph.zig_exe });
        _ = run.addOutputDirectoryArg("hyperv-object-fixtures");
        for (objects) |object| run.addFileArg(object);
        for (mappings) |mapping| run.addFileArg(mapping);
        run.addFileArg(undefined_object.getEmittedBin());
        run.setCwd(.{ .cwd_relative = b.cache_root.path orelse ".zig-cache" });
        step.dependOn(&run.step);
    }
};
