// SPDX-License-Identifier: BSD-3-Clause

//! Standalone, Python-free validation (Zig 0.16.0):
//! zig build --build-file support/build/native-postprocess-tests.build.zig test -j2
//! Use `integration -j2` for real LLVM strip/objcopy fixtures. Tool commands
//! can be supplied with -Dobjcopy=... and -Dstrip=...; -Dfixture-arch=arm64
//! also supports hosts whose native GNU binutils lack x86_64 support.
const std = @import("std");
const postprocess = @import("native-postprocess.zig");
const api = @import("component-api.zig");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test native ELF/image postprocessing without Python");
    b.default_step = test_step;
    for ([_][]const u8{ "native-postprocess-tests.zig", "native-postprocess.zig" }) |path| {
        const tests = b.addTest(.{ .root_module = b.createModule(.{
            .root_source_file = b.path(path),
            .target = b.graph.host,
        }) });
        test_step.dependOn(&b.addRunArtifact(tests).step);
    }
    const runner = b.addExecutable(.{
        .name = "native-postprocess-runner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("native-postprocess-runner.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    b.installArtifact(runner);
    test_step.dependOn(&runner.step);
    const integration = b.step("integration", "Run real LLVM postprocess fixture transformations");
    integration.dependOn(test_step);
    const fixture = b.addExecutable(.{
        .name = "native-postprocess-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("native-postprocess-fixture.zig"),
            .target = b.graph.host,
        }),
    });
    const run = b.addRunArtifact(fixture);
    run.addArtifactArg(runner);
    const objcopy = b.option([]const u8, "objcopy", "Native objcopy command") orelse "llvm-objcopy";
    const strip = b.option([]const u8, "strip", "Native strip command") orelse "llvm-strip";
    const architecture = b.option([]const u8, "fixture-arch", "Fixture architecture: x86_64 or arm64") orelse "x86_64";
    run.addArg(objcopy);
    run.addArg(strip);
    _ = run.addOutputDirectoryArg("fixtures");
    run.addArg(architecture);
    integration.dependOn(&run.step);
    graphFixture(b, integration, runner, fixture, architecture, objcopy, strip);
}

fn output(transformation: []const u8, name: []const u8) api.ArtifactReference {
    return .{ .post_process_output = .{ .platform = "hyperv", .transformation = transformation, .output = name } };
}

fn disabled(_: ?*const anyopaque, _: []const u8) bool {
    return false;
}

fn noValue(_: ?*const anyopaque, _: []const u8) ?[]const u8 {
    return null;
}

fn graphFixture(
    b: *std.Build,
    integration: *std.Build.Step,
    runner: *std.Build.Step.Compile,
    fixture: *std.Build.Step.Compile,
    architecture: []const u8,
    objcopy: []const u8,
    strip: []const u8,
) void {
    const generate = b.addRunArtifact(fixture);
    generate.addArgs(&.{ "generate", architecture });
    const input = generate.addOutputFileArg("raw.dbg");
    const source = api.ArtifactReference{ .path = "raw.dbg" };
    const plan = postprocess.planPlatform(b.allocator, .{
        .name = "hyperv",
        .origin = .{ .internal = .platform },
        .post_process = &.{
            .{ .name = "uk-reloc", .kind = .uk_reloc, .input = source, .effects = &.{
                .{ .create = .{ .name = "relocations", .path = "image.uk_reloc.bin", .role = .side } },
                .{ .mutate_input = .{ .name = "debug", .role = .debug } },
            } },
            .{
                .name = "strip",
                .kind = .strip,
                .input = output("uk-reloc", "debug"),
                .flags = &.{ ".dynamic", ".gnu.hash", ".hash", ".dynsym", ".dynstr", ".rela.dyn" },
                .effects = &.{.{ .create = .{ .name = "image", .path = "image.elf", .role = .image } }},
            },
            .{ .name = "bootinfo", .kind = .bootinfo, .input = output("strip", "image"), .effects = &.{
                .{ .create = .{ .name = "bootinfo", .path = "image.bootinfo", .role = .side } },
                .{ .mutate_input = .{ .name = "image", .role = .image } },
            } },
            .{
                .name = "efi",
                .kind = .efi,
                .input = output("bootinfo", "image"),
                .additional_inputs = &.{output("uk-reloc", "debug")},
                .effects = &.{.{ .mutate_input = .{ .name = "image", .role = .image } }},
            },
            .{
                .name = "compile-db",
                .kind = .compile_database,
                .input = output("efi", "image"),
                .effects = &.{.{ .create = .{
                    .name = "database",
                    .path = b.pathFromRoot("compile_commands.json"),
                    .role = .auxiliary,
                } }},
            },
        },
    }, .{ .is_enabled_fn = disabled, .value_fn = noValue }, &.{.{
        .reference = source,
        .logical_path = "raw.dbg",
        .role = .debug,
    }}, .{ .architecture = if (std.mem.eql(u8, architecture, "x86_64")) .x86_64 else .arm64 }) catch @panic("fixture planning failed");
    const forbidden = b.path("FORBIDDEN-legacy-helper");
    const execution = postprocess.execute(b, plan, &.{input}, .{
        .python_executable = "FORBIDDEN-python-fallback",
        .strip = strip,
        .objcopy = objcopy,
        .objdump = null,
        .nm = "FORBIDDEN-nm",
        .readelf = "FORBIDDEN-readelf",
    }, .{
        .native_runner = runner,
        .runner = forbidden,
        .uk_reloc = forbidden,
        .bootinfo = forbidden,
        .multiboot = forbidden,
        .efi = forbidden,
        .linux_header = forbidden,
        .compile_database = forbidden,
        .elf_tools = forbidden,
    }) catch @panic("fixture execution planning failed");
    const verify = b.addRunArtifact(fixture);
    verify.addArg("verify-graph");
    verify.addFileArg(input);
    for (execution.outputs) |artifact| verify.addFileArg(artifact.path);
    integration.dependOn(&verify.step);
}
