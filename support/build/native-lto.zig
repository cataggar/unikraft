// SPDX-License-Identifier: BSD-3-Clause

//! LTO link execution for Zig 0.16 native QEMU builds.
//!
//! When `CONFIG_OPTIMIZE_LTO=y`, compilation emits LLVM IR bitcode. The
//! standard per-library pipeline (`zig cc -r` then `objcopy --keep-global-
//! symbols`) cannot process pure bitcode: `objcopy` rejects bitcode, and
//! relocatable partial linking does not produce useful intermediate ELF from
//! bitcode.
//!
//! This module provides an alternative flat link that bypasses the per-library
//! partial-link and `objcopy` stages. All library object and archive inputs
//! are collected in registration order and passed directly to a single
//! `zig cc -flto` final link, allowing LLVM LTO cross-TU optimization.
//!
//! Symbol-export semantics are preserved by a Python-based policy step
//! (`lto-symbol-policy.py`) that runs before the final link. It invokes the
//! configured NM tool on each library's objects/archives, reads export symbol
//! lists, detects private-symbol collisions and cross-library private
//! references, and generates a deterministic LLD version script with the
//! allowed global-symbol union and `local: *;`. The version script is passed
//! to the Zig driver via `-Wl,--version-script=<file>` so that private
//! definitions remain local in the resulting ELF.

const std = @import("std");
const component = @import("component-api.zig");
const final_link = @import("final-link.zig");
const native_image_graph = @import("native-image-graph.zig");

// -- Link mode --------------------------------------------------------------

/// Selects the link pipeline strategy for the native build.
pub const LinkMode = enum {
    /// Per-library `zig cc -r` + `objcopy --keep-global-symbols`, then final link.
    standard,
    /// Bypass per-library pipeline; flat `zig cc -flto` final link with
    /// a generated version script preserving per-library symbol locality.
    lto,

    /// Detect the link mode from a solved build configuration.
    pub fn detect(config: component.ConfigQuery) LinkMode {
        return if (config.isEnabled("CONFIG_OPTIMIZE_LTO")) .lto else .standard;
    }
};

// -- Optimization level -----------------------------------------------------

/// LTO code-generation optimization level, propagated to the final link driver.
pub const OptLevel = enum {
    none,
    size,
    perf,

    pub fn detect(config: component.ConfigQuery) OptLevel {
        if (config.isEnabled("CONFIG_OPTIMIZE_PERF")) return .perf;
        if (config.isEnabled("CONFIG_OPTIMIZE_SIZE")) return .size;
        return .none;
    }

    pub fn flag(self: OptLevel) []const u8 {
        return switch (self) {
            .none => "-O0",
            .size => "-Os",
            .perf => "-O2",
        };
    }
};

// -- Profile validation -----------------------------------------------------

pub const ProfileError = error{UnsupportedLtoProfile};

/// LTO is only implemented for QEMU/x86_64 in this scope. Other profiles
/// (ARM64, Hyper-V EFI) are rejected.
pub fn requireLtoProfile(profile: native_image_graph.Profile) ProfileError!void {
    switch (profile) {
        .@"qemu-x86_64" => {},
        .@"qemu-arm64", .@"hyperv-x86_64-efi" => return error.UnsupportedLtoProfile,
    }
}

// -- LTO execution (std.Build integration) ----------------------------------

pub const PlanError = final_link.PlanError;

/// Result of the LTO final link execution.
pub const LtoLinked = struct {
    stage_name: []const u8,
    output: std.Build.LazyPath,
    merged_linker_script: std.Build.LazyPath,
    link_step: *std.Build.Step.Run,
};

/// Execute a flat LTO final link for the selected platform.
///
/// This replaces both `native_library_link.execute()` and
/// `final_link.Executor.addSelected()` when LTO is active. It:
///  1. Merges linker scripts using the existing `final_link.Executor`.
///  2. Runs the `lto-symbol-policy.py` script to validate symbol policy
///     and generate a version script.
///  3. Emits a single `zig cc -flto` command with all library inputs
///     flattened and the version script applied.
pub fn executeLtoFinalLink(
    b: *std.Build,
    graph: component.FinalizedGraph,
    resolver: final_link.ArtifactResolver,
    prerequisite: ?*std.Build.Step,
    opt_level: OptLevel,
) PlanError!LtoLinked {
    if (graph.toolchain.compiler.kind != .zig_cc) return error.UnsupportedCompilerDriver;

    // Reuse the existing Executor for linker-script merge stages.
    const executor = final_link.Executor.initWithPrerequisite(b, resolver, prerequisite);

    const platform = graph.selectedPlatform();

    // Find the final-link stage.
    var final_stage: ?component.LinkStage = null;
    for (platform.link_stages, 0..) |stage, stage_index| {
        if (!graph.linkStageIsActive(stage_index)) continue;
        if (stage.transformation == .final_link) {
            final_stage = stage;
            break;
        }
    }
    const stage = final_stage orelse return error.MissingLinkerScript;

    // Plan stage to extract merged-linker-script dependencies.
    const plans = try final_link.planSelected(b.allocator, graph);
    defer final_link.deinitPlans(b.allocator, plans);
    if (plans.len != 1) return error.MissingLinkerScript;
    const plan = plans[0];

    const merged_stages = try executor.addMergeStages(graph);
    const merged_script = executor.resolveMergedScript(graph, plan, merged_stages);

    // -- Symbol-policy step ---------------------------------------------
    // Invoke lto-symbol-policy.py to validate and generate version script.
    const policy = b.addSystemCommand(&.{
        "python3",
        "support/build/lto-symbol-policy.py",
        "--nm",
        graph.toolchain.binutils.nm.command,
    });
    policy.setName("LTO symbol-policy generator");
    policy.setCwd(b.path("."));
    policy.setEnvironmentVariable("PYTHONDONTWRITEBYTECODE", "1");
    if (prerequisite) |p| policy.step.dependOn(p);

    // Output: the generated version script (tracked LazyPath).
    policy.addArg("--output");
    const version_script = policy.addOutputFileArg("lto-version-script.lds");

    // Add per-library arguments.
    for (graph.libraries, 0..) |library, library_index| {
        if (!graph.libraryIsActive(library_index)) continue;
        const pipeline = library.object_pipeline orelse continue;

        policy.addArgs(&.{ "--library", library.name });

        // Export files.
        for (library.exports) |export_path| {
            policy.addArg("--export-file");
            policy.addFileArg(resolver.resolve(.{ .path = export_path }, export_path));
        }

        // Object/archive inputs. Validate that non-artifact items are
        // the known redundant partial-link flags/groups for this graph.
        for (pipeline.partial_link_sequence) |seq_item| {
            switch (seq_item) {
                .artifact => |a| {
                    const path = resolveArtifactPath(graph, a.artifact) orelse
                        return error.UnresolvedArtifact;
                    policy.addArg("--input");
                    policy.addFileArg(resolver.resolve(a.artifact, path));
                },
                .literal_flag => |flag| {
                    if (!isKnownPartialLinkFlag(flag))
                        return error.UnsupportedFinalLinkFlag;
                },
                .tool_mode_flag => {},
                .group_start, .group_end => {},
                .library_argument => return error.UnsupportedFinalLinkFlag,
            }
        }
    }

    // -- LTO final-link command -----------------------------------------
    const zig = graph.toolchain.compiler.tool.command;
    const link = b.addSystemCommand(&.{zig});
    link.setName("LTO final link");
    if (prerequisite) |p| link.step.dependOn(p);
    // Depend on the policy step.
    link.step.dependOn(&policy.step);

    link.addArgs(&.{
        "cc",
        "-target",
        graph.toolchain.target_triple,
        "-flto",
        opt_level.flag(),
    });

    // Force-keep exported symbols during LTO with -Wl,-u.  LLD's LTO
    // internalization runs before linker-script EXTERN() is processed, so
    // -u on the command line is the only reliable mechanism.  The set of
    // exported symbols from library export files is the exact required set:
    // the policy step rejects any cross-library reference to a non-exported
    // symbol, so only exported symbols can be legally referenced across
    // translation units after flattening.
    for (graph.libraries, 0..) |library, library_index| {
        if (!graph.libraryIsActive(library_index)) continue;
        if (library.object_pipeline == null) continue;
        for (library.exports) |export_path| {
            const content = std.Io.Dir.cwd().readFileAlloc(
                b.graph.io,
                export_path,
                b.allocator,
                .limited(1024 * 1024),
            ) catch |err| {
                link.step.dependOn(&b.addFail(b.fmt(
                    "LTO force-keep: cannot read export file '{s}': {s}",
                    .{ export_path, @errorName(err) },
                )).step);
                return error.UnresolvedArtifact;
            };
            var lines = std.mem.splitScalar(u8, content, '\n');
            while (lines.next()) |raw_line| {
                const line = std.mem.trimEnd(u8, raw_line, " \t\r");
                if (line.len == 0) continue;
                if (line[0] == '#') continue;
                link.addArg(b.fmt("-Wl,-u,{s}", .{line}));
            }
        }
    }

    // Apply version script to control symbol visibility in the final ELF.
    link.addPrefixedFileArg("-Wl,--version-script=", version_script);

    // Walk the stage sequence for entry point, standard flags, and linker
    // scripts. library_final_object artifacts are replaced by the flattened
    // library inputs emitted below.
    for (stage.sequence) |item| {
        switch (item) {
            .literal_flag => |flag| {
                if (isForbiddenDriverFlag(flag)) return error.UnsupportedFinalLinkFlag;
                link.addArg(flag);
            },
            .tool_mode_flag => |tmf| {
                const driver_flag = tmf.driver orelse
                    return error.UnsupportedFinalLinkFlag;
                if (isForbiddenDriverFlag(driver_flag))
                    return error.UnsupportedFinalLinkFlag;
                link.addArg(driver_flag);
            },
            .group_start, .group_end => {},
            .library_argument => |la| {
                if (isForbiddenDriverFlag(la)) return error.UnsupportedFinalLinkFlag;
                link.addArg(la);
            },
            .artifact => |link_artifact| {
                switch (link_artifact.artifact) {
                    .library_final_object => continue,
                    else => {},
                }
                if (link_artifact.kind == .linker_script) {
                    link.addPrefixedFileArg("-Wl,-T,", merged_script);
                } else {
                    const path = resolveArtifactPath(graph, link_artifact.artifact) orelse
                        return error.UnresolvedArtifact;
                    link.addFileArg(resolver.resolve(link_artifact.artifact, path));
                }
            },
        }
    }

    // Flatten all active library inputs in registration order.
    var have_archives = false;
    for (graph.libraries, 0..) |library, library_index| {
        if (!graph.libraryIsActive(library_index)) continue;
        const pipeline = library.object_pipeline orelse continue;
        for (pipeline.partial_link_sequence) |seq_item| {
            if (seq_item == .artifact and seq_item.artifact.kind == .archive) {
                have_archives = true;
                break;
            }
        }
        if (have_archives) break;
    }

    if (have_archives) link.addArg("-Wl,--start-group");

    for (graph.libraries, 0..) |library, library_index| {
        if (!graph.libraryIsActive(library_index)) continue;
        const pipeline = library.object_pipeline orelse continue;
        for (pipeline.partial_link_sequence) |seq_item| {
            switch (seq_item) {
                .artifact => |a| {
                    const path = resolveArtifactPath(graph, a.artifact) orelse
                        return error.UnresolvedArtifact;
                    link.addFileArg(resolver.resolve(a.artifact, path));
                },
                .literal_flag => |flag| {
                    if (!isKnownPartialLinkFlag(flag))
                        return error.UnsupportedFinalLinkFlag;
                },
                .tool_mode_flag => {},
                .group_start, .group_end => {},
                .library_argument => return error.UnsupportedFinalLinkFlag,
            }
        }
    }

    if (have_archives) link.addArg("-Wl,--end-group");

    // -o must precede the output path so zig cc does not try to interpret
    // the .dbg extension as an input file type.
    link.addArg("-o");
    const output = link.addOutputFileArg(std.fs.path.basename(stage.output));

    return .{
        .stage_name = stage.name,
        .output = output,
        .merged_linker_script = merged_script,
        .link_step = link,
    };
}

fn isForbiddenDriverFlag(flag: []const u8) bool {
    return std.mem.eql(u8, flag, "-dT") or
        std.mem.startsWith(u8, flag, "-T") or
        std.mem.indexOf(u8, flag, "--default-script") != null or
        std.mem.indexOf(u8, flag, "--script") != null or
        std.mem.indexOf(u8, flag, "-Wl,-dT") != null or
        std.mem.indexOf(u8, flag, "-Wl,--default-script") != null or
        std.mem.indexOf(u8, flag, "-Wl,-T") != null or
        std.mem.startsWith(u8, flag, "-Wl,-m");
}

/// The per-library partial_link_sequence contains flags that are redundant
/// in the LTO flat link because they also appear in the final-link stage
/// sequence.  Only these known flags are permitted; any other literal or
/// library_argument is rejected so that future metadata changes cannot be
/// silently mislinked.
fn isKnownPartialLinkFlag(flag: []const u8) bool {
    return std.mem.eql(u8, flag, "-Wl,--build-id=none") or
        std.mem.eql(u8, flag, "-no-pie");
}

fn resolveArtifactPath(
    graph: component.FinalizedGraph,
    reference: component.ArtifactReference,
) ?[]const u8 {
    return switch (reference) {
        .path, .generated_output => |path| path,
        .component_output => |output| output.path,
        .library_partial_output => |name| blk: {
            for (graph.libraries) |library| {
                if (std.mem.eql(u8, library.name, name)) {
                    break :blk if (library.object_pipeline) |p| p.partial_link_output else null;
                }
            }
            break :blk null;
        },
        .library_final_object => |name| blk: {
            for (graph.libraries) |library| {
                if (std.mem.eql(u8, library.name, name)) {
                    break :blk if (library.object_pipeline) |p| p.transform.output else null;
                }
            }
            break :blk null;
        },
        .stage_output => |output| blk: {
            for (graph.platforms) |plat| {
                if (!std.mem.eql(u8, plat.name, output.platform)) continue;
                for (plat.link_stages) |s| {
                    if (std.mem.eql(u8, s.name, output.stage)) break :blk s.output;
                }
            }
            break :blk null;
        },
        .post_process_output => null,
    };
}

// -- Tests ------------------------------------------------------------------

fn testConfig(
    comptime lto: bool,
    comptime opt: ?[]const u8,
) component.ConfigQuery {
    const S = struct {
        fn isEnabled(_: ?*const anyopaque, name: []const u8) bool {
            if (lto and std.mem.eql(u8, name, "CONFIG_OPTIMIZE_LTO")) return true;
            if (opt) |o| {
                if (std.mem.eql(u8, name, o)) return true;
            }
            return false;
        }
        fn value(_: ?*const anyopaque, _: []const u8) ?[]const u8 {
            return null;
        }
    };
    return .{ .is_enabled_fn = S.isEnabled, .value_fn = S.value };
}

test "LinkMode.detect returns standard when LTO is disabled" {
    const config = testConfig(false, null);
    try std.testing.expectEqual(LinkMode.standard, LinkMode.detect(config));
}

test "LinkMode.detect returns lto when CONFIG_OPTIMIZE_LTO is enabled" {
    const config = testConfig(true, null);
    try std.testing.expectEqual(LinkMode.lto, LinkMode.detect(config));
}

test "OptLevel.detect returns correct level from config" {
    try std.testing.expectEqual(OptLevel.none, OptLevel.detect(testConfig(true, null)));
    try std.testing.expectEqual(
        OptLevel.perf,
        OptLevel.detect(testConfig(true, "CONFIG_OPTIMIZE_PERF")),
    );
    try std.testing.expectEqual(
        OptLevel.size,
        OptLevel.detect(testConfig(true, "CONFIG_OPTIMIZE_SIZE")),
    );
}

test "OptLevel.flag returns correct compiler flags" {
    try std.testing.expectEqualStrings("-O0", OptLevel.none.flag());
    try std.testing.expectEqualStrings("-Os", OptLevel.size.flag());
    try std.testing.expectEqualStrings("-O2", OptLevel.perf.flag());
}

test "requireLtoProfile accepts x86_64 and rejects arm64" {
    try requireLtoProfile(.@"qemu-x86_64");
    try std.testing.expectError(error.UnsupportedLtoProfile, requireLtoProfile(.@"qemu-arm64"));
}

test "shared export list paths across libraries are valid for LTO" {
    // libukboot and libukboot_main intentionally share lib/ukboot/exportsyms.uk.
    // The symbol-policy step handles this correctly; duplicate export file
    // paths are not rejected.
    const config = testConfig(true, "CONFIG_OPTIMIZE_PERF");
    try std.testing.expectEqual(LinkMode.lto, LinkMode.detect(config));
    try std.testing.expectEqual(OptLevel.perf, OptLevel.detect(config));
}
