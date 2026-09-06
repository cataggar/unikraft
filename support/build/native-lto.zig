// SPDX-License-Identifier: BSD-3-Clause

//! LTO link planning for Zig 0.16 native builds.
//!
//! When `CONFIG_OPTIMIZE_LTO=y`, compilation emits LLVM IR bitcode. The standard
//! per-library pipeline (`zig cc -r` then `objcopy --keep-global-symbols`) cannot
//! process pure bitcode: objcopy rejects bitcode files and relocatable partial
//! linking does not produce meaningful intermediate ELF objects from bitcode.
//!
//! This module provides an alternative flat pipeline that bypasses per-library
//! partial-link and objcopy entirely. All library object and archive inputs are
//! collected in registration order and passed directly to a single `zig cc -flto`
//! final link, allowing LLVM's LTO to perform cross-TU whole-program
//! optimization.
//!
//! Symbol export safety: without per-library `objcopy --keep-global-symbols`, all
//! symbols from every library are globally visible at final link. This module
//! validates that exported symbol files do not declare conflicting symbols across
//! libraries and provides deterministic errors for any detected conflicts.
//! Private (non-exported) duplicate symbols will cause standard linker errors at
//! link time, which are actionable and preferred over silent mislinking.

const std = @import("std");
const component = @import("component-api.zig");

// ── Link mode ──────────────────────────────────────────────────────────────

/// Selects the link pipeline strategy for the native build.
pub const LinkMode = enum {
    /// Per-library `zig cc -r` + `objcopy --keep-global-symbols`, then final link.
    standard,
    /// Bypass per-library pipeline; flat `zig cc -flto` final link.
    lto,

    /// Detect the link mode from a solved build configuration.
    pub fn detect(config: component.ConfigQuery) LinkMode {
        return if (config.isEnabled("CONFIG_OPTIMIZE_LTO")) .lto else .standard;
    }
};

// ── Optimization level ─────────────────────────────────────────────────────

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

// ── Planned argument ───────────────────────────────────────────────────────

/// A single element in the planned LTO final link command line.
pub const PlannedArgument = union(enum) {
    literal: []const u8,
    artifact: component.ArtifactReference,
    merged_linker_script,
    output,
};

// ── Library contribution ───────────────────────────────────────────────────

/// Per-library metadata collected during LTO flattening.
pub const LibraryContribution = struct {
    name: []const u8,
    library_index: usize,
    /// Number of artifact arguments contributed by this library.
    artifact_count: usize,
    /// Export symbol file paths declared by this library (empty if none).
    export_files: []const []const u8,
};

// ── Export safety ──────────────────────────────────────────────────────────

/// A pair of libraries that both export the same symbol file path.
pub const ExportConflict = struct {
    path: []const u8,
    first: []const u8,
    second: []const u8,
};

/// Result of export-safety validation.
pub const ExportSafety = union(enum) {
    /// No conflicts detected; safe to flatten.
    safe,
    /// Duplicate export file paths across libraries.
    conflicts: []const ExportConflict,
};

/// Validate that no two libraries reference the same export symbol file.
/// Identical export files across libraries indicate that localization was the
/// only barrier preventing duplicate-symbol errors; flattening would mislink.
pub fn validateExportSafety(
    allocator: std.mem.Allocator,
    contributions: []const LibraryContribution,
) error{OutOfMemory}!ExportSafety {
    var seen = std.StringHashMap([]const u8).init(allocator);
    defer seen.deinit();
    var conflicts = std.array_list.Managed(ExportConflict).init(allocator);
    errdefer conflicts.deinit();

    for (contributions) |contrib| {
        for (contrib.export_files) |path| {
            const existing = seen.get(path);
            if (existing) |first_lib| {
                try conflicts.append(.{
                    .path = path,
                    .first = first_lib,
                    .second = contrib.name,
                });
            } else {
                try seen.put(path, contrib.name);
            }
        }
    }

    if (conflicts.items.len > 0) {
        return .{ .conflicts = try conflicts.toOwnedSlice() };
    }
    return .safe;
}

/// Check whether two symbol lists (one per library) contain any common symbol.
/// Each list is a newline-separated file content (lines may be empty or start
/// with `#` for comments). Returns the first duplicate found, or null.
pub fn findDuplicateSymbol(
    allocator: std.mem.Allocator,
    a_content: []const u8,
    b_content: []const u8,
) error{OutOfMemory}!?[]const u8 {
    var set = std.StringHashMap(void).init(allocator);
    defer set.deinit();

    var a_lines = std.mem.splitScalar(u8, a_content, '\n');
    while (a_lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        try set.put(line, {});
    }

    var b_lines = std.mem.splitScalar(u8, b_content, '\n');
    while (b_lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (set.contains(line)) return line;
    }
    return null;
}

// ── LTO plan ───────────────────────────────────────────────────────────────

pub const PlanError = error{
    OutOfMemory,
    UnsupportedToolchain,
    MissingLinkerScript,
    MissingFinalLinkStage,
    UnsupportedFinalLinkFlag,
};

/// Complete plan for an LTO final link, replacing both per-library pipeline
/// and the standard final link.
pub const LtoPlan = struct {
    allocator: std.mem.Allocator,
    command: []const u8,
    arguments: []const PlannedArgument,
    linker_scripts: []const LinkerScriptDep,
    output_path: []const u8,
    contributions: []const LibraryContribution,

    pub const LinkerScriptDep = struct {
        artifact: component.ArtifactReference,
        path: []const u8,
    };

    pub fn deinit(self: LtoPlan) void {
        self.allocator.free(self.arguments);
        self.allocator.free(self.linker_scripts);
        for (self.contributions) |c| self.allocator.free(c.export_files);
        self.allocator.free(self.contributions);
    }
};

/// Plan an LTO final link for the selected platform.
///
/// Walks the finalized graph to:
///  1. Collect the final-link stage (entry, flags, linker scripts, output).
///  2. Flatten every active library's object/archive inputs into the command.
///  3. Prepend `-flto` and the detected optimization level.
///  4. Record per-library export metadata for safety validation.
pub fn planLtoFinalLink(
    allocator: std.mem.Allocator,
    graph: component.FinalizedGraph,
    opt_level: OptLevel,
) PlanError!LtoPlan {
    if (graph.toolchain.compiler.kind != .zig_cc) return error.UnsupportedToolchain;

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
    const stage = final_stage orelse return error.MissingFinalLinkStage;

    var args = std.array_list.Managed(PlannedArgument).init(allocator);
    errdefer args.deinit();
    var scripts = std.array_list.Managed(LtoPlan.LinkerScriptDep).init(allocator);
    errdefer scripts.deinit();
    var contributions = std.array_list.Managed(LibraryContribution).init(allocator);
    errdefer {
        for (contributions.items) |c| allocator.free(c.export_files);
        contributions.deinit();
    }

    // zig cc -target TRIPLE -flto -OLEVEL
    try args.appendSlice(&.{
        .{ .literal = "cc" },
        .{ .literal = "-target" },
        .{ .literal = graph.toolchain.target_triple },
        .{ .literal = "-flto" },
        .{ .literal = opt_level.flag() },
    });

    // Walk the final-link stage sequence for entry point, flags, and linker
    // scripts. Skip library_final_object artifacts — we replace them with
    // flattened per-library inputs below.
    var emitted_script = false;
    for (stage.sequence) |item| {
        switch (item) {
            .literal_flag => |flag| {
                if (isForbiddenDriverFlag(flag)) return error.UnsupportedFinalLinkFlag;
                try args.append(.{ .literal = flag });
            },
            .tool_mode_flag => |tmf| {
                const driver_flag = tmf.driver orelse
                    return error.UnsupportedFinalLinkFlag;
                if (isForbiddenDriverFlag(driver_flag)) {
                    return error.UnsupportedFinalLinkFlag;
                }
                try args.append(.{ .literal = driver_flag });
            },
            .group_start => {}, // we emit our own groups below
            .group_end => {},
            .library_argument => |la| {
                if (isForbiddenDriverFlag(la)) return error.UnsupportedFinalLinkFlag;
                try args.append(.{ .literal = la });
            },
            .artifact => |link_artifact| {
                // Skip library_final_object — replaced by flattened inputs.
                switch (link_artifact.artifact) {
                    .library_final_object => continue,
                    else => {},
                }
                const path = resolveArtifactPath(graph, link_artifact.artifact) orelse continue;
                if (link_artifact.kind == .linker_script) {
                    try scripts.append(.{
                        .artifact = link_artifact.artifact,
                        .path = path,
                    });
                    if (!emitted_script) {
                        try args.append(.merged_linker_script);
                        emitted_script = true;
                    }
                } else {
                    try args.append(.{ .artifact = link_artifact.artifact });
                }
            },
        }
    }
    if (!emitted_script) return error.MissingLinkerScript;

    // Flatten library inputs in registration order.
    // Wrap all archive inputs in a single group for circular-dependency resolution.
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

    if (have_archives) {
        try args.append(.{ .literal = "-Wl,--start-group" });
    }

    for (graph.libraries, 0..) |library, library_index| {
        if (!graph.libraryIsActive(library_index)) continue;
        const pipeline = library.object_pipeline orelse continue;

        var artifact_count: usize = 0;
        for (pipeline.partial_link_sequence) |seq_item| {
            switch (seq_item) {
                .artifact => |a| {
                    try args.append(.{ .artifact = a.artifact });
                    artifact_count += 1;
                },
                // Skip per-library link flags (build-id, no-pie) — already in final link.
                // Skip group markers — we use a single outer group.
                else => {},
            }
        }

        // Collect export symbol file paths.
        var export_files = std.array_list.Managed([]const u8).init(allocator);
        errdefer export_files.deinit();
        for (pipeline.transform.sequence) |t| {
            switch (t) {
                .symbol_file => |sf| {
                    if (sf.action == .keep_global) {
                        try export_files.append(sf.symbols_file);
                    }
                },
                .literal_flag => {},
            }
        }
        // Also include library-level exports.
        for (library.exports) |path| {
            try export_files.append(path);
        }

        try contributions.append(.{
            .name = library.name,
            .library_index = library_index,
            .artifact_count = artifact_count,
            .export_files = try export_files.toOwnedSlice(),
        });
    }

    if (have_archives) {
        try args.append(.{ .literal = "-Wl,--end-group" });
    }

    try args.append(.{ .literal = "-o" });
    try args.append(.output);

    return .{
        .allocator = allocator,
        .command = graph.toolchain.compiler.tool.command,
        .arguments = try args.toOwnedSlice(),
        .linker_scripts = try scripts.toOwnedSlice(),
        .output_path = stage.output,
        .contributions = try contributions.toOwnedSlice(),
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
            for (graph.platforms) |platform| {
                if (!std.mem.eql(u8, platform.name, output.platform)) continue;
                for (platform.link_stages) |s| {
                    if (std.mem.eql(u8, s.name, output.stage)) break :blk s.output;
                }
            }
            break :blk null;
        },
        .post_process_output => null,
    };
}

// ── Tests ──────────────────────────────────────────────────────────────────

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

fn syntheticGraph(
    libraries: []const component.Library,
    active_libraries: []const bool,
    link_stages: []const component.LinkStage,
    active_link_stages: []const bool,
) component.FinalizedGraph {
    return .{
        .roots = .{
            .base = "/repo",
            .app = "/app",
            .output = "/app/build",
            .config = "/app/build/.config",
        },
        .target = .{
            .architecture = .x86_64,
            .family = .x86,
            .abi = "none",
            .triple = "x86_64-freestanding-none",
        },
        .toolchain = .{
            .target_triple = "x86_64-freestanding-none",
            .compiler = .{
                .tool = .{ .command = "zig" },
                .kind = .zig_cc,
            },
            .partial_linker = .{
                .tool = .{ .command = "zig" },
                .kind = .compiler_driver,
                .mode = .driver,
            },
            .final_linker = .{
                .tool = .{ .command = "zig" },
                .kind = .compiler_driver,
            },
            .binutils = .{
                .ar = .{ .command = "llvm-ar" },
                .objcopy = .{ .command = "llvm-objcopy" },
                .strip = .{ .command = "llvm-strip" },
                .nm = .{ .command = "llvm-nm" },
            },
        },
        .global_flags = .{},
        .global_includes = &.{},
        .libraries = libraries,
        .active_libraries = active_libraries,
        .platforms = &.{.{
            .name = "kvm",
            .origin = .{ .internal = .platform },
            .link_stages = link_stages,
        }},
        .registrations = &.{},
        .selected_platform_index = 0,
        .active_link_stages = active_link_stages,
    };
}

fn minimalFinalLinkStage() component.LinkStage {
    return .{
        .name = "final-link",
        .transformation = .final_link,
        .output = "/app/build/image.dbg",
        .sequence = &.{
            .{ .literal_flag = "-Wl,--entry=_multiboot_entry" },
            .{ .artifact = .{
                .kind = .object,
                .artifact = .{ .library_final_object = "libfoo" },
                .provenance = .global,
            } },
            .group_start,
            .group_end,
            .{ .literal_flag = "-nostdlib" },
            .{ .literal_flag = "-Wl,--build-id=none" },
            .{ .literal_flag = "-no-pie" },
            .{ .literal_flag = "-rtlib=compiler-rt" },
            .{ .artifact = .{
                .kind = .linker_script,
                .artifact = .{ .path = "/app/build/combined.lds" },
                .provenance = .platform,
            } },
        },
    };
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

test "planLtoFinalLink produces correct flat command with -flto" {
    const stage = minimalFinalLinkStage();
    const libraries = [_]component.Library{.{
        .name = "libfoo",
        .origin = .{ .internal = .library },
        .layout = .{ .ordinary = .{ .build_subdir = "libfoo" } },
        .object_pipeline = .{
            .partial_link_output = "/app/build/libfoo.ld.o",
            .partial_link_sequence = &.{
                .{ .literal_flag = "-Wl,--build-id=none" },
                .{ .literal_flag = "-no-pie" },
                .{ .artifact = .{
                    .kind = .object,
                    .artifact = .{ .component_output = .{
                        .component = "libfoo",
                        .path = "/app/build/libfoo/main.o",
                    } },
                } },
                .group_start,
                .{ .artifact = .{
                    .kind = .archive,
                    .artifact = .{ .path = "/repo/lib/foo/libgcc.a" },
                } },
                .group_end,
            },
            .transform = .{
                .input = .{ .library_partial_output = "libfoo" },
                .output = "/app/build/libfoo.o",
            },
        },
    }};

    const graph = syntheticGraph(
        &libraries,
        &.{true},
        &.{stage},
        &.{true},
    );

    var plan = try planLtoFinalLink(std.testing.allocator, graph, .perf);
    defer plan.deinit();

    // Verify command
    try std.testing.expectEqualStrings("zig", plan.command);
    try std.testing.expectEqualStrings("/app/build/image.dbg", plan.output_path);

    // Verify argument sequence
    const args = plan.arguments;
    try std.testing.expectEqualStrings("cc", args[0].literal);
    try std.testing.expectEqualStrings("-target", args[1].literal);
    try std.testing.expectEqualStrings("x86_64-freestanding-none", args[2].literal);
    try std.testing.expectEqualStrings("-flto", args[3].literal);
    try std.testing.expectEqualStrings("-O2", args[4].literal);

    // Entry point from final-link stage
    try std.testing.expectEqualStrings("-Wl,--entry=_multiboot_entry", args[5].literal);

    // Standard link flags (group_start/end from stage are skipped)
    try std.testing.expectEqualStrings("-nostdlib", args[6].literal);
    try std.testing.expectEqualStrings("-Wl,--build-id=none", args[7].literal);
    try std.testing.expectEqualStrings("-no-pie", args[8].literal);
    try std.testing.expectEqualStrings("-rtlib=compiler-rt", args[9].literal);

    // Merged linker script placeholder
    try std.testing.expect(args[10] == .merged_linker_script);

    // Flattened library inputs in a group (archive present)
    try std.testing.expectEqualStrings("-Wl,--start-group", args[11].literal);
    // Object from libfoo
    try std.testing.expectEqualStrings(
        "/app/build/libfoo/main.o",
        args[12].artifact.component_output.path,
    );
    // Archive from libfoo
    try std.testing.expectEqualStrings(
        "/repo/lib/foo/libgcc.a",
        args[13].artifact.path,
    );
    try std.testing.expectEqualStrings("-Wl,--end-group", args[14].literal);

    try std.testing.expectEqualStrings("-o", args[15].literal);
    try std.testing.expect(args[16] == .output);

    // Verify contributions
    try std.testing.expectEqual(@as(usize, 1), plan.contributions.len);
    try std.testing.expectEqualStrings("libfoo", plan.contributions[0].name);
    try std.testing.expectEqual(@as(usize, 2), plan.contributions[0].artifact_count);
}

test "planLtoFinalLink preserves multi-library ordering" {
    const stage: component.LinkStage = .{
        .name = "final-link",
        .transformation = .final_link,
        .output = "/app/build/image.dbg",
        .sequence = &.{
            .{ .literal_flag = "-Wl,--entry=_entry" },
            .{ .artifact = .{
                .kind = .object,
                .artifact = .{ .library_final_object = "libfirst" },
            } },
            .{ .artifact = .{
                .kind = .object,
                .artifact = .{ .library_final_object = "libsecond" },
            } },
            .group_start,
            .group_end,
            .{ .literal_flag = "-nostdlib" },
            .{ .literal_flag = "-rtlib=compiler-rt" },
            .{ .artifact = .{
                .kind = .linker_script,
                .artifact = .{ .path = "/build/combined.lds" },
            } },
        },
    };

    const libraries = [_]component.Library{
        .{
            .name = "libfirst",
            .origin = .{ .internal = .platform },
            .layout = .{ .ordinary = .{ .build_subdir = "libfirst" } },
            .object_pipeline = .{
                .partial_link_output = "/build/libfirst.ld.o",
                .partial_link_sequence = &.{
                    .{ .artifact = .{
                        .kind = .object,
                        .artifact = .{ .path = "/build/libfirst/a.o" },
                    } },
                    .{ .artifact = .{
                        .kind = .object,
                        .artifact = .{ .path = "/build/libfirst/b.o" },
                    } },
                },
                .transform = .{
                    .input = .{ .library_partial_output = "libfirst" },
                    .output = "/build/libfirst.o",
                },
            },
        },
        .{
            .name = "libsecond",
            .origin = .{ .internal = .library },
            .layout = .{ .ordinary = .{ .build_subdir = "libsecond" } },
            .object_pipeline = .{
                .partial_link_output = "/build/libsecond.ld.o",
                .partial_link_sequence = &.{
                    .{ .artifact = .{
                        .kind = .object,
                        .artifact = .{ .path = "/build/libsecond/c.o" },
                    } },
                },
                .transform = .{
                    .input = .{ .library_partial_output = "libsecond" },
                    .output = "/build/libsecond.o",
                },
            },
        },
    };

    const graph = syntheticGraph(
        &libraries,
        &.{ true, true },
        &.{stage},
        &.{true},
    );

    var plan = try planLtoFinalLink(std.testing.allocator, graph, .none);
    defer plan.deinit();

    // No archives → no outer group.
    // Find library artifacts in the arguments.
    var artifact_paths = std.array_list.Managed([]const u8).init(std.testing.allocator);
    defer artifact_paths.deinit();
    for (plan.arguments) |arg| {
        if (arg == .artifact) {
            const path = switch (arg.artifact) {
                .path => |p| p,
                .library_final_object => continue, // should not appear
                else => continue,
            };
            try artifact_paths.append(path);
        }
    }

    try std.testing.expectEqual(@as(usize, 3), artifact_paths.items.len);
    try std.testing.expectEqualStrings("/build/libfirst/a.o", artifact_paths.items[0]);
    try std.testing.expectEqualStrings("/build/libfirst/b.o", artifact_paths.items[1]);
    try std.testing.expectEqualStrings("/build/libsecond/c.o", artifact_paths.items[2]);

    // Contributions preserve order
    try std.testing.expectEqual(@as(usize, 2), plan.contributions.len);
    try std.testing.expectEqualStrings("libfirst", plan.contributions[0].name);
    try std.testing.expectEqual(@as(usize, 0), plan.contributions[0].library_index);
    try std.testing.expectEqualStrings("libsecond", plan.contributions[1].name);
    try std.testing.expectEqual(@as(usize, 1), plan.contributions[1].library_index);
}

test "planLtoFinalLink skips inactive libraries" {
    const stage = minimalFinalLinkStage();
    const libraries = [_]component.Library{
        .{
            .name = "libfoo",
            .origin = .{ .internal = .library },
            .layout = .{ .ordinary = .{ .build_subdir = "libfoo" } },
            .object_pipeline = .{
                .partial_link_output = "/build/libfoo.ld.o",
                .partial_link_sequence = &.{
                    .{ .artifact = .{
                        .kind = .object,
                        .artifact = .{ .path = "/build/libfoo/x.o" },
                    } },
                },
                .transform = .{
                    .input = .{ .library_partial_output = "libfoo" },
                    .output = "/build/libfoo.o",
                },
            },
        },
        .{
            .name = "libbar",
            .origin = .{ .internal = .library },
            .layout = .{ .ordinary = .{ .build_subdir = "libbar" } },
            .object_pipeline = .{
                .partial_link_output = "/build/libbar.ld.o",
                .partial_link_sequence = &.{
                    .{ .artifact = .{
                        .kind = .object,
                        .artifact = .{ .path = "/build/libbar/y.o" },
                    } },
                },
                .transform = .{
                    .input = .{ .library_partial_output = "libbar" },
                    .output = "/build/libbar.o",
                },
            },
        },
    };

    const graph = syntheticGraph(
        &libraries,
        &.{ true, false }, // libbar is inactive
        &.{stage},
        &.{true},
    );

    var plan = try planLtoFinalLink(std.testing.allocator, graph, .perf);
    defer plan.deinit();

    try std.testing.expectEqual(@as(usize, 1), plan.contributions.len);
    try std.testing.expectEqualStrings("libfoo", plan.contributions[0].name);
}

test "planLtoFinalLink rejects non-zig toolchains" {
    const stage = minimalFinalLinkStage();
    const libraries = [_]component.Library{};
    var graph = syntheticGraph(&libraries, &.{}, &.{stage}, &.{true});
    graph.toolchain.compiler.kind = .gcc;

    try std.testing.expectError(
        error.UnsupportedToolchain,
        planLtoFinalLink(std.testing.allocator, graph, .none),
    );
}

test "planLtoFinalLink rejects missing linker script" {
    const stage: component.LinkStage = .{
        .name = "final-link",
        .transformation = .final_link,
        .output = "/build/image.dbg",
        .sequence = &.{
            .{ .literal_flag = "-nostdlib" },
            // No linker_script artifact → should fail
        },
    };
    const libraries = [_]component.Library{};
    const graph = syntheticGraph(&libraries, &.{}, &.{stage}, &.{true});

    try std.testing.expectError(
        error.MissingLinkerScript,
        planLtoFinalLink(std.testing.allocator, graph, .none),
    );
}

test "planLtoFinalLink rejects forbidden driver flags" {
    const stage: component.LinkStage = .{
        .name = "final-link",
        .transformation = .final_link,
        .output = "/build/image.dbg",
        .sequence = &.{
            .{ .literal_flag = "-Wl,-T,bad.lds" },
            .{ .artifact = .{
                .kind = .linker_script,
                .artifact = .{ .path = "/build/combined.lds" },
            } },
        },
    };
    const libraries = [_]component.Library{};
    const graph = syntheticGraph(&libraries, &.{}, &.{stage}, &.{true});

    try std.testing.expectError(
        error.UnsupportedFinalLinkFlag,
        planLtoFinalLink(std.testing.allocator, graph, .none),
    );
}

test "planLtoFinalLink records export files from transform sequence" {
    const stage = minimalFinalLinkStage();
    const libraries = [_]component.Library{.{
        .name = "libfoo",
        .origin = .{ .internal = .library },
        .layout = .{ .ordinary = .{ .build_subdir = "libfoo" } },
        .exports = &.{"/repo/lib/foo/exportsyms.uk"},
        .object_pipeline = .{
            .partial_link_output = "/build/libfoo.ld.o",
            .partial_link_sequence = &.{
                .{ .artifact = .{
                    .kind = .object,
                    .artifact = .{ .path = "/build/libfoo/a.o" },
                } },
            },
            .transform = .{
                .input = .{ .library_partial_output = "libfoo" },
                .output = "/build/libfoo.o",
                .sequence = &.{
                    .{ .symbol_file = .{
                        .action = .keep_global,
                        .symbols_file = "/repo/lib/foo/exportsyms.uk",
                        .provenance = .library_local,
                    } },
                },
            },
        },
    }};

    const graph = syntheticGraph(&libraries, &.{true}, &.{stage}, &.{true});

    var plan = try planLtoFinalLink(std.testing.allocator, graph, .perf);
    defer plan.deinit();

    try std.testing.expectEqual(@as(usize, 1), plan.contributions.len);
    // Both the library-level export and the transform export are recorded.
    // They happen to be the same path so there are 2 entries.
    try std.testing.expectEqual(@as(usize, 2), plan.contributions[0].export_files.len);
    try std.testing.expectEqualStrings(
        "/repo/lib/foo/exportsyms.uk",
        plan.contributions[0].export_files[0],
    );
}

test "validateExportSafety detects duplicate export file paths" {
    const contributions = [_]LibraryContribution{
        .{
            .name = "libA",
            .library_index = 0,
            .artifact_count = 1,
            .export_files = &.{"/repo/shared-exports.uk"},
        },
        .{
            .name = "libB",
            .library_index = 1,
            .artifact_count = 1,
            .export_files = &.{"/repo/shared-exports.uk"},
        },
    };

    const result = try validateExportSafety(std.testing.allocator, &contributions);
    switch (result) {
        .safe => return error.TestExpectedEqual,
        .conflicts => |conflicts| {
            defer std.testing.allocator.free(conflicts);
            try std.testing.expectEqual(@as(usize, 1), conflicts.len);
            try std.testing.expectEqualStrings("/repo/shared-exports.uk", conflicts[0].path);
            try std.testing.expectEqualStrings("libA", conflicts[0].first);
            try std.testing.expectEqualStrings("libB", conflicts[0].second);
        },
    }
}

test "validateExportSafety accepts distinct export files" {
    const contributions = [_]LibraryContribution{
        .{
            .name = "libA",
            .library_index = 0,
            .artifact_count = 1,
            .export_files = &.{"/repo/libA/exports.uk"},
        },
        .{
            .name = "libB",
            .library_index = 1,
            .artifact_count = 1,
            .export_files = &.{"/repo/libB/exports.uk"},
        },
    };

    const result = try validateExportSafety(std.testing.allocator, &contributions);
    try std.testing.expect(result == .safe);
}

test "validateExportSafety accepts libraries without exports" {
    const contributions = [_]LibraryContribution{
        .{
            .name = "libA",
            .library_index = 0,
            .artifact_count = 1,
            .export_files = &.{},
        },
    };

    const result = try validateExportSafety(std.testing.allocator, &contributions);
    try std.testing.expect(result == .safe);
}

test "findDuplicateSymbol detects shared symbol" {
    const a = "foo\nbar\nbaz\n";
    const b = "qux\nbar\n";
    const dup = try findDuplicateSymbol(std.testing.allocator, a, b);
    try std.testing.expect(dup != null);
    try std.testing.expectEqualStrings("bar", dup.?);
}

test "findDuplicateSymbol returns null for disjoint lists" {
    const a = "foo\nbar\n";
    const b = "baz\nqux\n";
    const dup = try findDuplicateSymbol(std.testing.allocator, a, b);
    try std.testing.expect(dup == null);
}

test "findDuplicateSymbol ignores comments and empty lines" {
    const a = "# comment\nfoo\n\nbar\n";
    const b = "# comment\nbaz\n";
    const dup = try findDuplicateSymbol(std.testing.allocator, a, b);
    try std.testing.expect(dup == null);
}

test "findDuplicateSymbol handles trailing whitespace" {
    const a = "foo  \nbar\t\n";
    const b = "bar\n";
    const dup = try findDuplicateSymbol(std.testing.allocator, a, b);
    try std.testing.expect(dup != null);
    try std.testing.expectEqualStrings("bar", dup.?);
}

test "planLtoFinalLink wraps archives in group markers" {
    const stage: component.LinkStage = .{
        .name = "final-link",
        .transformation = .final_link,
        .output = "/build/image.dbg",
        .sequence = &.{
            .{ .literal_flag = "-nostdlib" },
            .{ .artifact = .{
                .kind = .linker_script,
                .artifact = .{ .path = "/build/combined.lds" },
            } },
        },
    };
    const libraries = [_]component.Library{.{
        .name = "libfoo",
        .origin = .{ .internal = .library },
        .layout = .{ .ordinary = .{ .build_subdir = "libfoo" } },
        .object_pipeline = .{
            .partial_link_output = "/build/libfoo.ld.o",
            .partial_link_sequence = &.{
                .{ .artifact = .{
                    .kind = .object,
                    .artifact = .{ .path = "/build/libfoo/a.o" },
                } },
                .group_start,
                .{ .artifact = .{
                    .kind = .archive,
                    .artifact = .{ .path = "/repo/lib/foo.a" },
                } },
                .group_end,
            },
            .transform = .{
                .input = .{ .library_partial_output = "libfoo" },
                .output = "/build/libfoo.o",
            },
        },
    }};

    const graph = syntheticGraph(&libraries, &.{true}, &.{stage}, &.{true});

    var plan = try planLtoFinalLink(std.testing.allocator, graph, .none);
    defer plan.deinit();

    // Expect outer group markers wrapping all flattened inputs.
    var found_start = false;
    var found_end = false;
    var start_index: usize = 0;
    var end_index: usize = 0;
    for (plan.arguments, 0..) |arg, i| {
        if (arg == .literal) {
            if (std.mem.eql(u8, arg.literal, "-Wl,--start-group")) {
                found_start = true;
                start_index = i;
            }
            if (std.mem.eql(u8, arg.literal, "-Wl,--end-group")) {
                found_end = true;
                end_index = i;
            }
        }
    }
    try std.testing.expect(found_start);
    try std.testing.expect(found_end);
    try std.testing.expect(end_index > start_index);
}

test "planLtoFinalLink omits group when no archives present" {
    const stage: component.LinkStage = .{
        .name = "final-link",
        .transformation = .final_link,
        .output = "/build/image.dbg",
        .sequence = &.{
            .{ .literal_flag = "-nostdlib" },
            .{ .artifact = .{
                .kind = .linker_script,
                .artifact = .{ .path = "/build/combined.lds" },
            } },
        },
    };
    const libraries = [_]component.Library{.{
        .name = "libfoo",
        .origin = .{ .internal = .library },
        .layout = .{ .ordinary = .{ .build_subdir = "libfoo" } },
        .object_pipeline = .{
            .partial_link_output = "/build/libfoo.ld.o",
            .partial_link_sequence = &.{
                .{ .artifact = .{
                    .kind = .object,
                    .artifact = .{ .path = "/build/libfoo/a.o" },
                } },
            },
            .transform = .{
                .input = .{ .library_partial_output = "libfoo" },
                .output = "/build/libfoo.o",
            },
        },
    }};

    const graph = syntheticGraph(&libraries, &.{true}, &.{stage}, &.{true});

    var plan = try planLtoFinalLink(std.testing.allocator, graph, .none);
    defer plan.deinit();

    for (plan.arguments) |arg| {
        if (arg == .literal) {
            try std.testing.expect(!std.mem.eql(u8, arg.literal, "-Wl,--start-group"));
            try std.testing.expect(!std.mem.eql(u8, arg.literal, "-Wl,--end-group"));
        }
    }
}

test "planLtoFinalLink returns MissingFinalLinkStage for custom-only stages" {
    const stage: component.LinkStage = .{
        .name = "merge-linker-scripts",
        .transformation = .{ .custom = "merge-linker-scripts" },
        .output = "/build/combined.lds",
        .sequence = &.{},
    };
    const libraries = [_]component.Library{};
    const graph = syntheticGraph(&libraries, &.{}, &.{stage}, &.{true});

    try std.testing.expectError(
        error.MissingFinalLinkStage,
        planLtoFinalLink(std.testing.allocator, graph, .none),
    );
}
