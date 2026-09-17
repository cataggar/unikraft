const std = @import("std");
pub fn build(b: *std.Build) void {
    b.cache_root.path = b.cache_root.handle.realPathFileAlloc(b.graph.io, ".", b.allocator) catch
        @panic("cannot canonicalize the selected fixture cache");
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_root = b.option([]const u8, "test-root", "Existing private absolute fixture directory");
    const timing = b.option(bool, "persistence-timing", "Synthetic timing only (inside unchanged deadlines; never installed)") orelse false;
    const filter = b.option([]const u8, "test-filter", "Run only matching native fixture names");
    const strip_debug = b.option(bool, "strip-fixture-debug", "QUALIFICATION ONLY: verify a debug-stripped synthetic persistence worker copy") orelse false;
    const file_relayout = b.option(bool, "fixture-file-relayout", "QUALIFICATION ONLY: explicitly verify file-offset-only ELF relayout") orelse false;
    if (file_relayout and !strip_debug) @panic("fixture-file-relayout requires strip-fixture-debug=true");
    const layout_policy = if (file_relayout) "file_offset_relayout" else "identical_program_headers";
    const objcopy = b.option([]const u8, "fixture-objcopy", "Explicit absolute pinned native llvm-objcopy for QUALIFICATION ONLY");
    if (strip_debug and objcopy == null) @panic("strip-fixture-debug=true requires -Dfixture-objcopy=ABS");
    if (objcopy) |path| {
        if (!strip_debug) @panic("fixture-objcopy requires strip-fixture-debug=true");
        if (!std.fs.path.isAbsolute(path)) @panic("fixture-objcopy must be absolute");
    }
    const strip_report = b.option([]const u8, "strip-fixture-report", "Optional private create-only absolute persistence worker qualification report");
    if (strip_report) |path| {
        if (!strip_debug) @panic("strip-fixture-report requires strip-fixture-debug=true");
        if (!std.fs.path.isAbsolute(path)) @panic("strip-fixture-report must be absolute");
    }
    const evidence_root = b.option([]const u8, "fixture-build-evidence-root", "Private fresh absolute child for post-test exact fixture build evidence");
    const source_commit = b.option([]const u8, "fixture-source-commit", "User-supplied lowercase commit identity, not authentication");
    const source_tree = b.option([]const u8, "fixture-source-tree", "User-supplied lowercase tree identity, not authentication");
    if (evidence_root) |path| {
        if (!std.fs.path.isAbsolute(path)) @panic("fixture-build-evidence-root must be absolute");
        if (source_commit == null or source_tree == null) @panic("fixture build evidence requires fixture-source-commit and fixture-source-tree");
        const schema = @import("fixture_build_schema.zig");
        schema.validateIdentity(source_commit.?) catch @panic("fixture-source-commit must be 40 lowercase hex characters");
        schema.validateIdentity(source_tree.?) catch @panic("fixture-source-tree must be 40 lowercase hex characters");
        if (filter != null) @panic("fixture build evidence requires all unfiltered persistence tests");
        if (!timing or !strip_debug or !file_relayout or strip_report == null or test_root == null)
            @panic("fixture build evidence requires persistence-timing, strip-fixture-debug, fixture-file-relayout, strip-fixture-report and test-root");
        if (!std.fs.path.isAbsolute(test_root.?)) @panic("fixture build evidence requires absolute test-root");
        if (target.result.os.tag != .linux or target.result.ofmt != .elf or
            target.result.cpu.arch != b.graph.host.result.cpu.arch or
            (target.result.cpu.arch != .aarch64 and target.result.cpu.arch != .x86_64))
            @panic("fixture build evidence requires a native Linux ELF64 qualification target");
    } else if (source_commit != null or source_tree != null) {
        @panic("fixture source identities require fixture-build-evidence-root");
    }
    const sdk = b.dependency("azure_sdk_core", .{ .target = target, .optimize = optimize }).module("azure_sdk_core");
    const storage = b.dependency("azure_sdk_storage_common", .{ .target = target, .optimize = optimize }).module("azure_sdk_storage_common");
    const core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = target, .optimize = optimize });
    const azure = b.createModule(.{
        .root_source_file = b.path("../azure/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "azure_sdk_core", .module = sdk }, .{ .name = "hyperv_core", .module = core } },
    });
    const transfer = b.createModule(.{
        .root_source_file = b.path("../transfer/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "azure_sdk_core", .module = sdk },               .{ .name = "hyperv_core", .module = core },
            .{ .name = "azure_sdk_storage_common", .module = storage },
        },
    });
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "hyperv_core", .module = core },         .{ .name = "hyperv_azure", .module = azure },
        .{ .name = "hyperv_transfer", .module = transfer }, .{ .name = "azure_sdk_core", .module = sdk },
    };
    const module = b.addModule("hyperv_persistence", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    });
    const cli = b.addExecutable(.{
        .name = "uk-hyperv-persistence-engine",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{ .{ .name = "hyperv_persistence", .module = module }, .{ .name = "hyperv_core", .module = core } },
        }),
    });
    b.installArtifact(cli);
    const test_options = b.addOptions();
    if (evidence_root != null) test_options.addOption(bool, "fixture_build_evidence", true);
    test_options.addOption(bool, "persistence_timing", timing);
    test_options.addOption(?[]const u8, "test_root", test_root);
    test_options.addOptionPath("cli", cli.getEmittedBin());
    const worker_fixture = b.addExecutable(.{
        .name = "hyperv-persistence-worker-fixture",
        .root_module = b.createModule(.{ .root_source_file = b.path("worker_fixture.zig"), .target = target, .optimize = optimize, .imports = imports }),
    });
    const measurement = b.createModule(.{ .root_source_file = b.path("../synthetic_measurement.zig"), .target = target, .optimize = optimize });
    worker_fixture.root_module.addImport("synthetic_measurement", measurement);
    const fixture_options = b.addOptions();
    fixture_options.addOption(bool, "persistence_timing", timing);
    worker_fixture.root_module.addOptions("fixture_options", fixture_options);
    const raw_worker = worker_fixture.getEmittedBin();
    const selected_worker = if (strip_debug) stripped: {
        const strip = b.addSystemCommand(&.{ objcopy.?, "--strip-debug" });
        strip.addFileInput(.{ .cwd_relative = objcopy.? });
        strip.addFileArg(raw_worker);
        break :stripped strip.addOutputFileArg("hyperv-persistence-worker-fixture");
    } else raw_worker;
    test_options.addOptionPath("worker", selected_worker);
    const gate_core = b.createModule(.{ .root_source_file = b.path("../core.zig"), .target = b.graph.host, .optimize = .ReleaseSafe });
    const gate_elf = b.createModule(.{ .root_source_file = b.path("../../../build/postprocess-elf.zig"), .target = b.graph.host, .optimize = .ReleaseSafe });
    const equivalence = b.createModule(.{
        .root_source_file = b.path("../preparation/namespace/fixture_debug_equivalence.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
        .imports = &.{ .{ .name = "hyperv_core", .module = gate_core }, .{ .name = "producer_elf", .module = gate_elf } },
    });
    const qualification = b.createModule(.{
        .root_source_file = b.path("fixture_strip.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
        .imports = &.{.{ .name = "equivalence", .module = equivalence }},
    });
    const verifier = b.addExecutable(.{
        .name = "persistence-fixture-strip-verifier",
        .root_module = b.createModule(.{
            .root_source_file = b.path("fixture_strip_verifier.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .imports = &.{.{ .name = "qualification", .module = qualification }},
        }),
    });
    const check: ?*std.Build.Step.Run = if (strip_debug) checked: {
        const verify = b.addRunArtifact(verifier);
        // Cached candidates and an omitted report still require fresh reads.
        verify.has_side_effects = true;
        verify.addFileArg(raw_worker);
        verify.addFileArg(selected_worker);
        verify.addArgs(&.{ "--layout-policy", layout_policy });
        if (strip_report) |path| verify.addArgs(&.{ "--report", path });
        verify.expectExitCode(0);
        break :checked verify;
    } else null;
    const qualify = b.step("qualify-fixture", "Qualify only the non-installed synthetic persistence worker");
    if (check) |verify| qualify.dependOn(&verify.step) else qualify.dependOn(&b.addFail("qualify-fixture requires strip-fixture-debug=true").step);
    const gate_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("../preparation/namespace/fixture_debug_equivalence_tests.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "equivalence", .module = equivalence }},
    }) });
    const run_gate_tests = b.addRunArtifact(gate_tests);
    run_gate_tests.setCwd(.{ .cwd_relative = test_root orelse b.cache_root.path.? });
    const gate_test_step = b.step("test-strip-equivalence", "Run the existing 13 shared ELF and private-file qualification cases");
    gate_test_step.dependOn(&run_gate_tests.step);
    const proof_options = b.addOptions();
    proof_options.addOptionPath("raw", raw_worker);
    proof_options.addOptionPath("candidate", selected_worker);
    proof_options.addOption(bool, "qualified", strip_debug);
    proof_options.addOption(bool, "file_relayout", file_relayout);
    const proof_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("fixture_strip_tests.zig"),
        .target = b.graph.host,
        .optimize = optimize,
        .imports = &.{.{ .name = "qualification", .module = qualification }},
    }) });
    proof_tests.root_module.addOptions("strip_options", proof_options);
    const run_proof_tests = b.addRunArtifact(proof_tests);
    run_proof_tests.setCwd(.{ .cwd_relative = test_root orelse b.cache_root.path.? });
    const proof_test_step = b.step("test-strip-proof", "Test the single persistence-worker proof and explicit verifier options");
    proof_test_step.dependOn(&run_proof_tests.step);
    const tests = b.addTest(.{ .filters = if (filter) |value| &.{value} else &.{}, .root_module = b.createModule(.{
        .root_source_file = b.path("tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    }) });
    tests.root_module.addOptions("test_options", test_options);
    tests.root_module.addImport("synthetic_measurement", measurement);
    const run = b.addRunArtifact(tests);
    b.step("test", "Run offline persistence engine fixtures").dependOn(&run.step);
    const arm_tests = b.addTest(.{ .root_module = azure });
    const arm_run = b.addRunArtifact(arm_tests);
    b.step("test-arm", "Run the affected shared ARM fixtures").dependOn(&arm_run.step);
    if (check) |verify| {
        for ([_]*std.Build.Step{ &run.step, &arm_run.step, &run_gate_tests.step, &run_proof_tests.step, b.getInstallStep() }) |step|
            step.dependOn(&verify.step);
    }
    const library = b.addLibrary(.{ .name = "hyperv-persistence", .root_module = module, .linkage = .static });
    const evidence_steps = addEvidenceTests(b, gate_core, gate_elf, qualification, optimize);
    if (evidence_root == null) {
        const exclusion_options = b.addOptions();
        exclusion_options.addOptionPath("default_parent", tests.getEmittedBin());
        exclusion_options.addOptionPath("production_cli", cli.getEmittedBin());
        exclusion_options.addOptionPath("production_library", library.getEmittedBin());
        exclusion_options.addOptionPath("default_options", test_options.getOutput());
        const exclusion = b.addTest(.{ .root_module = b.createModule(.{
            .root_source_file = b.path("fixture_build_exclusion_tests.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "producer_elf", .module = gate_elf }},
        }) });
        exclusion.root_module.addOptions("exclusion_options", exclusion_options);
        const exclude = b.addRunArtifact(exclusion);
        exclude.setCwd(.{ .cwd_relative = b.cache_root.path.? });
        b.step("test-build-evidence-exclusion", "Check actual default parent and production binaries exclude build evidence without executing fixtures").dependOn(&exclude.step);
    }
    if (evidence_root) |root| {
        const graph = captureModuleGraph(b, tests.root_module);
        const configured = configuredJson(b, tests, graph);
        const baseline = b.addRunArtifact(evidence_steps.collector);
        baseline.has_side_effects = true;
        addCaptureArgs(b, baseline, "baseline", root, source_commit.?, source_tree.?, configured, null, tests, test_options, raw_worker, selected_worker, strip_report.?, test_root.?, graph);
        // Bookend only the actual parent compilation. Options already depend on
        // the worker pair; changing those dependencies would create a cycle.
        tests.step.dependOn(&baseline.step);
        const prepare = b.addRunArtifact(evidence_steps.collector);
        prepare.has_side_effects = true;
        prepare.step.dependOn(&baseline.step);
        addCaptureArgs(b, prepare, "prepare", root, source_commit.?, source_tree.?, configured, tests.getEmittedBin(), tests, test_options, raw_worker, selected_worker, strip_report.?, test_root.?, graph);
        run.step.dependOn(&prepare.step);
        for (evidence_steps.tests) |evidence_test| evidence_test.step.dependOn(&run.step);
        b.step("prepare-build-evidence", "Compile and prepare exact parent custody without running or collecting fixtures").dependOn(&prepare.step);
    }
    b.installArtifact(library);
}

const CapturedModule = struct {
    name: []const u8,
    module: *std.Build.Module,
};

fn captureModuleGraph(b: *std.Build, root: *std.Build.Module) []const CapturedModule {
    const schema = @import("fixture_build_schema.zig");
    var result: std.ArrayList(CapturedModule) = .empty;
    result.append(b.allocator, .{ .name = "main", .module = root }) catch @panic("OOM");
    var index: usize = 0;
    // Public import tables are complete here. getGraph must not be cached in
    // configure phase, before the build runner has finished graph discovery.
    while (index < result.items.len) : (index += 1) {
        const module = result.items[index].module;
        const names = b.allocator.dupe([]const u8, module.import_table.keys()) catch @panic("OOM");
        std.mem.sort([]const u8, names, {}, lessString);
        for (names) |name| {
            schema.validateModuleName(name) catch @panic("unsupported evidence module name");
            const imported = module.import_table.get(name).?;
            const found = for (result.items) |item| {
                if (item.module == imported) break true;
            } else false;
            if (found) continue;
            if (result.items.len >= schema.max_modules) @panic("fixture module graph exceeds evidence bound");
            const collision = for (result.items) |item| {
                if (std.mem.eql(u8, item.name, name)) break true;
            } else false;
            const label = if (collision) b.fmt("{s}_{d}", .{ name, result.items.len }) else name;
            schema.validateModuleName(label) catch @panic("unsupported evidence module label");
            result.append(b.allocator, .{ .name = label, .module = imported }) catch @panic("OOM");
        }
    }
    std.mem.sort(CapturedModule, result.items, {}, struct {
        fn less(_: void, left: CapturedModule, right: CapturedModule) bool {
            return std.mem.lessThan(u8, left.name, right.name);
        }
    }.less);
    return result.toOwnedSlice(b.allocator) catch @panic("OOM");
}

fn lessString(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

const GraphDescription = struct {
    modules: []const CapturedModule,

    pub fn jsonStringify(self: GraphDescription, j: *std.json.Stringify) !void {
        try j.beginArray();
        for (self.modules) |item| {
            try j.beginObject();
            try j.objectField("name");
            try j.write(item.name);
            try j.objectField("imports");
            try j.beginArray();
            const module = item.module;
            const names = module.owner.allocator.dupe([]const u8, module.import_table.keys()) catch return error.WriteFailed;
            std.mem.sort([]const u8, names, {}, lessString);
            for (names) |name| {
                const imported = module.import_table.get(name).?;
                const label = for (self.modules) |candidate| {
                    if (candidate.module == imported) break candidate.name;
                } else unreachable;
                try j.write(.{ .name = name, .module = label });
            }
            try j.endArray();
            try j.endObject();
        }
        try j.endArray();
    }
};

const QueryVersion = struct {
    value: ?std.Target.Query.OsVersion,

    pub fn jsonStringify(self: QueryVersion, j: *std.json.Stringify) !void {
        const value = self.value orelse return j.write(null);
        try j.beginObject();
        try j.objectField(@tagName(value));
        switch (value) {
            .none => try j.write(null),
            inline else => |version| try j.write(version),
        }
        try j.endObject();
    }
};

fn configuredJson(b: *std.Build, compile: *std.Build.Step.Compile, graph: []const CapturedModule) []const u8 {
    const metadata = @import("fixture_parent_metadata.zig");
    const m = compile.root_module;
    const build_id = compile.build_id orelse b.build_id;
    const build_id_hex = if (build_id) |value| switch (value) {
        .hexstring => |hex| std.fmt.allocPrint(b.allocator, "{x}", .{hex.toSlice()}) catch @panic("cannot serialize build ID"),
        else => @as(?[]const u8, null),
    } else null;
    const resolved = m.resolved_target.?;
    const q = resolved.query;
    const explicit_model: ?struct {
        name: []const u8,
        llvm_name: ?[:0]const u8,
        baseline_features: metadata.Features,
    } = switch (q.cpu_model) {
        .explicit => |model| .{
            .name = model.name,
            .llvm_name = model.llvm_name,
            .baseline_features = .{ .arch = resolved.result.cpu.arch, .set = model.features },
        },
        else => null,
    };
    const value = .{
        .schema = "hyperv_persistence_fixture_configured_build_v1",
        .origin = "actual_parent_Compile_and_rootModule",
        .null_semantics = "unspecified_compiler_default_not_observed_false",
        .source_identity = "user_supplied_not_authenticated",
        .test_selection = "all_unfiltered_35_main_cases",
        .test_filters = compile.filters,
        .test_run_seed = b.graph.random_seed,
        .parent_compilation_bookend = "metadata_only_baseline_and_prepare",
        .worker_compiler_bookend = "not_claimed_workers_precede_baseline",
        .module_scope = "configured_reachable_package_envelopes_not_compiler_resolved_import_embed_closure",
        .modules = GraphDescription{ .modules = graph },
        .target_query = .{
            .cpu_arch = q.cpu_arch,
            .cpu_model = @tagName(q.cpu_model),
            .explicit_cpu_model = explicit_model,
            .cpu_features_add = metadata.Features{ .arch = resolved.result.cpu.arch, .set = q.cpu_features_add },
            .cpu_features_sub = metadata.Features{ .arch = resolved.result.cpu.arch, .set = q.cpu_features_sub },
            .os_tag = q.os_tag,
            .os_version_min = QueryVersion{ .value = q.os_version_min },
            .os_version_max = QueryVersion{ .value = q.os_version_max },
            .glibc_version = q.glibc_version,
            .android_api_level = q.android_api_level,
            .abi = q.abi,
            .ofmt = q.ofmt,
            .dynamic_linker_specified = q.dynamic_linker != null,
            .dynamic_linker_path = "omitted_path",
        },
        .resolved_target = metadata.Target{ .value = resolved.result },
        .compile = .{
            .kind = compile.kind,
            .debug_compiler_runtime_libs = b.graph.debug_compiler_runtime_libs,
            .incremental = b.graph.incremental,
            .debug_incremental = b.debug_incremental,
            .build_id_kind = if (build_id) |value| @tagName(value) else null,
            .build_id_hex = build_id_hex,
            .build_id_override = compile.build_id != null,
            .use_llvm = compile.use_llvm,
            .use_lld = compile.use_lld,
            .use_new_linker = compile.use_new_linker,
            .linkage = compile.linkage,
            .pie = compile.pie,
            .lto = compile.lto,
            .stack_size = compile.stack_size,
            .rdynamic = compile.rdynamic,
            .link_gc_sections = compile.link_gc_sections,
            .link_function_sections = compile.link_function_sections,
            .link_data_sections = compile.link_data_sections,
            .compress_debug_sections = compile.compress_debug_sections,
            .bundle_compiler_rt = compile.bundle_compiler_rt,
            .bundle_ubsan_rt = compile.bundle_ubsan_rt,
            .zig_lib_dir_override = compile.zig_lib_dir != null,
            .custom_test_runner = compile.test_runner != null,
        },
        .root_module = .{
            .optimize = m.optimize,
            .strip = m.strip,
            .dwarf_format = m.dwarf_format,
            .unwind_tables = m.unwind_tables,
            .single_threaded = m.single_threaded,
            .stack_protector = m.stack_protector,
            .stack_check = m.stack_check,
            .sanitize_c = m.sanitize_c,
            .sanitize_thread = m.sanitize_thread,
            .fuzz = m.fuzz,
            .code_model = m.code_model,
            .valgrind = m.valgrind,
            .pic = m.pic,
            .red_zone = m.red_zone,
            .omit_frame_pointer = m.omit_frame_pointer,
            .error_tracing = m.error_tracing,
            .link_libc = m.link_libc,
            .link_libcpp = m.link_libcpp,
            .no_builtin = m.no_builtin,
        },
    };
    const result = std.json.Stringify.valueAlloc(b.allocator, value, .{}) catch @panic("cannot serialize configured parent build");
    if (result.len > @import("fixture_build_schema.zig").max_metadata_bytes) @panic("configured parent build exceeds evidence bound");
    return result;
}

fn addCaptureArgs(
    b: *std.Build,
    run: *std.Build.Step.Run,
    mode: []const u8,
    root: []const u8,
    commit: []const u8,
    tree: []const u8,
    configured: []const u8,
    parent: ?std.Build.LazyPath,
    compile: *std.Build.Step.Compile,
    main_options: *std.Build.Step.Options,
    raw: std.Build.LazyPath,
    selected: std.Build.LazyPath,
    proof: []const u8,
    test_root: []const u8,
    graph: []const CapturedModule,
) void {
    run.addArgs(&.{ mode, root, commit, tree, configured });
    if (parent) |path| run.addFileArg(path) else run.addArg("");
    run.addFileArg(raw);
    run.addFileArg(selected);
    run.addFileArg(.{ .cwd_relative = b.graph.zig_exe });
    run.addDirectoryArg(absoluteLazy(b, compile.zig_lib_dir orelse .{ .cwd_relative = b.graph.zig_lib_directory.path.? }));
    run.addFileArg(main_options.getOutput());
    run.addFileArg(absoluteLazy(b, compile.root_module.root_source_file.?));
    run.addDirectoryArg(absoluteLazy(b, b.path("..")));
    run.addDirectoryArg(absoluteLazy(b, b.path("../../../build")));
    const mode_root = std.fs.path.dirname(test_root) orelse @panic("invalid test root");
    run.addArgs(&.{ proof, b.pathJoin(&.{ mode_root, "fixtures.log" }), b.pathJoin(&.{ mode_root, "fixture-build-exit.txt" }) });
    for (graph) |item| {
        const source = item.module.root_source_file orelse @panic("evidence module requires a root source");
        run.addArg(item.name);
        run.addFileArg(absoluteLazy(b, source));
        const scope = switch (source) {
            .generated => source.dirname(),
            else => if (item.module.owner == b) b.path("..") else item.module.owner.path("."),
        };
        run.addDirectoryArg(absoluteLazy(b, scope));
    }
}

fn absoluteLazy(b: *std.Build, path: std.Build.LazyPath) std.Build.LazyPath {
    // Only the private helper argv is normalized; compiler paths stay intact.
    const absolute = switch (path) {
        .generated => return path,
        .src_path => |source| b.pathResolve(&.{ b.graph.cache.cwd, source.owner.build_root.path orelse ".", source.sub_path }),
        .dependency => |source| b.pathResolve(&.{ b.graph.cache.cwd, source.dependency.builder.build_root.path orelse ".", source.sub_path }),
        .cwd_relative => |source| b.pathResolve(&.{ b.graph.cache.cwd, source }),
    };
    return .{ .cwd_relative = absolute };
}

fn addEvidenceTests(
    b: *std.Build,
    core: *std.Build.Module,
    elf: *std.Build.Module,
    qualification: *std.Build.Module,
    optimize: std.builtin.OptimizeMode,
) struct { collector: *std.Build.Step.Compile, tests: [2]*std.Build.Step.Run } {
    const paths = b.createModule(.{
        .root_source_file = b.path("../../../build/zig-facade-paths.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
    });
    const files = b.createModule(.{
        .root_source_file = b.path("../preparation/files.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
        .imports = &.{ .{ .name = "hyperv_core", .module = core }, .{ .name = "facade_paths", .module = paths } },
    });
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "hyperv_core", .module = core },
        .{ .name = "preparation_files", .module = files },
        .{ .name = "producer_elf", .module = elf },
        .{ .name = "qualification", .module = qualification },
    };
    const collector = b.addExecutable(.{
        .name = "persistence-fixture-build-capture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("fixture_build_capture.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .imports = imports,
        }),
    });
    const evidence_test_step = b.step("test-build-evidence", "Test bounded native collection and static compile metadata without running main fixtures");
    var test_runs: [2]*std.Build.Step.Run = undefined;
    for ([_][]const u8{ "fixture_build_evidence_tests.zig", "fixture_build_metadata_tests.zig" }, &test_runs) |source, *test_run| {
        const tests = b.addTest(.{ .root_module = b.createModule(.{
            .root_source_file = b.path(source),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = imports,
        }) });
        const run = b.addRunArtifact(tests);
        run.setCwd(.{ .cwd_relative = b.cache_root.path.? });
        test_run.* = run;
        evidence_test_step.dependOn(&run.step);
    }
    return .{ .collector = collector, .tests = test_runs };
}
