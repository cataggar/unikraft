// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/core.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../../tools/hyperv/sha256_clear_upper.S"));
    const serial = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/local_boot/serial.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    });
    const validator = b.createModule(.{
        .root_source_file = b.path("../../apps/wamr-aot/validator/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "local_boot_serial", .module = serial },
        },
    });
    const source_closure = sourceClosureModule(b, target, optimize);
    const controller = b.createModule(.{
        .root_source_file = b.path("controller/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "wamr_log_validator", .module = validator },
            .{ .name = "controller_source_closure", .module = source_closure },
            .{ .name = "handoff_contracts", .module = b.createModule(.{
                .root_source_file = b.path("handoff/contracts.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "hyperv_core", .module = core }},
            }) },
        },
    });
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("handoff/tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "hyperv_core", .module = core },
                .{ .name = "wamr_controller", .module = controller },
            },
        }),
    });
    const candidate_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("handoff/candidate.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "hyperv_core", .module = core },
                .{ .name = "wamr_controller", .module = controller },
            },
        }),
    });
    const candidate_run = b.addRunArtifact(candidate_tests);
    b.step("test-candidate", "Run no-authority candidate encoding and result edge cases")
        .dependOn(&candidate_run.step);
    const repo_root_abs = std.Io.Dir.cwd().realPathFileAlloc(
        b.graph.io,
        b.root.joinString(b.allocator, "../..") catch @panic("OOM"),
        b.allocator,
    ) catch @panic("OOM");
    const default_fixture_root = b.pathJoin(&.{ repo_root_abs, ".zig-cache/handoff-tests" });
    const fixture_root = if (b.option([]const u8, "test-root", "Existing absolute private handoff fixture root")) |path| blk: {
        if (!std.fs.path.isAbsolute(path)) @panic("handoff fixture root must be absolute");
        break :blk path;
    } else default_fixture_root;
    const options = b.addOptions();
    options.addOption([]const u8, "fixture_root", fixture_root);
    candidate_tests.root_module.addOptions("test_options", options);
    options.addOption([]const u8, "accepted_result_fixture", std.Io.Dir.cwd().realPathFileAlloc(
        b.graph.io,
        b.root.joinString(b.allocator, "tests/fixtures/differential/accepted-v2.json") catch @panic("OOM"),
        b.allocator,
    ) catch @panic("cannot resolve accepted handoff fixture"));
    tests.root_module.addOptions("test_options", options);
    const run = b.addRunArtifact(tests);
    const step = b.step("test", "Run native handoff contract goldens");
    step.dependOn(&run.step);
    const archive_options = b.addOptions();
    archive_options.addOption([]const u8, "fixture_root", b.pathJoin(&.{ fixture_root, "handoff-public-archive-tests" }));
    const genuine_archive = b.option([]const u8, "public-archive", "Read-only genuine public inner ZIP fixture");
    archive_options.addOption(?[]const u8, "genuine_archive", genuine_archive);
    const archive_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("handoff/public_archive_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "hyperv_core", .module = core },
                .{ .name = "wamr_controller", .module = controller },
            },
        }),
    });
    archive_tests.root_module.addOptions("test_options", archive_options);
    const archive_run = b.addRunArtifact(archive_tests);
    const transport_options = b.addOptions();
    const genuine_source = b.option([]const u8, "public-source", "Independently trusted genuine archive producer commit") orelse "c8f45aefcb855480605830ea47a8990c72d0fda3";
    const genuine_tree = b.option([]const u8, "public-tree", "Independently trusted genuine archive producer tree") orelse "47fafaddda9b4c56cba06c868c1cad0a62084c60";
    const genuine_run = b.option([]const u8, "public-run-id", "Independently trusted genuine archive run") orelse "37321447300";
    const genuine_attempt = b.option([]const u8, "public-run-attempt", "Independently trusted genuine archive attempt") orelse "1";
    const genuine_sha = b.option([]const u8, "public-inner-sha256", "Independently trusted inner archive SHA-256") orelse "269d0c17d48ac5c722d79774f6b399bd56d8b8e68f9d2ff24f827deab63c27c4";
    const genuine_bytes = b.option(u64, "public-archive-bytes", "Independently trusted genuine inner archive byte count") orelse 146418230;
    inline for (.{ archive_options, transport_options }) |genuine_options| {
        genuine_options.addOption([]const u8, "genuine_source", genuine_source);
        genuine_options.addOption([]const u8, "genuine_tree", genuine_tree);
        genuine_options.addOption([]const u8, "genuine_run", genuine_run);
        genuine_options.addOption([]const u8, "genuine_attempt", genuine_attempt);
        genuine_options.addOption([]const u8, "genuine_sha", genuine_sha);
        genuine_options.addOption(u64, "genuine_bytes", genuine_bytes);
    }
    transport_options.addOption([]const u8, "genuine_artifact_id", b.option([]const u8, "public-artifact-id", "Independently trusted exact Actions artifact ID") orelse "11356844780");
    transport_options.addOption([]const u8, "genuine_container_sha", b.option([]const u8, "public-container-sha256", "Independently trusted outer Actions container SHA-256") orelse "d1f3055c1eba55b1f21f7a78c63e8d9f8b340052f66dfc1369b53b50a33cefef");
    transport_options.addOption([]const u8, "fixture_root", b.pathJoin(&.{ fixture_root, "handoff-public-transport-tests" }));
    transport_options.addOption(?[]const u8, "genuine_archive", genuine_archive);
    transport_options.addOption(?[]const u8, "python_receipt", b.option([]const u8, "transport-receipt", "Live Python v2 transport receipt oracle for the genuine archive"));
    const transport_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("handoff/public_transport_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "hyperv_core", .module = core },
                .{ .name = "wamr_controller", .module = controller },
            },
        }),
    });
    transport_tests.root_module.addOptions("test_options", transport_options);
    const transport_run = b.addRunArtifact(transport_tests);
    const fixture_dirs = b.addSystemCommand(&.{ "mkdir", "-p", "-m", "0700", "--" });
    fixture_dirs.has_side_effects = true;
    fixture_dirs.addArg(fixture_root);
    inline for (.{ "handoff-export-tests", "handoff-public-archive-tests", "handoff-public-transport-tests" }) |name|
        fixture_dirs.addArg(b.pathJoin(&.{ fixture_root, name }));
    inline for (.{ &run.step, &archive_run.step, &transport_run.step, &candidate_run.step }) |test_step|
        test_step.dependOn(&fixture_dirs.step);
    b.step("test-unit", "Run native handoff contract unit tests").dependOn(&run.step);
    b.step("test-public-archive", "Run native public archive engine tests").dependOn(&archive_run.step);
    b.step("test-public-transport", "Run native public transport staging and binding tests").dependOn(&transport_run.step);
    step.dependOn(&archive_run.step);
    step.dependOn(&transport_run.step);
}

fn sourceClosureModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
) *std.Build.Module {
    const source_file = b.path("../../controller_source_closure.zig");
    b.dependOnFileContents(source_file);
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        b.graph.io,
        b.root.joinString(b.allocator, "../../controller_source_closure.zig") catch @panic("OOM"),
        b.allocator,
        .limited(1024 * 1024),
    ) catch |err| std.debug.panic("read controller source closure: {s}", .{@errorName(err)});
    const text = b.allocator.dupeSentinel(u8, bytes, 0) catch @panic("OOM");
    const module = b.createModule(.{
        .root_source_file = source_file,
        .target = target,
        .optimize = optimize,
    });
    var tokenizer = std.zig.Tokenizer.init(text);
    while (true) {
        const token = tokenizer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid)
            @panic("invalid controller source inventory");
        if (token.tag != .builtin or
            !std.mem.eql(u8, text[token.loc.start..token.loc.end], "@embedFile"))
            continue;
        if (tokenizer.next().tag != .l_paren)
            @panic("invalid controller source embed");
        const literal = tokenizer.next();
        if (literal.tag != .string_literal or tokenizer.next().tag != .r_paren)
            @panic("controller source embeds must name literal files");
        const name = std.zig.string_literal.parseAlloc(b.allocator, text[literal.loc.start..literal.loc.end]) catch
            @panic("invalid controller source embed name");
        if (module.import_table.contains(name))
            continue;
        module.addImport(name, b.createModule(.{
            .root_source_file = b.path(b.fmt("../../{s}", .{name})),
            .target = target,
            .optimize = optimize,
        }));
    }
    return module;
}
