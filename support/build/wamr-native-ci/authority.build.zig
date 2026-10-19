// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub fn addImports(b: *std.Build, module: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize, core: *std.Build.Module, serial: *std.Build.Module, validator: *std.Build.Module, handoff: *std.Build.Module) void {
    module.addImport("hyperv_core", core);
    module.addImport("wamr_handoff", handoff);
    module.addImport("wamr_controller", handoff.import_table.get("wamr_controller").?);
    module.addImport("producer_elf", b.createModule(.{
        .root_source_file = b.path("../postprocess-elf.zig"),
        .target = target,
        .optimize = optimize,
    }));
    module.addImport("wamr_direct_compute", b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/direct/compute.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "local_serial", .module = serial },
            .{ .name = "wamr_log_validator", .module = validator },
        },
    }));
}

pub fn defaultFixtureRoot(b: *std.Build) []const u8 {
    if (b.option([]const u8, "test-root", "Existing private absolute authority fixture root")) |root| {
        if (!std.fs.path.isAbsolute(root)) @panic("authority fixture root must be absolute");
        return root;
    }
    const cwd = std.Io.Dir.cwd().realPathFileAlloc(b.graph.io, ".", b.allocator) catch
        @panic("cannot resolve authority current working directory");
    const base = if (b.graph.environ_map.get("ZIG_LOCAL_CACHE_DIR")) |cache_dir|
        std.fs.path.resolve(b.allocator, &.{ cwd, cache_dir }) catch @panic("cannot resolve authority cache root")
    else
        std.fs.path.resolve(b.allocator, &.{ cwd, b.root.joinString(b.allocator, ".zig-cache") catch @panic("OOM") }) catch @panic("cannot resolve authority cache root");
    const root = b.pathJoin(&.{ base, "authority-fixture-root" });
    std.Io.Dir.cwd().createDirPath(b.graph.io, base) catch @panic("cannot create authority cache root");
    std.Io.Dir.cwd().createDir(b.graph.io, root, .fromMode(0o700)) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => @panic("cannot create authority fixture root"),
    };
    return root;
}

pub fn sourceClosureModule(
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

pub fn testOptions(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize, fixture_root: anytype) *std.Build.Step.Options {
    return testOptionsWithTools(b, target, optimize, fixture_root, null, null);
}

pub fn testOptionsWithTools(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
    fixture_root: anytype,
    existing_validator: ?std.Build.LazyPath,
    existing_package: ?std.Build.LazyPath,
) *std.Build.Step.Options {
    const fixture = b.addExecutable(.{
        .name = "authority-process-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("../../tools/hyperv/process_fixture.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
        }),
    });
    const options = b.addOptions();
    if (@TypeOf(fixture_root) == std.Build.LazyPath) {
        options.addOptionPathUntracked("fixture_root", fixture_root);
    } else {
        if (!std.fs.path.isAbsolute(fixture_root)) @panic("authority fixture root must be absolute");
        options.addOption([]const u8, "fixture_root", fixture_root);
    }
    options.addOptionPath("process_fixture", fixture.getEmittedBin());
    const probe_fixture = b.addExecutable(.{
        .name = "authority-runtime-probe-fault-fixture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("authority/runtime_probes_fixture.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
        }),
    });
    options.addOptionPath("probe_fixture", probe_fixture.getEmittedBin());
    options.addOptionPath("validator", existing_validator orelse b.dependency("direct_validator", .{ .target = target, .optimize = .safe }).artifact("uk-wamr-direct-validate").getEmittedBin());
    if (existing_package) |pkg_bin| {
        options.addOptionPath("authorization_package", pkg_bin);
    } else {
        const image = b.dependency("public_image", .{ .target = target, .optimize = .safe }).module("hyperv_public_image");
        for (b.graph.configure_dependencies.items) |*dep| switch (dep.lazy_path) {
            .src_path => |sp| if (sp.owner != b) {
                dep.lazy_path = b.graph.cwdRelativePath(
                    sp.owner.root.joinString(b.allocator, sp.sub_path) catch @panic("OOM"),
                );
            },
            else => {},
        };
        const package_options = b.addOptions();
        package_options.addOption([]const u8, "miz_revision", "66ea6701cf0e1b6d31e5f30fade00b7a546d4b44");
        const package = b.addExecutable(.{
            .name = "authorization-image-fixture",
            .root_module = b.createModule(.{
                .root_source_file = b.path("package.zig"),
                .target = target,
                .optimize = .safe,
                .strip = true,
                .imports = &.{
                    .{ .name = "public_image", .module = image },
                    .{ .name = "package_options", .module = package_options.createModule() },
                },
            }),
        });
        options.addOptionPath("authorization_package", package.getEmittedBin());
    }
    return options;
}

pub fn sourceCheck(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize, authority: *std.Build.Module) *std.Build.Step.Compile {
    const generated = b.addWriteFiles();
    const source = generated.add("authority-source-check.zig",
        \\const authority = @import("wamr_authority");
        \\export fn authoritySourceCheck(inputs: *const authority.types.PlanInputs, transaction: *authority.transaction.Transaction, barrier: *const authority.transaction.Barrier, bytes: [*]const u8, len: usize) u16 {
        \\    _ = authority.records.plan(inputs.*, null) catch |err| return @intFromError(err);
        \\    return switch (transaction.publish(bytes[0..len], barrier.*)) {
        \\        .success => 0,
        \\        .refused, .poisoned => |failure| @intFromError(failure.err),
        \\    };
        \\}
        \\export fn authorityHandlers(ctx: *const authority.handlers.Context, command: *const authority.types.Command) u16 {
        \\    return switch (authority.handlers.run(ctx.*, command.*)) {
        \\        .prepare => |outcome| switch (outcome) {
        \\            .success => |owner| result: { defer owner.deinit(); _ = owner.result() catch |err| break :result @intFromError(err); break :result 0; },
        \\            .refused, .poisoned => |failure| @intFromError(failure.err),
        \\        },
        \\        .plan => |outcome| switch (outcome) {
        \\            .success => |owner| result: { defer owner.deinit(); _ = owner.result() catch |err| break :result @intFromError(err); break :result 0; },
        \\            .refused, .poisoned => |failure| @intFromError(failure.err),
        \\        },
        \\        .authorization => |outcome| switch (outcome) {
        \\            .success => |owner| result: { defer owner.deinit(); owner.revalidate() catch |err| break :result @intFromError(err); _ = owner.value(); _ = owner.artifact(); break :result 0; },
        \\            .refused, .poisoned => |failure| @intFromError(failure.err),
        \\        },
        \\        .admission => |outcome| switch (outcome) {
        \\            .success => |owner| result: { defer owner.deinit(); _ = owner.artifact() catch |err| break :result @intFromError(err); break :result 0; },
        \\            .refused, .poisoned => |failure| @intFromError(failure.err),
        \\        },
        \\    };
        \\}
    );
    return b.addObject(.{
        .name = "authority-source-check",
        .root_module = b.createModule(.{
            .root_source_file = source,
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "wamr_authority", .module = authority }},
        }),
    });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.createModule(.{ .root_source_file = b.path("../../tools/hyperv/core.zig"), .target = target, .optimize = optimize });
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
    const identity_writer = b.addExecutable(.{
        .name = "authority-validator-identity",
        .root_module = b.createModule(.{ .root_source_file = b.path("authority.build.zig"), .target = b.graph.host, .optimize = .safe }),
    });
    const identity_run = b.addRunArtifact(identity_writer);
    identity_run.addFileArg(b.dependency("direct_validator", .{ .target = target, .optimize = .safe }).artifact("uk-wamr-direct-validate").getEmittedBin());
    const identity = b.createModule(.{
        .root_source_file = b.addWriteFiles().addCopyFile(identity_run.captureStdOut(.{}), "authority-validator-identity.zig"),
        .target = target,
        .optimize = optimize,
    });
    const controller = b.createModule(.{
        .root_source_file = b.path("controller/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "wamr_log_validator", .module = validator },
            .{ .name = "import_validator_identity", .module = identity },
            .{ .name = "controller_source_closure", .module = sourceClosureModule(b, target, optimize) },
            .{ .name = "handoff_contracts", .module = b.createModule(.{
                .root_source_file = b.path("handoff/contracts.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "hyperv_core", .module = core }},
            }) },
        },
    });
    const handoff = b.createModule(.{
        .root_source_file = b.path("handoff/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "hyperv_core", .module = core },
            .{ .name = "wamr_controller", .module = controller },
        },
    });
    const filter = b.option([]const u8, "test-filter", "Run matching authority source tests");
    const filters = b.option([]const []const u8, "authority-test-filter", "Select bounded authority fixtures") orelse
        if (filter) |value| &.{value} else &.{};
    const tests = b.addTest(.{ .filters = filters, .root_module = b.createModule(.{
        .root_source_file = b.path("authority/library_tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "hyperv_core", .module = core }},
    }) });
    addImports(b, tests.root_module, target, optimize, core, serial, validator, handoff);
    const fixture_root = defaultFixtureRoot(b);
    const options = testOptions(b, target, optimize, fixture_root);
    const options_module = options.createModule();
    tests.root_module.addImport("test_options", options_module);
    handoff.addImport("test_options", options_module);
    const run = b.addRunArtifact(tests);
    const authority = b.createModule(.{ .root_source_file = b.path("authority/root.zig"), .target = target, .optimize = optimize });
    addImports(b, authority, target, optimize, core, serial, validator, handoff);
    const source_check = sourceCheck(b, target, optimize, authority);
    const native_step = b.step("test-native", "Run native authority contracts and foundations");
    native_step.dependOn(&run.step);
    native_step.dependOn(&source_check.step);
    b.step("source-check", "Compile all real authority source library operations").dependOn(&source_check.step);
    const direct = b.addSystemCommand(&.{"/usr/bin/env"});
    direct.addFileArg(tests.getEmittedBin());
    const direct_step = b.step("test-native-direct", "Run native authority fixtures with direct failure output");
    direct_step.dependOn(&direct.step);
    direct_step.dependOn(&source_check.step);
    const scratch_root = b.pathJoin(&.{ fixture_root, "authority-contract-work" });
    std.Io.Dir.cwd().createDir(b.graph.io, scratch_root, .fromMode(0o700)) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => @panic("cannot create authority contract scratch root"),
    };
    const python = b.addSystemCommand(&.{ "python3", "-B" });
    python.setEnvironmentVariable("WAMR_AUTHORITY_CONTRACT_SCRATCH", scratch_root);
    python.addFileArg(b.path("tests/test_authority_contract_goldens.py"));
    const step = b.step("test", "Run native authority foundations and Python contract goldens");
    step.dependOn(&run.step);
    step.dependOn(&source_check.step);
    step.dependOn(&python.step);
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidUsage;
    const file = try std.Io.Dir.cwd().openFile(init.io, args[1], .{ .follow_symlinks = false });
    defer file.close(init.io);
    const before = try file.stat(init.io);
    if (before.size > 64 * 1024 * 1024) return error.ArtifactLimit;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < before.size) {
        const count = try file.readPositionalAll(init.io, buffer[0..@intCast(@min(buffer.len, before.size - offset))], offset);
        if (count == 0) return error.ArtifactChanged;
        hash.update(buffer[0..count]);
        offset += count;
    }
    const after = try file.stat(init.io);
    if (before.size != after.size or !std.meta.eql(before.mtime, after.mtime))
        return error.ArtifactChanged;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &.{});
    try stdout.interface.print("pub const sha256 = \"{s}\";\n", .{std.fmt.bytesToHex(hash.finalResult(), .lower)});
}

