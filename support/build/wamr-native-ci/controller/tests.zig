// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const controller = @import("wamr_controller");
const core = @import("hyperv_core");
const options = @import("test_options");

test "build command table has closed roles, order, deadlines and native executables" {
    const plan = controller.command_plan;
    const expected = [_]struct { stage: plan.Stage, seconds: u32, executable: []const u8 }{
        .{ .stage = .adapter, .seconds = 900, .executable = "tool:zig" },
        .{ .stage = .@"local-boot-tool", .seconds = 900, .executable = "tool:zig" },
        .{ .stage = .fixtures, .seconds = 600, .executable = "native:wamr-native-ci-fixtures" },
        .{ .stage = .prepare, .seconds = 1800, .executable = "native:wamr-aot-build" },
        .{ .stage = .config, .seconds = 600, .executable = "native:wamr-aot-build" },
        .{ .stage = .@"native-image", .seconds = 1800, .executable = "native:wamr-aot-build" },
    };
    for (expected) |item| {
        const stage = plan.spec(item.stage);
        try std.testing.expectEqual(item.stage, stage.stage);
        try std.testing.expectEqual(item.seconds, stage.seconds);
        try std.testing.expectEqualStrings(item.executable, stage.executable);
        try std.testing.expectEqualStrings(item.executable, stage.argv[0].path.role);
        try std.testing.expectEqual(@as(usize, 4 * 1024 * 1024), plan.limits(stage).stdout_bytes);
        const env = try plan.environment(std.testing.allocator, item.stage);
        defer plan.freeEnvironment(std.testing.allocator, env);
        for (env, 0..) |binding, i| {
            if (i > 0) try std.testing.expect(std.mem.lessThan(u8, env[i - 1].name, binding.name));
        }
    }
    try std.testing.expectEqualStrings("prepare", plan.spec(.prepare).argv[1].literal);
    try std.testing.expectEqualStrings("olddefconfig", plan.spec(.config).argv[1].literal);
    try std.testing.expectEqualStrings("native-images", plan.spec(.@"native-image").argv[1].literal);
    try std.testing.expectEqualStrings("local-boot-tools", plan.spec(.@"local-boot-tool").argv[7].path.relative);
    try std.testing.expectError(error.UnboundCommandRole, (plan.Roots{
        .source_root = "/source",
        .runtime = "/runtime",
        .work = "/work",
        .zig = "/zig",
        .producer = "/producer",
        .fixture_runner = "/fixtures",
        .supervisor = "/controller",
        .package_tool = "/package",
        .validator = "/validator",
        .supervisor_fixture = "/supervisor-fixture",
        .tools = @as([controller.input_custody.host_tools.len][]const u8, @splat("/tool")),
    }).get("tool:sh"));
}

test "handoff inspect command matches Python's closed post-run contract" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const plan = controller.command_plan;
    const selected = plan.spec(.@"handoff-inspect");
    try std.testing.expectEqual(@as(u32, 150), selected.seconds);
    try std.testing.expectEqual(@as(usize, 64 * 1024), selected.output_limit);
    try std.testing.expectEqualStrings("input:package_tool", selected.executable);
    try std.testing.expect(plan.isBoot(selected.stage));
    try std.testing.expectEqual(@as(usize, 64 * 1024 + 1), plan.limits(selected).stdout_bytes);
    try std.testing.expectEqual(@as(usize, 64 * 1024 + 1), plan.limits(selected).stderr_bytes);
    const reference = try std.fs.path.join(a, &.{ options.repository_root, "support/build/wamr-native-ci/run.py" });
    defer a.free(reference);
    const script =
        \\import importlib.util,sys
        \\s=importlib.util.spec_from_file_location("ci",sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
        \\sys.stdout.buffer.write(m.canonical_json(m.production_command_contract("handoff-inspect")))
    ;
    const response = try std.process.run(a, io, .{
        .argv = &.{ options.python_executable, "-B", "-c", script, reference },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(16384),
        .stderr_limit = .limited(4096),
    });
    defer a.free(response.stdout);
    defer a.free(response.stderr);
    if (response.term != .exited or response.term.exited != 0)
        std.debug.print("handoff contract oracle: {s}\n", .{response.stderr});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, response.term);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, response.stdout, .{ .duplicate_field_behavior = .@"error", .parse_numbers = false });
    defer parsed.deinit();
    const contract = parsed.value.object;
    try std.testing.expectEqualStrings("bound-tools", contract.get("kind").?.string);
    try std.testing.expectEqual(selected.seconds, try core.contracts.integer(u32, contract.get("seconds").?));
    try std.testing.expectEqual(selected.output_limit, try core.contracts.integer(usize, contract.get("output_limit").?));
    const argv = contract.get("argv").?.array.items;
    try std.testing.expectEqual(selected.argv.len, argv.len);
    for (selected.argv, argv) |entry, expected| {
        const local = switch (entry) {
            .literal => |literal| try std.json.Stringify.valueAlloc(a, .{ .kind = "literal", .value = literal }, .{}),
            .path => |path| try std.json.Stringify.valueAlloc(a, .{ .kind = "path", .role = path.role, .relative = path.relative }, .{}),
        };
        defer a.free(local);
        const remote = try std.json.Stringify.valueAlloc(a, expected, .{});
        defer a.free(remote);
        try std.testing.expectEqualStrings(try controller.records.canonicalAlloc(a, remote), try controller.records.canonicalAlloc(a, local));
    }
    try std.testing.expectEqualStrings("source", selected.argv[2].path.role);
    try std.testing.expectEqualStrings("compute", selected.argv[3].path.role);
    const environment = try plan.environment(a, selected.stage);
    defer plan.freeEnvironment(a, environment);
    const expected_env = contract.get("environment").?.array.items;
    try std.testing.expectEqual(environment.len, expected_env.len);
    for (environment, expected_env) |entry, expected| {
        try std.testing.expectEqualStrings(entry.name, expected.object.get("name").?.string);
        const binding = entry.value;
        const local = switch (binding) {
            .literal => |literal| try std.json.Stringify.valueAlloc(a, .{ .kind = "literal", .value = literal }, .{}),
            .path => |path| try std.json.Stringify.valueAlloc(a, .{ .kind = "path", .role = path.role, .relative = path.relative }, .{}),
        };
        defer a.free(local);
        const remote = try std.json.Stringify.valueAlloc(a, expected.object.get("value").?, .{});
        defer a.free(remote);
        try std.testing.expectEqualStrings(try controller.records.canonicalAlloc(a, remote), try controller.records.canonicalAlloc(a, local));
    }
    const limits = try std.json.Stringify.valueAlloc(a, plan.limits(selected), .{});
    defer a.free(limits);
    const expected_limits = try std.json.Stringify.valueAlloc(a, contract.get("limits").?, .{});
    defer a.free(expected_limits);
    try std.testing.expectEqualStrings(try controller.records.canonicalAlloc(a, expected_limits), try controller.records.canonicalAlloc(a, limits));
}

fn commandDigest(a: std.mem.Allocator, value: std.json.Value) ![]const u8 {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    const canonical = try controller.records.canonicalAlloc(a, raw);
    const digest = std.fmt.bytesToHex(controller.records.fileIdentity(canonical), .lower);
    return try a.dupe(u8, &digest);
}

fn withoutFields(a: std.mem.Allocator, value: std.json.Value, skipped: []const []const u8) !std.json.Value {
    var result = std.json.Value{ .object = .empty };
    var iterator = value.object.iterator();
    while (iterator.next()) |entry| {
        var skip = false;
        for (skipped) |name| if (std.mem.eql(u8, entry.key_ptr.*, name)) {
            skip = true;
            break;
        };
        if (!skip) try result.object.put(a, entry.key_ptr.*, entry.value_ptr.*);
    }
    return result;
}

fn rehashCommandRecord(a: std.mem.Allocator, record: *std.json.Value) ![]const u8 {
    const supervisor = record.object.getPtr("supervisor") orelse return error.InvalidCommand;
    const request = supervisor.object.getPtr("request") orelse return error.InvalidCommand;
    request.object.getPtr("argv_sha256").?.* = .{ .string = try commandDigest(a, request.object.get("argv").?) };
    request.object.getPtr("environment_sha256").?.* = .{ .string = try commandDigest(a, request.object.get("environment").?) };
    request.object.getPtr("cwd_sha256").?.* = .{ .string = try commandDigest(a, request.object.get("cwd").?) };
    request.object.getPtr("canonical_sha256").?.* = .{ .string = try commandDigest(a, try withoutFields(a, request.*, &.{
        "canonical_sha256",
        "argv_sha256",
        "environment_sha256",
        "cwd_sha256",
    })) };
    const result = supervisor.object.getPtr("result") orelse return error.InvalidCommand;
    result.object.getPtr("request_canonical_sha256").?.* = request.object.get("canonical_sha256").?;
    result.object.getPtr("canonical_sha256").?.* = .{ .string = try commandDigest(a, try withoutFields(a, result.*, &.{"canonical_sha256"})) };
    return controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, record.*, .{}));
}

fn handoffInspectFixtures() !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const plan = controller.command_plan;
    var accepted = controller.accepted_run.AcceptedRun{
        .arena = std.heap.ArenaAllocator.init(a),
        .io = io,
        .context = .trusted_inner_zip,
        .compatibility = .tiny_v2_qcow2_derived_vhd,
        .production_profile = .tiny_exact_v2,
        .source = undefined,
        .result = undefined,
        .records = &.{},
        .artifacts = &.{},
        .runtime_inputs = &.{},
        .root = "/runtime",
        .repository = null,
        .environ = null,
    };
    defer accepted.deinit();
    try std.testing.expectError(error.InvalidContext, controller.handoff_inspect.bind(&accepted, "/output"));
    try std.testing.expectError(error.InvalidContext, controller.handoff_inspect.run(a, io, &accepted, "/output", false, null));
    try std.testing.expectError(error.InvalidContext, controller.public_validator_build.run(a, io, &accepted, "/output", null));
    try std.testing.expectError(error.InvalidContext, controller.public_validator_build.revalidateHandoff(a, io, &accepted, "/output", null));
    accepted.context = .local_runtime;
    accepted.repository = "/source";
    try std.testing.expectError(error.MissingInput, controller.handoff_inspect.bind(&accepted, "/output"));

    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("handoff-inspect-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("handoff inspect fixture cleanup failed");
    const fixture_dir = try parent.openDir(io, name, .{ .iterate = true });
    defer fixture_dir.close(io);
    try fixture_dir.createDirPath(io, "source/support/apps/wamr-aot/build");
    try fixture_dir.createDir(io, "compute", .fromMode(0o700));
    const compute_dir = try fixture_dir.openDir(io, "compute", .{ .iterate = true });
    defer compute_dir.close(io);
    try compute_dir.createDir(io, "package", .fromMode(0o700));
    try compute_dir.createDir(io, "tools", .fromMode(0o700));
    const tools_dir = try compute_dir.openDir(io, "tools", .{ .iterate = true });
    defer tools_dir.close(io);
    try tools_dir.createDir(io, "bin", .fromMode(0o700));
    const tools_bin = try tools_dir.openDir(io, "bin", .{ .iterate = true });
    defer tools_bin.close(io);
    try compute_dir.createDir(io, "supervisor", .fromMode(0o700));
    const supervisor_dir = try compute_dir.openDir(io, "supervisor", .{ .iterate = true });
    defer supervisor_dir.close(io);
    try supervisor_dir.createDir(io, "bin", .fromMode(0o700));
    const supervisor_bin = try supervisor_dir.openDir(io, "bin", .{ .iterate = true });
    defer supervisor_bin.close(io);
    try fixture_dir.createDir(io, "controller", .fromMode(0o700));
    const controller_dir = try fixture_dir.openDir(io, "controller", .{ .iterate = true });
    defer controller_dir.close(io);
    try controller_dir.createDir(io, "bin", .fromMode(0o700));
    const controller_bin = try controller_dir.openDir(io, "bin", .{ .iterate = true });
    defer controller_bin.close(io);
    try fixture_dir.createDir(io, "output", .fromMode(0o700));
    const output_dir = try fixture_dir.openDir(io, "output", .{ .iterate = true });
    defer output_dir.close(io);
    try output_dir.createDir(io, "private", .fromMode(0o700));
    try output_dir.createDir(io, "evidence", .fromMode(0o700));
    const private = try output_dir.openDir(io, "private", .{ .iterate = true });
    defer private.close(io);
    const evidence = try output_dir.openDir(io, "evidence", .{ .iterate = true });
    defer evidence.close(io);
    const efi_dir = try fixture_dir.openDir(io, "source/support/apps/wamr-aot/build", .{});
    defer efi_dir.close(io);
    try writeFixtureFile(io, efi_dir, "wamr_hyperv-x86_64-efi", "efi");
    const root = try std.fs.path.join(a, &.{ options.fixture_root, name });
    defer a.free(root);
    const source = try std.fs.path.join(a, &.{ root, "source" });
    defer a.free(source);
    const compute = try std.fs.path.join(a, &.{ root, "compute" });
    defer a.free(compute);
    const output = try std.fs.path.join(a, &.{ root, "output" });
    defer a.free(output);
    const efi = try std.fs.path.join(a, &.{ source, "support/apps/wamr-aot/build/wamr_hyperv-x86_64-efi" });
    defer a.free(efi);
    const executable = try std.fs.path.resolve(a, &.{ options.repository_root, options.command_fixture });
    defer a.free(executable);
    const bound_tool = try std.Io.Dir.realPathFileAbsoluteAlloc(io, "/usr/bin/true", a);
    defer a.free(bound_tool);
    try copyFixtureExecutable(io, a, executable, tools_bin, "wamr-ci-package");
    try copyFixtureExecutable(io, a, bound_tool, supervisor_bin, "wamr-ci-supervisor");
    try copyFixtureExecutable(io, a, bound_tool, controller_bin, "uk-wamr-native-ci");
    const original_tool = try std.fs.path.join(a, &.{ compute, "tools/bin/wamr-ci-package" });
    const original_supervisor = try std.fs.path.join(a, &.{ compute, "supervisor/bin/wamr-ci-supervisor" });
    const records_controller = try std.fs.path.join(a, &.{ root, "controller/bin/uk-wamr-native-ci" });
    const handoff_controller = try std.Io.Dir.realPathFileAbsoluteAlloc(io, "/proc/self/exe", a);
    const roots = plan.Roots{
        .source_root = source,
        .work = output,
        .compute = compute,
        .runtime = root,
        .zig = bound_tool,
        .producer = bound_tool,
        .fixture_runner = bound_tool,
        .supervisor = records_controller,
        .package_tool = original_tool,
        .validator = bound_tool,
        .supervisor_fixture = bound_tool,
        .efi = efi,
        .tools = @as([controller.input_custody.host_tools.len][]const u8, @splat(bound_tool)),
    };
    const sample = controller.accepted_run.PinnedInput{
        .role = "",
        .path = "",
        .snapshot = .{ .bytes = 1, .sha256 = @as([64]u8, @splat('0')), .metadata = @as([9]i128, @splat(0)) },
    };
    var pinned: [controller.input_custody.host_tools.len + 6]controller.accepted_run.PinnedInput = undefined;
    for (controller.input_custody.host_tools, 0..) |tool, i| {
        pinned[i] = sample;
        pinned[i].role = try std.fmt.allocPrint(accepted.arena.allocator(), "tool:{s}", .{tool});
        pinned[i].path = bound_tool;
    }
    const additional = [_]struct { role: []const u8, path: []const u8 }{
        .{ .role = "package_tool", .path = original_tool },
        .{ .role = "efi", .path = efi },
        .{ .role = "command-supervisor", .path = records_controller },
        .{ .role = controller.accepted_run.handoff_controller_role, .path = handoff_controller },
        .{ .role = "native:wamr-aot-build", .path = bound_tool },
        .{ .role = "native:wamr-log-validate", .path = bound_tool },
    };
    for (additional, 0..) |entry, i| {
        pinned[controller.input_custody.host_tools.len + i] = sample;
        pinned[controller.input_custody.host_tools.len + i].role = entry.role;
        pinned[controller.input_custody.host_tools.len + i].path = entry.path;
    }
    accepted.root = root;
    accepted.repository = source;
    accepted.runtime_inputs = &pinned;
    try expectInvalidHandoffRun(a, io, &accepted, try std.fs.path.join(a, &.{ root, "native-v2-legacy-refused" }), true);
    const bound = try controller.handoff_inspect.bind(&accepted, output);
    try std.testing.expectEqualStrings("command-supervisor", controller.handoff_inspect.supervisorRole(&accepted));
    try std.testing.expectEqualStrings(records_controller, bound.supervisor);
    try std.testing.expectEqualStrings(original_tool, bound.package_tool);
    try std.testing.expectEqualStrings(efi, bound.efi);
    try std.testing.expectEqualStrings(compute, bound.compute);
    try std.testing.expectEqualStrings(output, bound.work);
    try std.testing.expectError(error.UnboundCommandRole, bound.get("native:wamr-native-ci-fixtures"));
    try std.testing.expectError(error.UnboundCommandRole, bound.get("native:wamr-ci-supervisor-fixture"));
    pinned[controller.input_custody.host_tools.len + 2].path = original_supervisor;
    try std.testing.expectError(error.InputChanged, controller.handoff_inspect.bind(&accepted, output));
    accepted.local_producer = .python;
    const python_bound = try controller.handoff_inspect.bind(&accepted, output);
    try expectInvalidHandoffRun(a, io, &accepted, try std.fs.path.join(a, &.{ root, "python-v2-legacy-refused" }), true);
    try std.testing.expectEqualStrings(controller.accepted_run.handoff_controller_role, controller.handoff_inspect.supervisorRole(&accepted));
    try std.testing.expectEqualStrings(original_supervisor, python_bound.supervisor);
    try std.testing.expectEqualStrings(handoff_controller, python_bound.handoff_controller);
    accepted.local_producer = .native;
    pinned[controller.input_custody.host_tools.len + 2].path = records_controller;
    pinned[controller.input_custody.host_tools.len + 1].path = "/substituted/efi";
    try std.testing.expectError(error.InputChanged, controller.handoff_inspect.bind(&accepted, output));
    pinned[controller.input_custody.host_tools.len + 1].path = efi;
    pinned[controller.input_custody.host_tools.len].path = "/substituted/package-tool";
    try std.testing.expectError(error.InputChanged, controller.handoff_inspect.bind(&accepted, output));
    pinned[controller.input_custody.host_tools.len].path = original_tool;
    try std.testing.expectEqualStrings(efi, try plan.path(a, plan.spec(.@"handoff-inspect").argv[2], roots));
    try std.testing.expectEqualStrings(try std.fs.path.join(a, &.{ compute, "package" }), try plan.path(a, plan.spec(.@"handoff-inspect").argv[3], roots));
    var incomplete = roots;
    incomplete.compute = "";
    try std.testing.expectError(error.UnboundCommandRole, plan.path(a, plan.spec(.@"handoff-inspect").argv[3], incomplete));
    const result = try controller.command_adapter.execute(a, io, .{
        .roots = roots,
        .stage = .@"handoff-inspect",
        .private_dir = private,
        .evidence_dir = evidence,
        .capture_stdout = true,
    });
    defer a.free(result.stdout);
    try std.testing.expect(result.accepted);
    try std.testing.expect(!result.poisoned);
    try std.testing.expectEqual(@as(usize, 0), result.stderr_bytes);
    const original = "{\"image\":{\"efi\":{\"size\":3}},\"producer_sha256\":\"fixture\"}\n";
    try std.testing.expectEqualStrings(original, result.stdout);
    try controller.handoff_inspect.matchPackage(a, result.stdout, original);
    try std.testing.expectError(error.PackageChanged, controller.handoff_inspect.matchPackage(a, result.stdout, "{\"image\":{\"efi\":{\"size\":4}},\"producer_sha256\":\"fixture\"}\n"));
    try std.testing.expectError(error.PackageChanged, controller.handoff_inspect.matchPackage(a, result.stdout, "{\"image\":{\"efi\":{\"size\":3}},\"producer_sha256\":\"changed\"}\n"));
    const record_path = try std.fs.path.join(a, &.{ output, "evidence/command-handoff-inspect.json" });
    defer a.free(record_path);
    const recorded = try controller.custody_files.readFile(io, record_path, 1024 * 1024, true);
    const raw = try a.alloc(u8, @intCast(recorded.bytes));
    defer a.free(raw);
    const file = try evidence.openFile(io, "command-handoff-inspect.json", .{ .follow_symlinks = false });
    defer file.close(io);
    try std.testing.expectEqual(raw.len, try file.readPositionalAll(io, raw, 0));
    const checked = try controller.accepted_run.validateCommandBinding(a, raw, .@"handoff-inspect", .local_runtime);
    try std.testing.expectEqual(plan.Stage.@"handoff-inspect", checked.stage);
    try compute_dir.createDir(io, "evidence", .fromMode(0o700));
    const source_evidence = try compute_dir.openDir(io, "evidence", .{ .iterate = true });
    defer source_evidence.close(io);
    const tool_record = try controller.custody_files.readFile(io, bound_tool, 64 * 1024 * 1024, false);
    const package_record = try controller.custody_files.readFile(io, original_tool, 64 * 1024 * 1024, false);
    const supervisor_record = try controller.custody_files.readFile(io, records_controller, 64 * 1024 * 1024, false);
    const python_supervisor_record = try controller.custody_files.readFile(io, original_supervisor, 64 * 1024 * 1024, false);
    const handoff_controller_record = try controller.custody_files.readFile(io, handoff_controller, 64 * 1024 * 1024, false);
    const tool_json = try std.json.parseFromSliceLeaky(std.json.Value, a, try std.json.Stringify.valueAlloc(a, .{ .metadata = tool_record.metadata, .sha256 = tool_record.sha256 }, .{}), .{ .parse_numbers = false });
    const package_json = try std.json.parseFromSliceLeaky(std.json.Value, a, try std.json.Stringify.valueAlloc(a, .{ .metadata = package_record.metadata, .sha256 = package_record.sha256 }, .{}), .{ .parse_numbers = false });
    const supervisor_json = try std.json.parseFromSliceLeaky(std.json.Value, a, try std.json.Stringify.valueAlloc(a, .{ .metadata = supervisor_record.metadata, .sha256 = supervisor_record.sha256 }, .{}), .{ .parse_numbers = false });
    const python_supervisor_json = try std.json.parseFromSliceLeaky(std.json.Value, a, try std.json.Stringify.valueAlloc(a, .{ .metadata = python_supervisor_record.metadata, .sha256 = python_supervisor_record.sha256 }, .{}), .{ .parse_numbers = false });
    var start_files = std.json.Value{ .object = .empty };
    for (controller.input_custody.host_tools) |tool|
        try start_files.object.put(a, try a.print("tool:{s}", .{tool}), tool_json);
    try start_files.object.put(a, "command-supervisor", supervisor_json);
    const build_start = try controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, .{ .consumer_inputs = .{ .files = start_files } }, .{}));
    try writeFixtureFile(io, source_evidence, "build-start.json", build_start);
    const boot_inputs = try controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, .{ .files = .{ .package_tool = package_json } }, .{}));
    try writeFixtureFile(io, source_evidence, "boot-inputs.json", boot_inputs);
    const verified = try controller.accepted_run.validateLocalHandoffCommand(&accepted, raw);
    try std.testing.expectEqual(plan.Stage.@"handoff-inspect", verified.stage);
    try fixture_dir.createDir(io, "python-output", .fromMode(0o700));
    const python_output = try std.fs.path.join(a, &.{ root, "python-output" });
    const python_output_dir = try fixture_dir.openDir(io, "python-output", .{ .iterate = true });
    defer python_output_dir.close(io);
    try python_output_dir.createDir(io, "private", .fromMode(0o700));
    try python_output_dir.createDir(io, "evidence", .fromMode(0o700));
    const python_private = try python_output_dir.openDir(io, "private", .{ .iterate = true });
    defer python_private.close(io);
    const python_evidence = try python_output_dir.openDir(io, "evidence", .{ .iterate = true });
    defer python_evidence.close(io);
    accepted.local_producer = .python;
    pinned[controller.input_custody.host_tools.len + 2].path = original_supervisor;
    const python_roots = try controller.handoff_inspect.bind(&accepted, python_output);
    const python_result = try controller.command_adapter.execute(a, io, .{
        .roots = python_roots,
        .stage = .@"handoff-inspect",
        .private_dir = python_private,
        .evidence_dir = python_evidence,
        .supervisor_role = controller.accepted_run.handoff_controller_role,
        .capture_stdout = true,
    });
    defer a.free(python_result.stdout);
    try std.testing.expect(python_result.accepted);
    const python_record_path = try std.fs.path.join(a, &.{ python_output, "evidence/command-handoff-inspect.json" });
    const python_record = try controller.custody_files.readFile(io, python_record_path, 1024 * 1024, true);
    const python_raw = try a.alloc(u8, @intCast(python_record.bytes));
    defer a.free(python_raw);
    const python_file = try python_evidence.openFile(io, "command-handoff-inspect.json", .{ .follow_symlinks = false });
    defer python_file.close(io);
    try std.testing.expectEqual(python_raw.len, try python_file.readPositionalAll(io, python_raw, 0));
    var python_doc = try std.json.parseFromSlice(std.json.Value, a, python_raw, .{ .duplicate_field_behavior = .@"error", .parse_numbers = false });
    defer python_doc.deinit();
    const python_request = python_doc.value.object.get("supervisor").?.object.get("request").?;
    const python_supervisor_binding = python_request.object.get("supervisor").?;
    try std.testing.expectEqualStrings(
        controller.accepted_run.handoff_controller_role,
        python_supervisor_binding.object.get("path").?.object.get("role").?.string,
    );
    try std.testing.expectEqualStrings(
        &handoff_controller_record.sha256,
        python_supervisor_binding.object.get("identity").?.object.get("content_sha256").?.string,
    );
    _ = try source_evidence.deleteFile(io, "build-start.json");
    var python_start_files = std.json.Value{ .object = .empty };
    for (controller.input_custody.host_tools) |tool|
        try python_start_files.object.put(a, try a.print("tool:{s}", .{tool}), tool_json);
    try python_start_files.object.put(a, "command-supervisor", python_supervisor_json);
    const python_build_start = try controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, .{ .consumer_inputs = .{ .files = python_start_files } }, .{}));
    try writeFixtureFile(io, source_evidence, "build-start.json", python_build_start);
    pinned[controller.input_custody.host_tools.len + 3].snapshot = .{
        .bytes = handoff_controller_record.bytes,
        .sha256 = handoff_controller_record.sha256,
        .metadata = handoff_controller_record.metadata,
    };
    const verified_python = try controller.accepted_run.validateLocalHandoffCommand(&accepted, python_raw);
    try std.testing.expectEqual(plan.Stage.@"handoff-inspect", verified_python.stage);

    try fixture_dir.createDir(io, "python-mislabel-output", .fromMode(0o700));
    const python_mislabel_output = try std.fs.path.join(a, &.{ root, "python-mislabel-output" });
    const python_mislabel_dir = try fixture_dir.openDir(io, "python-mislabel-output", .{ .iterate = true });
    defer python_mislabel_dir.close(io);
    try python_mislabel_dir.createDir(io, "private", .fromMode(0o700));
    try python_mislabel_dir.createDir(io, "evidence", .fromMode(0o700));
    const python_mislabel_private = try python_mislabel_dir.openDir(io, "private", .{ .iterate = true });
    defer python_mislabel_private.close(io);
    const python_mislabel_evidence = try python_mislabel_dir.openDir(io, "evidence", .{ .iterate = true });
    defer python_mislabel_evidence.close(io);
    var python_mislabel_roots = python_roots;
    python_mislabel_roots.work = python_mislabel_output;
    const python_mislabel_result = try controller.command_adapter.execute(a, io, .{
        .roots = python_mislabel_roots,
        .stage = .@"handoff-inspect",
        .private_dir = python_mislabel_private,
        .evidence_dir = python_mislabel_evidence,
        .supervisor_role = "command-supervisor",
        .capture_stdout = true,
    });
    defer a.free(python_mislabel_result.stdout);
    try std.testing.expect(python_mislabel_result.accepted);
    const python_mislabel_record_path = try std.fs.path.join(a, &.{ python_mislabel_output, "evidence/command-handoff-inspect.json" });
    const python_mislabel_record = try controller.custody_files.readFile(io, python_mislabel_record_path, 1024 * 1024, true);
    const python_mislabel_raw = try a.alloc(u8, @intCast(python_mislabel_record.bytes));
    const python_mislabel_file = try python_mislabel_evidence.openFile(io, "command-handoff-inspect.json", .{ .follow_symlinks = false });
    defer python_mislabel_file.close(io);
    try std.testing.expectEqual(python_mislabel_raw.len, try python_mislabel_file.readPositionalAll(io, python_mislabel_raw, 0));
    try std.testing.expectError(error.InvalidCommandIdentity, controller.accepted_run.validateLocalHandoffCommand(&accepted, python_mislabel_raw));

    const identity_cases = [_]struct {
        field: []const u8,
        value: std.json.Value,
        err: anyerror,
    }{
        .{ .field = "content_sha256", .value = .{ .string = "0000000000000000000000000000000000000000000000000000000000000000" }, .err = error.EvidenceChanged },
        .{ .field = "inode", .value = .{ .integer = 99 }, .err = error.InvalidCommandIdentity },
        .{ .field = "ctime_seconds", .value = .{ .integer = 99 }, .err = error.InvalidCommandIdentity },
    };
    for (identity_cases) |case| {
        var tampered = try std.json.parseFromSlice(std.json.Value, a, python_raw, .{ .duplicate_field_behavior = .@"error", .parse_numbers = false });
        defer tampered.deinit();
        const identity = tampered.value.object.getPtr("supervisor").?.object.getPtr("request").?.object.getPtr("supervisor").?.object.getPtr("identity").?;
        identity.object.getPtr(case.field).?.* = case.value;
        const tampered_raw = try rehashCommandRecord(a, &tampered.value);
        try std.testing.expectError(case.err, controller.accepted_run.validateLocalHandoffCommand(&accepted, tampered_raw));
    }

    accepted.local_producer = .native;
    pinned[controller.input_custody.host_tools.len + 2].path = records_controller;
    _ = try source_evidence.deleteFile(io, "build-start.json");
    try writeFixtureFile(io, source_evidence, "build-start.json", build_start);

    try fixture_dir.createDir(io, "native-wrong-role-output", .fromMode(0o700));
    const native_wrong_output = try std.fs.path.join(a, &.{ root, "native-wrong-role-output" });
    const native_wrong_dir = try fixture_dir.openDir(io, "native-wrong-role-output", .{ .iterate = true });
    defer native_wrong_dir.close(io);
    try native_wrong_dir.createDir(io, "private", .fromMode(0o700));
    try native_wrong_dir.createDir(io, "evidence", .fromMode(0o700));
    const native_wrong_private = try native_wrong_dir.openDir(io, "private", .{ .iterate = true });
    defer native_wrong_private.close(io);
    const native_wrong_evidence = try native_wrong_dir.openDir(io, "evidence", .{ .iterate = true });
    defer native_wrong_evidence.close(io);
    var native_wrong_roots = roots;
    native_wrong_roots.handoff_controller = handoff_controller;
    const native_wrong_result = try controller.command_adapter.execute(a, io, .{
        .roots = native_wrong_roots,
        .stage = .@"handoff-inspect",
        .private_dir = native_wrong_private,
        .evidence_dir = native_wrong_evidence,
        .supervisor_role = controller.accepted_run.handoff_controller_role,
        .capture_stdout = true,
    });
    defer a.free(native_wrong_result.stdout);
    try std.testing.expect(native_wrong_result.accepted);
    const native_wrong_record_path = try std.fs.path.join(a, &.{ native_wrong_output, "evidence/command-handoff-inspect.json" });
    const native_wrong_record = try controller.custody_files.readFile(io, native_wrong_record_path, 1024 * 1024, true);
    const native_wrong_raw = try a.alloc(u8, @intCast(native_wrong_record.bytes));
    const native_wrong_file = try native_wrong_evidence.openFile(io, "command-handoff-inspect.json", .{ .follow_symlinks = false });
    defer native_wrong_file.close(io);
    try std.testing.expectEqual(native_wrong_raw.len, try native_wrong_file.readPositionalAll(io, native_wrong_raw, 0));
    try std.testing.expectError(error.InvalidCommandIdentity, controller.accepted_run.validateLocalHandoffCommand(&accepted, native_wrong_raw));

    const validator_plan = plan.spec(.@"public-validator-build");
    try std.testing.expectEqualStrings("tool:zig", validator_plan.executable);
    try std.testing.expectEqual(@as(u32, 1800), validator_plan.seconds);
    try std.testing.expectEqual(@as(usize, 8 * 1024 * 1024), validator_plan.output_limit);
    try std.testing.expectEqualStrings(
        try std.fs.path.join(a, &.{ output, "public-source/tools" }),
        try plan.path(a, validator_plan.argv[9], roots),
    );
    const env = try plan.environment(a, .@"public-validator-build");
    defer plan.freeEnvironment(a, env);
    var launch = false;
    var temporary = false;
    for (env) |entry| {
        if (std.mem.eql(u8, entry.name, "WAMR_CI_LAUNCH_EXECUTABLE")) {
            try std.testing.expectEqualStrings("tool:zig", entry.value.path.role);
            launch = true;
        } else if (std.mem.eql(u8, entry.name, "TMPDIR")) {
            try std.testing.expectEqualStrings("private", entry.value.path.relative);
            temporary = true;
        }
        try std.testing.expect(!std.mem.eql(u8, entry.name, "KCONFIG_CONFIG"));
    }
    try std.testing.expect(launch and temporary);
    const built = try controller.command_adapter.execute(a, io, .{
        .roots = roots,
        .stage = .@"public-validator-build",
        .private_dir = private,
        .evidence_dir = evidence,
    });
    try std.testing.expect(built.accepted);
    const builder_path = try std.fs.path.join(a, &.{ output, "evidence/command-public-validator-build.json" });
    defer a.free(builder_path);
    const builder_record = try controller.custody_files.readFile(io, builder_path, 1024 * 1024, true);
    const builder_raw = try a.alloc(u8, @intCast(builder_record.bytes));
    defer a.free(builder_raw);
    const builder_file = try evidence.openFile(io, "command-public-validator-build.json", .{ .follow_symlinks = false });
    defer builder_file.close(io);
    try std.testing.expectEqual(builder_raw.len, try builder_file.readPositionalAll(io, builder_raw, 0));
    const validated_builder = try controller.accepted_run.validateLocalPostRunCommand(&accepted, builder_raw, .@"public-validator-build");
    try std.testing.expectEqual(plan.Stage.@"public-validator-build", validated_builder.stage);
    try std.testing.expectEqual(@as(u64, 0), validated_builder.output_bytes);
    const checked_builder = try controller.public_validator_build.validateCommandEvidence(a, io, &accepted, output, built.bytes);
    try std.testing.expectEqual(plan.Stage.@"public-validator-build", checked_builder.stage);
    try std.testing.expectError(error.CommandOutputChanged, controller.public_validator_build.validateCommandEvidence(
        a,
        io,
        &accepted,
        output,
        built.bytes + 1,
    ));
    try std.testing.expectError(error.InvalidCommand, controller.accepted_run.validateLocalPostRunCommand(&accepted, builder_raw, .package));
    var changed_boot = try std.json.parseFromSlice(std.json.Value, a, boot_inputs, .{
        .duplicate_field_behavior = .@"error",
        .parse_numbers = false,
    });
    defer changed_boot.deinit();
    changed_boot.value.object.getPtr("files").?.object.getPtr("package_tool").?.object.getPtr("sha256").?.* =
        .{ .string = "0000000000000000000000000000000000000000000000000000000000000000" };
    const changed_json = try std.json.Stringify.valueAlloc(a, changed_boot.value, .{});
    const changed_raw = try controller.records.canonicalAlloc(a, changed_json);
    const boot_file = try source_evidence.openFile(io, "boot-inputs.json", .{ .mode = .read_write, .follow_symlinks = false });
    try boot_file.setLength(io, 0);
    try boot_file.writePositionalAll(io, changed_raw, 0);
    boot_file.close(io);
    try std.testing.expectError(error.EvidenceChanged, controller.accepted_run.validateLocalHandoffCommand(&accepted, raw));
    var parsed = try std.json.parseFromSlice(std.json.Value, a, raw, .{ .duplicate_field_behavior = .@"error", .parse_numbers = false });
    defer parsed.deinit();
    const command = parsed.value.object.getPtr("supervisor").?.object.getPtr("request").?;
    try std.testing.expectEqualStrings("source", command.object.get("argv").?.array.items[2].object.get("role").?.string);
    try std.testing.expectEqualStrings("compute", command.object.get("argv").?.array.items[3].object.get("role").?.string);
    const argv = command.object.getPtr("argv").?;
    argv.array.items[3].object.getPtr("role").?.* = .{ .string = "work" };
    try std.testing.expectError(error.InvalidCommand, controller.command_validation.validate(a, parsed.value, .@"handoff-inspect", .local_runtime));
}

test "six boot modes bind exact image, APIC flags, validator and command budgets" {
    const a = std.testing.allocator;
    const plan = controller.command_plan;
    const profile = controller.profile;
    for (profile.production_modes, 0..) |mode, index| {
        const stage = plan.modeStage(mode);
        const selected = plan.spec(stage);
        try std.testing.expectEqual(stage, selected.stage);
        try std.testing.expectEqual(@as(u32, 90), selected.seconds);
        try std.testing.expectEqual(@as(usize, 64 * 1024), selected.output_limit);
        try std.testing.expectEqualStrings("input:local_boot_tool", selected.executable);
        try std.testing.expectEqualStrings("input:local_boot_tool", selected.argv[0].path.role);
        const image_path = try a.print("package/{s}", .{plan.bootImage(mode)});
        defer a.free(image_path);
        const slot_path = try a.print("boot-{s}", .{@tagName(mode)});
        defer a.free(slot_path);
        try std.testing.expectEqualStrings(image_path, selected.argv[2].path.relative);
        try std.testing.expectEqualStrings(slot_path, selected.argv[10].path.relative);
        try std.testing.expectEqual(index % 2 == 1, mode.legacyApic());
        var required = false;
        var disabled = false;
        var forbidden_legacy = false;
        for (selected.argv, 0..) |entry, at| {
            if (entry != .literal) continue;
            if (std.mem.eql(u8, entry.literal, "--disable-x2apic")) disabled = true;
            if (std.mem.eql(u8, entry.literal, "--require-marker")) required = true;
            if (std.mem.eql(u8, entry.literal, "--forbid-marker") and at + 1 < selected.argv.len and
                selected.argv[at + 1] == .literal and std.mem.eql(u8, selected.argv[at + 1].literal, "Using legacy xAPIC MMIO"))
                forbidden_legacy = true;
        }
        try std.testing.expectEqual(mode.legacyApic(), disabled);
        try std.testing.expectEqual(mode.legacyApic(), required);
        try std.testing.expectEqual(!mode.legacyApic(), forbidden_legacy);
        const env = try plan.environment(a, stage);
        defer plan.freeEnvironment(a, env);
        try std.testing.expect(env.len > 20);
    }
    for ([_]plan.Stage{ .package, .@"finalize-qcow2", .@"derive-fixed-vhd", .inspect }) |stage| {
        const selected = plan.spec(stage);
        try std.testing.expectEqual(@as(u32, 150), selected.seconds);
        try std.testing.expectEqualStrings("input:package_tool", selected.argv[0].path.role);
    }
    for ([_]plan.Stage{ .@"log-validator-x2apic", .@"log-validator-legacy" }) |stage| {
        const selected = plan.spec(stage);
        try std.testing.expectEqual(@as(u32, 30), selected.seconds);
        try std.testing.expectEqual(@as(usize, 64 * 1024), plan.limits(selected).stdout_bytes);
        try std.testing.expectEqual(@as(usize, 4 * 1024), plan.limits(selected).stderr_bytes);
        try std.testing.expectEqualStrings("native:wamr-log-validate", selected.argv[0].path.role);
        try std.testing.expectEqualStrings("tiny", selected.argv[1].literal);
        try std.testing.expectEqualStrings("input:serial", selected.argv[3].path.role);
        try std.testing.expectEqualStrings("input:identity", selected.argv[5].path.role);
        try std.testing.expectEqualStrings(if (stage == .@"log-validator-legacy") "required" else "forbidden", selected.argv[7].literal);
        const env = try plan.environment(a, stage);
        defer plan.freeEnvironment(a, env);
        try std.testing.expectEqual(@as(usize, 0), env.len);
    }
    try std.testing.expectError(error.KvmUnavailable, controller.boot_pipeline.admitHost(.aarch64, std.os.linux.S.IFCHR, true));
    try std.testing.expectError(error.KvmUnavailable, controller.boot_pipeline.admitHost(.x86_64, std.os.linux.S.IFREG, true));
    try std.testing.expectError(error.KvmUnavailable, controller.boot_pipeline.admitHost(.x86_64, std.os.linux.S.IFCHR, false));
    try controller.boot_pipeline.admitHost(.x86_64, std.os.linux.S.IFCHR, true);
}

test "exact bounded validator JSON rejects every malformed tiny result" {
    const a = std.testing.allocator;
    const raw_hash = std.fmt.bytesToHex(controller.records.fileIdentity("abc"), .lower);
    const valid = try a.print(
        "{{\"compute\":{{\"answer\":42}},\"mode\":\"tiny\",\"raw_serial_bytes\":3,\"raw_serial_sha256\":\"{s}\",\"schema\":\"uk.wamr.log-validation\",\"schema_version\":1}}\n",
        .{&raw_hash},
    );
    defer a.free(valid);
    const Mutate = struct { from: []const u8, to: []const u8 };
    const cases = [_]Mutate{
        .{ .from = "", .to = "" },
        .{ .from = "\"schema_version\":1", .to = "\"schema_version\":2" },
        .{ .from = "\"schema_version\":1", .to = "\"schema_version\":true" },
        .{ .from = "\"raw_serial_bytes\":3", .to = "\"raw_serial_bytes\":4" },
        .{ .from = "\"raw_serial_bytes\":3", .to = "\"raw_serial_bytes\":true" },
        .{ .from = "\"compute\":{\"answer\":42}", .to = "\"compute\":[]" },
        .{ .from = "\"mode\":\"tiny\"", .to = "\"mode\":\"coremark\"" },
        .{ .from = "\"schema\":\"uk.wamr.log-validation\"", .to = "\"schema\":\"other\"" },
        .{ .from = "\"schema_version\":1", .to = "\"schema_version\":1,\"extra\":true" },
        .{ .from = "\"schema_version\":1", .to = "\"schema_version\":1,\"schema_version\":1" },
        .{ .from = "}\n", .to = "}" },
    };
    for (cases, 0..) |mutation, index| {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const bytes = if (index == 0) valid else try std.mem.replaceOwned(u8, a, valid, mutation.from, mutation.to);
        defer if (index != 0) a.free(bytes);
        const native = if (controller.boot_pipeline.parseValidator(arena.allocator(), bytes, 3, &raw_hash)) |_| true else |_| false;
        try std.testing.expectEqual(index == 0, native);
    }
}

test "native diagnostics retain only bounded allowlisted observations and never acceptance" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("boot-diagnostics-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("diagnostics fixture cleanup failed");
    const runtime = try std.fs.path.join(a, &.{ options.fixture_root, name });
    defer a.free(runtime);
    const root = try parent.openDir(io, name, .{ .iterate = true });
    defer root.close(io);
    try root.createDir(io, "compute", .fromMode(0o700));
    const compute = try root.openDir(io, "compute", .{ .iterate = true });
    defer compute.close(io);
    for ([_][]const u8{ "evidence", "private", "boot-raw-x2apic" }) |entry|
        try compute.createDir(io, entry, .fromMode(0o700));
    const evidence = try compute.openDir(io, "evidence", .{ .iterate = true });
    defer evidence.close(io);
    const private = try compute.openDir(io, "private", .{ .iterate = true });
    defer private.close(io);
    const boot = try compute.openDir(io, "boot-raw-x2apic", .{ .iterate = true });
    defer boot.close(io);
    const secret = "PRIVATE_SYNTHETIC_SERIAL_AND_PATH";
    try writeFixtureFile(io, boot, "hyperv-efi-boot.log", secret);
    const report = try controller.records.canonicalAlloc(a,
        \\{"passed":false,"cleanup_complete":true,"input_unchanged":true,"serial_valid":false,"serial_limit_reached":false,"failures":{"primary":{"payload":"PRIVATE_SYNTHETIC_SERIAL_AND_PATH"},"cleanup":null,"recording":null}}
    );
    defer a.free(report);
    try writeFixtureFile(io, boot, "report.json", report);
    try writeFixtureFile(io, evidence, "command-fixtures.json", "{\"exit_code\":1}\n");
    try writeFixtureFile(io, private, "fixtures.log", "test_safe_name (test_adapter.Evidence.test_safe_name) ... ERROR\nPRIVATE_SYNTHETIC_SERIAL_AND_PATH\n");
    var signal = try controller.build_pipeline.installCancellation();
    defer signal.deinit();
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    const compute_path = try std.fs.path.join(a, &.{ runtime, "compute" });
    defer a.free(compute_path);
    var base: controller.build_pipeline.Context = .{
        .allocator = scratch.allocator(),
        .io = io,
        .environ = undefined,
        .runtime = runtime,
        .repository = options.repository_root,
        .wamr = "",
        .compute = compute_path,
        .git = undefined,
        .tools = undefined,
        .roots = undefined,
        .signal = &signal,
    };
    var ctx: controller.boot_pipeline.Context = .{
        .build_context = &base,
        .pinned = std.StringHashMap(controller.custody_files.File).init(scratch.allocator()),
    };
    defer ctx.pinned.deinit();
    try controller.boot_pipeline.diagnostics(&ctx);
    const output_file = try evidence.openFile(io, "diagnostics.json", .{ .follow_symlinks = false });
    defer output_file.close(io);
    const output_size: usize = @intCast((try core.private_files.snapshot(output_file)).size);
    try std.testing.expect(output_size < 16 * 1024);
    const output = try a.alloc(u8, output_size);
    defer a.free(output);
    try std.testing.expectEqual(output_size, try output_file.readPositionalAll(io, output, 0));
    try std.testing.expect(std.mem.indexOf(u8, output, secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, output, runtime) == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "test_adapter.Evidence.test_safe_name") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "diagnostics_not_acceptance") != null);
    try std.testing.expectError(error.PathAlreadyExists, controller.boot_pipeline.diagnostics(&ctx));
    try std.testing.expectError(error.FileNotFound, evidence.openFile(io, "result.json", .{}));
}

test "result refuses unpinned evidence files and directories before publication" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("result-evidence-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("result evidence fixture cleanup failed");
    const path = try std.fs.path.join(a, &.{ options.fixture_root, name });
    defer a.free(path);
    const root = try parent.openDir(io, name, .{ .iterate = true });
    defer root.close(io);
    try root.createDir(io, "evidence", .fromMode(0o700));
    const evidence = try root.openDir(io, "evidence", .{ .iterate = true });
    defer evidence.close(io);
    try writeFixtureFile(io, evidence, "build.json", "{}\n");
    var signal = try controller.build_pipeline.installCancellation();
    defer signal.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var base: controller.build_pipeline.Context = .{
        .allocator = arena.allocator(),
        .io = io,
        .environ = undefined,
        .runtime = path,
        .repository = options.repository_root,
        .wamr = "",
        .compute = path,
        .git = undefined,
        .tools = undefined,
        .roots = undefined,
        .signal = &signal,
    };
    var ctx: controller.boot_pipeline.Context = .{
        .build_context = &base,
        .pinned = std.StringHashMap(controller.custody_files.File).init(arena.allocator()),
    };
    defer ctx.pinned.deinit();
    const build_path = try std.fs.path.join(a, &.{ path, "evidence", "build.json" });
    defer a.free(build_path);
    try ctx.pinned.put("build.json", try controller.custody_files.readFile(io, build_path, 4096, true));
    try controller.boot_pipeline.testing.checkExactEvidence(&ctx);

    try writeFixtureFile(io, evidence, "unlisted.json", "{}\n");
    try std.testing.expectError(error.UnexpectedEvidence, controller.boot_pipeline.testing.publishResult(&ctx));
    try std.testing.expectError(error.FileNotFound, evidence.openFile(io, "result.json", .{}));
    try evidence.deleteFile(io, "unlisted.json");
    try evidence.createDir(io, "unlisted", .fromMode(0o700));
    try std.testing.expectError(error.UnexpectedEvidence, controller.boot_pipeline.testing.publishResult(&ctx));
    try std.testing.expectError(error.FileNotFound, evidence.openFile(io, "result.json", .{}));
    try evidence.deleteDir(io, "unlisted");
    try controller.boot_pipeline.testing.checkExactEvidence(&ctx);
}

test "boot recheck uses transient scratch and refuses changed pinned evidence with no persistent space" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("boot-recheck-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("boot recheck fixture cleanup failed");
    const path = try std.fs.path.join(a, &.{ options.fixture_root, name });
    defer a.free(path);
    const root = try parent.openDir(io, name, .{ .iterate = true });
    defer root.close(io);
    try root.createDir(io, "evidence", .fromMode(0o700));
    const evidence = try root.openDir(io, "evidence", .{ .iterate = true });
    defer evidence.close(io);
    try writeFixtureFile(io, evidence, "build.json", "{}\n");
    try writeFixtureFile(io, evidence, "build-start.json", "{}\n");
    const build_path = try std.fs.path.join(a, &.{ path, "evidence/build.json" });
    defer a.free(build_path);
    const start_path = try std.fs.path.join(a, &.{ path, "evidence/build-start.json" });
    defer a.free(start_path);
    var signal = try controller.build_pipeline.installCancellation();
    defer signal.deinit();
    var empty: [0]u8 = .{};
    var no_growth = std.heap.FixedBufferAllocator.init(&empty);
    var base: controller.build_pipeline.Context = .{
        .allocator = no_growth.allocator(),
        .io = io,
        .environ = undefined,
        .runtime = path,
        .repository = options.repository_root,
        .wamr = "",
        .compute = path,
        .git = undefined,
        .tools = undefined,
        .roots = undefined,
        .signal = &signal,
        .build_start_record = try controller.custody_files.readFile(io, start_path, 4096, true),
    };
    base.build_start_record.?.bytes += 1;
    var ctx: controller.boot_pipeline.Context = .{
        .build_context = &base,
        .pinned = std.StringHashMap(controller.custody_files.File).init(a),
    };
    defer ctx.pinned.deinit();
    try ctx.pinned.put("build.json", try controller.custody_files.readFile(io, build_path, 4096, true));
    for (0..3) |_| try std.testing.expectError(error.BuildStartChanged, controller.boot_pipeline.testing.revalidateBase(&ctx));
    try evidence.deleteFile(io, "build.json");
    var missing_build = base;
    missing_build.allocator = a;
    try std.testing.expectError(error.FileNotFound, controller.build_pipeline.readAcceptedRecord(&missing_build, "build.json"));
    try writeFixtureFile(io, evidence, "build.json", "{\"changed\":true}\n");
    try std.testing.expectError(error.EvidenceChanged, controller.boot_pipeline.testing.revalidateBase(&ctx));
}

test "occupied build output and boot slots refuse without erasing prior state" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const parent = try core.private_files.Directory.open(io, options.fixture_root);
    defer parent.close(io);
    const name = try a.print("native-prior-output-{d}", .{std.os.linux.getpid()});
    try parent.dir.createDir(io, name, .fromMode(0o700));
    defer parent.dir.deleteTree(io, name) catch @panic("prior-output cleanup failed");
    const path = try std.fs.path.join(a, &.{ options.fixture_root, name });
    const root = try core.private_files.Directory.open(io, path);
    defer root.close(io);
    try root.dir.createDir(io, "compute", .fromMode(0o700));
    const compute_path = try std.fs.path.join(a, &.{ path, "compute" });
    const compute = try core.private_files.Directory.open(io, compute_path);
    defer compute.close(io);
    var signal = try controller.build_pipeline.installCancellation();
    defer signal.deinit();
    var build: controller.build_pipeline.Context = .{
        .allocator = a,
        .io = io,
        .environ = undefined,
        .runtime = path,
        .repository = options.repository_root,
        .wamr = "",
        .compute = compute_path,
        .git = undefined,
        .tools = undefined,
        .roots = undefined,
        .signal = &signal,
    };
    try writeFixtureFile(io, compute.dir, "prior", "retained");
    try std.testing.expectError(error.PathAlreadyExists, controller.build_pipeline.reserve(.{ .context = &build, .runtime = root }));
    const prior = try compute.dir.readFileAlloc(io, "prior", a, .limited(32));
    try std.testing.expectEqualStrings("retained", prior);
    for ([_][]const u8{ "package", "public-source", "boot-raw-x2apic", "boot-raw-legacy-apic", "boot-qcow2-x2apic", "boot-qcow2-legacy-apic", "boot-vpc-x2apic", "boot-vpc-legacy-apic" }) |slot|
        try compute.dir.createDir(io, slot, .fromMode(0o700));
    var boot: controller.boot_pipeline.Context = .{
        .build_context = &build,
        .pinned = std.StringHashMap(controller.custody_files.File).init(a),
    };
    try controller.boot_pipeline.testing.emptySlots(&boot);
    const slot = try compute.dir.openDir(io, "boot-raw-x2apic", .{ .iterate = true });
    defer slot.close(io);
    try writeFixtureFile(io, slot, "prior", "occupied");
    try std.testing.expectError(error.PriorOutput, controller.boot_pipeline.testing.emptySlots(&boot));
    const occupied = try slot.readFileAlloc(io, "prior", a, .limited(32));
    try std.testing.expectEqualStrings("occupied", occupied);
    try std.testing.expectError(error.FileNotFound, compute.dir.openFile(io, "evidence/result.json", .{}));
}

test "changed raw QCOW2 and derived VHD images never publish compute evidence" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("compute-image-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("compute image fixture cleanup failed");
    const path = try std.fs.path.join(a, &.{ options.fixture_root, name });
    defer a.free(path);
    const root = try parent.openDir(io, name, .{ .iterate = true });
    defer root.close(io);
    try root.createDir(io, "package", .fromMode(0o700));
    try root.createDir(io, "evidence", .fromMode(0o700));
    const package_dir = try root.openDir(io, "package", .{ .iterate = true });
    defer package_dir.close(io);
    const evidence_dir = try root.openDir(io, "evidence", .{ .iterate = true });
    defer evidence_dir.close(io);
    var signal = try controller.build_pipeline.installCancellation();
    defer signal.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var base: controller.build_pipeline.Context = .{
        .allocator = arena.allocator(),
        .io = io,
        .environ = undefined,
        .runtime = path,
        .repository = options.repository_root,
        .wamr = "",
        .compute = path,
        .git = undefined,
        .tools = undefined,
        .roots = undefined,
        .signal = &signal,
    };
    var ctx: controller.boot_pipeline.Context = .{
        .build_context = &base,
        .pinned = std.StringHashMap(controller.custody_files.File).init(arena.allocator()),
    };
    defer ctx.pinned.deinit();
    const source = "original-image";
    const hash = std.fmt.bytesToHex(controller.records.fileIdentity(source), .lower);
    ctx.package = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), try std.fmt.allocPrint(arena.allocator(), "{{\"image\":{{\"raw\":{{\"sha256\":\"{s}\"}}}}}}", .{&hash}), .{});
    const output = try std.fmt.allocPrint(arena.allocator(), "{{\"output\":{{\"sha256\":\"{s}\"}}}}", .{&hash});
    ctx.finalization = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), output, .{});
    ctx.derivation = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), output, .{});
    for ([_]usize{ 0, 2, 4 }, [_][]const u8{
        "unikraft.raw", "unikraft.qcow2", "unikraft-derived.vhd",
    }, [_][]const u8{
        "raw-x2apic-compute.json", "qcow2-x2apic-compute.json", "vpc-x2apic-compute.json",
    }) |index, filename, record_name| {
        try writeFixtureFile(io, package_dir, filename, source);
        try controller.boot_pipeline.testing.checkModeImage(&ctx, index);
        const image = try package_dir.openFile(io, filename, .{ .mode = .read_write, .follow_symlinks = false });
        try image.writePositionalAll(io, "changed--image", 0);
        image.close(io);
        try std.testing.expectError(error.ArtifactChanged, controller.boot_pipeline.testing.publishCompute(&ctx, index, .null));
        try std.testing.expectError(error.FileNotFound, evidence_dir.openFile(io, record_name, .{}));
    }
}

test "transport encoder preserves full 3 MiB and 8 MiB streams and refuses true excess" {
    const a = std.testing.allocator;
    const sizes = [_]struct { stdout: usize, stderr: usize }{
        .{ .stdout = 3 * 1024 * 1024, .stderr = 0 },
        .{ .stdout = 4 * 1024 * 1024, .stderr = 4 * 1024 * 1024 },
    };
    for (sizes) |selected| {
        const out = try a.alloc(u8, selected.stdout);
        defer a.free(out);
        @memset(out, 'A');
        const err = try a.alloc(u8, selected.stderr);
        defer a.free(err);
        @memset(err, 'B');
        const out64 = try a.alloc(u8, std.base64.standard.Encoder.calcSize(out.len));
        defer a.free(out64);
        _ = std.base64.standard.Encoder.encode(out64, out);
        const err64 = try a.alloc(u8, std.base64.standard.Encoder.calcSize(err.len));
        defer a.free(err64);
        _ = std.base64.standard.Encoder.encode(err64, err);
        var value = std.json.Value{ .object = .empty };
        defer value.object.deinit(a);
        try value.object.put(a, "stdout_base64", .{ .string = out64 });
        try value.object.put(a, "stderr_base64", .{ .string = err64 });
        const encoded = try controller.command_adapter.canonicalTransport(a, value);
        defer a.free(encoded);
        try std.testing.expect(encoded.len > controller.records.max_record_bytes);
        try std.testing.expect(encoded.len < controller.command_adapter.transport_result_max_bytes);
        var parsed = try std.json.parseFromSlice(std.json.Value, a, encoded, .{
            .max_value_len = controller.command_adapter.transport_result_max_bytes,
        });
        defer parsed.deinit();
        try std.testing.expectEqualStrings(out64, parsed.value.object.get("stdout_base64").?.string);
        try std.testing.expectEqualStrings(err64, parsed.value.object.get("stderr_base64").?.string);
    }
    const excess = try a.alloc(u8, controller.command_adapter.transport_result_max_bytes);
    defer a.free(excess);
    @memset(excess, 'A');
    var value = std.json.Value{ .object = .empty };
    defer value.object.deinit(a);
    try value.object.put(a, "stdout_base64", .{ .string = excess });
    try std.testing.expectError(error.CommandResultTooLarge, controller.command_adapter.canonicalTransport(a, value));
}

test "native tiny build identity refuses development optional JIT and altered file sets" {
    const a = std.testing.allocator;
    const identity = try a.print(
        \\{{"wamr_revision":"{s}","compiler_profile":"unikraft-x86_64","zig_version":"0.17.0","minimal_wasi":false,"development_only":false,"variant":"tiny","jit_mode":null,"files":{{
        \\"embedded.c":"{s}","identity.h":"{s}","libwamr-aot.a":"{s}","tiny.cwasm":"{s}","tiny.wasm":"{s}","wamr_aot.h":"{s}","wamrc":"{s}"}}}}
    , .{ controller.custody_limits.wamr_revision, &@as([64]u8, @splat('a')), &@as([64]u8, @splat('a')), &@as([64]u8, @splat('a')), &@as([64]u8, @splat('a')), &@as([64]u8, @splat('a')), &@as([64]u8, @splat('a')), &@as([64]u8, @splat('a')) });
    defer a.free(identity);
    const Mutation = struct { key: []const u8, value: ?std.json.Value = null };
    const changes = [_]Mutation{
        .{ .key = "" },
        .{ .key = "development_only", .value = .{ .bool = true } },
        .{ .key = "development_only", .value = .{ .integer = 1 } },
        .{ .key = "variant", .value = .{ .string = "coremark" } },
        .{ .key = "jit_mode", .value = .{ .string = "fast" } },
        .{ .key = "minimal_wasi", .value = .{ .bool = true } },
        .{ .key = "compiler_profile", .value = .{ .string = "different" } },
        .{ .key = "zig_version", .value = .{ .string = "0.16.0" } },
        .{ .key = "files", .value = .{ .object = .empty } },
    };
    for (changes, 0..) |change, index| {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const local = arena.allocator();
        var value = try std.json.parseFromSliceLeaky(std.json.Value, local, identity, .{ .allocate = .alloc_always });
        if (change.value) |replacement| try value.object.put(local, change.key, replacement);
        const native = if (controller.build_pipeline.admitPreparedIdentity(value)) |_| true else |_| false;
        try std.testing.expectEqual(index == 0, native);
        if (std.mem.eql(u8, change.key, "zig_version")) {
            try std.testing.expectError(error.InvalidProducer, controller.build_pipeline.admitImportedIdentity(value));
            try value.object.put(local, "wamr_revision", .{ .string = controller.custody_limits.historical_wamr_revision });
            try controller.build_pipeline.admitImportedIdentity(value);
            try std.testing.expectError(error.InvalidProducer, controller.build_pipeline.admitPreparedIdentity(value));
            try value.object.put(local, "zig_version", .{ .string = "0.17.0" });
            try std.testing.expectError(error.InvalidProducer, controller.build_pipeline.admitImportedIdentity(value));
            try value.object.put(local, "zig_version", .{ .string = "0.15.2" });
            try std.testing.expectError(error.InvalidProducer, controller.build_pipeline.admitImportedIdentity(value));
        }
    }
}

fn directSharedSupervisorFixtures() !void {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const cache = try a.dupe(u8, options.fixture_root);
    defer a.free(cache);
    const parent = try std.Io.Dir.openDirAbsolute(io, cache, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("supervision-fixture-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("supervision fixture cleanup failed");
    const fixture_root = try std.fs.path.join(a, &.{ cache, name });
    defer a.free(fixture_root);
    const executable = try std.fs.path.resolve(a, &.{ options.repository_root, options.command_fixture });
    defer a.free(executable);
    const bound_tool = try std.Io.Dir.realPathFileAbsoluteAlloc(io, "/usr/bin/true", a);
    defer a.free(bound_tool);
    const fixture_dir = try parent.openDir(io, name, .{ .iterate = true });
    defer fixture_dir.close(io);
    const scenarios = [_]struct {
        name: []const u8,
        accepted: bool,
        kind: []const u8,
        limit: usize = 256,
        seconds: u32 = 4,
        cancelled: bool = false,
    }{
        .{ .name = "ok", .accepted = true, .kind = "exited", .limit = 8 * 1024 * 1024, .seconds = 600 },
        .{ .name = "reported-error", .accepted = false, .kind = "exited" },
        .{ .name = "nonzero", .accepted = false, .kind = "exited" },
        .{ .name = "partial", .accepted = false, .kind = "exited" },
        .{ .name = "signal", .accepted = false, .kind = "signal" },
        .{ .name = "overflow", .accepted = false, .kind = "output_overflow", .limit = 32 },
        .{ .name = "timeout", .accepted = false, .kind = "timeout", .seconds = 1 },
        .{ .name = "cancelled", .accepted = false, .kind = "cancelled", .cancelled = true },
        .{ .name = "large-3m", .accepted = true, .kind = "exited", .limit = 8 * 1024 * 1024 },
        .{ .name = "large-8m", .accepted = true, .kind = "exited", .limit = 8 * 1024 * 1024 },
    };
    for (scenarios) |scenario| {
        try fixture_dir.createDir(io, scenario.name, .fromMode(0o700));
        const slot = try fixture_dir.openDir(io, scenario.name, .{ .iterate = true });
        defer slot.close(io);
        for ([_][]const u8{ "private", "evidence", "fixtures" }) |directory|
            try slot.createDir(io, directory, .fromMode(0o700));
        const private = try slot.openDir(io, "private", .{ .iterate = true });
        defer private.close(io);
        const evidence = try slot.openDir(io, "evidence", .{ .iterate = true });
        defer evidence.close(io);
        const fixtures = try slot.openDir(io, "fixtures", .{ .iterate = true });
        defer fixtures.close(io);
        try writeFixtureFile(io, fixtures, "scenario", if (scenario.cancelled) "timeout" else scenario.name);
        const work = try std.fs.path.join(a, &.{ fixture_root, scenario.name });
        defer a.free(work);
        const repeated = @as([controller.input_custody.host_tools.len][]const u8, @splat(bound_tool));
        const stop = std.atomic.Value(bool).init(scenario.cancelled);
        const result = try controller.command_adapter.execute(a, io, .{
            .roots = .{
                .source_root = options.repository_root,
                .work = work,
                .runtime = fixture_root,
                .zig = bound_tool,
                .producer = bound_tool,
                .fixture_runner = executable,
                .supervisor = bound_tool,
                .package_tool = bound_tool,
                .validator = bound_tool,
                .supervisor_fixture = bound_tool,
                .tools = repeated,
            },
            .stage = .fixtures,
            .private_dir = private,
            .evidence_dir = evidence,
            .test_seconds = scenario.seconds,
            .test_output_limit = scenario.limit,
            .cancel = if (scenario.cancelled) &stop else null,
        });
        try std.testing.expectEqual(scenario.accepted, result.accepted);
        try std.testing.expect(!result.poisoned);
        try std.testing.expectEqualStrings(scenario.kind, @tagName(result.primary));
        const private_log = try private.openFile(io, "fixtures.log", .{ .follow_symlinks = false });
        defer private_log.close(io);
        const log_path = try std.fs.path.join(a, &.{ work, "private/fixtures.log" });
        defer a.free(log_path);
        const log_stat = try controller.custody_files.readFile(io, log_path, scenario.limit + 1, true);
        try std.testing.expect(log_stat.bytes <= scenario.limit + 1);
        const public_file = try evidence.openFile(io, "command-fixtures.json", .{ .follow_symlinks = false });
        defer public_file.close(io);
        const size = (try core.private_files.snapshot(public_file)).size;
        const raw = try a.alloc(u8, @intCast(size));
        defer a.free(raw);
        try std.testing.expectEqual(raw.len, try public_file.readPositionalAll(io, raw, 0));
        const record = try core.contracts.Document.parse(a, raw, .{});
        defer record.deinit();
        try record.requireCanonical(a, raw);
        const record_path = try std.fs.path.join(a, &.{ work, "evidence/command-fixtures.json" });
        defer a.free(record_path);
        const value = record.value().object;
        try std.testing.expectEqual(log_stat.bytes, try core.contracts.integer(u64, value.get("bytes").?));
        try std.testing.expectEqualStrings(&log_stat.sha256, value.get("sha256").?.string);
        try std.testing.expectEqualStrings("command_diagnostic_not_acceptance", value.get("scope").?.string);
        try std.testing.expectEqualStrings("fixtures", value.get("stage").?.string);
        try std.testing.expectEqual(scenario.accepted, !value.get("over_limit").?.bool and
            try core.contracts.integer(i32, value.get("exit_code").?) == 0 and
            value.get("known_error_markers").?.array.items.len == 0);
        try std.testing.expectEqualStrings("uk.wamr.command-supervisor-result", value.get("supervisor").?.object.get("schema").?.string);
        try std.testing.expect(std.mem.indexOf(u8, raw, "/private/secret") == null);
        try std.testing.expect(std.mem.indexOf(u8, raw, "partial private output") == null);
        if (std.mem.eql(u8, scenario.name, "nonzero"))
            try std.testing.expectEqualStrings("PermissionDenied", value.get("known_error_markers").?.array.items[0].string);
        try std.testing.expectError(error.PathAlreadyExists, controller.command_adapter.execute(a, io, .{
            .roots = .{
                .source_root = options.repository_root,
                .work = work,
                .runtime = fixture_root,
                .zig = bound_tool,
                .producer = bound_tool,
                .fixture_runner = executable,
                .supervisor = bound_tool,
                .package_tool = bound_tool,
                .validator = bound_tool,
                .supervisor_fixture = bound_tool,
                .tools = repeated,
            },
            .stage = .fixtures,
            .private_dir = private,
            .evidence_dir = evidence,
            .test_seconds = 1,
            .test_output_limit = scenario.limit,
        }));
        if (std.mem.eql(u8, scenario.name, "ok")) {
            const validated = try controller.accepted_run.validateCommandBinding(a, raw, .fixtures, .local_runtime);
            try std.testing.expectEqual(controller.command_plan.Stage.fixtures, validated.stage);
            _ = try controller.accepted_run.validateCommandBinding(a, raw, .fixtures, .trusted_inner_zip);
            var mutated = try std.json.parseFromSlice(std.json.Value, a, raw, .{
                .duplicate_field_behavior = .@"error",
                .allocate = .alloc_always,
            });
            defer mutated.deinit();
            const request = mutated.value.object.getPtr("supervisor").?.object.getPtr("request").?;
            try request.object.put(a, "timeout_ns", .{ .integer = 1 });
            const tampered_raw = try std.json.Stringify.valueAlloc(a, mutated.value, .{});
            defer a.free(tampered_raw);
            const tampered = try controller.records.canonicalAlloc(a, tampered_raw);
            defer a.free(tampered);
            try std.testing.expectError(error.InvalidCommand, controller.accepted_run.validateCommandBinding(a, tampered, .fixtures, .trusted_inner_zip));
            var cancellation = try controller.build_pipeline.installCancellation();
            defer cancellation.deinit();
            var context: controller.build_pipeline.Context = .{
                .allocator = a,
                .io = io,
                .environ = undefined,
                .runtime = fixture_root,
                .repository = options.repository_root,
                .wamr = fixture_root,
                .compute = work,
                .git = undefined,
                .tools = undefined,
                .roots = undefined,
                .signal = &cancellation,
            };
            context.command_records[@backingInt(controller.command_plan.Stage.fixtures)] =
                try controller.custody_files.readFile(io, record_path, 1024 * 1024, true);
            try controller.build_pipeline.requireBuildEvidence(&context);
            const changed = try evidence.openFile(io, "command-fixtures.json", .{
                .mode = .read_write,
                .follow_symlinks = false,
            });
            defer changed.close(io);
            try changed.writePositionalAll(io, " ", 0);
            try std.testing.expectError(error.CommandEvidenceChanged, controller.build_pipeline.requireBuildEvidence(&context));
        }
    }
}

test "closed production profile and historical read-only mode order" {
    const profile = controller.profile;
    try std.testing.expectEqual(profile.CompatibleRecordSet.tiny_v2_qcow2_derived_vhd, profile.productionSet(.tiny_exact_v2));
    try std.testing.expectEqualStrings("qcow2-derived-vhd", profile.profileName(.tiny_exact_v2));
    try std.testing.expectEqual(profile.CompatibleRecordSet.tiny_v1_legacy, try profile.recordSet(1, null));
    try std.testing.expectEqual(profile.CompatibleRecordSet.tiny_v2_qcow2_derived_vhd, try profile.recordSet(2, "qcow2-derived-vhd"));
    try std.testing.expectError(error.UnsupportedRecordSet, profile.recordSet(1, "qcow2-derived-vhd"));
    try std.testing.expectError(error.UnsupportedRecordSet, profile.recordSet(2, "coremark"));
    try std.testing.expectError(error.UnsupportedRecordSet, profile.recordSet(3, "qcow2-derived-vhd"));
    for (profile.modes(.tiny_v1_legacy), [_][]const u8{
        "raw-x2apic", "raw-legacy-apic", "vpc-x2apic", "vpc-legacy-apic",
    }) |mode, name| try std.testing.expectEqualStrings(name, @tagName(mode));
    for (profile.modes(.tiny_v2_qcow2_derived_vhd), [_][]const u8{
        "raw-x2apic",        "raw-legacy-apic", "qcow2-x2apic",
        "qcow2-legacy-apic", "vpc-x2apic",      "vpc-legacy-apic",
    }) |mode, name| try std.testing.expectEqualStrings(name, @tagName(mode));
    for (profile.production_modes, 0..) |mode, i|
        try std.testing.expectEqual(i % 2 == 1, mode.legacyApic());
}

test "portable target installer refuses musl, v3 and incomplete overrides" {
    const target = controller.target;
    const correct = target.portableQuery();
    try std.testing.expect(target.permitsInstall(correct, .safe));
    try std.testing.expect(!target.permitsInstall(correct, .debug));
    try std.testing.expect(!target.permitsInstall(.{}, .safe));
    for ([_]struct { triple: []const u8, cpu: ?[]const u8 }{
        .{ .triple = "x86_64-linux-musl", .cpu = "x86_64_v2" },
        .{ .triple = "x86_64-linux-gnu", .cpu = "x86_64_v3" },
        .{ .triple = "x86_64-linux-gnu", .cpu = null },
    }) |bad| {
        const query = try std.Target.Query.parse(.{
            .arch_os_abi = bad.triple,
            .cpu_features = bad.cpu,
        });
        try std.testing.expect(!target.permitsInstall(query, .safe));
    }
}

test "imported validator build binds the fixed portable plan with minimal tools" {
    const plan = controller.command_plan;
    const native = plan.spec(.@"public-validator-build");
    const imported = plan.spec(.@"import-validator-build");
    try std.testing.expectEqualStrings("tool:zig", imported.executable);
    try std.testing.expectEqual(native.seconds, imported.seconds);
    try std.testing.expectEqual(native.output_limit, imported.output_limit);
    try std.testing.expectEqualSlices(plan.Binding, native.argv, imported.argv);
    const env = try plan.environment(std.testing.allocator, .@"import-validator-build");
    defer plan.freeEnvironment(std.testing.allocator, env);
    var git = false;
    var compiler = false;
    var library = false;
    for (env, 0..) |item, i| {
        if (i > 0) try std.testing.expect(std.mem.lessThan(u8, env[i - 1].name, item.name));
        if (std.mem.eql(u8, item.name, "WAMR_CI_GIT")) git = std.mem.eql(u8, item.value.path.role, "tool:git");
        if (std.mem.eql(u8, item.name, "WAMR_CI_LAUNCH_EXECUTABLE")) compiler = std.mem.eql(u8, item.value.path.role, "tool:zig");
        if (std.mem.eql(u8, item.name, "ZIG_LIB_DIR")) library = std.mem.eql(u8, item.value.path.role, "tool-tree:zig");
        try std.testing.expect(!std.mem.startsWith(u8, item.name, "WAMR_CI_TOOL_"));
    }
    try std.testing.expect(git and compiler and library);
}

test "imported revalidation binds only the built validator and private bundle" {
    const plan = controller.command_plan;
    const spec = plan.spec(.@"import-native-revalidation");
    try std.testing.expectEqualStrings("input:validator", spec.executable);
    try std.testing.expectEqual(@as(u32, 600), spec.seconds);
    try std.testing.expectEqual(@as(usize, 4096), spec.output_limit);
    try std.testing.expectEqual(@as(usize, 3), spec.argv.len);
    try std.testing.expectEqualStrings("input:validator", spec.argv[0].path.role);
    try std.testing.expectEqualStrings("handoff", spec.argv[1].literal);
    try std.testing.expectEqualStrings("input:bundle", spec.argv[2].path.role);
    const env = try plan.environment(std.testing.allocator, .@"import-native-revalidation");
    defer plan.freeEnvironment(std.testing.allocator, env);
    try std.testing.expectEqual(@as(usize, 6), env.len);
    for (env, 0..) |entry, i| {
        if (i > 0) try std.testing.expect(std.mem.lessThan(u8, env[i - 1].name, entry.name));
        try std.testing.expect(!std.mem.startsWith(u8, entry.name, "WAMR_CI_TOOL_"));
        try std.testing.expect(!std.mem.eql(u8, entry.name, "WAMR_CI_LAUNCH_EXECUTABLE"));
    }
}

test "trusted import authenticates relocated native tools without producer filesystem identities" {
    var checkpoint: []const u8 = "setup";
    errdefer std.debug.print("relocated import failed at {s}\n", .{checkpoint});
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("relocated-native-import-{d}", .{std.os.linux.getpid()});
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("relocated import cleanup failed");
    const root = try parent.openDir(io, name, .{ .iterate = true });
    defer root.close(io);
    const path = try std.fs.path.join(a, &.{ options.fixture_root, name });
    for ([_][]const u8{ "producer", "destination" }) |runner| try root.createDir(io, runner, .fromMode(0o700));
    const producer = try root.openDir(io, "producer", .{ .iterate = true });
    defer producer.close(io);
    const destination = try root.openDir(io, "destination", .{ .iterate = true });
    defer destination.close(io);
    const producer_repo = try std.fs.path.join(a, &.{ path, "producer/source" });
    const repository = try std.fs.path.join(a, &.{ path, "destination/source" });
    for ([_][]const u8{ producer_repo, repository }) |checkout| {
        const cloned = try std.process.run(a, io, .{
            .argv = &.{ options.git_executable, "clone", "-q", "--no-hardlinks", "--", options.repository_root, checkout },
            .cwd = .{ .path = options.fixture_root },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, cloned.term);
    }
    checkpoint = "copy tools";
    try copyFixtureExecutable(io, a, options.host_controller_cli, producer, "controller");
    try copyFixtureExecutable(io, a, options.host_controller_cli, destination, "controller");
    try copyFixtureExecutable(io, a, options.host_controller_cli, destination, "supervisor");
    try copyFixtureExecutable(io, a, options.import_validator, destination, "validator");
    try copyFixtureExecutable(io, a, options.git_executable, producer, "git");
    {
        const original_zig = try std.Io.Dir.openFileAbsolute(io, options.zig_executable, .{});
        defer original_zig.close(io);
        const copied_zig = try producer.createFile(io, "zig", .{ .exclusive = true, .permissions = .fromMode(0o500) });
        defer copied_zig.close(io);
        var buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (true) {
            const count = try original_zig.readPositionalAll(io, &buffer, offset);
            if (count == 0) break;
            try copied_zig.writeStreamingAll(io, buffer[0..count]);
            offset += count;
        }
    }
    const producer_controller = try std.fs.path.join(a, &.{ path, "producer/controller" });
    const owner = try std.fs.path.join(a, &.{ path, "destination/controller" });
    const supervisor = try std.fs.path.join(a, &.{ path, "destination/supervisor" });
    const validator = try std.fs.path.join(a, &.{ path, "destination/validator" });
    const producer_git = try std.fs.path.join(a, &.{ path, "producer/git" });
    const producer_zig = try std.fs.path.join(a, &.{ path, "producer/zig" });
    const producer_identity = try controller.custody_files.readFile(io, producer_controller, 64 * 1024 * 1024, false);
    const relocated_identity = try controller.custody_files.readFile(io, supervisor, 64 * 1024 * 1024, false);
    try std.testing.expectEqualSlices(u8, &producer_identity.sha256, &relocated_identity.sha256);
    try std.testing.expect(producer_identity.metadata[1] != relocated_identity.metadata[1]);
    try std.testing.expect(producer_identity.metadata[7] != relocated_identity.metadata[7]);
    checkpoint = "producer source";
    try std.testing.expectError(error.FileNotFound, controller.source_custody.source(a, io, producer_repo, options.git_executable));
    const origin = try controller.source_custody.portableSource(a, io, producer_repo, options.git_executable);
    checkpoint = "capture producer inputs";
    const source_identity = controller.accepted_run.SourceIdentity{ .revision = origin.revision, .tree = origin.tree };
    var custody = try controller.input_custody.capture(a, io, &.{
        .{ .role = "command-supervisor", .path = producer_controller },
        .{ .role = "tool:git", .path = producer_git },
        .{ .role = "tool:zig", .path = producer_zig },
    }, &.{});
    defer custody.deinit(a);
    var start = std.json.Value{ .object = .empty };
    try start.object.put(a, "source_custody", try std.json.parseFromSliceLeaky(std.json.Value, a, try std.json.Stringify.valueAlloc(a, origin.custody, .{}), .{}));
    try start.object.put(a, "consumer_inputs", try std.json.parseFromSliceLeaky(std.json.Value, a, try custody.canonical(a), .{}));
    try start.object.put(a, "command_supervisor", try controller.build_pipeline.captureSupervisorState(a, io, producer_repo, producer_controller));
    start = try std.json.parseFromSliceLeaky(std.json.Value, a, try canonicalJsonValue(a, start), .{ .parse_numbers = false });
    checkpoint = "bind relocated tools";
    try producer.deleteFile(io, "git");
    try producer.deleteFile(io, "zig");
    const local = controller.import_validator_build.LocalTools{ .git = options.git_executable, .supervisor = supervisor, .validator = validator };
    var bound = try controller.import_validator_build.PortableTools.bind(a, io, .trusted_inner_zip, source_identity, start, repository, owner, local, null);
    defer bound.deinit(io);
    try bound.verify(io, repository, local.git);
    checkpoint = "owner identity";
    const identity_command = try std.process.run(a, io, .{
        .argv = &.{ owner, "--identity" },
        .cwd = .{ .path = repository },
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, identity_command.term);
    const closure = try controller.import_supervisor_identity.nativeSourceContentClosure(a);
    try std.testing.expectEqualStrings(try controller.import_supervisor_identity.identityBytes(a, &closure), identity_command.stdout);
    try std.testing.expectError(error.InvalidContext, controller.import_validator_build.PortableTools.bind(a, io, .local_runtime, source_identity, start, repository, owner, local, null));

    const producer_source = try std.Io.Dir.openDirAbsolute(io, producer_repo, .{ .iterate = true });
    checkpoint = "rehash source";
    defer producer_source.close(io);
    const relative = "support/build/wamr-native-ci/controller/cli.zig";
    const original = try producer_source.readFileAlloc(io, relative, a, .limited(1024 * 1024));
    try appendRelativeFixtureFile(io, producer_source, relative, "\n");
    var altered = start;
    altered.object = try start.object.clone(a);
    try altered.object.put(a, "command_supervisor", try controller.build_pipeline.captureSupervisorState(a, io, producer_repo, producer_controller));
    altered = try std.json.parseFromSliceLeaky(std.json.Value, a, try canonicalJsonValue(a, altered), .{ .parse_numbers = false });
    try std.testing.expectError(error.ImportSourceChanged, controller.import_validator_build.PortableTools.bind(a, io, .trusted_inner_zip, source_identity, altered, repository, owner, local, null));
    {
        const restored = try producer_source.openFile(io, relative, .{ .mode = .write_only, .follow_symlinks = false });
        defer restored.close(io);
        try restored.setLength(io, original.len);
        try restored.writePositionalAll(io, original, 0);
    }
    checkpoint = "rehash supervisor";
    const substituted_executable = options.command_fixture;
    try producer.deleteFile(io, "controller");
    try copyFixtureExecutable(io, a, substituted_executable, producer, "controller");
    var substituted_custody = try controller.input_custody.capture(a, io, &.{.{ .role = "command-supervisor", .path = producer_controller }}, &.{});
    defer substituted_custody.deinit(a);
    try altered.object.put(a, "consumer_inputs", try std.json.parseFromSliceLeaky(std.json.Value, a, try substituted_custody.canonical(a), .{}));
    try altered.object.put(a, "command_supervisor", try controller.build_pipeline.captureSupervisorState(a, io, producer_repo, producer_controller));
    altered = try std.json.parseFromSliceLeaky(std.json.Value, a, try canonicalJsonValue(a, altered), .{ .parse_numbers = false });
    const substituted = controller.import_validator_build.LocalTools{ .git = local.git, .supervisor = producer_controller, .validator = validator };
    try std.testing.expectError(error.ImportSupervisorChanged, controller.import_validator_build.PortableTools.bind(a, io, .trusted_inner_zip, source_identity, altered, repository, owner, substituted, null));
    try destination.deleteFile(io, "validator");
    checkpoint = "substitute local validator";
    try copyFixtureExecutable(io, a, substituted_executable, destination, "validator");
    try std.testing.expectError(error.InvalidValidator, controller.import_validator_build.PortableTools.bind(a, io, .trusted_inner_zip, source_identity, start, repository, owner, local, null));
    try std.testing.expectError(error.FileChanged, bound.verify(io, repository, local.git));
    try destination.deleteFile(io, "validator");
    try copyFixtureExecutable(io, a, options.import_validator, destination, "validator");
    var source_bound = try controller.import_validator_build.PortableTools.bind(a, io, .trusted_inner_zip, source_identity, start, repository, owner, local, null);
    defer source_bound.deinit(io);
    const source_dir = try std.Io.Dir.openDirAbsolute(io, repository, .{ .iterate = true });
    defer source_dir.close(io);
    try appendRelativeFixtureFile(io, source_dir, relative, "\n");
    try std.testing.expectError(error.DirtySource, source_bound.verify(io, repository, local.git));
    try std.testing.expectError(error.DirtySource, controller.import_validator_build.PortableTools.bind(a, io, .trusted_inner_zip, source_identity, start, repository, owner, local, null));
}

test "native handoff revalidation is supervised and retains bounded refusal evidence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("native-handoff-revalidation-{d}", .{std.os.linux.getpid()});
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("handoff revalidation fixture cleanup failed");
    const root = try parent.openDir(io, name, .{ .iterate = true });
    defer root.close(io);
    for ([_][]const u8{ "accepted", "reported-error", "nonzero", "overflow", "ok" }) |scenario| {
        try root.createDir(io, scenario, .fromMode(0o700));
        const work = try root.openDir(io, scenario, .{ .iterate = true });
        defer work.close(io);
        try writeFixtureFile(io, work, "bundle.json", scenario);
        for ([_][]const u8{ "private", "evidence" }) |entry| try work.createDir(io, entry, .fromMode(0o700));
        const private = try work.openDir(io, "private", .{ .iterate = true });
        defer private.close(io);
        const evidence = try work.openDir(io, "evidence", .{ .iterate = true });
        defer evidence.close(io);
        const path = try std.fs.path.join(a, &.{ options.fixture_root, name, scenario });
        const checked = controller.import_validator_build.revalidateHandoffCommand(a, io, .{
            .source_root = options.repository_root,
            .work = path,
            .runtime = options.fixture_root,
            .zig = "",
            .producer = "",
            .supervisor = options.host_controller_cli,
            .package_tool = "",
            .validator = "",
            .direct_validator = options.command_fixture,
            .bundle = try std.fs.path.join(a, &.{ path, "bundle.json" }),
            .tools = @as([controller.input_custody.host_tools.len][]const u8, @splat("")),
        }, private, evidence, null);
        if (std.mem.eql(u8, scenario, "accepted")) {
            try std.testing.expectEqual(controller.command_plan.Stage.@"import-native-revalidation", (try checked).stage);
        } else try std.testing.expectError(error.StageRefused, checked);
        const record = try evidence.readFileAlloc(io, "command-import-native-revalidation.json", a, .limited(controller.records.max_record_bytes));
        try std.testing.expect(record.len != 0);
        const log = try private.openFile(io, "import-native-revalidation.log", .{});
        defer log.close(io);
        try std.testing.expect((try log.stat(io)).size <= 4097);
    }
}

test "imported handoff member rebasing preserves only safe expected relative paths" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var valid = std.json.Value{ .object = .empty };
    try valid.object.put(a, "path", .{ .string = "artifacts/wasm" });
    try controller.import_validator_build.Fixture.rebaseMember(a, "/trusted/stage", &valid, "artifacts/");
    try std.testing.expectEqualStrings("/trusted/stage/artifacts/wasm", valid.object.get("path").?.string);
    for ([_]struct { path: []const u8, expected: anyerror }{
        .{ .path = "artifacts/../wasm", .expected = error.UnsafePath },
        .{ .path = "evidence/wasm", .expected = error.InvalidImportedBundle },
        .{ .path = "/trusted/wasm", .expected = error.UnsafePath },
    }) |case| {
        var item = std.json.Value{ .object = .empty };
        try item.object.put(a, "path", .{ .string = case.path });
        try std.testing.expectError(
            case.expected,
            controller.import_validator_build.Fixture.rebaseMember(a, "/trusted/stage", &item, "artifacts/"),
        );
    }
}

test "borrowed custody hashing checks the held descriptor and its current name" {
    const files = core.private_files;
    const a = std.testing.allocator;
    const io = std.testing.io;
    const parent = try files.openDirectory(io, options.fixture_root, .private);
    defer parent.close(io);
    const name = try a.print("borrowed-custody-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch {};
    const directory = try parent.openDir(io, name, .{ .iterate = true });
    defer directory.close(io);
    const path = try std.fs.path.join(a, &.{ options.fixture_root, name, "member" });
    defer a.free(path);
    try writeFixtureFile(io, directory, "member", "native inventory member");
    var held = try files.RetainedFile.open(io, path, .private);
    defer held.close(io);
    const observed = try controller.custody_files.readRetained(io, &held, 4096);
    try std.testing.expectEqualSlices(u8, &std.fmt.bytesToHex(controller.records.fileIdentity("native inventory member"), .lower), &observed.sha256);
    try std.testing.expectEqualDeep(controller.custody_files.metadata(held.file_snapshot), observed.metadata);
    try directory.deleteFile(io, "member");
    try writeFixtureFile(io, directory, "member", "native inventory member");
    try std.testing.expectError(
        error.FileChanged,
        controller.custody_files.readRetained(io, &held, 4096),
    );
}

const CustodyIoProbe = struct {
    const Mode = enum { count, replace_ancestor, replace_fifo, cancel_verify };
    table: std.Io.VTable = std.testing.io.vtable.*,
    mode: Mode = .count,
    root: ?std.Io.Dir = null,
    directory_opens: usize = 0,
    reads: usize = 0,
    bytes: usize = 0,
    eof: bool = false,
    read_file: ?std.Io.File = null,
    injected: bool = false,
    threadlocal var active: ?*CustodyIoProbe = null;

    fn install(self: *CustodyIoProbe) std.Io {
        std.debug.assert(active == null);
        active = self;
        self.table.dirOpenDir = openDirectory;
        self.table.fileReadPositional = read;
        return .{ .userdata = std.testing.io.userdata, .vtable = &self.table };
    }

    fn deinit(_: *CustodyIoProbe) void {
        active = null;
    }

    fn openDirectory(
        userdata: ?*anyopaque,
        directory: std.Io.Dir,
        path: []const u8,
        open_options: std.Io.Dir.OpenOptions,
    ) std.Io.Dir.OpenError!std.Io.Dir {
        const self = active.?;
        self.directory_opens += 1;
        if (self.eof and !self.injected and self.mode != .count) {
            self.injected = true;
            const io = std.testing.io;
            switch (self.mode) {
                .count => unreachable,
                .cancel_verify => return error.Canceled,
                .replace_ancestor => {
                    const root = self.root.?;
                    const held = core.private_files.snapshot(self.read_file.?) catch |err| return injectionError(err);
                    std.Io.Dir.rename(root, "tree", root, "retained-tree", io) catch |err| return injectionError(err);
                    root.createDir(io, "tree", .fromMode(0o700)) catch |err| return injectionError(err);
                    const replacement = root.openDir(io, "tree", .{ .iterate = true }) catch |err| return injectionError(err);
                    defer replacement.close(io);
                    writeFixtureFile(io, replacement, "member", "native inventory member") catch |err| return injectionError(err);
                    const after = core.private_files.snapshot(self.read_file.?) catch |err| return injectionError(err);
                    if (!core.private_files.sameSnapshot(held, after)) return injectionError(error.FixtureDescriptorChanged);
                },
                .replace_fifo => {
                    const tree = self.root.?.openDir(io, "tree", .{ .iterate = true }) catch |err| return injectionError(err);
                    defer tree.close(io);
                    tree.deleteFile(io, "member") catch |err| return injectionError(err);
                    if (std.os.linux.errno(std.os.linux.mknodat(tree.handle, "member", std.os.linux.S.IFIFO | 0o600, 0)) != .SUCCESS)
                        return injectionError(error.FixtureFifo);
                },
            }
        }
        return std.testing.io.vtable.dirOpenDir(userdata, directory, path, open_options);
    }

    fn injectionError(err: anyerror) error{Unexpected} {
        std.debug.print("custody terminal fixture injection failed: {s}\n", .{@errorName(err)});
        return error.Unexpected;
    }

    fn read(
        userdata: ?*anyopaque,
        file: std.Io.File,
        data: []const []u8,
        offset: u64,
    ) std.Io.File.ReadPositionalError!usize {
        const count = try std.testing.io.vtable.fileReadPositional(userdata, file, data, offset);
        const self = active.?;
        self.reads += 1;
        self.bytes += count;
        if (count == 0) {
            self.eof = true;
            self.read_file = file;
        }
        return count;
    }
};

test "input tree uses one terminal borrowed descriptor verification and recaptures fresh bytes" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const parent = try core.private_files.openDirectory(io, options.fixture_root, .private);
    defer parent.close(io);
    const name = try a.print("input-terminal-verification-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("terminal verification fixture cleanup failed");
    const root = try parent.openDir(io, name, .{ .iterate = true });
    defer root.close(io);
    const path = try std.fs.path.join(a, &.{ options.fixture_root, name });
    defer a.free(path);
    const binding: controller.input_custody.Binding = .{ .role = "test", .path = path };
    var probe: CustodyIoProbe = .{};
    const traced = probe.install();
    defer probe.deinit();
    _ = try controller.input_custody.tree(a, traced, binding);
    const tree_directories = probe.directory_opens;
    const names = [_][]const u8{ "first", "second", "third" };
    for (names) |member| try writeFixtureFile(io, root, member, "native inventory member");
    probe.directory_opens = 0;
    for (names) |member| {
        const file_path = try std.fs.path.join(a, &.{ path, member });
        defer a.free(file_path);
        _ = try controller.custody_files.readFile(traced, file_path, 4096, false);
    }
    const expected_directories = tree_directories + probe.directory_opens;
    const expected_reads = probe.reads;
    const expected_bytes = probe.bytes;
    probe.directory_opens = 0;
    probe.reads = 0;
    probe.bytes = 0;
    const first = try controller.input_custody.tree(a, traced, binding);
    try std.testing.expectEqual(expected_directories, probe.directory_opens);
    try std.testing.expectEqual(expected_reads, probe.reads);
    try std.testing.expectEqual(expected_bytes, probe.bytes);
    const second = try controller.input_custody.tree(a, traced, binding);
    try std.testing.expectEqual(expected_directories * 2, probe.directory_opens);
    try std.testing.expectEqual(expected_reads * 2, probe.reads);
    try std.testing.expectEqual(expected_bytes * 2, probe.bytes);
    try std.testing.expectEqualDeep(first, second);
    try appendRelativeFixtureFile(io, root, "first", "\n");
    const changed = try controller.input_custody.tree(a, traced, binding);
    try std.testing.expect(!std.mem.eql(u8, &first.content_sha256, &changed.content_sha256));
}

test "input tree terminal verification refuses ancestor replacement FIFO and cancellation" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const parent = try core.private_files.openDirectory(io, options.fixture_root, .private);
    defer parent.close(io);
    for ([_]CustodyIoProbe.Mode{ .replace_ancestor, .replace_fifo, .cancel_verify }) |mode| {
        const name = try a.print("input-terminal-{s}-{d}", .{ @tagName(mode), std.os.linux.getpid() });
        defer a.free(name);
        try parent.createDir(io, name, .fromMode(0o700));
        defer parent.deleteTree(io, name) catch @panic("terminal refusal fixture cleanup failed");
        const root = try parent.openDir(io, name, .{ .iterate = true });
        defer root.close(io);
        try root.createDir(io, "tree", .fromMode(0o700));
        const tree = try root.openDir(io, "tree", .{ .iterate = true });
        defer tree.close(io);
        try writeFixtureFile(io, tree, "member", "native inventory member");
        const path = try std.fs.path.join(a, &.{ options.fixture_root, name, "tree" });
        defer a.free(path);
        var probe: CustodyIoProbe = .{ .mode = mode, .root = root };
        const traced = probe.install();
        defer probe.deinit();
        const expected: anyerror = switch (mode) {
            .replace_ancestor => error.FileChanged,
            .replace_fifo => error.UnsafeFile,
            .cancel_verify => error.Canceled,
            .count => unreachable,
        };
        try std.testing.expectError(expected, controller.input_custody.tree(a, traced, .{ .role = "test", .path = path }));
        try std.testing.expect(probe.injected);
    }
}

test "local consumer custody recaptures exact files trees and ancestry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("local-consumer-custody-{d}", .{std.os.linux.getpid()});
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("local consumer fixture cleanup failed");
    const root = try parent.openDir(io, name, .{ .iterate = true });
    defer root.close(io);
    try writeFixtureFile(io, root, "input", "original");
    try root.createDir(io, "tree", .fromMode(0o700));
    const tree = try root.openDir(io, "tree", .{ .iterate = true });
    defer tree.close(io);
    try writeFixtureFile(io, tree, "member", "member");
    const fixture_path = try std.fs.path.join(a, &.{ options.fixture_root, name });
    const file_path = try std.fs.path.join(a, &.{ fixture_path, "input" });
    const tree_path = try std.fs.path.join(a, &.{ fixture_path, "tree" });
    var original = try controller.input_custody.capture(a, io, &.{
        .{ .role = "tool:git", .path = file_path },
    }, &.{
        .{ .role = "zig", .path = tree_path },
    });
    defer original.deinit(a);
    const encoded = try original.canonical(a);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, encoded, .{ .parse_numbers = false });
    defer parsed.deinit();
    try controller.local_consumer_custody.Fixture.recaptureDocument(a, io, parsed.value);
    const digest_hex = std.fmt.bytesToHex(controller.records.fileIdentity(encoded), .lower);
    const digest = try core.contracts.parseSha256(&digest_hex);
    try controller.local_consumer_custody.Fixture.requireBuildStartDigest(encoded, digest);
    try controller.local_consumer_custody.Fixture.requireBootInputsDigest(encoded, digest);
    var other_digest = digest;
    other_digest[0] ^= 1;
    try std.testing.expectError(
        error.BuildStartDigestMismatch,
        controller.local_consumer_custody.Fixture.requireBuildStartDigest(encoded, other_digest),
    );
    try std.testing.expectError(
        error.BootInputsDigestMismatch,
        controller.local_consumer_custody.Fixture.requireBootInputsDigest(encoded, other_digest),
    );

    var allowed: std.StringHashMap(void) = .init(a);
    defer allowed.deinit();
    try allowed.put("tool:git", {});
    try controller.local_consumer_custody.Fixture.exactRoleSet(&allowed, parsed.value.object.get("files").?);
    var unexpected = std.json.Value{ .object = .empty };
    try unexpected.object.put(a, "tool:other", .null);
    try std.testing.expectError(
        error.UnexpectedInputRole,
        controller.local_consumer_custody.Fixture.exactRoleSet(&allowed, unexpected),
    );
    var substituted = std.json.Value{ .object = .empty };
    var substituted_file = std.json.Value{ .object = .empty };
    try substituted_file.object.put(a, "path", .{ .string = "/untrusted/qemu" });
    try substituted.object.put(a, "qemu", substituted_file);
    try std.testing.expectError(
        error.UnexpectedInputPath,
        controller.local_consumer_custody.Fixture.fixedRolePath(a, substituted, "qemu", fixture_path, "bin/qemu-system-x86_64"),
    );
    var native_paths = std.json.Value{ .object = .empty };
    for ([_]struct { role: []const u8, relative: []const u8 }{
        .{ .role = "command-supervisor", .relative = "controller/bin/uk-wamr-native-ci" },
        .{ .role = "local_boot_tool", .relative = "compute/local-boot-tools/bin/uk-hyperv-local-boot" },
        .{ .role = "log_validator", .relative = "compute/tools/bin/uk-wamr-log-validate" },
    }) |item| {
        var entry = std.json.Value{ .object = .empty };
        try entry.object.put(a, "path", .{ .string = try std.fs.path.join(a, &.{ fixture_path, item.relative }) });
        try native_paths.object.put(a, item.role, entry);
        try controller.local_consumer_custody.Fixture.fixedRolePath(a, native_paths, item.role, fixture_path, item.relative);
    }
    try std.testing.expect(try controller.local_consumer_custody.Fixture.producer(a, fixture_path, native_paths));
    native_paths.object.getPtr("command-supervisor").?.object.getPtr("path").?.* =
        .{ .string = try std.fs.path.join(a, &.{ fixture_path, "compute/supervisor/bin/wamr-ci-supervisor" }) };
    try std.testing.expect(!try controller.local_consumer_custody.Fixture.producer(a, fixture_path, native_paths));
    native_paths.object.getPtr("command-supervisor").?.object.getPtr("path").?.* = .{ .string = "/unrecorded/controller" };
    try std.testing.expectError(error.UnexpectedInputPath, controller.local_consumer_custody.Fixture.producer(a, fixture_path, native_paths));
    const changed = try root.openFile(io, "input", .{ .mode = .write_only });
    try changed.writePositionalAll(io, "modified", 0);
    try changed.sync(io);
    changed.close(io);
    try std.testing.expectError(
        error.RecordedCustodyChanged,
        controller.local_consumer_custody.Fixture.recaptureDocument(a, io, parsed.value),
    );
}

test "local consumer custody rejects non-stdlib python tree path" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const python = try std.Io.Dir.realPathFileAbsoluteAlloc(io, options.python_executable, a);
    var files_map = std.json.Value{ .object = .empty };
    var python_record = std.json.Value{ .object = .empty };
    try python_record.object.put(a, "path", .{ .string = python });
    try files_map.object.put(a, "tool:python3", python_record);
    var tree_map = std.json.Value{ .object = .empty };
    var stdlib_record = std.json.Value{ .object = .empty };
    try stdlib_record.object.put(a, "path", .{ .string = "/not-the-recorded-python-stdlib" });
    try tree_map.object.put(a, "python-stdlib", stdlib_record);
    try std.testing.expectError(
        error.UnexpectedInputPath,
        controller.local_consumer_custody.Fixture.requirePythonStdlibTree(
            a,
            io,
            options.repository_root,
            files_map,
            tree_map,
        ),
    );
}

test "imported validator retains runtime paths after the source buffer is released" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const path = try std.Io.Dir.realPathFileAbsoluteAlloc(io, options.python_executable, a);
    const identity = try controller.custody_files.readFile(io, path, 64 * 1024 * 1024, false);
    const encoded = try std.json.Stringify.valueAlloc(a, .{
        .path = path,
        .sha256 = identity.sha256,
        .metadata = identity.metadata,
    }, .{});
    var parsed = try std.json.parseFromSlice(std.json.Value, a, encoded, .{ .parse_numbers = false });
    defer parsed.deinit();
    var file_records = std.json.Value{ .object = .empty };
    try file_records.object.put(a, try a.print("runtime:{s}", .{path}), parsed.value);
    var consumer = std.json.Value{ .object = .empty };
    try consumer.object.put(a, "files", file_records);
    var start = std.json.Value{ .object = .empty };
    try start.object.put(a, "consumer_inputs", consumer);
    try controller.import_validator_build.Fixture.runtimePathRemainsPinned(
        std.testing.allocator,
        io,
        start,
        path,
    );
}

test "CLI accepts only closed arguments and no caller-selected profile" {
    const cli = controller.cli;
    const build = try cli.parse(&.{ "uk-wamr-native-ci", "build", "--wamr-source", "/wamr", "--runtime", "/runtime" });
    try std.testing.expectEqual(cli.Action.build, build.action);
    try std.testing.expectEqualStrings("/wamr", build.wamr_source.?);
    try std.testing.expectEqual(cli.Action.@"--identity", (try cli.parse(&.{ "uk-wamr-native-ci", "--identity" })).action);
    try std.testing.expectEqual(cli.Action.describe, (try cli.parse(&.{ "uk-wamr-native-ci", "describe", "--output", "json-v1" })).action);
    const source_closure = try cli.parse(&.{ "uk-wamr-native-ci", "supervisor-source-closure", "--git", "/usr/bin/git", "--output", "sha256-v1" });
    try std.testing.expectEqual(cli.Action.@"supervisor-source-closure", source_closure.action);
    try std.testing.expectEqualStrings("/usr/bin/git", source_closure.git.?);
    try std.testing.expectEqual(cli.Action.boot, (try cli.parse(&.{ "uk-wamr-native-ci", "boot", "--runtime", "/runtime" })).action);
    try std.testing.expectEqual(cli.Action.diagnostics, (try cli.parse(&.{ "uk-wamr-native-ci", "diagnostics", "--runtime", "/runtime" })).action);
    const local_records = try cli.parse(&.{ "uk-wamr-native-ci", "records", "--output", "handoff-v1", "--runtime", "/runtime" });
    try std.testing.expectEqual(cli.Action.records, local_records.action);
    try std.testing.expectEqualStrings("/runtime", local_records.runtime.?);
    const imported_records = try cli.parse(&.{ "uk-wamr-native-ci", "records", "--stage-root", "/stage", "--transport", "trusted-inner-zip", "--output", "handoff-v1" });
    try std.testing.expectEqual(cli.Action.records, imported_records.action);
    try std.testing.expectEqualStrings("/stage", imported_records.stage_root.?);
    const empty_digest = std.fmt.bytesToHex(controller.records.fileIdentity("{}\n"), .lower);
    const local_custody = try cli.parse(&.{
        "uk-wamr-native-ci",             "local-consumer-custody", "--runtime",                     "/runtime",
        "--expected-build-start-sha256", &empty_digest,            "--expected-boot-inputs-sha256", &empty_digest,
    });
    try std.testing.expectEqual(cli.Action.@"local-consumer-custody", local_custody.action);
    try std.testing.expectEqualStrings("/runtime", local_custody.runtime.?);
    try std.testing.expectEqualDeep(
        try core.contracts.parseSha256(&empty_digest),
        local_custody.expected_build_start_sha256.?,
    );
    try std.testing.expectEqualDeep(
        try core.contracts.parseSha256(&empty_digest),
        local_custody.expected_boot_inputs_sha256.?,
    );
    const inspection = try cli.parse(&.{ "uk-wamr-native-ci", "handoff-inspect", "--output", "/private/inspection", "--runtime", "/runtime" });
    try std.testing.expectEqual(cli.Action.@"handoff-inspect", inspection.action);
    try std.testing.expectEqualStrings("/runtime", inspection.runtime.?);
    try std.testing.expectEqualStrings("/private/inspection", inspection.output.?);
    const validator_build = try cli.parse(&.{ "uk-wamr-native-ci", "public-validator-build", "--output", "/private/validator", "--runtime", "/runtime" });
    try std.testing.expectEqual(cli.Action.@"public-validator-build", validator_build.action);
    try std.testing.expectEqualStrings("/runtime", validator_build.runtime.?);
    const local_revalidation = try cli.parse(&.{ "uk-wamr-native-ci", "local-handoff-revalidation", "--runtime", "/runtime", "--output", "/private/revalidation" });
    try std.testing.expectEqual(cli.Action.@"local-handoff-revalidation", local_revalidation.action);
    try std.testing.expectEqualStrings("/private/validator", validator_build.output.?);
    const imported_validator = try cli.parse(&.{ "uk-wamr-native-ci", "import-validator-build", "--output", "/private/validator", "--stage-root", "/stage" });
    try std.testing.expectEqual(cli.Action.@"import-validator-build", imported_validator.action);
    try std.testing.expectEqualStrings("/stage", imported_validator.stage_root.?);
    try std.testing.expectEqualStrings("/private/validator", imported_validator.output.?);
    const revalidation = try cli.parse(&.{
        "uk-wamr-native-ci", "import-native-revalidation", "--output", "/private/revalidated", "--stage-root", "/stage",
    });
    try std.testing.expectEqual(cli.Action.@"import-native-revalidation", revalidation.action);
    const portable_import = try cli.parse(&.{
        "uk-wamr-native-ci", "import-handoff-revalidation", "--stage-root", "/stage",
        "--git",             "/local/git",                  "--supervisor", "/local/controller",
        "--validator",       "/local/validator",            "--output",     "/private/revalidated",
    });
    try std.testing.expectEqual(cli.Action.@"import-handoff-revalidation", portable_import.action);
    try std.testing.expectEqualStrings("/stage", revalidation.stage_root.?);
    try std.testing.expectEqualStrings("/private/revalidated", revalidation.output.?);
    const imported_identity = try cli.parse(&.{
        "uk-wamr-native-ci", "supervisor-import-identity", "--stage-root", "/stage",
        "--supervisor",      "/trusted/supervisor",        "--git",        "/usr/bin/git",
        "--output",          "/private/identity",
    });
    try std.testing.expectEqual(cli.Action.@"supervisor-import-identity", imported_identity.action);
    try std.testing.expectEqualStrings("/stage", imported_identity.stage_root.?);
    try std.testing.expectEqualStrings("/trusted/supervisor", imported_identity.supervisor.?);
    const rejected = [_][]const []const u8{
        &.{"uk-wamr-native-ci"},
        &.{ "uk-wamr-native-ci", "--identity", "--runtime", "/runtime" },
        &.{ "uk-wamr-native-ci", "local-handoff-revalidation", "--runtime", "/runtime" },
        &.{ "uk-wamr-native-ci", "local-handoff-revalidation", "--runtime", "/runtime", "--output", "/private/revalidation", "--validator", "/caller" },
        &.{ "uk-wamr-native-ci", "supervised-command-record", "--record", "/record", "--identities", "/ids", "--stage", "adapter", "--transport", "trusted-inner-zip", "--profile", "tiny-aot-two-boot" },
        &.{ "uk-wamr-native-ci", "handoff-inspect", "--runtime", "/runtime" },
        &.{ "uk-wamr-native-ci", "handoff-inspect", "--runtime", "/runtime", "--output", "/private/../inspection" },
        &.{ "uk-wamr-native-ci", "handoff-inspect", "--runtime", "/runtime", "--output", "/private/inspection", "--profile", "tiny" },
        &.{ "uk-wamr-native-ci", "handoff-inspect", "--runtime", "/runtime", "--runtime", "/other" },
        &.{ "uk-wamr-native-ci", "handoff-inspect", "--stage-root", "/stage", "--output", "/private/inspection" },
        &.{ "uk-wamr-native-ci", "public-validator-build", "--runtime", "/runtime" },
        &.{ "uk-wamr-native-ci", "public-validator-build", "--output", "/private/validator", "--runtime", "/runtime", "--profile", "tiny" },
        &.{ "uk-wamr-native-ci", "public-validator-build", "--stage-root", "/stage", "--output", "/private/validator" },
        &.{ "uk-wamr-native-ci", "import-validator-build", "--stage-root", "/stage" },
        &.{ "uk-wamr-native-ci", "local-consumer-custody", "--runtime", "/runtime" },
        &.{ "uk-wamr-native-ci", "local-consumer-custody", "--stage-root", "/stage" },
        &.{
            "uk-wamr-native-ci",             "local-consumer-custody", "--runtime",                     "/runtime",
            "--expected-build-start-sha256", "bad",                    "--expected-boot-inputs-sha256", &empty_digest,
        },
        &.{ "uk-wamr-native-ci", "local-consumer-custody", "--runtime", "/runtime", "--output", "/result" },
        &.{ "uk-wamr-native-ci", "local-consumer-custody", "--runtime", "/runtime/../other" },
        &.{ "uk-wamr-native-ci", "import-validator-build", "--runtime", "/runtime", "--output", "/private/validator" },
        &.{ "uk-wamr-native-ci", "import-validator-build", "--stage-root", "/stage", "--output", "/stage/../validator" },
        &.{ "uk-wamr-native-ci", "import-validator-build", "--stage-root", "/stage", "--output", "/private/validator", "--zig", "/arbitrary/zig" },
        &.{ "uk-wamr-native-ci", "import-validator-build", "--stage-root", "/stage", "--stage-root", "/another" },
        &.{ "uk-wamr-native-ci", "import-native-revalidation", "--stage-root", "/stage" },
        &.{ "uk-wamr-native-ci", "import-native-revalidation", "--runtime", "/runtime", "--output", "/private/revalidated" },
        &.{ "uk-wamr-native-ci", "import-native-revalidation", "--stage-root", "/stage", "--output", "/private/../revalidated" },
        &.{ "uk-wamr-native-ci", "import-native-revalidation", "--stage-root", "/stage", "--output", "/private/revalidated", "--validator", "/untrusted/validator" },
        &.{ "uk-wamr-native-ci", "import-handoff-revalidation", "--stage-root", "/stage", "--git", "/local/git", "--supervisor", "/local/controller", "--output", "/private/revalidated" },
        &.{ "uk-wamr-native-ci", "import-handoff-revalidation", "--stage-root", "/stage", "--git", "/local/git", "--supervisor", "/local/controller", "--validator", "/local/validator", "--output", "/private/../revalidated" },
        &.{ "uk-wamr-native-ci", "import-handoff-revalidation", "--runtime", "/runtime", "--git", "/local/git", "--supervisor", "/local/controller", "--validator", "/local/validator", "--output", "/private/revalidated" },
        &.{ "uk-wamr-native-ci", "supervisor-import-identity", "--stage-root", "/stage", "--supervisor", "/trusted/supervisor", "--git", "/usr/bin/git" },
        &.{ "uk-wamr-native-ci", "supervisor-import-identity", "--stage-root", "/stage", "--supervisor", "/trusted/supervisor", "--git", "/usr/bin/git", "--output", "/stage/../identity" },
        &.{ "uk-wamr-native-ci", "supervisor-import-identity", "--stage-root", "/stage", "--supervisor", "/trusted/supervisor", "--git", "/usr/bin/git", "--output", "/private/identity", "--profile", "tiny" },
        &.{ "uk-wamr-native-ci", "supervisor-import-identity", "--stage-root", "/stage", "--supervisor", "/trusted/supervisor", "--git", "/usr/bin/git", "--git", "/another" },
        &.{ "uk-wamr-native-ci", "supervisor-import-identity", "--runtime", "/runtime", "--supervisor", "/trusted/supervisor", "--git", "/usr/bin/git", "--output", "/private/identity" },
        &.{ "uk-wamr-native-ci", "records", "--runtime", "/runtime" },
        &.{ "uk-wamr-native-ci", "records", "--runtime", "/runtime", "--transport", "trusted-inner-zip", "--output", "handoff-v1" },
        &.{ "uk-wamr-native-ci", "records", "--stage-root", "/stage", "--output", "handoff-v1" },
        &.{ "uk-wamr-native-ci", "records", "--runtime", "/runtime", "--stage-root", "/stage", "--output", "handoff-v1" },
        &.{ "uk-wamr-native-ci", "records", "--stage-root", "/stage", "--transport", "producer-direct", "--output", "handoff-v1" },
        &.{ "uk-wamr-native-ci", "records", "--stage-root", "/stage", "--transport", "trusted-inner-zip", "--output", "json-v1" },
        &.{ "uk-wamr-native-ci", "records", "--runtime", "/root/../runtime", "--output", "handoff-v1" },
        &.{ "uk-wamr-native-ci", "describe" },
        &.{ "uk-wamr-native-ci", "describe", "--output", "text" },
        &.{ "uk-wamr-native-ci", "supervisor-source-closure" },
        &.{ "uk-wamr-native-ci", "supervisor-source-closure", "--output", "sha256-v1" },
        &.{ "uk-wamr-native-ci", "supervisor-source-closure", "--git", "git", "--output", "sha256-v1" },
        &.{ "uk-wamr-native-ci", "supervisor-source-closure", "--git", "/usr/bin/git" },
        &.{ "uk-wamr-native-ci", "supervisor-source-closure", "--output", "json-v1" },
        &.{ "uk-wamr-native-ci", "supervisor-source-closure", "--output", "sha256-v1", "--git", "/usr/bin/git", "--runtime", "/runtime" },
        &.{ "uk-wamr-native-ci", "boot", "--runtime", "/runtime", "--wamr-source", "/wamr" },
        &.{ "uk-wamr-native-ci", "build", "--runtime", "/runtime" },
        &.{ "uk-wamr-native-ci", "build", "--runtime", "/runtime", "--wamr-source", "../wamr" },
        &.{ "uk-wamr-native-ci", "boot", "--runtime", "/runtime/../other" },
        &.{ "uk-wamr-native-ci", "boot", "--runtime", "/runtime", "--profile", "tiny" },
        &.{ "uk-wamr-native-ci", "boot", "--runtime", "/runtime", "--runtime", "/other" },
        &.{ "uk-wamr-native-ci", "boot", "--runtime", "/runtime", "--output", "json-v1" },
    };
    for (rejected) |argv| try std.testing.expectError(error.InvalidUsage, cli.parse(argv));
}

test "import identity source allowlist matches the historical supervisor source set" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const script =
        \\import importlib.util, json, sys
        \\spec=importlib.util.spec_from_file_location("ci",sys.argv[1])
        \\ci=importlib.util.module_from_spec(spec); spec.loader.exec_module(ci)
        \\sys.stdout.write(json.dumps({
        \\    "names": ci.SUPERVISOR_SOURCE_FILES,
        \\    "closure": ci.supervisor_source_map()["content_closure_sha256"],
        \\}))
    ;
    const witness_path = try std.fs.path.join(a, &.{ options.repository_root, "support/build/wamr-native-ci/run.py" });
    const output = try std.process.run(a, std.testing.io, .{
        .argv = &.{ options.python_executable, "-B", "-c", script, witness_path },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(8192),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    const witness_json = try std.json.parseFromSliceLeaky(std.json.Value, a, output.stdout, .{});
    try std.testing.expect(witness_json == .object);
    const names = witness_json.object.get("names").?;
    try std.testing.expect(names == .array);
    var selected = std.json.Value{ .object = .empty };
    var modified = std.json.Value{ .object = .empty };
    for (names.array.items, 0..) |entry, index| {
        try std.testing.expect(entry == .string);
        try selected.object.put(a, entry.string, .null);
        try modified.object.put(a, if (index == 0) "support/unexpected.zig" else entry.string, .null);
    }
    try controller.import_supervisor_identity.validateSourceNames(selected);
    try std.testing.expectError(error.InvalidImportIdentity, controller.import_supervisor_identity.validateSourceNames(modified));
    var native = std.json.Value{ .object = .empty };
    for (controller.source_custody.closure) |entry|
        try native.object.put(a, entry.name, .null);
    try controller.import_supervisor_identity.validateSourceNames(native);
    const closure = try controller.import_supervisor_identity.supervisorSourceContentClosure(a, std.testing.io, options.repository_root, options.git_executable);
    try std.testing.expectEqualStrings(witness_json.object.get("closure").?.string, closure[0..]);
}

test "native import identity matches Python guarded source map under supervision" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    var names: std.ArrayList([]const u8) = .empty;
    for (controller.source_custody.closure) |entry| try names.append(a, entry.name);
    const script =
        \\import hashlib, importlib.util, json, pathlib, sys
        \\spec=importlib.util.spec_from_file_location("ci",sys.argv[1])
        \\ci=importlib.util.module_from_spec(spec); spec.loader.exec_module(ci)
        \\records={}
        \\for name in json.loads(sys.argv[2]):
        \\    raw=pathlib.Path(name).read_bytes()
        \\    records[name]={"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"metadata":[]}
        \\closure=ci.guarded_record_map("uk.wamr.command-supervisor-source-v1", records)
        \\sys.stdout.buffer.write(ci.canonical_json({
        \\    "protocol":"uk.wamr.command-supervisor/1 process-command/1",
        \\    "schema":"uk.wamr.command-supervisor-identity",
        \\    "source_content_closure_sha256":closure["content_closure_sha256"],
        \\    "version":1}))
    ;
    const oracle = try std.process.run(a, io, .{
        .argv = &.{
            options.python_executable,                                                                     "-B",                                                   "-c", script,
            try std.fs.path.join(a, &.{ options.repository_root, "support/build/wamr-native-ci/run.py" }), try std.json.Stringify.valueAlloc(a, names.items, .{}),
        },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, oracle.term);
    try std.testing.expectEqualStrings("", oracle.stderr);

    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("native-import-identity-{d}", .{std.os.linux.getpid()});
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("native identity fixture cleanup failed");
    const work = try parent.openDir(io, name, .{ .iterate = true });
    defer work.close(io);
    for ([_][]const u8{ "private", "evidence" }) |entry| try work.createDir(io, entry, .fromMode(0o700));
    const private = try work.openDir(io, "private", .{ .iterate = true });
    defer private.close(io);
    const evidence = try work.openDir(io, "evidence", .{ .iterate = true });
    defer evidence.close(io);
    const outcome = try controller.command_adapter.execute(a, io, .{
        .roots = .{
            .source_root = options.repository_root,
            .work = try std.fs.path.join(a, &.{ options.fixture_root, name }),
            .runtime = options.fixture_root,
            .zig = "",
            .producer = "",
            .supervisor = options.host_controller_cli,
            .package_tool = "",
            .validator = "",
            .tools = @as([controller.input_custody.host_tools.len][]const u8, @splat("")),
        },
        .stage = .@"supervisor-import-identity",
        .private_dir = private,
        .evidence_dir = evidence,
        .capture_stdout = true,
    });
    try std.testing.expect(outcome.accepted and !outcome.poisoned);
    try std.testing.expectEqual(@as(usize, 0), outcome.stderr_bytes);
    try std.testing.expectEqualStrings(oracle.stdout, outcome.stdout);
    const command = try evidence.readFileAlloc(io, "command-supervisor-import-identity.json", a, .limited(controller.records.max_record_bytes));
    _ = try controller.accepted_run.validateCommandBinding(a, command, .@"supervisor-import-identity", .trusted_inner_zip);
}

fn writeRelativeFixtureFile(io: std.Io, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    if (std.fs.path.dirname(name)) |parent| try dir.createDirPath(io, parent);
    try writeFixtureFile(io, dir, name, bytes);
}

fn writeSupervisorSourceFixture(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, skip: ?[]const u8) !void {
    for (controller.import_supervisor_identity.historical_supervisor_sources) |relative| {
        if (skip) |skipped| if (std.mem.eql(u8, relative, skipped)) continue;
        const bytes = try allocator.print("fixture:{s}\n", .{relative});
        defer allocator.free(bytes);
        try writeRelativeFixtureFile(io, dir, relative, bytes);
    }
}

fn appendRelativeFixtureFile(io: std.Io, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try dir.openFile(io, name, .{ .mode = .write_only });
    defer file.close(io);
    const size = (try file.stat(io)).size;
    try file.writePositionalAll(io, bytes, size);
}

test "supervisor source closure requires tracked clean Git blobs" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const base_path = try allocator.dupe(u8, options.fixture_root);
    defer allocator.free(base_path);
    const base = try std.Io.Dir.openDirAbsolute(io, base_path, .{ .iterate = true });
    defer base.close(io);
    const name = try allocator.print("supervisor-source-fixture-{d}", .{std.os.linux.getpid()});
    defer allocator.free(name);
    try base.createDir(io, name, .fromMode(0o700));
    defer base.deleteTree(io, name) catch @panic("supervisor source fixture cleanup failed");
    const repo = try base.openDir(io, name, .{ .iterate = true });
    defer repo.close(io);
    const path = try std.fs.path.join(allocator, &.{ base_path, name });
    defer allocator.free(path);
    try writeSupervisorSourceFixture(allocator, io, repo, null);
    try fixtureGit(allocator, path, &.{ options.git_executable, "init", "-q" });
    try fixtureGit(allocator, path, &.{ options.git_executable, "add", "-A" });
    try fixtureGit(allocator, path, &.{
        options.git_executable, "-c",  "user.name=Fixture",         "-c", "user.email=fixture@example.invalid",
        "commit",               "-qm", "supervisor source fixture",
    });
    _ = try controller.import_supervisor_identity.supervisorSourceContentClosure(allocator, io, path, options.git_executable);
    try appendRelativeFixtureFile(
        io,
        repo,
        "support/build/wamr-native-ci/supervisor.zig",
        "dirty\n",
    );
    try std.testing.expectError(error.SourceChanged, controller.import_supervisor_identity.supervisorSourceContentClosure(
        allocator,
        io,
        path,
        options.git_executable,
    ));

    const untracked_name = try allocator.print("supervisor-source-untracked-{d}", .{std.os.linux.getpid()});
    defer allocator.free(untracked_name);
    try base.createDir(io, untracked_name, .fromMode(0o700));
    defer base.deleteTree(io, untracked_name) catch @panic("supervisor untracked fixture cleanup failed");
    const untracked_repo = try base.openDir(io, untracked_name, .{ .iterate = true });
    defer untracked_repo.close(io);
    const untracked_path = try std.fs.path.join(allocator, &.{ base_path, untracked_name });
    defer allocator.free(untracked_path);
    try writeSupervisorSourceFixture(allocator, io, untracked_repo, "support/build/wamr-native-ci/supervisor.zig");
    try fixtureGit(allocator, untracked_path, &.{ options.git_executable, "init", "-q" });
    try fixtureGit(allocator, untracked_path, &.{ options.git_executable, "add", "-A" });
    try fixtureGit(allocator, untracked_path, &.{
        options.git_executable, "-c",  "user.name=Fixture",         "-c", "user.email=fixture@example.invalid",
        "commit",               "-qm", "supervisor source fixture",
    });
    try writeRelativeFixtureFile(io, untracked_repo, "support/build/wamr-native-ci/supervisor.zig", "untracked\n");
    try std.testing.expectError(error.UntrackedManifest, controller.import_supervisor_identity.supervisorSourceContentClosure(
        allocator,
        io,
        untracked_path,
        options.git_executable,
    ));
    try untracked_repo.deleteFile(io, "support/build/wamr-native-ci/supervisor.zig");
    try std.testing.expectError(error.UntrackedManifest, controller.import_supervisor_identity.supervisorSourceContentClosure(
        allocator,
        io,
        untracked_path,
        options.git_executable,
    ));

    const missing_name = try allocator.print("supervisor-source-missing-{d}", .{std.os.linux.getpid()});
    defer allocator.free(missing_name);
    try base.createDir(io, missing_name, .fromMode(0o700));
    defer base.deleteTree(io, missing_name) catch @panic("supervisor missing fixture cleanup failed");
    const missing_repo = try base.openDir(io, missing_name, .{ .iterate = true });
    defer missing_repo.close(io);
    const missing_path = try std.fs.path.join(allocator, &.{ base_path, missing_name });
    defer allocator.free(missing_path);
    try writeSupervisorSourceFixture(allocator, io, missing_repo, null);
    try fixtureGit(allocator, missing_path, &.{ options.git_executable, "init", "-q" });
    try fixtureGit(allocator, missing_path, &.{ options.git_executable, "add", "-A" });
    try fixtureGit(allocator, missing_path, &.{
        options.git_executable, "-c",  "user.name=Fixture",         "-c", "user.email=fixture@example.invalid",
        "commit",               "-qm", "supervisor source fixture",
    });
    try missing_repo.deleteFile(io, "support/build/wamr-native-ci/supervisor.zig");
    try std.testing.expectError(error.FileNotFound, controller.import_supervisor_identity.supervisorSourceContentClosure(
        allocator,
        io,
        missing_path,
        options.git_executable,
    ));
}

test "canonical bytes and domain-separated file versus record identity" {
    const allocator = std.testing.allocator;
    const compact = try controller.records.canonicalAlloc(allocator, "{\"z\":18446744073709551615,\"a\":\"é\",\"list\":[true,null,-9223372036854775808]}");
    defer allocator.free(compact);
    try std.testing.expectEqualStrings("{\"a\":\"é\",\"list\":[true,null,-9223372036854775808],\"z\":18446744073709551615}\n", compact);
    const record = try controller.records.identity(allocator, "{\"z\":1,\"a\":2}");
    const hex = std.fmt.bytesToHex(record, .lower);
    try std.testing.expectEqualStrings("c2985c5ba6f7d2a55e768f92490ca09388e95bc4cccb9fdf11b15f4d42f93e73", &hex);
    const file = controller.records.fileIdentity("{\"a\":2,\"z\":1}\n");
    try std.testing.expect(!std.mem.eql(u8, &record, &file));
    try std.testing.expectError(error.IntegerOverflow, controller.records.identity(allocator, "{\"value\":18446744073709551616}"));
    try std.testing.expectError(error.DuplicateField, controller.records.identity(allocator, "{\"a\":1,\"a\":2}"));
}

test "historical v2 supervised bindings use the closed imported producer contract" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const script =
        \\import copy, importlib.util, sys
        \\s=importlib.util.spec_from_file_location("witness",sys.argv[1])
        \\m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
        \\e=m.Evidence()
        \\stages=("adapter","local-boot-tool","fixtures","prepare","config","native-image","package","raw-x2apic","raw-legacy-apic","finalize-qcow2","qcow2-x2apic","qcow2-legacy-apic","derive-fixed-vhd","vpc-x2apic","vpc-legacy-apic","inspect","log-validator-x2apic","log-validator-legacy")
        \\records={name:e.supervised_binding(name)[0] for name in stages}
        \\for record in records.values():
        \\    request=record["supervisor"]["request"]
        \\    request["argv"]=[m.ci.command_literal("-Doptimize=ReleaseSafe") if item==m.ci.command_literal("-Doptimize=safe") else item for item in request["argv"]]
        \\    e.rehash_supervised_binding(record)
        \\tampered=copy.deepcopy(records["adapter"]); tampered["supervisor"]["request"]["argv"][1]={"kind":"literal","value":"--arbitrary"}
        \\records["tampered"]=e.rehash_supervised_binding(tampered)
        \\sys.stdout.buffer.write(m.ci.canonical_json(records))
    ;
    const witness = try std.fs.path.join(a, &.{ options.repository_root, "support/build/wamr-native-ci/tests/test_adapter.py" });
    const response = try std.process.run(a, std.testing.io, .{
        .argv = &.{ options.python_executable, "-B", "-c", script, witness },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(4096),
    });
    if (response.term != .exited or response.term.exited != 0)
        std.debug.print("historical binding witness: {s}\n", .{response.stderr});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, response.term);
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, a, response.stdout, .{ .duplicate_field_behavior = .@"error" });
    const values = parsed.object;
    var verified: usize = 0;
    for (values.keys(), values.values()) |name, value| {
        const bytes = try fixtureCanonical(a, value);
        if (std.mem.eql(u8, name, "tampered")) {
            try std.testing.expectError(error.InvalidCommand, controller.accepted_run.validateCommandBinding(a, bytes, .adapter, .trusted_inner_zip));
            continue;
        }
        const stage = std.meta.stringToEnum(controller.command_plan.Stage, name) orelse return error.UnexpectedStage;
        const observed = try controller.accepted_run.validateCommandBinding(a, bytes, stage, .trusted_inner_zip);
        try std.testing.expectEqual(stage, observed.stage);
        if (stage == .adapter or stage == .@"local-boot-tool" or stage == .fixtures or controller.command_plan.isValidator(stage))
            try std.testing.expectError(error.InvalidCommand, controller.accepted_run.validateCommandBinding(a, bytes, stage, .local_runtime));
        verified += 1;
    }
    try std.testing.expectEqual(@as(usize, 18), verified);
}

test "public validator cache flag is historical import only" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const script =
        \\import copy, importlib.util, sys
        \\s=importlib.util.spec_from_file_location("witness",sys.argv[1])
        \\m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
        \\e=m.Evidence(); current=e.supervised_binding("public-validator-build")[0]
        \\q=current["supervisor"]["request"]; q["argv"]=q["argv"][2:]
        \\q["native_executable"]=copy.deepcopy(q["command_executable"])
        \\q["timeout_ns"]=1800*1000000000
        \\q["issued_ns"]=q["primary_deadline_ns"]-q["timeout_ns"]
        \\current["supervisor"]["result"]["command"]["executable"]=q["native_executable"]["identity"]
        \\e.rehash_supervised_binding(current)
        \\old=copy.deepcopy(current); q=old["supervisor"]["request"]
        \\i=q["argv"].index(m.ci.command_literal("--prefix"))
        \\q["argv"][i:i]=[m.ci.command_literal("--global-cache-dir"),m.ci.command_path("work","global-cache")]
        \\q["argv"]=[m.ci.command_literal("-Doptimize=ReleaseSafe") if item==m.ci.command_literal("-Doptimize=safe") else item for item in q["argv"]]
        \\e.rehash_supervised_binding(old)
        \\bad=copy.deepcopy(old); q=bad["supervisor"]["request"]
        \\i=q["argv"].index(m.ci.command_literal("--global-cache-dir"))
        \\q["argv"][i+1]=m.ci.command_path("work","unbound-cache")
        \\e.rehash_supervised_binding(bad)
        \\sys.stdout.buffer.write(m.ci.canonical_json({"current":current,"historical":old,"tampered":bad}))
    ;
    const witness = try std.fs.path.join(a, &.{ options.repository_root, "support/build/wamr-native-ci/tests/test_adapter.py" });
    const response = try std.process.run(a, std.testing.io, .{
        .argv = &.{ options.python_executable, "-B", "-c", script, witness },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(4096),
    });
    if (response.term != .exited or response.term.exited != 0)
        std.debug.print("public validator cache witness: {s}\n", .{response.stderr});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, response.term);
    const values = try std.json.parseFromSliceLeaky(std.json.Value, a, response.stdout, .{ .duplicate_field_behavior = .@"error" });
    const current = try fixtureCanonical(a, values.object.get("current").?);
    _ = try controller.accepted_run.validateCommandBinding(a, current, .@"public-validator-build", .local_runtime);
    const historical = try fixtureCanonical(a, values.object.get("historical").?);
    _ = try controller.accepted_run.validateCommandBinding(a, historical, .@"public-validator-build", .trusted_inner_zip);
    try std.testing.expectError(error.InvalidCommand, controller.accepted_run.validateCommandBinding(a, historical, .@"public-validator-build", .local_runtime));
    const tampered = try fixtureCanonical(a, values.object.get("tampered").?);
    try std.testing.expectError(error.InvalidCommand, controller.accepted_run.validateCommandBinding(a, tampered, .@"public-validator-build", .trusted_inner_zip));
}

test "legacy handoff inspect command fixture matches Python strictness" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const script =
        \\import copy, importlib.util, sys
        \\s=importlib.util.spec_from_file_location("witness",sys.argv[1])
        \\m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
        \\e=m.Evidence()
        \\profile="tiny-aot-two-boot"
        \\stage="handoff-inspect-legacy"
        \\transport="producer_direct"
        \\record,identities=e.supervised_binding(stage,profile=profile)
        \\def check(record):
        \\    m.ci.validate_supervised_command_binding(record,stage,identities,transport_context=transport,profile=profile)
        \\check(record)
        \\mutations={}
        \\def refuse(name, changed, rehash=True):
        \\    if rehash:
        \\        e.rehash_supervised_binding(changed)
        \\    try:
        \\        check(changed)
        \\    except m.ci.Refusal:
        \\        mutations[name]=changed
        \\    else:
        \\        raise AssertionError(name+" admitted")
        \\changed=copy.deepcopy(record)
        \\changed["supervisor"]["request"]["retained_executables"]=[]
        \\changed["supervisor"]["result"]["command"]["retained_executables"]=[]
        \\refuse("retained-empty", changed)
        \\changed=copy.deepcopy(record)
        \\changed["sha256"]="0"*64
        \\refuse("record-empty-sha", changed, rehash=False)
        \\changed=copy.deepcopy(record)
        \\changed["supervisor"]["result"]["command"]["output"]["combined_sha256"]="0"*64
        \\refuse("output-empty-sha", changed)
        \\changed=copy.deepcopy(record)
        \\non_empty="1"*64
        \\changed["sha256"]=non_empty
        \\changed["supervisor"]["result"]["command"]["output"]["combined_sha256"]=non_empty
        \\refuse("zero-bytes-non-empty-hash", changed)
        \\changed=copy.deepcopy(record)
        \\changed["supervisor"]["request"]["supervisor"]["identity"]["mode"]=65536
        \\refuse("identity-mode-u16", changed)
        \\sys.stdout.buffer.write(m.ci.canonical_json({"accepted":record,"mutations":mutations}))
    ;
    const witness = try std.fs.path.join(a, &.{ options.repository_root, "support/build/wamr-native-ci/tests/test_adapter.py" });
    const response = try std.process.run(a, std.testing.io, .{
        .argv = &.{ options.python_executable, "-B", "-c", script, witness },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(2 * 1024 * 1024),
        .stderr_limit = .limited(4096),
    });
    if (response.term != .exited or response.term.exited != 0)
        std.debug.print("v1 command witness: {s}\n", .{response.stderr});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, response.term);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, response.stdout, .{ .duplicate_field_behavior = .@"error", .parse_numbers = false });
    defer parsed.deinit();
    const accepted = try fixtureField(parsed.value, "accepted");
    const mutations = try fixtureField(parsed.value, "mutations");
    const checked = try controller.command_validation.validateLegacyV1(
        a,
        accepted,
        .@"handoff-inspect-legacy",
        .local_runtime,
    );
    try std.testing.expectEqual(controller.command_plan.Stage.@"handoff-inspect-legacy", checked.stage);
    var refused_count: usize = 0;
    for (mutations.object.values()) |record| {
        try std.testing.expectError(error.InvalidCommand, controller.command_validation.validateLegacyV1(
            a,
            record,
            .@"handoff-inspect-legacy",
            .local_runtime,
        ));
        refused_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 5), refused_count);
    try std.testing.expectError(error.InvalidCommand, controller.command_validation.validateLegacyV1(
        a,
        accepted,
        .@"handoff-inspect",
        .local_runtime,
    ));
    try std.testing.expectError(error.InvalidCommand, controller.command_validation.validateLegacyV1(
        a,
        accepted,
        .@"handoff-inspect-legacy",
        .trusted_inner_zip,
    ));
}

fn fixtureField(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidFixture;
    return value.object.get(name) orelse error.InvalidFixture;
}

fn canonicalJsonValue(a: std.mem.Allocator, value: std.json.Value) ![]u8 {
    return controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, value, .{}));
}

fn writeCanonicalValue(io: std.Io, dir: std.Io.Dir, name: []const u8, a: std.mem.Allocator, value: std.json.Value) ![]const u8 {
    const raw = try canonicalJsonValue(a, value);
    try writeFixtureFile(io, dir, name, raw);
    return raw;
}

fn expectInvalidLocalPostRun(
    accepted: *controller.accepted_run.AcceptedRun,
    raw: []const u8,
    stage: controller.command_plan.Stage,
) !void {
    _ = controller.accepted_run.validateLocalPostRunCommand(accepted, raw, stage) catch |err| switch (err) {
        error.InvalidContext, error.InvalidCommand, error.InvalidCommandIdentity => return,
        else => return err,
    };
    return error.InvalidRouteAccepted;
}

fn expectInvalidHandoffRun(
    a: std.mem.Allocator,
    io: std.Io,
    accepted: *controller.accepted_run.AcceptedRun,
    output: []const u8,
    legacy: bool,
) !void {
    _ = controller.handoff_inspect.run(a, io, accepted, output, legacy, null) catch |err| switch (err) {
        error.InvalidContext, error.InvalidCommand, error.InvalidCommandIdentity => return,
        else => return err,
    };
    return error.InvalidRouteAccepted;
}

fn legacyHandoffInspectLiveFixture() !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("legacy-handoff-inspect-{d}", .{std.os.linux.getpid()});
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("legacy handoff fixture cleanup failed");
    const fixture_dir = try parent.openDir(io, name, .{ .iterate = true });
    defer fixture_dir.close(io);
    const root = try std.fs.path.join(a, &.{ options.fixture_root, name });
    const output_parent_name = try a.print("{s}-outputs", .{name});
    try parent.createDir(io, output_parent_name, .fromMode(0o700));
    defer parent.deleteTree(io, output_parent_name) catch @panic("legacy handoff output cleanup failed");
    const output_parent = try std.fs.path.join(a, &.{ options.fixture_root, output_parent_name });
    const source = try std.fs.path.join(a, &.{ root, "source" });
    const compute = try std.fs.path.join(a, &.{ root, "compute" });
    try fixture_dir.createDir(io, "source", .fromMode(0o700));
    try fixture_dir.createDir(io, "compute", .fromMode(0o700));
    try fixture_dir.createDir(io, "bin", .fromMode(0o700));
    try fixture_dir.createDir(io, "firmware", .fromMode(0o700));
    const compute_root = try fixture_dir.openDir(io, "compute", .{ .iterate = true });
    defer compute_root.close(io);
    try compute_root.createDir(io, "evidence", .fromMode(0o700));
    try compute_root.createDir(io, "package", .fromMode(0o700));
    try compute_root.createDir(io, "tools", .fromMode(0o700));
    try compute_root.createDir(io, "host-tools", .fromMode(0o700));
    try compute_root.createDir(io, "supervisor", .fromMode(0o700));
    const compute_tools = try compute_root.openDir(io, "tools", .{ .iterate = true });
    defer compute_tools.close(io);
    try compute_tools.createDir(io, "bin", .fromMode(0o700));
    const compute_supervisor = try compute_root.openDir(io, "supervisor", .{ .iterate = true });
    defer compute_supervisor.close(io);
    try compute_supervisor.createDir(io, "bin", .fromMode(0o700));
    try fixture_dir.createDirPath(io, "source/support/apps/wamr-aot/build/artifacts");
    const source_build_path = try std.fs.path.join(a, &.{ source, "support/apps/wamr-aot/build" });
    const source_artifacts_path = try std.fs.path.join(a, &.{ source, "support/apps/wamr-aot/build/artifacts" });
    const source_app_path = try std.fs.path.join(a, &.{ source, "support/apps/wamr-aot" });
    const package_path = try std.fs.path.join(a, &.{ compute, "package" });
    const evidence_path = try std.fs.path.join(a, &.{ compute, "evidence" });
    const tools_bin_path = try std.fs.path.join(a, &.{ compute, "tools/bin" });
    const host_tools_path = try std.fs.path.join(a, &.{ compute, "host-tools" });
    const supervisor_bin_path = try std.fs.path.join(a, &.{ compute, "supervisor/bin" });
    const bin_path = try std.fs.path.join(a, &.{ root, "bin" });
    const firmware_path = try std.fs.path.join(a, &.{ root, "firmware" });
    const source_build = try std.Io.Dir.openDirAbsolute(io, source_build_path, .{ .iterate = true });
    defer source_build.close(io);
    const source_artifacts = try std.Io.Dir.openDirAbsolute(io, source_artifacts_path, .{ .iterate = true });
    defer source_artifacts.close(io);
    const source_app = try std.Io.Dir.openDirAbsolute(io, source_app_path, .{ .iterate = true });
    defer source_app.close(io);
    const compute_package = try std.Io.Dir.openDirAbsolute(io, package_path, .{ .iterate = true });
    defer compute_package.close(io);
    const evidence = try std.Io.Dir.openDirAbsolute(io, evidence_path, .{ .iterate = true });
    defer evidence.close(io);
    const tools_bin = try std.Io.Dir.openDirAbsolute(io, tools_bin_path, .{ .iterate = true });
    defer tools_bin.close(io);
    const host_tools_dir = try std.Io.Dir.openDirAbsolute(io, host_tools_path, .{ .iterate = true });
    defer host_tools_dir.close(io);
    const supervisor_bin = try std.Io.Dir.openDirAbsolute(io, supervisor_bin_path, .{ .iterate = true });
    defer supervisor_bin.close(io);
    const bin = try std.Io.Dir.openDirAbsolute(io, bin_path, .{ .iterate = true });
    defer bin.close(io);
    const firmware = try std.Io.Dir.openDirAbsolute(io, firmware_path, .{ .iterate = true });
    defer firmware.close(io);

    try writeFixtureFile(io, source_build, "wamr_hyperv-x86_64-efi", "efi");
    try writeFixtureFile(io, source_build, "wamr_hyperv-x86_64-efi.dbg", "dbg");
    try writeFixtureFile(io, source_build, "wamr_hyperv-x86_64-efi.bootinfo", "bootinfo");
    try writeFixtureFile(io, source_artifacts, "libwamr-aot.a", "runtime");
    try writeFixtureFile(io, source_artifacts, "wamrc", "compiler");
    try writeFixtureFile(io, source_artifacts, "tiny.wasm", "wasm");
    try writeFixtureFile(io, source_artifacts, "tiny.cwasm", "cwasm");
    try writeFixtureFile(io, source_artifacts, "identity.json", "{}\n");
    try writeFixtureFile(io, source_build, "image-identity.json", "{}\n");
    try writeFixtureFile(io, source_app, ".config", "CONFIG_APP=y\n");
    try writeFixtureFile(io, compute_package, "unikraft.raw", "raw");
    try writeFixtureFile(io, compute_package, "unikraft.vhd", "vhd");
    try writeFixtureFile(io, compute_package, "unikraft-derived.vhd", "vhd");
    try writeFixtureFile(io, firmware, "code.fd", "code");
    try writeFixtureFile(io, firmware, "vars.fd", "vars");
    const package_value = try std.json.parseFromSliceLeaky(std.json.Value, a, "{\"image\":{\"efi\":{\"size\":3}},\"producer_sha256\":\"fixture\"}", .{});
    const package_json = try writeCanonicalValue(io, evidence, "package.json", a, package_value);

    const executable = try std.fs.path.resolve(a, &.{ options.repository_root, options.command_fixture });
    const bound_tool = try std.Io.Dir.realPathFileAbsoluteAlloc(io, "/usr/bin/true", a);
    try copyFixtureExecutable(io, a, executable, tools_bin, "wamr-ci-package");
    var host_tool_paths: [controller.input_custody.host_tools.len][]const u8 = undefined;
    for (controller.input_custody.host_tools, 0..) |tool, i| {
        try copyFixtureExecutable(io, a, bound_tool, host_tools_dir, tool);
        host_tool_paths[i] = try std.fs.path.join(a, &.{ compute, "host-tools", tool });
    }
    try copyFixtureExecutable(io, a, bound_tool, supervisor_bin, "wamr-ci-supervisor");
    try copyFixtureExecutable(io, a, bound_tool, bin, "qemu-system-x86_64");
    const package_tool = try std.fs.path.join(a, &.{ compute, "tools/bin/wamr-ci-package" });
    const supervisor = try std.fs.path.join(a, &.{ compute, "supervisor/bin/wamr-ci-supervisor" });
    const efi = try std.fs.path.join(a, &.{ source, "support/apps/wamr-aot/build/wamr_hyperv-x86_64-efi" });
    const qemu = try std.fs.path.join(a, &.{ root, "bin/qemu-system-x86_64" });
    const ovmf_code = try std.fs.path.join(a, &.{ root, "firmware/code.fd" });
    const ovmf_vars = try std.fs.path.join(a, &.{ root, "firmware/vars.fd" });

    for (controller.profile.modes(.tiny_v1_legacy)) |mode| {
        const boot_name = try a.print("boot-{s}", .{@tagName(mode)});
        try compute_root.createDir(io, boot_name, .fromMode(0o700));
        const boot_dir = try compute_root.openDir(io, boot_name, .{ .iterate = true });
        defer boot_dir.close(io);
        try writeFixtureFile(io, boot_dir, "hyperv-efi-boot.log", "serial\n");
        try writeFixtureFile(io, boot_dir, "request.json", "{}\n");
        try writeFixtureFile(io, boot_dir, "report.json", "{}\n");
        const compute_name = try a.print("{s}-compute.json", .{@tagName(mode)});
        const compute_value = try std.json.parseFromSliceLeaky(std.json.Value, a, "{\"accepted\":true}", .{});
        _ = try writeCanonicalValue(io, evidence, compute_name, a, compute_value);
    }

    var start_bindings: [controller.input_custody.host_tools.len + 1]controller.input_custody.Binding = undefined;
    for (controller.input_custody.host_tools, 0..) |tool, i|
        start_bindings[i] = .{ .role = try a.print("tool:{s}", .{tool}), .path = host_tool_paths[i] };
    start_bindings[controller.input_custody.host_tools.len] = .{ .role = "command-supervisor", .path = supervisor };
    var start_custody = try controller.input_custody.capture(a, io, &start_bindings, &.{});
    defer start_custody.deinit(a);
    const start_custody_raw = try start_custody.canonical(a);
    const consumer_inputs = try std.json.parseFromSliceLeaky(std.json.Value, a, start_custody_raw, .{ .parse_numbers = false });
    const legacy_source = .{
        .revision = "993e4d0d394c08202c0d0c57ea97450a19a4f394",
        .tree = "54f8e118146c78c24e7c802657c6ec62b268a5de",
    };
    var start = std.json.Value{ .object = .empty };
    try start.object.put(a, "source", try std.json.parseFromSliceLeaky(std.json.Value, a, try std.json.Stringify.valueAlloc(a, legacy_source, .{}), .{}));
    try start.object.put(a, "consumer_inputs", consumer_inputs);
    _ = try writeCanonicalValue(io, evidence, "build-start.json", a, start);

    var build = std.json.Value{ .object = .empty };
    try build.object.put(a, "source", try std.json.parseFromSliceLeaky(std.json.Value, a, try std.json.Stringify.valueAlloc(a, legacy_source, .{}), .{}));
    _ = try writeCanonicalValue(io, evidence, "build.json", a, build);

    const boot_bindings = [_]controller.input_custody.Binding{
        .{ .role = "package_tool", .path = package_tool },
        .{ .role = "local_boot_tool", .path = bound_tool },
        .{ .role = "qemu", .path = qemu },
        .{ .role = "ovmf_code", .path = ovmf_code },
        .{ .role = "ovmf_vars", .path = ovmf_vars },
        .{ .role = "efi", .path = efi },
    };
    var boot_custody = try controller.input_custody.capture(a, io, &boot_bindings, &.{});
    defer boot_custody.deinit(a);
    const boot_custody_raw = try boot_custody.canonical(a);
    const boot_inputs = try std.json.parseFromSliceLeaky(std.json.Value, a, boot_custody_raw, .{ .parse_numbers = false });
    _ = try writeCanonicalValue(io, evidence, "boot-inputs.json", a, boot_inputs);

    var records_map = std.json.Value{ .object = .empty };
    for ([_][]const u8{
        "build-start.json",
        "build.json",
        "boot-inputs.json",
        "package.json",
        "raw-x2apic-compute.json",
        "raw-legacy-apic-compute.json",
        "vpc-x2apic-compute.json",
        "vpc-legacy-apic-compute.json",
    }) |record_name| {
        const path = try std.fs.path.join(a, &.{ compute, "evidence", record_name });
        const observed = try controller.custody_files.readFile(io, path, controller.records.max_record_bytes, true);
        try records_map.object.put(a, record_name, .{ .string = try a.dupe(u8, &observed.sha256) });
    }
    var result = std.json.Value{ .object = .empty };
    try result.object.put(a, "schema_version", .{ .integer = 1 });
    try result.object.put(a, "scope", .{ .string = "local_native_compute_only" });
    try result.object.put(a, "passed", .{ .bool = true });
    try result.object.put(a, "hardware_acceptance", .{ .string = "not_established" });
    try result.object.put(a, "cloud_authority", .{ .string = "not_admitted" });
    try result.object.put(a, "benchmark", .{ .string = "not_measured" });
    try result.object.put(a, "workload", .{ .string = "tiny" });
    var modes = std.json.Value{ .array = std.array_list.Managed(std.json.Value).init(a) };
    for (controller.profile.modes(.tiny_v1_legacy)) |mode|
        try modes.array.append(.{ .string = @tagName(mode) });
    try result.object.put(a, "modes", modes);
    try result.object.put(a, "records", records_map);
    _ = try writeCanonicalValue(io, evidence, "result.json", a, result);

    const runtime_dir = try controller.layout.runtime(io, root);
    defer runtime_dir.close(io);
    var accepted = try controller.accepted_run.openAndValidateForHandoffInspectWithSignal(
        a,
        io,
        std.process.Environ.empty,
        &runtime_dir,
        root,
        source,
        null,
    );
    defer accepted.deinit();
    try std.testing.expectEqual(controller.profile.CompatibleRecordSet.tiny_v1_legacy, accepted.compatibility);
    try expectInvalidHandoffRun(a, io, &accepted, try std.fs.path.join(a, &.{ output_parent, "wrong-v1-output" }), false);
    const output = try std.fs.path.join(a, &.{ output_parent, "legacy-output" });
    var inspection = try controller.handoff_inspect.runRetained(a, io, &accepted, output, true, null);
    defer inspection.deinit(io);
    const checked = inspection.command;
    try std.testing.expectEqual(controller.command_plan.Stage.@"handoff-inspect-legacy", checked.stage);
    try std.testing.expectEqual(@as(u64, package_json.len), checked.output_bytes);
    const record_path = try std.fs.path.join(a, &.{ output, "evidence/command-handoff-inspect-legacy.json" });
    const record = try controller.custody_files.readFile(io, record_path, controller.records.max_record_bytes, true);
    const raw = try a.alloc(u8, @intCast(record.bytes));
    const record_file = try std.Io.Dir.openFileAbsolute(io, record_path, .{ .follow_symlinks = false });
    defer record_file.close(io);
    try std.testing.expectEqual(raw.len, try record_file.readPositionalAll(io, raw, 0));
    try expectInvalidLocalPostRun(&accepted, raw, .@"handoff-inspect");
    var mutated = try std.json.parseFromSlice(std.json.Value, a, raw, .{ .duplicate_field_behavior = .@"error", .parse_numbers = false });
    defer mutated.deinit();
    mutated.value.object.getPtr("sha256").?.* = .{ .string = "0000000000000000000000000000000000000000000000000000000000000000" };
    const mutated_raw = try canonicalJsonValue(a, mutated.value);
    try std.testing.expectError(error.InvalidCommand, controller.accepted_run.validateLocalPostRunCommand(&accepted, mutated_raw, .@"handoff-inspect-legacy"));

    var wrong = accepted;
    wrong.compatibility = .tiny_v2_qcow2_derived_vhd;
    try expectInvalidHandoffRun(a, io, &wrong, try std.fs.path.join(a, &.{ output_parent, "wrong-v2-output" }), true);
    try expectInvalidLocalPostRun(&wrong, raw, .@"handoff-inspect-legacy");
    const record_parent = try core.private_files.FileParent.open(io, record_path, .private);
    defer record_parent.close(io);
    try record_parent.directory.rename(record_parent.name, record_parent.directory, "original-inspection", io);
    const replacement = try record_parent.directory.createFile(io, record_parent.name, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer replacement.close(io);
    try replacement.writePositionalAll(io, raw, 0);
    try replacement.sync(io);
    if (inspection.record.verify(io)) |_| return error.ReplacedInspectionAccepted else |_| {}
}

fn fixture(allocator: std.mem.Allocator, v2: bool, commands: bool) ![]u8 {
    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    const w = &writer.writer;
    try w.writeAll("{\"schema_version\":");
    try w.writeAll(if (v2) "2,\"profile\":\"qcow2-derived-vhd\"," else "1,");
    try w.writeAll(
        "\"scope\":\"local_native_compute_only\",\"passed\":true,\"hardware_acceptance\":\"not_established\"," ++
            "\"cloud_authority\":\"not_admitted\",\"benchmark\":\"not_measured\",\"workload\":\"tiny\",\"modes\":[",
    );
    const set: controller.profile.CompatibleRecordSet = if (v2)
        .tiny_v2_qcow2_derived_vhd
    else
        .tiny_v1_legacy;
    const digest = std.fmt.bytesToHex(controller.records.fileIdentity("{}\n"), .lower);
    for (controller.profile.modes(set), 0..) |mode, i| {
        if (i != 0) try w.writeByte(',');
        try w.print("\"{s}\"", .{@tagName(mode)});
    }
    try w.writeAll("],\"records\":{");
    var first = true;
    for ([_][]const u8{ "build-start.json", "build.json", "boot-inputs.json", "package.json" }) |name| {
        if (!first) try w.writeByte(',');
        first = false;
        try w.print("\"{s}\":\"{s}\"", .{ name, &digest });
    }
    for (controller.profile.modes(set)) |mode|
        try w.print(",\"{s}-compute.json\":\"{s}\"", .{ @tagName(mode), &digest });
    if (v2) for ([_][]const u8{
        "qcow2-finalization-intent.json",   "qcow2-finalization.json",        "qcow2-acceptance.json",
        "fixed-vhd-derivation-intent.json", "fixed-vhd-derivation-gate.json", "fixed-vhd-derivation.json",
        "final-inspection.json",
    }) |name| try w.print(",\"{s}\":\"{s}\"", .{ name, &digest });
    if (commands) {
        for ([_][]const u8{
            "adapter",      "local-boot-tool", "fixtures",       "prepare",          "config",
            "native-image", "package",         "finalize-qcow2", "derive-fixed-vhd", "inspect",
        }) |stage| try w.print(",\"command-{s}.json\":\"{s}\"", .{ stage, &digest });
        for (controller.profile.modes(set)) |mode|
            try w.print(",\"command-{s}.json\":\"{s}\"", .{ @tagName(mode), &digest });
    }
    try w.writeAll("}}");
    return writer.toOwnedSlice();
}

test "python-produced local runtimes stay outside records and validator-build acceptance" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("python-produced-policy-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("python producer policy fixture cleanup failed");
    const root = try parent.openDir(io, name, .{ .iterate = true });
    defer root.close(io);
    try root.createDir(io, "compute", .fromMode(0o700));
    const compute = try root.openDir(io, "compute", .{ .iterate = true });
    defer compute.close(io);
    try compute.createDir(io, "evidence", .fromMode(0o700));
    const local = try compute.openDir(io, "evidence", .{ .iterate = true });
    defer local.close(io);
    const path = try std.fs.path.join(a, &.{ options.fixture_root, name });
    defer a.free(path);
    const supervisor_path = try std.fs.path.join(a, &.{ path, "compute/supervisor/bin/wamr-ci-supervisor" });
    defer a.free(supervisor_path);
    const source = .{
        .revision = "1111111111111111111111111111111111111111",
        .tree = "2222222222222222222222222222222222222222",
    };
    const start_raw = try controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, .{
        .source = source,
        .consumer_inputs = .{ .files = .{
            .@"command-supervisor" = .{ .path = supervisor_path },
        } },
    }, .{}));
    defer a.free(start_raw);
    const build_raw = try controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, .{ .source = source }, .{}));
    defer a.free(build_raw);
    const fixture_raw = try fixture(a, true, true);
    defer a.free(fixture_raw);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, fixture_raw, .{
        .duplicate_field_behavior = .@"error",
        .parse_numbers = false,
    });
    defer parsed.deinit();
    const start_digest = std.fmt.bytesToHex(controller.records.fileIdentity(start_raw), .lower);
    const build_digest = std.fmt.bytesToHex(controller.records.fileIdentity(build_raw), .lower);
    parsed.value.object.getPtr("records").?.object.getPtr("build-start.json").?.* = .{ .string = start_digest[0..] };
    parsed.value.object.getPtr("records").?.object.getPtr("build.json").?.* = .{ .string = build_digest[0..] };
    const result_raw = try controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, parsed.value, .{}));
    defer a.free(result_raw);
    try writeFixtureFile(io, local, "result.json", result_raw);
    for (parsed.value.object.get("records").?.object.keys()) |record| {
        if (std.mem.eql(u8, record, "build-start.json")) {
            try writeFixtureFile(io, local, record, start_raw);
        } else if (std.mem.eql(u8, record, "build.json")) {
            try writeFixtureFile(io, local, record, build_raw);
        } else {
            try writeFixtureFile(io, local, record, "{}\n");
        }
    }
    const directory = try core.private_files.Directory.open(io, path);
    defer directory.close(io);
    try std.testing.expectError(error.UnsupportedLocalProducer, controller.accepted_run.openAndValidate(
        a,
        io,
        std.process.Environ.empty,
        &directory,
        path,
        options.repository_root,
    ));
    const local_refusal = try std.process.run(a, io, .{
        .argv = &.{ options.host_controller_cli, "records", "--runtime", path, "--output", "handoff-v1" },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(256),
        .stderr_limit = .limited(4096),
    });
    defer a.free(local_refusal.stdout);
    defer a.free(local_refusal.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, local_refusal.term);
    try std.testing.expectEqualStrings("", local_refusal.stdout);
    try std.testing.expect(std.mem.indexOf(u8, local_refusal.stderr, "cause: UnsupportedLocalProducer") != null);
    const validation_path = try std.fs.path.join(a, &.{ path, "validator" });
    defer a.free(validation_path);
    const validator_build = try std.process.run(a, io, .{
        .argv = &.{ options.host_controller_cli, "public-validator-build", "--runtime", path, "--output", validation_path },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(256),
        .stderr_limit = .limited(4096),
    });
    defer a.free(validator_build.stdout);
    defer a.free(validator_build.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, validator_build.term);
    try std.testing.expectEqualStrings("", validator_build.stdout);
    try std.testing.expect(std.mem.indexOf(u8, validator_build.stderr, "cause: UnsupportedLocalProducer") != null);
    try std.testing.expectError(error.FileNotFound, root.openDir(io, "validator", .{}));
}

test "accepted run requires complete local and trusted-inner-zip evidence before handoff" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("accepted-records-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("accepted records fixture cleanup failed");
    const root = try parent.openDir(io, name, .{ .iterate = true });
    defer root.close(io);
    try root.createDir(io, "compute", .fromMode(0o700));
    try root.createDir(io, "artifacts", .fromMode(0o700));
    try root.createDir(io, "evidence", .fromMode(0o700));
    const compute = try root.openDir(io, "compute", .{ .iterate = true });
    defer compute.close(io);
    try compute.createDir(io, "evidence", .fromMode(0o700));
    const local = try compute.openDir(io, "evidence", .{ .iterate = true });
    defer local.close(io);
    const imported = try root.openDir(io, "evidence", .{ .iterate = true });
    defer imported.close(io);
    const artifacts = try root.openDir(io, "artifacts", .{ .iterate = true });
    defer artifacts.close(io);
    const unencoded = try fixture(a, true, true);
    defer a.free(unencoded);
    const accepted = try controller.records.canonicalAlloc(a, unencoded);
    defer a.free(accepted);
    try writeFixtureFile(io, local, "result.json", accepted);
    try writeFixtureFile(io, artifacts, "local_result", accepted);
    const path = try std.fs.path.join(a, &.{ options.fixture_root, name });
    defer a.free(path);
    const directory = try core.private_files.Directory.open(io, path);
    defer directory.close(io);
    {
        var signal = try controller.build_pipeline.installCancellation();
        defer signal.deinit();
        var local_view = controller.accepted_run.AcceptedRun{
            .arena = std.heap.ArenaAllocator.init(a),
            .io = io,
            .context = .local_runtime,
            .compatibility = .tiny_v2_qcow2_derived_vhd,
            .production_profile = null,
            .source = undefined,
            .result = undefined,
            .records = &.{},
            .artifacts = &.{},
            .runtime_inputs = &.{},
            .root = path,
            .repository = options.repository_root,
            .environ = std.process.Environ.empty,
        };
        defer local_view.deinit();
        try std.testing.expectError(error.FileNotFound, local_view.revalidateWithSignal(&signal));
        try std.testing.expectError(error.MissingEvidence, controller.accepted_run.openAndValidateWithSignal(
            a,
            io,
            undefined,
            &directory,
            path,
            options.repository_root,
            &signal,
        ));
    }
    try std.testing.expectError(error.MissingEvidence, controller.accepted_run.openImportedStage(a, io, &directory, path));
    try std.testing.expectError(error.MissingEvidence, controller.accepted_run.openAndValidate(a, io, undefined, &directory, path, options.repository_root));
    const local_refusal = try std.process.run(a, io, .{
        .argv = &.{ options.host_controller_cli, "records", "--runtime", path, "--output", "handoff-v1" },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(256),
        .stderr_limit = .limited(4096),
    });
    defer a.free(local_refusal.stdout);
    defer a.free(local_refusal.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, local_refusal.term);
    try std.testing.expectEqualStrings("", local_refusal.stdout);
    const inspection_path = try std.fs.path.join(a, &.{ path, "inspection" });
    defer a.free(inspection_path);
    const inspection = try std.process.run(a, io, .{
        .argv = &.{ options.host_controller_cli, "handoff-inspect", "--runtime", path, "--output", inspection_path },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(256),
        .stderr_limit = .limited(4096),
    });
    defer a.free(inspection.stdout);
    defer a.free(inspection.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, inspection.term);
    try std.testing.expectEqualStrings("", inspection.stdout);
    try std.testing.expectError(error.FileNotFound, root.openDir(io, "inspection", .{}));
    const validation_path = try std.fs.path.join(a, &.{ path, "validator" });
    defer a.free(validation_path);
    const validator_build = try std.process.run(a, io, .{
        .argv = &.{ options.host_controller_cli, "public-validator-build", "--runtime", path, "--output", validation_path },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(256),
        .stderr_limit = .limited(4096),
    });
    defer a.free(validator_build.stdout);
    defer a.free(validator_build.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, validator_build.term);
    try std.testing.expectEqualStrings("", validator_build.stdout);
    try std.testing.expectError(error.FileNotFound, root.openDir(io, "validator", .{}));

    var parsed = try controller.records.parseCanonicalResult(a, accepted);
    defer parsed.deinit();
    for (parsed.value.records.keys()) |record| {
        try writeFixtureFile(io, local, record, "{}\n");
        try writeFixtureFile(io, imported, record, "{}\n");
    }
    try std.testing.expectError(error.InvalidEvidence, controller.accepted_run.openImportedStage(a, io, &directory, path));
    try std.testing.expectError(error.InvalidEvidence, controller.accepted_run.openAndValidate(a, io, undefined, &directory, path, options.repository_root));
    const changed = try imported.openFile(io, "build.json", .{ .mode = .read_write, .follow_symlinks = false });
    try changed.setLength(io, 0);
    try changed.writePositionalAll(io, "{\"forged\":true}\n", 0);
    changed.close(io);
    try std.testing.expectError(error.RecordChanged, controller.accepted_run.openImportedStage(a, io, &directory, path));
}

test "handoff document has a fixed canonical shape and finite output limit" {
    const a = std.testing.allocator;
    var view = controller.accepted_run.AcceptedRun{
        .arena = std.heap.ArenaAllocator.init(a),
        .io = std.testing.io,
        .context = .trusted_inner_zip,
        .compatibility = .tiny_v1_legacy,
        .production_profile = null,
        .source = .{ .revision = "993e4d0d394c08202c0d0c57ea97450a19a4f394", .tree = "54f8e118146c78c24e7c802657c6ec62b268a5de" },
        .result = .{ .relative_path = "artifacts/local_result", .bytes = 1, .sha256 = @as([64]u8, @splat('a')) },
        .records = &.{},
        .artifacts = &.{},
        .runtime_inputs = &.{},
        .root = "/fixture",
        .repository = null,
        .environ = null,
    };
    defer view.deinit();
    const raw = try view.handoffV1();
    var document = try core.contracts.Document.parse(a, raw, .{});
    defer document.deinit();
    try document.requireCanonical(a, raw);
    _ = try core.contracts.exactFields(document.value(), &.{
        "schema",         "schema_version", "context", "compatibility", "profile",
        "source",         "modes",          "result",  "records",       "artifacts",
        "runtime_inputs",
    });
    try std.testing.expectEqualStrings("trusted-inner-zip", document.value().object.get("context").?.string);
    try std.testing.expectEqual(@as(usize, 4), document.value().object.get("modes").?.array.items.len);
    const result = document.value().object.get("result").?;
    try std.testing.expect(result.object.get("sha256").? == .string);
    const oversized = try view.arena.allocator().alloc(u8, 2 * 1024 * 1024);
    @memset(oversized, 'a');
    view.source.revision = oversized;
    try std.testing.expectError(error.HandoffTooLarge, view.handoffV1());
}

fn fixtureCanonical(a: std.mem.Allocator, value: anytype) ![]const u8 {
    return controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, value, .{}));
}

fn fixtureMember(
    a: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    members: *std.json.Value,
    path: []const u8,
    bytes: []const u8,
) !std.json.Value {
    try writeFixtureFile(io, dir, path, bytes);
    const sha256 = try a.dupe(u8, &std.fmt.bytesToHex(controller.records.fileIdentity(bytes), .lower));
    const size: u64 = @intCast(bytes.len);
    try members.object.put(a, path, try std.json.parseFromSliceLeaky(std.json.Value, a, try std.json.Stringify.valueAlloc(a, .{
        .size = size,
        .sha256 = sha256,
    }, .{}), .{}));
    return std.json.parseFromSliceLeaky(std.json.Value, a, try std.json.Stringify.valueAlloc(a, .{
        .path = path,
        .size = size,
        .sha256 = sha256,
    }, .{}), .{});
}

fn fixtureItem(a: std.mem.Allocator, members: std.json.Value, path: []const u8) !std.json.Value {
    const member = members.object.get(path) orelse return error.MissingFixture;
    return std.json.parseFromSliceLeaky(std.json.Value, a, try std.json.Stringify.valueAlloc(a, .{
        .path = path,
        .size = member.object.get("size").?,
        .sha256 = member.object.get("sha256").?,
    }, .{}), .{});
}

fn fixtureSparseImage(
    a: std.mem.Allocator,
    io: std.Io,
    root: std.Io.Dir,
    root_path: []const u8,
    members: *std.json.Value,
    role: []const u8,
    footer: ?*const [512]u8,
) !std.json.Value {
    const path = try a.print("artifacts/{s}", .{role});
    const file = try root.createFile(io, path, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    const bytes: u64 = 66 * 1024 * 1024;
    try file.setLength(io, bytes + @as(u64, if (footer == null) 0 else 512));
    if (footer) |value| try file.writePositionalAll(io, value, bytes);
    const recorded = try controller.custody_files.readFile(io, try std.fs.path.join(a, &.{ root_path, path }), bytes + 512, true);
    const size = recorded.bytes;
    const digest = try a.dupe(u8, &recorded.sha256);
    try members.object.put(a, path, try std.json.parseFromSliceLeaky(std.json.Value, a, try std.json.Stringify.valueAlloc(a, .{
        .size = size,
        .sha256 = digest,
    }, .{}), .{}));
    return fixtureItem(a, members.*, path);
}

test "trusted historical inner stage accepts complete records and refuses tampered boot bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("accepted-import-v1-{d}", .{std.os.linux.getpid()});
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("import fixture cleanup failed");
    const root = try parent.openDir(io, name, .{ .iterate = true });
    defer root.close(io);
    for ([_][]const u8{ "artifacts", "evidence", "boots" }) |part|
        try root.createDir(io, part, .fromMode(0o700));
    for (controller.profile.legacy_modes) |mode|
        try root.createDir(io, try a.print("boots/{s}", .{@tagName(mode)}), .fromMode(0o700));
    const stage_root_path = try std.fs.path.join(a, &.{ options.fixture_root, name });
    var members = std.json.Value{ .object = .empty };
    var record_hashes = std.json.Value{ .object = .empty };
    const source = .{
        .revision = "993e4d0d394c08202c0d0c57ea97450a19a4f394",
        .tree = "54f8e118146c78c24e7c802657c6ec62b268a5de",
    };
    const wamr_revision = controller.custody_limits.historical_wamr_revision;
    for ([_][]const u8{
        "efi",      "debug_elf", "bootinfo", "runtime",
        "compiler", "wasm",      "cwasm",    "config",
    }) |role| {
        const artifact_path = try a.print("artifacts/{s}", .{role});
        _ = try fixtureMember(a, io, root, &members, artifact_path, role);
    }
    var footer = @as([512]u8, @splat(0));
    footer[0..8].* = "conectix".*;
    std.mem.writeInt(u32, footer[8..12], 2, .big);
    std.mem.writeInt(u32, footer[12..16], 0x10000, .big);
    std.mem.writeInt(u64, footer[16..24], std.math.maxInt(u64), .big);
    footer[28..32].* = "miz ".*;
    std.mem.writeInt(u64, footer[40..48], 66 * 1024 * 1024, .big);
    std.mem.writeInt(u64, footer[48..56], 66 * 1024 * 1024, .big);
    std.mem.writeInt(u16, footer[56..58], 134, .big);
    footer[58] = 16;
    footer[59] = 63;
    std.mem.writeInt(u32, footer[60..64], 2, .big);
    footer[68] = 1;
    var footer_sum: u32 = 0;
    for (footer, 0..) |byte, index| if (index < 64 or index >= 68) {
        footer_sum +%= byte;
    };
    std.mem.writeInt(u32, footer[64..68], ~footer_sum, .big);
    const footer_hash = std.fmt.bytesToHex(controller.records.fileIdentity(&footer), .lower);
    _ = try fixtureSparseImage(a, io, root, stage_root_path, &members, "raw", null);
    _ = try fixtureSparseImage(a, io, root, stage_root_path, &members, "vhd", &footer);
    const identity = .{
        .wamr_revision = wamr_revision,
        .compiler_profile = "unikraft-x86_64",
        .zig_version = "0.16.0",
        .minimal_wasi = false,
        .files = .{
            .@"tiny.wasm" = members.object.get("artifacts/wasm").?.object.get("sha256").?.string,
            .@"tiny.cwasm" = members.object.get("artifacts/cwasm").?.object.get("sha256").?.string,
            .@"libwamr-aot.a" = members.object.get("artifacts/runtime").?.object.get("sha256").?.string,
            .wamrc = members.object.get("artifacts/compiler").?.object.get("sha256").?.string,
        },
    };
    const identity_raw = try fixtureCanonical(a, identity);
    _ = try fixtureMember(a, io, root, &members, "artifacts/runtime_identity", identity_raw);
    const image = .{
        .unikraft_revision = source.revision,
        .files = .{
            .@"wamr_hyperv-x86_64-efi" = members.object.get("artifacts/efi").?.object.get("sha256").?.string,
            .@"wamr_hyperv-x86_64-efi.dbg" = members.object.get("artifacts/debug_elf").?.object.get("sha256").?.string,
            .@"wamr_hyperv-x86_64-efi.bootinfo" = members.object.get("artifacts/bootinfo").?.object.get("sha256").?.string,
        },
        .solved_config_sha256 = members.object.get("artifacts/config").?.object.get("sha256").?.string,
        .runtime_inputs_sha256 = members.object.get("artifacts/runtime_identity").?.object.get("sha256").?.string,
    };
    const image_raw = try fixtureCanonical(a, image);
    _ = try fixtureMember(a, io, root, &members, "artifacts/image_identity", image_raw);

    const start = try fixtureCanonical(a, .{ .source = source });
    const built = try fixtureCanonical(a, .{ .source = source, .runtime = identity, .image = image });
    const empty_hash = std.fmt.bytesToHex(controller.records.fileIdentity(""), .lower);
    const boot_inputs = try fixtureCanonical(a, .{
        .package_tool = empty_hash,
        .local_boot_tool = empty_hash,
        .qemu = empty_hash,
        .ovmf_code = empty_hash,
        .ovmf_vars = empty_hash,
    });
    const package = try fixtureCanonical(a, .{
        .scope = "public_local_compute_packaging_only",
        .acceptance = "not_established",
        .producer_sha256 = empty_hash,
        .image = .{
            .schema_version = @as(u8, 1),
            .miz_revision = controller.custody_limits.historical_miz_revision,
            .efi = .{ .size = @as(u64, 3), .sha256 = image.files.@"wamr_hyperv-x86_64-efi" },
            .raw = .{ .size = @as(u64, 66 * 1024 * 1024), .sha256 = members.object.get("artifacts/raw").?.object.get("sha256").?.string },
            .vhd = .{ .size = @as(u64, 66 * 1024 * 1024 + 512), .sha256 = members.object.get("artifacts/vhd").?.object.get("sha256").?.string },
            .footer_sha256 = footer_hash,
            .packaging = .{
                .architecture = "x86_64",
                .@"boot-file-sha256" = image.files.@"wamr_hyperv-x86_64-efi",
                .@"boot-path" = "EFI/BOOT/BOOTX64.EFI",
                .contract = "miz.efi-application-image",
                .@"esp-length" = 64 * 1024 * 1024,
                .@"esp-offset" = 1024 * 1024,
                .@"file-size" = 66 * 1024 * 1024 + 512,
                .format = "vhd",
                .generation = 2,
                .@"schema-version" = 1,
                .subformat = "fixed",
                .valid = true,
                .@"virtual-size" = 66 * 1024 * 1024,
            },
        },
    });
    for ([_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "build-start.json", .value = start },
        .{ .name = "build.json", .value = built },
        .{ .name = "boot-inputs.json", .value = boot_inputs },
        .{ .name = "package.json", .value = package },
    }) |item| {
        const path = try a.print("evidence/{s}", .{item.name});
        const descriptor = try fixtureMember(a, io, root, &members, path, item.value);
        try record_hashes.object.put(a, item.name, descriptor.object.get("sha256").?);
        const role: []const u8 = if (std.mem.eql(u8, item.name, "build.json"))
            "build"
        else
            item.name[0 .. item.name.len - ".json".len];
        const copy_path = try a.print("artifacts/{s}", .{if (std.mem.eql(u8, role, "build-start"))
            "build_start"
        else if (std.mem.eql(u8, role, "boot-inputs"))
            "boot_inputs"
        else
            role});
        _ = try fixtureMember(a, io, root, &members, copy_path, item.value);
    }
    for ([_][]const u8{
        "adapter", "local-boot-tool", "fixtures",        "prepare",    "config",          "native-image",
        "package", "raw-x2apic",      "raw-legacy-apic", "vpc-x2apic", "vpc-legacy-apic", "inspect",
    }) |stage| {
        const filename = try a.print("command-{s}.json", .{stage});
        const bytes = try fixtureCanonical(a, .{
            .scope = "command_diagnostic_not_acceptance",
            .stage = stage,
            .exit_code = @as(u8, 0),
            .bytes = @as(u8, 0),
            .sha256 = empty_hash,
            .over_limit = false,
            .known_error_markers = &[_][]const u8{},
        });
        const path = try a.print("evidence/{s}", .{filename});
        const descriptor = try fixtureMember(a, io, root, &members, path, bytes);
        try record_hashes.object.put(a, filename, descriptor.object.get("sha256").?);
    }
    var boots = std.json.Value{ .array = std.array_list.Managed(std.json.Value).init(a) };
    const compute_json = try a.print(
        "{{\"version\":1,\"workload\":\"tiny\",\"wamr_revision\":\"{s}\",\"wasm_sha256\":\"{s}\",\"cwasm_sha256\":\"{s}\",\"runtime_sha256\":\"{s}\",\"platform_status\":0,\"checks\":2,\"answer\":42,\"terminal\":1,\"detail\":2,\"reserved_bytes\":0,\"frame_bytes\":0,\"accessible_bytes\":0,\"allocation_bytes\":0,\"system_page_table_bytes\":4096,\"error_name\":\"\"}}",
        .{ wamr_revision, identity.files.@"tiny.wasm", identity.files.@"tiny.cwasm", identity.files.@"libwamr-aot.a" },
    );
    const compute_value = try std.json.parseFromSliceLeaky(std.json.Value, a, compute_json, .{});
    for (controller.profile.legacy_modes) |mode| {
        const mode_name = @tagName(mode);
        const serial = try a.print(
            "Hyper-V Hv#1 hypercall page enabled\nHyper-V SynIC:\nPowered by\n{s}Calling main(0, 0)\nWAMR_NATIVE_COMPUTE={s}\nWAMR_NATIVE_AOT_OK answer=42 teardown=0\n[    1.000001] Info: [libukboot] main returned 0\n",
            .{ if (mode.legacyApic()) "Using legacy xAPIC MMIO\n" else "", compute_json },
        );
        const serial_path = try a.print("boots/{s}/serial", .{mode_name});
        const serial_item = try fixtureMember(a, io, root, &members, serial_path, serial);
        const image_role: []const u8 = if (std.mem.startsWith(u8, mode_name, "raw-")) "raw" else "vhd";
        const image_pin = members.object.get(try a.print("artifacts/{s}", .{image_role})).?;
        const image_hash = try core.contracts.parseSha256(image_pin.object.get("sha256").?.string);
        const empty_digest = try core.contracts.parseSha256(&empty_hash);
        const pins = [_]struct { size: u64, sha256: [32]u8 }{
            .{ .size = if (std.mem.eql(u8, image_role, "raw")) 66 * 1024 * 1024 else 66 * 1024 * 1024 + 512, .sha256 = image_hash },
            .{ .size = 1, .sha256 = empty_digest },
            .{ .size = 1, .sha256 = empty_digest },
            .{ .size = 1, .sha256 = empty_digest },
        };
        const request = try fixtureCanonical(a, .{
            .schema_version = @as(u8, 1),
            .supervisor_pid = @as(u32, 1234),
            .config = try controller.boot_pipeline.expectedModeConfig(
                a,
                mode,
                if (std.mem.startsWith(u8, mode_name, "raw-"))
                    "/d/wamr-ci/wamr-native-runtime/compute/package/unikraft.raw"
                else
                    "/d/wamr-ci/wamr-native-runtime/compute/package/unikraft.vhd",
                "/d/wamr-ci/wamr-native-runtime/firmware/code.fd",
                "/d/wamr-ci/wamr-native-runtime/firmware/vars.fd",
                "/d/wamr-ci/wamr-native-runtime/bin/qemu-system-x86_64",
                try a.print("/d/wamr-ci/wamr-native-runtime/compute/boot-{s}", .{mode_name}),
            ),
            .pins = pins,
        });
        const report = try fixtureCanonical(a, .{
            .scope = "public_local_qemu_only",
            .acceptance = "not_established",
            .schema_version = @as(u8, 1),
            .passed = true,
            .consumed = true,
            .cleanup_complete = true,
            .input_unchanged = true,
            .serial_valid = true,
            .serial_limit_reached = false,
            .termination = .{ .exited = @as(u8, 0) },
            .failures = .{ .primary = @as(?[]const u8, null), .cleanup = @as(?[]const u8, null), .recording = @as(?[]const u8, null) },
            .serial_bytes = serial_item.object.get("size").?,
            .serial_sha256 = serial_item.object.get("sha256").?,
        });
        const request_item = try fixtureMember(a, io, root, &members, try a.print("boots/{s}/request", .{mode_name}), request);
        const report_item = try fixtureMember(a, io, root, &members, try a.print("boots/{s}/report", .{mode_name}), report);
        const pins_value = try std.json.parseFromSliceLeaky(std.json.Value, a, try std.json.Stringify.valueAlloc(a, pins, .{}), .{});
        const report_value = try std.json.parseFromSliceLeaky(std.json.Value, a, report, .{});
        const evidence = try fixtureCanonical(a, .{
            .scope = "local_native_compute_only",
            .report = report_value,
            .input_pins = pins_value,
            .request_sha256 = request_item.object.get("sha256").?,
            .report_sha256 = report_item.object.get("sha256").?,
            .compute = compute_value,
        });
        const filename = try a.print("{s}-compute.json", .{mode_name});
        const evidence_item = try fixtureMember(a, io, root, &members, try a.print("evidence/{s}", .{filename}), evidence);
        try record_hashes.object.put(a, filename, evidence_item.object.get("sha256").?);
        const compute_item = try fixtureMember(a, io, root, &members, try a.print("boots/{s}/compute", .{mode_name}), evidence);
        const boot = try std.json.parseFromSliceLeaky(std.json.Value, a, try std.json.Stringify.valueAlloc(a, .{
            .mode = mode_name,
            .serial = serial_item,
            .request = request_item,
            .report = report_item,
            .compute = compute_item,
        }, .{}), .{});
        try boots.array.append(boot);
    }
    const result = try fixtureCanonical(a, .{
        .schema_version = @as(u8, 1),
        .scope = "local_native_compute_only",
        .passed = true,
        .hardware_acceptance = "not_established",
        .cloud_authority = "not_admitted",
        .benchmark = "not_measured",
        .workload = "tiny",
        .modes = &[_][]const u8{
            "raw-x2apic", "raw-legacy-apic", "vpc-x2apic", "vpc-legacy-apic",
        },
        .records = record_hashes,
    });
    _ = try fixtureMember(a, io, root, &members, "artifacts/local_result", result);
    const artifact_names = [_][]const u8{
        "efi",         "debug_elf", "bootinfo",         "raw",            "vhd",          "runtime", "compiler", "wasm",
        "cwasm",       "config",    "runtime_identity", "image_identity", "local_result", "package", "build",    "build_start",
        "boot_inputs",
    };
    var artifacts = std.json.Value{ .array = std.array_list.Managed(std.json.Value).init(a) };
    for (artifact_names) |role|
        try artifacts.array.append(try fixtureItem(a, members, try a.print("artifacts/{s}", .{role})));
    var evidence = std.json.Value{ .array = std.array_list.Managed(std.json.Value).init(a) };
    const sorted = try a.dupe([]const u8, record_hashes.object.keys());
    std.mem.sort([]const u8, sorted, {}, struct {
        fn less(_: void, first: []const u8, second: []const u8) bool {
            return std.mem.lessThan(u8, first, second);
        }
    }.less);
    for (sorted) |entry|
        try evidence.array.append(try fixtureItem(a, members, try a.print("evidence/{s}", .{entry})));
    const context = .{
        .repository = "cataggar/unikraft",
        .run_id = "1",
        .run_attempt = "1",
        .source_revision = source.revision,
        .source_tree = source.tree,
        .wamr_revision = wamr_revision,
    };
    try writeFixtureFile(io, root, "portable-bundle.json", try fixtureCanonical(a, .{
        .schema = "uk.wamr.local-image-handoff",
        .version = @as(u8, 1),
        .authority = "not_admitted",
        .source_revision = source.revision,
        .source_tree = source.tree,
        .identity = .{
            .wamr_revision = wamr_revision,
            .wasm_sha256 = identity.files.@"tiny.wasm",
            .cwasm_sha256 = identity.files.@"tiny.cwasm",
            .runtime_sha256 = identity.files.@"libwamr-aot.a",
            .compiler_sha256 = identity.files.wamrc,
            .config_sha256 = image.solved_config_sha256,
        },
        .artifacts = artifacts,
        .boots = boots,
        .evidence = evidence,
    }));
    try writeFixtureFile(io, root, "public-source.json", try fixtureCanonical(a, .{
        .schema = "uk.wamr.public-source-bundle",
        .version = @as(u8, 1),
        .authority = "not_admitted",
        .source = context,
        .members = members,
    }));
    const directory = try core.private_files.Directory.open(io, stage_root_path);
    defer directory.close(io);
    var accepted = try controller.accepted_run.openImportedStage(a, io, &directory, stage_root_path);
    defer accepted.deinit();
    try accepted.revalidate();
    const handoff = try accepted.handoffV1();
    try std.testing.expect(std.mem.indexOf(u8, handoff, "\"context\":\"trusted-inner-zip\"") != null);
    try std.testing.expectEqual(@as(usize, 20), accepted.records.len);
    const cli_success = try std.process.run(a, io, .{
        .argv = &.{ options.host_controller_cli, "records", "--stage-root", stage_root_path, "--transport", "trusted-inner-zip", "--output", "handoff-v1" },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(2 * 1024 * 1024),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, cli_success.term);
    try std.testing.expectEqualStrings(handoff, cli_success.stdout);
    const reader_name = try a.print("{s}-reader-source", .{name});
    const reader_repository = try std.fs.path.join(a, &.{ options.fixture_root, reader_name });
    const cloned = try std.process.run(a, io, .{
        .argv = &.{ options.git_executable, "-c", "gc.auto=0", "-c", "maintenance.auto=false", "clone", "-q", "--no-hardlinks", "--", options.repository_root, reader_repository },
        .cwd = .{ .path = options.fixture_root },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, cloned.term);
    defer parent.deleteTree(io, reader_name) catch @panic("legacy reader source cleanup failed");
    const revalidated_name = try a.print("{s}-native-revalidation", .{name});
    const revalidated_path = try std.fs.path.join(a, &.{ options.fixture_root, revalidated_name });
    defer parent.deleteTree(io, revalidated_name) catch @panic("legacy revalidation cleanup failed");
    const revalidated = try std.process.run(a, io, .{
        .argv = &.{
            options.host_controller_cli, "import-handoff-revalidation",
            "--stage-root",              stage_root_path,
            "--git",                     options.git_executable,
            "--supervisor",              options.host_controller_cli,
            "--validator",               options.import_validator,
            "--output",                  revalidated_path,
        },
        .cwd = .{ .path = reader_repository },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    if (revalidated.term != .exited or revalidated.term.exited != 0) {
        std.debug.print("legacy native revalidation: {s}\n", .{revalidated.stderr});
        if (parent.openDir(io, revalidated_name, .{})) |refused_output| {
            defer refused_output.close(io);
            const log = refused_output.readFileAlloc(io, "private/import-native-revalidation.log", a, .limited(4096)) catch "private log unavailable";
            std.debug.print("legacy validator log: {s}\n", .{log});
        } else |_| {}
    }
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, revalidated.term);
    try std.testing.expectEqualStrings("", revalidated.stdout);
    try std.testing.expectEqualStrings("", revalidated.stderr);
    const revalidated_output = try parent.openDir(io, revalidated_name, .{ .iterate = true });
    defer revalidated_output.close(io);
    try std.testing.expectEqualStrings(
        "Compute handoff revalidated; authority=not_admitted.\n",
        try revalidated_output.readFileAlloc(io, "private/import-native-revalidation.log", a, .limited(4096)),
    );
    const command = try revalidated_output.readFileAlloc(io, "evidence/command-import-native-revalidation.json", a, .limited(controller.records.max_record_bytes));
    _ = try controller.accepted_run.validateCommandBinding(a, command, .@"import-native-revalidation", .trusted_inner_zip);
    try accepted.revalidate();
    try parent.deleteTree(io, revalidated_name);

    for ([_][]const u8{ "supervisor", "validator" }) |substituted| {
        const refused = try std.process.run(a, io, .{
            .argv = &.{
                options.host_controller_cli, "import-handoff-revalidation",
                "--stage-root",              stage_root_path,
                "--git",                     options.git_executable,
                "--supervisor",              if (std.mem.eql(u8, substituted, "supervisor")) options.command_fixture else options.host_controller_cli,
                "--validator",               if (std.mem.eql(u8, substituted, "validator")) options.command_fixture else options.import_validator,
                "--output",                  revalidated_path,
            },
            .cwd = .{ .path = reader_repository },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, refused.term);
        try std.testing.expectEqualStrings("", refused.stdout);
        try std.testing.expect(std.mem.indexOf(u8, refused.stderr, if (std.mem.eql(u8, substituted, "supervisor")) "ImportSupervisorChanged" else "InvalidValidator") != null);
        try std.testing.expectError(error.FileNotFound, parent.openDir(io, revalidated_name, .{}));
        try accepted.revalidate();
    }
    const dirty_source_path = try std.fs.path.join(a, &.{ reader_repository, "support/build/wamr-native-ci/controller/import_validator_build.zig" });
    {
        const dirty_source = try std.Io.Dir.cwd().openFile(io, dirty_source_path, .{ .mode = .read_write, .follow_symlinks = false });
        defer dirty_source.close(io);
        try dirty_source.writePositionalAll(io, "\n", (try dirty_source.stat(io)).size);
    }
    const dirty_reader = try std.process.run(a, io, .{
        .argv = &.{
            options.host_controller_cli, "import-handoff-revalidation",
            "--stage-root",              stage_root_path,
            "--git",                     options.git_executable,
            "--supervisor",              options.host_controller_cli,
            "--validator",               options.import_validator,
            "--output",                  revalidated_path,
        },
        .cwd = .{ .path = reader_repository },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, dirty_reader.term);
    try std.testing.expectEqualStrings("", dirty_reader.stdout);
    try std.testing.expect(std.mem.indexOf(u8, dirty_reader.stderr, "DirtySource") != null);
    try std.testing.expectError(error.FileNotFound, parent.openDir(io, revalidated_name, .{}));
    try accepted.revalidate();
    {
        const mismatched_source = try std.Io.Dir.cwd().openFile(io, dirty_source_path, .{ .mode = .read_write, .follow_symlinks = false });
        defer mismatched_source.close(io);
        try mismatched_source.setLength(io, (try mismatched_source.stat(io)).size - 1);
        try mismatched_source.writePositionalAll(io, "X", 3);
    }
    const committed = try std.process.run(a, io, .{
        .argv = &.{
            options.git_executable, "-c",                              "gc.auto=0",                       "-c",                                 "maintenance.auto=false",
            "-c",                   "user.name=Native reader fixture", "-c",                              "user.email=fixture@example.invalid", "commit",
            "-aq",                  "-m",                              "fixture: changed source closure",
        },
        .cwd = .{ .path = reader_repository },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, committed.term);
    const mismatched_reader = try std.process.run(a, io, .{
        .argv = &.{
            options.host_controller_cli, "import-handoff-revalidation",
            "--stage-root",              stage_root_path,
            "--git",                     options.git_executable,
            "--supervisor",              options.host_controller_cli,
            "--validator",               options.import_validator,
            "--output",                  revalidated_path,
        },
        .cwd = .{ .path = reader_repository },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, mismatched_reader.term);
    try std.testing.expectEqualStrings("", mismatched_reader.stdout);
    try std.testing.expect(std.mem.indexOf(u8, mismatched_reader.stderr, "SourceChanged") != null);
    try std.testing.expectError(error.FileNotFound, parent.openDir(io, revalidated_name, .{}));
    try accepted.revalidate();
    try root.createDir(io, "boots/unexpected", .fromMode(0o700));
    try std.testing.expectError(error.InvalidImportedBundle, accepted.revalidate());
    try root.deleteDir(io, "boots/unexpected");
    try writeFixtureFile(io, root, "evidence/extra.json", "{}\n");
    try std.testing.expectError(error.UnexpectedImportedFile, accepted.revalidate());
    try root.deleteFile(io, "evidence/extra.json");
    const serial_path = try a.print("boots/{s}/serial", .{@tagName(controller.profile.legacy_modes[0])});
    const changed = try root.openFile(io, serial_path, .{ .mode = .read_write, .follow_symlinks = false });
    try changed.writePositionalAll(io, "!", 0);
    changed.close(io);
    try std.testing.expectError(error.EvidenceChanged, accepted.revalidate());
    try std.testing.expectError(error.BootChanged, accepted.pinBoot(.@"raw-x2apic", .serial));
    const cli_refusal = try std.process.run(a, io, .{
        .argv = &.{ options.host_controller_cli, "records", "--stage-root", stage_root_path, "--transport", "trusted-inner-zip", "--output", "handoff-v1" },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(256),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, cli_refusal.term);
    try std.testing.expectEqualStrings("", cli_refusal.stdout);
}

test "v1 and v2 frozen result evidence sets reject rehashed fields" {
    const allocator = std.testing.allocator;
    for ([_]bool{ false, true }) |v2| {
        const raw = try fixture(allocator, v2, v2);
        defer allocator.free(raw);
        try std.testing.expectError(error.NonCanonical, controller.records.parseCanonicalResult(allocator, raw));
        const canonical = try controller.records.canonicalAlloc(allocator, raw);
        defer allocator.free(canonical);
        var accepted = try controller.records.parseCanonicalResult(allocator, canonical);
        defer accepted.deinit();
        try std.testing.expectEqual(@as(usize, if (v2) 33 else 8), accepted.value.records.count());
        for (accepted.value.records.keys()) |name|
            try controller.records.verifyRecord(accepted.value, name, "{}\n");
        const document = try core.contracts.Document.parse(allocator, raw, .{});
        defer document.deinit();
        const result = try controller.records.readResult(document.value());
        try std.testing.expectEqual(if (v2) controller.profile.CompatibleRecordSet.tiny_v2_qcow2_derived_vhd else controller.profile.CompatibleRecordSet.tiny_v1_legacy, result.set);
        try std.testing.expectError(error.RecordChanged, controller.records.verifyRecord(result, "build.json", "{\"tampered\":true}\n"));
        try std.testing.expectError(error.MissingRecord, controller.records.verifyRecord(result, "result.json", "{}\n"));
        const changed = try std.mem.replaceOwned(u8, allocator, raw, "\"cloud_authority\":\"not_admitted\"", "\"cloud_authority\":\"admitted\"");
        defer allocator.free(changed);
        const mutation = try core.contracts.Document.parse(allocator, changed, .{});
        defer mutation.deinit();
        try std.testing.expectError(error.InvalidResult, controller.records.readResult(mutation.value()));
        const bad_mode = try std.mem.replaceOwned(u8, allocator, raw, "\"raw-x2apic\",\"raw-legacy-apic\"", "\"raw-legacy-apic\",\"raw-x2apic\"");
        defer allocator.free(bad_mode);
        const modes_document = try core.contracts.Document.parse(allocator, bad_mode, .{});
        defer modes_document.deinit();
        try std.testing.expectError(error.InvalidModes, controller.records.readResult(modes_document.value()));
        const extraneous = try std.mem.replaceOwned(u8, allocator, raw, "\"build.json\":\"", "\"../build.json\":\"");
        defer allocator.free(extraneous);
        const extra_document = try core.contracts.Document.parse(allocator, extraneous, .{});
        defer extra_document.deinit();
        try std.testing.expectError(error.InvalidRecordName, controller.records.readResult(extra_document.value()));
        const boolean = try std.mem.replaceOwned(u8, allocator, raw, "\"passed\":true", "\"passed\":1");
        defer allocator.free(boolean);
        const boolean_document = try core.contracts.Document.parse(allocator, boolean, .{});
        defer boolean_document.deinit();
        try std.testing.expectError(error.InvalidResult, controller.records.readResult(boolean_document.value()));
        const missing = try std.mem.replaceOwned(u8, allocator, raw, "\"build.json\":\"", "\"unused.json\":\"");
        defer allocator.free(missing);
        const missing_document = try core.contracts.Document.parse(allocator, missing, .{});
        defer missing_document.deinit();
        try std.testing.expectError(error.InvalidRecordName, controller.records.readResult(missing_document.value()));
        if (!v2) {
            const downgrade = try std.mem.replaceOwned(u8, allocator, raw, "\"schema_version\":1", "\"schema_version\":2");
            defer allocator.free(downgrade);
            const downgraded = try core.contracts.Document.parse(allocator, downgrade, .{});
            defer downgraded.deinit();
            try std.testing.expectError(error.UnsupportedRecordSet, controller.records.readResult(downgraded.value()));
        }
    }
}

test "v2 results bind every supervised stage; v1 remains read-only compatible" {
    const allocator = std.testing.allocator;
    const bare_v1 = try fixture(allocator, false, false);
    defer allocator.free(bare_v1);
    const legacy = try core.contracts.Document.parse(allocator, bare_v1, .{});
    defer legacy.deinit();
    try std.testing.expectEqual(controller.profile.CompatibleRecordSet.tiny_v1_legacy, (try controller.records.readResult(legacy.value())).set);

    const bare_v2 = try fixture(allocator, true, false);
    defer allocator.free(bare_v2);
    const incomplete = try core.contracts.Document.parse(allocator, bare_v2, .{});
    defer incomplete.deinit();
    try std.testing.expectError(error.MissingRecord, controller.records.readResult(incomplete.value()));

    const complete = try fixture(allocator, true, true);
    defer allocator.free(complete);
    const digest = std.fmt.bytesToHex(controller.records.fileIdentity("{}\n"), .lower);
    for ([_][]const u8{
        "adapter",      "local-boot-tool",   "fixtures",         "prepare",         "config",     "native-image",
        "package",      "finalize-qcow2",    "derive-fixed-vhd", "inspect",         "raw-x2apic", "raw-legacy-apic",
        "qcow2-x2apic", "qcow2-legacy-apic", "vpc-x2apic",       "vpc-legacy-apic",
    }) |stage| {
        const removed = try allocator.print(",\"command-{s}.json\":\"{s}\"", .{ stage, &digest });
        defer allocator.free(removed);
        const missing = try std.mem.replaceOwned(u8, allocator, complete, removed, "");
        defer allocator.free(missing);
        const parsed = try core.contracts.Document.parse(allocator, missing, .{});
        defer parsed.deinit();
        try std.testing.expectError(error.MissingRecord, controller.records.readResult(parsed.value()));
    }
    const altered = try allocator.print("\"command-adapter.json\":\"{s}\"", .{&digest});
    defer allocator.free(altered);
    const changed = try std.mem.replaceOwned(u8, allocator, complete, altered, "\"command-adapter.json\":\"0000000000000000000000000000000000000000000000000000000000000000\"");
    defer allocator.free(changed);
    const forged = try core.contracts.Document.parse(allocator, changed, .{});
    defer forged.deinit();
    const result = try controller.records.readResult(forged.value());
    try std.testing.expectError(error.RecordChanged, controller.records.verifyRecord(result, "command-adapter.json", "{}\n"));
}

test "embedded tracked source closure and physical/no-follow checks" {
    const source = controller.source_custody;
    try std.testing.expect(source.closure.len >= 18);
    for (source.closure, 0..) |entry, index| {
        try source.verifyContent(entry, entry.content);
        try std.testing.expectError(error.SourceChanged, source.verifyContent(entry, ""));
        if (index > 0) try std.testing.expect(std.mem.lessThan(u8, source.closure[index - 1].name, entry.name));
    }

    const closure_hash = source.contentClosure();
    try std.testing.expect(!std.mem.eql(u8, &closure_hash, &@as([32]u8, @splat(0))));
    try source.verifyPhysical(std.testing.io, std.testing.allocator, options.repository_root);
    try std.testing.expectError(error.FileNotFound, source.verifyPhysical(std.testing.io, std.testing.allocator, "/d/does-not-exist-controller"));
}

test "recaptured source custody compares content, not allocated string addresses" {
    const allocator = std.testing.allocator;
    const source = controller.source_custody;
    const before: source.Source = .{
        .revision = "revision",
        .tree = "tree",
        .custody = .{
            .object_format = "sha1",
            .files = 4,
            .directories = 2,
            .bytes = 128,
            .content_sha256 = @as([64]u8, @splat('a')),
            .physical_sha256 = @as([64]u8, @splat('b')),
        },
    };
    const revision = try allocator.dupe(u8, before.revision);
    defer allocator.free(revision);
    const tree = try allocator.dupe(u8, before.tree);
    defer allocator.free(tree);
    const format = try allocator.dupe(u8, before.custody.object_format);
    defer allocator.free(format);
    var actual = before;
    actual.revision = revision;
    actual.tree = tree;
    actual.custody.object_format = format;
    try std.testing.expect(before.same(actual));

    actual.custody.physical_sha256[0] = 'c';
    try std.testing.expect(!before.same(actual));
    actual.custody = before.custody;
    actual.custody.object_format = "sha256";
    try std.testing.expect(!before.same(actual));
    actual.custody = before.custody;
    actual.custody.role_excluded_outputs[0] = "unexpected";
    try std.testing.expect(!before.same(actual));
}

test "frozen custody limits, component-bound roles and first excess" {
    const l = controller.custody_limits;
    try std.testing.expectEqual(@as(usize, 40_000), l.tracked_entries);
    try std.testing.expectEqual(@as(usize, 131_072), l.ignored_entries);
    try std.testing.expectEqual(@as(usize, 8 * 1024 * 1024 * 1024), l.ignored_bytes);
    try std.testing.expectEqual(@as(usize, 512), l.bison_entries);
    try std.testing.expectEqual(@as(usize, 128), l.dependency_roots);
    try std.testing.expectEqualStrings("4d393552cf1797e1d4a65328ddb444f96ee5b816", l.wamr_revision);
    for (l.roles, 0..) |role, index|
        try std.testing.expectEqual(index, try l.outputRole(role));
    try std.testing.expectEqual(@as(usize, 0), try l.outputRole(".d/private/file"));
    try std.testing.expectError(error.IgnoredOutsideOutput, l.outputRole(".d-neighbor/file"));
    try std.testing.expectError(error.UnsafePath, l.outputRole(".d/../other"));
    try std.testing.expectError(error.UnsafePath, l.outputRole(".d//file"));
    try std.testing.expectError(error.UnsafePath, l.outputRole(".d/\xff"));
    var exact: [1025]u8 = undefined;
    @memcpy(exact[0..2], ".d");
    var offset: usize = 2;
    for (0..62) |_| {
        exact[offset] = '/';
        @memset(exact[offset + 1 .. offset + 16], 'x');
        offset += 16;
    }
    exact[offset] = '/';
    @memset(exact[offset + 1 .. 1025], 'x');
    try l.relative(exact[0..1024], l.ignored_path, l.ignored_depth);
    try std.testing.expectError(error.UnsafePath, l.relative(&exact, l.ignored_path, l.ignored_depth));
    var too_deep: [130]u8 = undefined;
    @memcpy(too_deep[0..2], ".d");
    for (0..64) |i| @memcpy(too_deep[2 + i * 2 ..][0..2], "/x");
    try std.testing.expectError(error.LimitExceeded, l.relative(&too_deep, l.ignored_path, l.ignored_depth));
    var bytes: usize = l.ignored_bytes - 1;
    try l.addBounded(&bytes, 1, l.ignored_bytes);
    try std.testing.expectError(error.LimitExceeded, l.addBounded(&bytes, 1, l.ignored_bytes));
    var hashed: usize = 0;
    for (0..4) |_| try l.addBounded(&hashed, l.input_file, l.input_bytes);
    try std.testing.expectEqual(l.input_bytes, hashed);
    try std.testing.expectError(error.LimitExceeded, l.addBounded(&hashed, l.input_file, l.input_bytes));
    var entries: usize = l.ignored_entries - 1;
    try l.addBounded(&entries, 1, l.ignored_entries);
    try std.testing.expectError(error.LimitExceeded, l.addBounded(&entries, 1, l.ignored_entries));
    try l.packageName("miz-0.2.0-Z3lHlD--2gAdGiguNwbjjdjBmv2f8QlAcwHYRw1De0Sx");
    try std.testing.expectError(error.UnsafePackageName, l.packageName("../outside"));
}

test "physical custody snapshot has Python-compatible device and ns" {
    const l = controller.custody_files;
    const source = try std.fs.path.join(std.testing.allocator, &.{ options.repository_root, "support/controller_source_closure.zig" });
    defer std.testing.allocator.free(source);
    const before = try l.readFile(std.testing.io, source, 1024 * 1024, false);
    const after = try l.readFile(std.testing.io, source, 1024 * 1024, false);
    try std.testing.expectEqualDeep(before, after);
    try std.testing.expect(before.bytes > 0);
    const missing = try std.testing.allocator.print("{s}.gone", .{source});
    defer std.testing.allocator.free(missing);
    try std.testing.expectError(error.FileNotFound, l.readFile(std.testing.io, missing, 1024 * 1024, false));
}

fn writeFixtureFile(io: std.Io, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

fn copyFixtureExecutable(io: std.Io, a: std.mem.Allocator, path: []const u8, dir: std.Io.Dir, name: []const u8) !void {
    const source = try std.Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false });
    defer source.close(io);
    const size: usize = @intCast((try core.private_files.snapshot(source)).size);
    if (size == 0 or size > 64 * 1024 * 1024) return error.TestFixtureTooLarge;
    const bytes = try a.alloc(u8, size);
    defer a.free(bytes);
    if (try source.readPositionalAll(io, bytes, 0) != size) return error.TestFixtureChanged;
    const target = try dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o700) });
    defer target.close(io);
    try target.writePositionalAll(io, bytes, 0);
    try target.sync(io);
}

fn fixtureGit(allocator: std.mem.Allocator, cwd: []const u8, argv: []const []const u8) !void {
    const command = try allocator.alloc([]const u8, argv.len + 4);
    defer allocator.free(command);
    command[0] = argv[0];
    const git_config = [_][]const u8{ "-c", "gc.auto=0", "-c", "maintenance.auto=false" };
    @memcpy(command[1..5], &git_config);
    @memcpy(command[5..], argv[1..]);
    const result = std.process.run(allocator, std.testing.io, .{
        .argv = command,
        .cwd = .{ .path = cwd },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    }) catch |err| {
        std.debug.print("Git fixture spawn failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) return error.FixtureGitFailed;
}

test "native clean Git custody, stable physical identities and pinned archive refusal" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const base_path = try allocator.dupe(u8, options.fixture_root);
    defer allocator.free(base_path);
    const base = try std.Io.Dir.openDirAbsolute(io, base_path, .{ .iterate = true });
    defer base.close(io);
    const name = try allocator.print("custody-fixture-{d}", .{std.os.linux.getpid()});
    defer allocator.free(name);
    try base.createDir(io, name, .fromMode(0o700));
    defer base.deleteTree(io, name) catch @panic("controller custody fixture cleanup failed");
    const repo = try base.openDir(io, name, .{ .iterate = true });
    defer repo.close(io);
    const path = try std.fs.path.join(allocator, &.{ base_path, name });
    defer allocator.free(path);
    try writeFixtureFile(io, repo, ".gitignore", "/.d/\n/.zig-cache/\n/support/apps/wamr-aot/.config\n/support/apps/wamr-aot/build/\n");
    try writeFixtureFile(io, repo, "tracked", "clean content\n");
    try repo.symLink(io, "tracked", "link", .{});
    try repo.createDir(io, "support", .fromMode(0o700));
    const support = try repo.openDir(io, "support", .{ .iterate = true });
    defer support.close(io);
    try support.createDir(io, "apps", .fromMode(0o700));
    const apps = try support.openDir(io, "apps", .{ .iterate = true });
    defer apps.close(io);
    try apps.createDir(io, "wamr-aot", .fromMode(0o700));
    const app = try apps.openDir(io, "wamr-aot", .{ .iterate = true });
    defer app.close(io);
    try writeFixtureFile(io, app, "defconfig", "CONFIG_FIXTURE=y\n");
    try fixtureGit(allocator, path, &.{ options.git_executable, "init", "-q" });
    try fixtureGit(allocator, path, &.{ options.git_executable, "add", ".gitignore", "tracked", "link", "support/apps/wamr-aot/defconfig" });
    try fixtureGit(allocator, path, &.{
        options.git_executable, "-c",  "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
        "commit",               "-qm", "custody fixture",
    });
    const version = try controller.source_custody.gitOutput(allocator, io, path, options.git_executable, &.{"version"}, 128, null);
    defer allocator.free(version);
    const exact_version = try controller.source_custody.gitOutput(allocator, io, path, options.git_executable, &.{"version"}, version.len, null);
    defer allocator.free(exact_version);
    try std.testing.expectEqualStrings(version, exact_version);
    try std.testing.expectError(error.GitOutputOverflow, controller.source_custody.gitOutput(
        allocator,
        io,
        path,
        options.git_executable,
        &.{"version"},
        version.len - 1,
        null,
    ));
    try repo.createDir(io, ".d", .fromMode(0o700));
    const initial_output = try repo.openDir(io, ".d", .{ .iterate = true });
    defer initial_output.close(io);
    try initial_output.symLink(io, "../tracked", "safe-link", .{});
    try repo.createDir(io, ".zig-cache", .fromMode(0o700));
    try app.createDir(io, "build", .fromMode(0o700));
    try writeFixtureFile(io, app, ".config", "CONFIG_FIXTURE=y\n");
    const captured = try controller.source_custody.source(allocator, io, path, options.git_executable);
    defer {
        allocator.free(captured.revision);
        allocator.free(captured.tree);
        allocator.free(captured.custody.object_format);
    }
    try std.testing.expectEqual(@as(usize, 4), captured.custody.files);
    var signal = try controller.build_pipeline.installCancellation();
    defer signal.deinit();
    var empty: [0]u8 = .{};
    var no_growth = std.heap.FixedBufferAllocator.init(&empty);
    var context: controller.build_pipeline.Context = .{
        .allocator = no_growth.allocator(),
        .io = io,
        .environ = undefined,
        .runtime = path,
        .repository = path,
        .wamr = "",
        .compute = path,
        .git = options.git_executable,
        .tools = undefined,
        .roots = undefined,
        .signal = &signal,
        .source = captured,
    };
    for (0..3) |_| try controller.build_pipeline.requireSource(&context);
    const unchanged = try controller.source_custody.source(allocator, io, path, options.git_executable);
    defer {
        allocator.free(unchanged.revision);
        allocator.free(unchanged.tree);
        allocator.free(unchanged.custody.object_format);
    }
    try std.testing.expectEqualDeep(captured.custody, unchanged.custody);
    try std.testing.expectError(error.UnpinnedSource, controller.source_custody.sealWamr(allocator, io, path, path, options.git_executable));
    const output_root = try repo.openDir(io, ".d", .{ .iterate = true });
    defer output_root.close(io);
    try output_root.createDir(io, "runtime", .fromMode(0o700));
    const runtime_dir = try output_root.openDir(io, "runtime", .{ .iterate = true });
    defer runtime_dir.close(io);
    try runtime_dir.createDir(io, "custody", .fromMode(0o700));
    const runtime_path = try std.fs.path.join(allocator, &.{ path, ".d/runtime" });
    defer allocator.free(runtime_path);
    try output_root.createDir(io, "runtime-limited", .fromMode(0o700));
    const limited_dir = try output_root.openDir(io, "runtime-limited", .{ .iterate = true });
    defer limited_dir.close(io);
    try limited_dir.createDir(io, "custody", .fromMode(0o700));
    const limited_path = try std.fs.path.join(allocator, &.{ path, ".d/runtime-limited" });
    defer allocator.free(limited_path);
    if (controller.source_custody.Fixture.sealLimited(
        allocator,
        io,
        path,
        limited_path,
        options.git_executable,
        captured.revision,
        1024,
    )) |_| return error.OversizedArchiveAccepted else |err| try std.testing.expect(err == error.GitExited or err == error.GitOutputOverflow);
    const limited_archive = try std.fs.path.join(allocator, &.{ limited_path, "custody/wamr-source.tar" });
    defer allocator.free(limited_archive);
    try std.testing.expect((try controller.custody_files.readFile(io, limited_archive, 1024, true)).bytes <= 1024);
    const sealed = try controller.source_custody.Fixture.seal(allocator, io, path, runtime_path, options.git_executable, captured.revision);
    const oracle_archive = try std.process.run(allocator, io, .{
        .argv = &.{ options.git_executable, "archive", "--format=tar", captured.revision },
        .cwd = .{ .path = path },
        .stdout_limit = .limited(256 * 1024),
        .stderr_limit = .limited(4096),
    });
    defer allocator.free(oracle_archive.stdout);
    defer allocator.free(oracle_archive.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, oracle_archive.term);
    try std.testing.expectEqual(oracle_archive.stdout.len, sealed.bytes);
    try std.testing.expectEqualDeep(controller.records.fileIdentity(oracle_archive.stdout), try core.contracts.parseSha256(&sealed.sha256));
    try std.testing.expectError(error.PathAlreadyExists, controller.source_custody.Fixture.seal(
        allocator,
        io,
        path,
        runtime_path,
        options.git_executable,
        captured.revision,
    ));
    var baseline = try controller.source_custody.sourceMetadata(allocator, io, path, options.git_executable);
    defer baseline.deinit(allocator);
    try std.testing.expectEqual(@as(usize, captured.custody.files + captured.custody.directories), baseline.records.len);
    var diagnostic = try controller.source_custody.ignoredDiagnostic(allocator, io, path, options.git_executable);
    defer diagnostic.deinit(allocator);
    try std.testing.expect(!diagnostic.truncated);
    const roots = try controller.source_custody.rootInventory(allocator, io, path);
    defer {
        for (roots) |entry| allocator.free(entry.name);
        allocator.free(roots);
    }
    try std.testing.expect(roots.len >= 6);
    try initial_output.symLink(io, "b", "a", .{});
    try initial_output.symLink(io, "a", "b", .{});
    try std.testing.expectError(error.IgnoredLinkEscapesRole, controller.source_custody.source(allocator, io, path, options.git_executable));
    try initial_output.deleteFile(io, "a");
    try initial_output.deleteFile(io, "b");
    const contained = try controller.source_custody.source(allocator, io, path, options.git_executable);
    defer {
        allocator.free(contained.revision);
        allocator.free(contained.tree);
        allocator.free(contained.custody.object_format);
    }
    try output_root.symLink(io, "../../escape", "bad-link", .{});
    try std.testing.expectError(error.IgnoredLinkEscapesRole, controller.source_custody.source(allocator, io, path, options.git_executable));
    try output_root.deleteFile(io, "bad-link");
    try app.deleteFile(io, ".config");
    try app.symLink(io, "defconfig", ".config", .{});
    try std.testing.expectError(error.UnsafeIgnoredEntry, controller.source_custody.source(allocator, io, path, options.git_executable));
    try app.deleteFile(io, ".config");
    try writeFixtureFile(io, app, ".config", "CONFIG_FIXTURE=y\n");
    try writeFixtureFile(io, repo, "unexpected", "not ignored");
    try std.testing.expectError(error.DirtySource, controller.source_custody.source(allocator, io, path, options.git_executable));
    for (roots.len + 1..controller.custody_limits.diagnostic_root) |index| {
        const entry = try allocator.print("inventory-{d:0>3}", .{index});
        defer allocator.free(entry);
        try writeFixtureFile(io, repo, entry, "");
    }
    const exact_roots = try controller.source_custody.rootInventory(allocator, io, path);
    try std.testing.expectEqual(controller.custody_limits.diagnostic_root, exact_roots.len);
    for (exact_roots) |entry| allocator.free(entry.name);
    allocator.free(exact_roots);
    try writeFixtureFile(io, repo, "inventory-overflow", "");
    try std.testing.expectError(error.LimitExceeded, controller.source_custody.rootInventory(allocator, io, path));
}

test "input tree deduplicates bounded symlink hash work and refuses first excess" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const input = controller.input_custody;
    const base_path = try allocator.dupe(u8, options.fixture_root);
    defer allocator.free(base_path);
    const base = try std.Io.Dir.openDirAbsolute(io, base_path, .{ .iterate = true });
    defer base.close(io);
    const name = try allocator.print("input-link-limits-{d}", .{std.os.linux.getpid()});
    defer allocator.free(name);
    try base.createDir(io, name, .fromMode(0o700));
    defer base.deleteTree(io, name) catch @panic("input link fixture cleanup failed");
    const fixture_dir = try base.openDir(io, name, .{ .iterate = true });
    defer fixture_dir.close(io);
    const fixture_path = try std.fs.path.join(allocator, &.{ base_path, name });
    defer allocator.free(fixture_path);
    try fixture_dir.createDir(io, "hash", .fromMode(0o700));
    const hash_dir = try fixture_dir.openDir(io, "hash", .{ .iterate = true });
    defer hash_dir.close(io);
    const hash_path = try std.fs.path.join(allocator, &.{ fixture_path, "hash" });
    defer allocator.free(hash_path);
    const binding: input.Binding = .{ .role = "test", .path = hash_path };
    for ("abcde") |character| {
        const target = [_]u8{character};
        try writeFixtureFile(io, fixture_dir, &target, "12345678");
    }
    for ("abcd") |character| {
        const link = [_]u8{character};
        const target = [_]u8{ '.', '.', '/', character };
        try hash_dir.symLink(io, &target, &link, .{});
    }
    const boundary = try input.Fixture.treeWithHashLimit(allocator, io, binding, 32);
    try std.testing.expectEqual(@as(usize, 4), boundary.symlinks);
    try std.testing.expectEqual(@as(usize, 16), boundary.bytes);
    try hash_dir.symLink(io, "../a", "duplicate", .{});
    _ = try input.Fixture.treeWithHashLimit(allocator, io, binding, 32);
    try hash_dir.symLink(io, "../e", "extra", .{});
    try std.testing.expectError(error.LimitExceeded, input.Fixture.treeWithHashLimit(allocator, io, binding, 32));
}

test "missing input symlink target enforces the absolute 64-component boundary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const input = controller.input_custody;
    const base_path = try allocator.dupe(u8, options.fixture_root);
    defer allocator.free(base_path);
    const base = try std.Io.Dir.openDirAbsolute(io, base_path, .{ .iterate = true });
    defer base.close(io);
    const name = try allocator.print("input-missing-depth-{d}", .{std.os.linux.getpid()});
    defer allocator.free(name);
    try base.createDir(io, name, .fromMode(0o700));
    defer base.deleteTree(io, name) catch @panic("input depth fixture cleanup failed");
    const fixture_dir = try base.openDir(io, name, .{ .iterate = true });
    defer fixture_dir.close(io);
    const path = try std.fs.path.join(allocator, &.{ base_path, name });
    defer allocator.free(path);
    const binding: input.Binding = .{ .role = "test", .path = path };
    var target: std.ArrayList(u8) = .empty;
    defer target.deinit(allocator);
    const first = try allocator.print("/usr/unikraft-custody-{d}", .{std.os.linux.getpid()});
    defer allocator.free(first);
    try target.appendSlice(allocator, first);
    for (0..62) |_| try target.appendSlice(allocator, "/x");
    try fixture_dir.symLink(io, target.items, "missing", .{});
    const exact = try input.tree(allocator, io, binding);
    try std.testing.expectEqual(@as(usize, 1), exact.symlinks);
    try fixture_dir.deleteFile(io, "missing");
    try target.appendSlice(allocator, "/x");
    try fixture_dir.symLink(io, target.items, "missing", .{});
    try std.testing.expectError(error.UnsafeInputLink, input.tree(allocator, io, binding));
}

test "native Bison production entry and sparse byte boundaries" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const base_path = try allocator.dupe(u8, options.fixture_root);
    defer allocator.free(base_path);
    const base = try std.Io.Dir.openDirAbsolute(io, base_path, .{ .iterate = true });
    defer base.close(io);
    const name = try allocator.print("bison-limits-{d}", .{std.os.linux.getpid()});
    defer allocator.free(name);
    try base.createDir(io, name, .fromMode(0o700));
    defer base.deleteTree(io, name) catch @panic("Bison limit fixture cleanup failed");
    const directory = try base.openDir(io, name, .{ .iterate = true });
    defer directory.close(io);
    const path = try std.fs.path.join(allocator, &.{ base_path, name });
    defer allocator.free(path);
    for (0..controller.custody_limits.bison_entries) |index| {
        const entry = try allocator.print("entry-{d:0>3}", .{index});
        defer allocator.free(entry);
        try writeFixtureFile(io, directory, entry, "");
    }
    const exact = try controller.input_custody.bison(allocator, io, path);
    try std.testing.expectEqual(controller.custody_limits.bison_entries, exact.files);
    try std.testing.expectEqual(@as(usize, 0), exact.bytes);
    try writeFixtureFile(io, directory, "entry-overflow", "");
    try std.testing.expectError(error.LimitExceeded, controller.input_custody.bison(allocator, io, path));
    for (0..controller.custody_limits.bison_entries) |index| {
        const entry = try allocator.print("entry-{d:0>3}", .{index});
        defer allocator.free(entry);
        try directory.deleteFile(io, entry);
    }
    try directory.deleteFile(io, "entry-overflow");
    const sparse = try directory.createFile(io, "sparse", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer sparse.close(io);
    try sparse.writePositionalAll(io, "X", controller.custody_limits.bison_bytes - 1);
    const boundary = try controller.input_custody.bison(allocator, io, path);
    try std.testing.expectEqual(controller.custody_limits.bison_bytes, boundary.bytes);
    try writeFixtureFile(io, directory, "overflow", "X");
    try std.testing.expectError(error.UnsafeBisonInput, controller.input_custody.bison(allocator, io, path));
}

test "Bison and consumer v2 custody bind bytes, roles, ancestors and replacement" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const base_path = try allocator.dupe(u8, options.fixture_root);
    defer allocator.free(base_path);
    const base = try std.Io.Dir.openDirAbsolute(io, base_path, .{ .iterate = true });
    defer base.close(io);
    const name = try allocator.print("input-fixture-{d}", .{std.os.linux.getpid()});
    defer allocator.free(name);
    try base.createDir(io, name, .fromMode(0o700));
    defer base.deleteTree(io, name) catch @panic("input fixture cleanup failed");
    const fixture_path = try std.fs.path.join(allocator, &.{ base_path, name });
    defer allocator.free(fixture_path);
    const fixture_dir = try base.openDir(io, name, .{ .iterate = true });
    defer fixture_dir.close(io);
    try fixture_dir.createDir(io, "bison", .fromMode(0o700));
    const bison_dir = try fixture_dir.openDir(io, "bison", .{ .iterate = true });
    defer bison_dir.close(io);
    const bison_path = try std.fs.path.join(allocator, &.{ fixture_path, "bison" });
    defer allocator.free(bison_path);
    try std.testing.expectError(error.EmptyBisonData, controller.input_custody.bison(allocator, io, bison_path));
    try writeFixtureFile(io, bison_dir, "grammar", "table");
    const bison = try controller.input_custody.bison(allocator, io, bison_path);
    try std.testing.expectEqual(@as(usize, 1), bison.files);
    try std.testing.expectEqual(@as(usize, 5), bison.bytes);
    try bison_dir.symLink(io, "grammar", "alias", .{});
    const missing_target = try allocator.print("/usr/lib/unikraft-custody-{d}/missing", .{std.os.linux.getpid()});
    defer allocator.free(missing_target);
    try bison_dir.symLink(io, missing_target, "root-owned-dangling", .{});
    try std.testing.expectError(error.UnsafeBisonInput, controller.input_custody.bison(allocator, io, bison_path));
    const path = try std.fs.path.join(allocator, &.{ bison_path, "grammar" });
    defer allocator.free(path);
    const file_binding = [_]controller.input_custody.Binding{.{ .role = "tool:bison", .path = path }};
    const tree_binding = [_]controller.input_custody.Binding{.{ .role = "bison", .path = bison_path }};
    var expected = try controller.input_custody.capture(allocator, io, &file_binding, &tree_binding);
    defer expected.deinit(allocator);
    const canonical = try expected.canonical(allocator);
    defer allocator.free(canonical);
    const document = try core.contracts.Document.parse(allocator, canonical, .{});
    defer document.deinit();
    const record = document.value().object;
    try std.testing.expectEqualStrings("uk.wamr.consumer-input-custody", (try core.contracts.string(record.get("schema").?)));
    try std.testing.expect(record.get("files").?.object.contains("tool:bison"));
    try std.testing.expect(record.get("trees").?.object.contains("bison"));
    try std.testing.expect(record.get("directories").?.object.contains(bison_path));
    try controller.input_custody.requireSame(allocator, io, expected, &file_binding, &tree_binding);
    try std.testing.expectError(error.InvalidInputCustody, controller.input_custody.requireSame(allocator, io, expected, &.{}, &tree_binding));
    try bison_dir.symLink(io, "missing/descendant", "mutable-dangling", .{});
    try std.testing.expectError(error.UnsafeInputLink, controller.input_custody.tree(allocator, io, tree_binding[0]));
    try bison_dir.deleteFile(io, "mutable-dangling");
    const replacement = try std.fs.path.join(allocator, &.{ fixture_path, "replacement" });
    defer allocator.free(replacement);
    try writeFixtureFile(io, fixture_dir, "replacement", "table");
    const renamed = [_]controller.input_custody.Binding{.{ .role = "tool:bison", .path = replacement }};
    try std.testing.expectError(error.InputChanged, controller.input_custody.requireSame(allocator, io, expected, &renamed, &tree_binding));
    try std.testing.expectError(error.DuplicateInputRole, controller.input_custody.capture(allocator, io, &.{ file_binding[0], file_binding[0] }, &tree_binding));
    try std.testing.expectError(error.DuplicateInputAlias, controller.input_custody.capture(allocator, io, &.{
        file_binding[0], .{ .role = "tool:alias", .path = path },
    }, &tree_binding));
    const changed = try bison_dir.openFile(io, "grammar", .{ .mode = .read_write });
    defer changed.close(io);
    try changed.writePositionalAll(io, "TABLE", 0);
    try std.testing.expectError(error.InputChanged, controller.input_custody.requireSame(allocator, io, expected, &file_binding, &tree_binding));
}

test "dependency custody parses pinned native ZON, tracked manifests and bounded packages" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const dependency = controller.dependency_custody;
    const manifest = try std.fs.path.join(allocator, &.{ options.repository_root, "support/tools/hyperv/local_boot/build.zig.zon" });
    defer allocator.free(manifest);
    var manifest_file = try core.private_files.RetainedFile.open(io, manifest, .artifact);
    defer manifest_file.close(io);
    var manifest_data = try core.private_files.readSensitiveFile(io, allocator, manifest_file.file, 1024 * 1024, .artifact);
    defer manifest_data.deinit();
    try dependency.pinnedManifest(allocator, manifest_data.bytes());
    const mutated = try std.mem.replaceOwned(u8, allocator, manifest_data.bytes(), controller.custody_limits.miz_package_hash, "miz-0.2.0-invalid");
    defer allocator.free(mutated);
    try std.testing.expectError(error.UnpinnedDependency, dependency.pinnedManifest(allocator, mutated));
    const sources = try dependency.sourceManifests(allocator, io, options.repository_root, options.git_executable);
    defer for (sources) |item| item.deinit(allocator);
    try std.testing.expectEqualStrings(dependency.manifest_paths[0], sources[0].path);
    try std.testing.expectEqualStrings(dependency.manifest_paths[1], sources[1].path);

    const base_path = try allocator.dupe(u8, options.fixture_root);
    defer allocator.free(base_path);
    const base = try std.Io.Dir.openDirAbsolute(io, base_path, .{ .iterate = true });
    defer base.close(io);
    const name = try allocator.print("dependency-fixture-{d}", .{std.os.linux.getpid()});
    defer allocator.free(name);
    try base.createDir(io, name, .fromMode(0o700));
    defer base.deleteTree(io, name) catch @panic("dependency fixture cleanup failed");
    const fixture_dir = try base.openDir(io, name, .{ .iterate = true });
    defer fixture_dir.close(io);
    const compute_path = try std.fs.path.join(allocator, &.{ base_path, name });
    defer allocator.free(compute_path);
    try fixture_dir.createDir(io, "dependencies", .fromMode(0o700));
    const restore_dir = try fixture_dir.openDir(io, "dependencies", .{ .iterate = true });
    defer restore_dir.close(io);
    try writeFixtureFile(io, restore_dir, "build.zig", sources[0].content);
    try writeFixtureFile(io, restore_dir, "build.zig.zon", sources[1].content);
    try fixture_dir.createDir(io, "private", .fromMode(0o700));
    const private_dir = try fixture_dir.openDir(io, "private", .{ .iterate = true });
    defer private_dir.close(io);
    try writeFixtureFile(io, private_dir, "dependency-restore.log", "restored\n");
    const hash_line = try allocator.print("{s}\n", .{controller.custody_limits.miz_package_hash});
    defer allocator.free(hash_line);
    try writeFixtureFile(io, private_dir, "dependency-hash-000.log", hash_line);
    try restore_dir.createDir(io, "zig-pkg", .fromMode(0o700));
    const packages = try restore_dir.openDir(io, "zig-pkg", .{ .iterate = true });
    defer packages.close(io);
    const packages_path = try std.fs.path.join(allocator, &.{ compute_path, "dependencies", "zig-pkg" });
    defer allocator.free(packages_path);
    try std.testing.expectError(error.EmptyPackages, dependency.packageSet(allocator, io, packages_path));
    try packages.createDir(io, controller.custody_limits.miz_package_hash, .fromMode(0o700));
    const miz = try packages.openDir(io, controller.custody_limits.miz_package_hash, .{ .iterate = true });
    defer miz.close(io);
    try writeFixtureFile(io, miz, "main.zig", "pub fn main() void {}\n");
    var captured = try dependency.packageSet(allocator, io, packages_path);
    defer captured.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), captured.roots);
    try std.testing.expectEqual(@as(usize, 1), captured.files);
    try dependency.requireSame(allocator, io, packages_path, captured);
    var record = try dependency.capture(allocator, io, options.repository_root, options.git_executable, compute_path);
    defer record.deinit(allocator);
    const native_json = try record.canonical(allocator);
    defer allocator.free(native_json);
    const document = try core.contracts.Document.parse(allocator, native_json, .{});
    defer document.deinit();
    try document.requireCanonical(allocator, native_json);
    try dependency.requireDocument(allocator, io, options.repository_root, options.git_executable, compute_path, record);
    try std.testing.expectError(error.PackageHashMismatch, dependency.verifyZigPackageHashes(
        allocator,
        io,
        options.repository_root,
        options.git_executable,
        compute_path,
        options.zig_executable,
        record,
    ));
    try writeFixtureFile(io, miz, "injected", "tampered\n");
    try std.testing.expectError(error.DependencyChanged, dependency.requireSame(allocator, io, packages_path, captured));
    try std.testing.expectError(error.DependencyChanged, dependency.requireDocument(allocator, io, options.repository_root, options.git_executable, compute_path, record));
}

test "native ELF runtime closure retains sorted canonical dynamic-loader paths" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const python_path = try std.Io.Dir.realPathFileAbsoluteAlloc(io, "/usr/bin/python3", allocator);
    defer allocator.free(python_path);
    const actual = try controller.input_custody.executableRuntimePaths(allocator, io, python_path);
    defer {
        for (actual) |path| allocator.free(path);
        allocator.free(actual);
    }

    try std.testing.expect(actual.len > 0);
    for (actual, 0..) |path, index| {
        const canonical = try std.Io.Dir.realPathFileAbsoluteAlloc(io, path, allocator);
        defer allocator.free(canonical);
        try std.testing.expectEqualStrings(path, canonical);
        if (index > 0) try std.testing.expect(std.mem.lessThan(u8, actual[index - 1], path));
    }
    const invalid: controller.input_custody.ProductionPaths = .{
        .runtime = "/",
        .tools = @as([controller.input_custody.host_tools.len][]const u8, @splat("")),
        .python_stdlib = "/",
    };
    try std.testing.expectError(error.UnsafePath, controller.input_custody.captureProduction(allocator, io, invalid));
}

test "source custody diagnostics cap changes at 64 without losing total" {
    const allocator = std.testing.allocator;
    const source = controller.source_custody;
    const before = try allocator.alloc(source.MetadataEntry, 65);
    defer allocator.free(before);
    const after = try allocator.alloc(source.MetadataEntry, 65);
    defer allocator.free(after);
    for (before, after, 0..) |*old, *new, i| {
        const name = try allocator.print("tracked-{d:0>3}", .{i});
        old.* = .{ .kind = "file", .path = name, .metadata = @as([9]i128, @splat(0)) };
        new.* = .{ .kind = "file", .path = name, .metadata = @as([9]i128, @splat(1)) };
    }
    defer for (before) |item| allocator.free(item.path);
    var changes = try source.metadataChanges(allocator, before, after);
    defer changes.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 65), changes.changed_records);
    try std.testing.expectEqual(@as(usize, 64), changes.changed.len);
    try std.testing.expect(changes.truncated);
    try std.testing.expectEqualStrings("tracked-000", changes.changed[0].path);
    try std.testing.expectEqualStrings("tracked-063", changes.changed[63].path);
}

test "direct shared supervisor retains bounded native success and failure evidence" {
    try directSharedSupervisorFixtures();
}

test "accepted build records replay at the 4 MiB boundary, not the tracked-file limit" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("build-record-replay-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("build record fixture cleanup failed");
    const work = try std.fs.path.join(a, &.{ options.fixture_root, name });
    defer a.free(work);
    const slot = try parent.openDir(io, name, .{ .iterate = true });
    defer slot.close(io);
    try slot.createDir(io, "evidence", .fromMode(0o700));
    const evidence = try slot.openDir(io, "evidence", .{ .iterate = true });
    defer evidence.close(io);
    const boundary = 4 * 1024 * 1024;
    const content = try a.alloc(u8, boundary + 1);
    defer a.free(content);
    @memset(content, 'x');
    for ([_][]const u8{ "build-start.json", "build.json" }, 0..) |record, index| {
        const file = try evidence.createFile(io, record, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writePositionalAll(io, content[0 .. boundary + index], 0);
    }
    var signal = try controller.build_pipeline.installCancellation();
    defer signal.deinit();
    var context: controller.build_pipeline.Context = .{
        .allocator = a,
        .io = io,
        .environ = undefined,
        .runtime = work,
        .repository = options.repository_root,
        .wamr = work,
        .compute = work,
        .git = undefined,
        .tools = undefined,
        .roots = undefined,
        .signal = &signal,
    };
    const accepted = try controller.build_pipeline.readAcceptedRecord(&context, "build-start.json");
    defer a.free(accepted);
    try std.testing.expectEqualSlices(u8, content[0..boundary], accepted);
    try std.testing.expectError(error.FileTooLarge, controller.build_pipeline.readAcceptedRecord(&context, "build.json"));
}

test "late cancellation refuses final build publication after record preparation" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("late-build-cancellation-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("late cancellation fixture cleanup failed");
    const work = try std.fs.path.join(a, &.{ options.fixture_root, name });
    defer a.free(work);
    const slot = try parent.openDir(io, name, .{ .iterate = true });
    defer slot.close(io);
    try slot.createDir(io, "evidence", .fromMode(0o700));
    var signal = try controller.build_pipeline.installCancellation();
    defer signal.deinit();
    var context: controller.build_pipeline.Context = .{
        .allocator = a,
        .io = io,
        .environ = undefined,
        .runtime = work,
        .repository = options.repository_root,
        .wamr = work,
        .compute = work,
        .git = undefined,
        .tools = undefined,
        .roots = undefined,
        .signal = &signal,
    };
    const accepted = .{ .source = "prepared", .runtime = "checked", .image = "checked" };
    context.test_before_publication = struct {
        fn cancel(before: *controller.build_pipeline.Context) void {
            @constCast(before.signal.flag()).store(true, .release);
        }
    }.cancel;
    try std.testing.expectError(error.Cancelled, controller.build_pipeline.publishBuild(&context, accepted));
    try std.testing.expect(signal.flag().load(.acquire));
    const evidence = try slot.openDir(io, "evidence", .{ .iterate = true });
    defer evidence.close(io);
    var iterator = evidence.iterate();
    try std.testing.expect(try iterator.next(io) == null);
}

test "installed native fixture runner is private, create-only and rejects replay" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const cache = try a.dupe(u8, options.fixture_root);
    defer a.free(cache);
    const parent = try std.Io.Dir.openDirAbsolute(io, cache, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("runner-fixture-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("native runner fixture cleanup failed");
    const root = try std.fs.path.join(a, &.{ cache, name });
    defer a.free(root);
    const work_dir = try parent.openDir(io, name, .{ .iterate = true });
    defer work_dir.close(io);
    try work_dir.createDir(io, "fixtures", .fromMode(0o700));
    const fixture_path = try std.fs.path.join(a, &.{ root, "fixtures" });
    defer a.free(fixture_path);
    const runner = try std.fs.path.resolve(a, &.{ options.repository_root, options.fixture_runner });
    defer a.free(runner);
    for ([_]bool{ true, false }) |success| {
        const result = try std.process.run(a, io, .{
            .argv = &.{ runner, "--fixture-root", fixture_path },
            .cwd = .{ .path = options.repository_root },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        defer a.free(result.stdout);
        defer a.free(result.stderr);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = if (success) 0 else 1 }, result.term);
        try std.testing.expectEqual(@as(usize, 0), result.stdout.len + result.stderr.len);
    }
    const output_path = try std.fs.path.join(a, &.{ fixture_path, "native-scenarios.json" });
    defer a.free(output_path);
    const output = try controller.custody_files.readFile(io, output_path, 8192, true);
    try std.testing.expect(output.bytes > 500);
    const published = try std.Io.Dir.openFileAbsolute(io, output_path, .{
        .follow_symlinks = false,
    });
    defer published.close(io);
    const raw = try a.alloc(u8, @intCast(output.bytes));
    defer a.free(raw);
    try std.testing.expectEqual(raw.len, try published.readPositionalAll(io, raw, 0));
    try controller.fixture_contract.verify(a, raw);
    const changed = try std.mem.replaceOwned(u8, a, raw, "\"status\":\"passed\"", "\"status\":\"failed\"");
    defer a.free(changed);
    try std.testing.expectError(error.FixtureChanged, controller.fixture_contract.verify(a, changed));
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), raw, .{ .allocate = .alloc_always });
    parsed.object.getPtr("scenarios").?.array.items.len -= 1;
    const skipped = try std.json.Stringify.valueAlloc(a, parsed, .{});
    defer a.free(skipped);
    try std.testing.expectError(error.FixtureChanged, controller.fixture_contract.verify(a, skipped));
    var signal = try controller.build_pipeline.installCancellation();
    defer signal.deinit();
    var context: controller.build_pipeline.Context = .{
        .allocator = a,
        .io = io,
        .environ = undefined,
        .runtime = root,
        .repository = options.repository_root,
        .wamr = root,
        .compute = root,
        .git = undefined,
        .tools = undefined,
        .roots = undefined,
        .signal = &signal,
        .fixture_report = output,
    };
    try controller.build_pipeline.requireBuildEvidence(&context);
    const tamper = try std.Io.Dir.openFileAbsolute(io, output_path, .{
        .mode = .read_write,
        .follow_symlinks = false,
    });
    defer tamper.close(io);
    try tamper.writePositionalAll(io, " ", 0);
    try std.testing.expectError(error.FixtureChanged, controller.build_pipeline.requireBuildEvidence(&context));
}

test "native command refuses changed executable after use and retains failed record" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const cache = try a.dupe(u8, options.fixture_root);
    defer a.free(cache);
    const parent = try std.Io.Dir.openDirAbsolute(io, cache, .{ .iterate = true });
    defer parent.close(io);
    const name = try a.print("executable-swap-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("executable swap fixture cleanup failed");
    const work = try std.fs.path.join(a, &.{ cache, name });
    defer a.free(work);
    const folder = try parent.openDir(io, name, .{ .iterate = true });
    defer folder.close(io);
    for ([_][]const u8{ "private", "evidence", "fixtures" }) |directory|
        try folder.createDir(io, directory, .fromMode(0o700));
    const fixtures = try folder.openDir(io, "fixtures", .{});
    defer fixtures.close(io);
    try writeFixtureFile(io, fixtures, "scenario", "ok");
    const executable = try std.fs.path.resolve(a, &.{ options.repository_root, options.command_fixture });
    defer a.free(executable);
    const source = try std.Io.Dir.openFileAbsolute(io, executable, .{ .follow_symlinks = false });
    defer source.close(io);
    const file_size: usize = @intCast((try core.private_files.snapshot(source)).size);
    const binary = try a.alloc(u8, file_size);
    defer a.free(binary);
    try std.testing.expectEqual(file_size, try source.readPositionalAll(io, binary, 0));
    for ([_][]const u8{ "runner", "replacement" }) |target| {
        const file = try folder.createFile(io, target, .{
            .exclusive = true,
            .permissions = .fromMode(0o700),
        });
        defer file.close(io);
        try file.writePositionalAll(io, binary, 0);
        try file.sync(io);
    }
    const bound_tool = try std.Io.Dir.realPathFileAbsoluteAlloc(io, "/usr/bin/true", a);
    defer a.free(bound_tool);
    const repeated = @as([controller.input_custody.host_tools.len][]const u8, @splat(bound_tool));
    const runner_path = try std.fs.path.join(a, &.{ work, "runner" });
    defer a.free(runner_path);
    const replacement_path = try std.fs.path.join(a, &.{ work, "replacement" });
    defer a.free(replacement_path);
    var smoke = try core.process.Executable.open(io, runner_path);
    smoke.close(io);
    const private = try folder.openDir(io, "private", .{ .iterate = true });
    defer private.close(io);
    const evidence_dir = try folder.openDir(io, "evidence", .{ .iterate = true });
    defer evidence_dir.close(io);
    const result = try controller.command_adapter.execute(a, io, .{
        .roots = .{
            .source_root = options.repository_root,
            .work = work,
            .runtime = work,
            .zig = bound_tool,
            .producer = bound_tool,
            .fixture_runner = runner_path,
            .supervisor = bound_tool,
            .package_tool = bound_tool,
            .validator = bound_tool,
            .supervisor_fixture = bound_tool,
            .tools = repeated,
        },
        .stage = .fixtures,
        .private_dir = private,
        .evidence_dir = evidence_dir,
        .test_seconds = 4,
        .test_output_limit = 256,
        .test_replacement = replacement_path,
    });
    try std.testing.expect(!result.accepted);
    try std.testing.expect(result.poisoned);
    try std.testing.expectEqualStrings("executable_changed", @tagName(result.primary));
    const public = try evidence_dir.openFile(io, "command-fixtures.json", .{ .follow_symlinks = false });
    defer public.close(io);
    const diagnostic = try private.openFile(io, "fixtures.log", .{ .follow_symlinks = false });
    defer diagnostic.close(io);
    try std.testing.expect((try core.private_files.snapshot(public)).size > 100);
    try std.testing.expect((try core.private_files.snapshot(diagnostic)).size > 0);
}

test "handoff inspect supervises original roles, captures output and refuses missing custody" {
    try handoffInspectFixtures();
    try legacyHandoffInspectLiveFixture();
}
