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
        .tools = [_][]const u8{"/tool"} ** controller.input_custody.host_tools.len,
    }).get("tool:sh"));
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
        const image_path = try std.fmt.allocPrint(a, "package/{s}", .{plan.bootImage(mode)});
        defer a.free(image_path);
        const slot_path = try std.fmt.allocPrint(a, "boot-{s}", .{@tagName(mode)});
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

test "exact bounded validator JSON and Python tiny differential faults" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const raw_hash = std.fmt.bytesToHex(controller.records.fileIdentity("abc"), .lower);
    const valid = try std.fmt.allocPrint(a,
        "{{\"compute\":{{\"answer\":42}},\"mode\":\"tiny\",\"raw_serial_bytes\":3,\"raw_serial_sha256\":\"{s}\",\"schema\":\"uk.wamr.log-validation\",\"schema_version\":1}}\n",
        .{&raw_hash},
    );
    defer a.free(valid);
    const reference = try std.fs.path.join(a, &.{ options.repository_root, "support/build/wamr-native-ci/run.py" });
    defer a.free(reference);
    const oracle =
        \\import importlib.util,sys,hashlib
        \\s=importlib.util.spec_from_file_location("ci",sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
        \\data=bytes.fromhex(sys.argv[2]); m.read=lambda path, limit: data
        \\try:
        \\ m.native_result("private",{"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data)},b"abc",65536)
        \\ print("accepted")
        \\except (m.Refusal,ValueError,KeyError,TypeError): print("refused")
    ;
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
        const hex = try a.alloc(u8, bytes.len * 2);
        defer a.free(hex);
        const digits = "0123456789abcdef";
        for (bytes, 0..) |byte, at| {
            hex[at * 2] = digits[byte >> 4];
            hex[at * 2 + 1] = digits[byte & 15];
        }
        const result = try std.process.run(a, io, .{
            .argv = &.{ options.python_executable, "-B", "-c", oracle, reference, hex },
            .cwd = .{ .path = options.repository_root },
            .stdout_limit = .limited(64), .stderr_limit = .limited(4096),
        });
        defer a.free(result.stdout);
        defer a.free(result.stderr);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try std.testing.expectEqualStrings(if (native) "accepted\n" else "refused\n", result.stdout);
    }
}

test "native diagnostics retain only bounded allowlisted observations and never acceptance" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try std.fmt.allocPrint(a, "boot-diagnostics-{d}", .{std.os.linux.getpid()});
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
    try writeFixtureFile(io, private, "fixtures.log",
        "test_safe_name (test_adapter.Evidence.test_safe_name) ... ERROR\nPRIVATE_SYNTHETIC_SERIAL_AND_PATH\n");
    var signal = try controller.build_pipeline.installCancellation();
    defer signal.deinit();
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    const compute_path = try std.fs.path.join(a, &.{ runtime, "compute" });
    defer a.free(compute_path);
    var base: controller.build_pipeline.Context = .{
        .allocator = scratch.allocator(), .io = io, .environ = undefined, .runtime = runtime,
        .repository = options.repository_root, .wamr = "",
        .compute = compute_path, .git = undefined, .tools = undefined,
        .roots = undefined, .signal = &signal,
    };
    var ctx: controller.boot_pipeline.Context = .{
        .build_context = &base, .pinned = std.StringHashMap(controller.custody_files.File).init(scratch.allocator()),
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
    const name = try std.fmt.allocPrint(a, "result-evidence-{d}", .{std.os.linux.getpid()});
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
        .allocator = arena.allocator(), .io = io, .environ = undefined, .runtime = path,
        .repository = options.repository_root, .wamr = "", .compute = path,
        .git = undefined, .tools = undefined, .roots = undefined, .signal = &signal,
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
    const name = try std.fmt.allocPrint(a, "boot-recheck-{d}", .{std.os.linux.getpid()});
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
        .allocator = no_growth.allocator(), .io = io, .environ = undefined, .runtime = path,
        .repository = options.repository_root, .wamr = "", .compute = path,
        .git = undefined, .tools = undefined, .roots = undefined, .signal = &signal,
        .build_start_record = try controller.custody_files.readFile(io, start_path, 4096, true),
    };
    base.build_start_record.?.bytes += 1;
    var ctx: controller.boot_pipeline.Context = .{
        .build_context = &base,
        .pinned = std.StringHashMap(controller.custody_files.File).init(a),
    };
    defer ctx.pinned.deinit();
    try ctx.pinned.put("build.json", try controller.custody_files.readFile(io, build_path, 4096, true));
    for (0..3) |_| try std.testing.expectError(error.BuildStartChanged,
        controller.boot_pipeline.testing.revalidateBase(&ctx));
    try evidence.deleteFile(io, "build.json");
    try writeFixtureFile(io, evidence, "build.json", "{\"changed\":true}\n");
    try std.testing.expectError(error.EvidenceChanged,
        controller.boot_pipeline.testing.revalidateBase(&ctx));
}

test "changed raw QCOW2 and derived VHD images never publish compute evidence" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try std.fmt.allocPrint(a, "compute-image-{d}", .{std.os.linux.getpid()});
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
        .allocator = arena.allocator(), .io = io, .environ = undefined, .runtime = path,
        .repository = options.repository_root, .wamr = "", .compute = path,
        .git = undefined, .tools = undefined, .roots = undefined, .signal = &signal,
    };
    var ctx: controller.boot_pipeline.Context = .{
        .build_context = &base,
        .pinned = std.StringHashMap(controller.custody_files.File).init(arena.allocator()),
    };
    defer ctx.pinned.deinit();
    const source = "original-image";
    const hash = std.fmt.bytesToHex(controller.records.fileIdentity(source), .lower);
    ctx.package = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(),
        try std.fmt.allocPrint(arena.allocator(), "{{\"image\":{{\"raw\":{{\"sha256\":\"{s}\"}}}}}}", .{&hash}), .{});
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
        try std.testing.expectError(error.ArtifactChanged,
            controller.boot_pipeline.testing.publishCompute(&ctx, index, .null));
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

test "native tiny build identity admissions match Python build refusal boundary" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const reference = try std.fs.path.join(a, &.{ options.repository_root, "support/build/wamr-native-ci/run.py" });
    defer a.free(reference);
    const identity = try std.fmt.allocPrint(a,
        \\{{"wamr_revision":"{s}","compiler_profile":"unikraft-x86_64","zig_version":"0.16.0","minimal_wasi":false,"development_only":false,"variant":"tiny","jit_mode":null,"files":{{
        \\"embedded.c":"{s}","identity.h":"{s}","libwamr-aot.a":"{s}","tiny.cwasm":"{s}","tiny.wasm":"{s}","wamr_aot.h":"{s}","wamrc":"{s}"}}}}
    , .{ controller.custody_limits.wamr_revision, &([_]u8{'a'} ** 64), &([_]u8{'a'} ** 64), &([_]u8{'a'} ** 64), &([_]u8{'a'} ** 64), &([_]u8{'a'} ** 64), &([_]u8{'a'} ** 64), &([_]u8{'a'} ** 64) });
    defer a.free(identity);
    const python =
        \\import importlib.util,json,sys
        \\s=importlib.util.spec_from_file_location("ci",sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
        \\identity=json.loads(sys.argv[2])
        \\class ImageReached(Exception): pass
        \\m.document=lambda path: identity
        \\m.digest=lambda path: "a"*64
        \\m.source=lambda: (_ for _ in ()).throw(ImageReached())
        \\try: m.check_build()
        \\except ImageReached: print("accepted")
        \\except (m.Refusal, KeyError, TypeError): print("refused")
    ;
    const Mutation = struct { key: []const u8, value: ?std.json.Value = null };
    const changes = [_]Mutation{
        .{ .key = "" },
        .{ .key = "development_only", .value = .{ .bool = true } },
        .{ .key = "development_only", .value = .{ .integer = 1 } },
        .{ .key = "variant", .value = .{ .string = "coremark" } },
        .{ .key = "jit_mode", .value = .{ .string = "fast" } },
        .{ .key = "minimal_wasi", .value = .{ .bool = true } },
        .{ .key = "compiler_profile", .value = .{ .string = "different" } },
        .{ .key = "files", .value = .{ .object = .empty } },
    };
    for (changes, 0..) |change, index| {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const local = arena.allocator();
        var value = try std.json.parseFromSliceLeaky(std.json.Value, local, identity, .{ .allocate = .alloc_always });
        if (change.value) |replacement| try value.object.put(local, change.key, replacement);
        const native = if (controller.build_pipeline.admitPreparedIdentity(value)) |_| true else |_| false;
        const raw = try std.json.Stringify.valueAlloc(a, value, .{});
        defer a.free(raw);
        const result = try std.process.run(a, io, .{
            .argv = &.{ options.python_executable, "-B", "-c", python, reference, raw },
            .cwd = .{ .path = options.repository_root },
            .stdout_limit = .limited(64),
            .stderr_limit = .limited(4096),
        });
        defer a.free(result.stdout);
        defer a.free(result.stderr);
        if (result.term != .exited or result.term.exited != 0)
            std.debug.print("Python build oracle case {d}: {s}\n", .{ index, result.stderr });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try std.testing.expectEqualStrings(if (native) "accepted\n" else "refused\n", result.stdout);
    }
}

fn directSharedSupervisorFixtures() !void {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const cache = try a.dupe(u8, options.fixture_root);
    defer a.free(cache);
    const parent = try std.Io.Dir.openDirAbsolute(io, cache, .{ .iterate = true });
    defer parent.close(io);
    const name = try std.fmt.allocPrint(a, "supervision-fixture-{d}", .{std.os.linux.getpid()});
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
        .{ .name = "ok", .accepted = true, .kind = "exited" },
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
        const repeated = [_][]const u8{bound_tool} ** controller.input_custody.host_tools.len;
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
        const python_reference = try std.fs.path.join(a, &.{ options.repository_root, "support/build/wamr-native-ci/run.py" });
        defer a.free(python_reference);
        const python_oracle = try std.fs.path.join(a, &.{ options.repository_root, "support/build/wamr-native-ci/tests/native_command_oracle.py" });
        defer a.free(python_oracle);
        const record_path = try std.fs.path.join(a, &.{ work, "evidence/command-fixtures.json" });
        defer a.free(record_path);
        const comparison = try std.process.run(a, io, .{
            .argv = &.{ options.python_executable, "-B", python_oracle, python_reference, record_path, log_path },
            .cwd = .{ .path = options.repository_root },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        defer a.free(comparison.stdout);
        defer a.free(comparison.stderr);
        if (comparison.term != .exited or comparison.term.exited != 0)
            std.debug.print("Python command oracle: {s}\n", .{comparison.stderr});
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, comparison.term);
        const value = record.value().object;
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
            context.command_records[@intFromEnum(controller.command_plan.Stage.fixtures)] =
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
    try std.testing.expect(target.permitsInstall(correct, .ReleaseSafe));
    try std.testing.expect(!target.permitsInstall(correct, .Debug));
    try std.testing.expect(!target.permitsInstall(.{}, .ReleaseSafe));
    for ([_]struct { triple: []const u8, cpu: ?[]const u8 }{
        .{ .triple = "x86_64-linux-musl", .cpu = "x86_64_v2" },
        .{ .triple = "x86_64-linux-gnu", .cpu = "x86_64_v3" },
        .{ .triple = "x86_64-linux-gnu", .cpu = null },
    }) |bad| {
        const query = try std.Target.Query.parse(.{
            .arch_os_abi = bad.triple,
            .cpu_features = bad.cpu,
        });
        try std.testing.expect(!target.permitsInstall(query, .ReleaseSafe));
    }
}

test "CLI accepts only closed arguments and no caller-selected profile" {
    const cli = controller.cli;
    const build = try cli.parse(&.{ "uk-wamr-native-ci", "build", "--wamr-source", "/wamr", "--runtime", "/runtime" });
    try std.testing.expectEqual(cli.Action.build, build.action);
    try std.testing.expectEqualStrings("/wamr", build.wamr_source.?);
    try std.testing.expectEqual(cli.Action.describe, (try cli.parse(&.{ "uk-wamr-native-ci", "describe", "--output", "json-v1" })).action);
    try std.testing.expectEqual(cli.Action.boot, (try cli.parse(&.{ "uk-wamr-native-ci", "boot", "--runtime", "/runtime" })).action);
    try std.testing.expectEqual(cli.Action.diagnostics, (try cli.parse(&.{ "uk-wamr-native-ci", "diagnostics", "--runtime", "/runtime" })).action);
    const rejected = [_][]const []const u8{
        &.{"uk-wamr-native-ci"},
        &.{ "uk-wamr-native-ci", "records", "--runtime", "/runtime" },
        &.{ "uk-wamr-native-ci", "describe" },
        &.{ "uk-wamr-native-ci", "describe", "--output", "text" },
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
        const removed = try std.fmt.allocPrint(allocator, ",\"command-{s}.json\":\"{s}\"", .{ stage, &digest });
        defer allocator.free(removed);
        const missing = try std.mem.replaceOwned(u8, allocator, complete, removed, "");
        defer allocator.free(missing);
        const parsed = try core.contracts.Document.parse(allocator, missing, .{});
        defer parsed.deinit();
        try std.testing.expectError(error.MissingRecord, controller.records.readResult(parsed.value()));
    }
    const altered = try std.fmt.allocPrint(allocator, "\"command-adapter.json\":\"{s}\"", .{&digest});
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
    try std.testing.expect(!std.mem.eql(u8, &closure_hash, &([_]u8{0} ** 32)));
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
            .content_sha256 = [_]u8{'a'} ** 64,
            .physical_sha256 = [_]u8{'b'} ** 64,
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
    try std.testing.expectEqualStrings("a53205d77be3b880eb8f8b96679512ba58e2331a", l.wamr_revision);
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
    const missing = try std.fmt.allocPrint(std.testing.allocator, "{s}.gone", .{source});
    defer std.testing.allocator.free(missing);
    try std.testing.expectError(error.FileNotFound, l.readFile(std.testing.io, missing, 1024 * 1024, false));
}

fn writeFixtureFile(io: std.Io, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

fn fixtureGit(allocator: std.mem.Allocator, cwd: []const u8, argv: []const []const u8) !void {
    const result = std.process.run(allocator, std.testing.io, .{
        .argv = argv,
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

fn pythonCustody(allocator: std.mem.Allocator, mode: []const u8, path: []const u8, hash_limit: usize) ![]u8 {
    const run_py = try std.fs.path.join(allocator, &.{ options.repository_root, "support/build/wamr-native-ci/run.py" });
    defer allocator.free(run_py);
    const limit = try std.fmt.allocPrint(allocator, "{d}", .{hash_limit});
    defer allocator.free(limit);
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{
            "python3", "-B", "-c",
            "import importlib.util,sys,pathlib\n" ++
                "s=importlib.util.spec_from_file_location('ci',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)\n" ++
                "m.INPUT_TREE_MAX_BYTES=int(sys.argv[4])\n" ++
                "try:\n" ++
                " r=m.physical_tree_record(pathlib.Path(sys.argv[3]))[0] if sys.argv[2]=='tree' else m.source(pathlib.Path(sys.argv[3]))\n" ++
                " print('ACCEPTED:'+(r['content_sha256'] if sys.argv[2]=='tree' else 'source'))\n" ++
                "except m.Refusal as error:\n" ++
                " print('REFUSED:'+str(error))\n",
            run_py,    mode, path,
            limit,
        },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    defer allocator.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) {
        std.debug.print("Python custody oracle failed: {s}\n", .{result.stderr});
        allocator.free(result.stdout);
        return error.PythonOracleFailed;
    }
    return result.stdout;
}

test "native clean Git custody, stable physical identities and pinned archive refusal" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const base_path = try allocator.dupe(u8, options.fixture_root);
    defer allocator.free(base_path);
    const base = try std.Io.Dir.openDirAbsolute(io, base_path, .{ .iterate = true });
    defer base.close(io);
    const name = try std.fmt.allocPrint(allocator, "custody-fixture-{d}", .{std.os.linux.getpid()});
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
    const run_py = try std.fs.path.join(allocator, &.{ options.repository_root, "support/build/wamr-native-ci/run.py" });
    defer allocator.free(run_py);
    const python = try std.process.run(allocator, io, .{
        .argv = &.{
            "python3",                                                                                                                                                                                                                                                      "-B",   "-c",
            "import importlib.util,sys; s=importlib.util.spec_from_file_location('ci',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); v=m.source(sys.argv[2]); print(v['custody']['content_sha256']); print(v['custody']['physical_sha256'])", run_py, path,
        },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(4096),
    });
    defer allocator.free(python.stdout);
    defer allocator.free(python.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, python.term);
    var lines = std.mem.splitScalar(u8, python.stdout, '\n');
    try std.testing.expectEqualStrings(&captured.custody.content_sha256, lines.next().?);
    try std.testing.expectEqualStrings(&captured.custody.physical_sha256, lines.next().?);
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
    )) |_| return error.OversizedArchiveAccepted else |err|
        try std.testing.expect(err == error.GitExited or err == error.GitOutputOverflow);
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
    const loop_oracle = try pythonCustody(allocator, "source", path, controller.custody_limits.input_bytes);
    defer allocator.free(loop_oracle);
    try std.testing.expect(std.mem.startsWith(u8, loop_oracle, "REFUSED:"));
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
        const entry = try std.fmt.allocPrint(allocator, "inventory-{d:0>3}", .{index});
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

test "input tree deduplicates bounded symlink hash work against Python" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const input = controller.input_custody;
    const base_path = try allocator.dupe(u8, options.fixture_root);
    defer allocator.free(base_path);
    const base = try std.Io.Dir.openDirAbsolute(io, base_path, .{ .iterate = true });
    defer base.close(io);
    const name = try std.fmt.allocPrint(allocator, "input-link-limits-{d}", .{std.os.linux.getpid()});
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
    const boundary_oracle = try pythonCustody(allocator, "tree", hash_path, 32);
    defer allocator.free(boundary_oracle);
    const digest = try std.fmt.allocPrint(allocator, "ACCEPTED:{s}\n", .{&boundary.content_sha256});
    defer allocator.free(digest);
    try std.testing.expectEqualStrings(digest, boundary_oracle);
    try hash_dir.symLink(io, "../a", "duplicate", .{});
    _ = try input.Fixture.treeWithHashLimit(allocator, io, binding, 32);
    const duplicate_oracle = try pythonCustody(allocator, "tree", hash_path, 32);
    defer allocator.free(duplicate_oracle);
    try std.testing.expect(std.mem.startsWith(u8, duplicate_oracle, "ACCEPTED:"));
    try hash_dir.symLink(io, "../e", "extra", .{});
    try std.testing.expectError(error.LimitExceeded, input.Fixture.treeWithHashLimit(allocator, io, binding, 32));
    const excess_oracle = try pythonCustody(allocator, "tree", hash_path, 32);
    defer allocator.free(excess_oracle);
    try std.testing.expectEqualStrings("REFUSED:physical input tree hash limit exceeded\n", excess_oracle);
}

test "missing input symlink target respects Python's absolute 64-component boundary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const input = controller.input_custody;
    const base_path = try allocator.dupe(u8, options.fixture_root);
    defer allocator.free(base_path);
    const base = try std.Io.Dir.openDirAbsolute(io, base_path, .{ .iterate = true });
    defer base.close(io);
    const name = try std.fmt.allocPrint(allocator, "input-missing-depth-{d}", .{std.os.linux.getpid()});
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
    const first = try std.fmt.allocPrint(allocator, "/usr/unikraft-custody-{d}", .{std.os.linux.getpid()});
    defer allocator.free(first);
    try target.appendSlice(allocator, first);
    for (0..62) |_| try target.appendSlice(allocator, "/x");
    try fixture_dir.symLink(io, target.items, "missing", .{});
    const exact = try input.tree(allocator, io, binding);
    try std.testing.expectEqual(@as(usize, 1), exact.symlinks);
    const exact_oracle = try pythonCustody(allocator, "tree", path, controller.custody_limits.input_bytes);
    defer allocator.free(exact_oracle);
    try std.testing.expect(std.mem.startsWith(u8, exact_oracle, "ACCEPTED:"));
    try fixture_dir.deleteFile(io, "missing");
    try target.appendSlice(allocator, "/x");
    try fixture_dir.symLink(io, target.items, "missing", .{});
    try std.testing.expectError(error.UnsafeInputLink, input.tree(allocator, io, binding));
    const excess_oracle = try pythonCustody(allocator, "tree", path, controller.custody_limits.input_bytes);
    defer allocator.free(excess_oracle);
    try std.testing.expect(std.mem.startsWith(u8, excess_oracle, "REFUSED:unsafe physical input tree symlink:"));
}

test "native Bison production entry and sparse byte boundaries" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const base_path = try allocator.dupe(u8, options.fixture_root);
    defer allocator.free(base_path);
    const base = try std.Io.Dir.openDirAbsolute(io, base_path, .{ .iterate = true });
    defer base.close(io);
    const name = try std.fmt.allocPrint(allocator, "bison-limits-{d}", .{std.os.linux.getpid()});
    defer allocator.free(name);
    try base.createDir(io, name, .fromMode(0o700));
    defer base.deleteTree(io, name) catch @panic("Bison limit fixture cleanup failed");
    const directory = try base.openDir(io, name, .{ .iterate = true });
    defer directory.close(io);
    const path = try std.fs.path.join(allocator, &.{ base_path, name });
    defer allocator.free(path);
    for (0..controller.custody_limits.bison_entries) |index| {
        const entry = try std.fmt.allocPrint(allocator, "entry-{d:0>3}", .{index});
        defer allocator.free(entry);
        try writeFixtureFile(io, directory, entry, "");
    }
    const exact = try controller.input_custody.bison(allocator, io, path);
    try std.testing.expectEqual(controller.custody_limits.bison_entries, exact.files);
    try std.testing.expectEqual(@as(usize, 0), exact.bytes);
    try writeFixtureFile(io, directory, "entry-overflow", "");
    try std.testing.expectError(error.LimitExceeded, controller.input_custody.bison(allocator, io, path));
    for (0..controller.custody_limits.bison_entries) |index| {
        const entry = try std.fmt.allocPrint(allocator, "entry-{d:0>3}", .{index});
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
    const name = try std.fmt.allocPrint(allocator, "input-fixture-{d}", .{std.os.linux.getpid()});
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
    const run_py = try std.fs.path.join(allocator, &.{ options.repository_root, "support/build/wamr-native-ci/run.py" });
    defer allocator.free(run_py);
    const python = try std.process.run(allocator, io, .{
        .argv = &.{
            "python3",                                                                                                                                                                                                                  "-B",   "-c",
            "import importlib.util,sys,pathlib; s=importlib.util.spec_from_file_location('ci',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(m.bison_inputs(pathlib.Path(sys.argv[2]))['sha256'])", run_py, bison_path,
        },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(4096),
    });
    defer allocator.free(python.stdout);
    defer allocator.free(python.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, python.term);
    try std.testing.expectEqualStrings(&bison.sha256, std.mem.trimEnd(u8, python.stdout, "\n"));
    try bison_dir.symLink(io, "grammar", "alias", .{});
    const missing_target = try std.fmt.allocPrint(allocator, "/usr/lib/unikraft-custody-{d}/missing", .{std.os.linux.getpid()});
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
    const oracle = try std.process.run(allocator, io, .{
        .argv = &.{
            "python3",                                                                                                                                                                                                                                                                                                                                                                                       "-B",   "-c",
            "import importlib.util,sys,pathlib; s=importlib.util.spec_from_file_location('ci',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); r=m.record_input_paths({'tool:bison':pathlib.Path(sys.argv[2])},{'bison':pathlib.Path(sys.argv[3])}); print(r['aggregate_sha256']); print(r['trees']['bison']['content_sha256']); print(r['trees']['bison']['physical_sha256'])", run_py, path,
            bison_path,
        },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(4096),
    });
    defer allocator.free(oracle.stdout);
    defer allocator.free(oracle.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, oracle.term);
    var oracle_lines = std.mem.splitScalar(u8, oracle.stdout, '\n');
    try std.testing.expectEqualStrings(&expected.aggregate_sha256, oracle_lines.next().?);
    try std.testing.expectEqualStrings(&expected.trees[0].content_sha256, oracle_lines.next().?);
    try std.testing.expectEqualStrings(&expected.trees[0].physical_sha256, oracle_lines.next().?);
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
    const mutated = try std.mem.replaceOwned(u8, allocator, manifest_data.bytes(), "miz-0.2.0-Z3lHlD--2gAdGiguNwbjjdjBmv2f8QlAcwHYRw1De0Sx", "miz-0.2.0-invalid");
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
    const name = try std.fmt.allocPrint(allocator, "dependency-fixture-{d}", .{std.os.linux.getpid()});
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
    const hash_line = try std.fmt.allocPrint(allocator, "{s}\n", .{controller.custody_limits.miz_package_hash});
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
    const run_py = try std.fs.path.join(allocator, &.{ options.repository_root, "support/build/wamr-native-ci/run.py" });
    defer allocator.free(run_py);
    const oracle = try std.process.run(allocator, io, .{
        .argv = &.{
            "python3",                                                                                                                                                                                                                                                                                                                "-B",   "-c",
            "import importlib.util,sys,pathlib; s=importlib.util.spec_from_file_location('ci',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); p=pathlib.Path(sys.argv[2]); r=m.directory_inventory(p,m.MIZ_PACKAGE_HASH,m.package_tree_state(p)); print(r['tree_sha256']); print(r['physical_sha256'])", run_py, packages_path,
        },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(4096),
    });
    defer allocator.free(oracle.stdout);
    defer allocator.free(oracle.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, oracle.term);
    var oracle_lines = std.mem.splitScalar(u8, oracle.stdout, '\n');
    try std.testing.expectEqualStrings(&captured.packages[0].tree_sha256, oracle_lines.next().?);
    try std.testing.expectEqualStrings(&captured.packages[0].physical_sha256, oracle_lines.next().?);
    try dependency.requireSame(allocator, io, packages_path, captured);
    var record = try dependency.capture(allocator, io, options.repository_root, options.git_executable, compute_path);
    defer record.deinit(allocator);
    const native_json = try record.canonical(allocator);
    defer allocator.free(native_json);
    const python_record = try std.process.run(allocator, io, .{
        .argv = &.{
            "python3",                                                                                                                                                                                                                                                "-B",   "-c",
            "import importlib.util,sys,pathlib; s=importlib.util.spec_from_file_location('ci',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(m.canonical_json(m.dependency_custody(pathlib.Path(sys.argv[2]))).decode(),end='')", run_py, compute_path,
        },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(4096),
    });
    defer allocator.free(python_record.stdout);
    defer allocator.free(python_record.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, python_record.term);
    try std.testing.expectEqualStrings(python_record.stdout, native_json);
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

test "native ELF runtime closure matches Python dynamic-loader inventory" {
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
    const run_py = try std.fs.path.join(allocator, &.{ options.repository_root, "support/build/wamr-native-ci/run.py" });
    defer allocator.free(run_py);
    const oracle = try std.process.run(allocator, io, .{
        .argv = &.{
            "python3",                                                                                                                                                                                                                                                 "-B",   "-c",
            "import importlib.util,sys,pathlib; s=importlib.util.spec_from_file_location('ci',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print('\\n'.join(sorted(map(str,m.executable_runtime_paths(pathlib.Path(sys.argv[2]))))))", run_py, python_path,
        },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(4096),
    });
    defer allocator.free(oracle.stdout);
    defer allocator.free(oracle.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, oracle.term);
    var lines = std.mem.splitScalar(u8, oracle.stdout, '\n');
    for (actual) |path| try std.testing.expectEqualStrings(path, lines.next().?);
    try std.testing.expectEqualStrings("", lines.next().?);
    const invalid: controller.input_custody.ProductionPaths = .{
        .runtime = "/",
        .tools = .{""} ** controller.input_custody.host_tools.len,
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
        const name = try std.fmt.allocPrint(allocator, "tracked-{d:0>3}", .{i});
        old.* = .{ .kind = "file", .path = name, .metadata = .{0} ** 9 };
        new.* = .{ .kind = "file", .path = name, .metadata = .{1} ** 9 };
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
    const name = try std.fmt.allocPrint(a, "build-record-replay-{d}", .{std.os.linux.getpid()});
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
    const name = try std.fmt.allocPrint(a, "late-build-cancellation-{d}", .{std.os.linux.getpid()});
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
    const name = try std.fmt.allocPrint(a, "runner-fixture-{d}", .{std.os.linux.getpid()});
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
    const name = try std.fmt.allocPrint(a, "executable-swap-{d}", .{std.os.linux.getpid()});
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
    const repeated = [_][]const u8{bound_tool} ** controller.input_custody.host_tools.len;
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
