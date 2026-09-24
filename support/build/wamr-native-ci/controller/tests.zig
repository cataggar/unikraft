// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const controller = @import("wamr_controller");
const core = @import("hyperv_core");
const options = @import("test_options");

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

test "install-controller rejects incompatible build flags without creating output" {
    const allocator = std.testing.allocator;
    const runtime = try std.fs.path.join(allocator, &.{ options.repository_root, ".d/controller-invalid-target" });
    defer allocator.free(runtime);
    const runtime_flag = try std.fmt.allocPrint(allocator, "-Dcontroller-runtime={s}", .{runtime});
    defer allocator.free(runtime_flag);
    for ([_]struct { triple: []const u8, cpu: []const u8 }{
        .{ .triple = "-Dtarget=x86_64-linux-musl", .cpu = "-Dcpu=x86_64_v2" },
        .{ .triple = "-Dtarget=x86_64-linux-gnu", .cpu = "-Dcpu=x86_64_v3" },
    }) |bad| {
        const result = try std.process.run(allocator, std.testing.io, .{
            .argv = &.{
                options.zig_executable,                   "build",                  "--build-file",
                "support/build/wamr-native-ci/build.zig", "install-controller",     bad.triple,
                bad.cpu,                                  "-Doptimize=ReleaseSafe", runtime_flag,
            },
            .cwd = .{ .path = options.repository_root },
            .stdout_limit = .limited(32 * 1024),
            .stderr_limit = .limited(32 * 1024),
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
        try std.testing.expect(std.mem.indexOf(u8, result.stderr, "install-controller requires -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v2") != null);
        try std.testing.expectError(error.FileNotFound, std.Io.Dir.openDirAbsolute(std.testing.io, runtime, .{}));
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
