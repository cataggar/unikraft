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

fn fixture(allocator: std.mem.Allocator, v2: bool) ![]u8 {
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
    for (controller.profile.modes(set), 0..) |mode, i| {
        if (i != 0) try w.writeByte(',');
        try w.print("\"{s}\"", .{@tagName(mode)});
    }
    try w.writeAll("],\"records\":{");
    var first = true;
    for ([_][]const u8{ "build-start.json", "build.json", "boot-inputs.json", "package.json" }) |name| {
        if (!first) try w.writeByte(',');
        first = false;
        try w.print("\"{s}\":\"{s}\"", .{ name, "0" ** 64 });
    }
    for (controller.profile.modes(set)) |mode|
        try w.print(",\"{s}-compute.json\":\"{s}\"", .{ @tagName(mode), "0" ** 64 });
    if (v2) for ([_][]const u8{
        "qcow2-finalization-intent.json",   "qcow2-finalization.json",        "qcow2-acceptance.json",
        "fixed-vhd-derivation-intent.json", "fixed-vhd-derivation-gate.json", "fixed-vhd-derivation.json",
        "final-inspection.json",
    }) |name| try w.print(",\"{s}\":\"{s}\"", .{ name, "0" ** 64 });
    try w.writeAll("}}");
    return writer.toOwnedSlice();
}

test "v1 and v2 frozen result evidence sets reject rehashed fields" {
    const allocator = std.testing.allocator;
    for ([_]bool{ false, true }) |v2| {
        const raw = try fixture(allocator, v2);
        defer allocator.free(raw);
        try std.testing.expectError(error.NonCanonical, controller.records.parseCanonicalResult(allocator, raw));
        const canonical = try controller.records.canonicalAlloc(allocator, raw);
        defer allocator.free(canonical);
        var accepted = try controller.records.parseCanonicalResult(allocator, canonical);
        defer accepted.deinit();
        const document = try core.contracts.Document.parse(allocator, raw, .{});
        defer document.deinit();
        const result = try controller.records.readResult(document.value());
        try std.testing.expectEqual(if (v2) controller.profile.CompatibleRecordSet.tiny_v2_qcow2_derived_vhd else controller.profile.CompatibleRecordSet.tiny_v1_legacy, result.set);
        try std.testing.expectError(error.RecordChanged, controller.records.verifyRecord(result, "build.json", "{}\n"));
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
