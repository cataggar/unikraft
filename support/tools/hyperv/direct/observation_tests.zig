// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const o = @import("observations.zig");
const f = @import("observation_fixtures.zig");
const direct = @import("main.zig");
const core = @import("hyperv_core");
const evidence = @import("evidence");
const t = std.testing;
const a = t.allocator;
const io = t.io;

fn parse(source: []const u8) !o.Document {
    return o.Document.parse(a, .{ .complete = source });
}

const Check = enum {
    group,
    absent,
    inventory,
    os_ready,
    data_ready,
    os_after,
    data_after,
    os_attached,
    data_attached,
    os_reserved,
    data_reserved,
    vm,
    initial_vm,
    allocated,
    deallocated,
    cleanup_os,
    cleanup_data,
    cleanup_vm,
    revoke_data,
};

fn check(kind: Check, source: []const u8) !void {
    const expected = try o.Expectations.init(a, f.scope);
    defer expected.deinit();
    const document = try parse(source);
    defer document.deinit();
    const value = document.value();
    switch (kind) {
        .group => try o.group(value, expected),
        .absent => try o.freshAbsence(value),
        .inventory => _ = try o.inventory(value, expected),
        .os_ready => _ = try o.uploadReady(value, expected, .os, null),
        .data_ready => _ = try o.uploadReady(value, expected, .data, null),
        .os_after => _ = try o.afterUpload(value, expected, .os, "original-os"),
        .data_after => _ = try o.afterUpload(value, expected, .data, "original-data"),
        .os_attached => _ = try o.retainedDisk(value, expected, .os, .allocated, "original-os"),
        .data_attached => _ = try o.retainedDisk(value, expected, .data, .allocated, "original-data"),
        .os_reserved => _ = try o.retainedDisk(value, expected, .os, .deallocated, "original-os"),
        .data_reserved => _ = try o.retainedDisk(value, expected, .data, .deallocated, "original-data"),
        .vm => _ = try o.vm(value, expected, "original-vm"),
        .initial_vm => _ = try o.vm(value, expected, null),
        .allocated => _ = try o.power(value, .allocated),
        .deallocated => _ = try o.power(value, .deallocated),
        .cleanup_os => try o.cleanupDisk(value, expected, .os, "original-os"),
        .cleanup_data => try o.cleanupDisk(value, expected, .data, "original-data"),
        .cleanup_vm => try o.cleanupVm(value, expected, "original-vm"),
        .revoke_data => try o.cleanupRevoke(value, expected, .data, "original-data"),
    }
}

fn changed(kind: Check, source: []const u8, from: []const u8, to: []const u8, expected: ?anyerror) !void {
    try t.expect(std.mem.indexOf(u8, source, from) != null);
    const mutated = try std.mem.replaceOwned(u8, a, source, from, to);
    defer a.free(mutated);
    if (expected) |err| try t.expectError(err, check(kind, mutated)) else try check(kind, mutated);
}

test "success: exact scope-derived IDs and positive Azure observations" {
    const expected = try o.Expectations.init(a, f.scope);
    defer expected.deinit();
    try t.expectEqualStrings(f.group_id, expected.group_id);
    try t.expectEqualStrings(f.vm_id, expected.vm_id);
    try t.expectEqualStrings(f.os_id, expected.os_id);
    try t.expectEqualStrings(f.data_id, expected.data_id);
    try t.expectEqualStrings(f.nic_id, expected.nic_id);
    inline for (.{
        .{ Check.group, f.group },             .{ Check.absent, "false" },
        .{ Check.os_ready, f.os_ready },       .{ Check.data_ready, f.data_ready },
        .{ Check.os_after, f.os_after },       .{ Check.data_after, f.data_after },
        .{ Check.os_attached, f.os_attached }, .{ Check.data_attached, f.data_attached },
        .{ Check.os_reserved, f.os_reserved }, .{ Check.data_reserved, f.data_reserved },
        .{ Check.vm, f.vm },                   .{ Check.initial_vm, f.vm },
        .{ Check.allocated, f.running },       .{ Check.deallocated, f.deallocated },
        .{ Check.cleanup_os, f.os_after },     .{ Check.cleanup_data, f.data_reserved },
        .{ Check.cleanup_vm, f.vm },
    }) |case| try check(case[0], case[1]);
    const vm = try parse(f.vm);
    defer vm.deinit();
    try t.expectEqualStrings("original-vm", (try o.vm(vm.value(), expected, null)).unique_id);
    const os = try parse(f.os_ready);
    defer os.deinit();
    const upload = try o.uploadReady(os.value(), expected, .os, null);
    try t.expectEqualStrings("original-os", upload.unique_id);
    try t.expectEqual(@as(u64, 1049088), upload.upload_bytes);
    const data = try parse(f.data_attached);
    defer data.deinit();
    try t.expectEqual(@as(u64, 4294967296), (try o.retainedDisk(data.value(), expected, .data, .allocated, "original-data")).logical_bytes);
}

test "uint JSON integral floats and decimal strings have distinct exact semantics" {
    const Case = struct { json: []const u8, expected: u64 };
    for ([_]Case{
        .{ .json = "0", .expected = 0 },                                      .{ .json = "\"0\"", .expected = 0 },
        .{ .json = "4.0", .expected = 4 },                                    .{ .json = "4e0", .expected = 4 },
        .{ .json = "4e+0000", .expected = 4 },                                .{ .json = "\"\\u0034\"", .expected = 4 },
        .{ .json = "40e-1", .expected = 4 },                                  .{ .json = "0.04E+2", .expected = 4 },
        .{ .json = "4000000000000000000000000000000000e-33", .expected = 4 }, .{ .json = "7.000000000000000000000000000", .expected = 7 },
        .{ .json = "512.0", .expected = 512 },                                .{ .json = "\"512\"", .expected = 512 },
        .{ .json = "9007199254740991", .expected = o.maximum_uint },          .{ .json = "\"9007199254740991\"", .expected = o.maximum_uint },
        .{ .json = "9007199254740991.000", .expected = o.maximum_uint },      .{ .json = "900719925474099100e-2", .expected = o.maximum_uint },
        .{ .json = "-0", .expected = 0 },                                     .{ .json = "-0.0e+99999999999999", .expected = 0 },
        .{ .json = "0e-99999999999999999999", .expected = 0 },
    }) |case| {
        const document = try parse(case.json);
        defer document.deinit();
        try t.expectEqual(case.expected, try o.uint(document.value()));
    }
    for ([_][]const u8{
        "9007199254740992",   "\"9007199254740992\"",           "18446744073709551616",
        "9007199254740991.1", "0.0000000000000000000000000001", "1e-999999",
        "4.01",               "-1",                             "-0.00001",
        "1e9999999999999999", "null",                           "true",
        "false",              "[]",                             "{}",
        "\"\"",               "\"-0\"",                         "\"-1\"",
        "\"+1\"",             "\" 1\"",                         "\"1 \"",
        "\"1\\n\"",           "\"01\"",                         "\"00\"",
        "\"1e3\"",            "\"1E3\"",                        "\"4.0\"",
        "\"0x10\"",           "\"\\uff11\\uff12\"",             "\"90071992547409910\"",
        "\"NaN\"",            "\"Infinity\"",
    }) |source| {
        const document = try parse(source);
        defer document.deinit();
        try t.expectError(error.InvalidUint, o.uint(document.value()));
    }
    try t.expectEqual(@as(u64, 4), try o.uint(.{ .float = 4.0 }));
    try t.expectError(error.InvalidUint, o.uint(.{ .float = std.math.inf(f64) }));
    try t.expectError(error.InvalidUint, o.uint(.{ .float = std.math.nan(f64) }));
    try t.expectError(error.InvalidUint, o.uint(.{ .integer = -1 }));
}

test "preexisting-group and uncertain absence never establish freshness" {
    for ([_][]const u8{ "true", "null", "\"false\"", "0", "{}", "[]" }) |source|
        try t.expectError(error.ObservationRefused, check(.absent, source));
    for ([_][]const u8{ "", "false true", "false\n{}", "{", "+1", "01", "NaN", "\"\xff\"", "\"\\ud800\"" }) |source|
        try t.expectError(error.MalformedJson, parse(source));
    try t.expectError(error.CaptureFailed, o.Document.parse(a, .failed));
}

test "cleanup-unowned and diagnostics-unowned-group: ownership is exact, extra fields allowed" {
    const refused = error.ObservationRefused;
    try changed(.group, f.group, "resourceGroups", "resourcegroups", refused);
    try changed(.group, f.group, "bbbbbbbb-bbbb-4bbb", "cccccccc-bbbb-4bbb", refused);
    try changed(.group, f.group, "aaaaaaaa-aaaa-4aaa", "aaaaaaaa-aaaa-4baa", refused);
    try changed(.group, f.group, "\"unikraft-run\":\"fixture-direct\"", "\"unikraft-run\":\"Fixture-direct\"", refused);
    try changed(.group, f.group, "\"managed-by\":\"unikraft-hyperv\"", "\"managed-by\":\"Unikraft-hyperv\"", refused);
    try changed(.group, f.group, "\"image-sha256\":\"a", "\"image-sha256\":\"A", refused);
    try changed(.group, f.group, f.tags, "\"tags\":null", refused);
    try changed(.group, f.group, "\"managed-by\":", "\"other-tag\":", refused);
    try changed(.group, f.group, "\"tags\":{", "\"provisioningState\":\"Updating\",\"unused\":2.5,\"tags\":{\"azure-extra\":\"tag\",", null);
    try t.expectError(refused, check(.group, "{}"));
    try t.expectError(refused, check(.group, "null"));
    try t.expectError(error.InvalidObservationShape, check(.group, "[]"));
    try changed(.group, f.group, "\"tags\":{", "\"id\":\"duplicate\",\"tags\":{", error.DuplicateField);
    try changed(.group, f.group, "\"tags\":{", "\"tags\":{\"\\u006danaged-by\":\"duplicate\",", error.DuplicateField);
}

test "inventory allowlist folds only types and IDs, not resource names or tags" {
    try check(.inventory, "[]");
    for ([_][2][]const u8{
        .{ "Microsoft.Compute/disks", "os" },
        .{ "Microsoft.Compute/disks", "data" },
        .{ "Microsoft.Compute/virtualMachines", "vm" },
        .{ "Microsoft.Network/networkInterfaces", "nic" },
        .{ "Microsoft.Network/networkSecurityGroups", "nsg" },
        .{ "Microsoft.Network/virtualNetworks", "vnet" },
    }) |row| {
        const source = try std.fmt.allocPrint(a, "[{{\"id\":\"{s}/providers/{s}/fixture-direct-{s}\",\"name\":\"fixture-direct-{s}\",\"type\":\"{s}\",{s}}}]", .{ f.group_id, row[0], row[1], row[1], row[0], f.tags });
        defer a.free(source);
        try check(.inventory, source);
        try changed(.inventory, source, "Microsoft.", "mICROSOFT.", null);
        try changed(.inventory, source, "/resourceGroups/", "/RESOURCEGROUPS/", null);
        try changed(.inventory, source, "\"name\":\"fixture-direct-", "\"name\":\"Fixture-direct-", error.ObservationRefused);
        try changed(.inventory, source, "\"unikraft-run\":\"fixture-direct\"", "\"unikraft-run\":\"Fixture-direct\"", error.ObservationRefused);
        try changed(.inventory, source, "bbbbbbbb-bbbb-4bbb", "cccccccc-bbbb-4bbb", error.ObservationRefused);
    }
    try check(.inventory, "[" ++ f.os_ready ++ "," ++ f.data_ready ++ "," ++ f.vm ++ "]");
    // jq's all() does not impose row uniqueness; duplicate keys still fail.
    try check(.inventory, "[" ++ f.os_ready ++ "," ++ f.os_ready ++ "]");
    try changed(.inventory, "[" ++ f.os_ready ++ "]", "Microsoft.Compute/disks", "Microsoft.Compute/snapshots", error.ObservationRefused);
    try changed(.inventory, "[" ++ f.os_ready ++ "]", "\"name\":\"fixture-direct-os\"", "\"name\":\"foreign\"", error.ObservationRefused);
    try changed(.inventory, "[" ++ f.os_ready ++ "]", "\"type\":\"Microsoft.Compute/disks\"", "\"type\":null", error.InvalidObservationShape);
    try t.expectError(error.ObservationRefused, check(.inventory, "{}"));
}

test "upload exact size SKU sector size and specialized Gen2 Linux boundary" {
    const refused = error.ObservationRefused;
    try changed(.os_ready, f.os_ready, "\"1049088\"", "1049088.0", null);
    try changed(.os_ready, f.os_ready, "\"1049088\"", "1049088e0", null);
    try changed(.os_ready, f.os_ready, "\"1049088\"", "\"1e6\"", error.InvalidUint);
    try changed(.os_ready, f.os_ready, "\"1049088\"", "\"1049088.0\"", error.InvalidUint);
    try changed(.os_ready, f.os_ready, "\"1049088\"", "1049088.1", error.InvalidUint);
    try changed(.os_ready, f.os_ready, "\"1049088\"", "1049087", refused);
    try changed(.os_ready, f.os_ready, "\"1049088\"", "true", error.InvalidUint);
    try changed(.os_ready, f.os_ready, "\"1049088\"", "null", error.InvalidUint);
    try changed(.os_ready, f.os_ready, "\"logicalSectorSize\":\"512\"", "\"logicalSectorSize\":512.0", null);
    try changed(.os_ready, f.os_ready, "\"logicalSectorSize\":\"512\"", "\"logicalSectorSize\":null", null);
    try changed(.os_ready, f.os_ready, ",\"logicalSectorSize\":\"512\"", "", null);
    try changed(.os_ready, f.os_ready, "\"logicalSectorSize\":\"512\"", "\"logicalSectorSize\":4096", refused);
    try changed(.os_ready, f.os_ready, "\"logicalSectorSize\":\"512\"", "\"logicalSectorSize\":\"0512\"", error.InvalidUint);
    inline for (.{
        .{ "ReadyToUpload", "Unattached" },    .{ "\"Upload\"", "\"Import\"" },
        .{ "StandardSSD_LRS", "Premium_LRS" }, .{ "\"Linux\"", "\"Windows\"" },
        .{ "\"V2\"", "\"V1\"" },               .{ "\"original-os\"", "\"\"" },
        .{ "\"original-os\"", "null" },        .{ "\"Linux\"", "null" },
    }) |row| try changed(.os_ready, f.os_ready, row[0], row[1], refused);
    try changed(.data_ready, f.data_ready, "\"osType\":null", "\"osType\":\"Linux\"", refused);
    try changed(.data_ready, f.data_ready, ",\"osType\":null", "", null);
    try changed(.data_ready, f.data_ready, "\"hyperVGeneration\":null", "\"hyperVGeneration\":\"V1\"", null);
    try changed(.os_ready, f.os_ready, "\"diskState\":", "\"managedBy\":\"ignored-until-after-upload\",\"diskState\":", null);
    const expected = try o.Expectations.init(a, f.scope);
    defer expected.deinit();
    const os = try parse(f.os_ready);
    defer os.deinit();
    try t.expectError(refused, o.uploadReady(os.value(), expected, .os, "replacement"));
    try t.expectError(error.UnknownOriginalIdentity, o.uploadReady(os.value(), expected, .os, ""));
}

test "after upload and allocated/deallocated disk states retain original identity and exact logical bytes" {
    const refused = error.ObservationRefused;
    try changed(.os_after, f.os_after, "\"diskSizeBytes\":\"1048576\"", "\"diskSizeBytes\":1048576.0", null);
    try changed(.os_after, f.os_after, "\"diskSizeBytes\":\"1048576\"", "\"diskSizeBytes\":1049088", refused);
    try changed(.os_after, f.os_after, "\"managedBy\":null", "\"managedBy\":\"\"", refused);
    try changed(.os_after, f.os_after, "\"managedBy\":null", "\"managedBy\":\"" ++ f.vm_id ++ "\"", refused);
    try changed(.data_after, f.data_after, "\"Unattached\"", "\"Attached\"", refused);
    try changed(.data_after, f.data_after, "original-data", "replacement", refused);
    try changed(.data_attached, f.data_attached, "\"Attached\"", "\"Reserved\"", refused); // running-reserved
    try changed(.data_reserved, f.data_reserved, "\"Reserved\"", "\"Attached\"", refused); // retained-attached
    try changed(.os_reserved, f.os_reserved, "\"Reserved\"", "\"Attached\"", refused); // final-attached
    try changed(.data_reserved, f.data_reserved, "\"Reserved\"", "\"Unattached\"", refused); // retained-unattached
    try changed(.data_reserved, f.data_reserved, "original-data", "replacement", refused); // identity-drift
    try changed(.data_attached, f.data_attached, "\"managedBy\":\"" ++ f.vm_id ++ "\"", "\"managedBy\":null", refused);
    try changed(.data_reserved, f.data_reserved, "\"managedBy\":\"" ++ f.vm_id ++ "\"", "\"managedBy\":null", refused);
    try changed(.data_attached, f.data_attached, "/virtualMachines/", "/virtualmachines/", refused);
    try changed(.os_reserved, f.os_reserved, "\"diskSizeBytes\":1048576", "\"diskSizeBytes\":\"1e6\"", error.InvalidUint);
    try changed(.os_reserved, f.os_reserved, "\"diskSizeBytes\":1048576", "\"diskSizeBytes\":1048575", refused);
    try changed(.os_after, f.os_after, ",\"logicalSectorSize\":\"512\"", "", null);
    try changed(.os_after, f.os_after, "\"osType\":\"Linux\"", "\"osType\":\"ignored-later\"", null);
}

test "VM profile every compared field and mandatory original attachments" {
    const refused = error.ObservationRefused;
    inline for (.{
        .{ "\"securityType\":\"Standard\"", "\"securityType\":\"TrustedLaunch\"" },
        .{ "\"vmSize\":\"Standard_D2s_v5\"", "\"vmSize\":\"unapproved-size\"" },
        .{ "\"enabled\":true", "\"enabled\":false" },
        .{ "\"enabled\":true", "\"enabled\":\"true\"" },
        .{ "\"diskControllerType\":\"SCSI\"", "\"diskControllerType\":\"NVMe\"" },
        .{ "\"createOption\":\"Attach\"", "\"createOption\":\"FromImage\"" },
        .{ "\"caching\":\"ReadOnly\"", "\"caching\":\"None\"" },
        .{ "\"caching\":\"None\"", "\"caching\":\"ReadWrite\"" },
        .{ "\"deleteOption\":\"Detach\"", "\"deleteOption\":\"Delete\"" },
        .{ "\"lun\":\"7\"", "\"lun\":6" },
        .{ "/disks/fixture-direct-os", "/disks/replacement" },
        .{ "/disks/fixture-direct-data", "/disks/replacement" },
        .{ "/networkInterfaces/fixture-direct-nic", "/networkInterfaces/replacement" },
        .{ "/networkInterfaces/", "/networkinterfaces/" },
        .{ "\"vmId\":\"original-vm\"", "\"vmId\":\"replacement\"" },
        .{ "\"vmId\":\"original-vm\"", "\"vmId\":\"\"" },
        .{ "\"vmId\":\"original-vm\"", "\"vmId\":null" },
    }) |row| try changed(.vm, f.vm, row[0], row[1], refused);
    try changed(.initial_vm, f.vm, "\"vmId\":\"original-vm\"", "\"vmId\":\"first-accepted-vm\"", null);
    try changed(.vm, f.vm, "\"securityProfile\":", "\"osProfile\":null,\"securityProfile\":", null);
    try changed(.vm, f.vm, "\"securityProfile\":", "\"osProfile\":{},\"securityProfile\":", refused);
    try changed(.vm, f.vm, "\"enabled\":true", "\"enabled\":true,\"storageUri\":null", null);
    try changed(.vm, f.vm, "\"enabled\":true", "\"enabled\":true,\"storageUri\":\"https://foreign\"", refused);
    try changed(.vm, f.vm, "\"lun\":\"7\"", "\"lun\":7.0", null);
    try changed(.vm, f.vm, "\"lun\":\"7\"", "\"lun\":\"7.0\"", error.InvalidUint);
    try changed(.vm, f.vm, "\"lun\":\"7\"", "\"lun\":null", error.InvalidUint);
    try changed(.vm, f.vm, "\"dataDisks\":[", "\"dataDisks\":[{},", refused);
    try changed(.vm, f.vm, "\"networkInterfaces\":[", "\"networkInterfaces\":[{},", refused);
    try changed(.vm, f.vm, "\"networkInterfaces\":[{\"id\":\"" ++ f.nic_id ++ "\"}]", "\"networkInterfaces\":[]", refused);
    try changed(.vm, f.vm, "\"networkInterfaces\":[{\"id\":\"" ++ f.nic_id ++ "\"}]", "\"networkInterfaces\":null", refused);
    try changed(.vm, f.vm, "\"networkInterfaces\":[{\"id\":\"" ++ f.nic_id ++ "\"}]", "\"networkInterfaces\":{\"0\":{\"id\":\"" ++ f.nic_id ++ "\"}}", error.InvalidObservationShape);
    try changed(.vm, f.vm, "\"securityProfile\":", "\"unobserved\":{\"future\":1.5},\"securityProfile\":", null);
    try changed(.vm, f.vm, "\"hardwareProfile\":{\"vmSize\":\"Standard_D2s_v5\"}", "\"hardwareProfile\":null", refused);
}

test "stopped-boot1 stopped-boot2 stopped-both are allocated; stopped is never deallocated" {
    try check(.allocated, f.running);
    try check(.allocated, f.stopped);
    try t.expectError(error.ObservationRefused, check(.deallocated, f.stopped)); // retained/final-stopped
    try t.expectError(error.ObservationRefused, check(.allocated, f.deallocated));
    const stopped = try parse(f.stopped);
    defer stopped.deinit();
    try t.expectEqual(o.PowerState.stopped, try o.power(stopped.value(), .allocated));
    for ([_][]const u8{ "PowerState/starting", "PowerState/deallocating", "PowerState/unknown", "PowerState/Running", "PowerState/stopped (deallocated)" }) |code|
        try changed(.allocated, f.running, "PowerState/running", code, error.ObservationRefused);
}

test "malformed-power: exactly one status source and exactly one string PowerState code" {
    const Case = struct { source: []const u8, err: anyerror };
    for ([_]Case{
        .{ .source = "{}", .err = error.InvalidPowerShape },
        .{ .source = "null", .err = error.InvalidPowerShape },
        .{ .source = "{\"statuses\":[]}", .err = error.InvalidPowerCount },
        .{ .source = "{\"statuses\":null}", .err = error.InvalidPowerShape },
        .{ .source = "{\"statuses\":{\"0\":{\"code\":\"PowerState/running\"}}}", .err = error.InvalidPowerShape },
        .{ .source = "{\"instanceView\":{}}", .err = error.InvalidPowerShape },
        .{ .source = "{\"instanceView\":null}", .err = error.InvalidPowerShape },
        .{ .source = "{\"statuses\":[],\"instanceView\":null}", .err = error.InvalidPowerShape },
        .{ .source = "{\"statuses\":null,\"instanceView\":{\"statuses\":[]}}", .err = error.InvalidPowerShape },
        .{ .source = "{\"statuses\":[{\"code\":null}]}", .err = error.InvalidPowerCode },
        .{ .source = "{\"statuses\":[{}]}", .err = error.InvalidPowerCode },
        .{ .source = "{\"statuses\":[{\"code\":1}]}", .err = error.InvalidPowerCode },
        .{ .source = "{\"statuses\":[{\"code\":\"ProvisioningState/succeeded\"}]}", .err = error.InvalidPowerCount },
        .{ .source = "{\"statuses\":[{\"code\":\"powerState/running\"}]}", .err = error.InvalidPowerCount },
        .{ .source = "{\"statuses\":[{\"code\":\"PowerState/running\"},{\"code\":\"PowerState/running\"}]}", .err = error.InvalidPowerCount },
        .{ .source = "{\"statuses\":[{\"code\":\"PowerState/running\"},{\"code\":\"PowerState/stopped\"}]}", .err = error.InvalidPowerCount },
        .{ .source = "{\"statuses\":[{\"code\":\"PowerState/running\"},{\"code\":null}]}", .err = error.InvalidPowerCode },
        .{ .source = "{\"statuses\":[{\"code\":\"PowerState/running\",\"code\":\"PowerState/stopped\"}]}", .err = error.DuplicateField },
    }) |case| try t.expectError(case.err, check(.allocated, case.source));
    try check(.allocated, "{\"statuses\":[{\"code\":\"ProvisioningState/failed\",\"unknown\":true},{\"code\":\"PowerState/running\",\"displayStatus\":\"ignored\"}],\"unknown\":1.5}");
}

test "cleanup diagnostics require known original UUIDs; unknown identity is not cleanup authority" {
    const expected = try o.Expectations.init(a, f.scope);
    defer expected.deinit();
    const vm = try parse(f.vm);
    defer vm.deinit();
    const data = try parse(f.data_reserved);
    defer data.deinit();
    for ([_]?[]const u8{ null, "" }) |unknown| {
        try t.expectError(error.UnknownOriginalIdentity, o.cleanupVm(vm.value(), expected, unknown));
        try t.expectError(error.UnknownOriginalIdentity, o.cleanupDisk(data.value(), expected, .data, unknown));
        try t.expectError(error.UnknownOriginalIdentity, o.cleanupRevoke(data.value(), expected, .data, unknown));
    }
    try t.expectError(error.UnknownOriginalIdentity, o.vm(vm.value(), expected, ""));
    try t.expectError(error.UnknownOriginalIdentity, o.afterUpload(data.value(), expected, .data, ""));
    try t.expectError(error.UnknownOriginalIdentity, o.retainedDisk(data.value(), expected, .data, .deallocated, ""));
    try changed(.cleanup_vm, f.vm, "\"vmId\":\"original-vm\"", "\"vmId\":\"replacement\"", error.ObservationRefused);
    try changed(.cleanup_data, f.data_reserved, "original-data", "replacement", error.ObservationRefused);
    try changed(.cleanup_data, f.data_reserved, "\"managedBy\":\"" ++ f.vm_id ++ "\"", "\"managedBy\":\"foreign-vm\"", error.ObservationRefused);
    try changed(.cleanup_data, f.data_reserved, "\"managedBy\":\"" ++ f.vm_id ++ "\"", "\"managedBy\":null", null);
    try check(.cleanup_data, f.data_after); // missing managedBy is null
    try changed(.cleanup_vm, f.vm, "\"vmSize\":\"Standard_D2s_v5\"", "\"vmSize\":\"not-a-new-admission\"", null);
    try changed(.revoke_data, f.data_ready, "\"diskState\":", "\"managedBy\":\"upload-provider\",\"diskState\":", null);
    try changed(.revoke_data, f.data_ready, "original-data", "replacement", error.ObservationRefused);
}

test "grant uppercase lowercase alternate domain ports and exact private shape" {
    for ([_][]const u8{ f.grant, f.lower_grant, f.storage_grant }) |source| {
        const grant = try o.Grant.parse(a, .{ .complete = source });
        defer grant.deinit();
        try t.expect(std.mem.startsWith(u8, grant.endpoint(), "https://"));
        try t.expect(std.mem.indexOfAny(u8, grant.endpoint(), "?&") == null);
    }
    for ([_][]const u8{
        "{}",                                                  "null",                                           "[]",                         "\"string\"",
        "{\"accessSAS\":\"secret\",\"accessSas\":\"secret\"}", "{\"accessSAS\":\"secret\",\"unexpected\":true}", "{\"accesssas\":\"secret\"}", "{\"AccessSAS\":\"secret\"}",
    }) |source| try t.expectError(error.InvalidGrantShape, o.Grant.parse(a, .{ .complete = source }));
    for ([_][]const u8{ "null", "1", "true", "[]", "{}" }) |value| {
        const source = try std.fmt.allocPrint(a, "{{\"accessSAS\":{s}}}", .{value});
        defer a.free(source);
        try t.expectError(error.InvalidGrantValue, o.Grant.parse(a, .{ .complete = source }));
    }
    try t.expectError(error.DuplicateField, o.Grant.parse(a, .{ .complete = "{\"accessSAS\":\"first\",\"accessSAS\":\"second\"}" }));
    try t.expectError(error.DuplicateField, o.Grant.parse(a, .{ .complete = "{\"accessSAS\":\"first\",\"access\\u0053AS\":\"second\"}" }));
    try t.expectError(error.MalformedJson, o.Grant.parse(a, .{ .complete = "{\"accessSAS\":" }));
    try t.expectError(error.MalformedJson, o.Grant.parse(a, .{ .complete = "{\"accessSAS\":4.0}" }));
    try t.expectError(error.CaptureFailed, o.Grant.parse(a, .failed));
}

fn grantJson(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, .{ .accessSAS = url }, .{});
}

test "grant URL narrow hosts, domain boundary, optional ports and nonempty path and query" {
    for ([_][]const u8{
        "http://fixture.blob.core.windows.net/u?q",
        "HTTPS://fixture.blob.core.windows.net/u?q",
        "https://Fixture.blob.core.windows.net/u?q",
        "https://fixture.blob.core.windows.net.evil.invalid/u?q",
        "https://fixture.blob.storage.azure.net.evil.invalid/u?q",
        "https://fixture.blob.core.windows.net@evil.invalid/u?q",
        "https://user@fixture.blob.core.windows.net/u?q",
        "https://fixture.blob.core.windows.net\\@evil.invalid/u?q",
        "https://fixture.blob.core.windows.net:80/u?q",
        "https://fixture.blob.core.windows.net:0443/u?q",
        "https://fixture.blob.core.windows.net:443:8443/u?q",
        "https://fixture.blob.core.windows.net:/u?q",
        "https://a.blob.core.windows.net/u?q",
        "https://.blob.core.windows.net/u?q",
        "https://-a.blob.core.windows.net/u?q",
        "https://a_b.blob.core.windows.net/u?q",
        "https://fixture.blob.core.windows.net/?q",
        "https://fixture.blob.core.windows.net/u?",
        "https://fixture.blob.core.windows.net/u",
        "https://fixture.blob.core.windows.net/u?q?extra",
        "https://fixture.blob.core.windows.net/u#fragment?q",
        "https://fixture.blob.core.windows.net/u?q#fragment",
        "https://fixture.blob.core.windows.net/u p?q",
        "https://fixture.blob.core.windows.net/u?q\n",
        "https://fixture.blob.core.windows.net/u?q\t",
        "https://fixture.blob.core.windows.net/u?q\r",
        "https://fixture.blob.core.windows.net/u?q\u{a0}",
        "https://fixture.blob.core.windows.net/u\u{2000}p?q",
    }) |url| {
        const source = try grantJson(a, url);
        defer a.free(source);
        try t.expectError(error.InvalidGrantValue, o.Grant.parse(a, .{ .complete = source }));
    }
    for ([_][]const u8{
        "https://ab.blob.core.windows.net/p?q",
        "https://md-fixture.z99.blob.storage.azure.net/p?sig=encoded%2Bvalue%3D&sv=fixture",
        "https://fixture.blob.core.windows.net:8443/p%20ath?q=encoded%20space",
        // Observation regex parity only: the native uploader separately imposes
        // its stricter endpoint/SAS contract. Do not silently move that policy.
        "https://a..b.blob.core.windows.net/p?q",
        "https://fixture.blob.core.windows.net/p?q=\x00",
    }) |url| {
        const source = try grantJson(a, url);
        defer a.free(source);
        const grant = try o.Grant.parse(a, .{ .complete = source });
        defer grant.deinit();
    }
}

test "grant retains native private-JSON 4096-byte string and 65536-byte document boundaries" {
    const prefix = "https://fixture.blob.core.windows.net/p?q=";
    const url = prefix ++ "x" ** (4096 - prefix.len);
    const source = try grantJson(a, url);
    defer a.free(source);
    const grant = try o.Grant.parse(a, .{ .complete = source });
    defer grant.deinit();
    try t.expectEqualStrings("https://fixture.blob.core.windows.net/p", grant.endpoint());
    const too_long = try grantJson(a, url ++ "x");
    defer a.free(too_long);
    try t.expectError(error.ValueTooLong, o.Grant.parse(a, .{ .complete = too_long }));
    const padded = try a.alloc(u8, 65537);
    defer a.free(padded);
    @memset(padded, ' ');
    @memcpy(padded[0..source.len], source);
    const maximum = try o.Grant.parse(a, .{ .complete = padded[0..65536] });
    defer maximum.deinit();
    try t.expectError(error.InputTooLarge, o.Grant.parse(a, .{ .complete = padded }));
}

const input: evidence.EvidenceInput = .{
    .run_id = "11111111111111111111111111111111".*,
    .disk_id = "22222222222222222222222222222222".*,
    .sectors = 8388608,
    .lun = 7,
};

test "diagnostic wrapper preserves decoded NUL ANSI CRLF and empty canonical-incomplete input" {
    const decoded = try o.Diagnostics.decode(a, .{ .complete = "\"\\u0000banner\\u0000\\u001b[0m\\r\\ntext\\n\\u0000\\u0000\"" }, .primary);
    defer decoded.deinit();
    try t.expectEqualStrings("\x00banner\x00\x1b[0m\r\ntext\n\x00\x00", try decoded.evidenceBytes());
    const empty = try o.Diagnostics.decode(a, .{ .complete = "\"\"" }, .primary);
    defer empty.deinit();
    try t.expectEqual(@as(usize, 0), (try empty.evidenceBytes()).len);
    try t.expectError(error.EvidenceIncomplete, direct.serialFirst(try empty.evidenceBytes(), .per_boot, input));
    for ([_][]const u8{ "null", "true", "123", "{}", "[]", "{\"unexpected\":\"not a JSON string\"}" }) |source|
        try t.expectError(error.InvalidSerialWrapper, o.Diagnostics.decode(a, .{ .complete = source }, .primary));
    for ([_][]const u8{ "", "\"a\" \"b\"", "\"\x00\"", "\"\\x00\"", "\"unterminated", "{]" }) |source| {
        try t.expectError(error.MalformedJson, o.Diagnostics.decode(a, .{ .complete = source }, .primary));
    }
    try t.expectError(error.CaptureFailed, o.Diagnostics.decode(a, .failed, .primary));
    try t.expectError(error.CaptureFailed, o.Diagnostics.decode(a, .failed, .failure_only));
}

test "decoded primary bytes use unchanged canonical serial modes; failure-only bytes never grant acceptance" {
    const first = f.first_serial ++ "\x00\x00";
    const first_json = try std.json.Stringify.valueAlloc(a, first, .{});
    defer a.free(first_json);
    const decoded_first = try o.Diagnostics.decode(a, .{ .complete = first_json }, .primary);
    defer decoded_first.deinit();
    inline for (.{ direct.SerialMode.per_boot, .cumulative, .azure_cumulative }) |mode| {
        const second = if (mode == .per_boot) f.second_serial else if (mode == .cumulative) first ++ f.second_serial else f.first_serial ++ f.second_serial;
        const wrapper = try std.json.Stringify.valueAlloc(a, second ++ "\x00", .{});
        defer a.free(wrapper);
        const decoded_second = try o.Diagnostics.decode(a, .{ .complete = wrapper }, .primary);
        defer decoded_second.deinit();
        const boot1 = try direct.serialFirst(try decoded_first.evidenceBytes(), mode, input);
        try direct.serialSecond(try decoded_second.evidenceBytes(), mode, input, boot1);
        const diagnostics = try o.Diagnostics.decode(a, .{ .complete = wrapper }, .failure_only);
        defer diagnostics.deinit();
        try t.expectEqualStrings(second ++ "\x00", diagnostics.privateBytes());
        try t.expectError(error.FailureOnlyDiagnostics, diagnostics.evidenceBytes());
    }
    const failure = try o.Diagnostics.decode(a, .{ .complete = "\"UK_HYPERV_ACCEPTANCE_FAIL:fixture\\n\"" }, .primary);
    defer failure.deinit();
    try t.expectError(error.GuestFailure, direct.serialFirst(try failure.evidenceBytes(), .per_boot, input));
}

test "ARM parsing keeps arbitrary extra numeric fields but rejects duplicate or unbounded documents" {
    const document = try parse("{\"future\":1e99999,\"fraction\":0.5,\"negative\":-100,\"nested\":[]}");
    defer document.deinit();
    try t.expectError(error.DuplicateField, parse("{\"a\":1,\"\\u0061\":2}"));
    try t.expectError(error.DuplicateField, parse("{\"extra\":{\"a\":1,\"a\":2}}"));
    const oversized = try a.alloc(u8, o.maximum_capture_bytes + 1);
    defer a.free(oversized);
    @memset(oversized, ' ');
    try t.expectError(error.InputTooLarge, parse(oversized));
    const depth = "[" ** 33 ++ "0" ++ "]" ** 33;
    try t.expectError(error.TooDeep, parse(depth));
    try t.expectError(error.TooManyItems, parse("[0" ++ ",0" ** 4096 ++ "]"));
    try t.expectError(error.TooManyTokens, parse("[" ++ ("[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]," ** 4095) ++ "[]]"));
    const boundary = try a.alloc(u8, o.maximum_capture_bytes);
    defer a.free(boundary);
    @memset(boundary, 'x');
    boundary[0] = '"';
    boundary[boundary.len - 1] = '"';
    const maximum = try o.Diagnostics.decode(a, .{ .complete = boundary }, .primary);
    defer maximum.deinit();
    try t.expectEqual(o.maximum_capture_bytes - 2, (try maximum.evidenceBytes()).len);
    const large_grant = try grantJson(a, "https://fixture.blob.core.windows.net/p?q=" ++ "x" ** 4096);
    defer a.free(large_grant);
    try t.expectError(error.ValueTooLong, o.Grant.parse(a, .{ .complete = large_grant }));
}

test "failure categories are explicit and do not conflate primary refusal with malformed/capture/local errors" {
    try t.expectEqual(o.FailureClass.refused, o.failureClass(error.ObservationRefused));
    try t.expectEqual(o.FailureClass.refused, o.failureClass(error.UnknownOriginalIdentity));
    try t.expectEqual(o.FailureClass.filter_error, o.failureClass(error.InvalidPowerCode));
    try t.expectEqual(o.FailureClass.filter_error, o.failureClass(error.InvalidUint));
    try t.expectEqual(o.FailureClass.filter_error, o.failureClass(error.InvalidSerialWrapper));
    try t.expectEqual(o.FailureClass.malformed, o.failureClass(error.DuplicateField));
    try t.expectEqual(o.FailureClass.malformed, o.failureClass(error.MalformedJson));
    try t.expectEqual(o.FailureClass.capture, o.failureClass(error.CaptureFailed));
    try t.expectEqual(o.FailureClass.local, o.failureClass(error.OutOfMemory));
    try t.expectEqual(o.FailureClass.local, o.failureClass(error.PrivateHandoffNotDurable));
}

const WipeCheck = struct {
    live: usize = 0,
    allocations: usize = 0,
    dirty: bool = false,
    allowance: ?usize = null,

    fn allocator(self: *WipeCheck) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = std.mem.Allocator.noResize,
            .remap = std.mem.Allocator.noRemap,
            .free = free,
        } };
    }

    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, address: usize) ?[*]u8 {
        const self: *WipeCheck = @ptrCast(@alignCast(context));
        if (self.allowance) |remaining| {
            if (remaining == 0) return null;
            self.allowance = remaining - 1;
        }
        const bytes = a.rawAlloc(len, alignment, address) orelse return null;
        @memset(bytes[0..len], 0xa5);
        self.live += 1;
        self.allocations += 1;
        return bytes;
    }

    fn free(context: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, address: usize) void {
        const self: *WipeCheck = @ptrCast(@alignCast(context));
        self.dirty = self.dirty or !std.mem.allEqual(u8, bytes, 0);
        self.live -= 1;
        a.rawFree(bytes, alignment, address);
    }

    fn verify(self: WipeCheck) !void {
        try t.expectEqual(@as(usize, 0), self.live);
        try t.expect(!self.dirty);
    }
};

fn sensitiveLifecycle(allocator: std.mem.Allocator) !void {
    const document = try o.Document.parse(allocator, .{ .complete = "{\"future\":1.0,\"private\":\"SYNTHETIC_ONLY\",\"nested\":[\"\\u0000\\u001b\"]}" });
    defer document.deinit();
    const grant = try o.Grant.parse(allocator, .{ .complete = f.grant });
    defer grant.deinit();
    const diagnostics = try o.Diagnostics.decode(allocator, .{ .complete = "\"\\u0000SYNTHETIC_ONLY\\r\\n\"" }, .failure_only);
    defer diagnostics.deinit();
}

test "sensitive parser and grant allocations are wiped on success, failure and every allocation failure" {
    var baseline: WipeCheck = .{};
    try sensitiveLifecycle(baseline.allocator());
    try baseline.verify();
    for (0..baseline.allocations + 1) |allowed| {
        var observer: WipeCheck = .{ .allowance = allowed };
        sensitiveLifecycle(observer.allocator()) catch |err| try t.expect(err == error.OutOfMemory);
        try observer.verify();
    }
    for ([_][]const u8{
        "{\"token\":\"SYNTHETIC_ONLY\",\"token\":\"duplicate\"}",
        "{\"token\":\"SYNTHETIC_ONLY\",\"broken\":[}",
        "{\"accessSAS\":\"https://foreign.invalid/?sig=SYNTHETIC_ONLY\"}",
        "{\"accessSAS\":\"SYNTHETIC_ONLY\",\"extra\":true}",
    }) |source| {
        var observer: WipeCheck = .{};
        if (o.Document.parse(observer.allocator(), .{ .complete = source })) |document| document.deinit() else |_| {}
        if (o.Grant.parse(observer.allocator(), .{ .complete = source })) |grant| grant.deinit() else |_| {}
        try observer.verify();
    }
}

const PrivateFixture = struct {
    relative: []const u8,
    directory: core.private_files.Directory,

    fn init() !PrivateFixture {
        try std.Io.Dir.cwd().createDirPath(io, ".d");
        var random: [16]u8 = undefined;
        io.random(&random);
        const name = std.fmt.bytesToHex(random, .lower);
        const relative = try std.fmt.allocPrint(a, ".d/observations-{s}", .{name});
        errdefer a.free(relative);
        try std.Io.Dir.cwd().createDir(io, relative, .fromMode(0o700));
        errdefer std.Io.Dir.cwd().deleteDir(io, relative) catch {};
        const absolute = try std.Io.Dir.cwd().realPathFileAlloc(io, relative, a);
        defer a.free(absolute);
        return .{ .relative = relative, .directory = try core.private_files.Directory.open(io, absolute) };
    }

    fn deinit(self: PrivateFixture) void {
        self.directory.close(io);
        std.Io.Dir.cwd().deleteTree(io, self.relative) catch @panic("observation fixture cleanup failed");
        a.free(self.relative);
    }
};

test "grant handoff creates only durable owner-private SAS and request files without exposing query" {
    var fixture = try PrivateFixture.init();
    defer fixture.deinit();
    var locked = try fixture.directory.lock(io);
    defer locked.close(io);
    const grant = try o.Grant.parse(a, .{ .complete = f.grant });
    defer grant.deinit();
    try grant.writePrivateFiles(a, io, &locked, f.scope.os_vhd);
    var sas = try fixture.directory.readSensitive(io, a, "sas.txt", 4096, null);
    defer sas.deinit();
    try t.expectEqualStrings("sv=fixture&sig=SYNTHETIC_ONLY", sas.bytes());
    var request = try fixture.directory.readSensitive(io, a, "request.json", 4096, null);
    defer request.deinit();
    try t.expectEqualStrings(
        "{\"schema\":\"unikraft.hyperv.managed-disk-page-worker\",\"schema_version\":1," ++
            "\"endpoint\":\"https://fixture.blob.core.windows.net/upload\",\"path\":\"/synthetic-only/os.vhd\"," ++
            "\"size\":1049088,\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n",
        request.bytes(),
    );
    try t.expect(std.mem.indexOf(u8, request.bytes(), "SYNTHETIC_ONLY") == null);
    try t.expectError(error.PathAlreadyExists, grant.writePrivateFiles(a, io, &locked, f.scope.os_vhd));
    var public = std.Io.Writer.Allocating.init(a);
    defer public.deinit();
    const diagnostics = try o.Diagnostics.decode(a, .{ .complete = "\"SYNTHETIC_ONLY\"" }, .failure_only);
    defer diagnostics.deinit();
    try public.writer.print("{f} {f}", .{ grant, diagnostics });
    try t.expectEqualStrings("AzureGrant(redacted) AzureDiagnostics(redacted)", public.written());
    locked.close(io);
    try t.expectError(error.LockNotHeld, grant.writePrivateFiles(a, io, &locked, f.scope.os_vhd));
}

test "partial private handoff never replaces an existing request or reports success" {
    var fixture = try PrivateFixture.init();
    defer fixture.deinit();
    var locked = try fixture.directory.lock(io);
    defer locked.close(io);
    try t.expectEqual(core.private_files.CommitStatus.durable, (try locked.createImmutable(io, "request.json", "original")).status);
    const grant = try o.Grant.parse(a, .{ .complete = f.grant });
    defer grant.deinit();
    try t.expectError(error.PathAlreadyExists, grant.writePrivateFiles(a, io, &locked, f.scope.os_vhd));
    var unchanged = try fixture.directory.readSensitive(io, a, "request.json", 4096, null);
    defer unchanged.deinit();
    try t.expectEqualStrings("original", unchanged.bytes());
    // The caller's cleanup must erase this successfully published SAS even
    // though the following request publication failed.
    var sas = try fixture.directory.readSensitive(io, a, "sas.txt", 4096, null);
    defer sas.deinit();
    try t.expectEqualStrings("sv=fixture&sig=SYNTHETIC_ONLY", sas.bytes());
}
