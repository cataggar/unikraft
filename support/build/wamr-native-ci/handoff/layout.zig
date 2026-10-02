// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const profile = @import("profile.zig");

pub const max_members: usize = 96;
pub const max_total_bytes: u64 = 512 * 1024 * 1024;
pub const max_json_bytes: u64 = 64 * 1024;
pub const max_serial_bytes: u64 = 4 * 1024 * 1024;
pub const max_config_bytes: u64 = 1024 * 1024;
pub const max_large_artifact_bytes: u64 = 256 * 1024 * 1024 + 512;
pub const v1_zip_member_count: usize = 55;
pub const v2_zip_member_count: usize = 85;

pub const BootKey = enum { serial, request, report, compute };
pub const boot_keys = [_]BootKey{ .serial, .request, .report, .compute };

pub const artifact_names_v1 = [_][]const u8{
    "efi",
    "debug_elf",
    "bootinfo",
    "raw",
    "vhd",
    "runtime",
    "compiler",
    "wasm",
    "cwasm",
    "config",
    "runtime_identity",
    "image_identity",
    "local_result",
    "package",
    "build",
    "build_start",
    "boot_inputs",
};

pub const artifact_names_v2 = [_][]const u8{
    "efi",
    "debug_elf",
    "bootinfo",
    "raw",
    "qcow2",
    "vhd",
    "runtime",
    "compiler",
    "wasm",
    "cwasm",
    "config",
    "runtime_identity",
    "image_identity",
    "local_result",
    "package",
    "build",
    "build_start",
    "boot_inputs",
    "qcow2_finalization_intent",
    "qcow2_finalization",
    "qcow2_acceptance",
    "fixed_vhd_derivation_intent",
    "fixed_vhd_derivation_gate",
    "fixed_vhd_derivation",
    "final_inspection",
    "cleanup",
};

pub const evidence_v1 = [_][]const u8{
    "boot-inputs.json",
    "build-start.json",
    "build.json",
    "command-adapter.json",
    "command-config.json",
    "command-fixtures.json",
    "command-inspect.json",
    "command-local-boot-tool.json",
    "command-native-image.json",
    "command-package.json",
    "command-prepare.json",
    "command-raw-legacy-apic.json",
    "command-raw-x2apic.json",
    "command-vpc-legacy-apic.json",
    "command-vpc-x2apic.json",
    "package.json",
    "raw-legacy-apic-compute.json",
    "raw-x2apic-compute.json",
    "vpc-legacy-apic-compute.json",
    "vpc-x2apic-compute.json",
};

pub const evidence_v2 = [_][]const u8{
    "boot-inputs.json",
    "build-start.json",
    "build.json",
    "command-adapter.json",
    "command-config.json",
    "command-derive-fixed-vhd.json",
    "command-finalize-qcow2.json",
    "command-fixtures.json",
    "command-inspect.json",
    "command-local-boot-tool.json",
    "command-native-image.json",
    "command-package.json",
    "command-prepare.json",
    "command-qcow2-legacy-apic.json",
    "command-qcow2-x2apic.json",
    "command-raw-legacy-apic.json",
    "command-raw-x2apic.json",
    "command-vpc-legacy-apic.json",
    "command-vpc-x2apic.json",
    "final-inspection.json",
    "fixed-vhd-derivation-gate.json",
    "fixed-vhd-derivation-intent.json",
    "fixed-vhd-derivation.json",
    "package.json",
    "qcow2-acceptance.json",
    "qcow2-finalization-intent.json",
    "qcow2-finalization.json",
    "qcow2-legacy-apic-compute.json",
    "qcow2-x2apic-compute.json",
    "raw-legacy-apic-compute.json",
    "raw-x2apic-compute.json",
    "vpc-legacy-apic-compute.json",
    "vpc-x2apic-compute.json",
};

pub fn artifactNames(compatibility: profile.Compatibility) []const []const u8 {
    return switch (compatibility) {
        .frozen_tiny_v1 => &artifact_names_v1,
        .tiny_qcow2_derived_vhd_v2 => &artifact_names_v2,
    };
}

pub fn evidenceNames(compatibility: profile.Compatibility) []const []const u8 {
    return switch (compatibility) {
        .frozen_tiny_v1 => &evidence_v1,
        .tiny_qcow2_derived_vhd_v2 => &evidence_v2,
    };
}

pub fn artifactLimit(name: []const u8) u64 {
    const large = [_][]const u8{
        "efi",     "debug_elf", "bootinfo", "raw",   "qcow2", "vhd",
        "runtime", "compiler",  "wasm",     "cwasm",
    };
    for (large) |item| if (std.mem.eql(u8, item, name)) return max_large_artifact_bytes;
    if (std.mem.eql(u8, name, "config")) return max_config_bytes;
    return max_json_bytes;
}

pub fn memberLimit(name: []const u8) !u64 {
    if (std.mem.startsWith(u8, name, "artifacts/"))
        return artifactLimit(name["artifacts/".len..]);
    if (std.mem.startsWith(u8, name, "boots/"))
        return if (std.mem.endsWith(u8, name, "/serial")) max_serial_bytes else max_json_bytes;
    if (std.mem.startsWith(u8, name, "evidence/")) return max_json_bytes;
    if (std.mem.eql(u8, name, "bundle.json") or std.mem.eql(u8, name, "public-source.json"))
        return max_json_bytes;
    return error.UnknownMember;
}

pub fn selectedMemberCount(compatibility: profile.Compatibility) usize {
    return artifactNames(compatibility).len + evidenceNames(compatibility).len +
        bootMemberCount(compatibility);
}

pub fn bootMemberCount(compatibility: profile.Compatibility) usize {
    return profile.modes(compatibility).len * boot_keys.len;
}

pub fn expectedZipMemberCount(compatibility: profile.Compatibility) usize {
    return artifactNames(compatibility).len + evidenceNames(compatibility).len +
        bootMemberCount(compatibility) + 2;
}

pub fn containsSelectedPublicMember(compatibility: profile.Compatibility, name: []const u8) bool {
    if (std.mem.startsWith(u8, name, "artifacts/"))
        return contains(artifactNames(compatibility), name["artifacts/".len..]);
    if (std.mem.startsWith(u8, name, "evidence/"))
        return contains(evidenceNames(compatibility), name["evidence/".len..]);
    if (!std.mem.startsWith(u8, name, "boots/")) return false;
    var parts = std.mem.splitScalar(u8, name["boots/".len..], '/');
    const mode_name = parts.next() orelse return false;
    const key_name = parts.next() orelse return false;
    if (parts.next() != null) return false;
    var mode_ok = false;
    for (profile.modes(compatibility)) |mode| {
        if (std.mem.eql(u8, @tagName(mode), mode_name)) mode_ok = true;
    }
    return mode_ok and containsEnum(BootKey, &boot_keys, key_name);
}

fn contains(values: []const []const u8, needle: []const u8) bool {
    for (values) |value| if (std.mem.eql(u8, value, needle)) return true;
    return false;
}

fn containsEnum(comptime T: type, values: []const T, needle: []const u8) bool {
    for (values) |value| if (std.mem.eql(u8, @tagName(value), needle)) return true;
    return false;
}
