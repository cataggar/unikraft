// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub const ProductionProfile = enum { tiny_exact_v2 };
pub const CompatibleRecordSet = enum { tiny_v1_legacy, tiny_v2_qcow2_derived_vhd };
pub const Mode = enum {
    @"raw-x2apic",
    @"raw-legacy-apic",
    @"qcow2-x2apic",
    @"qcow2-legacy-apic",
    @"vpc-x2apic",
    @"vpc-legacy-apic",

    pub fn legacyApic(self: Mode) bool {
        return switch (self) {
            .@"raw-legacy-apic", .@"qcow2-legacy-apic", .@"vpc-legacy-apic" => true,
            else => false,
        };
    }
};

pub const legacy_modes = [_]Mode{
    .@"raw-x2apic", .@"raw-legacy-apic", .@"vpc-x2apic", .@"vpc-legacy-apic",
};
pub const production_modes = [_]Mode{
    .@"raw-x2apic",        .@"raw-legacy-apic", .@"qcow2-x2apic",
    .@"qcow2-legacy-apic", .@"vpc-x2apic",      .@"vpc-legacy-apic",
};
pub const executable_target = [_][]const u8{
    "-Dtarget=x86_64-linux-gnu", "-Dcpu=x86_64_v2",
};

pub fn modes(set: CompatibleRecordSet) []const Mode {
    return switch (set) {
        .tiny_v1_legacy => &legacy_modes,
        .tiny_v2_qcow2_derived_vhd => &production_modes,
    };
}

pub fn productionSet(profile: ProductionProfile) CompatibleRecordSet {
    return switch (profile) {
        .tiny_exact_v2 => .tiny_v2_qcow2_derived_vhd,
    };
}

pub fn recordSet(version: u32, profile: ?[]const u8) !CompatibleRecordSet {
    if (version == 1 and profile == null) return .tiny_v1_legacy;
    if (version == 2 and profile != null and
        std.mem.eql(u8, profile.?, "qcow2-derived-vhd"))
        return .tiny_v2_qcow2_derived_vhd;
    return error.UnsupportedRecordSet;
}

pub fn profileName(profile: ProductionProfile) []const u8 {
    return switch (profile) {
        .tiny_exact_v2 => "qcow2-derived-vhd",
    };
}
