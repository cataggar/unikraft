// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub const ProductionProfile = enum { tiny_exact_v2, coremark_exact_v2 };
pub const CompatibleRecordSet = enum { tiny_v1_legacy, tiny_v2_qcow2_derived_vhd, coremark_v2_qcow2_derived_vhd };
pub const CpuBaseline = enum { x86_64_v2, x86_64_v3 };
pub const default_cpu_baseline: CpuBaseline = .x86_64_v2;
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
pub const executable_target_v2 = [_][]const u8{
    "-Dtarget=x86_64-linux-gnu", "-Dcpu=x86_64_v2",
};
pub const executable_target_v3 = [_][]const u8{
    "-Dtarget=x86_64-linux-gnu", "-Dcpu=x86_64_v3",
};
pub const executable_target = executable_target_v2;

pub fn cpuFlag(baseline: CpuBaseline) []const u8 {
    return switch (baseline) {
        .x86_64_v2 => executable_target_v2[1],
        .x86_64_v3 => executable_target_v3[1],
    };
}

pub fn executableTargetFor(baseline: CpuBaseline) [2][]const u8 {
    return switch (baseline) {
        .x86_64_v2 => executable_target_v2,
        .x86_64_v3 => executable_target_v3,
    };
}

pub fn compiledCpuBaseline(target: std.Target) ?CpuBaseline {
    if (target.cpu.arch != .x86_64 or target.os.tag != .linux or target.abi != .gnu)
        return null;
    const v2 = std.Target.x86.cpu.x86_64_v2.toCpu(.x86_64);
    if (std.mem.eql(u8, target.cpu.model.name, v2.model.name) and target.cpu.features.eql(v2.features))
        return .x86_64_v2;
    const v3 = std.Target.x86.cpu.x86_64_v3.toCpu(.x86_64);
    if (std.mem.eql(u8, target.cpu.model.name, v3.model.name) and target.cpu.features.eql(v3.features))
        return .x86_64_v3;
    return null;
}

pub fn activeCpuBaseline() CpuBaseline {
    return comptime (compiledCpuBaseline(@import("builtin").target) orelse default_cpu_baseline);
}

pub fn activeExecutableTarget() [2][]const u8 {
    return executableTargetFor(activeCpuBaseline());
}

pub const tiny_profile_name = "qcow2-derived-vhd";
pub const coremark_profile_name = "coremark-qcow2-derived-vhd";

pub fn isV2(set: CompatibleRecordSet) bool {
    return switch (set) {
        .tiny_v1_legacy => false,
        .tiny_v2_qcow2_derived_vhd, .coremark_v2_qcow2_derived_vhd => true,
    };
}

pub fn isCoremark(set: CompatibleRecordSet) bool {
    return set == .coremark_v2_qcow2_derived_vhd;
}

pub fn modes(set: CompatibleRecordSet) []const Mode {
    return switch (set) {
        .tiny_v1_legacy => &legacy_modes,
        .tiny_v2_qcow2_derived_vhd, .coremark_v2_qcow2_derived_vhd => &production_modes,
    };
}

pub fn productionSet(profile: ProductionProfile) CompatibleRecordSet {
    return switch (profile) {
        .tiny_exact_v2 => .tiny_v2_qcow2_derived_vhd,
        .coremark_exact_v2 => .coremark_v2_qcow2_derived_vhd,
    };
}

pub fn recordSet(version: u32, profile: ?[]const u8) !CompatibleRecordSet {
    if (version == 1 and profile == null) return .tiny_v1_legacy;
    if (version == 2 and profile != null) {
        if (std.mem.eql(u8, profile.?, tiny_profile_name))
            return .tiny_v2_qcow2_derived_vhd;
        if (std.mem.eql(u8, profile.?, coremark_profile_name))
            return .coremark_v2_qcow2_derived_vhd;
    }
    return error.UnsupportedRecordSet;
}

pub fn profileName(profile: ProductionProfile) []const u8 {
    return switch (profile) {
        .tiny_exact_v2 => tiny_profile_name,
        .coremark_exact_v2 => coremark_profile_name,
    };
}

pub fn parseProductionProfile(name: []const u8) !ProductionProfile {
    if (std.mem.eql(u8, name, tiny_profile_name)) return .tiny_exact_v2;
    if (std.mem.eql(u8, name, coremark_profile_name)) return .coremark_exact_v2;
    return error.UnsupportedRecordSet;
}

pub fn recordSetProfileName(set: CompatibleRecordSet) ?[]const u8 {
    return switch (set) {
        .tiny_v1_legacy => null,
        .tiny_v2_qcow2_derived_vhd => tiny_profile_name,
        .coremark_v2_qcow2_derived_vhd => coremark_profile_name,
    };
}

pub fn productionProfileForSet(set: CompatibleRecordSet) ?ProductionProfile {
    return switch (set) {
        .tiny_v1_legacy => null,
        .tiny_v2_qcow2_derived_vhd => .tiny_exact_v2,
        .coremark_v2_qcow2_derived_vhd => .coremark_exact_v2,
    };
}
