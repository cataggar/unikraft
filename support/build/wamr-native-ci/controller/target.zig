// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const profile = @import("profile.zig");

pub const HostCpuError = error{
    UnsupportedHostCpu,
    OsAvxStateDisabled,
};

pub const HostCpuSnapshot = struct {
    max_basic_leaf: u32,
    leaf1_ecx: u32,
    leaf1_edx: u32,
    max_extended_leaf: u32,
    ext1_ecx: u32,
    ext1_edx: u32,
    leaf7_ebx: u32,
    xcr0: u64,
};

pub const leaf1_edx_v2_mask: u32 =
    (@as(u32, 1) << 0) | // fpu
    (@as(u32, 1) << 8) | // cx8
    (@as(u32, 1) << 15) | // cmov
    (@as(u32, 1) << 23) | // mmx
    (@as(u32, 1) << 24) | // fxsr
    (@as(u32, 1) << 25) | // sse
    (@as(u32, 1) << 26); // sse2

pub const leaf1_ecx_v2_mask: u32 =
    (@as(u32, 1) << 0) | // sse3
    (@as(u32, 1) << 9) | // ssse3
    (@as(u32, 1) << 13) | // cx16
    (@as(u32, 1) << 19) | // sse4_1
    (@as(u32, 1) << 20) | // sse4_2
    (@as(u32, 1) << 23); // popcnt

pub const ext1_edx_v2_mask: u32 =
    (@as(u32, 1) << 29); // lm

pub const ext1_ecx_v2_mask: u32 =
    (@as(u32, 1) << 0); // lahf_lm

pub const leaf1_ecx_v3_cpu_mask: u32 =
    (@as(u32, 1) << 12) | // fma
    (@as(u32, 1) << 22) | // movbe
    (@as(u32, 1) << 26) | // xsave
    (@as(u32, 1) << 28) | // avx
    (@as(u32, 1) << 29); // f16c

pub const leaf1_ecx_osxsave_bit: u32 = (@as(u32, 1) << 27);

pub const leaf7_ebx_v3_mask: u32 =
    (@as(u32, 1) << 3) | // bmi1
    (@as(u32, 1) << 5) | // avx2
    (@as(u32, 1) << 8); // bmi2

pub const ext1_ecx_v3_mask: u32 =
    (@as(u32, 1) << 5); // lzcnt / abm

pub const xcr0_avx_mask: u64 = 0x6; // XMM (bit 1) | YMM (bit 2)

pub fn portableQueryFor(baseline: profile.CpuBaseline) std.Target.Query {
    const pair = profile.executableTargetFor(baseline);
    const target = pair[0];
    const cpu = pair[1];
    comptime {
        for ([_]profile.CpuBaseline{ .x86_64_v2, .x86_64_v3 }) |candidate| {
            const flags = profile.executableTargetFor(candidate);
            if (!std.mem.startsWith(u8, flags[0], "-Dtarget=") or
                !std.mem.startsWith(u8, flags[1], "-Dcpu="))
                @compileError("invalid controller executable target flags");
        }
    }
    return std.Target.Query.parse(.{
        .arch_os_abi = target["-Dtarget=".len..],
        .cpu_features = cpu["-Dcpu=".len..],
    }) catch unreachable;
}

pub fn portableQuery() std.Target.Query {
    return portableQueryFor(profile.default_cpu_baseline);
}

pub fn requestedBaseline(requested: std.Target.Query) ?profile.CpuBaseline {
    if (requested.eql(portableQueryFor(.x86_64_v2))) return .x86_64_v2;
    if (requested.eql(portableQueryFor(.x86_64_v3))) return .x86_64_v3;
    return null;
}

pub fn permitsInstall(requested: std.Target.Query, optimize: std.builtin.Optimize) bool {
    return requestedBaseline(requested) != null and optimize == .safe;
}

pub fn evaluateHostCpu(baseline: profile.CpuBaseline, snapshot: HostCpuSnapshot) HostCpuError!void {
    if (snapshot.max_basic_leaf < 1 or
        snapshot.max_extended_leaf < 0x80000001 or
        (snapshot.leaf1_edx & leaf1_edx_v2_mask) != leaf1_edx_v2_mask or
        (snapshot.leaf1_ecx & leaf1_ecx_v2_mask) != leaf1_ecx_v2_mask or
        (snapshot.ext1_edx & ext1_edx_v2_mask) != ext1_edx_v2_mask or
        (snapshot.ext1_ecx & ext1_ecx_v2_mask) != ext1_ecx_v2_mask)
        return error.UnsupportedHostCpu;
    if (baseline == .x86_64_v3) {
        if (snapshot.max_basic_leaf < 7 or
            (snapshot.leaf1_ecx & leaf1_ecx_v3_cpu_mask) != leaf1_ecx_v3_cpu_mask or
            (snapshot.leaf7_ebx & leaf7_ebx_v3_mask) != leaf7_ebx_v3_mask or
            (snapshot.ext1_ecx & ext1_ecx_v3_mask) != ext1_ecx_v3_mask)
            return error.UnsupportedHostCpu;
        if ((snapshot.leaf1_ecx & leaf1_ecx_osxsave_bit) == 0 or
            (snapshot.xcr0 & xcr0_avx_mask) != xcr0_avx_mask)
            return error.OsAvxStateDisabled;
    }
}

const CpuidLeaf = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

fn cpuid(leaf: u32, subleaf: u32) CpuidLeaf {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (leaf),
          [subleaf] "{ecx}" (subleaf),
    );
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

fn xgetbv(index: u32) u64 {
    var eax: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("xgetbv"
        : [eax] "={eax}" (eax),
          [edx] "={edx}" (edx),
        : [index] "{ecx}" (index),
    );
    return (@as(u64, edx) << 32) | @as(u64, eax);
}

pub fn probeHostCpu() HostCpuSnapshot {
    if (comptime builtin.cpu.arch != .x86_64) {
        return .{
            .max_basic_leaf = 0,
            .leaf1_ecx = 0,
            .leaf1_edx = 0,
            .max_extended_leaf = 0,
            .ext1_ecx = 0,
            .ext1_edx = 0,
            .leaf7_ebx = 0,
            .xcr0 = 0,
        };
    }
    const leaf0 = cpuid(0, 0);
    const leaf1 = if (leaf0.eax >= 1) cpuid(1, 0) else CpuidLeaf{ .eax = 0, .ebx = 0, .ecx = 0, .edx = 0 };
    const leaf7 = if (leaf0.eax >= 7) cpuid(7, 0) else CpuidLeaf{ .eax = 0, .ebx = 0, .ecx = 0, .edx = 0 };
    const ext0 = cpuid(0x80000000, 0);
    const ext1 = if (ext0.eax >= 0x80000001) cpuid(0x80000001, 0) else CpuidLeaf{ .eax = 0, .ebx = 0, .ecx = 0, .edx = 0 };
    const xcr0 = if ((leaf1.ecx & leaf1_ecx_osxsave_bit) != 0) xgetbv(0) else 0;
    return .{
        .max_basic_leaf = leaf0.eax,
        .leaf1_ecx = leaf1.ecx,
        .leaf1_edx = leaf1.edx,
        .max_extended_leaf = ext0.eax,
        .ext1_ecx = ext1.ecx,
        .ext1_edx = ext1.edx,
        .leaf7_ebx = leaf7.ebx,
        .xcr0 = xcr0,
    };
}

pub fn requireHostCpu(baseline: profile.CpuBaseline) HostCpuError!void {
    try evaluateHostCpu(baseline, probeHostCpu());
}

pub fn requireActiveHostCpu() HostCpuError!void {
    try requireHostCpu(profile.activeCpuBaseline());
}
