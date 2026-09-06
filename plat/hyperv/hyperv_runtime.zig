// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");

const cpuid_hypervisor_present = @as(u32, 1) << 31;
const cpuid_hv_base = 0x40000000;
const cpuid_hv_interface = 0x40000001;
const cpuid_hv_features = 0x40000003;
const cpuid_hv_minimum = 0x40000005;
const access_time_ref_count = @as(u32, 1) << 1;
const access_hypercall_msrs = @as(u32, 1) << 5;

const msr_guest_os_id = 0x40000000;
const msr_hypercall = 0x40000001;
const msr_time_ref_count = 0x40000020;
const hypercall_enable = @as(u64, 1);
const hypercall_reserved = @as(u64, 0x0ffe);
const page_mask = ~@as(u64, 0xfff);

pub const CpuidRegs = extern struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

pub const Discovery = extern struct {
    leaf1_ecx: u32,
    max_leaf: u32,
    vendor_ebx: u32,
    vendor_ecx: u32,
    vendor_edx: u32,
    interface_eax: u32,
    features_eax: u32,
};

pub const DetectResult = enum(c_int) {
    ok = 0,
    no_hypervisor = 1,
    leaf_range = 2,
    vendor = 3,
    interface = 4,
    hypercall_privilege = 5,
    time_ref_privilege = 6,
};

pub const EnableResult = enum(c_int) {
    ok = 0,
    bad_page = 1,
    msr_rejected = 2,
};

pub const StatusKind = enum(u16) {
    success = 0,
    invalid_hypercall_code = 1,
    invalid_hypercall_input = 2,
    invalid_alignment = 3,
    invalid_parameter = 4,
    access_denied = 5,
    operation_denied = 6,
    unknown = 0xffff,
};

comptime {
    if (@sizeOf(CpuidRegs) != 16 or @alignOf(CpuidRegs) != 4)
        @compileError("Hyper-V CPUID ABI layout changed");
    if (@sizeOf(Discovery) != 28 or @alignOf(Discovery) != 4)
        @compileError("Hyper-V discovery ABI layout changed");
}

export const hyperv_hypercall_page_storage: [4096]u8 align(4096) linksection(".text.hyperv_hypercall_page") = [_]u8{0} ** 4096;

var enabled = false;
var guest_id_active = false;

pub fn decodeDiscovery(info: Discovery) DetectResult {
    if ((info.leaf1_ecx & cpuid_hypervisor_present) == 0)
        return .no_hypervisor;
    if (info.max_leaf < cpuid_hv_minimum)
        return .leaf_range;
    if (info.vendor_ebx != 0x7263694d or
        info.vendor_ecx != 0x666f736f or
        info.vendor_edx != 0x76482074)
        return .vendor;
    if (info.interface_eax != 0x31237648)
        return .interface;
    if ((info.features_eax & access_hypercall_msrs) == 0)
        return .hypercall_privilege;
    if ((info.features_eax & access_time_ref_count) == 0)
        return .time_ref_privilege;
    return .ok;
}

pub fn encodeGuestId(
    build: u16,
    version: u32,
    os_id: u8,
    os_type: u8,
    open_source: bool,
) u64 {
    return @as(u64, build) |
        (@as(u64, version) << 16) |
        (@as(u64, os_id) << 48) |
        (@as(u64, os_type & 0x7f) << 56) |
        (if (open_source) @as(u64, 1) << 63 else 0);
}

fn cpuid(leaf: u32) CpuidRegs {
    var eax = leaf;
    var ebx: u32 = undefined;
    var ecx: u32 = 0;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (eax),
          [subleaf] "{ecx}" (ecx),
        : .{ .memory = true });
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

fn rdmsr(msr: u32) u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdmsr"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
        : [msr] "{ecx}" (msr),
        : .{ .memory = true });
    return (@as(u64, hi) << 32) | lo;
}

fn wrmsr(msr: u32, value: u64) void {
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [lo] "{eax}" (@as(u32, @truncate(value))),
          [hi] "{edx}" (@as(u32, @truncate(value >> 32))),
        : .{ .memory = true });
}

export fn hyperv_hypercall_page() callconv(.c) *anyopaque {
    return @ptrCast(@constCast(&hyperv_hypercall_page_storage));
}

export fn hyperv_guest_id_encode(
    build: u16,
    version: u32,
    os_id: u8,
    os_type: u8,
    open_source: u8,
) callconv(.c) u64 {
    return encodeGuestId(build, version, os_id, os_type, open_source != 0);
}

export fn hyperv_runtime_detect() callconv(.c) c_int {
    const basic = cpuid(1);
    const identity = cpuid(cpuid_hv_base);
    const interface = cpuid(cpuid_hv_interface);
    const features = cpuid(cpuid_hv_features);
    return @intFromEnum(decodeDiscovery(.{
        .leaf1_ecx = basic.ecx,
        .max_leaf = identity.eax,
        .vendor_ebx = identity.ebx,
        .vendor_ecx = identity.ecx,
        .vendor_edx = identity.edx,
        .interface_eax = interface.eax,
        .features_eax = features.eax,
    }));
}

export fn hyperv_runtime_enable(page_gpa: u64, guest_id: u64) callconv(.c) c_int {
    if ((page_gpa & ~page_mask) != 0 or guest_id == 0)
        return @intFromEnum(EnableResult.bad_page);

    wrmsr(msr_guest_os_id, guest_id);
    guest_id_active = true;

    const original = rdmsr(msr_hypercall);
    wrmsr(msr_hypercall, (page_gpa & page_mask) |
        (original & hypercall_reserved) | hypercall_enable);
    const installed = rdmsr(msr_hypercall);
    if ((installed & hypercall_enable) == 0 or
        (installed & page_mask) != (page_gpa & page_mask))
    {
        wrmsr(msr_guest_os_id, 0);
        guest_id_active = false;
        return @intFromEnum(EnableResult.msr_rejected);
    }
    enabled = true;
    return @intFromEnum(EnableResult.ok);
}

export fn hyperv_runtime_disable() callconv(.c) void {
    if (enabled) {
        const current = rdmsr(msr_hypercall);
        wrmsr(msr_hypercall, current & hypercall_reserved);
        enabled = false;
    }
    if (guest_id_active) {
        wrmsr(msr_guest_os_id, 0);
        guest_id_active = false;
    }
}

export fn hyperv_hypercall(
    control: u64,
    input_gpa: u64,
    output_gpa: u64,
) callconv(.c) u64 {
    const Hypercall = *const fn (u64, u64, u64) callconv(.winapi) u64;
    const invoke: Hypercall = @ptrCast(&hyperv_hypercall_page_storage);
    return invoke(control, input_gpa, output_gpa);
}

export fn hyperv_status_code(result: u64) callconv(.c) u16 {
    return @truncate(result);
}

export fn hyperv_status_kind(result: u64) callconv(.c) u16 {
    return @intFromEnum(switch (hyperv_status_code(result)) {
        0x0000 => StatusKind.success,
        0x0002 => StatusKind.invalid_hypercall_code,
        0x0003 => StatusKind.invalid_hypercall_input,
        0x0004 => StatusKind.invalid_alignment,
        0x0005 => StatusKind.invalid_parameter,
        0x0006 => StatusKind.access_denied,
        0x0008 => StatusKind.operation_denied,
        else => StatusKind.unknown,
    });
}

export fn hyperv_msr_read(msr: u32) callconv(.c) u64 {
    return rdmsr(msr);
}

export fn hyperv_msr_write(msr: u32, value: u64) callconv(.c) void {
    wrmsr(msr, value);
}

export fn hyperv_time_ref_count() callconv(.c) u64 {
    return rdmsr(msr_time_ref_count);
}

test "Guest OS ID layout follows TLFS open-source format" {
    const value = encodeGuestId(0x1234, 0x55667788, 0x9a, 0x7f, true);
    try std.testing.expectEqual(@as(u64, 0xff9a556677881234), value);
}

test "CPUID discovery reports each precise failure" {
    const valid = Discovery{
        .leaf1_ecx = cpuid_hypervisor_present,
        .max_leaf = cpuid_hv_minimum,
        .vendor_ebx = 0x7263694d,
        .vendor_ecx = 0x666f736f,
        .vendor_edx = 0x76482074,
        .interface_eax = 0x31237648,
        .features_eax = access_hypercall_msrs | access_time_ref_count,
    };
    try std.testing.expectEqual(DetectResult.ok, decodeDiscovery(valid));
    var changed = valid;
    changed.leaf1_ecx = 0;
    try std.testing.expectEqual(DetectResult.no_hypervisor, decodeDiscovery(changed));
    changed = valid;
    changed.max_leaf = cpuid_hv_minimum - 1;
    try std.testing.expectEqual(DetectResult.leaf_range, decodeDiscovery(changed));
    changed = valid;
    changed.vendor_ebx = 0;
    try std.testing.expectEqual(DetectResult.vendor, decodeDiscovery(changed));
    changed = valid;
    changed.interface_eax = 0;
    try std.testing.expectEqual(DetectResult.interface, decodeDiscovery(changed));
    changed = valid;
    changed.features_eax &= ~access_hypercall_msrs;
    try std.testing.expectEqual(DetectResult.hypercall_privilege, decodeDiscovery(changed));
    changed = valid;
    changed.features_eax &= ~access_time_ref_count;
    try std.testing.expectEqual(DetectResult.time_ref_privilege, decodeDiscovery(changed));
}

test "status decoding masks the result field" {
    try std.testing.expectEqual(@as(u16, 2), hyperv_status_code(0x123400000002));
    try std.testing.expectEqual(
        @intFromEnum(StatusKind.invalid_hypercall_code),
        hyperv_status_kind(0x123400000002),
    );
    try std.testing.expectEqual(
        @intFromEnum(StatusKind.unknown),
        hyperv_status_kind(0xbeef),
    );
}
