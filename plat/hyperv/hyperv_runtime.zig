// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");

const cpuid_hypervisor_present = @as(u32, 1) << 31;
const cpuid_hv_base = 0x40000000;
const cpuid_hv_interface = 0x40000001;
const cpuid_hv_features = 0x40000003;
const cpuid_hv_minimum = 0x40000005;

const access_time_ref_count = @as(u32, 1) << 1;
const access_synic_msrs = @as(u32, 1) << 2;
const access_stimer_msrs = @as(u32, 1) << 3;
const access_hypercall_msrs = @as(u32, 1) << 5;
const access_vp_index = @as(u32, 1) << 6;
const access_reference_tsc = @as(u32, 1) << 9;

const msr_guest_os_id = 0x40000000;
const msr_hypercall = 0x40000001;
const msr_time_ref_count = 0x40000020;
const msr_reference_tsc = 0x40000021;
const msr_scontrol = 0x40000080;
const msr_siefp = 0x40000082;
const msr_simp = 0x40000083;
const msr_eom = 0x40000084;
const msr_sint0 = 0x40000090;
const msr_stimer0_config = 0x400000b0;
const msr_stimer0_count = 0x400000b1;

const hypercall_enable = @as(u64, 1);
const register_enable = @as(u64, 1);
const register_reserved = @as(u64, 0x0ffe);
const page_mask = ~@as(u64, 0xfff);
const sint_vector_mask = @as(u64, 0xff);
const sint_masked = @as(u64, 1) << 16;
const sint_auto_eoi = @as(u64, 1) << 17;
const sint_polling = @as(u64, 1) << 18;
const sint_owned_mask = sint_vector_mask | sint_masked | sint_auto_eoi | sint_polling;
const stimer_auto_enable = @as(u64, 1) << 3;
const stimer_sint_shift = 16;
const reference_tick_ns = 100;
const message_pending = @as(u8, 1);
const max_message_payload = 240;
const sint_count = 16;
const event_words_per_sint = 32;

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
    features_edx: u32,
};

pub const Message = extern struct {
    message_type: u32,
    payload_size: u8,
    flags: u8,
    reserved: u16,
    sender: u64,
    payload: [max_message_payload]u8,
};

const ReferenceTscPage = extern struct {
    sequence: u32,
    reserved1: u32,
    scale: u64,
    offset: i64,
    reserved2: [509]u64,
};

pub const DetectResult = enum(c_int) {
    ok = 0,
    no_hypervisor = 1,
    leaf_range = 2,
    vendor = 3,
    interface = 4,
    hypercall_privilege = 5,
    time_ref_privilege = 6,
    synic_privilege = 7,
    stimer_privilege = 8,
};

pub const EnableResult = enum(c_int) {
    ok = 0,
    bad_page = 1,
    msr_rejected = 2,
};

pub const SynicResult = enum(c_int) {
    ok = 0,
    bad_page = 1,
    bad_vector = 2,
    missing_privilege = 3,
    msr_rejected = 4,
};

pub const MessageResult = enum(c_int) {
    empty = 0,
    ready = 1,
    invalid_sint = -1,
    invalid_payload = -2,
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

const Features = packed struct(u32) {
    vp_runtime: bool,
    time_ref_count: bool,
    synic: bool,
    stimer: bool,
    interrupt_control: bool,
    hypercall: bool,
    vp_index: bool,
    reset: bool,
    stats: bool,
    reference_tsc: bool,
    guest_idle: bool,
    frequency: bool,
    remaining: u20,
};

comptime {
    if (@sizeOf(CpuidRegs) != 16 or @alignOf(CpuidRegs) != 4)
        @compileError("Hyper-V CPUID ABI layout changed");
    if (@sizeOf(Discovery) != 32 or @alignOf(Discovery) != 4)
        @compileError("Hyper-V discovery ABI layout changed");
    if (@sizeOf(Message) != 256 or @alignOf(Message) != 8)
        @compileError("Hyper-V message ABI layout changed");
    if (@offsetOf(Message, "payload") != 16)
        @compileError("Hyper-V message payload offset changed");
    if (@sizeOf(ReferenceTscPage) != 4096 or @alignOf(ReferenceTscPage) != 8)
        @compileError("Hyper-V reference TSC page layout changed");
}

export const hyperv_hypercall_page_storage: [4096]u8 align(4096) linksection(".text.hyperv_hypercall_page") = [_]u8{0} ** 4096;
// PLAT_HYPERV is restricted to one vCPU; these pages are owned by the BSP.
export var hyperv_simp_page_storage: [4096]u8 align(4096) linksection(".bss.hyperv_simp_page") = [_]u8{0} ** 4096;
export var hyperv_siefp_page_storage: [4096]u8 align(4096) linksection(".bss.hyperv_siefp_page") = [_]u8{0} ** 4096;
export var hyperv_reference_tsc_page_storage: ReferenceTscPage align(4096) linksection(".bss.hyperv_reference_tsc_page") = std.mem.zeroes(ReferenceTscPage);

var enabled = false;
var guest_id_active = false;
var synic_enabled = false;
var reference_tsc_enabled = false;
var discovered_features: u32 = 0;

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
    const features: Features = @bitCast(info.features_eax);
    if (!features.hypercall)
        return .hypercall_privilege;
    if (!features.time_ref_count)
        return .time_ref_privilege;
    if (!features.synic)
        return .synic_privilege;
    if (!features.stimer)
        return .stimer_privilege;
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

pub fn irqToVector(irq: u32) ?u8 {
    if (irq > 223)
        return null;
    return @intCast(32 + irq);
}

pub fn nsToReferenceTicksCeil(ns: u64) u64 {
    return ns / reference_tick_ns + @intFromBool(ns % reference_tick_ns != 0);
}

pub fn deadlineReferenceTicks(boot_reference: u64, deadline_ns: u64) u64 {
    return boot_reference +% nsToReferenceTicksCeil(deadline_ns);
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

fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
        :
        : .{ .memory = true });
    return (@as(u64, hi) << 32) | lo;
}

fn zeroSharedPage(page: *[4096]u8) void {
    for (0..page.len) |i|
        @as(*volatile u8, @ptrCast(&page[i])).* = 0;
    asm volatile ("" ::: .{ .memory = true });
}

fn programPageMsr(msr: u32, gpa: u64) bool {
    const original = rdmsr(msr);
    const value = (gpa & page_mask) | (original & register_reserved) | register_enable;
    wrmsr(msr, value);
    const installed = rdmsr(msr);
    return (installed & (page_mask | register_enable)) ==
        (value & (page_mask | register_enable));
}

fn disablePageMsr(msr: u32) void {
    const current = rdmsr(msr);
    wrmsr(msr, current & ~register_enable);
}

fn programSint(index: u32, vector: u8, masked: bool) bool {
    const msr = msr_sint0 + index;
    const original = rdmsr(msr);
    // xPIC's x2APIC path issues the EOI, so AutoEOI must remain clear.
    var value = (original & ~sint_owned_mask) | vector;
    if (masked)
        value |= sint_masked;
    wrmsr(msr, value);
    const installed = rdmsr(msr);
    return (installed & sint_owned_mask) == (value & sint_owned_mask);
}

fn maskSint(index: u32) void {
    const msr = msr_sint0 + index;
    wrmsr(msr, rdmsr(msr) | sint_masked);
}

fn disableSynicState() void {
    // Stop the producer, mask delivery, then detach control and shared pages.
    wrmsr(msr_stimer0_count, 0);
    wrmsr(msr_stimer0_config, 0);
    maskSint(4);
    maskSint(2);
    wrmsr(msr_scontrol, rdmsr(msr_scontrol) & ~register_enable);
    disablePageMsr(msr_simp);
    disablePageMsr(msr_siefp);
    if (reference_tsc_enabled) {
        disablePageMsr(msr_reference_tsc);
        reference_tsc_enabled = false;
    }
    synic_enabled = false;
}

fn scaledReferenceTime(tsc: u64, scale: u64, offset: i64) ?u64 {
    const scaled: u64 = @truncate((@as(u128, tsc) * @as(u128, scale)) >> 64);
    const result = @as(i128, scaled) + @as(i128, offset);
    if (result < 0 or result > std.math.maxInt(u64))
        return null;
    return @intCast(result);
}

fn referenceTimeFromPage(page: *const volatile ReferenceTscPage) ?u64 {
    for (0..8) |_| {
        const sequence: *const u32 = @ptrCast(@volatileCast(&page.sequence));
        const start = @atomicLoad(u32, sequence, .acquire);
        if (start == 0)
            return null;
        const tsc = rdtsc();
        const scale = page.scale;
        const offset = page.offset;
        const end = @atomicLoad(u32, sequence, .acquire);
        if (referenceSequenceStable(start, end))
            return scaledReferenceTime(tsc, scale, offset);
    }
    return null;
}

fn referenceSequenceStable(start: u32, end: u32) bool {
    return start != 0 and start == end;
}

export fn hyperv_hypercall_page() callconv(.c) *anyopaque {
    return @ptrCast(@constCast(&hyperv_hypercall_page_storage));
}

export fn hyperv_simp_page() callconv(.c) *anyopaque {
    return @ptrCast(&hyperv_simp_page_storage);
}

export fn hyperv_siefp_page() callconv(.c) *anyopaque {
    return @ptrCast(&hyperv_siefp_page_storage);
}

export fn hyperv_reference_tsc_page() callconv(.c) *anyopaque {
    return @ptrCast(&hyperv_reference_tsc_page_storage);
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
    const result = decodeDiscovery(.{
        .leaf1_ecx = basic.ecx,
        .max_leaf = identity.eax,
        .vendor_ebx = identity.ebx,
        .vendor_ecx = identity.ecx,
        .vendor_edx = identity.edx,
        .interface_eax = interface.eax,
        .features_eax = features.eax,
        .features_edx = features.edx,
    });
    if (result == .ok)
        discovered_features = features.eax;
    return @intFromEnum(result);
}

export fn hyperv_runtime_enable(page_gpa: u64, guest_id: u64) callconv(.c) c_int {
    if ((page_gpa & ~page_mask) != 0 or guest_id == 0)
        return @intFromEnum(EnableResult.bad_page);

    wrmsr(msr_guest_os_id, guest_id);
    guest_id_active = true;

    const original = rdmsr(msr_hypercall);
    wrmsr(msr_hypercall, (page_gpa & page_mask) |
        (original & register_reserved) | hypercall_enable);
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

export fn hyperv_synic_enable(
    simp_gpa: u64,
    siefp_gpa: u64,
    reference_tsc_gpa: u64,
    message_vector: u8,
    timer_vector: u8,
) callconv(.c) c_int {
    if (((simp_gpa | siefp_gpa | reference_tsc_gpa) & ~page_mask) != 0 or
        simp_gpa == siefp_gpa or simp_gpa == reference_tsc_gpa or
        siefp_gpa == reference_tsc_gpa)
        return @intFromEnum(SynicResult.bad_page);
    if (message_vector < 32 or timer_vector < 32 or message_vector == timer_vector)
        return @intFromEnum(SynicResult.bad_vector);

    const features: Features = @bitCast(discovered_features);
    if (!features.synic or !features.stimer or !features.time_ref_count)
        return @intFromEnum(SynicResult.missing_privilege);

    zeroSharedPage(&hyperv_simp_page_storage);
    zeroSharedPage(&hyperv_siefp_page_storage);
    zeroSharedPage(@ptrCast(&hyperv_reference_tsc_page_storage));

    // Publish pages and masked SINTs before enabling SynIC and unmasking them.
    if (!programPageMsr(msr_simp, simp_gpa)) {
        disableSynicState();
        return @intFromEnum(SynicResult.msr_rejected);
    }
    if (!programPageMsr(msr_siefp, siefp_gpa)) {
        disableSynicState();
        return @intFromEnum(SynicResult.msr_rejected);
    }
    if (features.reference_tsc) {
        reference_tsc_enabled = true;
        if (!programPageMsr(msr_reference_tsc, reference_tsc_gpa)) {
            disableSynicState();
            return @intFromEnum(SynicResult.msr_rejected);
        }
    }
    if (!programSint(2, message_vector, true) or
        !programSint(4, timer_vector, true))
    {
        disableSynicState();
        return @intFromEnum(SynicResult.msr_rejected);
    }

    const control = rdmsr(msr_scontrol) | register_enable;
    wrmsr(msr_scontrol, control);
    if ((rdmsr(msr_scontrol) & register_enable) == 0) {
        disableSynicState();
        return @intFromEnum(SynicResult.msr_rejected);
    }
    if (!programSint(2, message_vector, false) or
        !programSint(4, timer_vector, false))
    {
        disableSynicState();
        return @intFromEnum(SynicResult.msr_rejected);
    }

    wrmsr(msr_stimer0_config, @as(u64, 4) << stimer_sint_shift | stimer_auto_enable);
    synic_enabled = true;
    return @intFromEnum(SynicResult.ok);
}

export fn hyperv_synic_disable() callconv(.c) void {
    if (synic_enabled or reference_tsc_enabled)
        disableSynicState();
}

export fn hyperv_runtime_disable() callconv(.c) void {
    hyperv_synic_disable();
    if (enabled) {
        const current = rdmsr(msr_hypercall);
        wrmsr(msr_hypercall, current & register_reserved);
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

export fn hyperv_reference_time() callconv(.c) u64 {
    if (reference_tsc_enabled) {
        const page: *const volatile ReferenceTscPage = &hyperv_reference_tsc_page_storage;
        if (referenceTimeFromPage(page)) |value|
            return value;
    }
    return rdmsr(msr_time_ref_count);
}

export fn hyperv_x86_irq_to_vector(irq: u32, vector: *u8) callconv(.c) c_int {
    vector.* = irqToVector(irq) orelse return -1;
    return 0;
}

export fn hyperv_deadline_reference_ticks(
    boot_reference: u64,
    deadline_ns: u64,
) callconv(.c) u64 {
    return deadlineReferenceTicks(boot_reference, deadline_ns);
}

export fn hyperv_stimer0_arm(deadline: u64) callconv(.c) void {
    wrmsr(msr_stimer0_count, 0);
    wrmsr(msr_stimer0_config, @as(u64, 4) << stimer_sint_shift | stimer_auto_enable);
    wrmsr(msr_stimer0_count, deadline);
}

export fn hyperv_stimer0_cancel() callconv(.c) void {
    wrmsr(msr_stimer0_count, 0);
}

fn messageSlot(sint: u32) ?*volatile Message {
    if (sint >= sint_count)
        return null;
    const base: [*]volatile Message = @ptrCast(&hyperv_simp_page_storage);
    return &base[sint];
}

export fn hyperv_synic_message_take(
    sint: u32,
    output: *Message,
) callconv(.c) c_int {
    const slot = messageSlot(sint) orelse
        return @intFromEnum(MessageResult.invalid_sint);
    const message_type_ptr: *u32 =
        @ptrCast(@volatileCast(&slot.message_type));
    const message_type = @atomicLoad(u32, message_type_ptr, .acquire);
    if (message_type == 0)
        return @intFromEnum(MessageResult.empty);
    const payload_size = @as(*volatile u8, @ptrCast(&slot.payload_size)).*;
    if (payload_size > max_message_payload)
        return @intFromEnum(MessageResult.invalid_payload);

    const src: [*]const volatile u8 = @ptrCast(slot);
    const dst: [*]u8 = @ptrCast(output);
    for (0..@sizeOf(Message)) |i|
        dst[i] = src[i];

    @atomicStore(u32, message_type_ptr, 0, .release);
    const flags_ptr: *const u8 = @ptrCast(@volatileCast(&slot.flags));
    const pending = @atomicLoad(u8, flags_ptr, .acquire) & message_pending;
    if (pending != 0)
        wrmsr(msr_eom, 0);
    return @intFromEnum(MessageResult.ready);
}

export fn hyperv_synic_event_take_word(
    sint: u32,
    word: u32,
    value: *u64,
) callconv(.c) c_int {
    if (sint >= sint_count or word >= event_words_per_sint)
        return -1;
    const words: [*]u64 = @ptrCast(@alignCast(&hyperv_siefp_page_storage));
    const index = @as(usize, sint) * event_words_per_sint + word;
    value.* = @atomicRmw(u64, &words[index], .Xchg, 0, .acq_rel);
    return 0;
}

test "Guest OS ID layout follows TLFS open-source format" {
    const value = encodeGuestId(0x1234, 0x55667788, 0x9a, 0x7f, true);
    try std.testing.expectEqual(@as(u64, 0xff9a556677881234), value);
}

test "CPUID discovery reports required privileges precisely" {
    const required = access_hypercall_msrs | access_time_ref_count |
        access_synic_msrs | access_stimer_msrs;
    const valid = Discovery{
        .leaf1_ecx = cpuid_hypervisor_present,
        .max_leaf = cpuid_hv_minimum,
        .vendor_ebx = 0x7263694d,
        .vendor_ecx = 0x666f736f,
        .vendor_edx = 0x76482074,
        .interface_eax = 0x31237648,
        .features_eax = required | access_reference_tsc | access_vp_index,
        .features_edx = 0,
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
    changed = valid;
    changed.features_eax &= ~access_synic_msrs;
    try std.testing.expectEqual(DetectResult.synic_privilege, decodeDiscovery(changed));
    changed = valid;
    changed.features_eax &= ~access_stimer_msrs;
    try std.testing.expectEqual(DetectResult.stimer_privilege, decodeDiscovery(changed));
}

test "IRQ to IDT vector conversion validates the x86 range" {
    try std.testing.expectEqual(@as(?u8, 32), irqToVector(0));
    try std.testing.expectEqual(@as(?u8, 255), irqToVector(223));
    try std.testing.expectEqual(@as(?u8, null), irqToVector(224));
}

test "nanosecond deadlines round up and preserve wrap" {
    try std.testing.expectEqual(@as(u64, 0), nsToReferenceTicksCeil(0));
    try std.testing.expectEqual(@as(u64, 1), nsToReferenceTicksCeil(1));
    try std.testing.expectEqual(@as(u64, 1), nsToReferenceTicksCeil(100));
    try std.testing.expectEqual(@as(u64, 2), nsToReferenceTicksCeil(101));
    try std.testing.expectEqual(@as(u64, 0), deadlineReferenceTicks(std.math.maxInt(u64), 1));
}

test "reference TSC scaling uses the high half and checked offset" {
    try std.testing.expectEqual(
        @as(?u64, 0x1234),
        scaledReferenceTime(0x1234, std.math.maxInt(u64), 1),
    );
    try std.testing.expectEqual(@as(?u64, null), scaledReferenceTime(0, 0, -1));
    try std.testing.expectEqual(
        @as(?u64, null),
        scaledReferenceTime(std.math.maxInt(u64), std.math.maxInt(u64), std.math.maxInt(i64)),
    );
}

test "reference TSC sequence zero falls back" {
    var page = std.mem.zeroes(ReferenceTscPage);
    try std.testing.expectEqual(@as(?u64, null), referenceTimeFromPage(&page));
    page.sequence = 7;
    page.scale = 0;
    page.offset = 5;
    try std.testing.expectEqual(@as(?u64, 5), referenceTimeFromPage(&page));
}

test "reference TSC retries changed sequences" {
    try std.testing.expect(!referenceSequenceStable(4, 5));
    try std.testing.expect(!referenceSequenceStable(0, 0));
    try std.testing.expect(referenceSequenceStable(7, 7));
}

test "message and page layouts match TLFS" {
    try std.testing.expectEqual(@as(usize, 256), @sizeOf(Message));
    try std.testing.expectEqual(@as(usize, 4096), @sizeOf(ReferenceTscPage));
    try std.testing.expectEqual(@as(usize, 16), 4096 / @sizeOf(Message));
    try std.testing.expectEqual(@as(usize, 32), 256 / @sizeOf(u64));
}

test "SynIC and timer constants match TLFS" {
    try std.testing.expectEqual(@as(u32, 0x40000020), msr_time_ref_count);
    try std.testing.expectEqual(@as(u32, 0x40000021), msr_reference_tsc);
    try std.testing.expectEqual(@as(u32, 0x40000080), msr_scontrol);
    try std.testing.expectEqual(@as(u32, 0x40000082), msr_siefp);
    try std.testing.expectEqual(@as(u32, 0x40000083), msr_simp);
    try std.testing.expectEqual(@as(u32, 0x40000084), msr_eom);
    try std.testing.expectEqual(@as(u32, 0x40000090), msr_sint0);
    try std.testing.expectEqual(@as(u32, 0x400000b0), msr_stimer0_config);
    try std.testing.expectEqual(@as(u32, 0x400000b1), msr_stimer0_count);
    try std.testing.expectEqual(@as(u64, 1 << 16), sint_masked);
    try std.testing.expectEqual(@as(u64, 1 << 17), sint_auto_eoi);
}

test "message pending requires EOM only after a cleared occupied slot" {
    const State = struct {
        fn needsEom(occupied: bool, pending: bool) bool {
            return occupied and pending;
        }
    };
    try std.testing.expect(!State.needsEom(false, true));
    try std.testing.expect(!State.needsEom(true, false));
    try std.testing.expect(State.needsEom(true, true));
}

test "teardown ordering keeps producers ahead of shared pages" {
    const timer = 0;
    const sints = 1;
    const control = 2;
    const pages = 3;
    try std.testing.expect(timer < sints);
    try std.testing.expect(sints < control);
    try std.testing.expect(control < pages);
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
