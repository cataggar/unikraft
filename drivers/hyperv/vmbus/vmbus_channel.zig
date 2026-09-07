// SPDX-License-Identifier: BSD-3-Clause
//
// VMBus channel wire formats follow Microsoft TLFS. Ring and GPADL behavior
// was checked against FreeBSD sys/dev/hyperv (BSD-2-Clause); see NOTICE.

const std = @import("std");

pub const page_size: usize = 4096;
pub const max_message: usize = 240;
pub const packet_header_size: usize = 16;
pub const packet_footer_size: usize = 8;
pub const gpadl_header_pfns: usize = (max_message - 28) / 8;
pub const gpadl_body_pfns: usize = (max_message - 16) / 8;
pub const signal_event_call: u64 = 0x005d;
const pending_size_feature: u32 = 1;

pub const PacketType = enum(u16) {
    data_inband = 6,
    data_using_transfer_pages = 7,
    data_using_gpadl = 8,
    data_using_gpa_direct = 9,
    cancel_request = 10,
    completion = 11,
    data_using_additional_packets = 12,
    additional_data = 13,
};

pub const RingResult = enum(c_int) {
    ok = 0,
    empty = 1,
    no_space = -1,
    malformed = -2,
    output_small = -3,
    invalid_ring = -4,
    overflow = -5,
};

pub const PacketMeta = extern struct {
    packet_type: u16,
    flags: u16,
    transaction_id: u64,
    descriptor_size: u32,
    payload_size: u32,
    total_size: u32,
    need_signal: u8,
    trailer_mismatch: u8,
};

pub const GpaRange = extern struct {
    byte_count: u32,
    byte_offset: u32,
    pfn_count: u32,
    pfns: [*]const u64,
};

pub const SignalInput = extern struct {
    connection_id: u32,
    event_flag: u16,
    reserved: u16,
};

pub const Hypercall = *const fn (?*anyopaque, u64) callconv(.c) u64;

var fence_byte: u8 = 0;

comptime {
    if (@sizeOf(SignalInput) != 8 or @alignOf(SignalInput) != 4)
        @compileError("SignalEvent input ABI changed");
    if (gpadl_header_pfns != 26 or gpadl_body_pfns != 28)
        @compileError("GPADL PFN chunk limits changed");
    if (@sizeOf(PacketMeta) != 32)
        @compileError("packet metadata C ABI changed");
}

fn zero(object: anytype) void {
    const bytes: [*]volatile u8 = @ptrCast(object);
    for (0..@sizeOf(@TypeOf(object.*))) |i|
        bytes[i] = 0;
}

fn zeroBytes(bytes: []u8) void {
    for (0..bytes.len) |i|
        @as(*volatile u8, @ptrCast(&bytes[i])).* = 0;
}

fn align8(value: usize) ?usize {
    if (value > std.math.maxInt(usize) - 7)
        return null;
    return (value + 7) & ~@as(usize, 7);
}

fn put16(dst: []u8, off: usize, value: u16) void {
    dst[off] = @truncate(value);
    dst[off + 1] = @truncate(value >> 8);
}

fn put32(dst: []u8, off: usize, value: u32) void {
    for (0..4) |i|
        dst[off + i] = @truncate(value >> @intCast(i * 8));
}

fn put64(dst: []u8, off: usize, value: u64) void {
    for (0..8) |i|
        dst[off + i] = @truncate(value >> @intCast(i * 8));
}

fn get16(src: []const u8, off: usize) u16 {
    return @as(u16, src[off]) | (@as(u16, src[off + 1]) << 8);
}

fn get32(src: []const u8, off: usize) u32 {
    var value: u32 = 0;
    for (0..4) |i|
        value |= @as(u32, src[off + i]) << @intCast(i * 8);
    return value;
}

fn get64(src: []const u8, off: usize) u64 {
    var value: u64 = 0;
    for (0..8) |i|
        value |= @as(u64, src[off + i]) << @intCast(i * 8);
    return value;
}

fn headerPtr(base: [*]u8, offset: usize) *u32 {
    return @ptrCast(@alignCast(base + offset));
}

fn loadHeader(base: [*]u8, offset: usize, comptime order: std.builtin.AtomicOrder) u32 {
    return @atomicLoad(u32, headerPtr(base, offset), order);
}

fn storeHeader(base: [*]u8, offset: usize, value: u32, comptime order: std.builtin.AtomicOrder) void {
    @atomicStore(u32, headerPtr(base, offset), value, order);
}

fn fullFence() void {
    _ = @atomicRmw(u8, &fence_byte, .Xchg, 0, .seq_cst);
}

fn postIndexStoreLoadFence() void {
    fullFence();
}

fn endReadStoreLoadFence() void {
    fullFence();
}

fn validateRing(total_size: usize) ?usize {
    if (total_size < page_size * 2 or total_size % page_size != 0)
        return null;
    const data_size = total_size - page_size;
    if (data_size > std.math.maxInt(u32))
        return null;
    return data_size;
}

fn ringCopyTo(base: [*]u8, data_size: usize, index: usize, src: []const u8) usize {
    var cursor = index;
    for (src) |byte| {
        @as(*volatile u8, @ptrCast(base + page_size + cursor)).* = byte;
        cursor += 1;
        if (cursor == data_size)
            cursor = 0;
    }
    return cursor;
}

fn ringCopyFrom(base: [*]u8, data_size: usize, index: usize, dst: []u8) usize {
    var cursor = index;
    for (dst) |*byte| {
        byte.* = @as(*volatile u8, @ptrCast(base + page_size + cursor)).*;
        cursor += 1;
        if (cursor == data_size)
            cursor = 0;
    }
    return cursor;
}

fn writable(read: u32, write: u32, size: u32) ?u32 {
    if (read >= size or write >= size)
        return null;
    return if (write >= read) size - (write - read) else read - write;
}

fn readable(read: u32, write: u32, size: u32) ?u32 {
    const free = writable(read, write, size) orelse return null;
    return size - free;
}

fn packetTypeValid(raw: u16) bool {
    return raw >= @intFromEnum(PacketType.data_inband) and
        raw <= @intFromEnum(PacketType.additional_data);
}

fn validateGpaDirectDescriptor(desc: []const u8) bool {
    if (desc.len < 8)
        return false;
    const ranges = get32(desc, 4);
    var off: usize = 8;
    var range_index: u32 = 0;
    while (range_index < ranges) : (range_index += 1) {
        if (off > desc.len or desc.len - off < 8)
            return false;
        const byte_count = get32(desc, off);
        const byte_offset = get32(desc, off + 4);
        off += 8;
        if (byte_offset >= page_size or byte_count == 0)
            return false;
        const covered = @as(u64, byte_offset) + byte_count;
        const pfn_count = (covered + page_size - 1) / page_size;
        if (pfn_count > (desc.len - off) / 8)
            return false;
        off += @intCast(pfn_count * 8);
    }
    return off == desc.len;
}

fn validateTransferPagesDescriptor(desc: []const u8) bool {
    if (desc.len < 8)
        return false;
    const owns = desc[2];
    const reserved = desc[3];
    const ranges = get32(desc, 4);
    if (owns > 1 or reserved != 0 or ranges > (desc.len - 8) / 8)
        return false;
    if (8 + @as(usize, ranges) * 8 != desc.len)
        return false;
    for (0..ranges) |i| {
        const off = 8 + i * 8;
        if (get32(desc, off) == 0)
            return false;
    }
    return true;
}

export fn vmbus_ring_initialize(base: [*]u8, total_size: usize) callconv(.c) c_int {
    _ = validateRing(total_size) orelse return @intFromEnum(RingResult.invalid_ring);
    for (0..total_size) |i|
        @as(*volatile u8, @ptrCast(base + i)).* = 0;
    storeHeader(base, 64, pending_size_feature, .release);
    return @intFromEnum(RingResult.ok);
}

const InterleaveHook = ?*const fn ([*]u8, usize) void;

fn ringWrite(
    base: [*]u8,
    total_size: usize,
    packet_type: u16,
    flags: u16,
    transaction_id: u64,
    descriptor: [*]const u8,
    descriptor_size: usize,
    payload: [*]const u8,
    payload_size: usize,
    need_signal: *u8,
    interleave: InterleaveHook,
) c_int {
    const data_size_usize = validateRing(total_size) orelse
        return @intFromEnum(RingResult.invalid_ring);
    const data_size: u32 = @intCast(data_size_usize);
    if (!packetTypeValid(packet_type))
        return @intFromEnum(RingResult.malformed);
    if (packet_type == @intFromEnum(PacketType.data_using_gpa_direct) and
        !validateGpaDirectDescriptor(descriptor[0..descriptor_size]))
        return @intFromEnum(RingResult.malformed);
    if (packet_type == @intFromEnum(PacketType.data_using_transfer_pages) and
        !validateTransferPagesDescriptor(descriptor[0..descriptor_size]))
        return @intFromEnum(RingResult.malformed);
    const desc_end = std.math.add(usize, packet_header_size, descriptor_size) catch
        return @intFromEnum(RingResult.overflow);
    const payload_off = align8(desc_end) orelse
        return @intFromEnum(RingResult.overflow);
    const packet_end = std.math.add(usize, payload_off, payload_size) catch
        return @intFromEnum(RingResult.overflow);
    const packet_size = align8(packet_end) orelse
        return @intFromEnum(RingResult.overflow);
    const total = std.math.add(usize, packet_size, packet_footer_size) catch
        return @intFromEnum(RingResult.overflow);
    if (total >= data_size_usize or packet_size / 8 > std.math.maxInt(u16) or
        payload_off / 8 > std.math.maxInt(u16))
        return @intFromEnum(RingResult.no_space);

    const old_write = loadHeader(base, 0, .acquire);
    const read = loadHeader(base, 4, .acquire);
    const free = writable(read, old_write, data_size) orelse
        return @intFromEnum(RingResult.malformed);
    if (total >= free) {
        storeHeader(base, 12, @intCast(total), .release);
        return @intFromEnum(RingResult.no_space);
    }

    var header: [packet_header_size]u8 = undefined;
    zeroBytes(&header);
    put16(&header, 0, packet_type);
    put16(&header, 2, @intCast(payload_off / 8));
    put16(&header, 4, @intCast(packet_size / 8));
    put16(&header, 6, flags);
    put64(&header, 8, transaction_id);

    var cursor: usize = old_write;
    cursor = ringCopyTo(base, data_size_usize, cursor, &header);
    cursor = ringCopyTo(base, data_size_usize, cursor, descriptor[0..descriptor_size]);
    const padding = payload_off - desc_end;
    for (0..padding) |_| {
        const zero_byte = [_]u8{0};
        cursor = ringCopyTo(base, data_size_usize, cursor, &zero_byte);
    }
    cursor = ringCopyTo(base, data_size_usize, cursor, payload[0..payload_size]);
    const tail_padding = packet_size - packet_end;
    for (0..tail_padding) |_| {
        const zero_byte = [_]u8{0};
        cursor = ringCopyTo(base, data_size_usize, cursor, &zero_byte);
    }
    var footer: [8]u8 = undefined;
    zeroBytes(&footer);
    put64(&footer, 0, @as(u64, old_write) << 32);
    cursor = ringCopyTo(base, data_size_usize, cursor, &footer);

    storeHeader(base, 12, 0, .release);
    fullFence();
    storeHeader(base, 0, @intCast(cursor), .release);
    postIndexStoreLoadFence();
    if (interleave) |hook|
        hook(base, data_size_usize);
    const post_read = loadHeader(base, 4, .acquire);
    const masked = loadHeader(base, 8, .acquire);
    need_signal.* = @intFromBool(masked == 0 and old_write == post_read);
    return @intFromEnum(RingResult.ok);
}

export fn vmbus_ring_write(
    base: [*]u8,
    total_size: usize,
    packet_type: u16,
    flags: u16,
    transaction_id: u64,
    descriptor: [*]const u8,
    descriptor_size: usize,
    payload: [*]const u8,
    payload_size: usize,
    need_signal: *u8,
) callconv(.c) c_int {
    return ringWrite(base, total_size, packet_type, flags, transaction_id, descriptor, descriptor_size, payload, payload_size, need_signal, null);
}

fn ringRead(
    base: [*]u8,
    total_size: usize,
    meta: *PacketMeta,
    descriptor_out: [*]u8,
    descriptor_capacity: usize,
    payload_out: [*]u8,
    payload_capacity: usize,
    interleave: InterleaveHook,
) c_int {
    const data_size_usize = validateRing(total_size) orelse
        return @intFromEnum(RingResult.invalid_ring);
    const data_size: u32 = @intCast(data_size_usize);
    const read = loadHeader(base, 4, .acquire);
    const write = loadHeader(base, 0, .acquire);
    const available = readable(read, write, data_size) orelse
        return @intFromEnum(RingResult.malformed);
    if (available == 0)
        return @intFromEnum(RingResult.empty);
    fullFence();
    if (available < packet_header_size + packet_footer_size)
        return @intFromEnum(RingResult.malformed);

    var header: [packet_header_size]u8 = undefined;
    _ = ringCopyFrom(base, data_size_usize, read, &header);
    const raw_type = get16(&header, 0);
    const payload_off = @as(usize, get16(&header, 2)) * 8;
    const packet_size = @as(usize, get16(&header, 4)) * 8;
    const flags = get16(&header, 6);
    const transaction_id = get64(&header, 8);
    if (!packetTypeValid(raw_type) or payload_off < packet_header_size or
        payload_off > packet_size or packet_size % 8 != 0)
        return @intFromEnum(RingResult.malformed);
    const total = packet_size + packet_footer_size;
    if (total > available or total >= data_size_usize)
        return @intFromEnum(RingResult.malformed);
    const descriptor_size = payload_off - packet_header_size;
    const payload_size = packet_size - payload_off;
    if (descriptor_size > descriptor_capacity or payload_size > payload_capacity)
        return @intFromEnum(RingResult.output_small);

    var cursor = (read + packet_header_size) % data_size_usize;
    cursor = ringCopyFrom(base, data_size_usize, cursor, descriptor_out[0..descriptor_size]);
    cursor = (read + payload_off) % data_size_usize;
    _ = ringCopyFrom(base, data_size_usize, cursor, payload_out[0..payload_size]);
    if (raw_type == @intFromEnum(PacketType.data_using_gpa_direct) and
        !validateGpaDirectDescriptor(descriptor_out[0..descriptor_size]))
        return @intFromEnum(RingResult.malformed);
    if (raw_type == @intFromEnum(PacketType.data_using_transfer_pages) and
        !validateTransferPagesDescriptor(descriptor_out[0..descriptor_size]))
        return @intFromEnum(RingResult.malformed);

    var footer: [8]u8 = undefined;
    const footer_index = (read + packet_size) % data_size_usize;
    _ = ringCopyFrom(base, data_size_usize, footer_index, &footer);
    const old_free = writable(read, write, data_size).?;
    const new_read: u32 = @intCast((read + total) % data_size_usize);
    fullFence();
    storeHeader(base, 4, new_read, .release);
    postIndexStoreLoadFence();
    if (interleave) |hook|
        hook(base, data_size_usize);
    const pending = loadHeader(base, 12, .acquire);
    const feature = loadHeader(base, 64, .acquire);
    const new_free = writable(new_read, write, data_size).?;

    zero(meta);
    meta.packet_type = raw_type;
    meta.flags = flags;
    meta.transaction_id = transaction_id;
    meta.descriptor_size = @intCast(descriptor_size);
    meta.payload_size = @intCast(payload_size);
    meta.total_size = @intCast(total);
    // The footer is informational; descriptor lengths define safe progress.
    meta.trailer_mismatch = @intFromBool(
        get64(&footer, 0) != (@as(u64, read) << 32),
    );
    meta.need_signal = @intFromBool((feature & pending_size_feature) != 0 and pending != 0 and
        old_free <= pending and new_free > pending);
    return @intFromEnum(RingResult.ok);
}

export fn vmbus_ring_read(
    base: [*]u8,
    total_size: usize,
    meta: *PacketMeta,
    descriptor_out: [*]u8,
    descriptor_capacity: usize,
    payload_out: [*]u8,
    payload_capacity: usize,
) callconv(.c) c_int {
    return ringRead(base, total_size, meta, descriptor_out, descriptor_capacity, payload_out, payload_capacity, null);
}

export fn vmbus_ring_set_interrupt_mask(
    base: [*]u8,
    total_size: usize,
    masked: u8,
) callconv(.c) c_int {
    _ = validateRing(total_size) orelse return @intFromEnum(RingResult.invalid_ring);
    storeHeader(base, 8, @intFromBool(masked != 0), .release);
    return 0;
}

fn ringUnmaskAndReadable(
    base: [*]u8,
    total_size: usize,
    interleave: InterleaveHook,
) u32 {
    const size: u32 = @intCast(validateRing(total_size) orelse return 0);
    storeHeader(base, 8, 0, .release);
    endReadStoreLoadFence();
    if (interleave) |hook|
        hook(base, @intCast(size));
    return readable(
        loadHeader(base, 4, .acquire),
        loadHeader(base, 0, .acquire),
        size,
    ) orelse 0;
}

export fn vmbus_ring_unmask_and_readable(
    base: [*]u8,
    total_size: usize,
) callconv(.c) u32 {
    return ringUnmaskAndReadable(base, total_size, null);
}

export fn vmbus_ring_readable(base: [*]u8, total_size: usize) callconv(.c) u32 {
    const size: u32 = @intCast(validateRing(total_size) orelse return 0);
    return readable(loadHeader(base, 4, .acquire), loadHeader(base, 0, .acquire), size) orelse 0;
}

export fn vmbus_gpadl_header(
    output: [*]u8,
    capacity: usize,
    channel_id: u32,
    gpadl_id: u32,
    byte_count: u32,
    pfns: [*]const u64,
    pfn_count: usize,
    consumed: *usize,
) callconv(.c) c_int {
    if (channel_id == 0 or gpadl_id == 0 or pfn_count == 0 or
        byte_count == 0 or byte_count % page_size != 0)
        return @intFromEnum(RingResult.malformed);
    if (@as(usize, byte_count / page_size) != pfn_count)
        return @intFromEnum(RingResult.malformed);
    const count: usize = @min(pfn_count, gpadl_header_pfns);
    const size = 28 + count * 8;
    const pfn_bytes = std.math.mul(usize, pfn_count, 8) catch
        return @intFromEnum(RingResult.overflow);
    const range_len = std.math.add(usize, 8, pfn_bytes) catch
        return @intFromEnum(RingResult.overflow);
    if (capacity < size or range_len > std.math.maxInt(u16))
        return @intFromEnum(RingResult.output_small);
    const out = output[0..size];
    zeroBytes(out);
    put32(out, 0, 8);
    put32(out, 8, channel_id);
    put32(out, 12, gpadl_id);
    put16(out, 16, @intCast(range_len));
    put16(out, 18, 1);
    put32(out, 20, byte_count);
    put32(out, 24, 0);
    for (0..count) |i|
        put64(out, 28 + i * 8, pfns[i]);
    consumed.* = count;
    return @intCast(size);
}

export fn vmbus_gpadl_body(
    output: [*]u8,
    capacity: usize,
    message_number: u32,
    gpadl_id: u32,
    pfns: [*]const u64,
    pfn_count: usize,
    consumed: *usize,
) callconv(.c) c_int {
    if (gpadl_id == 0 or pfn_count == 0)
        return @intFromEnum(RingResult.malformed);
    const count: usize = @min(pfn_count, gpadl_body_pfns);
    const size = 16 + count * 8;
    if (capacity < size)
        return @intFromEnum(RingResult.output_small);
    const out = output[0..size];
    zeroBytes(out);
    put32(out, 0, 9);
    put32(out, 8, message_number);
    put32(out, 12, gpadl_id);
    for (0..count) |i|
        put64(out, 16 + i * 8, pfns[i]);
    consumed.* = count;
    return @intCast(size);
}

export fn vmbus_open_message(
    output: [*]u8,
    capacity: usize,
    channel_id: u32,
    open_id: u32,
    gpadl_id: u32,
    target_vp: u32,
    tx_pages: u32,
    user_data: [*]const u8,
    user_data_size: usize,
) callconv(.c) c_int {
    if (capacity < 148 or channel_id == 0 or open_id == 0 or gpadl_id == 0 or
        tx_pages < 2 or user_data_size > 120)
        return @intFromEnum(RingResult.malformed);
    const out = output[0..148];
    zeroBytes(out);
    put32(out, 0, 5);
    put32(out, 8, channel_id);
    put32(out, 12, open_id);
    put32(out, 16, gpadl_id);
    put32(out, 20, target_vp);
    put32(out, 24, tx_pages);
    for (0..user_data_size) |i|
        out[28 + i] = user_data[i];
    return 148;
}

export fn vmbus_close_message(
    output: [*]u8,
    capacity: usize,
    channel_id: u32,
) callconv(.c) c_int {
    if (capacity < 12 or channel_id == 0)
        return @intFromEnum(RingResult.malformed);
    const out = output[0..12];
    zeroBytes(out);
    put32(out, 0, 7);
    put32(out, 8, channel_id);
    return 12;
}

export fn vmbus_gpadl_teardown_message(
    output: [*]u8,
    capacity: usize,
    channel_id: u32,
    gpadl_id: u32,
) callconv(.c) c_int {
    if (capacity < 16 or channel_id == 0 or gpadl_id == 0)
        return @intFromEnum(RingResult.malformed);
    const out = output[0..16];
    zeroBytes(out);
    put32(out, 0, 11);
    put32(out, 8, channel_id);
    put32(out, 12, gpadl_id);
    return 16;
}

export fn vmbus_signal_event(
    signal: *SignalInput,
    connection_id: u32,
    event_flag: u16,
    input_gpa: u64,
    hypercall: Hypercall,
    user_context: ?*anyopaque,
) callconv(.c) c_int {
    if (connection_id == 0 or (connection_id & 0xff000000) != 0)
        return -1;
    if ((input_gpa & 7) != 0)
        return -2;
    signal.connection_id = connection_id;
    signal.event_flag = event_flag;
    signal.reserved = 0;
    fullFence();
    return if (@as(u16, @truncate(hypercall(user_context, input_gpa))) == 0) 0 else -3;
}

fn testRing(pages: usize) []u8 {
    const Holder = struct {
        var memory: [page_size * 4]u8 align(page_size) = [_]u8{0} ** (page_size * 4);
    };
    return Holder.memory[0 .. pages * page_size];
}

test "ring reserved byte and exact boundary" {
    const ring = testRing(2);
    try std.testing.expectEqual(@as(c_int, 0), vmbus_ring_initialize(ring.ptr, ring.len));
    var signal: u8 = 0;
    const payload = [_]u8{0xaa} ** 4072;
    try std.testing.expectEqual(
        @intFromEnum(RingResult.no_space),
        vmbus_ring_write(ring.ptr, ring.len, 6, 0, 1, payload[0..0].ptr, 0, &payload, payload.len, &signal),
    );
}

test "ring empty write read and notification suppression" {
    const ring = testRing(2);
    _ = vmbus_ring_initialize(ring.ptr, ring.len);
    const payload = "hello";
    var signal: u8 = 0;
    try std.testing.expectEqual(@as(c_int, 0), vmbus_ring_write(
        ring.ptr,
        ring.len,
        6,
        1,
        42,
        payload.ptr,
        0,
        payload.ptr,
        payload.len,
        &signal,
    ));
    try std.testing.expectEqual(@as(u8, 1), signal);
    try std.testing.expect(vmbus_ring_readable(ring.ptr, ring.len) != 0);
    var meta: PacketMeta = undefined;
    var desc: [32]u8 = undefined;
    var out: [32]u8 = undefined;
    try std.testing.expectEqual(@intFromEnum(RingResult.output_small), vmbus_ring_read(
        ring.ptr,
        ring.len,
        &meta,
        &desc,
        desc.len,
        &out,
        0,
    ));
    try std.testing.expect(vmbus_ring_readable(ring.ptr, ring.len) != 0);
    try std.testing.expectEqual(@as(c_int, 0), vmbus_ring_read(
        ring.ptr,
        ring.len,
        &meta,
        &desc,
        desc.len,
        &out,
        out.len,
    ));
    try std.testing.expectEqual(@as(u8, 0), meta.trailer_mismatch);
    try std.testing.expectEqual(@as(u64, 42), meta.transaction_id);
    try std.testing.expectEqualStrings(payload, out[0..payload.len]);
    try std.testing.expectEqual(@as(u32, 0), vmbus_ring_readable(ring.ptr, ring.len));
    try std.testing.expectEqual(@intFromEnum(RingResult.empty), vmbus_ring_read(
        ring.ptr,
        ring.len,
        &meta,
        &desc,
        desc.len,
        &out,
        out.len,
    ));
    _ = vmbus_ring_set_interrupt_mask(ring.ptr, ring.len, 1);
    _ = vmbus_ring_write(ring.ptr, ring.len, 6, 0, 2, payload.ptr, 0, payload.ptr, payload.len, &signal);
    try std.testing.expectEqual(@as(u8, 0), signal);
}

test "ring single and double wrap preserve packets and footer" {
    const ring = testRing(2);
    _ = vmbus_ring_initialize(ring.ptr, ring.len);
    const data_size: u32 = @intCast(ring.len - page_size);
    storeHeader(ring.ptr, 0, data_size - 12, .release);
    storeHeader(ring.ptr, 4, data_size - 12, .release);
    var payload: [64]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @truncate(i);
    var signal: u8 = 0;
    _ = vmbus_ring_write(ring.ptr, ring.len, 6, 0, 9, payload[0..0].ptr, 0, &payload, payload.len, &signal);
    var meta: PacketMeta = undefined;
    var desc: [8]u8 = undefined;
    var out: [80]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), vmbus_ring_read(ring.ptr, ring.len, &meta, &desc, desc.len, &out, out.len));
    try std.testing.expectEqualSlices(u8, &payload, out[0..payload.len]);
    storeHeader(ring.ptr, 0, data_size - 4, .release);
    storeHeader(ring.ptr, 4, data_size - 4, .release);
    _ = vmbus_ring_write(ring.ptr, ring.len, 6, 0, 10, payload[0..0].ptr, 0, &payload, payload.len, &signal);
    try std.testing.expectEqual(@as(c_int, 0), vmbus_ring_read(ring.ptr, ring.len, &meta, &desc, desc.len, &out, out.len));
}

test "malformed truncated overflowing packets fail before output" {
    const ring = testRing(2);
    _ = vmbus_ring_initialize(ring.ptr, ring.len);
    storeHeader(ring.ptr, 0, 8, .release);
    var meta: PacketMeta = undefined;
    var out: [16]u8 = undefined;
    try std.testing.expectEqual(@intFromEnum(RingResult.malformed), vmbus_ring_read(
        ring.ptr,
        ring.len,
        &meta,
        &out,
        out.len,
        &out,
        out.len,
    ));
    try std.testing.expectEqual(@intFromEnum(RingResult.overflow), vmbus_ring_write(
        ring.ptr,
        ring.len,
        6,
        0,
        0,
        out[0..0].ptr,
        std.math.maxInt(usize),
        &out,
        1,
        &out[0],
    ));
}

test "pending send threshold requests notification" {
    const ring = testRing(2);
    _ = vmbus_ring_initialize(ring.ptr, ring.len);
    var signal: u8 = 0;
    const payload = [_]u8{1} ** 128;
    _ = vmbus_ring_write(ring.ptr, ring.len, 6, 0, 1, payload[0..0].ptr, 0, &payload, payload.len, &signal);
    const before = writable(loadHeader(ring.ptr, 4, .acquire), loadHeader(ring.ptr, 0, .acquire), @intCast(ring.len - page_size)).?;
    storeHeader(ring.ptr, 12, before + 64, .release);
    storeHeader(ring.ptr, 8, 1, .release);
    var meta: PacketMeta = undefined;
    var desc: [8]u8 = undefined;
    var out: [160]u8 = undefined;
    _ = vmbus_ring_read(ring.ptr, ring.len, &meta, &desc, desc.len, &out, out.len);
    try std.testing.expectEqual(@as(u8, 1), meta.need_signal);

    _ = vmbus_ring_write(ring.ptr, ring.len, 6, 0, 2, payload[0..0].ptr, 0, &payload, payload.len, &signal);
    storeHeader(ring.ptr, 12, @intCast(ring.len - page_size), .release);
    _ = vmbus_ring_read(ring.ptr, ring.len, &meta, &desc, desc.len, &out, out.len);
    try std.testing.expectEqual(@as(u8, 0), meta.need_signal);
}

test "write notification rechecks host drain and unmask after publication" {
    const Hooks = struct {
        var read_value: u32 = 0;
        fn drain(base: [*]u8, _: usize) void {
            storeHeader(base, 4, read_value, .release);
        }
        fn unmask(base: [*]u8, _: usize) void {
            storeHeader(base, 8, 0, .release);
        }
    };
    const ring = testRing(2);
    _ = vmbus_ring_initialize(ring.ptr, ring.len);
    const payload = [_]u8{1} ** 16;
    var signal: u8 = 0;
    _ = ringWrite(ring.ptr, ring.len, 6, 0, 1, payload[0..0].ptr, 0, &payload, payload.len, &signal, null);
    Hooks.read_value = loadHeader(ring.ptr, 0, .acquire);
    signal = 0;
    _ = ringWrite(ring.ptr, ring.len, 6, 0, 2, payload[0..0].ptr, 0, &payload, payload.len, &signal, Hooks.drain);
    try std.testing.expectEqual(@as(u8, 1), signal);

    storeHeader(ring.ptr, 4, loadHeader(ring.ptr, 0, .acquire), .release);
    storeHeader(ring.ptr, 8, 1, .release);
    signal = 0;
    _ = ringWrite(ring.ptr, ring.len, 6, 0, 3, payload[0..0].ptr, 0, &payload, payload.len, &signal, Hooks.unmask);
    try std.testing.expectEqual(@as(u8, 1), signal);
}

test "read notification observes pending store after read publication" {
    const Hooks = struct {
        fn pending(base: [*]u8, data_size: usize) void {
            storeHeader(base, 12, @intCast(data_size - 100), .release);
        }
    };
    const ring = testRing(2);
    _ = vmbus_ring_initialize(ring.ptr, ring.len);
    const payload = [_]u8{1} ** 128;
    var signal: u8 = 0;
    _ = vmbus_ring_write(ring.ptr, ring.len, 6, 0, 1, payload[0..0].ptr, 0, &payload, payload.len, &signal);
    storeHeader(ring.ptr, 8, 1, .release);
    var meta: PacketMeta = undefined;
    var desc: [8]u8 = undefined;
    var out: [160]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), ringRead(
        ring.ptr,
        ring.len,
        &meta,
        &desc,
        desc.len,
        &out,
        out.len,
        Hooks.pending,
    ));
    try std.testing.expectEqual(@as(u8, 1), meta.need_signal);
}

test "unmask end-read barrier observes concurrent host publication" {
    const Hook = struct {
        fn publish(base: [*]u8, _: usize) void {
            storeHeader(base, 0, 24, .release);
        }
    };
    const ring = testRing(2);
    _ = vmbus_ring_initialize(ring.ptr, ring.len);
    storeHeader(ring.ptr, 8, 1, .release);
    try std.testing.expectEqual(@as(u32, 24), ringUnmaskAndReadable(
        ring.ptr,
        ring.len,
        Hook.publish,
    ));
    try std.testing.expectEqual(@as(u32, 0), loadHeader(ring.ptr, 8, .acquire));
}

test "GPADL chunks derive from wire capacity" {
    var pfns: [60]u64 = undefined;
    for (&pfns, 0..) |*pfn, i| pfn.* = i + 1;
    var message: [240]u8 = undefined;
    var used: usize = 0;
    try std.testing.expectEqual(@as(c_int, 236), vmbus_gpadl_header(
        &message,
        message.len,
        2,
        3,
        60 * page_size,
        &pfns,
        pfns.len,
        &used,
    ));
    try std.testing.expectEqual(@as(usize, 26), used);
    try std.testing.expectEqual(@as(c_int, 240), vmbus_gpadl_body(
        &message,
        message.len,
        1,
        3,
        pfns[used..].ptr,
        pfns.len - used,
        &used,
    ));
    try std.testing.expectEqual(@as(usize, 28), used);
    const remaining = pfns.len - 26 - used;
    try std.testing.expectEqual(@as(c_int, @intCast(16 + remaining * 8)), vmbus_gpadl_body(
        &message,
        message.len,
        2,
        3,
        pfns[26 + used ..].ptr,
        remaining,
        &used,
    ));
    try std.testing.expectEqual(@as(usize, 6), used);
}

test "GPA direct descriptor validates ranges and PFNs" {
    const ring = testRing(2);
    _ = vmbus_ring_initialize(ring.ptr, ring.len);
    var desc: [24]u8 = [_]u8{0} ** 24;
    put32(&desc, 4, 1);
    put32(&desc, 8, 100);
    put32(&desc, 12, 20);
    put64(&desc, 16, 0x123);
    var signal: u8 = 0;
    const payload = "x";
    try std.testing.expectEqual(@as(c_int, 0), vmbus_ring_write(
        ring.ptr,
        ring.len,
        9,
        0,
        4,
        &desc,
        desc.len,
        payload.ptr,
        payload.len,
        &signal,
    ));
    put32(&desc, 12, page_size);
    try std.testing.expectEqual(@intFromEnum(RingResult.malformed), vmbus_ring_write(
        ring.ptr,
        ring.len,
        9,
        0,
        4,
        &desc,
        desc.len,
        payload.ptr,
        payload.len,
        &signal,
    ));
}

test "transfer page validation rejects corruption and footer mismatch progresses" {
    const ring = testRing(2);
    _ = vmbus_ring_initialize(ring.ptr, ring.len);
    var transfer: [16]u8 = [_]u8{0} ** 16;
    transfer[2] = 1;
    put32(&transfer, 4, 1);
    put32(&transfer, 8, 64);
    put32(&transfer, 12, 4);
    const payload = "data";
    var signal: u8 = 0;
    try std.testing.expectEqual(@as(c_int, 0), vmbus_ring_write(
        ring.ptr,
        ring.len,
        7,
        0,
        8,
        &transfer,
        transfer.len,
        payload.ptr,
        payload.len,
        &signal,
    ));
    const write = loadHeader(ring.ptr, 0, .acquire);
    const footer_index = (write + ring.len - page_size - packet_footer_size) %
        (ring.len - page_size);
    @as(*volatile u8, @ptrCast(ring.ptr + page_size + footer_index)).* = 1;
    var meta: PacketMeta = undefined;
    var desc: [32]u8 = undefined;
    var out: [32]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), vmbus_ring_read(
        ring.ptr,
        ring.len,
        &meta,
        &desc,
        desc.len,
        &out,
        out.len,
    ));
    try std.testing.expectEqual(@as(u8, 1), meta.trailer_mismatch);
    try std.testing.expectEqual(@intFromEnum(RingResult.empty), vmbus_ring_read(
        ring.ptr,
        ring.len,
        &meta,
        &desc,
        desc.len,
        &out,
        out.len,
    ));
    transfer[3] = 1;
    try std.testing.expectEqual(@intFromEnum(RingResult.malformed), vmbus_ring_write(
        ring.ptr,
        ring.len,
        7,
        0,
        9,
        &transfer,
        transfer.len,
        payload.ptr,
        payload.len,
        &signal,
    ));
}

test "control message layouts are exact" {
    var message: [240]u8 = undefined;
    const user = [_]u8{1} ** 120;
    try std.testing.expectEqual(@as(c_int, 148), vmbus_open_message(
        &message,
        message.len,
        7,
        9,
        11,
        3,
        4,
        &user,
        user.len,
    ));
    try std.testing.expectEqual(@as(u32, 5), get32(&message, 0));
    try std.testing.expectEqual(@as(u32, 7), get32(&message, 8));
    try std.testing.expectEqual(@as(u32, 4), get32(&message, 24));
    try std.testing.expectEqual(@as(c_int, 12), vmbus_close_message(
        &message,
        message.len,
        7,
    ));
    try std.testing.expectEqual(@as(c_int, 16), vmbus_gpadl_teardown_message(
        &message,
        message.len,
        7,
        11,
    ));
}

test "SignalEvent validates alignment and status" {
    const Fake = struct {
        var status: u64 = 0;
        fn call(_: ?*anyopaque, _: u64) callconv(.c) u64 {
            return status;
        }
    };
    var input: SignalInput align(8) = undefined;
    try std.testing.expectEqual(@as(c_int, 0), vmbus_signal_event(&input, 7, 2, 0x1000, Fake.call, null));
    try std.testing.expectEqual(@as(u32, 7), input.connection_id);
    try std.testing.expectEqual(@as(u16, 2), input.event_flag);
    try std.testing.expectEqual(@as(c_int, -2), vmbus_signal_event(&input, 7, 2, 0x1001, Fake.call, null));
    Fake.status = 5;
    try std.testing.expectEqual(@as(c_int, -3), vmbus_signal_event(&input, 7, 2, 0x1000, Fake.call, null));
}

test "per-channel SignalEvent inputs remain immutable across interleaving" {
    const Interleave = struct {
        var first: *SignalInput = undefined;
        var second: *SignalInput = undefined;
        var nested = false;
        fn call(_: ?*anyopaque, gpa: u64) callconv(.c) u64 {
            if (gpa == 0x1000 and !nested) {
                nested = true;
                _ = vmbus_signal_event(second, 22, 4, 0x2000, call, null);
                tryExpect(first.connection_id == 11 and first.event_flag == 3);
            } else if (gpa == 0x2000) {
                tryExpect(second.connection_id == 22 and second.event_flag == 4);
            }
            return 0;
        }
        fn tryExpect(ok: bool) void {
            if (!ok)
                @panic("SignalEvent input was overwritten");
        }
    };
    var first: SignalInput align(8) = undefined;
    var second: SignalInput align(8) = undefined;
    Interleave.first = &first;
    Interleave.second = &second;
    Interleave.nested = false;
    try std.testing.expectEqual(@as(c_int, 0), vmbus_signal_event(
        &first,
        11,
        3,
        0x1000,
        Interleave.call,
        null,
    ));
    try std.testing.expectEqual(@as(u32, 11), first.connection_id);
    try std.testing.expectEqual(@as(u32, 22), second.connection_id);
}
