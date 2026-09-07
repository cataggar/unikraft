// SPDX-License-Identifier: BSD-3-Clause
//
// Hyper-V NVS layouts follow the public Hyper-V protocol definitions and
// Microsoft MS-RNDIS. Behavior was checked against FreeBSD's BSD-2-Clause
// Hyper-V network driver; see NOTICE.

const std = @import("std");

pub const nvs_request_size: usize = 40;
pub const nvs_status_ok: u32 = 1;
pub const nvs_status_failed: u32 = 2;
pub const nvs_status_protocol_too_new: u32 = 3;
pub const nvs_status_protocol_too_old: u32 = 4;
pub const nvs_status_protocol_unsupported: u32 = 7;
pub const rx_buffer_id: u16 = 0xcafe;
pub const send_buffer_id: u16 = 0xface;
pub const send_section_invalid: u32 = 0xffff_ffff;
pub const max_sections: usize = 8;
pub const max_transfer_ranges: usize = 375;

pub const nvs_version_1: u32 = 0x0000_0002;
pub const nvs_version_2: u32 = 0x0003_0002;
pub const nvs_version_4: u32 = 0x0004_0000;
pub const nvs_version_5: u32 = 0x0005_0000;
pub const nvs_version_6: u32 = 0x0006_0000;
pub const nvs_version_61: u32 = 0x0006_0001;

pub const ndis_version_61: u32 = 0x0006_0001;
pub const ndis_version_630: u32 = 0x0006_001e;

pub const nvs_type_init: u32 = 1;
pub const nvs_type_init_complete: u32 = 2;
pub const nvs_type_ndis_version: u32 = 100;
pub const nvs_type_receive_buffer: u32 = 101;
pub const nvs_type_receive_buffer_complete: u32 = 102;
pub const nvs_type_revoke_receive_buffer: u32 = 103;
pub const nvs_type_send_buffer: u32 = 104;
pub const nvs_type_send_buffer_complete: u32 = 105;
pub const nvs_type_revoke_send_buffer: u32 = 106;
pub const nvs_type_send_rndis: u32 = 107;
pub const nvs_type_send_rndis_complete: u32 = 108;
pub const nvs_type_ndis_config: u32 = 125;

pub const nvs_rndis_data: u32 = 0;
pub const nvs_rndis_control: u32 = 1;

pub const rndis_packet: u32 = 0x0000_0001;
pub const rndis_initialize: u32 = 0x0000_0002;
pub const rndis_initialize_complete: u32 = 0x8000_0002;
pub const rndis_halt: u32 = 0x0000_0003;
pub const rndis_query: u32 = 0x0000_0004;
pub const rndis_query_complete: u32 = 0x8000_0004;
pub const rndis_set: u32 = 0x0000_0005;
pub const rndis_set_complete: u32 = 0x8000_0005;
pub const rndis_indicate_status: u32 = 0x0000_0007;
pub const rndis_keepalive: u32 = 0x0000_0008;
pub const rndis_keepalive_complete: u32 = 0x8000_0008;

pub const rndis_status_success: u32 = 0;
pub const rndis_status_media_connect: u32 = 0x4001_000b;
pub const rndis_status_media_disconnect: u32 = 0x4001_000c;
pub const rndis_status_link_speed_change: u32 = 0x4001_0013;
pub const rndis_status_network_change: u32 = 0x4001_0018;

pub const oid_gen_maximum_frame_size: u32 = 0x0001_0106;
pub const oid_gen_current_packet_filter: u32 = 0x0001_010e;
pub const oid_gen_maximum_total_size: u32 = 0x0001_0111;
pub const oid_gen_media_connect_status: u32 = 0x0001_0114;
pub const oid_802_3_permanent_address: u32 = 0x0101_0101;
pub const oid_802_3_current_address: u32 = 0x0101_0102;

pub const packet_filter_none: u32 = 0;
pub const packet_filter_directed: u32 = 0x0000_0001;
pub const packet_filter_multicast: u32 = 0x0000_0002;
pub const packet_filter_all_multicast: u32 = 0x0000_0004;
pub const packet_filter_broadcast: u32 = 0x0000_0008;
pub const packet_filter_promiscuous: u32 = 0x0000_0020;

const rndis_version_major: u32 = 1;
const rndis_version_minor: u32 = 0;
const rndis_medium_802_3: u32 = 0;
const rndis_device_connectionless: u32 = 1;
const rndis_relative_base: usize = 8;
const rndis_packet_header_size: usize = 44;
const rndis_packet_offset_min: u32 = 36;

pub const Result = enum(c_int) {
    ok = 0,
    invalid = -1,
    output_small = -2,
    overflow = -3,
    unexpected = -4,
    remote_failure = -5,
    version_unsupported = -6,
};

pub const NvsInitComplete = extern struct {
    version: u32,
    max_mdl_chain: u32,
    status: u32,
};

pub const NvsSection = extern struct {
    start: u32,
    slot_size: u32,
    slot_count: u32,
    end: u32,
};

pub const NvsSendBufferComplete = extern struct {
    section_size: u32,
    section_count: u32,
};

pub const TransferRange = extern struct {
    offset: u32,
    length: u32,
    section_index: u16,
    reserved: u16,
};

pub const RndisCompletion = extern struct {
    message_type: u32,
    message_length: u32,
    request_id: u32,
    status: u32,
    info_offset: u32,
    info_length: u32,
    max_packets: u32,
    max_transfer_size: u32,
    alignment: u32,
};

pub const RndisPacketInfo = extern struct {
    message_length: u32,
    data_offset: u32,
    data_length: u32,
    packet_info_offset: u32,
    packet_info_length: u32,
};

pub const RndisStatusInfo = extern struct {
    status: u32,
    buffer_offset: u32,
    buffer_length: u32,
    link_state: i32,
};

comptime {
    if (@sizeOf(NvsInitComplete) != 12)
        @compileError("NVS init completion ABI changed");
    if (@sizeOf(NvsSection) != 16)
        @compileError("NVS section ABI changed");
    if (@sizeOf(NvsSendBufferComplete) != 8)
        @compileError("NVS send-buffer completion ABI changed");
    if (@sizeOf(TransferRange) != 12 or @offsetOf(TransferRange, "section_index") != 8)
        @compileError("NVS transfer-range ABI changed");
    if (@sizeOf(RndisCompletion) != 36 or @offsetOf(RndisCompletion, "status") != 12)
        @compileError("RNDIS completion ABI changed");
    if (@sizeOf(RndisPacketInfo) != 20)
        @compileError("RNDIS packet parser ABI changed");
    if (@sizeOf(RndisStatusInfo) != 16)
        @compileError("RNDIS status parser ABI changed");
}

fn zeroBytes(bytes: []u8) void {
    for (bytes) |*byte|
        @as(*volatile u8, @ptrCast(byte)).* = 0;
}

fn zeroObject(object: anytype) void {
    const bytes: [*]volatile u8 = @ptrCast(object);
    for (0..@sizeOf(@TypeOf(object.*))) |i|
        bytes[i] = 0;
}

fn put16(dst: []u8, offset: usize, value: u16) void {
    dst[offset] = @truncate(value);
    dst[offset + 1] = @truncate(value >> 8);
}

fn put32(dst: []u8, offset: usize, value: u32) void {
    for (0..4) |i|
        dst[offset + i] = @truncate(value >> @intCast(i * 8));
}

fn put64(dst: []u8, offset: usize, value: u64) void {
    for (0..8) |i|
        dst[offset + i] = @truncate(value >> @intCast(i * 8));
}

fn get16(src: []const u8, offset: usize) u16 {
    return @as(u16, src[offset]) | (@as(u16, src[offset + 1]) << 8);
}

fn get32(src: []const u8, offset: usize) u32 {
    var value: u32 = 0;
    for (0..4) |i|
        value |= @as(u32, src[offset + i]) << @intCast(i * 8);
    return value;
}

fn addUsize(a: usize, b: usize) ?usize {
    return std.math.add(usize, a, b) catch null;
}

fn mulUsize(a: usize, b: usize) ?usize {
    return std.math.mul(usize, a, b) catch null;
}

fn regionEnd(offset: u32, length: u32) ?u32 {
    return std.math.add(u32, offset, length) catch null;
}

fn regionsOverlap(first_offset: u32, first_length: u32, second_offset: u32, second_length: u32) bool {
    if (first_length == 0 or second_length == 0)
        return false;
    const first_end = regionEnd(first_offset, first_length) orelse return true;
    const second_end = regionEnd(second_offset, second_length) orelse return true;
    return first_offset < second_end and second_offset < first_end;
}

fn buildNvsBase(output: [*]u8, capacity: usize, message_type: u32) ?[]u8 {
    if (capacity < nvs_request_size)
        return null;
    const out = output[0..nvs_request_size];
    zeroBytes(out);
    put32(out, 0, message_type);
    return out;
}

export fn netvsc_nvs_version_count() callconv(.c) u32 {
    return 6;
}

export fn netvsc_nvs_version(index: u32) callconv(.c) u32 {
    return switch (index) {
        0 => nvs_version_61,
        1 => nvs_version_6,
        2 => nvs_version_5,
        3 => nvs_version_4,
        4 => nvs_version_2,
        5 => nvs_version_1,
        else => 0,
    };
}

export fn netvsc_nvs_ndis_version(nvs_version: u32) callconv(.c) u32 {
    return switch (nvs_version) {
        nvs_version_1, nvs_version_2, nvs_version_4 => ndis_version_61,
        nvs_version_5, nvs_version_6, nvs_version_61 => ndis_version_630,
        else => 0,
    };
}

export fn netvsc_nvs_build_init(
    output: [*]u8,
    capacity: usize,
    version: u32,
) callconv(.c) c_int {
    if (netvsc_nvs_ndis_version(version) == 0)
        return @intFromEnum(Result.invalid);
    const out = buildNvsBase(output, capacity, nvs_type_init) orelse
        return @intFromEnum(Result.output_small);
    put32(out, 4, version);
    put32(out, 8, version);
    return nvs_request_size;
}

export fn netvsc_nvs_build_ndis_config(
    output: [*]u8,
    capacity: usize,
    frame_size: u32,
) callconv(.c) c_int {
    if (frame_size < 14)
        return @intFromEnum(Result.invalid);
    const out = buildNvsBase(output, capacity, nvs_type_ndis_config) orelse
        return @intFromEnum(Result.output_small);
    put32(out, 4, frame_size);
    put64(out, 12, 0);
    return nvs_request_size;
}

export fn netvsc_nvs_build_ndis_version(
    output: [*]u8,
    capacity: usize,
    ndis_version: u32,
) callconv(.c) c_int {
    if (ndis_version != ndis_version_61 and ndis_version != ndis_version_630)
        return @intFromEnum(Result.invalid);
    const out = buildNvsBase(output, capacity, nvs_type_ndis_version) orelse
        return @intFromEnum(Result.output_small);
    put32(out, 4, ndis_version >> 16);
    put32(out, 8, ndis_version & 0xffff);
    return nvs_request_size;
}

fn buildBufferMessage(
    output: [*]u8,
    capacity: usize,
    message_type: u32,
    gpadl_id: u32,
    buffer_id: u16,
) c_int {
    if (gpadl_id == 0)
        return @intFromEnum(Result.invalid);
    const out = buildNvsBase(output, capacity, message_type) orelse
        return @intFromEnum(Result.output_small);
    put32(out, 4, gpadl_id);
    put16(out, 8, buffer_id);
    return nvs_request_size;
}

fn buildRevokeMessage(
    output: [*]u8,
    capacity: usize,
    message_type: u32,
    buffer_id: u16,
) c_int {
    const out = buildNvsBase(output, capacity, message_type) orelse
        return @intFromEnum(Result.output_small);
    put16(out, 4, buffer_id);
    return nvs_request_size;
}

export fn netvsc_nvs_build_receive_buffer(
    output: [*]u8,
    capacity: usize,
    gpadl_id: u32,
) callconv(.c) c_int {
    return buildBufferMessage(output, capacity, nvs_type_receive_buffer, gpadl_id, rx_buffer_id);
}

export fn netvsc_nvs_build_revoke_receive_buffer(
    output: [*]u8,
    capacity: usize,
) callconv(.c) c_int {
    return buildRevokeMessage(output, capacity, nvs_type_revoke_receive_buffer, rx_buffer_id);
}

export fn netvsc_nvs_build_send_buffer(
    output: [*]u8,
    capacity: usize,
    gpadl_id: u32,
) callconv(.c) c_int {
    return buildBufferMessage(output, capacity, nvs_type_send_buffer, gpadl_id, send_buffer_id);
}

export fn netvsc_nvs_build_revoke_send_buffer(
    output: [*]u8,
    capacity: usize,
) callconv(.c) c_int {
    return buildRevokeMessage(output, capacity, nvs_type_revoke_send_buffer, send_buffer_id);
}

export fn netvsc_nvs_build_rndis(
    output: [*]u8,
    capacity: usize,
    channel_type: u32,
    section_index: u32,
    section_size: u32,
) callconv(.c) c_int {
    if ((channel_type != nvs_rndis_data and channel_type != nvs_rndis_control) or
        (section_index == send_section_invalid and section_size != 0) or
        (section_index != send_section_invalid and section_size == 0))
        return @intFromEnum(Result.invalid);
    const out = buildNvsBase(output, capacity, nvs_type_send_rndis) orelse
        return @intFromEnum(Result.output_small);
    put32(out, 4, channel_type);
    put32(out, 8, section_index);
    put32(out, 12, section_size);
    return nvs_request_size;
}

export fn netvsc_nvs_build_rndis_ack(
    output: [*]u8,
    capacity: usize,
    status: u32,
) callconv(.c) c_int {
    if (status != nvs_status_ok and status != nvs_status_failed)
        return @intFromEnum(Result.invalid);
    const out = buildNvsBase(output, capacity, nvs_type_send_rndis_complete) orelse
        return @intFromEnum(Result.output_small);
    put32(out, 4, status);
    return nvs_request_size;
}

export fn netvsc_nvs_parse_init_complete(
    input: [*]const u8,
    length: usize,
    requested_version: u32,
    result: *NvsInitComplete,
) callconv(.c) c_int {
    zeroObject(result);
    if (length < 16 or get32(input[0..length], 0) != nvs_type_init_complete)
        return @intFromEnum(Result.invalid);
    if (netvsc_nvs_ndis_version(requested_version) == 0)
        return @intFromEnum(Result.invalid);
    result.version = requested_version;
    result.max_mdl_chain = get32(input[0..length], 8);
    result.status = get32(input[0..length], 12);
    return switch (result.status) {
        nvs_status_ok => @intFromEnum(Result.ok),
        nvs_status_failed,
        nvs_status_protocol_too_new,
        nvs_status_protocol_too_old,
        nvs_status_protocol_unsupported,
        => @intFromEnum(Result.version_unsupported),
        else => @intFromEnum(Result.remote_failure),
    };
}

export fn netvsc_nvs_parse_receive_buffer_complete(
    input: [*]const u8,
    length: usize,
    buffer_size: u32,
    sections: [*]NvsSection,
    section_capacity: usize,
    section_count: *u32,
) callconv(.c) c_int {
    section_count.* = 0;
    if (length < 12 or buffer_size == 0 or section_capacity == 0)
        return @intFromEnum(Result.invalid);
    const bytes = input[0..length];
    if (get32(bytes, 0) != nvs_type_receive_buffer_complete)
        return @intFromEnum(Result.unexpected);
    if (get32(bytes, 4) != nvs_status_ok)
        return @intFromEnum(Result.remote_failure);
    const count = get32(bytes, 8);
    if (count == 0 or count > max_sections or count > section_capacity)
        return @intFromEnum(Result.invalid);
    const table_size = mulUsize(@intCast(count), 16) orelse
        return @intFromEnum(Result.overflow);
    const required = addUsize(12, table_size) orelse
        return @intFromEnum(Result.overflow);
    if (required > length)
        return @intFromEnum(Result.invalid);

    var index: usize = 0;
    while (index < count) : (index += 1) {
        const offset = 12 + index * 16;
        const start = get32(bytes, offset);
        const slot_size = get32(bytes, offset + 4);
        const slot_count = get32(bytes, offset + 8);
        // EndOffset is informational; the computed span bounds every access.
        if (slot_size == 0 or (slot_size & 3) != 0 or slot_count == 0 or
            start >= buffer_size or (start & 3) != 0)
            return @intFromEnum(Result.invalid);
        const span = std.math.mul(u32, slot_size, slot_count) catch
            return @intFromEnum(Result.overflow);
        const end = std.math.add(u32, start, span) catch
            return @intFromEnum(Result.overflow);
        if (end > buffer_size)
            return @intFromEnum(Result.invalid);
        sections[index] = .{
            .start = start,
            .slot_size = slot_size,
            .slot_count = slot_count,
            .end = end,
        };
    }

    index = 0;
    while (index < count) : (index += 1) {
        var other = index + 1;
        while (other < count) : (other += 1) {
            if (regionsOverlap(
                sections[index].start,
                sections[index].end - sections[index].start,
                sections[other].start,
                sections[other].end - sections[other].start,
            ))
                return @intFromEnum(Result.invalid);
        }
    }
    section_count.* = count;
    return @intFromEnum(Result.ok);
}

export fn netvsc_nvs_parse_send_buffer_complete(
    input: [*]const u8,
    length: usize,
    buffer_size: u32,
    result: *NvsSendBufferComplete,
) callconv(.c) c_int {
    zeroObject(result);
    if (length < 12 or buffer_size == 0)
        return @intFromEnum(Result.invalid);
    const bytes = input[0..length];
    if (get32(bytes, 0) != nvs_type_send_buffer_complete)
        return @intFromEnum(Result.unexpected);
    if (get32(bytes, 4) != nvs_status_ok)
        return @intFromEnum(Result.remote_failure);
    const size = get32(bytes, 8);
    if (size == 0 or (size & 3) != 0 or size > buffer_size)
        return @intFromEnum(Result.invalid);
    result.section_size = size;
    result.section_count = buffer_size / size;
    if (result.section_count == 0)
        return @intFromEnum(Result.invalid);
    return @intFromEnum(Result.ok);
}

export fn netvsc_nvs_parse_rndis_completion(
    input: [*]const u8,
    length: usize,
) callconv(.c) c_int {
    if (length < 8)
        return @intFromEnum(Result.invalid);
    const bytes = input[0..length];
    if (get32(bytes, 0) != nvs_type_send_rndis_complete)
        return @intFromEnum(Result.unexpected);
    return if (get32(bytes, 4) == nvs_status_ok)
        @intFromEnum(Result.ok)
    else
        @intFromEnum(Result.remote_failure);
}

export fn netvsc_nvs_message_type(
    input: [*]const u8,
    length: usize,
    message_type: *u32,
) callconv(.c) c_int {
    message_type.* = 0;
    if (length < 4)
        return @intFromEnum(Result.invalid);
    message_type.* = get32(input[0..length], 0);
    return @intFromEnum(Result.ok);
}

export fn netvsc_nvs_parse_rndis(
    input: [*]const u8,
    length: usize,
    channel_type: *u32,
) callconv(.c) c_int {
    channel_type.* = 0;
    if (length < 8)
        return @intFromEnum(Result.invalid);
    const bytes = input[0..length];
    if (get32(bytes, 0) != nvs_type_send_rndis)
        return @intFromEnum(Result.unexpected);
    const kind = get32(bytes, 4);
    channel_type.* = kind;
    return @intFromEnum(Result.ok);
}

export fn netvsc_nvs_transfer_range_count(
    descriptor: [*]const u8,
    descriptor_length: usize,
    range_count: *u32,
) callconv(.c) c_int {
    range_count.* = 0;
    if (descriptor_length < 8)
        return @intFromEnum(Result.invalid);
    const bytes = descriptor[0..descriptor_length];
    if (get16(bytes, 0) != rx_buffer_id or bytes[2] > 1 or bytes[3] != 0)
        return @intFromEnum(Result.unexpected);
    const count = get32(bytes, 4);
    if (count == 0 or count > max_transfer_ranges)
        return @intFromEnum(Result.invalid);
    const range_bytes = mulUsize(@intCast(count), 8) orelse
        return @intFromEnum(Result.overflow);
    const required = addUsize(8, range_bytes) orelse
        return @intFromEnum(Result.overflow);
    if (required > descriptor_length or
        (descriptor_length - required) % 4 != 0)
        return @intFromEnum(Result.invalid);
    range_count.* = count;
    return @intFromEnum(Result.ok);
}

export fn netvsc_nvs_parse_transfer_range(
    descriptor: [*]const u8,
    descriptor_length: usize,
    range_index: u32,
    buffer_size: u32,
    sections: [*]const NvsSection,
    section_count: u32,
    result: *TransferRange,
) callconv(.c) c_int {
    zeroObject(result);
    if (section_count == 0 or section_count > max_sections)
        return @intFromEnum(Result.invalid);
    var count: u32 = 0;
    const count_rc = netvsc_nvs_transfer_range_count(
        descriptor,
        descriptor_length,
        &count,
    );
    if (count_rc != @intFromEnum(Result.ok))
        return count_rc;
    if (range_index >= count)
        return @intFromEnum(Result.invalid);
    const bytes = descriptor[0..descriptor_length];
    const offset = 8 + @as(usize, range_index) * 8;
    const range_length = get32(bytes, offset);
    const range_offset = get32(bytes, offset + 4);
    const range_end = regionEnd(range_offset, range_length) orelse
        return @intFromEnum(Result.overflow);
    if (range_length == 0 or range_end > buffer_size)
        return @intFromEnum(Result.invalid);

    var index: u32 = 0;
    while (index < section_count) : (index += 1) {
        const section = sections[index];
        if (section.slot_size == 0 or section.slot_count == 0 or
            section.end <= section.start or section.end > buffer_size)
            return @intFromEnum(Result.invalid);
        if (range_offset < section.start or range_end > section.end)
            continue;
        result.offset = range_offset;
        result.length = range_length;
        result.section_index = @intCast(index);
        return @intFromEnum(Result.ok);
    }
    return @intFromEnum(Result.invalid);
}

fn buildRndis(output: [*]u8, capacity: usize, length: usize, message_type: u32, request_id: u32) ?[]u8 {
    if (capacity < length or length > std.math.maxInt(u32) or request_id == 0)
        return null;
    const out = output[0..length];
    zeroBytes(out);
    put32(out, 0, message_type);
    put32(out, 4, @intCast(length));
    put32(out, 8, request_id);
    return out;
}

export fn netvsc_rndis_build_initialize(
    output: [*]u8,
    capacity: usize,
    request_id: u32,
    max_transfer_size: u32,
) callconv(.c) c_int {
    if (max_transfer_size < 512)
        return @intFromEnum(Result.invalid);
    const out = buildRndis(output, capacity, 24, rndis_initialize, request_id) orelse
        return @intFromEnum(Result.output_small);
    put32(out, 12, rndis_version_major);
    put32(out, 16, rndis_version_minor);
    put32(out, 20, max_transfer_size);
    return 24;
}

export fn netvsc_rndis_build_query(
    output: [*]u8,
    capacity: usize,
    request_id: u32,
    oid: u32,
    info: [*]const u8,
    info_length: usize,
) callconv(.c) c_int {
    const length = addUsize(28, info_length) orelse
        return @intFromEnum(Result.overflow);
    const out = buildRndis(output, capacity, length, rndis_query, request_id) orelse
        return @intFromEnum(Result.output_small);
    if (oid == 0 or info_length > std.math.maxInt(u32))
        return @intFromEnum(Result.invalid);
    put32(out, 12, oid);
    put32(out, 16, @intCast(info_length));
    // Hyper-V requires the canonical post-RequestId offset even for an empty
    // query input, despite MS-RNDIS requiring zero in that special case.
    put32(out, 20, 20);
    if (info_length != 0) {
        for (0..info_length) |i|
            out[28 + i] = info[i];
    }
    return @intCast(length);
}

export fn netvsc_rndis_build_set(
    output: [*]u8,
    capacity: usize,
    request_id: u32,
    oid: u32,
    info: [*]const u8,
    info_length: usize,
) callconv(.c) c_int {
    const length = addUsize(28, info_length) orelse
        return @intFromEnum(Result.overflow);
    const out = buildRndis(output, capacity, length, rndis_set, request_id) orelse
        return @intFromEnum(Result.output_small);
    if (oid == 0 or info_length == 0 or info_length > std.math.maxInt(u32))
        return @intFromEnum(Result.invalid);
    put32(out, 12, oid);
    put32(out, 16, @intCast(info_length));
    put32(out, 20, 20);
    for (0..info_length) |i|
        out[28 + i] = info[i];
    return @intCast(length);
}

export fn netvsc_rndis_build_keepalive(
    output: [*]u8,
    capacity: usize,
    request_id: u32,
) callconv(.c) c_int {
    _ = buildRndis(output, capacity, 12, rndis_keepalive, request_id) orelse
        return @intFromEnum(Result.output_small);
    return 12;
}

export fn netvsc_rndis_build_halt(
    output: [*]u8,
    capacity: usize,
    request_id: u32,
) callconv(.c) c_int {
    _ = buildRndis(output, capacity, 12, rndis_halt, request_id) orelse
        return @intFromEnum(Result.output_small);
    return 12;
}

export fn netvsc_rndis_build_packet_header(
    output: [*]u8,
    capacity: usize,
    frame_length: u32,
) callconv(.c) c_int {
    if (frame_length == 0)
        return @intFromEnum(Result.invalid);
    const message_length = std.math.add(u32, @intCast(rndis_packet_header_size), frame_length) catch
        return @intFromEnum(Result.overflow);
    if (capacity < rndis_packet_header_size)
        return @intFromEnum(Result.output_small);
    const out = output[0..rndis_packet_header_size];
    zeroBytes(out);
    put32(out, 0, rndis_packet);
    put32(out, 4, message_length);
    put32(out, 8, rndis_packet_offset_min);
    put32(out, 12, frame_length);
    return rndis_packet_header_size;
}

export fn netvsc_rndis_message_type(
    input: [*]const u8,
    length: usize,
    message_type: *u32,
    message_length: *u32,
) callconv(.c) c_int {
    message_type.* = 0;
    message_length.* = 0;
    if (length < 8)
        return @intFromEnum(Result.invalid);
    const bytes = input[0..length];
    const declared = get32(bytes, 4);
    if (declared < 8 or declared > length)
        return @intFromEnum(Result.invalid);
    message_type.* = get32(bytes, 0);
    message_length.* = declared;
    return @intFromEnum(Result.ok);
}

export fn netvsc_rndis_parse_completion(
    input: [*]const u8,
    length: usize,
    expected_type: u32,
    expected_request_id: u32,
    result: *RndisCompletion,
) callconv(.c) c_int {
    zeroObject(result);
    if (length < 16 or expected_request_id == 0)
        return @intFromEnum(Result.invalid);
    const bytes = input[0..length];
    const message_type = get32(bytes, 0);
    const message_length = get32(bytes, 4);
    const request_id = get32(bytes, 8);
    if (message_length < 16 or message_length > length)
        return @intFromEnum(Result.invalid);
    if (message_type != expected_type or request_id != expected_request_id)
        return @intFromEnum(Result.unexpected);
    result.message_type = message_type;
    result.message_length = message_length;
    result.request_id = request_id;
    result.status = get32(bytes, 12);
    if (result.status != rndis_status_success)
        return @intFromEnum(Result.remote_failure);

    switch (expected_type) {
        rndis_initialize_complete => {
            if (message_length < 48)
                return @intFromEnum(Result.invalid);
            if (get32(bytes, 16) != rndis_version_major or
                get32(bytes, 20) != rndis_version_minor or
                (get32(bytes, 24) & rndis_device_connectionless) == 0 or
                get32(bytes, 28) != rndis_medium_802_3)
                return @intFromEnum(Result.unexpected);
            result.max_packets = get32(bytes, 32);
            result.max_transfer_size = get32(bytes, 36);
            const alignment_exponent = get32(bytes, 40);
            if (result.max_packets == 0 or result.max_transfer_size < rndis_packet_header_size or
                alignment_exponent > 31)
                return @intFromEnum(Result.invalid);
            result.alignment = @as(u32, 1) << @intCast(alignment_exponent);
            if (result.alignment < 4)
                result.alignment = 4;
        },
        rndis_query_complete => {
            if (message_length < 24)
                return @intFromEnum(Result.invalid);
            result.info_length = get32(bytes, 16);
            const relative = get32(bytes, 20);
            if (result.info_length == 0) {
                if (relative != 0)
                    return @intFromEnum(Result.invalid);
            } else {
                if (relative == 0)
                    return @intFromEnum(Result.invalid);
                result.info_offset = std.math.add(u32, relative, rndis_relative_base) catch
                    return @intFromEnum(Result.overflow);
                if (result.info_offset < 24)
                    return @intFromEnum(Result.invalid);
                const end = regionEnd(result.info_offset, result.info_length) orelse
                    return @intFromEnum(Result.overflow);
                if (end > message_length)
                    return @intFromEnum(Result.invalid);
            }
        },
        rndis_set_complete, rndis_keepalive_complete => {
            if (message_length < 16)
                return @intFromEnum(Result.invalid);
        },
        else => return @intFromEnum(Result.invalid),
    }
    return @intFromEnum(Result.ok);
}

fn validatePacketInfo(bytes: []const u8, offset: u32, length: u32) bool {
    if (length == 0)
        return offset == 0;
    if ((offset & 3) != 0)
        return false;
    const end = regionEnd(offset, length) orelse return false;
    if (offset < rndis_packet_header_size or end > bytes.len)
        return false;
    var cursor: u32 = offset;
    while (cursor < end) {
        if (end - cursor < 12)
            return false;
        const size = get32(bytes, cursor);
        const data_offset = get32(bytes, cursor + 8);
        if (size < 12 or (size & 3) != 0 or size > end - cursor or
            data_offset < 12 or data_offset > size)
            return false;
        cursor += size;
    }
    return cursor == end;
}

export fn netvsc_rndis_parse_packet(
    input: [*]const u8,
    length: usize,
    result: *RndisPacketInfo,
) callconv(.c) c_int {
    zeroObject(result);
    if (length < rndis_packet_header_size)
        return @intFromEnum(Result.invalid);
    const bytes = input[0..length];
    if (get32(bytes, 0) != rndis_packet)
        return @intFromEnum(Result.unexpected);
    const message_length = get32(bytes, 4);
    if (message_length < rndis_packet_header_size or message_length > length)
        return @intFromEnum(Result.invalid);
    const data_relative = get32(bytes, 8);
    const data_length = get32(bytes, 12);
    const oob_relative = get32(bytes, 16);
    const oob_length = get32(bytes, 20);
    const oob_elements = get32(bytes, 24);
    const info_relative = get32(bytes, 28);
    const info_length = get32(bytes, 32);
    if (data_length == 0 or data_relative < rndis_packet_offset_min)
        return @intFromEnum(Result.invalid);
    const data_offset = std.math.add(u32, data_relative, rndis_relative_base) catch
        return @intFromEnum(Result.overflow);
    const data_end = regionEnd(data_offset, data_length) orelse
        return @intFromEnum(Result.overflow);
    if (data_offset < rndis_packet_header_size or data_end > message_length)
        return @intFromEnum(Result.invalid);

    var oob_offset: u32 = 0;
    if (oob_length == 0) {
        if (oob_relative != 0 or oob_elements != 0)
            return @intFromEnum(Result.invalid);
    } else {
        if (oob_relative < rndis_packet_offset_min or (oob_relative & 3) != 0 or
            oob_elements == 0)
            return @intFromEnum(Result.invalid);
        oob_offset = std.math.add(u32, oob_relative, rndis_relative_base) catch
            return @intFromEnum(Result.overflow);
        const oob_end = regionEnd(oob_offset, oob_length) orelse
            return @intFromEnum(Result.overflow);
        if (oob_offset < rndis_packet_header_size or oob_end > message_length or
            regionsOverlap(oob_offset, oob_length, data_offset, data_length))
            return @intFromEnum(Result.invalid);
    }

    var info_offset: u32 = 0;
    if (info_length == 0) {
        if (info_relative != 0)
            return @intFromEnum(Result.invalid);
    } else {
        if (info_relative < rndis_packet_offset_min or (info_relative & 3) != 0)
            return @intFromEnum(Result.invalid);
        info_offset = std.math.add(u32, info_relative, rndis_relative_base) catch
            return @intFromEnum(Result.overflow);
        if (!validatePacketInfo(bytes[0..message_length], info_offset, info_length) or
            regionsOverlap(info_offset, info_length, data_offset, data_length) or
            regionsOverlap(info_offset, info_length, oob_offset, oob_length))
            return @intFromEnum(Result.invalid);
    }

    result.message_length = message_length;
    result.data_offset = data_offset;
    result.data_length = data_length;
    result.packet_info_offset = info_offset;
    result.packet_info_length = info_length;
    return @intFromEnum(Result.ok);
}

export fn netvsc_rndis_parse_status(
    input: [*]const u8,
    length: usize,
    result: *RndisStatusInfo,
) callconv(.c) c_int {
    zeroObject(result);
    result.link_state = -1;
    if (length < 20)
        return @intFromEnum(Result.invalid);
    const bytes = input[0..length];
    if (get32(bytes, 0) != rndis_indicate_status)
        return @intFromEnum(Result.unexpected);
    const message_length = get32(bytes, 4);
    if (message_length < 20 or message_length > length)
        return @intFromEnum(Result.invalid);
    result.status = get32(bytes, 8);
    result.buffer_length = get32(bytes, 12);
    const relative = get32(bytes, 16);
    if (result.buffer_length == 0) {
        if (relative != 0)
            return @intFromEnum(Result.invalid);
    } else {
        if (relative == 0)
            return @intFromEnum(Result.invalid);
        result.buffer_offset = std.math.add(u32, relative, 8) catch
            return @intFromEnum(Result.overflow);
        const end = regionEnd(result.buffer_offset, result.buffer_length) orelse
            return @intFromEnum(Result.overflow);
        if (result.buffer_offset < 20 or end > message_length)
            return @intFromEnum(Result.invalid);
    }
    result.link_state = switch (result.status) {
        rndis_status_media_connect => 1,
        rndis_status_media_disconnect => 0,
        else => -1,
    };
    return @intFromEnum(Result.ok);
}

test "NVS versions fall back safely and select NDIS" {
    const expected = [_]u32{
        nvs_version_61,
        nvs_version_6,
        nvs_version_5,
        nvs_version_4,
        nvs_version_2,
        nvs_version_1,
    };
    try std.testing.expectEqual(@as(u32, expected.len), netvsc_nvs_version_count());
    for (expected, 0..) |version, index| {
        try std.testing.expectEqual(version, netvsc_nvs_version(@intCast(index)));
        try std.testing.expect(netvsc_nvs_ndis_version(version) != 0);
    }
    try std.testing.expectEqual(@as(u32, 0), netvsc_nvs_version(6));
    try std.testing.expectEqual(ndis_version_61, netvsc_nvs_ndis_version(nvs_version_4));
    try std.testing.expectEqual(ndis_version_630, netvsc_nvs_ndis_version(nvs_version_5));
}

test "all fixed NVS requests have exact zeroed layouts" {
    var message: [nvs_request_size]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 40), netvsc_nvs_build_init(&message, message.len, nvs_version_61));
    try std.testing.expectEqual(nvs_type_init, get32(&message, 0));
    try std.testing.expectEqual(nvs_version_61, get32(&message, 4));
    try std.testing.expectEqual(nvs_version_61, get32(&message, 8));
    try std.testing.expectEqual(@as(u32, 0), get32(&message, 12));

    try std.testing.expectEqual(@as(c_int, 40), netvsc_nvs_build_ndis_config(&message, message.len, 1514));
    try std.testing.expectEqual(nvs_type_ndis_config, get32(&message, 0));
    try std.testing.expectEqual(@as(u32, 1514), get32(&message, 4));
    try std.testing.expectEqual(@as(u32, 0), get32(&message, 12));

    try std.testing.expectEqual(@as(c_int, 40), netvsc_nvs_build_ndis_version(&message, message.len, ndis_version_630));
    try std.testing.expectEqual(@as(u32, 6), get32(&message, 4));
    try std.testing.expectEqual(@as(u32, 30), get32(&message, 8));

    try std.testing.expectEqual(@as(c_int, 40), netvsc_nvs_build_receive_buffer(&message, message.len, 7));
    try std.testing.expectEqual(nvs_type_receive_buffer, get32(&message, 0));
    try std.testing.expectEqual(@as(u16, rx_buffer_id), get16(&message, 8));
    try std.testing.expectEqual(@as(c_int, 40), netvsc_nvs_build_send_buffer(&message, message.len, 8));
    try std.testing.expectEqual(@as(u16, send_buffer_id), get16(&message, 8));
    try std.testing.expectEqual(@as(c_int, 40), netvsc_nvs_build_revoke_receive_buffer(&message, message.len));
    try std.testing.expectEqual(@as(u16, rx_buffer_id), get16(&message, 4));
    try std.testing.expectEqual(@as(c_int, 40), netvsc_nvs_build_revoke_send_buffer(&message, message.len));
    try std.testing.expectEqual(@as(u16, send_buffer_id), get16(&message, 4));
}

test "NVS init completion accepts padding and classifies rejection" {
    var response = [_]u8{0} ** 40;
    put32(&response, 0, nvs_type_init_complete);
    put32(&response, 4, nvs_version_6);
    put32(&response, 8, 4);
    put32(&response, 12, nvs_status_ok);
    var result: NvsInitComplete = undefined;
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_parse_init_complete(&response, 16, nvs_version_61, &result));
    try std.testing.expectEqual(nvs_version_61, result.version);
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_parse_init_complete(&response, response.len, nvs_version_6, &result));
    try std.testing.expectEqual(@intFromEnum(Result.invalid), netvsc_nvs_parse_init_complete(&response, 15, nvs_version_6, &result));
    put32(&response, 12, nvs_status_failed);
    try std.testing.expectEqual(@intFromEnum(Result.version_unsupported), netvsc_nvs_parse_init_complete(&response, response.len, nvs_version_6, &result));
    put32(&response, 12, 6);
    try std.testing.expectEqual(@intFromEnum(Result.remote_failure), netvsc_nvs_parse_init_complete(&response, response.len, nvs_version_6, &result));
}

test "receive section table and transfer ranges are bounded" {
    var response = [_]u8{0} ** (12 + 32);
    put32(&response, 0, nvs_type_receive_buffer_complete);
    put32(&response, 4, nvs_status_ok);
    put32(&response, 8, 2);
    put32(&response, 12, 0);
    put32(&response, 16, 2048);
    put32(&response, 20, 4);
    put32(&response, 24, 8191);
    put32(&response, 28, 8192);
    put32(&response, 32, 4096);
    put32(&response, 36, 2);
    put32(&response, 40, 16384);
    var sections: [max_sections]NvsSection = undefined;
    var count: u32 = 0;
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_parse_receive_buffer_complete(
        &response,
        response.len,
        16384,
        &sections,
        sections.len,
        &count,
    ));
    try std.testing.expectEqual(@as(u32, 2), count);
    put32(&response, 24, 1);
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_parse_receive_buffer_complete(
        &response,
        response.len,
        16384,
        &sections,
        sections.len,
        &count,
    ));
    put32(&response, 24, 8191);

    var descriptor = [_]u8{0} ** 24;
    put16(&descriptor, 0, rx_buffer_id);
    put32(&descriptor, 4, 2);
    put32(&descriptor, 8, 1600);
    put32(&descriptor, 12, 2048);
    put32(&descriptor, 16, 4000);
    put32(&descriptor, 20, 8192);
    var range_count: u32 = 0;
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_transfer_range_count(
        &descriptor,
        descriptor.len,
        &range_count,
    ));
    try std.testing.expectEqual(@as(u32, 2), range_count);
    var padded4 = [_]u8{0} ** 28;
    @memcpy(padded4[0..descriptor.len], &descriptor);
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_transfer_range_count(
        &padded4,
        padded4.len,
        &range_count,
    ));
    var padded8 = [_]u8{0} ** 32;
    @memcpy(padded8[0..descriptor.len], &descriptor);
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_transfer_range_count(
        &padded8,
        padded8.len,
        &range_count,
    ));
    try std.testing.expectEqual(@intFromEnum(Result.invalid), netvsc_nvs_transfer_range_count(
        &descriptor,
        descriptor.len - 1,
        &range_count,
    ));
    var misaligned = [_]u8{0} ** 25;
    @memcpy(misaligned[0..descriptor.len], &descriptor);
    try std.testing.expectEqual(@intFromEnum(Result.invalid), netvsc_nvs_transfer_range_count(
        &misaligned,
        misaligned.len,
        &range_count,
    ));
    put32(&padded8, 4, std.math.maxInt(u32));
    try std.testing.expectEqual(@intFromEnum(Result.invalid), netvsc_nvs_transfer_range_count(
        &padded8,
        padded8.len,
        &range_count,
    ));
    descriptor[2] = 1;
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_transfer_range_count(
        &descriptor,
        descriptor.len,
        &range_count,
    ));
    descriptor[2] = 0;
    descriptor[3] = 1;
    try std.testing.expectEqual(@intFromEnum(Result.unexpected), netvsc_nvs_transfer_range_count(
        &descriptor,
        descriptor.len,
        &range_count,
    ));
    descriptor[3] = 0;
    var range: TransferRange = undefined;
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_parse_transfer_range(
        &descriptor,
        descriptor.len,
        0,
        16384,
        &sections,
        count,
        &range,
    ));
    try std.testing.expectEqual(@as(u16, 0), range.section_index);
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_parse_transfer_range(
        &descriptor,
        descriptor.len,
        1,
        16384,
        &sections,
        count,
        &range,
    ));
    try std.testing.expectEqual(@as(u16, 1), range.section_index);

    put32(&descriptor, 8, 4097);
    put32(&descriptor, 12, 3);
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_parse_transfer_range(
        &descriptor,
        descriptor.len,
        0,
        16384,
        &sections,
        count,
        &range,
    ));
    try std.testing.expectEqual(@as(u16, 0), range.section_index);
    put32(&descriptor, 8, 300);
    put32(&descriptor, 12, 8000);
    try std.testing.expectEqual(@intFromEnum(Result.invalid), netvsc_nvs_parse_transfer_range(
        &descriptor,
        descriptor.len,
        0,
        16384,
        &sections,
        count,
        &range,
    ));

    put32(&descriptor, 20, 16380);
    try std.testing.expectEqual(@intFromEnum(Result.invalid), netvsc_nvs_parse_transfer_range(
        &descriptor,
        descriptor.len,
        1,
        16384,
        &sections,
        count,
        &range,
    ));
    put32(&response, 20, std.math.maxInt(u32));
    try std.testing.expectEqual(@intFromEnum(Result.overflow), netvsc_nvs_parse_receive_buffer_complete(
        &response,
        response.len,
        16384,
        &sections,
        sections.len,
        &count,
    ));
}

test "maximum receive section reply accepts VMBus padding" {
    var response = [_]u8{0} ** 144;
    put32(&response, 0, nvs_type_receive_buffer_complete);
    put32(&response, 4, nvs_status_ok);
    put32(&response, 8, max_sections);
    for (0..max_sections) |index| {
        const offset = 12 + index * 16;
        const start: u32 = @intCast(index * 4096);
        put32(&response, offset, start);
        put32(&response, offset + 4, 4096);
        put32(&response, offset + 8, 1);
        put32(&response, offset + 12, start + 4095);
    }
    var sections: [max_sections]NvsSection = undefined;
    var count: u32 = 0;
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_parse_receive_buffer_complete(
        &response,
        response.len,
        @intCast(max_sections * 4096),
        &sections,
        sections.len,
        &count,
    ));
    try std.testing.expectEqual(@as(u32, @intCast(max_sections)), count);
    try std.testing.expectEqual(@intFromEnum(Result.invalid), netvsc_nvs_parse_receive_buffer_complete(
        &response,
        139,
        @intCast(max_sections * 4096),
        &sections,
        sections.len,
        &count,
    ));
}

test "received NVS RNDIS envelope treats channel type as informational" {
    var message = [_]u8{0} ** 40;
    put32(&message, 0, nvs_type_send_rndis);
    put32(&message, 4, nvs_rndis_control);
    var channel_type: u32 = 0;
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_parse_rndis(
        &message,
        message.len,
        &channel_type,
    ));
    try std.testing.expectEqual(nvs_rndis_control, channel_type);
    put32(&message, 4, 9);
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_parse_rndis(
        &message,
        message.len,
        &channel_type,
    ));
    try std.testing.expectEqual(@as(u32, 9), channel_type);
    put32(&message, 0, 999);
    try std.testing.expectEqual(@intFromEnum(Result.unexpected), netvsc_nvs_parse_rndis(
        &message,
        message.len,
        &channel_type,
    ));
}

test "send buffer and RNDIS NVS envelope validate sections" {
    var response = [_]u8{0} ** 40;
    put32(&response, 0, nvs_type_send_buffer_complete);
    put32(&response, 4, nvs_status_ok);
    put32(&response, 8, 6144);
    var complete: NvsSendBufferComplete = undefined;
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_parse_send_buffer_complete(
        &response,
        12,
        6144 * 8,
        &complete,
    ));
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_nvs_parse_send_buffer_complete(
        &response,
        response.len,
        6144 * 8,
        &complete,
    ));
    try std.testing.expectEqual(@as(u32, 8), complete.section_count);
    try std.testing.expectEqual(@intFromEnum(Result.invalid), netvsc_nvs_parse_send_buffer_complete(
        &response,
        11,
        6144 * 8,
        &complete,
    ));
    var request: [40]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 40), netvsc_nvs_build_rndis(
        &request,
        request.len,
        nvs_rndis_data,
        3,
        1514,
    ));
    try std.testing.expectEqual(@as(c_int, -1), netvsc_nvs_build_rndis(
        &request,
        request.len,
        nvs_rndis_data,
        send_section_invalid,
        1,
    ));
}

test "RNDIS serializers use exact MS-RNDIS offsets" {
    var message: [128]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 24), netvsc_rndis_build_initialize(&message, message.len, 0x10001, 2048));
    try std.testing.expectEqual(rndis_initialize, get32(&message, 0));
    try std.testing.expectEqual(@as(u32, 24), get32(&message, 4));
    try std.testing.expectEqual(@as(u32, 1), get32(&message, 12));

    const info = [_]u8{ 1, 2, 3, 4 };
    try std.testing.expectEqual(@as(c_int, 32), netvsc_rndis_build_query(&message, message.len, 0x10002, oid_gen_maximum_frame_size, &info, info.len));
    try std.testing.expectEqual(@as(u32, 20), get32(&message, 20));
    try std.testing.expectEqualSlices(u8, &info, message[28..32]);
    try std.testing.expectEqual(@as(c_int, 32), netvsc_rndis_build_set(&message, message.len, 0x10003, oid_gen_current_packet_filter, &info, info.len));
    try std.testing.expectEqual(@as(c_int, 12), netvsc_rndis_build_keepalive(&message, message.len, 0x10004));
    try std.testing.expectEqual(@as(c_int, 12), netvsc_rndis_build_halt(&message, message.len, 0x10005));
    try std.testing.expectEqual(@as(c_int, 44), netvsc_rndis_build_packet_header(&message, message.len, 60));
    try std.testing.expectEqual(@as(u32, 104), get32(&message, 4));
    try std.testing.expectEqual(rndis_packet_offset_min, get32(&message, 8));
}

test "RNDIS lifecycle completions reject wrong late IDs and contradictions" {
    var response = [_]u8{0} ** 52;
    put32(&response, 0, rndis_initialize_complete);
    put32(&response, 4, 52);
    put32(&response, 8, 0x20001);
    put32(&response, 12, rndis_status_success);
    put32(&response, 16, 1);
    put32(&response, 20, 0);
    put32(&response, 24, rndis_device_connectionless);
    put32(&response, 28, rndis_medium_802_3);
    put32(&response, 32, 1);
    put32(&response, 36, 2048);
    put32(&response, 40, 2);
    var complete: RndisCompletion = undefined;
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_rndis_parse_completion(
        &response,
        response.len,
        rndis_initialize_complete,
        0x20001,
        &complete,
    ));
    try std.testing.expectEqual(@as(u32, 4), complete.alignment);
    try std.testing.expectEqual(@intFromEnum(Result.unexpected), netvsc_rndis_parse_completion(
        &response,
        response.len,
        rndis_initialize_complete,
        0x20002,
        &complete,
    ));
    put32(&response, 28, 1);
    try std.testing.expectEqual(@intFromEnum(Result.unexpected), netvsc_rndis_parse_completion(
        &response,
        response.len,
        rndis_initialize_complete,
        0x20001,
        &complete,
    ));
}

test "RNDIS query set and keepalive completion bounds" {
    var response = [_]u8{0} ** 32;
    put32(&response, 0, rndis_query_complete);
    put32(&response, 4, 28);
    put32(&response, 8, 0x30001);
    put32(&response, 12, rndis_status_success);
    put32(&response, 16, 4);
    put32(&response, 20, 16);
    put32(&response, 24, 1500);
    var complete: RndisCompletion = undefined;
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_rndis_parse_completion(
        &response,
        response.len,
        rndis_query_complete,
        0x30001,
        &complete,
    ));
    try std.testing.expectEqual(@as(u32, 24), complete.info_offset);
    put32(&response, 20, std.math.maxInt(u32));
    try std.testing.expectEqual(@intFromEnum(Result.overflow), netvsc_rndis_parse_completion(
        &response,
        response.len,
        rndis_query_complete,
        0x30001,
        &complete,
    ));

    response = [_]u8{0} ** 32;
    put32(&response, 0, rndis_set_complete);
    put32(&response, 4, 16);
    put32(&response, 8, 0x30002);
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_rndis_parse_completion(
        &response,
        response.len,
        rndis_set_complete,
        0x30002,
        &complete,
    ));
    put32(&response, 0, rndis_keepalive_complete);
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_rndis_parse_completion(
        &response,
        response.len,
        rndis_keepalive_complete,
        0x30002,
        &complete,
    ));
}

test "RNDIS packet framing validates all host offsets" {
    var packet = [_]u8{0} ** 128;
    _ = netvsc_rndis_build_packet_header(&packet, packet.len, 60);
    for (44..104) |i|
        packet[i] = @truncate(i);
    var info: RndisPacketInfo = undefined;
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_rndis_parse_packet(
        &packet,
        104,
        &info,
    ));
    try std.testing.expectEqual(@as(u32, 44), info.data_offset);
    try std.testing.expectEqual(@as(u32, 60), info.data_length);

    put32(&packet, 8, std.math.maxInt(u32));
    try std.testing.expectEqual(@intFromEnum(Result.overflow), netvsc_rndis_parse_packet(&packet, 104, &info));
    put32(&packet, 8, rndis_packet_offset_min);
    put32(&packet, 12, 61);
    try std.testing.expectEqual(@intFromEnum(Result.invalid), netvsc_rndis_parse_packet(&packet, 104, &info));
    put32(&packet, 12, 60);
    put32(&packet, 28, 37);
    put32(&packet, 32, 12);
    try std.testing.expectEqual(@intFromEnum(Result.invalid), netvsc_rndis_parse_packet(&packet, 104, &info));
}

test "RNDIS status messages validate buffers and link transitions" {
    var status = [_]u8{0} ** 24;
    put32(&status, 0, rndis_indicate_status);
    put32(&status, 4, 20);
    put32(&status, 8, rndis_status_media_connect);
    var info: RndisStatusInfo = undefined;
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_rndis_parse_status(&status, status.len, &info));
    try std.testing.expectEqual(@as(i32, 1), info.link_state);
    put32(&status, 8, rndis_status_media_disconnect);
    try std.testing.expectEqual(@intFromEnum(Result.ok), netvsc_rndis_parse_status(&status, status.len, &info));
    try std.testing.expectEqual(@as(i32, 0), info.link_state);
    put32(&status, 12, 8);
    put32(&status, 16, std.math.maxInt(u32));
    try std.testing.expectEqual(@intFromEnum(Result.overflow), netvsc_rndis_parse_status(&status, status.len, &info));
}
