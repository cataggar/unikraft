// SPDX-License-Identifier: BSD-3-Clause
//
// Microsoft TLFS defines the Hyper-V message and HvCallPostMessage ABIs.
// Message sequencing and offer interpretation were behaviorally checked
// against FreeBSD sys/dev/hyperv (BSD-2-Clause); see NOTICE.

const std = @import("std");

pub const post_message_call: u64 = 0x005c;
pub const legacy_message_connection_id: u32 = 1;
pub const initiate_contact_connection_id: u32 = 4;
pub const hyperv_channel_message_type: u32 = 1;
pub const max_payload_size: usize = 240;
pub const offer_size: usize = 196;

const version_timeout_default: u64 = 5_000_000; // 500 ms in 100 ns ticks.
const sint: u8 = 2;
const vtl: u8 = 0;

pub const versions = [_]u32{
    makeVersion(6, 0),
    makeVersion(5, 3),
    makeVersion(5, 2),
    makeVersion(5, 1),
    makeVersion(5, 0),
    makeVersion(4, 1),
    makeVersion(4, 0),
    makeVersion(3, 0),
    makeVersion(2, 4),
    makeVersion(1, 1),
    makeVersion(0, 13),
};

pub const MessageType = enum(u32) {
    offer_channel = 1,
    rescind_channel_offer = 2,
    request_offers = 3,
    all_offers_delivered = 4,
    relid_released = 13,
    initiate_contact = 14,
    version_response = 15,
    unload = 16,
    unload_response = 17,
};

pub const State = enum(c_int) {
    idle = 0,
    wait_version = 1,
    wait_offers = 2,
    ready = 3,
    unloading = 4,
    disconnected = 5,
    failed = 6,
};

pub const ActionKind = enum(c_int) {
    none = 0,
    transmit = 1,
    offer = 2,
    rescind = 3,
    offers_complete = 4,
    cleanup = 5,
    failed = 6,
    stale = 7,
    malformed = 8,
    reject_offer = 9,
};

pub const ProtocolError = enum(c_int) {
    none = 0,
    timeout = 1,
    unsupported = 2,
    connection_failed = 3,
    malformed = 4,
    unexpected = 5,
};

pub const PostResult = enum(c_int) {
    ok = 0,
    bad_payload = -1,
    bad_message_type = -2,
    bad_alignment = -3,
    missing_privilege = -4,
    invalid_connection = -5,
    invalid_port = -6,
    invalid_vp = -7,
    invalid_synic = -8,
    access_denied = -9,
    invalid_parameter = -10,
    insufficient_buffers = -11,
    hypervisor_error = -12,
};

pub const Guid = extern struct {
    bytes: [16]u8,
};

pub const Offer = extern struct {
    class_id: Guid,
    instance_id: Guid,
    channel_id: u32,
    connection_id: u32,
    flags: u16,
    mmio_megabytes: u16,
    mmio_megabytes_optional: u16,
    subchannel_index: u16,
    monitor_id: u8,
    monitor_allocated: u8,
    dedicated: u16,
    user_data: [120]u8,
};

pub const Action = extern struct {
    kind: ActionKind,
    err: ProtocolError,
    generation: u32,
    tx_len: u32,
    tx: [64]u8,
    offer: Offer,
    channel_id: u32,
    connection_id: u32,
};

pub const StartConfig = extern struct {
    target_vp: u32,
    timeout_ticks: u64,
    interrupt_page_gpa: u64,
    parent_to_child_monitor_gpa: u64,
    child_to_parent_monitor_gpa: u64,
};

const PostMessageInput = extern struct {
    connection_id: u32,
    reserved: u32,
    message_type: u32,
    payload_size: u32,
    payload: [max_payload_size]u8,
};

const WireHeader = extern struct {
    message_type_le: [4]u8,
    reserved: [4]u8,
};

const WireInitiateContact = extern struct {
    header: WireHeader,
    version_requested_le: [4]u8,
    target_vp_le: [4]u8,
    interrupt_page_or_target_info_le: [8]u8,
    parent_to_child_monitor_gpa_le: [8]u8,
    child_to_parent_monitor_gpa_le: [8]u8,
};

const WireVersionResponse = extern struct {
    header: WireHeader,
    version_supported: u8,
    connection_state: u8,
    reserved: [2]u8,
    selected_version_or_connection_id_le: [4]u8,
};

const WireOfferChannel = extern struct {
    header: WireHeader,
    interface_id: [16]u8,
    instance_id: [16]u8,
    reserved: [16]u8,
    flags_le: [2]u8,
    mmio_megabytes_le: [2]u8,
    user_data: [120]u8,
    subchannel_index_le: [2]u8,
    mmio_megabytes_optional_le: [2]u8,
    channel_id_le: [4]u8,
    monitor_id: u8,
    monitor_allocated: u8,
    dedicated_le: [2]u8,
    connection_id_le: [4]u8,
};

const WireRescindChannelOffer = extern struct {
    header: WireHeader,
    channel_id_le: [4]u8,
};

const Context = struct {
    state: State = .idle,
    generation: u32 = 0,
    version_index: usize = 0,
    selected_version: u32 = 0,
    message_connection_id: u32 = legacy_message_connection_id,
    deadline: u64 = 0,
    config: StartConfig = .{
        .target_vp = 0,
        .timeout_ticks = version_timeout_default,
        .interrupt_page_gpa = 0,
        .parent_to_child_monitor_gpa = 0,
        .child_to_parent_monitor_gpa = 0,
    },
};

pub const Hypercall = *const fn (?*anyopaque, u64) callconv(.c) u64;
pub const Backoff = *const fn (?*anyopaque, u32) callconv(.c) void;

var context = Context{};
var post_input: PostMessageInput align(256) = std.mem.zeroes(PostMessageInput);

pub const storage_guid = Guid{ .bytes = .{
    0xba, 0x61, 0x63, 0xd9, 0x04, 0xa1, 0x4d, 0x29,
    0xb6, 0x05, 0x72, 0xe2, 0xff, 0xb1, 0xdc, 0x7f,
} };
pub const network_guid = Guid{ .bytes = .{
    0xf8, 0x61, 0x51, 0x63, 0xdf, 0x3e, 0x46, 0xc5,
    0x91, 0x3f, 0xf2, 0xd2, 0xf9, 0x65, 0xed, 0x0e,
} };

comptime {
    if (@sizeOf(PostMessageInput) != 256 or @alignOf(PostMessageInput) != 4)
        @compileError("HvCallPostMessage input layout changed");
    if (@offsetOf(PostMessageInput, "connection_id") != 0 or
        @offsetOf(PostMessageInput, "message_type") != 8 or
        @offsetOf(PostMessageInput, "payload_size") != 12 or
        @offsetOf(PostMessageInput, "payload") != 16)
        @compileError("HvCallPostMessage input offsets changed");
    if (@sizeOf(Guid) != 16 or @alignOf(Guid) != 1)
        @compileError("VMBus GUID ABI changed");
    if (@sizeOf(WireHeader) != 8 or
        @sizeOf(WireInitiateContact) != 40 or
        @offsetOf(WireInitiateContact, "interrupt_page_or_target_info_le") != 16)
        @compileError("VMBus initiate-contact wire layout changed");
    if (@sizeOf(WireVersionResponse) != 16 or
        @offsetOf(WireVersionResponse, "selected_version_or_connection_id_le") != 12)
        @compileError("VMBus version-response wire layout changed");
    if (@sizeOf(WireOfferChannel) != offer_size or
        @offsetOf(WireOfferChannel, "user_data") != 60 or
        @offsetOf(WireOfferChannel, "channel_id_le") != 184 or
        @offsetOf(WireOfferChannel, "connection_id_le") != 192)
        @compileError("VMBus offer-channel wire layout changed");
    if (@sizeOf(WireRescindChannelOffer) != 12)
        @compileError("VMBus rescind wire layout changed");
    if (@sizeOf(Offer) != 172 or @offsetOf(Offer, "user_data") != 52)
        @compileError("VMBus decoded offer ABI changed");
}

pub fn makeVersion(major: u16, minor: u16) u32 {
    return (@as(u32, major) << 16) | minor;
}

fn clearAction(action: *Action) void {
    zeroObject(action);
}

fn zeroObject(object: anytype) void {
    const bytes: [*]volatile u8 = @ptrCast(object);
    for (0..@sizeOf(@TypeOf(object.*))) |i|
        bytes[i] = 0;
}

fn putU16(bytes: []u8, offset: usize, value: u16) void {
    bytes[offset] = @truncate(value);
    bytes[offset + 1] = @truncate(value >> 8);
}

fn putU32(bytes: []u8, offset: usize, value: u32) void {
    bytes[offset] = @truncate(value);
    bytes[offset + 1] = @truncate(value >> 8);
    bytes[offset + 2] = @truncate(value >> 16);
    bytes[offset + 3] = @truncate(value >> 24);
}

fn putU64(bytes: []u8, offset: usize, value: u64) void {
    for (0..8) |i|
        bytes[offset + i] = @truncate(value >> @intCast(i * 8));
}

fn readU16(bytes: []const u8, offset: usize) u16 {
    return @as(u16, bytes[offset]) |
        (@as(u16, bytes[offset + 1]) << 8);
}

fn readU32(bytes: []const u8, offset: usize) u32 {
    return @as(u32, bytes[offset]) |
        (@as(u32, bytes[offset + 1]) << 8) |
        (@as(u32, bytes[offset + 2]) << 16) |
        (@as(u32, bytes[offset + 3]) << 24);
}

fn readU64(bytes: []const u8, offset: usize) u64 {
    var value: u64 = 0;
    for (0..8) |i|
        value |= @as(u64, bytes[offset + i]) << @intCast(i * 8);
    return value;
}

pub fn decodeGuid(wire: []const u8) ?Guid {
    if (wire.len < 16)
        return null;
    return .{ .bytes = .{
        wire[3],  wire[2],  wire[1],  wire[0],
        wire[5],  wire[4],  wire[7],  wire[6],
        wire[8],  wire[9],  wire[10], wire[11],
        wire[12], wire[13], wire[14], wire[15],
    } };
}

fn header(action: *Action, kind: MessageType, len: usize) void {
    clearAction(action);
    action.kind = .transmit;
    action.generation = context.generation;
    action.connection_id = context.message_connection_id;
    action.tx_len = @intCast(len);
    putU32(action.tx[0..], 0, @intFromEnum(kind));
}

fn initiate(now: u64, action: *Action) void {
    const version = versions[context.version_index];
    context.message_connection_id = if (version >= makeVersion(5, 0))
        initiate_contact_connection_id
    else
        legacy_message_connection_id;
    header(action, .initiate_contact, 40);
    putU32(action.tx[0..], 8, version);
    putU32(action.tx[0..], 12, context.config.target_vp);
    const interrupt_info = if (version >= makeVersion(5, 0))
        @as(u64, sint) | (@as(u64, vtl) << 8)
    else
        context.config.interrupt_page_gpa;
    putU64(action.tx[0..], 16, interrupt_info);
    putU64(action.tx[0..], 24, context.config.parent_to_child_monitor_gpa);
    putU64(action.tx[0..], 32, context.config.child_to_parent_monitor_gpa);
    context.deadline = now +| context.config.timeout_ticks;
    context.state = .wait_version;
}

fn nextVersion(now: u64, action: *Action) void {
    if (context.version_index + 1 >= versions.len) {
        context.state = .failed;
        clearAction(action);
        action.kind = .failed;
        action.err = .unsupported;
        action.generation = context.generation;
        return;
    }
    context.version_index += 1;
    context.generation +%= 1;
    if (context.generation == 0)
        context.generation = 1;
    initiate(now, action);
}

fn retryLegacyContact(status: u16, now: u64, action: *Action) bool {
    clearAction(action);
    action.generation = context.generation;
    if (status != 0x0012 or context.state != .wait_version or
        context.version_index >= versions.len or
        versions[context.version_index] < makeVersion(5, 0) or
        context.message_connection_id != initiate_contact_connection_id)
        return false;

    while (context.version_index + 1 < versions.len and
        versions[context.version_index + 1] >= makeVersion(5, 0))
        context.version_index += 1;
    if (context.version_index + 1 >= versions.len)
        return false;

    context.version_index += 1;
    context.generation +%= 1;
    if (context.generation == 0)
        context.generation = 1;
    initiate(now, action);
    return true;
}

fn requestOffers(now: u64, action: *Action) void {
    header(action, .request_offers, 8);
    context.state = .wait_offers;
    context.deadline = now +| context.config.timeout_ticks;
}

fn decodeOffer(bytes: []const u8, offer: *Offer) bool {
    if (bytes.len < offer_size)
        return false;
    zeroObject(offer);
    offer.class_id = decodeGuid(bytes[8..24]) orelse return false;
    offer.instance_id = decodeGuid(bytes[24..40]) orelse return false;
    offer.flags = readU16(bytes, 56);
    offer.mmio_megabytes = readU16(bytes, 58);
    for (0..offer.user_data.len) |i|
        offer.user_data[i] = bytes[60 + i];
    offer.subchannel_index = readU16(bytes, 180);
    offer.mmio_megabytes_optional = readU16(bytes, 182);
    offer.channel_id = readU32(bytes, 184);
    offer.monitor_id = bytes[188];
    offer.monitor_allocated = bytes[189];
    offer.dedicated = readU16(bytes, 190);
    offer.connection_id = readU32(bytes, 192);
    if (offer.channel_id == 0 or offer.connection_id == 0)
        return false;
    if (offer.monitor_allocated > 1)
        return false;
    if (offer.monitor_allocated != 0 and offer.monitor_id >= 128)
        return false;
    return true;
}

fn receive(bytes: []const u8, generation: u32, now: u64, action: *Action) void {
    clearAction(action);
    action.generation = context.generation;
    if (generation != context.generation) {
        action.kind = .stale;
        return;
    }
    if (bytes.len < 8 or bytes.len > max_payload_size) {
        action.kind = .malformed;
        action.err = .malformed;
        return;
    }
    const raw_type = readU32(bytes, 0);
    const message_type: MessageType = switch (raw_type) {
        1 => .offer_channel,
        2 => .rescind_channel_offer,
        3 => .request_offers,
        4 => .all_offers_delivered,
        13 => .relid_released,
        14 => .initiate_contact,
        15 => .version_response,
        16 => .unload,
        17 => .unload_response,
        else => {
            action.kind = .malformed;
            action.err = .unexpected;
            return;
        },
    };
    switch (message_type) {
        .version_response => {
            if (context.state != .wait_version or now > context.deadline) {
                action.kind = .stale;
                return;
            }
            if (bytes.len < 10) {
                action.kind = .malformed;
                action.err = .malformed;
                return;
            }
            if (bytes[8] == 0) {
                nextVersion(now, action);
                return;
            }
            if (bytes[9] != 0) {
                context.state = .failed;
                action.kind = .failed;
                action.err = .connection_failed;
                return;
            }
            context.selected_version = versions[context.version_index];
            if (context.selected_version >= makeVersion(5, 0)) {
                if (bytes.len < 16) {
                    context.state = .failed;
                    action.kind = .malformed;
                    action.err = .malformed;
                    return;
                }
                context.message_connection_id = readU32(bytes, 12);
                if (context.message_connection_id == 0 or
                    (context.message_connection_id & 0xff000000) != 0)
                {
                    context.state = .failed;
                    action.kind = .malformed;
                    action.err = .malformed;
                    return;
                }
            } else {
                context.message_connection_id = legacy_message_connection_id;
            }
            requestOffers(now, action);
        },
        .offer_channel => {
            if (context.state != .wait_offers and context.state != .ready) {
                action.kind = .stale;
                return;
            }
            if (!decodeOffer(bytes, &action.offer)) {
                if (bytes.len >= 188 and readU32(bytes, 184) != 0) {
                    action.kind = .reject_offer;
                    action.channel_id = readU32(bytes, 184);
                } else {
                    action.kind = .malformed;
                    action.err = .malformed;
                }
                return;
            }
            action.kind = .offer;
        },
        .rescind_channel_offer => {
            if (context.state != .wait_offers and context.state != .ready) {
                action.kind = .stale;
                return;
            }
            if (bytes.len < 12) {
                action.kind = .malformed;
                action.err = .malformed;
                return;
            }
            action.channel_id = readU32(bytes, 8);
            if (action.channel_id == 0) {
                action.kind = .malformed;
                action.err = .malformed;
                return;
            }
            action.kind = .rescind;
        },
        .all_offers_delivered => {
            if (context.state != .wait_offers) {
                action.kind = .stale;
                return;
            }
            context.state = .ready;
            action.kind = .offers_complete;
        },
        .unload_response => {
            if (context.state != .unloading) {
                action.kind = .stale;
                return;
            }
            context.state = .disconnected;
            action.kind = .cleanup;
        },
        else => {
            action.kind = .malformed;
            action.err = .unexpected;
        },
    }
}

fn tick(now: u64, action: *Action) void {
    clearAction(action);
    action.generation = context.generation;
    if (now <= context.deadline)
        return;
    switch (context.state) {
        .wait_version => {
            context.state = .failed;
            action.kind = .failed;
            action.err = .timeout;
        },
        .wait_offers => {
            context.state = .failed;
            action.kind = .failed;
            action.err = .timeout;
        },
        .unloading => {
            // Local parser cleanup only; timeout is not host teardown proof.
            context.state = .disconnected;
            action.kind = .cleanup;
            action.err = .timeout;
        },
        else => {},
    }
}

fn beginUnload(now: u64, action: *Action) void {
    clearAction(action);
    if (context.state == .idle or context.state == .disconnected) {
        context.state = .disconnected;
        action.kind = .cleanup;
        return;
    }

    context.generation +%= 1;
    if (context.generation == 0)
        context.generation = 1;
    header(action, .unload, 8);
    context.state = .unloading;
    context.deadline = now +| context.config.timeout_ticks;
}

fn releaseRelid(channel_id: u32, action: *Action) void {
    clearAction(action);
    if (channel_id == 0 or
        (context.state != .wait_offers and context.state != .ready))
    {
        action.kind = .malformed;
        action.err = .unexpected;
        action.generation = context.generation;
        return;
    }
    header(action, .relid_released, 12);
    putU32(action.tx[0..], 8, channel_id);
    action.channel_id = channel_id;
}

fn resetProtocol() void {
    const next_generation = context.generation +% 1;
    zeroObject(&context);
    context.config.timeout_ticks = version_timeout_default;
    context.message_connection_id = legacy_message_connection_id;
    context.generation = if (next_generation == 0) 1 else next_generation;
    context.state = .disconnected;
}

fn statusToResult(status: u16) PostResult {
    return switch (status) {
        0x0000 => .ok,
        0x0005 => .invalid_parameter,
        0x0006 => .access_denied,
        0x000e => .invalid_vp,
        0x0011 => .invalid_port,
        0x0012 => .invalid_connection,
        0x0013 => .insufficient_buffers,
        0x0018 => .invalid_synic,
        else => .hypervisor_error,
    };
}

export fn vmbus_post_input() callconv(.c) *anyopaque {
    return @ptrCast(&post_input);
}

export fn vmbus_post_message(
    connection_id: u32,
    message_type: u32,
    payload: [*]const u8,
    payload_len: usize,
    input_gpa: u64,
    status_code: ?*u16,
    has_post_messages: u8,
    retry_limit: u32,
    hypercall: Hypercall,
    backoff: Backoff,
    user_context: ?*anyopaque,
) callconv(.c) c_int {
    if (status_code) |status|
        status.* = 0xffff;
    if (has_post_messages == 0)
        return @intFromEnum(PostResult.missing_privilege);
    if (connection_id == 0 or (connection_id & 0xff000000) != 0)
        return @intFromEnum(PostResult.invalid_connection);
    if (message_type == 0 or (message_type & 0x80000000) != 0)
        return @intFromEnum(PostResult.bad_message_type);
    if (payload_len > max_payload_size)
        return @intFromEnum(PostResult.bad_payload);
    if ((input_gpa & 0xff) != 0)
        return @intFromEnum(PostResult.bad_alignment);

    zeroObject(&post_input);
    post_input.connection_id = connection_id;
    post_input.message_type = message_type;
    post_input.payload_size = @intCast(payload_len);
    for (0..payload_len) |i|
        post_input.payload[i] = payload[i];

    var attempt: u32 = 0;
    while (true) {
        const raw_status: u16 = @truncate(hypercall(user_context, input_gpa));
        if (status_code) |status|
            status.* = raw_status;
        const result = statusToResult(raw_status);
        if (result != .insufficient_buffers)
            return @intFromEnum(result);
        if (attempt >= retry_limit)
            return @intFromEnum(PostResult.insufficient_buffers);
        const shift: u5 = @intCast(@min(attempt, 10));
        backoff(user_context, @as(u32, 10) << shift);
        attempt += 1;
    }
}

export fn vmbus_protocol_post_failure(
    status_code: u16,
    now: u64,
    action: *Action,
) callconv(.c) c_int {
    return @intFromBool(retryLegacyContact(status_code, now, action));
}

export fn vmbus_protocol_start(
    now: u64,
    config: *const StartConfig,
    action: *Action,
) callconv(.c) void {
    zeroObject(&context);
    context.message_connection_id = legacy_message_connection_id;
    context.config = config.*;
    if (context.config.timeout_ticks == 0)
        context.config.timeout_ticks = version_timeout_default;
    context.generation = 1;
    initiate(now, action);
}

export fn vmbus_protocol_receive(
    payload: [*]const u8,
    payload_len: usize,
    generation: u32,
    now: u64,
    action: *Action,
) callconv(.c) void {
    if (payload_len > max_payload_size) {
        clearAction(action);
        action.kind = .malformed;
        action.err = .malformed;
        action.generation = context.generation;
        return;
    }
    receive(payload[0..payload_len], generation, now, action);
}

export fn vmbus_protocol_tick(now: u64, action: *Action) callconv(.c) void {
    tick(now, action);
}

export fn vmbus_protocol_unload(now: u64, action: *Action) callconv(.c) void {
    beginUnload(now, action);
}

export fn vmbus_protocol_release(
    channel_id: u32,
    action: *Action,
) callconv(.c) void {
    releaseRelid(channel_id, action);
}

export fn vmbus_protocol_reset() callconv(.c) void {
    resetProtocol();
}

export fn vmbus_protocol_state() callconv(.c) c_int {
    return @intFromEnum(context.state);
}

export fn vmbus_protocol_generation() callconv(.c) u32 {
    return context.generation;
}

export fn vmbus_protocol_version() callconv(.c) u32 {
    return context.selected_version;
}

export fn vmbus_protocol_connection_id() callconv(.c) u32 {
    return context.message_connection_id;
}

fn makeMessage(kind: MessageType, len: usize) [240]u8 {
    var bytes = [_]u8{0} ** 240;
    putU32(bytes[0..], 0, @intFromEnum(kind));
    _ = len;
    return bytes;
}

test "wire sizes and offsets match TLFS and VMBus protocol" {
    try std.testing.expectEqual(@as(usize, 256), @sizeOf(PostMessageInput));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(PostMessageInput, "payload"));
    try std.testing.expectEqual(@as(usize, 172), @sizeOf(Offer));
    try std.testing.expectEqual(@as(usize, 52), @offsetOf(Offer, "user_data"));
    try std.testing.expectEqual(@as(usize, 196), offer_size);
}

test "GUID wire endianness decodes canonical storage and network classes" {
    const storage_wire = [_]u8{
        0xd9, 0x63, 0x61, 0xba, 0xa1, 0x04, 0x29, 0x4d,
        0xb6, 0x05, 0x72, 0xe2, 0xff, 0xb1, 0xdc, 0x7f,
    };
    const network_wire = [_]u8{
        0x63, 0x51, 0x61, 0xf8, 0x3e, 0xdf, 0xc5, 0x46,
        0x91, 0x3f, 0xf2, 0xd2, 0xf9, 0x65, 0xed, 0x0e,
    };
    try std.testing.expectEqual(storage_guid, decodeGuid(&storage_wire).?);
    try std.testing.expectEqual(network_guid, decodeGuid(&network_wire).?);
    try std.testing.expect(decodeGuid(storage_wire[0..15]) == null);
}

test "PostMessage validates input, retries boundedly, and preserves failures" {
    const Fake = struct {
        var calls: u32 = 0;
        var delays: u32 = 0;
        var status: u16 = 0;
        fn call(_: ?*anyopaque, _: u64) callconv(.c) u64 {
            calls += 1;
            if (status == 0x0013 and calls >= 3)
                return 0;
            return status;
        }
        fn delay(_: ?*anyopaque, _: u32) callconv(.c) void {
            delays += 1;
        }
    };
    const payload = [_]u8{ 1, 2, 3 };
    var status_code: u16 = undefined;
    Fake.calls = 0;
    Fake.delays = 0;
    Fake.status = 0x0013;
    try std.testing.expectEqual(
        @intFromEnum(PostResult.ok),
        vmbus_post_message(7, 1, &payload, payload.len, 0x1000, &status_code, 1, 4, Fake.call, Fake.delay, null),
    );
    try std.testing.expectEqual(@as(u16, 0), status_code);
    try std.testing.expectEqual(@as(u32, 3), Fake.calls);
    try std.testing.expectEqual(@as(u32, 2), Fake.delays);
    try std.testing.expectEqual(@as(u32, 7), post_input.connection_id);
    Fake.calls = 0;
    Fake.delays = 0;
    try std.testing.expectEqual(
        @intFromEnum(PostResult.insufficient_buffers),
        vmbus_post_message(7, 1, &payload, payload.len, 0x1000, &status_code, 1, 1, Fake.call, Fake.delay, null),
    );
    try std.testing.expectEqual(@as(u16, 0x0013), status_code);
    try std.testing.expectEqual(@as(u32, 2), Fake.calls);
    Fake.status = 0x0012;
    try std.testing.expectEqual(
        @intFromEnum(PostResult.invalid_connection),
        vmbus_post_message(7, 1, &payload, payload.len, 0x1000, &status_code, 1, 2, Fake.call, Fake.delay, null),
    );
    try std.testing.expectEqual(@as(u16, 0x0012), status_code);
    try std.testing.expectEqual(
        @intFromEnum(PostResult.missing_privilege),
        vmbus_post_message(7, 1, &payload, payload.len, 0x1000, &status_code, 0, 2, Fake.call, Fake.delay, null),
    );
    try std.testing.expectEqual(@as(u16, 0xffff), status_code);
    try std.testing.expectEqual(
        @intFromEnum(PostResult.bad_alignment),
        vmbus_post_message(7, 1, &payload, payload.len, 0x1008, &status_code, 1, 2, Fake.call, Fake.delay, null),
    );
    try std.testing.expectEqual(@as(u16, 0xffff), status_code);
    try std.testing.expectEqual(
        @intFromEnum(PostResult.invalid_connection),
        vmbus_post_message(0, 1, &payload, payload.len, 0x1000, &status_code, 1, 2, Fake.call, Fake.delay, null),
    );
    try std.testing.expectEqual(@as(u16, 0xffff), status_code);
}

test "invalid modern contact connection retries the legacy version range" {
    var action: Action = undefined;
    const config = StartConfig{
        .target_vp = 7,
        .timeout_ticks = 10,
        .interrupt_page_gpa = 0x4000,
        .parent_to_child_monitor_gpa = 0x5000,
        .child_to_parent_monitor_gpa = 0x6000,
    };
    vmbus_protocol_start(100, &config, &action);
    const modern_generation = context.generation;
    try std.testing.expect(vmbus_protocol_post_failure(0x0012, 101, &action) != 0);
    try std.testing.expectEqual(ActionKind.transmit, action.kind);
    try std.testing.expectEqual(makeVersion(4, 1), readU32(action.tx[0..], 8));
    try std.testing.expectEqual(@as(u64, 0x4000), readU64(action.tx[0..], 16));
    try std.testing.expectEqual(legacy_message_connection_id, action.connection_id);
    try std.testing.expect(action.generation != modern_generation);

    try std.testing.expectEqual(
        @as(c_int, 0),
        vmbus_protocol_post_failure(0x0012, 102, &action),
    );
    try std.testing.expectEqual(ActionKind.none, action.kind);

    vmbus_protocol_start(200, &config, &action);
    try std.testing.expectEqual(
        @as(c_int, 0),
        vmbus_protocol_post_failure(0x0005, 201, &action),
    );
    try std.testing.expectEqual(ActionKind.none, action.kind);
}

test "explicit version rejection falls back to a legacy 4.0 packet" {
    var action: Action = undefined;
    const config = StartConfig{
        .target_vp = 7,
        .timeout_ticks = 10,
        .interrupt_page_gpa = 0x4000,
        .parent_to_child_monitor_gpa = 0x5000,
        .child_to_parent_monitor_gpa = 0x6000,
    };
    vmbus_protocol_start(100, &config, &action);
    try std.testing.expectEqual(ActionKind.transmit, action.kind);
    try std.testing.expectEqual(versions[0], readU32(action.tx[0..], 8));
    try std.testing.expectEqual(@as(u32, 7), readU32(action.tx[0..], 12));
    try std.testing.expectEqual(initiate_contact_connection_id, action.connection_id);
    var response = makeMessage(.version_response, 16);
    response[8] = 0;
    for (1..7) |index| {
        vmbus_protocol_receive(&response, 16, context.generation, 101 + index, &action);
        try std.testing.expectEqual(ActionKind.transmit, action.kind);
        try std.testing.expectEqual(versions[index], readU32(action.tx[0..], 8));
    }
    try std.testing.expectEqual(makeVersion(4, 0), readU32(action.tx[0..], 8));
    try std.testing.expectEqual(@as(u64, 0x4000), readU64(action.tx[0..], 16));
    try std.testing.expectEqual(legacy_message_connection_id, action.connection_id);

    response[8] = 1;
    vmbus_protocol_receive(&response, 10, context.generation, 110, &action);
    try std.testing.expectEqual(ActionKind.transmit, action.kind);
    try std.testing.expectEqual(legacy_message_connection_id, action.connection_id);
}

test "all documented version attempts terminate on explicit rejection" {
    var action: Action = undefined;
    const config = StartConfig{
        .target_vp = 0,
        .timeout_ticks = 1,
        .interrupt_page_gpa = 0,
        .parent_to_child_monitor_gpa = 0,
        .child_to_parent_monitor_gpa = 0,
    };
    vmbus_protocol_start(0, &config, &action);
    var response = makeMessage(.version_response, 16);
    response[8] = 0;
    for (1..versions.len) |_| {
        vmbus_protocol_receive(&response, 16, context.generation, 0, &action);
        try std.testing.expectEqual(ActionKind.transmit, action.kind);
    }
    vmbus_protocol_receive(&response, 16, context.generation, 0, &action);
    try std.testing.expectEqual(ActionKind.failed, action.kind);
    try std.testing.expectEqual(ProtocolError.unsupported, action.err);
    try std.testing.expectEqual(State.failed, context.state);
}

test "timeout fails closed and a delayed response is stale" {
    var action: Action = undefined;
    const config = StartConfig{
        .target_vp = 0,
        .timeout_ticks = 10,
        .interrupt_page_gpa = 0,
        .parent_to_child_monitor_gpa = 0,
        .child_to_parent_monitor_gpa = 0,
    };
    vmbus_protocol_start(0, &config, &action);
    vmbus_protocol_tick(11, &action);
    try std.testing.expectEqual(ActionKind.failed, action.kind);
    try std.testing.expectEqual(ProtocolError.timeout, action.err);
    try std.testing.expectEqual(State.failed, context.state);
    var response = makeMessage(.version_response, 16);
    response[8] = 1;
    putU32(response[0..], 12, 0x44);
    vmbus_protocol_receive(&response, 16, context.generation, 12, &action);
    try std.testing.expectEqual(ActionKind.stale, action.kind);
}

test "modern negotiation switches to the returned message connection ID" {
    var action: Action = undefined;
    const config = StartConfig{
        .target_vp = 0,
        .timeout_ticks = 10,
        .interrupt_page_gpa = 0x8877665544332211,
        .parent_to_child_monitor_gpa = 0x2000,
        .child_to_parent_monitor_gpa = 0x3000,
    };
    vmbus_protocol_start(0, &config, &action);
    try std.testing.expectEqual(initiate_contact_connection_id, action.connection_id);
    try std.testing.expectEqual(@as(u64, 2), readU64(action.tx[0..], 16));
    var response = makeMessage(.version_response, 16);
    response[8] = 1;
    putU32(response[0..], 12, 0x1234);
    vmbus_protocol_receive(&response, 16, context.generation, 1, &action);
    try std.testing.expectEqual(ActionKind.transmit, action.kind);
    try std.testing.expectEqual(State.wait_offers, context.state);
    try std.testing.expectEqual(versions[0], context.selected_version);
    try std.testing.expectEqual(@as(u32, 0x1234), action.connection_id);

    vmbus_protocol_release(9, &action);
    try std.testing.expectEqual(ActionKind.transmit, action.kind);
    try std.testing.expectEqual(@intFromEnum(MessageType.relid_released), readU32(action.tx[0..], 0));
    try std.testing.expectEqual(@as(u32, 9), readU32(action.tx[0..], 8));
    try std.testing.expectEqual(@as(u32, 0x1234), action.connection_id);

    vmbus_protocol_unload(2, &action);
    try std.testing.expectEqual(ActionKind.transmit, action.kind);
    try std.testing.expectEqual(@intFromEnum(MessageType.unload), readU32(action.tx[0..], 0));
    try std.testing.expectEqual(@as(u32, 0x1234), action.connection_id);
}

fn makeOffer(class_wire: [16]u8, channel_id: u32) [240]u8 {
    var bytes = makeMessage(.offer_channel, offer_size);
    for (0..class_wire.len) |i|
        bytes[8 + i] = class_wire[i];
    for (0..16) |i|
        bytes[24 + i] = @intCast(i);
    putU16(bytes[0..], 56, 0x21);
    putU16(bytes[0..], 58, 4);
    for (0..120) |i|
        bytes[60 + i] = @truncate(i);
    putU16(bytes[0..], 180, 2);
    putU16(bytes[0..], 182, 8);
    putU32(bytes[0..], 184, channel_id);
    bytes[188] = 3;
    bytes[189] = 1;
    putU16(bytes[0..], 190, 1);
    putU32(bytes[0..], 192, 0x1234);
    return bytes;
}

test "offer rescind and all-offers transitions preserve unknown devices" {
    var action: Action = undefined;
    const config = StartConfig{
        .target_vp = 0,
        .timeout_ticks = 100,
        .interrupt_page_gpa = 0,
        .parent_to_child_monitor_gpa = 0,
        .child_to_parent_monitor_gpa = 0,
    };
    vmbus_protocol_start(0, &config, &action);
    var response = makeMessage(.version_response, 16);
    response[8] = 1;
    putU32(response[0..], 12, 0x44);
    vmbus_protocol_receive(&response, 16, context.generation, 1, &action);
    const unknown_wire = [_]u8{
        0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    };
    var offer = makeOffer(unknown_wire, 42);
    vmbus_protocol_receive(&offer, offer_size, context.generation, 2, &action);
    try std.testing.expectEqual(ActionKind.offer, action.kind);
    try std.testing.expectEqual(@as(u32, 42), action.offer.channel_id);
    try std.testing.expectEqual(@as(u32, 0x1234), action.offer.connection_id);
    try std.testing.expectEqual(@as(u16, 0x21), action.offer.flags);
    try std.testing.expectEqual(@as(u8, 119), action.offer.user_data[119]);

    var rescind = makeMessage(.rescind_channel_offer, 12);
    putU32(rescind[0..], 8, 42);
    vmbus_protocol_receive(&rescind, 12, context.generation, 3, &action);
    try std.testing.expectEqual(ActionKind.rescind, action.kind);
    try std.testing.expectEqual(@as(u32, 42), action.channel_id);

    var done = makeMessage(.all_offers_delivered, 8);
    vmbus_protocol_receive(&done, 8, context.generation, 4, &action);
    try std.testing.expectEqual(ActionKind.offers_complete, action.kind);
    try std.testing.expectEqual(State.ready, context.state);
}

test "malformed lengths fields and message types are rejected" {
    var action: Action = undefined;
    const config = StartConfig{
        .target_vp = 0,
        .timeout_ticks = 100,
        .interrupt_page_gpa = 0,
        .parent_to_child_monitor_gpa = 0,
        .child_to_parent_monitor_gpa = 0,
    };
    vmbus_protocol_start(0, &config, &action);
    var response = makeMessage(.version_response, 16);
    vmbus_protocol_receive(&response, 7, context.generation, 1, &action);
    try std.testing.expectEqual(ActionKind.malformed, action.kind);
    response[8] = 1;
    putU32(response[0..], 12, 0x44);
    vmbus_protocol_receive(&response, 16, context.generation, 1, &action);
    var offer = makeOffer(.{0} ** 16, 1);
    vmbus_protocol_receive(&offer, 187, context.generation, 2, &action);
    try std.testing.expectEqual(ActionKind.malformed, action.kind);
    offer[189] = 2;
    vmbus_protocol_receive(&offer, offer_size, context.generation, 2, &action);
    try std.testing.expectEqual(ActionKind.reject_offer, action.kind);
    try std.testing.expectEqual(@as(u32, 1), action.channel_id);
    var unknown = [_]u8{0} ** 8;
    putU32(unknown[0..], 0, 0xffff);
    vmbus_protocol_receive(&unknown, unknown.len, context.generation, 2, &action);
    try std.testing.expectEqual(ActionKind.malformed, action.kind);
}

test "offer enumeration timeout is surfaced" {
    var action: Action = undefined;
    const config = StartConfig{
        .target_vp = 0,
        .timeout_ticks = 10,
        .interrupt_page_gpa = 0,
        .parent_to_child_monitor_gpa = 0,
        .child_to_parent_monitor_gpa = 0,
    };
    vmbus_protocol_start(0, &config, &action);
    var response = makeMessage(.version_response, 16);
    response[8] = 1;
    putU32(response[0..], 12, 0x44);
    vmbus_protocol_receive(&response, 16, context.generation, 1, &action);
    vmbus_protocol_tick(12, &action);
    try std.testing.expectEqual(ActionKind.failed, action.kind);
    try std.testing.expectEqual(ProtocolError.timeout, action.err);
}

test "unload response and timeout both clean transactions" {
    var action: Action = undefined;
    const config = StartConfig{
        .target_vp = 0,
        .timeout_ticks = 10,
        .interrupt_page_gpa = 0,
        .parent_to_child_monitor_gpa = 0,
        .child_to_parent_monitor_gpa = 0,
    };
    vmbus_protocol_start(0, &config, &action);
    vmbus_protocol_unload(1, &action);
    try std.testing.expectEqual(ActionKind.transmit, action.kind);
    var complete = makeMessage(.unload_response, 8);
    vmbus_protocol_receive(&complete, 8, context.generation, 2, &action);
    try std.testing.expectEqual(ActionKind.cleanup, action.kind);
    try std.testing.expectEqual(State.disconnected, context.state);

    vmbus_protocol_start(20, &config, &action);
    vmbus_protocol_unload(21, &action);
    vmbus_protocol_tick(32, &action);
    try std.testing.expectEqual(ActionKind.cleanup, action.kind);
    try std.testing.expectEqual(ProtocolError.timeout, action.err);
    try std.testing.expectEqual(State.disconnected, context.state);
}

test "forced reset invalidates queued protocol responses" {
    var action: Action = undefined;
    const config = StartConfig{
        .target_vp = 0,
        .timeout_ticks = 10,
        .interrupt_page_gpa = 0,
        .parent_to_child_monitor_gpa = 0,
        .child_to_parent_monitor_gpa = 0,
    };
    vmbus_protocol_start(0, &config, &action);
    const queued_generation = context.generation;
    vmbus_protocol_reset();
    try std.testing.expectEqual(State.disconnected, context.state);
    var response = makeMessage(.version_response, 16);
    response[8] = 1;
    putU32(response[0..], 12, 0x44);
    vmbus_protocol_receive(&response, 16, queued_generation, 1, &action);
    try std.testing.expectEqual(ActionKind.stale, action.kind);
}

test "bounded inventory reports capacity and retains unknown offers" {
    const Inventory = struct {
        entries: [2]?Offer = .{ null, null },
        fn add(self: *@This(), offer: Offer) error{Capacity}!void {
            for (&self.entries) |*entry| {
                if (entry.* == null) {
                    entry.* = offer;
                    return;
                }
            }
            return error.Capacity;
        }
    };
    var inventory = Inventory{};
    var one = std.mem.zeroes(Offer);
    one.channel_id = 1;
    var two = one;
    two.channel_id = 2;
    var unknown = one;
    unknown.channel_id = 3;
    unknown.class_id.bytes[0] = 0xff;
    try inventory.add(one);
    try inventory.add(two);
    try std.testing.expectError(error.Capacity, inventory.add(unknown));
    try std.testing.expect(inventory.entries[0] != null);
    try std.testing.expect(inventory.entries[1] != null);
}
