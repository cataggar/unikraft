// SPDX-License-Identifier: BSD-3-Clause
//
// VMStor wire formats follow the Microsoft Hyper-V storage protocol. The
// version sequence and SRB layout were checked against FreeBSD's BSD-2-Clause
// Hyper-V StorVSC implementation; see NOTICE.

const std = @import("std");

pub const core_storage_size: usize = 8192;
pub const core_storage_align: usize = 8;
pub const max_contexts: usize = 64;
pub const max_packet_size: usize = 64;
pub const legacy_packet_size: u32 = 48;
pub const modern_packet_size: u32 = 64;
pub const max_sense_size: usize = 20;
pub const legacy_max_transfer: u32 = 128 * 1024;
pub const report_luns_max: usize = 64;
pub const report_luns_header_size: usize = 8;
pub const report_lun_entry_size: usize = 8;
pub const report_luns_data_size: usize =
    report_luns_header_size + report_luns_max * report_lun_entry_size;
pub const vpd_id_max: usize = 64;

pub const protocol_versions = [_]u16{
    makeVersion(6, 2),
    makeVersion(6, 0),
    makeVersion(5, 1),
    makeVersion(4, 2),
    makeVersion(2, 0),
};

pub const Operation = enum(u32) {
    complete_io = 1,
    remove_device = 2,
    execute_srb = 3,
    reset_lun = 4,
    reset_adapter = 5,
    reset_bus = 6,
    begin_initialization = 7,
    end_initialization = 8,
    query_protocol_version = 9,
    query_properties = 10,
    enumerate_bus = 11,
    fc_hba_data = 12,
    create_sub_channels = 13,
};

pub const EventKind = enum(c_int) {
    ignored = 0,
    transmit = 1,
    initialization_ready = 2,
    initialization_failed = 3,
    request_complete = 4,
    request_timeout = 5,
    reset_complete = 6,
    remove_device = 7,
    enumerate_bus = 8,
    protocol_error = 9,
};

pub const Direction = enum(u8) {
    write = 0,
    read = 1,
    none = 2,
};

pub const Tx = extern struct {
    transaction_id: u64,
    packet_len: u32,
    transfer_len: u32,
    slot: u16,
    direction: u8,
    reserved: u8,
    packet: [max_packet_size]u8,
};

pub const Event = extern struct {
    kind: EventKind,
    err: c_int,
    transaction_id: u64,
    transferred: u32,
    slot: u16,
    srb_status: u8,
    scsi_status: u8,
    sense_len: u8,
    reserved: [3]u8,
    sense: [max_sense_size]u8,
    tx: Tx,
};

pub const ScsiSpec = extern struct {
    transfer_len: u32,
    minimum_transfer: u32,
    timeout_ns: u64,
    cdb: [16]u8,
    cdb_len: u8,
    direction: u8,
    allow_short: u8,
    reserved: u8,
    path_id: u8,
    target_id: u8,
    lun: u8,
    address_reserved: u8,
};

pub const Address = extern struct {
    path_id: u8,
    target_id: u8,
    lun: u8,
    reserved: u8,
};

pub const Capacity = extern struct {
    sectors: u64,
    sector_size: u32,
    needs_capacity16: u8,
    reserved: [3]u8,
};

pub const Inquiry = extern struct {
    peripheral_type: u8,
    removable: u8,
    reserved: [2]u8,
};

pub const Mode = extern struct {
    read_only: u8,
    reserved: [3]u8,
};

pub const Media = extern struct {
    sectors: u64,
    sector_size: u32,
    read_only: u8,
    reserved: [3]u8,
};

pub const VpdId = extern struct {
    length: u8,
    code_set: u8,
    designator_type: u8,
    association: u8,
    bytes: [vpd_id_max]u8,
};

const VmScsiWin8Extension = extern struct {
    reserved: u16,
    queue_tag: u8,
    queue_action: u8,
    srb_flags: u32,
    timeout_value: u32,
    queue_sort_key: u32,
};

const VmScsiRequest = extern struct {
    length: u16,
    srb_status: u8,
    scsi_status: u8,
    port: u8,
    path_id: u8,
    target_id: u8,
    lun: u8,
    cdb_len: u8,
    sense_info_len: u8,
    data_in: u8,
    reserved: u8,
    transfer_len: u32,
    cdb_or_sense: [20]u8,
    extension: VmScsiWin8Extension,
};

const ChannelProperties = extern struct {
    reserved: u32,
    max_channel_count: u16,
    reserved1: u16,
    flags: u32,
    max_transfer_bytes: u32,
    reserved2: u64,
};

const ProtocolVersion = extern struct {
    major_minor: u16,
    revision: u16,
};

const VstorPacket = extern struct {
    operation: u32,
    flags: u32,
    status: u32,
    body: [52]u8,
};

const Phase = enum(u8) {
    idle,
    initializing,
    ready,
    failed,
};

const ControlKind = enum(u8) {
    none,
    begin,
    version,
    properties,
    end,
    reset,
};

const ContextState = enum(u8) {
    free,
    in_flight,
    completed,
};

const RequestContext = struct {
    id: u64 = 0,
    deadline: u64 = 0,
    expected_transfer: u32 = 0,
    minimum_transfer: u32 = 0,
    transferred: u32 = 0,
    result: c_int = 0,
    state: ContextState = .free,
    direction: u8 = @intFromEnum(Direction.none),
    allow_short: u8 = 0,
    srb_status: u8 = 0,
    scsi_status: u8 = 0,
    sense_len: u8 = 0,
    sense: [max_sense_size]u8 = [_]u8{0} ** max_sense_size,
};

const Core = struct {
    epoch: u32 = 0,
    next_sequence: u32 = 1,
    queue_depth: u16 = 0,
    version_index: u8 = 0,
    sense_size: u8 = 18,
    phase: Phase = .idle,
    control_kind: ControlKind = .none,
    resetting: u8 = 0,
    media_ready: u8 = 0,
    read_only: u8 = 0,
    reserved0: [3]u8 = [_]u8{0} ** 3,
    selected_version: u16 = 0,
    reserved1: u16 = 0,
    packet_size: u32 = legacy_packet_size,
    host_max_transfer: u32 = 0,
    transfer_limit: u32 = 0,
    sector_size: u32 = 0,
    sectors: u64 = 0,
    control_id: u64 = 0,
    control_deadline: u64 = 0,
    control_timeout_ns: u64 = 0,
    contexts: [max_contexts]RequestContext =
        [_]RequestContext{.{}} ** max_contexts,
};

const request_completion_flag: u32 = 1;
const srb_status_success: u8 = 0x01;
const srb_status_aborted: u8 = 0x02;
const srb_status_error: u8 = 0x04;
const srb_status_busy: u8 = 0x05;
const srb_status_invalid_request: u8 = 0x06;
const srb_status_invalid_path: u8 = 0x07;
const srb_status_no_device: u8 = 0x08;
const srb_status_timeout: u8 = 0x09;
const srb_status_selection_timeout: u8 = 0x0a;
const srb_status_command_timeout: u8 = 0x0b;
const srb_status_bus_reset: u8 = 0x0e;
const srb_status_data_overrun: u8 = 0x12;
const srb_status_request_flushed: u8 = 0x16;
const srb_status_invalid_lun: u8 = 0x20;
const srb_status_invalid_target: u8 = 0x21;
const srb_status_autosense_valid: u8 = 0x80;
const srb_status_queue_frozen: u8 = 0x40;
const srb_flags_disable_synch_transfer: u32 = 0x00000008;
const srb_flags_data_in: u32 = 0x00000040;
const srb_flags_data_out: u32 = 0x00000080;

const eperm: c_int = 1;
const enoent: c_int = 2;
const eio: c_int = 5;
const eagain: c_int = 11;
const ebusy: c_int = 16;
const eexist: c_int = 17;
const enodev: c_int = 19;
const einval: c_int = 22;
const enospc: c_int = 28;
const erofs: c_int = 30;
const eproto: c_int = 71;
const eoverflow: c_int = 75;
const enotsup: c_int = 95;
const etimedout: c_int = 110;
const enomedium: c_int = 123;
const ecanceled: c_int = 125;

comptime {
    if (@sizeOf(Core) > core_storage_size or @alignOf(Core) > core_storage_align)
        @compileError("StorVSC opaque core storage is too small");
    if (@sizeOf(Tx) != 88 or @alignOf(Tx) != 8 or
        @offsetOf(Tx, "packet") != 20)
        @compileError("StorVSC transmit C ABI changed");
    if (@sizeOf(Event) != 136 or @alignOf(Event) != 8 or
        @offsetOf(Event, "tx") != 48)
        @compileError("StorVSC event C ABI changed");
    if (@sizeOf(ScsiSpec) != 40 or @offsetOf(ScsiSpec, "cdb") != 16 or
        @offsetOf(ScsiSpec, "path_id") != 36 or
        @offsetOf(ScsiSpec, "target_id") != 37 or
        @offsetOf(ScsiSpec, "lun") != 38 or
        @offsetOf(ScsiSpec, "address_reserved") != 39 or
        @sizeOf(Address) != 4 or report_luns_data_size != 520)
        @compileError("StorVSC SCSI specification C ABI changed");
    if (@sizeOf(Capacity) != 16 or @sizeOf(Inquiry) != 4 or
        @sizeOf(Mode) != 4 or @sizeOf(Media) != 16 or
        @sizeOf(VpdId) != 68)
        @compileError("StorVSC parser C ABI changed");
    if (@sizeOf(VmScsiWin8Extension) != 16 or
        @offsetOf(VmScsiWin8Extension, "srb_flags") != 4 or
        @offsetOf(VmScsiWin8Extension, "timeout_value") != 8)
        @compileError("VMStor Windows 8 SRB extension layout changed");
    if (@sizeOf(VmScsiRequest) != 52 or
        @offsetOf(VmScsiRequest, "transfer_len") != 12 or
        @offsetOf(VmScsiRequest, "cdb_or_sense") != 16 or
        @offsetOf(VmScsiRequest, "extension") != 36)
        @compileError("VMStor SRB wire layout changed");
    if (@sizeOf(ChannelProperties) != 24 or
        @offsetOf(ChannelProperties, "max_channel_count") != 4 or
        @offsetOf(ChannelProperties, "max_transfer_bytes") != 12)
        @compileError("VMStor channel-properties wire layout changed");
    if (@sizeOf(ProtocolVersion) != 4 or
        @offsetOf(ProtocolVersion, "revision") != 2)
        @compileError("VMStor protocol-version wire layout changed");
    if (@sizeOf(VstorPacket) != modern_packet_size or
        @offsetOf(VstorPacket, "body") != 12 or
        legacy_packet_size !=
            @offsetOf(VstorPacket, "body") +
                @offsetOf(VmScsiRequest, "extension"))
        @compileError("VMStor packet wire layout changed");
}

pub fn makeVersion(major: u8, minor: u8) u16 {
    return (@as(u16, major) << 8) | minor;
}

fn coreFrom(storage: *align(core_storage_align) anyopaque) *Core {
    return @ptrCast(storage);
}

fn zeroObject(object: anytype) void {
    const bytes: [*]volatile u8 = @ptrCast(object);
    for (0..@sizeOf(@TypeOf(object.*))) |i|
        bytes[i] = 0;
}

fn clearEvent(event: *Event) void {
    zeroObject(event);
    event.kind = .ignored;
    event.tx.slot = std.math.maxInt(u16);
}

fn putLe16(bytes: []u8, offset: usize, value: u16) void {
    bytes[offset] = @truncate(value);
    bytes[offset + 1] = @truncate(value >> 8);
}

fn putLe32(bytes: []u8, offset: usize, value: u32) void {
    for (0..4) |i|
        bytes[offset + i] = @truncate(value >> @intCast(i * 8));
}

fn getLe16(bytes: []const u8, offset: usize) u16 {
    return @as(u16, bytes[offset]) |
        (@as(u16, bytes[offset + 1]) << 8);
}

fn getLe32(bytes: []const u8, offset: usize) u32 {
    var value: u32 = 0;
    for (0..4) |i|
        value |= @as(u32, bytes[offset + i]) << @intCast(i * 8);
    return value;
}

fn putBe16(bytes: []u8, offset: usize, value: u16) void {
    bytes[offset] = @truncate(value >> 8);
    bytes[offset + 1] = @truncate(value);
}

fn putBe32(bytes: []u8, offset: usize, value: u32) void {
    for (0..4) |i|
        bytes[offset + i] =
            @truncate(value >> @intCast((3 - i) * 8));
}

fn putBe64(bytes: []u8, offset: usize, value: u64) void {
    for (0..8) |i|
        bytes[offset + i] =
            @truncate(value >> @intCast((7 - i) * 8));
}

fn getBe16(bytes: []const u8, offset: usize) u16 {
    return (@as(u16, bytes[offset]) << 8) |
        @as(u16, bytes[offset + 1]);
}

fn getBe32(bytes: []const u8, offset: usize) u32 {
    var value: u32 = 0;
    for (0..4) |i|
        value = (value << 8) | bytes[offset + i];
    return value;
}

fn getBe64(bytes: []const u8, offset: usize) u64 {
    var value: u64 = 0;
    for (0..8) |i|
        value = (value << 8) | bytes[offset + i];
    return value;
}

fn addSaturating(a: u64, b: u64) u64 {
    if (std.math.maxInt(u64) - a < b)
        return std.math.maxInt(u64);
    return a + b;
}

fn addChecked(a: u64, b: u64) ?u64 {
    if (std.math.maxInt(u64) - a < b)
        return null;
    return a + b;
}

fn multiplyChecked(a: u64, b: u64) ?u64 {
    if (a != 0 and b > std.math.maxInt(u64) / a)
        return null;
    return a * b;
}

fn allocateId(core: *Core) ?u64 {
    if (core.epoch == 0 or core.next_sequence == 0)
        return null;
    const id = (@as(u64, core.epoch) << 32) | core.next_sequence;
    core.next_sequence = if (core.next_sequence == std.math.maxInt(u32))
        0
    else
        core.next_sequence + 1;
    return id;
}

fn beginControl(
    core: *Core,
    kind: ControlKind,
    operation: Operation,
    packet_size: u32,
    now: u64,
    event: *Event,
) c_int {
    const id = allocateId(core) orelse return -enospc;
    clearEvent(event);
    event.kind = .transmit;
    event.tx.transaction_id = id;
    event.tx.packet_len = packet_size;
    event.tx.direction = @intFromEnum(Direction.none);
    putLe32(event.tx.packet[0..], 0, @intFromEnum(operation));
    putLe32(event.tx.packet[0..], 4, request_completion_flag);
    core.control_kind = kind;
    core.control_id = id;
    core.control_deadline = addSaturating(now, core.control_timeout_ns);
    return 0;
}

fn beginVersion(core: *Core, now: u64, event: *Event) c_int {
    const rc = beginControl(
        core,
        .version,
        .query_protocol_version,
        legacy_packet_size,
        now,
        event,
    );
    if (rc != 0)
        return rc;
    putLe16(
        event.tx.packet[0..],
        12,
        protocol_versions[core.version_index],
    );
    return 0;
}

fn failInitialization(core: *Core, event: *Event, err: c_int) void {
    core.phase = .failed;
    core.control_kind = .none;
    core.control_id = 0;
    core.control_deadline = 0;
    clearEvent(event);
    event.kind = .initialization_failed;
    event.err = err;
}

fn completeRequest(
    context: *RequestContext,
    slot: usize,
    event: *Event,
    result: c_int,
    transferred: u32,
    srb_status: u8,
    scsi_status: u8,
    sense: []const u8,
) void {
    context.result = result;
    context.transferred = transferred;
    context.srb_status = srb_status;
    context.scsi_status = scsi_status;
    context.sense_len = @intCast(@min(sense.len, max_sense_size));
    for (0..context.sense.len) |i|
        context.sense[i] = if (i < context.sense_len) sense[i] else 0;
    context.state = .completed;

    clearEvent(event);
    event.kind = .request_complete;
    event.err = result;
    event.transaction_id = context.id;
    event.transferred = transferred;
    event.slot = @intCast(slot);
    event.srb_status = srb_status;
    event.scsi_status = scsi_status;
    event.sense_len = context.sense_len;
    for (0..event.sense.len) |i|
        event.sense[i] = context.sense[i];
}

fn senseError(sense: []const u8) c_int {
    if (sense.len == 0)
        return -eio;
    const response = sense[0] & 0x7f;
    var key: u8 = 0;
    var asc: u8 = 0;
    if (response == 0x70 or response == 0x71) {
        if (sense.len < 14)
            return -eproto;
        key = sense[2] & 0x0f;
        asc = sense[12];
    } else if (response == 0x72 or response == 0x73) {
        if (sense.len < 4)
            return -eproto;
        key = sense[1] & 0x0f;
        asc = sense[2];
    } else {
        return -eproto;
    }
    return switch (key) {
        0x02 => if (asc == 0x3a) -enomedium else -eagain,
        0x05 => -einval,
        0x06 => -eagain,
        0x07 => -erofs,
        0x0b => -eio,
        else => -eio,
    };
}

fn srbError(raw: u8) c_int {
    const status = raw & ~(srb_status_autosense_valid |
        srb_status_queue_frozen);
    return switch (status) {
        srb_status_busy => -eagain,
        srb_status_invalid_request => -einval,
        srb_status_invalid_path,
        srb_status_no_device,
        srb_status_invalid_lun,
        srb_status_invalid_target,
        srb_status_selection_timeout,
        => -enodev,
        srb_status_timeout, srb_status_command_timeout => -etimedout,
        srb_status_aborted,
        srb_status_bus_reset,
        srb_status_request_flushed,
        => -ecanceled,
        else => -eio,
    };
}

fn findContext(core: *Core, id: u64) ?usize {
    for (0..core.queue_depth) |slot| {
        if (core.contexts[slot].state != .free and
            core.contexts[slot].id == id)
            return slot;
    }
    return null;
}

fn completionPacketSizeValid(length: usize) bool {
    // VMStor defines the pre-Win8 and Win8+ packet envelopes.
    return length == legacy_packet_size or
        length == modern_packet_size;
}

fn parseRequestCompletion(
    core: *Core,
    slot: usize,
    payload: []const u8,
    event: *Event,
) void {
    const context = &core.contexts[slot];
    if (context.state != .in_flight) {
        clearEvent(event);
        return;
    }
    if (!completionPacketSizeValid(payload.len)) {
        completeRequest(
            context,
            slot,
            event,
            -eproto,
            0,
            0,
            0,
            &.{},
        );
        return;
    }
    if (getLe32(payload, 0) != @intFromEnum(Operation.complete_io)) {
        completeRequest(
            context,
            slot,
            event,
            -eproto,
            0,
            0,
            0,
            &.{},
        );
        return;
    }
    const packet_status = getLe32(payload, 8);
    const srb_status = payload[14];
    const scsi_status = payload[15];
    const sense_len = payload[21];
    const transferred = getLe32(payload, 24);
    if (sense_len > core.sense_size or sense_len > max_sense_size or
        transferred > context.expected_transfer or
        ((srb_status & srb_status_autosense_valid) != 0 and
            28 + @as(usize, sense_len) > payload.len))
    {
        completeRequest(
            context,
            slot,
            event,
            -eproto,
            0,
            srb_status,
            scsi_status,
            &.{},
        );
        return;
    }

    var result: c_int = 0;
    var sense: []const u8 = &.{};
    if (packet_status != 0) {
        result = -eio;
    } else if (scsi_status != 0) {
        if (scsi_status == 0x02 and
            (srb_status & srb_status_autosense_valid) != 0)
        {
            sense = payload[28 .. 28 + sense_len];
            result = senseError(sense);
        } else if (scsi_status == 0x08 or scsi_status == 0x18 or
            scsi_status == 0x28)
        {
            result = -ebusy;
        } else {
            result = -eio;
        }
    } else {
        const base_status = srb_status & ~(srb_status_autosense_valid |
            srb_status_queue_frozen);
        if (base_status == srb_status_success) {
            if (transferred != context.expected_transfer and
                (context.allow_short == 0 or
                    transferred < context.minimum_transfer))
                result = -eio;
        } else if (base_status == srb_status_data_overrun and
            context.allow_short != 0 and
            transferred >= context.minimum_transfer)
        {
            result = 0;
        } else if ((srb_status & srb_status_autosense_valid) != 0 and
            sense_len != 0)
        {
            sense = payload[28 .. 28 + sense_len];
            result = senseError(sense);
        } else {
            result = srbError(srb_status);
        }
    }
    completeRequest(
        context,
        slot,
        event,
        result,
        transferred,
        srb_status,
        scsi_status,
        sense,
    );
}

fn controlPacketValid(payload: []const u8) bool {
    return completionPacketSizeValid(payload.len) and
        getLe32(payload, 0) == @intFromEnum(Operation.complete_io);
}

export fn storvsc_core_initialize(
    storage: *align(core_storage_align) anyopaque,
    epoch: u32,
    queue_depth: u16,
) callconv(.c) c_int {
    if (epoch == 0 or queue_depth == 0 or queue_depth > max_contexts)
        return -einval;
    const core = coreFrom(storage);
    zeroObject(core);
    core.epoch = epoch;
    core.next_sequence = 1;
    core.queue_depth = queue_depth;
    core.packet_size = legacy_packet_size;
    core.sense_size = 18;
    return 0;
}

export fn storvsc_core_start(
    storage: *align(core_storage_align) anyopaque,
    now: u64,
    timeout_ns: u64,
    event: *Event,
) callconv(.c) c_int {
    const core = coreFrom(storage);
    clearEvent(event);
    if (core.epoch == 0 or core.phase != .idle or timeout_ns == 0)
        return -einval;
    core.phase = .initializing;
    core.version_index = 0;
    core.control_timeout_ns = timeout_ns;
    const rc = beginControl(
        core,
        .begin,
        .begin_initialization,
        legacy_packet_size,
        now,
        event,
    );
    if (rc != 0)
        failInitialization(core, event, rc);
    return rc;
}

export fn storvsc_core_receive(
    storage: *align(core_storage_align) anyopaque,
    transaction_id: u64,
    payload_ptr: [*]const u8,
    payload_len: usize,
    now: u64,
    event: *Event,
) callconv(.c) c_int {
    const core = coreFrom(storage);
    const payload = payload_ptr[0..payload_len];
    clearEvent(event);

    if (transaction_id == 0) {
        if (payload.len < 4 or payload.len > max_packet_size) {
            event.kind = .protocol_error;
            event.err = -eproto;
            return 0;
        }
        switch (getLe32(payload, 0)) {
            @intFromEnum(Operation.remove_device) => {
                event.kind = .remove_device;
                event.err = -enodev;
            },
            @intFromEnum(Operation.enumerate_bus) => {
                event.kind = .enumerate_bus;
            },
            else => {},
        }
        return 0;
    }

    if (core.control_kind != .none and transaction_id == core.control_id) {
        const control_kind = core.control_kind;
        if (!controlPacketValid(payload)) {
            if (control_kind == .reset) {
                core.control_kind = .none;
                core.control_id = 0;
                core.resetting = 0;
                event.kind = .reset_complete;
                event.err = -eproto;
            } else {
                failInitialization(core, event, -eproto);
            }
            return 0;
        }
        const status = getLe32(payload, 8);
        switch (control_kind) {
            .begin => {
                if (status != 0) {
                    failInitialization(core, event, -eio);
                    return 0;
                }
                core.control_kind = .none;
                if (beginVersion(core, now, event) != 0)
                    failInitialization(core, event, -enospc);
            },
            .version => {
                core.control_kind = .none;
                if (status != 0) {
                    if (core.version_index + 1 >= protocol_versions.len) {
                        failInitialization(core, event, -enotsup);
                        return 0;
                    }
                    core.version_index += 1;
                    if (beginVersion(core, now, event) != 0)
                        failInitialization(core, event, -enospc);
                    return 0;
                }
                core.selected_version =
                    protocol_versions[core.version_index];
                if (core.selected_version >= makeVersion(5, 1)) {
                    core.packet_size = modern_packet_size;
                    core.sense_size = 20;
                } else {
                    core.packet_size = legacy_packet_size;
                    core.sense_size = 18;
                }
                if (beginControl(
                    core,
                    .properties,
                    .query_properties,
                    core.packet_size,
                    now,
                    event,
                ) != 0)
                    failInitialization(core, event, -enospc);
            },
            .properties => {
                core.control_kind = .none;
                if (status != 0) {
                    failInitialization(core, event, -eio);
                    return 0;
                }
                var maximum = getLe32(payload, 24);
                if (maximum == 0)
                    maximum = if (core.selected_version <
                        makeVersion(5, 1))
                        legacy_max_transfer
                    else {
                        failInitialization(core, event, -eproto);
                        return 0;
                    };
                core.host_max_transfer = maximum;
                core.transfer_limit = maximum;
                if (beginControl(
                    core,
                    .end,
                    .end_initialization,
                    core.packet_size,
                    now,
                    event,
                ) != 0)
                    failInitialization(core, event, -enospc);
            },
            .end => {
                core.control_kind = .none;
                core.control_id = 0;
                if (status != 0) {
                    failInitialization(core, event, -eio);
                    return 0;
                }
                core.phase = .ready;
                event.kind = .initialization_ready;
            },
            .reset => {
                core.control_kind = .none;
                core.control_id = 0;
                core.resetting = 0;
                event.kind = .reset_complete;
                event.err = if (status == 0) 0 else -eio;
            },
            .none => {},
        }
        return 0;
    }

    const slot = findContext(core, transaction_id) orelse return 0;
    parseRequestCompletion(core, slot, payload, event);
    return 0;
}

export fn storvsc_core_tick(
    storage: *align(core_storage_align) anyopaque,
    now: u64,
    event: *Event,
) callconv(.c) c_int {
    const core = coreFrom(storage);
    clearEvent(event);
    if (core.control_kind != .none and now >= core.control_deadline) {
        const was_reset = core.control_kind == .reset;
        core.control_kind = .none;
        core.control_id = 0;
        core.control_deadline = 0;
        if (was_reset) {
            core.resetting = 0;
            event.kind = .reset_complete;
            event.err = -etimedout;
        } else {
            failInitialization(core, event, -etimedout);
        }
        return 0;
    }
    for (0..core.queue_depth) |slot| {
        const context = &core.contexts[slot];
        if (context.state == .in_flight and now >= context.deadline) {
            event.kind = .request_timeout;
            event.err = -etimedout;
            event.transaction_id = context.id;
            event.slot = @intCast(slot);
            return 0;
        }
    }
    return 0;
}

fn allocateContext(
    core: *Core,
    spec: *const ScsiSpec,
    now: u64,
    tx: *Tx,
) c_int {
    if (core.phase != .ready)
        return -enodev;
    if (core.resetting != 0)
        return -eagain;
    if (spec.timeout_ns == 0 or spec.cdb_len == 0 or spec.cdb_len > 16 or
        spec.minimum_transfer > spec.transfer_len or
        spec.transfer_len > core.transfer_limit or spec.reserved != 0 or
        spec.address_reserved != 0)
        return -einval;
    if (spec.direction > @intFromEnum(Direction.none))
        return -einval;
    if (spec.direction == @intFromEnum(Direction.none)) {
        if (spec.transfer_len != 0 or spec.minimum_transfer != 0)
            return -einval;
    } else if (spec.transfer_len == 0) {
        return -einval;
    }

    var slot: usize = 0;
    while (slot < core.queue_depth and
        core.contexts[slot].state != .free) : (slot += 1)
    {}
    if (slot == core.queue_depth)
        return -enospc;
    const id = allocateId(core) orelse return -enospc;
    var context = &core.contexts[slot];
    zeroObject(context);
    context.id = id;
    context.deadline = addSaturating(now, spec.timeout_ns);
    context.expected_transfer = spec.transfer_len;
    context.minimum_transfer = spec.minimum_transfer;
    context.direction = spec.direction;
    context.allow_short = @intFromBool(spec.allow_short != 0);
    context.state = .in_flight;

    zeroObject(tx);
    tx.transaction_id = id;
    tx.packet_len = core.packet_size;
    tx.transfer_len = spec.transfer_len;
    tx.slot = @intCast(slot);
    tx.direction = spec.direction;
    putLe32(tx.packet[0..], 0, @intFromEnum(Operation.execute_srb));
    putLe32(tx.packet[0..], 4, request_completion_flag);
    putLe16(
        tx.packet[0..],
        12,
        if (core.packet_size == modern_packet_size) 52 else 36,
    );
    tx.packet[20] = spec.cdb_len;
    tx.packet[21] = core.sense_size;
    tx.packet[22] = spec.direction;
    tx.packet[17] = spec.path_id;
    tx.packet[18] = spec.target_id;
    tx.packet[19] = spec.lun;
    putLe32(tx.packet[0..], 24, spec.transfer_len);
    for (0..spec.cdb_len) |i|
        tx.packet[28 + i] = spec.cdb[i];
    if (core.packet_size == modern_packet_size) {
        var flags = srb_flags_disable_synch_transfer;
        if (spec.direction == @intFromEnum(Direction.read))
            flags |= srb_flags_data_in;
        if (spec.direction == @intFromEnum(Direction.write))
            flags |= srb_flags_data_out;
        putLe32(tx.packet[0..], 52, flags);
        putLe32(tx.packet[0..], 56, 60);
    }
    return 0;
}

export fn storvsc_core_prepare_scsi(
    storage: *align(core_storage_align) anyopaque,
    spec: *const ScsiSpec,
    now: u64,
    tx: *Tx,
) callconv(.c) c_int {
    return allocateContext(coreFrom(storage), spec, now, tx);
}

fn prepareBlock(
    core: *Core,
    address: *const Address,
    media: *const Media,
    operation: c_int,
    start_sector: u64,
    sector_count: u64,
    buffer_address: u64,
    now: u64,
    timeout_ns: u64,
    tx: *Tx,
) c_int {
    if (address.reserved != 0)
        return -einval;
    if (media.read_only > 1 or
        media.reserved[0] != 0 or
        media.reserved[1] != 0 or
        media.reserved[2] != 0)
        return -einval;
    if (media.sectors == 0 or !sectorSizeValid(media.sector_size) or
        multiplyChecked(media.sectors, media.sector_size) == null)
        return -einval;

    var spec: ScsiSpec = .{
        .transfer_len = 0,
        .minimum_transfer = 0,
        .timeout_ns = timeout_ns,
        .cdb = [_]u8{0} ** 16,
        .cdb_len = 0,
        .direction = @intFromEnum(Direction.none),
        .allow_short = 0,
        .reserved = 0,
        .path_id = address.path_id,
        .target_id = address.target_id,
        .lun = address.lun,
        .address_reserved = 0,
    };
    if (operation == 4) {
        if (start_sector != 0 or sector_count != 0)
            return -einval;
        spec.cdb[0] = 0x35;
        spec.cdb_len = 10;
        return allocateContext(core, &spec, now, tx);
    }
    if (operation != 0 and operation != 1)
        return -einval;
    if (operation == 1 and media.read_only != 0)
        return -erofs;
    if (sector_count == 0 or buffer_address == 0 or
        (buffer_address & 7) != 0)
        return -einval;
    const end = addChecked(start_sector, sector_count) orelse
        return -eoverflow;
    if (end > media.sectors)
        return -einval;
    const bytes = multiplyChecked(sector_count, media.sector_size) orelse
        return -eoverflow;
    if (bytes > std.math.maxInt(u32) or bytes > core.transfer_limit)
        return -einval;
    spec.transfer_len = @intCast(bytes);
    spec.minimum_transfer = @intCast(bytes);
    spec.direction = if (operation == 0)
        @intFromEnum(Direction.read)
    else
        @intFromEnum(Direction.write);
    const last_sector = end - 1;
    if (last_sector <= std.math.maxInt(u32) and
        sector_count <= std.math.maxInt(u16))
    {
        spec.cdb[0] = if (operation == 0) 0x28 else 0x2a;
        putBe32(spec.cdb[0..], 2, @intCast(start_sector));
        putBe16(spec.cdb[0..], 7, @intCast(sector_count));
        spec.cdb_len = 10;
    } else {
        if (sector_count > std.math.maxInt(u32))
            return -einval;
        spec.cdb[0] = if (operation == 0) 0x88 else 0x8a;
        putBe64(spec.cdb[0..], 2, start_sector);
        putBe32(spec.cdb[0..], 10, @intCast(sector_count));
        spec.cdb_len = 16;
    }
    return allocateContext(core, &spec, now, tx);
}

export fn storvsc_core_prepare_block(
    storage: *align(core_storage_align) anyopaque,
    operation: c_int,
    start_sector: u64,
    sector_count: u64,
    buffer_address: u64,
    now: u64,
    timeout_ns: u64,
    tx: *Tx,
) callconv(.c) c_int {
    const core = coreFrom(storage);
    if (core.media_ready == 0)
        return -enodev;
    const address: Address = .{
        .path_id = 0,
        .target_id = 0,
        .lun = 0,
        .reserved = 0,
    };
    const media: Media = .{
        .sectors = core.sectors,
        .sector_size = core.sector_size,
        .read_only = core.read_only,
        .reserved = [_]u8{0} ** 3,
    };
    return prepareBlock(
        core,
        &address,
        &media,
        operation,
        start_sector,
        sector_count,
        buffer_address,
        now,
        timeout_ns,
        tx,
    );
}

export fn storvsc_core_prepare_block_at(
    storage: *align(core_storage_align) anyopaque,
    address: *const Address,
    operation: c_int,
    start_sector: u64,
    sector_count: u64,
    buffer_address: u64,
    now: u64,
    timeout_ns: u64,
    tx: *Tx,
) callconv(.c) c_int {
    const core = coreFrom(storage);
    if (core.media_ready == 0)
        return -enodev;
    const media: Media = .{
        .sectors = core.sectors,
        .sector_size = core.sector_size,
        .read_only = core.read_only,
        .reserved = [_]u8{0} ** 3,
    };
    return prepareBlock(
        core,
        address,
        &media,
        operation,
        start_sector,
        sector_count,
        buffer_address,
        now,
        timeout_ns,
        tx,
    );
}

export fn storvsc_core_prepare_block_media(
    storage: *align(core_storage_align) anyopaque,
    address: *const Address,
    media: *const Media,
    operation: c_int,
    start_sector: u64,
    sector_count: u64,
    buffer_address: u64,
    now: u64,
    timeout_ns: u64,
    tx: *Tx,
) callconv(.c) c_int {
    return prepareBlock(
        coreFrom(storage),
        address,
        media,
        operation,
        start_sector,
        sector_count,
        buffer_address,
        now,
        timeout_ns,
        tx,
    );
}

export fn storvsc_core_begin_reset(
    storage: *align(core_storage_align) anyopaque,
    now: u64,
    timeout_ns: u64,
    event: *Event,
) callconv(.c) c_int {
    const core = coreFrom(storage);
    clearEvent(event);
    if (core.phase != .ready or core.resetting != 0 or
        core.control_kind != .none or timeout_ns == 0)
        return -ebusy;
    core.resetting = 1;
    core.control_timeout_ns = timeout_ns;
    const rc = beginControl(
        core,
        .reset,
        .reset_bus,
        core.packet_size,
        now,
        event,
    );
    if (rc != 0)
        core.resetting = 0;
    return rc;
}

export fn storvsc_core_abort(
    storage: *align(core_storage_align) anyopaque,
    slot: u16,
    transaction_id: u64,
) callconv(.c) c_int {
    const core = coreFrom(storage);
    if (slot >= core.queue_depth)
        return -einval;
    const context = &core.contexts[slot];
    if (context.state != .in_flight or context.id != transaction_id)
        return -enoent;
    zeroObject(context);
    return 0;
}

export fn storvsc_core_cancel_all(
    storage: *align(core_storage_align) anyopaque,
    result: c_int,
) callconv(.c) u32 {
    const core = coreFrom(storage);
    var count: u32 = 0;
    for (0..core.queue_depth) |slot| {
        const context = &core.contexts[slot];
        if (context.state != .in_flight)
            continue;
        context.result = result;
        context.transferred = 0;
        context.state = .completed;
        count += 1;
    }
    return count;
}

export fn storvsc_core_next_completed(
    storage: *align(core_storage_align) anyopaque,
    slot_out: *u16,
) callconv(.c) c_int {
    const core = coreFrom(storage);
    for (0..core.queue_depth) |slot| {
        if (core.contexts[slot].state == .completed) {
            slot_out.* = @intCast(slot);
            return 0;
        }
    }
    return -enoent;
}

export fn storvsc_core_take_completed(
    storage: *align(core_storage_align) anyopaque,
    slot: u16,
    transaction_id: u64,
    event: *Event,
) callconv(.c) c_int {
    const core = coreFrom(storage);
    clearEvent(event);
    if (slot >= core.queue_depth)
        return -einval;
    const context = &core.contexts[slot];
    if (context.state != .completed or context.id != transaction_id)
        return -enoent;
    event.kind = .request_complete;
    event.err = context.result;
    event.transaction_id = context.id;
    event.transferred = context.transferred;
    event.slot = slot;
    event.srb_status = context.srb_status;
    event.scsi_status = context.scsi_status;
    event.sense_len = context.sense_len;
    for (0..event.sense.len) |i|
        event.sense[i] = context.sense[i];
    zeroObject(context);
    return 0;
}

export fn storvsc_core_active_count(
    storage: *align(core_storage_align) anyopaque,
) callconv(.c) u32 {
    const core = coreFrom(storage);
    var count: u32 = 0;
    for (0..core.queue_depth) |slot| {
        if (core.contexts[slot].state != .free) {
            count += 1;
        }
    }
    return count;
}

export fn storvsc_core_free_count(
    storage: *align(core_storage_align) anyopaque,
) callconv(.c) u32 {
    const core = coreFrom(storage);
    return core.queue_depth - storvsc_core_active_count(storage);
}

export fn storvsc_core_set_transfer_limit(
    storage: *align(core_storage_align) anyopaque,
    transfer_limit: u32,
) callconv(.c) c_int {
    const core = coreFrom(storage);
    if (core.phase != .ready or transfer_limit == 0 or
        transfer_limit > core.host_max_transfer)
        return -einval;
    core.transfer_limit = transfer_limit;
    return 0;
}

export fn storvsc_core_set_media(
    storage: *align(core_storage_align) anyopaque,
    sectors: u64,
    sector_size: u32,
    read_only: u8,
) callconv(.c) c_int {
    const core = coreFrom(storage);
    if (core.phase != .ready or sectors == 0 or
        !sectorSizeValid(sector_size) or
        multiplyChecked(sectors, sector_size) == null)
        return -einval;
    core.sectors = sectors;
    core.sector_size = sector_size;
    core.read_only = @intFromBool(read_only != 0);
    core.media_ready = 1;
    return 0;
}

export fn storvsc_core_version(
    storage: *align(core_storage_align) anyopaque,
) callconv(.c) u16 {
    return coreFrom(storage).selected_version;
}

export fn storvsc_core_packet_size(
    storage: *align(core_storage_align) anyopaque,
) callconv(.c) u32 {
    return coreFrom(storage).packet_size;
}

export fn storvsc_core_host_max_transfer(
    storage: *align(core_storage_align) anyopaque,
) callconv(.c) u32 {
    return coreFrom(storage).host_max_transfer;
}

export fn storvsc_build_report_luns(
    spec: *ScsiSpec,
    path_id: u8,
    target_id: u8,
    lun_capacity: u32,
    timeout_ns: u64,
) callconv(.c) c_int {
    if (lun_capacity == 0 or timeout_ns == 0)
        return -einval;
    if (lun_capacity > report_luns_max)
        return -enospc;
    const payload_size = multiplyChecked(
        lun_capacity,
        report_lun_entry_size,
    ) orelse return -eoverflow;
    const allocation_size = addChecked(
        report_luns_header_size,
        payload_size,
    ) orelse return -eoverflow;
    if (allocation_size > std.math.maxInt(u32))
        return -eoverflow;

    zeroObject(spec);
    spec.transfer_len = @intCast(allocation_size);
    spec.minimum_transfer = report_luns_header_size;
    spec.timeout_ns = timeout_ns;
    spec.cdb[0] = 0xa0;
    putBe32(spec.cdb[0..], 6, @intCast(allocation_size));
    spec.cdb_len = 12;
    spec.direction = @intFromEnum(Direction.read);
    spec.allow_short = 1;
    spec.path_id = path_id;
    spec.target_id = target_id;
    return 0;
}

export fn storvsc_parse_report_luns(
    data_ptr: [*]const u8,
    data_len: usize,
    path_id: u8,
    target_id: u8,
    addresses_ptr: [*]Address,
    address_capacity: usize,
    address_count: *usize,
) callconv(.c) c_int {
    address_count.* = 0;
    const data = data_ptr[0..data_len];
    if (data.len < report_luns_header_size)
        return -eproto;
    for (data[4..report_luns_header_size]) |byte| {
        if (byte != 0)
            return -eproto;
    }

    const list_size: usize = @intCast(getBe32(data, 0));
    if (list_size == 0)
        return -enodev;
    if (list_size % report_lun_entry_size != 0)
        return -eproto;
    const count = list_size / report_lun_entry_size;
    if (count > report_luns_max or count > address_capacity)
        return -enospc;
    const required_size = addChecked(
        report_luns_header_size,
        list_size,
    ) orelse return -eoverflow;
    if (required_size > data.len)
        return -eproto;

    var parsed: [report_luns_max]Address = undefined;
    for (0..count) |index| {
        const offset =
            report_luns_header_size + index * report_lun_entry_size;
        const entry = data[offset .. offset + report_lun_entry_size];
        for (entry[2..]) |byte| {
            if (byte != 0)
                return -enotsup;
        }
        const method = entry[0] >> 6;
        const upper = entry[0] & 0x3f;
        switch (method) {
            0 => if (upper != 0)
                return -enotsup,
            1 => if (upper != 0)
                return -eoverflow,
            else => return -enotsup,
        }
        const lun = entry[1];
        for (parsed[0..index]) |address| {
            if (address.lun == lun)
                return -eexist;
        }
        parsed[index] = .{
            .path_id = path_id,
            .target_id = target_id,
            .lun = lun,
            .reserved = 0,
        };
    }

    for (1..count) |index| {
        const address = parsed[index];
        var insertion = index;
        while (insertion > 0 and
            parsed[insertion - 1].lun > address.lun) : (insertion -= 1)
        {
            parsed[insertion] = parsed[insertion - 1];
        }
        parsed[insertion] = address;
    }
    for (0..count) |index| {
        addresses_ptr[index].path_id = parsed[index].path_id;
        addresses_ptr[index].target_id = parsed[index].target_id;
        addresses_ptr[index].lun = parsed[index].lun;
        addresses_ptr[index].reserved = 0;
    }
    address_count.* = count;
    return 0;
}

fn vpdPriority(designator_type: u8) u8 {
    return switch (designator_type) {
        3 => 0,
        2 => 1,
        8 => 2,
        1 => 3,
        else => 4,
    };
}

fn vpdLess(
    candidate: []const u8,
    candidate_type: u8,
    selected: []const u8,
    selected_type: u8,
) bool {
    const candidate_priority = vpdPriority(candidate_type);
    const selected_priority = vpdPriority(selected_type);
    if (candidate_priority != selected_priority)
        return candidate_priority < selected_priority;
    const compared = @min(candidate.len, selected.len);
    for (0..compared) |index| {
        if (candidate[index] != selected[index])
            return candidate[index] < selected[index];
    }
    return candidate.len < selected.len;
}

export fn storvsc_parse_vpd83(
    data_ptr: [*]const u8,
    data_len: usize,
    identity: *VpdId,
) callconv(.c) c_int {
    zeroObject(identity);
    const data = data_ptr[0..data_len];
    if (data.len < 4 or data[1] != 0x83 or data[0] >> 5 != 0 or
        data[0] & 0x1f != 0)
        return -eproto;
    const page_size: usize = getBe16(data, 2);
    if (page_size > std.math.maxInt(usize) - 4)
        return -eoverflow;
    const total_size = page_size + 4;
    if (total_size > data.len)
        return -eproto;

    var offset: usize = 4;
    var selected_offset: usize = 0;
    var selected_length: usize = 0;
    var selected_type: u8 = 0;
    var selected_code_set: u8 = 0;
    while (offset < total_size) {
        if (total_size - offset < 4)
            return -eproto;
        const code_set = data[offset] & 0x0f;
        const association = (data[offset + 1] >> 4) & 0x03;
        const designator_type = data[offset + 1] & 0x0f;
        const length: usize = data[offset + 3];
        if (length == 0 or length > total_size - offset - 4)
            return -eproto;
        const designator = data[offset + 4 .. offset + 4 + length];
        if (association == 0 and code_set >= 1 and code_set <= 3 and
            vpdPriority(designator_type) < 4)
        {
            if (length > vpd_id_max)
                return -eoverflow;
            if (selected_length == 0 or vpdLess(
                designator,
                designator_type,
                data[selected_offset .. selected_offset + selected_length],
                selected_type,
            )) {
                selected_offset = offset + 4;
                selected_length = length;
                selected_type = designator_type;
                selected_code_set = code_set;
            }
        }
        offset += 4 + length;
    }
    if (selected_length == 0)
        return -enoent;
    identity.length = @intCast(selected_length);
    identity.code_set = selected_code_set;
    identity.designator_type = selected_type;
    identity.association = 0;
    for (0..selected_length) |index|
        identity.bytes[index] = data[selected_offset + index];
    return 0;
}

fn sectorSizeValid(size: u32) bool {
    return size >= 512 and size <= 4096 and (size & (size - 1)) == 0;
}

export fn storvsc_parse_inquiry(
    data_ptr: [*]const u8,
    data_len: usize,
    inquiry: *Inquiry,
) callconv(.c) c_int {
    zeroObject(inquiry);
    const data = data_ptr[0..data_len];
    if (data.len < 5)
        return -eproto;
    const reported = @as(usize, data[4]) + 5;
    if (reported < 36)
        return -eproto;
    const qualifier = data[0] >> 5;
    const peripheral_type = data[0] & 0x1f;
    if (qualifier != 0)
        return -enodev;
    if (peripheral_type != 0)
        return -enotsup;
    inquiry.peripheral_type = peripheral_type;
    inquiry.removable = @intFromBool((data[1] & 0x80) != 0);
    return 0;
}

export fn storvsc_parse_capacity10(
    data_ptr: [*]const u8,
    data_len: usize,
    capacity: *Capacity,
) callconv(.c) c_int {
    zeroObject(capacity);
    const data = data_ptr[0..data_len];
    if (data.len != 8)
        return -eproto;
    const last_lba = getBe32(data, 0);
    const sector_size = getBe32(data, 4);
    if (!sectorSizeValid(sector_size))
        return -eproto;
    capacity.sector_size = sector_size;
    if (last_lba == std.math.maxInt(u32)) {
        capacity.needs_capacity16 = 1;
        return 0;
    }
    capacity.sectors = @as(u64, last_lba) + 1;
    if (multiplyChecked(capacity.sectors, sector_size) == null)
        return -eoverflow;
    return 0;
}

export fn storvsc_parse_capacity16(
    data_ptr: [*]const u8,
    data_len: usize,
    capacity: *Capacity,
) callconv(.c) c_int {
    zeroObject(capacity);
    const data = data_ptr[0..data_len];
    if (data.len < 12 or data.len > 32)
        return -eproto;
    const last_lba = getBe64(data, 0);
    const sector_size = getBe32(data, 8);
    if (last_lba == std.math.maxInt(u64) or
        !sectorSizeValid(sector_size))
        return -eproto;
    capacity.sectors = last_lba + 1;
    capacity.sector_size = sector_size;
    if (multiplyChecked(capacity.sectors, sector_size) == null)
        return -eoverflow;
    return 0;
}

export fn storvsc_parse_mode_sense6(
    data_ptr: [*]const u8,
    data_len: usize,
    mode: *Mode,
) callconv(.c) c_int {
    zeroObject(mode);
    const data = data_ptr[0..data_len];
    if (data.len < 4)
        return -eproto;
    const reported = @as(usize, data[0]) + 1;
    if (reported < 4)
        return -eproto;
    mode.read_only = @intFromBool((data[2] & 0x80) != 0);
    return 0;
}

export fn storvsc_parse_mode_sense10(
    data_ptr: [*]const u8,
    data_len: usize,
    mode: *Mode,
) callconv(.c) c_int {
    zeroObject(mode);
    const data = data_ptr[0..data_len];
    if (data.len < 8)
        return -eproto;
    const reported = @as(usize, getBe16(data, 0)) + 2;
    if (reported < 8)
        return -eproto;
    mode.read_only = @intFromBool((data[3] & 0x80) != 0);
    return 0;
}

fn completionPacket(
    packet_size: usize,
    status: u32,
    srb_status: u8,
    scsi_status: u8,
    transfer: u32,
) [max_packet_size]u8 {
    var packet = [_]u8{0} ** max_packet_size;
    putLe32(packet[0..], 0, @intFromEnum(Operation.complete_io));
    putLe32(packet[0..], 8, status);
    packet[14] = srb_status;
    packet[15] = scsi_status;
    putLe32(packet[0..], 24, transfer);
    _ = packet_size;
    return packet;
}

fn expectTransmit(event: *const Event, operation: Operation) !void {
    try std.testing.expectEqual(EventKind.transmit, event.kind);
    try std.testing.expectEqual(
        @intFromEnum(operation),
        getLe32(event.tx.packet[0..], 0),
    );
    try std.testing.expect(event.tx.transaction_id != 0);
}

fn initializeReady(
    storage: *align(core_storage_align) anyopaque,
    rejected_versions: usize,
) !void {
    var event: Event = undefined;
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_start(storage, 1, 100, &event),
    );
    try expectTransmit(&event, .begin_initialization);
    var packet = completionPacket(48, 0, 0, 0, 0);
    var id = event.tx.transaction_id;
    _ = storvsc_core_receive(storage, id, &packet, 48, 2, &event);
    try expectTransmit(&event, .query_protocol_version);
    var rejected: usize = 0;
    while (rejected < rejected_versions) : (rejected += 1) {
        id = event.tx.transaction_id;
        packet = completionPacket(48, 1, 0, 0, 0);
        _ = storvsc_core_receive(storage, id, &packet, 48, 3, &event);
        try expectTransmit(&event, .query_protocol_version);
    }
    id = event.tx.transaction_id;
    packet = completionPacket(48, 0, 0, 0, 0);
    _ = storvsc_core_receive(storage, id, &packet, 48, 4, &event);
    try expectTransmit(&event, .query_properties);
    const selected_size = event.tx.packet_len;
    id = event.tx.transaction_id;
    packet = completionPacket(selected_size, 0, 0, 0, 0);
    putLe32(packet[0..], 24, 256 * 1024);
    _ = storvsc_core_receive(
        storage,
        id,
        &packet,
        selected_size,
        5,
        &event,
    );
    try expectTransmit(&event, .end_initialization);
    id = event.tx.transaction_id;
    packet = completionPacket(selected_size, 0, 0, 0, 0);
    _ = storvsc_core_receive(
        storage,
        id,
        &packet,
        selected_size,
        6,
        &event,
    );
    try std.testing.expectEqual(EventKind.initialization_ready, event.kind);
}

fn initializeReadyWithCompletionLengths(
    storage: *align(core_storage_align) anyopaque,
    rejected_versions: usize,
    lengths: [4]usize,
) !void {
    var event: Event = undefined;
    var packet = completionPacket(64, 0, 0, 0, 0);
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_start(storage, 1, 100, &event),
    );
    _ = storvsc_core_receive(
        storage,
        event.tx.transaction_id,
        &packet,
        lengths[0],
        2,
        &event,
    );
    try expectTransmit(&event, .query_protocol_version);
    for (0..rejected_versions) |_| {
        const id = event.tx.transaction_id;
        packet = completionPacket(64, 1, 0, 0, 0);
        _ = storvsc_core_receive(
            storage,
            id,
            &packet,
            lengths[1],
            3,
            &event,
        );
        try expectTransmit(&event, .query_protocol_version);
    }
    packet = completionPacket(64, 0, 0, 0, 0);
    _ = storvsc_core_receive(
        storage,
        event.tx.transaction_id,
        &packet,
        lengths[1],
        4,
        &event,
    );
    try expectTransmit(&event, .query_properties);
    packet = completionPacket(64, 0, 0, 0, 0);
    putLe32(packet[0..], 24, 256 * 1024);
    _ = storvsc_core_receive(
        storage,
        event.tx.transaction_id,
        &packet,
        lengths[2],
        5,
        &event,
    );
    try expectTransmit(&event, .end_initialization);
    packet = completionPacket(64, 0, 0, 0, 0);
    _ = storvsc_core_receive(
        storage,
        event.tx.transaction_id,
        &packet,
        lengths[3],
        6,
        &event,
    );
    try std.testing.expectEqual(EventKind.initialization_ready, event.kind);
}

test "wire layouts and exact C ABI stay stable" {
    try std.testing.expectEqual(@as(usize, 88), @sizeOf(Tx));
    try std.testing.expectEqual(@as(usize, 136), @sizeOf(Event));
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(ScsiSpec));
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(Address));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(Media));
    try std.testing.expectEqual(@as(usize, 68), @sizeOf(VpdId));
    try std.testing.expectEqual(@as(usize, 12), @offsetOf(Media, "read_only"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(VpdId, "bytes"));
    try std.testing.expectEqual(@as(usize, 20), @offsetOf(Tx, "packet"));
    try std.testing.expectEqual(@as(usize, 48), @offsetOf(Event, "tx"));
    try std.testing.expectEqual(@as(usize, 36), @offsetOf(ScsiSpec, "path_id"));
    try std.testing.expectEqual(@as(usize, 37), @offsetOf(ScsiSpec, "target_id"));
    try std.testing.expectEqual(@as(usize, 38), @offsetOf(ScsiSpec, "lun"));
    try std.testing.expectEqual(
        @as(usize, 39),
        @offsetOf(ScsiSpec, "address_reserved"),
    );
    try std.testing.expectEqual(@as(u32, 48), legacy_packet_size);
    try std.testing.expectEqual(@as(u32, 64), modern_packet_size);
}

test "REPORT LUNS construction and SRB addressing are exact" {
    var spec: ScsiSpec = undefined;
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_build_report_luns(
            &spec,
            2,
            3,
            report_luns_max,
            100,
        ),
    );
    try std.testing.expectEqual(
        @as(u32, report_luns_data_size),
        spec.transfer_len,
    );
    try std.testing.expectEqual(
        @as(u32, report_luns_header_size),
        spec.minimum_transfer,
    );
    try std.testing.expectEqual(@as(u8, 0xa0), spec.cdb[0]);
    try std.testing.expectEqual(@as(u8, 12), spec.cdb_len);
    try std.testing.expectEqual(
        @as(u8, @intFromEnum(Direction.read)),
        spec.direction,
    );
    try std.testing.expectEqual(@as(u8, 1), spec.allow_short);
    try std.testing.expectEqual(@as(u8, 2), spec.path_id);
    try std.testing.expectEqual(@as(u8, 3), spec.target_id);
    try std.testing.expectEqual(@as(u8, 0), spec.lun);
    try std.testing.expectEqual(
        @as(u32, report_luns_data_size),
        getBe32(&spec.cdb, 6),
    );
    try std.testing.expectEqual(
        -einval,
        storvsc_build_report_luns(&spec, 0, 0, 0, 100),
    );
    try std.testing.expectEqual(
        -enospc,
        storvsc_build_report_luns(
            &spec,
            0,
            0,
            report_luns_max + 1,
            100,
        ),
    );
    try std.testing.expectEqual(
        -einval,
        storvsc_build_report_luns(&spec, 0, 0, 1, 0),
    );

    var storage: [core_storage_size]u8 align(core_storage_align) = undefined;
    var tx: Tx = undefined;
    _ = storvsc_core_initialize(&storage, 1, 2);
    try initializeReady(&storage, 0);
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_build_report_luns(&spec, 2, 3, 4, 100),
    );
    spec.lun = 7;
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_prepare_scsi(&storage, &spec, 10, &tx),
    );
    try std.testing.expectEqual(@as(u8, 2), tx.packet[17]);
    try std.testing.expectEqual(@as(u8, 3), tx.packet[18]);
    try std.testing.expectEqual(@as(u8, 7), tx.packet[19]);
    try std.testing.expectEqual(@as(u8, 0xa0), tx.packet[28]);
}

test "REPORT LUNS parsing is bounded deterministic and fail closed" {
    var data = [_]u8{0} ** report_luns_data_size;
    var addresses: [report_luns_max]Address = undefined;
    var count: usize = 99;
    putBe32(&data, 0, 3 * report_lun_entry_size);
    data[9] = 7;
    data[16] = 0x40;
    data[25] = 3;
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_parse_report_luns(
            &data,
            data.len,
            4,
            5,
            &addresses,
            addresses.len,
            &count,
        ),
    );
    try std.testing.expectEqual(@as(usize, 3), count);
    for (addresses[0..count], [_]u8{ 0, 3, 7 }) |address, lun| {
        try std.testing.expectEqual(@as(u8, 4), address.path_id);
        try std.testing.expectEqual(@as(u8, 5), address.target_id);
        try std.testing.expectEqual(lun, address.lun);
        try std.testing.expectEqual(@as(u8, 0), address.reserved);
    }

    count = 99;
    try std.testing.expectEqual(
        -eproto,
        storvsc_parse_report_luns(
            &data,
            report_luns_header_size - 1,
            0,
            0,
            &addresses,
            addresses.len,
            &count,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), count);

    data = [_]u8{0} ** report_luns_data_size;
    count = 99;
    try std.testing.expectEqual(
        -enodev,
        storvsc_parse_report_luns(
            &data,
            report_luns_header_size,
            0,
            0,
            &addresses,
            addresses.len,
            &count,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), count);

    data[4] = 1;
    try std.testing.expectEqual(
        -eproto,
        storvsc_parse_report_luns(
            &data,
            report_luns_header_size,
            0,
            0,
            &addresses,
            addresses.len,
            &count,
        ),
    );
    data[4] = 0;
    putBe32(&data, 0, report_lun_entry_size + 1);
    try std.testing.expectEqual(
        -eproto,
        storvsc_parse_report_luns(
            &data,
            report_luns_header_size + report_lun_entry_size + 1,
            0,
            0,
            &addresses,
            addresses.len,
            &count,
        ),
    );

    putBe32(&data, 0, 2 * report_lun_entry_size);
    try std.testing.expectEqual(
        -eproto,
        storvsc_parse_report_luns(
            &data,
            report_luns_header_size + report_lun_entry_size,
            0,
            0,
            &addresses,
            addresses.len,
            &count,
        ),
    );

    putBe32(&data, 0, 3 * report_lun_entry_size);
    try std.testing.expectEqual(
        -enospc,
        storvsc_parse_report_luns(
            &data,
            data.len,
            0,
            0,
            &addresses,
            2,
            &count,
        ),
    );
    putBe32(&data, 0, (report_luns_max + 1) * report_lun_entry_size);
    try std.testing.expectEqual(
        -enospc,
        storvsc_parse_report_luns(
            &data,
            report_luns_header_size,
            0,
            0,
            &addresses,
            addresses.len,
            &count,
        ),
    );

    data = [_]u8{0} ** report_luns_data_size;
    putBe32(&data, 0, report_lun_entry_size);
    data[8] = 0x41;
    try std.testing.expectEqual(
        -eoverflow,
        storvsc_parse_report_luns(
            &data,
            16,
            0,
            0,
            &addresses,
            addresses.len,
            &count,
        ),
    );
    data[8] = 0x80;
    try std.testing.expectEqual(
        -enotsup,
        storvsc_parse_report_luns(
            &data,
            16,
            0,
            0,
            &addresses,
            addresses.len,
            &count,
        ),
    );
    data[8] = 1;
    try std.testing.expectEqual(
        -enotsup,
        storvsc_parse_report_luns(
            &data,
            16,
            0,
            0,
            &addresses,
            addresses.len,
            &count,
        ),
    );
    data[8] = 0;
    data[10] = 1;
    try std.testing.expectEqual(
        -enotsup,
        storvsc_parse_report_luns(
            &data,
            16,
            0,
            0,
            &addresses,
            addresses.len,
            &count,
        ),
    );

    data = [_]u8{0} ** report_luns_data_size;
    putBe32(&data, 0, 2 * report_lun_entry_size);
    data[9] = 9;
    data[16] = 0x40;
    data[17] = 9;
    try std.testing.expectEqual(
        -eexist,
        storvsc_parse_report_luns(
            &data,
            24,
            0,
            0,
            &addresses,
            addresses.len,
            &count,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "all handshake stages and explicit version fallback are wire safe" {
    var storage: [core_storage_size]u8 align(core_storage_align) = undefined;
    for (0..protocol_versions.len) |rejections| {
        try std.testing.expectEqual(
            @as(c_int, 0),
            storvsc_core_initialize(&storage, @intCast(rejections + 1), 4),
        );
        try initializeReady(&storage, rejections);
        try std.testing.expectEqual(
            protocol_versions[rejections],
            storvsc_core_version(&storage),
        );
        const expected_size: u32 =
            if (protocol_versions[rejections] >= makeVersion(5, 1))
                modern_packet_size
            else
                legacy_packet_size;
        try std.testing.expectEqual(
            expected_size,
            storvsc_core_packet_size(&storage),
        );
    }
}

test "48 and 64 byte control completions interoperate across versions" {
    var storage: [core_storage_size]u8 align(core_storage_align) = undefined;
    _ = storvsc_core_initialize(&storage, 1, 4);
    try initializeReadyWithCompletionLengths(
        &storage,
        0,
        .{ 64, 64, 48, 64 },
    );
    try std.testing.expectEqual(
        protocol_versions[0],
        storvsc_core_version(&storage),
    );

    _ = storvsc_core_initialize(&storage, 2, 4);
    try initializeReadyWithCompletionLengths(
        &storage,
        3,
        .{ 64, 48, 64, 48 },
    );
    try std.testing.expectEqual(
        protocol_versions[3],
        storvsc_core_version(&storage),
    );

    _ = storvsc_core_initialize(&storage, 3, 4);
    try initializeReadyWithCompletionLengths(
        &storage,
        2,
        .{ 48, 64, 48, 64 },
    );
    try std.testing.expectEqual(
        protocol_versions[2],
        storvsc_core_version(&storage),
    );

    _ = storvsc_core_initialize(&storage, 4, 4);
    try initializeReadyWithCompletionLengths(
        &storage,
        4,
        .{ 64, 48, 64, 48 },
    );
    try std.testing.expectEqual(
        protocol_versions[4],
        storvsc_core_version(&storage),
    );
}

test "unsupported versions and every malformed handshake stage fail closed" {
    var storage: [core_storage_size]u8 align(core_storage_align) = undefined;
    var event: Event = undefined;
    var packet = completionPacket(48, 0, 0, 0, 0);
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_initialize(&storage, 1, 4),
    );
    _ = storvsc_core_start(&storage, 1, 10, &event);
    _ = storvsc_core_receive(
        &storage,
        event.tx.transaction_id,
        &packet,
        47,
        2,
        &event,
    );
    try std.testing.expectEqual(EventKind.initialization_failed, event.kind);
    try std.testing.expectEqual(-eproto, event.err);

    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_initialize(&storage, 2, 4),
    );
    _ = storvsc_core_start(&storage, 1, 10, &event);
    var id = event.tx.transaction_id;
    _ = storvsc_core_receive(&storage, id, &packet, 48, 2, &event);
    for (0..protocol_versions.len) |_| {
        id = event.tx.transaction_id;
        packet = completionPacket(48, 1, 0, 0, 0);
        _ = storvsc_core_receive(&storage, id, &packet, 48, 3, &event);
    }
    try std.testing.expectEqual(EventKind.initialization_failed, event.kind);
    try std.testing.expectEqual(-enotsup, event.err);
}

test "late duplicate and wrong control completions cannot advance state" {
    var storage: [core_storage_size]u8 align(core_storage_align) = undefined;
    var event: Event = undefined;
    var packet = completionPacket(48, 0, 0, 0, 0);
    _ = storvsc_core_initialize(&storage, 8, 4);
    _ = storvsc_core_start(&storage, 1, 5, &event);
    const begin_id = event.tx.transaction_id;
    _ = storvsc_core_receive(&storage, begin_id + 99, &packet, 48, 2, &event);
    try std.testing.expectEqual(EventKind.ignored, event.kind);
    _ = storvsc_core_receive(&storage, begin_id, &packet, 48, 2, &event);
    try expectTransmit(&event, .query_protocol_version);
    _ = storvsc_core_receive(&storage, begin_id, &packet, 48, 3, &event);
    try std.testing.expectEqual(EventKind.ignored, event.kind);
    _ = storvsc_core_tick(&storage, 100, &event);
    try std.testing.expectEqual(EventKind.initialization_failed, event.kind);
    _ = storvsc_core_receive(
        &storage,
        begin_id + 1,
        &packet,
        48,
        101,
        &event,
    );
    try std.testing.expectEqual(EventKind.ignored, event.kind);
}

test "legacy property fallback is bounded and modern zero is malformed" {
    var storage: [core_storage_size]u8 align(core_storage_align) = undefined;
    var event: Event = undefined;
    var packet = completionPacket(48, 0, 0, 0, 0);
    _ = storvsc_core_initialize(&storage, 1, 4);
    _ = storvsc_core_start(&storage, 1, 100, &event);
    _ = storvsc_core_receive(
        &storage,
        event.tx.transaction_id,
        &packet,
        48,
        2,
        &event,
    );
    for (0..3) |_| {
        const id = event.tx.transaction_id;
        packet = completionPacket(48, 1, 0, 0, 0);
        _ = storvsc_core_receive(&storage, id, &packet, 48, 3, &event);
    }
    packet = completionPacket(48, 0, 0, 0, 0);
    _ = storvsc_core_receive(
        &storage,
        event.tx.transaction_id,
        &packet,
        48,
        4,
        &event,
    );
    try expectTransmit(&event, .query_properties);
    _ = storvsc_core_receive(
        &storage,
        event.tx.transaction_id,
        &packet,
        48,
        5,
        &event,
    );
    try expectTransmit(&event, .end_initialization);
    try std.testing.expectEqual(
        legacy_max_transfer,
        storvsc_core_host_max_transfer(&storage),
    );

    _ = storvsc_core_initialize(&storage, 2, 4);
    _ = storvsc_core_start(&storage, 1, 100, &event);
    packet = completionPacket(48, 0, 0, 0, 0);
    _ = storvsc_core_receive(
        &storage,
        event.tx.transaction_id,
        &packet,
        48,
        2,
        &event,
    );
    _ = storvsc_core_receive(
        &storage,
        event.tx.transaction_id,
        &packet,
        48,
        3,
        &event,
    );
    try expectTransmit(&event, .query_properties);
    packet = completionPacket(64, 0, 0, 0, 0);
    _ = storvsc_core_receive(
        &storage,
        event.tx.transaction_id,
        &packet,
        64,
        4,
        &event,
    );
    try std.testing.expectEqual(EventKind.initialization_failed, event.kind);
    try std.testing.expectEqual(-eproto, event.err);
}

test "pool exhaustion reuse and generation bearing IDs are exact once" {
    var storage: [core_storage_size]u8 align(core_storage_align) = undefined;
    var tx: Tx = undefined;
    var event: Event = undefined;
    _ = storvsc_core_initialize(&storage, 0x1234, 2);
    try initializeReady(&storage, 0);
    var spec = ScsiSpec{
        .transfer_len = 0,
        .minimum_transfer = 0,
        .timeout_ns = 100,
        .cdb = [_]u8{0} ** 16,
        .cdb_len = 6,
        .direction = @intFromEnum(Direction.none),
        .allow_short = 0,
        .reserved = 0,
        .path_id = 0,
        .target_id = 0,
        .lun = 0,
        .address_reserved = 0,
    };
    spec.cdb[0] = 0;
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_prepare_scsi(&storage, &spec, 10, &tx),
    );
    const first_id = tx.transaction_id;
    try std.testing.expectEqual(@as(u32, 0x1234), @as(u32, @truncate(first_id >> 32)));
    var second: Tx = undefined;
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_prepare_scsi(&storage, &spec, 10, &second),
    );
    try std.testing.expectEqual(
        -enospc,
        storvsc_core_prepare_scsi(&storage, &spec, 10, &tx),
    );
    var packet = completionPacket(64, 0, srb_status_success, 0, 0);
    _ = storvsc_core_receive(
        &storage,
        first_id,
        &packet,
        64,
        11,
        &event,
    );
    try std.testing.expectEqual(EventKind.request_complete, event.kind);
    _ = storvsc_core_receive(
        &storage,
        first_id,
        &packet,
        64,
        12,
        &event,
    );
    try std.testing.expectEqual(EventKind.ignored, event.kind);
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_take_completed(&storage, 0, first_id, &event),
    );
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_prepare_scsi(&storage, &spec, 13, &tx),
    );
    try std.testing.expect(tx.transaction_id != first_id);
    _ = storvsc_core_receive(
        &storage,
        first_id,
        &packet,
        64,
        14,
        &event,
    );
    try std.testing.expectEqual(EventKind.ignored, event.kind);
}

test "known malformed oversized and short completions finish deterministically" {
    var storage: [core_storage_size]u8 align(core_storage_align) = undefined;
    var tx: Tx = undefined;
    var event: Event = undefined;
    _ = storvsc_core_initialize(&storage, 1, 4);
    try initializeReady(&storage, 0);
    var spec = ScsiSpec{
        .transfer_len = 8,
        .minimum_transfer = 8,
        .timeout_ns = 100,
        .cdb = [_]u8{0} ** 16,
        .cdb_len = 10,
        .direction = @intFromEnum(Direction.read),
        .allow_short = 0,
        .reserved = 0,
        .path_id = 0,
        .target_id = 0,
        .lun = 0,
        .address_reserved = 0,
    };
    spec.cdb[0] = 0x25;
    _ = storvsc_core_prepare_scsi(&storage, &spec, 10, &tx);
    var packet = completionPacket(64, 0, srb_status_success, 0, 7);
    _ = storvsc_core_receive(
        &storage,
        tx.transaction_id,
        &packet,
        64,
        11,
        &event,
    );
    try std.testing.expectEqual(-eio, event.err);
    _ = storvsc_core_take_completed(
        &storage,
        tx.slot,
        tx.transaction_id,
        &event,
    );

    _ = storvsc_core_prepare_scsi(&storage, &spec, 12, &tx);
    _ = storvsc_core_receive(
        &storage,
        tx.transaction_id,
        &packet,
        63,
        13,
        &event,
    );
    try std.testing.expectEqual(-eproto, event.err);
    _ = storvsc_core_take_completed(
        &storage,
        tx.slot,
        tx.transaction_id,
        &event,
    );

    spec.allow_short = 1;
    spec.minimum_transfer = 4;
    _ = storvsc_core_prepare_scsi(&storage, &spec, 14, &tx);
    packet = completionPacket(64, 0, srb_status_data_overrun, 0, 4);
    _ = storvsc_core_receive(
        &storage,
        tx.transaction_id,
        &packet,
        64,
        15,
        &event,
    );
    try std.testing.expectEqual(@as(c_int, 0), event.err);
}

test "request completions accept sanctioned sizes and reject all others" {
    var storage: [core_storage_size]u8 align(core_storage_align) = undefined;
    var tx: Tx = undefined;
    var event: Event = undefined;
    var spec = ScsiSpec{
        .transfer_len = 0,
        .minimum_transfer = 0,
        .timeout_ns = 100,
        .cdb = [_]u8{0} ** 16,
        .cdb_len = 6,
        .direction = @intFromEnum(Direction.none),
        .allow_short = 0,
        .reserved = 0,
        .path_id = 0,
        .target_id = 0,
        .lun = 0,
        .address_reserved = 0,
    };
    var packet = completionPacket(64, 0, srb_status_success, 0, 0);

    _ = storvsc_core_initialize(&storage, 1, 4);
    try initializeReady(&storage, 0);
    for ([_]usize{ 48, 64 }) |length| {
        _ = storvsc_core_prepare_scsi(&storage, &spec, 10, &tx);
        _ = storvsc_core_receive(
            &storage,
            tx.transaction_id,
            &packet,
            length,
            11,
            &event,
        );
        try std.testing.expectEqual(EventKind.request_complete, event.kind);
        try std.testing.expectEqual(@as(c_int, 0), event.err);
        _ = storvsc_core_take_completed(
            &storage,
            tx.slot,
            tx.transaction_id,
            &event,
        );
    }
    _ = storvsc_core_prepare_scsi(&storage, &spec, 12, &tx);
    _ = storvsc_core_receive(
        &storage,
        tx.transaction_id,
        &packet,
        47,
        13,
        &event,
    );
    try std.testing.expectEqual(-eproto, event.err);
    _ = storvsc_core_take_completed(
        &storage,
        tx.slot,
        tx.transaction_id,
        &event,
    );
    _ = storvsc_core_prepare_scsi(&storage, &spec, 14, &tx);
    var oversized = [_]u8{0} ** 65;
    for (packet, 0..) |byte, index|
        oversized[index] = byte;
    _ = storvsc_core_receive(
        &storage,
        tx.transaction_id,
        &oversized,
        oversized.len,
        15,
        &event,
    );
    try std.testing.expectEqual(-eproto, event.err);

    _ = storvsc_core_initialize(&storage, 2, 4);
    try initializeReady(&storage, 3);
    for ([_]usize{ 64, 48 }) |length| {
        _ = storvsc_core_prepare_scsi(&storage, &spec, 20, &tx);
        packet = completionPacket(64, 0, srb_status_success, 0, 0);
        _ = storvsc_core_receive(
            &storage,
            tx.transaction_id,
            &packet,
            length,
            21,
            &event,
        );
        try std.testing.expectEqual(@as(c_int, 0), event.err);
        _ = storvsc_core_take_completed(
            &storage,
            tx.slot,
            tx.transaction_id,
            &event,
        );
    }
    for ([_]struct { rejected: usize, length: usize }{
        .{ .rejected = 2, .length = 48 },
        .{ .rejected = 4, .length = 64 },
    }, 3..) |scenario, epoch| {
        _ = storvsc_core_initialize(&storage, @intCast(epoch), 4);
        try initializeReady(&storage, scenario.rejected);
        _ = storvsc_core_prepare_scsi(&storage, &spec, 30, &tx);
        packet = completionPacket(64, 0, srb_status_success, 0, 0);
        _ = storvsc_core_receive(
            &storage,
            tx.transaction_id,
            &packet,
            scenario.length,
            31,
            &event,
        );
        try std.testing.expectEqual(@as(c_int, 0), event.err);
        _ = storvsc_core_take_completed(
            &storage,
            tx.slot,
            tx.transaction_id,
            &event,
        );
    }
}

test "timeout reset and cancellation leave every request completable once" {
    var storage: [core_storage_size]u8 align(core_storage_align) = undefined;
    var tx: Tx = undefined;
    var event: Event = undefined;
    _ = storvsc_core_initialize(&storage, 1, 3);
    try initializeReady(&storage, 0);
    var spec = ScsiSpec{
        .transfer_len = 0,
        .minimum_transfer = 0,
        .timeout_ns = 10,
        .cdb = [_]u8{0} ** 16,
        .cdb_len = 6,
        .direction = @intFromEnum(Direction.none),
        .allow_short = 0,
        .reserved = 0,
        .path_id = 0,
        .target_id = 0,
        .lun = 0,
        .address_reserved = 0,
    };
    _ = storvsc_core_prepare_scsi(&storage, &spec, 20, &tx);
    _ = storvsc_core_tick(&storage, 30, &event);
    try std.testing.expectEqual(EventKind.request_timeout, event.kind);
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_begin_reset(&storage, 30, 10, &event),
    );
    try expectTransmit(&event, .reset_bus);
    var packet = completionPacket(64, 0, 0, 0, 0);
    _ = storvsc_core_receive(
        &storage,
        event.tx.transaction_id,
        &packet,
        64,
        31,
        &event,
    );
    try std.testing.expectEqual(EventKind.reset_complete, event.kind);
    try std.testing.expectEqual(
        @as(u32, 1),
        storvsc_core_cancel_all(&storage, -etimedout),
    );
    var slot: u16 = undefined;
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_next_completed(&storage, &slot),
    );
    const id = coreFrom(&storage).contexts[slot].id;
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_take_completed(&storage, slot, id, &event),
    );
    try std.testing.expectEqual(-etimedout, event.err);
    try std.testing.expectEqual(
        -enoent,
        storvsc_core_take_completed(&storage, slot, id, &event),
    );
}

test "sense SRB SCSI and host status mapping is bounded" {
    var storage: [core_storage_size]u8 align(core_storage_align) = undefined;
    var tx: Tx = undefined;
    var event: Event = undefined;
    _ = storvsc_core_initialize(&storage, 1, 4);
    try initializeReady(&storage, 0);
    var spec = ScsiSpec{
        .transfer_len = 0,
        .minimum_transfer = 0,
        .timeout_ns = 100,
        .cdb = [_]u8{0} ** 16,
        .cdb_len = 6,
        .direction = @intFromEnum(Direction.none),
        .allow_short = 0,
        .reserved = 0,
        .path_id = 0,
        .target_id = 0,
        .lun = 0,
        .address_reserved = 0,
    };
    _ = storvsc_core_prepare_scsi(&storage, &spec, 10, &tx);
    var packet = completionPacket(
        64,
        0,
        srb_status_error | srb_status_autosense_valid,
        0x02,
        0,
    );
    packet[21] = 14;
    packet[28] = 0x70;
    packet[30] = 0x07;
    _ = storvsc_core_receive(
        &storage,
        tx.transaction_id,
        &packet,
        64,
        11,
        &event,
    );
    try std.testing.expectEqual(-erofs, event.err);
    try std.testing.expectEqual(@as(u8, 14), event.sense_len);
    _ = storvsc_core_take_completed(
        &storage,
        tx.slot,
        tx.transaction_id,
        &event,
    );

    _ = storvsc_core_prepare_scsi(&storage, &spec, 12, &tx);
    packet = completionPacket(64, 0, srb_status_busy, 0, 0);
    _ = storvsc_core_receive(
        &storage,
        tx.transaction_id,
        &packet,
        64,
        13,
        &event,
    );
    try std.testing.expectEqual(-eagain, event.err);
    _ = storvsc_core_take_completed(
        &storage,
        tx.slot,
        tx.transaction_id,
        &event,
    );

    _ = storvsc_core_prepare_scsi(&storage, &spec, 14, &tx);
    packet = completionPacket(64, 1, srb_status_success, 0, 0);
    _ = storvsc_core_receive(
        &storage,
        tx.transaction_id,
        &packet,
        64,
        15,
        &event,
    );
    try std.testing.expectEqual(-eio, event.err);
}

test "capacity inquiry and mode parsers reject arithmetic and layout edges" {
    var capacity: Capacity = undefined;
    var inquiry: Inquiry = undefined;
    var mode: Mode = undefined;
    var data = [_]u8{0} ** 36;
    data[4] = 31;
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_parse_inquiry(&data, data.len, &inquiry),
    );
    var long_inquiry = [_]u8{0} ** 96;
    long_inquiry[4] = 0xff;
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_parse_inquiry(
            &long_inquiry,
            long_inquiry.len,
            &inquiry,
        ),
    );
    try std.testing.expectEqual(
        -eproto,
        storvsc_parse_inquiry(&data, 4, &inquiry),
    );
    var minimum_inquiry = [_]u8{ 0, 0, 0, 0, 31 };
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_parse_inquiry(
            &minimum_inquiry,
            minimum_inquiry.len,
            &inquiry,
        ),
    );
    data[4] = 30;
    try std.testing.expectEqual(
        -eproto,
        storvsc_parse_inquiry(&data, data.len, &inquiry),
    );
    data[4] = 31;
    data[0] = 5;
    try std.testing.expectEqual(
        -enotsup,
        storvsc_parse_inquiry(&data, data.len, &inquiry),
    );

    var capacity10 = [_]u8{0} ** 8;
    putBe32(&capacity10, 0, 99);
    putBe32(&capacity10, 4, 512);
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_parse_capacity10(&capacity10, 8, &capacity),
    );
    try std.testing.expectEqual(@as(u64, 100), capacity.sectors);
    putBe32(&capacity10, 0, std.math.maxInt(u32));
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_parse_capacity10(&capacity10, 8, &capacity),
    );
    try std.testing.expectEqual(@as(u8, 1), capacity.needs_capacity16);

    var capacity16 = [_]u8{0} ** 32;
    putBe64(&capacity16, 0, 0x1_0000_0000);
    putBe32(&capacity16, 8, 4096);
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_parse_capacity16(&capacity16, 32, &capacity),
    );
    try std.testing.expectEqual(@as(u64, 0x1_0000_0001), capacity.sectors);
    putBe64(&capacity16, 0, std.math.maxInt(u64));
    try std.testing.expectEqual(
        -eproto,
        storvsc_parse_capacity16(&capacity16, 32, &capacity),
    );
    putBe64(&capacity16, 0, (@as(u64, 1) << 56) - 1);
    putBe32(&capacity16, 8, 512);
    try std.testing.expectEqual(
        -eoverflow,
        storvsc_parse_capacity16(&capacity16, 32, &capacity),
    );

    var mode6 = [_]u8{ 3, 0, 0x80, 0 };
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_parse_mode_sense6(&mode6, 4, &mode),
    );
    try std.testing.expectEqual(@as(u8, 1), mode.read_only);
    var mode10 = [_]u8{ 0, 6, 0, 0x80, 0, 0, 0, 0 };
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_parse_mode_sense10(&mode10, 8, &mode),
    );
    try std.testing.expectEqual(@as(u8, 1), mode.read_only);
}

test "per-LUN media controls bounds and access independently" {
    var storage: [core_storage_size]u8 align(core_storage_align) = undefined;
    var tx: Tx = undefined;
    const address: Address = .{
        .path_id = 1,
        .target_id = 2,
        .lun = 3,
        .reserved = 0,
    };
    const small: Media = .{
        .sectors = 1000,
        .sector_size = 512,
        .read_only = 0,
        .reserved = [_]u8{0} ** 3,
    };
    const large: Media = .{
        .sectors = 2000,
        .sector_size = 512,
        .read_only = 0,
        .reserved = [_]u8{0} ** 3,
    };
    const large_read_only: Media = .{
        .sectors = 2000,
        .sector_size = 512,
        .read_only = 1,
        .reserved = [_]u8{0} ** 3,
    };

    _ = storvsc_core_initialize(&storage, 1, 4);
    try initializeReady(&storage, 0);
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_set_transfer_limit(&storage, 128 * 1024),
    );
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_prepare_block_media(
            &storage,
            &address,
            &small,
            0,
            999,
            1,
            0x1000,
            10,
            100,
            &tx,
        ),
    );
    try std.testing.expectEqual(@as(u8, 1), tx.packet[17]);
    try std.testing.expectEqual(@as(u8, 2), tx.packet[18]);
    try std.testing.expectEqual(@as(u8, 3), tx.packet[19]);
    _ = storvsc_core_abort(&storage, tx.slot, tx.transaction_id);
    try std.testing.expectEqual(
        -einval,
        storvsc_core_prepare_block_media(
            &storage,
            &address,
            &small,
            0,
            1000,
            1,
            0x1000,
            10,
            100,
            &tx,
        ),
    );
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_prepare_block_media(
            &storage,
            &address,
            &large,
            0,
            1000,
            1,
            0x1000,
            10,
            100,
            &tx,
        ),
    );
    _ = storvsc_core_abort(&storage, tx.slot, tx.transaction_id);
    try std.testing.expectEqual(
        -erofs,
        storvsc_core_prepare_block_media(
            &storage,
            &address,
            &large_read_only,
            1,
            0,
            1,
            0x1000,
            10,
            100,
            &tx,
        ),
    );
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_prepare_block_media(
            &storage,
            &address,
            &small,
            1,
            0,
            1,
            0x1000,
            10,
            100,
            &tx,
        ),
    );
    _ = storvsc_core_abort(&storage, tx.slot, tx.transaction_id);
    var invalid_media = small;
    invalid_media.reserved[0] = 1;
    try std.testing.expectEqual(
        -einval,
        storvsc_core_prepare_block_media(
            &storage,
            &address,
            &invalid_media,
            0,
            0,
            1,
            0x1000,
            10,
            100,
            &tx,
        ),
    );
}

test "VPD page 83 parsing is deterministic bounded and fail closed" {
    var data = [_]u8{0} ** 128;
    var identity: VpdId = undefined;
    var offset: usize = 4;

    data[1] = 0x83;
    data[offset] = 2;
    data[offset + 1] = 1;
    data[offset + 3] = 3;
    data[offset + 4] = 'T';
    data[offset + 5] = '1';
    data[offset + 6] = '0';
    offset += 7;
    data[offset] = 1;
    data[offset + 1] = 0x13;
    data[offset + 3] = 2;
    data[offset + 4] = 0;
    data[offset + 5] = 0;
    offset += 6;
    data[offset] = 1;
    data[offset + 1] = 2;
    data[offset + 3] = 2;
    data[offset + 4] = 0;
    data[offset + 5] = 1;
    offset += 6;
    data[offset] = 1;
    data[offset + 1] = 3;
    data[offset + 3] = 2;
    data[offset + 4] = 9;
    data[offset + 5] = 9;
    offset += 6;
    data[offset] = 1;
    data[offset + 1] = 3;
    data[offset + 3] = 2;
    data[offset + 4] = 1;
    data[offset + 5] = 2;
    offset += 6;
    putBe16(&data, 2, @intCast(offset - 4));

    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_parse_vpd83(&data, offset, &identity),
    );
    try std.testing.expectEqual(@as(u8, 2), identity.length);
    try std.testing.expectEqual(@as(u8, 1), identity.code_set);
    try std.testing.expectEqual(@as(u8, 3), identity.designator_type);
    try std.testing.expectEqual(@as(u8, 0), identity.association);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 1, 2 },
        identity.bytes[0..identity.length],
    );

    data = [_]u8{0} ** 128;
    data[1] = 0x83;
    putBe16(&data, 2, 5);
    data[4] = 1;
    data[5] = 4;
    data[7] = 1;
    data[8] = 7;
    try std.testing.expectEqual(
        -enoent,
        storvsc_parse_vpd83(&data, 9, &identity),
    );
    data[5] = 0x13;
    try std.testing.expectEqual(
        -enoent,
        storvsc_parse_vpd83(&data, 9, &identity),
    );

    data = [_]u8{0} ** 128;
    data[1] = 0x83;
    putBe16(&data, 2, 4);
    data[4] = 1;
    data[5] = 3;
    data[7] = 8;
    try std.testing.expectEqual(
        -eproto,
        storvsc_parse_vpd83(&data, 8, &identity),
    );
    putBe16(&data, 2, 8);
    try std.testing.expectEqual(
        -eproto,
        storvsc_parse_vpd83(&data, 8, &identity),
    );

    data = [_]u8{0} ** 128;
    data[1] = 0x83;
    putBe16(&data, 2, 69);
    data[4] = 1;
    data[5] = 3;
    data[7] = vpd_id_max + 1;
    try std.testing.expectEqual(
        -eoverflow,
        storvsc_parse_vpd83(&data, 73, &identity),
    );
    try std.testing.expectEqual(
        -eproto,
        storvsc_parse_vpd83(&data, 3, &identity),
    );
    data[0] = 0x20;
    try std.testing.expectEqual(
        -eproto,
        storvsc_parse_vpd83(&data, 73, &identity),
    );
}

test "block boundaries CDB selection read only and flush validation" {
    var storage: [core_storage_size]u8 align(core_storage_align) = undefined;
    var tx: Tx = undefined;
    _ = storvsc_core_initialize(&storage, 1, 8);
    try initializeReady(&storage, 0);
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_set_transfer_limit(&storage, 128 * 1024),
    );
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_set_media(&storage, 0x1_0000_0100, 512, 0),
    );
    const address: Address = .{
        .path_id = 4,
        .target_id = 5,
        .lun = 6,
        .reserved = 0,
    };
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_prepare_block_at(
            &storage,
            &address,
            0,
            0,
            1,
            0x1000,
            10,
            100,
            &tx,
        ),
    );
    try std.testing.expectEqual(@as(u8, 4), tx.packet[17]);
    try std.testing.expectEqual(@as(u8, 5), tx.packet[18]);
    try std.testing.expectEqual(@as(u8, 6), tx.packet[19]);
    _ = storvsc_core_abort(&storage, tx.slot, tx.transaction_id);
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_prepare_block(
            &storage,
            0,
            0,
            1,
            0x1000,
            10,
            100,
            &tx,
        ),
    );
    try std.testing.expectEqual(@as(u8, 0), tx.packet[17]);
    try std.testing.expectEqual(@as(u8, 0), tx.packet[18]);
    try std.testing.expectEqual(@as(u8, 0), tx.packet[19]);
    try std.testing.expectEqual(@as(u8, 0x28), tx.packet[28]);
    _ = storvsc_core_abort(&storage, tx.slot, tx.transaction_id);
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_prepare_block(
            &storage,
            1,
            0x1_0000_0000,
            1,
            0x2000,
            10,
            100,
            &tx,
        ),
    );
    try std.testing.expectEqual(@as(u8, 0x8a), tx.packet[28]);
    _ = storvsc_core_abort(&storage, tx.slot, tx.transaction_id);
    try std.testing.expectEqual(
        -einval,
        storvsc_core_prepare_block(
            &storage,
            0,
            0x1_0000_00ff,
            2,
            0x2000,
            10,
            100,
            &tx,
        ),
    );
    try std.testing.expectEqual(
        -eoverflow,
        storvsc_core_prepare_block(
            &storage,
            0,
            std.math.maxInt(u64),
            2,
            0x2000,
            10,
            100,
            &tx,
        ),
    );
    try std.testing.expectEqual(
        -einval,
        storvsc_core_prepare_block(
            &storage,
            0,
            0,
            1,
            0x2001,
            10,
            100,
            &tx,
        ),
    );
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_prepare_block(
            &storage,
            4,
            0,
            0,
            0,
            10,
            100,
            &tx,
        ),
    );
    try std.testing.expectEqual(@as(u8, 0x35), tx.packet[28]);
    _ = storvsc_core_abort(&storage, tx.slot, tx.transaction_id);
    try std.testing.expectEqual(
        @as(c_int, 0),
        storvsc_core_set_media(&storage, 1024, 512, 1),
    );
    try std.testing.expectEqual(
        -erofs,
        storvsc_core_prepare_block(
            &storage,
            1,
            0,
            1,
            0x2000,
            10,
            100,
            &tx,
        ),
    );
}

test "unsolicited remove enumerate and oversized packets are separated" {
    var storage: [core_storage_size]u8 align(core_storage_align) = undefined;
    var event: Event = undefined;
    _ = storvsc_core_initialize(&storage, 1, 2);
    var packet = [_]u8{0} ** 65;
    putLe32(packet[0..], 0, @intFromEnum(Operation.remove_device));
    _ = storvsc_core_receive(&storage, 0, &packet, 4, 0, &event);
    try std.testing.expectEqual(EventKind.remove_device, event.kind);
    putLe32(packet[0..], 0, @intFromEnum(Operation.enumerate_bus));
    _ = storvsc_core_receive(&storage, 0, &packet, 4, 0, &event);
    try std.testing.expectEqual(EventKind.enumerate_bus, event.kind);
    _ = storvsc_core_receive(&storage, 0, &packet, 65, 0, &event);
    try std.testing.expectEqual(EventKind.protocol_error, event.kind);
}
