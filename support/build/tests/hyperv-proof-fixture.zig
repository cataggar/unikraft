// SPDX-License-Identifier: BSD-3-Clause
const protocol = @import("vmbus_protocol");

pub export const storvsc_device_ids: [2]protocol.Guid = .{ protocol.storage_guid, .{ .bytes = @splat(0) } };
pub export const netvsc_device_ids: [2]protocol.Guid = .{ protocol.network_guid, .{ .bytes = @splat(0) } };

extern fn vmbus_protocol_state() callconv(.c) c_int;
extern fn vmbus_protocol_generation() callconv(.c) u32;
extern fn vmbus_protocol_version() callconv(.c) u32;
var observed: u32 = 0;
fn retain(value: u32) void {
    const destination: *volatile u32 = &observed;
    destination.* = value;
}
pub export fn hyperv_synic_message_take_page() callconv(.c) void {
    retain(@intCast(@call(.never_inline, vmbus_protocol_state, .{})));
}
pub export fn hyperv_synic_event_take_word_page() callconv(.c) void {
    retain(@call(.never_inline, vmbus_protocol_generation, .{}));
}
pub export fn hyperv_vmbus_message() callconv(.c) void {
    retain(@call(.never_inline, vmbus_protocol_version, .{}));
}
pub export fn hyperv_vmbus_event_word() callconv(.c) void {
    retain(@intCast(@call(.never_inline, vmbus_protocol_state, .{})));
}
pub export fn hyperv_vmbus_event() callconv(.c) void {
    @call(.never_inline, hyperv_vmbus_event_word, .{});
}
pub export fn hyperv_vmbus_fini() callconv(.c) void {
    retain(@call(.never_inline, vmbus_protocol_generation, .{}));
}
pub export fn hyperv_vmbus_shutdown() callconv(.c) void {
    @call(.never_inline, hyperv_vmbus_fini, .{});
}
