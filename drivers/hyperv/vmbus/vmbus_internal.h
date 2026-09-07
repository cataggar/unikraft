/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_INTERNAL_H__
#define __VMBUS_INTERNAL_H__

#include <stddef.h>
#include <uk/arch/types.h>

struct vmbus_device;

int vmbus_control_transmit(const __u8 *message, size_t length);
int vmbus_control_pump(void);
int vmbus_control_enter(int *acquired);
void vmbus_control_exit(int acquired);
__u64 vmbus_control_relid_sequence(__u32 channel_id);
int vmbus_control_release_relid(__u32 channel_id, __u64 sequence);
void vmbus_control_fail(void);
int vmbus_control_set_event(__u32 channel_id);
__u64 vmbus_control_channel_capacity_epoch(struct vmbus_device *device);
void vmbus_control_note_channel_capacity(struct vmbus_device *device,
					 __u64 epoch);
void vmbus_control_channel_resource_released(void);
int vmbus_channel_control_receive(const __u8 *message, size_t length);
__u32 vmbus_channel_take_ignored_responses(void);
void vmbus_channel_event(__u32 event);
int vmbus_channel_rescind(__u32 channel_id);
void vmbus_channel_close_all(void);
void vmbus_channel_reset_all(void);

#endif /* __VMBUS_INTERNAL_H__ */
