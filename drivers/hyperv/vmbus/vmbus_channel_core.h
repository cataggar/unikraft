/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_CHANNEL_CORE_H__
#define __VMBUS_CHANNEL_CORE_H__

#include <stddef.h>
#include <uk/arch/types.h>

struct vmbus_packet_meta_abi {
	__u16 packet_type;
	__u16 flags;
	__u64 transaction_id;
	__u32 descriptor_size;
	__u32 payload_size;
	__u32 total_size;
	__u8 need_signal;
	__u8 trailer_mismatch;
};

typedef __u64 (*vmbus_channel_hypercall_fn)(void *, __u64);

struct vmbus_signal_input_abi {
	__u32 connection_id;
	__u16 event_flag;
	__u16 reserved;
};

int vmbus_ring_initialize(__u8 *base, size_t total_size);
int vmbus_ring_write(__u8 *base, size_t total_size, __u16 packet_type,
		     __u16 flags, __u64 transaction_id,
		     const __u8 *descriptor, size_t descriptor_size,
		     const __u8 *payload, size_t payload_size,
		     __u8 *need_signal);
int vmbus_ring_read(__u8 *base, size_t total_size,
		    struct vmbus_packet_meta_abi *meta,
		    __u8 *descriptor, size_t descriptor_capacity,
		    __u8 *payload, size_t payload_capacity);
int vmbus_ring_set_interrupt_mask(__u8 *base, size_t total_size,
				  __u8 masked);
__u32 vmbus_ring_readable(__u8 *base, size_t total_size);
int vmbus_gpadl_header(__u8 *output, size_t capacity, __u32 channel_id,
		       __u32 gpadl_id, __u32 byte_count,
		       const __u64 *pfns, size_t pfn_count, size_t *consumed);
int vmbus_gpadl_body(__u8 *output, size_t capacity, __u32 message_number,
		     __u32 gpadl_id, const __u64 *pfns, size_t pfn_count,
		     size_t *consumed);
int vmbus_open_message(__u8 *output, size_t capacity, __u32 channel_id,
		       __u32 open_id, __u32 gpadl_id, __u32 target_vp,
		       __u32 tx_pages, const __u8 *user_data,
		       size_t user_data_size);
int vmbus_close_message(__u8 *output, size_t capacity, __u32 channel_id);
int vmbus_gpadl_teardown_message(__u8 *output, size_t capacity,
				 __u32 channel_id, __u32 gpadl_id);
int vmbus_signal_event(struct vmbus_signal_input_abi *input,
		       __u32 connection_id, __u16 event_flag,
		       __u64 input_gpa, vmbus_channel_hypercall_fn hypercall,
		       void *arg);

_Static_assert(sizeof(struct vmbus_packet_meta_abi) == 32,
	       "VMBus packet metadata ABI mismatch");
_Static_assert(sizeof(struct vmbus_signal_input_abi) == 8,
	       "VMBus SignalEvent ABI mismatch");

#endif /* __VMBUS_CHANNEL_CORE_H__ */
