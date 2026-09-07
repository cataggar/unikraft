/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_PROTOCOL_H__
#define __VMBUS_PROTOCOL_H__

#include <stddef.h>
#include <uk/arch/types.h>

#define VMBUS_ACTION_TX_SIZE	64U
#define VMBUS_HV_MESSAGE_TYPE	1U

enum vmbus_protocol_state {
	VMBUS_STATE_IDLE = 0,
	VMBUS_STATE_WAIT_VERSION = 1,
	VMBUS_STATE_WAIT_OFFERS = 2,
	VMBUS_STATE_READY = 3,
	VMBUS_STATE_UNLOADING = 4,
	VMBUS_STATE_DISCONNECTED = 5,
	VMBUS_STATE_FAILED = 6,
};

enum vmbus_action_kind {
	VMBUS_ACTION_NONE = 0,
	VMBUS_ACTION_TRANSMIT = 1,
	VMBUS_ACTION_OFFER = 2,
	VMBUS_ACTION_RESCIND = 3,
	VMBUS_ACTION_OFFERS_COMPLETE = 4,
	VMBUS_ACTION_CLEANUP = 5,
	VMBUS_ACTION_FAILED = 6,
	VMBUS_ACTION_STALE = 7,
	VMBUS_ACTION_MALFORMED = 8,
	VMBUS_ACTION_REJECT_OFFER = 9,
};

struct vmbus_decoded_offer {
	__u8 class_id[16];
	__u8 instance_id[16];
	__u32 channel_id;
	__u32 connection_id;
	__u16 flags;
	__u16 mmio_megabytes;
	__u16 mmio_megabytes_optional;
	__u16 subchannel_index;
	__u8 monitor_id;
	__u8 monitor_allocated;
	__u16 dedicated;
	__u8 user_data[120];
};

struct vmbus_action {
	int kind;
	int error;
	__u32 generation;
	__u32 tx_len;
	__u8 tx[VMBUS_ACTION_TX_SIZE];
	struct vmbus_decoded_offer offer;
	__u32 channel_id;
	__u32 connection_id;
};

struct vmbus_start_config {
	__u32 target_vp;
	__u32 reserved;
	__u64 timeout_ticks;
	__u64 interrupt_page_gpa;
	__u64 parent_to_child_monitor_gpa;
	__u64 child_to_parent_monitor_gpa;
};

typedef __u64 (*vmbus_hypercall_fn)(void *arg, __u64 input_gpa);
typedef void (*vmbus_backoff_fn)(void *arg, __u32 usec);

void *vmbus_post_input(void);
int vmbus_post_message(__u32 connection_id, __u32 message_type,
		       const __u8 *payload,
		       size_t payload_len, __u64 input_gpa,
		       __u8 has_post_messages, __u32 retry_limit,
		       vmbus_hypercall_fn hypercall,
		       vmbus_backoff_fn backoff, void *arg);
void vmbus_protocol_start(__u64 now,
			  const struct vmbus_start_config *config,
			  struct vmbus_action *action);
void vmbus_protocol_receive(const __u8 *payload, size_t payload_len,
			    __u32 generation, __u64 now,
			    struct vmbus_action *action);
void vmbus_protocol_tick(__u64 now, struct vmbus_action *action);
void vmbus_protocol_unload(__u64 now, struct vmbus_action *action);
void vmbus_protocol_release(__u32 channel_id,
			    struct vmbus_action *action);
void vmbus_protocol_reset(void);
int vmbus_protocol_state(void);
__u32 vmbus_protocol_generation(void);
__u32 vmbus_protocol_version(void);
__u32 vmbus_protocol_connection_id(void);

_Static_assert(sizeof(struct vmbus_decoded_offer) == 172,
	       "decoded offer ABI mismatch");
_Static_assert(offsetof(struct vmbus_decoded_offer, user_data) == 52,
	       "decoded offer user-data offset mismatch");
_Static_assert(sizeof(struct vmbus_action) == 260,
	       "protocol action ABI mismatch");
_Static_assert(sizeof(struct vmbus_start_config) == 40,
	       "protocol start configuration ABI mismatch");

#endif /* __VMBUS_PROTOCOL_H__ */
