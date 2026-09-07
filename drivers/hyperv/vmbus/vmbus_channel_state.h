/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_CHANNEL_STATE_H__
#define __VMBUS_CHANNEL_STATE_H__

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <uk/arch/types.h>

enum vmbus_transaction_type {
	VMBUS_TRANSACTION_GPADL_CREATE,
	VMBUS_TRANSACTION_OPEN,
	VMBUS_TRANSACTION_GPADL_TEARDOWN,
};

enum vmbus_channel_state {
	CHANNEL_FREE,
	CHANNEL_ALLOCATED,
	CHANNEL_GPADL,
	CHANNEL_OPENING,
	CHANNEL_OPEN,
	CHANNEL_CLOSING,
	CHANNEL_RESCINDED,
};

struct vmbus_rescind_plan {
	__u8 send_close;
	__u8 send_gpadl_teardown;
};

static inline struct vmbus_rescind_plan
vmbus_channel_rescind_plan(__u8 state, int has_gpadl)
{
	struct vmbus_rescind_plan plan = { 0 };

	plan.send_close = state == CHANNEL_OPENING || state == CHANNEL_OPEN;
	plan.send_gpadl_teardown = !!has_gpadl;
	return plan;
}

static inline int vmbus_channel_state_gpadl_created(__u8 *state)
{
	if (*state != CHANNEL_ALLOCATED)
		return -EPROTO;
	*state = CHANNEL_GPADL;
	return 0;
}

static inline int vmbus_channel_state_open_begin(__u8 *state)
{
	if (*state != CHANNEL_GPADL)
		return -EPROTO;
	*state = CHANNEL_OPENING;
	return 0;
}

static inline int vmbus_channel_state_open_complete(__u8 *state, int status)
{
	if (*state != CHANNEL_OPENING)
		return -EPROTO;
	*state = status ? CHANNEL_GPADL : CHANNEL_OPEN;
	return status ? -EIO : 0;
}

static inline int vmbus_channel_state_close_begin(__u8 *state)
{
	if (*state == CHANNEL_GPADL)
		return 0;
	if (*state != CHANNEL_OPEN && *state != CHANNEL_OPENING)
		return -EPROTO;
	*state = CHANNEL_CLOSING;
	return 0;
}

static inline void vmbus_channel_state_rescind(__u8 *state)
{
	*state = CHANNEL_RESCINDED;
}

struct vmbus_channel_transaction {
	__u32 channel_id;
	__u32 id;
	__u32 status;
	__u8 type;
	__u8 used;
	__u8 done;
};

static inline struct vmbus_channel_transaction *
vmbus_transaction_allocate(struct vmbus_channel_transaction *transactions,
			   unsigned int capacity, unsigned int type,
			   __u32 channel_id, __u32 id)
{
	unsigned int i;

	for (i = 0; i < capacity; i++) {
		if (transactions[i].used)
			continue;
		transactions[i].used = 1;
		transactions[i].done = 0;
		transactions[i].type = type;
		transactions[i].channel_id = channel_id;
		transactions[i].id = id;
		transactions[i].status = 0;
		return &transactions[i];
	}
	return NULL;
}

static inline void
vmbus_transaction_release(struct vmbus_channel_transaction *transaction)
{
	transaction->used = 0;
	transaction->done = 0;
}

static inline int
vmbus_transaction_complete(struct vmbus_channel_transaction *transactions,
			   unsigned int capacity, unsigned int type,
			   __u32 channel_id, __u32 id, __u32 status)
{
	struct vmbus_channel_transaction *match = NULL;
	unsigned int i;

	for (i = 0; i < capacity; i++) {
		if (!transactions[i].used || transactions[i].type != type ||
		    transactions[i].id != id)
			continue;
		if (channel_id && transactions[i].channel_id != channel_id)
			continue;
		if (match)
			return -EPROTO;
		match = &transactions[i];
	}
	if (!match)
		return -ENOENT;
	if (match->done)
		return -EALREADY;
	match->status = status;
	__atomic_store_n(&match->done, 1, __ATOMIC_RELEASE);
	return 0;
}

static inline int vmbus_transaction_timed_out(__u64 now, __u64 deadline)
{
	return now > deadline;
}

static inline unsigned int
vmbus_transaction_cancel_channel(
	struct vmbus_channel_transaction *transactions,
	unsigned int capacity, __u32 channel_id, __u32 status)
{
	unsigned int cancelled = 0;
	unsigned int i;

	for (i = 0; i < capacity; i++) {
		if (!transactions[i].used ||
		    transactions[i].channel_id != channel_id)
			continue;
		transactions[i].status = status;
		__atomic_store_n(&transactions[i].done, 1, __ATOMIC_RELEASE);
		cancelled++;
	}
	return cancelled;
}

/* IDs are never reused, including across reconnect epochs. */
static inline int vmbus_monotonic_id_allocate(__u32 *next, __u32 *id)
{
	if (!*next)
		return -ENOSPC;
	*id = *next;
	*next = *next == UINT32_MAX ? 0 : *next + 1;
	return 0;
}

static inline int
vmbus_transaction_completion_policy(int result, __u32 *ignored)
{
	if (result == -ENOENT || result == -EALREADY) {
		__atomic_add_fetch(ignored, 1, __ATOMIC_RELAXED);
		return 0;
	}
	return result;
}

#endif /* __VMBUS_CHANNEL_STATE_H__ */
