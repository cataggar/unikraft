/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_RELEASE_H__
#define __VMBUS_RELEASE_H__

#include <errno.h>
#include <stddef.h>
#include <uk/arch/types.h>

enum vmbus_relid_state {
	VMBUS_RELID_FREE = 0,
	VMBUS_RELID_ACTIVE = 1,
	VMBUS_RELID_PENDING = 2,
	VMBUS_RELID_RELEASED = 3,
};

struct vmbus_relid_lifecycle {
	__u32 channel_id;
	__u8 state;
	__u8 retained;
	__u64 sequence;
};

static inline struct vmbus_relid_lifecycle *
vmbus_relid_find(struct vmbus_relid_lifecycle *entries,
		 unsigned int capacity, __u32 channel_id)
{
	unsigned int i;

	for (i = 0; i < capacity; i++)
		if (entries[i].state != VMBUS_RELID_FREE &&
		    entries[i].channel_id == channel_id)
			return &entries[i];
	return NULL;
}

/*
 * Starts an offer lifecycle. An active/pending entry is a duplicate offer;
 * an already released entry is recycled for a legitimate re-offer.
 */
static inline int
vmbus_relid_offer(struct vmbus_relid_lifecycle *entries,
		  unsigned int capacity, __u32 channel_id, int retained,
		  __u64 *sequence)
{
	struct vmbus_relid_lifecycle *entry;
	struct vmbus_relid_lifecycle *oldest_released = NULL;
	unsigned int i;

	if (!channel_id)
		return -EINVAL;
	if (*sequence == UINT64_MAX)
		return -ENOSPC;
	entry = vmbus_relid_find(entries, capacity, channel_id);
	if (entry) {
		if (entry->state != VMBUS_RELID_RELEASED)
			return 1;
		if (!retained)
			return 1;
		entry->state = VMBUS_RELID_ACTIVE;
		entry->retained = !!retained;
		entry->sequence = ++*sequence;
		return 0;
	}
	for (i = 0; i < capacity; i++) {
		if (entries[i].state == VMBUS_RELID_FREE) {
			entry = &entries[i];
			break;
		}
		if (entries[i].state == VMBUS_RELID_RELEASED &&
		    (!oldest_released ||
		     entries[i].sequence < oldest_released->sequence))
			oldest_released = &entries[i];
	}
	if (!entry)
		entry = oldest_released;
	if (!entry)
		return -ENOSPC;
	entry->channel_id = channel_id;
	entry->state = VMBUS_RELID_ACTIVE;
	entry->retained = !!retained;
	entry->sequence = ++*sequence;
	return 0;
}

/*
 * Returns 0 when a release should be posted, 1 when it was already posted,
 * or -ENOENT when no offer lifecycle exists. Pending releases are retryable.
 */
static inline int
vmbus_relid_release_begin(struct vmbus_relid_lifecycle *entries,
			  unsigned int capacity, __u32 channel_id)
{
	struct vmbus_relid_lifecycle *entry =
		vmbus_relid_find(entries, capacity, channel_id);

	if (!entry)
		return -ENOENT;
	if (entry->state == VMBUS_RELID_RELEASED)
		return 1;
	entry->state = VMBUS_RELID_PENDING;
	return 0;
}

static inline void
vmbus_relid_release_finish(struct vmbus_relid_lifecycle *entries,
			   unsigned int capacity, __u32 channel_id,
			   int success, int retain_claim)
{
	struct vmbus_relid_lifecycle *entry =
		vmbus_relid_find(entries, capacity, channel_id);

	if (!entry)
		return;
	if (!success) {
		entry->state = VMBUS_RELID_PENDING;
		return;
	}
	if (retain_claim) {
		entry->state = VMBUS_RELID_RELEASED;
		entry->retained = 0;
	} else {
		entry->channel_id = 0;
		entry->state = VMBUS_RELID_FREE;
		entry->retained = 0;
	}
}

static inline void
vmbus_relid_forget(struct vmbus_relid_lifecycle *entries,
		   unsigned int capacity, __u32 channel_id)
{
	vmbus_relid_release_finish(entries, capacity, channel_id, 1, 0);
}

#endif /* __VMBUS_RELEASE_H__ */
