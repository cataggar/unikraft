/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_CHANNEL_OWNER_H__
#define __VMBUS_CHANNEL_OWNER_H__

#include <errno.h>
#include <stdint.h>
#include <uk/arch/types.h>

struct vmbus_channel_owner {
	__u64 generation;
	__u16 operations;
	__u8 revoked;
	__u8 cleanup_pending;
};

struct vmbus_channel_token {
	struct vmbus_channel_owner *owner;
	__u64 generation;
};

static inline int
vmbus_channel_owner_begin(struct vmbus_channel_owner *owner,
			  struct vmbus_channel_token *token)
{
	if (!owner->generation || owner->revoked ||
	    owner->operations == UINT16_MAX)
		return -ECANCELED;
	owner->operations++;
	token->owner = owner;
	token->generation = owner->generation;
	return 0;
}

static inline int
vmbus_channel_owner_valid(const struct vmbus_channel_token *token)
{
	return token->owner && token->owner->generation == token->generation &&
	       !token->owner->revoked;
}

/* Returns non-zero when cleanup can run immediately. */
static inline int vmbus_channel_owner_revoke(struct vmbus_channel_owner *owner)
{
	owner->revoked = 1;
	owner->cleanup_pending = 1;
	return owner->operations == 0;
}

/* Returns non-zero when the final owning operation must perform cleanup. */
static inline int
vmbus_channel_owner_end(struct vmbus_channel_token *token)
{
	struct vmbus_channel_owner *owner = token->owner;

	if (!owner || owner->generation != token->generation ||
	    !owner->operations)
		return 0;
	owner->operations--;
	token->owner = NULL;
	return owner->operations == 0 && owner->cleanup_pending;
}

static inline int
vmbus_channel_owner_reusable(const struct vmbus_channel_owner *owner)
{
	return owner->operations == 0 && !owner->cleanup_pending;
}

#endif /* __VMBUS_CHANNEL_OWNER_H__ */
