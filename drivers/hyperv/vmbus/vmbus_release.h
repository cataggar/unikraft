/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_RELEASE_H__
#define __VMBUS_RELEASE_H__

#include <errno.h>
#include <uk/arch/types.h>

/*
 * Claims a RELID for exactly-once release. The claim is recorded before the
 * caller posts the release, so a failed post cannot cause duplicate releases.
 */
static inline int vmbus_release_claim(__u32 *released, unsigned int *count,
				      unsigned int capacity, __u32 channel_id)
{
	unsigned int i;

	if (!channel_id)
		return -EINVAL;
	for (i = 0; i < *count; i++)
		if (released[i] == channel_id)
			return 1;
	if (*count >= capacity)
		return -ENOSPC;
	released[(*count)++] = channel_id;
	return 0;
}

#endif /* __VMBUS_RELEASE_H__ */
