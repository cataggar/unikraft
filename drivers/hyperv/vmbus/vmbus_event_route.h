/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_EVENT_ROUTE_H__
#define __VMBUS_EVENT_ROUTE_H__

#include <errno.h>
#include "vmbus_legacy_events.h"

#define VMBUS_EVENT_VERSION_WIN8	((2U << 16) | 4U)

static inline int
vmbus_event_route(__u32 version, __u32 event, __u64 *legacy_words,
		  unsigned int legacy_word_count, unsigned int relid_limit,
		  vmbus_legacy_event_fn emit, void *arg)
{
	if (version < VMBUS_EVENT_VERSION_WIN8) {
		if (event != 0)
			return -EINVAL;
		return (int)vmbus_legacy_event_scan(legacy_words,
				legacy_word_count, relid_limit, emit, arg);
	}
	/* Modern SIEFP bit 0 announces protocol-message work, not a channel. */
	if (!event)
		return 0;
	if (event >= relid_limit)
		return -ERANGE;
	emit(event, arg);
	return 1;
}

#endif /* __VMBUS_EVENT_ROUTE_H__ */
