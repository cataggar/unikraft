/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_LEGACY_EVENTS_H__
#define __VMBUS_LEGACY_EVENTS_H__

#include <uk/arch/types.h>

typedef void (*vmbus_legacy_event_fn)(__u32 relid, void *arg);

static inline unsigned int
vmbus_legacy_event_scan(__u64 *words, unsigned int word_count,
			unsigned int relid_limit,
			vmbus_legacy_event_fn emit, void *arg)
{
	unsigned int emitted = 0;
	unsigned int word;

	for (word = 0; word < word_count; word++) {
		__u64 pending = __atomic_exchange_n(&words[word], 0,
						    __ATOMIC_ACQ_REL);

		while (pending) {
			unsigned int bit = __builtin_ctzll(pending);
			__u32 relid = word * 64U + bit;

			if (relid && relid < relid_limit) {
				emit(relid, arg);
				emitted++;
			}
			pending &= pending - 1;
		}
	}
	return emitted;
}

#endif /* __VMBUS_LEGACY_EVENTS_H__ */
