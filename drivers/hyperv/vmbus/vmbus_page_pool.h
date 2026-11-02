/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_PAGE_POOL_H__
#define __VMBUS_PAGE_POOL_H__

#include <errno.h>

static inline int
vmbus_page_pool_allocate(unsigned char *used, unsigned int capacity,
			 unsigned int count, unsigned int *start)
{
	unsigned int begin;
	unsigned int i;

	if (!count || count > capacity)
		return -ENOSPC;
	for (begin = 0; begin + count <= capacity; begin++) {
		for (i = 0; i < count && !used[begin + i]; i++)
			;
		if (i != count) {
			begin += i;
			continue;
		}
		for (i = 0; i < count; i++)
			used[begin + i] = 1;
		*start = begin;
		return 0;
	}
	return -ENOSPC;
}

static inline void
vmbus_page_pool_free(unsigned char *used, unsigned int capacity,
		     unsigned int start, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count && start + i < capacity; i++)
		used[start + i] = 0;
}

#endif /* __VMBUS_PAGE_POOL_H__ */
