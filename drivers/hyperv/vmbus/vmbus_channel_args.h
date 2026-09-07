/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_CHANNEL_ARGS_H__
#define __VMBUS_CHANNEL_ARGS_H__

#include <errno.h>
#include <stddef.h>

static inline int
vmbus_channel_validate_open_data(const void *data, size_t size,
				 size_t maximum)
{
	if ((!data && size) || size > maximum)
		return -EINVAL;
	return 0;
}

#endif /* __VMBUS_CHANNEL_ARGS_H__ */
