/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __UK_SCHED_FIXED_H__
#define __UK_SCHED_FIXED_H__

#include <errno.h>

typedef int (*uk_sched_kick_once_t)(void *arg);

static inline int
uk_sched_kick_bounded(uk_sched_kick_once_t kick_once, void *arg,
		      unsigned int attempts)
{
	int rc = -EINVAL;

	while (attempts--) {
		rc = kick_once(arg);
		if (!rc)
			break;
	}
	return rc;
}

#endif /* __UK_SCHED_FIXED_H__ */
