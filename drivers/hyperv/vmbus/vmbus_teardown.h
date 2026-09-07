/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_TEARDOWN_H__
#define __VMBUS_TEARDOWN_H__

#include <errno.h>

struct vmbus_teardown_ops {
	void (*deactivate_rx)(void *arg);
	void (*signal_stop)(void *arg, int can_schedule);
	int (*try_acquire_control)(void *arg);
	int (*control_owned_by_caller)(void *arg);
	int (*worker_present)(void *arg);
	int (*caller_is_worker)(void *arg);
	void (*wait_once)(void *arg);
};

/* Ordinary errno-returning teardown: failed entry has no side effects. */
static inline int
vmbus_teardown_enter(const struct vmbus_teardown_ops *ops, void *arg,
		     int can_schedule, unsigned int wait_limit,
		     int *control_acquired)
{
	unsigned int attempt;

	*control_acquired = 0;
	if (ops->control_owned_by_caller(arg))
		return -EDEADLK;
	if (!can_schedule)
		return -EWOULDBLOCK;

	for (attempt = 0; ; attempt++) {
		if (!ops->try_acquire_control(arg)) {
			*control_acquired = 1;
			break;
		}
		if (attempt >= wait_limit)
			return -EBUSY;
		ops->wait_once(arg);
	}

	ops->deactivate_rx(arg);
	ops->signal_stop(arg, 1);
	if (!ops->worker_present(arg) || ops->caller_is_worker(arg))
		return 0;
	for (attempt = 0; ops->worker_present(arg); attempt++) {
		if (attempt >= wait_limit)
			return 0; /* Control ownership makes forced progress safe. */
		ops->wait_once(arg);
	}
	return 0;
}

/* Non-returning halt/crash fallback: stop producers without waiting. */
static inline void
vmbus_teardown_final_fallback(const struct vmbus_teardown_ops *ops, void *arg)
{
	ops->deactivate_rx(arg);
	ops->signal_stop(arg, 0);
}

#endif /* __VMBUS_TEARDOWN_H__ */
