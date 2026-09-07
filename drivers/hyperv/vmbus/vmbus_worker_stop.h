/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_WORKER_STOP_H__
#define __VMBUS_WORKER_STOP_H__

enum vmbus_worker_stop_result {
	VMBUS_WORKER_STOP_NONE = 0,
	VMBUS_WORKER_STOP_JOINED = 1,
	VMBUS_WORKER_STOP_SELF = 2,
	VMBUS_WORKER_STOP_UNSCHEDULABLE = 3,
	VMBUS_WORKER_STOP_TIMED_OUT = 4,
};

struct vmbus_worker_stop_ops {
	int (*can_wait_before_lock)(void *arg);
	void (*lock)(void *arg);
	void (*unlock)(void *arg);
	int (*worker_present_locked)(void *arg);
	int (*caller_is_worker_locked)(void *arg);
	void (*set_stop_locked)(void *arg);
	void (*wake_locked)(void *arg);
	int (*worker_present)(void *arg);
	void (*wait_once)(void *arg);
};

/*
 * Snapshot schedulability before lock() masks interrupts. The worker pointer
 * and wake operation stay under the lock; all bounded waiting occurs after it.
 */
static inline int
vmbus_worker_stop_run(const struct vmbus_worker_stop_ops *ops, void *arg,
		      unsigned int wait_limit)
{
	const int can_wait = ops->can_wait_before_lock(arg);
	unsigned int attempt;
	int self;

	ops->lock(arg);
	if (!ops->worker_present_locked(arg)) {
		ops->unlock(arg);
		return VMBUS_WORKER_STOP_NONE;
	}
	ops->set_stop_locked(arg);
	self = ops->caller_is_worker_locked(arg);
	if (!self && can_wait)
		ops->wake_locked(arg);
	ops->unlock(arg);

	if (self)
		return VMBUS_WORKER_STOP_SELF;
	if (!can_wait)
		return VMBUS_WORKER_STOP_UNSCHEDULABLE;
	for (attempt = 0; ops->worker_present(arg); attempt++) {
		if (attempt >= wait_limit)
			return VMBUS_WORKER_STOP_TIMED_OUT;
		ops->wait_once(arg);
	}
	return VMBUS_WORKER_STOP_JOINED;
}

#endif /* __VMBUS_WORKER_STOP_H__ */
