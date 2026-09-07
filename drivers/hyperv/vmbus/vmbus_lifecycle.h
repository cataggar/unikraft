/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_LIFECYCLE_H__
#define __VMBUS_LIFECYCLE_H__

struct vmbus_unwind_ops {
	void (*stop_work)(void *arg);
	void (*remove_devices)(void *arg);
	int (*unload)(void *arg);
	void (*drain_queues)(void *arg);
	void (*reset_protocol)(void *arg);
};

static inline int
vmbus_probe_unwind_run(const struct vmbus_unwind_ops *ops, void *arg,
		       int primary_error)
{
	int unload_error;

	ops->stop_work(arg);
	ops->remove_devices(arg);
	unload_error = ops->unload(arg);
	ops->drain_queues(arg);
	ops->reset_protocol(arg);
	return primary_error ? primary_error : unload_error;
}

#endif /* __VMBUS_LIFECYCLE_H__ */
