/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_QUEUE_H__
#define __VMBUS_QUEUE_H__

#include <errno.h>
#include <uk/arch/types.h>

struct vmbus_queue_state {
	__u32 head;
	__u32 tail;
	__u32 lost;
};

static inline int vmbus_queue_reserve(struct vmbus_queue_state *queue,
				      __u32 capacity, __u32 *ticket)
{
	__u32 head;

	if (__atomic_load_n(&queue->lost, __ATOMIC_ACQUIRE))
		return -EPIPE;
	head = __atomic_load_n(&queue->head, __ATOMIC_RELAXED);
	if (head - __atomic_load_n(&queue->tail, __ATOMIC_ACQUIRE) >=
	    capacity) {
		__atomic_store_n(&queue->lost, 1, __ATOMIC_RELEASE);
		return -ENOSPC;
	}
	*ticket = head;
	return 0;
}

static inline void vmbus_queue_commit(struct vmbus_queue_state *queue,
				      __u32 ticket)
{
	__atomic_store_n(&queue->head, ticket + 1, __ATOMIC_RELEASE);
}

static inline int vmbus_queue_take(struct vmbus_queue_state *queue,
				   __u32 *ticket)
{
	__u32 tail = __atomic_load_n(&queue->tail, __ATOMIC_RELAXED);

	if (tail == __atomic_load_n(&queue->head, __ATOMIC_ACQUIRE))
		return 0;
	*ticket = tail;
	__atomic_store_n(&queue->tail, tail + 1, __ATOMIC_RELEASE);
	return 1;
}

static inline void vmbus_queue_drain(struct vmbus_queue_state *queue)
{
	__atomic_store_n(&queue->tail,
			 __atomic_load_n(&queue->head, __ATOMIC_ACQUIRE),
			 __ATOMIC_RELEASE);
}

static inline void vmbus_queue_recover(struct vmbus_queue_state *queue)
{
	vmbus_queue_drain(queue);
	__atomic_store_n(&queue->lost, 0, __ATOMIC_RELEASE);
}

#endif /* __VMBUS_QUEUE_H__ */
