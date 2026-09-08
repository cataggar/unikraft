/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __UK_SCHEDCOOP_FIXED_H__
#define __UK_SCHEDCOOP_FIXED_H__

#include <stdbool.h>
#include <uk/assert.h>

enum uk_schedcoop_queue {
	UK_SCHEDCOOP_QUEUE_NONE = 0,
	UK_SCHEDCOOP_QUEUE_RUN,
	UK_SCHEDCOOP_QUEUE_SLEEP
};

struct uk_schedcoop_fixed_guard {
	unsigned int run_count;
	unsigned int sleep_count;
	unsigned int idle_armed;
};

static inline int
uk_schedcoop_run_publish(struct uk_schedcoop_fixed_guard *guard,
			 unsigned int *membership)
{
	if (*membership == UK_SCHEDCOOP_QUEUE_RUN)
		return 0;
	UK_ASSERT(*membership == UK_SCHEDCOOP_QUEUE_NONE);
	*membership = UK_SCHEDCOOP_QUEUE_RUN;
	guard->run_count++;
	__atomic_store_n(&guard->idle_armed, 0, __ATOMIC_RELEASE);
	return 1;
}

static inline void
uk_schedcoop_run_take(struct uk_schedcoop_fixed_guard *guard,
		      unsigned int *membership)
{
	UK_ASSERT(*membership == UK_SCHEDCOOP_QUEUE_RUN);
	UK_ASSERT(guard->run_count);
	*membership = UK_SCHEDCOOP_QUEUE_NONE;
	guard->run_count--;
}

static inline void
uk_schedcoop_sleep_publish(struct uk_schedcoop_fixed_guard *guard,
			   unsigned int *membership)
{
	UK_ASSERT(*membership == UK_SCHEDCOOP_QUEUE_NONE);
	*membership = UK_SCHEDCOOP_QUEUE_SLEEP;
	guard->sleep_count++;
}

static inline void
uk_schedcoop_sleep_take(struct uk_schedcoop_fixed_guard *guard,
			unsigned int *membership)
{
	UK_ASSERT(*membership == UK_SCHEDCOOP_QUEUE_SLEEP);
	UK_ASSERT(guard->sleep_count);
	*membership = UK_SCHEDCOOP_QUEUE_NONE;
	guard->sleep_count--;
}

static inline int
uk_schedcoop_idle_prepare(struct uk_schedcoop_fixed_guard *guard)
{
	if (guard->run_count) {
		__atomic_store_n(&guard->idle_armed, 0, __ATOMIC_RELEASE);
		return 0;
	}
	__atomic_store_n(&guard->idle_armed, 1, __ATOMIC_RELEASE);
	return 1;
}

enum uk_schedcoop_work_state {
	UK_SCHEDCOOP_WORK_IDLE = 0,
	UK_SCHEDCOOP_WORK_PUBLISHING,
	UK_SCHEDCOOP_WORK_QUEUED,
	UK_SCHEDCOOP_WORK_RUNNING,
	UK_SCHEDCOOP_WORK_DONE
};

static inline int uk_schedcoop_work_reserve(unsigned int *state)
{
	unsigned int expected = UK_SCHEDCOOP_WORK_IDLE;

	return __atomic_compare_exchange_n(
		state, &expected, UK_SCHEDCOOP_WORK_PUBLISHING, false,
		__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static inline void uk_schedcoop_work_commit(unsigned int *state)
{
	UK_ASSERT(__atomic_load_n(state, __ATOMIC_RELAXED) ==
		  UK_SCHEDCOOP_WORK_PUBLISHING);
	__atomic_store_n(state, UK_SCHEDCOOP_WORK_QUEUED, __ATOMIC_RELEASE);
}

static inline int uk_schedcoop_work_take(unsigned int *state)
{
	unsigned int expected = UK_SCHEDCOOP_WORK_QUEUED;

	return __atomic_compare_exchange_n(
		state, &expected, UK_SCHEDCOOP_WORK_RUNNING, false,
		__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static inline void uk_schedcoop_work_complete(unsigned int *state)
{
	UK_ASSERT(__atomic_load_n(state, __ATOMIC_RELAXED) ==
		  UK_SCHEDCOOP_WORK_RUNNING);
	__atomic_store_n(state, UK_SCHEDCOOP_WORK_DONE, __ATOMIC_RELEASE);
}

static inline void uk_schedcoop_work_reap(unsigned int *state)
{
	unsigned int expected = UK_SCHEDCOOP_WORK_DONE;

	UK_ASSERT(__atomic_compare_exchange_n(
		state, &expected, UK_SCHEDCOOP_WORK_IDLE, false,
		__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
}

#endif /* __UK_SCHEDCOOP_FIXED_H__ */
