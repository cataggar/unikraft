#pragma once

#include <stdint.h>

#define UK_THREADF_RUNNABLE 0x1U
#define UK_THREADF_EXITING  0x2U
#define UK_THREADF_EXITED   0x4U

struct uk_sched;

struct uk_thread {
	struct uk_sched *sched;
	unsigned int flags;
	int64_t wakeup_time;
};

#define uk_thread_is_runnable(thread) \
	((thread)->flags & UK_THREADF_RUNNABLE)
#define uk_thread_is_exiting(thread) \
	((thread)->flags & UK_THREADF_EXITING)
#define uk_thread_is_exited(thread) \
	((thread)->flags & UK_THREADF_EXITED)
#define uk_thread_set_runnable(thread) \
	((thread)->flags |= UK_THREADF_RUNNABLE)

void uk_thread_wake(struct uk_thread *thread);
int uk_thread_wake_published(struct uk_thread *thread, int *published);
