#pragma once

#include <assert.h>
#include <uk/plat/spinlock.h>

#define UK_ASSERT(expr) assert(expr)
#define UK_SCHED_ONLINE 2U
#define UK_SCHED_KICK_RETRIES_DEFAULT 4U

struct uk_thread;

struct uk_sched {
	__spinlock lock;
	unsigned int lcpu_idx;
	unsigned int state;
};

void uk_sched_thread_woken(struct uk_thread *thread);
unsigned int uk_sched_state(const struct uk_sched *sched);
int uk_sched_kick(struct uk_sched *sched);
int uk_sched_kick_retry(struct uk_sched *sched, unsigned int attempts);
