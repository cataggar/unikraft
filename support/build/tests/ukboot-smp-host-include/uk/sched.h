#pragma once
struct uk_thread;
struct uk_sched {
	unsigned int lcpu_idx;
	unsigned int state;
};
enum {
	UK_SCHED_PREPARED = 0,
	UK_SCHED_STARTING,
	UK_SCHED_ONLINE,
	UK_SCHED_ROLLED_BACK,
	UK_SCHED_QUARANTINED
};
int uk_sched_start_thread(struct uk_sched *, struct uk_thread *);
unsigned int uk_sched_state(const struct uk_sched *);
void uk_sched_set_state(struct uk_sched *, unsigned int);
void uk_sched_yield(void);
