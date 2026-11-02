#ifndef __UK_SCHED_H__
#define __UK_SCHED_H__
#include <uk/arch/types.h>
struct uk_sched;
struct uk_sched *uk_sched_current(void);
void uk_sched_thread_sleep(__u64 nanoseconds);
#endif
