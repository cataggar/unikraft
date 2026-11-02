/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __STORVSC_HOST_SCHED_H__
#define __STORVSC_HOST_SCHED_H__
#include <uk/arch/types.h>
struct uk_sched {
	int placeholder;
};
struct uk_thread;
typedef void (*uk_thread_fn1_t)(void *);
struct uk_sched *uk_sched_current(void);
struct uk_thread *uk_sched_thread_create(struct uk_sched *sched,
					  uk_thread_fn1_t function,
					  void *argument,
					  const char *name);
void uk_sched_thread_sleep(__nsec nanoseconds);
void uk_sched_thread_exit(void) __attribute__((noreturn));
#endif
