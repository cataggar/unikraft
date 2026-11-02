#ifndef __UK_THREAD_H__
#define __UK_THREAD_H__
#include <pthread.h>
#include <stdint.h>
struct uk_thread;
static inline struct uk_thread *uk_thread_current(void)
{
	return (struct uk_thread *)(uintptr_t)pthread_self();
}
static inline void uk_thread_wake_isr(struct uk_thread *thread)
{
	(void)thread;
}
static inline void uk_thread_wake(struct uk_thread *thread)
{
	(void)thread;
}
static inline __attribute__((noreturn)) void uk_sched_thread_exit(void)
{
	pthread_exit(NULL);
	__builtin_unreachable();
}
#endif
