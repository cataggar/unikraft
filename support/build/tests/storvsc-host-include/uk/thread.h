/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __STORVSC_HOST_THREAD_H__
#define __STORVSC_HOST_THREAD_H__
#include <uk/sched.h>
struct uk_thread *uk_thread_current(void);
void uk_thread_wake(struct uk_thread *thread);
#endif
