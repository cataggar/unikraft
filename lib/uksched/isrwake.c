/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */
#include <uk/isr/sched.h>
#include <uk/isr/thread.h>
#if CONFIG_LIBUKSCHED_FIXED_SMP
#include <uk/pcpuvar.h>
#include <uk/plat/spinlock.h>
#endif

void uk_thread_wake_isr(struct uk_thread *thread)
{
	unsigned long flags;
#if CONFIG_LIBUKSCHED_FIXED_SMP
	struct uk_sched *sched = thread->sched;
	int published = 0;
#endif

#if CONFIG_LIBUKSCHED_FIXED_SMP
	if (sched)
		ukplat_spin_lock_irqsave(&sched->lock, flags);
	else
		flags = uk_lcpu_save_irqf();
#else
	flags = uk_lcpu_save_irqf();
#endif
	if (!uk_thread_is_runnable(thread)
#if CONFIG_LIBUKSCHED_FIXED_SMP
	    && !uk_thread_is_exiting(thread)
	    && !uk_thread_is_exited(thread)
#endif
	    ) {
		uk_thread_set_runnable(thread);
		if (thread->sched)
			uk_sched_thread_woken_isr(thread);
#if CONFIG_LIBUKSCHED_FIXED_SMP
		published = 1;
#endif
	}
	thread->wakeup_time = 0LL;
#if CONFIG_LIBUKSCHED_FIXED_SMP
	if (sched)
		ukplat_spin_unlock_irqrestore(&sched->lock, flags);
	else
		uk_lcpu_restore_irqf(flags);
	if (published && sched &&
	    sched->lcpu_idx != uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx) &&
	    uk_sched_state(sched) == UK_SCHED_ONLINE) {
		unsigned int attempts = UK_SCHED_KICK_RETRIES_DEFAULT;

		while (attempts-- && uk_sched_kick(sched))
			;
	}
#else
	uk_lcpu_restore_irqf(flags);
#endif
}
