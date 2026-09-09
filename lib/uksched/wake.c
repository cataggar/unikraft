/* SPDX-License-Identifier: BSD-3-Clause */
#include <stddef.h>
#include <uk/config.h>
#include <uk/lcpu.h>
#include <uk/pcpuvar.h>
#include <uk/print.h>
#include <uk/sched.h>
#include <uk/thread.h>
#if CONFIG_LIBUKSCHED_FIXED_SMP
#include <uk/plat/spinlock.h>
#endif

static int _uk_thread_wake(struct uk_thread *thread, int *published,
			   struct uk_sched **published_sched)
{
	unsigned long flags;
#if CONFIG_LIBUKSCHED_FIXED_SMP
	struct uk_sched *sched;
	int rc = 0;

	UK_ASSERT(published);
	UK_ASSERT(published_sched);
	*published = 0;
	*published_sched = NULL;
	sched = thread->sched;
	if (sched)
		ukplat_spin_lock_irqsave(&sched->lock, flags);
	else
		flags = uk_lcpu_save_irqf();
#else
	(void)published;
	(void)published_sched;
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
			uk_sched_thread_woken(thread);
#if CONFIG_LIBUKSCHED_FIXED_SMP
		*published = 1;
		/* The thread may now disappear; its online scheduler cannot. */
		*published_sched = sched;
#endif
	}
	thread->wakeup_time = 0LL;
#if CONFIG_LIBUKSCHED_FIXED_SMP
	if (sched)
		ukplat_spin_unlock_irqrestore(&sched->lock, flags);
	else
		uk_lcpu_restore_irqf(flags);

	if (*published && sched &&
	    sched->lcpu_idx != uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx) &&
	    uk_sched_state(sched) == UK_SCHED_ONLINE)
		rc = uk_sched_kick(sched);
	return rc;
#else
	uk_lcpu_restore_irqf(flags);
	return 0;
#endif
}

void uk_thread_wake(struct uk_thread *thread)
{
#if CONFIG_LIBUKSCHED_FIXED_SMP
	struct uk_sched *published_sched;
	int published;
	int rc;

	rc = _uk_thread_wake(thread, &published, &published_sched);
	if (rc && published && published_sched)
		rc = uk_sched_kick_retry(published_sched,
					 UK_SCHED_KICK_RETRIES_DEFAULT);
	if (rc)
		uk_pr_err("thread %p: wake published but scheduler kick failed: %d\n",
			  thread, rc);
#else
	(void)_uk_thread_wake(thread, NULL, NULL);
#endif
}

#if CONFIG_LIBUKSCHED_FIXED_SMP
int uk_thread_wake_published(struct uk_thread *thread, int *published)
{
	struct uk_sched *published_sched;

	return _uk_thread_wake(thread, published, &published_sched);
}
#endif
