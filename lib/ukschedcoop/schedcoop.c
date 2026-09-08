/* SPDX-License-Identifier: MIT */
/*
 * Authors: Grzegorz Milos
 *          Robert Kaiser
 *          Costin Lupu <costin.lupu@cs.pub.ro>
 *
 * Copyright (c) 2005, Intel Research Cambridge
 * Copyright (c) 2017, NEC Europe Ltd., NEC Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
/*
 * The scheduler is non-preemptive (cooperative), and schedules according
 * to Round Robin algorithm.
 */
#include <uk/plat/config.h>
#include <uk/lcpu.h>
#include <uk/plat/memory.h>
#include <uk/plat/time.h>
#include <uk/sched_impl.h>
#include <uk/schedcoop.h>
#include <uk/essentials.h>
#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
#include <uk/pcpuvar.h>
#include <uk/plat/spinlock.h>
#endif
#include "schedcoop.h"

static void schedcoop_schedule(struct uk_sched *s)
{
	struct schedcoop *c = uksched2schedcoop(s);
	struct uk_thread *prev, *next, *thread, *tmp;
	__snsec now, min_wakeup_time;
	unsigned long flags;

	if (unlikely(uk_lcpu_irqs_disabled()))
		UK_CRASH("Must not call %s with IRQs disabled\n", __func__);

	now = ukplat_monotonic_clock();
	prev = uk_thread_current();
#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
	UK_ASSERT(s->lcpu_idx ==
		  uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx));
	ukplat_spin_lock_irqsave(&s->lock, flags);
#else
	flags = uk_lcpu_save_irqf();
#endif

#if 0 //TODO
	if (in_callback)
		UK_CRASH("Must not call %s from a callback\n", __func__);
#endif

	/* Update execution time of current thread */
	/* WARNING: We assume here that scheduler `s` is only responsible for
	 *          the current logical CPU. Otherwise, we would have to store
	 *          the time of the last context switch per logical core.
	 */
	prev->exec_time += now - c->ts_prev_switch;
	c->ts_prev_switch = now;

	/* Examine all sleeping threads.
	 * Wake up expired ones and find the time when the next timeout expires.
	 */
	min_wakeup_time = 0;
	UK_TAILQ_FOREACH_SAFE(thread, &c->sleep_queue,
			      queue, tmp) {
		if (likely(thread->wakeup_time)) {
			if (thread->wakeup_time <= now) {
				uk_thread_set_runnable(thread);
				schedcoop_thread_woken_isr(s, thread);
				thread->wakeup_time = 0;
			}
			else if (!min_wakeup_time
				 || thread->wakeup_time < min_wakeup_time)
				min_wakeup_time = thread->wakeup_time;
		}
	}

	next = UK_TAILQ_FIRST(&c->run_queue);
	if (next) {
		UK_ASSERT(next != prev);
		UK_ASSERT(uk_thread_is_runnable(next));
		UK_ASSERT(!uk_thread_is_exited(next));
		UK_TAILQ_REMOVE(&c->run_queue, next,
				queue);
#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
		uk_schedcoop_run_take(&c->fixed_guard,
				      &next->sched_queue);
#endif

		/* Put previous thread on the end of the list */
		if ((prev != &c->idle)
		    && uk_thread_is_runnable(prev)
		    && !uk_thread_is_exited(prev)) {
#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
			UK_ASSERT(uk_schedcoop_run_publish(
				&c->fixed_guard, &prev->sched_queue));
#endif
			UK_TAILQ_INSERT_TAIL(&c->run_queue, prev,
					     queue);
		}
	} else if (uk_thread_is_runnable(prev)
		   && !uk_thread_is_exited(prev)) {
		next = prev;
	} else {
		/*
		 * Schedule idle thread that will halt the CPU
		 * We select the idle thread only if we do not have anything
		 * else to execute
		 */
		c->idle_return_time = min_wakeup_time;
		next = &c->idle;
		uk_sched_stats_idle_count_incr(s);
	}

	if (next != prev) {
		/*
		 * Queueable is used to cover the case when during a
		 * context switch, the thread that is about to be
		 * evacuated is interrupted and woken up.
		 */
		uk_thread_set_queueable(prev);
		uk_thread_clear_queueable(next);
	}

	uk_sched_stats_sched_count_incr(s);

#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
	ukplat_spin_unlock_irqrestore(&s->lock, flags);
#else
	uk_lcpu_restore_irqf(flags);
#endif

	/* Interrupting the switch is equivalent to having the next thread
	 * interrupted at the return instruction. And therefore at safe point.
	 */
	if (prev != next) {
		if (next != &c->idle)
			uk_sched_stats_next_count_incr(s);
		uk_sched_thread_switch(next);
	}
}

static void schedcoop_yield(struct uk_sched *s)
{
	uk_sched_stats_yield_count_incr(s);
	schedcoop_schedule(s);
}

static int schedcoop_thread_add(struct uk_sched *s, struct uk_thread *t)
{
	struct schedcoop *c = uksched2schedcoop(s);

	UK_ASSERT(t);
	UK_ASSERT(!uk_thread_is_exited(t));

	/* Add to run queue if runnable */
	if (uk_thread_is_runnable(t)) {
#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
		UK_ASSERT(uk_schedcoop_run_publish(&c->fixed_guard,
						   &t->sched_queue));
#endif
		UK_TAILQ_INSERT_TAIL(&c->run_queue, t, queue);
	}

	return 0;
}

static void schedcoop_thread_remove(struct uk_sched *s, struct uk_thread *t)
{
	struct schedcoop *c = uksched2schedcoop(s);

#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
	if (t == uk_thread_current())
		return;
	if (t->sched_queue == UK_SCHEDCOOP_QUEUE_RUN) {
		UK_TAILQ_REMOVE(&c->run_queue, t, queue);
		uk_schedcoop_run_take(&c->fixed_guard, &t->sched_queue);
	} else if (t->sched_queue == UK_SCHEDCOOP_QUEUE_SLEEP) {
		UK_TAILQ_REMOVE(&c->sleep_queue, t, queue);
		uk_schedcoop_sleep_take(&c->fixed_guard, &t->sched_queue);
	}
#else
	/* Remove from run_queue */
	if (t != uk_thread_current()
	    && uk_thread_is_runnable(t)) {
		UK_TAILQ_REMOVE(&c->run_queue, t, queue);
	}
#endif
}

static void schedcoop_thread_blocked(struct uk_sched *s, struct uk_thread *t)
{
	struct schedcoop *c = uksched2schedcoop(s);

	UK_ASSERT(uk_lcpu_irqs_disabled());

	if (t != uk_thread_current()) {
		UK_TAILQ_REMOVE(&c->run_queue, t, queue);
#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
		uk_schedcoop_run_take(&c->fixed_guard, &t->sched_queue);
#endif
	}
	if (t->wakeup_time > 0) {
		UK_TAILQ_INSERT_TAIL(&c->sleep_queue, t, queue);
#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
		uk_schedcoop_sleep_publish(&c->fixed_guard,
					   &t->sched_queue);
#endif
	}
}

static __noreturn void idle_thread_fn(void *argp)
{
	struct schedcoop *c = (struct schedcoop *) argp;
	__nsec now, wake_up_time;
	unsigned long flags;

	UK_ASSERT(c);

	for (;;) {
#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
		int collected = 0;

		/*
		 * Secondary schedulers own persistent threads only. Reaping on
		 * them would execute allocator and termination callbacks on an
		 * AP, which the fixed-SMP contract intentionally forbids.
		 */
		if (c->sched.lcpu_idx == 0)
			collected = uk_sched_thread_gc(&c->sched);

		ukplat_spin_lock_irqsave(&c->sched.lock, flags);
		if (collected || UK_TAILQ_FIRST(&c->run_queue)) {
			__atomic_store_n(&c->fixed_guard.idle_armed, 0,
					 __ATOMIC_RELEASE);
			ukplat_spin_unlock_irqrestore(&c->sched.lock, flags);
			schedcoop_yield(&c->sched);
			continue;
		}
		UK_ASSERT(uk_schedcoop_idle_prepare(&c->fixed_guard));
#else
		flags = uk_lcpu_save_irqf();

		/*
		 * FIXME: We assume that `uk_sched_thread_gc()` is non-blocking
		 *        because we implement a cooperative scheduler. However,
		 *        this assumption may not be true depending on the
		 *        destructor functions that are assigned to the threads
		 *        and are called by `uk_sched_thred_gc()`.
		 *	  Also check if in the meantime we got a runnable
		 *	  thread.
		 * NOTE:  This idle thread must be non-blocking so that the
		 *        scheduler has always something to schedule.
		 */
		if (uk_sched_thread_gc(&c->sched) > 0 ||
		    UK_TAILQ_FIRST(&c->run_queue)) {
			/* We collected successfully some garbage or there is
			 * a runnable thread in the queue.
			 * Check if something else can be scheduled now.
			 */
			uk_lcpu_restore_irqf(flags);

			/* Use yield() here instead of schedule(), as the
			 * latter would cause num_sched to exceed num_yield,
			 * which would errneously imply a preemption, as
			 * num_preempt = num_sched - num_yield
			 */
			schedcoop_yield(&c->sched);

			continue;
		}
#endif

		/* Read return time set by last schedule operation */
		wake_up_time = (volatile __nsec) c->idle_return_time;
		now = ukplat_monotonic_clock();

		if (!wake_up_time || wake_up_time > now) {
#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
			/*
			 * The scheduler lock serializes the empty check with a
			 * remote enqueue. IRQs stay disabled until halt_irq()
			 * atomically enables them and sleeps, so a post-unlock
			 * kick is either pending or wakes the halt.
			 */
			ukarch_spin_unlock(&c->sched.lock);
#endif
			if (wake_up_time)
				uk_lcpu_halt_irq_until(wake_up_time);
			else
				uk_lcpu_halt_irq();

			/* handle pending events if any */
			uk_lcpu_irqs_handle_pending();
#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
		} else {
			ukarch_spin_unlock(&c->sched.lock);
#endif
		}

		uk_lcpu_restore_irqf(flags);

		/* Try to schedule a thread that might now be available.
		 * Use yield() here instead of schedule(), as the
		 * latter would cause num_sched to exceed num_yield,
		 * which would errneously imply a preemption, as
		 * num_preempt = num_sched - num_yield
		 */
		schedcoop_yield(&c->sched);
	}
}

static int schedcoop_start(struct uk_sched *s,
			   struct uk_thread *main_thread __maybe_unused)
{
	struct schedcoop *c = uksched2schedcoop(s);

	UK_ASSERT(main_thread);
	UK_ASSERT(main_thread->sched == s);
	UK_ASSERT(uk_thread_is_runnable(main_thread));
	UK_ASSERT(!uk_thread_is_exited(main_thread));
	UK_ASSERT(uk_thread_current() == main_thread);

	/* Since we are now starting to schedule, we save the current timestamp
	 * as the start time for the first time slice.
	 */
	c->ts_prev_switch = ukplat_monotonic_clock();

	/* NOTE: We do not put `main_thread` into the thread list.
	 *       Current running threads will be added as soon as
	 *       a different thread is scheduled.
	 */

#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
	/* Boot publishes all fixed schedulers before enabling BSP/AP IRQs. */
	(void)s;
#else
	uk_lcpu_enable_irq();
#endif

	return 0;
}

static const struct uk_thread *schedcoop_idle_thread(struct uk_sched *s,
						     unsigned int proc_id)
{
	struct schedcoop *c = uksched2schedcoop(s);

	/* Every fixed scheduler still owns exactly one processing LCPU. */
	if (proc_id > 0)
		return NULL;

	return &(c->idle);
}

#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
static __noreturn void schedcoop_fixed_worker(void *argp)
{
	struct schedcoop *c = argp;

	for (;;) {
		uk_schedcoop_work_fn_t fn;
		void *arg;
		int published;
		int rc;

		uk_waitq_wait_event(&c->work_wait,
			__atomic_load_n(&c->work_state, __ATOMIC_ACQUIRE) ==
				UK_SCHEDCOOP_WORK_QUEUED);

		if (!uk_schedcoop_work_take(&c->work_state))
			continue;

		fn = c->work_fn;
		arg = c->work_arg;
		UK_ASSERT(fn);
		rc = fn(arg);
		c->work_result = rc;
		c->completion_kick_error = 0;
		__atomic_store_n(&c->completion_finalized, 0,
				 __ATOMIC_RELAXED);
		uk_schedcoop_work_complete(&c->work_state);
		rc = uk_waitq_wake_up_one_published(&c->done_wait,
						    &published);
		if (rc && published && c->completion_sched)
			rc = uk_sched_kick_retry(
				c->completion_sched,
				UK_SCHED_KICK_RETRIES_DEFAULT);
		if (rc)
			__atomic_store_n(&c->completion_kick_error, rc,
					 __ATOMIC_RELEASE);
		__atomic_store_n(&c->completion_finalized, 1,
				 __ATOMIC_RELEASE);
	}
}
#endif

static struct uk_sched *
schedcoop_create(struct uk_alloc *a, struct uk_alloc *sa,
		 struct uk_alloc *auxsa, struct uk_alloc *tls_a,
		 unsigned int lcpu_idx)
{
	struct schedcoop *c = NULL;
	int rc;

	uk_pr_info("Initializing cooperative scheduler\n");
	c = uk_zalloc(a, sizeof(struct schedcoop));
	if (!c)
		goto err_out;

	UK_TAILQ_INIT(&c->run_queue);
	UK_TAILQ_INIT(&c->sleep_queue);
#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
	c->fixed_guard = (struct uk_schedcoop_fixed_guard){ 0 };
	c->work_state = UK_SCHEDCOOP_WORK_IDLE;
	uk_waitq_init(&c->work_wait);
	uk_waitq_init(&c->done_wait);
#endif

	/* Create idle thread */
	rc = uk_thread_init_fn1(&c->idle,
				idle_thread_fn, (void *) c,
				sa, STACK_SIZE,
				auxsa, AUXSTACK_SIZE,
				a, false,
				NULL,
				"idle",
				NULL,
				NULL);
	if (rc < 0)
		goto err_free_c;

	c->idle.sched = &c->sched;

	uk_sched_init(&c->sched,
			schedcoop_start,
			schedcoop_yield,
			schedcoop_thread_add,
			schedcoop_thread_remove,
			schedcoop_thread_blocked,
			schedcoop_thread_woken_isr,
			schedcoop_thread_woken_isr,
			schedcoop_idle_thread,
			a, sa, auxsa, tls_a);

#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
	rc = uk_sched_bind_lcpu(&c->sched, lcpu_idx);
	if (rc < 0)
		goto err_release_idle;
#else
	(void) lcpu_idx;
#endif

	/* Add idle thread to the scheduler's thread list */
	UK_TAILQ_INSERT_TAIL(&c->sched.thread_list, &c->idle, thread_list);

#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
	if (lcpu_idx > 0) {
		c->worker = uk_sched_thread_create(&c->sched,
						   schedcoop_fixed_worker, c,
						   "fixed-ap-work");
		if (!c->worker)
			goto err_unbind;
	}
#endif

	return &c->sched;

#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
err_unbind:
	uk_sched_unbind_lcpu(&c->sched);
err_release_idle:
	c->idle.sched = NULL;
	uk_thread_release(&c->idle);
#endif
err_free_c:
	uk_free(a, c);
err_out:
	return NULL;
}

struct uk_sched *uk_schedcoop_create(struct uk_alloc *a,
				     struct uk_alloc *sa,
				     struct uk_alloc *auxsa,
				     struct uk_alloc *tls_a)
{
#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
	return schedcoop_create(a, sa, auxsa, tls_a,
		uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx));
#else
	return schedcoop_create(a, sa, auxsa, tls_a, 0);
#endif
}

#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
struct uk_sched *uk_schedcoop_create_on(struct uk_alloc *a,
					struct uk_alloc *sa,
					struct uk_alloc *auxsa,
					struct uk_alloc *tls_a,
					unsigned int lcpu_idx)
{
	return schedcoop_create(a, sa, auxsa, tls_a, lcpu_idx);
}

int uk_schedcoop_fixed_submit(unsigned int lcpu_idx,
			      uk_schedcoop_work_fn_t fn, void *arg,
			      int *published)
{
	struct uk_sched *sched = uk_sched_get_lcpu(lcpu_idx);
	struct schedcoop *c;
	int wake_published;
	int rc;

	if (!published || !fn || !sched || lcpu_idx == 0)
		return -EINVAL;
	if (!uk_sched_current() || uk_sched_lcpu(uk_sched_current()) != 0)
		return -EPERM;
	*published = 0;
	if (uk_sched_state(sched) != UK_SCHED_ONLINE)
		return -EHOSTDOWN;
	c = uksched2schedcoop(sched);

	if (!uk_schedcoop_work_reserve(&c->work_state))
		return -EBUSY;

	c->work_fn = fn;
	c->work_arg = arg;
	c->completion_sched = uk_sched_current();
	c->completion_kick_error = 0;
	uk_schedcoop_work_commit(&c->work_state);
	*published = 1;

	rc = uk_waitq_wake_up_one_published(&c->work_wait,
					    &wake_published);
	return rc;
}

int uk_schedcoop_fixed_wait(unsigned int lcpu_idx, __nsec deadline,
			    int *work_result, int *completion_kick_error)
{
	struct uk_sched *sched = uk_sched_get_lcpu(lcpu_idx);
	struct schedcoop *c;

	if (!sched || !work_result || !completion_kick_error)
		return -EINVAL;
	c = uksched2schedcoop(sched);

	if (uk_waitq_wait_event_deadline(
		    &c->done_wait,
		    __atomic_load_n(&c->work_state, __ATOMIC_ACQUIRE) ==
			    UK_SCHEDCOOP_WORK_DONE,
		    deadline))
		return -ETIMEDOUT;
	while (!__atomic_load_n(&c->completion_finalized,
				 __ATOMIC_ACQUIRE)) {
		if (deadline && ukplat_monotonic_clock() >= deadline)
			return -ETIMEDOUT;
	}

	*work_result = c->work_result;
	*completion_kick_error = __atomic_load_n(
		&c->completion_kick_error, __ATOMIC_ACQUIRE);
	uk_schedcoop_work_reap(&c->work_state);
	return 0;
}

int uk_schedcoop_fixed_idle_armed(unsigned int lcpu_idx)
{
	struct uk_sched *sched = uk_sched_get_lcpu(lcpu_idx);
	struct schedcoop *c;

	if (!sched)
		return 0;
	c = uksched2schedcoop(sched);
	return __atomic_load_n(&c->fixed_guard.idle_armed,
			       __ATOMIC_ACQUIRE);
}

void uk_schedcoop_fixed_destroy(struct uk_sched *sched)
{
	struct schedcoop *c = uksched2schedcoop(sched);
	struct uk_alloc *a = sched->a;

	UK_ASSERT(sched->state != UK_SCHED_ONLINE);
	uk_sched_unbind_lcpu(sched);
	if (c->worker) {
		c->worker->sched = NULL;
		uk_thread_release(c->worker);
		c->worker = NULL;
	}
	c->idle.sched = NULL;
	uk_thread_release(&c->idle);
	uk_free(a, c);
}
#endif
