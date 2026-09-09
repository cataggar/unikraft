/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Costin Lupu <costin.lupu@cs.pub.ro>
 *          Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 * Copyright (c) 2017, NEC Europe Ltd., NEC Corporation. All rights reserved.
 * Copyright (c) 2022, NEC Laboratories GmbH, NEC Corrporation,
 *                     All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/membarrier.h>
#include <uk/plat/config.h>
#include <uk/plat/time.h>
#include <uk/alloc.h>
#include <uk/lcpu.h>
#include <uk/sched.h>
#include <uk/syscall.h>
#include <uk/wait.h>
#include <uk/pcpuvar.h>
#if CONFIG_LIBUKSCHED_FIXED_SMP
#include <uk/plat/spinlock.h>
#include <uk/sched/fixed.h>
#endif

struct uk_sched *uk_sched_head;

__uk_pcpuvar struct uk_thread *__uk_sched_thread_current;

#if CONFIG_LIBUKSCHED_FIXED_SMP
static struct uk_sched *uk_sched_lcpu_map[CONFIG_UKPLAT_CPU_MAXCOUNT];

int uk_sched_bind_lcpu(struct uk_sched *s, unsigned int lcpu_idx)
{
	struct uk_sched *existing;

	if (lcpu_idx >= CONFIG_UKPLAT_CPU_MAXCOUNT)
		return -ERANGE;
	existing = __atomic_load_n(&uk_sched_lcpu_map[lcpu_idx],
				   __ATOMIC_ACQUIRE);
	if (existing && existing != s)
		return -EEXIST;

	s->lcpu_idx = lcpu_idx;
	__atomic_store_n(&uk_sched_lcpu_map[lcpu_idx], s, __ATOMIC_RELEASE);
	return 0;
}

void uk_sched_unbind_lcpu(struct uk_sched *s)
{
	struct uk_sched **link;

	if (s->lcpu_idx < CONFIG_UKPLAT_CPU_MAXCOUNT &&
	    __atomic_load_n(&uk_sched_lcpu_map[s->lcpu_idx],
			    __ATOMIC_ACQUIRE) == s)
		__atomic_store_n(&uk_sched_lcpu_map[s->lcpu_idx], NULL,
				 __ATOMIC_RELEASE);

	for (link = &uk_sched_head; *link; link = &(*link)->next) {
		if (*link == s) {
			*link = s->next;
			s->next = NULL;
			break;
		}
	}
}

struct uk_sched *uk_sched_get_lcpu(unsigned int lcpu_idx)
{
	if (lcpu_idx >= CONFIG_UKPLAT_CPU_MAXCOUNT)
		return NULL;
	return __atomic_load_n(&uk_sched_lcpu_map[lcpu_idx],
			       __ATOMIC_ACQUIRE);
}

unsigned int uk_sched_lcpu(const struct uk_sched *s)
{
	return s->lcpu_idx;
}

__isr unsigned int uk_sched_state(const struct uk_sched *s)
{
	return __atomic_load_n(&s->state, __ATOMIC_ACQUIRE);
}

void uk_sched_set_state(struct uk_sched *s, unsigned int state)
{
	__atomic_store_n(&s->state, state, __ATOMIC_RELEASE);
}

__isr int uk_sched_kick(struct uk_sched *s)
{
	int rc;

	if (s->lcpu_idx ==
	    uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx))
		return 0;
	if (uk_sched_state(s) != UK_SCHED_ONLINE)
		return -EHOSTDOWN;

	rc = uk_lcpu_wakeup_one(s->lcpu_idx);
	__atomic_store_n(&s->kick_error, rc, __ATOMIC_RELEASE);
	return rc;
}

static int uk_sched_kick_once(void *arg)
{
	return uk_sched_kick(arg);
}

int uk_sched_kick_retry(struct uk_sched *s, unsigned int attempts)
{
	return uk_sched_kick_bounded(uk_sched_kick_once, s, attempts);
}

int uk_sched_last_kick_error(const struct uk_sched *s)
{
	return __atomic_load_n(&s->kick_error, __ATOMIC_ACQUIRE);
}
#endif

int uk_sched_register(struct uk_sched *s)
{
	struct uk_sched *this = uk_sched_head;

	if (!uk_sched_head) {
		uk_sched_head = s;
		s->next = NULL;
		return 0;
	}

	while (this && this->next)
		this = this->next;
	this->next = s;
	s->next = NULL;
	return 0;
}

struct uk_thread *uk_sched_thread_create_fn0(struct uk_sched *s,
					     uk_thread_fn0_t fn0,
					     size_t stack_len,
					     size_t auxstack_len,
					     bool no_uktls,
					     bool no_ectx,
					     const char *name,
					     void *priv,
					     uk_thread_dtor_t dtor)
{
	struct uk_thread *t;
	int rc;

	UK_ASSERT(s);
	UK_ASSERT(s->a_stack);
	UK_ASSERT(s->a_auxstack);

	if (!no_uktls && !s->a_uktls)
		goto err_out;

	t = uk_thread_create_fn0(s->a,
				 fn0,
				 s->a_stack, stack_len,
				 s->a_auxstack, auxstack_len,
				 no_uktls ? NULL : s->a_uktls,
				 no_ectx,
				 name,
				 priv,
				 dtor);
	if (!t)
		goto err_out;

	rc = uk_sched_thread_add(s, t);
	if (rc < 0)
		goto err_free_t;

	return t;

err_free_t:
	uk_thread_release(t);
err_out:
	return NULL;
}

struct uk_thread *uk_sched_thread_create_fn1(struct uk_sched *s,
					     uk_thread_fn1_t fn1,
					     void *argp,
					     size_t stack_len,
					     size_t auxstack_len,
					     bool no_uktls,
					     bool no_ectx,
					     const char *name,
					     void *priv,
					     uk_thread_dtor_t dtor)
{
	struct uk_thread *t;
	int rc;

	UK_ASSERT(s);
	UK_ASSERT(s->a_stack);
	UK_ASSERT(s->a_auxstack);

	if (!no_uktls && !s->a_uktls)
		goto err_out;

	t = uk_thread_create_fn1(s->a,
				 fn1, argp,
				 s->a_stack, stack_len,
				 s->a_auxstack, auxstack_len,
				 no_uktls ? NULL : s->a_uktls,
				 no_ectx,
				 name,
				 priv,
				 dtor);
	if (!t)
		goto err_out;

	rc = uk_sched_thread_add(s, t);
	if (rc < 0)
		goto err_free_t;

	return t;

err_free_t:
	uk_thread_release(t);
err_out:
	return NULL;
}

struct uk_thread *uk_sched_thread_create_fn2(struct uk_sched *s,
					     uk_thread_fn2_t fn2,
					     void *argp0, void *argp1,
					     size_t stack_len,
					     size_t auxstack_len,
					     bool no_uktls,
					     bool no_ectx,
					     const char *name,
					     void *priv,
					     uk_thread_dtor_t dtor)
{
	struct uk_thread *t;
	int rc;

	UK_ASSERT(s);
	UK_ASSERT(s->a_stack);
	UK_ASSERT(s->a_auxstack);

	if (!no_uktls && !s->a_uktls)
		goto err_out;

	t = uk_thread_create_fn2(s->a,
				 fn2, argp0, argp1,
				 s->a_stack, stack_len,
				 s->a_auxstack, auxstack_len,
				 no_uktls ? NULL : s->a_uktls,
				 no_ectx,
				 name,
				 priv,
				 dtor);
	if (!t)
		goto err_out;

	rc = uk_sched_thread_add(s, t);
	if (rc < 0)
		goto err_free_t;

	return t;

err_free_t:
	uk_thread_release(t);
err_out:
	return NULL;
}

static int _uk_sched_start(struct uk_sched *s,
			   struct uk_thread *main_thread)
{
	int ret;

	UK_ASSERT(s);
	UK_ASSERT(s->sched_start);
	UK_ASSERT(!s->is_started);
	UK_ASSERT(!uk_thread_current()); /* No other thread runs */
#if CONFIG_LIBUKSCHED_FIXED_SMP
	UK_ASSERT(s->lcpu_idx ==
		  uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx));
	uk_sched_set_state(s, UK_SCHED_STARTING);
#endif
	main_thread->sched = s;

	/* Because `main_thread` acts as container for storing the current
	 * context, it does not have IP and SP set. We have to manually mark
	 * the thread as RUNNABLE.
	 */
	uk_thread_set_runnable(main_thread);

	/* Set main_thread as current scheduled thread */
	uk_pcpuvar_current_set(__uk_sched_thread_current, main_thread);

	/* Add main to the scheduler's thread list */
	UK_TAILQ_INSERT_TAIL(&s->thread_list, main_thread, thread_list);

	/* Enable scheduler, like time slicing, etc. and notify that `s`
	 * has an (already) scheduled thread
	 */
	ret = s->sched_start(s, main_thread);
	if (ret < 0)
		goto err_unset_thread_current;
	s->is_started = true;
#if CONFIG_LIBUKSCHED_FIXED_SMP
	uk_sched_set_state(s, UK_SCHED_ONLINE);
#endif

#if CONFIG_LIBUKSCHED_STATS
	s->start_time = (__u64)ukplat_monotonic_clock();
#endif /* CONFIG_LIBUKSCHED_STATS */

	return 0;

err_unset_thread_current:
	uk_pcpuvar_current_set(__uk_sched_thread_current, NULL);
	UK_TAILQ_REMOVE(&s->thread_list, main_thread, thread_list);
	main_thread->sched = NULL;
#if CONFIG_LIBUKSCHED_FIXED_SMP
	uk_sched_set_state(s, UK_SCHED_ROLLED_BACK);
#endif
	return ret;
}

#if CONFIG_LIBUKSCHED_FIXED_SMP
int uk_sched_start_thread(struct uk_sched *s,
			  struct uk_thread *main_thread)
{
	UK_ASSERT(main_thread);
	return _uk_sched_start(s, main_thread);
}
#endif

int uk_sched_start(struct uk_sched *s)
{
	struct uk_thread *main_thread;
	uintptr_t tlsp;
	uintptr_t auxsp;
	int ret;

	UK_ASSERT(s);

	/* Allocate an `uk_thread` instance for current context
	 * NOTE: We assume that if we have a TLS pointer, it points to
	 *       an TLS that is derived from the Unikraft TLS template.
	 */
#if CONFIG_LIBUKSCHED_FIXED_SMP
	uk_pr_info("Fixed SMP: capture BSP scheduler context\n");
#endif
	tlsp = uk_lcpu_tlsp_get();
	auxsp = uk_pcpuvar_current_get(UK_LCPU_AUXSP_SYM);
	main_thread = uk_thread_create_bare(s->a,
					    0x0, 0x0, auxsp,
					    tlsp, !(!tlsp), false,
					    "init", NULL, NULL);
	if (!main_thread)
		return -ENOMEM;
#if CONFIG_LIBUKSCHED_FIXED_SMP
	uk_pr_info("Fixed SMP: BSP scheduler context ready\n");
#endif

	ret = _uk_sched_start(s, main_thread);
	if (ret < 0)
		uk_thread_release(main_thread);
#if CONFIG_LIBUKSCHED_FIXED_SMP
	else
		uk_pr_info("Fixed SMP: BSP scheduler online\n");
#endif
	return ret;
}

unsigned int uk_sched_thread_gc(struct uk_sched *sched)
{
	struct uk_thread *thread;
#if !CONFIG_LIBUKSCHED_FIXED_SMP
	struct uk_thread *tmp;
#endif
	unsigned int num = 0;
#if CONFIG_LIBUKSCHED_FIXED_SMP
	unsigned long flags;

	UK_ASSERT(sched->lcpu_idx ==
		  uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx));
#endif

	/* Cleanup finished threads */
#if CONFIG_LIBUKSCHED_FIXED_SMP
	for (;;) {
		ukplat_spin_lock_irqsave(&sched->lock, flags);
		thread = UK_TAILQ_FIRST(&sched->exited_threads);
		if (thread)
			UK_TAILQ_REMOVE(&sched->exited_threads, thread,
					thread_list);
		ukplat_spin_unlock_irqrestore(&sched->lock, flags);
		if (!thread)
			break;
#else
	UK_TAILQ_FOREACH_SAFE(thread, &sched->exited_threads,
			      thread_list, tmp) {
#endif
		UK_ASSERT(thread != uk_thread_current());
		UK_ASSERT(uk_thread_is_exited(thread));

		uk_pr_debug("%p: garbage collect thread %p (%s)\n",
			    sched, thread,
			    thread->name ? thread->name : "<unnamed>");

#if !CONFIG_LIBUKSCHED_FIXED_SMP
		UK_TAILQ_REMOVE(&sched->exited_threads, thread, thread_list);
#endif
		if (thread->_gc_fn)
			thread->_gc_fn(thread,  thread->_gc_argp);
		uk_thread_release(thread);
		++num;
	}

	return num;
}

void uk_sched_thread_terminate(struct uk_thread *thread)
{
	struct uk_sched *sched;

	UK_ASSERT(thread);
	 /* NOTE: The following assertion can also fail on a double-termination.
	  *       This can happen when the thread was already put on the
	  *       exited_thread list and waits for getting garbage collected.
	  *       Double-termination can be avoided by testing for the exited
	  *       flag.
	  */
	UK_ASSERT(thread->sched);

	sched = thread->sched;
#if CONFIG_LIBUKSCHED_FIXED_SMP
	UK_ASSERT(sched->lcpu_idx ==
		  uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx));
#endif

	uk_pr_debug("%p: thread %p (%s) terminated\n",
		    sched, thread, thread->name ? thread->name : "<unnamed>");

	if (uk_thread_in_waitq(thread))
		uk_waitq_cancel(thread);
	/* remove from scheduling queue */
#if CONFIG_LIBUKSCHED_FIXED_SMP
	{
		unsigned long flags;

		ukplat_spin_lock_irqsave(&sched->lock, flags);
		thread->flags |= UK_THREADF_EXITING;
		sched->thread_remove(sched, thread);
		UK_TAILQ_REMOVE(&sched->thread_list, thread, thread_list);
		ukplat_spin_unlock_irqrestore(&sched->lock, flags);
	}
#else
	uk_sched_thread_remove(thread);
#endif
	/* causes calling termination table */
	uk_thread_set_exited(thread);

	if (thread == uk_thread_current()) {
		/* enqueue thread for garbage collecting */
		uk_pr_debug("%p: thread %p (%s) on gc list\n",
			    sched, thread, thread->name ?
					   thread->name : "<unnamed>");
#if CONFIG_LIBUKSCHED_FIXED_SMP
		unsigned long flags;

		ukplat_spin_lock_irqsave(&sched->lock, flags);
		thread->sched = NULL;
		UK_TAILQ_INSERT_TAIL(&sched->exited_threads, thread,
				     thread_list);
		ukplat_spin_unlock_irqrestore(&sched->lock, flags);
#else
		UK_TAILQ_INSERT_TAIL(&sched->exited_threads, thread,
				     thread_list);
#endif

		/* leave this thread */
		sched->yield(sched); /* we won't return */
		UK_CRASH("Unexpectedly returned to exited thread %p\n", thread);
	} else {
		/* free thread resources immediately */
#if CONFIG_LIBUKSCHED_FIXED_SMP
		unsigned long flags;

		ukplat_spin_lock_irqsave(&sched->lock, flags);
		thread->sched = NULL;
		ukplat_spin_unlock_irqrestore(&sched->lock, flags);
#endif
		uk_thread_release(thread);
	}
}

/* This function has the __noreturn attribute set */
void uk_sched_thread_exit2(uk_thread_gc_t gc_fn, void *gc_argp)
{
	struct uk_thread *t = uk_thread_current();

	t->_gc_fn   = gc_fn;
	t->_gc_argp = gc_argp;
	uk_sched_thread_terminate(t);
	UK_CRASH("Unexpectedly returned to exited thread %p\n", t);
}

/* This function has the __noreturn attribute set */
void uk_sched_thread_exit(void)
{
	uk_sched_thread_exit2(NULL, NULL);
}

void uk_sched_thread_sleep(__nsec nsec)
{
	struct uk_thread *thread;

	thread = uk_thread_current();
	uk_thread_block_timeout(thread, nsec);
	uk_sched_yield();
}

int uk_sched_thread_add(struct uk_sched *s, struct uk_thread *t)
{
	unsigned long flags;
	int rc;

	UK_ASSERT(s);
	UK_ASSERT(t);
	UK_ASSERT(!t->sched);

#if CONFIG_LIBUKSCHED_FIXED_SMP
	ukplat_spin_lock_irqsave(&s->lock, flags);
#else
	flags = uk_lcpu_save_irqf();
#endif

	rc = s->thread_add(s, t);
	if (rc < 0)
		goto out;

	t->sched = s;
	UK_TAILQ_INSERT_TAIL(&s->thread_list, t, thread_list);
out:
#if CONFIG_LIBUKSCHED_FIXED_SMP
	ukplat_spin_unlock_irqrestore(&s->lock, flags);
	if (!rc && s->is_started &&
	    s->lcpu_idx != uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx)) {
		int kick_rc = uk_sched_kick_retry(
			s, UK_SCHED_KICK_RETRIES_DEFAULT);

		if (kick_rc)
			uk_pr_err("sched %p: runnable thread published, LCPU %u kick failed: %d\n",
				  s, s->lcpu_idx, kick_rc);
	}
#else
	uk_lcpu_restore_irqf(flags);
#endif
	return rc;
}

int uk_sched_thread_remove(struct uk_thread *t)
{
	unsigned long flags;
	struct uk_sched *s;

	UK_ASSERT(t);
	UK_ASSERT(t->sched);

	s = t->sched;
#if CONFIG_LIBUKSCHED_FIXED_SMP
	UK_ASSERT(s->lcpu_idx ==
		  uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx));
	ukplat_spin_lock_irqsave(&s->lock, flags);
#else
	flags = uk_lcpu_save_irqf();
#endif
	s->thread_remove(s, t);
	t->sched = NULL;
	UK_TAILQ_REMOVE(&s->thread_list, t, thread_list);
#if CONFIG_LIBUKSCHED_FIXED_SMP
	ukplat_spin_unlock_irqrestore(&s->lock, flags);
#else
	uk_lcpu_restore_irqf(flags);
#endif
	return 0;
}

UK_SYSCALL_R_DEFINE(int, sched_yield)
{
	uk_sched_yield();
	return 0;
}

void uk_sched_dumpk_threads(int klvl, struct uk_sched *s)
{
	struct uk_thread *t, *tmp;

	if (uk_sched_current() == s) {
		/* Let the scheduler update the thread execution time
		 * of the current thread with a forced context switch.
		 */
		uk_sched_yield();
	}

	uk_printk(klvl, "sched %p:\n", s);
	uk_sched_foreach_thread_safe(s, t, tmp) {
		uk_printk(klvl,
			  " + thread %p (%s), ctx: %p, "
			  "execution time: %"__PRInsec".%06"__PRInsec"s, "
			  "flags: %c%c%c%c%c\n",
			  t, t->name ? t->name : "<unnamed>",
			  &t->ctx,
			  ukarch_time_nsec_to_sec(t->exec_time),
			  ukarch_time_nsec_to_usec(t->exec_time) % 1000000,
			  (t->flags & UK_THREADF_RUNNABLE) ? 'R' : '-',
			  (t->flags & UK_THREADF_EXITED)   ? 'D' : '-',
			  (t->flags & UK_THREADF_ECTX)     ? 'E' : '-',
			  (t->flags & UK_THREADF_AUXSP)    ? 'A' : '-',
			  (t->flags & UK_THREADF_UKTLS)    ? 'T' : '-');
	}
}

UK_SYSCALL_R_DEFINE(int, sched_getaffinity, int, pid, long, cpusetsize,
						unsigned long*, mask)
{
	UK_WARN_STUBBED();
	/* NOTE: Some applications use this to get the count of CPUs,
	 *       and the result must be positive.
	 *       So just return CPU0 to make them run.
	 */
	UK_ASSERT(cpusetsize > 0);
	UK_ASSERT(mask);
	memset(mask, 0, cpusetsize);

	/* Set CPU0 */
	*mask = 1UL << 0;

	return cpusetsize;
}

UK_SYSCALL_R_DEFINE(int, sched_setaffinity, int, pid, long, cpusetsize,
						unsigned long*, mask)
{
	UK_WARN_STUBBED();
	return 0;
}

#define MEMBARRIER_SUPPORTED_CMDS (\
	MEMBARRIER_CMD_GLOBAL | \
	MEMBARRIER_CMD_GLOBAL_EXPEDITED | \
	MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED | \
	MEMBARRIER_CMD_PRIVATE_EXPEDITED | \
	MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED | \
	MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE | \
	MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE)

UK_LLSYSCALL_R_DEFINE(int, membarrier, int, cmd, unsigned int, flags,
		      int __unused, cpu_id)
{
	/*
	 * membarrier is intended as an optimized alternative to using SMP-safe
	 * memory barriers in threads that might run in parallel.
	 * In essence, it allows threads in the fast path to proceed without
	 * barriers, while providing a safe option to trigger a barrier between
	 * running threads on demand with the `membarrier` syscall.
	 * Only threads actively executing on different cores are affected,
	 * since sleeping threads are implicitly already "barriered".
	 *
	 * Without SMP support membarrier is a no-op, since only a single thread
	 * -- the one calling membarrier -- can run at one time.
	 * With SMP support, membarrier needs to force (a subset of) cores on
	 * the system to execute memory barriers.
	 */
	if (unlikely(flags))
		return -EINVAL;
	switch (cmd) {
	case MEMBARRIER_CMD_QUERY:
		return MEMBARRIER_SUPPORTED_CMDS;
	case MEMBARRIER_CMD_GLOBAL:
	case MEMBARRIER_CMD_GLOBAL_EXPEDITED:
	case MEMBARRIER_CMD_PRIVATE_EXPEDITED:
	case MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE:
		/* TODO: implement real cross-core barrier when SMP supported */
		return 0;
	case MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED:
	case MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED:
	case MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE:
		/* Registrations not supported; no-op */
		return 0;
	default:
		return -EINVAL;
	}
}
