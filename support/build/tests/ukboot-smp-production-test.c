/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>

#include <uk/alloc.h>
#include <uk/boot/smp.h>
#include <uk/lcpu.h>
#include <uk/sched.h>
#include <uk/thread.h>

unsigned int ukboot_host_cpu_idx;

static struct uk_alloc allocator;
static struct uk_sched schedulers[4];
static struct uk_thread bootstraps[4];
static struct uk_lcpu lcpus[4];
static unsigned int scheduler_creates;
static unsigned int bootstrap_creates;
static unsigned int bootstrap_releases;
static unsigned int scheduler_destroys;
static unsigned int tls_sets;
static unsigned int auxsp_sets;
static unsigned int idle_publishes;
static unsigned int irq_enables;
static unsigned int blocks;
static int scheduler_backing_live[4];
static int lcpu_reported_halted[4];
static int start_error[4];
static jmp_buf ap_exit;
static int ap_halt_error;

struct uk_sched *uk_schedcoop_create_on(struct uk_alloc *a,
					struct uk_alloc *sa,
					struct uk_alloc *auxsa,
					struct uk_alloc *tls_a,
					unsigned int idx)
{
	assert(ukboot_host_cpu_idx == 0);
	assert(a == &allocator && sa == &allocator);
	assert(auxsa == &allocator && tls_a == &allocator);
	schedulers[idx].lcpu_idx = idx;
	schedulers[idx].state = UK_SCHED_PREPARED;
	scheduler_creates++;
	return &schedulers[idx];
}

void uk_schedcoop_fixed_destroy(struct uk_sched *sched)
{
	assert(ukboot_host_cpu_idx == 0);
	assert(sched->state == UK_SCHED_ROLLED_BACK);
	assert(!scheduler_backing_live[sched->lcpu_idx]);
	scheduler_destroys++;
}

struct uk_thread *uk_thread_create_container(
	struct uk_alloc *a, struct uk_alloc *sa, size_t stack_len,
	struct uk_alloc *auxsa, size_t auxstack_len, struct uk_alloc *tls_a,
	bool no_ectx, const char *name, void *priv, void *dtor)
{
	unsigned int idx = bootstrap_creates + 1;

	assert(ukboot_host_cpu_idx == 0);
	assert(a == &allocator && !sa && !stack_len);
	assert(auxsa == &allocator && !auxstack_len && tls_a == &allocator);
	assert(!no_ectx && name && !priv && !dtor);
	bootstraps[idx].tlsp = 0x1000U + idx;
	bootstraps[idx].auxsp = 0x2000U + idx;
	bootstrap_creates++;
	return &bootstraps[idx];
}

void uk_thread_release(struct uk_thread *thread)
{
	assert(ukboot_host_cpu_idx == 0);
	assert(!thread->sched);
	bootstrap_releases++;
}

int uk_sched_start_thread(struct uk_sched *sched, struct uk_thread *thread)
{
	assert(ukboot_host_cpu_idx == sched->lcpu_idx);
	if (start_error[sched->lcpu_idx])
		return start_error[sched->lcpu_idx];
	thread->sched = sched;
	sched->state = UK_SCHED_ONLINE;
	return 0;
}

unsigned int uk_sched_state(const struct uk_sched *sched)
{
	return sched->state;
}

void uk_sched_set_state(struct uk_sched *sched, unsigned int state)
{
	sched->state = state;
}

struct uk_lcpu *uk_lcpu_get_current(void)
{
	return &lcpus[ukboot_host_cpu_idx];
}

int uk_lcpu_current_is_bsp(void)
{
	return ukboot_host_cpu_idx == 0;
}

void uk_lcpu_tlsp_set(uintptr_t tlsp)
{
	assert(tlsp == bootstraps[ukboot_host_cpu_idx].tlsp);
	tls_sets++;
}

void uk_lcpu_set_auxsp(uintptr_t auxsp)
{
	assert(auxsp == bootstraps[ukboot_host_cpu_idx].auxsp);
	auxsp_sets++;
}

void uk_lcpu_startup_idle(void)
{
	idle_publishes++;
}

void uk_lcpu_enable_irq(void)
{
	irq_enables++;
}

void uk_thread_block(struct uk_thread *thread)
{
	assert(thread == &bootstraps[ukboot_host_cpu_idx]);
	blocks++;
}

void uk_sched_yield(void)
{
	scheduler_backing_live[ukboot_host_cpu_idx] = 1;
	longjmp(ap_exit, 1);
}

void uk_lcpu_halt_error(int error)
{
	ap_halt_error = error;
	longjmp(ap_exit, 2);
}

static void run_ap(unsigned int idx, int expected_exit)
{
	int exit_reason;

	ukboot_host_cpu_idx = idx;
	exit_reason = setjmp(ap_exit);
	if (!exit_reason)
		uk_boot_fixed_smp_lcpu_entry(&lcpus[idx]);
	assert(exit_reason == expected_exit);
	lcpu_reported_halted[idx] = 1;
	ukboot_host_cpu_idx = 0;
}

int main(void)
{
	const __u64 cpus[] = { 1, 2, 3 };
	unsigned int creates;

	for (unsigned int i = 0; i < 4; i++)
		lcpus[i].idx = i;
	assert(uk_boot_fixed_smp_prepare(&allocator, &allocator,
					 &allocator, 4) == 0);
	assert(scheduler_creates == 4);
	assert(bootstrap_creates == 3);

	run_ap(1, 1);
	assert(tls_sets == 1 && auxsp_sets == 1);
	assert(idle_publishes == 1 && irq_enables == 1 && blocks == 1);
	assert(lcpu_reported_halted[1] && scheduler_backing_live[1]);
	assert(uk_boot_fixed_smp_wait_online(cpus, 1) == 0);

	/*
	 * CPUs 1 and 2 were attempted. CPU 1 has reported HALTED while still
	 * retaining scheduler backing; CPU 2 may arrive late. CPU 3 was never
	 * attempted and is the only safe release.
	 */
	uk_boot_fixed_smp_rollback(cpus, 3, 2);
	assert(schedulers[1].state == UK_SCHED_QUARANTINED);
	assert(schedulers[2].state == UK_SCHED_QUARANTINED);
	assert(bootstrap_releases == 1);
	assert(scheduler_destroys == 1);

	/* A late attempted AP is rejected without switching to freed backing. */
	run_ap(2, 2);
	assert(ap_halt_error == -ECANCELED);
	assert(tls_sets == 1 && auxsp_sets == 1);
	assert(!scheduler_backing_live[2]);

	/* Quarantine and never-started cleanup are idempotent. */
	uk_boot_fixed_smp_rollback(cpus, 3, 2);
	assert(bootstrap_releases == 1);
	assert(scheduler_destroys == 1);

	/* Retained ownership prevents an unbounded second allocation set. */
	creates = scheduler_creates;
	assert(uk_boot_fixed_smp_prepare(&allocator, &allocator,
					 &allocator, 4) == -EBUSY);
	assert(scheduler_creates == creates);
	return 0;
}
