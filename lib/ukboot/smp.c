/* SPDX-License-Identifier: BSD-3-Clause */
#include <uk/config.h>

#if CONFIG_LIBUKBOOT_FIXED_SMP

#include <errno.h>
#include <uk/alloc.h>
#include <uk/assert.h>
#include <uk/boot/smp.h>
#include <uk/lcpu.h>
#include <uk/pcpuvar.h>
#include <uk/print.h>
#include <uk/sched.h>
#include <uk/schedcoop.h>
#include <uk/thread.h>

enum fixed_smp_boot_state {
	FIXED_SMP_UNUSED = 0,
	FIXED_SMP_PREPARED,
	FIXED_SMP_STARTING,
	FIXED_SMP_ONLINE,
	FIXED_SMP_ROLLED_BACK,
	FIXED_SMP_QUARANTINED
};

struct fixed_smp_boot_cpu {
	struct uk_sched *sched;
	struct uk_thread *bootstrap;
	unsigned int state;
	int error;
};

static struct fixed_smp_boot_cpu
	fixed_smp_cpus[CONFIG_UKPLAT_CPU_MAXCOUNT];

unsigned int __weak ukplat_lcpu_count(void)
{
	return 1;
}

int uk_boot_fixed_smp_prepare(struct uk_alloc *a, struct uk_alloc *sa,
			      struct uk_alloc *auxsa,
			      unsigned int lcpu_count)
{
	unsigned int i;
	unsigned int created = 0;

	if (lcpu_count < 2 || lcpu_count > CONFIG_UKPLAT_CPU_MAXCOUNT)
		return -ERANGE;

	for (i = 0; i < lcpu_count; ++i) {
		struct fixed_smp_boot_cpu *cpu = &fixed_smp_cpus[i];

		cpu->sched = uk_schedcoop_create_on(a, sa, auxsa, a, i);
		if (!cpu->sched)
			goto err_clean;
		created++;
		cpu->state = FIXED_SMP_PREPARED;
		if (i == 0)
			continue;

		cpu->bootstrap = uk_thread_create_container(
			a, NULL, 0, auxsa, 0, a, false,
			"fixed-ap-bootstrap", NULL, NULL);
		if (!cpu->bootstrap)
			goto err_clean;
	}
	return 0;

err_clean:
	while (created > 0) {
		struct fixed_smp_boot_cpu *cpu =
			&fixed_smp_cpus[--created];

		if (cpu->bootstrap)
			uk_thread_release(cpu->bootstrap);
		if (cpu->sched) {
			uk_sched_set_state(cpu->sched, UK_SCHED_ROLLED_BACK);
			uk_schedcoop_fixed_destroy(cpu->sched);
		}
		*cpu = (struct fixed_smp_boot_cpu){ 0 };
	}
	return -ENOMEM;
}

void __noreturn uk_boot_fixed_smp_lcpu_entry(struct uk_lcpu *lcpu)
{
	unsigned int idx = uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx);
	struct fixed_smp_boot_cpu *cpu;
	int rc;

	UK_ASSERT(idx > 0 && idx < CONFIG_UKPLAT_CPU_MAXCOUNT);
	UK_ASSERT(lcpu == uk_lcpu_get_current());
	cpu = &fixed_smp_cpus[idx];
	UK_ASSERT(cpu->state == FIXED_SMP_PREPARED);
	UK_ASSERT(cpu->sched && cpu->bootstrap);
	__atomic_store_n(&cpu->state, FIXED_SMP_STARTING, __ATOMIC_RELEASE);

	uk_lcpu_tlsp_set(cpu->bootstrap->tlsp);
	uk_lcpu_set_auxsp(cpu->bootstrap->auxsp);

	rc = uk_sched_start_thread(cpu->sched, cpu->bootstrap);
	if (unlikely(rc))
		goto err_halt;

	__atomic_store_n(&cpu->state, FIXED_SMP_ONLINE, __ATOMIC_RELEASE);
	uk_lcpu_startup_idle();
	uk_lcpu_enable_irq();

	/* The bootstrap context is retained but never resumed or reaped. */
	uk_thread_block(cpu->bootstrap);
	uk_sched_yield();
	UK_CRASH("Secondary bootstrap thread resumed unexpectedly\n");

err_halt:
	cpu->error = rc;
	uk_sched_set_state(cpu->sched, UK_SCHED_ROLLED_BACK);
	__atomic_store_n(&cpu->state, FIXED_SMP_ROLLED_BACK,
			 __ATOMIC_RELEASE);
	uk_lcpu_halt_error(rc);
}

int uk_boot_fixed_smp_wait_online(const __u64 *indices,
				   unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; ++i) {
		unsigned int idx = (unsigned int)indices[i];
		struct fixed_smp_boot_cpu *cpu;

		if (idx >= CONFIG_UKPLAT_CPU_MAXCOUNT)
			return -ERANGE;
		cpu = &fixed_smp_cpus[idx];
		if (__atomic_load_n(&cpu->state, __ATOMIC_ACQUIRE) !=
		    FIXED_SMP_ONLINE)
			return cpu->error ? cpu->error : -EIO;
		if (!cpu->sched ||
		    uk_sched_state(cpu->sched) != UK_SCHED_ONLINE)
			return -EIO;
	}
	return 0;
}

void uk_boot_fixed_smp_rollback(const __u64 *indices,
				unsigned int count, int clean)
{
	unsigned int i;

	UK_ASSERT(uk_lcpu_current_is_bsp());
	for (i = 0; i < count; ++i) {
		unsigned int idx = (unsigned int)indices[i];
		struct fixed_smp_boot_cpu *cpu;

		if (!idx || idx >= CONFIG_UKPLAT_CPU_MAXCOUNT)
			continue;
		cpu = &fixed_smp_cpus[idx];
		if (!cpu->sched)
			continue;
		if (!clean) {
			uk_sched_set_state(cpu->sched, UK_SCHED_QUARANTINED);
			__atomic_store_n(&cpu->state, FIXED_SMP_QUARANTINED,
					 __ATOMIC_RELEASE);
			continue;
		}

		uk_sched_set_state(cpu->sched, UK_SCHED_ROLLED_BACK);
		if (cpu->bootstrap) {
			cpu->bootstrap->sched = NULL;
			uk_thread_release(cpu->bootstrap);
		}
		uk_schedcoop_fixed_destroy(cpu->sched);
		*cpu = (struct fixed_smp_boot_cpu){ 0 };
	}
}

#endif /* CONFIG_LIBUKBOOT_FIXED_SMP */
