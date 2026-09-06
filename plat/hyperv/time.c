/* SPDX-License-Identifier: BSD-3-Clause */
#include <hyperv/hyperv.h>
#include <hyperv/clock.h>
#include <stdint.h>
#include <uk/atomic.h>
#include <uk/plat/time.h>

static __u64 hyperv_epoch_ns;
/* Paired with hyperv_epoch_ns before ExitBootServices. */
static __u64 hyperv_efi_ref;
/* Keeps the public monotonic clock anchored at ukplat_time_init(). */
static __u64 hyperv_boot_ref;

unsigned long sched_have_pending_events;

void hyperv_clock_set_efi_sample(__u64 epoch_ns, __u64 reference_time)
{
	hyperv_epoch_ns = epoch_ns;
	hyperv_efi_ref = reference_time;
}

void ukplat_time_init(void)
{
	hyperv_boot_ref = hyperv_time_ref_count();
}

__nsec ukplat_monotonic_clock(void)
{
	return hyperv_reference_delta_ns(hyperv_time_ref_count(),
					 hyperv_boot_ref);
}

__nsec ukplat_wall_clock(void)
{
	return hyperv_wall_time_ns(hyperv_epoch_ns, hyperv_efi_ref,
				    hyperv_time_ref_count());
}

void ukplat_time_fini(void)
{
}

__u32 ukplat_time_get_irq(void)
{
	return UINT32_MAX;
}

void time_block_until(__snsec until)
{
	while ((__snsec)ukplat_monotonic_clock() < until) {
		if (uk_and_relax(&sched_have_pending_events, 0))
			break;
		__asm__ __volatile__("pause" ::: "memory");
	}
}
