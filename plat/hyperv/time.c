/* SPDX-License-Identifier: BSD-3-Clause */
#include <hyperv/hyperv.h>
#include <stdint.h>
#include <uk/atomic.h>
#include <uk/plat/time.h>

#define HYPERV_100NS_TO_NS	100ULL

static __u64 hyperv_epoch_ns;
static __u64 hyperv_boot_ref;

unsigned long sched_have_pending_events;

void hyperv_clock_set_efi_epoch(__u64 epoch_ns)
{
	hyperv_epoch_ns = epoch_ns;
}

void ukplat_time_init(void)
{
	hyperv_boot_ref = hyperv_time_ref_count();
}

__nsec ukplat_monotonic_clock(void)
{
	return (hyperv_time_ref_count() - hyperv_boot_ref) *
	       HYPERV_100NS_TO_NS;
}

__nsec ukplat_wall_clock(void)
{
	return hyperv_epoch_ns + ukplat_monotonic_clock();
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
