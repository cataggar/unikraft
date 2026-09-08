/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __UK_BOOT_SMP_H__
#define __UK_BOOT_SMP_H__

#include <uk/config.h>

#if CONFIG_LIBUKBOOT_FIXED_SMP
#include <uk/arch/types.h>
#include <uk/essentials.h>

struct uk_alloc;
struct uk_sched;
struct uk_lcpu;

unsigned int ukplat_lcpu_count(void);

int uk_boot_fixed_smp_prepare(struct uk_alloc *a, struct uk_alloc *sa,
			      struct uk_alloc *auxsa,
			      unsigned int lcpu_count);

void __noreturn uk_boot_fixed_smp_lcpu_entry(struct uk_lcpu *lcpu);

int uk_boot_fixed_smp_wait_online(const __u64 *indices,
				   unsigned int count);

void uk_boot_fixed_smp_rollback(const __u64 *indices,
				unsigned int count, int clean);
#endif

#endif /* __UK_BOOT_SMP_H__ */
