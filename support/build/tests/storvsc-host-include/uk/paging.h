/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __STORVSC_HOST_PAGING_H__
#define __STORVSC_HOST_PAGING_H__
#include <uk/arch/types.h>
#define UK_PAGING_PADDR_INV UINT64_MAX
__paddr_t storvsc_host_virt_to_phys(__vaddr_t address);
static inline __paddr_t uk_paging_virt_to_phys(__vaddr_t address)
{
	return storvsc_host_virt_to_phys(address);
}
#endif
