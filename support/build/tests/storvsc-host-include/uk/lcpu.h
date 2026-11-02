/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __STORVSC_HOST_LCPU_H__
#define __STORVSC_HOST_LCPU_H__
int storvsc_host_irqs_disabled(void);
static inline int uk_lcpu_irqs_disabled(void)
{
	return storvsc_host_irqs_disabled();
}
#endif
