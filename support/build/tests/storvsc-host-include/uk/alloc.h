/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __STORVSC_HOST_ALLOC_H__
#define __STORVSC_HOST_ALLOC_H__
struct uk_alloc {
	int placeholder;
};
struct uk_alloc *uk_alloc_get_default(void);
#endif
