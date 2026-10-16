/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __STORVSC_HOST_ALLOC_H__
#define __STORVSC_HOST_ALLOC_H__
#include <sys/types.h>

struct uk_alloc_stats {
	ssize_t cur_mem_use;
	ssize_t max_mem_use;
	ssize_t cur_nb_allocs;
	ssize_t max_nb_allocs;
	ssize_t tot_nb_allocs;
	ssize_t tot_nb_frees;
	ssize_t cur_mem_free;
	ssize_t min_mem_free;
	ssize_t max_mem_free;
	ssize_t nb_enomem;
};

struct uk_alloc {
	int placeholder;
	struct uk_alloc_stats _stats;
};
struct uk_alloc *uk_alloc_get_default(void);
void *uk_palloc(struct uk_alloc *a, unsigned long num_pages);
void uk_pfree(struct uk_alloc *a, void *ptr, unsigned long num_pages);
#endif
