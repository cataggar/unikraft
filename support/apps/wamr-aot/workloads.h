/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef WAMR_UNIKRAFT_WORKLOADS_H
#define WAMR_UNIKRAFT_WORKLOADS_H

#include "platform.h"

struct wamr_workload_facts {
	const char *revision;
	const char *source_tree_sha256;
	const char *runtime_sha256;
	const char *compiler_sha256;
};

struct wamr_workload_pages {
	size_t reserved_bytes;
	size_t frame_bytes;
	size_t accessible_bytes;
	size_t allocation_bytes;
};

void wamr_workload_observe(void *, struct wamr_workload_pages *);
int wamr_workload_write(const uint8_t *, size_t);
int wamr_workload_run(const wamr_aot_config *,
		     const struct wamr_workload_facts *, unsigned int);
int wamr_workload_main(int, char **);

#endif
