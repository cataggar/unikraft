/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef WAMR_UNIKRAFT_PLATFORM_H
#define WAMR_UNIKRAFT_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <wamr_aot.h>

struct uk_alloc;
struct uk_vas;
struct uk_pagetable;
struct wamr_mapping;

/* Caller-owned, single-CPU, non-reentrant state. Metadata is not page storage. */
struct wamr_platform {
	struct uk_alloc *allocator;
	struct uk_vas *vas;
	struct uk_pagetable *pt;
	struct wamr_mapping *mappings;
	size_t reserved_bytes;
	size_t frame_bytes;       /* Includes frames hidden by NONE. */
	size_t accessible_bytes;
	size_t allocation_bytes;  /* Requested runtime/adapter allocator bytes. */
};

int wamr_platform_config(struct wamr_platform *, struct uk_alloc *,
			 wamr_aot_config *);
int wamr_platform_selftest(struct wamr_platform *, wamr_aot_config *);
int wamr_platform_permissions(struct wamr_platform *, const void *, uint32_t);

#endif
