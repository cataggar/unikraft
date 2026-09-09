/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef HYPERV_ACCEPTANCE_STORAGE_TARGET_H
#define HYPERV_ACCEPTANCE_STORAGE_TARGET_H

#include <uk/blkdev.h>
#include <uk/storvsc.h>

struct hyperv_acceptance_storage_target {
	struct uk_storvsc_target_snapshot snapshot;
	struct uk_storvsc_session session;
	struct uk_blkdev *device;
	unsigned int inventory_count;
};

int hyperv_acceptance_storage_target_acquire(
	struct hyperv_acceptance_storage_target *target);
int hyperv_acceptance_storage_target_validate(
	const struct hyperv_acceptance_storage_target *target);
int hyperv_acceptance_storage_target_release(
	struct hyperv_acceptance_storage_target *target);

#endif
