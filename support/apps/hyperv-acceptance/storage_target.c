/* SPDX-License-Identifier: BSD-3-Clause */
#include "storage_target.h"

#include <errno.h>
#include <string.h>

int hyperv_acceptance_storage_target_acquire(
	struct hyperv_acceptance_storage_target *target)
{
	struct uk_storvsc_inventory_snapshot inventory;
	struct uk_storvsc_inventory_snapshot final_inventory;
	struct uk_storvsc_target_snapshot candidate;
	struct uk_blkdev *expected;
	int rc;

	if (!target)
		return -EINVAL;
	memset(target, 0, sizeof(*target));
	rc = uk_storvsc_inventory_get(&inventory);
	if (rc)
		return rc;
	if (!inventory.count)
		return -ENODEV;
	expected = uk_blkdev_get(0);
	if (!expected)
		return -ENODEV;
	/* The acceptance contract designates the first registered disk as OS. */
	for (unsigned int index = 0; index < inventory.count; index++) {
		rc = uk_storvsc_target_get(index, &candidate);
		if (rc)
			return rc;
		if (candidate.topology_generation !=
		    inventory.topology_generation)
			return -ESTALE;
		if (candidate.mapping.blkdev_id == 0)
			target->snapshot = candidate;
	}
	if (!target->snapshot.size)
		return -ESTALE;
	rc = uk_storvsc_inventory_get(&final_inventory);
	if (rc)
		return rc;
	if (final_inventory.topology_generation !=
		    inventory.topology_generation ||
	    final_inventory.count != inventory.count)
		return -ESTALE;
	target->device = expected;
	target->inventory_count = inventory.count;
	rc = uk_storvsc_session_begin_read(
		&target->snapshot, &target->session);
	if (rc == -ENOTSUP ||
	    (rc == -EINVAL && !target->snapshot.mapping.vpd_length))
		return hyperv_acceptance_storage_target_validate(target);
	if (rc)
		goto fail;
	rc = hyperv_acceptance_storage_target_validate(target);
	if (!rc)
		return 0;
	(void)uk_storvsc_session_end(&target->session);
fail:
	memset(target, 0, sizeof(*target));
	return rc;
}

int hyperv_acceptance_storage_target_validate(
	const struct hyperv_acceptance_storage_target *target)
{
	struct uk_storvsc_inventory_snapshot inventory;
	struct uk_storvsc_target_snapshot current;
	int rc;

	if (!target || !target->device || !target->snapshot.size ||
	    !target->inventory_count)
		return -EINVAL;
	if (target->session.opaque[0]) {
		rc = uk_storvsc_session_validate(&target->session, &current);
		if (rc)
			return rc;
		return memcmp(&current, &target->snapshot, sizeof(current)) ?
		       -ESTALE : 0;
	}
	rc = uk_storvsc_inventory_get(&inventory);
	if (rc)
		return rc;
	if (inventory.topology_generation !=
		    target->snapshot.topology_generation ||
	    inventory.count != target->inventory_count)
		return -ESTALE;
	for (unsigned int index = 0; index < inventory.count; index++) {
		rc = uk_storvsc_target_get(index, &current);
		if (rc)
			return rc;
		if (current.mapping.blkdev_id ==
		    target->snapshot.mapping.blkdev_id)
			return memcmp(&current, &target->snapshot,
				      sizeof(current)) ? -ESTALE : 0;
	}
	return -ESTALE;
}

int hyperv_acceptance_storage_target_release(
	struct hyperv_acceptance_storage_target *target)
{
	int rc;

	if (!target)
		return -EINVAL;
	if (!target->session.opaque[0]) {
		memset(target, 0, sizeof(*target));
		return 0;
	}
	rc = uk_storvsc_session_end(&target->session);
	if (!rc)
		memset(target, 0, sizeof(*target));
	return rc;
}
