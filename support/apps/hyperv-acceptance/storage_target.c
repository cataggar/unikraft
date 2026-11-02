/* SPDX-License-Identifier: BSD-3-Clause */
#include "storage_target.h"

#include <errno.h>
#include <string.h>

#include <uk/config.h>

#if defined(CONFIG_APPHYPERVACCEPTANCE_STORAGE_TOPOLOGY) && \
	CONFIG_APPHYPERVACCEPTANCE_STORAGE_TOPOLOGY
#include <inttypes.h>
#include <stdio.h>

#include <uk/alloc.h>
#include <uk/plat/time.h>
#include <uk/sched.h>
#endif

int hyperv_acceptance_storage_target_acquire(
	struct hyperv_acceptance_storage_target *target)
{
	struct uk_storvsc_inventory_snapshot inventory;
	struct uk_storvsc_inventory_snapshot final_inventory;
	struct uk_storvsc_target_snapshot candidate;
	struct uk_blkdev *expected = NULL;
	int rc;

	if (!target)
		return -EINVAL;
	memset(target, 0, sizeof(*target));
	rc = uk_storvsc_discovery_status();
	if (rc)
		return rc;
	rc = uk_storvsc_inventory_get(&inventory);
	if (rc)
		return rc;
	if (!inventory.count)
		return -ENODEV;
	/* The bounded smoke profile has one OS candidate at LUN 0. */
	for (unsigned int index = 0; index < inventory.count; index++) {
		rc = uk_storvsc_target_get(index, &candidate);
		if (rc)
			return rc;
		if (candidate.topology_generation !=
		    inventory.topology_generation)
			return -ESTALE;
		if (candidate.mapping.lun)
			continue;
		if (expected)
			return -EEXIST;
		expected = uk_blkdev_get(candidate.mapping.blkdev_id);
		if (!expected)
			return -ENODEV;
		if (!candidate.size)
			return -ESTALE;
		target->snapshot = candidate;
	}
	if (!expected)
		return -ENODEV;
	rc = uk_storvsc_discovery_status();
	if (rc)
		return rc;
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
	rc = uk_storvsc_discovery_status();
	if (rc)
		return rc;
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
		    target->snapshot.mapping.blkdev_id) {
			rc = uk_storvsc_discovery_status();
			if (rc)
				return rc;
			return memcmp(&current, &target->snapshot,
				      sizeof(current)) ? -ESTALE : 0;
		}
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

#if defined(CONFIG_APPHYPERVACCEPTANCE_STORAGE_TOPOLOGY) && \
	CONFIG_APPHYPERVACCEPTANCE_STORAGE_TOPOLOGY
#define TOPOLOGY_SECTOR_SIZE HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE
#define TOPOLOGY_READ_SECTORS 2U
#define TOPOLOGY_QUEUE_DEPTH 4U
#define TOPOLOGY_READ_TIMEOUT_NS (7ULL * 1000000000ULL)
#define TOPOLOGY_POLL_NS 10000000ULL

static _Alignas(4096) uint8_t topology_buffer[
	TOPOLOGY_READ_SECTORS * TOPOLOGY_SECTOR_SIZE];
static struct uk_blkreq topology_request;
static struct hyperv_acceptance_storage_target topology_target;
static int topology_request_owned;
static int topology_request_abandoned;
static int topology_session_quarantined;

static int topology_expected(
	struct hyperv_acceptance_persistence_expected expected[2])
{
	memset(expected, 0, 2 * sizeof(*expected));
	if (CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_SECTORS <= 0 ||
	    CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_SECTORS <= 0 ||
	    hyperv_acceptance_parse_hex_id(
		    CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_RUN_ID,
		    expected[0].run_id) ||
	    hyperv_acceptance_parse_hex_id(
		    CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_ID,
		    expected[0].disk_id) ||
	    hyperv_acceptance_parse_hex_id(
		    CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_ID,
		    expected[1].disk_id) ||
	    !memcmp(expected[0].disk_id, expected[1].disk_id,
		    sizeof(expected[0].disk_id)))
		return -EINVAL;
	memcpy(expected[1].run_id, expected[0].run_id,
	       sizeof(expected[0].run_id));
	expected[0].sectors =
		CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_SECTORS;
	expected[1].sectors =
		CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_SECTORS;
	expected[0].sector_size = TOPOLOGY_SECTOR_SIZE;
	expected[1].sector_size = TOPOLOGY_SECTOR_SIZE;
	expected[1].lun = CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_NONZERO_LUN;
	expected[0].identity_policy =
		HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2;
	expected[1].identity_policy =
		HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2;
	for (unsigned int i = 0; i < 2; i++) {
		uint8_t manifest[TOPOLOGY_SECTOR_SIZE];

		if (hyperv_acceptance_persistence_build_manifest(
			    &expected[i], manifest))
			return -EINVAL;
	}
	return 0;
}

static int topology_configure(struct uk_blkdev *device)
{
	struct uk_blkdev_conf config = { .nb_queues = 1 };
	struct uk_blkdev_queue_conf queue = { 0 };
	int rc;

	if (uk_blkdev_state_get(device) == UK_BLKDEV_RUNNING)
		return 0;
	if (uk_blkdev_state_get(device) != UK_BLKDEV_UNCONFIGURED)
		return -EINVAL;
	rc = uk_blkdev_configure(device, &config);
	if (rc)
		return rc;
	queue.a = uk_alloc_get_default();
	if (!queue.a)
		return -ENOMEM;
	rc = uk_blkdev_queue_configure(
		device, 0, TOPOLOGY_QUEUE_DEPTH, &queue);
	if (rc)
		return rc;
	return uk_blkdev_start(device);
}

static int topology_read(struct uk_blkdev *device, uint64_t sector)
{
	uint64_t deadline;
	int finish_error = 0;
	int status;
	int rc;

	if (topology_request_abandoned)
		return -ESHUTDOWN;
	if (topology_request_owned)
		return -EBUSY;
	memset(topology_buffer, 0, sizeof(topology_buffer));
	uk_blkreq_init(&topology_request, UK_BLKREQ_READ, sector,
		       TOPOLOGY_READ_SECTORS, topology_buffer, NULL, NULL);
	status = uk_blkdev_queue_submit_one(device, 0, &topology_request);
	if (status < 0 || !(status & UK_BLKDEV_STATUS_SUCCESS))
		return status < 0 ? status : -EIO;
	topology_request_owned = 1;
	deadline = ukplat_monotonic_clock() + TOPOLOGY_READ_TIMEOUT_NS;
	while (!uk_blkreq_is_done(&topology_request) &&
	       ukplat_monotonic_clock() < deadline) {
		rc = uk_blkdev_queue_finish_reqs(device, 0);
		if (rc && !finish_error)
			finish_error = rc;
		if (!uk_blkreq_is_done(&topology_request))
			uk_sched_thread_sleep(TOPOLOGY_POLL_NS);
	}
	if (!uk_blkreq_is_done(&topology_request)) {
		topology_request_abandoned = 1;
		return -ETIMEDOUT;
	}
	topology_request_owned = 0;
	if (topology_request.result)
		return topology_request.result;
	return finish_error;
}

static int topology_read_target(
	const struct uk_storvsc_target_snapshot *snapshot,
	unsigned int inventory_count,
	const struct hyperv_acceptance_persistence_expected expected[2],
	unsigned int found[3])
{
	const struct uk_storvsc_mapping *mapping = &snapshot->mapping;
	const struct uk_blkdev_cap *capabilities;
	uint8_t manifest[TOPOLOGY_SECTOR_SIZE];
	int role = -1;
	int rc;
	int release_rc;
	int mbr;
	int gpt;

	memset(&topology_target, 0, sizeof(topology_target));
	topology_target.snapshot = *snapshot;
	topology_target.inventory_count = inventory_count;
	topology_target.device = uk_blkdev_get(mapping->blkdev_id);
	if (!topology_target.device || !snapshot->size ||
	    !mapping->vpd_length ||
	    mapping->vpd_length > UK_STORVSC_VPD_ID_MAX)
		return -ENODEV;
	rc = uk_storvsc_session_begin_read(
		snapshot, &topology_target.session);
	if (rc)
		return rc;
	rc = topology_configure(topology_target.device);
	if (rc)
		goto out;
#ifdef STORVSC_HOST_TEST
	capabilities = &topology_target.device->capabilities;
#else
	capabilities = uk_blkdev_capabilities(topology_target.device);
#endif
	if (!capabilities ||
	    capabilities->sectors != mapping->sectors ||
	    capabilities->ssize != TOPOLOGY_SECTOR_SIZE ||
	    mapping->sector_size != TOPOLOGY_SECTOR_SIZE ||
	    capabilities->ioalign > 4096 ||
	    capabilities->max_sectors_per_req < TOPOLOGY_READ_SECTORS ||
	    capabilities->sectors <=
		    HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_LBA +
			    HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS) {
		rc = -EINVAL;
		goto out;
	}
	rc = topology_read(topology_target.device, 0);
	if (rc)
		goto out;
	mbr = hyperv_acceptance_has_mbr_signature(
		topology_buffer, TOPOLOGY_SECTOR_SIZE);
	gpt = hyperv_acceptance_has_gpt_signature(
		topology_buffer + TOPOLOGY_SECTOR_SIZE,
		TOPOLOGY_SECTOR_SIZE);
	printf("HYPERV_TOPOLOGY TARGET INFO id=%" PRIu16
	       " controller=%" PRIu16 " channel=%" PRIu32
	       " address=%u:%u:%u sectors=%" PRIu64
	       " sector_size=%u instance_crc32=%08" PRIx32
	       " vpd_length=%u vpd_crc32=%08" PRIx32 "\n",
	       mapping->blkdev_id, mapping->controller_index,
	       mapping->channel_id, mapping->path_id, mapping->target_id,
	       mapping->lun, mapping->sectors, mapping->sector_size,
	       hyperv_acceptance_persistence_crc32(
		       mapping->instance_id, sizeof(mapping->instance_id)),
	       mapping->vpd_length,
	       hyperv_acceptance_persistence_crc32(
		       mapping->vpd_id, mapping->vpd_length));
	if (mbr || gpt) {
		if (!mbr || !gpt || mapping->lun || found[0]) {
			rc = -EEXIST;
			goto out;
		}
		found[0]++;
		printf("HYPERV_TOPOLOGY OS_READ PASS id=%" PRIu16
		       " controller=%" PRIu16 " channel=%" PRIu32
		       " lun=0 bytes=%u mbr=1 gpt=1\n",
		       mapping->blkdev_id, mapping->controller_index,
		       mapping->channel_id,
		       TOPOLOGY_READ_SECTORS * TOPOLOGY_SECTOR_SIZE);
	} else {
		for (unsigned int i = 0; i < 2; i++) {
			if (mapping->lun == expected[i].lun &&
			    mapping->sectors == expected[i].sectors) {
				role = (int)i;
				break;
			}
		}
		if (role < 0) {
			printf("HYPERV_TOPOLOGY TARGET SKIP id=%" PRIu16
			       " reason=outside-seeded-geometry\n",
			       mapping->blkdev_id);
			goto out;
		}
		if (found[role + 1]) {
			rc = -EEXIST;
			goto out;
		}
		rc = topology_read(
			topology_target.device,
			HYPERV_ACCEPTANCE_PERSISTENCE_SEED0_LBA);
		if (rc)
			goto out;
		rc = hyperv_acceptance_persistence_build_manifest(
			&expected[role], manifest);
		if (rc || memcmp(topology_buffer, manifest, sizeof(manifest)) ||
		    memcmp(topology_buffer + sizeof(manifest), manifest,
			   sizeof(manifest))) {
			rc = -EILSEQ;
			goto out;
		}
		found[role + 1]++;
		printf("HYPERV_TOPOLOGY DATA_READ PASS role=%u"
		       " id=%" PRIu16 " controller=%" PRIu16
		       " channel=%" PRIu32 " address=%u:%u:%u"
		       " sectors=%" PRIu64 " bytes=%u"
		       " seed_crc32=%08" PRIx32 "\n",
		       (unsigned int)role, mapping->blkdev_id,
		       mapping->controller_index, mapping->channel_id,
		       mapping->path_id, mapping->target_id, mapping->lun,
		       mapping->sectors,
		       TOPOLOGY_READ_SECTORS * TOPOLOGY_SECTOR_SIZE,
		       hyperv_acceptance_persistence_crc32(
			       topology_buffer, sizeof(topology_buffer)));
	}
	rc = hyperv_acceptance_storage_target_validate(&topology_target);
out:
	if (topology_request_owned) {
		printf("HYPERV_TOPOLOGY TARGET FAIL reason=request-owned rc=%d\n",
		       rc);
		return rc;
	}
	release_rc = hyperv_acceptance_storage_target_release(
		&topology_target);
	if (release_rc) {
		topology_session_quarantined = 1;
		printf("HYPERV_TOPOLOGY TARGET FAIL reason=session-end rc=%d\n",
		       release_rc);
		return release_rc;
	}
	return rc;
}

enum hyperv_acceptance_result hyperv_acceptance_storage_topology_probe(
	unsigned int storage_offers, int binding_ready, int discovery_error)
{
	struct hyperv_acceptance_persistence_expected expected[2];
	struct uk_storvsc_inventory_snapshot inventory;
	struct uk_storvsc_inventory_snapshot final_inventory;
	unsigned int found[3] = { 0 };
	int rc;

	if (topology_request_abandoned || topology_session_quarantined ||
	    topology_request_owned ||
	    topology_target.session.opaque[0]) {
		if (topology_request_abandoned && topology_request_owned &&
		    uk_blkreq_is_done(&topology_request))
			topology_request_owned = 0;
		if (!topology_request_owned && topology_target.session.opaque[0])
			(void)hyperv_acceptance_storage_target_release(
				&topology_target);
		puts("HYPERV_TOPOLOGY FINAL FAIL reason=session-quarantined");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	rc = topology_expected(expected);
	if (rc) {
		puts("HYPERV_TOPOLOGY FINAL FAIL reason=invalid-expectation");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (discovery_error && discovery_error != -EAGAIN) {
		printf("HYPERV_TOPOLOGY FINAL FAIL reason=discovery rc=%d\n",
		       discovery_error);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (!binding_ready) {
		puts("HYPERV_TOPOLOGY FINAL FAIL reason=binding-timeout");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	rc = uk_storvsc_discovery_status();
	if (!rc)
		rc = uk_storvsc_inventory_get(&inventory);
	if (rc) {
		printf("HYPERV_TOPOLOGY FINAL FAIL reason=inventory rc=%d\n",
		       rc);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (inventory.count >
	    CONFIG_LIBSTORVSC_MAX_DEVICES * CONFIG_LIBSTORVSC_MAX_LUNS) {
		puts("HYPERV_TOPOLOGY FINAL FAIL reason=inventory-overflow");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (!inventory.count) {
		if (storage_offers) {
			puts("HYPERV_TOPOLOGY FINAL FAIL reason=offered-unbound");
			return HYPERV_ACCEPTANCE_FAIL;
		}
		rc = uk_storvsc_inventory_get(&final_inventory);
		if (rc || !uk_storvsc_inventory_pristine_empty(
				    &inventory, &final_inventory)) {
			puts("HYPERV_TOPOLOGY FINAL FAIL reason=unproven-empty");
			return HYPERV_ACCEPTANCE_FAIL;
		}
		puts("HYPERV_TOPOLOGY FINAL UNAVAILABLE reason=no-devices");
		return HYPERV_ACCEPTANCE_UNAVAILABLE;
	}
	if (!storage_offers) {
		puts("HYPERV_TOPOLOGY FINAL FAIL reason=unoffered-mappings");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	for (unsigned int index = 0; index < inventory.count; index++) {
		struct uk_storvsc_target_snapshot snapshot;

		rc = uk_storvsc_target_get(index, &snapshot);
		if (!rc && snapshot.topology_generation !=
				   inventory.topology_generation)
			rc = -ESTALE;
		if (!rc)
			rc = topology_read_target(
				&snapshot, inventory.count, expected, found);
		if (rc) {
			printf("HYPERV_TOPOLOGY FINAL FAIL index=%u rc=%d\n",
			       index, rc);
			return HYPERV_ACCEPTANCE_FAIL;
		}
	}
	rc = uk_storvsc_discovery_status();
	if (!rc)
		rc = uk_storvsc_inventory_get(&final_inventory);
	if (rc ||
	    final_inventory.topology_generation !=
		    inventory.topology_generation ||
	    final_inventory.count != inventory.count ||
	    found[0] != 1 || found[1] != 1 || found[2] != 1) {
		printf("HYPERV_TOPOLOGY FINAL FAIL reason=missing-or-changed"
		       " rc=%d os=%u data0=%u data_nonzero=%u\n",
		       rc, found[0], found[1], found[2]);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	printf("HYPERV_TOPOLOGY FINAL PASS devices=%u os=1 data0=1"
	       " data_nonzero=1\n", inventory.count);
	puts("UK_HYPERV_TOPOLOGY_READ_OK");
	return HYPERV_ACCEPTANCE_PASS;
}
#endif
