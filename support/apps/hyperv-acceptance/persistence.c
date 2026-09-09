/* SPDX-License-Identifier: BSD-3-Clause */
#include "acceptance_protocol.h"
#include "persistence.h"
#include "persistence_host.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <uk/alloc.h>
#include <uk/blkdev.h>
#include <uk/config.h>
#include <uk/plat/time.h>
#include <uk/sched.h>
#include <uk/storvsc.h>

#define PERSISTENCE_QUEUE_DEPTH 4U
#ifndef PERSISTENCE_TIMEOUT_NS
#define PERSISTENCE_TIMEOUT_NS (7ULL * 1000000000ULL)
#endif
#ifndef PERSISTENCE_BIND_TIMEOUT_NS
#define PERSISTENCE_BIND_TIMEOUT_NS (3ULL * 1000000000ULL)
#endif
#ifndef PERSISTENCE_POLL_NS
#define PERSISTENCE_POLL_NS 10000000ULL
#endif
#ifndef CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_PATH
#define CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_PATH 0
#endif
#ifndef CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_TARGET
#define CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_TARGET 0
#endif

struct persistence_candidate {
	struct uk_storvsc_target_snapshot target;
	struct uk_storvsc_session session;
	struct uk_blkdev *device;
	enum hyperv_acceptance_persistence_state state;
	struct hyperv_acceptance_persistence_identity identity;
	struct hyperv_acceptance_persistence_checksums checksums;
	uint8_t intent[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t receipt[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
};

enum persistence_selection_class {
	PERSISTENCE_SELECTION_ERROR,
	PERSISTENCE_SELECTION_FOUND,
	PERSISTENCE_SELECTION_PRISTINE_EMPTY,
};

static _Alignas(4096) uint8_t persistence_buffer[
	HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS *
	HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
static _Alignas(4096) uint8_t persistence_verify[
	HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS *
	HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
static struct uk_blkreq persistence_request;
static struct persistence_candidate persistence_selected;
static int persistence_request_owned;
static int persistence_request_abandoned;
#ifdef HYPERV_PERSISTENCE_HOST_TEST
static unsigned int persistence_host_identity_policy;
#endif

static void persistence_queue_event(struct uk_blkdev *device,
				    uint16_t queue_id, void *cookie)
{
	(void)cookie;
	(void)uk_blkdev_queue_finish_reqs(device, queue_id);
}

#ifndef HYPERV_PERSISTENCE_HOST_TEST
static inline void hyperv_persistence_host_event(
	enum hyperv_persistence_host_event event,
	unsigned int index, int value)
{
	(void)event;
	(void)index;
	(void)value;
}
#endif

static int persistence_hex_id(const char *text, uint8_t output[16])
{
	for (unsigned int i = 0; i < 16; i++) {
		unsigned int high;
		unsigned int low;
		char a = text[i * 2];
		char b = text[i * 2 + 1];

		if (!a || !b)
			return -EINVAL;
		high = a >= '0' && a <= '9' ? (unsigned int)(a - '0') :
		       a >= 'a' && a <= 'f' ?
			       (unsigned int)(a - 'a' + 10) : 16;
		low = b >= '0' && b <= '9' ? (unsigned int)(b - '0') :
		      b >= 'a' && b <= 'f' ?
			      (unsigned int)(b - 'a' + 10) : 16;
		if (high > 15 || low > 15)
			return -EINVAL;
		output[i] = (uint8_t)(high << 4 | low);
	}
	return text[32] ? -EINVAL : 0;
}

static void persistence_print_run(const uint8_t run_id[16])
{
	for (unsigned int i = 0; i < 16; i++)
		printf("%02x", run_id[i]);
}

static void persistence_print_hex(const uint8_t *bytes, size_t length)
{
	for (size_t i = 0; i < length; i++)
		printf("%02x", bytes[i]);
}

static int persistence_expected(
	struct hyperv_acceptance_persistence_expected *expected)
{
	memset(expected, 0, sizeof(*expected));
	if (persistence_hex_id(
		    CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID,
		    expected->run_id) ||
	    persistence_hex_id(
		    CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_DISK_ID,
		    expected->disk_id))
		return -EINVAL;
	expected->sectors =
		CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTORS;
	expected->sector_size =
		CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTOR_SIZE;
	expected->path_id = CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_PATH;
	expected->target_id = CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_TARGET;
	expected->lun = CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_LUN;
	expected->identity_policy =
		CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY;
#ifdef HYPERV_PERSISTENCE_HOST_TEST
	if (persistence_host_identity_policy)
		expected->identity_policy = persistence_host_identity_policy;
#endif
	return expected->sector_size ==
			       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE &&
		       expected->sectors >
			       HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_LBA +
			       HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS &&
		       (expected->identity_policy ==
				HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_ADDRESS_V1 ||
			expected->identity_policy ==
				HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2) ?
		       0 : -EINVAL;
}

static int persistence_configure(struct uk_blkdev *device)
{
	struct uk_blkdev_queue_conf queue = {
		.callback = persistence_queue_event
	};
	struct uk_blkdev_conf config = { .nb_queues = 1 };
	struct uk_alloc *allocator;
	int rc;

	if (uk_blkdev_state_get(device) == UK_BLKDEV_RUNNING)
		return 0;
	if (uk_blkdev_state_get(device) != UK_BLKDEV_UNCONFIGURED)
		return -EINVAL;
	rc = uk_blkdev_configure(device, &config);
	if (rc)
		return rc;
	allocator = uk_alloc_get_default();
	if (!allocator)
		return -ENOMEM;
	queue.a = allocator;
	rc = uk_blkdev_queue_configure(
		device, 0, PERSISTENCE_QUEUE_DEPTH, &queue);
	if (rc)
		return rc;
	rc = uk_blkdev_start(device);
	if (rc)
		return rc;
	return uk_blkdev_queue_intr_enable(device, 0);
}

static int persistence_io(struct uk_blkdev *device, int operation,
			  uint64_t sector, uint64_t count, void *buffer)
{
	uint64_t deadline;
	int finish_error = 0;
	int status;
	int rc;

	if (persistence_request_abandoned)
		return -ESHUTDOWN;
	if (persistence_request_owned)
		return -EBUSY;
	uk_blkreq_init(&persistence_request, operation, sector, count,
		       buffer, NULL, NULL);
	status = uk_blkdev_queue_submit_one(device, 0, &persistence_request);
	if (status < 0 || !(status & UK_BLKDEV_STATUS_SUCCESS))
		return status < 0 ? status : -EIO;
	persistence_request_owned = 1;
	deadline = ukplat_monotonic_clock() + PERSISTENCE_TIMEOUT_NS;
	while (!uk_blkreq_is_done(&persistence_request) &&
	       ukplat_monotonic_clock() < deadline) {
		rc = uk_blkdev_queue_finish_reqs(device, 0);
		if (rc && !finish_error)
			finish_error = rc;
		if (!uk_blkreq_is_done(&persistence_request))
			uk_sched_thread_sleep(PERSISTENCE_POLL_NS);
	}
	if (!uk_blkreq_is_done(&persistence_request)) {
		persistence_request_abandoned = 1;
		hyperv_persistence_host_event(
			HYPERV_PERSISTENCE_HOST_IO_TIMEOUT, 0, operation);
		return -ETIMEDOUT;
	}
	persistence_request_owned = 0;
	if (persistence_request.result)
		return persistence_request.result;
	return finish_error;
}

static int persistence_read(struct uk_blkdev *device, uint64_t sector,
			    uint64_t count, void *buffer)
{
	return persistence_io(
		device, UK_BLKREQ_READ, sector, count, buffer);
}

static int persistence_write(struct uk_blkdev *device, uint64_t sector,
			     uint64_t count, void *buffer)
{
	return persistence_io(
		device, UK_BLKREQ_WRITE, sector, count, buffer);
}

static int persistence_flush(struct uk_blkdev *device)
{
	return persistence_io(device, UK_BLKREQ_FFLUSH, 0, 0, NULL);
}

static void persistence_identity(
	const struct uk_storvsc_mapping *mapping,
	struct hyperv_acceptance_persistence_identity *identity)
{
	memset(identity, 0, sizeof(*identity));
	memcpy(identity->controller_instance, mapping->instance_id,
	       sizeof(identity->controller_instance));
	identity->path_id = mapping->path_id;
	identity->target_id = mapping->target_id;
	identity->lun = mapping->lun;
	identity->vpd_length = mapping->vpd_length;
	identity->vpd_code_set = mapping->vpd_code_set;
	identity->vpd_designator_type = mapping->vpd_designator_type;
	identity->vpd_association = mapping->vpd_association;
	memcpy(identity->vpd_id, mapping->vpd_id, mapping->vpd_length);
}

static int persistence_snapshot_in_scope(
	const struct uk_storvsc_target_snapshot *target,
	const struct hyperv_acceptance_persistence_expected *expected)
{
	const struct uk_storvsc_mapping *mapping = &target->mapping;

	return mapping->lun == expected->lun &&
	       mapping->sectors == expected->sectors &&
	       mapping->sector_size == expected->sector_size &&
	       (expected->identity_policy ==
			HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2 ||
		(mapping->path_id == expected->path_id &&
		 mapping->target_id == expected->target_id));
}

static int persistence_snapshot_has_safe_identity(
	const struct uk_storvsc_target_snapshot *target)
{
	const struct uk_storvsc_mapping *mapping = &target->mapping;

	return !mapping->read_only && mapping->vpd_length &&
	       mapping->vpd_length <= HYPERV_ACCEPTANCE_PERSISTENCE_VPD_MAX;
}

#ifdef HYPERV_PERSISTENCE_HOST_TEST
int hyperv_acceptance_persistence_host_mapping_in_scope(
	unsigned int identity_policy, uint8_t path, uint8_t target,
	uint8_t lun, uint64_t sectors, uint32_t sector_size)
{
	const struct hyperv_acceptance_persistence_expected expected = {
		.sectors = CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTORS,
		.sector_size =
			CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTOR_SIZE,
		.path_id = CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_PATH,
		.target_id = CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_TARGET,
		.lun = CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_LUN,
		.identity_policy = identity_policy,
	};
	const struct uk_storvsc_target_snapshot snapshot = {
		.mapping = {
			.path_id = path,
			.target_id = target,
			.lun = lun,
			.sectors = sectors,
			.sector_size = sector_size,
		},
	};

	return persistence_snapshot_in_scope(&snapshot, &expected);
}
#endif

static int persistence_read_records(
	struct uk_blkdev *device,
	uint8_t seed0[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	uint8_t seed1[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	uint8_t intent[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	uint8_t receipt[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE])
{
	int rc;

	rc = persistence_read(device, 0, 2, persistence_buffer);
	if (rc)
		return rc;
	if (hyperv_acceptance_has_mbr_signature(
		    persistence_buffer,
		    HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE) ||
	    hyperv_acceptance_has_gpt_signature(
		    persistence_buffer +
			    HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE,
		    HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE))
		return -EPERM;
	rc = persistence_read(
		device, HYPERV_ACCEPTANCE_PERSISTENCE_SEED0_LBA,
		2, persistence_buffer);
	if (rc)
		return rc;
	memcpy(seed0, persistence_buffer,
	       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	memcpy(seed1,
	       persistence_buffer +
		       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE,
	       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	rc = persistence_read(
		device, HYPERV_ACCEPTANCE_PERSISTENCE_INTENT_LBA,
		2, persistence_buffer);
	if (rc)
		return rc;
	memcpy(intent, persistence_buffer,
	       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	memcpy(receipt,
	       persistence_buffer +
		       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE,
	       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	return 0;
}

static int persistence_end_session(struct uk_storvsc_session *session,
				   unsigned int index)
{
	int rc;

	if (!session->opaque[0])
		return 0;
	if (persistence_request_owned) {
		hyperv_persistence_host_event(
			HYPERV_PERSISTENCE_HOST_SESSION_END_ERROR,
			index, -EBUSY);
		return -EBUSY;
	}
	rc = uk_storvsc_session_end(session);
	if (rc)
		hyperv_persistence_host_event(
			HYPERV_PERSISTENCE_HOST_SESSION_END_ERROR,
			index, rc);
	return rc;
}

static int persistence_select(
	const struct hyperv_acceptance_persistence_expected *expected,
	struct persistence_candidate *selected,
	enum persistence_selection_class *selection)
{
	struct uk_storvsc_inventory_snapshot inventory;
	struct uk_storvsc_inventory_snapshot final_inventory;
	uint8_t seed0[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t seed1[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t intent[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t receipt[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	unsigned int matches = 0;
	unsigned int unsafe_candidates = 0;
	int rc;

	memset(selected, 0, sizeof(*selected));
	*selection = PERSISTENCE_SELECTION_ERROR;
	rc = uk_storvsc_inventory_get(&inventory);
	if (rc)
		return rc;
	hyperv_persistence_host_event(
		HYPERV_PERSISTENCE_HOST_INVENTORY, inventory.count, 0);
	for (unsigned int i = 0; i < inventory.count; i++) {
		struct uk_storvsc_target_snapshot target;
		struct uk_storvsc_session session;
		struct hyperv_acceptance_persistence_identity identity;
		struct hyperv_acceptance_persistence_checksums checksums;
		enum hyperv_acceptance_persistence_state state;
		struct uk_blkdev *device;
		int end_rc;

		rc = uk_storvsc_target_get(i, &target);
		if (rc || target.topology_generation !=
				  inventory.topology_generation) {
			rc = rc ? rc : -ESTALE;
			goto fail;
		}
		if (!persistence_snapshot_in_scope(&target, expected))
			continue;
		if (!persistence_snapshot_has_safe_identity(&target)) {
			unsafe_candidates++;
			continue;
		}
		device = uk_blkdev_get(target.mapping.blkdev_id);
		if (!device) {
			unsafe_candidates++;
			continue;
		}
		memset(&session, 0, sizeof(session));
		rc = uk_storvsc_session_begin_read(&target, &session);
		if (rc)
			goto fail;
		rc = persistence_configure(device);
		if (!rc)
			rc = persistence_read_records(
				device, seed0, seed1, intent, receipt);
		if (rc == -EPERM) {
			unsafe_candidates++;
			printf("HYPERV_PERSISTENCE CANDIDATE_REJECT PASS "
			       "reason=boot-signature id=%" PRIu16 "\n",
			       target.mapping.blkdev_id);
			hyperv_persistence_host_event(
				HYPERV_PERSISTENCE_HOST_BEFORE_REJECT_END,
				i, rc);
			end_rc = persistence_end_session(&session, i);
			if (end_rc)
				return end_rc;
			continue;
		}
		if (rc) {
			end_rc = persistence_end_session(&session, i);
			if (end_rc && rc != -ETIMEDOUT)
				return end_rc;
			return rc;
		}
		if (hyperv_acceptance_persistence_validate_manifest(
			    seed0, expected) ||
		    hyperv_acceptance_persistence_validate_manifest(
			    seed1, expected) ||
		    memcmp(seed0, seed1, sizeof(seed0))) {
			hyperv_persistence_host_event(
				HYPERV_PERSISTENCE_HOST_BEFORE_REJECT_END,
				i, -ENOENT);
			end_rc = persistence_end_session(&session, i);
			if (end_rc)
				return end_rc;
			continue;
		}
		matches++;
		persistence_identity(&target.mapping, &identity);
		state = hyperv_acceptance_persistence_classify(
			expected, &identity, seed0, seed1, intent, receipt,
			&checksums);
		if (state == HYPERV_ACCEPTANCE_PERSISTENCE_INVALID) {
			end_rc = persistence_end_session(&session, i);
			if (!end_rc)
				end_rc = persistence_end_session(
					&selected->session, i);
			if (end_rc)
				return end_rc;
			return -EUCLEAN;
		}
		if (matches != 1) {
			end_rc = persistence_end_session(&session, i);
			if (!end_rc)
				end_rc = persistence_end_session(
					&selected->session, i);
			if (end_rc)
				return end_rc;
			return -EEXIST;
		}
		selected->target = target;
		selected->session = session;
		selected->device = device;
		selected->state = state;
		selected->identity = identity;
		selected->checksums = checksums;
		memcpy(selected->intent, intent, sizeof(intent));
		memcpy(selected->receipt, receipt, sizeof(receipt));
	}
	hyperv_persistence_host_event(
		HYPERV_PERSISTENCE_HOST_BEFORE_REVALIDATE,
		inventory.count, 0);
	rc = uk_storvsc_inventory_get(&final_inventory);
	if (rc ||
	    final_inventory.topology_generation !=
		    inventory.topology_generation ||
	    final_inventory.count != inventory.count) {
		rc = rc ? rc : -ESTALE;
		goto fail;
	}
	if (unsafe_candidates) {
		rc = -EPERM;
		goto fail;
	}
	if (!matches &&
	    expected->identity_policy ==
		    HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2 &&
	    uk_storvsc_inventory_pristine_empty(
		    &inventory, &final_inventory)) {
		*selection = PERSISTENCE_SELECTION_PRISTINE_EMPTY;
		return 0;
	}
	if (matches != 1) {
		rc = -ENOENT;
		goto fail;
	}
	{
		struct uk_storvsc_target_snapshot current;

		rc = uk_storvsc_session_validate(
			&selected->session, &current);
		if (rc || memcmp(&current, &selected->target,
				 sizeof(current))) {
			rc = rc ? rc : -ESTALE;
			goto fail;
		}
		if (selected->state ==
		    HYPERV_ACCEPTANCE_PERSISTENCE_PRISTINE)
			rc = uk_storvsc_session_authorize_write(
				&selected->session);
	}
	if (!rc) {
		*selection = PERSISTENCE_SELECTION_FOUND;
		return 0;
	}
fail:
	{
		int end_rc = persistence_end_session(
			&selected->session, inventory.count);

		if (end_rc && rc != -ETIMEDOUT)
			return end_rc;
	}
	return rc;
}

static void persistence_print_identity_evidence(
	const struct hyperv_acceptance_persistence_expected *expected,
	const struct persistence_candidate *candidate)
{
	const struct hyperv_acceptance_persistence_identity *identity =
		&candidate->identity;

	printf("UK_HYPERV_PERSISTENCE_IDENTITY:1:%u:",
	       expected->identity_policy);
	persistence_print_hex(expected->run_id, sizeof(expected->run_id));
	putchar(':');
	persistence_print_hex(expected->disk_id, sizeof(expected->disk_id));
	putchar(':');
	persistence_print_hex(identity->controller_instance,
			      sizeof(identity->controller_instance));
	printf(":%u:%u:%u:%" PRIu64 ":%u:%u:%u:%u:%u:",
	       identity->path_id, identity->target_id, identity->lun,
	       expected->sectors, expected->sector_size,
	       identity->vpd_length, identity->vpd_code_set,
	       identity->vpd_designator_type, identity->vpd_association);
	persistence_print_hex(identity->vpd_id, identity->vpd_length);
	putchar('\n');
	fflush(stdout);
}

static void persistence_pattern_checksums(
	const struct hyperv_acceptance_persistence_expected *expected,
	struct hyperv_acceptance_persistence_checksums *checksums)
{
	hyperv_acceptance_persistence_pattern(
		expected, HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_FIRST,
		0, persistence_buffer,
		HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	checksums->first = hyperv_acceptance_persistence_crc32(
		persistence_buffer,
		HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	hyperv_acceptance_persistence_pattern(
		expected, HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_LAST,
		0, persistence_buffer,
		HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	checksums->last = hyperv_acceptance_persistence_crc32(
		persistence_buffer,
		HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	hyperv_acceptance_persistence_pattern(
		expected, HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_EXTENT,
		0, persistence_buffer, sizeof(persistence_buffer));
	checksums->extent = hyperv_acceptance_persistence_crc32(
		persistence_buffer, sizeof(persistence_buffer));
}

static int persistence_verify_region(
	struct persistence_candidate *candidate,
	const struct hyperv_acceptance_persistence_expected *expected,
	uint32_t region, uint64_t lba, uint64_t sectors)
{
	size_t bytes = sectors * expected->sector_size;

	hyperv_acceptance_persistence_pattern(
		expected, region, 0, persistence_buffer, bytes);
	memset(persistence_verify, 0, bytes);
	if (persistence_read(
		    candidate->device, lba, sectors, persistence_verify))
		return -EIO;
	return memcmp(persistence_buffer, persistence_verify, bytes) ?
	       -EILSEQ : 0;
}

static int persistence_verify_patterns(
	struct persistence_candidate *candidate,
	const struct hyperv_acceptance_persistence_expected *expected)
{
	if (persistence_verify_region(
		    candidate, expected,
		    HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_FIRST, 0, 1) ||
	    persistence_verify_region(
		    candidate, expected,
		    HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_LAST,
		    expected->sectors - 1, 1) ||
	    persistence_verify_region(
		    candidate, expected,
		    HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_EXTENT,
		    HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_LBA,
		    HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS))
		return -EIO;
	return 0;
}

static int persistence_verify_seeds(
	struct uk_blkdev *device,
	const struct hyperv_acceptance_persistence_expected *expected)
{
	if (persistence_read(
		    device, HYPERV_ACCEPTANCE_PERSISTENCE_SEED0_LBA,
		    2, persistence_buffer) ||
	    hyperv_acceptance_persistence_validate_manifest(
		    persistence_buffer, expected) ||
	    hyperv_acceptance_persistence_validate_manifest(
		    persistence_buffer +
			    HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE,
		    expected) ||
	    memcmp(persistence_buffer,
		   persistence_buffer +
			   HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE,
		   HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE))
		return -EIO;
	return 0;
}

static int persistence_verify_complete(
	struct persistence_candidate *candidate,
	const struct hyperv_acceptance_persistence_expected *expected,
	const struct hyperv_acceptance_persistence_checksums *checksums)
{
	struct hyperv_acceptance_persistence_checksums found;
	uint8_t seed0[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t seed1[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t intent[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t receipt[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];

	if (persistence_read(
		    candidate->device, HYPERV_ACCEPTANCE_PERSISTENCE_SEED0_LBA,
		    2, persistence_buffer))
		return -EIO;
	memcpy(seed0, persistence_buffer, sizeof(seed0));
	memcpy(seed1, persistence_buffer + sizeof(seed0), sizeof(seed1));
	if (persistence_read(
		    candidate->device, HYPERV_ACCEPTANCE_PERSISTENCE_INTENT_LBA,
		    2, persistence_buffer))
		return -EIO;
	memcpy(intent, persistence_buffer, sizeof(intent));
	memcpy(receipt, persistence_buffer + sizeof(intent), sizeof(receipt));
	if (hyperv_acceptance_persistence_classify(
		    expected, &candidate->identity, seed0, seed1,
		    intent, receipt, &found) !=
		    HYPERV_ACCEPTANCE_PERSISTENCE_COMPLETE ||
	    memcmp(&found, checksums, sizeof(found)))
		return -EILSEQ;
	return 0;
}

static int persistence_boot1(
	struct persistence_candidate *candidate,
	const struct hyperv_acceptance_persistence_expected *expected)
{
	struct hyperv_acceptance_persistence_checksums checksums;

	persistence_pattern_checksums(expected, &checksums);
	if (hyperv_acceptance_persistence_build_intent(
		    expected, &candidate->identity, &checksums,
		    candidate->intent))
		return -EINVAL;
	if (persistence_write(
		    candidate->device,
		    HYPERV_ACCEPTANCE_PERSISTENCE_INTENT_LBA,
		    1, candidate->intent) ||
	    persistence_flush(candidate->device))
		return -EIO;

	if (uk_storvsc_session_set_cdb(
		    &candidate->session, UK_STORVSC_CDB_10))
		return -EIO;
	hyperv_acceptance_persistence_pattern(
		expected, HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_FIRST,
		0, persistence_buffer,
		HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	if (persistence_write(
		    candidate->device, 0, 1, persistence_buffer))
		return -EIO;

	if (uk_storvsc_session_set_cdb(
		    &candidate->session, UK_STORVSC_CDB_16))
		return -EIO;
	hyperv_acceptance_persistence_pattern(
		expected, HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_LAST,
		0, persistence_buffer,
		HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	if (persistence_write(
		    candidate->device, expected->sectors - 1, 1,
		    persistence_buffer))
		return -EIO;
	hyperv_acceptance_persistence_pattern(
		expected, HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_EXTENT,
		0, persistence_buffer, sizeof(persistence_buffer));
	if (persistence_write(
		    candidate->device,
		    HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_LBA,
		    HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS,
		    persistence_buffer) ||
	    persistence_verify_patterns(candidate, expected) ||
	    persistence_flush(candidate->device) ||
	    persistence_verify_patterns(candidate, expected) ||
	    persistence_verify_seeds(candidate->device, expected))
		return -EIO;

	if (hyperv_acceptance_persistence_build_receipt(
		    expected, &candidate->identity, &checksums,
		    candidate->intent, candidate->receipt) ||
	    persistence_write(
		    candidate->device,
		    HYPERV_ACCEPTANCE_PERSISTENCE_RECEIPT_LBA,
		    1, candidate->receipt) ||
	    persistence_flush(candidate->device))
		return -EIO;
	if (persistence_verify_complete(
		    candidate, expected, &checksums))
		return -EIO;
	return 0;
}

static int persistence_boot2(
	struct persistence_candidate *candidate,
	const struct hyperv_acceptance_persistence_expected *expected)
{
	struct hyperv_acceptance_persistence_checksums checksums;
	struct uk_storvsc_target_snapshot current;

	persistence_pattern_checksums(expected, &checksums);
	if (uk_storvsc_session_validate(&candidate->session, &current) ||
	    memcmp(&current, &candidate->target, sizeof(current)) ||
	    memcmp(&checksums, &candidate->checksums, sizeof(checksums)) ||
	    persistence_verify_patterns(candidate, expected))
		return -ESTALE;
	return 0;
}

int hyperv_acceptance_persistence_main(void)
{
	struct hyperv_acceptance_persistence_expected expected;
	enum persistence_selection_class selection =
		PERSISTENCE_SELECTION_ERROR;
	uint64_t deadline;
	int unavailable_disqualified = 0;
	int rc;

	if (persistence_request_abandoned) {
		puts("HYPERV_PERSISTENCE FINAL FAIL reason=request-owned");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (persistence_expected(&expected)) {
		puts("HYPERV_PERSISTENCE FINAL FAIL reason=invalid-expectation");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	printf("HYPERV_PERSISTENCE START PASS run=");
	persistence_print_run(expected.run_id);
	printf(" address=%u:%u:%u sectors=%" PRIu64 " sector_size=%u\n",
	       expected.path_id, expected.target_id, expected.lun,
	       expected.sectors, expected.sector_size);

	deadline = ukplat_monotonic_clock() + PERSISTENCE_BIND_TIMEOUT_NS;
	do {
		while (!uk_storvsc_mapping_count() &&
		       ukplat_monotonic_clock() < deadline)
			uk_sched_thread_sleep(PERSISTENCE_POLL_NS);
		rc = persistence_select(
			&expected, &persistence_selected, &selection);
		if (selection == PERSISTENCE_SELECTION_PRISTINE_EMPTY) {
			if (unavailable_disqualified) {
				selection = PERSISTENCE_SELECTION_ERROR;
				rc = -EPERM;
			}
			break;
		}
		if (selection == PERSISTENCE_SELECTION_FOUND)
			break;
		unavailable_disqualified = 1;
		if (rc != -ESTALE && rc != -EAGAIN && rc != -ENOENT)
			break;
		if (ukplat_monotonic_clock() < deadline)
			uk_sched_thread_sleep(PERSISTENCE_POLL_NS);
	} while (ukplat_monotonic_clock() < deadline);
	if (selection == PERSISTENCE_SELECTION_PRISTINE_EMPTY) {
		puts("HYPERV_PERSISTENCE SELECT UNAVAILABLE "
		     "reason=no-devices writes=0 flushes=0");
		puts("UK_HYPERV_PLATFORM_READY");
		printf("UK_HYPERV_PERSISTENCE_UNAVAILABLE:%u:%u:%s\n",
		       HYPERV_ACCEPTANCE_PERSISTENCE_UNAVAILABLE_PROTOCOL,
		       expected.identity_policy,
		       HYPERV_ACCEPTANCE_PERSISTENCE_UNAVAILABLE_NO_DEVICES);
		fflush(stdout);
		return HYPERV_ACCEPTANCE_UNAVAILABLE;
	}
	if (rc || selection != PERSISTENCE_SELECTION_FOUND) {
		printf("HYPERV_PERSISTENCE SELECT FAIL rc=%d writes=0\n", rc);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	printf("HYPERV_PERSISTENCE SELECT PASS id=%" PRIu16
	       " controller=%" PRIu16 " state=%d\n",
	       persistence_selected.target.mapping.blkdev_id,
	       persistence_selected.target.mapping.controller_index,
	       persistence_selected.state);
	persistence_print_identity_evidence(
		&expected, &persistence_selected);
	if (persistence_selected.state ==
	    HYPERV_ACCEPTANCE_PERSISTENCE_PRISTINE) {
		rc = persistence_boot1(&persistence_selected, &expected);
		if (!rc) {
			printf("HYPERV_PERSISTENCE BOOT1_WRITE PASS run=");
			persistence_print_run(expected.run_id);
			putchar('\n');
			if (expected.identity_policy ==
			    HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2) {
				printf("UK_HYPERV_PERSISTENCE_IO:1:1:");
				persistence_print_run(expected.run_id);
				puts(":5:3:receipt-verified");
			}
			printf("UK_HYPERV_PERSISTENCE_BOOT1_COMPLETE:");
			persistence_print_run(expected.run_id);
			putchar('\n');
		}
	} else if (persistence_selected.state ==
		   HYPERV_ACCEPTANCE_PERSISTENCE_COMPLETE) {
		rc = persistence_boot2(&persistence_selected, &expected);
		if (!rc) {
			printf("HYPERV_PERSISTENCE BOOT2_READ PASS run=");
			persistence_print_run(expected.run_id);
			putchar('\n');
			if (expected.identity_policy ==
			    HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2) {
				printf("UK_HYPERV_PERSISTENCE_IO:1:2:");
				persistence_print_run(expected.run_id);
				puts(":0:0:receipt-verified");
			}
			printf("UK_HYPERV_PERSISTENCE_BOOT2_COMPLETE:");
			persistence_print_run(expected.run_id);
			putchar('\n');
		}
	} else {
		rc = -EUCLEAN;
	}
	{
		int end_rc = persistence_end_session(
			&persistence_selected.session, 0);

		if (end_rc && !rc)
			rc = end_rc;
	}
	printf("HYPERV_PERSISTENCE FINAL %s rc=%d\n",
	       rc ? "FAIL" : "PASS", rc);
	fflush(stdout);
	return rc ? HYPERV_ACCEPTANCE_FAIL : HYPERV_ACCEPTANCE_PASS;
}

#ifdef HYPERV_PERSISTENCE_HOST_TEST
int hyperv_acceptance_persistence_host_request_owned(void)
{
	return persistence_request_owned;
}

int hyperv_acceptance_persistence_host_request_done(void)
{
	return persistence_request_owned &&
	       uk_blkreq_is_done(&persistence_request);
}

void hyperv_acceptance_persistence_host_reset(void)
{
	if (persistence_request_owned &&
	    !uk_blkreq_is_done(&persistence_request))
		return;
	memset(&persistence_request, 0, sizeof(persistence_request));
	memset(&persistence_selected, 0, sizeof(persistence_selected));
	memset(persistence_buffer, 0, sizeof(persistence_buffer));
	memset(persistence_verify, 0, sizeof(persistence_verify));
	persistence_request_owned = 0;
	persistence_request_abandoned = 0;
}

void hyperv_acceptance_persistence_host_set_identity_policy(
	unsigned int identity_policy)
{
	persistence_host_identity_policy = identity_policy;
}
#endif
