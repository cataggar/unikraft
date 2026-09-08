/* SPDX-License-Identifier: BSD-3-Clause */
#include <uk/storvsc.h>

#define PERSISTENCE_QUEUE_DEPTH 4U
#define PERSISTENCE_TIMEOUT_NS (7ULL * 1000000000ULL)
#define PERSISTENCE_BIND_TIMEOUT_NS (3ULL * 1000000000ULL)
#define PERSISTENCE_POLL_NS 10000000ULL

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

static _Alignas(4096) uint8_t persistence_buffer[
	HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS *
	HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
static _Alignas(4096) uint8_t persistence_verify[
	HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS *
	HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
static struct uk_blkreq persistence_request;

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
	return expected->sector_size ==
			       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE &&
		       expected->sectors >
			       HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_LBA +
			       HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS ?
		       0 : -EINVAL;
}

static int persistence_configure(struct uk_blkdev *device)
{
	struct uk_blkdev_queue_conf queue = { 0 };
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
	return uk_blkdev_start(device);
}

static int persistence_io(struct uk_blkdev *device, int operation,
			  uint64_t sector, uint64_t count, void *buffer)
{
	uint64_t deadline;
	int status;
	int rc;

	uk_blkreq_init(&persistence_request, operation, sector, count,
		       buffer, NULL, NULL);
	status = uk_blkdev_queue_submit_one(device, 0, &persistence_request);
	if (status < 0 || !(status & UK_BLKDEV_STATUS_SUCCESS))
		return status < 0 ? status : -EIO;
	deadline = ukplat_monotonic_clock() + PERSISTENCE_TIMEOUT_NS;
	while (!uk_blkreq_is_done(&persistence_request) &&
	       ukplat_monotonic_clock() < deadline) {
		rc = uk_blkdev_queue_finish_reqs(device, 0);
		if (rc)
			return rc;
		if (!uk_blkreq_is_done(&persistence_request))
			uk_sched_thread_sleep(PERSISTENCE_POLL_NS);
	}
	if (!uk_blkreq_is_done(&persistence_request))
		return -ETIMEDOUT;
	return persistence_request.result;
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

static int persistence_snapshot_matches(
	const struct uk_storvsc_target_snapshot *target,
	const struct hyperv_acceptance_persistence_expected *expected)
{
	const struct uk_storvsc_mapping *mapping = &target->mapping;

	return mapping->path_id == expected->path_id &&
	       mapping->target_id == expected->target_id &&
	       mapping->lun == expected->lun &&
	       mapping->sectors == expected->sectors &&
	       mapping->sector_size == expected->sector_size &&
	       !mapping->read_only && mapping->vpd_length &&
	       mapping->vpd_length <= HYPERV_ACCEPTANCE_PERSISTENCE_VPD_MAX;
}

static int persistence_read_records(
	struct uk_blkdev *device,
	uint8_t seed0[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	uint8_t seed1[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	uint8_t intent[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	uint8_t receipt[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE])
{
	if (persistence_read(device, 0, 2, persistence_buffer))
		return -EIO;
	if (hyperv_acceptance_has_mbr_signature(
		    persistence_buffer,
		    HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE) ||
	    hyperv_acceptance_has_gpt_signature(
		    persistence_buffer +
			    HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE,
		    HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE))
		return -EPERM;
	if (persistence_read(
		    device, HYPERV_ACCEPTANCE_PERSISTENCE_SEED0_LBA,
		    2, persistence_buffer))
		return -EIO;
	memcpy(seed0, persistence_buffer,
	       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	memcpy(seed1,
	       persistence_buffer +
		       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE,
	       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	if (persistence_read(
		    device, HYPERV_ACCEPTANCE_PERSISTENCE_INTENT_LBA,
		    2, persistence_buffer))
		return -EIO;
	memcpy(intent, persistence_buffer,
	       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	memcpy(receipt,
	       persistence_buffer +
		       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE,
	       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	return 0;
}

static int persistence_select(
	const struct hyperv_acceptance_persistence_expected *expected,
	struct persistence_candidate *selected)
{
	uint8_t seed0[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t seed1[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t intent[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t receipt[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	unsigned int count = uk_storvsc_mapping_count();
	unsigned int matches = 0;

	memset(selected, 0, sizeof(*selected));
	for (unsigned int i = 0; i < count; i++) {
		struct uk_storvsc_target_snapshot target;
		struct uk_storvsc_session session;
		struct hyperv_acceptance_persistence_identity identity;
		struct hyperv_acceptance_persistence_checksums checksums;
		enum hyperv_acceptance_persistence_state state;
		struct uk_blkdev *device;
		int rc;

		if (uk_storvsc_target_get(i, &target) ||
		    !persistence_snapshot_matches(&target, expected))
			continue;
		device = uk_blkdev_get(target.mapping.blkdev_id);
		if (!device ||
		    uk_storvsc_session_begin_read(&target, &session))
			continue;
		rc = persistence_configure(device);
		if (!rc)
			rc = persistence_read_records(
				device, seed0, seed1, intent, receipt);
		if (rc == -EPERM) {
			printf("HYPERV_PERSISTENCE CANDIDATE_REJECT PASS "
			       "reason=boot-signature id=%" PRIu16 "\n",
			       target.mapping.blkdev_id);
			(void)uk_storvsc_session_end(&session);
			continue;
		}
		if (rc) {
			(void)uk_storvsc_session_end(&session);
			return rc;
		}
		if (hyperv_acceptance_persistence_validate_manifest(
			    seed0, expected) ||
		    hyperv_acceptance_persistence_validate_manifest(
			    seed1, expected) ||
		    memcmp(seed0, seed1, sizeof(seed0))) {
			(void)uk_storvsc_session_end(&session);
			continue;
		}
		matches++;
		persistence_identity(&target.mapping, &identity);
		state = hyperv_acceptance_persistence_classify(
			expected, &identity, seed0, seed1, intent, receipt,
			&checksums);
		if (state == HYPERV_ACCEPTANCE_PERSISTENCE_INVALID) {
			(void)uk_storvsc_session_end(&session);
			if (selected->session.opaque[0])
				(void)uk_storvsc_session_end(
					&selected->session);
			return -EUCLEAN;
		}
		if (matches != 1) {
			(void)uk_storvsc_session_end(&session);
			(void)uk_storvsc_session_end(&selected->session);
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
	if (matches != 1)
		return -ENOENT;
	{
		struct uk_storvsc_target_snapshot current;
		int rc = uk_storvsc_session_validate(
			&selected->session, &current);

		if (rc || memcmp(&current, &selected->target,
				 sizeof(current)))
			return rc ? rc : -ESTALE;
		if (selected->state ==
		    HYPERV_ACCEPTANCE_PERSISTENCE_PRISTINE)
			return uk_storvsc_session_authorize_write(
				&selected->session);
	}
	return 0;
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
	uint8_t intent[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t receipt[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	struct hyperv_acceptance_persistence_checksums checksums;

	persistence_pattern_checksums(expected, &checksums);
	if (hyperv_acceptance_persistence_build_intent(
		    expected, &candidate->identity, &checksums, intent))
		return -EINVAL;
	if (persistence_write(
		    candidate->device,
		    HYPERV_ACCEPTANCE_PERSISTENCE_INTENT_LBA,
		    1, intent) ||
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
		    intent, receipt) ||
	    persistence_write(
		    candidate->device,
		    HYPERV_ACCEPTANCE_PERSISTENCE_RECEIPT_LBA,
		    1, receipt) ||
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

int main(void)
{
	struct hyperv_acceptance_persistence_expected expected;
	struct persistence_candidate selected;
	uint64_t deadline;
	int rc;

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
		rc = persistence_select(&expected, &selected);
		if (rc != -ESTALE && rc != -ENOENT)
			break;
		if (ukplat_monotonic_clock() < deadline)
			uk_sched_thread_sleep(PERSISTENCE_POLL_NS);
	} while (ukplat_monotonic_clock() < deadline);
	if (rc) {
		printf("HYPERV_PERSISTENCE SELECT FAIL rc=%d writes=0\n", rc);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	printf("HYPERV_PERSISTENCE SELECT PASS id=%" PRIu16
	       " controller=%" PRIu16 " state=%d\n",
	       selected.target.mapping.blkdev_id,
	       selected.target.mapping.controller_index, selected.state);
	if (selected.state == HYPERV_ACCEPTANCE_PERSISTENCE_PRISTINE) {
		rc = persistence_boot1(&selected, &expected);
		if (!rc) {
			printf("HYPERV_PERSISTENCE BOOT1_WRITE PASS run=");
			persistence_print_run(expected.run_id);
			putchar('\n');
			printf("UK_HYPERV_PERSISTENCE_BOOT1_COMPLETE:");
			persistence_print_run(expected.run_id);
			putchar('\n');
		}
	} else if (selected.state ==
		   HYPERV_ACCEPTANCE_PERSISTENCE_COMPLETE) {
		rc = persistence_boot2(&selected, &expected);
		if (!rc) {
			printf("HYPERV_PERSISTENCE BOOT2_READ PASS run=");
			persistence_print_run(expected.run_id);
			putchar('\n');
			printf("UK_HYPERV_PERSISTENCE_BOOT2_COMPLETE:");
			persistence_print_run(expected.run_id);
			putchar('\n');
		}
	} else {
		rc = -EUCLEAN;
	}
	if (uk_storvsc_session_end(&selected.session) && !rc)
		rc = -EBUSY;
	printf("HYPERV_PERSISTENCE FINAL %s rc=%d\n",
	       rc ? "FAIL" : "PASS", rc);
	fflush(stdout);
	return rc ? HYPERV_ACCEPTANCE_FAIL : HYPERV_ACCEPTANCE_PASS;
}
