/* SPDX-License-Identifier: BSD-3-Clause */
#include "storage_benchmark.h"

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

#ifndef STORAGE_BENCHMARK_READ_TIMEOUT_NS
#define STORAGE_BENCHMARK_READ_TIMEOUT_NS (7ULL * 1000000000ULL)
#endif
#ifndef STORAGE_BENCHMARK_POLL_NS
#define STORAGE_BENCHMARK_POLL_NS 10000000ULL
#endif
#define STORAGE_BENCHMARK_PAGE_SIZE 4096U

static uint64_t gcd_u64(uint64_t a, uint64_t b)
{
	while (b != 0) {
		uint64_t r = a % b;

		a = b;
		b = r;
	}
	return a;
}

int hyperv_storage_benchmark_compute_stats(
	uint64_t *samples, uint32_t count,
	struct hyperv_storage_benchmark_lat_stats *out)
{
	uint64_t sum = 0;
	uint32_t gap;
	uint32_t i;
	uint32_t p50_idx;
	uint32_t p95_idx;
	uint32_t p99_idx;

	if (!samples || !out || !count ||
	    count > HYPERV_STORAGE_BENCHMARK_MAX_SAMPLES_LIMIT)
		return -EINVAL;

	for (gap = count / 2U; gap > 0U; gap /= 2U) {
		for (i = gap; i < count; i++) {
			uint64_t temp = samples[i];
			uint32_t j = i;

			while (j >= gap && samples[j - gap] > temp) {
				samples[j] = samples[j - gap];
				j -= gap;
			}
			samples[j] = temp;
		}
	}

	for (i = 0; i < count; i++)
		sum += samples[i];

	p50_idx = (uint32_t)(((uint64_t)count * 50ULL + 99ULL) / 100ULL) - 1U;
	p95_idx = (uint32_t)(((uint64_t)count * 95ULL + 99ULL) / 100ULL) - 1U;
	p99_idx = (uint32_t)(((uint64_t)count * 99ULL + 99ULL) / 100ULL) - 1U;
	if (p50_idx >= count)
		p50_idx = count - 1U;
	if (p95_idx >= count)
		p95_idx = count - 1U;
	if (p99_idx >= count)
		p99_idx = count - 1U;

	out->min_ns = samples[0];
	out->p50_ns = samples[p50_idx];
	out->p95_ns = samples[p95_idx];
	out->p99_ns = samples[p99_idx];
	out->max_ns = samples[count - 1U];
	out->mean_ns = sum / count;
	out->sample_count = count;
	return 0;
}

uint64_t hyperv_storage_benchmark_next_lba(
	enum hyperv_storage_benchmark_pattern pattern,
	uint64_t data_start_lba, uint64_t total_sectors,
	uint32_t req_sectors, uint32_t cell_index,
	uint32_t trial_index, uint32_t op_index)
{
	uint64_t usable_sectors;
	uint64_t num_blocks;
	uint64_t stream_seed;
	uint64_t start_block;
	uint64_t block_index;

	if (!req_sectors || total_sectors <= data_start_lba ||
	    total_sectors - data_start_lba < req_sectors)
		return data_start_lba;

	usable_sectors = total_sectors - data_start_lba;
	num_blocks = usable_sectors / req_sectors;
	stream_seed = (uint64_t)cell_index * 31ULL + (uint64_t)trial_index;
	start_block = (stream_seed * 4099ULL) % num_blocks;

	if (pattern == HYPERV_STORAGE_BENCHMARK_PATTERN_SEQ) {
		block_index = (start_block + (uint64_t)op_index) % num_blocks;
	} else {
		uint64_t step = ((num_blocks * 618033989ULL) / 1000000000ULL) |
				1ULL;

		if (num_blocks <= 1ULL) {
			block_index = 0;
		} else {
			if (step >= num_blocks)
				step %= num_blocks;
			if (!step)
				step = 1ULL;
			while (gcd_u64(step, num_blocks) != 1ULL) {
				step++;
				if (step >= num_blocks)
					step = 1ULL;
			}
			block_index = (start_block +
				       (uint64_t)op_index * step) % num_blocks;
		}
	}
	return data_start_lba + block_index * (uint64_t)req_sectors;
}

#if defined(CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK) && \
	CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK

static const uint32_t benchmark_req_sizes[
	HYPERV_STORAGE_BENCHMARK_REQ_SIZE_COUNT] = {
	4096U, 16384U, 65536U, 131072U
};

static const uint32_t benchmark_queue_depths[
	HYPERV_STORAGE_BENCHMARK_QD_COUNT] = {
	1U, 2U, 4U, 8U, 16U, 32U
};

struct benchmark_slot {
	struct uk_blkreq req;
	uint8_t *buffer;
	uint64_t t_submit;
	uint64_t t_complete;
	uint32_t op_index;
	uint8_t in_flight;
	uint8_t cb_invoked;
};

struct benchmark_alloc_snapshot {
	uint64_t tot_nb_allocs;
	uint64_t tot_nb_frees;
	uint64_t cur_nb_allocs;
	uint64_t max_nb_allocs;
	uint64_t cur_mem_use;
	uint64_t max_mem_use;
	uint64_t nb_enomem;
	unsigned int enabled;
};

static struct benchmark_slot benchmark_slots[
	HYPERV_STORAGE_BENCHMARK_MAX_SLOTS_LIMIT];
static uint64_t *benchmark_sub_comp_samples;
static uint64_t *benchmark_comp_res_samples;
static struct uk_storvsc_target_snapshot benchmark_target;
static struct uk_storvsc_session benchmark_session;
static struct uk_blkdev *benchmark_device;
static unsigned int benchmark_inventory_count;
static int benchmark_request_owned;
static int benchmark_request_abandoned;
static int benchmark_session_quarantined;

static const char *pattern_name(enum hyperv_storage_benchmark_pattern pattern)
{
	switch (pattern) {
	case HYPERV_STORAGE_BENCHMARK_PATTERN_SEQ:
		return "seq";
	case HYPERV_STORAGE_BENCHMARK_PATTERN_STRIDED:
		return "strided";
	default:
		return "unknown";
	}
}

static void benchmark_snapshot_alloc(struct uk_alloc *a,
				     struct benchmark_alloc_snapshot *out)
{
	memset(out, 0, sizeof(*out));
	if (!a)
		return;
#if defined(CONFIG_LIBUKALLOC_IFSTATS) && CONFIG_LIBUKALLOC_IFSTATS
	out->enabled = 1U;
	out->tot_nb_allocs = (uint64_t)a->_stats.tot_nb_allocs;
	out->tot_nb_frees = (uint64_t)a->_stats.tot_nb_frees;
	out->cur_nb_allocs = (uint64_t)a->_stats.cur_nb_allocs;
	out->max_nb_allocs = (uint64_t)a->_stats.max_nb_allocs;
	out->cur_mem_use = (uint64_t)a->_stats.cur_mem_use;
	out->max_mem_use = (uint64_t)a->_stats.max_mem_use;
	out->nb_enomem = (uint64_t)a->_stats.nb_enomem;
#endif
}

static void benchmark_req_complete_cb(struct uk_blkreq *req, void *cookie)
{
	struct benchmark_slot *slot = (struct benchmark_slot *)cookie;

	(void)req;
	if (!slot)
		return;
	slot->t_complete = ukplat_monotonic_clock();
	slot->cb_invoked = 1U;
}

static int benchmark_expected_config(
	struct hyperv_acceptance_persistence_expected *expected)
{
	uint8_t manifest[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];

	memset(expected, 0, sizeof(*expected));
	if (CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_SECTORS <=
		    (int64_t)HYPERV_STORAGE_BENCHMARK_DATA_START_LBA + 256 ||
	    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_SECTOR_SIZE !=
		    (int)HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE ||
	    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_IDENTITY_POLICY !=
		    (int)HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2 ||
	    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_LUN <= 0 ||
	    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_LUN > 255 ||
	    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_MAX_SLOTS < 1 ||
	    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_MAX_SLOTS >
		    (int)HYPERV_STORAGE_BENCHMARK_MAX_SLOTS_LIMIT ||
	    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_MAX_TRANSFER_BYTES <
		    4096 ||
	    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_MAX_TRANSFER_BYTES >
		    (int)HYPERV_STORAGE_BENCHMARK_MAX_TRANSFER_LIMIT ||
	    (CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_MAX_TRANSFER_BYTES %
	     4096) != 0 ||
	    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_WARMUP_OPS < 1 ||
	    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_WARMUP_OPS > 1024 ||
	    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_STEADY_OPS < 1 ||
	    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_STEADY_OPS >
		    (int)HYPERV_STORAGE_BENCHMARK_MAX_SAMPLES_LIMIT ||
	    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_TRIALS < 1 ||
	    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_TRIALS >
		    (int)HYPERV_STORAGE_BENCHMARK_MAX_TRIALS_LIMIT)
		return -EINVAL;

	if (hyperv_acceptance_parse_hex_id(
		    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_RUN_ID,
		    expected->run_id) ||
	    hyperv_acceptance_parse_hex_id(
		    CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_DISK_ID,
		    expected->disk_id))
		return -EINVAL;

	expected->sectors =
		(uint64_t)CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_SECTORS;
	expected->sector_size =
		(uint32_t)CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_SECTOR_SIZE;
	expected->lun =
		(uint8_t)CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_LUN;
	expected->identity_policy =
		(uint8_t)CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_IDENTITY_POLICY;
	return hyperv_acceptance_persistence_build_manifest(expected, manifest);
}

static int benchmark_validate_session(void)
{
	struct uk_storvsc_inventory_snapshot inventory;
	struct uk_storvsc_target_snapshot current;
	int rc;

	if (!benchmark_device || !benchmark_target.size ||
	    !benchmark_inventory_count || !benchmark_session.opaque[0])
		return -EINVAL;
	rc = uk_storvsc_discovery_status();
	if (rc)
		return rc;
	rc = uk_storvsc_session_validate(&benchmark_session, &current);
	if (rc)
		return rc;
	if (memcmp(&current, &benchmark_target, sizeof(current)))
		return -ESTALE;
	rc = uk_storvsc_inventory_get(&inventory);
	if (rc)
		return rc;
	if (inventory.topology_generation !=
		    benchmark_target.topology_generation ||
	    inventory.count != benchmark_inventory_count)
		return -ESTALE;
	return 0;
}

static int benchmark_release_session(void)
{
	int rc;

	if (!benchmark_session.opaque[0]) {
		memset(&benchmark_target, 0, sizeof(benchmark_target));
		benchmark_device = NULL;
		benchmark_inventory_count = 0;
		return 0;
	}
	if (benchmark_request_owned)
		return -EBUSY;
	rc = uk_storvsc_session_end(&benchmark_session);
	if (!rc) {
		memset(&benchmark_session, 0, sizeof(benchmark_session));
		memset(&benchmark_target, 0, sizeof(benchmark_target));
		benchmark_device = NULL;
		benchmark_inventory_count = 0;
	}
	return rc;
}

static int benchmark_configure_device(struct uk_blkdev *device,
				      uint16_t max_slots)
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
	rc = uk_blkdev_queue_configure(device, 0, max_slots, &queue);
	if (rc)
		return rc;
	return uk_blkdev_start(device);
}

static int benchmark_single_read(struct uk_blkdev *device, uint64_t lba,
				 uint32_t sectors, uint8_t *buffer,
				 size_t byte_len)
{
	struct benchmark_slot *slot = &benchmark_slots[0];
	uint64_t deadline;
	int finish_error = 0;
	int status;
	int rc;

	if (benchmark_request_abandoned)
		return -ESHUTDOWN;
	if (benchmark_request_owned)
		return -EBUSY;
	rc = benchmark_validate_session();
	if (rc)
		return rc;

	memset(buffer, 0, byte_len);
	slot->cb_invoked = 0;
	slot->t_submit = ukplat_monotonic_clock();
	slot->t_complete = 0;
	uk_blkreq_init(&slot->req, UK_BLKREQ_READ, lba, sectors, buffer,
		       benchmark_req_complete_cb, slot);
	status = uk_blkdev_queue_submit_one(device, 0, &slot->req);
	if (status < 0 || !(status & UK_BLKDEV_STATUS_SUCCESS))
		return status < 0 ? status : -EIO;

	benchmark_request_owned = 1;
	deadline = ukplat_monotonic_clock() + STORAGE_BENCHMARK_READ_TIMEOUT_NS;
	while (!uk_blkreq_is_done(&slot->req) &&
	       ukplat_monotonic_clock() < deadline) {
		rc = uk_blkdev_queue_finish_reqs(device, 0);
		if (rc && !finish_error)
			finish_error = rc;
		if (!uk_blkreq_is_done(&slot->req))
			uk_sched_thread_sleep(STORAGE_BENCHMARK_POLL_NS);
	}
	if (!uk_blkreq_is_done(&slot->req)) {
		benchmark_request_abandoned = 1;
		return -ETIMEDOUT;
	}
	benchmark_request_owned = 0;
	if (!slot->cb_invoked)
		return -EPROTO;
	if (slot->req.result)
		return slot->req.result;
	if (finish_error)
		return finish_error;
	return benchmark_validate_session();
}

static int benchmark_verify_seed_and_fixture(
	const struct hyperv_acceptance_persistence_expected *expected,
	uint32_t *seed_crc32_out, uint32_t *fixture_crc32_out)
{
	uint8_t manifest[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t *buf = benchmark_slots[0].buffer;
	size_t sector_size = HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE;
	size_t extent_bytes = HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS *
			      sector_size;
	int rc;

	if (!buf)
		return -ENOMEM;
	rc = hyperv_acceptance_persistence_build_manifest(expected, manifest);
	if (rc)
		return rc;

	/* Refuse any target with MBR or GPT boot signatures on LBAs 0..1. */
	rc = benchmark_single_read(benchmark_device, 0, 2U, buf,
				   2U * sector_size);
	if (rc)
		return rc;
	if (hyperv_acceptance_has_mbr_signature(buf, sector_size) ||
	    hyperv_acceptance_has_gpt_signature(buf + sector_size, sector_size))
		return -EPERM;

	/* Verify both policy-2 seed manifest sectors at LBAs 8..9. */
	rc = benchmark_single_read(
		benchmark_device, HYPERV_ACCEPTANCE_PERSISTENCE_SEED0_LBA,
		2U, buf, 2U * sector_size);
	if (rc)
		return rc;
	if (hyperv_acceptance_persistence_validate_manifest(buf, expected) ||
	    hyperv_acceptance_persistence_validate_manifest(
		    buf + sector_size, expected) ||
	    memcmp(buf, manifest, sector_size) ||
	    memcmp(buf + sector_size, manifest, sector_size))
		return -EILSEQ;
	*seed_crc32_out = hyperv_acceptance_persistence_crc32(
		buf, 2U * sector_size);

	/* Read the 16-sector fixture extent at LBA 32 and record its CRC32. */
	rc = benchmark_single_read(
		benchmark_device, HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_LBA,
		HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS, buf,
		extent_bytes);
	if (rc)
		return rc;
	*fixture_crc32_out = hyperv_acceptance_persistence_crc32(
		buf, extent_bytes);
	return 0;
}

static int benchmark_alloc_resources(struct uk_alloc *allocator,
				     uint32_t max_slots,
				     uint32_t max_transfer_bytes,
				     uint32_t steady_ops)
{
	unsigned long slot_pages =
		(max_transfer_bytes + STORAGE_BENCHMARK_PAGE_SIZE - 1U) /
		STORAGE_BENCHMARK_PAGE_SIZE;
	unsigned long sample_pages =
		(steady_ops * sizeof(uint64_t) +
		 STORAGE_BENCHMARK_PAGE_SIZE - 1U) /
		STORAGE_BENCHMARK_PAGE_SIZE;
	uint32_t s;

	for (s = 0; s < max_slots; s++) {
		benchmark_slots[s].buffer = uk_palloc(allocator, slot_pages);
		if (!benchmark_slots[s].buffer ||
		    ((uintptr_t)benchmark_slots[s].buffer &
		     (STORAGE_BENCHMARK_PAGE_SIZE - 1U)) != 0)
			return -ENOMEM;
	}
	benchmark_sub_comp_samples = uk_palloc(allocator, sample_pages);
	if (!benchmark_sub_comp_samples)
		return -ENOMEM;
	benchmark_comp_res_samples = uk_palloc(allocator, sample_pages);
	if (!benchmark_comp_res_samples)
		return -ENOMEM;
	return 0;
}

static void benchmark_free_resources(struct uk_alloc *allocator,
				     uint32_t max_slots,
				     uint32_t max_transfer_bytes,
				     uint32_t steady_ops)
{
	unsigned long slot_pages =
		(max_transfer_bytes + STORAGE_BENCHMARK_PAGE_SIZE - 1U) /
		STORAGE_BENCHMARK_PAGE_SIZE;
	unsigned long sample_pages =
		(steady_ops * sizeof(uint64_t) +
		 STORAGE_BENCHMARK_PAGE_SIZE - 1U) /
		STORAGE_BENCHMARK_PAGE_SIZE;
	uint32_t s;

	if (!allocator || benchmark_request_abandoned ||
	    benchmark_request_owned)
		return;
	if (benchmark_comp_res_samples) {
		uk_pfree(allocator, benchmark_comp_res_samples, sample_pages);
		benchmark_comp_res_samples = NULL;
	}
	if (benchmark_sub_comp_samples) {
		uk_pfree(allocator, benchmark_sub_comp_samples, sample_pages);
		benchmark_sub_comp_samples = NULL;
	}
	for (s = 0; s < max_slots; s++) {
		if (benchmark_slots[s].buffer) {
			uk_pfree(allocator, benchmark_slots[s].buffer,
				 slot_pages);
			benchmark_slots[s].buffer = NULL;
		}
	}
}

static int benchmark_run_interval(
	enum hyperv_storage_benchmark_pattern pattern,
	uint64_t total_sectors, uint32_t req_bytes, uint32_t req_sectors,
	uint32_t target_qd, uint32_t cell_index, uint32_t trial_index,
	uint32_t op_count, int record_samples,
	uint32_t *max_in_flight_out, uint32_t *saturation_count_out,
	uint64_t *elapsed_ns_out)
{
	uint32_t submitted = 0;
	uint32_t completed = 0;
	uint32_t in_flight = 0;
	uint32_t max_in_flight = 0;
	uint32_t saturation_count = 0;
	uint64_t start_ns;
	uint64_t deadline;
	uint32_t s;
	int rc;

	if (benchmark_request_abandoned)
		return -ESHUTDOWN;
	if (benchmark_request_owned)
		return -EBUSY;

	for (s = 0; s < target_qd; s++) {
		benchmark_slots[s].in_flight = 0;
		benchmark_slots[s].cb_invoked = 0;
		benchmark_slots[s].t_submit = 0;
		benchmark_slots[s].t_complete = 0;
		benchmark_slots[s].op_index = 0;
	}

	start_ns = ukplat_monotonic_clock();
	deadline = start_ns + STORAGE_BENCHMARK_READ_TIMEOUT_NS;

	while (completed < op_count) {
		int made_progress = 0;

		while (submitted < op_count && in_flight < target_qd) {
			struct benchmark_slot *slot = NULL;
			uint64_t lba;
			int status;

			for (s = 0; s < target_qd; s++) {
				if (!benchmark_slots[s].in_flight) {
					slot = &benchmark_slots[s];
					break;
				}
			}
			if (!slot)
				break;

			rc = benchmark_validate_session();
			if (rc)
				goto out;

			lba = hyperv_storage_benchmark_next_lba(
				pattern,
				HYPERV_STORAGE_BENCHMARK_DATA_START_LBA,
				total_sectors, req_sectors, cell_index,
				trial_index, submitted);
			slot->cb_invoked = 0;
			slot->op_index = submitted;
			uk_blkreq_init(&slot->req, UK_BLKREQ_READ, lba,
				       req_sectors, slot->buffer,
				       benchmark_req_complete_cb, slot);
			slot->t_submit = ukplat_monotonic_clock();
			status = uk_blkdev_queue_submit_one(
				benchmark_device, 0, &slot->req);
			if (status == -ENOSPC || status == -EBUSY) {
				saturation_count++;
				break;
			}
			if (status < 0 || !(status & UK_BLKDEV_STATUS_SUCCESS)) {
				rc = status < 0 ? status : -EIO;
				goto out;
			}
			slot->in_flight = 1U;
			submitted++;
			in_flight++;
			benchmark_request_owned = 1;
			made_progress = 1;
			if (in_flight > max_in_flight)
				max_in_flight = in_flight;
			if (!(status & UK_BLKDEV_STATUS_MORE) &&
			    submitted < op_count && in_flight < target_qd) {
				saturation_count++;
				break;
			}
		}

		rc = uk_blkdev_queue_finish_reqs(benchmark_device, 0);
		if (rc)
			goto out;

		for (s = 0; s < target_qd; s++) {
			struct benchmark_slot *slot = &benchmark_slots[s];
			uint64_t t_resume;
			uint64_t sub_comp_ns;
			uint64_t comp_res_ns;

			if (!slot->in_flight || !uk_blkreq_is_done(&slot->req))
				continue;

			t_resume = ukplat_monotonic_clock();
			slot->in_flight = 0;
			in_flight--;
			if (!in_flight)
				benchmark_request_owned = 0;

			rc = benchmark_validate_session();
			if (rc)
				goto out;
			if (!slot->cb_invoked) {
				rc = -EPROTO;
				goto out;
			}
			if (slot->req.result) {
				rc = slot->req.result;
				goto out;
			}

			sub_comp_ns = slot->t_complete >= slot->t_submit ?
				      slot->t_complete - slot->t_submit : 0ULL;
			comp_res_ns = t_resume >= slot->t_complete ?
				      t_resume - slot->t_complete : 0ULL;
			if (record_samples) {
				benchmark_sub_comp_samples[completed] =
					sub_comp_ns;
				benchmark_comp_res_samples[completed] =
					comp_res_ns;
			}
			(void)req_bytes;
			completed++;
			made_progress = 1;
			deadline = t_resume + STORAGE_BENCHMARK_READ_TIMEOUT_NS;
		}

		if (completed < op_count) {
			if (ukplat_monotonic_clock() >= deadline) {
				benchmark_request_abandoned = 1;
				rc = -ETIMEDOUT;
				goto out;
			}
			if (!made_progress)
				uk_sched_thread_sleep(STORAGE_BENCHMARK_POLL_NS);
		}
	}

	{
		uint64_t end_ns = ukplat_monotonic_clock();

		*max_in_flight_out = max_in_flight;
		*saturation_count_out = saturation_count;
		*elapsed_ns_out = end_ns > start_ns ? (end_ns - start_ns) : 1ULL;
	}
	return 0;

out:
	if (in_flight) {
		benchmark_request_owned = 1;
		benchmark_request_abandoned = 1;
	}
	return rc;
}

static int benchmark_select_target(
	const struct hyperv_acceptance_persistence_expected *expected,
	uint16_t max_slots, uint32_t max_transfer_bytes,
	uint32_t *pre_seed_crc32_out, uint32_t *pre_fixture_crc32_out)
{
	struct uk_storvsc_inventory_snapshot inventory;
	struct uk_storvsc_inventory_snapshot final_inventory;
	unsigned int matches = 0;
	int rc;

	rc = uk_storvsc_discovery_status();
	if (!rc)
		rc = uk_storvsc_inventory_get(&inventory);
	if (rc)
		return rc;
	if (inventory.count >
	    CONFIG_LIBSTORVSC_MAX_DEVICES * CONFIG_LIBSTORVSC_MAX_LUNS)
		return -E2BIG;
	if (!inventory.count)
		return -ENODEV;

	for (unsigned int i = 0; i < inventory.count; i++) {
		struct uk_storvsc_target_snapshot snapshot;
		const struct uk_storvsc_mapping *mapping;
		const struct uk_blkdev_cap *capabilities;
		struct uk_blkdev *device;
		uint32_t seed_crc = 0;
		uint32_t fixture_crc = 0;

		rc = uk_storvsc_target_get(i, &snapshot);
		if (rc)
			return rc;
		if (snapshot.topology_generation !=
		    inventory.topology_generation)
			return -ESTALE;
		mapping = &snapshot.mapping;
		if (mapping->lun != expected->lun ||
		    mapping->sectors != expected->sectors ||
		    mapping->sector_size != expected->sector_size)
			continue;
		if (!snapshot.size || mapping->read_only ||
		    !mapping->vpd_length ||
		    mapping->vpd_length > UK_STORVSC_VPD_ID_MAX)
			return -EPERM;

		device = uk_blkdev_get(mapping->blkdev_id);
		if (!device)
			return -ENODEV;
		if (matches)
			return -EEXIST;

		benchmark_target = snapshot;
		benchmark_device = device;
		benchmark_inventory_count = inventory.count;
		rc = uk_storvsc_session_begin_read(
			&snapshot, &benchmark_session);
		if (rc) {
			memset(&benchmark_target, 0, sizeof(benchmark_target));
			benchmark_device = NULL;
			benchmark_inventory_count = 0;
			return rc;
		}

		rc = benchmark_configure_device(device, max_slots);
		if (rc) {
			(void)benchmark_release_session();
			return rc;
		}
#ifdef STORVSC_HOST_TEST
		capabilities = &device->capabilities;
#else
		capabilities = uk_blkdev_capabilities(device);
#endif
		if (!capabilities ||
		    capabilities->sectors != expected->sectors ||
		    capabilities->ssize != expected->sector_size ||
		    capabilities->ioalign > STORAGE_BENCHMARK_PAGE_SIZE ||
		    capabilities->max_sectors_per_req * expected->sector_size <
			    max_transfer_bytes) {
			(void)benchmark_release_session();
			return -EINVAL;
		}

		rc = benchmark_verify_seed_and_fixture(
			expected, &seed_crc, &fixture_crc);
		if (rc) {
			if (!benchmark_request_owned)
				(void)benchmark_release_session();
			return rc;
		}
		matches++;
		*pre_seed_crc32_out = seed_crc;
		*pre_fixture_crc32_out = fixture_crc;
	}

	if (matches != 1U) {
		(void)benchmark_release_session();
		return matches ? -EEXIST : -ENOENT;
	}
	rc = uk_storvsc_discovery_status();
	if (!rc)
		rc = uk_storvsc_inventory_get(&final_inventory);
	if (rc ||
	    final_inventory.topology_generation !=
		    inventory.topology_generation ||
	    final_inventory.count != inventory.count) {
		(void)benchmark_release_session();
		return rc ? rc : -ESTALE;
	}
	return benchmark_validate_session();
}

enum hyperv_acceptance_result hyperv_acceptance_storage_benchmark_probe(
	unsigned int storage_offers, int binding_ready, int discovery_error)
{
	struct hyperv_acceptance_persistence_expected expected;
	struct uk_storvsc_inventory_snapshot inventory;
	struct uk_storvsc_inventory_snapshot final_inventory;
	struct benchmark_alloc_snapshot alloc_before;
	struct benchmark_alloc_snapshot alloc_after;
	struct uk_alloc *allocator;
	uint32_t max_slots =
		(uint32_t)CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_MAX_SLOTS;
	uint32_t max_transfer_bytes =
		(uint32_t)CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_MAX_TRANSFER_BYTES;
	uint32_t warmup_ops =
		(uint32_t)CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_WARMUP_OPS;
	uint32_t steady_ops =
		(uint32_t)CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_STEADY_OPS;
	uint32_t trials =
		(uint32_t)CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_TRIALS;
	uint64_t t_discovery_start;
	uint64_t discovery_ns;
	uint32_t pre_seed_crc32 = 0;
	uint32_t pre_fixture_crc32 = 0;
	uint32_t post_seed_crc32 = 0;
	uint32_t post_fixture_crc32 = 0;
	uint32_t cell_index = 0;
	uint32_t total_trials = 0;
	uint64_t total_warmup_ops = 0;
	uint64_t total_steady_ops = 0;
	uint64_t total_bytes_read = 0;
	uint32_t global_max_in_flight = 0;
	uint64_t total_saturation_count = 0;
	int rc;

	if (benchmark_request_abandoned || benchmark_session_quarantined ||
	    benchmark_request_owned || benchmark_session.opaque[0]) {
		if (benchmark_request_abandoned && benchmark_request_owned) {
			uint32_t s;
			int any_inflight = 0;

			for (s = 0; s < HYPERV_STORAGE_BENCHMARK_MAX_SLOTS_LIMIT; s++) {
				if (benchmark_slots[s].in_flight &&
				    !uk_blkreq_is_done(&benchmark_slots[s].req))
					any_inflight = 1;
				else
					benchmark_slots[s].in_flight = 0;
			}
			if (!any_inflight)
				benchmark_request_owned = 0;
		}
		if (!benchmark_request_owned && benchmark_session.opaque[0])
			(void)benchmark_release_session();
		puts("HYPERV_STORAGE_BENCHMARK FINAL FAIL reason=session-quarantined");
		return HYPERV_ACCEPTANCE_FAIL;
	}

	rc = benchmark_expected_config(&expected);
	if (rc) {
		puts("HYPERV_STORAGE_BENCHMARK FINAL FAIL reason=invalid-expectation");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (discovery_error && discovery_error != -EAGAIN) {
		printf("HYPERV_STORAGE_BENCHMARK FINAL FAIL reason=discovery rc=%d\n",
		       discovery_error);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (!binding_ready) {
		puts("HYPERV_STORAGE_BENCHMARK FINAL FAIL reason=binding-timeout");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	rc = uk_storvsc_discovery_status();
	if (!rc)
		rc = uk_storvsc_inventory_get(&inventory);
	if (rc) {
		printf("HYPERV_STORAGE_BENCHMARK FINAL FAIL reason=inventory rc=%d\n",
		       rc);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (!inventory.count) {
		if (storage_offers) {
			puts("HYPERV_STORAGE_BENCHMARK FINAL FAIL reason=offered-unbound");
			return HYPERV_ACCEPTANCE_FAIL;
		}
		rc = uk_storvsc_inventory_get(&final_inventory);
		if (rc || !uk_storvsc_inventory_pristine_empty(
				  &inventory, &final_inventory)) {
			puts("HYPERV_STORAGE_BENCHMARK FINAL FAIL reason=unproven-empty");
			return HYPERV_ACCEPTANCE_FAIL;
		}
		puts("HYPERV_STORAGE_BENCHMARK FINAL UNAVAILABLE reason=no-devices");
		return HYPERV_ACCEPTANCE_UNAVAILABLE;
	}
	if (!storage_offers) {
		puts("HYPERV_STORAGE_BENCHMARK FINAL FAIL reason=unoffered-mappings");
		return HYPERV_ACCEPTANCE_FAIL;
	}

	allocator = uk_alloc_get_default();
	if (!allocator) {
		puts("HYPERV_STORAGE_BENCHMARK FINAL FAIL reason=no-allocator");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	rc = benchmark_alloc_resources(allocator, max_slots,
				       max_transfer_bytes, steady_ops);
	if (rc) {
		benchmark_free_resources(allocator, max_slots,
					 max_transfer_bytes, steady_ops);
		puts("HYPERV_STORAGE_BENCHMARK FINAL FAIL reason=alloc-resources");
		return HYPERV_ACCEPTANCE_FAIL;
	}

	t_discovery_start = ukplat_monotonic_clock();
	rc = benchmark_select_target(&expected, (uint16_t)max_slots,
				     max_transfer_bytes, &pre_seed_crc32,
				     &pre_fixture_crc32);
	if (rc) {
		benchmark_free_resources(allocator, max_slots,
					 max_transfer_bytes, steady_ops);
		printf("HYPERV_STORAGE_BENCHMARK FINAL FAIL reason=target-select rc=%d\n",
		       rc);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	discovery_ns = ukplat_monotonic_clock() - t_discovery_start;
	benchmark_snapshot_alloc(allocator, &alloc_before);

	printf("UK_HYPERV_STORAGE_BENCHMARK_BEGIN schema=%u id=%" PRIu16
	       " controller=%" PRIu16 " channel=%" PRIu32
	       " address=%u:%u:%u identity_policy=%u"
	       " session_state=read_only write_authorized=0"
	       " sectors=%" PRIu64 " sector_size=%u"
	       " max_transfer_bytes=%u configured_queue_depth=%u"
	       " max_transfer_pages=%u max_slots=%u"
	       " warmup_ops=%u steady_ops=%u trials=%u"
	       " discovery_ns=%" PRIu64
	       " pre_seed_crc32=%08" PRIx32 " pre_fixture_crc32=%08" PRIx32 "\n",
	       HYPERV_STORAGE_BENCHMARK_SCHEMA_VERSION,
	       benchmark_target.mapping.blkdev_id,
	       benchmark_target.mapping.controller_index,
	       benchmark_target.mapping.channel_id,
	       benchmark_target.mapping.path_id,
	       benchmark_target.mapping.target_id,
	       benchmark_target.mapping.lun,
	       expected.identity_policy,
	       expected.sectors,
	       expected.sector_size,
	       max_transfer_bytes,
	       (unsigned int)CONFIG_LIBSTORVSC_QUEUE_DEPTH,
	       (unsigned int)CONFIG_LIBSTORVSC_MAX_TRANSFER_PAGES,
	       max_slots, warmup_ops, steady_ops, trials,
	       discovery_ns, pre_seed_crc32, pre_fixture_crc32);

	for (unsigned int p = 0; p < HYPERV_STORAGE_BENCHMARK_PATTERN_COUNT; p++) {
		enum hyperv_storage_benchmark_pattern pat =
			(enum hyperv_storage_benchmark_pattern)p;

		for (unsigned int r = 0;
		     r < HYPERV_STORAGE_BENCHMARK_REQ_SIZE_COUNT; r++) {
			uint32_t req_bytes = benchmark_req_sizes[r];
			uint32_t req_sectors = req_bytes / expected.sector_size;

			if (req_bytes > max_transfer_bytes)
				continue;

			for (unsigned int q = 0;
			     q < HYPERV_STORAGE_BENCHMARK_QD_COUNT; q++) {
				uint32_t qd = benchmark_queue_depths[q];
				uint32_t warmup_max_inflight = 0;
				uint32_t warmup_sat = 0;
				uint64_t warmup_elapsed_ns = 0;
				uint32_t cell_max_inflight = 0;
				uint32_t cell_sat = 0;
				uint64_t trial_iops[
					HYPERV_STORAGE_BENCHMARK_MAX_TRIALS_LIMIT];
				uint64_t trial_bw[
					HYPERV_STORAGE_BENCHMARK_MAX_TRIALS_LIMIT];
				struct hyperv_storage_benchmark_lat_stats
					iops_stats;
				struct hyperv_storage_benchmark_lat_stats
					bw_stats;

				if (qd > max_slots)
					continue;

				/* Phase 1: Uncounted warmup interval for this cell. */
				rc = benchmark_run_interval(
					pat, expected.sectors, req_bytes,
					req_sectors, qd, cell_index, 0U,
					warmup_ops, 0, &warmup_max_inflight,
					&warmup_sat, &warmup_elapsed_ns);
				if (rc)
					goto fail;
				total_warmup_ops += warmup_ops;
				total_bytes_read +=
					(uint64_t)warmup_ops * req_bytes;

				/* Phase 2: Measured steady-state trials for this cell. */
				for (uint32_t t = 0; t < trials; t++) {
					uint32_t t_max_inflight = 0;
					uint32_t t_sat = 0;
					uint64_t elapsed_ns = 0;
					uint64_t bytes_read =
						(uint64_t)steady_ops * req_bytes;
					uint64_t iops;
					uint64_t bytes_per_s;
					struct hyperv_storage_benchmark_lat_stats
						sub_comp;
					struct hyperv_storage_benchmark_lat_stats
						comp_res;

					rc = benchmark_run_interval(
						pat, expected.sectors,
						req_bytes, req_sectors, qd,
						cell_index, t + 1U, steady_ops,
						1, &t_max_inflight, &t_sat,
						&elapsed_ns);
					if (rc)
						goto fail;

					rc = hyperv_storage_benchmark_compute_stats(
						benchmark_sub_comp_samples,
						steady_ops, &sub_comp);
					if (rc)
						goto fail;
					rc = hyperv_storage_benchmark_compute_stats(
						benchmark_comp_res_samples,
						steady_ops, &comp_res);
					if (rc)
						goto fail;

					iops = ((uint64_t)steady_ops *
						1000000000ULL) / elapsed_ns;
					bytes_per_s = (bytes_read *
						       1000000000ULL) /
						      elapsed_ns;
					trial_iops[t] = iops;
					trial_bw[t] = bytes_per_s;

					if (t_max_inflight > cell_max_inflight)
						cell_max_inflight =
							t_max_inflight;
					if (t_max_inflight >
					    global_max_in_flight)
						global_max_in_flight =
							t_max_inflight;
					cell_sat += t_sat;
					total_saturation_count += t_sat;
					total_steady_ops += steady_ops;
					total_bytes_read += bytes_read;
					total_trials++;

					printf("UK_HYPERV_STORAGE_BENCHMARK_TRIAL"
					       " cell=%u pattern=%s"
					       " req_bytes=%u req_sectors=%u"
					       " qd=%u trial=%u"
					       " warmup_ops=%u samples=%u"
					       " bytes_read=%" PRIu64
					       " elapsed_ns=%" PRIu64
					       " iops=%" PRIu64
					       " bytes_per_s=%" PRIu64
					       " max_in_flight=%u"
					       " saturation_count=%u"
					       " sub_comp_min_ns=%" PRIu64
					       " sub_comp_p50_ns=%" PRIu64
					       " sub_comp_p95_ns=%" PRIu64
					       " sub_comp_p99_ns=%" PRIu64
					       " sub_comp_max_ns=%" PRIu64
					       " sub_comp_mean_ns=%" PRIu64
					       " comp_res_min_ns=%" PRIu64
					       " comp_res_p50_ns=%" PRIu64
					       " comp_res_p95_ns=%" PRIu64
					       " comp_res_p99_ns=%" PRIu64
					       " comp_res_max_ns=%" PRIu64
					       " comp_res_mean_ns=%" PRIu64 "\n",
					       cell_index, pattern_name(pat),
					       req_bytes, req_sectors, qd, t,
					       warmup_ops, steady_ops,
					       bytes_read, elapsed_ns, iops,
					       bytes_per_s, t_max_inflight,
					       t_sat, sub_comp.min_ns,
					       sub_comp.p50_ns, sub_comp.p95_ns,
					       sub_comp.p99_ns, sub_comp.max_ns,
					       sub_comp.mean_ns,
					       comp_res.min_ns, comp_res.p50_ns,
					       comp_res.p95_ns, comp_res.p99_ns,
					       comp_res.max_ns,
					       comp_res.mean_ns);
				}

				rc = hyperv_storage_benchmark_compute_stats(
					trial_iops, trials, &iops_stats);
				if (rc)
					goto fail;
				rc = hyperv_storage_benchmark_compute_stats(
					trial_bw, trials, &bw_stats);
				if (rc)
					goto fail;

				printf("UK_HYPERV_STORAGE_BENCHMARK_CELL"
				       " cell=%u pattern=%s"
				       " req_bytes=%u req_sectors=%u"
				       " qd=%u trials=%u warmup_ops=%u"
				       " total_samples=%u"
				       " total_bytes=%" PRIu64
				       " max_in_flight=%u"
				       " saturation_count=%u"
				       " min_iops=%" PRIu64
				       " median_iops=%" PRIu64
				       " max_iops=%" PRIu64
				       " min_bytes_per_s=%" PRIu64
				       " median_bytes_per_s=%" PRIu64
				       " max_bytes_per_s=%" PRIu64 "\n",
				       cell_index, pattern_name(pat),
				       req_bytes, req_sectors, qd, trials,
				       warmup_ops, trials * steady_ops,
				       (uint64_t)trials * steady_ops * req_bytes,
				       cell_max_inflight, cell_sat,
				       iops_stats.min_ns, iops_stats.p50_ns,
				       iops_stats.max_ns, bw_stats.min_ns,
				       bw_stats.p50_ns, bw_stats.max_ns);
				cell_index++;
			}
		}
	}

	benchmark_snapshot_alloc(allocator, &alloc_after);
	if (alloc_after.enabled &&
	    (alloc_after.tot_nb_allocs != alloc_before.tot_nb_allocs ||
	     alloc_after.tot_nb_frees != alloc_before.tot_nb_frees ||
	     alloc_after.nb_enomem != alloc_before.nb_enomem ||
	     alloc_after.nb_enomem != 0)) {
		rc = -ENOMEM;
		goto fail;
	}

	/* Phase 3: Post-benchmark seed, fixture, session, and topology verification. */
	rc = benchmark_verify_seed_and_fixture(
		&expected, &post_seed_crc32, &post_fixture_crc32);
	if (rc)
		goto fail;
	if (post_seed_crc32 != pre_seed_crc32 ||
	    post_fixture_crc32 != pre_fixture_crc32) {
		rc = -EILSEQ;
		goto fail;
	}
	rc = benchmark_validate_session();
	if (rc)
		goto fail;

	rc = benchmark_release_session();
	if (rc) {
		benchmark_session_quarantined = 1;
		benchmark_free_resources(allocator, max_slots,
					 max_transfer_bytes, steady_ops);
		printf("HYPERV_STORAGE_BENCHMARK FINAL FAIL reason=session-end rc=%d\n",
		       rc);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	benchmark_free_resources(allocator, max_slots, max_transfer_bytes,
				 steady_ops);

	printf("UK_HYPERV_STORAGE_BENCHMARK_OK schema=%u lun=%u"
	       " session_state=read_only write_authorized=0"
	       " cells=%u total_trials=%u"
	       " total_warmup_ops=%" PRIu64 " total_steady_ops=%" PRIu64
	       " total_bytes_read=%" PRIu64
	       " global_max_in_flight=%u"
	       " total_saturation_count=%" PRIu64
	       " pre_seed_crc32=%08" PRIx32 " post_seed_crc32=%08" PRIx32
	       " pre_fixture_crc32=%08" PRIx32 " post_fixture_crc32=%08" PRIx32
	       " post_seed_verified=1"
	       " alloc_ifstats=%u"
	       " alloc_steady_allocs=%" PRIu64
	       " alloc_steady_frees=%" PRIu64
	       " alloc_steady_enomem=%" PRIu64
	       " alloc_cur_mem_bytes=%" PRIu64
	       " alloc_max_mem_bytes=%" PRIu64 "\n",
	       HYPERV_STORAGE_BENCHMARK_SCHEMA_VERSION, expected.lun,
	       cell_index, total_trials, total_warmup_ops, total_steady_ops,
	       total_bytes_read, global_max_in_flight, total_saturation_count,
	       pre_seed_crc32, post_seed_crc32, pre_fixture_crc32,
	       post_fixture_crc32, alloc_after.enabled,
	       alloc_after.tot_nb_allocs - alloc_before.tot_nb_allocs,
	       alloc_after.tot_nb_frees - alloc_before.tot_nb_frees,
	       alloc_after.nb_enomem - alloc_before.nb_enomem,
	       alloc_after.cur_mem_use, alloc_after.max_mem_use);
	puts("HYPERV_STORAGE_BENCHMARK FINAL PASS");
	return HYPERV_ACCEPTANCE_PASS;

fail:
	if (!benchmark_request_owned) {
		if (benchmark_release_session())
			benchmark_session_quarantined = 1;
		benchmark_free_resources(allocator, max_slots,
					 max_transfer_bytes, steady_ops);
	}
	printf("HYPERV_STORAGE_BENCHMARK FINAL FAIL reason=sweep rc=%d\n", rc);
	return HYPERV_ACCEPTANCE_FAIL;
}

#else

enum hyperv_acceptance_result hyperv_acceptance_storage_benchmark_probe(
	unsigned int storage_offers, int binding_ready, int discovery_error)
{
	(void)storage_offers;
	(void)binding_ready;
	(void)discovery_error;
	return HYPERV_ACCEPTANCE_FAIL;
}

#endif

#ifdef STORAGE_BENCHMARK_HOST_TEST
void hyperv_storage_benchmark_host_reset(void)
{
	memset(benchmark_slots, 0, sizeof(benchmark_slots));
	benchmark_sub_comp_samples = NULL;
	benchmark_comp_res_samples = NULL;
	memset(&benchmark_target, 0, sizeof(benchmark_target));
	memset(&benchmark_session, 0, sizeof(benchmark_session));
	benchmark_device = NULL;
	benchmark_inventory_count = 0;
	benchmark_request_owned = 0;
	benchmark_request_abandoned = 0;
	benchmark_session_quarantined = 0;
}

int hyperv_storage_benchmark_host_request_owned(void)
{
	return benchmark_request_owned;
}

int hyperv_storage_benchmark_host_session_quarantined(void)
{
	return benchmark_session_quarantined || benchmark_request_abandoned;
}
#endif
