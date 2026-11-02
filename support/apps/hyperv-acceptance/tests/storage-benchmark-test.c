/* SPDX-License-Identifier: BSD-3-Clause */
#define _GNU_SOURCE
#include "acceptance_protocol.h"
#include "storage_benchmark.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <uk/alloc.h>
#include <uk/blkdev.h>
#include <uk/plat/time.h>
#include <uk/sched.h>
#include <uk/storvsc.h>

#define TEST_SECTOR_SIZE 512U
#define TEST_DISK_SECTORS 8388608ULL
#define TEST_MAX_QUEUE_INFLIGHT 64U

struct fake_disk {
	struct uk_storvsc_target_snapshot snapshot;
	struct uk_blkdev blkdev;
	struct uk_blkdev_data blkdev_data;
	uint8_t low_sectors[64U * TEST_SECTOR_SIZE];
};

static struct uk_alloc test_allocator;
static struct uk_storvsc_inventory_snapshot test_inventory;
static struct fake_disk test_disks[2];
static uint64_t fake_clock_ns;
static unsigned int begin_read_calls;
static unsigned int authorize_write_calls;
static unsigned int validate_calls;
static unsigned int end_calls;
static unsigned int read_req_submissions;
static unsigned int write_req_submissions;
static uint32_t max_ring_inflight_limit;
static int inject_timeout_on_steady;
static int inject_post_seed_drift;
static int inject_post_fixture_drift;
static int inject_mid_sweep_generation_drift;
static int inject_steady_alloc_drift;

static struct uk_blkreq *pending_reqs[TEST_MAX_QUEUE_INFLIGHT];
static unsigned int pending_count;
static char serial_buf[131072];

static enum hyperv_acceptance_result run_probe(void)
{
	int memfd;
	int saved_stdout;
	enum hyperv_acceptance_result res;
	size_t used = 0;
	ssize_t got;

	fflush(stdout);
	memfd = memfd_create("storage-benchmark-serial", 0);
	assert(memfd >= 0);
	saved_stdout = dup(STDOUT_FILENO);
	assert(saved_stdout >= 0);
	assert(dup2(memfd, STDOUT_FILENO) >= 0);
	res = hyperv_acceptance_storage_benchmark_probe(1U, 1, 0);
	fflush(stdout);
	assert(dup2(saved_stdout, STDOUT_FILENO) >= 0);
	close(saved_stdout);
	assert(lseek(memfd, 0, SEEK_SET) == 0);
	while ((got = read(memfd, serial_buf + used,
			   sizeof(serial_buf) - 1U - used)) > 0)
		used += (size_t)got;
	assert(got == 0 && used < sizeof(serial_buf) - 1U);
	close(memfd);
	serial_buf[used] = '\0';
	return res;
}

struct uk_alloc *uk_alloc_get_default(void)
{
	return &test_allocator;
}

void *uk_palloc(struct uk_alloc *a, unsigned long num_pages)
{
	void *ptr = NULL;
	size_t bytes = (size_t)num_pages * 4096U;

	if (!a)
		return NULL;
	if (posix_memalign(&ptr, 4096U, bytes) != 0) {
		a->_stats.nb_enomem++;
		return NULL;
	}
	memset(ptr, 0, bytes);
	a->_stats.tot_nb_allocs++;
	a->_stats.cur_nb_allocs++;
	if (a->_stats.cur_nb_allocs > a->_stats.max_nb_allocs)
		a->_stats.max_nb_allocs = a->_stats.cur_nb_allocs;
	a->_stats.cur_mem_use += (ssize_t)bytes;
	if (a->_stats.cur_mem_use > a->_stats.max_mem_use)
		a->_stats.max_mem_use = a->_stats.cur_mem_use;
	return ptr;
}

void uk_pfree(struct uk_alloc *a, void *ptr, unsigned long num_pages)
{
	size_t bytes = (size_t)num_pages * 4096U;

	if (!a || !ptr)
		return;
	free(ptr);
	a->_stats.tot_nb_frees++;
	a->_stats.cur_nb_allocs--;
	a->_stats.cur_mem_use -= (ssize_t)bytes;
}

uint64_t ukplat_monotonic_clock(void)
{
	fake_clock_ns += 1000ULL;
	return fake_clock_ns;
}

void uk_sched_thread_sleep(uint64_t ns)
{
	fake_clock_ns += ns;
}

int uk_storvsc_discovery_status(void)
{
	return 0;
}

int uk_storvsc_inventory_get(struct uk_storvsc_inventory_snapshot *snapshot)
{
	if (!snapshot)
		return -EINVAL;
	*snapshot = test_inventory;
	return 0;
}

int uk_storvsc_target_get(unsigned int index,
			  struct uk_storvsc_target_snapshot *snapshot)
{
	if (!snapshot || index >= test_inventory.count)
		return -ENOENT;
	*snapshot = test_disks[index].snapshot;
	return 0;
}

int uk_storvsc_inventory_pristine_empty(
	const struct uk_storvsc_inventory_snapshot *first,
	const struct uk_storvsc_inventory_snapshot *second)
{
	return first && second && !first->count && !second->count &&
	       first->topology_generation == second->topology_generation;
}

int uk_storvsc_session_begin_read(
	const struct uk_storvsc_target_snapshot *snapshot,
	struct uk_storvsc_session *session)
{
	if (!snapshot || !session || !snapshot->size)
		return -EINVAL;
	begin_read_calls++;
	memset(session, 0, sizeof(*session));
	session->version = UK_STORVSC_SESSION_VERSION;
	session->size = sizeof(*session);
	session->opaque[0] = 1ULL;
	session->opaque[1] = snapshot->mapping.blkdev_id;
	return 0;
}

int uk_storvsc_session_authorize_write(struct uk_storvsc_session *session)
{
	(void)session;
	authorize_write_calls++;
	return -EPERM;
}

int uk_storvsc_session_validate(const struct uk_storvsc_session *session,
				struct uk_storvsc_target_snapshot *snapshot)
{
	if (!session || !session->opaque[0])
		return -EINVAL;
	validate_calls++;
	if (snapshot) {
		uint16_t id = (uint16_t)session->opaque[1];

		if (id >= test_inventory.count)
			return -ESTALE;
		*snapshot = test_disks[id].snapshot;
	}
	return 0;
}

int uk_storvsc_session_end(struct uk_storvsc_session *session)
{
	if (!session || !session->opaque[0])
		return -EINVAL;
	end_calls++;
	memset(session, 0, sizeof(*session));
	return 0;
}

struct uk_blkdev *uk_blkdev_get(uint16_t id)
{
	if (id >= test_inventory.count)
		return NULL;
	return &test_disks[id].blkdev;
}

enum uk_blkdev_state uk_blkdev_state_get(struct uk_blkdev *device)
{
	return device ? device->_data->state : UK_BLKDEV_INVALID;
}

int uk_blkdev_configure(struct uk_blkdev *device,
			const struct uk_blkdev_conf *config)
{
	if (!device || !config)
		return -EINVAL;
	device->_data->state = UK_BLKDEV_CONFIGURED;
	return 0;
}

int uk_blkdev_queue_configure(struct uk_blkdev *device, uint16_t queue_id,
			      uint16_t descriptors,
			      const struct uk_blkdev_queue_conf *config)
{
	if (!device || queue_id != 0 || !descriptors || !config)
		return -EINVAL;
	return 0;
}

int uk_blkdev_start(struct uk_blkdev *device)
{
	if (!device)
		return -EINVAL;
	device->_data->state = UK_BLKDEV_RUNNING;
	return 0;
}

int uk_blkdev_queue_submit_one(struct uk_blkdev *device, uint16_t queue_id,
			       struct uk_blkreq *request)
{
	struct fake_disk *disk = NULL;

	if (!device || queue_id != 0 || !request)
		return -EINVAL;
	for (unsigned int i = 0; i < test_inventory.count; i++) {
		if (&test_disks[i].blkdev == device) {
			disk = &test_disks[i];
			break;
		}
	}
	if (!disk)
		return -ENODEV;

	if (request->operation != UK_BLKREQ_READ) {
		write_req_submissions++;
		return -EPERM;
	}
	read_req_submissions++;

	if (request->start_sector + request->nb_sectors >
	    disk->snapshot.mapping.sectors)
		return -EINVAL;

	if (pending_count >= max_ring_inflight_limit)
		return -ENOSPC;

	if (request->start_sector < 64ULL) {
		size_t off = (size_t)request->start_sector * TEST_SECTOR_SIZE;
		size_t len = (size_t)request->nb_sectors * TEST_SECTOR_SIZE;

		memcpy(request->aio_buf, disk->low_sectors + off, len);
	} else {
		memset(request->aio_buf, 0x5AU,
		       (size_t)request->nb_sectors * TEST_SECTOR_SIZE);
	}

	pending_reqs[pending_count++] = request;
	if (pending_count >= max_ring_inflight_limit)
		return UK_BLKDEV_STATUS_SUCCESS;
	return UK_BLKDEV_STATUS_SUCCESS | UK_BLKDEV_STATUS_MORE;
}

int uk_blkdev_queue_finish_reqs(struct uk_blkdev *device, uint16_t queue_id)
{
	(void)device;
	(void)queue_id;

	if (inject_timeout_on_steady && read_req_submissions > 10U)
		return 0;

	if (inject_mid_sweep_generation_drift && read_req_submissions > 12U) {
		test_inventory.topology_generation++;
		test_disks[0].snapshot.topology_generation =
			test_inventory.topology_generation;
	}
	if (inject_post_seed_drift && read_req_submissions > 20U)
		test_disks[0].low_sectors[8U * TEST_SECTOR_SIZE] = 0xFFU;
	if (inject_post_fixture_drift && read_req_submissions > 20U)
		test_disks[0].low_sectors[32U * TEST_SECTOR_SIZE] = 0xFFU;
	if (inject_steady_alloc_drift && read_req_submissions > 20U)
		test_allocator._stats.tot_nb_allocs++;

	fake_clock_ns += 5000ULL;
	for (unsigned int i = 0; i < pending_count; i++) {
		struct uk_blkreq *req = pending_reqs[i];

		req->result = 0;
		atomic_store(&req->state.counter, UK_BLKREQ_FINISHED);
		if (req->cb)
			req->cb(req, req->cb_cookie);
	}
	pending_count = 0;
	return 0;
}

static void init_disk_fixture(struct fake_disk *disk, uint16_t id, uint8_t lun)
{
	struct hyperv_acceptance_persistence_expected expected = { 0 };
	uint8_t manifest[TEST_SECTOR_SIZE];

	memset(disk, 0, sizeof(*disk));
	assert(hyperv_acceptance_parse_hex_id(
		       CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_RUN_ID,
		       expected.run_id) == 0);
	assert(hyperv_acceptance_parse_hex_id(
		       CONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_DISK_ID,
		       expected.disk_id) == 0);
	expected.sectors = TEST_DISK_SECTORS;
	expected.sector_size = TEST_SECTOR_SIZE;
	expected.lun = lun;
	expected.identity_policy = 2U;
	assert(hyperv_acceptance_persistence_build_manifest(
		       &expected, manifest) == 0);

	disk->snapshot.version = UK_STORVSC_TARGET_SNAPSHOT_VERSION;
	disk->snapshot.size = sizeof(disk->snapshot);
	disk->snapshot.topology_generation = 1U;
	disk->snapshot.controller_generation = 1U;
	disk->snapshot.lun_generation = 1U;
	disk->snapshot.mapping.blkdev_id = id;
	disk->snapshot.mapping.controller_index = 0;
	disk->snapshot.mapping.channel_id = 7U;
	disk->snapshot.mapping.path_id = 0;
	disk->snapshot.mapping.target_id = 0;
	disk->snapshot.mapping.lun = lun;
	disk->snapshot.mapping.read_only = 0;
	disk->snapshot.mapping.sectors = TEST_DISK_SECTORS;
	disk->snapshot.mapping.sector_size = TEST_SECTOR_SIZE;
	disk->snapshot.mapping.vpd_length = 16U;
	memset(disk->snapshot.mapping.vpd_id, 0x42, 16U);

	disk->blkdev_data.id = id;
	disk->blkdev_data.state = UK_BLKDEV_UNCONFIGURED;
	disk->blkdev._data = &disk->blkdev_data;
	disk->blkdev.capabilities.sectors = TEST_DISK_SECTORS;
	disk->blkdev.capabilities.ssize = TEST_SECTOR_SIZE;
	disk->blkdev.capabilities.max_sectors_per_req = 256U;
	disk->blkdev.capabilities.ioalign = 4096U;

	memcpy(disk->low_sectors + 8U * TEST_SECTOR_SIZE, manifest,
	       TEST_SECTOR_SIZE);
	memcpy(disk->low_sectors + 9U * TEST_SECTOR_SIZE, manifest,
	       TEST_SECTOR_SIZE);
	for (size_t i = 0; i < 16U * TEST_SECTOR_SIZE; i++)
		disk->low_sectors[32U * TEST_SECTOR_SIZE + i] =
			(uint8_t)((i * 37U + 11U) & 0xFFU);
}

static void reset_fixture(void)
{
	hyperv_storage_benchmark_host_reset();
	memset(&test_allocator, 0, sizeof(test_allocator));
	memset(&test_inventory, 0, sizeof(test_inventory));
	test_inventory.version = UK_STORVSC_INVENTORY_SNAPSHOT_VERSION;
	test_inventory.size = sizeof(test_inventory);
	test_inventory.topology_generation = 1U;
	test_inventory.count = 1U;
	init_disk_fixture(&test_disks[0], 0, 7U);
	fake_clock_ns = 1000000ULL;
	begin_read_calls = 0;
	authorize_write_calls = 0;
	validate_calls = 0;
	end_calls = 0;
	read_req_submissions = 0;
	write_req_submissions = 0;
	max_ring_inflight_limit = 32U;
	inject_timeout_on_steady = 0;
	inject_post_seed_drift = 0;
	inject_post_fixture_drift = 0;
	inject_mid_sweep_generation_drift = 0;
	inject_steady_alloc_drift = 0;
	pending_count = 0;
}

static void test_percentile_calculations(void)
{
	struct hyperv_storage_benchmark_lat_stats stats;
	uint64_t samples[100];
	uint64_t single[1] = { 42000ULL };

	assert(hyperv_storage_benchmark_compute_stats(NULL, 10, &stats) ==
	       -EINVAL);
	assert(hyperv_storage_benchmark_compute_stats(samples, 0, &stats) ==
	       -EINVAL);
	assert(hyperv_storage_benchmark_compute_stats(
		       samples, HYPERV_STORAGE_BENCHMARK_MAX_SAMPLES_LIMIT + 1U,
		       &stats) == -EINVAL);

	assert(hyperv_storage_benchmark_compute_stats(single, 1U, &stats) == 0);
	assert(stats.min_ns == 42000ULL);
	assert(stats.p50_ns == 42000ULL);
	assert(stats.p95_ns == 42000ULL);
	assert(stats.p99_ns == 42000ULL);
	assert(stats.max_ns == 42000ULL);
	assert(stats.mean_ns == 42000ULL);
	assert(stats.sample_count == 1U);

	/* Reverse-sorted 1..100 * 1000 ns */
	for (uint32_t i = 0; i < 100U; i++)
		samples[i] = (uint64_t)(100U - i) * 1000ULL;
	assert(hyperv_storage_benchmark_compute_stats(samples, 100U, &stats) ==
	       0);
	assert(stats.min_ns == 1000ULL);
	assert(stats.p50_ns == 50000ULL);
	assert(stats.p95_ns == 95000ULL);
	assert(stats.p99_ns == 99000ULL);
	assert(stats.max_ns == 100000ULL);
	assert(stats.mean_ns == 50500ULL);
	assert(stats.sample_count == 100U);
}

static void test_lba_generator_bounds_and_span(void)
{
	const uint32_t req_sectors_list[4] = { 8U, 32U, 128U, 256U };

	for (unsigned int r = 0; r < 4U; r++) {
		uint32_t req_sec = req_sectors_list[r];
		uint64_t prev_strided = 0;
		uint64_t min_lba = TEST_DISK_SECTORS;
		uint64_t max_lba = 0;

		for (uint32_t op = 0; op < 256U; op++) {
			uint64_t seq_lba = hyperv_storage_benchmark_next_lba(
				HYPERV_STORAGE_BENCHMARK_PATTERN_SEQ,
				HYPERV_STORAGE_BENCHMARK_DATA_START_LBA,
				TEST_DISK_SECTORS, req_sec, r, 1U, op);
			uint64_t strided_lba = hyperv_storage_benchmark_next_lba(
				HYPERV_STORAGE_BENCHMARK_PATTERN_STRIDED,
				HYPERV_STORAGE_BENCHMARK_DATA_START_LBA,
				TEST_DISK_SECTORS, req_sec, r, 1U, op);

			assert(seq_lba >=
			       HYPERV_STORAGE_BENCHMARK_DATA_START_LBA);
			assert(seq_lba + req_sec <= TEST_DISK_SECTORS);
			assert(strided_lba >=
			       HYPERV_STORAGE_BENCHMARK_DATA_START_LBA);
			assert(strided_lba + req_sec <= TEST_DISK_SECTORS);
			if (op > 0)
				assert(strided_lba != prev_strided);
			prev_strided = strided_lba;
			if (strided_lba < min_lba)
				min_lba = strided_lba;
			if (strided_lba > max_lba)
				max_lba = strided_lba;
		}
		/* Full-span strided progression must span >90% of the 4-GiB disk */
		assert(max_lba - min_lba > (TEST_DISK_SECTORS * 9ULL) / 10ULL);
	}
}

static void test_happy_path_and_saturation(void)
{
	reset_fixture();
	assert(run_probe() == HYPERV_ACCEPTANCE_PASS);
	assert(begin_read_calls == 1U);
	assert(authorize_write_calls == 0U);
	assert(write_req_submissions == 0U);
	assert(end_calls == 1U);
	assert(validate_calls > 100U);
	assert(test_allocator._stats.cur_nb_allocs == 0);
	assert(strstr(serial_buf, "UK_HYPERV_STORAGE_BENCHMARK_BEGIN ") != NULL);
	assert(strstr(serial_buf, "UK_HYPERV_STORAGE_BENCHMARK_TRIAL ") != NULL);
	assert(strstr(serial_buf, "UK_HYPERV_STORAGE_BENCHMARK_CELL ") != NULL);
	assert(strstr(serial_buf, "UK_HYPERV_STORAGE_BENCHMARK_OK ") != NULL);
	assert(strstr(serial_buf, "HYPERV_STORAGE_BENCHMARK FINAL PASS\n") !=
	       NULL);

	/* Now test ring saturation counting when ring limit < max target QD */
	reset_fixture();
	max_ring_inflight_limit = 8U;
	assert(run_probe() == HYPERV_ACCEPTANCE_PASS);
	assert(authorize_write_calls == 0U);
	assert(write_req_submissions == 0U);
	assert(end_calls == 1U);
	assert(strstr(serial_buf, "max_in_flight=8 ") != NULL);
	assert(strstr(serial_buf, "HYPERV_STORAGE_BENCHMARK FINAL PASS\n") !=
	       NULL);
}

static void test_refusal_gates(void)
{
	/* 1. MBR signature on target disk -> refused before sweep */
	reset_fixture();
	test_disks[0].low_sectors[510] = 0x55U;
	test_disks[0].low_sectors[511] = 0xAAU;
	assert(run_probe() == HYPERV_ACCEPTANCE_FAIL);
	assert(authorize_write_calls == 0U);
	assert(end_calls == 1U);
	assert(strstr(serial_buf, "UK_HYPERV_STORAGE_BENCHMARK_OK ") == NULL);
	assert(strstr(serial_buf, "HYPERV_STORAGE_BENCHMARK FINAL FAIL ") !=
	       NULL);

	/* 2. GPT signature on target disk -> refused before sweep */
	reset_fixture();
	memcpy(test_disks[0].low_sectors + TEST_SECTOR_SIZE, "EFI PART", 8U);
	assert(run_probe() == HYPERV_ACCEPTANCE_FAIL);
	assert(end_calls == 1U);
	assert(strstr(serial_buf, "UK_HYPERV_STORAGE_BENCHMARK_OK ") == NULL);

	/* 3. Corrupted pre-warmup seed manifest -> refused before sweep */
	reset_fixture();
	test_disks[0].low_sectors[8U * TEST_SECTOR_SIZE] ^= 0xFFU;
	assert(run_probe() == HYPERV_ACCEPTANCE_FAIL);
	assert(end_calls == 1U);
	assert(strstr(serial_buf, "UK_HYPERV_STORAGE_BENCHMARK_OK ") == NULL);

	/* 4. Post-benchmark seed drift -> refused at post-verification */
	reset_fixture();
	inject_post_seed_drift = 1;
	assert(run_probe() == HYPERV_ACCEPTANCE_FAIL);
	assert(end_calls == 1U);
	assert(strstr(serial_buf, "UK_HYPERV_STORAGE_BENCHMARK_OK ") == NULL);

	/* 5. Post-benchmark fixture drift -> refused at post-verification */
	reset_fixture();
	inject_post_fixture_drift = 1;
	assert(run_probe() == HYPERV_ACCEPTANCE_FAIL);
	assert(end_calls == 1U);
	assert(strstr(serial_buf, "UK_HYPERV_STORAGE_BENCHMARK_OK ") == NULL);

	/* 6. Mid-sweep topology generation drift -> refused immediately */
	reset_fixture();
	inject_mid_sweep_generation_drift = 1;
	assert(run_probe() == HYPERV_ACCEPTANCE_FAIL);
	assert(end_calls == 1U);
	assert(strstr(serial_buf, "UK_HYPERV_STORAGE_BENCHMARK_OK ") == NULL);

	/* 7. Duplicate matching LUN 7 target -> refused with -EEXIST */
	reset_fixture();
	init_disk_fixture(&test_disks[1], 1U, 7U);
	test_inventory.count = 2U;
	assert(run_probe() == HYPERV_ACCEPTANCE_FAIL);
	assert(strstr(serial_buf, "UK_HYPERV_STORAGE_BENCHMARK_OK ") == NULL);

	/* 8. Steady-state allocator drift -> refused with -ENOMEM */
	reset_fixture();
	inject_steady_alloc_drift = 1;
	assert(run_probe() == HYPERV_ACCEPTANCE_FAIL);
	assert(end_calls == 1U);
	assert(strstr(serial_buf, "UK_HYPERV_STORAGE_BENCHMARK_OK ") == NULL);

	/* 9. Timeout during in-flight request -> session quarantined */
	reset_fixture();
	inject_timeout_on_steady = 1;
	assert(run_probe() == HYPERV_ACCEPTANCE_FAIL);
	assert(hyperv_storage_benchmark_host_request_owned() == 1);
	assert(hyperv_storage_benchmark_host_session_quarantined() == 1);
	assert(end_calls == 0U);
	assert(run_probe() == HYPERV_ACCEPTANCE_FAIL);
	assert(strstr(serial_buf, "UK_HYPERV_STORAGE_BENCHMARK_OK ") == NULL);
}

int main(void)
{
	test_percentile_calculations();
	test_lba_generator_bounds_and_span();
	test_happy_path_and_saturation();
	test_refusal_gates();
	printf("storage-benchmark-test: synthetic cases passed\n");
	return 0;
}
