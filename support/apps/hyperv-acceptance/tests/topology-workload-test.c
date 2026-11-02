/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <uk/alloc.h>
#include <uk/blkdev.h>
#include <uk/plat/time.h>
#include <uk/sched.h>

#include "storage_target.h"

enum { OS, EXTRA, DATA0, DATA7, DEVICE_COUNT };
enum fault {
	NONE, SWAPPED_SEED, CORRUPT_COPY, DUPLICATE_OS, PARTIAL_OS,
	BAD_SUBMIT, BAD_COMPLETION, BAD_RESULT, BAD_SESSION, BAD_CONFIGURE,
	UNGUARDED, HOLD_COMPLETION
};

static struct uk_blkdev disks[DEVICE_COUNT];
static struct uk_blkdev_data disk_data[DEVICE_COUNT];
static struct uk_storvsc_target_snapshot targets[DEVICE_COUNT];
static struct uk_blkreq *pending;
static struct uk_alloc allocator;
static uint8_t manifests[2][HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
static unsigned int order[DEVICE_COUNT];
static unsigned int count;
static unsigned int reads;
static unsigned int sessions_started;
static unsigned int sessions_ended;
static unsigned int sessions_active;
static unsigned int final_inventory_reads;
static uint64_t now;
static uint64_t generation;
static enum fault injected;
static int discovery_error;
static int pristine;
static int finish_target;
static int fail_end_once;

static void fixtures(int reversed)
{
	struct hyperv_acceptance_persistence_expected expected = {
		.sector_size = HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE,
		.identity_policy =
			HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2,
	};
	static const uint64_t sectors[DEVICE_COUNT] = {
		1000, 1200, 2000, 2300
	};
	static const uint8_t luns[DEVICE_COUNT] = { 0, 2, 0, 7 };

	memset(disks, 0, sizeof(disks));
	memset(disk_data, 0, sizeof(disk_data));
	memset(targets, 0, sizeof(targets));
	pending = NULL;
	count = DEVICE_COUNT;
	reads = 0;
	sessions_started = 0;
	sessions_ended = 0;
	sessions_active = 0;
	final_inventory_reads = 0;
	now = 0;
	generation = 1;
	injected = NONE;
	discovery_error = 0;
	pristine = 0;
	finish_target = -1;
	fail_end_once = 0;
	for (unsigned int i = 0; i < DEVICE_COUNT; i++) {
		order[i] = reversed ? DEVICE_COUNT - i - 1 : i;
		disks[i]._data = &disk_data[i];
		disks[i].capabilities = (struct uk_blkdev_cap){
			.sectors = sectors[i],
			.ssize = 512,
			.ioalign = 4096,
			.max_sectors_per_req = 2,
		};
		disk_data[i].state = UK_BLKDEV_UNCONFIGURED;
		targets[i].version = UK_STORVSC_TARGET_SNAPSHOT_VERSION;
		targets[i].size = sizeof(targets[i]);
		targets[i].topology_generation = generation;
		targets[i].controller_generation = 1;
		targets[i].lun_generation = 1;
		targets[i].mapping.blkdev_id = i;
		targets[i].mapping.controller_index = i < DATA0 ? 0 : 1;
		targets[i].mapping.channel_id = i < DATA0 ? 10 : 12;
		targets[i].mapping.instance_id[0] = i < DATA0 ? 1 : 2;
		targets[i].mapping.lun = luns[i];
		targets[i].mapping.sectors = sectors[i];
		targets[i].mapping.sector_size = 512;
		targets[i].mapping.vpd_length = 1;
		targets[i].mapping.vpd_id[0] = i + 1;
	}
	assert(!hyperv_acceptance_parse_hex_id(
		CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_RUN_ID,
		expected.run_id));
	assert(!hyperv_acceptance_parse_hex_id(
		CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_ID,
		expected.disk_id));
	expected.sectors = sectors[DATA0];
	assert(!hyperv_acceptance_persistence_build_manifest(
		&expected, manifests[0]));
	assert(!hyperv_acceptance_parse_hex_id(
		CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_ID,
		expected.disk_id));
	expected.sectors = sectors[DATA7];
	expected.lun = 7;
	assert(!hyperv_acceptance_persistence_build_manifest(
		&expected, manifests[1]));
	assert(memcmp(manifests[0], manifests[1], sizeof(manifests[0])));
}

int uk_storvsc_discovery_status(void)
{
	return discovery_error;
}

int uk_storvsc_inventory_get(struct uk_storvsc_inventory_snapshot *snapshot)
{
	final_inventory_reads++;
	*snapshot = (struct uk_storvsc_inventory_snapshot){
		.version = UK_STORVSC_INVENTORY_SNAPSHOT_VERSION,
		.size = sizeof(*snapshot),
		.topology_generation = generation,
		.count = count,
	};
	return 0;
}

int uk_storvsc_inventory_pristine_empty(
	const struct uk_storvsc_inventory_snapshot *first,
	const struct uk_storvsc_inventory_snapshot *second)
{
	return pristine && !first->count && !second->count &&
	       first->topology_generation == 0 &&
	       second->topology_generation == 0;
}

int uk_storvsc_target_get(unsigned int index,
			  struct uk_storvsc_target_snapshot *snapshot)
{
	if (index >= count || index >= DEVICE_COUNT)
		return -ENOENT;
	*snapshot = targets[order[index]];
	return 0;
}

int uk_storvsc_session_begin_read(
	const struct uk_storvsc_target_snapshot *snapshot,
	struct uk_storvsc_session *session)
{
	if (injected == UNGUARDED)
		return -ENOTSUP;
	if (injected == BAD_SESSION)
		return -EIO;
	assert(!sessions_active);
	sessions_active++;
	sessions_started++;
	session->opaque[0] = snapshot->mapping.blkdev_id + 1;
	return 0;
}

int uk_storvsc_session_validate(
	const struct uk_storvsc_session *session,
	struct uk_storvsc_target_snapshot *snapshot)
{
	assert(sessions_active && session->opaque[0]);
	*snapshot = targets[session->opaque[0] - 1];
	return 0;
}

int uk_storvsc_session_end(struct uk_storvsc_session *session)
{
	assert(sessions_active && session->opaque[0] && !pending);
	if (fail_end_once) {
		fail_end_once = 0;
		return -EIO;
	}
	sessions_active--;
	sessions_ended++;
	memset(session, 0, sizeof(*session));
	return 0;
}

struct uk_blkdev *uk_blkdev_get(uint16_t id)
{
	return id < DEVICE_COUNT ? &disks[id] : NULL;
}

enum uk_blkdev_state uk_blkdev_state_get(struct uk_blkdev *device)
{
	return device->_data->state;
}

int uk_blkdev_configure(struct uk_blkdev *device,
			const struct uk_blkdev_conf *config)
{
	assert(config->nb_queues == 1);
	if (injected == BAD_CONFIGURE)
		return -EIO;
	device->_data->state = UK_BLKDEV_CONFIGURED;
	return 0;
}

int uk_blkdev_queue_configure(struct uk_blkdev *device, uint16_t queue_id,
			      uint16_t descriptors,
			      const struct uk_blkdev_queue_conf *config)
{
	(void)device;
	assert(!queue_id && descriptors == 4 && config->a == &allocator);
	return 0;
}

int uk_blkdev_start(struct uk_blkdev *device)
{
	device->_data->state = UK_BLKDEV_RUNNING;
	return 0;
}

struct uk_alloc *uk_alloc_get_default(void)
{
	return &allocator;
}

int uk_blkdev_queue_submit_one(struct uk_blkdev *device, uint16_t queue_id,
			       struct uk_blkreq *request)
{
	(void)device;
	assert(!queue_id && !pending && sessions_active == 1);
	assert(request->operation == UK_BLKREQ_READ &&
	       request->nb_sectors == 2 &&
	       (request->start_sector == 0 || request->start_sector == 8));
	if (injected == BAD_SUBMIT)
		return -EIO;
	reads++;
	pending = request;
	return UK_BLKDEV_STATUS_SUCCESS;
}

int uk_blkdev_queue_finish_reqs(struct uk_blkdev *device, uint16_t queue_id)
{
	unsigned int id = device - disks;
	uint8_t *buffer;

	assert(!queue_id && id < DEVICE_COUNT && pending);
	if (injected == HOLD_COMPLETION)
		return 0;
	buffer = pending->aio_buf;
	memset(buffer, 0, 1024);
	if (!pending->start_sector) {
		if (id == OS || (id == DATA0 && injected == DUPLICATE_OS)) {
			buffer[510] = 0x55;
			buffer[511] = 0xaa;
			if (injected != PARTIAL_OS)
				memcpy(buffer + 512, "EFI PART", 8);
		}
	} else {
		assert(id == DATA0 || id == DATA7);
		unsigned int role = id == DATA0 ? 0 : 1;
		const uint8_t *manifest = manifests[
			injected == SWAPPED_SEED && !role ? 1 : role];

		memcpy(buffer, manifest, 512);
		memcpy(buffer + 512, manifest, 512);
		if (injected == CORRUPT_COPY && role)
			buffer[512 + 48] ^= 1;
	}
	pending->result = injected == BAD_RESULT ? -EIO : 0;
	atomic_store(&pending->state.counter, UK_BLKREQ_FINISHED);
	pending = NULL;
	finish_target = id;
	return injected == BAD_COMPLETION ? -EIO : 0;
}

__nsec ukplat_monotonic_clock(void)
{
	return now;
}

void uk_sched_thread_sleep(__nsec nanoseconds)
{
	now += nanoseconds;
}

static void check(enum hyperv_acceptance_result expected,
		  unsigned int offers)
{
	unsigned int before = sessions_started;

	assert(hyperv_acceptance_storage_topology_probe(
		offers, 1, 0) == expected);
	if (expected == HYPERV_ACCEPTANCE_PASS) {
		assert(reads == 6 && sessions_started - before == 4);
		assert(final_inventory_reads == 2);
	}
	assert(!pending && !sessions_active &&
	       sessions_started == sessions_ended);
}

int main(int argc, char **argv)
{
	for (unsigned int reverse = 0; reverse < 2; reverse++) {
		fixtures(reverse);
		check(HYPERV_ACCEPTANCE_PASS, 2);
		fixtures(reverse);
		injected = SWAPPED_SEED;
		check(HYPERV_ACCEPTANCE_FAIL, 2);
		fixtures(reverse);
		injected = CORRUPT_COPY;
		check(HYPERV_ACCEPTANCE_FAIL, 2);
		fixtures(reverse);
		injected = DUPLICATE_OS;
		check(HYPERV_ACCEPTANCE_FAIL, 2);
		fixtures(reverse);
		injected = PARTIAL_OS;
		check(HYPERV_ACCEPTANCE_FAIL, 2);
		fixtures(reverse);
		disks[DATA0].capabilities.sectors--;
		check(HYPERV_ACCEPTANCE_FAIL, 2);
		fixtures(reverse);
		targets[DATA7].mapping.sectors--;
		check(HYPERV_ACCEPTANCE_FAIL, 2);
		fixtures(reverse);
		injected = BAD_SUBMIT;
		check(HYPERV_ACCEPTANCE_FAIL, 2);
		fixtures(reverse);
		injected = BAD_COMPLETION;
		check(HYPERV_ACCEPTANCE_FAIL, 2);
		fixtures(reverse);
		injected = BAD_RESULT;
		check(HYPERV_ACCEPTANCE_FAIL, 2);
		fixtures(reverse);
		injected = BAD_SESSION;
		check(HYPERV_ACCEPTANCE_FAIL, 2);
		fixtures(reverse);
		injected = BAD_CONFIGURE;
		check(HYPERV_ACCEPTANCE_FAIL, 2);
		fixtures(reverse);
		injected = UNGUARDED;
		check(HYPERV_ACCEPTANCE_FAIL, 2);
		assert(!reads);
		fixtures(reverse);
		targets[DATA7].mapping.vpd_length = 0;
		check(HYPERV_ACCEPTANCE_FAIL, 2);
	}
	fixtures(0);
	count = 0;
	generation = 0;
	pristine = 1;
	check(HYPERV_ACCEPTANCE_UNAVAILABLE, 0);
	assert(final_inventory_reads == 2 && !reads);
	fixtures(0);
	count = 0;
	check(HYPERV_ACCEPTANCE_FAIL, 0);
	fixtures(0);
	count = 0;
	check(HYPERV_ACCEPTANCE_FAIL, 2);
	fixtures(0);
	check(HYPERV_ACCEPTANCE_FAIL, 0);
	assert(!reads);
	fixtures(0);
	count = CONFIG_LIBSTORVSC_MAX_DEVICES *
		CONFIG_LIBSTORVSC_MAX_LUNS + 1;
	check(HYPERV_ACCEPTANCE_FAIL, 2);
	assert(!reads);
	fixtures(0);
	discovery_error = -ENOSPC;
	assert(hyperv_acceptance_storage_topology_probe(2, 1,
		discovery_error) == HYPERV_ACCEPTANCE_FAIL);
	assert(!reads && !sessions_started);
	fixtures(0);
	assert(hyperv_acceptance_storage_topology_probe(2, 0, -EAGAIN) ==
	       HYPERV_ACCEPTANCE_FAIL);
	assert(!reads && !sessions_started);

	assert(argc == 2);
	if (!strcmp(argv[1], "end")) {
		fixtures(0);
		fail_end_once = 1;
		assert(hyperv_acceptance_storage_topology_probe(2, 1, 0) ==
		       HYPERV_ACCEPTANCE_FAIL);
		assert(!pending && sessions_active == 1);
		unsigned int prior = reads;

		assert(hyperv_acceptance_storage_topology_probe(2, 1, 0) ==
		       HYPERV_ACCEPTANCE_FAIL);
		assert(reads == prior && !sessions_active &&
		       sessions_started == sessions_ended);
		assert(hyperv_acceptance_storage_topology_probe(2, 1, 0) ==
		       HYPERV_ACCEPTANCE_FAIL);
		assert(reads == prior);
		return 0;
	}
	assert(!strcmp(argv[1], "timeout"));

	fixtures(0);
	injected = HOLD_COMPLETION;
	assert(hyperv_acceptance_storage_topology_probe(2, 1, 0) ==
	       HYPERV_ACCEPTANCE_FAIL);
	assert(now == 7000000000ULL && pending && sessions_active == 1);
	unsigned int before = reads;
	assert(hyperv_acceptance_storage_topology_probe(2, 1, 0) ==
	       HYPERV_ACCEPTANCE_FAIL);
	assert(reads == before && sessions_active == 1);
	injected = NONE;
	assert(!uk_blkdev_queue_finish_reqs(&disks[OS], 0));
	assert(!pending && finish_target == OS);
	assert(hyperv_acceptance_storage_topology_probe(2, 1, 0) ==
	       HYPERV_ACCEPTANCE_FAIL);
	assert(reads == before && !sessions_active &&
	       sessions_started == sessions_ended);
	assert(hyperv_acceptance_storage_topology_probe(2, 1, 0) ==
	       HYPERV_ACCEPTANCE_FAIL);
	assert(reads == before);
	return 0;
}
