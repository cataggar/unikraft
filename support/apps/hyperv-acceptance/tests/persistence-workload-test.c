/* SPDX-License-Identifier: BSD-3-Clause */
#include "acceptance_protocol.h"
#include "persistence.h"
#include "persistence_host.h"
#include "storage_target.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <uk/alloc.h>
#include <uk/blkdev.h>
#include <uk/plat/time.h>
#include <uk/sched.h>
#include <uk/storvsc.h>

#define DISKS 3U
#define DATA 1U
#define SECTORS 8388608ULL
#define SECTOR_SIZE 512U

struct synthetic_disk {
	struct uk_storvsc_target_snapshot target;
	struct uk_blkdev device;
	uint8_t media[65][SECTOR_SIZE];
	unsigned int active;
	unsigned int authorized;
	unsigned int cdb;
	unsigned int writes;
	unsigned int flushes;
	unsigned int releases;
};

static struct synthetic_disk disks[DISKS];
static struct uk_alloc allocator;
static struct uk_blkreq *pending;
static struct synthetic_disk *pending_disk;
static uint64_t clock_ns;
static unsigned int submitted;
static unsigned int completed;
static unsigned int error_at;
static unsigned int timeout_at;
static unsigned int finish_error_at;
static unsigned int corrupt_after_extent;
static unsigned int stale_after_receipt;
static unsigned int release_error;
static unsigned int read10;
static unsigned int read16;
static unsigned int write10;
static unsigned int write16;
static unsigned int extent_reads;
static unsigned int extent_writes;
static unsigned int last_reads;
static unsigned int last_writes;
static unsigned int timeout_events;
static unsigned int status_calls;
static unsigned int inventory_calls;
static unsigned int visible_disks;
static unsigned int pending_status_polls;
static unsigned int discovery_error_after_io;
static unsigned int discovery_error_at_call;
static int discovery_error;
static unsigned int cases;
static char serial[8192];

static struct synthetic_disk *session_disk(
	const struct uk_storvsc_session *session)
{
	assert(session->opaque[0] && session->opaque[0] <= DISKS);
	return &disks[session->opaque[0] - 1];
}

static struct synthetic_disk *device_disk(struct uk_blkdev *device)
{
	for (unsigned int i = 0; i < DISKS; i++)
		if (device == &disks[i].device)
			return &disks[i];
	assert(0);
	return NULL;
}

unsigned int uk_storvsc_mapping_count(void)
{
	return visible_disks;
}

int uk_storvsc_discovery_status(void)
{
	status_calls++;
	if (pending_status_polls) {
		pending_status_polls--;
		return -EAGAIN;
	}
	if (discovery_error_at_call && status_calls != discovery_error_at_call)
		return 0;
	if (!discovery_error_after_io || completed >= discovery_error_after_io)
		return discovery_error;
	return 0;
}

int uk_storvsc_inventory_get(struct uk_storvsc_inventory_snapshot *snapshot)
{
	inventory_calls++;
	*snapshot = (struct uk_storvsc_inventory_snapshot) {
		.version = UK_STORVSC_INVENTORY_SNAPSHOT_VERSION,
		.size = sizeof(*snapshot),
		.topology_generation = visible_disks ? 1 : 0,
		.count = visible_disks,
	};
	return 0;
}

int uk_storvsc_target_get(unsigned int index,
			 struct uk_storvsc_target_snapshot *snapshot)
{
	assert(index < DISKS);
	*snapshot = disks[index].target;
	return 0;
}

int uk_storvsc_inventory_pristine_empty(
	const struct uk_storvsc_inventory_snapshot *first,
	const struct uk_storvsc_inventory_snapshot *second)
{
	return !first->count && !second->count &&
	       !first->topology_generation && !second->topology_generation;
}

struct uk_blkdev *uk_blkdev_get(uint16_t id)
{
	for (unsigned int i = 0; i < DISKS; i++)
		if (id == disks[i].target.mapping.blkdev_id)
			return &disks[i].device;
	return NULL;
}

enum uk_blkdev_state uk_blkdev_state_get(struct uk_blkdev *device)
{
	(void)device;
	return UK_BLKDEV_RUNNING;
}

struct uk_alloc *uk_alloc_get_default(void)
{
	return &allocator;
}

int uk_blkdev_configure(struct uk_blkdev *device,
			const struct uk_blkdev_conf *config)
{
	(void)device;
	(void)config;
	assert(0);
	return -EIO;
}

int uk_blkdev_queue_configure(struct uk_blkdev *device, uint16_t queue,
			      uint16_t descriptors,
			      const struct uk_blkdev_queue_conf *config)
{
	(void)device;
	(void)queue;
	(void)descriptors;
	(void)config;
	assert(0);
	return -EIO;
}

int uk_blkdev_start(struct uk_blkdev *device)
{
	(void)device;
	assert(0);
	return -EIO;
}

int uk_blkdev_queue_intr_enable(struct uk_blkdev *device, uint16_t queue)
{
	(void)device;
	(void)queue;
	assert(0);
	return -EIO;
}

int uk_storvsc_session_begin_read(
	const struct uk_storvsc_target_snapshot *snapshot,
	struct uk_storvsc_session *session)
{
	struct synthetic_disk *disk = device_disk(
		uk_blkdev_get(snapshot->mapping.blkdev_id));

	assert(!disk->active);
	assert(!memcmp(snapshot, &disk->target, sizeof(*snapshot)));
	disk->active = 1;
	disk->authorized = 0;
	disk->cdb = UK_STORVSC_CDB_AUTO;
	memset(session, 0, sizeof(*session));
	session->opaque[0] = (uint64_t)(disk - disks) + 1;
	return 0;
}

int uk_storvsc_session_authorize_write(struct uk_storvsc_session *session)
{
	struct synthetic_disk *disk = session_disk(session);

	assert(disk == &disks[DATA]);
	assert(disk->active && !pending);
	disk->authorized = 1;
	return 0;
}

int uk_storvsc_session_set_cdb(struct uk_storvsc_session *session,
			      uint8_t cdb)
{
	struct synthetic_disk *disk = session_disk(session);

	assert(disk->active && !pending);
	if (!disk->authorized)
		return -EBUSY;
	assert(cdb == UK_STORVSC_CDB_10 || cdb == UK_STORVSC_CDB_16);
	disk->cdb = cdb;
	return 0;
}

int uk_storvsc_session_validate(
	const struct uk_storvsc_session *session,
	struct uk_storvsc_target_snapshot *snapshot)
{
	struct synthetic_disk *disk = session_disk(session);

	assert(disk->active);
	*snapshot = disk->target;
	return 0;
}

int uk_storvsc_session_end(struct uk_storvsc_session *session)
{
	struct synthetic_disk *disk = session_disk(session);

	assert(disk->active && !pending);
	disk->releases++;
	if (release_error == session->opaque[0])
		return -EIO;
	disk->active = 0;
	disk->authorized = 0;
	memset(session, 0, sizeof(*session));
	return 0;
}

static void transfer(struct synthetic_disk *disk, struct uk_blkreq *request)
{
	unsigned int slot = request->start_sector == SECTORS - 1 ?
			    64 : (unsigned int)request->start_sector;
	size_t bytes = request->nb_sectors * SECTOR_SIZE;

	assert(request->start_sector < SECTORS);
	assert(request->start_sector < 64 ||
	       request->start_sector == SECTORS - 1);
	assert(request->nb_sectors &&
	       request->nb_sectors <= SECTORS - request->start_sector);
	assert(request->nb_sectors <= 16);
	assert(slot + request->nb_sectors <= (slot == 64 ? 65 : 64));
	if (request->operation == UK_BLKREQ_WRITE) {
		memcpy(disk->media[slot], request->aio_buf, bytes);
	} else {
		assert(request->operation == UK_BLKREQ_READ);
		memcpy(request->aio_buf, disk->media[slot], bytes);
	}
	if (request->start_sector == SECTORS - 1) {
		assert(request->nb_sectors == 1);
		if (request->operation == UK_BLKREQ_READ)
			last_reads++;
		else
			last_writes++;
	}
	if (request->start_sector ==
	    HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_LBA) {
		assert(bytes == 8192);
		assert(!((uintptr_t)request->aio_buf & 4095));
		if (request->operation == UK_BLKREQ_READ) {
			extent_reads++;
			if (corrupt_after_extent)
				disk->media[corrupt_after_extent][0] ^= 1;
		} else {
			extent_writes++;
		}
	}
	if (stale_after_receipt &&
	    request->operation == UK_BLKREQ_READ &&
	    request->start_sector == HYPERV_ACCEPTANCE_PERSISTENCE_INTENT_LBA &&
	    extent_reads)
		disk->target.controller_generation++;
}

int uk_blkdev_queue_submit_one(struct uk_blkdev *device, uint16_t queue,
			       struct uk_blkreq *request)
{
	struct synthetic_disk *disk = device_disk(device);

	assert(!queue && !pending && disk->active);
	assert(!uk_blkreq_is_done(request));
	if (request->operation != UK_BLKREQ_READ) {
		assert(disk == &disks[DATA] && disk->authorized);
		if (request->operation == UK_BLKREQ_WRITE) {
			disk->writes++;
			if (disk->cdb == UK_STORVSC_CDB_16)
				write16++;
			else
				write10++;
		} else {
			assert(request->operation == UK_BLKREQ_FFLUSH);
			assert(!request->nb_sectors && !request->aio_buf);
			disk->flushes++;
		}
	} else if (disk->cdb == UK_STORVSC_CDB_16) {
		read16++;
	} else {
		read10++;
	}
	submitted++;
	pending = request;
	pending_disk = disk;
	return UK_BLKDEV_STATUS_SUCCESS;
}

int uk_blkdev_queue_finish_reqs(struct uk_blkdev *device, uint16_t queue)
{
	assert(!queue);
	if (!pending)
		return 0;
	assert(pending_disk == device_disk(device));
	if (timeout_at == submitted)
		return 0;
	assert(!uk_blkreq_is_done(pending));
	pending->result = error_at == submitted ? -EIO : 0;
	if (!pending->result && pending->operation != UK_BLKREQ_FFLUSH)
		transfer(pending_disk, pending);
	atomic_store(&pending->state.counter, UK_BLKREQ_FINISHED);
	pending = NULL;
	completed++;
	return finish_error_at == submitted ? -EIO : 0;
}

__nsec ukplat_monotonic_clock(void)
{
	return clock_ns;
}

void uk_sched_thread_sleep(__nsec nanoseconds)
{
	clock_ns += nanoseconds;
}

void hyperv_persistence_host_event(enum hyperv_persistence_host_event event,
				  unsigned int index, int value)
{
	(void)index;
	(void)value;
	if (event == HYPERV_PERSISTENCE_HOST_IO_TIMEOUT)
		timeout_events++;
}

static void reset_boot(void)
{
	assert(!pending);
	hyperv_acceptance_persistence_host_reset();
	clock_ns = 0;
	submitted = completed = error_at = timeout_at = finish_error_at = 0;
	corrupt_after_extent = stale_after_receipt = release_error = 0;
	read10 = read16 = write10 = write16 = 0;
	extent_reads = extent_writes = last_reads = last_writes = 0;
	timeout_events = 0;
	status_calls = inventory_calls = pending_status_polls = 0;
	visible_disks = DISKS;
	discovery_error_after_io = 0;
	discovery_error_at_call = 0;
	discovery_error = 0;
	for (unsigned int i = 0; i < DISKS; i++) {
		disks[i].active = disks[i].authorized = 0;
		disks[i].writes = disks[i].flushes = disks[i].releases = 0;
	}
}

static void fixture(void)
{
	const struct hyperv_acceptance_persistence_expected expected = {
		.run_id = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
		.disk_id = { 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
			     0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f },
		.sectors = SECTORS,
		.sector_size = SECTOR_SIZE,
		.lun = 7,
		.identity_policy =
			HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2,
	};

	reset_boot();
	memset(disks, 0, sizeof(disks));
	for (unsigned int i = 0; i < DISKS; i++) {
		struct uk_storvsc_target_snapshot *target = &disks[i].target;

		target->version = UK_STORVSC_TARGET_SNAPSHOT_VERSION;
		target->size = sizeof(*target);
		target->topology_generation = 1;
		target->controller_generation = 1;
		target->lun_generation = 1;
		target->mapping.blkdev_id = i == DATA ? 0 : 20 + i;
		target->mapping.controller_index = i == DATA ? 1 : 0;
		target->mapping.instance_id[0] =
			target->mapping.controller_index + 1;
		target->mapping.path_id = 4;
		target->mapping.target_id = 5;
		target->mapping.lun = i == DATA ? 7 : i;
		target->mapping.sectors = SECTORS;
		target->mapping.sector_size = SECTOR_SIZE;
		target->mapping.vpd_length = 1;
		target->mapping.vpd_code_set = 1;
		target->mapping.vpd_designator_type = 3;
		target->mapping.vpd_id[0] = i + 1;
	}
	disks[0].media[0][510] = 0x55;
	disks[0].media[0][511] = 0xaa;
	assert(!hyperv_acceptance_persistence_build_manifest(
		&expected, disks[DATA].media[8]));
	memcpy(disks[DATA].media[9], disks[DATA].media[8], SECTOR_SIZE);
}

static int run(void)
{
	int output[2];
	int saved;
	int result;
	size_t used = 0;
	ssize_t got;

	fflush(stdout);
	assert(!pipe(output));
	saved = dup(STDOUT_FILENO);
	assert(saved >= 0 && dup2(output[1], STDOUT_FILENO) >= 0);
	close(output[1]);
	result = hyperv_acceptance_persistence_main();
	fflush(stdout);
	assert(dup2(saved, STDOUT_FILENO) >= 0);
	close(saved);
	while ((got = read(output[0], serial + used,
			   sizeof(serial) - 1 - used)) > 0)
		used += (size_t)got;
	assert(!got && used < sizeof(serial) - 1);
	close(output[0]);
	serial[used] = 0;
	assert(!disks[0].writes && !disks[0].flushes);
	assert(!disks[2].writes && !disks[2].flushes);
	return result;
}

static void success(unsigned int boot)
{
	assert(run() == HYPERV_ACCEPTANCE_PASS);
	assert(strstr(serial,
		"UK_HYPERV_PERSISTENCE_IDENTITY:1:2:"
		"00112233445566778899aabbccddeeff:"
		"102132435465768798a9bacbdcedfe0f:"
		"02000000000000000000000000000000:"
		"4:5:7:8388608:512:1:1:3:0:02\n"));
	assert(strstr(serial, "HYPERV_PERSISTENCE FINAL PASS rc=0\n"));
	assert(strstr(serial, boot == 1 ?
		"UK_HYPERV_PERSISTENCE_IO:1:1:00112233445566778899aabbccddeeff:5:3:receipt-verified\n" :
		"UK_HYPERV_PERSISTENCE_IO:1:2:00112233445566778899aabbccddeeff:0:0:receipt-verified\n"));
	assert(strstr(serial, boot == 1 ?
		"UK_HYPERV_PERSISTENCE_BOOT1_COMPLETE:" :
		"UK_HYPERV_PERSISTENCE_BOOT2_COMPLETE:"));
	assert(!strstr(serial, boot == 1 ? "BOOT2_" : "BOOT1_"));
	assert(submitted == completed);
	assert(!disks[DATA].active && disks[DATA].releases == 1);
	assert(disks[DATA].writes == (boot == 1 ? 5U : 0U));
	assert(disks[DATA].flushes == (boot == 1 ? 3U : 0U));
	assert(extent_reads == (boot == 1 ? 2U : 1U));
	assert(extent_writes == (boot == 1 ? 1U : 0U));
	assert(last_reads == (boot == 1 ? 2U : 1U));
	assert(last_writes == (boot == 1 ? 1U : 0U));
	cases++;
}

static void failure(void)
{
	assert(run() == HYPERV_ACCEPTANCE_FAIL);
	assert(strstr(serial, " FAIL "));
	assert(!strstr(serial, "UK_HYPERV_PERSISTENCE_BOOT"));
	assert(!strstr(serial, "UK_HYPERV_PERSISTENCE_IO:"));
	assert(!strstr(serial, "HYPERV_PERSISTENCE BOOT"));
	assert(!strstr(serial, "HYPERV_PERSISTENCE FINAL PASS"));
	if (!pending)
		assert(submitted == completed);
	cases++;
}

static void no_mutation(void)
{
	failure();
	assert(!disks[DATA].writes && !disks[DATA].flushes);
}

static void test_success(void)
{
	uint8_t seeds[2][SECTOR_SIZE];
	uint8_t original[65][SECTOR_SIZE];
	uint8_t os[65][SECTOR_SIZE];
	uint8_t unintended[65][SECTOR_SIZE];

	fixture();
	memcpy(seeds, disks[DATA].media[8], sizeof(seeds));
	memcpy(os, disks[0].media, sizeof(os));
	memcpy(unintended, disks[2].media, sizeof(unintended));
	success(1);
	assert(read10 && read16 && write10 && write16);
	assert(!memcmp(seeds, disks[DATA].media[8], sizeof(seeds)));
	assert(!memcmp(os, disks[0].media, sizeof(os)));
	assert(!memcmp(unintended, disks[2].media, sizeof(unintended)));
	memcpy(original, disks[DATA].media, sizeof(original));
	reset_boot();
	success(2);
	assert(!write10 && !write16);
	assert(!memcmp(original, disks[DATA].media, sizeof(original)));
	assert(!memcmp(os, disks[0].media, sizeof(os)));
	assert(!memcmp(unintended, disks[2].media, sizeof(unintended)));

	fixture();
	disks[2].target.mapping.lun = 7;
	success(1);
	assert(disks[2].releases == 1 && !disks[2].active);
	assert(!memcmp(unintended, disks[2].media, sizeof(unintended)));
}

static void test_finalization(void)
{
	for (unsigned int boot = 1; boot <= 2; boot++) {
		fixture();
		if (boot == 2) {
			success(1);
			reset_boot();
		}
		release_error = DATA + 1;
		failure();
		assert(disks[DATA].releases == 1);
		assert(strstr(serial, "HYPERV_PERSISTENCE FINAL FAIL"));

		fixture();
		if (boot == 2) {
			success(1);
			reset_boot();
		}
		stale_after_receipt = 1;
		failure();
		assert(disks[DATA].releases == 1);
		assert(!disks[DATA].active);
	}
	for (unsigned int lba = 8; lba <= 17; lba++) {
		if (lba > 9 && lba < 16)
			continue;
		fixture();
		success(1);
		reset_boot();
		corrupt_after_extent = lba;
		no_mutation();
		assert(disks[DATA].releases == 1);
		assert(!disks[DATA].active);
	}
}

static void test_selection_cleanup(void)
{
	fixture();
	disks[2].target.mapping.lun = 7;
	error_at = 4;
	no_mutation();
	assert(disks[DATA].releases == 1 && !disks[DATA].active);
	assert(disks[2].releases == 1 && !disks[2].active);

	for (unsigned int boot_signature = 0; boot_signature <= 1;
	     boot_signature++) {
		fixture();
		disks[2].target.mapping.lun = 7;
		if (boot_signature) {
			disks[2].media[0][510] = 0x55;
			disks[2].media[0][511] = 0xaa;
		}
		release_error = 3;
		no_mutation();
		assert(disks[DATA].releases == 1 && !disks[DATA].active);
		assert(disks[2].releases == 1);
	}
}

static void test_refusals(void)
{
	fixture();
	disks[DATA].target.mapping.lun = 6;
	no_mutation();
	fixture();
	disks[DATA].target.mapping.sectors--;
	no_mutation();
	fixture();
	disks[DATA].target.mapping.sectors++;
	no_mutation();
	fixture();
	disks[DATA].target.mapping.sector_size = 4096;
	no_mutation();
	fixture();
	disks[DATA].target.mapping.read_only = 1;
	no_mutation();
	fixture();
	disks[DATA].target.mapping.vpd_length = 0;
	no_mutation();
	fixture();
	disks[DATA].target.mapping.vpd_length = 65;
	no_mutation();
	fixture();
	disks[0].target.mapping.lun = 7;
	no_mutation();
	fixture();
	disks[DATA].media[8][16] ^= 1;
	no_mutation();
	fixture();
	disks[DATA].media[9][32] ^= 1;
	no_mutation();
	fixture();
	disks[2].target.mapping.lun = 7;
	memcpy(disks[2].media[8], disks[DATA].media[8], 2 * SECTOR_SIZE);
	no_mutation();
	assert(!disks[DATA].active && !disks[2].active);
}

static void test_boot2_refusals(void)
{
	for (unsigned int changed = 0; changed < 7; changed++) {
		fixture();
		success(1);
		reset_boot();
		switch (changed) {
		case 0: disks[DATA].target.mapping.instance_id[0] ^= 1; break;
		case 1: disks[DATA].target.mapping.path_id++; break;
		case 2: disks[DATA].target.mapping.target_id++; break;
		case 3: disks[DATA].target.mapping.vpd_id[0] ^= 1; break;
		case 4: disks[DATA].media[0][0] ^= 1; break;
		case 5: disks[DATA].media[64][0] ^= 1; break;
		case 6: disks[DATA].media[47][511] ^= 1; break;
		}
		no_mutation();
	}
	fixture();
	success(1);
	reset_boot();
	memset(disks[DATA].media[17], 0, SECTOR_SIZE);
	no_mutation();
}

static void test_io_failures(void)
{
	unsigned int requests[2];

	fixture();
	success(1);
	requests[0] = submitted;
	reset_boot();
	success(2);
	requests[1] = submitted;
	for (unsigned int boot = 1; boot <= 2; boot++) {
		for (unsigned int at = 1; at <= requests[boot - 1]; at++) {
			fixture();
			if (boot == 2) {
				success(1);
				reset_boot();
			}
			error_at = at;
			failure();
			assert(!disks[DATA].active);
			assert(disks[DATA].releases == 1);
			if (boot == 2)
				assert(!disks[DATA].writes && !disks[DATA].flushes);
		}
	}
	fixture();
	finish_error_at = 4;
	failure();
	assert(disks[DATA].writes == 1 && !disks[DATA].flushes);
}

static void test_timeout_ownership(void)
{
	unsigned int requests[2];

	fixture();
	success(1);
	requests[0] = submitted;
	reset_boot();
	success(2);
	requests[1] = submitted;
	for (unsigned int boot = 1; boot <= 2; boot++) {
		for (unsigned int at = 1; at <= requests[boot - 1]; at++) {
			uint8_t saved[8192];
			size_t bytes;
			unsigned int count;

			fixture();
			if (boot == 2) {
				success(1);
				reset_boot();
			}
			timeout_at = at;
			failure();
			assert(timeout_events == 1 && pending);
			assert(hyperv_acceptance_persistence_host_request_owned());
			assert(!hyperv_acceptance_persistence_host_request_done());
			assert(!disks[DATA].releases);
			bytes = pending->nb_sectors * SECTOR_SIZE;
			assert(bytes <= sizeof(saved));
			if (bytes)
				memcpy(saved, pending->aio_buf, bytes);
			count = submitted;
			failure();
			assert(submitted == count);
			if (bytes)
				assert(!memcmp(saved, pending->aio_buf, bytes));
			timeout_at = 0;
			assert(!uk_blkdev_queue_finish_reqs(
				&disks[DATA].device, 0));
			assert(hyperv_acceptance_persistence_host_request_done());
			assert(completed == submitted);
			failure();
			assert(submitted == count);
			if (boot == 2)
				assert(!disks[DATA].writes && !disks[DATA].flushes);
		}
	}
	reset_boot();
}

static void test_discovery_readiness(void)
{
	const int terminal[] = { -ENOSPC, -EPROTO, -EIO, -ENOENT, -ESTALE };
	unsigned int requests;

	for (unsigned int i = 0; i < sizeof(terminal) / sizeof(terminal[0]);
	     i++) {
		char marker[80];

		fixture();
		discovery_error = terminal[i];
		no_mutation();
		snprintf(marker, sizeof(marker),
			 "HYPERV_PERSISTENCE SELECT FAIL rc=%d writes=0\n",
			 terminal[i]);
		assert(strstr(serial, marker));
		assert(status_calls == 1 && !inventory_calls && !submitted);
		assert(!clock_ns);
	}
	for (unsigned int at = 2; at <= 5; at++) {
		fixture();
		discovery_error = -ESTALE;
		discovery_error_at_call = at;
		no_mutation();
		assert(status_calls == at && !clock_ns);
		assert(!disks[DATA].active);
	}
	fixture();
	pending_status_polls = 2;
	success(1);
	assert(clock_ns == 2 * PERSISTENCE_POLL_NS);

	fixture();
	pending_status_polls = UINT32_MAX;
	no_mutation();
	assert(clock_ns == PERSISTENCE_BIND_TIMEOUT_NS);
	assert(!inventory_calls && !submitted);

	fixture();
	visible_disks = 0;
	assert(run() == HYPERV_ACCEPTANCE_UNAVAILABLE);
	assert(strstr(serial, "UK_HYPERV_PERSISTENCE_UNAVAILABLE:1:2:no-devices"));
	assert(clock_ns == PERSISTENCE_BIND_TIMEOUT_NS);
	assert(!submitted && !disks[DATA].writes && !disks[DATA].flushes);
	cases++;
	fixture();
	visible_disks = 0;
	pending_status_polls = 1;
	no_mutation();
	assert(!strstr(serial, "UNAVAILABLE"));
	assert(!strstr(serial, "UK_HYPERV_PLATFORM_READY"));
	assert(!submitted);

	fixture();
	discovery_error = -ENOSPC;
	discovery_error_after_io = 3;
	no_mutation();
	assert(disks[DATA].releases == 1 && !disks[DATA].active);

	fixture();
	success(1);
	requests = submitted;
	fixture();
	discovery_error = -ENOSPC;
	discovery_error_after_io = requests;
	failure();
	assert(disks[DATA].writes == 5 && disks[DATA].flushes == 3);
	assert(disks[DATA].releases == 1 && !disks[DATA].active);
}

static void test_storage_target_readiness(void)
{
	struct hyperv_acceptance_storage_target target;

	fixture();
	pending_status_polls = 1;
	assert(hyperv_acceptance_storage_target_acquire(&target) == -EAGAIN);
	assert(!inventory_calls && !target.device && !submitted);
	cases++;
	fixture();
	discovery_error = -ENOSPC;
	assert(hyperv_acceptance_storage_target_acquire(&target) == -ENOSPC);
	assert(!inventory_calls && !target.device && !submitted);
	cases++;
	fixture();
	assert(!hyperv_acceptance_storage_target_acquire(&target));
	assert(target.device == &disks[0].device);
	assert(!hyperv_acceptance_storage_target_validate(&target));
	pending_status_polls = 1;
	assert(hyperv_acceptance_storage_target_validate(&target) == -EAGAIN);
	discovery_error = -EPROTO;
	assert(hyperv_acceptance_storage_target_validate(&target) == -EPROTO);
	assert(!hyperv_acceptance_storage_target_release(&target));
	assert(!target.device && !disks[0].active && !submitted);
	cases++;
	fixture();
	disks[0].target.mapping.lun = 1;
	assert(hyperv_acceptance_storage_target_acquire(&target) == -ENODEV);
	assert(!target.device && !submitted);
	cases++;
	fixture();
	disks[2].target.mapping.lun = 0;
	disks[2].target.mapping.controller_index = 1;
	disks[2].target.mapping.instance_id[0] = 2;
	assert(hyperv_acceptance_storage_target_acquire(&target) == -EEXIST);
	assert(!target.device && !submitted);
	cases++;
}

int main(void)
{
	test_success();
	test_finalization();
	test_selection_cleanup();
	test_refusals();
	test_boot2_refusals();
	test_io_failures();
	test_timeout_ownership();
	test_discovery_readiness();
	test_storage_target_readiness();
	printf("persistence-workload-test: %u synthetic cases passed\n", cases);
	return 0;
}
