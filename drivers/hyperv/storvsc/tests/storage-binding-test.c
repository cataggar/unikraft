/* SPDX-License-Identifier: BSD-3-Clause */
#define main storage_binding_existing_main
#define ukplat_monotonic_clock storage_binding_real_clock
#define vmbus_channel_send_gpa_direct_ex storage_binding_original_gpa
#define vmbus_channel_close storage_binding_original_close
#include "../../../../support/build/tests/storvsc-production-test.c"
#undef main
#undef ukplat_monotonic_clock
#undef vmbus_channel_send_gpa_direct_ex
#undef vmbus_channel_close
#include <stdarg.h>
#include "../../vmbus/include/uk/vmbus_storage.h"

int vmbus_bus_host_storage_enumeration(unsigned int stage);
int vmbus_bus_host_storage_prefix(unsigned int length, int nonstorage);
unsigned int storvsc_host_discovery_owned(unsigned int controller);
int storvsc_host_discovery_quarantined(unsigned int controller);

static uint64_t clock_offset;
static unsigned int discovery_sends;
static unsigned int expired_inquiries;
static int expire_inquiry;
static int expire_lun = -1;
static int close_with_epoch_proof;
static int topology_swap_seed;
static int topology_duplicate_boot;
static int topology_corrupt_seed_copy;
static int topology_seed_fixture;
static unsigned int topology_seed_reads[2];
static unsigned int pool_log_count;
static char pool_log[256];

void storage_binding_capture_log(const char *format, ...)
{
	char message[sizeof(pool_log)];
	va_list args;

	va_start(args, format);
	vsnprintf(message, sizeof(message), format, args);
	va_end(args);
	if (strstr(message, "pool exhausted")) {
		pool_log_count++;
		strcpy(pool_log, message);
	}
}

static void seeded_topology_read(
	struct vmbus_channel *channel, const uint8_t *packet)
{
	struct hyperv_acceptance_persistence_expected expected = {
		.sector_size = HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE,
		.identity_policy =
			HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2,
	};
	uint8_t bytes[2 * HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE] = { 0 };
	uint8_t lun = packet[19];
	uint8_t opcode = packet[28];
	uint64_t lba = scsi_io_lba(packet, opcode);
	int data = channel->device->instance_id.bytes[0] == 2;
	int role = lun == 0 ? 0 : 1;

	if (get_le32(packet, 24) != sizeof(bytes) ||
	    (lba != 0 && lba != HYPERV_ACCEPTANCE_PERSISTENCE_SEED0_LBA))
		abort();
	if (lba == 0) {
		if ((!data && !lun) ||
		    (topology_duplicate_boot && data && !lun)) {
			bytes[510] = 0x55;
			bytes[511] = 0xaa;
			memcpy(bytes + 512, "EFI PART", 8);
		}
	} else if (lba == HYPERV_ACCEPTANCE_PERSISTENCE_SEED0_LBA &&
		   data && (lun == 0 ||
			    lun == CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_NONZERO_LUN)) {
		expected.lun = role ?
			CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_NONZERO_LUN : 0;
		expected.sectors = role ?
			CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_SECTORS :
			CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_SECTORS;
		if (hyperv_acceptance_parse_hex_id(
			    CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_RUN_ID,
			    expected.run_id) ||
		    hyperv_acceptance_parse_hex_id(
			    topology_swap_seed && !role ?
			    CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_ID :
			    role ?
			    CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_ID :
			    CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_ID,
			    expected.disk_id) ||
		    hyperv_acceptance_persistence_build_manifest(
			    &expected, bytes))
			abort();
		memcpy(bytes + 512, bytes, 512);
		if (topology_corrupt_seed_copy && role)
			bytes[512 + 48] ^= 1;
		topology_seed_reads[role]++;
	}
	memcpy(backing_media + lba * 512, bytes, sizeof(bytes));
}

__nsec ukplat_monotonic_clock(void)
{
	return storage_binding_real_clock() + clock_offset;
}

int vmbus_channel_send_gpa_direct_ex(
	struct vmbus_channel *channel, __u16 flags, __u64 id,
	const struct vmbus_gpa_range *ranges, __u32 range_count,
	const void *payload, size_t payload_size, int *published)
{
	const uint8_t *packet = payload;

	discovery_sends++;
	if (topology_seed_fixture && payload_size >= 30 &&
	    (packet[28] == 0x28 || packet[28] == 0x88))
		seeded_topology_read(channel, packet);
	if (expire_inquiry && payload_size >= 30 && packet[28] == 0x12 &&
	    !(packet[29] & 1) && (expire_lun < 0 || packet[19] == expire_lun)) {
		/* A regressed second submission fails immediately, never hangs. */
		if (expired_inquiries++) {
			*published = 0;
			return -EIO;
		}
		*published = 1;
		clock_offset += CONFIG_LIBSTORVSC_CONTROL_TIMEOUT_MS *
			1000000ULL + 1;
		return 0;
	}
	return storage_binding_original_gpa(channel, flags, id, ranges,
		range_count, payload, payload_size, published);
}

int vmbus_channel_close(struct vmbus_channel *channel)
{
	int rc = storage_binding_original_close(channel);

	if (!rc && close_with_epoch_proof) {
		close_with_epoch_proof = 0;
		if (vmbus_bus_host_connection_quiesce())
			abort();
		return -ECANCELED;
	}
	return rc;
}

static const struct vmbus_guid os_id = { .bytes = { 1, 0x89 } };
static const struct vmbus_guid data_id = { .bytes = { 2, 0x89 } };
static const struct vmbus_guid excess_id = { .bytes = { 3, 0x89 } };

#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "storage-binding-test:%d: %s\n", \
			__LINE__, #condition); \
		return 1; \
	} \
} while (0)

static int test_hex_id(void)
{
	uint8_t id[16];

	CHECK(!hyperv_acceptance_parse_hex_id(
		"00112233445566778899aabbccddeeff", id));
	CHECK(id[0] == 0 && id[1] == 0x11 &&
	      id[14] == 0xee && id[15] == 0xff);
	CHECK(hyperv_acceptance_parse_hex_id("", id));
	CHECK(hyperv_acceptance_parse_hex_id("0", id));
	CHECK(hyperv_acceptance_parse_hex_id(
		"00112233445566778899aabbccddeef", id));
	CHECK(hyperv_acceptance_parse_hex_id(
		"00112233445566778899aabbccddeeff0", id));
	CHECK(hyperv_acceptance_parse_hex_id(
		"00112233445566778899aabbccddeefZ", id));
	CHECK(hyperv_acceptance_parse_hex_id(
		"00112233445566778899aabbccddeefF", id));
	CHECK(hyperv_acceptance_parse_hex_id(NULL, id));
	CHECK(hyperv_acceptance_parse_hex_id(
		"00112233445566778899aabbccddeeff", NULL));
	return 0;
}

static int setup(void)
{
	CHECK(!vmbus_bus_host_offer_lifetime_setup(storvsc_host_driver()));
	use_vmbus_offer_lifetimes = 1;
	storvsc_host_set_lun_discovery(1);
	storvsc_host_set_guarded_io(1);
	report_luns_mode = REPORT_LUNS_SINGLE;
	vpd_mode = VPD_NORMAL;
	return 0;
}

static int offer(const struct vmbus_guid *id, uint32_t channel, uint8_t lun)
{
	single_report_lun = lun;
	return vmbus_bus_host_offer_storage(id, channel, channel + 100);
}

static int saturated_controller_requests(
	const struct uk_storvsc_mapping mappings[4],
	struct uk_blkdev *const disks[4], uint8_t *buffer, int reverse)
{
	struct uk_blkreq requests[5];
	struct uk_blkreq overflow;
	atomic_int callbacks;
	unsigned int first = reverse ? 2 : 0;
	unsigned int other = reverse ? 0 : 2;
	unsigned int target;
	unsigned int sent;

	CHECK(CONFIG_LIBSTORVSC_QUEUE_DEPTH == 4);
	atomic_init(&callbacks, 0);
	hold_io = 1;
	pending_count = 0;
	for (unsigned int i = 0; i < 4; i++) {
		target = first + (i & 1);
		initialize_request(&requests[i], UK_BLKREQ_READ, 20 + i, 1,
				   buffer + i * 512, request_done, &callbacks);
		CHECK(disks[target]->submit_one(
			      disks[target], disks[target]->_queue[0],
			      &requests[i]) & UK_BLKDEV_STATUS_SUCCESS);
	}
	CHECK(pending_count == 4);
	sent = discovery_sends;
	initialize_request(&overflow, UK_BLKREQ_READ, 24, 1,
			   buffer + 2560, NULL, NULL);
	CHECK(disks[first]->submit_one(disks[first], disks[first]->_queue[0],
				       &overflow) == -ENOSPC);
	CHECK(discovery_sends == sent && pending_count == 4 &&
	      !storvsc_host_request_bound(&overflow));
	CHECK(pool_log_count == 1 &&
	      strstr(pool_log, reverse ?
		     "controller0 relid=12 0:0:0 request pool exhausted (max 4)" :
		     "controller0 relid=10 0:0:0 request pool exhausted (max 4)"));

	initialize_request(&requests[4], UK_BLKREQ_READ, 25, 1,
			   buffer + 2048, request_done, &callbacks);
	CHECK(disks[other]->submit_one(disks[other], disks[other]->_queue[0],
				       &requests[4]) & UK_BLKDEV_STATUS_SUCCESS);
	CHECK(pending_count == 5);
	complete_pending_reverse(0);
	fire_channel_on(&host_channels[1]);
	fire_channel_on(&host_channels[0]);
	CHECK(!wait_atomic_value(&callbacks, 5,
				 CONFIG_LIBSTORVSC_REQUEST_TIMEOUT_MS));
	CHECK(atomic_load(&callbacks) == 5);
	for (unsigned int i = 0; i < 5; i++) {
		target = i == 4 ? other : first + (i & 1);
		CHECK(atomic_load(&requests[i].state.counter) ==
		      UK_BLKREQ_FINISHED);
		CHECK(requests[i].result == 0 &&
		      buffer[i * 512] ==
			      (uint8_t)((target >= 2 ? 0x30 : 0x20) +
					mappings[target].lun));
	}
	hold_io = 0;
	return 0;
}

static int pair(int reverse, int empty)
{
	struct uk_storvsc_inventory_snapshot inventory;
	struct uk_storvsc_mapping mapping;
	struct uk_storvsc_mapping mappings[4];
	unsigned int reports = 0;
	unsigned int data_found = 0;
	unsigned int os_found = 0;

	CHECK(!setup());
	if (!empty && CONFIG_LIBSTORVSC_MAX_DEVICES > 1)
		topology_fixture = 1;
	for (unsigned int i = 0; i < 2; i++) {
		int data = (i == 1) != reverse;

		report_luns_mode = data && empty ? REPORT_LUNS_EMPTY :
			topology_fixture ? REPORT_LUNS_NORMAL :
			REPORT_LUNS_SINGLE;
		CHECK(!offer(data ? &data_id : &os_id,
			     data ? 12 : 10, data ? 7 : 0));
		reports += data && empty ? 2 : 1;
	}
	if (CONFIG_LIBSTORVSC_MAX_DEVICES == 1) {
		CHECK(uk_storvsc_discovery_status() == -ENOSPC);
		CHECK(uk_storvsc_inventory_get(&inventory) == -EAGAIN);
		CHECK(uk_storvsc_mapping_count() == (reverse && empty ? 0 : 1));
		CHECK(pool_log_count == 1 &&
		      strstr(pool_log, "controller pool exhausted (max 1)"));
		return 0;
	}
	CHECK(!vmbus_storage_binding_status());
	CHECK(!uk_storvsc_discovery_status());
	CHECK(!uk_storvsc_inventory_get(&inventory));
	if (inventory.count != (empty ? 1U : 4U))
		fprintf(stderr,
			"pair reverse=%d empty=%d count=%u reports=%u fixture=%d\n",
			reverse, empty, inventory.count, report_luns_commands,
			topology_fixture);
	CHECK(inventory.count == (empty ? 1U : 4U));
	CHECK(report_luns_commands == reports);
	CHECK(storvsc_host_controller_online(0));
	CHECK(storvsc_host_controller_online(1));
	for (unsigned int i = 0; i < inventory.count; i++) {
		int data = !empty && i >= 2;
		unsigned int controller = data == reverse ? 0 : 1;
		uint8_t lun = empty || !(i & 1) ? 0 :
			(data ? 3 : 2);

		CHECK(!uk_storvsc_mapping_get(i, &mapping));
		mappings[i] = mapping;
		CHECK(mapping.controller_index == controller);
		CHECK(mapping.path_id == 0 && mapping.target_id == 0);
		CHECK(mapping.vpd_length == 8);
		CHECK(mapping.lun == lun);
		CHECK(mapping.sectors == (empty ? 1000U :
		      (data + 1) * 1000U + lun * 100U));
		CHECK(mapping.sector_size == 512);
		CHECK(mapping.read_only == (data && lun == 3));
		CHECK(mapping.vpd_id[7] == lun);
		CHECK(mapping.channel_id == (data ? 12U : 10U));
		CHECK(!memcmp(mapping.instance_id,
			      data ? data_id.bytes : os_id.bytes,
			      VMBUS_GUID_SIZE));
		for (unsigned int j = 0; j < i; j++)
			CHECK(mapping.blkdev_id != mappings[j].blkdev_id);
		CHECK(!uk_storvsc_mapping_find(mapping.blkdev_id, &mappings[i]));
		CHECK(!memcmp(&mapping, &mappings[i], sizeof(mapping)));
		if (data)
			data_found++;
		else
			os_found++;
	}
	CHECK(os_found == (empty ? 1U : 2U));
	CHECK(data_found == (empty ? 0U : 2U));
	if (!empty) {
		struct uk_storvsc_target_snapshot targets[4];
		struct uk_storvsc_session sessions[4];
		struct uk_blkdev *disks[4];
		struct uk_blkreq requests[4];
		struct uk_blkreq retry;
		atomic_int callbacks;
		uint8_t *buffer;
		int events[4] = { 0 };

		CHECK(!posix_memalign((void **)&buffer, 4096, 4096));
		atomic_init(&callbacks, 0);
		for (unsigned int i = 0; i < 4; i++) {
			disks[i] = storvsc_host_blkdev_address(
				mappings[i].controller_index, mappings[i].lun);
			CHECK(disks[i] &&
			      disks[i]->capabilities.sectors ==
				      mappings[i].sectors &&
			      disks[i]->capabilities.ssize == 512 &&
			      disks[i]->capabilities.mode ==
				      (mappings[i].read_only ? O_RDONLY : O_RDWR));
			CHECK(!configure_device(disks[i], 4, &events[i]));
			CHECK(!uk_storvsc_target_get(i, &targets[i]));
			CHECK(!uk_storvsc_session_begin_read(
				&targets[i], &sessions[i]));
		}
		hold_io = 1;
		for (unsigned int i = 0; i < 4; i++) {
			initialize_request(&requests[i], UK_BLKREQ_READ, 8, 1,
					   buffer + i * 512, request_done,
					   &callbacks);
			CHECK(disks[i]->submit_one(disks[i], disks[i]->_queue[0],
						   &requests[i]) &
			      UK_BLKDEV_STATUS_SUCCESS);
		}
		CHECK(pending_count == 4);
		CHECK(pending[0].id == pending[2].id &&
		      pending[1].id == pending[3].id);
		CHECK(!hold_receive_gate(0));
		for (unsigned int i = 4; i > 0; i--) {
			struct pending_io *entry = &pending[i - 1];
			int error = i == 3;

			enqueue_completion_on(entry->channel, entry->id, 64,
					      error, 1, 0,
					      error ? 0 : entry->length);
		}
		pending_count = 0;
		fire_channel_on(&host_channels[1]);
		CHECK(!wait_atomic_value(&callbacks, 2,
					 CONFIG_LIBSTORVSC_REQUEST_TIMEOUT_MS));
		for (unsigned int i = 0; i < 4; i++) {
			if (mappings[i].controller_index == 1)
				CHECK(atomic_load(&requests[i].state.counter) ==
				      UK_BLKREQ_FINISHED);
			else
				CHECK(requests[i].result == -EINPROGRESS &&
				      atomic_load(&requests[i].state.counter) ==
				      UK_BLKREQ_UNFINISHED);
		}
		release_receive_gate();
		fire_channel_on(&host_channels[0]);
		CHECK(!wait_atomic_value(&callbacks, 4,
					 CONFIG_LIBSTORVSC_REQUEST_TIMEOUT_MS));
		for (unsigned int i = 0; i < 4; i++) {
			CHECK(atomic_load(&requests[i].state.counter) ==
			      UK_BLKREQ_FINISHED);
			CHECK(requests[i].result == (i == 2 ? -EIO : 0));
			if (i != 2)
				CHECK(buffer[i * 512] ==
				      (uint8_t)((i >= 2 ? 0x30 : 0x20) +
						mappings[i].lun));
		}
		hold_io = 0;
		initialize_request(&retry, UK_BLKREQ_READ, 10, 1,
				   buffer + 2048, request_done, &callbacks);
		CHECK(disks[2]->submit_one(disks[2], disks[2]->_queue[0],
					   &retry) & UK_BLKDEV_STATUS_SUCCESS);
		fire_channel_on(&host_channels[mappings[2].controller_index]);
		CHECK(!wait_atomic_value(&callbacks, 5,
					 CONFIG_LIBSTORVSC_REQUEST_TIMEOUT_MS));
		CHECK(retry.result == 0 && buffer[2048] == 0x30);
		CHECK(!saturated_controller_requests(
			mappings, disks, buffer, reverse));
		for (unsigned int i = 0; i < 4; i++)
			CHECK(!uk_storvsc_session_end(&sessions[i]));
		{
			unsigned int reads = io_command_count;

			CHECK(hyperv_acceptance_storage_topology_probe(
				      2, 0, 0) == HYPERV_ACCEPTANCE_FAIL);
			CHECK(hyperv_acceptance_storage_topology_probe(
				      2, 1, -ENOSPC) == HYPERV_ACCEPTANCE_FAIL);
			CHECK(io_command_count == reads);
		}
		topology_seed_fixture = 1;
		backing_media_enabled = 1;
		CHECK(hyperv_acceptance_storage_topology_probe(
			      2, 1, 0) == HYPERV_ACCEPTANCE_PASS);
		CHECK(topology_seed_reads[0] == 1 &&
		      topology_seed_reads[1] == 1);
		topology_swap_seed = 1;
		CHECK(hyperv_acceptance_storage_topology_probe(
			      2, 1, 0) == HYPERV_ACCEPTANCE_FAIL);
		topology_swap_seed = 0;
		topology_corrupt_seed_copy = 1;
		CHECK(hyperv_acceptance_storage_topology_probe(
			      2, 1, 0) == HYPERV_ACCEPTANCE_FAIL);
		topology_corrupt_seed_copy = 0;
		topology_duplicate_boot = 1;
		CHECK(hyperv_acceptance_storage_topology_probe(
			      2, 1, 0) == HYPERV_ACCEPTANCE_FAIL);
		topology_duplicate_boot = 0;
		backing_media_enabled = 0;
		topology_seed_fixture = 0;
		free(buffer);
	}
	CHECK(!write10_command_count && !write16_command_count &&
	      !flush_command_count);
	return 0;
}

static int rejected(int before_admission)
{
	struct uk_storvsc_inventory_snapshot inventory;
	struct uk_storvsc_target_snapshot target;
	struct uk_storvsc_session session;
	struct uk_blkdev *disk;
	struct uk_blkreq request;
	uint8_t *buffer;
	int events = 0;
	int rc;

	CHECK(!setup());
	CHECK(!offer(&os_id, 10, 0));
	CHECK(!offer(&data_id, 12, 7));
	disk = storvsc_host_blkdev_address(1, 7);
	CHECK(disk && !activate_device(disk, &events));
	CHECK(!target_for_device(disk, &target));
	CHECK(!uk_storvsc_session_begin_read(&target, &session));
	CHECK(!uk_storvsc_session_authorize_write(&session));
	CHECK(!posix_memalign((void **)&buffer, 4096, 4096));
	if (before_admission)
		CHECK(vmbus_bus_host_fill_nonstorage_offers(40) == -ENOSPC);
	rc = offer(&excess_id, 20, 7);
	CHECK(rc == (before_admission ? -ENOSPC : 0));
	CHECK(pool_log_count == (before_admission ? 0U : 1U));
	if (!before_admission)
		CHECK(strstr(pool_log,
			     "controller pool exhausted (max 2) for relid=20"));
	CHECK(uk_storvsc_mapping_count() == 2);
	CHECK(uk_storvsc_inventory_get(&inventory) == -EAGAIN);
	CHECK(uk_storvsc_discovery_status() == -ENOSPC);
	CHECK(uk_storvsc_session_validate(&session, &target) == -ESTALE);
	for (unsigned int i = 0; i < 3; i++) {
		static const enum uk_blkreq_op operations[] = {
			UK_BLKREQ_READ, UK_BLKREQ_WRITE, UK_BLKREQ_FFLUSH
		};

		initialize_request(&request, operations[i], 8, 1, buffer,
				   NULL, NULL);
		CHECK(disk->submit_one(disk, disk->_queue[0], &request) ==
		      -EACCES);
	}
	CHECK(!write10_command_count && !write16_command_count &&
	      !flush_command_count);
	if (!before_admission) {
		struct vmbus_offer_identity stale = {
			.instance_id = excess_id,
			.channel_id = 20,
			.generation = vmbus_bus_host_offer_generation(20) + 1,
		};

		CHECK(uk_storvsc_inventory_get(&inventory) == -EAGAIN);
		storvsc_host_driver()->offer_removed(&stale);
		CHECK(uk_storvsc_discovery_status() == -ENOSPC);
		CHECK(!vmbus_bus_host_confirm_rescind(20));
		CHECK(!uk_storvsc_discovery_status());
		CHECK(!uk_storvsc_inventory_get(&inventory));
		CHECK(inventory.count == 2);
	} else {
		CHECK(!vmbus_bus_host_confirm_rescind(20));
		CHECK(uk_storvsc_discovery_status() == -ENOSPC);
	}
	storvsc_host_set_guarded_io(0);
	{
		atomic_int callbacks;

		atomic_init(&callbacks, 0);
		initialize_request(&request, UK_BLKREQ_READ, 8, 1, buffer,
				   request_done, &callbacks);
		CHECK(disk->submit_one(disk, disk->_queue[0], &request) &
		      UK_BLKDEV_STATUS_SUCCESS);
		fire_channel_on(&host_channels[1]);
		CHECK(!wait_request_completion(&request, &callbacks, 1,
					       CONFIG_LIBSTORVSC_REQUEST_TIMEOUT_MS));
		CHECK(request.result == 0 && buffer[0] == 0x5a);
	}
	free(buffer);
	return 0;
}

static int failed_discovery(int mode)
{
	struct uk_storvsc_inventory_snapshot inventory;

	CHECK(!setup());
	CHECK(!offer(&os_id, 10, 0));
	if (mode == 0)
		report_luns_mode = REPORT_LUNS_TRUNCATED;
	else if (mode == 1)
		vpd_mode = VPD_MALFORMED;
	else if (mode == 2)
		report_luns_mode = REPORT_LUNS_NORMAL;
	else {
		report_luns_mode = REPORT_LUNS_EMPTY;
		enumerate_during_report_luns = 1;
	}
	CHECK(!offer(&data_id, 12, 7));
	CHECK(uk_storvsc_discovery_status() < 0);
	CHECK(uk_storvsc_discovery_status() != -EAGAIN);
	if (mode == 2) {
		struct uk_storvsc_target_snapshot target;
		struct uk_storvsc_session session;
		struct uk_blkdev *disk = storvsc_host_blkdev_address(1, 0);
		struct uk_blkdev *os = storvsc_host_blkdev_address(0, 0);
		struct uk_blkdev *nonzero = storvsc_host_blkdev_address(1, 3);
		struct uk_blkdev *disks[] = { os, disk, nonzero };
		struct uk_blkreq requests[3];
		atomic_int callbacks;
		uint8_t *buffer;
		int events[3] = { 0 };

		CHECK(uk_storvsc_discovery_status() == -ENOSPC);
		CHECK(uk_storvsc_inventory_get(&inventory) == -EAGAIN);
		CHECK(uk_storvsc_mapping_count() == 3 && nonzero &&
		      !storvsc_host_blkdev_address(1, 7));
		CHECK(pool_log_count == 1 &&
		      strstr(pool_log,
			     "controller1 relid=12 0:0:7 LUN pool exhausted (max 2)"));
		CHECK(disk && !target_for_device(disk, &target));
		CHECK(!uk_storvsc_session_begin_read(&target, &session));
		CHECK(uk_storvsc_session_authorize_write(&session) == -ENOSPC);
		storvsc_host_set_guarded_io(0);
		CHECK(!posix_memalign((void **)&buffer, 4096, 4096));
		atomic_init(&callbacks, 0);
		for (unsigned int i = 0; i < 3; i++) {
			CHECK(!activate_device(disks[i], &events[i]));
			initialize_request(&requests[i], UK_BLKREQ_READ, 8, 1,
					   buffer + i * 512, request_done,
					   &callbacks);
			CHECK(disks[i]->submit_one(disks[i],
						   disks[i]->_queue[0], &requests[i]) &
			      UK_BLKDEV_STATUS_SUCCESS);
			fire_channel_on(&host_channels[i ? 1 : 0]);
		}
		for (unsigned int i = 0; i < 3; i++) {
			CHECK(!wait_request_completion(&requests[i], &callbacks,
						       3,
						       CONFIG_LIBSTORVSC_REQUEST_TIMEOUT_MS));
			CHECK(requests[i].result == 0 &&
			      buffer[i * 512] == 0x5a);
		}
		free(buffer);
	}
	CHECK(!write10_command_count && !write16_command_count &&
	      !flush_command_count);
	return 0;
}

static int enumeration_state(unsigned int stage)
{
	struct uk_storvsc_inventory_snapshot first = {
		.version = UK_STORVSC_INVENTORY_SNAPSHOT_VERSION,
		.size = sizeof(first),
	};
	struct uk_storvsc_inventory_snapshot snapshot;
	int expected = stage == 0 ? -EAGAIN : stage == 1 ? 0 :
		stage == 3 ? -ENOMEM : -ETIMEDOUT;

	CHECK(!vmbus_bus_host_storage_enumeration(stage));
	CHECK(uk_storvsc_discovery_status() == expected);
	CHECK(uk_storvsc_inventory_get(&snapshot) ==
	      (expected ? -EAGAIN : 0));
	CHECK(uk_storvsc_inventory_pristine_empty(&first, &first) ==
	      (stage == 1));
	return 0;
}

static int incomplete_offer(unsigned int test)
{
	static const unsigned int prefixes[] = { 0, 4, 8, 16, 24, 64, 188, 255 };
	struct uk_storvsc_inventory_snapshot snapshot;
	struct uk_storvsc_inventory_snapshot empty = {
		.version = UK_STORVSC_INVENTORY_SNAPSHOT_VERSION,
		.size = sizeof(empty),
	};
	int known_nonstorage = test == 8;

	CHECK(!vmbus_bus_host_storage_prefix(
		known_nonstorage ? 64 : prefixes[test], known_nonstorage));
	CHECK(uk_storvsc_discovery_status() ==
	      (known_nonstorage ? 0 : -EPROTO));
	CHECK(uk_storvsc_inventory_get(&snapshot) ==
	      (known_nonstorage ? 0 : -EAGAIN));
	CHECK(uk_storvsc_inventory_pristine_empty(&empty, &empty) ==
	      known_nonstorage);
	return 0;
}

static int discovery_ownership(unsigned int test)
{
	struct vmbus_driver *driver = storvsc_host_driver();
	struct vmbus_device device = {
		.channel_id = 10, .connection_id = 110, .present = 1,
	};
	struct uk_storvsc_inventory_snapshot inventory;
	int quarantined = test != 0 && test != 5 && test != 6;
	unsigned int sent;

	CHECK(!setup());
	use_vmbus_offer_lifetimes = 0;
	device.instance_id = os_id;
	device.class_id = driver->device_ids[0].class_id;
	CHECK(!vmbus_bus_host_connection_begin());
	report_luns_mode = REPORT_LUNS_NO_ZERO;
	expire_inquiry = 1;
	expire_lun = test >= 6 ? 7 : -1;
	if (test == 1 || test == 7)
		configure_close_failure(-EBUSY, TEST_CLOSE_RETRY_LIMIT);
	else if (test == 2)
		configure_close_failure(-EIO, 1);
	else if (test == 3)
		configure_close_failure(-ECANCELED, 1);
	else if (test == 4)
		configure_close_failure(-ENODEV, 1);
	else if (test == 5)
		close_with_epoch_proof = 1;
	CHECK(driver->add_dev(&device) == -ETIMEDOUT);
	CHECK(expired_inquiries == 1);
	CHECK(report_luns_commands == 1 && !storvsc_host_controller_online(0));
	CHECK(!uk_storvsc_mapping_count());
	CHECK(uk_storvsc_inventory_get(&inventory) == -EAGAIN);
	CHECK(uk_storvsc_discovery_status() == -ETIMEDOUT);
	CHECK(storvsc_host_discovery_owned(0) == (unsigned int)quarantined);
	CHECK(!!storvsc_host_discovery_quarantined(0) == quarantined);
	CHECK(!storvsc_host_worker_present());
	CHECK(!write10_command_count && !write16_command_count &&
	      !flush_command_count && !unregister_calls);
	if (test < 6)
		CHECK(discovery_sends == 2);
	else
		CHECK(next_blkdev_id == 1);
	sent = discovery_sends;
	expire_inquiry = 0;
	configure_close_failure(0, 0);
	remove_test_offer(driver, &device);
	if (quarantined) {
		CHECK(uk_storvsc_discovery_status() == -ETIMEDOUT);
		CHECK(driver->add_dev(&device) == -ETIMEDOUT);
		CHECK(discovery_sends == sent);
		CHECK(storvsc_host_discovery_owned(0) == 1);
	} else {
		report_luns_mode = REPORT_LUNS_SINGLE;
		single_report_lun = 7;
		CHECK(!driver->add_dev(&device));
		CHECK(!uk_storvsc_discovery_status());
		CHECK(!storvsc_host_discovery_owned(0));
		CHECK(!persistence_remove_device(driver, &device));
	}
	return 0;
}

static int run_case(unsigned int test)
{
	if (test >= 25)
		return discovery_ownership(test - 25);
	if (test >= 16)
		return incomplete_offer(test - 16);
	if (test >= 11)
		return enumeration_state(test - 11);
	if (test == 10) {
		struct uk_storvsc_inventory_snapshot inventory;

		CHECK(!vmbus_bus_host_reject_storage_wire(
			storvsc_host_driver(), &data_id, 12, 112));
		CHECK(uk_storvsc_discovery_status() == -EPROTO);
		CHECK(uk_storvsc_inventory_get(&inventory) == -EAGAIN);
		CHECK(!uk_storvsc_mapping_count());
		return 0;
	}
	if (test < 4)
		return pair(test & 1, test >> 1);
	if (test < 6)
		return rejected(test == 5);
	return failed_discovery((int)test - 6);
}

int main(int argc, char **argv)
{
	unsigned int count = CONFIG_LIBSTORVSC_MAX_DEVICES == 1 ? 4 : 33;
	unsigned int test;

	CHECK(argc == 2);
	test = (unsigned int)strtoul(argv[1], NULL, 10);
	CHECK(test < count);
	CHECK(!test_hex_id());
	return run_case(test);
}
