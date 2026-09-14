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

static int pair(int reverse, int empty)
{
	struct uk_storvsc_inventory_snapshot inventory;
	struct uk_storvsc_mapping mapping;
	unsigned int reports = 0;
	unsigned int data_found = 0;
	unsigned int os_found = 0;

	CHECK(!setup());
	for (unsigned int i = 0; i < 2; i++) {
		int data = (i == 1) != reverse;

		report_luns_mode = data && empty ?
			REPORT_LUNS_EMPTY : REPORT_LUNS_SINGLE;
		CHECK(!offer(data ? &data_id : &os_id,
			     data ? 12 : 10, data ? 7 : 0));
		reports += data && empty ? 2 : 1;
	}
	if (CONFIG_LIBSTORVSC_MAX_DEVICES == 1) {
		CHECK(uk_storvsc_discovery_status() == -ENOSPC);
		CHECK(uk_storvsc_inventory_get(&inventory) == -EAGAIN);
		CHECK(uk_storvsc_mapping_count() == (reverse && empty ? 0 : 1));
		return 0;
	}
	CHECK(!vmbus_storage_binding_status());
	CHECK(!uk_storvsc_discovery_status());
	CHECK(!uk_storvsc_inventory_get(&inventory));
	CHECK(inventory.count == (empty ? 1U : 2U));
	CHECK(report_luns_commands == reports);
	CHECK(storvsc_host_controller_online(0));
	CHECK(storvsc_host_controller_online(1));
	for (unsigned int i = 0; i < inventory.count; i++) {
		CHECK(!uk_storvsc_mapping_get(i, &mapping));
		CHECK(mapping.path_id == 0 && mapping.target_id == 0);
		CHECK(mapping.vpd_length == 8);
		CHECK(mapping.sectors == 1000 && mapping.sector_size == 512);
		if (!memcmp(mapping.instance_id, os_id.bytes, VMBUS_GUID_SIZE)) {
			CHECK(mapping.lun == 0 && mapping.channel_id == 10);
			os_found++;
		} else {
			CHECK(!memcmp(mapping.instance_id, data_id.bytes,
				      VMBUS_GUID_SIZE));
			CHECK(mapping.lun == 7 && mapping.channel_id == 12);
			data_found++;
		}
	}
	CHECK(os_found == 1 && data_found == !empty);
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
	free(buffer);
	return 0;
}

static int failed_discovery(int mode)
{
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

		CHECK(disk && !target_for_device(disk, &target));
		CHECK(!uk_storvsc_session_begin_read(&target, &session));
		CHECK(uk_storvsc_session_authorize_write(&session) == -ENOSPC);
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
	return run_case(test);
}
