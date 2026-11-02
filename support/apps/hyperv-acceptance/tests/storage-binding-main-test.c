/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#define VMBUS_GUID_SIZE 16
struct vmbus_guid { uint8_t bytes[VMBUS_GUID_SIZE]; };
struct vmbus_driver { const char *name; };
struct vmbus_device {
	struct vmbus_guid class_id;
	uint32_t channel_id;
	uint16_t subchannel_index;
	struct vmbus_driver *driver;
	int bound;
};
static const struct vmbus_guid vmbus_storage_guid = { .bytes = { 1 } };
static const struct vmbus_guid vmbus_network_guid = { .bytes = { 2 } };
static struct vmbus_device offers[4];
static unsigned int offer_count;
static int discovery_error;
static int finish_after_sleep;
static uint64_t now;
static unsigned int sleeps;

static unsigned int vmbus_device_count(void) { return offer_count; }
static const struct vmbus_device *vmbus_device_get(unsigned int index)
{
	return &offers[index];
}
static int vmbus_device_is_bound(const struct vmbus_device *device)
{
	return device->bound;
}
static int uk_storvsc_discovery_status(void) { return discovery_error; }
static unsigned int uk_netdev_count(void) { return 1; }
static uint64_t ukplat_monotonic_clock(void) { return now; }
static void uk_sched_thread_sleep(uint64_t ns)
{
	now += ns;
	sleeps++;
	if (finish_after_sleep) {
		discovery_error = 0;
		offers[1].bound = 1;
	}
}

#define HYPERV_ACCEPTANCE_BINDING_HOST_TEST
#define CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION 0
#include "../main.c"

int main(void)
{
	struct target_binding_status status;
	unsigned int storage;
	unsigned int network;

	offers[0].class_id = vmbus_storage_guid;
	offers[0].bound = 1;
	offers[1].class_id = vmbus_storage_guid;
	offers[2].class_id = vmbus_network_guid;
	offers[2].bound = 1;
	offers[3].class_id = vmbus_storage_guid;
	offers[3].subchannel_index = 1;
	offer_count = 4;
	count_vmbus_classes(&storage, &network);
	assert(storage == 2 && network == 1);

	discovery_error = -ENOSPC;
	status = wait_for_target_bindings(storage, network);
	assert(!status.storage && status.network);
	assert(status.storage_error == -ENOSPC && !sleeps);

	discovery_error = -EPROTO;
	status = wait_for_target_bindings(0, network);
	assert(!status.storage && status.storage_error == -EPROTO && !sleeps);

	discovery_error = -EAGAIN;
	finish_after_sleep = 1;
	status = wait_for_target_bindings(storage, network);
	assert(status.storage && status.network && !status.storage_error);
	assert(sleeps == 1);

	/* A bound, verified empty controller is complete, not a missing disk. */
	sleeps = 0;
	status = wait_for_target_bindings(storage, network);
	assert(status.storage && !sleeps);

	finish_after_sleep = 0;
	discovery_error = -EAGAIN;
	offers[1].bound = 0;
	now = 0;
	status = wait_for_target_bindings(storage, network);
	assert(!status.storage && status.storage_error == -EAGAIN);
	assert(now == BIND_TIMEOUT_NS);
	assert(sleeps == BIND_TIMEOUT_NS / POLL_INTERVAL_NS);
	puts("storage-binding-main-test: PASS (5 readiness cases)");
	return 0;
}
