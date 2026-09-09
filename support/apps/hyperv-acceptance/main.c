/* SPDX-License-Identifier: BSD-3-Clause */
#include "acceptance_protocol.h"
#include "application_network.h"
#include "persistence.h"
#include "storage_target.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <uk/config.h>
#include <uk/alloc.h>
#include <uk/blkdev.h>
#include <uk/netbuf.h>
#include <uk/netdev.h>
#include <uk/plat/time.h>
#include <uk/sched.h>
#include <uk/storvsc.h>
#include <uk/vmbus.h>

#if defined(CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE) && \
	CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE && \
	defined(CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION) && \
	CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION
#error "persistence and application-network workloads are mutually exclusive"
#endif

#if defined(CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE) && \
	CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE
#define HYPERV_ACCEPTANCE_PERSISTENCE_ENABLED 1
#else
#define HYPERV_ACCEPTANCE_PERSISTENCE_ENABLED 0
#endif

#if !HYPERV_ACCEPTANCE_PERSISTENCE_ENABLED
#define BLOCK_QUEUE_DEPTH 4U
#define BLOCK_SECTORS_TO_READ 2U
#define BLOCK_SECTOR_SIZE_MAX 4096U
#define BLOCK_TIMEOUT_NS (7ULL * 1000000000ULL)
#define BIND_TIMEOUT_NS (3ULL * 1000000000ULL)
#if !CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION
#define NETWORK_QUEUE_DEPTH 8U
#define NETWORK_BUFFER_SIZE 1536U
#define DHCP_TIMEOUT_NS (8ULL * 1000000000ULL)
#define DHCP_RETRY_NS (2ULL * 1000000000ULL)
#endif
#define POLL_INTERVAL_NS 10000000ULL
#if !CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION
#define MAX_RX_PACKETS 256U

struct rx_allocator_context {
	struct uk_alloc *allocator;
	size_t alignment;
};

static struct rx_allocator_context rx_context;
#endif
static struct uk_blkreq block_request;
static _Alignas(4096) uint8_t block_buffer[
	BLOCK_SECTORS_TO_READ * BLOCK_SECTOR_SIZE_MAX];

static const char *result_name(enum hyperv_acceptance_result result)
{
	switch (result) {
	case HYPERV_ACCEPTANCE_PASS:
		return "PASS";
	case HYPERV_ACCEPTANCE_FAIL:
		return "FAIL";
	case HYPERV_ACCEPTANCE_UNAVAILABLE:
		return "UNAVAILABLE";
	}
	return "FAIL";
}

static int guid_equal(const struct vmbus_guid *left,
		      const struct vmbus_guid *right)
{
	return !memcmp(left->bytes, right->bytes, VMBUS_GUID_SIZE);
}

static const char *vmbus_class_name(const struct vmbus_guid *guid)
{
	if (guid_equal(guid, &vmbus_storage_guid))
		return "storage";
	if (guid_equal(guid, &vmbus_network_guid))
		return "network";
	return "other";
}

static void count_vmbus_classes(unsigned int *storage, unsigned int *network)
{
	unsigned int count = vmbus_device_count();
	unsigned int index;

	*storage = 0;
	*network = 0;
	for (index = 0; index < count; index++) {
		const struct vmbus_device *device = vmbus_device_get(index);
		const char *class_name;

		if (!device)
			continue;
		class_name = vmbus_class_name(&device->class_id);
		if (!strcmp(class_name, "storage"))
			(*storage)++;
		else if (!strcmp(class_name, "network"))
			(*network)++;
		printf("HYPERV_ACCEPTANCE VMBUS_OFFER PASS index=%u "
		       "channel=%" PRIu32 " class=%s bound=%s\n",
		       index, device->channel_id, class_name,
		       device->driver ? device->driver->name : "none");
	}
}

struct target_binding_status {
	int storage;
	int network;
};

static void current_bound_offers(unsigned int *storage,
				 unsigned int *network)
{
	unsigned int count = vmbus_device_count();
	unsigned int index;

	*storage = 0;
	*network = 0;
	for (index = 0; index < count; index++) {
		const struct vmbus_device *device = vmbus_device_get(index);

		if (!device || !vmbus_device_is_bound(device))
			continue;
		if (guid_equal(&device->class_id, &vmbus_storage_guid))
			(*storage)++;
		else if (guid_equal(&device->class_id, &vmbus_network_guid))
			(*network)++;
	}
}

static struct target_binding_status
wait_for_target_bindings(unsigned int storage_offers,
			 unsigned int network_offers)
{
	uint64_t deadline = ukplat_monotonic_clock() + BIND_TIMEOUT_NS;
	struct target_binding_status status = { 0 };

	while (ukplat_monotonic_clock() < deadline) {
		struct uk_storvsc_inventory_snapshot inventory = { 0 };
		unsigned int storage_bound;
		unsigned int network_bound;
		unsigned int storage_targets = 0;

		current_bound_offers(&storage_bound, &network_bound);
		if (!uk_storvsc_inventory_get(&inventory))
			storage_targets = inventory.count;
		status.storage = hyperv_acceptance_binding_ready(
			storage_offers, storage_bound, storage_targets);
		status.network = hyperv_acceptance_binding_ready(
			network_offers, network_bound, uk_netdev_count());
		if (status.storage && status.network)
			return status;
		uk_sched_thread_sleep(POLL_INTERVAL_NS);
	}
	return status;
}

static enum hyperv_acceptance_result probe_storage(
	unsigned int storage_offers, int binding_ready)
{
	struct hyperv_acceptance_storage_target selected = { 0 };
	struct uk_blkdev *device;
	struct uk_blkdev_conf config = { .nb_queues = 1 };
	struct uk_blkdev_queue_conf queue_config = { 0 };
	const struct uk_blkdev_cap *capabilities;
	struct uk_alloc *allocator;
	enum hyperv_acceptance_result result = HYPERV_ACCEPTANCE_FAIL;
	uint64_t deadline;
	size_t bytes;
	int rc;
	int status;
	int mbr;
	int gpt;
	int release_rc;
	unsigned int index;

	if (storage_offers && !binding_ready) {
		puts("HYPERV_ACCEPTANCE STORAGE_INVENTORY FAIL "
		     "reason=binding-timeout");
		puts("HYPERV_ACCEPTANCE STORAGE_READ FAIL "
		     "reason=binding-timeout");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (!uk_blkdev_count()) {
		enum hyperv_acceptance_result unavailable = storage_offers ?
			HYPERV_ACCEPTANCE_FAIL : HYPERV_ACCEPTANCE_UNAVAILABLE;

		printf("HYPERV_ACCEPTANCE STORAGE_INVENTORY %s "
		       "devices=0 offers=%u reason=%s\n",
		       result_name(unavailable),
		       storage_offers, storage_offers ? "offered-unbound" :
		       "no-storvsc-offer");
		printf("HYPERV_ACCEPTANCE STORAGE_READ %s reason=no-device\n",
		       result_name(unavailable));
		return unavailable;
	}

	deadline = ukplat_monotonic_clock() + BIND_TIMEOUT_NS;
	do {
		rc = hyperv_acceptance_storage_target_acquire(&selected);
		if (!rc)
			break;
		if (rc != -EAGAIN && rc != -ESTALE && rc != -ENODEV)
			break;
		uk_sched_thread_sleep(POLL_INTERVAL_NS);
	} while (ukplat_monotonic_clock() < deadline);
	if (rc) {
		printf("HYPERV_ACCEPTANCE STORAGE_INVENTORY FAIL "
		       "devices=%u offers=%u reason=target-readiness rc=%d\n",
		       uk_blkdev_count(), storage_offers, rc);
		puts("HYPERV_ACCEPTANCE STORAGE_READ FAIL "
		     "reason=target-readiness");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	device = selected.device;
	for (index = 0; index < uk_blkdev_count(); index++) {
		struct uk_blkdev *inventory_device = uk_blkdev_get(index);
		const char *driver = uk_blkdev_drv_name_get(inventory_device);

		printf("HYPERV_ACCEPTANCE STORAGE_DEVICE PASS index=%u "
		       "id=%" PRIu16 " driver=%s state=%d\n", index,
		       uk_blkdev_id_get(inventory_device),
		       driver ? driver : "unknown",
		       uk_blkdev_state_get(inventory_device));
	}
	printf("HYPERV_ACCEPTANCE STORAGE_INVENTORY PASS devices=%u offers=%u "
	       "selected=%" PRIu16 " driver=%s state=%d\n",
	       uk_blkdev_count(), storage_offers, uk_blkdev_id_get(device),
	       uk_blkdev_drv_name_get(device) ?
	       uk_blkdev_drv_name_get(device) : "unknown",
	       uk_blkdev_state_get(device));
	if (uk_blkdev_state_get(device) != UK_BLKDEV_UNCONFIGURED) {
		printf("HYPERV_ACCEPTANCE STORAGE_READ FAIL "
		       "reason=unexpected-state state=%d\n",
		       uk_blkdev_state_get(device));
		goto out;
	}

	rc = uk_blkdev_configure(device, &config);
	if (rc) {
		printf("HYPERV_ACCEPTANCE STORAGE_READ FAIL "
		       "reason=configure rc=%d\n", rc);
		goto out;
	}
	allocator = uk_alloc_get_default();
	if (!allocator) {
		printf("HYPERV_ACCEPTANCE STORAGE_READ FAIL "
		       "reason=no-allocator\n");
		goto out;
	}
	queue_config.a = allocator;
	rc = uk_blkdev_queue_configure(device, 0, BLOCK_QUEUE_DEPTH,
				       &queue_config);
	if (rc) {
		printf("HYPERV_ACCEPTANCE STORAGE_READ FAIL "
		       "reason=queue-configure rc=%d\n", rc);
		goto out;
	}
	rc = uk_blkdev_start(device);
	if (rc) {
		printf("HYPERV_ACCEPTANCE STORAGE_READ FAIL reason=start rc=%d\n",
		       rc);
		goto out;
	}

	capabilities = uk_blkdev_capabilities(device);
	if (capabilities->sectors < BLOCK_SECTORS_TO_READ ||
	    capabilities->ssize < 512 ||
	    capabilities->ssize > BLOCK_SECTOR_SIZE_MAX ||
	    capabilities->ioalign > 4096 ||
	    capabilities->max_sectors_per_req < BLOCK_SECTORS_TO_READ) {
		printf("HYPERV_ACCEPTANCE STORAGE_READ FAIL "
		       "reason=unsupported-geometry sectors=%" PRIu64
		       " sector_size=%zu ioalign=%" PRIu16
		       " max_request=%" PRIu64 "\n",
		       (uint64_t)capabilities->sectors, capabilities->ssize,
		       capabilities->ioalign,
		       (uint64_t)capabilities->max_sectors_per_req);
		goto out;
	}
	bytes = capabilities->ssize * BLOCK_SECTORS_TO_READ;
	memset(block_buffer, 0, bytes);
	uk_blkreq_init(&block_request, UK_BLKREQ_READ, 0,
		       BLOCK_SECTORS_TO_READ, block_buffer, NULL, NULL);
	status = uk_blkdev_queue_submit_one(device, 0, &block_request);
	if (status < 0 || !(status & UK_BLKDEV_STATUS_SUCCESS)) {
		printf("HYPERV_ACCEPTANCE STORAGE_READ FAIL "
		       "reason=submit status=%d\n", status);
		goto out;
	}

	deadline = ukplat_monotonic_clock() + BLOCK_TIMEOUT_NS;
	while (!uk_blkreq_is_done(&block_request) &&
	       ukplat_monotonic_clock() < deadline) {
		rc = uk_blkdev_queue_finish_reqs(device, 0);
		if (rc) {
			printf("HYPERV_ACCEPTANCE STORAGE_READ FAIL "
			       "reason=completion rc=%d\n", rc);
			goto out;
		}
		if (!uk_blkreq_is_done(&block_request))
			uk_sched_thread_sleep(POLL_INTERVAL_NS);
	}
	if (!uk_blkreq_is_done(&block_request)) {
		printf("HYPERV_ACCEPTANCE STORAGE_READ FAIL reason=timeout\n");
		goto out;
	}
	if (block_request.result) {
		printf("HYPERV_ACCEPTANCE STORAGE_READ FAIL "
		       "reason=request rc=%d\n", block_request.result);
		goto out;
	}
	rc = hyperv_acceptance_storage_target_validate(&selected);
	if (rc) {
		printf("HYPERV_ACCEPTANCE STORAGE_READ FAIL "
		       "reason=topology-changed rc=%d\n", rc);
		goto out;
	}

	mbr = hyperv_acceptance_has_mbr_signature(block_buffer,
						  capabilities->ssize);
	gpt = hyperv_acceptance_has_gpt_signature(
		block_buffer + capabilities->ssize, capabilities->ssize);
	if (!mbr || !gpt) {
		printf("HYPERV_ACCEPTANCE STORAGE_READ FAIL "
		       "reason=os-disk-signature bytes=%zu mbr=%d gpt=%d\n",
		       bytes, mbr, gpt);
		goto out;
	}
	printf("HYPERV_ACCEPTANCE STORAGE_READ PASS bytes=%zu "
	       "sector_size=%zu mbr=%d gpt=%d\n", bytes,
	       capabilities->ssize, mbr, gpt);
	puts("UK_HYPERV_BLOCK_READ_OK");
	result = HYPERV_ACCEPTANCE_PASS;
out:
	release_rc = hyperv_acceptance_storage_target_release(&selected);
	if (release_rc) {
		printf("HYPERV_ACCEPTANCE STORAGE_SESSION FAIL rc=%d\n",
		       release_rc);
		if (result == HYPERV_ACCEPTANCE_PASS)
			result = HYPERV_ACCEPTANCE_FAIL;
	}
	return result;
}

#if !CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION
static uint16_t allocate_rx_packets(void *argp, struct uk_netbuf *packets[],
				    uint16_t count)
{
	struct rx_allocator_context *context = argp;
	uint16_t allocated;

	for (allocated = 0; allocated < count; allocated++) {
		packets[allocated] = uk_netbuf_alloc_buf(
			context->allocator, NETWORK_BUFFER_SIZE,
			context->alignment, 0, 0, NULL);
		if (!packets[allocated])
			break;
		packets[allocated]->len = NETWORK_BUFFER_SIZE;
	}
	return allocated;
}

static int transmit_discover(struct uk_netdev *device, const uint8_t mac[6],
			     uint32_t xid)
{
	struct uk_netbuf *packet;
	size_t length;
	int status;

	packet = uk_netbuf_alloc_buf(rx_context.allocator, NETWORK_BUFFER_SIZE,
				    rx_context.alignment, 0, 0, NULL);
	if (!packet)
		return -ENOMEM;
	length = hyperv_acceptance_build_discover(packet->data,
						 packet->buflen, mac, xid);
	if (!length) {
		uk_netbuf_free(packet);
		return -EINVAL;
	}
	packet->len = length;
	status = uk_netdev_tx_one(device, 0, packet);
	if (!uk_netdev_status_successful(status)) {
		uk_netbuf_free(packet);
		return status < 0 ? status : -EAGAIN;
	}
	return 0;
}

static enum hyperv_acceptance_result probe_network(
	unsigned int network_offers, int binding_ready)
{
	struct uk_netdev *device;
	struct uk_netdev_conf config = {
		.nb_rx_queues = 1,
		.nb_tx_queues = 1,
	};
	struct uk_netdev_rxqueue_conf rx_config = { 0 };
	struct uk_netdev_txqueue_conf tx_config = { 0 };
	struct uk_netdev_info info;
	const struct uk_hwaddr *hwaddr;
	uint8_t mac[6];
	uint32_t xid;
	uint64_t deadline;
	uint64_t next_transmit = 0;
	unsigned int attempts = 0;
	unsigned int received = 0;
	unsigned int malformed = 0;
	int transmitted = 0;
	int rc;
	unsigned int index;

	if (network_offers && !binding_ready) {
		puts("HYPERV_ACCEPTANCE NETWORK_INVENTORY FAIL "
		     "reason=binding-timeout");
		puts("HYPERV_ACCEPTANCE NETWORK_DHCP_TX FAIL "
		     "reason=binding-timeout");
		puts("HYPERV_ACCEPTANCE NETWORK_DHCP_RX FAIL "
		     "reason=binding-timeout");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (!uk_netdev_count()) {
		enum hyperv_acceptance_result result = network_offers ?
			HYPERV_ACCEPTANCE_FAIL : HYPERV_ACCEPTANCE_UNAVAILABLE;

		printf("HYPERV_ACCEPTANCE NETWORK_INVENTORY %s "
		       "devices=0 offers=%u reason=%s\n", result_name(result),
		       network_offers, network_offers ? "offered-unbound" :
		       "no-netvsc-offer");
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_TX %s reason=no-device\n",
		       result_name(result));
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_RX %s reason=no-device\n",
		       result_name(result));
		return result;
	}

	device = uk_netdev_get(0);
	for (index = 0; index < uk_netdev_count(); index++) {
		struct uk_netdev *inventory_device = uk_netdev_get(index);
		const char *driver = uk_netdev_drv_name_get(inventory_device);

		printf("HYPERV_ACCEPTANCE NETWORK_DEVICE PASS index=%u "
		       "id=%" PRIu16 " driver=%s state=%d\n", index,
		       uk_netdev_id_get(inventory_device),
		       driver ? driver : "unknown",
		       uk_netdev_state_get(inventory_device));
	}
	printf("HYPERV_ACCEPTANCE NETWORK_INVENTORY PASS devices=%u offers=%u "
	       "selected=%" PRIu16 " driver=%s state=%d\n",
	       uk_netdev_count(), network_offers, uk_netdev_id_get(device),
	       uk_netdev_drv_name_get(device) ?
	       uk_netdev_drv_name_get(device) : "unknown",
	       uk_netdev_state_get(device));
	if (uk_netdev_state_get(device) == UK_NETDEV_UNPROBED) {
		rc = uk_netdev_probe(device);
		if (rc) {
			printf("HYPERV_ACCEPTANCE NETWORK_DHCP_TX FAIL "
			       "reason=probe rc=%d\n", rc);
			printf("HYPERV_ACCEPTANCE NETWORK_DHCP_RX FAIL "
			       "reason=probe rc=%d\n", rc);
			return HYPERV_ACCEPTANCE_FAIL;
		}
	}
	if (uk_netdev_state_get(device) != UK_NETDEV_UNCONFIGURED) {
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_TX FAIL "
		       "reason=unexpected-state state=%d\n",
		       uk_netdev_state_get(device));
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_RX FAIL "
		       "reason=unexpected-state state=%d\n",
		       uk_netdev_state_get(device));
		return HYPERV_ACCEPTANCE_FAIL;
	}

	memset(&info, 0, sizeof(info));
	uk_netdev_info_get(device, &info);
	if (!info.max_rx_queues || !info.max_tx_queues) {
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_TX FAIL "
		       "reason=device-info rxq=%" PRIu16
		       " txq=%" PRIu16 "\n", info.max_rx_queues,
		       info.max_tx_queues);
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_RX FAIL "
		       "reason=device-info\n");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	rc = uk_netdev_configure(device, &config);
	if (rc) {
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_TX FAIL "
		       "reason=configure rc=%d\n", rc);
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_RX FAIL "
		       "reason=configure rc=%d\n", rc);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	rx_context.allocator = uk_alloc_get_default();
	rx_context.alignment = hyperv_acceptance_buffer_alignment(info.ioalign);
	if (!rx_context.allocator) {
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_TX FAIL "
		       "reason=no-allocator\n");
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_RX FAIL "
		       "reason=no-allocator\n");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	rx_config.a = rx_context.allocator;
	rx_config.alloc_rxpkts = allocate_rx_packets;
	rx_config.alloc_rxpkts_argp = &rx_context;
	tx_config.a = rx_context.allocator;
	rc = uk_netdev_rxq_configure(device, 0, NETWORK_QUEUE_DEPTH,
				     &rx_config);
	if (!rc)
		rc = uk_netdev_txq_configure(device, 0, NETWORK_QUEUE_DEPTH,
					     &tx_config);
	if (rc) {
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_TX FAIL "
		       "reason=queue-configure rc=%d\n", rc);
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_RX FAIL "
		       "reason=queue-configure rc=%d\n", rc);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	rc = uk_netdev_start(device);
	if (rc) {
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_TX FAIL "
		       "reason=start rc=%d\n", rc);
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_RX FAIL "
		       "reason=start rc=%d\n", rc);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	hwaddr = uk_netdev_hwaddr_get(device);
	if (!hwaddr) {
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_TX FAIL "
		       "reason=no-hardware-address\n");
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_RX FAIL "
		       "reason=no-hardware-address\n");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	memcpy(mac, hwaddr->addr_bytes, sizeof(mac));
	xid = 0x554b0000U | ((uint32_t)mac[4] << 8) | mac[5];

	deadline = ukplat_monotonic_clock() + DHCP_TIMEOUT_NS;
	while (ukplat_monotonic_clock() < deadline &&
	       received < MAX_RX_PACKETS) {
		struct uk_netbuf *packet = NULL;
		uint64_t now = ukplat_monotonic_clock();
		int status;

		if (attempts < 3 && now >= next_transmit) {
			rc = transmit_discover(device, mac, xid);
			attempts++;
			next_transmit = now + DHCP_RETRY_NS;
			if (!rc && !transmitted)
				transmitted = 1;
		}
		status = uk_netdev_rx_one(device, 0, &packet);
		if (status < 0) {
			printf("HYPERV_ACCEPTANCE NETWORK_DHCP_RX FAIL "
			       "reason=receive rc=%d\n", status);
			if (!transmitted) {
				printf("HYPERV_ACCEPTANCE NETWORK_DHCP_TX FAIL "
				       "reason=not-transmitted attempts=%u\n",
				       attempts);
			} else {
				printf("HYPERV_ACCEPTANCE NETWORK_DHCP_TX FAIL "
				       "reason=unverified-receive-error "
				       "attempts=%u\n", attempts);
			}
			return HYPERV_ACCEPTANCE_FAIL;
		}
		if (uk_netdev_status_successful(status) && packet) {
			struct hyperv_acceptance_dhcp_offer offer = { 0 };

			received++;
			rc = hyperv_acceptance_parse_offer(
				packet->data, packet->len, mac, xid, &offer);
			uk_netbuf_free(packet);
			if (rc > 0) {
				printf("HYPERV_ACCEPTANCE NETWORK_DHCP_TX PASS "
				       "attempts=%u proof=matching-offer "
				       "xid=%08" PRIx32
				       " mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
				       attempts, xid, mac[0], mac[1], mac[2],
				       mac[3], mac[4], mac[5]);
				printf("HYPERV_ACCEPTANCE NETWORK_DHCP_RX PASS "
				       "offer=%u.%u.%u.%u "
				       "server=%u.%u.%u.%u packets=%u\n",
				       offer.offered_address[0],
				       offer.offered_address[1],
				       offer.offered_address[2],
				       offer.offered_address[3],
				       offer.server_identifier[0],
				       offer.server_identifier[1],
				       offer.server_identifier[2],
				       offer.server_identifier[3], received);
				puts("UK_HYPERV_NET_DHCP_OFFER");
				return HYPERV_ACCEPTANCE_PASS;
			}
			if (rc < 0)
				malformed++;
		}
		uk_sched_thread_sleep(POLL_INTERVAL_NS);
	}
	if (!transmitted) {
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_TX FAIL "
		       "reason=not-transmitted attempts=%u\n", attempts);
	} else {
		printf("HYPERV_ACCEPTANCE NETWORK_DHCP_TX FAIL "
		       "reason=no-matching-offer attempts=%u\n", attempts);
	}
	printf("HYPERV_ACCEPTANCE NETWORK_DHCP_RX FAIL "
	       "reason=%s packets=%u malformed=%u\n",
	       received >= MAX_RX_PACKETS ? "packet-limit" : "timeout",
	       received, malformed);
	return HYPERV_ACCEPTANCE_FAIL;
}
#endif
#endif

int main(void)
{
#if HYPERV_ACCEPTANCE_PERSISTENCE_ENABLED
	return hyperv_acceptance_persistence_main();
#else
	enum hyperv_acceptance_result storage;
	enum hyperv_acceptance_result network;
	enum hyperv_acceptance_result final;
	struct target_binding_status bindings;
	unsigned int storage_offers;
	unsigned int network_offers;

	printf("HYPERV_ACCEPTANCE PLATFORM_READY PASS cpu_count=1 "
	       "vmbus_offers=%u\n", vmbus_device_count());
	puts("UK_HYPERV_PLATFORM_READY");
	count_vmbus_classes(&storage_offers, &network_offers);
	bindings = wait_for_target_bindings(storage_offers, network_offers);
	storage = probe_storage(storage_offers, bindings.storage);
#if CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION
	network = hyperv_acceptance_probe_application_network(
		network_offers, bindings.network);
#else
	network = probe_network(network_offers, bindings.network);
#endif
	final = hyperv_acceptance_final_result(storage, network);
	if (final == HYPERV_ACCEPTANCE_PASS) {
		printf("HYPERV_ACCEPTANCE HARDWARE_IO_READY PASS "
		       "storage=PASS network=PASS\n");
		puts("UK_HYPERV_IO_READY");
	} else if (final == HYPERV_ACCEPTANCE_FAIL) {
		if (storage == HYPERV_ACCEPTANCE_FAIL &&
		    network == HYPERV_ACCEPTANCE_FAIL)
			puts("UK_HYPERV_ACCEPTANCE_FAIL:storage+network");
		else if (storage == HYPERV_ACCEPTANCE_FAIL)
			puts("UK_HYPERV_ACCEPTANCE_FAIL:storage");
		else
			puts("UK_HYPERV_ACCEPTANCE_FAIL:network");
	} else if (storage == HYPERV_ACCEPTANCE_UNAVAILABLE &&
		   network == HYPERV_ACCEPTANCE_UNAVAILABLE) {
		puts("UK_HYPERV_ACCEPTANCE_UNAVAILABLE:storage+network");
	} else if (storage == HYPERV_ACCEPTANCE_UNAVAILABLE) {
		puts("UK_HYPERV_ACCEPTANCE_UNAVAILABLE:storage");
	} else {
		puts("UK_HYPERV_ACCEPTANCE_UNAVAILABLE:network");
	}
	printf("HYPERV_ACCEPTANCE FINAL_RESULT %s storage=%s network=%s\n",
	       result_name(final), result_name(storage), result_name(network));
	fflush(stdout);
	return (int)final;
#endif
}
