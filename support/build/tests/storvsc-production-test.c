/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <uk/alloc.h>
#include <uk/blkdev.h>
#include <uk/blkdev_driver.h>
#include <uk/config.h>
#include <uk/paging.h>
#include <uk/sched.h>
#include <uk/storvsc.h>
#include <uk/thread.h>
#include <uk/vmbus.h>

#include "acceptance_protocol.h"
#include "persistence.h"
#include "persistence_host.h"
#include "storvsc_core.h"

#define TEST_CLOSE_RETRY_LIMIT 8

struct vmbus_driver *storvsc_host_driver(void);
struct uk_blkdev *storvsc_host_blkdev(void);
struct uk_blkdev *storvsc_host_blkdev_at(unsigned int controller,
					 unsigned int lun_slot);
struct uk_blkdev *storvsc_host_blkdev_address(unsigned int controller,
					      uint8_t lun_id);
int storvsc_host_controller_online(unsigned int controller);
size_t storvsc_host_lun_count(void);
void storvsc_host_set_lun_discovery(int enabled);
void storvsc_host_set_guarded_io(int enabled);
int storvsc_host_lun_address(size_t index,
			     struct storvsc_address *address);
int storvsc_host_receive(void);
int storvsc_host_reset_timed_out_io(void);
int storvsc_host_reset_controller(unsigned int controller);
int storvsc_host_start_timeout_worker(void);
void storvsc_host_stop_timeout_worker(void);
void storvsc_host_set_send_wait_limit(unsigned int limit);
void storvsc_host_set_busy_retry(unsigned int limit, uint64_t timeout_ns);
int storvsc_host_deferred_action(void);
int storvsc_host_online(void);
int storvsc_host_has_channel(void);
int storvsc_host_worker_present(void);
int storvsc_host_deferred_wait_vmbus(void);
int storvsc_host_deferred_close_busy(void);
int storvsc_host_deferred_close_required(void);
unsigned int storvsc_host_deferred_close_attempts(void);
uint64_t storvsc_host_deferred_vmbus_epoch(void);
int storvsc_host_update_deferred_vmbus_epoch(uint64_t expected,
					     uint64_t replacement);
int storvsc_host_request_bound(struct uk_blkreq *request);
uint64_t storvsc_host_request_pfn(struct uk_blkreq *request,
				  unsigned int index);
void storvsc_host_force_timeout(void);
int vmbus_bus_host_connection_begin(void);
int vmbus_bus_host_connection_quiesce(void);
int vmbus_bus_host_connection_live(void);
unsigned int vmbus_bus_host_connection_fail_calls(void);
int vmbus_bus_host_prepare_disconnect(void);
int vmbus_bus_host_disconnect_remove(
	void (*remove_hook)(void *), void *remove_arg,
	void (*unload_post_hook)(void *), void *unload_arg,
	int acknowledge);
int vmbus_bus_host_offer_lifetime_setup(struct vmbus_driver *driver);
int vmbus_bus_host_reject_storage_wire(
	struct vmbus_driver *driver, const struct vmbus_guid *instance_id,
	__u32 channel_id, __u32 connection_id);
int vmbus_bus_host_offer_storage(
	const struct vmbus_guid *instance_id, __u32 channel_id,
	__u32 connection_id);
int vmbus_bus_host_fill_nonstorage_offers(__u32 first_channel);
int vmbus_bus_host_confirm_rescind(__u32 channel_id);
int vmbus_bus_host_offer_present(__u32 channel_id);
__u64 vmbus_bus_host_offer_generation(__u32 channel_id);
int vmbus_epoch_object_bind_epoch(
	struct vmbus_device *device,
	struct vmbus_device_bind_token *token);
int vmbus_epoch_object_bind_retry(
	struct vmbus_device *device,
	const struct vmbus_device_bind_token *token);
void vmbus_epoch_object_bind_ready(void);

struct uk_thread {
	pthread_t pthread;
	uk_thread_fn1_t function;
	void *argument;
};

struct vmbus_channel {
	struct vmbus_device *device;
	vmbus_channel_callback_t callback;
	void *callback_arg;
	int open;
	int masked;
};

struct host_packet {
	uint64_t id;
	uint32_t length;
	uint16_t type;
	uint32_t descriptor_size;
	uint8_t payload[64];
};

struct page_mapping {
	uintptr_t virtual_page;
	uint64_t pfn;
};

struct pending_io {
	struct vmbus_channel *channel;
	uint64_t id;
	uint32_t length;
};

static struct uk_alloc host_allocator;
static struct uk_sched host_scheduler;
static struct uk_thread main_thread;
static _Thread_local struct uk_thread *current_thread = &main_thread;
static struct vmbus_channel
	host_channels[CONFIG_LIBSTORVSC_MAX_DEVICES];
#define host_channel host_channels[0]
static pthread_mutex_t packet_lock = PTHREAD_MUTEX_INITIALIZER;
static struct host_packet
	packets[CONFIG_LIBSTORVSC_MAX_DEVICES][128];
static unsigned int packet_head[CONFIG_LIBSTORVSC_MAX_DEVICES];
static unsigned int packet_tail[CONFIG_LIBSTORVSC_MAX_DEVICES];
static pthread_mutex_t mapping_lock = PTHREAD_MUTEX_INITIALIZER;
static struct page_mapping mappings[512];
static unsigned int mapping_count;
static struct pending_io pending[32];
static unsigned int pending_count;
static int reject_versions;
static int malformed_handshake;
static int use_capacity16;
static int read_only_media;
static int reject_mode_sense6;
static int reject_mode_sense10;
static int report_luns_mode;
static int topology_fixture;
static int vpd_mode;
static uint8_t vpd_variant;
static int targeted_vpd_malformed;
static unsigned int targeted_vpd_controller;
static uint8_t targeted_vpd_lun;
static int discovery_failure_kind;
static unsigned int discovery_failure_controller;
static uint8_t discovery_failure_lun;
static unsigned int discovery_failures_remaining;
static unsigned int registration_failure_controller;
static uint8_t registration_failure_lun;
static unsigned int registration_failures_remaining;
static int alternate_completion_size;
static int hold_io;
static int short_transfer_once;
static int io_packet_error_once;
static int publish_error_once;
static uint64_t last_io_id;
static uint32_t last_io_length;
static uint8_t last_io_opcode;
static unsigned int io_command_count;
static unsigned int write10_command_count;
static unsigned int write16_command_count;
static unsigned int flush_command_count;
static int backing_media_enabled;
static uint8_t backing_media[1000 * 512];
static uint32_t last_pfn_count;
static uint64_t last_pfns[64];
static unsigned int close_count;
static uint16_t next_blkdev_id;
static struct uk_blkdev *registered_blkdevs[256];
static unsigned int unregister_calls;
static struct uk_blkdev *deferred_finish_device;
static unsigned int deferred_finish_events;
static struct uk_blkdev *sync_finish_device;
static unsigned int sync_finish_calls;
static pthread_mutex_t race_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t race_condition = PTHREAD_COND_INITIALIZER;
static int race_pause_kind;
static int race_hook_entered;
static int race_release_sender;
static int race_recovery_begin;
static int race_reset_ack;
static int race_release_reset;
static int epoch_sample_enabled;
static int epoch_sample_entered;
static int epoch_sample_release;
static uint64_t epoch_sample_value;
static int binding_publish_pause;
static unsigned int binding_publish_controller;
static int binding_publish_entered;
static int binding_publish_release;
static uint64_t race_transaction_id;
static const uint64_t *race_pfn_source;
static unsigned int race_pfns_written;
static uint64_t race_first_pfn;
static struct uk_blkreq *race_sender_request;
static atomic_int race_post_completion_publication;
static struct vmbus_driver *persistence_hook_driver;
static struct vmbus_device *persistence_hook_device;
static int persistence_hook_mode;
static int persistence_hook_fired;
static int persistence_hook_end_error;
static int persistence_hook_timeouts;
static int use_vmbus_offer_lifetimes;
static int retained_callback_entered;
static int retained_callback_release;
static int retained_callback_count;

enum persistence_hook_mode {
	PERSISTENCE_HOOK_NONE = 0,
	PERSISTENCE_HOOK_ADD_BEFORE_REVALIDATE,
	PERSISTENCE_HOOK_ADD_BEFORE_REJECT_END,
};
static atomic_int host_irqs_disabled;
static atomic_int channel_mask_calls;
static atomic_int channel_unmask_calls;
static atomic_int close_failure_error;
static atomic_int close_failures_remaining;
static atomic_int close_attempts;
static atomic_int bind_retry_calls;
static atomic_int bind_ready_calls;
static atomic_ullong bind_resource_epoch = 1;
static int close_pause_enabled;
static int close_pause_entered;
static int close_pause_release;
static int receive_gate_enabled;
static unsigned int receive_gate_controller;
static int receive_gate_before_entered;
static int receive_gate_release_drain;
static int receive_gate_notify_entered;
static int receive_gate_release_notify;
static int removal_coherence_enabled;
static int removal_coherence_caller_registered;
static pthread_t removal_coherence_caller;
static int removal_coherence_caller_entered;
static int removal_coherence_release_caller;
static int removal_coherence_close_entered;
static int removal_coherence_release_close;
static int removal_coherence_wait_entered;
static unsigned int report_luns_commands;
static unsigned int vpd_commands;
static int invalid_scsi_address;

enum {
	RACE_PAUSE_NONE,
	RACE_PAUSE_BEFORE_PFNS,
	RACE_PAUSE_DURING_VMBUS_COPY,
};

enum {
	DISCOVERY_FAILURE_NONE,
	DISCOVERY_FAILURE_INQUIRY,
	DISCOVERY_FAILURE_CAPACITY,
};

enum {
	TEST_DEFER_NONE,
	TEST_DEFER_RESET,
	TEST_DEFER_FATAL,
	TEST_DEFER_REMOVE,
};

enum {
	REPORT_LUNS_NORMAL,
	REPORT_LUNS_EMPTY,
	REPORT_LUNS_TRUNCATED,
	REPORT_LUNS_CAPACITY,
	REPORT_LUNS_NO_ZERO,
	REPORT_LUNS_POOL_EXCESS,
};

enum {
	VPD_NORMAL,
	VPD_UNSUPPORTED,
	VPD_MALFORMED,
	VPD_MALFORMED_LUN2,
	VPD_DUPLICATE,
};

static uint32_t get_le32(const uint8_t *bytes, size_t offset)
{
	return (uint32_t)bytes[offset] |
		((uint32_t)bytes[offset + 1] << 8) |
		((uint32_t)bytes[offset + 2] << 16) |
		((uint32_t)bytes[offset + 3] << 24);
}

static uint32_t get_be32(const uint8_t *bytes, size_t offset)
{
	return ((uint32_t)bytes[offset] << 24) |
		((uint32_t)bytes[offset + 1] << 16) |
		((uint32_t)bytes[offset + 2] << 8) |
		(uint32_t)bytes[offset + 3];
}

static uint64_t get_be64(const uint8_t *bytes, size_t offset)
{
	return ((uint64_t)get_be32(bytes, offset) << 32) |
		get_be32(bytes, offset + 4);
}

static void put_le32(uint8_t *bytes, size_t offset, uint32_t value)
{
	bytes[offset] = (uint8_t)value;
	bytes[offset + 1] = (uint8_t)(value >> 8);
	bytes[offset + 2] = (uint8_t)(value >> 16);
	bytes[offset + 3] = (uint8_t)(value >> 24);
}

static void put_be32(uint8_t *bytes, size_t offset, uint32_t value)
{
	bytes[offset] = (uint8_t)(value >> 24);
	bytes[offset + 1] = (uint8_t)(value >> 16);
	bytes[offset + 2] = (uint8_t)(value >> 8);
	bytes[offset + 3] = (uint8_t)value;
}

static void put_be16(uint8_t *bytes, size_t offset, uint16_t value)
{
	bytes[offset] = (uint8_t)(value >> 8);
	bytes[offset + 1] = (uint8_t)value;
}

static void put_be64(uint8_t *bytes, size_t offset, uint64_t value)
{
	for (unsigned int i = 0; i < 8; i++)
		bytes[offset + i] = (uint8_t)(value >> ((7 - i) * 8));
}

static uint32_t response_packet_length(uint32_t request_length)
{
	if (!alternate_completion_size)
		return request_length;
	return request_length == 48 ? 64 : 48;
}

static unsigned int channel_index(const struct vmbus_channel *channel)
{
	if (!channel || channel < host_channels ||
	    channel >= host_channels + CONFIG_LIBSTORVSC_MAX_DEVICES)
		abort();
	return (unsigned int)(channel - host_channels);
}

static unsigned int storage_controller_index(
	const struct vmbus_channel *channel)
{
	return channel->device->instance_id.bytes[0] == 2 ? 1 : 0;
}

static void enqueue_packet_on(struct vmbus_channel *channel, uint64_t id,
			      const uint8_t *payload, uint32_t length)
{
	struct host_packet *packet;
	unsigned int index = channel_index(channel);

	pthread_mutex_lock(&packet_lock);
	if (packet_tail[index] - packet_head[index] >= 128)
		abort();
	packet = &packets[index][packet_tail[index]++ % 128];
	memset(packet, 0, sizeof(*packet));
	packet->id = id;
	packet->length = length;
	packet->type = VMBUS_PACKET_COMPLETION;
	memcpy(packet->payload, payload, length);
	pthread_mutex_unlock(&packet_lock);
}

static void enqueue_packet(uint64_t id, const uint8_t *payload,
			   uint32_t length)
{
	enqueue_packet_on(&host_channel, id, payload, length);
}

static void enqueue_completion_on(struct vmbus_channel *channel, uint64_t id,
				  uint32_t packet_length,
				  uint32_t packet_status,
				  uint8_t srb_status,
				  uint8_t scsi_status,
				  uint32_t transferred)
{
	uint8_t packet[64] = { 0 };

	put_le32(packet, 0, 1);
	put_le32(packet, 8, packet_status);
	packet[14] = srb_status;
	packet[15] = scsi_status;
	put_le32(packet, 24, transferred);
	enqueue_packet_on(channel, id, packet, packet_length);
}

static void enqueue_completion(uint64_t id, uint32_t packet_length,
			       uint32_t packet_status, uint8_t srb_status,
			       uint8_t scsi_status, uint32_t transferred)
{
	enqueue_completion_on(&host_channel, id, packet_length, packet_status,
			      srb_status, scsi_status, transferred);
}

static void enqueue_illegal_request_on(struct vmbus_channel *channel,
				       uint64_t id, uint32_t packet_length)
{
	uint8_t packet[64] = { 0 };

	put_le32(packet, 0, 1);
	packet[14] = 0x84;
	packet[15] = 0x02;
	packet[21] = 14;
	packet[28] = 0x70;
	packet[30] = 0x05;
	packet[40] = 0x20;
	enqueue_packet_on(channel, id, packet,
			  response_packet_length(packet_length));
}

static void enqueue_illegal_request(uint64_t id, uint32_t packet_length)
{
	enqueue_illegal_request_on(&host_channel, id, packet_length);
}

static void race_pause(uint64_t transaction_id, const uint64_t *pfns,
		       unsigned int written)
{
	pthread_mutex_lock(&race_lock);
	race_transaction_id = transaction_id;
	race_pfn_source = pfns;
	race_pfns_written = written;
	race_first_pfn = written ? pfns[0] : 0;
	race_hook_entered = 1;
	pthread_cond_broadcast(&race_condition);
	while (!race_release_sender)
		pthread_cond_wait(&race_condition, &race_lock);
	pthread_mutex_unlock(&race_lock);
}

void storvsc_host_pfn_copy_hook(uint64_t transaction_id,
				const uint64_t *pfns,
				unsigned int written)
{
	pthread_mutex_lock(&race_lock);
	if (race_pause_kind != RACE_PAUSE_BEFORE_PFNS || written != 0 ||
	    race_hook_entered) {
		pthread_mutex_unlock(&race_lock);
		return;
	}
	pthread_mutex_unlock(&race_lock);
	race_pause(transaction_id, pfns, written);
}

void storvsc_host_reset_ack_hook(void)
{
	pthread_mutex_lock(&race_lock);
	race_reset_ack = 1;
	pthread_cond_broadcast(&race_condition);
	while (race_pause_kind != RACE_PAUSE_NONE && !race_release_reset)
		pthread_cond_wait(&race_condition, &race_lock);
	pthread_mutex_unlock(&race_lock);
}

void storvsc_host_recovery_begin_hook(void)
{
	pthread_mutex_lock(&race_lock);
	race_recovery_begin = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
}

void storvsc_host_receive_hook(unsigned int controller, int before_notify)
{
	if (current_thread == &main_thread)
		return;

	pthread_mutex_lock(&race_lock);
	if (!receive_gate_enabled || controller != receive_gate_controller) {
		pthread_mutex_unlock(&race_lock);
		return;
	}
	if (!before_notify) {
		receive_gate_before_entered = 1;
		pthread_cond_broadcast(&race_condition);
		while (receive_gate_enabled && !receive_gate_release_drain)
			pthread_cond_wait(&race_condition, &race_lock);
	} else {
		receive_gate_notify_entered = 1;
		pthread_cond_broadcast(&race_condition);
		while (receive_gate_enabled && !receive_gate_release_notify)
			pthread_cond_wait(&race_condition, &race_lock);
	}
	pthread_mutex_unlock(&race_lock);
}

void storvsc_host_deferred_epoch_sample_hook(uint64_t epoch)
{
	pthread_mutex_lock(&race_lock);
	if (removal_coherence_enabled &&
	    removal_coherence_caller_registered &&
	    pthread_equal(pthread_self(), removal_coherence_caller)) {
		removal_coherence_caller_entered = 1;
		pthread_cond_broadcast(&race_condition);
		while (removal_coherence_enabled &&
		       !removal_coherence_release_caller)
			pthread_cond_wait(&race_condition, &race_lock);
	}
	if (!epoch_sample_enabled) {
		pthread_mutex_unlock(&race_lock);
		return;
	}
	epoch_sample_value = epoch;
	epoch_sample_entered = 1;
	pthread_cond_broadcast(&race_condition);
	while (!epoch_sample_release)
		pthread_cond_wait(&race_condition, &race_lock);
	pthread_mutex_unlock(&race_lock);
}

void storvsc_host_sync_completion_hook(void)
{
	if (!sync_finish_device)
		return;
	sync_finish_calls++;
	if (sync_finish_device->finish_reqs(
		    sync_finish_device, sync_finish_device->_queue[0]))
		abort();
}

void storvsc_host_binding_publish_hook(unsigned int controller)
{
	pthread_mutex_lock(&race_lock);
	if (!binding_publish_pause ||
	    controller != binding_publish_controller) {
		pthread_mutex_unlock(&race_lock);
		return;
	}
	binding_publish_entered = 1;
	pthread_cond_broadcast(&race_condition);
	while (!binding_publish_release)
		pthread_cond_wait(&race_condition, &race_lock);
	pthread_mutex_unlock(&race_lock);
}

int storvsc_host_registration_hook(unsigned int controller, uint8_t lun)
{
	if (!registration_failures_remaining ||
	    controller != registration_failure_controller ||
	    lun != registration_failure_lun)
		return 0;
	registration_failures_remaining--;
	return -EIO;
}

static void *thread_start(void *argument)
{
	struct uk_thread *thread = argument;

	current_thread = thread;
	thread->function(thread->argument);
	abort();
}

struct uk_alloc *uk_alloc_get_default(void)
{
	return &host_allocator;
}

void hyperv_persistence_host_event(enum hyperv_persistence_host_event event,
				  unsigned int index, int value)
{
	int should_add =
		(persistence_hook_mode ==
			 PERSISTENCE_HOOK_ADD_BEFORE_REVALIDATE &&
		 event == HYPERV_PERSISTENCE_HOST_BEFORE_REVALIDATE) ||
		(persistence_hook_mode ==
			 PERSISTENCE_HOOK_ADD_BEFORE_REJECT_END &&
		 event == HYPERV_PERSISTENCE_HOST_BEFORE_REJECT_END);

	(void)index;
	if (event == HYPERV_PERSISTENCE_HOST_SESSION_END_ERROR)
		persistence_hook_end_error = value;
	if (event == HYPERV_PERSISTENCE_HOST_IO_TIMEOUT)
		persistence_hook_timeouts++;
	if (!should_add || persistence_hook_fired)
		return;
	persistence_hook_fired = 1;
	if (!persistence_hook_driver || !persistence_hook_device)
		abort();
	persistence_hook_device->present = 1;
	if (persistence_hook_driver->add_dev(persistence_hook_device))
		abort();
}

int storvsc_host_irqs_disabled(void)
{
	return atomic_load(&host_irqs_disabled);
}

struct uk_sched *uk_sched_current(void)
{
	return &host_scheduler;
}

struct uk_thread *uk_thread_current(void)
{
	return current_thread;
}

struct uk_thread *uk_sched_thread_create(struct uk_sched *scheduler,
					  uk_thread_fn1_t function,
					  void *argument,
					  const char *name)
{
	struct uk_thread *thread;
	pthread_attr_t attributes;

	(void)scheduler;
	(void)name;
	thread = calloc(1, sizeof(*thread));
	if (!thread)
		return NULL;
	thread->function = function;
	thread->argument = argument;
	pthread_attr_init(&attributes);
	pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&thread->pthread, &attributes, thread_start, thread)) {
		pthread_attr_destroy(&attributes);
		free(thread);
		return NULL;
	}
	pthread_attr_destroy(&attributes);
	return thread;
}

void uk_thread_wake(struct uk_thread *thread)
{
	(void)thread;
}

void uk_sched_thread_sleep(__nsec nanoseconds)
{
	struct timespec delay = {
		.tv_sec = nanoseconds / 1000000000ULL,
		.tv_nsec = nanoseconds % 1000000000ULL,
	};

	nanosleep(&delay, NULL);
}

void uk_sched_thread_exit(void)
{
	struct uk_thread *thread = current_thread;

	current_thread = NULL;
	if (thread != &main_thread)
		free(thread);
	pthread_exit(NULL);
}

__nsec ukplat_monotonic_clock(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (__nsec)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

__paddr_t storvsc_host_virt_to_phys(__vaddr_t address)
{
	uintptr_t page = address & ~(uintptr_t)4095;
	uint64_t pfn = 0;

	pthread_mutex_lock(&mapping_lock);
	for (unsigned int i = 0; i < mapping_count; i++) {
		if (mappings[i].virtual_page == page) {
			pfn = mappings[i].pfn;
			break;
		}
	}
	if (!pfn) {
		if (mapping_count >= 512)
			abort();
		pfn = 0x10000 + (uint64_t)mapping_count * 3;
		mappings[mapping_count].virtual_page = page;
		mappings[mapping_count].pfn = pfn;
		mapping_count++;
	}
	pthread_mutex_unlock(&mapping_lock);
	return (pfn << 12) | (address & 4095);
}

static void *virtual_page_for_pfn(uint64_t pfn)
{
	void *result = NULL;

	pthread_mutex_lock(&mapping_lock);
	for (unsigned int i = 0; i < mapping_count; i++) {
		if (mappings[i].pfn == pfn) {
			result = (void *)mappings[i].virtual_page;
			break;
		}
	}
	pthread_mutex_unlock(&mapping_lock);
	return result;
}

static void range_write(const struct vmbus_gpa_range *range,
			const uint8_t *source, uint32_t length)
{
	uint32_t remaining = length;
	uint32_t source_offset = 0;

	for (uint32_t i = 0; i < range->pfn_count && remaining; i++) {
		uint8_t *page = virtual_page_for_pfn(range->pfns[i]);
		uint32_t offset = i ? 0 : range->byte_offset;
		uint32_t chunk = 4096 - offset;

		if (!page)
			abort();
		if (chunk > remaining)
			chunk = remaining;
		memcpy(page + offset, source + source_offset, chunk);
		source_offset += chunk;
		remaining -= chunk;
	}
	if (remaining)
		abort();
}

static void range_read(const struct vmbus_gpa_range *range,
		       uint8_t *destination, uint32_t length)
{
	uint32_t remaining = length;
	uint32_t destination_offset = 0;

	for (uint32_t i = 0; i < range->pfn_count && remaining; i++) {
		uint8_t *page = virtual_page_for_pfn(range->pfns[i]);
		uint32_t offset = i ? 0 : range->byte_offset;
		uint32_t chunk = 4096 - offset;

		if (!page)
			abort();
		if (chunk > remaining)
			chunk = remaining;
		memcpy(destination + destination_offset, page + offset, chunk);
		destination_offset += chunk;
		remaining -= chunk;
	}
	if (remaining)
		abort();
}

static void fill_read_data(const struct vmbus_gpa_range *range,
			   uint32_t length, uint8_t seed)
{
	uint8_t *data = malloc(length);

	if (!data)
		abort();
	for (uint32_t i = 0; i < length; i++)
		data[i] = (uint8_t)(i ^ seed);
	range_write(range, data, length);
	free(data);
}

static uint64_t scsi_io_lba(const uint8_t *payload, uint8_t opcode)
{
	return opcode == 0x28 || opcode == 0x2a ?
		get_be32(payload, 30) : get_be64(payload, 30);
}

static void handle_scsi(struct vmbus_channel *channel, uint64_t id,
			const struct vmbus_gpa_range *range,
			const uint8_t *payload, uint32_t packet_length)
{
	uint8_t opcode = payload[28];
	uint8_t lun = payload[19];
	unsigned int controller = storage_controller_index(channel);
	uint32_t transfer = get_le32(payload, 24);
	uint8_t data[STORVSC_REPORT_LUNS_DATA_SIZE] = { 0 };
	uint32_t response_transfer = transfer;

	if (payload[17] || payload[18])
		invalid_scsi_address = 1;
	if (discovery_failures_remaining &&
	    controller == discovery_failure_controller &&
	    lun == discovery_failure_lun &&
	    ((discovery_failure_kind == DISCOVERY_FAILURE_INQUIRY &&
	      opcode == 0x12 && !(payload[29] & 1)) ||
	     (discovery_failure_kind == DISCOVERY_FAILURE_CAPACITY &&
	      opcode == 0x25))) {
		discovery_failures_remaining--;
		enqueue_completion_on(
			channel, id, response_packet_length(packet_length),
			1, 1, 0, 0);
		return;
	}
	switch (opcode) {
	case 0xa0:
		report_luns_commands++;
		if (payload[20] != 12 || transfer !=
		    STORVSC_REPORT_LUNS_DATA_SIZE ||
		    get_be32(payload, 34) != STORVSC_REPORT_LUNS_DATA_SIZE)
			invalid_scsi_address = 1;
		response_transfer = STORVSC_REPORT_LUNS_HEADER_SIZE;
		if (topology_fixture &&
		    report_luns_mode == REPORT_LUNS_NORMAL) {
			put_be32(data, 0, 2 * STORVSC_REPORT_LUN_ENTRY_SIZE);
			if (controller == 0) {
				data[9] = 2;
				data[17] = 0;
			} else {
				data[9] = 3;
				data[16] = 0x40;
			}
			response_transfer +=
				2 * STORVSC_REPORT_LUN_ENTRY_SIZE;
			range_write(range, data, response_transfer);
			break;
		}
		switch (report_luns_mode) {
		case REPORT_LUNS_NORMAL:
			put_be32(data, 0, 3 * STORVSC_REPORT_LUN_ENTRY_SIZE);
			data[9] = 7;
			data[16] = 0x40;
			data[25] = 3;
			response_transfer +=
				3 * STORVSC_REPORT_LUN_ENTRY_SIZE;
			break;
		case REPORT_LUNS_EMPTY:
			break;
		case REPORT_LUNS_TRUNCATED:
			put_be32(data, 0,
				 2 * STORVSC_REPORT_LUN_ENTRY_SIZE);
			break;
		case REPORT_LUNS_CAPACITY:
			put_be32(data, 0,
				 (STORVSC_REPORT_LUNS_MAX + 1) *
				 STORVSC_REPORT_LUN_ENTRY_SIZE);
			break;
		case REPORT_LUNS_NO_ZERO:
			put_be32(data, 0, 2 * STORVSC_REPORT_LUN_ENTRY_SIZE);
			data[9] = 7;
			data[17] = 3;
			response_transfer +=
				2 * STORVSC_REPORT_LUN_ENTRY_SIZE;
			break;
		case REPORT_LUNS_POOL_EXCESS:
		{
			static const uint8_t pool_luns[] = { 0, 1, 3, 7, 2 };

			put_be32(data, 0, 5 * STORVSC_REPORT_LUN_ENTRY_SIZE);
			for (unsigned int i = 0; i < 5; i++)
				data[9 + i * STORVSC_REPORT_LUN_ENTRY_SIZE] =
					pool_luns[i];
			response_transfer +=
				5 * STORVSC_REPORT_LUN_ENTRY_SIZE;
			break;
		}
		default:
			abort();
		}
		range_write(range, data, response_transfer);
		break;
	case 0x12:
		if (payload[29] & 1) {
			vpd_commands++;
			if (payload[30] != 0x83) {
				enqueue_illegal_request_on(channel, id,
							   packet_length);
				return;
			}
			if (vpd_mode == VPD_UNSUPPORTED) {
				enqueue_illegal_request_on(channel, id,
							   packet_length);
				return;
			}
			data[1] = 0x83;
			if (vpd_mode == VPD_MALFORMED ||
			    (vpd_mode == VPD_MALFORMED_LUN2 &&
			     controller == 0 && lun == 2) ||
			    (targeted_vpd_malformed &&
			     controller == targeted_vpd_controller &&
			     lun == targeted_vpd_lun)) {
				put_be16(data, 2, 32);
				response_transfer = 4;
			} else {
				put_be16(data, 2, 12);
				data[4] = 1;
				data[5] = 3;
				data[7] = 8;
				data[8] = 0x50;
				if (vpd_mode != VPD_DUPLICATE) {
					data[9] = (uint8_t)controller;
					memcpy(data + 10,
					       channel->device->instance_id.bytes,
					       5);
					data[15] = lun;
					data[14] ^= vpd_variant;
				}
				response_transfer = 16;
			}
			range_write(range, data, response_transfer);
			break;
		}
		data[0] = 0;
		data[2] = 5;
		data[3] = 2;
		data[4] = 0xff;
		memcpy(data + 8, "Msft    Virtual Disk    ", 24);
		range_write(range, data, transfer);
		break;
	case 0x00:
		break;
	case 0x25:
		if (use_capacity16)
			put_be32(data, 0, UINT32_MAX);
		else if (topology_fixture)
			put_be32(data, 0,
				 (controller + 1) * 1000 + lun * 100 - 1);
		else
			put_be32(data, 0, 999);
		put_be32(data, 4, 512);
		range_write(range, data, 8);
		break;
	case 0x9e:
		put_be64(data, 0, 0x100000100ULL);
		put_be32(data, 8, 512);
		range_write(range, data, transfer);
		break;
	case 0x1a:
		if (reject_mode_sense6) {
			reject_mode_sense6--;
			enqueue_illegal_request_on(channel, id, packet_length);
			return;
		}
		data[0] = 3;
		data[2] = (read_only_media ||
			   (topology_fixture && controller == 1 && lun == 3)) ?
			0x80 : 0;
		range_write(range, data, transfer);
		break;
	case 0x5a:
		if (reject_mode_sense10) {
			reject_mode_sense10--;
			enqueue_illegal_request_on(channel, id, packet_length);
			return;
		}
		data[1] = 6;
		data[3] = (read_only_media ||
			   (topology_fixture && controller == 1 && lun == 3)) ?
			0x80 : 0;
		range_write(range, data, transfer);
		break;
	case 0x28:
	case 0x88:
		last_io_id = id;
		last_io_length = transfer;
		last_io_opcode = opcode;
		io_command_count++;
		if (hold_io) {
			if (backing_media_enabled) {
				uint64_t lba = scsi_io_lba(payload, opcode);

				if (lba * 512 + transfer >
				    sizeof(backing_media))
					abort();
				range_write(range, backing_media + lba * 512,
					    transfer);
			} else {
				fill_read_data(
					range, transfer,
					topology_fixture ?
					(uint8_t)(0x20 + controller * 0x10 +
						  lun) :
					0x5a);
			}
			if (pending_count >= 32)
				abort();
			pending[pending_count++] = (struct pending_io){
				.channel = channel,
				.id = id,
				.length = transfer,
			};
			return;
		}
		if (backing_media_enabled) {
			uint64_t lba = scsi_io_lba(payload, opcode);

			if (lba * 512 + transfer > sizeof(backing_media))
				abort();
			range_write(range, backing_media + lba * 512, transfer);
		} else {
			fill_read_data(range, transfer,
				       topology_fixture ?
				       (uint8_t)(0x20 + controller * 0x10 + lun) :
				       0x5a);
		}
		if (short_transfer_once) {
			response_transfer--;
			short_transfer_once = 0;
		}
		break;
	case 0x2a:
	case 0x8a:
		last_io_id = id;
		last_io_length = transfer;
		last_io_opcode = opcode;
		io_command_count++;
		if (opcode == 0x2a)
			write10_command_count++;
		else
			write16_command_count++;
		if (backing_media_enabled) {
			uint64_t lba = scsi_io_lba(payload, opcode);

			if (lba * 512 + transfer > sizeof(backing_media))
				abort();
			range_read(range, backing_media + lba * 512, transfer);
		}
		if (hold_io) {
			pending[pending_count++] = (struct pending_io){
				.channel = channel,
				.id = id,
				.length = transfer,
			};
			return;
		}
		break;
	case 0x35:
		last_io_id = id;
		last_io_length = 0;
		last_io_opcode = opcode;
		io_command_count++;
		flush_command_count++;
		if (hold_io) {
			if (pending_count >= 32)
				abort();
			pending[pending_count++] = (struct pending_io){
				.channel = channel,
				.id = id,
				.length = 0,
			};
			return;
		}
		break;
	default:
		enqueue_completion_on(channel, id, packet_length, 0, 0x86,
				      0x02, 0);
		return;
	}
	enqueue_completion_on(
		channel, id, response_packet_length(packet_length),
		io_packet_error_once ? (io_packet_error_once = 0, 1) : 0,
		1, 0, response_transfer);
}

static int handle_send(struct vmbus_channel *channel, uint64_t id,
		       const struct vmbus_gpa_range *range,
		       const uint8_t *payload, uint32_t packet_length,
		       int *published)
{
	uint32_t operation = get_le32(payload, 0);
	uint8_t response[64] = { 0 };

	*published = 1;
	put_le32(response, 0, 1);
	switch (operation) {
	case 7:
		if (malformed_handshake) {
			enqueue_packet_on(channel, id, response, 47);
			malformed_handshake = 0;
		} else {
			enqueue_packet_on(
				channel, id, response,
				response_packet_length(packet_length));
		}
		break;
	case 9:
		if (reject_versions > 0) {
			put_le32(response, 8, 1);
			reject_versions--;
		}
		enqueue_packet_on(channel, id, response,
				  response_packet_length(packet_length));
		break;
	case 10:
		put_le32(response, 24, 128 * 1024);
		enqueue_packet_on(channel, id, response,
				  response_packet_length(packet_length));
		break;
	case 8:
	case 6:
		enqueue_packet_on(channel, id, response,
				  response_packet_length(packet_length));
		break;
	case 3:
		handle_scsi(channel, id, range, payload, packet_length);
		break;
	default:
		put_le32(response, 8, 1);
		enqueue_packet_on(channel, id, response,
				  response_packet_length(packet_length));
		break;
	}
	if (publish_error_once) {
		publish_error_once = 0;
		return -EIO;
	}
	return 0;
}

int vmbus_channel_open(struct vmbus_device *device, __u16 tx_pages,
		       __u16 rx_pages, const void *user_data,
		       size_t user_data_size)
{
	struct vmbus_channel *channel = NULL;
	unsigned int i;

	if (!device || tx_pages < 2 || rx_pages < 2 ||
	    !user_data || user_data_size != 24)
		return -EINVAL;
	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_DEVICES; i++) {
		if (host_channels[i].device == device) {
			channel = &host_channels[i];
			break;
		}
		if (!channel && !host_channels[i].device)
			channel = &host_channels[i];
	}
	if (!channel || channel->open)
		return -ENOSPC;
	memset(channel, 0, sizeof(*channel));
	channel->device = device;
	channel->open = 1;
	device->channel = channel;
	return 0;
}

int vmbus_channel_close(struct vmbus_channel *channel)
{
	pthread_mutex_lock(&race_lock);
	if (removal_coherence_enabled && current_thread != &main_thread) {
		removal_coherence_close_entered = 1;
		pthread_cond_broadcast(&race_condition);
		while (removal_coherence_enabled &&
		       !removal_coherence_release_close)
			pthread_cond_wait(&race_condition, &race_lock);
	}
	pthread_mutex_unlock(&race_lock);
	atomic_fetch_add(&close_attempts, 1);
	if (atomic_load(&close_failures_remaining) > 0) {
		pthread_mutex_lock(&race_lock);
		if (close_pause_enabled) {
			close_pause_entered = 1;
			pthread_cond_broadcast(&race_condition);
			while (!close_pause_release)
				pthread_cond_wait(&race_condition,
						  &race_lock);
		}
		pthread_mutex_unlock(&race_lock);
		atomic_fetch_sub(&close_failures_remaining, 1);
		return atomic_load(&close_failure_error);
	}
	if (!channel || !channel->open)
		return -ENODEV;
	channel->open = 0;
	channel->callback = NULL;
	if (channel->device) {
		channel->device->channel = NULL;
		channel->device = NULL;
	}
	close_count++;
	return 0;
}

int vmbus_device_bind_epoch(struct vmbus_device *device,
			    struct vmbus_device_bind_token *token)
{
	if (use_vmbus_offer_lifetimes)
		return vmbus_epoch_object_bind_epoch(device, token);
	if (!device || !token)
		return -EINVAL;
	token->device_generation = 1;
	token->resource_epoch = atomic_load(&bind_resource_epoch);
	return 0;
}

int vmbus_device_bind_retry(
	struct vmbus_device *device,
	const struct vmbus_device_bind_token *token)
{
	if (use_vmbus_offer_lifetimes)
		return vmbus_epoch_object_bind_retry(device, token);
	if (!device || !token || !token->device_generation ||
	    !token->resource_epoch)
		return -EINVAL;
	atomic_fetch_add(&bind_retry_calls, 1);
	return -ENOSPC;
}

void vmbus_device_bind_ready(void)
{
	if (use_vmbus_offer_lifetimes) {
		vmbus_epoch_object_bind_ready();
		return;
	}
	atomic_fetch_add(&bind_ready_calls, 1);
	atomic_fetch_add(&bind_resource_epoch, 1);
}

int vmbus_channel_control_receive(const __u8 *message, size_t length)
{
	(void)message;
	(void)length;
	return 0;
}

__u32 vmbus_channel_take_ignored_responses(void)
{
	return 0;
}

void vmbus_channel_event(__u32 event)
{
	(void)event;
}

int vmbus_channel_rescind(__u32 channel_id)
{
	(void)channel_id;
	return -ENODEV;
}

void vmbus_channel_close_all(void)
{
}

void vmbus_channel_reset_all(void)
{
}

void vmbus_channel_quarantine_all(void)
{
}

int vmbus_channel_send_ex(struct vmbus_channel *channel, __u16 packet_type,
			  __u16 flags, __u64 id,
			  const void *descriptor, size_t descriptor_size,
			  const void *payload, size_t payload_size,
			  int *published)
{
	(void)flags;
	if (!channel || !channel->open || !published)
		return -ENODEV;
	if (packet_type != VMBUS_PACKET_DATA_INBAND || descriptor ||
	    descriptor_size || !payload || payload_size > 64) {
		*published = 0;
		return -EINVAL;
	}
	return handle_send(channel, id, NULL, payload, payload_size,
			   published);
}

int vmbus_channel_send_gpa_direct_ex(
	struct vmbus_channel *channel, __u16 flags, __u64 id,
	const struct vmbus_gpa_range *ranges, __u32 range_count,
	const void *payload, size_t payload_size, int *published)
{
	(void)flags;
	if (!channel || !channel->open || !published || !ranges ||
	    range_count != 1 || !payload || payload_size > 64) {
		if (published)
			*published = 0;
		return -EINVAL;
	}
	last_pfn_count = ranges[0].pfn_count;
	for (uint32_t i = 0; i < last_pfn_count; i++) {
		last_pfns[i] = ranges[0].pfns[i];
		if (race_pause_kind == RACE_PAUSE_DURING_VMBUS_COPY &&
		    i == 0 && !race_hook_entered)
			race_pause(id, ranges[0].pfns, i + 1);
	}
	if (race_sender_request && id == race_transaction_id &&
	    atomic_load(&race_sender_request->state.counter) ==
		    UK_BLKREQ_FINISHED)
		atomic_store(&race_post_completion_publication, 1);
	return handle_send(channel, id, &ranges[0], payload, payload_size,
			   published);
}

int vmbus_channel_receive(struct vmbus_channel *channel,
			  struct vmbus_packet *packet, void *descriptor,
			  size_t descriptor_capacity, void *payload,
			  size_t payload_capacity)
{
	struct host_packet queued;
	unsigned int index;

	(void)descriptor;
	(void)descriptor_capacity;
	if (!channel || !channel->open)
		return -ENODEV;
	index = channel_index(channel);
	pthread_mutex_lock(&packet_lock);
	if (packet_head[index] == packet_tail[index]) {
		pthread_mutex_unlock(&packet_lock);
		return -EAGAIN;
	}
	queued = packets[index][packet_head[index]++ % 128];
	pthread_mutex_unlock(&packet_lock);
	if (queued.length > payload_capacity)
		return -ENOBUFS;
	memset(packet, 0, sizeof(*packet));
	packet->type = queued.type;
	packet->transaction_id = queued.id;
	packet->descriptor_size = queued.descriptor_size;
	packet->payload_size = queued.length;
	memcpy(payload, queued.payload, queued.length);
	return 0;
}

int vmbus_channel_poll(struct vmbus_channel *channel)
{
	int available;
	unsigned int index;

	if (!channel || !channel->open)
		return -ENODEV;
	index = channel_index(channel);
	pthread_mutex_lock(&packet_lock);
	available = packet_head[index] != packet_tail[index];
	pthread_mutex_unlock(&packet_lock);
	return available;
}

void vmbus_channel_set_callback(struct vmbus_channel *channel,
				vmbus_channel_callback_t callback, void *arg)
{
	if (!channel || !channel->open)
		return;
	channel->callback = callback;
	channel->callback_arg = arg;
}

int vmbus_channel_mask_interrupts(struct vmbus_channel *channel)
{
	atomic_fetch_add(&channel_mask_calls, 1);
	if (!channel || !channel->open)
		return -ENODEV;
	channel->masked = 1;
	return 0;
}

int vmbus_channel_unmask_interrupts(struct vmbus_channel *channel)
{
	atomic_fetch_add(&channel_unmask_calls, 1);
	if (!channel || !channel->open)
		return -ENODEV;
	channel->masked = 0;
	return vmbus_channel_poll(channel);
}

int uk_blkdev_drv_register(struct uk_blkdev *device,
			   struct uk_alloc *allocator, const char *name)
{
	struct uk_blkdev_data *data = calloc(1, sizeof(*data));

	if (!data)
		return -ENOMEM;
	if (next_blkdev_id == UINT16_MAX) {
		free(data);
		return -ENOSPC;
	}
	data->id = next_blkdev_id++;
	data->state = UK_BLKDEV_UNCONFIGURED;
	data->drv_name = name;
	data->a = allocator;
	device->_data = data;
	if (data->id >= sizeof(registered_blkdevs) /
			 sizeof(registered_blkdevs[0])) {
		free(data);
		device->_data = NULL;
		return -ENOSPC;
	}
	registered_blkdevs[data->id] = device;
	return data->id;
}

void uk_blkdev_drv_unregister(struct uk_blkdev *device)
{
	unregister_calls++;
	if (device->_data &&
	    device->_data->id < sizeof(registered_blkdevs) /
				       sizeof(registered_blkdevs[0]))
		registered_blkdevs[device->_data->id] = NULL;
	free(device->_data);
	device->_data = NULL;
}

struct uk_blkdev *uk_blkdev_get(uint16_t id)
{
	if (id >= sizeof(registered_blkdevs) /
			  sizeof(registered_blkdevs[0]))
		return NULL;
	return registered_blkdevs[id];
}

enum uk_blkdev_state uk_blkdev_state_get(struct uk_blkdev *device)
{
	return device && device->_data ?
		device->_data->state : UK_BLKDEV_INVALID;
}

int uk_blkdev_configure(struct uk_blkdev *device,
			const struct uk_blkdev_conf *config)
{
	int rc = device->dev_ops->dev_configure(device, config);

	if (!rc)
		device->_data->state = UK_BLKDEV_CONFIGURED;
	return rc;
}

int uk_blkdev_queue_configure(struct uk_blkdev *device, uint16_t queue_id,
			      uint16_t descriptors,
			      const struct uk_blkdev_queue_conf *config)
{
	struct uk_blkdev_queue *queue = device->dev_ops->queue_configure(
		device, queue_id, descriptors, config);

	if ((uintptr_t)queue >= (uintptr_t)-4095)
		return (int)(intptr_t)queue;
	device->_queue[queue_id] = queue;
	device->_data->queue_handler[queue_id].callback = config->callback;
	device->_data->queue_handler[queue_id].cookie =
		config->callback_cookie;
	return 0;
}

int uk_blkdev_start(struct uk_blkdev *device)
{
	int rc = device->dev_ops->dev_start(device);

	if (!rc)
		device->_data->state = UK_BLKDEV_RUNNING;
	return rc;
}

int uk_blkdev_queue_intr_enable(struct uk_blkdev *device, uint16_t queue_id)
{
	return device->dev_ops->queue_intr_enable(
		device, device->_queue[queue_id]);
}

int uk_blkdev_queue_submit_one(struct uk_blkdev *device, uint16_t queue_id,
			       struct uk_blkreq *request)
{
	return device->submit_one(device, device->_queue[queue_id], request);
}

int uk_blkdev_queue_finish_reqs(struct uk_blkdev *device, uint16_t queue_id)
{
	return device->finish_reqs(device, device->_queue[queue_id]);
}

static void fire_channel_on(struct vmbus_channel *channel)
{
	if (channel && channel->callback)
		channel->callback(channel, channel->callback_arg);
}

static void fire_channel(void)
{
	fire_channel_on(&host_channel);
}

static void enqueue_enumerate_bus(struct vmbus_channel *channel)
{
	uint8_t payload[4] = { 0 };

	put_le32(payload, 0, 11);
	enqueue_packet_on(channel, 0, payload, sizeof(payload));
}

static void initialize_request(struct uk_blkreq *request,
			       enum uk_blkreq_op operation, __sector start,
			       __sector count, void *buffer,
			       uk_blkreq_event_t callback, void *cookie)
{
	memset(request, 0, sizeof(*request));
	request->operation = operation;
	request->start_sector = start;
	request->nb_sectors = count;
	request->aio_buf = buffer;
	request->cb = callback;
	request->cb_cookie = cookie;
	atomic_store(&request->state.counter, UK_BLKREQ_UNFINISHED);
}

static void request_done(struct uk_blkreq *request, void *cookie)
{
	atomic_int *count = cookie;

	(void)request;
	atomic_fetch_add(count, 1);
}

static int capture_persistence_output(
	char *output, size_t capacity, int *result)
{
	int descriptors[2];
	int saved_stdout;
	int flush_rc;
	int restore_rc;
	size_t used = 0;
	ssize_t count;

	if (!output || capacity < 2 || !result || fflush(stdout) ||
	    pipe(descriptors))
		return -EIO;
	saved_stdout = dup(STDOUT_FILENO);
	if (saved_stdout < 0) {
		close(descriptors[0]);
		close(descriptors[1]);
		return -EIO;
	}
	if (dup2(descriptors[1], STDOUT_FILENO) < 0) {
		close(saved_stdout);
		close(descriptors[0]);
		close(descriptors[1]);
		return -EIO;
	}
	close(descriptors[1]);
	*result = hyperv_acceptance_persistence_main();
	flush_rc = fflush(stdout);
	restore_rc = dup2(saved_stdout, STDOUT_FILENO);
	if (flush_rc || restore_rc < 0) {
		close(saved_stdout);
		close(descriptors[0]);
		return -EIO;
	}
	close(saved_stdout);
	while ((count = read(
			descriptors[0], output + used,
			capacity - used - 1)) > 0) {
		used += (size_t)count;
		if (used == capacity - 1)
			break;
	}
	close(descriptors[0]);
	output[used] = '\0';
	return count < 0 ? -EIO : 0;
}

static unsigned int persistence_log_line_count(
	const char *output, const char *marker, int prefix)
{
	const char *line = output;
	size_t marker_length = strlen(marker);
	unsigned int count = 0;

	while (*line) {
		const char *end = strchr(line, '\n');
		size_t line_length = end ? (size_t)(end - line) : strlen(line);

		if ((!prefix && line_length == marker_length) ||
		    (prefix && line_length >= marker_length))
			if (!memcmp(line, marker, marker_length))
				count++;
		if (!end)
			break;
		line = end + 1;
	}
	return count;
}

static int persistence_log_has_unavailable(const char *output)
{
	return persistence_log_line_count(
		       output, "HYPERV_PERSISTENCE SELECT UNAVAILABLE ", 1) ||
	       persistence_log_line_count(
		       output, "UK_HYPERV_PERSISTENCE_UNAVAILABLE:", 1) ||
	       persistence_log_line_count(
		       output, "UK_HYPERV_PLATFORM_READY", 0);
}

static void retained_request_done(struct uk_blkreq *request, void *cookie)
{
	(void)request;
	(void)cookie;
	pthread_mutex_lock(&race_lock);
	retained_callback_entered = 1;
	pthread_cond_broadcast(&race_condition);
	while (!retained_callback_release)
		pthread_cond_wait(&race_condition, &race_lock);
	retained_callback_count++;
	pthread_mutex_unlock(&race_lock);
}

static void retained_counted_request_done(
	struct uk_blkreq *request, void *cookie)
{
	request_done(request, cookie);
	retained_request_done(request, NULL);
}

static void retained_then_counted_request_done(
	struct uk_blkreq *request, void *cookie)
{
	retained_request_done(request, NULL);
	request_done(request, cookie);
}

struct fire_channel_context {
	struct vmbus_channel *channel;
};

static void *fire_channel_thread(void *argument)
{
	struct fire_channel_context *context = argument;

	fire_channel_on(context->channel);
	return NULL;
}

static void release_retained_callback(void)
{
	pthread_mutex_lock(&race_lock);
	retained_callback_release = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
}

static void release_retained_callback_thread(pthread_t thread)
{
	release_retained_callback();
	pthread_join(thread, NULL);
}

static void queue_event(struct uk_blkdev *device, uint16_t queue_id,
			void *cookie)
{
	int *events = cookie;

	(*events)++;
	if (device == deferred_finish_device) {
		deferred_finish_events++;
		return;
	}
	if (device->finish_reqs(device, device->_queue[queue_id]))
		abort();
}

static int wait_request_completion(struct uk_blkreq *request,
				   atomic_int *callbacks,
				   int expected_callbacks,
				   unsigned int limit_ms)
{
	for (unsigned int i = 0; i < limit_ms; i++) {
		if (atomic_load(&request->state.counter) ==
			    UK_BLKREQ_FINISHED &&
		    atomic_load(callbacks) == expected_callbacks)
			return 0;
		uk_sched_thread_sleep(1000000ULL);
	}
	return -ETIMEDOUT;
}

static void complete_pending(unsigned int duplicates)
{
	for (unsigned int i = 0; i < pending_count; i++) {
		enqueue_completion_on(pending[i].channel, pending[i].id, 64,
				      0, 1, 0, pending[i].length);
		for (unsigned int duplicate = 0; duplicate < duplicates;
		     duplicate++)
			enqueue_completion_on(
				pending[i].channel, pending[i].id, 64, 0, 1,
				0, pending[i].length);
	}
	pending_count = 0;
}

static void complete_pending_reverse(unsigned int duplicates)
{
	for (unsigned int i = pending_count; i > 0; i--) {
		struct pending_io *entry = &pending[i - 1];

		enqueue_completion_on(entry->channel, entry->id, 64,
				      0, 1, 0, entry->length);
		for (unsigned int duplicate = 0; duplicate < duplicates;
		     duplicate++)
			enqueue_completion_on(entry->channel, entry->id, 64,
					      0, 1, 0, entry->length);
	}
	pending_count = 0;
}

static void drop_packets(void)
{
	pthread_mutex_lock(&packet_lock);
	for (unsigned int i = 0; i < CONFIG_LIBSTORVSC_MAX_DEVICES; i++)
		packet_head[i] = packet_tail[i];
	pthread_mutex_unlock(&packet_lock);
}

static int configure_device(struct uk_blkdev *device, uint16_t descriptors,
			    int *events)
{
	struct uk_blkdev_conf config = { .nb_queues = 1 };
	struct uk_blkdev_queue_conf queue_config = {
		.a = &host_allocator,
		.callback = queue_event,
		.callback_cookie = events,
	};
	struct uk_blkdev_queue *queue;
	int rc;

	rc = device->dev_ops->dev_configure(device, &config);
	if (rc)
		return rc;
	device->_data->state = UK_BLKDEV_CONFIGURED;
	queue = device->dev_ops->queue_configure(device, 0, descriptors,
						  &queue_config);
	if ((uintptr_t)queue >= (uintptr_t)-4095)
		return (int)(intptr_t)queue;
	device->_queue[0] = queue;
	device->_data->queue_handler[0].callback = queue_config.callback;
	device->_data->queue_handler[0].cookie = queue_config.callback_cookie;
	rc = device->dev_ops->dev_start(device);
	if (rc)
		return rc;
	device->_data->state = UK_BLKDEV_RUNNING;
	return device->dev_ops->queue_intr_enable(device, queue);
}

static int activate_device(struct uk_blkdev *device, int *events)
{
	if (!device || !device->_data)
		return -ENODEV;
	if (device->_data->state == UK_BLKDEV_RUNNING)
		return device->dev_ops->queue_intr_enable(device,
							  device->_queue[0]);
	return configure_device(device, 2, events);
}

static int run_mixed_lun_completion(struct uk_blkdev *polled,
				    struct uk_blkdev *interrupt_driven,
				    struct vmbus_channel *channel,
				    uint8_t *buffer, int reverse,
				    int error_base)
{
	struct uk_blkreq polled_request;
	struct uk_blkreq interrupt_request;
	atomic_int callbacks;
	struct pending_io polled_pending;
	struct pending_io interrupt_pending;

	atomic_init(&callbacks, 0);
	if (polled->dev_ops->queue_intr_disable(polled,
						polled->_queue[0]))
		return error_base;
	deferred_finish_device = interrupt_driven;
	deferred_finish_events = 0;
	hold_io = 1;
	pending_count = 0;
	initialize_request(&polled_request, UK_BLKREQ_READ, 20, 1,
			   buffer, request_done, &callbacks);
	initialize_request(&interrupt_request, UK_BLKREQ_READ, 21, 1,
			   buffer + 512, NULL, NULL);
	if (!(polled->submit_one(polled, polled->_queue[0],
				 &polled_request) &
	      UK_BLKDEV_STATUS_SUCCESS) ||
	    !(interrupt_driven->submit_one(interrupt_driven,
					   interrupt_driven->_queue[0],
					   &interrupt_request) &
	      UK_BLKDEV_STATUS_SUCCESS) ||
	    pending_count != 2)
		return error_base + 1;
	polled_pending = pending[0];
	interrupt_pending = pending[1];
	if (reverse) {
		enqueue_completion_on(interrupt_pending.channel,
				      interrupt_pending.id, 64, 0, 1, 0,
				      interrupt_pending.length);
		enqueue_completion_on(polled_pending.channel,
				      polled_pending.id, 64, 0, 1, 0,
				      polled_pending.length);
	} else {
		enqueue_completion_on(polled_pending.channel,
				      polled_pending.id, 64, 0, 1, 0,
				      polled_pending.length);
		enqueue_completion_on(interrupt_pending.channel,
				      interrupt_pending.id, 64, 0, 1, 0,
				      interrupt_pending.length);
	}
	pending_count = 0;
	if (polled->finish_reqs(polled, polled->_queue[0]) ||
	    polled_request.result ||
	    atomic_load(&callbacks) != 1 ||
	    atomic_load(&interrupt_request.state.counter) ==
		    UK_BLKREQ_FINISHED ||
	    !storvsc_host_request_bound(&interrupt_request) ||
	    deferred_finish_events != 1)
		return error_base + 2;
	if (interrupt_driven->finish_reqs(interrupt_driven,
					  interrupt_driven->_queue[0]) ||
	    interrupt_request.result ||
	    atomic_load(&interrupt_request.state.counter) !=
		    UK_BLKREQ_FINISHED ||
	    storvsc_host_request_bound(&interrupt_request) ||
	    deferred_finish_events != 1)
		return error_base + 3;
	enqueue_completion_on(channel, polled_pending.id, 64,
			      0, 1, 0, polled_pending.length);
	enqueue_completion_on(channel, interrupt_pending.id, 64,
			      0, 1, 0, interrupt_pending.length);
	fire_channel_on(channel);
	if (atomic_load(&callbacks) != 1 || deferred_finish_events != 1)
		return error_base + 4;
	deferred_finish_device = NULL;
	hold_io = 0;
	if (polled->dev_ops->queue_intr_enable(polled,
					       polled->_queue[0]))
		return error_base + 5;
	return 0;
}

static int submit_and_fire(struct uk_blkdev *device,
			   struct uk_blkreq *request)
{
	int rc = device->submit_one(device, device->_queue[0], request);

	if (!(rc & UK_BLKDEV_STATUS_SUCCESS))
		return rc;
	fire_channel();
	return 0;
}

struct reentry_context {
	struct uk_blkdev *device;
	struct uk_blkreq *next;
	atomic_int callbacks;
	int nested_finish_result;
	int submit_result;
};

static void reentry_done(struct uk_blkreq *request, void *cookie)
{
	struct reentry_context *context = cookie;

	(void)request;
	atomic_fetch_add(&context->callbacks, 1);
	context->nested_finish_result = context->device->finish_reqs(
		context->device, context->device->_queue[0]);
	context->submit_result = context->device->submit_one(
		context->device, context->device->_queue[0], context->next);
}

struct submit_thread_context {
	struct uk_blkdev *device;
	struct uk_blkreq *request;
	atomic_int done;
	int result;
};

struct reset_thread_context {
	atomic_int done;
	int result;
};

struct add_thread_context {
	struct vmbus_driver *driver;
	struct vmbus_device *device;
	atomic_int done;
	int result;
};

struct rescind_thread_context {
	__u32 channel_id;
	int result;
};

static void *submit_thread(void *argument)
{
	struct submit_thread_context *context = argument;

	context->result = context->device->submit_one(
		context->device, context->device->_queue[0],
		context->request);
	atomic_store(&context->done, 1);
	return NULL;
}

static void *reset_thread(void *argument)
{
	struct reset_thread_context *context = argument;

	context->result = storvsc_host_reset_timed_out_io();
	atomic_store(&context->done, 1);
	return NULL;
}

static void *add_thread(void *argument)
{
	struct add_thread_context *context = argument;

	context->result = context->driver->add_dev(context->device);
	atomic_store(&context->done, 1);
	return NULL;
}

static void *rescind_thread(void *argument)
{
	struct rescind_thread_context *context = argument;

	context->result =
		vmbus_bus_host_confirm_rescind(context->channel_id);
	return NULL;
}

static int wait_race_flag(int *flag)
{
	struct timespec deadline;
	int rc = 0;

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 2;
	pthread_mutex_lock(&race_lock);
	while (!*flag && !rc)
		rc = pthread_cond_timedwait(&race_condition, &race_lock,
					    &deadline);
	pthread_mutex_unlock(&race_lock);
	return rc ? -ETIMEDOUT : 0;
}

static int wait_atomic_value(atomic_int *value, int expected,
			     unsigned int limit_ms)
{
	for (unsigned int i = 0; i < limit_ms; i++) {
		if (atomic_load(value) == expected)
			return 0;
		uk_sched_thread_sleep(1000000ULL);
	}
	return -ETIMEDOUT;
}

static int wait_atomic_at_least(atomic_int *value, int expected,
				unsigned int limit_ms)
{
	for (unsigned int i = 0; i < limit_ms; i++) {
		if (atomic_load(value) >= expected)
			return 0;
		uk_sched_thread_sleep(1000000ULL);
	}
	return -ETIMEDOUT;
}

static int wait_connection_fail_calls(unsigned int expected,
				      unsigned int limit_ms)
{
	for (unsigned int i = 0; i < limit_ms; i++) {
		if (vmbus_bus_host_connection_fail_calls() == expected)
			return 0;
		uk_sched_thread_sleep(1000000ULL);
	}
	return -ETIMEDOUT;
}

static void remove_test_offer(struct vmbus_driver *driver,
			      struct vmbus_device *device)
{
	struct vmbus_offer_identity offer = {
		.instance_id = device->instance_id,
		.channel_id = device->channel_id,
		.generation = 1,
	};

	driver->remove_dev(device);
	if (driver->offer_removed)
		driver->offer_removed(&offer);
}

static int wait_deferred_action(int expected, unsigned int limit_ms)
{
	for (unsigned int i = 0; i < limit_ms; i++) {
		if (storvsc_host_deferred_action() == expected)
			return 0;
		uk_sched_thread_sleep(1000000ULL);
	}
	return -ETIMEDOUT;
}

static int wait_worker_present(int expected, unsigned int limit_ms)
{
	for (unsigned int i = 0; i < limit_ms; i++) {
		if (storvsc_host_worker_present() == expected)
			return 0;
		uk_sched_thread_sleep(1000000ULL);
	}
	return -ETIMEDOUT;
}

static int wait_primary_removal_quiesced(unsigned int limit_ms)
{
	for (unsigned int i = 0; i < limit_ms; i++) {
		if (storvsc_host_deferred_action() == TEST_DEFER_NONE &&
		    !storvsc_host_worker_present() &&
		    !storvsc_host_controller_online(0) &&
		    !storvsc_host_has_channel())
			return 0;
		uk_sched_thread_sleep(1000000ULL);
	}
	return -ETIMEDOUT;
}

static int wait_deferred_close_busy(unsigned int limit_ms)
{
	for (unsigned int i = 0; i < limit_ms; i++) {
		if (storvsc_host_deferred_close_busy())
			return 0;
		uk_sched_thread_sleep(1000000ULL);
	}
	return -ETIMEDOUT;
}

static int wait_deferred_vmbus(unsigned int limit_ms)
{
	for (unsigned int i = 0; i < limit_ms; i++) {
		if (storvsc_host_deferred_wait_vmbus())
			return 0;
		uk_sched_thread_sleep(1000000ULL);
	}
	return -ETIMEDOUT;
}

static void reset_race_state(int pause_kind, struct uk_blkreq *sender)
{
	pthread_mutex_lock(&race_lock);
	race_pause_kind = pause_kind;
	race_hook_entered = 0;
	race_release_sender = 0;
	race_recovery_begin = 0;
	race_reset_ack = 0;
	race_release_reset = 0;
	race_transaction_id = 0;
	race_pfn_source = NULL;
	race_pfns_written = 0;
	race_first_pfn = 0;
	race_sender_request = sender;
	pthread_mutex_unlock(&race_lock);
	atomic_store(&race_post_completion_publication, 0);
}

static int run_reset_send_race(struct uk_blkdev *device, uint8_t *buffer,
			       int pause_kind, __sector sector,
			       int error_base)
{
	struct uk_blkreq victim;
	struct uk_blkreq sender;
	struct uk_blkreq retry;
	struct submit_thread_context submit_context = {
		.device = device,
	};
	struct reset_thread_context reset_context = { 0 };
	atomic_int victim_callbacks;
	atomic_int sender_callbacks;
	atomic_int retry_callbacks;
	pthread_t submit_tid;
	pthread_t reset_tid;
	int submit_created = 0;
	int submit_joined = 0;
	int reset_created = 0;
	int error = 0;
	int retry_result;

	atomic_init(&victim_callbacks, 0);
	atomic_init(&sender_callbacks, 0);
	atomic_init(&retry_callbacks, 0);
	atomic_init(&submit_context.done, 0);
	atomic_init(&reset_context.done, 0);
	initialize_request(&victim, UK_BLKREQ_READ, sector, 1, buffer,
			   request_done, &victim_callbacks);
	initialize_request(&sender, UK_BLKREQ_READ, sector + 1, 8,
			   buffer + 512, request_done, &sender_callbacks);
	initialize_request(&retry, UK_BLKREQ_READ, sector + 9, 1,
			   buffer + 8192, request_done, &retry_callbacks);
	submit_context.request = &sender;
	hold_io = 1;
	pending_count = 0;
	if (!(device->submit_one(device, device->_queue[0], &victim) &
	      UK_BLKDEV_STATUS_SUCCESS))
		return error_base;
	reset_race_state(pause_kind, &sender);
	if (pthread_create(&submit_tid, NULL, submit_thread,
			   &submit_context)) {
		error = error_base + 1;
		goto out;
	}
	submit_created = 1;
	if (wait_race_flag(&race_hook_entered)) {
		error = error_base + 2;
		goto out;
	}
	if (pthread_create(&reset_tid, NULL, reset_thread, &reset_context)) {
		error = error_base + 3;
		goto out;
	}
	reset_created = 1;
	if (wait_race_flag(&race_recovery_begin)) {
		error = error_base + 4;
		goto out;
	}
	if (atomic_load(&reset_context.done) ||
	    atomic_load(&submit_context.done) ||
	    atomic_load(&sender.state.counter) == UK_BLKREQ_FINISHED) {
		error = error_base + 5;
		goto out;
	}
	pthread_mutex_lock(&race_lock);
	if (!race_pfn_source ||
	    (race_pfns_written &&
	     (!race_first_pfn || race_pfn_source[0] != race_first_pfn)))
		error = error_base + 6;
	pthread_mutex_unlock(&race_lock);
	if (error)
		goto out;
	retry_result = device->submit_one(device, device->_queue[0],
					  &retry);
	if (retry_result != -EAGAIN ||
	    atomic_load(&race_post_completion_publication)) {
		error = error_base + 7;
		goto out;
	}
	pthread_mutex_lock(&race_lock);
	race_release_sender = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	pthread_join(submit_tid, NULL);
	submit_joined = 1;
	if (wait_race_flag(&race_reset_ack)) {
		error = error_base + 8;
		goto out;
	}
	if (atomic_load(&reset_context.done) ||
	    !(submit_context.result & UK_BLKDEV_STATUS_SUCCESS) ||
	    atomic_load(&sender.state.counter) == UK_BLKREQ_FINISHED ||
	    atomic_load(&race_post_completion_publication) ||
	    device->submit_one(device, device->_queue[0], &retry) !=
		    -EAGAIN) {
		error = error_base + 9;
		goto out;
	}
	pthread_mutex_lock(&race_lock);
	if (race_pfns_written &&
	    (!race_first_pfn || race_pfn_source[0] != race_first_pfn))
		error = error_base + 10;
	pthread_mutex_unlock(&race_lock);

out:
	pthread_mutex_lock(&race_lock);
	race_release_sender = 1;
	race_release_reset = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	if (submit_created && !submit_joined)
		pthread_join(submit_tid, NULL);
	if (reset_created)
		pthread_join(reset_tid, NULL);
	if (!error &&
	    (!(submit_context.result & UK_BLKDEV_STATUS_SUCCESS) ||
	     reset_context.result ||
	     victim.result != -ETIMEDOUT ||
	     sender.result != -ETIMEDOUT ||
	     atomic_load(&victim_callbacks) != 1 ||
	     atomic_load(&sender_callbacks) != 1 ||
	     atomic_load(&race_post_completion_publication)))
		error = error_base + 11;
	if (!error) {
		complete_pending(1);
		fire_channel();
		if (atomic_load(&victim_callbacks) != 1 ||
		    atomic_load(&sender_callbacks) != 1)
			error = error_base + 12;
	}
	pending_count = 0;
	hold_io = 0;
	pthread_mutex_lock(&race_lock);
	race_pause_kind = RACE_PAUSE_NONE;
	race_sender_request = NULL;
	pthread_mutex_unlock(&race_lock);
	if (!error) {
		if (submit_and_fire(device, &retry) || retry.result ||
		    atomic_load(&retry_callbacks) != 1)
			error = error_base + 13;
	}
	return error;
}

static int run_terminal_reset_quiesce(struct uk_blkdev *device,
				      uint8_t *buffer, int irqs_disabled,
				      int error_base)
{
	struct uk_blkreq victim;
	struct uk_blkreq sender;
	struct uk_blkreq retry;
	struct submit_thread_context submit_context = {
		.device = device,
	};
	struct reset_thread_context reset_context = { 0 };
	atomic_int victim_callbacks;
	atomic_int sender_callbacks;
	pthread_t submit_tid;
	pthread_t reset_tid;
	int submit_created = 0;
	int reset_created = 0;
	int error = 0;
	int mask_calls;
	int unmask_calls;

	atomic_init(&victim_callbacks, 0);
	atomic_init(&sender_callbacks, 0);
	atomic_init(&submit_context.done, 0);
	atomic_init(&reset_context.done, 0);
	initialize_request(&victim, UK_BLKREQ_READ, 60, 1, buffer,
			   request_done, &victim_callbacks);
	initialize_request(&sender, UK_BLKREQ_READ, 61, 8, buffer + 512,
			   request_done, &sender_callbacks);
	initialize_request(&retry, UK_BLKREQ_READ, 70, 1, buffer + 8192,
			   NULL, NULL);
	submit_context.request = &sender;
	storvsc_host_set_send_wait_limit(2);
	atomic_store(&host_irqs_disabled, irqs_disabled);
	hold_io = 1;
	pending_count = 0;
	if (!(device->submit_one(device, device->_queue[0], &victim) &
	      UK_BLKDEV_STATUS_SUCCESS))
		return error_base;
	reset_race_state(RACE_PAUSE_BEFORE_PFNS, &sender);
	if (pthread_create(&submit_tid, NULL, submit_thread,
			   &submit_context)) {
		error = error_base + 1;
		goto out;
	}
	submit_created = 1;
	if (wait_race_flag(&race_hook_entered)) {
		error = error_base + 2;
		goto out;
	}
	if (pthread_create(&reset_tid, NULL, reset_thread, &reset_context)) {
		error = error_base + 3;
		goto out;
	}
	reset_created = 1;
	if (wait_race_flag(&race_recovery_begin) ||
	    wait_atomic_value(&reset_context.done, 1, 1000)) {
		error = error_base + 4;
		goto out;
	}
	atomic_store(&host_irqs_disabled, 0);
	if (reset_context.result != -EINPROGRESS ||
	    storvsc_host_online() ||
	    storvsc_host_deferred_action() != TEST_DEFER_RESET ||
	    !storvsc_host_worker_present() ||
	    storvsc_host_has_channel() ||
	    atomic_load(&victim_callbacks) ||
	    atomic_load(&sender_callbacks) ||
	    atomic_load(&victim.state.counter) == UK_BLKREQ_FINISHED ||
	    atomic_load(&sender.state.counter) == UK_BLKREQ_FINISHED ||
	    device->submit_one(device, device->_queue[0], &retry) !=
		    -ENODEV ||
	    device->submit_one(device, device->_queue[0], &retry) !=
		    -ENODEV) {
		error = error_base + 5;
		goto out;
	}
	mask_calls = atomic_load(&channel_mask_calls);
	unmask_calls = atomic_load(&channel_unmask_calls);
	if (device->dev_ops->queue_intr_enable(device, device->_queue[0]) !=
		    -ENODEV ||
	    device->dev_ops->queue_intr_disable(device, device->_queue[0]) !=
		    -ENODEV ||
	    atomic_load(&channel_mask_calls) != mask_calls ||
	    atomic_load(&channel_unmask_calls) != unmask_calls) {
		error = error_base + 6;
		goto out;
	}
	pthread_mutex_lock(&race_lock);
	if (!race_pfn_source || race_pfns_written)
		error = error_base + 7;
	pthread_mutex_unlock(&race_lock);

out:
	atomic_store(&host_irqs_disabled, 0);
	pthread_mutex_lock(&race_lock);
	race_release_sender = 1;
	race_release_reset = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	if (submit_created)
		pthread_join(submit_tid, NULL);
	if (reset_created)
		pthread_join(reset_tid, NULL);
	if (!error && wait_deferred_action(TEST_DEFER_NONE, 1000))
		error = error_base + 8;
	if (!error && wait_worker_present(0, 1000))
		error = error_base + 9;
	if (!error &&
	    (!(submit_context.result & UK_BLKDEV_STATUS_SUCCESS) ||
	     victim.result != -ETIMEDOUT ||
	     sender.result != -ETIMEDOUT ||
	     atomic_load(&victim_callbacks) != 1 ||
	     atomic_load(&sender_callbacks) != 1 ||
	     atomic_load(&race_post_completion_publication)))
		error = error_base + 10;
	if (!error) {
		complete_pending(1);
		fire_channel();
		if (atomic_load(&victim_callbacks) != 1 ||
		    atomic_load(&sender_callbacks) != 1)
			error = error_base + 11;
	}
	drop_packets();
	pending_count = 0;
	hold_io = 0;
	storvsc_host_set_send_wait_limit(2000);
	pthread_mutex_lock(&race_lock);
	race_pause_kind = RACE_PAUSE_NONE;
	race_sender_request = NULL;
	pthread_mutex_unlock(&race_lock);
	return error;
}

static int run_terminal_remove_quiesce(
	struct vmbus_driver *driver, struct vmbus_device *vmbus_device,
	struct uk_blkdev *device, uint8_t *buffer, int race_fatal,
	int error_base)
{
	struct uk_blkreq victim;
	struct uk_blkreq sender;
	struct uk_blkreq retry;
	struct submit_thread_context submit_context = {
		.device = device,
	};
	atomic_int victim_callbacks;
	atomic_int sender_callbacks;
	pthread_t submit_tid;
	int submit_created = 0;
	int error = 0;
	int mask_calls;
	int unmask_calls;

	atomic_init(&victim_callbacks, 0);
	atomic_init(&sender_callbacks, 0);
	atomic_init(&submit_context.done, 0);
	initialize_request(&victim, UK_BLKREQ_READ, 80, 1, buffer,
			   request_done, &victim_callbacks);
	initialize_request(&sender, UK_BLKREQ_READ, 81, 8, buffer + 512,
			   request_done, &sender_callbacks);
	initialize_request(&retry, UK_BLKREQ_READ, 90, 1, buffer + 8192,
			   NULL, NULL);
	submit_context.request = &sender;
	storvsc_host_set_send_wait_limit(2);
	hold_io = 1;
	pending_count = 0;
	if (!(device->submit_one(device, device->_queue[0], &victim) &
	      UK_BLKDEV_STATUS_SUCCESS))
		return error_base;
	reset_race_state(RACE_PAUSE_DURING_VMBUS_COPY, &sender);
	if (pthread_create(&submit_tid, NULL, submit_thread,
			   &submit_context)) {
		error = error_base + 1;
		goto out;
	}
	submit_created = 1;
	if (wait_race_flag(&race_hook_entered)) {
		error = error_base + 2;
		goto out;
	}
	if (race_fatal) {
		storvsc_host_force_timeout();
		if (wait_deferred_action(TEST_DEFER_FATAL, 1000)) {
			error = error_base + 3;
			goto out;
		}
		enqueue_completion(last_io_id, 64, 0, 1, 0,
				   last_io_length);
		fire_channel();
	}
	remove_test_offer(driver, vmbus_device);
	if (storvsc_host_online() ||
	    storvsc_host_deferred_action() != TEST_DEFER_REMOVE ||
	    !storvsc_host_worker_present() ||
	    storvsc_host_has_channel() ||
	    atomic_load(&victim_callbacks) ||
	    atomic_load(&sender_callbacks) ||
	    atomic_load(&victim.state.counter) == UK_BLKREQ_FINISHED ||
	    atomic_load(&sender.state.counter) == UK_BLKREQ_FINISHED ||
	    device->submit_one(device, device->_queue[0], &retry) !=
		    -ENODEV) {
		error = error_base + 4;
		goto out;
	}
	mask_calls = atomic_load(&channel_mask_calls);
	unmask_calls = atomic_load(&channel_unmask_calls);
	if (device->dev_ops->queue_intr_enable(device, device->_queue[0]) !=
		    -ENODEV ||
	    device->dev_ops->queue_intr_disable(device, device->_queue[0]) !=
		    -ENODEV ||
	    atomic_load(&channel_mask_calls) != mask_calls ||
	    atomic_load(&channel_unmask_calls) != unmask_calls) {
		error = error_base + 5;
		goto out;
	}
	pthread_mutex_lock(&race_lock);
	if (!race_pfn_source || !race_pfns_written ||
	    race_pfn_source[0] != race_first_pfn)
		error = error_base + 6;
	pthread_mutex_unlock(&race_lock);
	if (error)
		goto out;
	enqueue_completion(last_io_id, 64, 0, 1, 0, last_io_length);
	fire_channel();

out:
	pthread_mutex_lock(&race_lock);
	race_release_sender = 1;
	race_release_reset = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	if (submit_created)
		pthread_join(submit_tid, NULL);
	if (!error && wait_deferred_action(TEST_DEFER_NONE, 1000))
		error = error_base + 7;
	if (!error && wait_worker_present(0, 1000))
		error = error_base + 8;
	if (!error &&
	    (!(submit_context.result & UK_BLKDEV_STATUS_SUCCESS) ||
	     victim.result != -ENODEV ||
	     sender.result != -ENODEV ||
	     atomic_load(&victim_callbacks) != 1 ||
	     atomic_load(&sender_callbacks) != 1 ||
	     atomic_load(&race_post_completion_publication)))
		error = error_base + 9;
	if (!error) {
		complete_pending(1);
		fire_channel();
		if (atomic_load(&victim_callbacks) != 1 ||
		    atomic_load(&sender_callbacks) != 1)
			error = error_base + 10;
	}
	drop_packets();
	pending_count = 0;
	hold_io = 0;
	storvsc_host_set_send_wait_limit(2000);
	pthread_mutex_lock(&race_lock);
	race_pause_kind = RACE_PAUSE_NONE;
	race_sender_request = NULL;
	pthread_mutex_unlock(&race_lock);
	return error;
}

static void configure_close_failure(int error, int count)
{
	atomic_store(&close_failure_error, error);
	atomic_store(&close_failures_remaining, count);
}

static int run_close_failure_case(
	struct vmbus_driver *driver, struct vmbus_device *vmbus_device,
	struct uk_blkdev *device, uint8_t *buffer, int close_error,
	int close_failure_count, int host_remove_packet, int transient,
	int error_base)
{
	struct uk_blkreq request;
	struct uk_blkreq retry;
	struct vmbus_device retry_device;
	atomic_int callbacks;
	uint8_t remove_packet[4] = { 2, 0, 0, 0 };
	int attempts_before = atomic_load(&close_attempts);
	unsigned int failures_before =
		vmbus_bus_host_connection_fail_calls();
	int retries_before = atomic_load(&bind_retry_calls);
	int ready_before = atomic_load(&bind_ready_calls);
	uint64_t retry_start;
	int attempts;

	atomic_init(&callbacks, 0);
	initialize_request(&request, UK_BLKREQ_READ, 100, 1, buffer,
			   request_done, &callbacks);
	initialize_request(&retry, UK_BLKREQ_READ, 101, 1, buffer + 512,
			   NULL, NULL);
	hold_io = 1;
	pending_count = 0;
	configure_close_failure(close_error, close_failure_count);
	if (!(device->submit_one(device, device->_queue[0], &request) &
	      UK_BLKDEV_STATUS_SUCCESS))
		return error_base;
	if (host_remove_packet) {
		enqueue_packet(0, remove_packet, sizeof(remove_packet));
	} else {
		storvsc_host_force_timeout();
	}
	if (transient) {
		if (wait_deferred_action(TEST_DEFER_NONE, 1000) ||
		    wait_worker_present(0, 1000) ||
		    request.result != -ETIMEDOUT ||
		    atomic_load(&callbacks) != 1 ||
		    vmbus_bus_host_connection_fail_calls() != failures_before)
			return error_base + 1;
		attempts = atomic_load(&close_attempts) - attempts_before;
		if (attempts != 2)
			return error_base + 2;
	} else if (close_error == -EBUSY) {
		if (wait_deferred_close_busy(1000) ||
		    storvsc_host_deferred_wait_vmbus() ||
		    storvsc_host_deferred_action() != TEST_DEFER_FATAL ||
		    !storvsc_host_worker_present() ||
		    storvsc_host_online() || storvsc_host_has_channel() ||
		    atomic_load(&callbacks) ||
		    vmbus_bus_host_connection_fail_calls() != failures_before)
			return error_base + 3;
		attempts = atomic_load(&close_attempts) - attempts_before;
		if (attempts != TEST_CLOSE_RETRY_LIMIT)
			return error_base + 4;
		uk_sched_thread_sleep(50000000ULL);
		if (atomic_load(&close_attempts) - attempts_before != attempts)
			return error_base + 5;
		configure_close_failure(0, 0);
		if (wait_deferred_action(TEST_DEFER_NONE, 1000) ||
		    wait_worker_present(0, 1000) ||
		    request.result != -ETIMEDOUT ||
		    atomic_load(&callbacks) != 1 ||
		    vmbus_bus_host_connection_fail_calls() != failures_before)
			return error_base + 6;
	} else {
		if (wait_connection_fail_calls(failures_before + 1, 1000) ||
		    !storvsc_host_deferred_wait_vmbus() ||
		    storvsc_host_deferred_action() != TEST_DEFER_FATAL ||
		    !storvsc_host_worker_present() ||
		    storvsc_host_online() || storvsc_host_has_channel() ||
		    atomic_load(&callbacks) ||
		    atomic_load(&request.state.counter) ==
			    UK_BLKREQ_FINISHED ||
		    device->submit_one(device, device->_queue[0], &retry) !=
			    -ENODEV)
			return error_base + 3;
		retry_device = *vmbus_device;
		retry_device.channel = NULL;
		retry_start = ukplat_monotonic_clock();
		if (driver->add_dev(&retry_device) != -ENOSPC ||
		    ukplat_monotonic_clock() - retry_start > 50000000ULL ||
		    atomic_load(&bind_retry_calls) != retries_before + 1)
			return error_base + 4;
		attempts = atomic_load(&close_attempts) - attempts_before;
		if (attempts != 1)
			return error_base + 5;
		uk_sched_thread_sleep(20000000ULL);
		if (atomic_load(&close_attempts) - attempts_before != attempts)
			return error_base + 6;
		configure_close_failure(0, 0);
		remove_test_offer(driver, vmbus_device);
		if (storvsc_host_deferred_action() != TEST_DEFER_REMOVE ||
		    !storvsc_host_worker_present() ||
		    atomic_load(&callbacks))
			return error_base + 7;
		if (vmbus_bus_host_connection_quiesce())
			return error_base + 8;
		if (wait_deferred_action(TEST_DEFER_NONE, 1000) ||
		    wait_worker_present(0, 1000) ||
		    request.result != -ENODEV ||
		    atomic_load(&callbacks) != 1 ||
		    atomic_load(&bind_ready_calls) != ready_before + 1)
			return error_base + 8;
	}
	drop_packets();
	pending_count = 0;
	hold_io = 0;
	configure_close_failure(0, 0);
	return 0;
}

static int run_close_remove_window(
	struct vmbus_driver *driver, struct vmbus_device *vmbus_device,
	struct uk_blkdev *device, uint8_t *buffer, int error_base)
{
	struct uk_blkreq request;
	atomic_int callbacks;
	unsigned int failures_before =
		vmbus_bus_host_connection_fail_calls();

	atomic_init(&callbacks, 0);
	initialize_request(&request, UK_BLKREQ_READ, 110, 1, buffer,
			   request_done, &callbacks);
	hold_io = 1;
	pending_count = 0;
	configure_close_failure(-EIO, 1);
	pthread_mutex_lock(&race_lock);
	close_pause_enabled = 1;
	close_pause_entered = 0;
	close_pause_release = 0;
	pthread_mutex_unlock(&race_lock);
	if (!(device->submit_one(device, device->_queue[0], &request) &
	      UK_BLKDEV_STATUS_SUCCESS))
		return error_base;
	storvsc_host_force_timeout();
	if (wait_race_flag(&close_pause_entered))
		return error_base + 1;
	remove_test_offer(driver, vmbus_device);
	if (storvsc_host_deferred_action() != TEST_DEFER_REMOVE ||
	    storvsc_host_has_channel() || atomic_load(&callbacks))
		return error_base + 2;
	pthread_mutex_lock(&race_lock);
	close_pause_release = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	if (wait_connection_fail_calls(failures_before + 1, 1000) ||
	    !storvsc_host_deferred_wait_vmbus() ||
	    storvsc_host_deferred_action() != TEST_DEFER_REMOVE ||
	    atomic_load(&callbacks) ||
	    atomic_load(&request.state.counter) == UK_BLKREQ_FINISHED)
		return error_base + 3;
	if (vmbus_bus_host_connection_quiesce())
		return error_base + 4;
	if (wait_deferred_action(TEST_DEFER_NONE, 1000) ||
	    wait_worker_present(0, 1000) ||
	    request.result != -ENODEV || atomic_load(&callbacks) != 1)
		return error_base + 4;
	pthread_mutex_lock(&race_lock);
	close_pause_enabled = 0;
	close_pause_release = 1;
	pthread_mutex_unlock(&race_lock);
	configure_close_failure(0, 0);
	drop_packets();
	pending_count = 0;
	hold_io = 0;
	return 0;
}

static int run_busy_remove_upgrade(
	struct vmbus_driver *driver, struct vmbus_device *vmbus_device,
	struct uk_blkdev *device, uint8_t *buffer, int pause_close,
	int error_base)
{
	struct uk_blkreq request;
	atomic_int callbacks;
	unsigned int failures_before =
		vmbus_bus_host_connection_fail_calls();
	int attempts_before = atomic_load(&close_attempts);
	uint64_t request_pfn = 0;
	int error = 0;

	atomic_init(&callbacks, 0);
	initialize_request(&request, UK_BLKREQ_READ, 112, 1, buffer,
			   request_done, &callbacks);
	hold_io = 1;
	pending_count = 0;
	configure_close_failure(-EBUSY, 128);
	if (pause_close) {
		pthread_mutex_lock(&race_lock);
		close_pause_enabled = 1;
		close_pause_entered = 0;
		close_pause_release = 0;
		pthread_mutex_unlock(&race_lock);
	}
	if (!(device->submit_one(device, device->_queue[0], &request) &
	      UK_BLKDEV_STATUS_SUCCESS)) {
		error = error_base;
		goto out;
	}
	request_pfn = storvsc_host_request_pfn(&request, 0);
	if (!request_pfn) {
		error = error_base + 1;
		goto out;
	}
	storvsc_host_force_timeout();
	if (pause_close) {
		if (wait_race_flag(&close_pause_entered)) {
			error = error_base + 2;
			goto out;
		}
		remove_test_offer(driver, vmbus_device);
		if (storvsc_host_deferred_action() != TEST_DEFER_REMOVE ||
		    !storvsc_host_deferred_close_required() ||
		    storvsc_host_deferred_wait_vmbus() ||
		    atomic_load(&callbacks) ||
		    !storvsc_host_request_bound(&request)) {
			error = error_base + 3;
			goto out;
		}
		pthread_mutex_lock(&race_lock);
		close_pause_release = 1;
		pthread_cond_broadcast(&race_condition);
		pthread_mutex_unlock(&race_lock);
	} else {
		if (wait_deferred_close_busy(1000) ||
		    !storvsc_host_deferred_close_required() ||
		    storvsc_host_deferred_close_attempts() !=
			    TEST_CLOSE_RETRY_LIMIT) {
			error = error_base + 2;
			goto out;
		}
		remove_test_offer(driver, vmbus_device);
	}
	if (wait_connection_fail_calls(failures_before + 1, 1000) ||
	    !storvsc_host_deferred_wait_vmbus() ||
	    storvsc_host_deferred_close_busy() ||
	    !storvsc_host_deferred_close_required() ||
	    storvsc_host_deferred_action() != TEST_DEFER_REMOVE ||
	    atomic_load(&callbacks) || !storvsc_host_request_bound(&request) ||
	    storvsc_host_request_pfn(&request, 0) != request_pfn ||
	    atomic_load(&request.state.counter) == UK_BLKREQ_FINISHED) {
		error = error_base + 4;
		goto out;
	}
	{
		int attempts = atomic_load(&close_attempts);

		uk_sched_thread_sleep(150000000ULL);
		if (atomic_load(&close_attempts) != attempts ||
		    atomic_load(&callbacks) ||
		    !storvsc_host_request_bound(&request) ||
		    storvsc_host_request_pfn(&request, 0) != request_pfn ||
		    vmbus_bus_host_connection_fail_calls() !=
			    failures_before + 1) {
			error = error_base + 5;
			goto out;
		}
	}
	if (vmbus_bus_host_connection_quiesce()) {
		error = error_base + 6;
		goto out;
	}
	if (wait_deferred_action(TEST_DEFER_NONE, 1000) ||
	    wait_worker_present(0, 1000) || request.result != -ENODEV ||
	    atomic_load(&callbacks) != 1 ||
	    storvsc_host_request_bound(&request)) {
		error = error_base + 7;
		goto out;
	}
	if (atomic_load(&close_attempts) - attempts_before !=
	    TEST_CLOSE_RETRY_LIMIT)
		error = error_base + 8;

out:
	pthread_mutex_lock(&race_lock);
	close_pause_release = 1;
	close_pause_enabled = 0;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	configure_close_failure(0, 0);
	drop_packets();
	pending_count = 0;
	hold_io = 0;
	return error;
}

static int run_busy_retry_bound(
	struct vmbus_device *vmbus_device, struct uk_blkdev *device,
	uint8_t *buffer, int error_base)
{
	struct uk_blkreq request;
	atomic_int callbacks;
	unsigned int failures_before =
		vmbus_bus_host_connection_fail_calls();
	int attempts_before = atomic_load(&close_attempts);
	uint64_t request_pfn = 0;
	int error = 0;

	(void)vmbus_device;
	atomic_init(&callbacks, 0);
	initialize_request(&request, UK_BLKREQ_READ, 113, 1, buffer,
			   request_done, &callbacks);
	hold_io = 1;
	pending_count = 0;
	storvsc_host_set_busy_retry(TEST_CLOSE_RETRY_LIMIT,
				    2000000000ULL);
	configure_close_failure(-EBUSY, 128);
	if (!(device->submit_one(device, device->_queue[0], &request) &
	      UK_BLKDEV_STATUS_SUCCESS)) {
		error = error_base;
		goto out;
	}
	request_pfn = storvsc_host_request_pfn(&request, 0);
	storvsc_host_force_timeout();
	if (wait_connection_fail_calls(failures_before + 1, 1000) ||
	    !storvsc_host_deferred_wait_vmbus() ||
	    !storvsc_host_deferred_close_required() ||
	    storvsc_host_deferred_action() != TEST_DEFER_FATAL ||
	    atomic_load(&callbacks) || !storvsc_host_request_bound(&request) ||
	    !request_pfn ||
	    storvsc_host_request_pfn(&request, 0) != request_pfn) {
		error = error_base + 1;
		goto out;
	}
	if (atomic_load(&close_attempts) - attempts_before !=
	    TEST_CLOSE_RETRY_LIMIT) {
		error = error_base + 2;
		goto out;
	}
	uk_sched_thread_sleep(150000000ULL);
	if (atomic_load(&close_attempts) - attempts_before !=
	    TEST_CLOSE_RETRY_LIMIT || atomic_load(&callbacks) ||
	    !storvsc_host_request_bound(&request) ||
	    storvsc_host_request_pfn(&request, 0) != request_pfn ||
	    vmbus_bus_host_connection_fail_calls() != failures_before + 1) {
		error = error_base + 3;
		goto out;
	}
	if (vmbus_bus_host_connection_quiesce()) {
		error = error_base + 4;
		goto out;
	}
	if (wait_deferred_action(TEST_DEFER_NONE, 1000) ||
	    wait_worker_present(0, 1000) || request.result != -ETIMEDOUT ||
	    atomic_load(&callbacks) != 1 ||
	    storvsc_host_request_bound(&request))
		error = error_base + 5;

out:
	storvsc_host_set_busy_retry(32, 2000000000ULL);
	configure_close_failure(0, 0);
	drop_packets();
	pending_count = 0;
	hold_io = 0;
	return error;
}

static int run_deferred_epoch_refresh(struct uk_blkdev *device,
				      uint8_t *buffer, int error_base)
{
	struct uk_blkreq request;
	atomic_int callbacks;
	unsigned int failures_before =
		vmbus_bus_host_connection_fail_calls();
	uint64_t old_epoch;
	uint64_t new_epoch;
	uint64_t request_pfn;
	uint64_t sampled_epoch;
	int error = 0;

	atomic_init(&callbacks, 0);
	initialize_request(&request, UK_BLKREQ_READ, 115, 1, buffer,
			   request_done, &callbacks);
	hold_io = 1;
	pending_count = 0;
	configure_close_failure(-EIO, 1);
	if (!(device->submit_one(device, device->_queue[0], &request) &
	      UK_BLKDEV_STATUS_SUCCESS)) {
		error = error_base;
		goto out;
	}
	request_pfn = storvsc_host_request_pfn(&request, 0);
	storvsc_host_force_timeout();
	if (wait_connection_fail_calls(failures_before + 1, 1000) ||
	    wait_deferred_vmbus(1000)) {
		error = error_base + 1;
		goto out;
	}
	old_epoch = storvsc_host_deferred_vmbus_epoch();
	if (!old_epoch || old_epoch != vmbus_connection_quiesce_epoch() ||
	    !request_pfn || !storvsc_host_request_bound(&request)) {
		error = error_base + 2;
		goto out;
	}
	uk_sched_thread_sleep(30000000ULL);
	if (!storvsc_host_deferred_wait_vmbus() ||
	    atomic_load(&callbacks) ||
	    storvsc_host_request_pfn(&request, 0) != request_pfn) {
		error = error_base + 3;
		goto out;
	}

	pthread_mutex_lock(&race_lock);
	epoch_sample_enabled = 1;
	epoch_sample_entered = 0;
	epoch_sample_release = 0;
	epoch_sample_value = 0;
	pthread_mutex_unlock(&race_lock);
	if (wait_race_flag(&epoch_sample_entered)) {
		error = error_base + 4;
		goto out;
	}
	if (vmbus_bus_host_connection_quiesce()) {
		error = error_base + 5;
		goto out;
	}
	new_epoch = vmbus_connection_quiesce_epoch();
	if (new_epoch != old_epoch + 1 ||
	    storvsc_host_update_deferred_vmbus_epoch(old_epoch, new_epoch) ||
	    vmbus_bus_host_connection_begin()) {
		error = error_base + 6;
		goto out;
	}
	pthread_mutex_lock(&race_lock);
	epoch_sample_enabled = 0;
	epoch_sample_release = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	uk_sched_thread_sleep(50000000ULL);
	pthread_mutex_lock(&race_lock);
	sampled_epoch = epoch_sample_value;
	pthread_mutex_unlock(&race_lock);
	if (sampled_epoch != old_epoch ||
	    vmbus_connection_quiesce_epoch() != new_epoch ||
	    storvsc_host_deferred_vmbus_epoch() != new_epoch ||
	    !storvsc_host_deferred_wait_vmbus() ||
	    atomic_load(&callbacks) ||
	    !storvsc_host_request_bound(&request) ||
	    storvsc_host_request_pfn(&request, 0) != request_pfn) {
		error = error_base + 7;
		goto out;
	}
	if (vmbus_bus_host_connection_quiesce()) {
		error = error_base + 8;
		goto out;
	}
	if (wait_deferred_action(TEST_DEFER_NONE, 1000) ||
	    wait_worker_present(0, 1000) ||
	    request.result != -ETIMEDOUT ||
	    atomic_load(&callbacks) != 1 ||
	    storvsc_host_request_bound(&request)) {
		error = error_base + 9;
		goto out;
	}

out:
	pthread_mutex_lock(&race_lock);
	epoch_sample_enabled = 0;
	epoch_sample_release = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	configure_close_failure(0, 0);
	drop_packets();
	pending_count = 0;
	hold_io = 0;
	return error;
}

struct integrated_disconnect_context {
	struct vmbus_driver *driver;
	struct vmbus_device *vmbus_device;
	struct uk_blkreq *request;
	atomic_int *callbacks;
	pthread_mutex_t lock;
	pthread_cond_t condition;
	int remove_observed_safe;
	int unload_posted;
	int release_unload;
	int acknowledge;
	int result;
};

static void integrated_remove_hook(void *arg)
{
	struct integrated_disconnect_context *context = arg;

	remove_test_offer(context->driver, context->vmbus_device);
	context->remove_observed_safe =
		storvsc_host_deferred_action() == TEST_DEFER_REMOVE &&
		storvsc_host_deferred_wait_vmbus() &&
		storvsc_host_deferred_close_required() &&
		!storvsc_host_deferred_close_busy() &&
		!atomic_load(context->callbacks) &&
		storvsc_host_request_bound(context->request);
}

static void integrated_unload_post_hook(void *arg)
{
	struct integrated_disconnect_context *context = arg;

	pthread_mutex_lock(&context->lock);
	context->unload_posted = 1;
	pthread_cond_broadcast(&context->condition);
	while (!context->release_unload)
		pthread_cond_wait(&context->condition, &context->lock);
	pthread_mutex_unlock(&context->lock);
}

static void *integrated_disconnect_thread(void *arg)
{
	struct integrated_disconnect_context *context = arg;

	current_thread = NULL;
	context->result = vmbus_bus_host_disconnect_remove(
		integrated_remove_hook, context,
		integrated_unload_post_hook, context,
		context->acknowledge);
	return NULL;
}

static int wait_integrated_unload(
	struct integrated_disconnect_context *context, unsigned int limit_ms)
{
	for (unsigned int i = 0; i < limit_ms; i++) {
		int posted;

		pthread_mutex_lock(&context->lock);
		posted = context->unload_posted;
		pthread_mutex_unlock(&context->lock);
		if (posted)
			return 0;
		uk_sched_thread_sleep(1000000ULL);
	}
	return -ETIMEDOUT;
}

static int run_integrated_remove_unload(
	struct vmbus_driver *driver, struct vmbus_device *vmbus_device,
	struct uk_blkdev *device, uint8_t *buffer, int acknowledge,
	int error_base)
{
	struct integrated_disconnect_context context = {
		.driver = driver,
		.vmbus_device = vmbus_device,
		.acknowledge = acknowledge,
	};
	struct uk_blkreq request;
	atomic_int callbacks;
	pthread_t thread;
	uint64_t epoch;
	uint64_t request_pfn = 0;
	unsigned int failures_before;
	int thread_created = 0;
	int error = 0;

	if (vmbus_bus_host_prepare_disconnect())
		return error_base;
	epoch = vmbus_connection_quiesce_epoch();
	failures_before = vmbus_bus_host_connection_fail_calls();
	atomic_init(&callbacks, 0);
	initialize_request(&request, UK_BLKREQ_READ, 114, 1, buffer,
			   request_done, &callbacks);
	context.request = &request;
	context.callbacks = &callbacks;
	pthread_mutex_init(&context.lock, NULL);
	pthread_cond_init(&context.condition, NULL);
	hold_io = 1;
	pending_count = 0;
	configure_close_failure(-EBUSY, 128);
	if (!(device->submit_one(device, device->_queue[0], &request) &
	      UK_BLKDEV_STATUS_SUCCESS)) {
		error = error_base + 1;
		goto out;
	}
	request_pfn = storvsc_host_request_pfn(&request, 0);
	if (pthread_create(&thread, NULL, integrated_disconnect_thread,
			   &context)) {
		error = error_base + 2;
		goto out;
	}
	thread_created = 1;
	if (wait_integrated_unload(&context, 1000) ||
	    !context.remove_observed_safe ||
	    vmbus_connection_quiesce_epoch() != epoch ||
	    atomic_load(&callbacks) || !storvsc_host_request_bound(&request) ||
	    !request_pfn ||
	    storvsc_host_request_pfn(&request, 0) != request_pfn ||
	    vmbus_bus_host_connection_fail_calls() != failures_before + 1) {
		error = error_base + 3;
		goto out;
	}
	uk_sched_thread_sleep(50000000ULL);
	if (vmbus_connection_quiesce_epoch() != epoch ||
	    atomic_load(&callbacks) || !storvsc_host_request_bound(&request) ||
	    storvsc_host_request_pfn(&request, 0) != request_pfn ||
	    vmbus_bus_host_connection_fail_calls() != failures_before + 1) {
		error = error_base + 4;
		goto out;
	}
	pthread_mutex_lock(&context.lock);
	context.release_unload = 1;
	pthread_cond_broadcast(&context.condition);
	pthread_mutex_unlock(&context.lock);
	pthread_join(thread, NULL);
	thread_created = 0;
	if (acknowledge) {
		if (context.result ||
		    vmbus_connection_quiesce_epoch() != epoch + 1 ||
		    wait_deferred_action(TEST_DEFER_NONE, 1000) ||
		    wait_worker_present(0, 1000) ||
		    request.result != -ENODEV ||
		    atomic_load(&callbacks) != 1 ||
		    storvsc_host_request_bound(&request)) {
			error = error_base + 5;
			goto out;
		}
	} else {
		if (context.result != -ETIMEDOUT ||
		    vmbus_connection_quiesce_epoch() != epoch ||
		    !storvsc_host_deferred_wait_vmbus() ||
		    !storvsc_host_deferred_close_required() ||
		    atomic_load(&callbacks) ||
		    !storvsc_host_request_bound(&request) ||
		    storvsc_host_request_pfn(&request, 0) != request_pfn ||
		    vmbus_bus_host_connection_fail_calls() !=
			    failures_before + 1) {
			error = error_base + 6;
			goto out;
		}
		uk_sched_thread_sleep(50000000ULL);
		if (atomic_load(&callbacks) ||
		    !storvsc_host_request_bound(&request) ||
		    vmbus_bus_host_connection_quiesce() ||
		    wait_deferred_action(TEST_DEFER_NONE, 1000) ||
		    wait_worker_present(0, 1000) ||
		    request.result != -ENODEV ||
		    atomic_load(&callbacks) != 1 ||
		    storvsc_host_request_bound(&request) ||
		    vmbus_bus_host_connection_fail_calls() !=
			    failures_before + 1)
			error = error_base + 7;
	}

out:
	pthread_mutex_lock(&context.lock);
	context.release_unload = 1;
	pthread_cond_broadcast(&context.condition);
	pthread_mutex_unlock(&context.lock);
	if (thread_created)
		pthread_join(thread, NULL);
	pthread_cond_destroy(&context.condition);
	pthread_mutex_destroy(&context.lock);
	configure_close_failure(0, 0);
	drop_packets();
	pending_count = 0;
	hold_io = 0;
	return error;
}

enum preserve_action {
	PRESERVE_RESET,
	PRESERVE_FATAL,
	PRESERVE_REMOVE,
};

static int run_completion_preservation(
	struct vmbus_driver *driver, struct vmbus_device *vmbus_device,
	struct uk_blkdev *device, uint8_t *buffer,
	enum preserve_action action, int host_error, int error_base)
{
	struct uk_blkreq completed;
	struct uk_blkreq inflight;
	atomic_int completed_callbacks;
	atomic_int inflight_callbacks;
	int terminal_error;
	int expected_completed = host_error ? -EIO : 0;
	int rc;

	atomic_init(&completed_callbacks, 0);
	atomic_init(&inflight_callbacks, 0);
	initialize_request(&completed, UK_BLKREQ_READ, 120, 1, buffer,
			   request_done, &completed_callbacks);
	initialize_request(&inflight, UK_BLKREQ_READ, 121, 1,
			   buffer + 512, request_done, &inflight_callbacks);
	hold_io = 1;
	pending_count = 0;
	if (!(device->submit_one(device, device->_queue[0], &completed) &
	      UK_BLKDEV_STATUS_SUCCESS) ||
	    !(device->submit_one(device, device->_queue[0], &inflight) &
	      UK_BLKDEV_STATUS_SUCCESS))
		return error_base;
	if (device->dev_ops->queue_intr_disable(device, device->_queue[0]))
		return error_base + 1;
	enqueue_completion(pending[0].id, 64, host_error ? 1 : 0, 1, 0,
			   pending[0].length);
	if (storvsc_host_receive() ||
	    atomic_load(&completed.state.counter) == UK_BLKREQ_FINISHED ||
	    atomic_load(&completed_callbacks))
		return error_base + 2;

	switch (action) {
	case PRESERVE_RESET:
		rc = storvsc_host_reset_timed_out_io();
		terminal_error = -ETIMEDOUT;
		if (rc || device->finish_reqs(device, device->_queue[0]))
			return error_base + 3;
		break;
	case PRESERVE_FATAL:
		storvsc_host_force_timeout();
		terminal_error = -ETIMEDOUT;
		if (wait_worker_present(0, 1000))
			return error_base + 4;
		break;
	case PRESERVE_REMOVE:
		remove_test_offer(driver, vmbus_device);
		terminal_error = -ENODEV;
		if (wait_worker_present(0, 1000))
			return error_base + 5;
		break;
	default:
		return error_base + 6;
	}
	if (completed.result != expected_completed ||
	    inflight.result != terminal_error ||
	    atomic_load(&completed_callbacks) != 1 ||
	    atomic_load(&inflight_callbacks) != 1)
		return error_base + 7;
	drop_packets();
	pending_count = 0;
	hold_io = 0;
	if (action == PRESERVE_RESET &&
	    device->dev_ops->queue_intr_enable(device, device->_queue[0]))
		return error_base + 8;
	return 0;
}

static int reoffer_device(struct vmbus_driver *driver,
			  struct vmbus_device *vmbus_device,
			  struct uk_blkdev *device)
{
	remove_test_offer(driver, vmbus_device);
	if (vmbus_device->channel)
		(void)vmbus_channel_close(vmbus_device->channel);
	if (!vmbus_bus_host_connection_live() &&
	    vmbus_bus_host_connection_begin())
		return -EIO;
	vmbus_device->present = 1;
	if (driver->add_dev(vmbus_device))
		return -EIO;
	if (!storvsc_host_online() || !storvsc_host_has_channel())
		return -ENODEV;
	return device->dev_ops->queue_intr_enable(device, device->_queue[0]);
}

static int run_topology_regression(struct vmbus_driver *driver,
				   struct vmbus_device *primary,
				   uint8_t *buffer, int *events)
{
	struct vmbus_device secondary = {
		.channel_id = 47,
		.connection_id = 147,
		.instance_id = {
			.bytes = { 2, 1, 2, 3, 4, 5, 6, 7,
				   8, 9, 10, 11, 12, 13, 14, 15 },
		},
		.present = 1,
	};
	struct vmbus_device excess = {
		.channel_id = 57,
		.connection_id = 157,
		.instance_id = {
			.bytes = { 3, 1, 2, 3, 4, 5, 6, 7,
				   8, 9, 10, 11, 12, 13, 14, 15 },
		},
		.present = 1,
	};
	struct vmbus_device failed_offer = {
		.channel_id = 67,
		.connection_id = 167,
		.instance_id = {
			.bytes = { 9, 1, 2, 3, 4, 5, 6, 7,
				   8, 9, 10, 11, 12, 13, 14, 15 },
		},
		.present = 1,
	};
	struct uk_storvsc_mapping mappings[8];
	struct uk_storvsc_mapping found;
	struct uk_storvsc_inventory_snapshot inventory;
	struct uk_storvsc_target_snapshot guarded_targets[3];
	struct uk_storvsc_session guarded_sessions[3];
	struct uk_blkdev *devices[4];
	struct uk_blkreq requests[4];
	struct uk_blkreq check;
	atomic_int callbacks;
	atomic_int teardown_callbacks;
	atomic_int rebind_callbacks;
	struct fire_channel_context retained_fire;
	pthread_t retained_fire_thread;
	struct vmbus_channel *primary_channel;
	uint16_t stable_ids[4];
	const uint8_t expected_luns[] = { 0, 2, 0, 3 };
	const uint16_t expected_controllers[] = { 0, 0, 1, 1 };
	const uint64_t expected_sectors[] = { 1000, 1200, 2000, 2300 };
	const uint8_t expected_seeds[] = { 0x20, 0x22, 0x30, 0x33 };
	int lun_events[4] = { 0 };
	int primary_events;
	unsigned int count;
	int rc;

	topology_fixture = 1;
	report_luns_mode = REPORT_LUNS_NORMAL;
	vpd_mode = VPD_NORMAL;
	malformed_handshake = 0;
	reject_versions = 0;
	reject_mode_sense6 = 0;
	reject_mode_sense10 = 0;
	read_only_media = 0;
	use_capacity16 = 0;
	hold_io = 0;
	pending_count = 0;
	drop_packets();

	vpd_mode = VPD_MALFORMED;
	rc = driver->add_dev(&failed_offer);
	if (rc != -EPROTO || failed_offer.channel ||
	    uk_storvsc_mapping_count())
		return 29;
	vpd_mode = VPD_NORMAL;
	rc = driver->add_dev(&secondary);
	if (rc || !storvsc_host_controller_online(1) ||
	    uk_storvsc_mapping_count() != 2)
		return 30;
	if (uk_storvsc_inventory_get(&inventory) != -EAGAIN)
		return 30;
	remove_test_offer(driver, &failed_offer);
	if (uk_storvsc_inventory_get(&inventory) ||
	    inventory.count != 2)
		return 30;
	primary->present = 1;
	rc = driver->add_dev(primary);
	if (rc || !storvsc_host_controller_online(0) ||
	    uk_storvsc_mapping_count() != 4)
		return 31;

	count = uk_storvsc_mapping_count();
	if (count != 4)
		return 32;
	for (unsigned int i = 0; i < count; i++) {
		if (uk_storvsc_mapping_get(i, &mappings[i]) ||
		    mappings[i].controller_index != expected_controllers[i] ||
		    mappings[i].lun != expected_luns[i] ||
		    mappings[i].path_id || mappings[i].target_id ||
		    mappings[i].sectors != expected_sectors[i] ||
		    mappings[i].sector_size != 512 ||
		    mappings[i].read_only != (i == 3) ||
		    mappings[i].vpd_length != 8 ||
		    mappings[i].vpd_code_set != 1 ||
		    mappings[i].vpd_designator_type != 3 ||
		    mappings[i].vpd_association ||
		    mappings[i].vpd_id[0] != 0x50 ||
		    mappings[i].vpd_id[7] != expected_luns[i])
			return 33;
		for (unsigned int j = 0; j < i; j++) {
			if (mappings[i].blkdev_id == mappings[j].blkdev_id)
				return 34;
		}
		stable_ids[i] = mappings[i].blkdev_id;
		if (uk_storvsc_mapping_find(mappings[i].blkdev_id, &found) ||
		    memcmp(&found, &mappings[i], sizeof(found)))
			return 35;
	}
	if (uk_storvsc_mapping_get(count, &found) != -ENOENT ||
	    uk_storvsc_mapping_find(UINT16_MAX, &found) != -ENOENT)
		return 36;
	if (mappings[0].channel_id != primary->channel_id ||
	    mappings[0].connection_id != primary->connection_id ||
	    mappings[2].channel_id != secondary.channel_id ||
	    mappings[2].connection_id != secondary.connection_id ||
	    memcmp(mappings[2].instance_id, secondary.instance_id.bytes,
		   sizeof(mappings[2].instance_id)))
		return 37;

	devices[0] = storvsc_host_blkdev_address(0, 0);
	devices[1] = storvsc_host_blkdev_address(0, 2);
	devices[2] = storvsc_host_blkdev_address(1, 0);
	devices[3] = storvsc_host_blkdev_address(1, 3);
	for (unsigned int i = 0; i < 4; i++) {
		if (!devices[i] ||
		    devices[i]->capabilities.sectors != expected_sectors[i] ||
		    devices[i]->capabilities.ssize != 512 ||
		    devices[i]->capabilities.mode !=
			    (i == 3 ? O_RDONLY : O_RDWR) ||
		    activate_device(devices[i],
				    i ? &lun_events[i] : events))
			return 38;
	}
	primary_events = *events;
	storvsc_host_set_guarded_io(1);
	if (uk_storvsc_target_get(0, &guarded_targets[0]) ||
	    uk_storvsc_target_get(2, &guarded_targets[1]) ||
	    uk_storvsc_target_get(3, &guarded_targets[2]) ||
	    uk_storvsc_session_begin_read(
		    &guarded_targets[0], &guarded_sessions[0]) ||
	    uk_storvsc_session_begin_read(
		    &guarded_targets[1], &guarded_sessions[1]) ||
	    uk_storvsc_session_begin_read(
		    &guarded_targets[2], &guarded_sessions[2]) ||
	    uk_storvsc_session_authorize_write(&guarded_sessions[0]) ||
	    uk_storvsc_session_authorize_write(&guarded_sessions[1]) !=
		    -EBUSY ||
	    uk_storvsc_session_authorize_write(&guarded_sessions[2]) !=
		    -EROFS ||
	    uk_storvsc_session_end(&guarded_sessions[0]) ||
	    uk_storvsc_session_end(&guarded_sessions[1]) ||
	    uk_storvsc_session_end(&guarded_sessions[2]))
		return 426;
	if (uk_storvsc_target_get(0, &guarded_targets[0]) ||
	    uk_storvsc_session_begin_read(
		    &guarded_targets[0], &guarded_sessions[0]))
		return 427;
	storvsc_host_set_guarded_io(1);
	if (uk_storvsc_session_validate(
		    &guarded_sessions[0], &guarded_targets[1]) != -ESTALE ||
	    uk_storvsc_target_get(0, &guarded_targets[0]) ||
	    uk_storvsc_session_begin_read(
		    &guarded_targets[0], &guarded_sessions[0]) ||
	    uk_storvsc_session_end(&guarded_sessions[0]))
		return 428;
	storvsc_host_set_guarded_io(0);

	atomic_init(&callbacks, 0);
	hold_io = 1;
	for (unsigned int i = 0; i < 4; i++) {
		initialize_request(&requests[i], UK_BLKREQ_READ,
				   expected_sectors[i] - 1, 1,
				   buffer + i * 512, request_done, &callbacks);
		if (!(devices[i]->submit_one(devices[i],
					     devices[i]->_queue[0],
					     &requests[i]) &
		      UK_BLKDEV_STATUS_SUCCESS))
			return 39;
	}
	if (pending_count != 4)
		return 40;
	enqueue_completion_on(secondary.channel, pending[0].id + 999,
			      64, 0, 1, 0, pending[0].length);
	fire_channel_on(secondary.channel);
	if (atomic_load(&callbacks) || *events != primary_events ||
	    lun_events[1] || lun_events[2] || lun_events[3])
		return 41;
	complete_pending_reverse(1);
	fire_channel_on(secondary.channel);
	if (atomic_load(&callbacks) != 2 ||
	    lun_events[2] != 1 || lun_events[3] != 1)
		return 42;
	fire_channel_on(primary->channel);
	if (atomic_load(&callbacks) != 4 ||
	    *events != primary_events + 1 || lun_events[1] != 1)
		return 43;
	for (unsigned int i = 0; i < 4; i++) {
		if (requests[i].result ||
		    buffer[i * 512] != expected_seeds[i])
			return 44;
	}
	fire_channel_on(secondary.channel);
	fire_channel_on(primary->channel);
	if (atomic_load(&callbacks) != 4)
		return 45;
	hold_io = 0;

	initialize_request(&check, UK_BLKREQ_READ, 1000, 1, buffer,
			   NULL, NULL);
	if (devices[0]->submit_one(devices[0], devices[0]->_queue[0],
				   &check) != -EINVAL)
		return 46;
	initialize_request(&check, UK_BLKREQ_WRITE, 0, 1, buffer,
			   request_done, &callbacks);
	if (!(devices[2]->submit_one(devices[2], devices[2]->_queue[0],
				     &check) &
	      UK_BLKDEV_STATUS_SUCCESS))
		return 47;
	fire_channel_on(secondary.channel);
	if (check.result || atomic_load(&callbacks) != 5)
		return 48;
	initialize_request(&check, UK_BLKREQ_WRITE, 0, 1, buffer,
			   NULL, NULL);
	if (devices[3]->submit_one(devices[3], devices[3]->_queue[0],
				   &check) != -EROFS)
		return 49;

	atomic_init(&teardown_callbacks, 0);
	hold_io = 1;
	initialize_request(&requests[0], UK_BLKREQ_READ, 12, 1, buffer,
			   request_done, &teardown_callbacks);
	initialize_request(&requests[1], UK_BLKREQ_READ, 13, 1,
			   buffer + 512, request_done, &teardown_callbacks);
	if (!(devices[0]->submit_one(devices[0], devices[0]->_queue[0],
				     &requests[0]) &
	      UK_BLKDEV_STATUS_SUCCESS) ||
	    !(devices[2]->submit_one(devices[2], devices[2]->_queue[0],
				     &requests[1]) &
	      UK_BLKDEV_STATUS_SUCCESS) ||
	    pending_count != 2)
		return 50;
	primary_channel = primary->channel;
	remove_test_offer(driver, primary);
	if (primary->channel)
		(void)vmbus_channel_close(primary->channel);
	if (requests[0].result != -ENODEV ||
	    atomic_load(&teardown_callbacks) != 1 ||
	    atomic_load(&requests[1].state.counter) == UK_BLKREQ_FINISHED)
		return 51;
	for (unsigned int i = 0; i < pending_count; i++) {
		enqueue_completion_on(pending[i].channel, pending[i].id, 64,
				      0, 1, 0, pending[i].length);
	}
	pending_count = 0;
	fire_channel_on(secondary.channel);
	if (requests[1].result ||
	    atomic_load(&teardown_callbacks) != 2)
		return 52;
	hold_io = 0;
	if (uk_storvsc_mapping_count() != 2 ||
	    storvsc_host_controller_online(0) ||
	    !storvsc_host_controller_online(1))
		return 53;
	initialize_request(&check, UK_BLKREQ_READ, 10, 1, buffer,
			   request_done, &callbacks);
	if (!(devices[2]->submit_one(devices[2], devices[2]->_queue[0],
				     &check) &
	      UK_BLKDEV_STATUS_SUCCESS))
		return 54;
	fire_channel_on(secondary.channel);
	if (check.result || atomic_load(&callbacks) != 6)
		return 55;

	primary->present = 1;
	sync_finish_device = devices[0];
	sync_finish_calls = 0;
	rc = driver->add_dev(primary);
	sync_finish_device = NULL;
	if (rc || !sync_finish_calls)
		return 56;
	fire_channel_on(primary_channel);
	if (atomic_load(&teardown_callbacks) != 2)
		return 57;
	for (unsigned int i = 0; i < 2; i++) {
		rc = uk_storvsc_mapping_get(i, &found);
		if (rc || found.blkdev_id != stable_ids[i]) {
			fprintf(stderr,
				"rebind mapping[%u] failed: rc=%d actual=%u expected=%u\n",
				i, rc,
				(unsigned int)(rc ? UINT16_MAX :
						     found.blkdev_id),
				(unsigned int)stable_ids[i]);
			return 58;
		}
	}
	pthread_mutex_lock(&race_lock);
	receive_gate_enabled = 1;
	receive_gate_controller = 0;
	receive_gate_before_entered = 0;
	receive_gate_release_drain = 0;
	receive_gate_notify_entered = 0;
	receive_gate_release_notify = 0;
	pthread_mutex_unlock(&race_lock);
	if (wait_race_flag(&receive_gate_before_entered)) {
		fprintf(stderr,
			"rebind worker did not reach the receive gate\n");
		pthread_mutex_lock(&race_lock);
		receive_gate_enabled = 0;
		receive_gate_release_drain = 1;
		receive_gate_release_notify = 1;
		pthread_cond_broadcast(&race_condition);
		pthread_mutex_unlock(&race_lock);
		return 58;
	}
	atomic_init(&rebind_callbacks, 0);
	hold_io = 1;
	pending_count = 0;
	for (unsigned int i = 0; i < 2; i++) {
		int status;

		initialize_request(&requests[i], UK_BLKREQ_READ, 30 + i, 1,
				   buffer + i * 512, request_done,
				   &rebind_callbacks);
		status = devices[i]->submit_one(devices[i],
					       devices[i]->_queue[0],
					       &requests[i]);
		if (!(status & UK_BLKDEV_STATUS_SUCCESS)) {
			fprintf(stderr,
				"rebind submit[%u] failed: status=%d pending=%u request_result=%d\n",
				i, status, pending_count, requests[i].result);
			pthread_mutex_lock(&race_lock);
			receive_gate_enabled = 0;
			receive_gate_release_drain = 1;
			receive_gate_release_notify = 1;
			pthread_cond_broadcast(&race_condition);
			pthread_mutex_unlock(&race_lock);
			return 58;
		}
	}
	complete_pending(0);
	pthread_mutex_lock(&race_lock);
	receive_gate_release_drain = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	if (wait_race_flag(&receive_gate_notify_entered)) {
		fprintf(stderr,
			"rebind worker did not retain notification ownership\n");
		pthread_mutex_lock(&race_lock);
		receive_gate_enabled = 0;
		receive_gate_release_notify = 1;
		pthread_cond_broadcast(&race_condition);
		pthread_mutex_unlock(&race_lock);
		return 58;
	}
	fire_channel_on(primary->channel);
	if (atomic_load(&rebind_callbacks) ||
	    !storvsc_host_request_bound(&requests[0]) ||
	    !storvsc_host_request_bound(&requests[1])) {
		fprintf(stderr,
			"rebind callback raced retained notification: callbacks=%d bound=%d,%d\n",
			atomic_load(&rebind_callbacks),
			storvsc_host_request_bound(&requests[0]),
			storvsc_host_request_bound(&requests[1]));
		pthread_mutex_lock(&race_lock);
		receive_gate_enabled = 0;
		receive_gate_release_notify = 1;
		pthread_cond_broadcast(&race_condition);
		pthread_mutex_unlock(&race_lock);
		return 58;
	}
	pthread_mutex_lock(&race_lock);
	receive_gate_release_notify = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	rc = wait_atomic_value(&rebind_callbacks, 2,
			       CONFIG_LIBSTORVSC_REQUEST_TIMEOUT_MS);
	pthread_mutex_lock(&race_lock);
	receive_gate_enabled = 0;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	if (rc || requests[0].result || requests[1].result ||
	    atomic_load(&requests[0].state.counter) != UK_BLKREQ_FINISHED ||
	    atomic_load(&requests[1].state.counter) != UK_BLKREQ_FINISHED ||
	    storvsc_host_request_bound(&requests[0]) ||
	    storvsc_host_request_bound(&requests[1])) {
		fprintf(stderr,
			"rebind completion failed: wait=%d callbacks=%d results=%d,%d states=%u,%u bound=%d,%d\n",
			rc, atomic_load(&rebind_callbacks),
			requests[0].result, requests[1].result,
			atomic_load(&requests[0].state.counter),
			atomic_load(&requests[1].state.counter),
			storvsc_host_request_bound(&requests[0]),
			storvsc_host_request_bound(&requests[1]));
		return 58;
	}
	hold_io = 0;
	rc = run_mixed_lun_completion(devices[0], devices[1],
				      primary->channel, buffer, 0, 70);
	if (rc)
		return rc;
	rc = run_mixed_lun_completion(devices[0], devices[1],
				      primary->channel, buffer, 1, 76);
	if (rc)
		return rc;
	if (devices[1]->dev_ops->queue_intr_disable(
		    devices[1], devices[1]->_queue[0]))
		return 82;
	remove_test_offer(driver, primary);
	if (primary->channel)
		(void)vmbus_channel_close(primary->channel);
	primary->present = 1;
	if (driver->add_dev(primary))
		return 83;
	atomic_store(&rebind_callbacks, 0);
	pthread_mutex_lock(&race_lock);
	retained_callback_entered = 0;
	retained_callback_release = 0;
	retained_callback_count = 0;
	pthread_mutex_unlock(&race_lock);
	hold_io = 1;
	pending_count = 0;
	for (unsigned int i = 0; i < 2; i++) {
		initialize_request(&requests[i], UK_BLKREQ_READ, 40 + i, 1,
				   buffer + i * 512,
				   i ? request_done :
				       retained_counted_request_done,
				   &rebind_callbacks);
		if (!(devices[i]->submit_one(devices[i],
					     devices[i]->_queue[0],
					     &requests[i]) &
		      UK_BLKDEV_STATUS_SUCCESS))
			return 84;
	}
	complete_pending(0);
	retained_fire.channel = primary->channel;
	if (pthread_create(&retained_fire_thread, NULL, fire_channel_thread,
			   &retained_fire))
		return 84;
	if (wait_race_flag(&retained_callback_entered)) {
		fprintf(stderr,
			"topology interrupt completion failed: "
			"branch=retain-enter rc=%d callbacks=%d "
			"states=%u,%u results=%d,%d bound=%d,%d\n",
			-ETIMEDOUT, atomic_load(&rebind_callbacks),
			atomic_load(&requests[0].state.counter),
			atomic_load(&requests[1].state.counter),
			requests[0].result, requests[1].result,
			storvsc_host_request_bound(&requests[0]),
			storvsc_host_request_bound(&requests[1]));
		release_retained_callback_thread(retained_fire_thread);
		return 85;
	}
	if (requests[0].result ||
	    atomic_load(&rebind_callbacks) != 1 ||
	    atomic_load(&requests[1].state.counter) == UK_BLKREQ_FINISHED ||
	    !storvsc_host_request_bound(&requests[1])) {
		fprintf(stderr,
			"topology interrupt completion failed: "
			"branch=first rc=%d callbacks=%d states=%u,%u "
			"results=%d,%d bound=%d,%d\n",
			-EIO, atomic_load(&rebind_callbacks),
			atomic_load(&requests[0].state.counter),
			atomic_load(&requests[1].state.counter),
			requests[0].result, requests[1].result,
			storvsc_host_request_bound(&requests[0]),
			storvsc_host_request_bound(&requests[1]));
		release_retained_callback_thread(retained_fire_thread);
		return 85;
	}
	rc = devices[1]->dev_ops->queue_intr_enable(
		devices[1], devices[1]->_queue[0]);
	if (rc) {
		fprintf(stderr,
			"topology interrupt completion failed: "
			"branch=enable rc=%d callbacks=%d states=%u,%u "
			"results=%d,%d bound=%d,%d\n",
			rc, atomic_load(&rebind_callbacks),
			atomic_load(&requests[0].state.counter),
			atomic_load(&requests[1].state.counter),
			requests[0].result, requests[1].result,
			storvsc_host_request_bound(&requests[0]),
			storvsc_host_request_bound(&requests[1]));
		release_retained_callback_thread(retained_fire_thread);
		return 86;
	}
	if (requests[1].result != -EINPROGRESS ||
	    atomic_load(&rebind_callbacks) != 1 ||
	    atomic_load(&requests[1].state.counter) == UK_BLKREQ_FINISHED ||
	    !storvsc_host_request_bound(&requests[1])) {
		fprintf(stderr,
			"topology interrupt completion failed: "
			"branch=deferred rc=%d callbacks=%d states=%u,%u "
			"results=%d,%d bound=%d,%d\n",
			-EIO, atomic_load(&rebind_callbacks),
			atomic_load(&requests[0].state.counter),
			atomic_load(&requests[1].state.counter),
			requests[0].result, requests[1].result,
			storvsc_host_request_bound(&requests[0]),
			storvsc_host_request_bound(&requests[1]));
		release_retained_callback_thread(retained_fire_thread);
		return 87;
	}
	pthread_mutex_lock(&race_lock);
	retained_callback_release = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	rc = wait_atomic_value(&rebind_callbacks, 2,
			       CONFIG_LIBSTORVSC_REQUEST_TIMEOUT_MS);
	pthread_join(retained_fire_thread, NULL);
	if (rc || retained_callback_count != 1 ||
	    requests[0].result || requests[1].result ||
	    atomic_load(&rebind_callbacks) != 2 ||
	    atomic_load(&requests[0].state.counter) != UK_BLKREQ_FINISHED ||
	    atomic_load(&requests[1].state.counter) != UK_BLKREQ_FINISHED ||
	    storvsc_host_request_bound(&requests[0]) ||
	    storvsc_host_request_bound(&requests[1])) {
		fprintf(stderr,
			"topology interrupt completion failed: "
			"branch=finished rc=%d callbacks=%d retained=%d "
			"states=%u,%u results=%d,%d bound=%d,%d\n",
			rc, atomic_load(&rebind_callbacks),
			retained_callback_count,
			atomic_load(&requests[0].state.counter),
			atomic_load(&requests[1].state.counter),
			requests[0].result, requests[1].result,
			storvsc_host_request_bound(&requests[0]),
			storvsc_host_request_bound(&requests[1]));
		return 87;
	}
	hold_io = 0;
	if (driver->add_dev(&excess) != -ENOSPC || excess.channel ||
	    uk_storvsc_mapping_count() != 4 ||
	    !storvsc_host_controller_online(0) ||
	    !storvsc_host_controller_online(1))
		return 59;
	if (uk_storvsc_inventory_get(&inventory) != -EAGAIN)
		return 59;
	remove_test_offer(driver, &excess);
	if (uk_storvsc_inventory_get(&inventory) ||
	    inventory.count != 4)
		return 59;

	remove_test_offer(driver, primary);
	if (primary->channel)
		(void)vmbus_channel_close(primary->channel);
	vpd_mode = VPD_UNSUPPORTED;
	primary->present = 1;
	if (driver->add_dev(primary) || uk_storvsc_mapping_count() != 4)
		return 60;
	for (unsigned int i = 0; i < 2; i++) {
		if (uk_storvsc_mapping_get(i, &found) || found.vpd_length)
			return 61;
	}
	remove_test_offer(driver, primary);
	if (primary->channel)
		(void)vmbus_channel_close(primary->channel);
	rc = wait_primary_removal_quiesced(
		CONFIG_LIBSTORVSC_REQUEST_TIMEOUT_MS);
	if (rc) {
		fprintf(stderr,
			"topology partial rediscovery failed: "
			"branch=quiesce rc=%d deferred=%d worker=%d "
			"online=%d channel=%d\n",
			rc, storvsc_host_deferred_action(),
			storvsc_host_worker_present(),
			storvsc_host_controller_online(0),
			storvsc_host_has_channel());
		return 68;
	}

	vpd_mode = VPD_MALFORMED_LUN2;
	primary->present = 1;
	{
		int before_deferred = storvsc_host_deferred_action();
		int before_worker = storvsc_host_worker_present();
		int before_online = storvsc_host_controller_online(0);
		int before_channel = storvsc_host_has_channel();
		unsigned int mapping_count;
		int lun0;
		int lun2;

		rc = driver->add_dev(primary);
		mapping_count = uk_storvsc_mapping_count();
		lun0 = storvsc_host_blkdev_address(0, 0) != NULL;
		lun2 = storvsc_host_blkdev_address(0, 2) != NULL;
		if (rc || mapping_count != 3 || !lun0 || lun2) {
			fprintf(stderr,
				"topology partial rediscovery failed: "
				"branch=add rc=%d count=%u lun0=%d lun2=%d "
				"before={deferred=%d worker=%d online=%d channel=%d} "
				"after={deferred=%d worker=%d online=%d channel=%d}\n",
				rc, mapping_count, lun0, lun2,
				before_deferred, before_worker, before_online,
				before_channel,
				storvsc_host_deferred_action(),
				storvsc_host_worker_present(),
				storvsc_host_controller_online(0),
				storvsc_host_has_channel());
			return 68;
		}
	}
	rc = uk_storvsc_inventory_get(&inventory);
	if (rc != -EAGAIN) {
		fprintf(stderr,
			"topology partial rediscovery failed: "
			"branch=inventory rc=%d count=%u generation=%" PRIu64
			" deferred=%d worker=%d online=%d channel=%d\n",
			rc, inventory.count, inventory.topology_generation,
			storvsc_host_deferred_action(),
			storvsc_host_worker_present(),
			storvsc_host_controller_online(0),
			storvsc_host_has_channel());
		return 68;
	}
	remove_test_offer(driver, primary);
	if (primary->channel)
		(void)vmbus_channel_close(primary->channel);

	remove_test_offer(driver, &secondary);
	if (secondary.channel)
		(void)vmbus_channel_close(secondary.channel);
	topology_fixture = 0;
	report_luns_mode = REPORT_LUNS_NORMAL;
	vpd_mode = VPD_NORMAL;
	secondary.present = 1;
	rc = driver->add_dev(&secondary);
	if (rc)
		return 62;
	remove_test_offer(driver, &secondary);
	if (secondary.channel)
		(void)vmbus_channel_close(secondary.channel);
	topology_fixture = 1;
	report_luns_mode = REPORT_LUNS_POOL_EXCESS;
	vpd_mode = VPD_NORMAL;
	secondary.present = 1;
	rc = driver->add_dev(&secondary);
	if (rc ||
	    uk_storvsc_mapping_count() != CONFIG_LIBSTORVSC_MAX_LUNS ||
	    storvsc_host_blkdev_address(1, 4))
		return 62;
	for (unsigned int i = 0; i < CONFIG_LIBSTORVSC_MAX_LUNS; i++) {
		static const uint8_t pool_luns[] = { 0, 1, 3, 7 };

		if (activate_device(storvsc_host_blkdev_address(1,
							       pool_luns[i]),
				    events))
			return 63;
	}

	report_luns_mode = REPORT_LUNS_NORMAL;
	vpd_mode = VPD_MALFORMED;
	primary->present = 1;
	if (driver->add_dev(primary) != -EPROTO || primary->channel ||
	    uk_storvsc_mapping_count() != CONFIG_LIBSTORVSC_MAX_LUNS ||
	    !storvsc_host_controller_online(1))
		return 64;
	initialize_request(&check, UK_BLKREQ_READ, 11, 1, buffer,
			   request_done, &callbacks);
	if (!(storvsc_host_blkdev_address(1, 0)->submit_one(
		      storvsc_host_blkdev_address(1, 0),
		      storvsc_host_blkdev_address(1, 0)->_queue[0], &check) &
	      UK_BLKDEV_STATUS_SUCCESS))
		return 65;
	fire_channel_on(secondary.channel);
	if (check.result || atomic_load(&callbacks) != 7)
		return 66;

	remove_test_offer(driver, &secondary);
	if (secondary.channel)
		(void)vmbus_channel_close(secondary.channel);
	vpd_mode = VPD_DUPLICATE;
	secondary.present = 1;
	primary->present = 1;
	if (driver->add_dev(&secondary) || driver->add_dev(primary) ||
	    uk_storvsc_mapping_count() != 4)
		return 429;
	for (unsigned int i = 0; i < 4; i++) {
		if (uk_storvsc_mapping_get(i, &mappings[i]) ||
		    mappings[i].vpd_length != 8 ||
		    memcmp(mappings[i].vpd_id, mappings[0].vpd_id, 8))
			return 430;
	}
	remove_test_offer(driver, primary);
	if (primary->channel)
		(void)vmbus_channel_close(primary->channel);
	remove_test_offer(driver, &secondary);
	if (secondary.channel)
		(void)vmbus_channel_close(secondary.channel);
	topology_fixture = 0;
	vpd_mode = VPD_NORMAL;
	report_luns_mode = REPORT_LUNS_NORMAL;
	return 0;
}

static int target_for_device(struct uk_blkdev *device,
			     struct uk_storvsc_target_snapshot *snapshot)
{
	unsigned int count = uk_storvsc_mapping_count();

	for (unsigned int i = 0; i < count; i++) {
		if (uk_storvsc_target_get(i, snapshot))
			continue;
		if (device && device->_data &&
		    snapshot->mapping.blkdev_id == device->_data->id)
			return 0;
	}
	return -ENOENT;
}

static int run_guarded_io_regression(
	struct vmbus_driver *driver, struct vmbus_device *vmbus_device,
	uint8_t *buffer, int *events)
{
	struct uk_storvsc_inventory_snapshot inventory;
	struct uk_storvsc_target_snapshot target;
	struct uk_storvsc_target_snapshot current;
	struct uk_storvsc_session session;
	struct uk_blkdev *device;
	struct uk_blkreq request;
	struct uk_blkreq request2;
	atomic_int callbacks;
	unsigned int sends;
	uint64_t generation;
	int rc;
	report_luns_mode = REPORT_LUNS_NORMAL;
	vpd_mode = VPD_NORMAL;
	read_only_media = 0;
	use_capacity16 = 0;
	topology_fixture = 0;
	backing_media_enabled = 1;
	memset(backing_media, 0, sizeof(backing_media));
	vmbus_device->present = 1;
	if (driver->add_dev(vmbus_device))
		return 500;
	device = storvsc_host_blkdev_address(0, 0);
	if (activate_device(device, events))
		return 501;
	if (target_for_device(device, &target) ||
	    uk_storvsc_session_begin_read(&target, &session) != -ENOTSUP)
		return 502;
	storvsc_host_set_guarded_io(1);
	if (target_for_device(device, &target) || !target.mapping.vpd_length)
		return 502;
	if (uk_storvsc_inventory_get(&inventory) ||
	    inventory.version != UK_STORVSC_INVENTORY_SNAPSHOT_VERSION ||
	    inventory.size != sizeof(inventory) ||
	    inventory.topology_generation != target.topology_generation ||
	    inventory.count != uk_storvsc_mapping_count())
		return 502;
	generation = target.controller_generation;

	atomic_init(&callbacks, 0);
	sends = io_command_count;
	initialize_request(&request, UK_BLKREQ_READ, 0, 1, buffer,
			   request_done, &callbacks);
	if (device->submit_one(device, device->_queue[0], &request) !=
	    -EACCES || io_command_count != sends)
		return 503;
	initialize_request(&request, UK_BLKREQ_WRITE, 0, 1, buffer,
			   request_done, &callbacks);
	if (device->submit_one(device, device->_queue[0], &request) !=
	    -EACCES || io_command_count != sends)
		return 504;
	initialize_request(&request, UK_BLKREQ_FFLUSH, 0, 0, NULL,
			   request_done, &callbacks);
	if (device->submit_one(device, device->_queue[0], &request) !=
	    -EACCES || io_command_count != sends)
		return 505;

	current = target;
	current.mapping.sectors++;
	if (uk_storvsc_session_begin_read(&current, &session) != -ESTALE)
		return 506;
	current = target;
	current.mapping.vpd_id[0] ^= 1;
	if (uk_storvsc_session_begin_read(&current, &session) != -ESTALE)
		return 506;
	if (uk_storvsc_session_begin_read(&target, &session))
		return 507;
	for (unsigned int attempt = 0; ; attempt++) {
		uk_sched_thread_sleep(1000000ULL);
		rc = uk_storvsc_session_validate(&session, &current);
		if (!rc)
			break;
		if (rc != -ESTALE || attempt == 99 ||
		    target_for_device(device, &target) ||
		    uk_storvsc_session_begin_read(&target, &session))
			return 508;
	}
	if (memcmp(&target, &current, sizeof(target)))
		return 508;

	initialize_request(&request, UK_BLKREQ_READ, 1, 1, buffer,
			   request_done, &callbacks);
	if (submit_and_fire(device, &request) || request.result)
		return 509;
	sends = io_command_count;
	initialize_request(&request, UK_BLKREQ_WRITE, 1, 1, buffer,
			   request_done, &callbacks);
	if (device->submit_one(device, device->_queue[0], &request) !=
	    -EACCES || io_command_count != sends)
		return 510;
	if (uk_storvsc_session_authorize_write(&session) ||
	    uk_storvsc_session_set_cdb(&session, 9) != -EINVAL ||
	    uk_storvsc_session_set_cdb(&session, UK_STORVSC_CDB_10))
		return 511;
	sends = io_command_count;
	initialize_request(&request, UK_BLKREQ_WRITE, 1000, 1, buffer,
			   request_done, &callbacks);
	if (device->submit_one(device, device->_queue[0], &request) !=
	    -EINVAL || io_command_count != sends)
		return 511;
	initialize_request(&request, UK_BLKREQ_WRITE, 1, 1, buffer + 1,
			   request_done, &callbacks);
	if (device->submit_one(device, device->_queue[0], &request) !=
	    -EINVAL || io_command_count != sends)
		return 511;

	for (unsigned int i = 0; i < 16 * 512; i++)
		buffer[i] = (uint8_t)(i * 17U + 3U);
	initialize_request(&request, UK_BLKREQ_WRITE, 32, 16, buffer,
			   request_done, &callbacks);
	if (submit_and_fire(device, &request) || request.result ||
	    last_io_opcode != 0x2a || last_pfn_count < 2)
		return 512;
	memset(buffer, 0, 16 * 512);
	initialize_request(&request, UK_BLKREQ_READ, 32, 16, buffer,
			   request_done, &callbacks);
	if (submit_and_fire(device, &request) || request.result ||
	    last_io_opcode != 0x28)
		return 513;
	for (unsigned int i = 0; i < 16 * 512; i++) {
		if (buffer[i] != (uint8_t)(i * 17U + 3U))
			return 514;
	}

	if (uk_storvsc_session_set_cdb(&session, UK_STORVSC_CDB_16))
		return 515;
	memset(buffer, 0xa7, 512);
	initialize_request(&request, UK_BLKREQ_WRITE, 127, 1, buffer,
			   request_done, &callbacks);
	if (submit_and_fire(device, &request) || request.result ||
	    last_io_opcode != 0x8a)
		return 516;
	initialize_request(&request, UK_BLKREQ_READ, 127, 1, buffer + 512,
			   request_done, &callbacks);
	if (submit_and_fire(device, &request) || request.result ||
	    last_io_opcode != 0x88 ||
	    memcmp(buffer, buffer + 512, 512))
		return 517;

	io_packet_error_once = 1;
	initialize_request(&request, UK_BLKREQ_FFLUSH, 0, 0, NULL,
			   request_done, &callbacks);
	if (submit_and_fire(device, &request) || request.result != -EIO)
		return 518;
	initialize_request(&request, UK_BLKREQ_FFLUSH, 0, 0, NULL,
			   request_done, &callbacks);
	if (submit_and_fire(device, &request) || request.result)
		return 519;

	hold_io = 1;
	pending_count = 0;
	initialize_request(&request, UK_BLKREQ_FFLUSH, 0, 0, NULL,
			   request_done, &callbacks);
	if (!(device->submit_one(device, device->_queue[0], &request) &
	      UK_BLKDEV_STATUS_SUCCESS))
		return 520;
	storvsc_host_force_timeout();
	if (wait_request_completion(&request, &callbacks, 8, 1000) ||
	    request.result != -ETIMEDOUT)
		return 521;
	enqueue_completion(last_io_id, 64, 0, 1, 0, 0);
	pending_count = 0;
	fire_channel();
	if (atomic_load(&callbacks) != 8)
		return 522;
	rc = uk_storvsc_session_validate(&session, &current);
	if (rc != -ESTALE)
		return 523;
	remove_test_offer(driver, vmbus_device);
	if (vmbus_device->channel)
		(void)vmbus_channel_close(vmbus_device->channel);
	hold_io = 0;
	vmbus_device->present = 1;
	if (driver->add_dev(vmbus_device) ||
	    activate_device(device, events))
		return 523;
	rc = target_for_device(device, &current);
	if (rc)
		return 523;
	rc = uk_storvsc_session_begin_read(&current, &session);
	if (rc)
		return 523;
	rc = uk_storvsc_session_authorize_write(&session);
	if (rc)
		return 523;
	if (uk_storvsc_session_set_cdb(
		    &session, UK_STORVSC_CDB_16))
		return 523;

	hold_io = 1;
	pending_count = 0;
	initialize_request(&request, UK_BLKREQ_WRITE, 2, 1, buffer,
			   request_done, &callbacks);
	if (!(device->submit_one(device, device->_queue[0], &request) &
	      UK_BLKDEV_STATUS_SUCCESS) ||
	    uk_storvsc_session_end(&session) != -EBUSY)
		return 524;
	remove_test_offer(driver, vmbus_device);
	if (request.result != -ENODEV ||
	    atomic_load(&request.state.counter) != UK_BLKREQ_FINISHED ||
	    uk_storvsc_session_validate(&session, &current) != -ESTALE)
		return 525;
	enqueue_completion(last_io_id, 64, 0, 1, 0, last_io_length);
	pending_count = 0;
	fire_channel();
	if (atomic_load(&callbacks) != 9)
		return 526;
	if (vmbus_device->channel)
		(void)vmbus_channel_close(vmbus_device->channel);
	hold_io = 0;

	vmbus_device->present = 1;
	if (driver->add_dev(vmbus_device) ||
	    target_for_device(device, &current) ||
	    current.controller_generation == generation ||
	    uk_storvsc_session_validate(&session, &target) != -ESTALE)
		return 527;
	if (uk_storvsc_session_begin_read(&current, &session) ||
	    uk_storvsc_session_authorize_write(&session) ||
	    uk_storvsc_session_end(&session))
		return 528;

	{
		struct vmbus_channel *enumerate_channel =
			vmbus_device->channel;
		unsigned int callbacks_before =
			(unsigned int)atomic_load(&callbacks);

		if (uk_storvsc_session_begin_read(&current, &session) ||
		    uk_storvsc_session_authorize_write(&session))
			return 530;
		hold_io = 1;
		pending_count = 0;
		pthread_mutex_lock(&race_lock);
		retained_callback_entered = 0;
		retained_callback_release = 0;
		retained_callback_count = 0;
		pthread_mutex_unlock(&race_lock);
		initialize_request(&request, UK_BLKREQ_WRITE, 4, 1, buffer,
				   retained_then_counted_request_done,
				   &callbacks);
		if (!(device->submit_one(device, device->_queue[0], &request) &
		      UK_BLKDEV_STATUS_SUCCESS) ||
		    pending_count != 1)
			return 531;
		enqueue_enumerate_bus(enumerate_channel);
		fire_channel_on(enumerate_channel);
		rc = wait_race_flag(&retained_callback_entered);
		if (rc ||
		    request.result != -ESTALE ||
		    atomic_load(&request.state.counter) !=
			    UK_BLKREQ_FINISHED ||
		    atomic_load(&callbacks) != (int)callbacks_before ||
		    storvsc_host_request_bound(&request)) {
			fprintf(stderr,
				"guarded I/O completion failed: "
				"fullrc=533 branch=held wait_rc=%d "
				"state=%u result=%d callbacks=%d "
				"expected=%u retained=%d bound=%d\n",
				rc,
				atomic_load(&request.state.counter),
				request.result, atomic_load(&callbacks),
				callbacks_before, retained_callback_count,
				storvsc_host_request_bound(&request));
			release_retained_callback();
			(void)wait_request_completion(
				&request, &callbacks,
				(int)callbacks_before + 1, 1000);
			return 533;
		}
		sends = io_command_count;
		initialize_request(&request2, UK_BLKREQ_READ, 5, 1,
				   buffer + 512, request_done, &callbacks);
		if (uk_storvsc_session_validate(&session, &target) !=
			    -ESTALE ||
		    device->submit_one(device, device->_queue[0],
				       &request2) != -ENODEV ||
		    io_command_count != sends) {
			release_retained_callback();
			(void)wait_request_completion(
				&request, &callbacks,
				(int)callbacks_before + 1, 1000);
			return 532;
		}
		enqueue_completion_on(
			enumerate_channel, pending[0].id, 64, 0, 1, 0,
			pending[0].length);
		release_retained_callback();
		rc = wait_request_completion(
			&request, &callbacks, (int)callbacks_before + 1,
			1000);
		if (rc ||
		    request.result != -ESTALE ||
		    atomic_load(&callbacks) !=
			    (int)callbacks_before + 1 ||
		    atomic_load(&request.state.counter) !=
			    UK_BLKREQ_FINISHED ||
		    retained_callback_count != 1 ||
		    storvsc_host_request_bound(&request)) {
			fprintf(stderr,
				"guarded I/O completion failed: "
				"fullrc=533 branch=delivered wait_rc=%d "
				"state=%u result=%d callbacks=%d "
				"expected=%u retained=%d bound=%d\n",
				rc,
				atomic_load(&request.state.counter),
				request.result, atomic_load(&callbacks),
				callbacks_before + 1,
				retained_callback_count,
				storvsc_host_request_bound(&request));
			return 533;
		}
		fire_channel_on(enumerate_channel);
		if (atomic_load(&callbacks) !=
		    (int)callbacks_before + 1)
			return 534;
		pending_count = 0;
		hold_io = 0;
		if (reoffer_device(driver, vmbus_device, device) ||
		    target_for_device(device, &current) ||
		    uk_storvsc_session_validate(&session, &target) !=
			    -ESTALE ||
		    uk_storvsc_session_begin_read(&current, &session) ||
		    uk_storvsc_session_end(&session))
			return 535;
	}

	remove_test_offer(driver, vmbus_device);
	if (vmbus_device->channel)
		(void)vmbus_channel_close(vmbus_device->channel);
	vpd_mode = VPD_UNSUPPORTED;
	vmbus_device->present = 1;
	if (driver->add_dev(vmbus_device) ||
	    target_for_device(device, &current) ||
	    current.mapping.vpd_length ||
	    uk_storvsc_session_begin_read(&current, &session) != -EINVAL)
		return 529;
	remove_test_offer(driver, vmbus_device);
	if (vmbus_device->channel)
		(void)vmbus_channel_close(vmbus_device->channel);

	storvsc_host_set_guarded_io(0);
	backing_media_enabled = 0;
	vpd_mode = VPD_NORMAL;
	return 0;
}

static int persistence_prepare_seed(unsigned int identity_policy,
				    int boot_signature,
				    uint64_t sectors, uint8_t lun,
				    int wrong_id)
{
	struct hyperv_acceptance_persistence_expected expected = {
		.run_id = {
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		},
		.disk_id = {
			0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
			0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
		},
		.sectors = sectors,
		.sector_size = 512,
		.path_id = 0,
		.target_id = 0,
		.lun = lun,
		.identity_policy = identity_policy,
	};
	uint8_t manifest[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];

	memset(backing_media, 0, sizeof(backing_media));
	if (wrong_id)
		expected.run_id[0] ^= 0x80;
	if (hyperv_acceptance_persistence_build_manifest(
		    &expected, manifest))
		return -EINVAL;
	memcpy(backing_media +
		       HYPERV_ACCEPTANCE_PERSISTENCE_SEED0_LBA * 512,
	       manifest, sizeof(manifest));
	memcpy(backing_media +
		       HYPERV_ACCEPTANCE_PERSISTENCE_SEED1_LBA * 512,
	       manifest, sizeof(manifest));
	if (boot_signature) {
		backing_media[510] = 0x55;
		backing_media[511] = 0xaa;
	}
	return 0;
}

static int persistence_remove_device(struct vmbus_driver *driver,
				     struct vmbus_device *device)
{
	unsigned int channel_id;
	int ready_before;
	int wait_for_ready;
	int rc;

	if (!device->present && !device->channel)
		return 0;
	channel_id = device->channel_id;
	wait_for_ready = device->channel != NULL;
	ready_before = atomic_load(&bind_ready_calls);
	remove_test_offer(driver, device);
	if (device->channel)
		(void)vmbus_channel_close(device->channel);
	if (!wait_for_ready)
		return 0;
	/* Deferred removal publishes bind readiness after clearing device state. */
	pthread_mutex_lock(&race_lock);
	if (removal_coherence_enabled) {
		removal_coherence_wait_entered = 1;
		pthread_cond_broadcast(&race_condition);
	}
	pthread_mutex_unlock(&race_lock);
	rc = wait_atomic_at_least(
		&bind_ready_calls, ready_before + 1,
		CONFIG_LIBSTORVSC_REQUEST_TIMEOUT_MS);
	if (rc)
		fprintf(stderr,
			"persistence removal wait failed: "
			"stage=bind-ready rc=%d channel=%u ready=%d/%d "
			"mappings=%u\n",
			rc, channel_id, atomic_load(&bind_ready_calls),
			ready_before + 1, uk_storvsc_mapping_count());
	return rc;
}

struct persistence_remove_context {
	struct vmbus_driver *driver;
	struct vmbus_device *device;
	atomic_int done;
	int result;
};

static void *persistence_remove_thread(void *argument)
{
	struct persistence_remove_context *context = argument;

	pthread_mutex_lock(&race_lock);
	removal_coherence_caller = pthread_self();
	removal_coherence_caller_registered = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	context->result =
		persistence_remove_device(context->driver, context->device);
	atomic_store(&context->done, 1);
	return NULL;
}

static int persistence_remove_with_worker_ownership(
	struct vmbus_driver *driver, struct vmbus_device *device)
{
	struct persistence_remove_context context = {
		.driver = driver,
		.device = device,
	};
	pthread_t thread;
	int created = 0;
	int error = 0;

	atomic_init(&context.done, 0);
	pthread_mutex_lock(&race_lock);
	removal_coherence_enabled = 1;
	removal_coherence_caller_registered = 0;
	removal_coherence_caller_entered = 0;
	removal_coherence_release_caller = 0;
	removal_coherence_close_entered = 0;
	removal_coherence_release_close = 0;
	removal_coherence_wait_entered = 0;
	pthread_mutex_unlock(&race_lock);
	if (pthread_create(&thread, NULL, persistence_remove_thread, &context)) {
		error = -EIO;
		goto out;
	}
	created = 1;
	if (wait_race_flag(&removal_coherence_caller_entered) ||
	    wait_race_flag(&removal_coherence_close_entered)) {
		error = -ETIMEDOUT;
		goto out;
	}
	pthread_mutex_lock(&race_lock);
	removal_coherence_release_caller = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	for (unsigned int i = 0; i < 1000; i++) {
		int waiting;

		pthread_mutex_lock(&race_lock);
		waiting = removal_coherence_wait_entered;
		pthread_mutex_unlock(&race_lock);
		if (waiting || atomic_load(&context.done))
			break;
		uk_sched_thread_sleep(1000000ULL);
	}
	pthread_mutex_lock(&race_lock);
	if (!removal_coherence_wait_entered)
		error = atomic_load(&context.done) ?
			-EALREADY : -ETIMEDOUT;
	else if (atomic_load(&context.done))
		error = -EALREADY;
	pthread_mutex_unlock(&race_lock);
out:
	pthread_mutex_lock(&race_lock);
	removal_coherence_enabled = 0;
	removal_coherence_release_caller = 1;
	removal_coherence_release_close = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	if (created)
		pthread_join(thread, NULL);
	pthread_mutex_lock(&race_lock);
	removal_coherence_caller_registered = 0;
	removal_coherence_caller_entered = 0;
	removal_coherence_close_entered = 0;
	removal_coherence_wait_entered = 0;
	pthread_mutex_unlock(&race_lock);
	if (!error && context.result)
		error = context.result;
	if (error)
		fprintf(stderr,
			"persistence removal coherence failed: rc=%d "
			"done=%d ready=%d online1=%d mappings=%u\n",
			error, atomic_load(&context.done),
			atomic_load(&bind_ready_calls),
			storvsc_host_controller_online(1),
			uk_storvsc_mapping_count());
	return error;
}

enum unresolved_discovery_case {
	UNRESOLVED_DISCOVERY_VPD,
	UNRESOLVED_DISCOVERY_INQUIRY,
	UNRESOLVED_DISCOVERY_CAPACITY,
	UNRESOLVED_DISCOVERY_REGISTRATION,
	UNRESOLVED_DISCOVERY_ALL_VPD,
};

static int run_unresolved_discovery_case(
	struct vmbus_driver *driver, struct vmbus_device *primary,
	struct vmbus_device *secondary,
	enum unresolved_discovery_case failure, int run_guest)
{
	char output[8192];
	struct uk_storvsc_inventory_snapshot inventory;
	unsigned int writes10 = write10_command_count;
	unsigned int writes16 = write16_command_count;
	unsigned int flushes = flush_command_count;
	int inventory_rc;
	int guest_result;
	int rc;

	hyperv_acceptance_persistence_host_reset();
	if (persistence_prepare_seed(
		    HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2,
		    0, 1000, 0, 0))
		return 650;
	primary->present = 1;
	if (driver->add_dev(primary))
		return 651;

	targeted_vpd_malformed =
		failure == UNRESOLVED_DISCOVERY_VPD;
	targeted_vpd_controller = 1;
	targeted_vpd_lun = 0;
	discovery_failure_kind =
		failure == UNRESOLVED_DISCOVERY_INQUIRY ?
			DISCOVERY_FAILURE_INQUIRY :
		failure == UNRESOLVED_DISCOVERY_CAPACITY ?
			DISCOVERY_FAILURE_CAPACITY :
			DISCOVERY_FAILURE_NONE;
	discovery_failure_controller = 1;
	discovery_failure_lun = 0;
	discovery_failures_remaining =
		discovery_failure_kind != DISCOVERY_FAILURE_NONE;
	registration_failure_controller = 1;
	registration_failure_lun = 0;
	registration_failures_remaining =
		failure == UNRESOLVED_DISCOVERY_REGISTRATION;
	if (failure == UNRESOLVED_DISCOVERY_ALL_VPD)
		vpd_mode = VPD_MALFORMED;
	secondary->present = 1;
	rc = driver->add_dev(secondary);
	targeted_vpd_malformed = 0;
	discovery_failure_kind = DISCOVERY_FAILURE_NONE;
	discovery_failures_remaining = 0;
	registration_failures_remaining = 0;
	vpd_mode = VPD_NORMAL;
	inventory_rc = uk_storvsc_inventory_get(&inventory);
	if ((failure == UNRESOLVED_DISCOVERY_ALL_VPD ?
		     rc != -EPROTO : rc) ||
	    uk_storvsc_mapping_count() !=
		    (failure == UNRESOLVED_DISCOVERY_ALL_VPD ? 3U : 5U)) {
		(void)persistence_remove_device(driver, secondary);
		(void)persistence_remove_device(driver, primary);
		return 652;
	}
	if (inventory_rc == -EAGAIN &&
	    failure != UNRESOLVED_DISCOVERY_ALL_VPD &&
	    storvsc_host_reset_controller(1)) {
		(void)persistence_remove_device(driver, secondary);
		(void)persistence_remove_device(driver, primary);
		return 653;
	}
	if (inventory_rc == -EAGAIN)
		inventory_rc = uk_storvsc_inventory_get(&inventory);
	if (run_guest) {
		rc = capture_persistence_output(
			output, sizeof(output), &guest_result);
		if (rc || guest_result != HYPERV_ACCEPTANCE_FAIL ||
		    persistence_log_has_unavailable(output) ||
		    write10_command_count != writes10 ||
		    write16_command_count != writes16 ||
		    flush_command_count != flushes) {
			(void)persistence_remove_device(driver, secondary);
			(void)persistence_remove_device(driver, primary);
			return 655;
		}
	}
	if (inventory_rc != -EAGAIN) {
		(void)persistence_remove_device(driver, secondary);
		(void)persistence_remove_device(driver, primary);
		return 654;
	}
	if (failure == UNRESOLVED_DISCOVERY_VPD)
		rc = persistence_remove_with_worker_ownership(
			driver, secondary);
	else
		rc = persistence_remove_device(driver, secondary);
	if (rc) {
		(void)persistence_remove_device(driver, primary);
		return 656;
	}
	inventory_rc = uk_storvsc_inventory_get(&inventory);
	if (inventory_rc || inventory.count != 3) {
		fprintf(stderr,
			"unresolved discovery removal failed: "
			"case=%d rc=%d count=%u generation=%" PRIu64
			" mappings=%u\n",
			failure, inventory_rc, inventory.count,
			inventory.topology_generation,
			uk_storvsc_mapping_count());
		(void)persistence_remove_device(driver, primary);
		return 656;
	}
	if (failure == UNRESOLVED_DISCOVERY_VPD) {
		secondary->present = 1;
		if (driver->add_dev(secondary) ||
		    uk_storvsc_inventory_get(&inventory) ||
		    inventory.count != 6 ||
		    hyperv_acceptance_persistence_main() !=
			    HYPERV_ACCEPTANCE_FAIL ||
		    write10_command_count != writes10 ||
		    write16_command_count != writes16 ||
		    flush_command_count != flushes) {
			(void)persistence_remove_device(driver, secondary);
			(void)persistence_remove_device(driver, primary);
			return 657;
		}
		if (persistence_remove_device(driver, secondary)) {
			(void)persistence_remove_device(driver, primary);
			return 658;
		}
	}
	if (persistence_remove_device(driver, primary))
		return 659;
	return 0;
}

enum vmbus_offer_lifetime_case {
	VMBUS_OFFER_FAILED_CLOSE,
	VMBUS_OFFER_NORMAL_CLOSE,
	VMBUS_OFFER_POOL_FAILURE,
};

static int run_vmbus_offer_lifetime_case(
	struct vmbus_driver *driver,
	const struct vmbus_guid *primary_id,
	const struct vmbus_guid *secondary_id,
	enum vmbus_offer_lifetime_case failure)
{
	struct vmbus_guid pool_id = {
		.bytes = {
			3, 1, 2, 3, 4, 5, 6, 7,
			8, 9, 10, 11, 12, 13, 14, 15,
		},
	};
	struct uk_storvsc_inventory_snapshot inventory;
	const __u32 primary_channel = 201;
	const __u32 failed_channel = 202;
	const struct vmbus_guid *failed_id =
		failure == VMBUS_OFFER_POOL_FAILURE ?
			&pool_id : secondary_id;
	unsigned int close_attempts_before =
		atomic_load(&close_attempts);
	unsigned int writes10 = write10_command_count;
	unsigned int writes16 = write16_command_count;
	unsigned int flushes = flush_command_count;
	__u64 failed_generation;
	int inventory_rc;
	int error = 0;

	hyperv_acceptance_persistence_host_reset();
	if (persistence_prepare_seed(
		    HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2,
		    0, 1000, 0, 0))
		return 660;
	report_luns_mode = REPORT_LUNS_NORMAL;
	topology_fixture = 0;
	vpd_mode = VPD_NORMAL;
	storvsc_host_set_guarded_io(1);
	storvsc_host_set_lun_discovery(1);
	read_only_media = 0;
	use_capacity16 = 0;
	hold_io = 0;
	pending_count = 0;
	if (vmbus_bus_host_offer_lifetime_setup(driver))
		return 661;
	use_vmbus_offer_lifetimes = 1;
	if (vmbus_bus_host_offer_storage(
		    primary_id, primary_channel, primary_channel + 100) ||
	    !vmbus_bus_host_offer_present(primary_channel)) {
		error = 662;
		goto out;
	}
	if (failure != VMBUS_OFFER_POOL_FAILURE)
		vpd_mode = VPD_MALFORMED;
	if (failure == VMBUS_OFFER_FAILED_CLOSE)
		configure_close_failure(
			-EBUSY, TEST_CLOSE_RETRY_LIMIT);
	if (vmbus_bus_host_offer_storage(
		    failed_id, failed_channel, failed_channel + 100) ||
	    !vmbus_bus_host_offer_present(failed_channel) ||
	    !(failed_generation =
		      vmbus_bus_host_offer_generation(failed_channel))) {
		error = 663;
		goto out;
	}
	vpd_mode = VPD_NORMAL;
	configure_close_failure(0, 0);
	if (failure == VMBUS_OFFER_FAILED_CLOSE &&
	    atomic_load(&close_attempts) - close_attempts_before !=
		    TEST_CLOSE_RETRY_LIMIT + 1) {
		error = 664;
		goto out;
	}
	inventory_rc = uk_storvsc_inventory_get(&inventory);
	if (uk_storvsc_mapping_count() != 3) {
		error = 665;
		goto out;
	}
	if (hyperv_acceptance_persistence_main() !=
		    HYPERV_ACCEPTANCE_FAIL ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes) {
		error = 666;
		goto out;
	}
	if (inventory_rc != -EAGAIN) {
		error = 665;
		goto out;
	}
	if (driver->offer_removed) {
		struct vmbus_offer_identity stale = {
			.instance_id = *failed_id,
			.channel_id = failed_channel,
			.generation = failed_generation == 1 ?
				2 : failed_generation - 1,
		};

		driver->offer_removed(&stale);
		if (uk_storvsc_inventory_get(&inventory) != -EAGAIN) {
			error = 668;
			goto out;
		}
	}
	if (vmbus_bus_host_confirm_rescind(failed_channel) ||
	    vmbus_bus_host_offer_present(failed_channel) ||
	    uk_storvsc_inventory_get(&inventory) ||
	    inventory.count != 3) {
		error = 667;
		goto out;
	}
out:
	vpd_mode = VPD_NORMAL;
	configure_close_failure(0, 0);
	if (vmbus_bus_host_offer_present(failed_channel))
		(void)vmbus_bus_host_confirm_rescind(failed_channel);
	if (vmbus_bus_host_offer_present(primary_channel))
		(void)vmbus_bus_host_confirm_rescind(primary_channel);
	use_vmbus_offer_lifetimes = 0;
	storvsc_host_set_guarded_io(0);
	return error;
}

static int run_vmbus_reoffer_cleanup_case(
	struct vmbus_driver *driver,
	const struct vmbus_guid *primary_id,
	const struct vmbus_guid *secondary_id,
	uint8_t *buffer)
{
	struct uk_storvsc_inventory_snapshot inventory;
	struct uk_storvsc_target_snapshot target;
	struct uk_storvsc_session session;
	struct rescind_thread_context rescind = {
		.channel_id = 212,
	};
	struct uk_blkdev *secondary;
	struct uk_blkreq request;
	pthread_t rescind_tid;
	unsigned int writes10;
	unsigned int writes16;
	unsigned int flushes;
	int events = 0;
	int guest_rc;
	int inventory_rc;
	int submit_rc;
	int rescind_created = 0;
	int error = 0;

	hyperv_acceptance_persistence_host_reset();
	hyperv_acceptance_persistence_host_set_identity_policy(
		HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2);
	if (persistence_prepare_seed(
		    HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2,
		    0, 1000, 0, 0))
		return 670;
	report_luns_mode = REPORT_LUNS_NORMAL;
	topology_fixture = 0;
	vpd_mode = VPD_NORMAL;
	storvsc_host_set_guarded_io(1);
	storvsc_host_set_lun_discovery(1);
	read_only_media = 0;
	use_capacity16 = 0;
	backing_media_enabled = 1;
	hold_io = 0;
	pending_count = 0;
	if (vmbus_bus_host_offer_lifetime_setup(driver))
		return 671;
	use_vmbus_offer_lifetimes = 1;
	if (vmbus_bus_host_offer_storage(primary_id, 211, 311) ||
	    vmbus_bus_host_offer_storage(secondary_id, 212, 312)) {
		error = 672;
		goto out;
	}
	secondary = storvsc_host_blkdev_address(1, 0);
	if (!secondary) {
		error = 673;
		goto out;
	}
	error = activate_device(secondary, &events);
	if (error) {
		error = 674;
		goto out;
	}
	if (target_for_device(secondary, &target) ||
	    uk_storvsc_session_begin_read(&target, &session)) {
		error = 675;
		goto out;
	}
	pthread_mutex_lock(&race_lock);
	retained_callback_entered = 0;
	retained_callback_release = 0;
	retained_callback_count = 0;
	pthread_mutex_unlock(&race_lock);
	hold_io = 1;
	initialize_request(&request, UK_BLKREQ_READ, 8, 1, buffer,
			   retained_request_done, NULL);
	submit_rc = secondary->submit_one(
		secondary, secondary->_queue[0], &request);
	if (submit_rc < 0 ||
	    !(submit_rc & UK_BLKDEV_STATUS_SUCCESS)) {
		error = 676;
		goto out;
	}
	if (pending_count != 1) {
		error = 676;
		goto out;
	}
	if (pthread_create(&rescind_tid, NULL, rescind_thread, &rescind)) {
		error = 677;
		goto out;
	}
	rescind_created = 1;
	if (wait_race_flag(&retained_callback_entered)) {
		error = 678;
		goto out;
	}
	if (vmbus_bus_host_offer_storage(secondary_id, 213, 313) ||
	    !vmbus_bus_host_offer_present(213) ||
	    uk_storvsc_inventory_get(&inventory) != -EAGAIN) {
		error = 679;
		goto out;
	}
	pthread_mutex_lock(&race_lock);
	retained_callback_release = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	pthread_join(rescind_tid, NULL);
	rescind_created = 0;
	if (rescind.result || retained_callback_count != 1 ||
	    request.result != -ENODEV ||
	    storvsc_host_controller_online(1)) {
		error = 680;
		goto out;
	}
	hold_io = 0;
	pending_count = 0;
	drop_packets();

	writes10 = write10_command_count;
	writes16 = write16_command_count;
	flushes = flush_command_count;
	inventory_rc = uk_storvsc_inventory_get(&inventory);
	guest_rc = hyperv_acceptance_persistence_main();
	if (inventory_rc != -EAGAIN ||
	    guest_rc != HYPERV_ACCEPTANCE_FAIL ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes) {
		error = 681;
		goto out;
	}
	if (vmbus_bus_host_confirm_rescind(213) ||
	    uk_storvsc_inventory_get(&inventory) ||
	    inventory.count != 3) {
		error = 682;
		goto out;
	}

out:
	pthread_mutex_lock(&race_lock);
	retained_callback_release = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	if (rescind_created)
		pthread_join(rescind_tid, NULL);
	hold_io = 0;
	pending_count = 0;
	drop_packets();
	if (vmbus_bus_host_offer_present(213))
		(void)vmbus_bus_host_confirm_rescind(213);
	if (vmbus_bus_host_offer_present(212))
		(void)vmbus_bus_host_confirm_rescind(212);
	if (vmbus_bus_host_offer_present(211))
		(void)vmbus_bus_host_confirm_rescind(211);
	use_vmbus_offer_lifetimes = 0;
	backing_media_enabled = 0;
	hyperv_acceptance_persistence_host_set_identity_policy(0);
	hyperv_acceptance_persistence_host_reset();
	storvsc_host_set_guarded_io(0);
	return error;
}

static int run_vmbus_offer_lifetime_regression(
	struct vmbus_driver *driver, const struct vmbus_device *primary,
	uint8_t *buffer)
{
	struct vmbus_guid secondary_id = {
		.bytes = {
			2, 1, 2, 3, 4, 5, 6, 7,
			8, 9, 10, 11, 12, 13, 14, 15,
		},
	};
	int rc;

	rc = run_vmbus_offer_lifetime_case(
		driver, &primary->instance_id, &secondary_id,
		VMBUS_OFFER_FAILED_CLOSE);
	if (rc)
		return rc;
	rc = run_vmbus_offer_lifetime_case(
		driver, &primary->instance_id, &secondary_id,
		VMBUS_OFFER_NORMAL_CLOSE);
	if (rc)
		return rc;
	rc = run_vmbus_offer_lifetime_case(
		driver, &primary->instance_id, &secondary_id,
		VMBUS_OFFER_POOL_FAILURE);
	if (rc)
		return rc;
	return run_vmbus_reoffer_cleanup_case(
		driver, &primary->instance_id, &secondary_id, buffer);
}

static int run_binding_publication_regression(
	struct vmbus_driver *driver, struct vmbus_device *secondary)
{
	struct uk_storvsc_inventory_snapshot before;
	struct uk_storvsc_inventory_snapshot after;
	struct uk_storvsc_target_snapshot target;
	struct uk_storvsc_target_snapshot during_target;
	struct uk_storvsc_session session;
	struct uk_storvsc_session during_session;
	struct add_thread_context add_context = {
		.driver = driver,
		.device = secondary,
	};
	struct uk_blkdev *device;
	struct uk_blkreq request;
	pthread_t add_tid;
	unsigned int sends;
	unsigned int writes10;
	unsigned int writes16;
	unsigned int flushes;
	int add_created = 0;
	int error = 0;

	device = storvsc_host_blkdev_address(0, 0);
	if (!device || uk_storvsc_inventory_get(&before) ||
	    target_for_device(device, &target) ||
	    target.topology_generation != before.topology_generation ||
	    uk_storvsc_session_begin_read(&target, &session))
		return 620;
	pthread_mutex_lock(&race_lock);
	binding_publish_pause = 1;
	binding_publish_controller = 1;
	binding_publish_entered = 0;
	binding_publish_release = 0;
	pthread_mutex_unlock(&race_lock);
	atomic_init(&add_context.done, 0);
	secondary->present = 1;
	if (pthread_create(&add_tid, NULL, add_thread, &add_context)) {
		error = 621;
		goto out;
	}
	add_created = 1;
	if (wait_race_flag(&binding_publish_entered)) {
		error = 622;
		goto out;
	}
	if (uk_storvsc_session_authorize_write(&session) != -ESTALE) {
		error = 623;
		goto out;
	}
	if (uk_storvsc_inventory_get(&after) != -EAGAIN ||
	    uk_storvsc_mapping_count() != before.count) {
		error = 624;
		goto out;
	}
	if (target_for_device(device, &during_target) ||
	    during_target.topology_generation ==
		    before.topology_generation ||
	    uk_storvsc_session_begin_read(
		    &during_target, &during_session)) {
		error = 625;
		goto out;
	}
out:
	pthread_mutex_lock(&race_lock);
	binding_publish_release = 1;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	if (add_created)
		pthread_join(add_tid, NULL);
	pthread_mutex_lock(&race_lock);
	binding_publish_pause = 0;
	binding_publish_entered = 0;
	binding_publish_release = 0;
	pthread_mutex_unlock(&race_lock);
	if (error)
		return error;
	if (!atomic_load(&add_context.done) || add_context.result)
		return 626;
	{
		int inventory_rc = uk_storvsc_inventory_get(&after);
		int authorize_rc = uk_storvsc_session_authorize_write(
			&during_session);

		if (inventory_rc ||
		    after.topology_generation ==
			    during_target.topology_generation ||
		    after.count <= before.count ||
		    authorize_rc != -ESTALE) {
			fprintf(stderr,
				"binding publication: inventory=%d "
				"generation=%" PRIu64 "/%" PRIu64
				" count=%u/%u authorize=%d\n",
				inventory_rc, after.topology_generation,
				during_target.topology_generation,
				after.count, before.count, authorize_rc);
			return 627;
		}
	}
	sends = io_command_count;
	initialize_request(&request, UK_BLKREQ_WRITE, 0, 1,
			   backing_media, NULL, NULL);
	if (device->submit_one(device, device->_queue[0], &request) !=
		    -EACCES ||
	    io_command_count != sends)
		return 628;
	writes10 = write10_command_count;
	writes16 = write16_command_count;
	flushes = flush_command_count;
	if (hyperv_acceptance_persistence_main() !=
		    HYPERV_ACCEPTANCE_FAIL ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 629;
	return 0;
}

static int persistence_expect_no_write_failure(
	struct vmbus_driver *driver, struct vmbus_device *device)
{
	char output[8192];
	unsigned int writes10 = write10_command_count;
	unsigned int writes16 = write16_command_count;
	unsigned int flushes = flush_command_count;
	int result;
	int rc;

	hyperv_acceptance_persistence_host_reset();
	device->present = 1;
	rc = driver->add_dev(device);
	if (rc)
		return rc;
	rc = capture_persistence_output(
		output, sizeof(output), &result);
	if (persistence_remove_device(driver, device))
		return -ETIMEDOUT;
	if (rc || result != HYPERV_ACCEPTANCE_FAIL ||
	    persistence_log_has_unavailable(output) ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return -EIO;
	return 0;
}

static int run_persistence_workflow_regression(
	struct vmbus_driver *driver, struct vmbus_device *primary,
	unsigned int identity_policy)
{
	char output[8192];
	struct vmbus_device secondary = {
		.channel_id = 47,
		.connection_id = 147,
		.instance_id = {
			.bytes = { 2, 1, 2, 3, 4, 5, 6, 7,
				   8, 9, 10, 11, 12, 13, 14, 15 },
		},
		.present = 1,
	};
	unsigned int writes10;
	unsigned int writes16;
	unsigned int flushes;
	unsigned int commands;
	uint8_t saved_intent;
	uint8_t saved_receipt;
	uint8_t saved_receipt_sector[
		HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	int result;
	int rc;

	storvsc_host_set_guarded_io(1);
	storvsc_host_set_lun_discovery(1);
	report_luns_mode = REPORT_LUNS_NORMAL;
	topology_fixture = 0;
	vpd_mode = VPD_NORMAL;
	read_only_media = 0;
	use_capacity16 = 0;
	backing_media_enabled = 1;
	hold_io = 0;
	pending_count = 0;
	persistence_hook_mode = PERSISTENCE_HOOK_NONE;
	persistence_hook_fired = 0;
	persistence_hook_end_error = 0;
	persistence_hook_timeouts = 0;
	hyperv_acceptance_persistence_host_reset();
	hyperv_acceptance_persistence_host_set_identity_policy(identity_policy);
	if (hyperv_acceptance_persistence_host_mapping_in_scope(
		    HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_ADDRESS_V1,
		    4, 5, 0, 1000, 512) ||
	    !hyperv_acceptance_persistence_host_mapping_in_scope(
		    HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2,
		    4, 5, 0, 1000, 512) ||
	    hyperv_acceptance_persistence_host_mapping_in_scope(
		    identity_policy, 0, 0, 1, 1000, 512) ||
	    hyperv_acceptance_persistence_host_mapping_in_scope(
		    identity_policy, 0, 0, 0, 999, 512))
		return 643;
	if (persistence_prepare_seed(
		    identity_policy, 0, 1000, 0, 0))
		return 600;
	primary->present = 1;
	if (driver->add_dev(primary))
		return 601;
	writes10 = write10_command_count;
	writes16 = write16_command_count;
	flushes = flush_command_count;
	rc = capture_persistence_output(
		output, sizeof(output), &result);
	if (rc || result != HYPERV_ACCEPTANCE_PASS ||
	    persistence_log_has_unavailable(output) ||
	    persistence_log_line_count(
		    output, "HYPERV_PERSISTENCE BOOT1_WRITE PASS ", 1) != 1 ||
	    persistence_log_line_count(
		    output, "UK_HYPERV_PERSISTENCE_BOOT1_COMPLETE:", 1) != 1 ||
	    persistence_log_line_count(
		    output, "UK_HYPERV_PERSISTENCE_IDENTITY:1:", 1) != 1 ||
	    write10_command_count <= writes10 ||
	    write16_command_count <= writes16 ||
	    flush_command_count <= flushes)
		return 602;
	writes10 = write10_command_count;
	writes16 = write16_command_count;
	flushes = flush_command_count;
	rc = capture_persistence_output(
		output, sizeof(output), &result);
	if (rc || result != HYPERV_ACCEPTANCE_PASS ||
	    persistence_log_has_unavailable(output) ||
	    persistence_log_line_count(
		    output, "HYPERV_PERSISTENCE BOOT2_READ PASS ", 1) != 1 ||
	    persistence_log_line_count(
		    output, "UK_HYPERV_PERSISTENCE_BOOT2_COMPLETE:", 1) != 1 ||
	    persistence_log_line_count(
		    output, "HYPERV_PERSISTENCE BOOT1_", 1) ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 603;
	saved_receipt =
		backing_media[HYPERV_ACCEPTANCE_PERSISTENCE_RECEIPT_LBA *
			      512 + 40];
	backing_media[HYPERV_ACCEPTANCE_PERSISTENCE_RECEIPT_LBA * 512 +
		      40] ^= 0x80;
	rc = hyperv_acceptance_persistence_main();
	if (rc != HYPERV_ACCEPTANCE_FAIL ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 604;
	backing_media[HYPERV_ACCEPTANCE_PERSISTENCE_RECEIPT_LBA * 512 +
		      40] = saved_receipt;
	saved_intent =
		backing_media[HYPERV_ACCEPTANCE_PERSISTENCE_INTENT_LBA *
			      512 + 80];
	backing_media[HYPERV_ACCEPTANCE_PERSISTENCE_INTENT_LBA * 512 +
		      80] ^= 0x40;
	rc = hyperv_acceptance_persistence_main();
	if (rc != HYPERV_ACCEPTANCE_FAIL ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 630;
	backing_media[HYPERV_ACCEPTANCE_PERSISTENCE_INTENT_LBA * 512 +
		      80] = saved_intent;
	memcpy(saved_receipt_sector,
	       backing_media +
		       HYPERV_ACCEPTANCE_PERSISTENCE_RECEIPT_LBA * 512,
	       sizeof(saved_receipt_sector));
	memset(backing_media +
		       HYPERV_ACCEPTANCE_PERSISTENCE_RECEIPT_LBA * 512,
	       0, HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	rc = hyperv_acceptance_persistence_main();
	if (rc != HYPERV_ACCEPTANCE_FAIL ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 631;
	memcpy(backing_media +
		       HYPERV_ACCEPTANCE_PERSISTENCE_RECEIPT_LBA * 512,
	       saved_receipt_sector, sizeof(saved_receipt_sector));
	if (persistence_remove_device(driver, primary))
		return 644;

	if (identity_policy ==
	    HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2) {
		vpd_variant = 1;
		rc = persistence_expect_no_write_failure(driver, primary);
		vpd_variant = 0;
		if (rc)
			return 633;

		if (persistence_prepare_seed(
			    HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_ADDRESS_V1,
			    0, 1000, 0, 0) ||
		    persistence_expect_no_write_failure(driver, primary))
			return 634;
		if (persistence_prepare_seed(
			    identity_policy, 0, 1000, 0, 1) ||
		    persistence_expect_no_write_failure(driver, primary))
			return 635;
		if (persistence_prepare_seed(
			    identity_policy, 0, 999, 0, 0) ||
		    persistence_expect_no_write_failure(driver, primary))
			return 636;
		if (persistence_prepare_seed(
			    identity_policy, 0, 1000, 1, 0) ||
		    persistence_expect_no_write_failure(driver, primary))
			return 637;
		if (persistence_prepare_seed(
			    identity_policy, 1, 1000, 0, 0) ||
		    persistence_expect_no_write_failure(driver, primary))
			return 638;
		if (persistence_prepare_seed(
			    identity_policy, 0, 1000, 0, 0))
			return 639;
		vpd_mode = VPD_UNSUPPORTED;
		rc = persistence_expect_no_write_failure(driver, primary);
		vpd_mode = VPD_NORMAL;
		if (rc)
			return 640;
		if (persistence_prepare_seed(
			    identity_policy, 0, 1000, 0, 0))
			return 641;
		read_only_media = 1;
		rc = persistence_expect_no_write_failure(driver, primary);
		read_only_media = 0;
		if (rc)
			return 642;
		rc = run_unresolved_discovery_case(
			driver, primary, &secondary,
			UNRESOLVED_DISCOVERY_VPD, 1);
		if (rc)
			return rc;
		rc = run_unresolved_discovery_case(
			driver, primary, &secondary,
			UNRESOLVED_DISCOVERY_INQUIRY, 0);
		if (rc)
			return rc;
		rc = run_unresolved_discovery_case(
			driver, primary, &secondary,
			UNRESOLVED_DISCOVERY_CAPACITY, 0);
		if (rc)
			return rc;
		rc = run_unresolved_discovery_case(
			driver, primary, &secondary,
			UNRESOLVED_DISCOVERY_REGISTRATION, 0);
		if (rc)
			return rc;
		rc = run_unresolved_discovery_case(
			driver, primary, &secondary,
			UNRESOLVED_DISCOVERY_ALL_VPD, 1);
		if (rc)
			return rc;
	}

	hyperv_acceptance_persistence_host_reset();
	if (persistence_prepare_seed(
		    identity_policy, 0, 1000, 0, 0))
		return 617;
	primary->present = 1;
	if (driver->add_dev(primary))
		return 618;
	secondary.present = 1;
	rc = run_binding_publication_regression(driver, &secondary);
	if (rc)
		return rc;
	rc = persistence_remove_device(driver, &secondary);
	if (persistence_remove_device(driver, primary) || rc)
		return 645;

	hyperv_acceptance_persistence_host_reset();
	if (persistence_prepare_seed(
		    identity_policy, 0, 1000, 0, 0))
		return 605;
	primary->present = 1;
	if (driver->add_dev(primary))
		return 606;
	persistence_hook_driver = driver;
	persistence_hook_device = &secondary;
	persistence_hook_mode = PERSISTENCE_HOOK_ADD_BEFORE_REVALIDATE;
	persistence_hook_fired = 0;
	persistence_hook_end_error = 0;
	writes10 = write10_command_count;
	writes16 = write16_command_count;
	flushes = flush_command_count;
	rc = hyperv_acceptance_persistence_main();
	if (rc != HYPERV_ACCEPTANCE_FAIL || !persistence_hook_fired ||
	    persistence_hook_end_error != -ESTALE ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 607;
	rc = persistence_remove_device(driver, &secondary);
	if (persistence_remove_device(driver, primary) || rc)
		return 646;

	hyperv_acceptance_persistence_host_reset();
	if (persistence_prepare_seed(
		    identity_policy, 1, 1000, 0, 0))
		return 608;
	primary->present = 1;
	if (driver->add_dev(primary))
		return 609;
	secondary.present = 1;
	persistence_hook_mode = PERSISTENCE_HOOK_ADD_BEFORE_REJECT_END;
	persistence_hook_fired = 0;
	persistence_hook_end_error = 0;
	writes10 = write10_command_count;
	writes16 = write16_command_count;
	flushes = flush_command_count;
	rc = hyperv_acceptance_persistence_main();
	if (rc != HYPERV_ACCEPTANCE_FAIL || !persistence_hook_fired ||
	    persistence_hook_end_error != -ESTALE ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 610;
	rc = persistence_remove_device(driver, &secondary);
	if (persistence_remove_device(driver, primary) || rc)
		return 647;

	hyperv_acceptance_persistence_host_reset();
	if (persistence_prepare_seed(
		    identity_policy, 0, 1000, 0, 0))
		return 611;
	primary->present = 1;
	if (driver->add_dev(primary))
		return 612;
	persistence_hook_mode = PERSISTENCE_HOOK_NONE;
	persistence_hook_fired = 0;
	persistence_hook_end_error = 0;
	persistence_hook_timeouts = 0;
	hold_io = 1;
	pending_count = 0;
	writes10 = write10_command_count;
	writes16 = write16_command_count;
	flushes = flush_command_count;
	rc = hyperv_acceptance_persistence_main();
	if (rc != HYPERV_ACCEPTANCE_FAIL || pending_count != 1 ||
	    persistence_hook_timeouts != 1 ||
	    persistence_hook_end_error != -EBUSY ||
	    !hyperv_acceptance_persistence_host_request_owned() ||
	    hyperv_acceptance_persistence_host_request_done() ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 613;
	commands = io_command_count;
	if (hyperv_acceptance_persistence_main() != HYPERV_ACCEPTANCE_FAIL ||
	    io_command_count != commands)
		return 614;
	complete_pending(2);
	pending_count = 0;
	fire_channel_on(primary->channel);
	if (!hyperv_acceptance_persistence_host_request_owned() ||
	    !hyperv_acceptance_persistence_host_request_done())
		return 615;
	commands = io_command_count;
	if (hyperv_acceptance_persistence_main() != HYPERV_ACCEPTANCE_FAIL ||
	    io_command_count != commands)
		return 616;
	hold_io = 0;
	hyperv_acceptance_persistence_host_reset();
	if (persistence_remove_device(driver, primary))
		return 648;

	persistence_hook_driver = NULL;
	persistence_hook_device = NULL;
	persistence_hook_mode = PERSISTENCE_HOOK_NONE;
	hyperv_acceptance_persistence_host_set_identity_policy(0);
	backing_media_enabled = 0;
	storvsc_host_set_guarded_io(0);
	return 0;
}

static int persistence_unavailable_log_valid(const char *output)
{
	return persistence_log_line_count(
		       output,
		       "HYPERV_PERSISTENCE SELECT UNAVAILABLE "
		       "reason=no-devices writes=0 flushes=0", 0) == 1 &&
	       persistence_log_line_count(
		       output, "HYPERV_PERSISTENCE SELECT UNAVAILABLE ", 1) ==
		       1 &&
	       persistence_log_line_count(
		       output, "UK_HYPERV_PLATFORM_READY", 0) == 1 &&
	       persistence_log_line_count(
		       output,
		       "UK_HYPERV_PERSISTENCE_UNAVAILABLE:1:2:no-devices",
		       0) == 1 &&
	       persistence_log_line_count(
		       output, "UK_HYPERV_PERSISTENCE_UNAVAILABLE:", 1) == 1 &&
	       !persistence_log_line_count(
		       output, "HYPERV_PERSISTENCE SELECT FAIL", 1) &&
	       !persistence_log_line_count(
		       output, "HYPERV_PERSISTENCE FINAL PASS", 1) &&
	       !persistence_log_line_count(
		       output, "UK_HYPERV_PERSISTENCE_IDENTITY:", 1) &&
	       !persistence_log_line_count(
		       output, "HYPERV_PERSISTENCE BOOT1_", 1) &&
	       !persistence_log_line_count(
		       output, "HYPERV_PERSISTENCE BOOT2_", 1) &&
	       !persistence_log_line_count(
		       output, "UK_HYPERV_PERSISTENCE_BOOT1_", 1) &&
	       !persistence_log_line_count(
		       output, "UK_HYPERV_PERSISTENCE_BOOT2_", 1);
}

static int run_persistence_unavailable_regression(
	struct vmbus_driver *driver, struct vmbus_device *device)
{
	char output[8192];
	struct uk_storvsc_inventory_snapshot inventory;
	unsigned int writes10 = write10_command_count;
	unsigned int writes16 = write16_command_count;
	unsigned int flushes = flush_command_count;
	int result;
	int rc;

	storvsc_host_set_guarded_io(1);
	hyperv_acceptance_persistence_host_reset();
	hyperv_acceptance_persistence_host_set_identity_policy(
		HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2);
	rc = capture_persistence_output(output, sizeof(output), &result);
	if (rc || result != HYPERV_ACCEPTANCE_UNAVAILABLE ||
	    !persistence_unavailable_log_valid(output) ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 690;

	hyperv_acceptance_persistence_host_reset();
	hyperv_acceptance_persistence_host_set_identity_policy(
		HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_ADDRESS_V1);
	rc = capture_persistence_output(output, sizeof(output), &result);
	if (rc || result != HYPERV_ACCEPTANCE_FAIL ||
	    persistence_log_has_unavailable(output) ||
	    persistence_log_line_count(
		    output, "HYPERV_PERSISTENCE SELECT FAIL", 1) != 1 ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 691;

	hyperv_acceptance_persistence_host_reset();
	hyperv_acceptance_persistence_host_set_identity_policy(3);
	rc = capture_persistence_output(output, sizeof(output), &result);
	if (rc || result != HYPERV_ACCEPTANCE_FAIL ||
	    persistence_log_has_unavailable(output) ||
	    persistence_log_line_count(
		    output,
		    "HYPERV_PERSISTENCE FINAL FAIL "
		    "reason=invalid-expectation", 0) != 1)
		return 692;

	if (vmbus_storage_offer_lifetime_observed() ||
	    vmbus_bus_host_reject_storage_wire(
		    driver, &device->instance_id, 690, 1690) ||
	    !vmbus_storage_offer_lifetime_observed() ||
	    uk_storvsc_inventory_get(&inventory) || inventory.count ||
	    inventory.topology_generation !=
		    UK_STORVSC_TOPOLOGY_PRISTINE_GENERATION)
		return 697;
	hyperv_acceptance_persistence_host_reset();
	hyperv_acceptance_persistence_host_set_identity_policy(
		HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2);
	rc = capture_persistence_output(output, sizeof(output), &result);
	if (rc || result != HYPERV_ACCEPTANCE_FAIL ||
	    persistence_log_has_unavailable(output) ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 698;

	if (vmbus_bus_host_offer_lifetime_setup(driver) ||
	    vmbus_bus_host_fill_nonstorage_offers(700) ||
	    vmbus_bus_host_offer_storage(&device->instance_id, 900, 1000) !=
		    -ENOSPC)
		return 699;
	hyperv_acceptance_persistence_host_reset();
	hyperv_acceptance_persistence_host_set_identity_policy(
		HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2);
	rc = capture_persistence_output(output, sizeof(output), &result);
	if (rc || result != HYPERV_ACCEPTANCE_FAIL ||
	    persistence_log_has_unavailable(output) ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 700;

	hyperv_acceptance_persistence_host_reset();
	hyperv_acceptance_persistence_host_set_identity_policy(
		HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2);
	report_luns_mode = REPORT_LUNS_NORMAL;
	vpd_mode = VPD_NORMAL;
	storvsc_host_set_lun_discovery(1);
	persistence_hook_driver = driver;
	persistence_hook_device = device;
	persistence_hook_mode = PERSISTENCE_HOOK_ADD_BEFORE_REVALIDATE;
	persistence_hook_fired = 0;
	rc = capture_persistence_output(output, sizeof(output), &result);
	persistence_hook_mode = PERSISTENCE_HOOK_NONE;
	if (rc || result != HYPERV_ACCEPTANCE_FAIL ||
	    !persistence_hook_fired ||
	    persistence_log_has_unavailable(output) ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 693;
	if (persistence_remove_device(driver, device))
		return 701;

	hyperv_acceptance_persistence_host_reset();
	rc = capture_persistence_output(output, sizeof(output), &result);
	if (rc || result != HYPERV_ACCEPTANCE_FAIL ||
	    persistence_log_has_unavailable(output) ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 694;

	hyperv_acceptance_persistence_host_reset();
	vpd_mode = VPD_MALFORMED;
	device->present = 1;
	rc = driver->add_dev(device);
	vpd_mode = VPD_NORMAL;
	if (rc != -EPROTO)
		return 695;
	rc = capture_persistence_output(output, sizeof(output), &result);
	if (rc || result != HYPERV_ACCEPTANCE_FAIL ||
	    persistence_log_has_unavailable(output) ||
	    write10_command_count != writes10 ||
	    write16_command_count != writes16 ||
	    flush_command_count != flushes)
		return 696;
	if (persistence_remove_device(driver, device))
		return 702;

	persistence_hook_driver = NULL;
	persistence_hook_device = NULL;
	persistence_hook_mode = PERSISTENCE_HOOK_NONE;
	hyperv_acceptance_persistence_host_set_identity_policy(0);
	hyperv_acceptance_persistence_host_reset();
	storvsc_host_set_lun_discovery(0);
	storvsc_host_set_guarded_io(0);
	report_luns_commands = 0;
	vpd_commands = 0;
	invalid_scsi_address = 0;
	return 0;
}

static int storvsc_production_test(void)
{
	struct vmbus_driver *driver = storvsc_host_driver();
	struct vmbus_device vmbus_device = {
		.channel_id = 37,
		.connection_id = 137,
		.instance_id = {
			.bytes = { 1, 1, 2, 3, 4, 5, 6, 7,
				   8, 9, 10, 11, 12, 13, 14, 15 },
		},
		.present = 1,
	};
	struct uk_blkdev *device;
	struct uk_blkreq request;
	struct uk_blkreq request2;
	struct uk_blkreq request3;
	struct storvsc_address address;
	struct reentry_context reentry;
	atomic_int callbacks;
	uint8_t *buffer;
	int events = 0;
	int rc;

	if (!driver || memcmp(driver->device_ids[0].class_id.bytes,
	    (uint8_t[]){ 0xba, 0x61, 0x63, 0xd9, 0x04, 0xa1, 0x4d, 0x29,
			 0xb6, 0x05, 0x72, 0xe2, 0xff, 0xb1, 0xdc, 0x7f },
	    16))
		return 1;
	rc = run_persistence_unavailable_regression(
		driver, &vmbus_device);
	if (rc)
		return rc;
	if (vmbus_bus_host_connection_begin())
		return 2;
	report_luns_mode = REPORT_LUNS_TRUNCATED;
	rc = driver->add_dev(&vmbus_device);
	report_luns_mode = REPORT_LUNS_NORMAL;
	if (rc)
		return 3;
	device = storvsc_host_blkdev();
	if (!device || device->capabilities.sectors != 1000 ||
	    device->capabilities.ssize != 512 ||
	    device->capabilities.mode != O_RDWR ||
	    device->capabilities.max_sectors_per_req != 56)
		return 3;
	if (report_luns_commands || vpd_commands || invalid_scsi_address ||
	    storvsc_host_lun_count() != 1 ||
	    storvsc_host_lun_address(0, &address) ||
	    address.path_id || address.target_id || address.lun)
		return 3;
	if (configure_device(device, 2, &events))
		return 4;
	enqueue_enumerate_bus(vmbus_device.channel);
	fire_channel();
	if (!storvsc_host_online())
		return 4;
	if (posix_memalign((void **)&buffer, 4096, 3 * 4096))
		return 5;

	atomic_init(&callbacks, 0);
	initialize_request(&request, UK_BLKREQ_READ, 0, 16, buffer,
			   request_done, &callbacks);
	if (submit_and_fire(device, &request) || request.result ||
	    atomic_load(&callbacks) != 1 || buffer[0] != 0x5a ||
	    last_pfn_count < 2 || last_pfns[1] == last_pfns[0] + 1)
		return 6;
	alternate_completion_size = 1;
	initialize_request(&request, UK_BLKREQ_READ, 999, 1, buffer,
			   request_done, &callbacks);
	if (submit_and_fire(device, &request) || request.result) {
		alternate_completion_size = 0;
		return 7;
	}
	alternate_completion_size = 0;
	initialize_request(&request, UK_BLKREQ_READ, 1000, 1, buffer,
			   request_done, &callbacks);
	if (device->submit_one(device, device->_queue[0], &request) !=
	    -EINVAL)
		return 8;
	initialize_request(&request, UK_BLKREQ_READ, 0, 1, buffer + 1,
			   request_done, &callbacks);
	if (device->submit_one(device, device->_queue[0], &request) !=
	    -EINVAL)
		return 9;

	short_transfer_once = 1;
	initialize_request(&request, UK_BLKREQ_READ, 1, 1, buffer,
			   request_done, &callbacks);
	if (submit_and_fire(device, &request) || request.result != -EIO)
		return 10;
	initialize_request(&request, UK_BLKREQ_FFLUSH, 0, 0, NULL,
			   request_done, &callbacks);
	rc = submit_and_fire(device, &request);
	if (rc || request.result)
		return 11;
	io_packet_error_once = 1;
	initialize_request(&request, UK_BLKREQ_FFLUSH, 0, 0, NULL,
			   request_done, &callbacks);
	if (submit_and_fire(device, &request) || request.result != -EIO)
		return 12;

	hold_io = 1;
	initialize_request(&request, UK_BLKREQ_READ, 2, 1, buffer,
			   request_done, &callbacks);
	initialize_request(&request2, UK_BLKREQ_READ, 3, 1, buffer + 512,
			   request_done, &callbacks);
	initialize_request(&request3, UK_BLKREQ_READ, 4, 1, buffer + 1024,
			   request_done, &callbacks);
	if (!(device->submit_one(device, device->_queue[0], &request) &
	      UK_BLKDEV_STATUS_SUCCESS) ||
	    !(device->submit_one(device, device->_queue[0], &request2) &
	      UK_BLKDEV_STATUS_SUCCESS) ||
	    device->submit_one(device, device->_queue[0], &request3) !=
	      -ENOSPC)
		return 13;
	enqueue_completion(last_io_id + 999, 64, 0, 1, 0, last_io_length);
	complete_pending(1);
	fire_channel();
	if (request.result || request2.result ||
	    atomic_load(&callbacks) != 7)
		return 14;
	hold_io = 0;

	publish_error_once = 1;
	initialize_request(&request, UK_BLKREQ_READ, 5, 1, buffer,
			   request_done, &callbacks);
	rc = device->submit_one(device, device->_queue[0], &request);
	if (!(rc & UK_BLKDEV_STATUS_SUCCESS))
		return 15;
	fire_channel();
	if (request.result)
		return 16;

	initialize_request(&request2, UK_BLKREQ_READ, 7, 1, buffer + 512,
			   request_done, &callbacks);
	memset(&reentry, 0, sizeof(reentry));
	reentry.device = device;
	reentry.next = &request2;
	atomic_init(&reentry.callbacks, 0);
	initialize_request(&request, UK_BLKREQ_READ, 6, 1, buffer,
			   reentry_done, &reentry);
	if (submit_and_fire(device, &request) ||
	    reentry.nested_finish_result ||
	    !(reentry.submit_result & UK_BLKDEV_STATUS_SUCCESS))
		return 17;
	fire_channel();
	if (request2.result || atomic_load(&reentry.callbacks) != 1)
		return 18;

	storvsc_host_stop_timeout_worker();
	rc = run_reset_send_race(device, buffer, RACE_PAUSE_BEFORE_PFNS,
				 20, 100);
	if (rc)
		return rc;
	rc = run_reset_send_race(device, buffer,
				 RACE_PAUSE_DURING_VMBUS_COPY, 40, 120);
	if (rc)
		return rc;
	if (storvsc_host_start_timeout_worker())
		return 19;

	rc = run_terminal_reset_quiesce(device, buffer, 0, 140);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 154;
	rc = run_terminal_reset_quiesce(device, buffer, 1, 160);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 174;
	rc = run_terminal_remove_quiesce(driver, &vmbus_device, device,
					 buffer, 0, 180);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 190;
	rc = run_terminal_remove_quiesce(driver, &vmbus_device, device,
					 buffer, 1, 200);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 210;
	rc = run_close_failure_case(driver, &vmbus_device, device, buffer,
				    -EBUSY, 1, 0, 1, 220);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 223;
	{
		const int close_errors[] = {
			-ETIMEDOUT, -EIO, -EPROTO, -ENOSPC, -EBUSY,
		};

		for (unsigned int i = 0;
		     i < sizeof(close_errors) / sizeof(close_errors[0]); i++) {
			rc = run_close_failure_case(
				driver, &vmbus_device, device, buffer,
				close_errors[i],
				close_errors[i] == -EBUSY ? 32 : 1,
				0, 0, 230 + (int)i * 10);
			if (rc)
				return rc;
			if (reoffer_device(driver, &vmbus_device, device))
				return 280 + (int)i;
		}
	}
	rc = run_close_failure_case(driver, &vmbus_device, device, buffer,
				    -EPROTO, 1, 1, 0, 290);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 300;
	rc = run_close_remove_window(
		driver, &vmbus_device, device, buffer, 301);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 306;
	rc = run_busy_remove_upgrade(
		driver, &vmbus_device, device, buffer, 0, 360);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 368;
	rc = run_busy_remove_upgrade(
		driver, &vmbus_device, device, buffer, 1, 370);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 378;
	rc = run_busy_retry_bound(
		&vmbus_device, device, buffer, 380);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 386;
	rc = run_deferred_epoch_refresh(device, buffer, 410);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 420;
	rc = run_integrated_remove_unload(
		driver, &vmbus_device, device, buffer, 1, 390);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 396;
	rc = run_integrated_remove_unload(
		driver, &vmbus_device, device, buffer, 0, 400);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 408;
	rc = run_completion_preservation(
		driver, &vmbus_device, device, buffer,
		PRESERVE_RESET, 0, 310);
	if (rc)
		return rc;
	rc = run_completion_preservation(
		driver, &vmbus_device, device, buffer,
		PRESERVE_FATAL, 1, 320);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 330;
	rc = run_completion_preservation(
		driver, &vmbus_device, device, buffer,
		PRESERVE_REMOVE, 0, 340);
	if (rc)
		return rc;
	if (reoffer_device(driver, &vmbus_device, device))
		return 350;

	hold_io = 1;
	initialize_request(&request, UK_BLKREQ_READ, 8, 1, buffer,
			   request_done, &callbacks);
	if (!(device->submit_one(device, device->_queue[0], &request) &
	      UK_BLKDEV_STATUS_SUCCESS))
		return 20;
	if (wait_request_completion(&request, &callbacks, 10, 1000) ||
	    request.result != -ETIMEDOUT)
		return 21;
	enqueue_completion(last_io_id, 64, 0, 1, 0, last_io_length);
	pending_count = 0;
	fire_channel();
	if (atomic_load(&callbacks) != 10)
		return 22;
	hold_io = 0;

	hold_io = 1;
	initialize_request(&request, UK_BLKREQ_READ, 9, 1, buffer,
			   request_done, &callbacks);
	if (!(device->submit_one(device, device->_queue[0], &request) &
	      UK_BLKDEV_STATUS_SUCCESS))
		return 23;
	remove_test_offer(driver, &vmbus_device);
	if (request.result != -ENODEV ||
	    atomic_load(&request.state.counter) != UK_BLKREQ_FINISHED)
		return 24;
	if (vmbus_device.channel)
		(void)vmbus_channel_close(vmbus_device.channel);
	pending_count = 0;
	hold_io = 0;

	if (report_luns_commands)
		return 25;
	storvsc_host_set_lun_discovery(1);
	vmbus_device.present = 1;
	read_only_media = 1;
	use_capacity16 = 1;
	reject_versions = 3;
	reject_mode_sense6 = 1;
	alternate_completion_size = 1;
	rc = driver->add_dev(&vmbus_device);
	alternate_completion_size = 0;
	if (rc || device->capabilities.mode != O_RDONLY ||
	    device->capabilities.sectors != 0x100000101ULL)
		return 25;
	if (report_luns_commands != 1 || vpd_commands != 3 ||
	    storvsc_host_lun_count() != 3)
		return 25;
	for (size_t i = 0; i < 3; i++) {
		if (storvsc_host_lun_address(i, &address) ||
		    address.path_id || address.target_id ||
		    address.lun != (uint8_t[]){ 0, 3, 7 }[i] ||
		    address.reserved)
			return 25;
	}
	initialize_request(&request, UK_BLKREQ_WRITE, 0, 1, buffer,
			   request_done, &callbacks);
	if (device->submit_one(device, device->_queue[0], &request) !=
	    -EROFS)
		return 26;
	remove_test_offer(driver, &vmbus_device);
	if (vmbus_device.channel)
		(void)vmbus_channel_close(vmbus_device.channel);

	read_only_media = 0;
	use_capacity16 = 0;
	reject_mode_sense6 = CONFIG_LIBSTORVSC_MAX_LUNS;
	reject_mode_sense10 = CONFIG_LIBSTORVSC_MAX_LUNS;
	vmbus_device.present = 1;
	rc = driver->add_dev(&vmbus_device);
	if (rc != -EINVAL || vmbus_device.channel)
		return 27;

	report_luns_mode = REPORT_LUNS_EMPTY;
	vmbus_device.present = 1;
	rc = driver->add_dev(&vmbus_device);
	if (rc != -ENODEV || vmbus_device.channel)
		return 421;

	report_luns_mode = REPORT_LUNS_TRUNCATED;
	vmbus_device.present = 1;
	rc = driver->add_dev(&vmbus_device);
	if (rc != -EPROTO || vmbus_device.channel)
		return 422;

	report_luns_mode = REPORT_LUNS_CAPACITY;
	vmbus_device.present = 1;
	rc = driver->add_dev(&vmbus_device);
	if (rc != -ENOSPC || vmbus_device.channel)
		return 423;

	report_luns_mode = REPORT_LUNS_NO_ZERO;
	vmbus_device.present = 1;
	rc = driver->add_dev(&vmbus_device);
	if (rc || !vmbus_device.channel || storvsc_host_lun_count() != 2)
		return 424;
	remove_test_offer(driver, &vmbus_device);
	if (vmbus_device.channel)
		(void)vmbus_channel_close(vmbus_device.channel);

	report_luns_mode = REPORT_LUNS_NORMAL;
	malformed_handshake = 1;
	vmbus_device.present = 1;
	rc = driver->add_dev(&vmbus_device);
	if (rc != -EPROTO || vmbus_device.channel || close_count < 2)
		return 28;
	remove_test_offer(driver, &vmbus_device);
	if (invalid_scsi_address)
		return 425;
	rc = run_topology_regression(driver, &vmbus_device, buffer, &events);
	if (rc)
		return rc;
	if (unregister_calls)
		return 67;
	rc = run_guarded_io_regression(
		driver, &vmbus_device, buffer, &events);
	if (rc)
		return rc;
	rc = run_persistence_workflow_regression(
		driver, &vmbus_device,
		HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_ADDRESS_V1);
	if (rc)
		return rc;
	rc = run_persistence_workflow_regression(
		driver, &vmbus_device,
		HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2);
	if (rc)
		return rc;
	rc = run_vmbus_offer_lifetime_regression(
		driver, &vmbus_device, buffer);
	if (rc)
		return rc;

	free(buffer);
	return 0;
}

int main(void)
{
	int rc = storvsc_production_test();

	if (rc)
		fprintf(stderr, "storvsc-production-test failed: rc=%d\n", rc);
	return rc;
}
