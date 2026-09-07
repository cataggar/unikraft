/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <uk/alloc.h>
#include <uk/blkdev.h>
#include <uk/blkdev_driver.h>
#include <uk/config.h>
#include <uk/paging.h>
#include <uk/sched.h>
#include <uk/thread.h>
#include <uk/vmbus.h>

struct vmbus_driver *storvsc_host_driver(void);
struct uk_blkdev *storvsc_host_blkdev(void);
int storvsc_host_receive(void);

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
	uint64_t id;
	uint32_t length;
};

static struct uk_alloc host_allocator;
static struct uk_sched host_scheduler;
static struct uk_thread main_thread;
static _Thread_local struct uk_thread *current_thread = &main_thread;
static struct vmbus_channel host_channel;
static pthread_mutex_t packet_lock = PTHREAD_MUTEX_INITIALIZER;
static struct host_packet packets[128];
static unsigned int packet_head;
static unsigned int packet_tail;
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
static int hold_io;
static int short_transfer_once;
static int io_packet_error_once;
static int publish_error_once;
static uint64_t last_io_id;
static uint32_t last_io_length;
static uint32_t last_pfn_count;
static uint64_t last_pfns[64];
static unsigned int close_count;

static uint32_t get_le32(const uint8_t *bytes, size_t offset)
{
	return (uint32_t)bytes[offset] |
		((uint32_t)bytes[offset + 1] << 8) |
		((uint32_t)bytes[offset + 2] << 16) |
		((uint32_t)bytes[offset + 3] << 24);
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

static void put_be64(uint8_t *bytes, size_t offset, uint64_t value)
{
	for (unsigned int i = 0; i < 8; i++)
		bytes[offset + i] = (uint8_t)(value >> ((7 - i) * 8));
}

static void enqueue_packet(uint64_t id, const uint8_t *payload,
			   uint32_t length)
{
	struct host_packet *packet;

	pthread_mutex_lock(&packet_lock);
	if (packet_tail - packet_head >= 128)
		abort();
	packet = &packets[packet_tail++ % 128];
	memset(packet, 0, sizeof(*packet));
	packet->id = id;
	packet->length = length;
	packet->type = VMBUS_PACKET_COMPLETION;
	memcpy(packet->payload, payload, length);
	pthread_mutex_unlock(&packet_lock);
}

static void enqueue_completion(uint64_t id, uint32_t packet_length,
			       uint32_t packet_status, uint8_t srb_status,
			       uint8_t scsi_status, uint32_t transferred)
{
	uint8_t packet[64] = { 0 };

	put_le32(packet, 0, 1);
	put_le32(packet, 8, packet_status);
	packet[14] = srb_status;
	packet[15] = scsi_status;
	put_le32(packet, 24, transferred);
	enqueue_packet(id, packet, packet_length);
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

static void fill_read_data(const struct vmbus_gpa_range *range,
			   uint32_t length)
{
	uint8_t *data = malloc(length);

	if (!data)
		abort();
	for (uint32_t i = 0; i < length; i++)
		data[i] = (uint8_t)(i ^ 0x5a);
	range_write(range, data, length);
	free(data);
}

static void handle_scsi(uint64_t id, const struct vmbus_gpa_range *range,
			const uint8_t *payload, uint32_t packet_length)
{
	uint8_t opcode = payload[28];
	uint32_t transfer = get_le32(payload, 24);
	uint8_t data[192] = { 0 };
	uint32_t response_transfer = transfer;

	switch (opcode) {
	case 0x12:
		data[0] = 0;
		data[2] = 5;
		data[3] = 2;
		data[4] = 91;
		memcpy(data + 8, "Msft    Virtual Disk    ", 24);
		range_write(range, data, transfer);
		break;
	case 0x00:
		break;
	case 0x25:
		if (use_capacity16)
			put_be32(data, 0, UINT32_MAX);
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
			uint8_t packet[64] = { 0 };

			reject_mode_sense6 = 0;
			put_le32(packet, 0, 1);
			packet[14] = 0x84;
			packet[15] = 0x02;
			packet[21] = 14;
			packet[28] = 0x70;
			packet[30] = 0x05;
			packet[40] = 0x20;
			enqueue_packet(id, packet, packet_length);
			return;
		}
		data[0] = 3;
		data[2] = read_only_media ? 0x80 : 0;
		range_write(range, data, transfer);
		break;
	case 0x5a:
		data[1] = 6;
		data[3] = read_only_media ? 0x80 : 0;
		range_write(range, data, transfer);
		break;
	case 0x28:
	case 0x88:
		last_io_id = id;
		last_io_length = transfer;
		if (hold_io) {
			if (pending_count >= 32)
				abort();
			pending[pending_count++] = (struct pending_io){
				.id = id,
				.length = transfer,
			};
			return;
		}
		fill_read_data(range, transfer);
		if (short_transfer_once) {
			response_transfer--;
			short_transfer_once = 0;
		}
		break;
	case 0x2a:
	case 0x8a:
		last_io_id = id;
		last_io_length = transfer;
		if (hold_io) {
			pending[pending_count++] = (struct pending_io){
				.id = id,
				.length = transfer,
			};
			return;
		}
		break;
	case 0x35:
		last_io_id = id;
		last_io_length = 0;
		break;
	default:
		enqueue_completion(id, packet_length, 0, 0x86, 0x02, 0);
		return;
	}
	enqueue_completion(id, packet_length,
		io_packet_error_once ? (io_packet_error_once = 0, 1) : 0,
		1, 0, response_transfer);
}

static int handle_send(uint64_t id, const struct vmbus_gpa_range *range,
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
			enqueue_packet(id, response, 47);
			malformed_handshake = 0;
		} else {
			enqueue_packet(id, response, packet_length);
		}
		break;
	case 9:
		if (reject_versions > 0) {
			put_le32(response, 8, 1);
			reject_versions--;
		}
		enqueue_packet(id, response, packet_length);
		break;
	case 10:
		put_le32(response, 24, 128 * 1024);
		enqueue_packet(id, response, packet_length);
		break;
	case 8:
	case 6:
		enqueue_packet(id, response, packet_length);
		break;
	case 3:
		handle_scsi(id, range, payload, packet_length);
		break;
	default:
		put_le32(response, 8, 1);
		enqueue_packet(id, response, packet_length);
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
	if (!device || tx_pages < 2 || rx_pages < 2 ||
	    !user_data || user_data_size != 24)
		return -EINVAL;
	memset(&host_channel, 0, sizeof(host_channel));
	host_channel.device = device;
	host_channel.open = 1;
	device->channel = &host_channel;
	return 0;
}

int vmbus_channel_close(struct vmbus_channel *channel)
{
	if (!channel || !channel->open)
		return -ENODEV;
	channel->open = 0;
	channel->callback = NULL;
	if (channel->device)
		channel->device->channel = NULL;
	close_count++;
	return 0;
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
	return handle_send(id, NULL, payload, payload_size, published);
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
	memcpy(last_pfns, ranges[0].pfns,
	       last_pfn_count * sizeof(last_pfns[0]));
	return handle_send(id, &ranges[0], payload, payload_size, published);
}

int vmbus_channel_receive(struct vmbus_channel *channel,
			  struct vmbus_packet *packet, void *descriptor,
			  size_t descriptor_capacity, void *payload,
			  size_t payload_capacity)
{
	struct host_packet queued;

	(void)descriptor;
	(void)descriptor_capacity;
	if (!channel || !channel->open)
		return -ENODEV;
	pthread_mutex_lock(&packet_lock);
	if (packet_head == packet_tail) {
		pthread_mutex_unlock(&packet_lock);
		return -EAGAIN;
	}
	queued = packets[packet_head++ % 128];
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

	if (!channel || !channel->open)
		return -ENODEV;
	pthread_mutex_lock(&packet_lock);
	available = packet_head != packet_tail;
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
	if (!channel || !channel->open)
		return -ENODEV;
	channel->masked = 1;
	return 0;
}

int vmbus_channel_unmask_interrupts(struct vmbus_channel *channel)
{
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
	data->id = 0;
	data->state = UK_BLKDEV_UNCONFIGURED;
	data->drv_name = name;
	data->a = allocator;
	device->_data = data;
	return 0;
}

void uk_blkdev_drv_unregister(struct uk_blkdev *device)
{
	free(device->_data);
}

static void fire_channel(void)
{
	if (host_channel.callback)
		host_channel.callback(&host_channel, host_channel.callback_arg);
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

static void queue_event(struct uk_blkdev *device, uint16_t queue_id,
			void *cookie)
{
	int *events = cookie;

	(*events)++;
	if (device->finish_reqs(device, device->_queue[queue_id]))
		abort();
}

static int wait_finished(struct uk_blkreq *request, unsigned int limit_ms)
{
	for (unsigned int i = 0; i < limit_ms; i++) {
		if (atomic_load(&request->state.counter) ==
		    UK_BLKREQ_FINISHED)
			return 0;
		uk_sched_thread_sleep(1000000ULL);
	}
	return -ETIMEDOUT;
}

static void complete_pending(unsigned int duplicates)
{
	for (unsigned int i = 0; i < pending_count; i++) {
		enqueue_completion(pending[i].id, 64, 0, 1, 0,
				   pending[i].length);
		for (unsigned int duplicate = 0; duplicate < duplicates;
		     duplicate++)
			enqueue_completion(pending[i].id, 64, 0, 1, 0,
					   pending[i].length);
	}
	pending_count = 0;
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

int main(void)
{
	struct vmbus_driver *driver = storvsc_host_driver();
	struct vmbus_device vmbus_device = {
		.channel_id = 37,
		.connection_id = 137,
		.present = 1,
	};
	struct uk_blkdev *device;
	struct uk_blkreq request;
	struct uk_blkreq request2;
	struct uk_blkreq request3;
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
	rc = driver->add_dev(&vmbus_device);
	if (rc)
		return 2;
	device = storvsc_host_blkdev();
	if (!device || device->capabilities.sectors != 1000 ||
	    device->capabilities.ssize != 512 ||
	    device->capabilities.mode != O_RDWR ||
	    device->capabilities.max_sectors_per_req != 56)
		return 3;
	if (configure_device(device, 2, &events))
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
	initialize_request(&request, UK_BLKREQ_READ, 999, 1, buffer,
			   request_done, &callbacks);
	if (submit_and_fire(device, &request) || request.result)
		return 7;
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
	if (submit_and_fire(device, &request) || request.result)
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

	hold_io = 1;
	initialize_request(&request, UK_BLKREQ_READ, 8, 1, buffer,
			   request_done, &callbacks);
	if (!(device->submit_one(device, device->_queue[0], &request) &
	      UK_BLKDEV_STATUS_SUCCESS))
		return 19;
	if (wait_finished(&request, 1000) || request.result != -ETIMEDOUT)
		return 20;
	enqueue_completion(last_io_id, 64, 0, 1, 0, last_io_length);
	pending_count = 0;
	fire_channel();
	if (atomic_load(&callbacks) != 10)
		return 21;
	hold_io = 0;

	hold_io = 1;
	initialize_request(&request, UK_BLKREQ_READ, 9, 1, buffer,
			   request_done, &callbacks);
	if (!(device->submit_one(device, device->_queue[0], &request) &
	      UK_BLKDEV_STATUS_SUCCESS))
		return 22;
	driver->remove_dev(&vmbus_device);
	if (request.result != -ENODEV ||
	    atomic_load(&request.state.counter) != UK_BLKREQ_FINISHED)
		return 23;
	if (vmbus_device.channel)
		(void)vmbus_channel_close(vmbus_device.channel);
	pending_count = 0;
	hold_io = 0;

	vmbus_device.present = 1;
	read_only_media = 1;
	use_capacity16 = 1;
	reject_versions = 3;
	reject_mode_sense6 = 1;
	rc = driver->add_dev(&vmbus_device);
	if (rc || device->capabilities.mode != O_RDONLY ||
	    device->capabilities.sectors != 0x100000101ULL)
		return 24;
	initialize_request(&request, UK_BLKREQ_WRITE, 0, 1, buffer,
			   request_done, &callbacks);
	if (device->submit_one(device, device->_queue[0], &request) !=
	    -EROFS)
		return 25;
	driver->remove_dev(&vmbus_device);
	if (vmbus_device.channel)
		(void)vmbus_channel_close(vmbus_device.channel);

	read_only_media = 0;
	use_capacity16 = 0;
	malformed_handshake = 1;
	vmbus_device.present = 1;
	rc = driver->add_dev(&vmbus_device);
	if (rc != -EPROTO || vmbus_device.channel || close_count < 2)
		return 26;

	free(buffer);
	return 0;
}
