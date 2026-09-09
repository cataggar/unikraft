/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uk/alloc.h>
#include <uk/config.h>
#include <uk/essentials.h>
#include <uk/netbuf.h>
#include <uk/netdev_driver.h>
#include <uk/sched.h>
#include <uk/vmbus.h>

#include "netvsc-host-test.h"
#include "netvsc_protocol.h"
#include "vmbus_event_route.h"

#if !CONFIG_LIBUKNETDEV_STATS
#error "NetVSC production ownership tests require uknetdev statistics"
#endif

#define MOCK_QUEUE 128
#define MOCK_DESCRIPTOR 520
#define MOCK_PAYLOAD 512
#define MOCK_RX_SLOT_SIZE 2048U
#define MOCK_NETBUF_COUNT 16
#define MOCK_NVS_RESPONSE_CAPACITY \
	(((12U + NETVSC_NVS_MAX_SECTIONS * 16U) + 7U) & ~7U)

#define CHECK(condition)						\
	do {								\
		if (!(condition)) {					\
			fprintf(stderr, "check failed at %s:%d: %s\n",	\
				__FILE__, __LINE__, #condition);		\
			return __LINE__;					\
		}							\
	} while (0)

struct vmbus_channel {
	int open;
};

struct mock_packet {
	struct vmbus_packet packet;
	size_t descriptor_length;
	size_t payload_length;
	__u8 descriptor[MOCK_DESCRIPTOR];
	__u8 payload[MOCK_PAYLOAD];
};

struct mock_state {
	struct mock_packet queue[MOCK_QUEUE];
	unsigned int head;
	unsigned int tail;
	struct vmbus_channel channel;
	struct vmbus_device *offered_device;
	vmbus_channel_callback_t callback;
	void *callback_arg;
	void *mapped[2];
	size_t mapped_size[2];
	unsigned int map_count;
	unsigned int live_gpadls;
	unsigned int close_count;
	unsigned int nvs_init_requests;
	unsigned int nvs_init_attempts;
	unsigned int nvs_accept_index;
	__u32 nvs_init_status;
	size_t init_response_length;
	size_t receive_response_length;
	size_t send_response_length;
	__u32 receive_end_offset;
	unsigned int suppress_nvs_init;
	unsigned int send_section_size;
	unsigned int next_rx_slot;
	unsigned int ack_count;
	unsigned int ack_failed;
	unsigned int ack_eagain;
	__u32 last_ack_status;
	unsigned int netdev_events;
	unsigned int suppress_control_nvs;
	unsigned int suppress_control_rndis;
	unsigned int delay_tx;
	unsigned int post_publish_error_once;
	unsigned int reenter_send_once;
	int data_send_error_once;
	unsigned int fail_open;
	unsigned int fail_close;
	int receive_error_once;
	int receive_error_after;
	unsigned int receive_calls;
	unsigned int replenish_receive;
	unsigned int reenter_channel_once;
	unsigned int deferred_signal;
	unsigned int deferred_count;
	__u32 protocol_version;
	unsigned int connection_fail_count;
	unsigned int bind_epoch_count;
	unsigned int bind_retry_count;
	unsigned int bind_ready_count;
	unsigned int advance_quiesce_on_bind_epoch;
	__u64 quiesce_epoch;
	unsigned int fail_map_call;
	unsigned int fail_receive_complete;
	unsigned int fail_send_complete;
	unsigned int fail_rndis_init;
	unsigned int fail_query_oid;
	unsigned int wrong_control_id_once;
	__u64 pending_tx[CONFIG_LIBNETVSC_TX_SLOTS * 2];
	unsigned int pending_tx_count;
	__u64 last_tx_id;
	__u64 last_control_transaction;
	__u64 last_transfer_id;
	__u32 last_control_request;
	__u64 stale_watch_id;
	unsigned int stale_ack_count;
	__u8 last_tx[4096];
	size_t last_tx_length;
	struct uk_netbuf *reentered_packet;
	int reenter_receive;
};

struct host_netbuf {
	struct uk_netbuf netbuf;
	__u8 storage[2048];
	unsigned int free_count;
	unsigned int in_use;
};

static struct mock_state mock;
static struct uk_alloc allocator;
static struct uk_sched *scheduler = (struct uk_sched *)1;
static struct host_netbuf rx_buffers[MOCK_NETBUF_COUNT];
static int chained_receive;
static int stats_lock_initialized;

struct stage_gate {
	pthread_mutex_t lock;
	pthread_cond_t condition;
	unsigned int target;
	unsigned int reached;
	unsigned int released;
	__u64 transaction_id;
	__u32 request_id;
};

static struct stage_gate tx_gate = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.condition = PTHREAD_COND_INITIALIZER,
};
static struct stage_gate control_gate = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.condition = PTHREAD_COND_INITIALIZER,
};
static struct stage_gate control_wait_gate = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.condition = PTHREAD_COND_INITIALIZER,
};
static struct stage_gate nvs_gate = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.condition = PTHREAD_COND_INITIALIZER,
};
static struct uk_netbuf *wrapper_gate_packet;

static void stage_gate_arm(struct stage_gate *gate, unsigned int target)
{
	pthread_mutex_lock(&gate->lock);
	gate->target = target;
	gate->reached = 0;
	gate->released = 0;
	gate->transaction_id = 0;
	gate->request_id = 0;
	pthread_mutex_unlock(&gate->lock);
}

static int stage_gate_wait(struct stage_gate *gate)
{
	struct timespec deadline;
	int rc = 0;

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 5;
	pthread_mutex_lock(&gate->lock);
	while (!gate->reached && !rc)
		rc = pthread_cond_timedwait(&gate->condition, &gate->lock,
					    &deadline);
	pthread_mutex_unlock(&gate->lock);
	return rc;
}

static void stage_gate_release(struct stage_gate *gate)
{
	pthread_mutex_lock(&gate->lock);
	gate->released = 1;
	pthread_cond_broadcast(&gate->condition);
	pthread_mutex_unlock(&gate->lock);
}

static void stage_gate_ids(struct stage_gate *gate, __u64 *transaction_id,
			   __u32 *request_id)
{
	pthread_mutex_lock(&gate->lock);
	*transaction_id = gate->transaction_id;
	if (request_id)
		*request_id = gate->request_id;
	pthread_mutex_unlock(&gate->lock);
}

static void stage_gate_enter(struct stage_gate *gate, unsigned int stage,
			     __u64 transaction_id, __u32 request_id)
{
	pthread_mutex_lock(&gate->lock);
	if (gate->target != stage) {
		pthread_mutex_unlock(&gate->lock);
		return;
	}
	gate->transaction_id = transaction_id;
	gate->request_id = request_id;
	gate->reached = 1;
	pthread_cond_broadcast(&gate->condition);
	while (!gate->released)
		pthread_cond_wait(&gate->condition, &gate->lock);
	gate->target = 0;
	pthread_mutex_unlock(&gate->lock);
}

void netvsc_host_tx_stage(unsigned int stage, __u64 transaction_id)
{
	stage_gate_enter(&tx_gate, stage, transaction_id, 0);
}

void netvsc_host_tx_wrapper_stage(struct uk_netbuf *packet,
				  int status __attribute__((unused)))
{
	if (wrapper_gate_packet && wrapper_gate_packet != packet)
		return;
	stage_gate_enter(&tx_gate, NETVSC_HOST_TX_STAGE_WRAPPER_RETURN, 0, 0);
}

void netvsc_host_control_stage(unsigned int stage, __u64 transaction_id,
			       __u32 request_id)
{
	stage_gate_enter(stage == NETVSC_HOST_CONTROL_STAGE_WAIT_DONE ?
			 &control_wait_gate : &control_gate,
			 stage, transaction_id, request_id);
}

void netvsc_host_nvs_stage(unsigned int stage, __u64 transaction_id)
{
	stage_gate_enter(&nvs_gate, stage, transaction_id, 0);
}

static __u32 get32(const __u8 *data)
{
	return (__u32)data[0] | ((__u32)data[1] << 8) |
		((__u32)data[2] << 16) | ((__u32)data[3] << 24);
}

static void put16(__u8 *data, __u16 value)
{
	data[0] = (__u8)value;
	data[1] = (__u8)(value >> 8);
}

static void put32(__u8 *data, __u32 value)
{
	data[0] = (__u8)value;
	data[1] = (__u8)(value >> 8);
	data[2] = (__u8)(value >> 16);
	data[3] = (__u8)(value >> 24);
}

static struct mock_packet *queue_reserve(void)
{
	struct mock_packet *packet;

	if (mock.head - mock.tail >= MOCK_QUEUE)
		return NULL;
	packet = &mock.queue[mock.head++ % MOCK_QUEUE];
	memset(packet, 0, sizeof(*packet));
	return packet;
}

static void enqueue_completion(__u64 transaction_id, const __u8 *payload,
			       size_t payload_length)
{
	struct mock_packet *queued = queue_reserve();

	if (!queued || payload_length > sizeof(queued->payload))
		abort();
	queued->packet.type = VMBUS_PACKET_COMPLETION;
	queued->packet.transaction_id = transaction_id;
	queued->packet.payload_size = payload_length;
	queued->payload_length = payload_length;
	memcpy(queued->payload, payload, payload_length);
}

static void enqueue_rndis_send_complete(__u64 transaction_id)
{
	__u8 complete[8] = { 0 };

	put32(complete, 108);
	put32(complete + 4, 1);
	enqueue_completion(transaction_id, complete, sizeof(complete));
}

static void enqueue_transfer(const __u8 *message, size_t message_length,
			     __u32 channel_type)
{
	struct mock_packet *queued = queue_reserve();
	__u8 *receive_buffer = netvsc_host_receive_buffer();
	__u32 offset;

	if (!queued || message_length > MOCK_RX_SLOT_SIZE)
		abort();
	offset = (mock.next_rx_slot++ % 128U) * MOCK_RX_SLOT_SIZE;
	memcpy(receive_buffer + offset, message, message_length);
	queued->packet.type = VMBUS_PACKET_DATA_USING_TRANSFER_PAGES;
	queued->packet.transaction_id = 0x90000000ULL + mock.next_rx_slot;
	mock.last_transfer_id = queued->packet.transaction_id;
	queued->descriptor_length = 16;
	queued->packet.descriptor_size = 16;
	put16(queued->descriptor, NETVSC_NVS_RX_BUFFER_ID);
	put32(queued->descriptor + 4, 1);
	put32(queued->descriptor + 8, (__u32)message_length);
	put32(queued->descriptor + 12, offset);
	put32(queued->payload, NETVSC_NVS_TYPE_SEND_RNDIS);
	put32(queued->payload + 4, channel_type);
	queued->payload_length = NETVSC_NVS_REQUEST_SIZE;
	queued->packet.payload_size = NETVSC_NVS_REQUEST_SIZE;
}

static void enqueue_rndis_control_complete(__u32 type, __u32 request_id)
{
	__u8 complete[16] = { 0 };

	put32(complete, type);
	put32(complete + 4, sizeof(complete));
	put32(complete + 8, request_id);
	enqueue_transfer(complete, sizeof(complete),
			 NETVSC_NVS_RNDIS_CONTROL);
}

static void enqueue_frame_range(const __u8 *frame, size_t frame_length,
				__u32 range_offset, __u32 range_length)
{
	struct mock_packet *queued = queue_reserve();
	__u8 *receive_buffer = netvsc_host_receive_buffer();
	int header;

	if (!queued || range_length > netvsc_host_receive_buffer_capacity() ||
	    range_offset > netvsc_host_receive_buffer_capacity() -
		    range_length)
		abort();
	memset(receive_buffer + range_offset, 0, range_length);
	header = netvsc_rndis_build_packet_header(
			receive_buffer + range_offset, range_length,
			frame_length);
	if (header < 0 || (size_t)header + frame_length > range_length)
		abort();
	memcpy(receive_buffer + range_offset + header, frame, frame_length);
	queued->packet.type = VMBUS_PACKET_DATA_USING_TRANSFER_PAGES;
	queued->packet.transaction_id = 0x91000000ULL + mock.next_rx_slot++;
	queued->descriptor_length = 16;
	queued->packet.descriptor_size = 16;
	put16(queued->descriptor, NETVSC_NVS_RX_BUFFER_ID);
	put32(queued->descriptor + 4, 1);
	put32(queued->descriptor + 8, range_length);
	put32(queued->descriptor + 12, range_offset);
	put32(queued->payload, NETVSC_NVS_TYPE_SEND_RNDIS);
	put32(queued->payload + 4, NETVSC_NVS_RNDIS_DATA);
	queued->payload_length = NETVSC_NVS_REQUEST_SIZE;
	queued->packet.payload_size = NETVSC_NVS_REQUEST_SIZE;
}

static void enqueue_init_complete(__u64 transaction_id, __u32 requested)
{
	__u8 response[MOCK_PAYLOAD] = { 0 };
	unsigned int attempt = mock.nvs_init_attempts++;
	__u32 status = mock.nvs_init_status ? mock.nvs_init_status :
		(attempt < mock.nvs_accept_index ? 2 : 1);

	put32(response, 2);
	put32(response + 4, requested);
	put32(response + 8, 32);
	put32(response + 12, status);
	enqueue_completion(transaction_id, response,
			   mock.init_response_length);
}

static void enqueue_receive_complete(__u64 transaction_id)
{
	__u8 response[MOCK_PAYLOAD] = { 0 };
	size_t receive_size = mock.mapped_size[0];
	__u32 slots = (__u32)(receive_size / MOCK_RX_SLOT_SIZE);

	put32(response, 102);
	put32(response + 4, mock.fail_receive_complete ? 2 : 1);
	put32(response + 8, 1);
	put32(response + 12, 0);
	put32(response + 16, MOCK_RX_SLOT_SIZE);
	put32(response + 20, slots);
	put32(response + 24, mock.receive_end_offset ?
	      mock.receive_end_offset : (__u32)receive_size);
	enqueue_completion(transaction_id, response,
			   mock.receive_response_length);
}

static void enqueue_send_complete(__u64 transaction_id)
{
	__u8 response[MOCK_PAYLOAD] = { 0 };

	put32(response, 105);
	put32(response + 4, mock.fail_send_complete ? 2 : 1);
	put32(response + 8, mock.send_section_size);
	enqueue_completion(transaction_id, response,
			   mock.send_response_length);
}

static void build_query_complete(__u8 *response, size_t *response_length,
				 __u32 request_id, __u32 oid)
{
	static const __u8 permanent[6] = { 0x00, 0x15, 0x5d, 0x11, 0x22, 0x33 };
	static const __u8 current[6] = { 0x00, 0x15, 0x5d, 0x44, 0x55, 0x66 };
	const __u8 *data = NULL;
	__u8 scalar[4];
	size_t data_length = 0;

	switch (oid) {
	case NETVSC_OID_802_3_PERMANENT_ADDRESS:
		data = permanent;
		data_length = sizeof(permanent);
		break;
	case NETVSC_OID_802_3_CURRENT_ADDRESS:
		data = current;
		data_length = sizeof(current);
		break;
	case NETVSC_OID_GEN_MAXIMUM_FRAME_SIZE:
		put32(scalar, 1500);
		data = scalar;
		data_length = sizeof(scalar);
		break;
	case NETVSC_OID_GEN_MAXIMUM_TOTAL_SIZE:
		put32(scalar, 1514);
		data = scalar;
		data_length = sizeof(scalar);
		break;
	case NETVSC_OID_GEN_MEDIA_CONNECT_STATUS:
		put32(scalar, 0);
		data = scalar;
		data_length = sizeof(scalar);
		break;
	default:
		break;
	}
	memset(response, 0, 64);
	put32(response, NETVSC_RNDIS_QUERY_COMPLETE);
	put32(response + 4, (__u32)(24 + data_length));
	put32(response + 8, request_id);
	put32(response + 12,
	      oid == mock.fail_query_oid ? 0xc0000001U : 0);
	put32(response + 16, (__u32)data_length);
	put32(response + 20, data_length ? 16 : 0);
	if (data_length)
		memcpy(response + 24, data, data_length);
	*response_length = 24 + data_length;
}

static void handle_rndis_request(__u64 transaction_id, const __u8 *request,
				 size_t request_length, __u32 channel_type)
{
	__u8 nvs_complete[8] = { 0 };
	__u8 response[128] = { 0 };
	struct netvsc_rndis_packet_info packet;
	size_t response_length = 0;
	__u32 type;
	__u32 request_id;

	put32(nvs_complete, 108);
	put32(nvs_complete + 4, 1);
	type = get32(request);
	request_id = request_length >= 12 ? get32(request + 8) : 0;

	if (channel_type == NETVSC_NVS_RNDIS_DATA) {
		if (netvsc_rndis_parse_packet(request, request_length, &packet))
			abort();
		mock.last_tx_length = packet.data_length;
		memcpy(mock.last_tx, request + packet.data_offset,
		       packet.data_length);
		mock.last_tx_id = transaction_id;
		if (mock.delay_tx) {
			if (mock.pending_tx_count >=
			    sizeof(mock.pending_tx) / sizeof(mock.pending_tx[0]))
				abort();
			mock.pending_tx[mock.pending_tx_count++] =
				transaction_id;
		} else {
			enqueue_completion(transaction_id, nvs_complete,
					   sizeof(nvs_complete));
		}
		return;
	}

	if (!mock.suppress_control_nvs)
		enqueue_completion(transaction_id, nvs_complete,
				   sizeof(nvs_complete));
	mock.last_control_transaction = transaction_id;
	mock.last_control_request = request_id;
	if (mock.suppress_control_rndis)
		return;
	switch (type) {
	case 2:
		put32(response, NETVSC_RNDIS_INITIALIZE_COMPLETE);
		put32(response + 4, 52);
		put32(response + 8, request_id);
		put32(response + 12, mock.fail_rndis_init ? 0xc0000001U : 0);
		put32(response + 16, 1);
		put32(response + 20, 0);
		put32(response + 24, 1);
		put32(response + 28, 0);
		put32(response + 32, 1);
		put32(response + 36, 2048);
		put32(response + 40, 2);
		response_length = 52;
		break;
	case 4:
		build_query_complete(response, &response_length, request_id,
				     get32(request + 12));
		break;
	case 5:
		put32(response, NETVSC_RNDIS_SET_COMPLETE);
		put32(response + 4, 16);
		put32(response + 8, mock.wrong_control_id_once ?
		      request_id + 1 : request_id);
		mock.wrong_control_id_once = 0;
		response_length = 16;
		break;
	case 8:
		put32(response, NETVSC_RNDIS_KEEPALIVE_COMPLETE);
		put32(response + 4, 16);
		put32(response + 8, request_id);
		response_length = 16;
		break;
	case 3:
		return;
	default:
		abort();
	}
	enqueue_transfer(response, response_length, NETVSC_NVS_RNDIS_CONTROL);
}

static size_t copy_ranges(__u8 *output, size_t capacity,
			  const struct vmbus_gpa_range *ranges,
			  __u32 range_count)
{
	size_t written = 0;
	unsigned int range_index;

	for (range_index = 0; range_index < range_count; range_index++) {
		const struct vmbus_gpa_range *range = &ranges[range_index];
		__u32 remaining = range->byte_count;
		__u32 page_index;
		__u32 page_offset = range->byte_offset;

		for (page_index = 0; page_index < range->pfn_count;
		     page_index++) {
			const __u8 *page = (const __u8 *)(uintptr_t)
				(range->pfns[page_index] << 12);
			size_t take = 4096 - page_offset;

			if (take > remaining)
				take = remaining;
			if (take > capacity - written)
				abort();
			memcpy(output + written, page + page_offset, take);
			written += take;
			remaining -= take;
			page_offset = 0;
		}
		if (remaining)
			abort();
	}
	return written;
}

static int handle_nvs_send(__u16 packet_type, __u16 flags,
			   __u64 transaction_id, const __u8 *payload,
			   size_t payload_length,
			   const struct vmbus_gpa_range *ranges,
			   __u32 range_count)
{
	__u32 type;

	if (packet_type == VMBUS_PACKET_COMPLETION) {
		if (mock.ack_eagain) {
			mock.ack_eagain--;
			return -EAGAIN;
		}
		mock.ack_count++;
		if (transaction_id == mock.stale_watch_id)
			mock.stale_ack_count++;
		mock.last_ack_status = payload_length >= 8 ?
			get32(payload + 4) : 0;
		if (payload_length < 8 || get32(payload) != 108 ||
		    (get32(payload + 4) != 1 && get32(payload + 4) != 2))
			mock.ack_failed++;
		return 0;
	}
	if (payload_length < 4)
		return -EINVAL;
	type = get32(payload);
	switch (type) {
	case 1:
		mock.nvs_init_requests++;
		if (!mock.suppress_nvs_init)
			enqueue_init_complete(transaction_id,
					      get32(payload + 4));
		break;
	case 101:
		enqueue_receive_complete(transaction_id);
		break;
	case 104:
		enqueue_send_complete(transaction_id);
		break;
	case 107: {
		__u8 request[4096];
		const __u8 *request_pointer;
		size_t request_length;
		__u32 channel_type = get32(payload + 4);
		__u32 section = get32(payload + 8);

		if (section != NETVSC_NVS_SEND_SECTION_INVALID) {
			request_pointer = netvsc_host_send_buffer() +
				(__u64)section * mock.send_section_size;
			request_length = get32(payload + 12);
		} else {
			request_length = copy_ranges(request, sizeof(request),
						    ranges, range_count);
			request_pointer = request;
		}
		handle_rndis_request(transaction_id, request_pointer,
				     request_length, channel_type);
		break;
	}
	case 100:
	case 103:
	case 106:
	case 125:
		break;
	default:
		return -EINVAL;
	}
	if ((flags & VMBUS_PACKET_FLAG_REQUEST_COMPLETION) &&
	    type != 1 && type != 101 && type != 104 && type != 107)
		return -EINVAL;
	return 0;
}

static void mock_signal(void)
{
	if (mock.callback)
		mock.callback(&mock.channel, mock.callback_arg);
}

static int mock_run_deferred(void)
{
	if (!mock.deferred_signal)
		return 0;
	mock.deferred_signal = 0;
	mock_signal();
	return 1;
}

static void mock_enqueue_event(__u32 event, void *arg __unused)
{
	if (!mock.offered_device ||
	    event != mock.offered_device->channel_id)
		abort();
	mock.deferred_count++;
	mock.deferred_signal = 1;
}

void hyperv_vmbus_event(__u32 event)
{
	(void)vmbus_event_route(mock.protocol_version, event, NULL, 0,
			       2048, mock_enqueue_event, NULL);
}

void vmbus_channel_schedule_event(__u32 channel_id)
{
	mock_enqueue_event(channel_id, NULL);
}

static void mock_flush_tx(void)
{
	__u8 complete[8] = { 0 };
	unsigned int i;

	put32(complete, 108);
	put32(complete + 4, 1);
	for (i = 0; i < mock.pending_tx_count; i++)
		enqueue_completion(mock.pending_tx[i], complete,
				   sizeof(complete));
	mock.pending_tx_count = 0;
	mock_signal();
}

static void mock_reset(void)
{
	memset(&mock, 0, sizeof(mock));
	mock.channel.open = 1;
	mock.quiesce_epoch = 1;
	mock.protocol_version = VMBUS_EVENT_VERSION_WIN8;
	mock.nvs_accept_index = 2;
	mock.init_response_length = NETVSC_NVS_REQUEST_SIZE;
	mock.receive_response_length = NETVSC_NVS_REQUEST_SIZE;
	mock.send_response_length = NETVSC_NVS_REQUEST_SIZE;
	mock.send_section_size = 2048;
	wrapper_gate_packet = NULL;
	memset(rx_buffers, 0, sizeof(rx_buffers));
	chained_receive = 0;
}

struct uk_alloc *uk_alloc_get_default(void)
{
	return &allocator;
}

struct uk_sched *uk_sched_current(void)
{
	return scheduler;
}

void uk_sched_thread_sleep(__u64 nanoseconds __attribute__((unused)))
{
}

__u64 ukplat_monotonic_clock(void)
{
	static __u64 now;

	return ++now * 1000000ULL;
}

static void host_netbuf_destructor(struct uk_netbuf *packet)
{
	struct host_netbuf *buffer = packet->priv;

	buffer->free_count++;
	buffer->in_use = 0;
	memset(buffer->storage, 0xa5, sizeof(buffer->storage));
	packet->next = (struct uk_netbuf *)(uintptr_t)1;
	packet->prev = (struct uk_netbuf *)(uintptr_t)1;
	packet->data = (void *)(uintptr_t)1;
	packet->buf = (void *)(uintptr_t)1;
	packet->len = UINT16_MAX;
	packet->buflen = 0;
}

void uk_netbuf_free(struct uk_netbuf *packet)
{
	while (packet) {
		struct uk_netbuf *next = packet->next;

		packet->next = NULL;
		packet->prev = NULL;
		if (packet->dtor)
			packet->dtor(packet);
		packet = next;
	}
}

static void init_host_netbuf(struct host_netbuf *buffer, size_t headroom,
			     size_t capacity)
{
	memset(&buffer->netbuf, 0, sizeof(buffer->netbuf));
	buffer->in_use = 1;
	buffer->netbuf.buf = buffer->storage;
	buffer->netbuf.buflen = sizeof(buffer->storage);
	buffer->netbuf.data = buffer->storage + headroom;
	buffer->netbuf.len = (uint16_t)capacity;
	buffer->netbuf.refcount = 1;
	buffer->netbuf.priv = buffer;
	buffer->netbuf.dtor = host_netbuf_destructor;
}

static uint16_t allocate_receive(void *arg __attribute__((unused)),
				 struct uk_netbuf **packets, uint16_t count)
{
	unsigned int i;

	if (!count)
		return 0;
	for (i = 0; i < MOCK_NETBUF_COUNT; i++) {
		if (rx_buffers[i].in_use)
			continue;
		init_host_netbuf(&rx_buffers[i], 64,
				chained_receive ? 40 : 1800);
		packets[0] = &rx_buffers[i].netbuf;
		if (chained_receive) {
			unsigned int second;

			for (second = i + 1; second < MOCK_NETBUF_COUNT;
			     second++)
				if (!rx_buffers[second].in_use)
					break;
			if (second == MOCK_NETBUF_COUNT) {
				rx_buffers[i].in_use = 0;
				return 0;
			}
			init_host_netbuf(&rx_buffers[second], 32, 1800);
			rx_buffers[i].netbuf.next =
				&rx_buffers[second].netbuf;
			rx_buffers[second].netbuf.prev =
				&rx_buffers[i].netbuf;
		}
		return 1;
	}
	return 0;
}

int uk_netdev_drv_register(struct uk_netdev *netdev,
			   struct uk_alloc *a __attribute__((unused)),
			   const char *name __attribute__((unused)))
{
	netdev->_data = netdev;
	if (!stats_lock_initialized) {
		ukarch_spin_init(&netdev->stats_lock);
		stats_lock_initialized = 1;
	}
	memset(&netdev->tx_stats, 0, sizeof(netdev->tx_stats));
	return 0;
}

void uk_netdev_drv_rx_event(struct uk_netdev *netdev, uint16_t queue_id)
{
	mock.netdev_events++;
	if (mock.reenter_receive) {
		struct uk_netbuf *packet = NULL;
		int status = netdev->rx_one(netdev, netdev->_rx_queue[queue_id],
					    &packet);

		if (status & UK_NETDEV_STATUS_SUCCESS)
			mock.reentered_packet = packet;
	}
}

int vmbus_channel_open(struct vmbus_device *device, __u16 tx_pages
		       __attribute__((unused)), __u16 rx_pages
		       __attribute__((unused)), const void *data
		       __attribute__((unused)), size_t length
		       __attribute__((unused)))
{
	if (mock.fail_open)
		return -EIO;
	mock.offered_device = device;
	device->channel = &mock.channel;
	mock.channel.open = 1;
	return 0;
}

int vmbus_channel_close(struct vmbus_channel *channel)
{
	channel->open = 0;
	mock.close_count++;
	mock.live_gpadls = 0;
	if (mock.offered_device)
		mock.offered_device->channel = NULL;
	return mock.fail_close ? -EIO : 0;
}

__u64 vmbus_connection_fail(void)
{
	mock.connection_fail_count++;
	mock.callback = NULL;
	mock.callback_arg = NULL;
	return mock.quiesce_epoch;
}

__u64 vmbus_connection_quiesce_epoch(void)
{
	return mock.quiesce_epoch;
}

int vmbus_device_bind_epoch(struct vmbus_device *device
			    __attribute__((unused)),
			    struct vmbus_device_bind_token *token)
{
	mock.bind_epoch_count++;
	token->device_generation = 1;
	token->resource_epoch = mock.quiesce_epoch;
	if (mock.advance_quiesce_on_bind_epoch) {
		mock.advance_quiesce_on_bind_epoch = 0;
		mock.quiesce_epoch++;
	}
	return 0;
}

int vmbus_device_bind_retry(struct vmbus_device *device
			    __attribute__((unused)),
			    const struct vmbus_device_bind_token *token)
{
	CHECK(token->device_generation != 0);
	CHECK(token->resource_epoch != 0);
	mock.bind_retry_count++;
	return -ENOSPC;
}

void vmbus_device_bind_ready(void)
{
	mock.bind_ready_count++;
}

int vmbus_channel_send(struct vmbus_channel *channel, __u16 type,
		       __u16 flags, __u64 transaction_id,
		       const void *descriptor __attribute__((unused)),
		       size_t descriptor_length __attribute__((unused)),
		       const void *payload, size_t payload_length)
{
	if (!channel || !channel->open)
		return -ECANCELED;
	return handle_nvs_send(type, flags, transaction_id, payload,
			       payload_length, NULL, 0);
}

int vmbus_channel_send_ex(struct vmbus_channel *channel, __u16 type,
			  __u16 flags, __u64 transaction_id,
			  const void *descriptor, size_t descriptor_length,
			  const void *payload, size_t payload_length,
			  int *published)
{
	int rc;

	if (mock.data_send_error_once && payload_length >= 8 &&
	    get32(payload) == NETVSC_NVS_TYPE_SEND_RNDIS &&
	    get32((const __u8 *)payload + 4) == NETVSC_NVS_RNDIS_DATA) {
		rc = mock.data_send_error_once;
		mock.data_send_error_once = 0;
		*published = 0;
		return rc;
	}
	rc = vmbus_channel_send(channel, type, flags, transaction_id,
			descriptor, descriptor_length, payload, payload_length);

	*published = rc == 0;
	if (!rc && mock.reenter_send_once) {
		mock.reenter_send_once = 0;
		mock_signal();
	}
	if (!rc && mock.post_publish_error_once) {
		mock.post_publish_error_once = 0;
		return -EIO;
	}
	return rc;
}

int vmbus_channel_send_gpa_direct(struct vmbus_channel *channel,
				  __u16 flags, __u64 transaction_id,
				  const struct vmbus_gpa_range *ranges,
				  __u32 range_count, const void *payload,
				  size_t payload_length)
{
	if (!channel || !channel->open)
		return -ECANCELED;
	return handle_nvs_send(VMBUS_PACKET_DATA_USING_GPA_DIRECT, flags,
			       transaction_id, payload, payload_length,
			       ranges, range_count);
}

int vmbus_channel_send_gpa_direct_ex(
				  struct vmbus_channel *channel,
				  __u16 flags, __u64 transaction_id,
				  const struct vmbus_gpa_range *ranges,
				  __u32 range_count, const void *payload,
				  size_t payload_length, int *published)
{
	int rc;

	if (mock.data_send_error_once && payload_length >= 8 &&
	    get32(payload) == NETVSC_NVS_TYPE_SEND_RNDIS &&
	    get32((const __u8 *)payload + 4) == NETVSC_NVS_RNDIS_DATA) {
		rc = mock.data_send_error_once;
		mock.data_send_error_once = 0;
		*published = 0;
		return rc;
	}
	rc = vmbus_channel_send_gpa_direct(channel, flags,
			transaction_id, ranges, range_count, payload,
			payload_length);

	*published = rc == 0;
	if (!rc && mock.reenter_send_once) {
		mock.reenter_send_once = 0;
		mock_signal();
	}
	if (!rc && mock.post_publish_error_once) {
		mock.post_publish_error_once = 0;
		return -EIO;
	}
	return rc;
}

int vmbus_channel_gpadl_map(struct vmbus_channel *channel
			    __attribute__((unused)), void *address,
			    size_t length, struct vmbus_gpadl *gpadl)
{
	unsigned int call = mock.map_count++;

	if (mock.fail_map_call && mock.fail_map_call == call + 1)
		return -ENOSPC;
	if (call < 2) {
		mock.mapped[call] = address;
		mock.mapped_size[call] = length;
	}
	gpadl->id = call + 1;
	gpadl->page_count = length / 4096;
	gpadl->generation = 1;
	mock.live_gpadls++;
	return 0;
}

int vmbus_channel_gpadl_unmap(struct vmbus_channel *channel
			      __attribute__((unused)),
			      struct vmbus_gpadl *gpadl)
{
	if (mock.live_gpadls)
		mock.live_gpadls--;
	memset(gpadl, 0, sizeof(*gpadl));
	return 0;
}

int vmbus_channel_receive(struct vmbus_channel *channel,
			  struct vmbus_packet *packet, void *descriptor,
			  size_t descriptor_capacity, void *payload,
			  size_t payload_capacity)
{
	struct mock_packet copy;
	struct mock_packet *queued;

	if (!channel || !channel->open)
		return -ECANCELED;
	if (mock.receive_error_once && mock.receive_error_after <= 0) {
		int rc = mock.receive_error_once;

		mock.receive_error_once = 0;
		return rc;
	}
	if (mock.tail == mock.head)
		return -EAGAIN;
	queued = &mock.queue[mock.tail % MOCK_QUEUE];
	if (queued->descriptor_length > descriptor_capacity ||
	    queued->payload_length > payload_capacity)
		return -ENOBUFS;
	*packet = queued->packet;
	memcpy(descriptor, queued->descriptor, queued->descriptor_length);
	memcpy(payload, queued->payload, queued->payload_length);
	copy = *queued;
	mock.tail++;
	mock.receive_calls++;
	if (mock.receive_error_after > 0)
		mock.receive_error_after--;
	if (mock.replenish_receive) {
		struct mock_packet *replacement = queue_reserve();

		if (!replacement)
			abort();
		*replacement = copy;
		replacement->packet.transaction_id += mock.receive_calls;
	}
	if (mock.reenter_channel_once) {
		mock.reenter_channel_once = 0;
		mock_signal();
	}
	return 0;
}

void vmbus_channel_set_callback(struct vmbus_channel *channel
				__attribute__((unused)),
				vmbus_channel_callback_t callback, void *arg)
{
	mock.callback = callback;
	mock.callback_arg = arg;
}

static int configure_and_start(struct uk_netdev **netdev_out)
{
	struct uk_netdev_rxqueue_conf rx_configuration = {
		.alloc_rxpkts = allocate_receive,
	};
	struct uk_netdev_txqueue_conf tx_configuration = { 0 };
	struct uk_netdev_conf configuration = {
		.nb_rx_queues = 1,
		.nb_tx_queues = 1,
	};
	struct uk_netdev *netdev = netvsc_host_netdev();

	CHECK(netdev->ops->probe(netdev) == 0);
	CHECK(netdev->ops->configure(netdev, &configuration) == 0);
	netdev->_rx_queue[0] = netdev->ops->rxq_configure(netdev, 0, 4,
							  &rx_configuration);
	netdev->_tx_queue[0] = netdev->ops->txq_configure(netdev, 0, 4,
							  &tx_configuration);
	CHECK(!PTRISERR(netdev->_rx_queue[0]));
	CHECK(!PTRISERR(netdev->_tx_queue[0]));
	CHECK(netdev->ops->start(netdev) == 0);
	*netdev_out = netdev;
	return 0;
}

static void prepare_tx_buffer(struct host_netbuf *buffer, __u8 seed,
			      size_t length)
{
	size_t i;

	init_host_netbuf(buffer, 32, length);
	buffer->netbuf.len = length;
	for (i = 0; i < length; i++)
		((__u8 *)buffer->netbuf.data)[i] = seed + i;
}

struct tx_thread_args {
	struct uk_netdev *netdev;
	struct uk_netbuf *packet;
	int result;
};

static void *tx_thread_main(void *argument)
{
	struct tx_thread_args *args = argument;

	args->result = uk_netdev_tx_one(args->netdev, 0, args->packet);
	return NULL;
}

struct control_thread_args {
	int result;
};

static void *control_thread_main(void *argument)
{
	struct control_thread_args *args = argument;

	args->result = netvsc_host_keepalive();
	return NULL;
}

static void *nvs_thread_main(void *argument)
{
	int *result = argument;

	*result = netvsc_host_nvs_probe();
	return NULL;
}

static void queue_frame_type(const __u8 *frame, size_t frame_length,
			     __u32 channel_type)
{
	__u8 message[MOCK_RX_SLOT_SIZE] = { 0 };
	int header = netvsc_rndis_build_packet_header(message,
			sizeof(message), frame_length);

	if (header != 44)
		abort();
	memcpy(message + header, frame, frame_length);
	enqueue_transfer(message, header + frame_length, channel_type);
}

static void inject_frame_type(const __u8 *frame, size_t frame_length,
			      __u32 channel_type)
{
	queue_frame_type(frame, frame_length, channel_type);
	mock_signal();
}

static void inject_frame(const __u8 *frame, size_t frame_length)
{
	inject_frame_type(frame, frame_length, NETVSC_NVS_RNDIS_DATA);
}

static int test_attach_and_lifecycle(struct vmbus_device *offered)
{
	struct uk_netdev *netdev;
	struct uk_netdev_info info;
	const struct uk_hwaddr *address;

	netvsc_host_reset();
	mock_reset();
	CHECK(netvsc_host_add_device(offered) == 0);
	CHECK(mock.nvs_init_attempts == 3);
	CHECK(netvsc_host_nvs_version() == NETVSC_NVS_VERSION_5);
	CHECK(mock.map_count == 2);
	CHECK(mock.live_gpadls == 2);
	CHECK(netvsc_host_send_section_size() == 2048);
	netdev = netvsc_host_netdev();
	address = netdev->ops->hwaddr_get(netdev);
	CHECK(address->addr_bytes[3] == 0x44);
	CHECK(netdev->ops->mtu_get(netdev) == 1500);
	netdev->ops->info_get(netdev, &info);
	CHECK(info.max_rx_queues == 1 && info.max_tx_queues == 1);
	CHECK(info.features == UK_NETDEV_F_RXQ_INTR);
	CHECK(configure_and_start(&netdev) == 0);
	CHECK(netdev->ops->promiscuous_set(netdev, 1) == 0);
	CHECK(netdev->ops->promiscuous_get(netdev) == 1);
	return 0;
}

static int test_tx_ownership_and_saturation(struct uk_netdev *netdev)
{
	struct host_netbuf packets[6] = { 0 };
	struct host_netbuf chain_tail = { 0 };
	struct host_netbuf reaper = { 0 };
	unsigned int i;

	mock.delay_tx = 1;
	for (i = 0; i < 5; i++)
		prepare_tx_buffer(&packets[i], (__u8)(0x10 + i), 42);
	for (i = 0; i < 4; i++)
		CHECK((uk_netdev_tx_one(netdev, 0, &packets[i].netbuf) &
		       UK_NETDEV_STATUS_SUCCESS) != 0);
	CHECK(netvsc_host_tx_active() == 4);
	CHECK(uk_netdev_tx_one(netdev, 0, &packets[4].netbuf) == 0);
	CHECK(packets[4].free_count == 0);
	mock_flush_tx();
	CHECK(netvsc_host_tx_active() == 4);
	for (i = 0; i < 4; i++)
		CHECK(packets[i].free_count == 0);
	CHECK((uk_netdev_tx_one(netdev, 0, &packets[4].netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	for (i = 0; i < 4; i++)
		CHECK(packets[i].free_count == 1);
	mock_flush_tx();
	CHECK(packets[4].free_count == 0);

	prepare_tx_buffer(&packets[5], 0x70, 30);
	prepare_tx_buffer(&chain_tail, 0x90, 30);
	packets[5].netbuf.next = &chain_tail.netbuf;
	chain_tail.netbuf.prev = &packets[5].netbuf;
	CHECK((uk_netdev_tx_one(netdev, 0, &packets[5].netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	CHECK(packets[4].free_count == 1);
	CHECK(mock.last_tx_length == 60);
	CHECK(mock.last_tx[0] == 0x70 && mock.last_tx[30] == 0x90);
	mock_flush_tx();
	CHECK(packets[5].free_count == 0);
	CHECK(chain_tail.free_count == 0);

	/* A duplicate expected completion cannot free a reused request. */
	{
		__u8 complete[8] = { 0 };

		put32(complete, 108);
		put32(complete + 4, 1);
		enqueue_completion(mock.last_tx_id, complete, sizeof(complete));
		mock_signal();
		CHECK(packets[5].free_count == 0);
	}
	prepare_tx_buffer(&reaper, 0xb0, 1);
	CHECK(uk_netdev_tx_one(netdev, 0, &reaper.netbuf) == -EMSGSIZE);
	CHECK(packets[5].free_count == 1);
	CHECK(chain_tail.free_count == 1);
	CHECK(reaper.free_count == 0);
	CHECK(netdev->tx_stats.packets == 6);
	CHECK(netdev->tx_stats.bytes == 270);
	mock.delay_tx = 0;
	return 0;
}

static int test_tx_publication_stage(unsigned int stage, int gpa)
{
	struct vmbus_device offered = {
		.channel_id = 80 + stage,
		.connection_id = 180 + stage,
		.present = 1,
	};
	struct uk_netdev_txqueue_conf tx_configuration = { 0 };
	struct host_netbuf packet = { 0 };
	struct host_netbuf blocked = { 0 };
	struct tx_thread_args args;
	struct uk_netdev *netdev;
	pthread_t thread;
	__u64 transaction_id;
	__u32 duplicate_before;
	__u32 malformed_before;
	__u32 unknown_before;
	int failure = 0;

	netvsc_host_reset();
	mock_reset();
	if (gpa)
		mock.send_section_size = 4;
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	netdev->_tx_queue[0] = netdev->ops->txq_configure(
			netdev, 0, 1, &tx_configuration);
	CHECK(!PTRISERR(netdev->_tx_queue[0]));
	mock.delay_tx = 1;
	prepare_tx_buffer(&packet, (__u8)(0x20 + stage), 60);
	prepare_tx_buffer(&blocked, (__u8)(0x40 + stage), 60);
	args.netdev = netdev;
	args.packet = &packet.netbuf;
	args.result = -1;
	stage_gate_arm(&tx_gate, stage);
	if (pthread_create(&thread, NULL, tx_thread_main, &args))
		return __LINE__;
	if (stage_gate_wait(&tx_gate)) {
		failure = __LINE__;
		goto release;
	}
	stage_gate_ids(&tx_gate, &transaction_id, NULL);
	if (!transaction_id || netvsc_host_tx_active() != 1 ||
	    netvsc_host_tx_transaction(0) != transaction_id ||
	    !netvsc_host_tx_state(0) || packet.free_count)
		failure = __LINE__;
	if (!failure &&
	    uk_netdev_tx_one(netdev, 0, &blocked.netbuf) != 0)
		failure = __LINE__;
	if (!failure && blocked.free_count)
		failure = __LINE__;
	duplicate_before = netvsc_host_duplicate_completions();
	malformed_before = netvsc_host_malformed_messages();
	unknown_before = netvsc_host_unknown_completions();
	if (stage == NETVSC_HOST_TX_STAGE_BUILD_RANGES) {
		__u8 malformed[4] = { 0 };

		enqueue_completion(transaction_id, malformed,
				   sizeof(malformed));
	} else {
		enqueue_rndis_send_complete(transaction_id);
	}
	enqueue_rndis_send_complete(transaction_id);
	enqueue_rndis_send_complete(transaction_id ^ 0x100000000ULL);
	mock_signal();
	if (!failure &&
	    (packet.free_count || netvsc_host_tx_active() != 1 ||
	     netvsc_host_tx_transaction(0) != transaction_id))
		failure = __LINE__;
release:
	stage_gate_release(&tx_gate);
	pthread_join(thread, NULL);
	if (failure)
		return failure;
	CHECK((args.result & UK_NETDEV_STATUS_SUCCESS) != 0);
	CHECK((args.result & UK_NETDEV_STATUS_MORE) == 0);
	CHECK(packet.free_count == 0);
	CHECK(netvsc_host_tx_active() == 1);
	CHECK(netdev->tx_stats.packets == 1);
	CHECK(netdev->tx_stats.bytes == 60);
	CHECK(netvsc_host_duplicate_completions() >= duplicate_before + 1);
	CHECK(netvsc_host_unknown_completions() >= unknown_before + 1);
	if (stage == NETVSC_HOST_TX_STAGE_BUILD_RANGES)
		CHECK(netvsc_host_malformed_messages() ==
		      malformed_before + 1);
	mock_flush_tx();
	CHECK(packet.free_count == 0);
	CHECK(netvsc_host_duplicate_completions() >= duplicate_before + 2);
	CHECK((uk_netdev_tx_one(netdev, 0, &blocked.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	CHECK(packet.free_count == 1);
	mock_flush_tx();
	CHECK(blocked.free_count == 0);
	netvsc_host_remove_device(&offered);
	CHECK(blocked.free_count == 1);
	return 0;
}

static int test_tx_publication_races(void)
{
	int rc;

	rc = test_tx_publication_stage(NETVSC_HOST_TX_STAGE_BEFORE_COPY, 0);
	if (rc)
		return rc;
	rc = test_tx_publication_stage(NETVSC_HOST_TX_STAGE_SECTION_COPY, 0);
	if (rc)
		return rc;
	rc = test_tx_publication_stage(NETVSC_HOST_TX_STAGE_BUILD_RANGES, 1);
	if (rc)
		return rc;
	return test_tx_publication_stage(
			NETVSC_HOST_TX_STAGE_AFTER_PUBLISH, 0);
}

static int test_tx_completion_races_wrapper_stats(void)
{
	struct vmbus_device offered = {
		.channel_id = 86,
		.connection_id = 186,
		.present = 1,
	};
	struct uk_netdev_txqueue_conf tx_configuration = { 0 };
	struct host_netbuf head = { 0 };
	struct host_netbuf tail = { 0 };
	struct host_netbuf blocked = { 0 };
	struct host_netbuf reaper = { 0 };
	struct tx_thread_args args;
	struct uk_netdev *netdev;
	pthread_t thread;
	__u64 transaction_id;
	int failure = 0;

	netvsc_host_reset();
	mock_reset();
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	netdev->_tx_queue[0] = netdev->ops->txq_configure(
			netdev, 0, 1, &tx_configuration);
	CHECK(!PTRISERR(netdev->_tx_queue[0]));
	mock.delay_tx = 1;
	prepare_tx_buffer(&head, 0x51, 30);
	prepare_tx_buffer(&tail, 0x71, 30);
	prepare_tx_buffer(&blocked, 0x91, 60);
	head.netbuf.next = &tail.netbuf;
	tail.netbuf.prev = &head.netbuf;
	args.netdev = netdev;
	args.packet = &head.netbuf;
	args.result = -1;
	wrapper_gate_packet = &head.netbuf;
	stage_gate_arm(&tx_gate, NETVSC_HOST_TX_STAGE_WRAPPER_RETURN);
	if (pthread_create(&thread, NULL, tx_thread_main, &args))
		return __LINE__;
	if (stage_gate_wait(&tx_gate)) {
		failure = __LINE__;
		goto release;
	}
	transaction_id = netvsc_host_tx_transaction(0);
	if (!transaction_id || netvsc_host_tx_active() != 1)
		failure = __LINE__;
	enqueue_rndis_send_complete(transaction_id);
	enqueue_rndis_send_complete(transaction_id);
	mock_signal();
	if (!failure &&
	    (head.free_count || tail.free_count ||
	     netvsc_host_tx_active() != 1 ||
	     uk_netdev_tx_one(netdev, 0, &blocked.netbuf) != 0))
		failure = __LINE__;
release:
	stage_gate_release(&tx_gate);
	pthread_join(thread, NULL);
	wrapper_gate_packet = NULL;
	if (failure)
		return failure;
	CHECK((args.result & UK_NETDEV_STATUS_SUCCESS) != 0);
	CHECK(head.free_count == 0 && tail.free_count == 0);
	CHECK(netdev->tx_stats.packets == 1);
	CHECK(netdev->tx_stats.bytes == 60);
	prepare_tx_buffer(&reaper, 0xb1, 1);
	CHECK(uk_netdev_tx_one(netdev, 0, &reaper.netbuf) == -EMSGSIZE);
	CHECK(head.free_count == 1 && tail.free_count == 1);
	CHECK(blocked.free_count == 0 && reaper.free_count == 0);
	netvsc_host_remove_device(&offered);
	return 0;
}

static int test_tx_concurrent_wrapper_grace(void)
{
	struct vmbus_device offered = {
		.channel_id = 81,
		.connection_id = 181,
		.present = 1,
	};
	struct uk_netdev_txqueue_conf tx_configuration = { 0 };
	struct host_netbuf first = { 0 };
	struct host_netbuf second = { 0 };
	struct host_netbuf reaper = { 0 };
	struct tx_thread_args args;
	struct uk_netdev *netdev;
	pthread_t thread;
	int failure = 0;

	netvsc_host_reset();
	mock_reset();
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	netdev->_tx_queue[0] = netdev->ops->txq_configure(
			netdev, 0, 2, &tx_configuration);
	CHECK(!PTRISERR(netdev->_tx_queue[0]));
	mock.delay_tx = 1;
	prepare_tx_buffer(&first, 0x22, 60);
	prepare_tx_buffer(&second, 0x42, 60);
	args.netdev = netdev;
	args.packet = &first.netbuf;
	args.result = -1;
	wrapper_gate_packet = &first.netbuf;
	stage_gate_arm(&tx_gate, NETVSC_HOST_TX_STAGE_WRAPPER_RETURN);
	if (pthread_create(&thread, NULL, tx_thread_main, &args))
		return __LINE__;
	if (stage_gate_wait(&tx_gate)) {
		failure = __LINE__;
		goto release;
	}
	if ((uk_netdev_tx_one(netdev, 0, &second.netbuf) &
	     UK_NETDEV_STATUS_SUCCESS) == 0 ||
	    mock.pending_tx_count != 2)
		failure = __LINE__;
	mock_flush_tx();
	if (!failure &&
	    (first.free_count || second.free_count ||
	     netvsc_host_tx_active() != 2))
		failure = __LINE__;
	prepare_tx_buffer(&reaper, 0x62, 1);
	if (!failure &&
	    (uk_netdev_tx_one(netdev, 0, &reaper.netbuf) != -EMSGSIZE ||
	     first.free_count || second.free_count ||
	     netvsc_host_tx_active() != 2))
		failure = __LINE__;
release:
	stage_gate_release(&tx_gate);
	pthread_join(thread, NULL);
	wrapper_gate_packet = NULL;
	if (failure)
		return failure;
	CHECK((args.result & UK_NETDEV_STATUS_SUCCESS) != 0);
	CHECK(first.free_count == 0 && second.free_count == 0);
	CHECK(uk_netdev_tx_one(netdev, 0, &reaper.netbuf) == -EMSGSIZE);
	CHECK(first.free_count == 1 && second.free_count == 1);
	CHECK(netvsc_host_tx_active() == 0);
	netvsc_host_remove_device(&offered);
	return 0;
}

static int test_tx_unpublished_early_completion(void)
{
	struct vmbus_device offered = {
		.channel_id = 87,
		.connection_id = 187,
		.present = 1,
	};
	struct host_netbuf packet = { 0 };
	struct tx_thread_args args;
	struct uk_netdev *netdev;
	pthread_t thread;
	__u64 transaction_id;
	__u32 early_before;
	int failure = 0;

	netvsc_host_reset();
	mock_reset();
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	mock.delay_tx = 1;
	mock.data_send_error_once = -EAGAIN;
	prepare_tx_buffer(&packet, 0x61, 60);
	args.netdev = netdev;
	args.packet = &packet.netbuf;
	args.result = -1;
	early_before = netvsc_host_early_completions();
	stage_gate_arm(&tx_gate, NETVSC_HOST_TX_STAGE_BEFORE_COPY);
	if (pthread_create(&thread, NULL, tx_thread_main, &args))
		return __LINE__;
	if (stage_gate_wait(&tx_gate)) {
		failure = __LINE__;
		goto release;
	}
	stage_gate_ids(&tx_gate, &transaction_id, NULL);
	enqueue_rndis_send_complete(transaction_id);
	mock_signal();
	if (packet.free_count || netvsc_host_tx_active() != 1)
		failure = __LINE__;
release:
	stage_gate_release(&tx_gate);
	pthread_join(thread, NULL);
	if (failure)
		return failure;
	CHECK(args.result == 0);
	CHECK(packet.free_count == 0);
	CHECK(netvsc_host_tx_active() == 0);
	CHECK(netvsc_host_early_completions() == early_before + 1);
	CHECK((uk_netdev_tx_one(netdev, 0, &packet.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	mock_flush_tx();
	CHECK(packet.free_count == 0);
	netvsc_host_remove_device(&offered);
	CHECK(packet.free_count == 1);
	return 0;
}

static int test_transaction_rollover(void)
{
	struct vmbus_device offered = {
		.channel_id = 85,
		.connection_id = 185,
		.present = 1,
	};
	struct host_netbuf first = { 0 };
	struct host_netbuf last = { 0 };
	struct host_netbuf next = { 0 };
	struct host_netbuf reaper = { 0 };
	struct uk_netdev *netdev;
	__u64 old_first;
	__u64 old_last;
	__u64 new_id;
	__u32 unknown_before;

	netvsc_host_reset();
	mock_reset();
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	mock.delay_tx = 1;
	netvsc_host_set_identity(7, (__u64)UINT32_MAX - 1, 1);
	prepare_tx_buffer(&first, 0x11, 60);
	prepare_tx_buffer(&last, 0x31, 60);
	prepare_tx_buffer(&next, 0x51, 60);
	CHECK((uk_netdev_tx_one(netdev, 0, &first.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	old_first = mock.last_tx_id;
	CHECK((__u32)old_first == UINT32_MAX - 1);
	CHECK((uk_netdev_tx_one(netdev, 0, &last.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	old_last = mock.last_tx_id;
	CHECK((__u32)old_last == UINT32_MAX);
	CHECK(netvsc_host_next_transaction() ==
	      (__u64)UINT32_MAX + 1);
	CHECK(uk_netdev_tx_one(netdev, 0, &next.netbuf) == 0);
	CHECK(netvsc_host_keepalive() == -EAGAIN);
	CHECK(netvsc_host_nvs_probe() == -EAGAIN);
	CHECK(next.free_count == 0 && netvsc_host_generation() == 7);
	mock_flush_tx();
	CHECK(first.free_count == 0 && last.free_count == 0);
	CHECK(netvsc_host_keepalive() == 0);
	CHECK(first.free_count == 1 && last.free_count == 1);
	CHECK(netvsc_host_generation() == 8);
	CHECK((uk_netdev_tx_one(netdev, 0, &next.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	new_id = mock.last_tx_id;
	CHECK((__u32)(new_id >> 32) == 8 && (__u32)new_id == 2);
	unknown_before = netvsc_host_unknown_completions();
	enqueue_rndis_send_complete(old_first);
	enqueue_rndis_send_complete(old_last);
	mock_signal();
	CHECK(next.free_count == 0 && netvsc_host_tx_active() == 1);
	CHECK(netvsc_host_unknown_completions() == unknown_before + 2);
	mock_flush_tx();
	prepare_tx_buffer(&reaper, 0x71, 1);
	CHECK(uk_netdev_tx_one(netdev, 0, &reaper.netbuf) == -EMSGSIZE);
	CHECK(next.free_count == 1);
	netvsc_host_set_identity(13, 5, 0);
	CHECK(netvsc_host_keepalive() == 0);
	CHECK(netvsc_host_generation() == 14);
	CHECK((__u32)(mock.last_control_transaction >> 32) == 14);
	CHECK((__u32)mock.last_control_transaction == 1);
	CHECK((mock.last_control_request >> 16) == 14);
	CHECK((__u16)mock.last_control_request == 1);
	netvsc_host_remove_device(&offered);
	return 0;
}

static int test_rollover_blocked_by_control(void)
{
	struct vmbus_device offered = {
		.channel_id = 84,
		.connection_id = 184,
		.present = 1,
	};
	struct control_thread_args control = { .result = -1 };
	struct host_netbuf packet = { 0 };
	struct host_netbuf reaper = { 0 };
	struct uk_netdev *netdev;
	pthread_t thread;
	int failure = 0;

	netvsc_host_reset();
	mock_reset();
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	netvsc_host_set_identity(9, UINT32_MAX, 1);
	prepare_tx_buffer(&packet, 0x81, 60);
	stage_gate_arm(&control_gate,
		       NETVSC_HOST_CONTROL_STAGE_AFTER_PUBLISH);
	if (pthread_create(&thread, NULL, control_thread_main, &control))
		return __LINE__;
	if (stage_gate_wait(&control_gate)) {
		failure = __LINE__;
		goto release;
	}
	if (uk_netdev_tx_one(netdev, 0, &packet.netbuf) != 0 ||
	    packet.free_count || netvsc_host_generation() != 9)
		failure = __LINE__;
release:
	stage_gate_release(&control_gate);
	pthread_join(thread, NULL);
	if (failure)
		return failure;
	CHECK(control.result == 0);
	CHECK((uk_netdev_tx_one(netdev, 0, &packet.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	CHECK(netvsc_host_generation() == 10);
	mock_signal();
	prepare_tx_buffer(&reaper, 0x91, 1);
	CHECK(uk_netdev_tx_one(netdev, 0, &reaper.netbuf) == -EMSGSIZE);
	CHECK(packet.free_count == 1);
	netvsc_host_remove_device(&offered);
	return 0;
}

static int test_rollover_blocked_by_nvs(void)
{
	struct vmbus_device offered = {
		.channel_id = 83,
		.connection_id = 183,
		.present = 1,
	};
	struct host_netbuf packet = { 0 };
	struct host_netbuf reaper = { 0 };
	struct uk_netdev *netdev;
	pthread_t thread;
	int nvs_result = -1;
	int failure = 0;

	netvsc_host_reset();
	mock_reset();
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	netvsc_host_set_identity(11, UINT32_MAX, 1);
	prepare_tx_buffer(&packet, 0xa1, 60);
	stage_gate_arm(&nvs_gate, NETVSC_HOST_NVS_STAGE_WAITING);
	if (pthread_create(&thread, NULL, nvs_thread_main, &nvs_result))
		return __LINE__;
	if (stage_gate_wait(&nvs_gate)) {
		failure = __LINE__;
		goto release;
	}
	if (!netvsc_host_nvs_active() ||
	    uk_netdev_tx_one(netdev, 0, &packet.netbuf) != 0 ||
	    packet.free_count || netvsc_host_generation() != 11)
		failure = __LINE__;
release:
	stage_gate_release(&nvs_gate);
	pthread_join(thread, NULL);
	if (failure)
		return failure;
	CHECK(nvs_result == 0);
	CHECK((uk_netdev_tx_one(netdev, 0, &packet.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	CHECK(netvsc_host_generation() == 12);
	mock_signal();
	prepare_tx_buffer(&reaper, 0xb1, 1);
	CHECK(uk_netdev_tx_one(netdev, 0, &reaper.netbuf) == -EMSGSIZE);
	CHECK(packet.free_count == 1);
	netvsc_host_remove_device(&offered);
	return 0;
}

static int test_generation_exhaustion_fails_closed(void)
{
	struct vmbus_device offered = {
		.channel_id = 82,
		.connection_id = 182,
		.present = 1,
	};
	struct host_netbuf packet = { 0 };
	struct uk_netdev *netdev;
	unsigned int failures;

	netvsc_host_reset();
	mock_reset();
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	netvsc_host_set_identity(UINT16_MAX, (__u64)UINT32_MAX + 1, 1);
	prepare_tx_buffer(&packet, 0xc1, 60);
	failures = mock.connection_fail_count;
	CHECK(uk_netdev_tx_one(netdev, 0, &packet.netbuf) == -EOVERFLOW);
	CHECK(packet.free_count == 0);
	CHECK(mock.connection_fail_count == failures + 1);
	CHECK(netdev->ops->probe(netdev) == -ENODEV);
	CHECK(uk_netdev_tx_one(netdev, 0, &packet.netbuf) == -ENODEV);
	CHECK(mock.connection_fail_count == failures + 1);
	netvsc_host_remove_device(&offered);
	return 0;
}

static int find_control_slot(__u64 transaction_id)
{
	unsigned int i;

	for (i = 0; i < CONFIG_LIBNETVSC_CONTROL_SLOTS; i++)
		if (netvsc_host_control_transaction(i) == transaction_id)
			return (int)i;
	return -1;
}

static int test_control_publication_reentry(void)
{
	struct vmbus_device offered = {
		.channel_id = 88,
		.connection_id = 188,
		.present = 1,
	};
	struct uk_netdev *netdev;

	netvsc_host_reset();
	mock_reset();
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	(void)netdev;
	mock.reenter_send_once = 1;
	CHECK(netvsc_host_keepalive() == 0);
	CHECK(netvsc_host_control_in_use() == 0);
	netvsc_host_remove_device(&offered);
	return 0;
}

static int test_control_waiter_generation_races(void)
{
	struct vmbus_device offered = {
		.channel_id = 89,
		.connection_id = 189,
		.present = 1,
	};
	struct control_thread_args first = { .result = -1 };
	struct control_thread_args second = { .result = -1 };
	struct uk_netdev *netdev;
	pthread_t first_thread;
	pthread_t second_thread;
	__u64 first_transaction;
	__u64 second_transaction;
	__u32 first_request;
	__u32 second_request;
	__u32 duplicate_before;
	__u32 unknown_before;
	int first_slot;
	int second_slot;
	int failure = 0;

	netvsc_host_reset();
	mock_reset();
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	(void)netdev;

	stage_gate_arm(&control_wait_gate,
		       NETVSC_HOST_CONTROL_STAGE_WAIT_DONE);
	if (pthread_create(&first_thread, NULL, control_thread_main, &first))
		return __LINE__;
	if (stage_gate_wait(&control_wait_gate)) {
		failure = __LINE__;
		goto release_waiter;
	}
	stage_gate_ids(&control_wait_gate, &first_transaction,
		       &first_request);
	first_slot = find_control_slot(first_transaction);
	if (!first_transaction || !first_request || first_slot < 0 ||
	    netvsc_host_control_in_use() != 1)
		failure = __LINE__;
	duplicate_before = netvsc_host_duplicate_completions();
	unknown_before = netvsc_host_unknown_completions();
	enqueue_rndis_send_complete(first_transaction);
	enqueue_rndis_control_complete(NETVSC_RNDIS_KEEPALIVE_COMPLETE,
				       first_request);
	enqueue_rndis_send_complete(first_transaction ^ 0x100000000ULL);
	enqueue_rndis_control_complete(NETVSC_RNDIS_KEEPALIVE_COMPLETE,
				       first_request ^ 0x10000U);
	mock_signal();
	if (!failure &&
	    (netvsc_host_control_in_use() != 1 ||
	     netvsc_host_control_transaction(first_slot) !=
		     first_transaction))
		failure = __LINE__;
release_waiter:
	stage_gate_release(&control_wait_gate);
	pthread_join(first_thread, NULL);
	if (failure)
		return failure;
	CHECK(first.result == 0);
	CHECK(netvsc_host_control_in_use() == 0);
	CHECK(netvsc_host_duplicate_completions() >= duplicate_before + 2);
	CHECK(netvsc_host_unknown_completions() >= unknown_before + 2);

	mock.suppress_control_nvs = 1;
	mock.suppress_control_rndis = 1;
	stage_gate_arm(&control_gate,
		       NETVSC_HOST_CONTROL_STAGE_CANCELLED);
	first.result = -1;
	if (pthread_create(&first_thread, NULL, control_thread_main, &first))
		return __LINE__;
	if (stage_gate_wait(&control_gate)) {
		failure = __LINE__;
		goto release_cancel;
	}
	stage_gate_ids(&control_gate, &first_transaction, &first_request);
	first_slot = find_control_slot(first_transaction);
	if (!first_transaction || !first_request || first_slot < 0 ||
	    netvsc_host_control_in_use() != 1)
		failure = __LINE__;
	enqueue_rndis_send_complete(first_transaction);
	mock_signal();
	if (!failure && netvsc_host_control_in_use() != 0)
		failure = __LINE__;

	mock.suppress_control_nvs = 0;
	mock.suppress_control_rndis = 0;
	stage_gate_arm(&control_wait_gate,
		       NETVSC_HOST_CONTROL_STAGE_WAIT_DONE);
	if (pthread_create(&second_thread, NULL, control_thread_main, &second)) {
		failure = __LINE__;
		goto release_cancel;
	}
	if (stage_gate_wait(&control_wait_gate)) {
		failure = __LINE__;
		stage_gate_release(&control_wait_gate);
		pthread_join(second_thread, NULL);
		goto release_cancel;
	}
	stage_gate_ids(&control_wait_gate, &second_transaction,
		       &second_request);
	second_slot = find_control_slot(second_transaction);
	if (!failure &&
	    (!second_transaction || !second_request ||
	     second_transaction == first_transaction ||
	     second_request == first_request || second_slot != first_slot ||
	     netvsc_host_control_in_use() != 1))
		failure = __LINE__;
	enqueue_rndis_send_complete(first_transaction);
	enqueue_rndis_control_complete(NETVSC_RNDIS_KEEPALIVE_COMPLETE,
				       first_request);
	mock_signal();
	if (!failure &&
	    (netvsc_host_control_in_use() != 1 ||
	     netvsc_host_control_transaction(second_slot) !=
		     second_transaction))
		failure = __LINE__;
	stage_gate_release(&control_gate);
	pthread_join(first_thread, NULL);
	if (!failure &&
	    (first.result != -ETIMEDOUT ||
	     netvsc_host_control_in_use() != 1 ||
	     netvsc_host_control_transaction(second_slot) !=
		     second_transaction))
		failure = __LINE__;
	stage_gate_release(&control_wait_gate);
	pthread_join(second_thread, NULL);
	if (failure)
		return failure;
	CHECK(second.result == 0);
	CHECK(netvsc_host_control_in_use() == 0);
	netvsc_host_remove_device(&offered);
	return 0;

release_cancel:
	stage_gate_release(&control_gate);
	pthread_join(first_thread, NULL);
	return failure;
}

static int test_rx_bounds_headroom_and_reentry(struct uk_netdev *netdev)
{
	__u8 frame[80];
	struct uk_netbuf *packet = NULL;
	unsigned int i;
	int status;

	for (i = 0; i < sizeof(frame); i++)
		frame[i] = (__u8)(0xa0 + i);
	CHECK(netdev->ops->rxq_intr_enable(netdev,
					   netdev->_rx_queue[0]) == 0);
	mock.reenter_receive = 1;
	inject_frame(frame, sizeof(frame));
	CHECK(mock.netdev_events != 0);
	CHECK(mock.reentered_packet != NULL);
	CHECK((uintptr_t)mock.reentered_packet->data -
	      (uintptr_t)mock.reentered_packet->buf == 64);
	CHECK(mock.reentered_packet->len == sizeof(frame));
	CHECK(memcmp(mock.reentered_packet->data, frame, sizeof(frame)) == 0);
	uk_netbuf_free(mock.reentered_packet);
	mock.reentered_packet = NULL;
	mock.reenter_receive = 0;

	chained_receive = 1;
	inject_frame(frame, sizeof(frame));
	status = netdev->rx_one(netdev, netdev->_rx_queue[0], &packet);
	CHECK((status & UK_NETDEV_STATUS_SUCCESS) != 0);
	CHECK(packet->len == 40);
	CHECK(packet->next && packet->next->len == 40);
	CHECK((uintptr_t)packet->data - (uintptr_t)packet->buf == 64);
	CHECK((uintptr_t)packet->next->data -
	      (uintptr_t)packet->next->buf == 32);
	CHECK(memcmp(packet->data, frame, 40) == 0);
	CHECK(memcmp(packet->next->data, frame + 40, 40) == 0);
	uk_netbuf_free(packet);
	chained_receive = 0;

	{
		const __u32 channel_types[] = {
			0,
			NETVSC_NVS_RNDIS_DATA,
			NETVSC_NVS_RNDIS_CONTROL,
			0xdeadbeefU,
		};
		unsigned int type_index;

		for (type_index = 0;
		     type_index < sizeof(channel_types) /
				      sizeof(channel_types[0]);
		     type_index++) {
			inject_frame_type(frame, sizeof(frame),
					  channel_types[type_index]);
			status = netdev->rx_one(netdev,
					netdev->_rx_queue[0], &packet);
			CHECK((status & UK_NETDEV_STATUS_SUCCESS) != 0);
			CHECK(packet->len == sizeof(frame));
			CHECK(memcmp(packet->data, frame,
				     sizeof(frame)) == 0);
			uk_netbuf_free(packet);
		}
	}

	/* RX ranges may start between slots and safely span multiple slots. */
	enqueue_frame_range(frame, sizeof(frame), 3, 4097);
	mock_signal();
	status = netdev->rx_one(netdev, netdev->_rx_queue[0], &packet);
	CHECK((status & UK_NETDEV_STATUS_SUCCESS) != 0);
	CHECK(packet->len == sizeof(frame));
	CHECK(memcmp(packet->data, frame, sizeof(frame)) == 0);
	uk_netbuf_free(packet);
	packet = NULL;

	/* NetVSC accepts aligned descriptor padding, never truncation. */
	{
		__u8 message[124] = { 0 };
		__u8 descriptor[24] = { 0 };
		__u8 nvs[NETVSC_NVS_REQUEST_SIZE] = { 0 };
		__u32 offset = 5;
		int header = netvsc_rndis_build_packet_header(
				message, sizeof(message), sizeof(frame));
		int nvs_length = netvsc_nvs_build_rndis(
				nvs, sizeof(nvs), NETVSC_NVS_RNDIS_DATA,
				NETVSC_NVS_SEND_SECTION_INVALID, 0);

		CHECK(header == 44 && nvs_length > 0);
		memcpy(message + header, frame, sizeof(frame));
		memcpy(netvsc_host_receive_buffer() + offset, message,
		       sizeof(message));
		put16(descriptor, NETVSC_NVS_RX_BUFFER_ID);
		put32(descriptor + 4, 1);
		put32(descriptor + 8, sizeof(message));
		put32(descriptor + 12, offset);
		memset(descriptor + 16, 0xcc, sizeof(descriptor) - 16);
		for (size_t descriptor_length = 16;
		     descriptor_length <= sizeof(descriptor);
		     descriptor_length += 4) {
			CHECK(netvsc_host_process_transfer(
					descriptor, descriptor_length,
					nvs, (size_t)nvs_length,
					0xa0000000ULL + descriptor_length) == 0);
			status = netdev->rx_one(netdev,
					netdev->_rx_queue[0], &packet);
			CHECK((status & UK_NETDEV_STATUS_SUCCESS) != 0);
			CHECK(packet->len == sizeof(frame));
			CHECK(memcmp(packet->data, frame,
				     sizeof(frame)) == 0);
			uk_netbuf_free(packet);
			packet = NULL;
		}
		CHECK(netvsc_host_process_transfer(descriptor, 15, nvs,
				(size_t)nvs_length, 0xa0000100ULL) == -EPROTO);
		CHECK(netvsc_host_process_transfer(descriptor, 17, nvs,
				(size_t)nvs_length, 0xa0000101ULL) == -EPROTO);
		put32(descriptor + 4, UINT32_MAX);
		CHECK(netvsc_host_process_transfer(descriptor,
				sizeof(descriptor), nvs, (size_t)nvs_length,
				0xa0000102ULL) == -EPROTO);
	}

	/* A saturated TX ring defers, then retries, the receive completion. */
	mock.ack_eagain = 2;
	{
		unsigned int acknowledgements = mock.ack_count;

		inject_frame(frame, sizeof(frame));
		CHECK(mock.ack_count == acknowledgements);
		mock_signal();
		CHECK(mock.ack_count == acknowledgements + 1);
		status = netdev->rx_one(netdev, netdev->_rx_queue[0], &packet);
		CHECK((status & UK_NETDEV_STATUS_SUCCESS) != 0);
		uk_netbuf_free(packet);
	}

	/* Malformed RNDIS and out-of-range transfer pages are acked and dropped. */
	{
		__u8 message[104] = { 0 };
		struct mock_packet *queued;
		unsigned int acknowledgements = mock.ack_count;

		CHECK(netvsc_rndis_build_packet_header(message,
				sizeof(message), 60) == 44);
		put32(message + 8, UINT32_MAX);
		mock.ack_eagain = 2;
		enqueue_transfer(message, sizeof(message),
				 NETVSC_NVS_RNDIS_DATA);
		mock_signal();
		CHECK(mock.ack_count == acknowledgements);
		mock_signal();
		CHECK(mock.ack_count == acknowledgements + 1);
		CHECK(mock.last_ack_status == NETVSC_NVS_STATUS_FAILED);
		CHECK(netvsc_host_receive_count() == 0);

		queued = queue_reserve();
		CHECK(queued != NULL);
		queued->packet.type =
			VMBUS_PACKET_DATA_USING_TRANSFER_PAGES;
		queued->packet.transaction_id = 0x123456;
		queued->descriptor_length = 16;
		queued->packet.descriptor_size = 16;
		put16(queued->descriptor, NETVSC_NVS_RX_BUFFER_ID);
		put32(queued->descriptor + 4, 1);
		put32(queued->descriptor + 8, 64);
		put32(queued->descriptor + 12,
		      (__u32)netvsc_host_receive_buffer_capacity());
		queued->payload_length = netvsc_nvs_build_rndis(
			queued->payload, sizeof(queued->payload),
			NETVSC_NVS_RNDIS_DATA,
			NETVSC_NVS_SEND_SECTION_INVALID, 0);
		queued->packet.payload_size = queued->payload_length;
		mock_signal();
		CHECK(mock.ack_count == acknowledgements + 2);

		enqueue_transfer(message, sizeof(message),
				 NETVSC_NVS_RNDIS_DATA);
		queued = &mock.queue[(mock.head - 1) % MOCK_QUEUE];
		put32(queued->payload, 999);
		mock_signal();
		CHECK(mock.ack_count == acknowledgements + 3);
		CHECK(mock.last_ack_status == NETVSC_NVS_STATUS_FAILED);

		enqueue_transfer(message, sizeof(message),
				 NETVSC_NVS_RNDIS_DATA);
		queued = &mock.queue[(mock.head - 1) % MOCK_QUEUE];
		queued->payload_length = 3;
		queued->packet.payload_size = 3;
		mock_signal();
		CHECK(mock.ack_count == acknowledgements + 4);
		CHECK(mock.last_ack_status == NETVSC_NVS_STATUS_FAILED);
	}
	return 0;
}

static int test_control_timeout_and_late_completion(struct uk_netdev *netdev)
{
	__u64 transactions[CONFIG_LIBNETVSC_CONTROL_SLOTS] = { 0 };
	__u32 requests[CONFIG_LIBNETVSC_CONTROL_SLOTS] = { 0 };
	unsigned int i;

	scheduler = NULL;
	CHECK(netdev->ops->promiscuous_set(netdev, 1) == -EWOULDBLOCK);
	CHECK(netvsc_host_control_in_use() == 0);
	scheduler = (struct uk_sched *)1;
	mock.suppress_control_nvs = 1;
	mock.suppress_control_rndis = 1;
	for (i = 0; i < CONFIG_LIBNETVSC_CONTROL_SLOTS; i++) {
		CHECK(netdev->ops->promiscuous_set(netdev, i & 1) ==
		      -ETIMEDOUT);
		transactions[i] = netvsc_host_control_transaction(i);
		requests[i] = netvsc_host_control_request(i);
		CHECK(transactions[i] != 0 && requests[i] != 0);
	}
	CHECK(netvsc_host_control_in_use() ==
	      CONFIG_LIBNETVSC_CONTROL_SLOTS);
	CHECK(netdev->ops->promiscuous_set(netdev, 1) == -ENOSPC);

	mock.suppress_control_nvs = 0;
	for (i = 0; i < CONFIG_LIBNETVSC_CONTROL_SLOTS; i++) {
		__u8 complete[8] = { 0 };

		put32(complete, 108);
		put32(complete + 4, 1);
		enqueue_completion(transactions[i], complete,
				   sizeof(complete));
	}
	mock_signal();
	CHECK(netvsc_host_control_in_use() == 0);

	/* Late RNDIS completions for cancelled IDs are harmless tombstones. */
	for (i = 0; i < CONFIG_LIBNETVSC_CONTROL_SLOTS; i++) {
		__u8 complete[16] = { 0 };

		put32(complete, NETVSC_RNDIS_SET_COMPLETE);
		put32(complete + 4, 16);
		put32(complete + 8, requests[i]);
		enqueue_transfer(complete, sizeof(complete),
				 NETVSC_NVS_RNDIS_CONTROL);
	}
	mock_signal();
	mock.suppress_control_rndis = 0;
	CHECK(netdev->ops->promiscuous_set(netdev, 1) == 0);
	mock.wrong_control_id_once = 1;
	CHECK(netdev->ops->promiscuous_set(netdev, 0) == -ETIMEDOUT);
	CHECK(netvsc_host_control_in_use() == 0);
	CHECK(netdev->ops->promiscuous_set(netdev, 0) == 0);
	return 0;
}

static int test_link_status(struct uk_netdev *netdev)
{
	struct host_netbuf packet = { 0 };
	struct host_netbuf reaper = { 0 };
	__u8 status_message[20] = { 0 };

	put32(status_message, NETVSC_RNDIS_INDICATE_STATUS);
	put32(status_message + 4, sizeof(status_message));
	put32(status_message + 8, NETVSC_RNDIS_STATUS_MEDIA_DISCONNECT);
	enqueue_transfer(status_message, sizeof(status_message),
			 NETVSC_NVS_RNDIS_CONTROL);
	mock_signal();
	prepare_tx_buffer(&packet, 0x19, 60);
	CHECK(uk_netdev_tx_one(netdev, 0, &packet.netbuf) == -ENETDOWN);
	CHECK(packet.free_count == 0);
	put32(status_message + 8, NETVSC_RNDIS_STATUS_MEDIA_CONNECT);
	enqueue_transfer(status_message, sizeof(status_message),
			 NETVSC_NVS_RNDIS_CONTROL);
	mock_signal();
	CHECK((uk_netdev_tx_one(netdev, 0, &packet.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	mock_signal();
	CHECK(packet.free_count == 0);
	prepare_tx_buffer(&reaper, 0x29, 1);
	CHECK(uk_netdev_tx_one(netdev, 0, &reaper.netbuf) == -EMSGSIZE);
	CHECK(packet.free_count == 1);
	return 0;
}

static int test_remove_and_reconnect(struct uk_netdev *netdev,
				     struct vmbus_device *offered)
{
	struct host_netbuf packet = { 0 };
	struct host_netbuf reaper = { 0 };
	__u8 frame[60] = { 0 };
	vmbus_channel_callback_t stale_callback;
	void *stale_arg;

	mock.delay_tx = 1;
	prepare_tx_buffer(&packet, 0x33, 60);
	CHECK((uk_netdev_tx_one(netdev, 0, &packet.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	mock.ack_eagain = 1000;
	inject_frame(frame, sizeof(frame));
	mock.stale_watch_id = mock.last_transfer_id;
	CHECK(netvsc_host_receive_count() == 1);
	stale_callback = mock.callback;
	stale_arg = mock.callback_arg;
	netvsc_host_remove_device(offered);
	CHECK(packet.free_count == 1);
	CHECK(netvsc_host_receive_count() == 0);
	CHECK(mock.close_count == 1);
	CHECK(mock.live_gpadls == 0);
	CHECK(mock.callback == NULL);
	stale_callback(&mock.channel, stale_arg);
	CHECK(packet.free_count == 1);

	mock.head = mock.tail = 0;
	mock.map_count = 0;
	mock.live_gpadls = 0;
	mock.nvs_init_attempts = 0;
	mock.delay_tx = 0;
	mock.ack_eagain = 0;
	mock.channel.open = 1;
	offered->channel = NULL;
	offered->present = 1;
	CHECK(netvsc_host_add_device(offered) == 0);
	CHECK(mock.stale_ack_count == 0);
	prepare_tx_buffer(&packet, 0x55, 60);
	CHECK((uk_netdev_tx_one(netdev, 0, &packet.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	mock_signal();
	CHECK(packet.free_count == 1);
	prepare_tx_buffer(&reaper, 0x65, 1);
	CHECK(uk_netdev_tx_one(netdev, 0, &reaper.netbuf) == -EMSGSIZE);
	CHECK(packet.free_count == 2);
	return 0;
}

static int test_handshake_cleanup_failures(void)
{
	struct {
		unsigned int open;
		unsigned int map;
		unsigned int rx;
		unsigned int send;
		unsigned int rndis;
		__u32 query;
	} failures[] = {
		{ .open = 1 },
		{ .map = 1 },
		{ .rx = 1 },
		{ .map = 2 },
		{ .send = 1 },
		{ .rndis = 1 },
		{ .query = NETVSC_OID_802_3_PERMANENT_ADDRESS },
	};
	unsigned int i;

	for (i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
		struct vmbus_device offered = {
			.channel_id = 50 + i,
			.connection_id = 70 + i,
			.present = 1,
		};

		netvsc_host_reset();
		mock_reset();
		mock.fail_open = failures[i].open;
		mock.fail_map_call = failures[i].map;
		mock.fail_receive_complete = failures[i].rx;
		mock.fail_send_complete = failures[i].send;
		mock.fail_rndis_init = failures[i].rndis;
		mock.fail_query_oid = failures[i].query;
		CHECK(netvsc_host_add_device(&offered) < 0);
		CHECK(netvsc_host_control_in_use() == 0);
		CHECK(netvsc_host_tx_active() == 0);
		CHECK(mock.live_gpadls == 0);
		if (!failures[i].open)
			CHECK(mock.close_count == 1);
	}

	return 0;
}

static int test_late_bind_consumer_readiness(void)
{
	struct vmbus_device offered = {
		.channel_id = 79,
		.connection_id = 179,
		.present = 1,
	};
	struct uk_netdev *netdev;

	netvsc_host_reset();
	mock_reset();
	mock.fail_map_call = 2;
	CHECK(netvsc_host_add_device(&offered) == -ENOSPC);
	CHECK(netvsc_host_netdev()->ops->probe(
		      netvsc_host_netdev()) == -ENODEV);
	CHECK(mock.close_count == 1);
	CHECK(mock.live_gpadls == 0);

	mock.fail_map_call = 0;
	mock.map_count = 0;
	mock.nvs_init_attempts = 0;
	mock.head = mock.tail = 0;
	mock.channel.open = 1;
	offered.channel = NULL;
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	CHECK(netdev == netvsc_host_netdev());
	netvsc_host_remove_device(&offered);
	return 0;
}

static int test_nvs_response_sizes_and_fallback(void)
{
	struct vmbus_device offered = {
		.channel_id = 80,
		.connection_id = 81,
		.present = 1,
	};
	int rc;

	netvsc_host_reset();
	mock_reset();
	mock.nvs_accept_index = 0;
	mock.init_response_length = 16;
	mock.receive_response_length = 28;
	mock.send_response_length = 12;
	CHECK(netvsc_host_add_device(&offered) == 0);
	netvsc_host_remove_device(&offered);

	netvsc_host_reset();
	mock_reset();
	mock.nvs_accept_index = 1;
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(mock.nvs_init_attempts == 2);
	CHECK(netvsc_host_nvs_version() == NETVSC_NVS_VERSION_6);
	netvsc_host_remove_device(&offered);

	netvsc_host_reset();
	mock_reset();
	mock.nvs_accept_index = 0;
	mock.receive_end_offset = 1;
	CHECK(netvsc_host_add_device(&offered) == 0);
	netvsc_host_remove_device(&offered);

	netvsc_host_reset();
	mock_reset();
	mock.nvs_accept_index = 0;
	mock.init_response_length = MOCK_NVS_RESPONSE_CAPACITY + 1;
	rc = netvsc_host_add_device(&offered);
	CHECK(rc == -ENOBUFS);
	CHECK(mock.nvs_init_requests == 1);

	netvsc_host_reset();
	mock_reset();
	mock.nvs_accept_index = 0;
	mock.init_response_length = 15;
	rc = netvsc_host_add_device(&offered);
	CHECK(rc == -EPROTO);
	CHECK(mock.nvs_init_requests == 1);

	netvsc_host_reset();
	mock_reset();
	mock.nvs_accept_index = 0;
	mock.suppress_nvs_init = 1;
	rc = netvsc_host_add_device(&offered);
	CHECK(rc == -ETIMEDOUT);
	CHECK(mock.nvs_init_requests == 1);

	netvsc_host_reset();
	mock_reset();
	mock.nvs_accept_index = 0;
	mock.nvs_init_status = 6;
	rc = netvsc_host_add_device(&offered);
	CHECK(rc == -EPROTO);
	CHECK(mock.nvs_init_requests == 1);

	netvsc_host_reset();
	mock_reset();
	mock.nvs_accept_index = 0;
	mock.send_response_length = MOCK_NVS_RESPONSE_CAPACITY + 1;
	CHECK(netvsc_host_add_device(&offered) == -ENOBUFS);

	netvsc_host_reset();
	mock_reset();
	mock.nvs_accept_index = 0;
	mock.send_response_length = 11;
	CHECK(netvsc_host_add_device(&offered) == -EPROTO);
	return 0;
}

static int test_gpa_fallback(void)
{
	struct vmbus_device offered = {
		.channel_id = 90,
		.connection_id = 91,
		.present = 1,
	};
	struct host_netbuf head = { 0 };
	struct host_netbuf tail = { 0 };
	struct uk_netdev *netdev;

	netvsc_host_reset();
	mock_reset();
	mock.send_section_size = 4;
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	prepare_tx_buffer(&head, 0x31, 30);
	prepare_tx_buffer(&tail, 0x61, 30);
	head.netbuf.next = &tail.netbuf;
	tail.netbuf.prev = &head.netbuf;
	CHECK((uk_netdev_tx_one(netdev, 0, &head.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	mock_signal();
	CHECK(head.free_count == 0 && tail.free_count == 0);
	CHECK(mock.last_tx[0] == 0x31 && mock.last_tx[30] == 0x61);
	netvsc_host_remove_device(&offered);
	CHECK(head.free_count == 1 && tail.free_count == 1);
	return 0;
}

static int test_failed_close_quarantines_tx(void)
{
	struct vmbus_device offered = {
		.channel_id = 92,
		.connection_id = 93,
		.present = 1,
	};
	struct host_netbuf packet = { 0 };
	struct uk_netdev *netdev;

	netvsc_host_reset();
	mock_reset();
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	mock.delay_tx = 1;
	prepare_tx_buffer(&packet, 0x71, 60);
	CHECK((uk_netdev_tx_one(netdev, 0, &packet.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	mock.fail_close = 1;
	netvsc_host_remove_device(&offered);
	CHECK(packet.free_count == 0);
	CHECK(netvsc_host_quarantined_tx() == 1);
	CHECK(mock.connection_fail_count == 1);

	mock.head = mock.tail = 0;
	mock.map_count = 0;
	mock.live_gpadls = 0;
	mock.nvs_init_attempts = 0;
	mock.delay_tx = 0;
	mock.fail_close = 0;
	mock.channel.open = 1;
	offered.channel = NULL;
	CHECK(netvsc_host_add_device(&offered) == -ENOSPC);
	CHECK(mock.bind_retry_count == 1);
	CHECK(packet.free_count == 0);
	mock.advance_quiesce_on_bind_epoch = 1;
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(mock.bind_epoch_count == 3);
	CHECK(packet.free_count == 1);
	CHECK(netvsc_host_quarantined_tx() == 0);
	CHECK(mock.bind_ready_count == 1);
	netvsc_host_remove_device(&offered);
	return 0;
}

static int test_post_publish_failure_quarantines_tx(void)
{
	struct vmbus_device offered = {
		.channel_id = 93,
		.connection_id = 94,
		.present = 1,
	};
	struct host_netbuf packet = { 0 };
	struct uk_netdev *netdev;

	netvsc_host_reset();
	mock_reset();
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	mock.delay_tx = 1;
	prepare_tx_buffer(&packet, 0x79, 60);
	mock.post_publish_error_once = 1;
	CHECK((uk_netdev_tx_one(netdev, 0, &packet.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	CHECK(mock.connection_fail_count == 1);
	CHECK(netvsc_host_tx_active() == 1);
	CHECK(packet.free_count == 0);
	mock_flush_tx();
	CHECK(packet.free_count == 0);

	netvsc_host_remove_device(&offered);
	CHECK(packet.free_count == 0);
	CHECK(netvsc_host_quarantined_tx() == 1);
	mock.head = mock.tail = 0;
	mock.map_count = 0;
	mock.live_gpadls = 0;
	mock.nvs_init_attempts = 0;
	mock.nvs_init_requests = 0;
	mock.delay_tx = 0;
	mock.channel.open = 1;
	offered.channel = NULL;
	CHECK(netvsc_host_add_device(&offered) == -ENOSPC);
	CHECK(packet.free_count == 0);
	mock.quiesce_epoch++;
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(packet.free_count == 1);
	CHECK(netvsc_host_quarantined_tx() == 0);
	netvsc_host_remove_device(&offered);
	return 0;
}

static int test_malformed_ring_recovery(void)
{
	struct vmbus_device offered = {
		.channel_id = 94,
		.connection_id = 95,
		.present = 1,
	};
	struct host_netbuf packet = { 0 };
	struct uk_netdev *netdev;
	struct uk_netbuf *received = NULL;
	__u8 frame[60] = { 0 };
	vmbus_channel_callback_t stale_callback;
	void *stale_arg;
	unsigned int events;

	netvsc_host_reset();
	mock_reset();
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	mock.delay_tx = 1;
	prepare_tx_buffer(&packet, 0x81, 60);
	CHECK((uk_netdev_tx_one(netdev, 0, &packet.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	CHECK(netdev->ops->rxq_intr_enable(netdev,
					   netdev->_rx_queue[0]) == 0);
	stale_callback = mock.callback;
	stale_arg = mock.callback_arg;
	events = mock.netdev_events;
	queue_frame_type(frame, sizeof(frame), NETVSC_NVS_RNDIS_DATA);
	mock.receive_error_once = -EPROTO;
	mock.receive_error_after = 1;
	mock_signal();
	CHECK(mock.connection_fail_count == 1);
	CHECK(mock.close_count == 0);
	CHECK(packet.free_count == 0);
	CHECK(mock.netdev_events == events);
	CHECK(netvsc_host_receive_count() == 1);
	stale_callback(&mock.channel, stale_arg);
	CHECK(mock.connection_fail_count == 1);
	netvsc_host_remove_device(&offered);
	CHECK(mock.close_count == 1);
	CHECK(packet.free_count == 0);
	CHECK(netvsc_host_quarantined_tx() == 1);

	mock.head = mock.tail = 0;
	mock.map_count = 0;
	mock.live_gpadls = 0;
	mock.nvs_init_attempts = 0;
	mock.nvs_init_requests = 0;
	mock.delay_tx = 0;
	mock.channel.open = 1;
	offered.channel = NULL;
	CHECK(netvsc_host_add_device(&offered) == -ENOSPC);
	CHECK(packet.free_count == 0);
	mock.quiesce_epoch++;
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(packet.free_count == 1);
	events = mock.netdev_events;
	inject_frame(frame, sizeof(frame));
	CHECK(mock.netdev_events == events + 1);
	CHECK((netdev->rx_one(netdev, netdev->_rx_queue[0], &received) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	uk_netbuf_free(received);
	netvsc_host_remove_device(&offered);

	netvsc_host_reset();
	mock_reset();
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	mock.delay_tx = 1;
	prepare_tx_buffer(&packet, 0x91, 60);
	CHECK((uk_netdev_tx_one(netdev, 0, &packet.netbuf) &
	       UK_NETDEV_STATUS_SUCCESS) != 0);
	mock.fail_close = 1;
	mock.receive_error_once = -ENOBUFS;
	mock_signal();
	CHECK(mock.connection_fail_count == 1);
	netvsc_host_remove_device(&offered);
	CHECK(packet.free_count == 1);
	CHECK(netvsc_host_quarantined_tx() == 1);

	mock.head = mock.tail = 0;
	mock.map_count = 0;
	mock.live_gpadls = 0;
	mock.nvs_init_attempts = 0;
	mock.nvs_init_requests = 0;
	mock.delay_tx = 0;
	mock.fail_close = 0;
	mock.channel.open = 1;
	offered.channel = NULL;
	CHECK(netvsc_host_add_device(&offered) == -ENOSPC);
	CHECK(packet.free_count == 1);
	mock.quiesce_epoch++;
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(packet.free_count == 2);
	CHECK(netvsc_host_quarantined_tx() == 0);
	netvsc_host_remove_device(&offered);
	return 0;
}

static int test_bounded_channel_drain_and_cleanup(__u32 version)
{
	struct vmbus_device offered = {
		.channel_id = 97,
		.connection_id = 197,
		.present = 1,
	};
	struct host_netbuf packets[CONFIG_LIBNETVSC_TX_SLOTS] = { 0 };
	struct host_netbuf blocked = { 0 };
	struct uk_netdev *netdev;
	__u8 frame[60] = { 0 };
	unsigned int acknowledgements;
	unsigned int deferred;
	unsigned int received;
	unsigned int budget;
	unsigned int i;

	netvsc_host_reset();
	mock_reset();
	mock.protocol_version = version;
	CHECK(netvsc_host_add_device(&offered) == 0);
	CHECK(configure_and_start(&netdev) == 0);
	mock.delay_tx = 1;
	for (i = 0; i < CONFIG_LIBNETVSC_TX_SLOTS; i++) {
		prepare_tx_buffer(&packets[i], (__u8)(0x80 + i), 60);
		CHECK((uk_netdev_tx_one(netdev, 0, &packets[i].netbuf) &
		       UK_NETDEV_STATUS_SUCCESS) != 0);
	}
	CHECK(netvsc_host_tx_active() == CONFIG_LIBNETVSC_TX_SLOTS);

	queue_frame_type(frame, sizeof(frame), NETVSC_NVS_RNDIS_DATA);
	mock.replenish_receive = 1;
	mock.reenter_channel_once = 1;
	received = mock.receive_calls;
	acknowledgements = mock.ack_count;
	deferred = mock.deferred_count;
	budget = netvsc_host_drain_budget();
	mock_signal();
	CHECK(mock.receive_calls == received + budget);
	CHECK(mock.ack_count == acknowledgements + budget);
	CHECK(mock.deferred_count == deferred + 1);
	CHECK(mock.deferred_signal);
	CHECK(!netvsc_host_drain_active());
	CHECK(!netvsc_host_drain_pending());

	received = mock.receive_calls;
	deferred = mock.deferred_count;
	CHECK(mock_run_deferred());
	CHECK(mock.receive_calls == received + budget);
	CHECK(mock.deferred_count == deferred + 1);
	CHECK(mock.deferred_signal);
	CHECK(!netvsc_host_drain_active());
	CHECK(!netvsc_host_drain_pending());

	prepare_tx_buffer(&blocked, 0xd0, 60);
	received = mock.receive_calls;
	CHECK(uk_netdev_tx_one(netdev, 0, &blocked.netbuf) == 0);
	CHECK(mock.receive_calls == received + budget);
	CHECK(blocked.free_count == 0);
	CHECK(mock.deferred_signal);
	CHECK(!netvsc_host_drain_active());
	CHECK(!netvsc_host_drain_pending());

	mock.replenish_receive = 0;
	netvsc_host_remove_device(&offered);
	for (i = 0; i < CONFIG_LIBNETVSC_TX_SLOTS; i++)
		CHECK(packets[i].free_count == 1);
	CHECK(blocked.free_count == 0);
	CHECK(netvsc_host_tx_active() == 0);
	CHECK(netvsc_host_receive_count() == 0);
	for (i = 0; i < MOCK_NETBUF_COUNT; i++)
		CHECK(!rx_buffers[i].in_use);
	CHECK(!netvsc_host_drain_active());
	CHECK(!netvsc_host_drain_pending());
	CHECK(mock.callback == NULL);
	received = mock.receive_calls;
	CHECK(mock_run_deferred());
	CHECK(mock.receive_calls == received);
	return 0;
}

int main(void)
{
	struct vmbus_device offered = {
		.channel_id = 7,
		.connection_id = 11,
		.present = 1,
	};
	struct uk_netdev *netdev;
	int rc;

	rc = test_attach_and_lifecycle(&offered);
	if (rc)
		return rc;
	netdev = netvsc_host_netdev();
	rc = test_tx_ownership_and_saturation(netdev);
	if (rc)
		return rc;
	rc = test_rx_bounds_headroom_and_reentry(netdev);
	if (rc)
		return rc;
	rc = test_control_timeout_and_late_completion(netdev);
	if (rc)
		return rc;
	rc = test_link_status(netdev);
	if (rc)
		return rc;
	rc = test_remove_and_reconnect(netdev, &offered);
	if (rc)
		return rc;
	netvsc_host_remove_device(&offered);
	rc = test_handshake_cleanup_failures();
	if (rc)
		return rc;
	rc = test_late_bind_consumer_readiness();
	if (rc)
		return rc;
	rc = test_nvs_response_sizes_and_fallback();
	if (rc)
		return rc;
	rc = test_gpa_fallback();
	if (rc)
		return rc;
	rc = test_tx_publication_races();
	if (rc)
		return rc;
	rc = test_tx_completion_races_wrapper_stats();
	if (rc)
		return rc;
	rc = test_tx_concurrent_wrapper_grace();
	if (rc)
		return rc;
	rc = test_tx_unpublished_early_completion();
	if (rc)
		return rc;
	rc = test_transaction_rollover();
	if (rc)
		return rc;
	rc = test_rollover_blocked_by_control();
	if (rc)
		return rc;
	rc = test_rollover_blocked_by_nvs();
	if (rc)
		return rc;
	rc = test_generation_exhaustion_fails_closed();
	if (rc)
		return rc;
	rc = test_control_publication_reentry();
	if (rc)
		return rc;
	rc = test_control_waiter_generation_races();
	if (rc)
		return rc;
	rc = test_post_publish_failure_quarantines_tx();
	if (rc)
		return rc;
	rc = test_failed_close_quarantines_tx();
	if (rc)
		return rc;
	{
		const __u32 versions[] = {
			VMBUS_EVENT_VERSION_WIN8, (1U << 16) | 1U, 13U
		};
		unsigned int i;

		for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
			rc = test_bounded_channel_drain_and_cleanup(versions[i]);
			if (rc)
				return rc;
		}
	}
	return test_malformed_ring_recovery();
}
