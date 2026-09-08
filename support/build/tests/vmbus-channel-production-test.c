/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <uk/arch/types.h>
#include <uk/vmbus.h>
#include "vmbus_channel_core.h"
#include "vmbus_internal.h"
#include "vmbus_protocol.h"

int vmbus_channel_host_nested_ownership_test(void);
int vmbus_bus_host_production_test(void);
int vmbus_bus_host_quiesce_epoch_test(void);
struct vmbus_channel *
vmbus_channel_host_prepare_open(struct vmbus_device *device);
struct vmbus_channel *
vmbus_channel_host_allocate_open(struct vmbus_device *device);
int vmbus_channel_host_pages_used(void);
int vmbus_channel_host_record_count(void);
int vmbus_channel_host_live_gpadls(void);
int vmbus_channel_host_is_free(struct vmbus_channel *channel);
int vmbus_channel_host_is_revoked(struct vmbus_channel *channel);
int vmbus_channel_host_attach_gpadl(struct vmbus_channel *channel,
				    __u32 gpadl_id);
void vmbus_bus_host_set_transmit_error(int error);
int vmbus_bus_host_connection_failed(void);
void vmbus_bus_host_clear_connection_failed(void);
void vmbus_bus_host_auto_pump(int enabled);
void vmbus_bus_host_set_gpadl_status(__u32 status);
void vmbus_bus_host_set_transmit_fail_after(int successful_posts);
void vmbus_bus_host_reset_gpadl_trace(void);
unsigned int vmbus_bus_host_gpadl_body_posts(void);
unsigned int vmbus_bus_host_gpadl_teardown_posts(void);

#ifndef VMBUS_REAL_PROTOCOL_TEST
int vmbus_post_message(__u32 connection_id __attribute__((unused)),
		       __u32 message_type __attribute__((unused)),
		       const __u8 *payload __attribute__((unused)),
		       size_t payload_len __attribute__((unused)),
		       __u64 input_gpa __attribute__((unused)),
		       __u16 *status_code __attribute__((unused)),
		       __u8 has_post_messages __attribute__((unused)),
		       __u32 retry_limit __attribute__((unused)),
		       vmbus_hypercall_fn hypercall __attribute__((unused)),
		       vmbus_backoff_fn backoff __attribute__((unused)),
		       void *arg __attribute__((unused)))
{
	return 0;
}

int vmbus_protocol_post_failure(__u16 status_code __attribute__((unused)),
				__u64 now __attribute__((unused)),
				struct vmbus_action *action)
{
	action->kind = VMBUS_ACTION_NONE;
	return 0;
}

void *vmbus_post_input(void)
{
	static __u8 input[256] __attribute__((aligned(256)));

	return input;
}
__u32 vmbus_protocol_connection_id(void) { return 1; }
__u32 vmbus_protocol_version(void) { return (2U << 16) | 4U; }
int vmbus_protocol_state(void) { return VMBUS_STATE_IDLE; }
__u32 vmbus_protocol_generation(void) { return 1; }
void vmbus_protocol_start(__u64 now __attribute__((unused)),
			  const struct vmbus_start_config *config
				  __attribute__((unused)),
			  struct vmbus_action *action)
{
	action->kind = VMBUS_ACTION_NONE;
}
void vmbus_protocol_tick(__u64 now __attribute__((unused)),
			 struct vmbus_action *action)
{
	action->kind = VMBUS_ACTION_NONE;
}
void vmbus_protocol_unload(__u64 now __attribute__((unused)),
			   struct vmbus_action *action)
{
	action->kind = VMBUS_ACTION_NONE;
}
void vmbus_protocol_reset(void)
{
}
void vmbus_protocol_receive(const __u8 *payload __attribute__((unused)),
			    size_t length __attribute__((unused)),
			    __u32 generation __attribute__((unused)),
			    __u64 now __attribute__((unused)),
			    struct vmbus_action *action)
{
	action->kind = VMBUS_ACTION_NONE;
}
void vmbus_protocol_release(__u32 channel_id __attribute__((unused)),
			    struct vmbus_action *action)
{
	action->kind = VMBUS_ACTION_NONE;
}
#endif

static void write32(__u8 *output, __u32 value)
{
	output[0] = (__u8)value;
	output[1] = (__u8)(value >> 8);
	output[2] = (__u8)(value >> 16);
	output[3] = (__u8)(value >> 24);
}

int vmbus_ring_initialize(__u8 *base __attribute__((unused)),
			  size_t size __attribute__((unused)))
{
	return 0;
}

static pthread_mutex_t ring_gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ring_condition = PTHREAD_COND_INITIALIZER;
static int ring_blocked;
static int ring_entered;
static int ring_need_signal;
static int ring_read_once;
static struct vmbus_packet_meta_abi ring_read_meta;
static pthread_mutex_t signal_gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t signal_condition = PTHREAD_COND_INITIALIZER;
static int host_signal_blocked;
static int host_signal_entered;
static int host_signal_result;

static void ring_wait(void)
{
	pthread_mutex_lock(&ring_gate);
	ring_entered = 1;
	pthread_cond_broadcast(&ring_condition);
	while (ring_blocked)
		pthread_cond_wait(&ring_condition, &ring_gate);
	pthread_mutex_unlock(&ring_gate);
}

int vmbus_ring_write(__u8 *base, size_t total_size,
		     __u16 packet_type __attribute__((unused)),
		     __u16 flags __attribute__((unused)),
		     __u64 transaction_id __attribute__((unused)),
		     const __u8 *descriptor __attribute__((unused)),
		     size_t descriptor_size __attribute__((unused)),
		     const __u8 *payload __attribute__((unused)),
		     size_t payload_size __attribute__((unused)),
		     __u8 *need_signal)
{
	if (!base || !total_size)
		return -2;
	ring_wait();
	*need_signal = ring_need_signal;
	return 0;
}

int vmbus_ring_read(__u8 *base, size_t total_size,
		    struct vmbus_packet_meta_abi *meta,
		    __u8 *descriptor __attribute__((unused)),
		    size_t descriptor_capacity __attribute__((unused)),
		    __u8 *payload __attribute__((unused)),
		    size_t payload_capacity __attribute__((unused)))
{
	if (!base || !total_size)
		return -2;
	ring_wait();
	if (ring_read_once) {
		ring_read_once = 0;
		*meta = ring_read_meta;
		return 0;
	}
	return 1;
}

int vmbus_ring_set_interrupt_mask(__u8 *base, size_t total_size,
				  __u8 masked __attribute__((unused)))
{
	if (!base || !total_size)
		return -2;
	ring_wait();
	return 0;
}

__u32 vmbus_ring_unmask_and_readable(__u8 *base, size_t total_size)
{
	if (!base || !total_size)
		return 0;
	ring_wait();
	return 1;
}

__u32 vmbus_ring_readable(__u8 *base, size_t total_size)
{
	if (!base || !total_size)
		return 0;
	ring_wait();
	return 1;
}

int vmbus_signal_event(
	struct vmbus_signal_input_abi *input __attribute__((unused)),
	__u32 connection_id __attribute__((unused)),
	__u16 event_flag __attribute__((unused)),
	__u64 input_gpa __attribute__((unused)),
	vmbus_channel_hypercall_fn hypercall __attribute__((unused)),
	void *arg __attribute__((unused)))
{
	pthread_mutex_lock(&signal_gate);
	host_signal_entered = 1;
	pthread_cond_broadcast(&signal_condition);
	while (host_signal_blocked)
		pthread_cond_wait(&signal_condition, &signal_gate);
	pthread_mutex_unlock(&signal_gate);
	return host_signal_result;
}

int vmbus_gpadl_header(__u8 *output, size_t capacity,
		       __u32 channel_id, __u32 gpadl_id,
		       __u32 byte_count __attribute__((unused)),
		       const __u64 *pfns __attribute__((unused)),
		       size_t pfn_count, size_t *consumed)
{
	if (capacity < 20)
		return -1;
	write32(output, 8);
	write32(output + 8, channel_id);
	write32(output + 12, gpadl_id);
	*consumed = pfn_count > 26 ? 26 : pfn_count;
	return 20;
}

int vmbus_gpadl_body(__u8 *output, size_t capacity,
		     __u32 message_number __attribute__((unused)),
		     __u32 gpadl_id, const __u64 *pfns __attribute__((unused)),
		     size_t pfn_count, size_t *consumed)
{
	if (capacity < 16)
		return -1;
	write32(output, 9);
	write32(output + 12, gpadl_id);
	*consumed = pfn_count > 28 ? 28 : pfn_count;
	return 16;
}

int vmbus_open_message(__u8 *output, size_t capacity, __u32 channel_id,
		       __u32 open_id, __u32 gpadl_id __attribute__((unused)),
		       __u32 target_vp __attribute__((unused)),
		       __u32 tx_pages __attribute__((unused)),
		       const __u8 *user_data __attribute__((unused)),
		       size_t user_data_size __attribute__((unused)))
{
	if (capacity < 20)
		return -1;
	write32(output, 5);
	write32(output + 8, channel_id);
	write32(output + 12, open_id);
	return 20;
}

int vmbus_close_message(__u8 *output, size_t capacity,
			__u32 channel_id)
{
	if (capacity < 12)
		return -1;
	write32(output, 7);
	write32(output + 8, channel_id);
	return 12;
}

int vmbus_gpadl_teardown_message(__u8 *output, size_t capacity,
				 __u32 channel_id, __u32 gpadl_id)
{
	if (capacity < 16)
		return -1;
	write32(output, 11);
	write32(output + 8, channel_id);
	write32(output + 12, gpadl_id);
	return 16;
}

struct channel_thread {
	struct vmbus_channel *channel;
	__u32 channel_id;
	int result;
};

static void *send_thread(void *arg)
{
	struct channel_thread *thread = arg;
	__u8 value = 1;

	thread->result = vmbus_channel_send(thread->channel, 6, 0, 1,
					    NULL, 0, &value, 1);
	return NULL;
}

static void *receive_thread(void *arg)
{
	struct channel_thread *thread = arg;
	struct vmbus_packet packet;

	thread->result = vmbus_channel_receive(thread->channel, &packet,
					       NULL, 0, NULL, 0);
	return NULL;
}

static void *rescind_thread(void *arg)
{
	struct channel_thread *thread = arg;

	thread->result = vmbus_channel_rescind(thread->channel_id);
	return NULL;
}

static void *poll_thread(void *arg)
{
	struct channel_thread *thread = arg;

	thread->result = vmbus_channel_poll(thread->channel);
	return NULL;
}

static void *mask_thread(void *arg)
{
	struct channel_thread *thread = arg;

	thread->result = vmbus_channel_mask_interrupts(thread->channel);
	return NULL;
}

static void *unmask_thread(void *arg)
{
	struct channel_thread *thread = arg;

	thread->result = vmbus_channel_unmask_interrupts(thread->channel);
	return NULL;
}

static void *close_thread(void *arg)
{
	struct channel_thread *thread = arg;

	thread->result = vmbus_channel_close(thread->channel);
	return NULL;
}

static void wait_for_ring(void)
{
	pthread_mutex_lock(&ring_gate);
	while (!ring_entered)
		pthread_cond_wait(&ring_condition, &ring_gate);
	pthread_mutex_unlock(&ring_gate);
}

static void release_ring(void)
{
	pthread_mutex_lock(&ring_gate);
	ring_blocked = 0;
	pthread_cond_broadcast(&ring_condition);
	pthread_mutex_unlock(&ring_gate);
}

static void wait_for_signal(void)
{
	pthread_mutex_lock(&signal_gate);
	while (!host_signal_entered)
		pthread_cond_wait(&signal_condition, &signal_gate);
	pthread_mutex_unlock(&signal_gate);
}

static void release_signal(void)
{
	pthread_mutex_lock(&signal_gate);
	host_signal_blocked = 0;
	pthread_cond_broadcast(&signal_condition);
	pthread_mutex_unlock(&signal_gate);
}

static int test_data_lifetime(void)
{
	struct vmbus_device device = {
		.channel_id = 20,
		.connection_id = 120,
		.present = 1,
	};
	struct channel_thread io = { 0 };
	struct channel_thread control = { 0 };
	struct vmbus_device second_device = {
		.channel_id = 26,
		.connection_id = 126,
		.present = 1,
	};
	struct vmbus_channel *second_channel;
	pthread_t io_thread;
	pthread_t control_thread;

	io.channel = vmbus_channel_host_prepare_open(&device);
	control.channel = io.channel;
	control.channel_id = 20;
	if (!io.channel || vmbus_channel_host_pages_used() != 4)
		return 201;
	ring_blocked = 1;
	ring_entered = 0;
	if (pthread_create(&io_thread, NULL, send_thread, &io) ||
	    (wait_for_ring(), pthread_create(&control_thread, NULL,
					     rescind_thread, &control)))
		return 202;
	while (!vmbus_channel_host_is_revoked(io.channel))
		;
	if (vmbus_channel_poll(io.channel) != -ECANCELED)
		return 203;
	second_channel = vmbus_channel_host_allocate_open(&second_device);
	if (!second_channel || second_channel == io.channel ||
	    vmbus_channel_host_pages_used() != 8)
		return 204;
	release_ring();
	pthread_join(io_thread, NULL);
	pthread_join(control_thread, NULL);
	if (io.result || control.result != -EINPROGRESS ||
	    !vmbus_channel_host_is_free(io.channel) ||
	    vmbus_channel_host_pages_used() != 4)
		return 205;
	if (vmbus_channel_send(io.channel, 6, 0, 1, NULL, 0, NULL, 0) !=
	    -ENODEV ||
	    vmbus_channel_poll(io.channel) != -ENODEV ||
	    vmbus_channel_mask_interrupts(io.channel) != -ENODEV ||
	    vmbus_channel_unmask_interrupts(io.channel) != -ENODEV)
		return 206;
	if (vmbus_channel_close(second_channel) ||
	    vmbus_channel_host_pages_used())
		return 207;

	device.channel_id = 21;
	device.connection_id = 121;
	device.channel = NULL;
	io.channel = vmbus_channel_host_prepare_open(&device);
	control.channel = io.channel;
	control.channel_id = 21;
	ring_blocked = 1;
	ring_entered = 0;
	if (!io.channel ||
	    pthread_create(&io_thread, NULL, receive_thread, &io))
		return 208;
	wait_for_ring();
	if (pthread_create(&control_thread, NULL, close_thread, &control))
		return 209;
	release_ring();
	pthread_join(io_thread, NULL);
	pthread_join(control_thread, NULL);
	if (io.result != -EAGAIN || control.result ||
	    !vmbus_channel_host_is_free(io.channel) ||
	    vmbus_channel_host_pages_used())
		return 210;
	return 0;
}

static int test_simple_io_race(void *(*operation)(void *), __u32 channel_id,
			       int expected, int error_base)
{
	struct vmbus_device device = {
		.channel_id = channel_id,
		.connection_id = channel_id + 100,
		.present = 1,
	};
	struct channel_thread io = { 0 };
	struct channel_thread control = { 0 };
	pthread_t io_thread;
	pthread_t control_thread;

	io.channel = vmbus_channel_host_prepare_open(&device);
	control.channel = io.channel;
	control.channel_id = channel_id;
	ring_blocked = 1;
	ring_entered = 0;
	if (!io.channel || pthread_create(&io_thread, NULL, operation, &io))
		return error_base;
	wait_for_ring();
	if (pthread_create(&control_thread, NULL, rescind_thread, &control))
		return error_base + 1;
	release_ring();
	pthread_join(io_thread, NULL);
	pthread_join(control_thread, NULL);
	if (io.result != expected || control.result != -EINPROGRESS ||
	    !vmbus_channel_host_is_free(io.channel) ||
	    vmbus_channel_host_pages_used())
		return error_base + 2;
	return 0;
}

static int test_signal_lifetime(void)
{
	struct vmbus_device device = {
		.channel_id = 25,
		.connection_id = 125,
		.present = 1,
	};
	struct channel_thread io = { 0 };
	struct channel_thread control = { 0 };
	pthread_t io_thread;
	pthread_t control_thread;

	io.channel = vmbus_channel_host_prepare_open(&device);
	control.channel = io.channel;
	control.channel_id = 25;
	if (!io.channel)
		return 271;
	ring_blocked = 0;
	ring_need_signal = 1;
	host_signal_blocked = 1;
	host_signal_entered = 0;
	if (pthread_create(&io_thread, NULL, send_thread, &io))
		return 272;
	wait_for_signal();
	if (pthread_create(&control_thread, NULL, rescind_thread, &control))
		return 273;
	release_signal();
	pthread_join(io_thread, NULL);
	pthread_join(control_thread, NULL);
	ring_need_signal = 0;
	if (io.result || control.result != -EINPROGRESS ||
	    !vmbus_channel_host_is_free(io.channel) ||
	    vmbus_channel_host_pages_used())
		return 274;
	return 0;
}

static int test_send_publication(void)
{
	struct vmbus_device device = {
		.channel_id = 27,
		.connection_id = 127,
		.present = 1,
	};
	struct vmbus_channel *channel;
	struct vmbus_gpa_range range;
	__u8 value = 1;
	__u64 pfn = 1;
	int published = -1;
	int rc;

	channel = vmbus_channel_host_prepare_open(&device);
	if (!channel)
		return 275;
	ring_blocked = 0;
	ring_need_signal = 1;
	host_signal_blocked = 0;
	host_signal_result = -1;
	rc = vmbus_channel_send_ex(channel, 6, 0, 1, NULL, 0,
				   &value, sizeof(value), &published);
	host_signal_result = 0;
	ring_need_signal = 0;
	if (rc != -EIO || published != 1)
		return 276;
	published = -1;
	if (vmbus_channel_send_ex(channel, 6, 0, 2, NULL, 1,
				  &value, sizeof(value), &published) !=
	    -EINVAL ||
	    published != 0)
		return 277;
	range.byte_count = 1;
	range.byte_offset = 0;
	range.pfns = &pfn;
	range.pfn_count = UINT32_MAX;
	published = -1;
	if (vmbus_channel_send_gpa_direct_ex(channel, 0, 3, &range, 1,
					     &value, sizeof(value),
					     &published) != -EINVAL ||
	    published != 0)
		return 279;
	if (vmbus_channel_rescind(27) != -EINPROGRESS)
		return 278;
	return 0;
}

static int test_connection_fail_api(void)
{
	__u64 epoch = vmbus_connection_quiesce_epoch();

	vmbus_bus_host_clear_connection_failed();
	if (vmbus_connection_fail() != epoch ||
	    vmbus_connection_quiesce_epoch() != epoch ||
	    !vmbus_bus_host_connection_failed())
		return 280;
	vmbus_bus_host_clear_connection_failed();
	return 0;
}

static pthread_mutex_t callback_gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t callback_condition = PTHREAD_COND_INITIALIZER;
static int callback_entered;
static int callback_blocked;
static int callback_count;

static void blocking_callback(struct vmbus_channel *channel
			      __attribute__((unused)),
			      void *arg __attribute__((unused)))
{
	pthread_mutex_lock(&callback_gate);
	callback_count++;
	callback_entered = 1;
	pthread_cond_broadcast(&callback_condition);
	while (callback_blocked)
		pthread_cond_wait(&callback_condition, &callback_gate);
	pthread_mutex_unlock(&callback_gate);
}

static void *event_thread(void *arg __attribute__((unused)))
{
	vmbus_channel_event(20);
	return NULL;
}

static int test_callback_lifetime(void)
{
	struct vmbus_device device = {
		.channel_id = 20,
		.connection_id = 120,
		.present = 1,
	};
	struct channel_thread control = { 0 };
	pthread_t callback_thread;
	pthread_t control_thread;

	control.channel = vmbus_channel_host_prepare_open(&device);
	control.channel_id = 20;
	if (!control.channel)
		return 211;
	vmbus_channel_set_callback(control.channel, blocking_callback, NULL);
	callback_entered = 0;
	callback_blocked = 1;
	callback_count = 0;
	if (pthread_create(&callback_thread, NULL, event_thread, NULL))
		return 212;
	pthread_mutex_lock(&callback_gate);
	while (!callback_entered)
		pthread_cond_wait(&callback_condition, &callback_gate);
	pthread_mutex_unlock(&callback_gate);
	if (pthread_create(&control_thread, NULL, rescind_thread, &control))
		return 213;
	pthread_join(control_thread, NULL);
	if (vmbus_channel_host_pages_used() != 4 ||
	    vmbus_channel_host_is_free(control.channel))
		return 214;
	pthread_mutex_lock(&callback_gate);
	callback_blocked = 0;
	pthread_cond_broadcast(&callback_condition);
	pthread_mutex_unlock(&callback_gate);
	pthread_join(callback_thread, NULL);
	if (!vmbus_channel_host_is_free(control.channel) ||
	    vmbus_channel_host_pages_used())
		return 215;
	vmbus_channel_event(20);
	if (callback_count != 1)
		return 216;
	return 0;
}

static void torndown(__u32 id)
{
	__u8 response[12] = { 0 };

	write32(response, 12);
	write32(response + 8, id);
	(void)vmbus_channel_control_receive(response, sizeof(response));
}

static void gpadl_created(__u32 channel_id, __u32 id, __u32 status)
{
	__u8 response[20] = { 0 };

	write32(response, 10);
	write32(response + 8, channel_id);
	write32(response + 12, id);
	write32(response + 16, status);
	(void)vmbus_channel_control_receive(response, sizeof(response));
}

static int test_gpadl_quarantine(void)
{
	struct vmbus_device first = {
		.channel_id = 20,
		.connection_id = 120,
		.present = 1,
	};
	struct vmbus_device second = {
		.channel_id = 21,
		.connection_id = 121,
		.present = 1,
	};
	struct vmbus_channel *first_channel;
	struct vmbus_channel *second_channel;

	first_channel = vmbus_channel_host_prepare_open(&first);
	if (!first_channel ||
	    vmbus_channel_host_attach_gpadl(first_channel, 0x1234))
		return 221;
	vmbus_bus_host_set_transmit_error(0);
	vmbus_bus_host_clear_connection_failed();
	if (vmbus_channel_rescind(20) != -EINPROGRESS ||
	    vmbus_channel_host_pages_used() != 4)
		return 222;
	second_channel = vmbus_channel_host_allocate_open(&second);
	if (!second_channel || vmbus_channel_host_pages_used() != 8)
		return 223;
	torndown(0x1235);
	if (vmbus_channel_host_pages_used() != 8)
		return 224;
	torndown(0x1234);
	if (vmbus_channel_host_pages_used() != 4)
		return 225;
	torndown(0x1234);
	if (vmbus_channel_host_pages_used() != 4)
		return 226;
	if (vmbus_channel_host_attach_gpadl(second_channel, 0x1236) ||
	    vmbus_channel_rescind(21) != -EINPROGRESS ||
	    vmbus_channel_host_pages_used() != 4)
		return 227;
	torndown(0x1234);
	if (vmbus_channel_host_pages_used() != 4)
		return 228;
	torndown(0x1236);
	if (vmbus_channel_host_pages_used())
		return 229;

	first.channel = NULL;
	first_channel = vmbus_channel_host_prepare_open(&first);
	if (!first_channel ||
	    vmbus_channel_host_attach_gpadl(first_channel, 0x2234))
		return 230;
	vmbus_bus_host_set_transmit_error(-EIO);
	if (vmbus_channel_rescind(20) != -EINPROGRESS ||
	    vmbus_channel_host_pages_used() != 4 ||
	    !vmbus_bus_host_connection_failed())
		return 231;
	torndown(0x2234);
	if (vmbus_channel_host_pages_used() != 4)
		return 232;
	vmbus_channel_reset_all();
	vmbus_bus_host_set_transmit_error(0);
	vmbus_bus_host_clear_connection_failed();
	if (vmbus_channel_host_pages_used())
		return 233;
	return 0;
}

static int test_external_gpadl_mapping(void)
{
	static __u8 pages[3][4096] __attribute__((aligned(4096)));
	struct vmbus_device device = {
		.channel_id = 30,
		.connection_id = 130,
		.present = 1,
	};
	struct vmbus_gpadl mapping = { 0 };
	struct vmbus_gpadl stale;
	struct vmbus_channel *channel;
	int rc;

	channel = vmbus_channel_host_prepare_open(&device);
	if (!channel)
		return 240;
	vmbus_bus_host_auto_pump(1);
	rc = vmbus_channel_gpadl_map(channel, pages, sizeof(pages),
				      &mapping);
	vmbus_bus_host_auto_pump(0);
	if (rc || !mapping.id || mapping.page_count != 3 ||
	    !mapping.generation || vmbus_channel_host_record_count() != 1 ||
	    vmbus_channel_host_live_gpadls() != 1)
		return 241;
	stale = mapping;
	stale.generation++;
	if (vmbus_channel_gpadl_unmap(channel, &stale) != -ESTALE ||
	    vmbus_channel_host_record_count() != 1)
		return 242;
	vmbus_bus_host_auto_pump(1);
	rc = vmbus_channel_gpadl_unmap(channel, &mapping);
	vmbus_bus_host_auto_pump(0);
	if (rc || mapping.id || mapping.page_count || mapping.generation ||
	    vmbus_channel_host_record_count() ||
	    vmbus_channel_host_live_gpadls())
		return 243;
	if (vmbus_channel_gpadl_map(channel, &pages[0][1], 4096,
				    &mapping) != -EINVAL ||
	    vmbus_channel_gpadl_map(channel, pages,
		    (size_t)(VMBUS_GPADL_MAX_PAGES + 1) * 4096,
		    &mapping) != -E2BIG)
		return 244;

	vmbus_bus_host_auto_pump(1);
	rc = vmbus_channel_gpadl_map(channel, pages, sizeof(pages),
				      &mapping);
	if (!rc)
		rc = vmbus_channel_close(channel);
	vmbus_bus_host_auto_pump(0);
	if (rc || device.channel || vmbus_channel_host_record_count() ||
	    vmbus_channel_host_live_gpadls() ||
	    vmbus_channel_host_pages_used())
		return 245;
	return 0;
}

static int test_gpadl_explicit_refusal(void)
{
	static __u8 pages[30][4096] __attribute__((aligned(4096)));
	struct vmbus_device device = {
		.channel_id = 31,
		.connection_id = 131,
		.present = 1,
	};
	struct vmbus_gpadl mapping = { 0 };
	struct vmbus_channel *channel;
	int rc;

	channel = vmbus_channel_host_prepare_open(&device);
	if (!channel)
		return 246;
	vmbus_bus_host_clear_connection_failed();
	vmbus_bus_host_reset_gpadl_trace();
	vmbus_bus_host_set_gpadl_status(1);
	vmbus_bus_host_auto_pump(1);
	rc = vmbus_channel_gpadl_map(channel, pages, sizeof(pages),
				      &mapping);
	vmbus_bus_host_auto_pump(0);
	vmbus_bus_host_set_gpadl_status(0);
	if (rc != -EIO || mapping.id || mapping.page_count ||
	    mapping.generation || !vmbus_bus_host_gpadl_body_posts() ||
	    vmbus_bus_host_gpadl_teardown_posts() ||
	    vmbus_channel_host_record_count() ||
	    vmbus_channel_host_live_gpadls() ||
	    vmbus_bus_host_connection_failed()) {
		fprintf(stderr, "refusal rc=%d id=%u pages=%u generation=%llu "
			"body=%u teardown=%u records=%d live=%d failed=%d\n",
			rc, mapping.id, mapping.page_count,
			(unsigned long long)mapping.generation,
			vmbus_bus_host_gpadl_body_posts(),
			vmbus_bus_host_gpadl_teardown_posts(),
			vmbus_channel_host_record_count(),
			vmbus_channel_host_live_gpadls(),
			vmbus_bus_host_connection_failed());
		return 247;
	}
	if (vmbus_channel_close(channel))
		return 248;

	device.channel = NULL;
	device.channel_id = 32;
	device.connection_id = 132;
	vmbus_channel_reset_all();
	vmbus_bus_host_clear_connection_failed();
	vmbus_bus_host_reset_gpadl_trace();
	vmbus_bus_host_set_gpadl_status(1);
	vmbus_bus_host_auto_pump(1);
	rc = vmbus_channel_open(&device, 16, 16, NULL, 0);
	vmbus_bus_host_auto_pump(0);
	vmbus_bus_host_set_gpadl_status(0);
	if (rc != -EIO || device.channel ||
	    !vmbus_bus_host_gpadl_body_posts() ||
	    vmbus_bus_host_gpadl_teardown_posts() ||
	    vmbus_channel_host_pages_used() ||
	    vmbus_channel_host_record_count() ||
	    vmbus_channel_host_live_gpadls() ||
	    vmbus_bus_host_connection_failed())
		return 249;
	return 0;
}

static int test_gpadl_ambiguous_failures(void)
{
	static __u8 pages[30][4096] __attribute__((aligned(4096)));
	struct vmbus_device device = {
		.channel_id = 33,
		.connection_id = 133,
		.present = 1,
	};
	struct vmbus_gpadl mapping = { 0 };
	struct vmbus_channel *channel;
	__u32 late_id;
	int rc;

	channel = vmbus_channel_host_prepare_open(&device);
	if (!channel)
		return 280;
	vmbus_bus_host_clear_connection_failed();
	vmbus_bus_host_reset_gpadl_trace();
	vmbus_bus_host_set_transmit_fail_after(0);
	rc = vmbus_channel_gpadl_map(channel, pages, sizeof(pages),
				      &mapping);
	if (rc != -EIO || mapping.id ||
	    vmbus_bus_host_gpadl_teardown_posts() ||
	    vmbus_channel_host_record_count() ||
	    vmbus_bus_host_connection_failed())
		return 281;

	vmbus_bus_host_reset_gpadl_trace();
	vmbus_bus_host_set_transmit_fail_after(1);
	vmbus_bus_host_auto_pump(1);
	rc = vmbus_channel_gpadl_map(channel, pages, sizeof(pages),
				      &mapping);
	vmbus_bus_host_auto_pump(0);
	if (rc != -EIO || mapping.id ||
	    vmbus_bus_host_gpadl_body_posts() ||
	    vmbus_bus_host_gpadl_teardown_posts() != 1 ||
	    vmbus_channel_host_record_count() ||
	    vmbus_bus_host_connection_failed())
		return 282;

	vmbus_bus_host_reset_gpadl_trace();
	rc = vmbus_channel_gpadl_map(channel, pages, sizeof(pages),
				      &mapping);
	if (rc != -EINPROGRESS || !mapping.id ||
	    vmbus_bus_host_gpadl_teardown_posts() != 1 ||
	    vmbus_channel_host_record_count() != 1 ||
	    vmbus_channel_host_live_gpadls() != 1 ||
	    !vmbus_bus_host_connection_failed())
		return 283;
	late_id = mapping.id;
	gpadl_created(device.channel_id, late_id, 1);
	if (vmbus_channel_host_record_count() != 1 ||
	    vmbus_channel_host_live_gpadls() != 1)
		return 284;
	torndown(late_id);
	if (vmbus_channel_host_record_count() ||
	    vmbus_channel_host_live_gpadls())
		return 285;
	vmbus_bus_host_clear_connection_failed();
	if (vmbus_channel_close(channel))
		return 286;
	return 0;
}

static int test_receive_signal_failure_preserves_packet(void)
{
	struct vmbus_device device = {
		.channel_id = 35,
		.connection_id = 135,
		.present = 1,
	};
	struct vmbus_channel *channel =
		vmbus_channel_host_prepare_open(&device);
	struct vmbus_packet packet = { 0 };
	__u8 data[8] = { 0 };

	if (!channel)
		return 292;
	vmbus_bus_host_clear_connection_failed();
	memset(&ring_read_meta, 0, sizeof(ring_read_meta));
	ring_read_meta.packet_type = VMBUS_PACKET_COMPLETION;
	ring_read_meta.transaction_id = 0x12345678;
	ring_read_meta.need_signal = 1;
	ring_read_once = 1;
	host_signal_result = -1;
	if (vmbus_channel_receive(channel, &packet, data, sizeof(data),
				  data, sizeof(data)) ||
	    packet.type != VMBUS_PACKET_COMPLETION ||
	    packet.transaction_id != 0x12345678 ||
	    !vmbus_bus_host_connection_failed())
		return 293;
	host_signal_result = 0;
	vmbus_bus_host_clear_connection_failed();
	if (vmbus_channel_close(channel))
		return 294;
	return 0;
}

int main(void)
{
#ifdef VMBUS_REAL_PROTOCOL_TEST
	return vmbus_bus_host_quiesce_epoch_test();
#else
	int rc = vmbus_channel_host_nested_ownership_test();

	if (rc)
		return rc;
	rc = vmbus_bus_host_production_test();
	if (rc)
		return rc;
	rc = test_data_lifetime();
	if (rc)
		return rc;
	rc = test_simple_io_race(poll_thread, 22, 1, 240);
	if (rc)
		return rc;
	rc = test_simple_io_race(mask_thread, 23, 0, 250);
	if (rc)
		return rc;
	rc = test_simple_io_race(unmask_thread, 24, 1, 260);
	if (rc)
		return rc;
	rc = test_signal_lifetime();
	if (rc)
		return rc;
	rc = test_send_publication();
	if (rc)
		return rc;
	rc = test_connection_fail_api();
	if (rc)
		return rc;
	rc = test_callback_lifetime();
	if (rc)
		return rc;
	rc = test_gpadl_quarantine();
	if (rc)
		return rc;
	rc = test_external_gpadl_mapping();
	if (rc)
		return rc;
	rc = test_gpadl_explicit_refusal();
	if (rc)
		return rc;
	rc = test_gpadl_ambiguous_failures();
	if (rc)
		return rc;
	rc = test_receive_signal_failure_preserves_packet();
	if (rc)
		return rc;
	return 0;
#endif
}
