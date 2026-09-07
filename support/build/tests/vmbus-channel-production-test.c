/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <string.h>
#include <uk/arch/types.h>
#include <uk/vmbus.h>
#include "vmbus_channel_core.h"
#include "vmbus_internal.h"
#include "vmbus_protocol.h"

int vmbus_channel_host_nested_ownership_test(void);
int vmbus_bus_host_production_test(void);
struct vmbus_channel *
vmbus_channel_host_prepare_open(struct vmbus_device *device);
struct vmbus_channel *
vmbus_channel_host_allocate_open(struct vmbus_device *device);
int vmbus_channel_host_pages_used(void);
int vmbus_channel_host_is_free(struct vmbus_channel *channel);
int vmbus_channel_host_is_revoked(struct vmbus_channel *channel);
int vmbus_channel_host_attach_gpadl(struct vmbus_channel *channel,
				    __u32 gpadl_id);
void vmbus_bus_host_set_transmit_error(int error);
int vmbus_bus_host_connection_failed(void);
void vmbus_bus_host_clear_connection_failed(void);

int vmbus_post_message(__u32 connection_id __attribute__((unused)),
		       __u32 message_type __attribute__((unused)),
		       const __u8 *payload __attribute__((unused)),
		       size_t payload_len __attribute__((unused)),
		       __u64 input_gpa __attribute__((unused)),
		       __u8 has_post_messages __attribute__((unused)),
		       __u32 retry_limit __attribute__((unused)),
		       vmbus_hypercall_fn hypercall __attribute__((unused)),
		       vmbus_backoff_fn backoff __attribute__((unused)),
		       void *arg __attribute__((unused)))
{
	return 0;
}

__u32 vmbus_protocol_connection_id(void) { return 1; }
__u32 vmbus_protocol_version(void) { return (2U << 16) | 4U; }
void *vmbus_post_input(void)
{
	static __u8 input[256] __attribute__((aligned(256)));

	return input;
}
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
static pthread_mutex_t signal_gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t signal_condition = PTHREAD_COND_INITIALIZER;
static int host_signal_blocked;
static int host_signal_entered;

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
		    struct vmbus_packet_meta_abi *meta __attribute__((unused)),
		    __u8 *descriptor __attribute__((unused)),
		    size_t descriptor_capacity __attribute__((unused)),
		    __u8 *payload __attribute__((unused)),
		    size_t payload_capacity __attribute__((unused)))
{
	if (!base || !total_size)
		return -2;
	ring_wait();
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
	return 0;
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
	*consumed = pfn_count;
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
	*consumed = pfn_count;
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

int main(void)
{
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
	rc = test_callback_lifetime();
	if (rc)
		return rc;
	return test_gpadl_quarantine();
}
