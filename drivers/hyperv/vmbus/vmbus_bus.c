/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <hyperv/hyperv.h>
#include <uk/arch/spinlock.h>
#include <uk/bus.h>
#include <uk/config.h>
#include <uk/isr/thread.h>
#include <uk/lcpu.h>
#include <uk/paging.h>
#include <uk/pcpuvar.h>
#include <uk/plat/time.h>
#include <uk/print.h>
#include <uk/sched.h>
#include <uk/thread.h>
#include <uk/vmbus.h>

#include "vmbus_protocol.h"
#include "vmbus_lifecycle.h"
#include "vmbus_event_route.h"
#include "vmbus_queue.h"
#include "vmbus_release.h"
#include "vmbus_teardown.h"
#include "vmbus_worker_stop.h"
#include "vmbus_internal.h"

#ifdef VMBUS_BUS_HOST_TEST
#include <pthread.h>
#include <string.h>
static _Thread_local __u64 host_cpu_index;
static unsigned int host_wake_isr_count;
#endif

#define VMBUS_REFERENCE_TICKS_PER_MS	10000ULL
#define VMBUS_WORKER_SLEEP_NS		1000000ULL
#define VMBUS_EVENT_LIMIT		2048U
#define VMBUS_TEARDOWN_WAIT_LIMIT	100U
#define VMBUS_RELID_CAPACITY		(CONFIG_LIBVMBUS_MAX_DEVICES + \
					 CONFIG_LIBVMBUS_RX_QUEUE)
#define VMBUS_LEGACY_EVENT_WORDS	(VMBUS_EVENT_LIMIT / 64U)

struct vmbus_rx_entry {
	__u32 generation;
	__u8 len;
	__u8 data[HYPERV_MESSAGE_PAYLOAD_SIZE];
};

enum vmbus_bind_state {
	VMBUS_BIND_UNUSED,
	VMBUS_BIND_UNATTEMPTED,
	VMBUS_BIND_ADDING,
	VMBUS_BIND_BOUND,
	VMBUS_BIND_TRANSIENT_WAIT,
	VMBUS_BIND_PERMANENT_FAILED,
	VMBUS_BIND_REMOVE_PENDING,
};

struct vmbus_device_binding {
	__u64 generation;
	__u64 retry_epoch;
	__u64 failure_epoch;
	const struct vmbus_driver *adding_driver;
	const struct vmbus_driver *offer_driver;
	struct vmbus_decoded_offer pending_offer;
	__u8 state;
	__u8 capacity_failure;
	__u8 pending_offer_valid;
	__u8 remove_called;
	__u8 offer_remove_notified;
};

const struct vmbus_guid vmbus_storage_guid = {
	.bytes = {
		0xba, 0x61, 0x63, 0xd9, 0x04, 0xa1, 0x4d, 0x29,
		0xb6, 0x05, 0x72, 0xe2, 0xff, 0xb1, 0xdc, 0x7f,
	},
};

const struct vmbus_guid vmbus_network_guid = {
	.bytes = {
		0xf8, 0x61, 0x51, 0x63, 0xdf, 0x3e, 0x46, 0xc5,
		0x91, 0x3f, 0xf2, 0xd2, 0xf9, 0x65, 0xed, 0x0e,
	},
};

static struct vmbus_device devices[CONFIG_LIBVMBUS_MAX_DEVICES];
static struct vmbus_device_binding
	device_bindings[CONFIG_LIBVMBUS_MAX_DEVICES];
static struct vmbus_driver *drivers[CONFIG_LIBVMBUS_MAX_DRIVERS];
static struct vmbus_rx_entry rx_queue[CONFIG_LIBVMBUS_RX_QUEUE];
static __u64 event_pending[VMBUS_LEGACY_EVENT_WORDS];
static struct vmbus_relid_lifecycle relids[VMBUS_RELID_CAPACITY];
struct vmbus_deferred_relid {
	__u32 channel_id;
	__u64 sequence;
};
static struct vmbus_deferred_relid
	deferred_relid_releases[VMBUS_RELID_CAPACITY];
static __spinlock deferred_release_lock;
static __u8 interrupt_page[HYPERV_PAGE_SIZE] __align(HYPERV_PAGE_SIZE);
static __u8 parent_to_child_monitor[HYPERV_PAGE_SIZE]
	__align(HYPERV_PAGE_SIZE);
static __u8 child_to_parent_monitor[HYPERV_PAGE_SIZE]
	__align(HYPERV_PAGE_SIZE);

static unsigned int driver_count;
static unsigned int device_count;
static struct vmbus_queue_state rx_state;
static __u32 rx_dropped;
static __u32 event_dropped;
static __u32 malformed_hv_messages;
static __u64 post_input_gpa;
static __u64 relid_sequence;
static __u64 device_generation = 1;
static __u64 channel_resource_epoch = 1;
static int storage_offer_lifetime_observed;
static int bind_work_pending;
static int bind_work_running;
static int bind_attempt_active;
static struct uk_thread *bind_attempt_owner;
static struct vmbus_device_binding *bind_attempt_binding;
static struct uk_thread *worker;
static struct uk_thread *control_owner;
static __spinlock worker_lock;
static __spinlock rx_queue_lock;
static int worker_stop;
static int control_busy;
static int initialized;
static int rx_active;
static int connection_failed;
static __u64 connection_quiesce_epoch = 1;
static __u64 next_connection_generation = 1;
static __u64 live_connection_generation;
static __u32 connection_target_vp;
static __u32 connection_target_generation;
static int connection_target_held;
static int connection_teardown_failed;
static int connection_teardown_error;
static int clearing_devices;
static __spinlock bind_lock;

#ifdef VMBUS_BUS_HOST_TEST
enum host_unload_response_mode {
	HOST_UNLOAD_NONE,
	HOST_UNLOAD_MATCH,
	HOST_UNLOAD_DUPLICATE,
	HOST_UNLOAD_WRONG_GENERATION,
};

static int (*host_pump_hook)(void);
static __u8 host_last_tx[HYPERV_MESSAGE_PAYLOAD_SIZE];
static size_t host_last_tx_len;
static int host_transmit_error;
static enum host_unload_response_mode host_unload_response_mode;
static unsigned int host_unload_posts;
static unsigned int host_unload_injections;
static int host_unload_injected_inactive;
static void (*host_remove_hook)(void *);
static void *host_remove_hook_arg;
static void (*host_unload_post_hook)(void *);
static void *host_unload_post_hook_arg;
static unsigned int host_connection_fail_calls;
static int host_transmit_fail_after = -1;
static __u32 host_transmit_backpressure_type;
static unsigned int host_transmit_backpressure;
static unsigned int host_transmit_attempts;
static __u32 host_gpadl_status;
static __u32 host_gpadl_channel;
static __u32 host_gpadl_id;
static unsigned int host_gpadl_body_posts;
static unsigned int host_gpadl_teardown_posts;

static __u32 host_read32(const __u8 *data)
{
	return (__u32)data[0] | ((__u32)data[1] << 8) |
		((__u32)data[2] << 16) | ((__u32)data[3] << 24);
}

static void host_write32(__u8 *data, __u32 value)
{
	data[0] = (__u8)value;
	data[1] = (__u8)(value >> 8);
	data[2] = (__u8)(value >> 16);
	data[3] = (__u8)(value >> 24);
}

static void host_encode_guid(__u8 *wire, const struct vmbus_guid *guid)
{
	unsigned int i;

	wire[0] = guid->bytes[3];
	wire[1] = guid->bytes[2];
	wire[2] = guid->bytes[1];
	wire[3] = guid->bytes[0];
	wire[4] = guid->bytes[5];
	wire[5] = guid->bytes[4];
	wire[6] = guid->bytes[7];
	wire[7] = guid->bytes[6];
	for (i = 8; i < VMBUS_GUID_SIZE; i++)
		wire[i] = guid->bytes[i];
}
#endif

static int vmbus_bus_init(struct uk_alloc *a);
static int vmbus_bus_probe(void);
static void vmbus_worker(void *arg) __noreturn;
static int handle_action(const struct vmbus_action *action);
static int disconnect_locked(void);
static int acquire_control(void);
static void release_control(void);
static void stop_worker_locked(void);
static int release_channel(__u32 channel_id, int retain_claim);
static int add_offer(const struct vmbus_decoded_offer *offer);
static void bind_device(struct vmbus_device *dev);
static void process_bind_work(void);
static void copy_offer(struct vmbus_device *dev,
		       const struct vmbus_decoded_offer *offer);

static void bind_state_lock(unsigned long *flags)
{
	ukplat_spin_lock_irqsave(&bind_lock, *flags);
}

static void bind_state_unlock(unsigned long flags)
{
	ukplat_spin_unlock_irqrestore(&bind_lock, flags);
}

static int guid_equal(const struct vmbus_guid *a,
		      const struct vmbus_guid *b)
{
	unsigned int i;

	for (i = 0; i < VMBUS_GUID_SIZE; i++)
		if (a->bytes[i] != b->bytes[i])
			return 0;
	return 1;
}

static inline void vmbus_cpu_relax(void)
{
#ifdef VMBUS_BUS_HOST_TEST
	__atomic_signal_fence(__ATOMIC_ACQ_REL);
#else
	__asm__ __volatile__("pause");
#endif
}

static int guid_equal_bytes(const struct vmbus_guid *a, const __u8 *b)
{
	unsigned int i;

	for (i = 0; i < VMBUS_GUID_SIZE; i++)
		if (a->bytes[i] != b[i])
			return 0;
	return 1;
}

static int guid_is_zero(const struct vmbus_guid *guid)
{
	unsigned int i;

	for (i = 0; i < VMBUS_GUID_SIZE; i++)
		if (guid->bytes[i])
			return 0;
	return 1;
}

static void copy_bytes(__u8 *dst, const __u8 *src, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
		dst[i] = src[i];
}

static void signal_worker(void)
{
	struct uk_thread *thread;
	unsigned long flags;

	/*
	 * schedcoop run/sleep queues are owned by the worker CPU. AP SINT2
	 * producers only publish into the MPSC queue/bitmap; BSP polling drains
	 * them without mutating scheduler queues cross-CPU.
	 */
#ifdef VMBUS_BUS_HOST_TEST
	if (host_cpu_index != 0)
		return;
#else
	if (uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx) != 0)
		return;
#endif
	ukplat_spin_lock_irqsave(&worker_lock, flags);
	thread = __atomic_load_n(&worker, __ATOMIC_ACQUIRE);
	if (thread && !__atomic_load_n(&worker_stop, __ATOMIC_ACQUIRE)) {
#ifdef VMBUS_BUS_HOST_TEST
		host_wake_isr_count++;
#endif
		uk_thread_wake_isr(thread);
	}
	ukplat_spin_unlock_irqrestore(&worker_lock, flags);
}

void hyperv_vmbus_message(const struct hyperv_message *message)
{
	__u32 ticket;
	struct vmbus_rx_entry *entry;
	unsigned long flags;
	size_t inspected_size;

	inspected_size = message->payload_size;
	if (inspected_size > sizeof(message->payload))
		inspected_size = sizeof(message->payload);
	if (message->message_type == VMBUS_HV_MESSAGE_TYPE &&
	    vmbus_protocol_offer_matches_class(
		    message->payload, inspected_size,
		    vmbus_storage_guid.bytes))
		__atomic_store_n(&storage_offer_lifetime_observed, 1,
				 __ATOMIC_RELEASE);
	if ((!__atomic_load_n(&rx_active, __ATOMIC_ACQUIRE) &&
	     vmbus_protocol_state() != VMBUS_STATE_UNLOADING) ||
	    __atomic_load_n(&rx_state.lost, __ATOMIC_ACQUIRE))
		return;
	if (message->message_type != VMBUS_HV_MESSAGE_TYPE ||
	    message->payload_size < 8 ||
	    message->payload_size > HYPERV_MESSAGE_PAYLOAD_SIZE) {
		__atomic_add_fetch(&malformed_hv_messages, 1, __ATOMIC_RELAXED);
		signal_worker();
		return;
	}

	ukplat_spin_lock_irqsave(&rx_queue_lock, flags);
	if (!__atomic_load_n(&rx_active, __ATOMIC_ACQUIRE) &&
	    vmbus_protocol_state() != VMBUS_STATE_UNLOADING) {
		ukplat_spin_unlock_irqrestore(&rx_queue_lock, flags);
		return;
	}
	if (vmbus_queue_reserve(&rx_state, CONFIG_LIBVMBUS_RX_QUEUE,
				&ticket)) {
		ukplat_spin_unlock_irqrestore(&rx_queue_lock, flags);
		__atomic_add_fetch(&rx_dropped, 1, __ATOMIC_RELAXED);
		signal_worker();
		return;
	}
	entry = &rx_queue[ticket % CONFIG_LIBVMBUS_RX_QUEUE];
	entry->generation = vmbus_protocol_generation();
	entry->len = message->payload_size;
	copy_bytes(entry->data, message->payload, entry->len);
	vmbus_queue_commit(&rx_state, ticket);
	ukplat_spin_unlock_irqrestore(&rx_queue_lock, flags);
	signal_worker();
}

static void enqueue_event_word(__u32 base, __u64 pending)
{
	if (!pending || (base & 63U) || base >= VMBUS_EVENT_LIMIT ||
	    base + 63U >= VMBUS_EVENT_LIMIT) {
		__atomic_add_fetch(&event_dropped, 1, __ATOMIC_RELAXED);
		return;
	}
	if (!__atomic_load_n(&rx_active, __ATOMIC_ACQUIRE))
		return;
	__atomic_fetch_or(&event_pending[base / 64U], pending,
			  __ATOMIC_RELEASE);
}

static void enqueue_event(__u32 event, void *arg __unused)
{
	if (event >= VMBUS_EVENT_LIMIT) {
		__atomic_add_fetch(&event_dropped, 1, __ATOMIC_RELAXED);
		return;
	}
	enqueue_event_word(event & ~63U, 1ULL << (event & 63U));
}

void vmbus_channel_schedule_event(__u32 channel_id)
{
	if (!__atomic_load_n(&rx_active, __ATOMIC_ACQUIRE))
		return;
	if (!channel_id)
		__atomic_add_fetch(&event_dropped, 1, __ATOMIC_RELAXED);
	else
		enqueue_event(channel_id, NULL);
	signal_worker();
}

void hyperv_vmbus_event(__u32 event)
{
	int rc;

	if (!__atomic_load_n(&rx_active, __ATOMIC_ACQUIRE))
		return;
	rc = vmbus_event_route(vmbus_protocol_version(), event,
			(__u64 *)interrupt_page, VMBUS_LEGACY_EVENT_WORDS,
			VMBUS_EVENT_LIMIT, enqueue_event, NULL);
	if (rc < 0)
		__atomic_add_fetch(&event_dropped, 1, __ATOMIC_RELAXED);
	signal_worker();
}

void hyperv_vmbus_event_word(__u32 base_event, __u64 pending)
{
	if (!__atomic_load_n(&rx_active, __ATOMIC_ACQUIRE))
		return;
	if ((base_event & 63U) || base_event >= VMBUS_EVENT_LIMIT ||
	    base_event + 63U >= VMBUS_EVENT_LIMIT) {
		__atomic_add_fetch(&event_dropped, 1, __ATOMIC_RELAXED);
		return;
	}
	if (vmbus_protocol_version() < VMBUS_EVENT_VERSION_WIN8) {
		if (base_event == 0 && (pending & 1U))
			hyperv_vmbus_event(0);
		if (pending & ~(base_event == 0 ? 1ULL : 0ULL))
			__atomic_add_fetch(&event_dropped, 1,
					   __ATOMIC_RELAXED);
		return;
	}
	enqueue_event_word(base_event, pending);
	signal_worker();
}

static int dequeue_message(struct vmbus_rx_entry *entry)
{
	__u32 ticket;
	unsigned long flags;

	ukplat_spin_lock_irqsave(&rx_queue_lock, flags);
	if (!vmbus_queue_take(&rx_state, &ticket)) {
		ukplat_spin_unlock_irqrestore(&rx_queue_lock, flags);
		return 0;
	}
	*entry = rx_queue[ticket % CONFIG_LIBVMBUS_RX_QUEUE];
	ukplat_spin_unlock_irqrestore(&rx_queue_lock, flags);
	return 1;
}

#ifndef VMBUS_BUS_HOST_TEST
static __u64 post_hypercall(void *arg __unused, __u64 input_gpa)
{
	return hyperv_hypercall(0x005c, input_gpa, 0);
}

static void post_backoff(void *arg __unused, __u32 usec)
{
	if (uk_sched_current())
		uk_sched_thread_sleep((__nsec)usec * 1000ULL);
	else {
		__u64 deadline = hyperv_reference_time() +
				 (__u64)usec * 10ULL;

		while (hyperv_reference_time() < deadline)
			__asm__ __volatile__("pause");
	}
}
#endif

#ifdef VMBUS_BUS_HOST_TEST
static void host_queue_unload_response(int wrong_generation)
{
	struct hyperv_message message = { 0 };

	message.message_type = VMBUS_HV_MESSAGE_TYPE;
	message.payload_size = 8;
	message.payload[0] = 17;
	if (!wrong_generation) {
		if (!__atomic_load_n(&rx_active, __ATOMIC_ACQUIRE) &&
		    vmbus_protocol_state() == VMBUS_STATE_UNLOADING)
			host_unload_injected_inactive = 1;
		hyperv_vmbus_message(&message);
		host_unload_injections++;
		return;
	}
	{
		struct vmbus_rx_entry *entry;
		__u32 generation = vmbus_protocol_generation();
		__u32 ticket;

		if (vmbus_queue_reserve(&rx_state, CONFIG_LIBVMBUS_RX_QUEUE,
					&ticket))
			return;
		entry = &rx_queue[ticket % CONFIG_LIBVMBUS_RX_QUEUE];
		entry->generation = generation == UINT32_MAX ?
			generation - 1 : generation + 1;
		entry->len = message.payload_size;
		copy_bytes(entry->data, message.payload, entry->len);
		vmbus_queue_commit(&rx_state, ticket);
		host_unload_injections++;
	}
}

static void host_handle_unload_transmit(const __u8 *message, size_t length)
{
	enum host_unload_response_mode mode;
	__u32 type;

	if (length < 4)
		return;
	type = (__u32)message[0] | ((__u32)message[1] << 8) |
		((__u32)message[2] << 16) | ((__u32)message[3] << 24);
	if (type != 16)
		return;
	host_unload_posts++;
	if (host_unload_post_hook)
		host_unload_post_hook(host_unload_post_hook_arg);
	mode = host_unload_response_mode;
	host_unload_response_mode = HOST_UNLOAD_NONE;
	if (mode == HOST_UNLOAD_WRONG_GENERATION) {
		host_queue_unload_response(1);
		return;
	}
	if (mode == HOST_UNLOAD_MATCH ||
	    mode == HOST_UNLOAD_DUPLICATE)
		host_queue_unload_response(0);
	if (mode == HOST_UNLOAD_DUPLICATE)
		host_queue_unload_response(0);
}
#endif

#ifndef VMBUS_BUS_HOST_TEST
static __u32 control_message_type(const __u8 *message, size_t length)
{
	if (length < sizeof(__u32))
		return 0;
	return (__u32)message[0] | ((__u32)message[1] << 8) |
		((__u32)message[2] << 16) | ((__u32)message[3] << 24);
}

static const char *post_status_name(__u16 status)
{
	switch (status) {
	case 0x0000:
		return "success";
	case 0x0005:
		return "invalid parameter";
	case 0x0006:
		return "access denied";
	case 0x000e:
		return "invalid VP index";
	case 0x0011:
		return "invalid port ID";
	case 0x0012:
		return "invalid connection ID";
	case 0x0013:
		return "insufficient buffers";
	case 0x0018:
		return "invalid SynIC state";
	case 0xffff:
		return "hypercall not issued";
	default:
		return "unknown";
	}
}

static void report_post_failure(__u32 connection_id, const __u8 *message,
				size_t length, __u16 status, int rc)
{
	uk_pr_err("VMBus: PostMessage connection %u control %u failed: "
		  "Hyper-V status 0x%04x (%s), transport rc %d, "
		  "input GPA 0x%lx\n",
		  connection_id, control_message_type(message, length),
		  status, post_status_name(status), rc, post_input_gpa);
}
#endif

int vmbus_control_transmit(const __u8 *message, size_t length)
{
#ifndef VMBUS_BUS_HOST_TEST
	__u32 connection_id;
	__u16 status;
	int rc;
#endif

	if (!length || length > HYPERV_MESSAGE_PAYLOAD_SIZE)
		return -EINVAL;
#ifdef VMBUS_BUS_HOST_TEST
	__u32 type;

	type = host_read32(message);
	host_transmit_attempts++;
	if (host_transmit_backpressure &&
	    (!host_transmit_backpressure_type ||
	     host_transmit_backpressure_type == type)) {
		host_transmit_backpressure--;
		return -EAGAIN;
	}
	copy_bytes(host_last_tx, message, (unsigned int)length);
	host_last_tx_len = length;
	if (host_transmit_error)
		return host_transmit_error;
	if (host_transmit_fail_after == 0) {
		host_transmit_fail_after = -1;
		return -EIO;
	}
	if (host_transmit_fail_after > 0)
		host_transmit_fail_after--;
	if (type == 8 && length >= 16) {
		host_gpadl_channel = host_read32(message + 8);
		host_gpadl_id = host_read32(message + 12);
	} else if (type == 9) {
		host_gpadl_body_posts++;
	} else if (type == 11) {
		host_gpadl_teardown_posts++;
	}
	host_handle_unload_transmit(message, length);
	return 0;
#else
	connection_id = vmbus_protocol_connection_id();
	rc = vmbus_post_message(connection_id,
				VMBUS_HV_MESSAGE_TYPE, message,
				length, post_input_gpa,
				&status,
				(__u8)hyperv_has_post_messages(),
				CONFIG_LIBVMBUS_POST_RETRIES,
				post_hypercall, post_backoff, NULL);
	if (rc) {
		if (status == 0x0013 &&
		    rc == VMBUS_POST_INSUFFICIENT_BUFFERS)
			return -EAGAIN;
		report_post_failure(connection_id, message, length, status, rc);
		return -EIO;
	}
	return 0;
#endif
}

static int transmit(const struct vmbus_action *action)
{
#ifdef VMBUS_BUS_HOST_TEST
	__u64 deadline = hyperv_reference_time() +
		(__u64)CONFIG_LIBVMBUS_VERSION_TIMEOUT_MS *
		VMBUS_REFERENCE_TICKS_PER_MS;
	int rc;

	for (;;) {
		rc = vmbus_control_transmit(action->tx, action->tx_len);
		if (rc != -EAGAIN)
			return rc;
		if (action->generation != vmbus_protocol_generation())
			return -ECANCELED;
		if (hyperv_reference_time() >= deadline)
			return -ETIMEDOUT;
		vmbus_cpu_relax();
	}
#else
	struct vmbus_action retry;
	__u64 deadline = hyperv_reference_time() +
		(__u64)CONFIG_LIBVMBUS_VERSION_TIMEOUT_MS *
		VMBUS_REFERENCE_TICKS_PER_MS;
	__u16 status;
	int rc;

	for (;;) {
		rc = vmbus_post_message(action->connection_id,
					VMBUS_HV_MESSAGE_TYPE, action->tx,
					action->tx_len, post_input_gpa, &status,
					(__u8)hyperv_has_post_messages(),
					CONFIG_LIBVMBUS_POST_RETRIES,
					post_hypercall, post_backoff, NULL);
		if (!rc)
			return 0;
		if (status != 0x0013 ||
		    rc != VMBUS_POST_INSUFFICIENT_BUFFERS)
			break;
		if (action->generation != vmbus_protocol_generation())
			return -ECANCELED;
		if (hyperv_reference_time() >= deadline) {
			report_post_failure(action->connection_id, action->tx,
					    action->tx_len, status, rc);
			return -ETIMEDOUT;
		}
		post_backoff(NULL, 1000);
	}
	if (vmbus_protocol_post_failure(status, hyperv_reference_time(),
					&retry)) {
		uk_pr_info("VMBus: PostMessage connection %u control %u at "
			   "input GPA 0x%lx returned Hyper-V status 0x%04x "
			   "(%s); retrying protocol %u.%u on legacy "
			   "connection %u\n",
			   action->connection_id,
			   control_message_type(action->tx, action->tx_len),
			   post_input_gpa, status, post_status_name(status),
			   ((__u32)retry.tx[8] | ((__u32)retry.tx[9] << 8) |
			    ((__u32)retry.tx[10] << 16) |
			    ((__u32)retry.tx[11] << 24)) >> 16,
			   (__u32)retry.tx[8] | ((__u32)retry.tx[9] << 8),
			   retry.connection_id);
		return handle_action(&retry);
	}
	report_post_failure(action->connection_id, action->tx,
			    action->tx_len, status, rc);
	return -EIO;
#endif
}

static struct vmbus_driver *find_driver(const struct vmbus_guid *class_id)
{
	unsigned int driver_index;

	for (driver_index = 0; driver_index < driver_count; driver_index++) {
		const struct vmbus_device_id *id;

		for (id = drivers[driver_index]->device_ids;
		     id && !guid_is_zero(&id->class_id); id++)
			if (guid_equal(class_id, &id->class_id))
				return drivers[driver_index];
	}
	return NULL;
}

static struct vmbus_device_binding *
device_binding(const struct vmbus_device *dev)
{
	uintptr_t address = (uintptr_t)dev;
	uintptr_t first = (uintptr_t)&devices[0];
	uintptr_t limit = (uintptr_t)&devices[CONFIG_LIBVMBUS_MAX_DEVICES];

	if (address < first || address >= limit ||
	    (address - first) % sizeof(devices[0]))
		return NULL;
	return &device_bindings[(address - first) / sizeof(devices[0])];
}

static int assign_device_generation(struct vmbus_device_binding *binding)
{
	unsigned long flags;

	bind_state_lock(&flags);
	if (!device_generation) {
		bind_state_unlock(flags);
		return -ENOSPC;
	}
	binding->generation = device_generation;
	device_generation = device_generation == UINT64_MAX ?
		0 : device_generation + 1;
	bind_state_unlock(flags);
	return 0;
}

static void clear_device_fields(struct vmbus_device *dev)
{
	dev->driver = NULL;
	dev->channel = NULL;
	dev->present = 0;
}

static void cleanup_added_device(struct vmbus_device *dev,
				 struct vmbus_device_binding *binding,
				 const struct vmbus_driver *driver)
{
	if (!binding->remove_called && driver && driver->remove_dev) {
		binding->remove_called = 1;
		driver->remove_dev(dev);
	}
	if (dev->channel)
		(void)vmbus_channel_close(dev->channel);
}

static const struct vmbus_driver *claim_offer_removed(
	struct vmbus_device *dev, struct vmbus_device_binding *binding,
	struct vmbus_offer_identity *offer)
{
	const struct vmbus_driver *driver = NULL;
	unsigned long flags;

	bind_state_lock(&flags);
	if (binding->generation && !binding->offer_remove_notified) {
		binding->offer_remove_notified = 1;
		driver = binding->offer_driver;
		offer->instance_id = dev->instance_id;
		offer->channel_id = dev->channel_id;
		offer->generation = binding->generation;
	}
	bind_state_unlock(flags);
	return driver;
}

static void try_install_pending_offer(struct vmbus_device *dev)
{
	struct vmbus_device_binding *binding = device_binding(dev);
	struct vmbus_decoded_offer offer;

	if (!binding || binding->state != VMBUS_BIND_UNUSED ||
	    !binding->pending_offer_valid || dev->present)
		return;
	offer = binding->pending_offer;
	binding->pending_offer_valid = 0;
	copy_offer(dev, &offer);
	if (assign_device_generation(binding)) {
		clear_device_fields(dev);
		(void)release_channel(offer.channel_id, 0);
		return;
	}
	binding->state = VMBUS_BIND_UNATTEMPTED;
	binding->retry_epoch = 0;
	binding->failure_epoch = 0;
	binding->adding_driver = NULL;
	binding->offer_driver = NULL;
	binding->capacity_failure = 0;
	binding->remove_called = 0;
	binding->offer_remove_notified = 0;
	device_count++;
	__atomic_store_n(&bind_work_pending, 1, __ATOMIC_RELEASE);
}

static void finish_device_removal(struct vmbus_device *dev,
				  struct vmbus_device_binding *binding,
				  const struct vmbus_driver *driver)
{
	struct vmbus_offer_identity offer;
	const struct vmbus_driver *offer_driver =
		claim_offer_removed(dev, binding, &offer);

	cleanup_added_device(dev, binding, driver);
	if (offer_driver && offer_driver->offer_removed)
		offer_driver->offer_removed(&offer);
	clear_device_fields(dev);
	binding->generation = 0;
	binding->adding_driver = NULL;
	binding->offer_driver = NULL;
	binding->capacity_failure = 0;
	binding->failure_epoch = 0;
	binding->remove_called = 0;
	binding->offer_remove_notified = 0;
	binding->state = VMBUS_BIND_UNUSED;
	if (!clearing_devices)
		try_install_pending_offer(dev);
}

static void bind_device(struct vmbus_device *dev)
{
	struct vmbus_device_binding *binding = device_binding(dev);
	struct vmbus_driver *driver;
	unsigned long state_flags;
	struct vmbus_device_binding *previous_binding;
	__u64 generation;
	int rc;

	if (!binding)
		return;
	bind_state_lock(&state_flags);
	if (!dev->present ||
	    binding->state == VMBUS_BIND_ADDING ||
	    binding->state == VMBUS_BIND_BOUND ||
	    binding->state == VMBUS_BIND_REMOVE_PENDING ||
	    binding->state == VMBUS_BIND_PERMANENT_FAILED) {
		bind_state_unlock(state_flags);
		return;
	}
	if (binding->state == VMBUS_BIND_TRANSIENT_WAIT &&
	    binding->retry_epoch == channel_resource_epoch) {
		bind_state_unlock(state_flags);
		return;
	}
	driver = find_driver(&dev->class_id);
	if (!driver) {
		bind_state_unlock(state_flags);
		return;
	}
	generation = binding->generation;
	binding->state = VMBUS_BIND_ADDING;
	binding->adding_driver = driver;
	binding->offer_driver = driver;
	binding->capacity_failure = 0;
	binding->failure_epoch = 0;
	binding->remove_called = 0;
	dev->driver = driver;
	bind_attempt_active++;
	bind_attempt_owner = uk_thread_current();
	previous_binding = bind_attempt_binding;
	bind_attempt_binding = binding;
	bind_state_unlock(state_flags);
	rc = driver->add_dev ? driver->add_dev(dev) : 0;
	bind_state_lock(&state_flags);
	bind_attempt_binding = previous_binding;
	bind_attempt_active--;
	if (!bind_attempt_active)
		bind_attempt_owner = NULL;
	if (binding->generation != generation) {
		bind_state_unlock(state_flags);
		return;
	}
	if (binding->state == VMBUS_BIND_REMOVE_PENDING) {
		bind_state_unlock(state_flags);
		finish_device_removal(dev, binding, driver);
		return;
	}
	if (!rc) {
		binding->adding_driver = NULL;
		binding->state = VMBUS_BIND_BOUND;
		bind_state_unlock(state_flags);
		return;
	}
	bind_state_unlock(state_flags);
	if (dev->channel)
		cleanup_added_device(dev, binding, driver);
	bind_state_lock(&state_flags);
	if (binding->generation != generation)
		goto stale;
	if (binding->state == VMBUS_BIND_REMOVE_PENDING) {
		bind_state_unlock(state_flags);
		finish_device_removal(dev, binding, driver);
		return;
	}
	dev->driver = NULL;
	binding->adding_driver = NULL;
	if (rc == -ENOSPC && binding->capacity_failure) {
		binding->state = VMBUS_BIND_TRANSIENT_WAIT;
		binding->retry_epoch = binding->failure_epoch;
		if (binding->retry_epoch != channel_resource_epoch)
			__atomic_store_n(&bind_work_pending, 1,
					 __ATOMIC_RELEASE);
		bind_state_unlock(state_flags);
		return;
	}
	binding->state = VMBUS_BIND_PERMANENT_FAILED;
	bind_state_unlock(state_flags);
	uk_pr_err("VMBus: driver %s rejected channel %u (%d)\n",
		  driver->name, dev->channel_id, rc);
	return;
stale:
	bind_state_unlock(state_flags);
}

static void process_bind_work(void)
{
	unsigned int budget = CONFIG_LIBVMBUS_MAX_DEVICES;
	unsigned int i;

	if (__atomic_exchange_n(&bind_work_running, 1, __ATOMIC_ACQ_REL))
		return;
	__atomic_store_n(&bind_work_pending, 0, __ATOMIC_RELEASE);
	while (budget--) {
		struct vmbus_device *work = NULL;

		for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
			try_install_pending_offer(&devices[i]);
			if (!work && devices[i].present &&
			    find_driver(&devices[i].class_id) &&
			    (device_bindings[i].state ==
				     VMBUS_BIND_UNATTEMPTED ||
			     device_bindings[i].state ==
				     VMBUS_BIND_TRANSIENT_WAIT) &&
			    (device_bindings[i].state !=
				     VMBUS_BIND_TRANSIENT_WAIT ||
			     device_bindings[i].retry_epoch !=
				     channel_resource_epoch))
				work = &devices[i];
		}
		if (!work)
			break;
		bind_device(work);
	}
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++)
		if (device_bindings[i].pending_offer_valid ||
		    (devices[i].present &&
		     find_driver(&devices[i].class_id) &&
		     (device_bindings[i].state == VMBUS_BIND_UNATTEMPTED ||
		      (device_bindings[i].state ==
			       VMBUS_BIND_TRANSIENT_WAIT &&
		       device_bindings[i].retry_epoch !=
			       channel_resource_epoch)))) {
			__atomic_store_n(&bind_work_pending, 1,
					 __ATOMIC_RELEASE);
			break;
		}
	__atomic_store_n(&bind_work_running, 0, __ATOMIC_RELEASE);
}

static void remove_device(struct vmbus_device *dev)
{
	struct vmbus_device_binding *binding = device_binding(dev);
	const struct vmbus_driver *driver;
	unsigned long flags;

	if (!binding)
		return;
	bind_state_lock(&flags);
	if (!dev->present) {
		bind_state_unlock(flags);
		return;
	}
	driver = binding->adding_driver ?
		binding->adding_driver : dev->driver;
	dev->present = 0;
	if (device_count)
		device_count--;
	if (binding->state == VMBUS_BIND_ADDING) {
		binding->state = VMBUS_BIND_REMOVE_PENDING;
		bind_state_unlock(flags);
		return;
	}
	binding->state = VMBUS_BIND_REMOVE_PENDING;
	bind_state_unlock(flags);
	finish_device_removal(dev, binding, driver);
}

static void clear_devices(void)
{
	unsigned int i;

	clearing_devices = 1;
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++)
		remove_device(&devices[i]);
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		if (device_bindings[i].state ==
		    VMBUS_BIND_REMOVE_PENDING) {
			device_bindings[i].pending_offer_valid = 0;
			continue;
		}
		device_bindings[i].state = VMBUS_BIND_UNUSED;
		device_bindings[i].pending_offer_valid = 0;
		device_bindings[i].adding_driver = NULL;
		device_bindings[i].offer_driver = NULL;
		device_bindings[i].capacity_failure = 0;
		device_bindings[i].failure_epoch = 0;
		device_bindings[i].remove_called = 0;
		device_bindings[i].offer_remove_notified = 0;
		clear_device_fields(&devices[i]);
	}
	clearing_devices = 0;
	device_count = 0;
}

static int release_channel(__u32 channel_id, int retain_claim)
{
	struct vmbus_action action;
	int rc;

	rc = vmbus_relid_release_begin(relids, VMBUS_RELID_CAPACITY,
				       channel_id);
	if (rc > 0)
		return 0;
	if (rc == -ENOENT)
		return 0;
	if (rc)
		return rc;
	vmbus_protocol_release(channel_id, &action);
	rc = handle_action(&action);
	vmbus_relid_release_finish(relids, VMBUS_RELID_CAPACITY,
				   channel_id, !rc, retain_claim);
	if (!rc)
		vmbus_control_channel_resource_released();
	return rc;
}

static int defer_relid_release(__u32 channel_id, __u64 sequence)
{
	unsigned long flags;
	unsigned int i;

	ukplat_spin_lock_irqsave(&deferred_release_lock, flags);
	for (i = 0; i < VMBUS_RELID_CAPACITY; i++) {
		if (deferred_relid_releases[i].channel_id == channel_id &&
		    deferred_relid_releases[i].sequence == sequence)
			goto found;
		if (!deferred_relid_releases[i].channel_id) {
			deferred_relid_releases[i].sequence = sequence;
			deferred_relid_releases[i].channel_id = channel_id;
			goto found;
		}
	}
	ukplat_spin_unlock_irqrestore(&deferred_release_lock, flags);
	return -ENOSPC;
found:
	ukplat_spin_unlock_irqrestore(&deferred_release_lock, flags);
	signal_worker();
	return 0;
}

static int process_deferred_releases(void)
{
	unsigned long flags;
	unsigned int i;

	for (i = 0; i < VMBUS_RELID_CAPACITY; i++) {
		__u64 sequence;
		__u32 channel_id;
		int rc;
		struct vmbus_relid_lifecycle *entry;

		ukplat_spin_lock_irqsave(&deferred_release_lock, flags);
		channel_id = deferred_relid_releases[i].channel_id;
		sequence = deferred_relid_releases[i].sequence;
		deferred_relid_releases[i].channel_id = 0;
		deferred_relid_releases[i].sequence = 0;
		ukplat_spin_unlock_irqrestore(&deferred_release_lock, flags);
		if (!channel_id)
			continue;
		entry = vmbus_relid_find(relids, VMBUS_RELID_CAPACITY,
					 channel_id);
		if (!entry || entry->sequence != sequence)
			continue;
		rc = release_channel(channel_id, 0);
		if (rc)
			return rc;
	}
	return 0;
}

static void reset_release_records(void)
{
	unsigned int i;

	for (i = 0; i < VMBUS_RELID_CAPACITY; i++) {
		relids[i].channel_id = 0;
		relids[i].state = VMBUS_RELID_FREE;
		relids[i].retained = 0;
		relids[i].sequence = 0;
		deferred_relid_releases[i].channel_id = 0;
		deferred_relid_releases[i].sequence = 0;
	}
}

static void copy_offer(struct vmbus_device *dev,
		       const struct vmbus_decoded_offer *offer)
{
	copy_bytes(dev->class_id.bytes, offer->class_id, 16);
	copy_bytes(dev->instance_id.bytes, offer->instance_id, 16);
	dev->channel_id = offer->channel_id;
	dev->connection_id = offer->connection_id;
	dev->flags = offer->flags;
	dev->mmio_megabytes = offer->mmio_megabytes;
	dev->mmio_megabytes_optional = offer->mmio_megabytes_optional;
	dev->subchannel_index = offer->subchannel_index;
	dev->monitor_id = offer->monitor_id;
	dev->monitor_allocated = offer->monitor_allocated;
	dev->dedicated = offer->dedicated;
	copy_bytes(dev->user_data, offer->user_data, VMBUS_USER_DATA_SIZE);
	dev->driver = NULL;
	dev->channel = NULL;
	dev->present = 1;
}

static int add_offer(const struct vmbus_decoded_offer *offer)
{
	struct vmbus_device *free_slot = NULL;
	struct vmbus_device *deferred_slot = NULL;
	struct vmbus_device *dev;
	struct vmbus_device_binding *binding;
	unsigned int i;
	int rc;

	if (guid_equal_bytes(&vmbus_storage_guid, offer->class_id))
		__atomic_store_n(&storage_offer_lifetime_observed, 1,
				 __ATOMIC_RELEASE);
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		dev = &devices[i];
		if (dev->present && dev->channel_id == offer->channel_id) {
			if (!guid_equal_bytes(&dev->class_id, offer->class_id) ||
			    !guid_equal_bytes(&dev->instance_id,
					      offer->instance_id))
				return -EINVAL;
			return 0;
		}

		binding = &device_bindings[i];
		if (!dev->present && binding->state == VMBUS_BIND_UNUSED &&
		    !binding->pending_offer_valid && !free_slot)
			free_slot = dev;
		if (!dev->present &&
		    binding->state == VMBUS_BIND_REMOVE_PENDING &&
		    !binding->pending_offer_valid && !deferred_slot)
			deferred_slot = dev;
	}
	if (!free_slot && deferred_slot) {
		binding = device_binding(deferred_slot);
		rc = vmbus_relid_offer(relids, VMBUS_RELID_CAPACITY,
				       offer->channel_id, 1,
				       &relid_sequence);
		if (rc > 0)
			return 0;
		if (rc)
			return rc;
		binding->pending_offer = *offer;
		binding->pending_offer_valid = 1;
		__atomic_store_n(&bind_work_pending, 1, __ATOMIC_RELEASE);
		return 0;
	}
	if (!free_slot) {
		rc = vmbus_relid_offer(relids, VMBUS_RELID_CAPACITY,
				       offer->channel_id, 0,
				       &relid_sequence);
		if (rc > 0)
			return 0;
		if (rc)
			return rc;
		rc = release_channel(offer->channel_id, 1);

		return rc ? rc : -ENOSPC;
	}

	rc = vmbus_relid_offer(relids, VMBUS_RELID_CAPACITY,
			       offer->channel_id, 1, &relid_sequence);
	if (rc > 0)
		return 0;
	if (rc)
		return rc;
	copy_offer(free_slot, offer);
	binding = device_binding(free_slot);
	rc = assign_device_generation(binding);
	if (rc) {
		clear_device_fields(free_slot);
		(void)release_channel(offer->channel_id, 0);
		return rc;
	}
	binding->state = VMBUS_BIND_UNATTEMPTED;
	binding->retry_epoch = 0;
	binding->failure_epoch = 0;
	binding->adding_driver = NULL;
	binding->offer_driver = NULL;
	binding->capacity_failure = 0;
	binding->remove_called = 0;
	binding->offer_remove_notified = 0;
	device_count++;
	__atomic_store_n(&bind_work_pending, 1, __ATOMIC_RELEASE);
	process_bind_work();
	if (binding->state == VMBUS_BIND_UNATTEMPTED &&
	    !find_driver(&free_slot->class_id)) {
		const char *kind =
			guid_equal(&free_slot->class_id, &vmbus_storage_guid) ?
			"storage (no data-path driver)" :
			guid_equal(&free_slot->class_id, &vmbus_network_guid) ?
			"network (no data-path driver)" : "unknown";

		uk_pr_info("VMBus: channel %u class %s preserved unbound\n",
			   free_slot->channel_id, kind);
	}
	return 0;
}

int vmbus_storage_offer_lifetime_observed(void)
{
	return __atomic_load_n(&storage_offer_lifetime_observed,
			       __ATOMIC_ACQUIRE);
}

static int rescind_offer(__u32 channel_id)
{
	struct vmbus_relid_lifecycle *lifecycle;
	unsigned int i;
	int channel_rc;
	int release_rc;

	lifecycle = vmbus_relid_find(relids, VMBUS_RELID_CAPACITY,
				     channel_id);
	if (!lifecycle)
		return 0;
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		if (!device_bindings[i].pending_offer_valid ||
		    device_bindings[i].pending_offer.channel_id !=
			    channel_id)
			continue;
		device_bindings[i].pending_offer_valid = 0;
		if (lifecycle->state == VMBUS_RELID_RELEASED)
			vmbus_relid_forget(relids, VMBUS_RELID_CAPACITY,
					   channel_id);
		else {
			int rc = release_channel(channel_id, 0);

			if (rc)
				return rc;
		}
		return 0;
	}
	channel_rc = vmbus_channel_rescind(channel_id);
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++)
		if (devices[i].present &&
		    devices[i].channel_id == channel_id) {
			remove_device(&devices[i]);
			break;
		}
	if (lifecycle->state == VMBUS_RELID_RELEASED) {
		vmbus_relid_forget(relids, VMBUS_RELID_CAPACITY, channel_id);
		return channel_rc == -EINPROGRESS ? 0 : channel_rc;
	}
	if (channel_rc == -EINPROGRESS)
		return 0;
	release_rc = release_channel(channel_id, 0);
	return channel_rc ? channel_rc : release_rc;
}

static int handle_action(const struct vmbus_action *action)
{
	int rc;

	switch (action->kind) {
	case VMBUS_ACTION_NONE:
	case VMBUS_ACTION_STALE:
		return 0;
	case VMBUS_ACTION_TRANSMIT:
		return transmit(action);
	case VMBUS_ACTION_OFFER:
		rc = add_offer(&action->offer);
		if (rc == -ENOSPC)
			uk_pr_err("VMBus: device capacity %u exhausted\n",
				  CONFIG_LIBVMBUS_MAX_DEVICES);
		else if (rc)
			uk_pr_err("VMBus: conflicting offer for channel %u\n",
				  action->offer.channel_id);
		return rc;
	case VMBUS_ACTION_RESCIND:
		return rescind_offer(action->channel_id);
	case VMBUS_ACTION_REJECT_OFFER:
		rc = vmbus_relid_offer(relids, VMBUS_RELID_CAPACITY,
				       action->channel_id, 0,
				       &relid_sequence);
		if (rc > 0)
			return 0;
		if (rc)
			return rc;
		return release_channel(action->channel_id, 1);
	case VMBUS_ACTION_OFFERS_COMPLETE:
		uk_pr_info("VMBus: protocol %u.%u enumerated %u device(s)\n",
			   vmbus_protocol_version() >> 16,
			   vmbus_protocol_version() & 0xffff,
			   device_count);
		return 0;
	case VMBUS_ACTION_CLEANUP:
		clear_devices();
		return action->error ? -ETIMEDOUT : 0;
	case VMBUS_ACTION_MALFORMED:
		uk_pr_warn("VMBus: ignored malformed/unexpected control message "
			   "(%d)\n", action->error);
		return 0;
	case VMBUS_ACTION_FAILED:
		uk_pr_err("VMBus: protocol transaction failed (%d)\n",
			  action->error);
		return -EIO;
	default:
		return -EINVAL;
	}
}

static int process_messages(void)
{
	struct vmbus_rx_entry entry;
	struct vmbus_action action;
	int rc;

	if (__atomic_load_n(&rx_state.lost, __ATOMIC_ACQUIRE))
		return -EOVERFLOW;
	while (dequeue_message(&entry)) {
		__u32 type = (__u32)entry.data[0] |
			((__u32)entry.data[1] << 8) |
			((__u32)entry.data[2] << 16) |
			((__u32)entry.data[3] << 24);

		if (type == 6 || type == 10 || type == 12) {
			rc = vmbus_channel_control_receive(entry.data, entry.len);
			if (rc)
				return rc;
			continue;
		}
		vmbus_protocol_receive(entry.data, entry.len, entry.generation,
				       hyperv_reference_time(), &action);
		rc = handle_action(&action);
		if (rc)
			return rc;
	}
	if (__atomic_load_n(&bind_work_pending, __ATOMIC_ACQUIRE))
		process_bind_work();
	return 0;
}

static void report_deferred_diagnostics(void)
{
	__u32 count;
	unsigned int word;

	count = __atomic_exchange_n(&malformed_hv_messages, 0,
				    __ATOMIC_ACQ_REL);
	if (count)
		uk_pr_warn("VMBus: dropped %u malformed Hyper-V message(s)\n",
			   count);
	count = __atomic_exchange_n(&rx_dropped, 0, __ATOMIC_ACQ_REL);
	if (count)
		uk_pr_warn("VMBus: SINT2 queue dropped %u message(s)\n", count);
	count = __atomic_exchange_n(&event_dropped, 0, __ATOMIC_ACQ_REL);
	if (count)
		uk_pr_warn("VMBus: event queue dropped %u event(s)\n", count);
	count = 0;
	for (word = 0; word < VMBUS_LEGACY_EVENT_WORDS; word++) {
		__u64 pending = __atomic_exchange_n(&event_pending[word], 0,
						    __ATOMIC_ACQ_REL);

		while (pending) {
			unsigned int bit = __builtin_ctzll(pending);
			__u32 event = word * 64U + bit;

			if (event)
				vmbus_channel_event(event);
			pending &= pending - 1;
			count++;
		}
	}
	if (count)
		uk_pr_debug("VMBus: deferred %u channel event(s)\n", count);
	count = vmbus_channel_take_ignored_responses();
	if (count)
		uk_pr_debug("VMBus: ignored %u late/duplicate channel "
			    "response(s)\n", count);
}

static void wait_once(void)
{
	if (uk_sched_current())
		uk_sched_thread_sleep(VMBUS_WORKER_SLEEP_NS);
	else
		vmbus_cpu_relax();
}

static int drive_until(int terminal_a, int terminal_b)
{
	struct vmbus_action action;
	int state;
	int rc;

	for (;;) {
		if (__atomic_load_n(&rx_state.lost, __ATOMIC_ACQUIRE))
			return -EOVERFLOW;
		rc = process_messages();
		if (rc)
			return rc;
		report_deferred_diagnostics();
		if (__atomic_load_n(&bind_work_pending, __ATOMIC_ACQUIRE)) {
			wait_once();
			continue;
		}
		state = vmbus_protocol_state();
		if (state == terminal_a || state == terminal_b)
			return state == terminal_a ? 0 : -EIO;
		vmbus_protocol_tick(hyperv_reference_time(), &action);
		rc = handle_action(&action);
		if (rc)
			return rc;
		wait_once();
	}
}

static __paddr_t page_gpa(void *page)
{
	__paddr_t gpa = uk_paging_virt_to_phys((__vaddr_t)page);

	if (gpa == UK_PAGING_PADDR_INV ||
	    (gpa & (HYPERV_PAGE_SIZE - 1)))
		return UK_PAGING_PADDR_INV;
	return gpa;
}

static int connection_generation_begin(void)
{
	__u64 generation;

	if (live_connection_generation)
		return -EBUSY;
	generation = next_connection_generation;
	if (!generation)
		return -ENOSPC;
	live_connection_generation = generation;
	next_connection_generation =
		generation == UINT64_MAX ? 0 : generation + 1;
	connection_teardown_failed = 0;
	connection_teardown_error = 0;
	return 0;
}

static void connection_generation_fail(int error)
{
	if (!live_connection_generation)
		return;
	connection_teardown_failed = 1;
	connection_teardown_error = error ? error : -EIO;
}

static int connection_generation_quiesce(void)
{
	if (!live_connection_generation)
		return 0;
	if (__atomic_load_n(&connection_quiesce_epoch,
			    __ATOMIC_ACQUIRE) == UINT64_MAX)
		return -ENOSPC;
	live_connection_generation = 0;
	connection_teardown_failed = 0;
	connection_teardown_error = 0;
	(void)__atomic_add_fetch(&connection_quiesce_epoch, 1,
				 __ATOMIC_ACQ_REL);
	return 0;
}

static int connect_protocol(void)
{
	struct vmbus_start_config config = { 0 };
	struct vmbus_action action;
	__paddr_t gpa;
	int rc;

	if (live_connection_generation)
		return -EBUSY;
	if (!next_connection_generation)
		return -ENOSPC;
	if (!hyperv_has_post_messages()) {
		uk_pr_err("VMBus: Hyper-V PostMessages privilege is absent\n");
		return -EACCES;
	}
	clear_devices();
	reset_release_records();
	{
		unsigned long flags;

		ukplat_spin_lock_irqsave(&rx_queue_lock, flags);
	vmbus_queue_recover(&rx_state);
		ukplat_spin_unlock_irqrestore(&rx_queue_lock, flags);
		for (unsigned int word = 0;
		     word < VMBUS_LEGACY_EVENT_WORDS; word++)
			__atomic_store_n(&event_pending[word], 0,
					 __ATOMIC_RELEASE);
	}
	__atomic_store_n(&connection_failed, 0, __ATOMIC_RELEASE);
	__atomic_store_n(&rx_active, 1, __ATOMIC_RELEASE);

	gpa = page_gpa(interrupt_page);
	if (gpa == UK_PAGING_PADDR_INV)
		return -EINVAL;
	config.interrupt_page_gpa = gpa;
	gpa = page_gpa(parent_to_child_monitor);
	if (gpa == UK_PAGING_PADDR_INV)
		return -EINVAL;
	config.parent_to_child_monitor_gpa = gpa;
	gpa = page_gpa(child_to_parent_monitor);
	if (gpa == UK_PAGING_PADDR_INV)
		return -EINVAL;
	config.child_to_parent_monitor_gpa = gpa;
	rc = hyperv_vmbus_target_acquire(&connection_target_vp,
					 &connection_target_generation);
	if (rc)
		return rc;
	connection_target_held = 1;
	config.target_vp = connection_target_vp;
	config.timeout_ticks =
		(__u64)CONFIG_LIBVMBUS_VERSION_TIMEOUT_MS *
		VMBUS_REFERENCE_TICKS_PER_MS;

	vmbus_protocol_start(hyperv_reference_time(), &config, &action);
	rc = handle_action(&action);
	if (rc) {
		hyperv_vmbus_target_release(connection_target_vp,
					   connection_target_generation);
		connection_target_held = 0;
		return rc;
	}
	rc = connection_generation_begin();
	if (rc) {
		hyperv_vmbus_target_release(connection_target_vp,
					   connection_target_generation);
		connection_target_held = 0;
		return rc;
	}
	rc = drive_until(VMBUS_STATE_READY, VMBUS_STATE_FAILED);
	return rc;
}

static void drain_queues(void)
{
	unsigned long flags;
	unsigned int word;

	ukplat_spin_lock_irqsave(&rx_queue_lock, flags);
	vmbus_queue_drain(&rx_state);
	ukplat_spin_unlock_irqrestore(&rx_queue_lock, flags);
	for (word = 0; word < VMBUS_LEGACY_EVENT_WORDS; word++)
		__atomic_store_n(&event_pending[word], 0, __ATOMIC_RELEASE);
}

static int disconnect_locked(void)
{
	struct vmbus_action action;
	int state = vmbus_protocol_state();
	int rc = 0;

	drain_queues();
	{
		unsigned long flags;

		ukplat_spin_lock_irqsave(&rx_queue_lock, flags);
		__atomic_store_n(&rx_state.lost, 0, __ATOMIC_RELEASE);
		ukplat_spin_unlock_irqrestore(&rx_queue_lock, flags);
	}
	vmbus_channel_close_all();
	clear_devices();
	if (!live_connection_generation)
		goto out_reset;
	if (connection_teardown_failed) {
		rc = connection_teardown_error;
		goto out_reset;
	}
	/*
	 * A local parser reset to IDLE/DISCONNECTED is not host teardown.
	 * Every negotiated generation requires CHANNELMSG_UNLOAD_RESPONSE;
	 * posting UNLOAD or timing out is never used as DMA-quiesce proof.
	 */
	if (state == VMBUS_STATE_IDLE || state == VMBUS_STATE_DISCONNECTED) {
		rc = -EIO;
		goto out_proof;
	}
	{
		vmbus_protocol_unload(hyperv_reference_time(), &action);
		rc = handle_action(&action);
		if (!rc)
			rc = drive_until(VMBUS_STATE_DISCONNECTED,
					 VMBUS_STATE_FAILED);
	}
out_proof:
	if (!rc)
		rc = connection_generation_quiesce();
	if (rc)
		connection_generation_fail(rc);
out_reset:
	__atomic_store_n(&rx_active, 0, __ATOMIC_RELEASE);
	reset_release_records();
	drain_queues();
	vmbus_protocol_reset();
	if (live_connection_generation)
		vmbus_channel_quarantine_all();
	else
		vmbus_channel_reset_all();
	if (!rc && connection_target_held) {
		hyperv_vmbus_target_release(connection_target_vp,
					   connection_target_generation);
		connection_target_held = 0;
	}
	return rc;
}

static void unwind_stop(void *arg __unused)
{
	stop_worker_locked();
}

static void unwind_remove(void *arg __unused)
{
	clear_devices();
}

static int unwind_unload(void *arg __unused)
{
	struct vmbus_action action;
	int state = vmbus_protocol_state();
	int tracked = live_connection_generation != 0;
	int rc = 0;

	drain_queues();
	{
		unsigned long flags;

		ukplat_spin_lock_irqsave(&rx_queue_lock, flags);
		__atomic_store_n(&rx_state.lost, 0, __ATOMIC_RELEASE);
		ukplat_spin_unlock_irqrestore(&rx_queue_lock, flags);
	}
	vmbus_channel_close_all();
	if (tracked &&
	    (state == VMBUS_STATE_IDLE || state == VMBUS_STATE_DISCONNECTED)) {
		rc = -EIO;
	} else if (state != VMBUS_STATE_IDLE &&
		   state != VMBUS_STATE_DISCONNECTED) {
		vmbus_protocol_unload(hyperv_reference_time(), &action);
		rc = handle_action(&action);
		if (!rc)
			rc = drive_until(VMBUS_STATE_DISCONNECTED,
					 VMBUS_STATE_FAILED);
	}
	if (tracked) {
		if (!rc)
			rc = connection_generation_quiesce();
		if (rc)
			connection_generation_fail(rc);
	}
	__atomic_store_n(&rx_active, 0, __ATOMIC_RELEASE);
	return rc;
}

static void unwind_drain(void *arg __unused)
{
	drain_queues();
}

static void unwind_reset(void *arg __unused)
{
	reset_release_records();
	__atomic_store_n(&connection_failed, 0, __ATOMIC_RELEASE);
	{
		unsigned long flags;

		ukplat_spin_lock_irqsave(&rx_queue_lock, flags);
		vmbus_queue_recover(&rx_state);
		ukplat_spin_unlock_irqrestore(&rx_queue_lock, flags);
	}
	vmbus_protocol_reset();
	if (live_connection_generation)
		vmbus_channel_quarantine_all();
	else
		vmbus_channel_reset_all();
}

static int probe_unwind_locked(int primary_error)
{
	static const struct vmbus_unwind_ops ops = {
		.stop_work = unwind_stop,
		.remove_devices = unwind_remove,
		.unload = unwind_unload,
		.drain_queues = unwind_drain,
		.reset_protocol = unwind_reset,
	};

	return vmbus_probe_unwind_run(&ops, NULL, primary_error);
}

static void vmbus_worker(void *arg __unused)
{
	struct vmbus_action action;
	int rc;

	for (;;) {
		if (__atomic_load_n(&worker_stop, __ATOMIC_ACQUIRE))
			break;
		if (__atomic_load_n(&rx_state.lost, __ATOMIC_ACQUIRE) ||
		    __atomic_load_n(&connection_failed, __ATOMIC_ACQUIRE)) {
			if (!acquire_control()) {
				uk_pr_err("VMBus: control state lost; reconnecting\n");
				rc = disconnect_locked();
				if (!rc)
					rc = connect_protocol();
				if (rc) {
					(void)disconnect_locked();
					__atomic_store_n(&connection_failed, 1,
							 __ATOMIC_RELEASE);
					__atomic_store_n(&rx_active, 0,
							 __ATOMIC_RELEASE);
					__atomic_store_n(&worker_stop, 1,
							 __ATOMIC_RELEASE);
					uk_pr_err("VMBus: overflow recovery failed "
						  "(%d); bus disabled\n", rc);
				}
				release_control();
			}
			uk_sched_thread_sleep(VMBUS_WORKER_SLEEP_NS);
			continue;
		}
		if (!acquire_control()) {
			rc = process_messages();
			if (!rc)
				rc = process_deferred_releases();
			if (!rc && __atomic_exchange_n(&bind_work_pending, 0,
						       __ATOMIC_ACQ_REL))
				process_bind_work();
			vmbus_protocol_tick(hyperv_reference_time(), &action);
			if (!rc)
				rc = handle_action(&action);
			if (rc)
				__atomic_store_n(&connection_failed, 1,
						 __ATOMIC_RELEASE);
			report_deferred_diagnostics();
			release_control();
		}
		uk_sched_thread_sleep(VMBUS_WORKER_SLEEP_NS);
	}
	{
		unsigned long flags;

		ukplat_spin_lock_irqsave(&worker_lock, flags);
		__atomic_store_n(&worker, NULL, __ATOMIC_RELEASE);
		ukplat_spin_unlock_irqrestore(&worker_lock, flags);
	}
	uk_sched_thread_exit();
}

static int start_worker(void)
{
	struct uk_sched *sched = uk_sched_current();
	struct uk_thread *thread;
	unsigned long flags;

	if (!sched)
		return -ENOSYS;
	ukplat_spin_lock_irqsave(&worker_lock, flags);
	if (__atomic_load_n(&worker, __ATOMIC_ACQUIRE)) {
		ukplat_spin_unlock_irqrestore(&worker_lock, flags);
		return -EBUSY;
	}
	ukplat_spin_unlock_irqrestore(&worker_lock, flags);
	worker_stop = 0;
	thread = uk_sched_thread_create(sched, vmbus_worker, NULL, "vmbus");
	if (!thread)
		return -ENOMEM;
	ukplat_spin_lock_irqsave(&worker_lock, flags);
	__atomic_store_n(&worker, thread, __ATOMIC_RELEASE);
	ukplat_spin_unlock_irqrestore(&worker_lock, flags);
	return 0;
}

struct worker_stop_context {
	unsigned long flags;
};

static int worker_stop_can_wait(void *arg __unused)
{
	return uk_sched_current() && !uk_lcpu_irqs_disabled();
}

static void worker_stop_lock(void *arg)
{
	struct worker_stop_context *context = arg;

	ukplat_spin_lock_irqsave(&worker_lock, context->flags);
}

static void worker_stop_unlock(void *arg)
{
	struct worker_stop_context *context = arg;

	ukplat_spin_unlock_irqrestore(&worker_lock, context->flags);
}

static int worker_stop_present_locked(void *arg __unused)
{
	return worker != NULL;
}

static int worker_stop_is_self_locked(void *arg __unused)
{
	return worker == uk_thread_current();
}

static void worker_stop_set_locked(void *arg __unused)
{
	worker_stop = 1;
}

static void worker_stop_wake_locked(void *arg __unused)
{
	uk_thread_wake(worker);
}

static int worker_stop_present(void *arg)
{
	int present;

	worker_stop_lock(arg);
	present = worker_stop_present_locked(arg);
	worker_stop_unlock(arg);
	return present;
}

static void worker_stop_wait(void *arg __unused)
{
	uk_sched_thread_sleep(VMBUS_WORKER_SLEEP_NS);
}

static const struct vmbus_worker_stop_ops worker_stop_ops = {
	.can_wait_before_lock = worker_stop_can_wait,
	.lock = worker_stop_lock,
	.unlock = worker_stop_unlock,
	.worker_present_locked = worker_stop_present_locked,
	.caller_is_worker_locked = worker_stop_is_self_locked,
	.set_stop_locked = worker_stop_set_locked,
	.wake_locked = worker_stop_wake_locked,
	.worker_present = worker_stop_present,
	.wait_once = worker_stop_wait,
};

static void stop_worker_locked(void)
{
	struct worker_stop_context context;

	(void)vmbus_worker_stop_run(&worker_stop_ops, &context,
				    VMBUS_TEARDOWN_WAIT_LIMIT);
}

static int acquire_control(void)
{
	int expected = 0;

	if (!__atomic_compare_exchange_n(&control_busy, &expected, 1, 0,
					 __ATOMIC_ACQ_REL,
					 __ATOMIC_ACQUIRE))
		return -EBUSY;
	__atomic_store_n(&control_owner, uk_thread_current(), __ATOMIC_RELEASE);
	return 0;
}

int vmbus_control_enter(int *acquired)
{
	if (__atomic_load_n(&control_busy, __ATOMIC_ACQUIRE) &&
	    __atomic_load_n(&control_owner, __ATOMIC_ACQUIRE) ==
		    uk_thread_current()) {
		*acquired = 0;
		return 0;
	}
	if (acquire_control())
		return -EBUSY;
	*acquired = 1;
	return 0;
}

void vmbus_control_exit(int acquired)
{
	if (acquired)
		release_control();
}

int vmbus_control_pump(void)
{
#ifdef VMBUS_BUS_HOST_TEST
	if (host_pump_hook)
		return host_pump_hook();
#endif
	return process_messages();
}

__u64 vmbus_control_relid_sequence(__u32 channel_id)
{
	struct vmbus_relid_lifecycle *entry =
		vmbus_relid_find(relids, VMBUS_RELID_CAPACITY, channel_id);

	return entry ? entry->sequence : 0;
}

int vmbus_control_release_relid(__u32 channel_id, __u64 sequence)
{
	struct vmbus_relid_lifecycle *entry;
	int acquired;
	int rc;

	entry = vmbus_relid_find(relids, VMBUS_RELID_CAPACITY, channel_id);
	if (!entry || !sequence || entry->sequence != sequence)
		return 0;
	rc = vmbus_control_enter(&acquired);
	if (rc == -EBUSY)
		return defer_relid_release(channel_id, sequence);
	if (rc)
		return rc;
	entry = vmbus_relid_find(relids, VMBUS_RELID_CAPACITY, channel_id);
	rc = (!entry || entry->sequence != sequence) ?
		0 : release_channel(channel_id, 0);
	vmbus_control_exit(acquired);
	return rc;
}

void vmbus_control_fail(void)
{
	__atomic_store_n(&connection_failed, 1, __ATOMIC_RELEASE);
}

int vmbus_control_set_event(__u32 channel_id)
{
	__u32 word;
	__u32 bit;
	__u32 *send_page = (__u32 *)&interrupt_page[HYPERV_PAGE_SIZE / 2];

	if (channel_id >= (HYPERV_PAGE_SIZE / 2) * 8)
		return -ERANGE;
	word = channel_id / 32;
	bit = channel_id % 32;
	__atomic_fetch_or(&send_page[word], 1U << bit, __ATOMIC_RELEASE);
	return 0;
}

__u64 vmbus_control_channel_capacity_epoch(struct vmbus_device *device)
{
	struct vmbus_device_binding *binding = device_binding(device);
	unsigned long flags;
	__u64 epoch = 0;

	if (!binding)
		return 0;
	bind_state_lock(&flags);
	if (binding->state == VMBUS_BIND_ADDING)
		epoch = channel_resource_epoch;
	bind_state_unlock(flags);
	return epoch;
}

void vmbus_control_note_channel_capacity(struct vmbus_device *device,
					 __u64 epoch)
{
	struct vmbus_device_binding *binding = device_binding(device);
	unsigned long flags;

	if (!binding)
		return;
	bind_state_lock(&flags);
	if (binding->state == VMBUS_BIND_ADDING) {
		binding->failure_epoch = epoch ? epoch : channel_resource_epoch;
		binding->capacity_failure = 1;
	}
	bind_state_unlock(flags);
}

void vmbus_control_channel_resource_released(void)
{
	unsigned long flags;

	bind_state_lock(&flags);
	if (bind_attempt_active &&
	    bind_attempt_owner == uk_thread_current() &&
	    bind_attempt_binding && bind_attempt_binding->capacity_failure) {
		bind_state_unlock(flags);
		return;
	}
	if (channel_resource_epoch == UINT64_MAX) {
		bind_state_unlock(flags);
		return;
	}
	channel_resource_epoch++;
	__atomic_store_n(&bind_work_pending, 1, __ATOMIC_RELEASE);
	bind_state_unlock(flags);
	signal_worker();
}

int vmbus_device_bind_epoch(struct vmbus_device *device,
			    struct vmbus_device_bind_token *token)
{
	struct vmbus_device_binding *binding = device_binding(device);
	unsigned long flags;
	int rc = 0;

	if (!binding || !token)
		return -EINVAL;
	bind_state_lock(&flags);
	if (binding->state != VMBUS_BIND_ADDING || !binding->generation ||
	    !bind_attempt_active || bind_attempt_binding != binding ||
	    bind_attempt_owner != uk_thread_current()) {
		rc = -ESTALE;
	} else {
		token->device_generation = binding->generation;
		token->resource_epoch = channel_resource_epoch;
	}
	bind_state_unlock(flags);
	return rc;
}

int vmbus_device_bind_retry(
	struct vmbus_device *device,
	const struct vmbus_device_bind_token *token)
{
	struct vmbus_device_binding *binding = device_binding(device);
	unsigned long flags;
	int rc = -ENOSPC;

	if (!binding || !token || !token->device_generation ||
	    !token->resource_epoch)
		return -EINVAL;
	bind_state_lock(&flags);
	if (binding->state != VMBUS_BIND_ADDING ||
	    binding->generation != token->device_generation ||
	    !bind_attempt_active || bind_attempt_binding != binding ||
	    bind_attempt_owner != uk_thread_current()) {
		rc = -ESTALE;
	} else if (token->resource_epoch > channel_resource_epoch) {
		rc = -EINVAL;
	} else {
		binding->failure_epoch = token->resource_epoch;
		binding->capacity_failure = 1;
	}
	bind_state_unlock(flags);
	return rc;
}

void vmbus_device_bind_ready(void)
{
	vmbus_control_channel_resource_released();
}

static void release_control(void)
{
	__atomic_store_n(&control_owner, NULL, __ATOMIC_RELEASE);
	__atomic_store_n(&control_busy, 0, __ATOMIC_RELEASE);
}

static void teardown_deactivate_rx(void *arg __unused)
{
	__atomic_store_n(&rx_active, 0, __ATOMIC_RELEASE);
}

static void teardown_signal_stop(void *arg __unused, int can_schedule)
{
	struct uk_thread *thread;
	unsigned long flags;

	ukplat_spin_lock_irqsave(&worker_lock, flags);
	thread = __atomic_load_n(&worker, __ATOMIC_ACQUIRE);
	__atomic_store_n(&worker_stop, 1, __ATOMIC_RELEASE);
	if (can_schedule && thread && thread != uk_thread_current())
		uk_thread_wake(thread);
	ukplat_spin_unlock_irqrestore(&worker_lock, flags);
}

static int teardown_try_control(void *arg __unused)
{
	return acquire_control();
}

static int teardown_control_owned(void *arg __unused)
{
	return __atomic_load_n(&control_busy, __ATOMIC_ACQUIRE) &&
	       __atomic_load_n(&control_owner, __ATOMIC_ACQUIRE) ==
		       uk_thread_current();
}

static int teardown_worker_present(void *arg __unused)
{
	return __atomic_load_n(&worker, __ATOMIC_ACQUIRE) != NULL;
}

static int teardown_caller_is_worker(void *arg __unused)
{
	struct uk_thread *thread =
		__atomic_load_n(&worker, __ATOMIC_ACQUIRE);

	return thread && thread == uk_thread_current();
}

static void teardown_wait(void *arg __unused)
{
	uk_sched_thread_sleep(VMBUS_WORKER_SLEEP_NS);
}

static const struct vmbus_teardown_ops teardown_ops = {
	.deactivate_rx = teardown_deactivate_rx,
	.signal_stop = teardown_signal_stop,
	.try_acquire_control = teardown_try_control,
	.control_owned_by_caller = teardown_control_owned,
	.worker_present = teardown_worker_present,
	.caller_is_worker = teardown_caller_is_worker,
	.wait_once = teardown_wait,
};

static int teardown_enter(int *control_acquired)
{
	int can_schedule = uk_sched_current() && !uk_lcpu_irqs_disabled();

	return vmbus_teardown_enter(&teardown_ops, NULL, can_schedule,
				    VMBUS_TEARDOWN_WAIT_LIMIT,
				    control_acquired);
}

int vmbus_unload(void)
{
	int control_acquired;
	int rc;

	rc = teardown_enter(&control_acquired);
	if (rc)
		return rc;
	rc = disconnect_locked();
	if (control_acquired)
		release_control();
	return rc;
}

int vmbus_reconnect(void)
{
	int rc;

	rc = vmbus_unload();
	if (rc)
		return rc;
	rc = acquire_control();
	if (rc)
		return rc;
	rc = connect_protocol();
	if (!rc)
		rc = start_worker();
	if (rc)
		(void)disconnect_locked();
	release_control();
	return rc;
}

__u64 vmbus_connection_fail(void)
{
	__u64 epoch = __atomic_load_n(&connection_quiesce_epoch,
				      __ATOMIC_ACQUIRE);

#ifdef VMBUS_BUS_HOST_TEST
	(void)__atomic_add_fetch(&host_connection_fail_calls, 1,
				 __ATOMIC_RELAXED);
#endif
	vmbus_control_fail();
	return epoch;
}

__u64 vmbus_connection_quiesce_epoch(void)
{
	return __atomic_load_n(&connection_quiesce_epoch, __ATOMIC_ACQUIRE);
}

int hyperv_vmbus_shutdown(void)
{
	int control_acquired;
	int rc;

	if (!teardown_enter(&control_acquired)) {
		rc = disconnect_locked();
		if (control_acquired)
			release_control();
	} else {
		vmbus_teardown_final_fallback(&teardown_ops, NULL);
		rc = -EWOULDBLOCK;
	}
	initialized = 0;
	return rc;
}

void hyperv_vmbus_fini(void)
{
	(void)hyperv_vmbus_shutdown();
}

unsigned int vmbus_device_count(void)
{
	return device_count;
}

const struct vmbus_device *vmbus_device_get(unsigned int index)
{
	unsigned int i;
	unsigned int found = 0;

	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		if (!devices[i].present)
			continue;
		if (found++ == index)
			return &devices[i];
	}
	return NULL;
}

int vmbus_device_is_bound(const struct vmbus_device *device)
{
	struct vmbus_device_binding *binding =
		device_binding(device);
	unsigned long flags;
	int bound = 0;

	if (!binding)
		return 0;
	bind_state_lock(&flags);
	if (device->present && device->driver &&
	    binding->state == VMBUS_BIND_BOUND && binding->generation)
		bound = 1;
	bind_state_unlock(flags);
	return bound;
}

int _vmbus_register_driver(struct vmbus_driver *driver)
{
	if (!driver || !driver->name || !driver->device_ids)
		return -EINVAL;
	for (unsigned int i = 0; i < driver_count; i++)
		if (drivers[i] == driver)
			return -EEXIST;
	if (driver_count >= CONFIG_LIBVMBUS_MAX_DRIVERS)
		return -ENOSPC;
	drivers[driver_count++] = driver;
	__atomic_store_n(&bind_work_pending, 1, __ATOMIC_RELEASE);
	process_bind_work();
	return 0;
}

static int vmbus_bus_init(struct uk_alloc *a __unused)
{
	__paddr_t gpa = uk_paging_virt_to_phys((__vaddr_t)vmbus_post_input());

	ukarch_spin_init(&worker_lock);
	ukarch_spin_init(&rx_queue_lock);
	ukarch_spin_init(&deferred_release_lock);
	ukarch_spin_init(&bind_lock);
	if (gpa == UK_PAGING_PADDR_INV || (gpa & 0xff)) {
		uk_pr_err("VMBus: invalid PostMessage input GPA 0x%lx\n", gpa);
		return -EINVAL;
	}
	post_input_gpa = gpa;
	return 0;
}

static int vmbus_bus_probe(void)
{
	int rc;

	rc = acquire_control();
	if (rc)
		return rc;
	rc = connect_protocol();
	if (rc)
		goto failed;
	rc = start_worker();
	if (rc)
		goto failed;
	initialized = 1;
	release_control();
	return (int)device_count;

failed:
	rc = probe_unwind_locked(rc);
	initialized = 0;
	release_control();
	return rc;
}

static struct uk_bus vmbus_bus = {
	.init = vmbus_bus_init,
	.probe = vmbus_bus_probe,
};
UK_BUS_REGISTER(&vmbus_bus);

#ifdef VMBUS_BUS_HOST_TEST
enum host_bind_mode {
	HOST_BIND_NESTED,
	HOST_BIND_PERMANENT,
	HOST_BIND_TRANSIENT,
	HOST_BIND_PARTIAL,
	HOST_BIND_TIMEOUT,
	HOST_BIND_NESTED_RESCIND,
	HOST_BIND_CASCADE,
	HOST_BIND_REMOVE_PUMP,
	HOST_BIND_EXPLICIT_RETRY,
	HOST_BIND_EPOCH_RACE,
	HOST_BIND_STALE_TOKEN,
};

static enum host_bind_mode host_bind_mode;
static unsigned int host_add_a;
static unsigned int host_add_b;
static unsigned int host_remove_count;
static unsigned int host_offer_removed_count;
static struct vmbus_offer_identity host_last_removed_offer;
static int host_add_active;
static int host_remove_during_add;
static unsigned int host_add_depth;
static unsigned int host_max_add_depth;
static unsigned int host_cascade_remaining;
static __u32 host_cascade_channel;
static __u32 host_remove_offer_channel;
static int host_remove_active;
static int host_add_during_remove;
static int host_stale_retry_result;
static struct vmbus_device_bind_token host_saved_bind_token;
static struct vmbus_decoded_offer host_nested_offer;
struct vmbus_channel *
vmbus_channel_host_allocate_open(struct vmbus_device *device);
struct vmbus_channel *
vmbus_channel_host_allocate_slot(struct vmbus_device *device);
int vmbus_channel_host_pin(struct vmbus_channel *channel);
void vmbus_channel_host_unpin(struct vmbus_channel *channel);
int vmbus_channel_host_is_free(struct vmbus_channel *channel);
int vmbus_channel_host_pages_used(void);
int vmbus_channel_host_record_count(void);
int vmbus_channel_host_live_gpadls(void);
int vmbus_channel_host_attach_gpadl(struct vmbus_channel *channel,
				    __u32 gpadl_id);

static void host_zero(void *pointer, size_t size)
{
	__u8 *bytes = pointer;
	size_t i;

	for (i = 0; i < size; i++)
		bytes[i] = 0;
}

static void host_make_offer(struct vmbus_decoded_offer *offer,
			    __u32 channel_id)
{
	host_zero(offer, sizeof(*offer));
	copy_bytes(offer->class_id, vmbus_storage_guid.bytes,
		   VMBUS_GUID_SIZE);
	offer->instance_id[0] = (__u8)channel_id;
	offer->channel_id = channel_id;
	offer->connection_id = channel_id + 100;
}

static int host_nested_pump(void)
{
	host_pump_hook = NULL;
	if (rescind_offer(1))
		return -EIO;
	return add_offer(&host_nested_offer);
}

static int host_nested_rescind_pump(void)
{
	host_pump_hook = NULL;
	if (rescind_offer(1) || add_offer(&host_nested_offer))
		return -EIO;
	return rescind_offer(host_nested_offer.channel_id);
}

static int host_cascade_pump(void)
{
	struct vmbus_decoded_offer offer;
	__u32 old_channel = host_cascade_channel;

	host_pump_hook = NULL;
	host_make_offer(&offer, ++host_cascade_channel);
	if (rescind_offer(old_channel))
		return -EIO;
	return add_offer(&offer);
}

static int host_auto_control_pump(void)
{
	__u8 response[20] = { 0 };
	__u32 type;
	__u32 response_type;
	__u32 channel_id;
	__u32 id;

	if (host_last_tx_len < 16)
		return 0;
	type = (__u32)host_last_tx[0] |
		((__u32)host_last_tx[1] << 8) |
		((__u32)host_last_tx[2] << 16) |
		((__u32)host_last_tx[3] << 24);
	if (type != 5 && type != 8 && type != 9 && type != 11)
		return 0;
	if (type == 9) {
		if (!host_gpadl_id)
			return 0;
		channel_id = host_gpadl_channel;
		id = host_gpadl_id;
	} else {
		channel_id = (__u32)host_last_tx[8] |
			((__u32)host_last_tx[9] << 8) |
			((__u32)host_last_tx[10] << 16) |
			((__u32)host_last_tx[11] << 24);
		id = (__u32)host_last_tx[12] |
			((__u32)host_last_tx[13] << 8) |
			((__u32)host_last_tx[14] << 16) |
			((__u32)host_last_tx[15] << 24);
	}
	response_type = type == 5 ? 6 :
		(type == 8 || type == 9) ? 10 : 12;
	response[0] = (__u8)response_type;
	if (response_type == 12) {
		response[8] = (__u8)id;
		response[9] = (__u8)(id >> 8);
		response[10] = (__u8)(id >> 16);
		response[11] = (__u8)(id >> 24);
		host_last_tx_len = 0;
		return vmbus_channel_control_receive(response, 12);
	}
	response[8] = (__u8)channel_id;
	response[9] = (__u8)(channel_id >> 8);
	response[10] = (__u8)(channel_id >> 16);
	response[11] = (__u8)(channel_id >> 24);
	response[12] = (__u8)id;
	response[13] = (__u8)(id >> 8);
	response[14] = (__u8)(id >> 16);
	response[15] = (__u8)(id >> 24);
	if (response_type == 10) {
		response[16] = (__u8)host_gpadl_status;
		response[17] = (__u8)(host_gpadl_status >> 8);
		response[18] = (__u8)(host_gpadl_status >> 16);
		response[19] = (__u8)(host_gpadl_status >> 24);
		host_gpadl_channel = 0;
		host_gpadl_id = 0;
	}
	host_last_tx_len = 0;
	return vmbus_channel_control_receive(response, 20);
}

static int host_no_response_pump(void)
{
	return 0;
}

static int host_fail_after_create_pump(void)
{
	int rc = host_auto_control_pump();

	host_transmit_error = -EIO;
	return rc;
}

static void host_complete_torndown(__u32 gpadl_id)
{
	__u8 response[12] = { 0 };

	response[0] = 12;
	response[8] = (__u8)gpadl_id;
	response[9] = (__u8)(gpadl_id >> 8);
	response[10] = (__u8)(gpadl_id >> 16);
	response[11] = (__u8)(gpadl_id >> 24);
	(void)vmbus_channel_control_receive(response, sizeof(response));
}

static int host_add_device(struct vmbus_device *dev)
{
	int rc;

	host_add_depth++;
	if (host_remove_active)
		host_add_during_remove = 1;
	if (host_add_depth > host_max_add_depth)
		host_max_add_depth = host_add_depth;
	if (host_bind_mode == HOST_BIND_CASCADE) {
		host_add_b++;
		host_add_active = 1;
		if (host_cascade_remaining) {
			host_cascade_remaining--;
			host_cascade_channel = dev->channel_id;
			host_pump_hook = host_cascade_pump;
			rc = vmbus_control_pump();
			host_add_active = 0;
			host_add_depth--;
			return rc ? rc : -ECANCELED;
		}
		host_add_active = 0;
		host_add_depth--;
		return 0;
	}
	if (dev->channel_id == 1 &&
	    (host_bind_mode == HOST_BIND_NESTED ||
	     host_bind_mode == HOST_BIND_NESTED_RESCIND)) {
		host_add_a++;
		host_add_active = 1;
		rc = vmbus_channel_open(dev, 2, 2, NULL, 0);
		host_add_active = 0;
		host_add_depth--;
		return rc;
	}
	host_add_b++;
	if (host_bind_mode == HOST_BIND_EXPLICIT_RETRY) {
		struct vmbus_device_bind_token token;

		host_add_depth--;
		if (host_add_b != 1)
			return 0;
		rc = vmbus_device_bind_epoch(dev, &token);
		return rc ? rc : vmbus_device_bind_retry(dev, &token);
	}
	if (host_bind_mode == HOST_BIND_EPOCH_RACE) {
		if (host_add_b == 1) {
			rc = vmbus_device_bind_epoch(
				dev, &host_saved_bind_token);
			if (!rc)
				vmbus_device_bind_ready();
			if (!rc)
				rc = vmbus_device_bind_retry(
					dev, &host_saved_bind_token);
			host_add_depth--;
			return rc;
		}
		host_add_depth--;
		return 0;
	}
	if (host_bind_mode == HOST_BIND_STALE_TOKEN) {
		host_stale_retry_result = vmbus_device_bind_retry(
			dev, &host_saved_bind_token);
		host_add_depth--;
		return 0;
	}
	if (host_bind_mode == HOST_BIND_PERMANENT) {
		host_add_depth--;
		return -ENOSPC;
	}
	if (host_bind_mode == HOST_BIND_TRANSIENT) {
		host_pump_hook = host_auto_control_pump;
		rc = vmbus_channel_open(dev, 2, 2, NULL, 0);
		host_pump_hook = NULL;
		host_add_depth--;
		return rc;
	}
	if (host_bind_mode == HOST_BIND_PARTIAL) {
		host_pump_hook = host_auto_control_pump;
		rc = vmbus_channel_open(dev, 2, 2, NULL, 0);
		host_pump_hook = NULL;
		host_add_depth--;
		return rc ? rc : -EINVAL;
	}
	if (host_bind_mode == HOST_BIND_TIMEOUT) {
		host_pump_hook = host_no_response_pump;
		rc = vmbus_channel_open(dev, 2, 2, NULL, 0);
		host_pump_hook = NULL;
		host_add_depth--;
		return rc;
	}
	host_add_depth--;
	return 0;
}

static void host_remove_device(struct vmbus_device *dev __unused)
{
	host_remove_count++;
	if (host_remove_hook)
		host_remove_hook(host_remove_hook_arg);
	if (host_add_active)
		host_remove_during_add = 1;
	if (host_bind_mode == HOST_BIND_REMOVE_PUMP &&
	    host_remove_offer_channel) {
		struct vmbus_decoded_offer offer;

		host_remove_active = 1;
		host_make_offer(&offer, host_remove_offer_channel);
		host_remove_offer_channel = 0;
		(void)add_offer(&offer);
		process_bind_work();
		host_remove_active = 0;
	}
}

static void
host_offer_removed(const struct vmbus_offer_identity *offer)
{
	host_offer_removed_count++;
	host_last_removed_offer = *offer;
}

static const struct vmbus_device_id host_ids[] = {
	{ .class_id = {
		.bytes = {
			0xba, 0x61, 0x63, 0xd9, 0x04, 0xa1, 0x4d, 0x29,
			0xb6, 0x05, 0x72, 0xe2, 0xff, 0xb1, 0xdc, 0x7f,
		},
	} },
	{ .class_id = { .bytes = { 0 } } },
};

static struct vmbus_driver host_driver = {
	.name = "host-vmbus",
	.device_ids = host_ids,
	.add_dev = host_add_device,
	.remove_dev = host_remove_device,
	.offer_removed = host_offer_removed,
};

static void host_reset_state(void)
{
	unsigned int i;

	clearing_devices = 1;
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		host_zero(&devices[i], sizeof(devices[i]));
		host_zero(&device_bindings[i], sizeof(device_bindings[i]));
	}
	clearing_devices = 0;
	host_zero(relids, sizeof(relids));
	driver_count = 1;
	drivers[0] = &host_driver;
	device_count = 0;
	relid_sequence = 0;
	device_generation = 1;
	channel_resource_epoch = 1;
	bind_work_pending = 0;
	connection_failed = 0;
	connection_quiesce_epoch = 1;
	next_connection_generation = 1;
	live_connection_generation = 0;
	connection_target_held = 0;
	connection_teardown_failed = 0;
	connection_teardown_error = 0;
	host_pump_hook = NULL;
	host_last_tx_len = 0;
	host_transmit_error = 0;
	host_transmit_backpressure_type = 0;
	host_transmit_backpressure = 0;
	host_transmit_attempts = 0;
	host_unload_response_mode = HOST_UNLOAD_NONE;
	host_unload_posts = 0;
	host_unload_injections = 0;
	host_unload_injected_inactive = 0;
	host_remove_hook = NULL;
	host_remove_hook_arg = NULL;
	host_unload_post_hook = NULL;
	host_unload_post_hook_arg = NULL;
	__atomic_store_n(&host_connection_fail_calls, 0, __ATOMIC_RELAXED);
	host_transmit_fail_after = -1;
	host_gpadl_status = 0;
	host_gpadl_channel = 0;
	host_gpadl_id = 0;
	host_gpadl_body_posts = 0;
	host_gpadl_teardown_posts = 0;
	host_add_a = 0;
	host_add_b = 0;
	host_remove_count = 0;
	host_offer_removed_count = 0;
	host_zero(&host_last_removed_offer,
		  sizeof(host_last_removed_offer));
	host_add_active = 0;
	host_remove_during_add = 0;
	host_add_depth = 0;
	host_max_add_depth = 0;
	host_cascade_remaining = 0;
	host_cascade_channel = 0;
	host_remove_offer_channel = 0;
	host_remove_active = 0;
	host_add_during_remove = 0;
	host_stale_retry_result = 0;
	host_zero(&host_saved_bind_token,
		  sizeof(host_saved_bind_token));
	bind_work_running = 0;
	bind_attempt_active = 0;
	bind_attempt_owner = NULL;
	bind_attempt_binding = NULL;
	ukarch_spin_init(&deferred_release_lock);
	ukarch_spin_init(&bind_lock);
	ukarch_spin_init(&rx_queue_lock);
	ukarch_spin_init(&worker_lock);
	vmbus_channel_reset_all();
}

struct host_irq_producer {
	unsigned int base;
	int events;
};

static void *host_irq_producer(void *arg)
{
	struct host_irq_producer *producer = arg;
	unsigned int i;

	for (i = 0; i < 4; i++) {
		if (producer->events)
			hyperv_vmbus_event(producer->base + i);
		else {
			struct hyperv_message message = { 0 };

			message.message_type = VMBUS_HV_MESSAGE_TYPE;
			message.payload_size = 8;
			message.payload[0] = (__u8)(producer->base + i);
			hyperv_vmbus_message(&message);
		}
	}
	return NULL;
}

static int host_test_concurrent_irqs(void)
{
	struct host_irq_producer producers[2] = {
		{ .base = 1, .events = 0 },
		{ .base = 5, .events = 0 },
	};
	struct vmbus_rx_entry entry;
	pthread_t threads[2];
	unsigned int seen = 0;
	unsigned int i;

	host_reset_state();
	__atomic_store_n(&rx_active, 1, __ATOMIC_RELEASE);
	worker = (struct uk_thread *)(uintptr_t)1;
	worker_stop = 0;
	host_wake_isr_count = 0;
	host_cpu_index = 1;
	{
		struct hyperv_message message = { 0 };

		message.message_type = VMBUS_HV_MESSAGE_TYPE;
		message.payload_size = 8;
		message.payload[0] = 12;
		hyperv_vmbus_message(&message);
	}
	if (host_wake_isr_count || !dequeue_message(&entry))
		return 89;
	hyperv_vmbus_event_word(64, 1);
	if (host_wake_isr_count ||
	    __atomic_exchange_n(&event_pending[1], 0,
				 __ATOMIC_ACQ_REL) != 1)
		return 90;
	host_cpu_index = 0;
	hyperv_vmbus_event_word(64, 1);
	if (host_wake_isr_count != 1)
		return 91;
	(void)__atomic_exchange_n(&event_pending[1], 0, __ATOMIC_ACQ_REL);
	{
		static const unsigned int lengths[] = {
			8, 196, HYPERV_MESSAGE_PAYLOAD_SIZE
		};
		struct hyperv_message message = { 0 };
		unsigned int j;

		message.message_type = VMBUS_HV_MESSAGE_TYPE;
		for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
			message.payload_size = lengths[i];
			for (j = 0; j < lengths[i]; j++)
				message.payload[j] = (__u8)(j ^ lengths[i]);
			hyperv_vmbus_message(&message);
			if (!dequeue_message(&entry) ||
			    entry.len != lengths[i] ||
			    entry.generation != vmbus_protocol_generation() ||
			    memcmp(entry.data, message.payload, lengths[i]))
				return 93;
		}
		if (host_wake_isr_count != 4 || rx_state.lost)
			return 94;
	}
	for (i = 0; i < 2; i++)
		if (pthread_create(&threads[i], NULL, host_irq_producer,
				   &producers[i]))
			return 90;
	for (i = 0; i < 2; i++)
		pthread_join(threads[i], NULL);
	while (dequeue_message(&entry))
		seen |= 1U << entry.data[0];
	if (seen != 0x1feU || rx_state.lost)
		return 91;
	{
		struct hyperv_message message = {
			.message_type = VMBUS_HV_MESSAGE_TYPE,
			.payload_size = 8,
		};
		unsigned long flags;

		rx_dropped = 0;
		for (i = 0; i <= CONFIG_LIBVMBUS_RX_QUEUE; i++) {
			message.payload[0] = (__u8)(i + 1);
			hyperv_vmbus_message(&message);
		}
		if (!rx_state.lost || rx_dropped != 1 ||
		    process_messages() != -EOVERFLOW)
			return 97;
		hyperv_vmbus_message(&message);
		if (rx_dropped != 1)
			return 98;
		drain_queues();
		ukplat_spin_lock_irqsave(&rx_queue_lock, flags);
		vmbus_queue_recover(&rx_state);
		ukplat_spin_unlock_irqrestore(&rx_queue_lock, flags);
		message.payload[0] = 42;
		hyperv_vmbus_message(&message);
		if (rx_state.lost || !dequeue_message(&entry) ||
		    entry.data[0] != 42 || dequeue_message(&entry))
			return 99;
	}

	producers[0].events = 1;
	producers[1].events = 1;
	seen = 0;
	for (i = 0; i < 2; i++)
		if (pthread_create(&threads[i], NULL, host_irq_producer,
				   &producers[i]))
			return 92;
	for (i = 0; i < 2; i++)
		pthread_join(threads[i], NULL);
	{
		__u64 pending = __atomic_exchange_n(&event_pending[0], 0,
						    __ATOMIC_ACQ_REL);

		while (pending) {
			unsigned int bit = __builtin_ctzll(pending);

			seen |= 1U << bit;
			pending &= pending - 1;
		}
	}
	if (seen != 0x1feU)
		return 93;
	for (i = 0; i < 10000; i++)
		hyperv_vmbus_event_word(64, 1);
	if (connection_failed ||
	    __atomic_exchange_n(&event_pending[1], 0,
				 __ATOMIC_ACQ_REL) != 1)
		return 94;
	hyperv_vmbus_event_word(VMBUS_EVENT_LIMIT, 1);
	if (!event_dropped)
		return 95;
	{
		__u32 dropped = event_dropped;

		hyperv_vmbus_event_word(1, 1);
		if (event_dropped != dropped + 1)
			return 96;
	}
	__atomic_store_n(&rx_active, 0, __ATOMIC_RELEASE);
	worker = NULL;
	return 0;
}

static int host_test_nested_bind(void)
{
	struct vmbus_decoded_offer offer;
	unsigned int i;

	host_reset_state();
	host_bind_mode = HOST_BIND_NESTED;
	host_make_offer(&offer, 1);
	host_make_offer(&host_nested_offer, 2);
	for (i = 1; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++)
		device_bindings[i].state = VMBUS_BIND_PERMANENT_FAILED;
	host_pump_hook = host_nested_pump;
	if (add_offer(&offer))
		return 101;
	if (host_add_a != 1 || host_add_b != 1 ||
	    host_remove_count != 1 || host_remove_during_add)
		return 102;
	if (!devices[0].present || devices[0].channel_id != 2 ||
	    devices[0].driver != &host_driver ||
	    device_bindings[0].state != VMBUS_BIND_BOUND ||
	    vmbus_channel_host_pages_used() != 4 ||
	    vmbus_channel_host_record_count() != 1 ||
	    vmbus_channel_host_live_gpadls() != 1 ||
	    connection_failed)
		return 103;
	if (host_last_tx_len < 16)
		return 104;
	host_complete_torndown((__u32)host_last_tx[12] |
		((__u32)host_last_tx[13] << 8) |
		((__u32)host_last_tx[14] << 16) |
		((__u32)host_last_tx[15] << 24));
	if (vmbus_channel_host_pages_used() ||
	    vmbus_channel_host_record_count() ||
	    vmbus_channel_host_live_gpadls())
		return 105;
	return 0;
}

static int host_test_deferred_offer_rescind(void)
{
	struct vmbus_decoded_offer offer;
	unsigned int i;

	host_reset_state();
	host_bind_mode = HOST_BIND_NESTED_RESCIND;
	host_make_offer(&offer, 1);
	host_make_offer(&host_nested_offer, 10);
	for (i = 1; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++)
		device_bindings[i].state = VMBUS_BIND_PERMANENT_FAILED;
	host_pump_hook = host_nested_rescind_pump;
	if (add_offer(&offer))
		return 106;
	if (devices[0].present ||
	    device_bindings[0].pending_offer_valid ||
	    vmbus_relid_find(relids, VMBUS_RELID_CAPACITY, 10) ||
	    host_add_b)
		return 107;
	return 0;
}

static int host_test_bounded_cascade(void)
{
	struct vmbus_decoded_offer offer;
	unsigned int guard = 0;

	host_reset_state();
	host_bind_mode = HOST_BIND_CASCADE;
	host_cascade_remaining = 1000;
	host_make_offer(&offer, 20);
	if (add_offer(&offer))
		return 106;
	if (!bind_work_pending || host_max_add_depth != 1)
		return 107;
	while (__atomic_load_n(&bind_work_pending, __ATOMIC_ACQUIRE) &&
	       guard++ < 2000)
		process_bind_work();
	if (guard >= 2000 || host_add_b != 1001 ||
	    host_remove_count != 1000 || host_remove_during_add ||
	    host_max_add_depth != 1 || !devices[0].present ||
	    devices[0].channel_id != 1020 ||
	    device_bindings[0].state != VMBUS_BIND_BOUND ||
	    device_count != 1)
		return 108;
	return 0;
}

static int host_test_remove_pump_defers_bind(void)
{
	struct vmbus_decoded_offer offer;
	unsigned int i;

	host_reset_state();
	host_bind_mode = HOST_BIND_REMOVE_PUMP;
	for (i = 1; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++)
		device_bindings[i].state = VMBUS_BIND_PERMANENT_FAILED;
	host_make_offer(&offer, 30);
	if (add_offer(&offer) || host_add_b != 1)
		return 109;
	host_remove_offer_channel = 31;
	if (rescind_offer(30) || host_add_during_remove)
		return 110;
	process_bind_work();
	if (host_add_b != 2 || !devices[0].present ||
	    devices[0].channel_id != 31 ||
	    device_bindings[0].state != VMBUS_BIND_BOUND)
		return 111;
	return 0;
}

static int host_test_bind_retries(void)
{
	struct vmbus_decoded_offer offer;
	struct vmbus_device fillers[CONFIG_LIBVMBUS_MAX_DEVICES];
	struct vmbus_channel *channels_used[CONFIG_LIBVMBUS_MAX_DEVICES];
	unsigned int i;

	host_reset_state();
	host_bind_mode = HOST_BIND_PERMANENT;
	host_make_offer(&offer, 3);
	if (add_offer(&offer) || host_add_b != 1)
		return 111;
	if (vmbus_device_is_bound(&devices[0]))
		return 112;
	vmbus_control_channel_resource_released();
	process_bind_work();
	if (host_add_b != 1 ||
	    device_bindings[0].state != VMBUS_BIND_PERMANENT_FAILED ||
	    host_remove_count || host_offer_removed_count)
		return 112;
	if (rescind_offer(3) || host_offer_removed_count != 1 ||
	    host_last_removed_offer.channel_id != 3)
		return 112;

	host_reset_state();
	host_bind_mode = HOST_BIND_TRANSIENT;
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		host_zero(&fillers[i], sizeof(fillers[i]));
		fillers[i].channel_id = 100 + i;
		fillers[i].connection_id = 200 + i;
		fillers[i].present = 1;
		channels_used[i] =
			vmbus_channel_host_allocate_slot(&fillers[i]);
		if (!channels_used[i])
			return 113;
	}
	host_make_offer(&offer, 4);
	if (add_offer(&offer) || host_add_b != 1)
		return 114;
	if (vmbus_device_is_bound(&devices[0]))
		return 115;
	process_bind_work();
	if (host_add_b != 1)
		return 115;
	if (vmbus_channel_rescind(fillers[0].channel_id) != -EINPROGRESS)
		return 116;
	process_bind_work();
	if (host_add_b != 2 ||
	    device_bindings[0].state != VMBUS_BIND_BOUND ||
	    !vmbus_device_is_bound(&devices[0]))
		return 117;
	host_pump_hook = host_auto_control_pump;
	if (vmbus_channel_close(devices[0].channel))
		return 118;
	host_pump_hook = NULL;
	for (i = 1; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++)
		(void)vmbus_channel_rescind(fillers[i].channel_id);
	return 0;
}

static int host_test_late_driver(void)
{
	struct vmbus_decoded_offer offer;

	host_reset_state();
	driver_count = 0;
	host_bind_mode = HOST_BIND_NESTED;
	host_make_offer(&offer, 8);
	if (add_offer(&offer) || host_add_b || bind_work_pending)
		return 116;
	if (_vmbus_register_driver(&host_driver) || host_add_b != 1 ||
	    device_bindings[0].state != VMBUS_BIND_BOUND)
		return 117;

	host_reset_state();
	host_bind_mode = HOST_BIND_EXPLICIT_RETRY;
	host_make_offer(&offer, 5);
	if (add_offer(&offer) || host_add_b != 1 ||
	    device_bindings[0].state != VMBUS_BIND_TRANSIENT_WAIT ||
	    bind_work_pending)
		return 118;
	process_bind_work();
	if (host_add_b != 1)
		return 119;
	vmbus_device_bind_ready();
	process_bind_work();
	if (host_add_b != 2 ||
	    device_bindings[0].state != VMBUS_BIND_BOUND)
		return 120;
	return 0;
}

static int host_test_bind_epoch_ordering(void)
{
	struct vmbus_decoded_offer offer;
	__u64 old_generation;

	host_reset_state();
	host_bind_mode = HOST_BIND_EPOCH_RACE;
	host_make_offer(&offer, 51);
	if (add_offer(&offer) || host_add_b != 2 ||
	    device_bindings[0].state != VMBUS_BIND_BOUND ||
	    host_saved_bind_token.resource_epoch != 1 ||
	    channel_resource_epoch != 2)
		return 121;
	process_bind_work();
	if (host_add_b != 2 || bind_work_pending)
		return 122;

	old_generation = host_saved_bind_token.device_generation;
	if (rescind_offer(51))
		return 123;
	host_bind_mode = HOST_BIND_STALE_TOKEN;
	host_make_offer(&offer, 52);
	if (add_offer(&offer) || host_stale_retry_result != -ESTALE ||
	    device_bindings[0].state != VMBUS_BIND_BOUND ||
	    device_bindings[0].generation == old_generation)
		return 124;
	process_bind_work();
	if (host_add_b != 3)
		return 125;

	channel_resource_epoch = UINT64_MAX;
	bind_work_pending = 0;
	vmbus_device_bind_ready();
	if (channel_resource_epoch != UINT64_MAX || bind_work_pending)
		return 126;
	return 0;
}

static int host_test_partial_add_cleanup(void)
{
	struct vmbus_decoded_offer offer;
	__u64 first_generation;

	host_reset_state();
	host_bind_mode = HOST_BIND_PARTIAL;
	host_make_offer(&offer, 5);
	if (add_offer(&offer))
		return 121;
	if (host_add_b != 1 || host_remove_count != 1 ||
	    host_offer_removed_count ||
	    devices[0].channel ||
	    device_bindings[0].state != VMBUS_BIND_PERMANENT_FAILED)
		return 122;
	first_generation = device_bindings[0].generation;
	if (rescind_offer(5) || host_offer_removed_count != 1 ||
	    host_last_removed_offer.channel_id != 5 ||
	    host_last_removed_offer.generation != first_generation ||
	    memcmp(host_last_removed_offer.instance_id.bytes,
		   offer.instance_id, VMBUS_GUID_SIZE))
		return 123;
	if (rescind_offer(5) || host_offer_removed_count != 1)
		return 124;
	if (add_offer(&offer) ||
	    device_bindings[0].generation == first_generation ||
	    host_offer_removed_count != 1)
		return 125;
	if (rescind_offer(5) || host_offer_removed_count != 2 ||
	    host_last_removed_offer.generation == first_generation)
		return 126;

	host_reset_state();
	host_bind_mode = HOST_BIND_NESTED;
	host_make_offer(&offer, 6);
	if (add_offer(&offer) ||
	    device_bindings[0].state != VMBUS_BIND_BOUND)
		return 127;
	clear_devices();
	if (host_remove_count != 1 || host_offer_removed_count != 1 ||
	    host_last_removed_offer.channel_id != 6 || device_count)
		return 128;
	clear_devices();
	if (host_remove_count != 1 || host_offer_removed_count != 1)
		return 129;
	return 0;
}

static int host_test_open_timeout_cleanup(void)
{
	struct vmbus_device raw = {
		.channel_id = 6,
		.connection_id = 106,
		.present = 1,
	};
	__u32 old_gpadl;
	int rc;

	host_reset_state();
	host_pump_hook = host_no_response_pump;
	rc = vmbus_channel_open(&raw, 2, 2, NULL, 0);
	host_pump_hook = NULL;
	if (rc != -ETIMEDOUT || raw.channel ||
	    vmbus_channel_host_pages_used() != 4 ||
	    vmbus_channel_host_record_count() != 1 ||
	    vmbus_channel_host_live_gpadls() != 1 ||
	    !connection_failed || host_last_tx_len < 16)
		return 131;
	old_gpadl = (__u32)host_last_tx[12] |
		((__u32)host_last_tx[13] << 8) |
		((__u32)host_last_tx[14] << 16) |
		((__u32)host_last_tx[15] << 24);
	host_transmit_error = 0;
	host_pump_hook = host_auto_control_pump;
	rc = vmbus_channel_open(&raw, 2, 2, NULL, 0);
	host_pump_hook = NULL;
	if (rc || !raw.channel ||
	    vmbus_channel_host_pages_used() != 8 ||
	    vmbus_channel_host_record_count() != 2 ||
	    vmbus_channel_host_live_gpadls() != 2)
		return 132;
	host_pump_hook = host_auto_control_pump;
	rc = vmbus_channel_close(raw.channel);
	host_pump_hook = NULL;
	if (rc || raw.channel ||
	    vmbus_channel_host_pages_used() != 4 ||
	    vmbus_channel_host_record_count() != 1 ||
	    vmbus_channel_host_live_gpadls() != 1)
		return 133;
	host_complete_torndown(old_gpadl);
	if (vmbus_channel_host_pages_used() ||
	    vmbus_channel_host_record_count() ||
	    vmbus_channel_host_live_gpadls())
		return 134;
	vmbus_channel_reset_all();
	if (vmbus_channel_host_pages_used() ||
	    vmbus_channel_host_record_count() ||
	    vmbus_channel_host_live_gpadls())
		return 135;
	return 0;
}

static int host_test_open_teardown_post_failure(void)
{
	struct vmbus_device raw = {
		.channel_id = 11,
		.connection_id = 111,
		.present = 1,
	};
	int rc;

	host_reset_state();
	host_pump_hook = host_fail_after_create_pump;
	rc = vmbus_channel_open(&raw, 2, 2, NULL, 0);
	host_pump_hook = NULL;
	host_transmit_error = 0;
	if (rc != -EIO || raw.channel ||
	    vmbus_channel_host_pages_used() != 4 ||
	    vmbus_channel_host_record_count() != 1 ||
	    vmbus_channel_host_live_gpadls() != 1 ||
	    !connection_failed)
		return 136;
	vmbus_channel_reset_all();
	if (vmbus_channel_host_pages_used() ||
	    vmbus_channel_host_record_count() ||
	    vmbus_channel_host_live_gpadls())
		return 137;
	return 0;
}

static int host_test_deferred_rescind(void)
{
	struct vmbus_decoded_offer offer;
	struct vmbus_channel *channel;

	host_reset_state();
	host_bind_mode = HOST_BIND_NESTED;
	host_make_offer(&offer, 7);
	if (add_offer(&offer) || !devices[0].present)
		return 141;
	channel = vmbus_channel_host_allocate_open(&devices[0]);
	if (!channel || vmbus_channel_host_pin(channel))
		return 142;
	if (rescind_offer(7) || connection_failed ||
	    devices[0].present ||
	    !vmbus_relid_find(relids, VMBUS_RELID_CAPACITY, 7))
		return 143;
	vmbus_channel_host_unpin(channel);
	if (!vmbus_channel_host_is_free(channel) || connection_failed ||
	    vmbus_relid_find(relids, VMBUS_RELID_CAPACITY, 7))
		return 144;
	return 0;
}

static int host_test_same_relid_reoffer(void)
{
	struct vmbus_decoded_offer offer;
	struct vmbus_channel *channel;
	struct vmbus_relid_lifecycle *lifecycle;

	host_reset_state();
	host_bind_mode = HOST_BIND_NESTED;
	host_make_offer(&offer, 9);
	if (add_offer(&offer))
		return 151;
	channel = vmbus_channel_host_allocate_open(&devices[0]);
	if (!channel || vmbus_channel_host_pin(channel))
		return 152;
	lifecycle = vmbus_relid_find(relids, VMBUS_RELID_CAPACITY, 9);
	if (!lifecycle)
		return 153;
	lifecycle->state = VMBUS_RELID_RELEASED;
	if (rescind_offer(9) || connection_failed)
		return 154;
	offer.instance_id[1] = 1;
	if (add_offer(&offer) || !devices[0].present ||
	    devices[0].channel_id != 9)
		return 155;
	vmbus_channel_host_unpin(channel);
	lifecycle = vmbus_relid_find(relids, VMBUS_RELID_CAPACITY, 9);
	if (!lifecycle || lifecycle->state != VMBUS_RELID_ACTIVE ||
	    devices[0].driver != &host_driver || connection_failed)
		return 156;
	return 0;
}

static int host_test_protocol_backpressure(void)
{
	struct vmbus_action action;
	unsigned int attempts;
	int rc;

	host_reset_state();
	host_zero(&action, sizeof(action));
	action.kind = VMBUS_ACTION_TRANSMIT;
	action.generation = vmbus_protocol_generation();
	action.connection_id = 4;
	action.tx_len = 12;
	host_write32(action.tx, 14);
	host_transmit_backpressure_type = 14;
	host_transmit_backpressure = 3;
	rc = handle_action(&action);
	attempts = host_transmit_attempts;
	if (rc || attempts != 4)
		return 157;

	host_transmit_attempts = 0;
	host_transmit_backpressure = 10000;
	rc = handle_action(&action);
	attempts = host_transmit_attempts;
	host_transmit_backpressure_type = 0;
	host_transmit_backpressure = 0;
	host_transmit_attempts = 0;
	if (rc != -ETIMEDOUT || attempts < 4 || attempts >= 10000)
		return 158;
	return 0;
}

int vmbus_bus_host_production_test(void)
{
	int rc;

	rc = host_test_protocol_backpressure();
	if (rc)
		return rc;
	rc = host_test_concurrent_irqs();
	if (rc)
		return rc;
	rc = host_test_nested_bind();
	if (rc)
		return rc;
	rc = host_test_deferred_offer_rescind();
	if (rc)
		return rc;
	rc = host_test_bounded_cascade();
	if (rc)
		return rc;
	rc = host_test_remove_pump_defers_bind();
	if (rc)
		return rc;
	rc = host_test_bind_retries();
	if (rc)
		return rc;
	rc = host_test_late_driver();
	if (rc)
		return rc;
	rc = host_test_bind_epoch_ordering();
	if (rc)
		return rc;
	rc = host_test_partial_add_cleanup();
	if (rc)
		return rc;
	rc = host_test_open_timeout_cleanup();
	if (rc)
		return rc;
	rc = host_test_open_teardown_post_failure();
	if (rc)
		return rc;
	rc = host_test_deferred_rescind();
	if (rc)
		return rc;
	return host_test_same_relid_reoffer();
}

#ifdef VMBUS_REAL_PROTOCOL_TEST
struct host_event_continuation {
	__u32 channel_id;
	unsigned int calls;
};

static void host_continue_event(struct vmbus_channel *channel __unused,
				void *arg)
{
	struct host_event_continuation *continuation = arg;

	continuation->calls++;
	if (continuation->calls < 3)
		vmbus_channel_schedule_event(continuation->channel_id);
}

int vmbus_bus_host_software_event_test(void)
{
	const __u32 versions[] = {
		VMBUS_EVENT_VERSION_WIN8, (1U << 16) | 1U, 13U
	};
	struct vmbus_start_config config = {
		.timeout_ticks = 100,
		.interrupt_page_gpa = 0x1000,
		.parent_to_child_monitor_gpa = 0x2000,
		.child_to_parent_monitor_gpa = 0x3000,
	};
	unsigned int i;

	for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
		struct vmbus_action action;
		struct vmbus_device device = {
			.channel_id = 97, .connection_id = 197, .present = 1
		};
		struct host_event_continuation continuation = {
			.channel_id = device.channel_id
		};
		struct vmbus_channel *channel;
		__u8 response[16] = { 15 };
		unsigned int attempt;
		__u32 dropped;

		host_reset_state();
		vmbus_protocol_reset();
		drain_queues();
		vmbus_protocol_start(0, &config, &action);
		for (attempt = 0; attempt < 16; attempt++) {
			if (action.kind != VMBUS_ACTION_TRANSMIT ||
			    action.tx_len < 12)
				return 401;
			response[8] = host_read32(action.tx + 8) == versions[i];
			vmbus_protocol_receive(response, sizeof(response),
						vmbus_protocol_generation(), 1,
						&action);
			if (response[8])
				break;
		}
		if (vmbus_protocol_version() != versions[i] ||
		    vmbus_protocol_state() != VMBUS_STATE_WAIT_OFFERS)
			return 402;
		__atomic_store_n(&rx_active, 1, __ATOMIC_RELEASE);
		worker = (struct uk_thread *)(uintptr_t)1;
		worker_stop = 0;
		host_cpu_index = 0;
		host_wake_isr_count = 0;
		channel = vmbus_channel_host_allocate_open(&device);
		if (!channel)
			return 403;
		vmbus_channel_set_callback(channel, host_continue_event,
					   &continuation);
		if (versions[i] < VMBUS_EVENT_VERSION_WIN8) {
			dropped = event_dropped;
			hyperv_vmbus_event(device.channel_id);
			if (event_dropped != dropped + 1 || event_pending[1])
				return 404;
		}
		vmbus_channel_schedule_event(device.channel_id);
		vmbus_channel_schedule_event(device.channel_id);
		if (continuation.calls || !host_wake_isr_count)
			return 405;
		for (attempt = 1; attempt <= 3; attempt++) {
			report_deferred_diagnostics();
			if (continuation.calls != attempt)
				return 406;
		}
		report_deferred_diagnostics();
		if (continuation.calls != 3 || event_pending[1])
			return 407;
		dropped = event_dropped;
		vmbus_channel_schedule_event(0);
		vmbus_channel_schedule_event(VMBUS_EVENT_LIMIT);
		if (event_dropped != dropped + 2 || event_pending[0])
			return 408;
		__atomic_store_n(&rx_active, 0, __ATOMIC_RELEASE);
		vmbus_channel_schedule_event(device.channel_id);
		if (event_pending[1])
			return 409;
		worker = NULL;
		vmbus_channel_reset_all();
	}
	vmbus_protocol_reset();
	return 0;
}
#endif

static int host_test_connection_start(void)
{
	struct vmbus_start_config config = {
		.target_vp = 0,
		.timeout_ticks = 30000,
		.interrupt_page_gpa = 0x1000,
		.parent_to_child_monitor_gpa = 0x2000,
		.child_to_parent_monitor_gpa = 0x3000,
	};
	struct vmbus_action action;
	int rc;

	vmbus_protocol_reset();
	drain_queues();
	vmbus_queue_recover(&rx_state);
	__atomic_store_n(&rx_active, 1, __ATOMIC_RELEASE);
	vmbus_protocol_start(hyperv_reference_time(), &config, &action);
	rc = handle_action(&action);
	if (rc)
		return rc;
	return connection_generation_begin();
}

int vmbus_bus_host_quiesce_epoch_test(void)
{
	__u64 epoch;
	unsigned int posts;
	int rc;

	host_reset_state();
	epoch = vmbus_connection_quiesce_epoch();
	if (disconnect_locked() || vmbus_connection_quiesce_epoch() != epoch ||
	    host_unload_posts)
		return 301;

	if (host_test_connection_start())
		return 302;
	__atomic_store_n(&rx_active, 0, __ATOMIC_RELEASE);
	host_unload_response_mode = HOST_UNLOAD_MATCH;
	rc = disconnect_locked();
	if (rc || vmbus_connection_quiesce_epoch() != epoch + 1 ||
	    live_connection_generation || host_unload_posts != 1 ||
	    host_unload_injections != 1 || !host_unload_injected_inactive)
		return 303;
	posts = host_unload_posts;
	if (disconnect_locked() ||
	    vmbus_connection_quiesce_epoch() != epoch + 1 ||
	    host_unload_posts != posts)
		return 304;

	epoch = vmbus_connection_quiesce_epoch();
	if (host_test_connection_start())
		return 305;
	__atomic_store_n(&rx_active, 0, __ATOMIC_RELEASE);
	host_unload_response_mode = HOST_UNLOAD_DUPLICATE;
	rc = disconnect_locked();
	if (rc || vmbus_connection_quiesce_epoch() != epoch + 1 ||
	    host_unload_injections != 3 || host_unload_posts != posts + 1)
		return 306;

	epoch = vmbus_connection_quiesce_epoch();
	if (host_test_connection_start())
		return 307;
	host_queue_unload_response(0);
	if (process_messages() ||
	    vmbus_protocol_state() == VMBUS_STATE_DISCONNECTED ||
	    vmbus_connection_quiesce_epoch() != epoch)
		return 308;
	__atomic_store_n(&rx_active, 0, __ATOMIC_RELEASE);
	rc = disconnect_locked();
	if (rc != -ETIMEDOUT ||
	    vmbus_connection_quiesce_epoch() != epoch ||
	    !live_connection_generation || !connection_teardown_failed)
		return 309;
	posts = host_unload_posts;
	if (disconnect_locked() != -ETIMEDOUT ||
	    vmbus_connection_quiesce_epoch() != epoch ||
	    host_unload_posts != posts)
		return 310;
	if (connection_generation_quiesce())
		return 311;

	epoch = vmbus_connection_quiesce_epoch();
	if (host_test_connection_start())
		return 312;
	__atomic_store_n(&rx_active, 0, __ATOMIC_RELEASE);
	host_unload_response_mode = HOST_UNLOAD_WRONG_GENERATION;
	rc = disconnect_locked();
	if (rc != -ETIMEDOUT ||
	    vmbus_connection_quiesce_epoch() != epoch ||
	    !connection_teardown_failed)
		return 313;
	if (connection_generation_quiesce())
		return 314;

	epoch = vmbus_connection_quiesce_epoch();
	if (host_test_connection_start())
		return 315;
	vmbus_protocol_reset();
	posts = host_unload_posts;
	if (disconnect_locked() != -EIO ||
	    vmbus_connection_quiesce_epoch() != epoch ||
	    host_unload_posts != posts || !connection_teardown_failed)
		return 316;
	if (disconnect_locked() != -EIO ||
	    vmbus_connection_quiesce_epoch() != epoch ||
	    host_unload_posts != posts)
		return 317;
	if (connection_generation_quiesce())
		return 318;

	{
		struct vmbus_device device = {
			.channel_id = 90,
			.connection_id = 190,
			.present = 1,
		};
		struct vmbus_channel *channel;
		int teardown_error;

		epoch = vmbus_connection_quiesce_epoch();
		if (host_test_connection_start())
			return 327;
		channel = vmbus_channel_host_allocate_open(&device);
		if (!channel ||
		    vmbus_channel_host_attach_gpadl(channel, 0x3090))
			return 328;
		host_transmit_error = -EIO;
		__atomic_store_n(&rx_active, 0, __ATOMIC_RELEASE);
		teardown_error = disconnect_locked();
		if (!teardown_error ||
		    vmbus_connection_quiesce_epoch() != epoch ||
		    !live_connection_generation || !connection_teardown_failed ||
		    vmbus_channel_host_pages_used() != 4 ||
		    vmbus_channel_host_record_count() != 1 ||
		    vmbus_channel_host_live_gpadls() != 1)
			return 329;
		posts = host_unload_posts;
		if (disconnect_locked() != teardown_error ||
		    host_unload_posts != posts ||
		    vmbus_channel_host_pages_used() != 4 ||
		    vmbus_channel_host_record_count() != 1)
			return 330;
		host_transmit_error = 0;
		if (connection_generation_quiesce())
			return 331;
		vmbus_channel_reset_all();
		if (vmbus_channel_host_pages_used() ||
		    vmbus_channel_host_record_count() ||
		    vmbus_channel_host_live_gpadls())
			return 332;
	}

	for (unsigned int generation = 0; generation < 32; generation++) {
		struct vmbus_device device = {
			.channel_id = 100 + generation,
			.connection_id = 200 + generation,
			.present = 1,
		};
		struct vmbus_channel *channel;

		epoch = vmbus_connection_quiesce_epoch();
		if (host_test_connection_start())
			return 333;
		channel = vmbus_channel_host_allocate_open(&device);
		if (!channel ||
		    vmbus_channel_host_attach_gpadl(
			    channel, 0x4000 + generation))
			return 334;
		if ((generation & 1U) &&
		    (vmbus_channel_rescind(device.channel_id) != -EINPROGRESS ||
		     vmbus_channel_host_pages_used() != 4 ||
		     vmbus_channel_host_record_count() != 1))
			return 335;
		host_pump_hook = host_auto_control_pump;
		__atomic_store_n(&rx_active, 0, __ATOMIC_RELEASE);
		host_unload_response_mode = HOST_UNLOAD_MATCH;
		rc = disconnect_locked();
		host_pump_hook = NULL;
		if (rc || vmbus_connection_quiesce_epoch() != epoch + 1 ||
		    live_connection_generation ||
		    vmbus_channel_host_pages_used() ||
		    vmbus_channel_host_record_count() ||
		    vmbus_channel_host_live_gpadls())
			return 336;
	}

	live_connection_generation = 0;
	next_connection_generation = UINT64_MAX;
	connection_teardown_failed = 0;
	if (connection_generation_begin() || next_connection_generation ||
	    connection_generation_quiesce() ||
	    connection_generation_begin() != -ENOSPC)
		return 325;

	live_connection_generation = 1;
	connection_teardown_failed = 0;
	connection_quiesce_epoch = UINT64_MAX;
	if (connection_generation_quiesce() != -ENOSPC ||
	    !live_connection_generation ||
	    connection_quiesce_epoch != UINT64_MAX)
		return 326;

	host_reset_state();
	vmbus_channel_reset_all();
	return 0;
}

int vmbus_bus_host_prepare_disconnect(void)
{
	host_reset_state();
	return host_test_connection_start();
}

int vmbus_bus_host_disconnect_remove(
	void (*remove_hook)(void *), void *remove_arg,
	void (*unload_post_hook)(void *), void *unload_arg,
	int acknowledge)
{
	struct vmbus_decoded_offer offer;
	struct vmbus_device_binding *binding = &device_bindings[0];
	int rc;

	if (!live_connection_generation)
		return -ENODEV;
	host_make_offer(&offer, 77);
	copy_offer(&devices[0], &offer);
	binding->generation = device_generation++;
	binding->state = VMBUS_BIND_BOUND;
	devices[0].driver = &host_driver;
	device_count = 1;
	host_remove_hook = remove_hook;
	host_remove_hook_arg = remove_arg;
	host_unload_post_hook = unload_post_hook;
	host_unload_post_hook_arg = unload_arg;
	host_unload_response_mode = acknowledge ?
		HOST_UNLOAD_MATCH : HOST_UNLOAD_NONE;
	__atomic_store_n(&rx_active, 0, __ATOMIC_RELEASE);
	rc = disconnect_locked();
	host_remove_hook = NULL;
	host_remove_hook_arg = NULL;
	host_unload_post_hook = NULL;
	host_unload_post_hook_arg = NULL;
	return rc;
}

int vmbus_bus_host_connection_begin(void)
{
	return connection_generation_begin();
}

int vmbus_bus_host_connection_quiesce(void)
{
	return connection_generation_quiesce();
}

int vmbus_bus_host_connection_live(void)
{
	return live_connection_generation != 0;
}

unsigned int vmbus_bus_host_connection_fail_calls(void)
{
	return __atomic_load_n(&host_connection_fail_calls,
			       __ATOMIC_RELAXED);
}

int vmbus_bus_host_offer_lifetime_setup(struct vmbus_driver *driver)
{
	host_reset_state();
	driver_count = 0;
	return _vmbus_register_driver(driver);
}

int vmbus_bus_host_reject_storage_wire(
	struct vmbus_driver *driver, const struct vmbus_guid *instance_id,
	__u32 channel_id, __u32 connection_id)
{
	struct hyperv_message message = {
		.message_type = VMBUS_HV_MESSAGE_TYPE,
		.payload_size = 196,
	};
	struct vmbus_action action;
	__u8 response[16] = { 15 };
	int rc;

	if (!driver || !instance_id || !channel_id || !connection_id)
		return -EINVAL;
	if (vmbus_bus_host_offer_lifetime_setup(driver))
		return -EIO;
	rc = host_test_connection_start();
	if (rc)
		return rc;
	response[8] = 1;
	host_write32(response + 12, 0x1234);
	vmbus_protocol_receive(
		response, sizeof(response), vmbus_protocol_generation(),
		hyperv_reference_time(), &action);
	if (action.kind != VMBUS_ACTION_TRANSMIT ||
	    handle_action(&action) ||
	    vmbus_protocol_state() != VMBUS_STATE_WAIT_OFFERS)
		return -EIO;

	host_write32(message.payload, 1);
	host_encode_guid(message.payload + 8, &vmbus_storage_guid);
	host_encode_guid(message.payload + 24, instance_id);
	host_write32(message.payload + 184, channel_id);
	message.payload[189] = 2;
	host_write32(message.payload + 192, connection_id);
	hyperv_vmbus_message(&message);
	rc = process_messages();
	if (rc || host_last_tx_len != 12 ||
	    host_read32(host_last_tx) != 13 ||
	    host_read32(host_last_tx + 8) != channel_id ||
	    device_count)
		return -EIO;

	host_zero(&message, sizeof(message));
	message.message_type = VMBUS_HV_MESSAGE_TYPE;
	message.payload_size = 8;
	host_write32(message.payload, 4);
	hyperv_vmbus_message(&message);
	rc = process_messages();
	if (rc || vmbus_protocol_state() != VMBUS_STATE_READY)
		return -EIO;
	return 0;
}

int vmbus_bus_host_offer_storage(
	const struct vmbus_guid *instance_id, __u32 channel_id,
	__u32 connection_id)
{
	struct vmbus_decoded_offer offer;

	if (!instance_id)
		return -EINVAL;
	host_zero(&offer, sizeof(offer));
	memcpy(offer.class_id, vmbus_storage_guid.bytes,
	       sizeof(offer.class_id));
	memcpy(offer.instance_id, instance_id->bytes,
	       sizeof(offer.instance_id));
	offer.channel_id = channel_id;
	offer.connection_id = connection_id;
	return add_offer(&offer);
}

int vmbus_bus_host_fill_nonstorage_offers(__u32 first_channel)
{
	struct vmbus_decoded_offer offer;
	unsigned int i;
	int rc;

	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		host_zero(&offer, sizeof(offer));
		copy_bytes(offer.class_id, vmbus_network_guid.bytes,
			   VMBUS_GUID_SIZE);
		offer.instance_id[0] = (__u8)i;
		offer.instance_id[1] = (__u8)(i >> 8);
		offer.channel_id = first_channel + i;
		offer.connection_id = first_channel + i + 100;
		rc = add_offer(&offer);
		if (rc)
			return rc;
	}
	return 0;
}

int vmbus_bus_host_offer_present(__u32 channel_id)
{
	unsigned int i;

	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++)
		if (devices[i].present &&
		    devices[i].channel_id == channel_id)
			return 1;
	return 0;
}

int vmbus_bus_host_confirm_rescind(__u32 channel_id)
{
	struct vmbus_relid_lifecycle *lifecycle =
		vmbus_relid_find(relids, VMBUS_RELID_CAPACITY, channel_id);
	int rc;

	if (!lifecycle)
		return -ENOENT;
	lifecycle->state = VMBUS_RELID_RELEASED;
	rc = rescind_offer(channel_id);
	if (rc == -ENODEV && !vmbus_bus_host_offer_present(channel_id))
		return 0;
	return rc;
}

__u64 vmbus_bus_host_offer_generation(__u32 channel_id)
{
	unsigned int i;

	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++)
		if (devices[i].present &&
		    devices[i].channel_id == channel_id)
			return device_bindings[i].generation;
	return 0;
}

void vmbus_bus_host_set_transmit_error(int error)
{
	host_transmit_error = error;
}

int vmbus_bus_host_connection_failed(void)
{
	return connection_failed;
}

void vmbus_bus_host_clear_connection_failed(void)
{
	connection_failed = 0;
}

void vmbus_bus_host_auto_pump(int enabled)
{
	host_pump_hook = enabled ? host_auto_control_pump : NULL;
}

void vmbus_bus_host_set_gpadl_status(__u32 status)
{
	host_gpadl_status = status;
}

void vmbus_bus_host_set_transmit_fail_after(int successful_posts)
{
	host_transmit_fail_after = successful_posts;
}

void vmbus_bus_host_set_transmit_backpressure(__u32 control_type,
					      unsigned int attempts)
{
	host_transmit_backpressure_type = control_type;
	host_transmit_backpressure = attempts;
}

unsigned int vmbus_bus_host_transmit_attempts(void)
{
	return host_transmit_attempts;
}

void vmbus_bus_host_reset_gpadl_trace(void)
{
	host_gpadl_channel = 0;
	host_gpadl_id = 0;
	host_gpadl_body_posts = 0;
	host_gpadl_teardown_posts = 0;
	host_transmit_fail_after = -1;
	host_transmit_backpressure_type = 0;
	host_transmit_backpressure = 0;
	host_transmit_attempts = 0;
}

unsigned int vmbus_bus_host_gpadl_body_posts(void)
{
	return host_gpadl_body_posts;
}

unsigned int vmbus_bus_host_gpadl_teardown_posts(void)
{
	return host_gpadl_teardown_posts;
}
#endif
