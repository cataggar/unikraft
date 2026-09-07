/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <hyperv/hyperv.h>
#include <uk/arch/spinlock.h>
#include <uk/bus.h>
#include <uk/config.h>
#include <uk/isr/thread.h>
#include <uk/lcpu.h>
#include <uk/paging.h>
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
static struct vmbus_driver *drivers[CONFIG_LIBVMBUS_MAX_DRIVERS];
static struct vmbus_rx_entry rx_queue[CONFIG_LIBVMBUS_RX_QUEUE];
static __u32 event_queue[CONFIG_LIBVMBUS_RX_QUEUE];
static struct vmbus_relid_lifecycle relids[VMBUS_RELID_CAPACITY];
static __u8 interrupt_page[HYPERV_PAGE_SIZE] __align(HYPERV_PAGE_SIZE);
static __u8 parent_to_child_monitor[HYPERV_PAGE_SIZE]
	__align(HYPERV_PAGE_SIZE);
static __u8 child_to_parent_monitor[HYPERV_PAGE_SIZE]
	__align(HYPERV_PAGE_SIZE);

static unsigned int driver_count;
static unsigned int device_count;
static struct vmbus_queue_state rx_state;
static __u32 event_head;
static __u32 event_tail;
static __u32 rx_dropped;
static __u32 event_dropped;
static __u32 malformed_hv_messages;
static __u64 post_input_gpa;
static __u64 relid_sequence;
static struct uk_thread *worker;
static struct uk_thread *control_owner;
static __spinlock worker_lock;
static int worker_stop;
static int control_busy;
static int initialized;
static int rx_active;
static int connection_failed;

static int vmbus_bus_init(struct uk_alloc *a);
static int vmbus_bus_probe(void);
static void vmbus_worker(void *arg) __noreturn;
static int handle_action(const struct vmbus_action *action);
static int disconnect_locked(void);
static int acquire_control(void);
static void release_control(void);
static void stop_worker_locked(void);

static int guid_equal(const struct vmbus_guid *a,
		      const struct vmbus_guid *b)
{
	unsigned int i;

	for (i = 0; i < VMBUS_GUID_SIZE; i++)
		if (a->bytes[i] != b->bytes[i])
			return 0;
	return 1;
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

	ukplat_spin_lock_irqsave(&worker_lock, flags);
	thread = __atomic_load_n(&worker, __ATOMIC_ACQUIRE);
	if (thread && !__atomic_load_n(&worker_stop, __ATOMIC_ACQUIRE))
		uk_thread_wake_isr(thread);
	ukplat_spin_unlock_irqrestore(&worker_lock, flags);
}

void hyperv_vmbus_message(const struct hyperv_message *message)
{
	__u32 ticket;
	struct vmbus_rx_entry *entry;

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

	if (vmbus_queue_reserve(&rx_state, CONFIG_LIBVMBUS_RX_QUEUE,
				&ticket)) {
		__atomic_add_fetch(&rx_dropped, 1, __ATOMIC_RELAXED);
		signal_worker();
		return;
	}
	entry = &rx_queue[ticket % CONFIG_LIBVMBUS_RX_QUEUE];
	entry->generation = vmbus_protocol_generation();
	entry->len = message->payload_size;
	copy_bytes(entry->data, message->payload, entry->len);
	vmbus_queue_commit(&rx_state, ticket);
	signal_worker();
}

static void enqueue_event(__u32 event, void *arg __unused)
{
	__u32 head;

	if (event >= VMBUS_EVENT_LIMIT) {
		__atomic_add_fetch(&event_dropped, 1, __ATOMIC_RELAXED);
		return;
	}
	head = __atomic_load_n(&event_head, __ATOMIC_RELAXED);
	if (head - __atomic_load_n(&event_tail, __ATOMIC_ACQUIRE) >=
	    CONFIG_LIBVMBUS_RX_QUEUE) {
		__atomic_add_fetch(&event_dropped, 1, __ATOMIC_RELAXED);
		return;
	}
	event_queue[head % CONFIG_LIBVMBUS_RX_QUEUE] = event;
	__atomic_store_n(&event_head, head + 1, __ATOMIC_RELEASE);
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

static int dequeue_message(struct vmbus_rx_entry *entry)
{
	__u32 ticket;

	if (!vmbus_queue_take(&rx_state, &ticket))
		return 0;
	*entry = rx_queue[ticket % CONFIG_LIBVMBUS_RX_QUEUE];
	return 1;
}

static int dequeue_event(__u32 *event)
{
	__u32 tail = __atomic_load_n(&event_tail, __ATOMIC_RELAXED);

	if (tail == __atomic_load_n(&event_head, __ATOMIC_ACQUIRE))
		return 0;
	*event = event_queue[tail % CONFIG_LIBVMBUS_RX_QUEUE];
	__atomic_store_n(&event_tail, tail + 1, __ATOMIC_RELEASE);
	return 1;
}

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

int vmbus_control_transmit(const __u8 *message, size_t length)
{
	int rc;

	if (!length || length > HYPERV_MESSAGE_PAYLOAD_SIZE)
		return -EINVAL;
	rc = vmbus_post_message(vmbus_protocol_connection_id(),
				VMBUS_HV_MESSAGE_TYPE, message,
				length, post_input_gpa,
				(__u8)hyperv_has_post_messages(),
				CONFIG_LIBVMBUS_POST_RETRIES,
				post_hypercall, post_backoff, NULL);
	if (rc) {
		uk_pr_err("VMBus: PostMessage failed (%d)\n", rc);
		return -EIO;
	}
	return 0;
}

static int transmit(const struct vmbus_action *action)
{
	if (action->connection_id != vmbus_protocol_connection_id())
		return vmbus_post_message(action->connection_id,
				VMBUS_HV_MESSAGE_TYPE, action->tx,
				action->tx_len, post_input_gpa,
				(__u8)hyperv_has_post_messages(),
				CONFIG_LIBVMBUS_POST_RETRIES,
				post_hypercall, post_backoff, NULL) ? -EIO : 0;
	return vmbus_control_transmit(action->tx, action->tx_len);
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

static void bind_device(struct vmbus_device *dev)
{
	struct vmbus_driver *driver;
	int rc;

	if (dev->driver)
		return;
	driver = find_driver(&dev->class_id);
	if (!driver)
		return;
	dev->driver = driver;
	rc = driver->add_dev ? driver->add_dev(dev) : 0;
	if (rc) {
		uk_pr_err("VMBus: driver %s rejected channel %u (%d)\n",
			  driver->name, dev->channel_id, rc);
		dev->driver = NULL;
		return;
	}
}

static void retry_unbound_devices(void)
{
	unsigned int i;

	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++)
		if (devices[i].present && !devices[i].driver)
			bind_device(&devices[i]);
}

static void remove_device(struct vmbus_device *dev)
{
	const struct vmbus_driver *driver;

	if (!dev->present)
		return;
	driver = dev->driver;
	dev->driver = NULL;
	dev->present = 0;
	if (device_count)
		device_count--;
	if (driver && driver->remove_dev)
		driver->remove_dev(dev);
}

static void clear_devices(void)
{
	unsigned int i;

	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++)
		remove_device(&devices[i]);
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
	return rc;
}

static void reset_release_records(void)
{
	unsigned int i;

	for (i = 0; i < VMBUS_RELID_CAPACITY; i++) {
		relids[i].channel_id = 0;
		relids[i].state = VMBUS_RELID_FREE;
		relids[i].retained = 0;
		relids[i].sequence = 0;
	}
	relid_sequence = 0;
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
	struct vmbus_device *dev;
	unsigned int i;
	int rc;

	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		dev = &devices[i];
		if (dev->present && dev->channel_id == offer->channel_id) {
			if (!guid_equal_bytes(&dev->class_id, offer->class_id) ||
			    !guid_equal_bytes(&dev->instance_id,
					      offer->instance_id))
				return -EINVAL;
			return 0;
		}
		if (!dev->present && !free_slot)
			free_slot = dev;
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
	device_count++;
	bind_device(free_slot);
	if (!free_slot->driver) {
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
	channel_rc = vmbus_channel_rescind(channel_id);
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++)
		if (devices[i].present &&
		    devices[i].channel_id == channel_id) {
			remove_device(&devices[i]);
			break;
		}
	if (lifecycle->state == VMBUS_RELID_RELEASED) {
		vmbus_relid_forget(relids, VMBUS_RELID_CAPACITY, channel_id);
		return channel_rc;
	}
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
	return 0;
}

static void report_deferred_diagnostics(void)
{
	__u32 count;
	__u32 event;

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
	while (dequeue_event(&event))
		vmbus_channel_event(event), count++;
	if (count)
		uk_pr_debug("VMBus: deferred %u channel event(s); channel rings "
			    "are not implemented\n", count);
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
		__asm__ __volatile__("pause");
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

static int connect_protocol(void)
{
	struct vmbus_start_config config = { 0 };
	struct vmbus_action action;
	__paddr_t gpa;
	int rc;

	if (!hyperv_has_post_messages()) {
		uk_pr_err("VMBus: Hyper-V PostMessages privilege is absent\n");
		return -EACCES;
	}
	clear_devices();
	reset_release_records();
	vmbus_queue_recover(&rx_state);
	__atomic_store_n(&event_tail,
			 __atomic_load_n(&event_head, __ATOMIC_ACQUIRE),
			 __ATOMIC_RELEASE);
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
	config.target_vp = 0;
	config.timeout_ticks =
		(__u64)CONFIG_LIBVMBUS_VERSION_TIMEOUT_MS *
		VMBUS_REFERENCE_TICKS_PER_MS;

	vmbus_protocol_start(hyperv_reference_time(), &config, &action);
	rc = handle_action(&action);
	if (rc)
		return rc;
	return drive_until(VMBUS_STATE_READY, VMBUS_STATE_FAILED);
}

static void drain_queues(void)
{
	vmbus_queue_drain(&rx_state);
	__atomic_store_n(&event_tail,
			 __atomic_load_n(&event_head, __ATOMIC_ACQUIRE),
			 __ATOMIC_RELEASE);
}

static int disconnect_locked(void)
{
	struct vmbus_action action;
	int state = vmbus_protocol_state();
	int rc = 0;

	drain_queues();
	__atomic_store_n(&rx_state.lost, 0, __ATOMIC_RELEASE);
	vmbus_channel_close_all();
	clear_devices();
	if (state != VMBUS_STATE_IDLE && state != VMBUS_STATE_DISCONNECTED) {
		vmbus_protocol_unload(hyperv_reference_time(), &action);
		rc = handle_action(&action);
		if (!rc)
			rc = drive_until(VMBUS_STATE_DISCONNECTED,
					 VMBUS_STATE_FAILED);
	}
	__atomic_store_n(&rx_active, 0, __ATOMIC_RELEASE);
	reset_release_records();
	drain_queues();
	vmbus_protocol_reset();
	vmbus_channel_reset_all();
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
	int rc = 0;

	drain_queues();
	__atomic_store_n(&rx_state.lost, 0, __ATOMIC_RELEASE);
	vmbus_channel_close_all();
	if (state != VMBUS_STATE_IDLE && state != VMBUS_STATE_DISCONNECTED) {
		vmbus_protocol_unload(hyperv_reference_time(), &action);
		rc = handle_action(&action);
		if (!rc)
			rc = drive_until(VMBUS_STATE_DISCONNECTED,
					 VMBUS_STATE_FAILED);
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
	vmbus_queue_recover(&rx_state);
	vmbus_protocol_reset();
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
				retry_unbound_devices();
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
	return process_messages();
}

int vmbus_control_release_relid(__u32 channel_id)
{
	return release_channel(channel_id, 0);
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

void hyperv_vmbus_fini(void)
{
	int control_acquired;

	if (!teardown_enter(&control_acquired)) {
		(void)disconnect_locked();
		if (control_acquired)
			release_control();
	} else
		vmbus_teardown_final_fallback(&teardown_ops, NULL);
	initialized = 0;
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

int _vmbus_register_driver(struct vmbus_driver *driver)
{
	unsigned int i;

	if (!driver || !driver->name || !driver->device_ids)
		return -EINVAL;
	for (i = 0; i < driver_count; i++)
		if (drivers[i] == driver)
			return -EEXIST;
	if (driver_count >= CONFIG_LIBVMBUS_MAX_DRIVERS)
		return -ENOSPC;
	drivers[driver_count++] = driver;
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++)
		if (devices[i].present)
			bind_device(&devices[i]);
	return 0;
}

static int vmbus_bus_init(struct uk_alloc *a __unused)
{
	__paddr_t gpa = uk_paging_virt_to_phys((__vaddr_t)vmbus_post_input());

	ukarch_spin_init(&worker_lock);
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
