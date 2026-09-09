/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <uk/alloc.h>
#include <uk/arch/spinlock.h>
#include <uk/blkdev.h>
#include <uk/blkdev_driver.h>
#include <uk/config.h>
#include <uk/errptr.h>
#include <uk/essentials.h>
#include <uk/lcpu.h>
#include <uk/paging.h>
#include <uk/plat/time.h>
#include <uk/print.h>
#include <uk/sched.h>
#include <uk/storvsc.h>
#include <uk/thread.h>
#include <uk/vmbus.h>

#include "storvsc_core.h"

#define DRIVER_NAME			"hyperv-storvsc"
#define STORVSC_PAGE_SIZE		4096U
#define STORVSC_RX_DESCRIPTOR_SIZE	1024U
#define STORVSC_INQUIRY_SIZE		96U
#define STORVSC_VPD_SIZE		255U
#define STORVSC_CAPACITY16_SIZE		32U
#define STORVSC_MODE_SENSE_SIZE		192U
#define STORVSC_WORKER_SLEEP_NS		1000000ULL
#define STORVSC_DEFERRED_SLEEP_NS	10000000ULL
#define STORVSC_BUSY_RETRY_SLEEP_NS	100000000ULL
#define STORVSC_STOP_WAIT_LIMIT		2000U
#define STORVSC_CLOSE_RETRY_LIMIT	8U
#define STORVSC_BUSY_RETRY_LIMIT	32U
#define STORVSC_BUSY_RETRY_TIMEOUT_NS	2000000000ULL
#define STORVSC_SEND_WAIT_LIMIT		2000U
#define STORVSC_CONTROL_TIMEOUT_NS	\
	((__u64)CONFIG_LIBSTORVSC_CONTROL_TIMEOUT_MS * 1000000ULL)
#define STORVSC_REQUEST_TIMEOUT_NS	\
	((__u64)CONFIG_LIBSTORVSC_REQUEST_TIMEOUT_MS * 1000000ULL)

#ifdef STORVSC_HOST_TEST
#define STORVSC_CPU_RELAX()	__asm__ __volatile__("" ::: "memory")
#else
#define STORVSC_CPU_RELAX()	__asm__ __volatile__("pause")
#endif

struct storvsc_device;
struct storvsc_lun;

enum storvsc_deferred_action {
	STORVSC_DEFER_NONE,
	STORVSC_DEFER_RESET,
	STORVSC_DEFER_FATAL,
	STORVSC_DEFER_REMOVE,
};

struct uk_blkdev_queue {
	struct storvsc_lun *lun;
	__u16 nb_desc;
	__u8 configured;
	__u8 intr_user;
	__u8 intr_active;
};

struct storvsc_request_binding {
	struct uk_blkreq *req;
	__u64 id;
	__u64 pfns[CONFIG_LIBSTORVSC_MAX_TRANSFER_PAGES];
	struct storvsc_lun *lun;
	__u8 synchronous;
};

struct storvsc_lun {
	struct uk_blkdev blkdev;
	struct uk_blkdev_queue queue;
	struct storvsc_device *controller;
	struct storvsc_address address;
	struct storvsc_media media;
	struct storvsc_vpd_id vpd_id;
	__u64 generation;
	__u64 session_cookie;
	__u64 session_topology_generation;
	__u64 session_controller_generation;
	__u64 session_lun_generation;
	__u16 uid;
	__u8 registered;
	__u8 present;
	__u8 started;
	__u8 completion_pending;
	__u8 session_state;
	__u8 session_cdb_size;
};

struct storvsc_device {
	struct vmbus_device *vmbus_device;
	struct vmbus_channel *channel;
	struct storvsc_request_binding
		bindings[CONFIG_LIBSTORVSC_QUEUE_DEPTH];
	__u8 core[STORVSC_CORE_STORAGE_SIZE]
		__attribute__((aligned(STORVSC_CORE_STORAGE_ALIGN)));
	__u8 rx_descriptor[STORVSC_RX_DESCRIPTOR_SIZE];
	__u8 rx_payload[STORVSC_PACKET_MAX];
	__u8 report_luns_data[STORVSC_REPORT_LUNS_DATA_SIZE];
	__u8 inquiry_data[STORVSC_INQUIRY_SIZE];
	__u8 vpd_data[STORVSC_VPD_SIZE];
	__u8 capacity_data[STORVSC_CAPACITY16_SIZE];
	__u8 mode_data[STORVSC_MODE_SENSE_SIZE];
	struct storvsc_address lun_addresses[STORVSC_REPORT_LUNS_MAX];
	struct storvsc_lun luns[CONFIG_LIBSTORVSC_MAX_LUNS];
	struct vmbus_guid instance_id;
	size_t lun_count;
	struct uk_thread *timeout_thread;
	__spinlock lock;
	__spinlock receive_lock;
	__u32 epoch;
	__u64 session_generation;
	__u16 index;
	__u16 interrupt_users;
	__u8 initialized;
	__u8 identity_valid;
	__u8 binding;
	__u8 online;
	__u8 removing;
	__u8 timeout_stop;
	__u8 recovering;
	__u8 reset_done;
	int reset_result;
	int fatal_error;
	__u8 finish_active;
	__u8 notify_active;
	__u16 active_sends;
	struct storvsc_lun *notifying_lun;
	__u8 deferred_action;
	__u8 deferred_running;
	__u8 deferred_wait_vmbus;
	__u8 deferred_close_busy;
	__u8 deferred_close_required;
	__u16 deferred_close_attempts;
	int deferred_error;
	struct vmbus_channel *deferred_channel;
	__u64 deferred_vmbus_epoch;
	__u64 deferred_close_deadline;
};

struct storvsc_unresolved_offer {
	struct vmbus_guid instance_id;
	__u32 channel_id;
	__u64 generation;
	int error;
	__u8 active;
};

static struct storvsc_device storvsc_devices[CONFIG_LIBSTORVSC_MAX_DEVICES];
static struct storvsc_unresolved_offer
	storvsc_unresolved_offers[CONFIG_LIBSTORVSC_MAX_DEVICES];
static __spinlock storvsc_topology_lock = UKARCH_SPINLOCK_INITIALIZER();
static struct storvsc_lun *storvsc_write_lun;
static __u64 storvsc_session_cookie;
static int storvsc_session_cookie_exhausted;
static int storvsc_unresolved_offer_overflow;
static __u64 storvsc_topology_generation =
	UK_STORVSC_TOPOLOGY_PRISTINE_GENERATION;
static int storvsc_topology_generation_exhausted;
static int storvsc_storage_lifetime_observed;
#if defined(CONFIG_LIBSTORVSC_LUN_DISCOVERY) && \
	CONFIG_LIBSTORVSC_LUN_DISCOVERY
#define STORVSC_LUN_DISCOVERY_DEFAULT 1
#else
#define STORVSC_LUN_DISCOVERY_DEFAULT 0
#endif
#ifdef STORVSC_HOST_TEST
static unsigned int storvsc_send_wait_limit = STORVSC_SEND_WAIT_LIMIT;
static unsigned int storvsc_busy_retry_limit = STORVSC_BUSY_RETRY_LIMIT;
static __u64 storvsc_busy_retry_timeout_ns =
	STORVSC_BUSY_RETRY_TIMEOUT_NS;
static int storvsc_lun_discovery_enabled =
	STORVSC_LUN_DISCOVERY_DEFAULT;
#if defined(CONFIG_LIBSTORVSC_GUARDED_IO) && \
	CONFIG_LIBSTORVSC_GUARDED_IO
static int storvsc_guarded_io_enabled = 1;
#else
static int storvsc_guarded_io_enabled;
#endif
#else
#define storvsc_lun_discovery_enabled STORVSC_LUN_DISCOVERY_DEFAULT
#if defined(CONFIG_LIBSTORVSC_GUARDED_IO) && \
	CONFIG_LIBSTORVSC_GUARDED_IO
#define storvsc_guarded_io_enabled 1
#else
#define storvsc_guarded_io_enabled 0
#endif
#endif

enum storvsc_session_state {
	STORVSC_SESSION_NONE,
	STORVSC_SESSION_READ,
	STORVSC_SESSION_WRITE,
};

_Static_assert(CONFIG_LIBSTORVSC_MAX_DEVICES >= 1 &&
	       CONFIG_LIBSTORVSC_MAX_DEVICES <= 8,
	       "StorVSC controller pool is out of range");
_Static_assert(CONFIG_LIBSTORVSC_MAX_LUNS >= 1 &&
	       CONFIG_LIBSTORVSC_MAX_LUNS <= STORVSC_REPORT_LUNS_MAX,
	       "StorVSC LUN pool is out of range");
_Static_assert(CONFIG_LIBSTORVSC_MAX_QUEUES == 1,
	       "StorVSC supports exactly one queue");
_Static_assert(CONFIG_LIBSTORVSC_QUEUE_DEPTH <=
	       STORVSC_CORE_MAX_CONTEXTS,
	       "StorVSC request pool exceeds the core ABI");
_Static_assert(CONFIG_LIBSTORVSC_MAX_TRANSFER_PAGES <=
	       VMBUS_GPA_DIRECT_MAX_PFNS,
	       "StorVSC transfer exceeds the VMBus GPA-direct ABI");
_Static_assert(UK_STORVSC_INSTANCE_ID_SIZE == VMBUS_GUID_SIZE,
	       "StorVSC mapping GUID size differs from VMBus");
_Static_assert(UK_STORVSC_VPD_ID_MAX == STORVSC_VPD_ID_MAX,
	       "StorVSC mapping VPD size differs from the core");

static const struct vmbus_device_id storvsc_device_ids[] = {
	{ .class_id = { .bytes = {
		0xba, 0x61, 0x63, 0xd9, 0x04, 0xa1, 0x4d, 0x29,
		0xb6, 0x05, 0x72, 0xe2, 0xff, 0xb1, 0xdc, 0x7f,
	} } },
	{ .class_id = VMBUS_GUID_END },
};

static const struct uk_blkdev_ops storvsc_blkdev_ops;

static int storvsc_schedule_fatal(struct storvsc_device *device, int error);
static int storvsc_receive_async(struct storvsc_device *device,
				 int notify_user);
static int storvsc_deferred_try_run(struct storvsc_device *device);
static void storvsc_stop_timeout_worker(struct storvsc_device *device);
static void storvsc_timeout_worker(void *arg) __attribute__((noreturn));

#ifdef STORVSC_HOST_TEST
void storvsc_host_pfn_copy_hook(__u64 transaction_id, const __u64 *pfns,
				unsigned int written);
void storvsc_host_recovery_begin_hook(void);
void storvsc_host_reset_ack_hook(void);
void storvsc_host_deferred_epoch_sample_hook(__u64 epoch);
void storvsc_host_sync_completion_hook(void);
void storvsc_host_receive_hook(unsigned int controller, int before_notify);
void storvsc_host_binding_publish_hook(unsigned int controller);
int storvsc_host_registration_hook(unsigned int controller, uint8_t lun);
#endif

static struct vmbus_channel *
storvsc_channel_get(struct storvsc_device *device)
{
	return __atomic_load_n(&device->channel, __ATOMIC_ACQUIRE);
}

static void storvsc_channel_set(struct storvsc_device *device,
				struct vmbus_channel *channel)
{
	__atomic_store_n(&device->channel, channel, __ATOMIC_RELEASE);
}

static struct vmbus_channel *
storvsc_channel_detach(struct storvsc_device *device)
{
	return __atomic_exchange_n(&device->channel, NULL, __ATOMIC_ACQ_REL);
}

static void storvsc_release_write_session(struct storvsc_lun *lun)
{
	struct storvsc_lun *expected = lun;

	(void)__atomic_compare_exchange_n(
		&storvsc_write_lun, &expected, NULL, 0,
		__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static void storvsc_advance_topology_generation(void)
{
	__u64 current;

	if (__atomic_load_n(
		    &storvsc_topology_generation_exhausted,
		    __ATOMIC_ACQUIRE))
		return;
	current = __atomic_load_n(
		&storvsc_topology_generation, __ATOMIC_RELAXED);
	for (;;) {
		if (current == UINT64_MAX) {
			__atomic_store_n(
				&storvsc_topology_generation_exhausted, 1,
				__ATOMIC_RELEASE);
			return;
		}
		if (__atomic_compare_exchange_n(
			    &storvsc_topology_generation, &current,
			    current + 1, 0, __ATOMIC_ACQ_REL,
			    __ATOMIC_RELAXED)) {
			__atomic_store_n(
				&storvsc_write_lun, NULL, __ATOMIC_RELEASE);
			return;
		}
	}
}

static void storvsc_note_storage_lifetime(void)
{
	unsigned long flags;

	ukplat_spin_lock_irqsave(&storvsc_topology_lock, flags);
	storvsc_storage_lifetime_observed = 1;
	ukplat_spin_unlock_irqrestore(&storvsc_topology_lock, flags);
}

static int storvsc_unresolved_offer_matches(
	const struct storvsc_unresolved_offer *offer,
	const struct vmbus_guid *instance_id, __u32 channel_id,
	__u64 generation)
{
	return offer->active &&
	       offer->channel_id == channel_id &&
	       offer->generation == generation &&
	       !memcmp(offer->instance_id.bytes, instance_id->bytes,
		       VMBUS_GUID_SIZE);
}

static void storvsc_note_unresolved_offer(
	const struct vmbus_guid *instance_id, __u32 channel_id,
	__u64 generation, int error)
{
	struct storvsc_unresolved_offer *free_offer = NULL;
	unsigned long flags;
	unsigned int i;

	ukplat_spin_lock_irqsave(&storvsc_topology_lock, flags);
	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_DEVICES; i++) {
		struct storvsc_unresolved_offer *offer =
			&storvsc_unresolved_offers[i];

		if (storvsc_unresolved_offer_matches(
			    offer, instance_id, channel_id, generation)) {
			offer->error = error ? error : -EIO;
			goto out;
		}
		if (!free_offer && !offer->active)
			free_offer = offer;
	}
	if (free_offer) {
		free_offer->instance_id = *instance_id;
		free_offer->channel_id = channel_id;
		free_offer->generation = generation;
		free_offer->error = error ? error : -EIO;
		free_offer->active = 1;
	} else {
		/* An unrecorded offer cannot later be proven absent by identity. */
		storvsc_unresolved_offer_overflow =
			error ? error : -ENOSPC;
	}
	storvsc_advance_topology_generation();
out:
	ukplat_spin_unlock_irqrestore(&storvsc_topology_lock, flags);
}

static void storvsc_clear_unresolved_offer(
	const struct vmbus_guid *instance_id, __u32 channel_id,
	__u64 generation)
{
	unsigned long flags;
	unsigned int i;

	ukplat_spin_lock_irqsave(&storvsc_topology_lock, flags);
	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_DEVICES; i++) {
		struct storvsc_unresolved_offer *offer =
			&storvsc_unresolved_offers[i];

		if (!storvsc_unresolved_offer_matches(
			    offer, instance_id, channel_id, generation))
			continue;
		memset(offer, 0, sizeof(*offer));
		storvsc_advance_topology_generation();
		break;
	}
	ukplat_spin_unlock_irqrestore(&storvsc_topology_lock, flags);
}

static int storvsc_has_unresolved_offer(void)
{
	unsigned long flags;
	unsigned int i;
	int unresolved = 0;

	ukplat_spin_lock_irqsave(&storvsc_topology_lock, flags);
	if (storvsc_unresolved_offer_overflow) {
		unresolved = 1;
		goto out;
	}
	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_DEVICES; i++) {
		if (storvsc_unresolved_offers[i].active) {
			unresolved = 1;
			break;
		}
	}
out:
	ukplat_spin_unlock_irqrestore(&storvsc_topology_lock, flags);
	return unresolved;
}

static void
storvsc_invalidate_sessions_locked(struct storvsc_device *device)
{
	unsigned int i;

	storvsc_advance_topology_generation();
	if (device->session_generation != UINT64_MAX)
		device->session_generation++;
	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_LUNS; i++) {
		struct storvsc_lun *lun = &device->luns[i];

		if (lun->session_state == STORVSC_SESSION_WRITE)
			storvsc_release_write_session(lun);
		lun->session_state = STORVSC_SESSION_NONE;
		lun->session_cookie = 0;
		lun->session_topology_generation = 0;
		lun->session_controller_generation = 0;
		lun->session_lun_generation = 0;
		lun->session_cdb_size = UK_STORVSC_CDB_AUTO;
	}
}

static int storvsc_build_gpa_range(
	struct storvsc_request_binding *binding, const void *buffer,
	__u32 length, __u64 transaction_id, struct vmbus_gpa_range *range)
{
	uintptr_t address = (uintptr_t)buffer;
	uintptr_t page;
	__u64 covered;
	__u64 page_count;
	__u32 offset;
	unsigned int i;

	(void)transaction_id;
	if (!buffer || !length ||
	    address > ~(uintptr_t)0 - (length - 1))
		return -EINVAL;
	offset = (__u32)(address & (STORVSC_PAGE_SIZE - 1));
	covered = (__u64)offset + length;
	page_count = (covered + STORVSC_PAGE_SIZE - 1) / STORVSC_PAGE_SIZE;
	if (!page_count ||
	    page_count > CONFIG_LIBSTORVSC_MAX_TRANSFER_PAGES ||
	    page_count > VMBUS_GPA_DIRECT_MAX_PFNS)
		return -E2BIG;
	page = address & ~(uintptr_t)(STORVSC_PAGE_SIZE - 1);
#ifdef STORVSC_HOST_TEST
	storvsc_host_pfn_copy_hook(transaction_id, binding->pfns, 0);
#endif
	for (i = 0; i < page_count; i++) {
		uintptr_t virtual_address;
		__paddr_t physical;
		__u32 expected_offset;

		if (page > ~(uintptr_t)0 -
		    (uintptr_t)i * STORVSC_PAGE_SIZE)
			return -EOVERFLOW;
		virtual_address = i ? page +
			(uintptr_t)i * STORVSC_PAGE_SIZE : address;
		expected_offset = i ? 0 : offset;
		physical = uk_paging_virt_to_phys((__vaddr_t)virtual_address);
		if (physical == UK_PAGING_PADDR_INV ||
		    (physical & (STORVSC_PAGE_SIZE - 1)) != expected_offset)
			return -EFAULT;
		binding->pfns[i] = physical >> 12;
#ifdef STORVSC_HOST_TEST
		storvsc_host_pfn_copy_hook(transaction_id, binding->pfns,
					   i + 1);
#endif
	}
	range->byte_count = length;
	range->byte_offset = offset;
	range->pfns = binding->pfns;
	range->pfn_count = (__u32)page_count;
	return 0;
}

static int storvsc_send_tx(struct storvsc_device *device,
			   struct storvsc_request_binding *binding,
			   const struct storvsc_tx *tx, const void *buffer,
			   int *published)
{
	struct vmbus_gpa_range range;
	struct vmbus_channel *channel;
	int rc;

	*published = 0;
	channel = storvsc_channel_get(device);
	if (!channel)
		return -ENODEV;
	if (!tx->transfer_len)
		return vmbus_channel_send_ex(channel,
			VMBUS_PACKET_DATA_INBAND,
			VMBUS_PACKET_FLAG_REQUEST_COMPLETION,
			tx->transaction_id, NULL, 0, tx->packet,
			tx->packet_len, published);
	if (!binding)
		return -EINVAL;
	rc = storvsc_build_gpa_range(binding, buffer, tx->transfer_len,
				     tx->transaction_id, &range);
	if (rc)
		return rc;
	return vmbus_channel_send_gpa_direct_ex(channel,
		VMBUS_PACKET_FLAG_REQUEST_COMPLETION, tx->transaction_id,
		&range, 1, tx->packet, tx->packet_len, published);
}

static int storvsc_read_event(struct storvsc_device *device,
			      struct storvsc_event *event)
{
	struct vmbus_packet packet;
	struct vmbus_channel *channel;
	unsigned long flags;
	size_t payload_length;
	int malformed = 0;
	int rc;

	channel = storvsc_channel_get(device);
	if (!channel)
		return -ENODEV;
	rc = vmbus_channel_receive(channel, &packet,
		device->rx_descriptor, sizeof(device->rx_descriptor),
		device->rx_payload, sizeof(device->rx_payload));
	if (rc)
		return rc;
	payload_length = packet.payload_size;
	if (packet.descriptor_size != 0 ||
	    (packet.type != VMBUS_PACKET_COMPLETION &&
	     packet.type != VMBUS_PACKET_DATA_INBAND))
		malformed = 1;
	if (payload_length > sizeof(device->rx_payload))
		malformed = 1;
	ukplat_spin_lock_irqsave(&device->lock, flags);
	rc = storvsc_core_receive(device->core, packet.transaction_id,
		device->rx_payload, malformed ? 0 : payload_length,
		ukplat_monotonic_clock(), event);
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

static void storvsc_wake_timeout(struct storvsc_device *device)
{
	struct uk_thread *thread;
	unsigned long flags;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	thread = device->timeout_thread;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (thread && thread != uk_thread_current())
		uk_thread_wake(thread);
}

static int storvsc_schedule_fatal(struct storvsc_device *device, int error)
{
	unsigned long flags;
	int scheduled = 0;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (!device->fatal_error && !device->removing &&
	    device->deferred_action != STORVSC_DEFER_REMOVE) {
		device->fatal_error = error ? error : -EIO;
		device->online = 0;
		storvsc_invalidate_sessions_locked(device);
		scheduled = 1;
	}
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (scheduled)
		storvsc_wake_timeout(device);
	return scheduled;
}

static void storvsc_process_async_event(struct storvsc_device *device,
					const struct storvsc_event *event,
					int *completed)
{
	struct storvsc_request_binding *binding;
	unsigned long flags;
	int wake = 0;

	switch (event->kind) {
	case STORVSC_EVENT_REQUEST_COMPLETE:
		ukplat_spin_lock_irqsave(&device->lock, flags);
		if (event->slot < CONFIG_LIBSTORVSC_QUEUE_DEPTH) {
			binding = &device->bindings[event->slot];
			if (binding->id == event->transaction_id &&
			    binding->lun)
				binding->lun->completion_pending = 1;
		}
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		*completed = 1;
		break;
	case STORVSC_EVENT_RESET_COMPLETE:
		ukplat_spin_lock_irqsave(&device->lock, flags);
		device->reset_result = event->error;
		device->reset_done = 1;
		wake = 1;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		if (wake)
			storvsc_wake_timeout(device);
		break;
	case STORVSC_EVENT_REMOVE_DEVICE:
		(void)storvsc_schedule_fatal(device, -ENODEV);
		break;
	case STORVSC_EVENT_ENUMERATE_BUS:
		if (storvsc_guarded_io_enabled || !device->lun_count)
			(void)storvsc_schedule_fatal(device, -ESTALE);
		break;
	case STORVSC_EVENT_PROTOCOL_ERROR:
	case STORVSC_EVENT_INITIALIZATION_FAILED:
		(void)storvsc_schedule_fatal(device,
					     event->error ? event->error : -EPROTO);
		break;
	case STORVSC_EVENT_TRANSMIT:
	case STORVSC_EVENT_INITIALIZATION_READY:
		(void)storvsc_schedule_fatal(device, -EPROTO);
		break;
	case STORVSC_EVENT_REQUEST_TIMEOUT:
	case STORVSC_EVENT_IGNORED:
	default:
		break;
	}
}

static void storvsc_notify_pending(struct storvsc_device *device)
{
	struct storvsc_lun *lun;
	struct vmbus_channel *channel;
	unsigned long flags;
	unsigned int i;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (device->notify_active || device->finish_active ||
	    device->binding) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return;
	}
	device->notify_active = 1;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);

	for (;;) {
		lun = NULL;
		ukplat_spin_lock_irqsave(&device->lock, flags);
		if (!device->online || device->removing || device->binding ||
		    device->finish_active ||
		    device->deferred_action != STORVSC_DEFER_NONE) {
			device->notify_active = 0;
			device->notifying_lun = NULL;
			ukplat_spin_unlock_irqrestore(&device->lock, flags);
			return;
		}
		channel = storvsc_channel_get(device);
		if (channel) {
			for (i = 0; i < CONFIG_LIBSTORVSC_MAX_LUNS; i++) {
				struct storvsc_lun *candidate =
					&device->luns[i];

				if (candidate->completion_pending &&
				    candidate->present &&
				    candidate->registered &&
				    candidate->queue.configured &&
				    candidate->queue.intr_user &&
				    candidate->blkdev._data &&
				    candidate->blkdev._data->state ==
					    UK_BLKDEV_RUNNING) {
					lun = candidate;
					lun->completion_pending = 0;
					lun->queue.intr_active = 0;
					device->notifying_lun = lun;
					break;
				}
			}
		}
		if (!lun) {
			device->notify_active = 0;
			device->notifying_lun = NULL;
		}
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		if (!lun)
			return;
		(void)vmbus_channel_mask_interrupts(channel);
		uk_blkdev_drv_queue_event(&lun->blkdev, 0);
		ukplat_spin_lock_irqsave(&device->lock, flags);
		device->notifying_lun = NULL;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
	}
}

static int storvsc_rearm_interrupts(struct storvsc_device *device)
{
	struct vmbus_channel *channel;
	unsigned long flags;
	unsigned int i;
	unsigned int users = 0;
	int readable;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	channel = storvsc_channel_get(device);
	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_LUNS; i++) {
		struct storvsc_lun *lun = &device->luns[i];

		lun->queue.intr_active = 0;
		if (lun->queue.intr_user && lun->present &&
		    lun->registered && lun->queue.configured &&
		    lun->blkdev._data &&
		    lun->blkdev._data->state == UK_BLKDEV_RUNNING)
			users++;
	}
	device->interrupt_users = (__u16)users;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (!users)
		return 0;
	if (!channel)
		return -ENODEV;
	readable = vmbus_channel_unmask_interrupts(channel);
	if (readable < 0) {
		ukplat_spin_lock_irqsave(&device->lock, flags);
		device->interrupt_users = 0;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return readable;
	}
	ukplat_spin_lock_irqsave(&device->lock, flags);
	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_LUNS; i++) {
		struct storvsc_lun *lun = &device->luns[i];

		if (lun->queue.intr_user && lun->present &&
		    lun->registered && lun->queue.configured &&
		    lun->blkdev._data &&
		    lun->blkdev._data->state == UK_BLKDEV_RUNNING)
			lun->queue.intr_active = !readable;
	}
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (readable) {
		(void)vmbus_channel_mask_interrupts(channel);
		(void)storvsc_receive_async(device, 0);
	}
	return 0;
}

static int storvsc_receive_async(struct storvsc_device *device,
				 int notify_user)
{
	struct storvsc_event event;
	unsigned long receive_flags;
	unsigned long flags;
	int completed = 0;
	int rc;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (!device->online || device->removing ||
	    device->deferred_action != STORVSC_DEFER_NONE) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return 0;
	}
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
#ifdef STORVSC_HOST_TEST
	storvsc_host_receive_hook(device->index, 0);
#endif
	ukplat_spin_lock_irqsave(&device->receive_lock, receive_flags);
	for (;;) {
		rc = storvsc_read_event(device, &event);
		if (rc == -EAGAIN)
			break;
		if (rc) {
			(void)storvsc_schedule_fatal(device,
				rc == -ECANCELED || rc == -ENODEV ?
					-ENODEV : -EPROTO);
			break;
		}
		storvsc_process_async_event(device, &event, &completed);
	}
	ukplat_spin_unlock_irqrestore(&device->receive_lock, receive_flags);

#ifdef STORVSC_HOST_TEST
	if (completed && notify_user)
		storvsc_host_receive_hook(device->index, 1);
#endif
	if (completed && notify_user)
		storvsc_notify_pending(device);
	return rc == -EAGAIN ? 0 : rc;
}

static void storvsc_channel_callback(struct vmbus_channel *channel __unused,
				     void *arg)
{
	struct storvsc_device *device = arg;
	unsigned long flags;
	int valid;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	valid = device->online && !device->removing &&
		device->deferred_action == STORVSC_DEFER_NONE &&
		storvsc_channel_get(device) == channel;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (valid)
		(void)storvsc_receive_async(device, 1);
}

static int storvsc_send_initialization(struct storvsc_device *device)
{
	struct storvsc_event event;
	int published;
	int rc;

	rc = storvsc_core_start(device->core, ukplat_monotonic_clock(),
				STORVSC_CONTROL_TIMEOUT_NS, &event);
	if (rc)
		return rc;
	for (;;) {
		if (event.kind == STORVSC_EVENT_TRANSMIT) {
			rc = storvsc_send_tx(device, NULL, &event.tx, NULL,
					     &published);
			if (rc && !published)
				return rc;
		}
		for (;;) {
			rc = storvsc_read_event(device, &event);
			if (rc == -EAGAIN) {
				(void)storvsc_core_tick(device->core,
					ukplat_monotonic_clock(), &event);
				if (event.kind != STORVSC_EVENT_IGNORED)
					break;
				if (uk_sched_current())
					uk_sched_thread_sleep(
						STORVSC_WORKER_SLEEP_NS);
				else
					STORVSC_CPU_RELAX();
				continue;
			}
			if (rc)
				return rc;
			if (event.kind != STORVSC_EVENT_IGNORED)
				break;
		}
		switch (event.kind) {
		case STORVSC_EVENT_TRANSMIT:
			continue;
		case STORVSC_EVENT_INITIALIZATION_READY:
			return 0;
		case STORVSC_EVENT_INITIALIZATION_FAILED:
		case STORVSC_EVENT_PROTOCOL_ERROR:
			return event.error ? event.error : -EPROTO;
		case STORVSC_EVENT_REMOVE_DEVICE:
			return -ENODEV;
		default:
			return -EPROTO;
		}
	}
}

static int storvsc_execute_scsi(struct storvsc_device *device,
				const struct storvsc_scsi_spec *spec,
				void *buffer, __u32 *transferred)
{
	struct storvsc_request_binding *binding;
	struct storvsc_event event;
	struct storvsc_tx tx;
	int topology_changed = 0;
	int published;
	int rc;

	rc = storvsc_core_prepare_scsi(device->core, spec,
				       ukplat_monotonic_clock(), &tx);
	if (rc)
		return rc;
	if (tx.slot >= CONFIG_LIBSTORVSC_QUEUE_DEPTH)
		return -EPROTO;
	binding = &device->bindings[tx.slot];
	memset(binding, 0, sizeof(*binding));
	binding->id = tx.transaction_id;
	binding->synchronous = 1;
	rc = storvsc_send_tx(device, binding, &tx, buffer, &published);
	if (rc && !published) {
		(void)storvsc_core_abort(device->core, tx.slot,
					 tx.transaction_id);
		memset(binding, 0, sizeof(*binding));
		return rc;
	}
	for (;;) {
		rc = storvsc_read_event(device, &event);
		if (rc == -EAGAIN) {
			(void)storvsc_core_tick(device->core,
				ukplat_monotonic_clock(), &event);
			if (event.kind == STORVSC_EVENT_REQUEST_TIMEOUT &&
			    event.transaction_id == tx.transaction_id)
				return -ETIMEDOUT;
			if (event.kind == STORVSC_EVENT_INITIALIZATION_FAILED ||
			    event.kind == STORVSC_EVENT_PROTOCOL_ERROR)
				return event.error ? event.error : -EPROTO;
			if (uk_sched_current())
				uk_sched_thread_sleep(STORVSC_WORKER_SLEEP_NS);
			else
				STORVSC_CPU_RELAX();
			continue;
		}
		if (rc)
			return rc;
		if (event.kind == STORVSC_EVENT_REMOVE_DEVICE)
			return -ENODEV;
		if (event.kind == STORVSC_EVENT_ENUMERATE_BUS) {
			topology_changed = 1;
			continue;
		}
		if (event.kind != STORVSC_EVENT_REQUEST_COMPLETE ||
		    event.transaction_id != tx.transaction_id)
			continue;
#ifdef STORVSC_HOST_TEST
		storvsc_host_sync_completion_hook();
#endif
		rc = storvsc_core_take_completed(device->core, tx.slot,
				tx.transaction_id, &event);
		memset(binding, 0, sizeof(*binding));
		if (rc)
			return rc;
		if (transferred)
			*transferred = event.transferred;
		if (event.error)
			return event.error;
		return topology_changed ? -ESTALE : 0;
	}
}

static void storvsc_scsi_spec_init(struct storvsc_scsi_spec *spec,
				   __u8 opcode, __u8 cdb_len,
				   __u8 direction, __u32 transfer_len,
				   __u32 minimum_transfer, int allow_short,
				   const struct storvsc_address *address)
{
	memset(spec, 0, sizeof(*spec));
	spec->cdb[0] = opcode;
	spec->cdb_len = cdb_len;
	spec->direction = direction;
	spec->transfer_len = transfer_len;
	spec->minimum_transfer = minimum_transfer;
	spec->allow_short = !!allow_short;
	spec->timeout_ns = STORVSC_CONTROL_TIMEOUT_NS;
	if (address) {
		spec->path_id = address->path_id;
		spec->target_id = address->target_id;
		spec->lun = address->lun;
	}
}

static int storvsc_enumerate_luns(struct storvsc_device *device)
{
	struct storvsc_scsi_spec spec;
	__u32 transferred;
	size_t count;
	int rc;

	memset(device->report_luns_data, 0,
	       sizeof(device->report_luns_data));
	memset(device->lun_addresses, 0, sizeof(device->lun_addresses));
	device->lun_count = 0;
	if (!storvsc_lun_discovery_enabled) {
		device->lun_count = 1;
		return 0;
	}
	rc = storvsc_build_report_luns(&spec, 0, 0,
				       STORVSC_REPORT_LUNS_MAX,
				       STORVSC_CONTROL_TIMEOUT_NS);
	if (rc)
		return rc;
	rc = storvsc_execute_scsi(device, &spec,
				  device->report_luns_data, &transferred);
	if (rc)
		return rc;
	rc = storvsc_parse_report_luns(
		device->report_luns_data, transferred, 0, 0,
		device->lun_addresses, STORVSC_REPORT_LUNS_MAX,
		&count);
	if (rc)
		return rc;
	device->lun_count = count;
	if (count)
		return 0;

	/*
	 * A single empty report can race a topology update. Require a second
	 * successful empty report before treating this controller as empty.
	 */
	memset(device->report_luns_data, 0,
	       sizeof(device->report_luns_data));
	rc = storvsc_execute_scsi(device, &spec,
				  device->report_luns_data, &transferred);
	if (rc)
		return rc;
	rc = storvsc_parse_report_luns(
		device->report_luns_data, transferred, 0, 0,
		device->lun_addresses, STORVSC_REPORT_LUNS_MAX,
		&count);
	if (!rc)
		device->lun_count = count;
	return rc;
}

static int storvsc_discover_lun(struct storvsc_device *device,
				const struct storvsc_address *address,
				struct storvsc_capacity *capacity,
				struct storvsc_mode *mode,
				struct storvsc_vpd_id *vpd_id)
{
	struct storvsc_scsi_spec spec;
	struct storvsc_inquiry inquiry;
	__u32 transferred;
	unsigned int retry;
	int rc;

	memset(device->inquiry_data, 0, sizeof(device->inquiry_data));
	storvsc_scsi_spec_init(&spec, 0x12, 6, STORVSC_DIRECTION_READ,
			       sizeof(device->inquiry_data), 5, 1,
			       address);
	spec.cdb[4] = sizeof(device->inquiry_data);
	rc = storvsc_execute_scsi(device, &spec, device->inquiry_data,
				  &transferred);
	if (rc)
		return rc;
	rc = storvsc_parse_inquiry(device->inquiry_data, transferred,
				   &inquiry);
	if (rc)
		return rc;

	memset(vpd_id, 0, sizeof(*vpd_id));
	if (storvsc_lun_discovery_enabled) {
		memset(device->vpd_data, 0, sizeof(device->vpd_data));
		storvsc_scsi_spec_init(&spec, 0x12, 6,
				       STORVSC_DIRECTION_READ,
				       sizeof(device->vpd_data), 4, 1,
				       address);
		spec.cdb[1] = 1;
		spec.cdb[2] = 0x83;
		spec.cdb[4] = sizeof(device->vpd_data);
		rc = storvsc_execute_scsi(device, &spec, device->vpd_data,
					  &transferred);
		if (!rc) {
			rc = storvsc_parse_vpd83(device->vpd_data, transferred,
						 vpd_id);
			if (rc && rc != -ENOENT)
				return rc;
		} else if (rc != -EINVAL) {
			return rc;
		}
	}

	for (retry = 0; retry < 3; retry++) {
		storvsc_scsi_spec_init(&spec, 0x00, 6,
				       STORVSC_DIRECTION_NONE, 0, 0, 0,
				       address);
		rc = storvsc_execute_scsi(device, &spec, NULL, NULL);
		if (rc != -EAGAIN)
			break;
		uk_sched_thread_sleep(100000000ULL);
	}
	if (rc)
		return rc;

	memset(device->capacity_data, 0, sizeof(device->capacity_data));
	storvsc_scsi_spec_init(&spec, 0x25, 10, STORVSC_DIRECTION_READ,
			       8, 8, 0, address);
	rc = storvsc_execute_scsi(device, &spec, device->capacity_data,
				  &transferred);
	if (rc)
		return rc;
	rc = storvsc_parse_capacity10(device->capacity_data, transferred,
				      capacity);
	if (rc)
		return rc;
	if (capacity->needs_capacity16) {
		memset(device->capacity_data, 0, sizeof(device->capacity_data));
		storvsc_scsi_spec_init(&spec, 0x9e, 16,
				       STORVSC_DIRECTION_READ,
				       sizeof(device->capacity_data), 12, 1,
				       address);
		spec.cdb[1] = 0x10;
		spec.cdb[13] = sizeof(device->capacity_data);
		rc = storvsc_execute_scsi(device, &spec,
					  device->capacity_data, &transferred);
		if (rc)
			return rc;
		rc = storvsc_parse_capacity16(device->capacity_data,
					      transferred, capacity);
		if (rc)
			return rc;
	}

	memset(device->mode_data, 0, sizeof(device->mode_data));
	storvsc_scsi_spec_init(&spec, 0x1a, 6, STORVSC_DIRECTION_READ,
			       sizeof(device->mode_data), 4, 1,
			       address);
	spec.cdb[1] = 0x08;
	spec.cdb[2] = 0x3f;
	spec.cdb[4] = sizeof(device->mode_data);
	rc = storvsc_execute_scsi(device, &spec, device->mode_data,
				  &transferred);
	if (!rc)
		return storvsc_parse_mode_sense6(device->mode_data,
						 transferred, mode);
	if (rc != -EINVAL)
		return rc;

	/*
	 * ukblkdev exposes a persistent access mode. Try both standard
	 * headers, but do not attach as writable if neither can establish
	 * whether the media is read-only.
	 */
	memset(device->mode_data, 0, sizeof(device->mode_data));
	storvsc_scsi_spec_init(&spec, 0x5a, 10, STORVSC_DIRECTION_READ,
			       sizeof(device->mode_data), 8, 1,
			       address);
	spec.cdb[1] = 0x08;
	spec.cdb[2] = 0x3f;
	spec.cdb[7] = (__u8)(sizeof(device->mode_data) >> 8);
	spec.cdb[8] = (__u8)sizeof(device->mode_data);
	rc = storvsc_execute_scsi(device, &spec, device->mode_data,
				  &transferred);
	if (rc)
		return rc;
	return storvsc_parse_mode_sense10(device->mode_data, transferred,
					  mode);
}

static int storvsc_take_completion_locked(struct storvsc_device *device,
					  struct uk_blkreq **request,
					  struct storvsc_event *event)
{
	struct storvsc_request_binding *binding;
	__u16 slot;
	int rc;

	*request = NULL;
	rc = storvsc_core_next_completed(device->core, &slot);
	if (rc)
		return rc;
	if (slot >= CONFIG_LIBSTORVSC_QUEUE_DEPTH)
		return -EPROTO;
	binding = &device->bindings[slot];
	if (!binding->id)
		return -EPROTO;
	rc = storvsc_core_take_completed(device->core, slot, binding->id,
					 event);
	if (rc)
		return rc;
	*request = binding->req;
	memset(binding, 0, sizeof(*binding));
	return 0;
}

static int storvsc_take_lun_completion_locked(
	struct storvsc_device *device, struct storvsc_lun *lun,
	struct uk_blkreq **request, struct storvsc_event *event)
{
	unsigned int slot;
	int rc;

	*request = NULL;
	for (slot = 0; slot < CONFIG_LIBSTORVSC_QUEUE_DEPTH; slot++) {
		struct storvsc_request_binding *binding =
			&device->bindings[slot];

		if (!binding->id || binding->lun != lun)
			continue;
		rc = storvsc_core_take_completed(device->core, (__u16)slot,
						 binding->id, event);
		if (rc == -ENOENT)
			continue;
		if (rc)
			return rc;
		*request = binding->req;
		memset(binding, 0, sizeof(*binding));
		return 0;
	}
	return -ENOENT;
}

static void storvsc_notify_completions(struct storvsc_device *device)
{
	unsigned long flags;
	unsigned int i;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	for (i = 0; i < CONFIG_LIBSTORVSC_QUEUE_DEPTH; i++) {
		struct storvsc_request_binding *binding = &device->bindings[i];

		if (binding->id && binding->lun)
			binding->lun->completion_pending = 1;
	}
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	storvsc_notify_pending(device);
}

static int storvsc_close_channel_pointer(struct vmbus_channel *channel,
					 unsigned int *attempts_out)
{
	unsigned int attempt;
	int rc = -ENODEV;

	if (attempts_out)
		*attempts_out = 0;
	if (!channel)
		return 0;
	vmbus_channel_set_callback(channel, NULL, NULL);
	for (attempt = 0; attempt < STORVSC_CLOSE_RETRY_LIMIT; attempt++) {
		rc = vmbus_channel_close(channel);
		if (attempts_out)
			(*attempts_out)++;
		if (rc != -EBUSY)
			break;
		if (!uk_sched_current() || uk_lcpu_irqs_disabled())
			break;
		uk_sched_thread_sleep(STORVSC_WORKER_SLEEP_NS *
				      (attempt + 1));
	}
	return rc;
}

static int storvsc_close_channel(struct storvsc_device *device)
{
	struct vmbus_channel *channel = storvsc_channel_get(device);
	int rc = storvsc_close_channel_pointer(channel, NULL);

	if (!rc || rc == -ENODEV || rc == -ECANCELED)
		storvsc_channel_set(device, NULL);
	return rc;
}

static int storvsc_wait_active_sends(struct storvsc_device *device)
{
	unsigned long flags;
	unsigned int attempt;
	unsigned int wait_limit = STORVSC_SEND_WAIT_LIMIT;
	__u16 active;

#ifdef STORVSC_HOST_TEST
	wait_limit = storvsc_send_wait_limit;
#endif
	for (attempt = 0; attempt < wait_limit; attempt++) {
		ukplat_spin_lock_irqsave(&device->lock, flags);
		active = device->active_sends;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		if (!active)
			return 0;
		if (!uk_sched_current() || uk_lcpu_irqs_disabled())
			return -EWOULDBLOCK;
		uk_sched_thread_sleep(STORVSC_WORKER_SLEEP_NS);
	}
	return -ETIMEDOUT;
}

static void storvsc_wait_finish(struct storvsc_device *device)
{
	unsigned long flags;
	unsigned int attempt;
	__u8 active;

	if (!uk_sched_current() || uk_lcpu_irqs_disabled())
		return;
	for (attempt = 0; attempt < STORVSC_SEND_WAIT_LIMIT; attempt++) {
		ukplat_spin_lock_irqsave(&device->lock, flags);
		active = device->finish_active || device->notify_active;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		if (!active)
			return;
		uk_sched_thread_sleep(STORVSC_WORKER_SLEEP_NS);
	}
}

static int storvsc_deferred_priority(unsigned int action)
{
	return action;
}

/*
 * device->lock publishes the terminal state and elects one cleanup owner.
 * It is never held while waiting, entering VMBus, or invoking blkreq
 * callbacks. receive_lock may precede device->lock; deferred cleanup never
 * takes receive_lock, avoiding an inverse edge.
 */
static void storvsc_deferred_schedule(struct storvsc_device *device,
				      unsigned int action, int error)
{
	struct vmbus_channel *detached;
	unsigned long flags;
	__u64 quiesce_epoch = vmbus_connection_quiesce_epoch();
	int fail_connection = 0;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->online = 0;
	device->recovering = 1;
	storvsc_invalidate_sessions_locked(device);
	if (action == STORVSC_DEFER_REMOVE) {
		device->removing = 1;
		device->vmbus_device = NULL;
	}
	detached = storvsc_channel_detach(device);
	if (detached && !device->deferred_close_required &&
	    !device->deferred_wait_vmbus) {
		device->deferred_channel = detached;
		device->deferred_close_required = 1;
	}
	if (storvsc_deferred_priority(action) >=
	    storvsc_deferred_priority(device->deferred_action)) {
		device->deferred_action = action;
		device->deferred_error = error;
	}
	/*
	 * EBUSY means no close was posted. If VMBus removal takes priority
	 * while that obligation is pending, wait for this connection's
	 * acknowledged teardown instead of dropping the retained channel.
	 */
	if (device->deferred_action == STORVSC_DEFER_REMOVE &&
	    device->deferred_close_busy && !device->deferred_running &&
	    !device->deferred_wait_vmbus) {
		device->deferred_vmbus_epoch = quiesce_epoch;
		device->deferred_wait_vmbus = 1;
		device->deferred_close_busy = 0;
		device->deferred_channel = NULL;
		device->deferred_close_attempts = 0;
		device->deferred_close_deadline = 0;
		fail_connection = 1;
	}
	ukplat_spin_unlock_irqrestore(&device->lock, flags);

	if (detached)
		vmbus_channel_set_callback(detached, NULL, NULL);
	if (fail_connection)
		(void)vmbus_connection_fail();
	storvsc_wake_timeout(device);
}

static int storvsc_deferred_pending(struct storvsc_device *device)
{
	unsigned long flags;
	int pending;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	pending = device->deferred_action != STORVSC_DEFER_NONE;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return pending;
}

static void storvsc_fail_after_quiesce(struct storvsc_device *device,
				       int error)
{
	storvsc_deferred_schedule(device, STORVSC_DEFER_FATAL, error);
}

static int storvsc_reset_timed_out_io(struct storvsc_device *device)
{
	struct storvsc_event event;
	__u64 deadline;
	unsigned long flags;
	int published;
	int reset_result;
	int stop;
	int rc;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (!device->online || device->recovering || device->removing) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -ENODEV;
	}
	device->recovering = 1;
	device->reset_done = 0;
	device->reset_result = -ETIMEDOUT;
	storvsc_invalidate_sessions_locked(device);
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
#ifdef STORVSC_HOST_TEST
	storvsc_host_recovery_begin_hook();
#endif
	/*
	 * Drain every request accepted before the recovering gate closed.
	 * This orders all of their descriptor publications before RESET BUS.
	 */
	rc = storvsc_wait_active_sends(device);
	if (rc) {
		storvsc_deferred_schedule(device, STORVSC_DEFER_RESET,
					  -ETIMEDOUT);
		return -EINPROGRESS;
	}
	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (!device->online || device->removing) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -ECANCELED;
	}
	rc = storvsc_core_begin_reset(device->core,
		ukplat_monotonic_clock(), STORVSC_CONTROL_TIMEOUT_NS, &event);
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (rc)
		return rc;
	rc = storvsc_send_tx(device, NULL, &event.tx, NULL, &published);
	if (rc && !published)
		return rc;
	deadline = ukplat_monotonic_clock();
	deadline = UINT64_MAX - deadline < STORVSC_CONTROL_TIMEOUT_NS ?
		UINT64_MAX : deadline + STORVSC_CONTROL_TIMEOUT_NS;
	for (;;) {
		(void)storvsc_receive_async(device, 0);
		ukplat_spin_lock_irqsave(&device->lock, flags);
		stop = device->timeout_stop || device->removing;
		if (device->reset_done) {
			reset_result = device->reset_result;
			ukplat_spin_unlock_irqrestore(&device->lock, flags);
			break;
		}
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		if (stop)
			return -ECANCELED;
		if (ukplat_monotonic_clock() >= deadline) {
			ukplat_spin_lock_irqsave(&device->lock, flags);
			(void)storvsc_core_tick(device->core,
				ukplat_monotonic_clock(), &event);
			reset_result = event.kind == STORVSC_EVENT_RESET_COMPLETE ?
				event.error : -ETIMEDOUT;
			ukplat_spin_unlock_irqrestore(&device->lock, flags);
			break;
		}
		uk_sched_thread_sleep(STORVSC_WORKER_SLEEP_NS);
	}
	if (reset_result)
		return reset_result;
#ifdef STORVSC_HOST_TEST
	storvsc_host_reset_ack_hook();
#endif
	/*
	 * Keep the gate closed through cancellation and defensively verify that
	 * no local descriptor publication re-entered the recovery window.
	 */
	rc = storvsc_wait_active_sends(device);
	if (rc) {
		storvsc_deferred_schedule(device, STORVSC_DEFER_RESET,
					  -ETIMEDOUT);
		return -EINPROGRESS;
	}
	ukplat_spin_lock_irqsave(&device->lock, flags);
	(void)storvsc_core_cancel_all(device->core, -ETIMEDOUT);
	device->recovering = 0;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	storvsc_notify_completions(device);
	return 0;
}

static void storvsc_timeout_worker(void *arg)
{
	struct storvsc_device *device = arg;
	struct storvsc_event event;
	unsigned long flags;
	int busy;
	int fatal;
	int online;
	int pending;
	int stop;

	for (;;) {
		ukplat_spin_lock_irqsave(&device->lock, flags);
		stop = device->timeout_stop;
		fatal = device->fatal_error;
		pending = device->deferred_action != STORVSC_DEFER_NONE;
		online = device->online;
		if (fatal)
			device->fatal_error = 0;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		if (stop)
			break;
		if (fatal) {
			storvsc_fail_after_quiesce(device, fatal);
			continue;
		}
		if (pending) {
			(void)storvsc_deferred_try_run(device);
			if (storvsc_deferred_pending(device)) {
				ukplat_spin_lock_irqsave(&device->lock, flags);
				busy = device->deferred_close_busy;
				ukplat_spin_unlock_irqrestore(
					&device->lock, flags);
				uk_sched_thread_sleep(
					busy ? STORVSC_BUSY_RETRY_SLEEP_NS :
					STORVSC_DEFERRED_SLEEP_NS);
			}
			continue;
		}
		if (!online)
			break;
		(void)storvsc_receive_async(device, 1);
		ukplat_spin_lock_irqsave(&device->lock, flags);
		stop = device->timeout_stop;
		fatal = device->fatal_error;
		if (fatal)
			device->fatal_error = 0;
		if (!stop && !fatal)
			(void)storvsc_core_tick(device->core,
				ukplat_monotonic_clock(), &event);
		else
			event.kind = STORVSC_EVENT_IGNORED;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		if (stop)
			break;
		if (fatal) {
			storvsc_fail_after_quiesce(device, fatal);
			continue;
		}
		if (event.kind == STORVSC_EVENT_REQUEST_TIMEOUT) {
			int rc = storvsc_reset_timed_out_io(device);

			if (rc == -EINPROGRESS)
				continue;
			if (rc == -ECANCELED &&
			    storvsc_deferred_pending(device))
				continue;
			if (rc && rc != -ECANCELED) {
				storvsc_fail_after_quiesce(device,
					rc == -ENODEV ? -ENODEV : -ETIMEDOUT);
				continue;
			}
		}
		uk_sched_thread_sleep(STORVSC_WORKER_SLEEP_NS);
	}
	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->timeout_thread = NULL;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	uk_sched_thread_exit();
}

static int storvsc_start_timeout_worker(struct storvsc_device *device)
{
	struct uk_sched *sched = uk_sched_current();
	struct uk_thread *thread;
	unsigned long flags;
	int stopping;

	if (!sched)
		return -ENOSYS;
	ukplat_spin_lock_irqsave(&device->lock, flags);
	thread = device->timeout_thread;
	stopping = device->timeout_stop;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (thread && stopping)
		storvsc_stop_timeout_worker(device);
	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (device->timeout_thread) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -EBUSY;
	}
	device->timeout_stop = 0;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	thread = uk_sched_thread_create(sched, storvsc_timeout_worker,
					device, "storvsc-timeout");
	if (!thread)
		return -ENOMEM;
	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->timeout_thread = thread;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return 0;
}

static void storvsc_stop_timeout_worker(struct storvsc_device *device)
{
	struct uk_thread *thread;
	unsigned long flags;
	unsigned int attempt;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->timeout_stop = 1;
	thread = device->timeout_thread;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (!thread)
		return;
	if (thread != uk_thread_current())
		uk_thread_wake(thread);
	if (!uk_sched_current() || uk_lcpu_irqs_disabled() ||
	    thread == uk_thread_current())
		return;
	for (attempt = 0; attempt < STORVSC_STOP_WAIT_LIMIT; attempt++) {
		ukplat_spin_lock_irqsave(&device->lock, flags);
		thread = device->timeout_thread;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		if (!thread)
			return;
		uk_sched_thread_sleep(STORVSC_WORKER_SLEEP_NS);
	}
}

static __u32 storvsc_lun_active_count_locked(
	const struct storvsc_device *device, const struct storvsc_lun *lun)
{
	__u32 count = 0;
	unsigned int i;

	for (i = 0; i < CONFIG_LIBSTORVSC_QUEUE_DEPTH; i++) {
		if (device->bindings[i].id &&
		    device->bindings[i].lun == lun)
			count++;
	}
	return count;
}

static int storvsc_submit(struct uk_blkdev *blkdev,
			  struct uk_blkdev_queue *queue,
			  struct uk_blkreq *request)
{
	struct storvsc_lun *lun = queue->lun;
	struct storvsc_device *device = lun->controller;
	struct storvsc_request_binding *binding;
	struct storvsc_tx tx;
	unsigned long flags;
	__u32 active;
	__u32 controller_active;
	int deferred_ready;
	int published;
	int rc;
	int status;
	__u8 cdb_size = UK_STORVSC_CDB_AUTO;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (!device->online || device->removing || !lun->present) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -ENODEV;
	}
	if (device->binding || device->recovering) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -EAGAIN;
	}
	if (!queue->configured || !lun->started || !queue->nb_desc) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -EINVAL;
	}
	if (storvsc_guarded_io_enabled) {
		if (lun->session_state == STORVSC_SESSION_NONE ||
		    lun->session_topology_generation !=
			    __atomic_load_n(&storvsc_topology_generation,
					    __ATOMIC_ACQUIRE) ||
		    lun->session_controller_generation !=
			    device->session_generation ||
		    lun->session_lun_generation != lun->generation) {
			ukplat_spin_unlock_irqrestore(&device->lock, flags);
			return -EACCES;
		}
		if (request->operation != UK_BLKREQ_READ &&
		    (lun->session_state != STORVSC_SESSION_WRITE ||
		     __atomic_load_n(&storvsc_write_lun,
				     __ATOMIC_ACQUIRE) != lun)) {
			ukplat_spin_unlock_irqrestore(&device->lock, flags);
			return -EACCES;
		}
		cdb_size = lun->session_cdb_size;
	}
	active = storvsc_lun_active_count_locked(device, lun);
	if (active >= queue->nb_desc) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -ENOSPC;
	}
	rc = storvsc_core_prepare_block_media_cdb(
		device->core, &lun->address, &lun->media, cdb_size,
		request->operation, request->start_sector,
		request->nb_sectors, (uintptr_t)request->aio_buf,
		ukplat_monotonic_clock(), STORVSC_REQUEST_TIMEOUT_NS, &tx);
	if (rc) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return rc;
	}
	if (tx.slot >= CONFIG_LIBSTORVSC_QUEUE_DEPTH) {
		(void)storvsc_core_abort(device->core, tx.slot,
					 tx.transaction_id);
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -EPROTO;
	}
	binding = &device->bindings[tx.slot];
	memset(binding, 0, sizeof(*binding));
	binding->req = request;
	binding->id = tx.transaction_id;
	binding->lun = lun;
	device->active_sends++;
	request->result = -EINPROGRESS;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);

	rc = storvsc_send_tx(device, binding, &tx, request->aio_buf,
			     &published);
	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (device->active_sends)
		device->active_sends--;
	deferred_ready = device->active_sends == 0 &&
		device->deferred_action != STORVSC_DEFER_NONE;
	if (rc && !published) {
		(void)storvsc_core_abort(device->core, tx.slot,
					 tx.transaction_id);
		memset(binding, 0, sizeof(*binding));
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		if (deferred_ready)
			storvsc_wake_timeout(device);
		return rc == -EAGAIN ? -ENOSPC : rc;
	}
	active = storvsc_lun_active_count_locked(device, lun);
	controller_active = storvsc_core_active_count(device->core);
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (rc == -ECANCELED || rc == -ENODEV)
		(void)storvsc_schedule_fatal(device, -ENODEV);
	if (deferred_ready)
		storvsc_wake_timeout(device);

	status = UK_BLKDEV_STATUS_SUCCESS;
	if (active < queue->nb_desc &&
	    controller_active < CONFIG_LIBSTORVSC_QUEUE_DEPTH)
		status |= UK_BLKDEV_STATUS_MORE;
	(void)blkdev;
	return status;
}

static int storvsc_finish(struct uk_blkdev *blkdev,
			  struct uk_blkdev_queue *queue)
{
	struct storvsc_lun *lun = queue->lun;
	struct storvsc_device *device = lun->controller;
	struct storvsc_event event;
	struct uk_blkreq *request;
	unsigned long flags;
	int deferred_ready;
	int rc = 0;
	int readable;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (device->finish_active || !device->online || device->binding ||
	    (device->notify_active && device->notifying_lun != lun) ||
	    device->removing ||
	    device->deferred_action != STORVSC_DEFER_NONE) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return 0;
	}
	device->finish_active = 1;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);

again:
	(void)storvsc_receive_async(device, 0);
	for (;;) {
		ukplat_spin_lock_irqsave(&device->lock, flags);
		rc = storvsc_take_lun_completion_locked(device, lun, &request,
							 &event);
		if (rc == -ENOENT)
			lun->completion_pending = 0;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		if (rc == -ENOENT) {
			rc = 0;
			break;
		}
		if (rc)
			break;
		if (!request)
			continue;
		request->result = event.error;
		uk_blkreq_finished(request);
		if (request->cb)
			request->cb(request, request->cb_cookie);
	}
	if (!rc && queue->intr_user) {
		struct vmbus_channel *channel;

		ukplat_spin_lock_irqsave(&device->lock, flags);
		channel = device->online && !device->removing &&
			device->deferred_action == STORVSC_DEFER_NONE ?
			storvsc_channel_get(device) : NULL;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		if (!channel)
			goto out;

		readable = vmbus_channel_unmask_interrupts(channel);
		if (readable > 0) {
			(void)vmbus_channel_mask_interrupts(channel);
			goto again;
		}
		if (!readable)
			queue->intr_active = 1;
		else
			rc = readable;
	}
out:
	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->finish_active = 0;
	deferred_ready = device->active_sends == 0 &&
		device->deferred_action != STORVSC_DEFER_NONE;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (deferred_ready)
		storvsc_wake_timeout(device);
	if (!rc)
		storvsc_notify_pending(device);
	(void)blkdev;
	return rc;
}

static void storvsc_get_info(struct uk_blkdev *blkdev __unused,
			     struct uk_blkdev_info *info)
{
	info->max_queues = CONFIG_LIBSTORVSC_MAX_QUEUES;
}

static int storvsc_configure(struct uk_blkdev *blkdev,
			     const struct uk_blkdev_conf *conf)
{
	struct storvsc_lun *lun =
		__containerof(blkdev, struct storvsc_lun, blkdev);
	struct storvsc_device *device = lun->controller;
	unsigned long flags;
	int rc = 0;

	if (!conf || conf->nb_queues != 1)
		return -EINVAL;
	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (!device->online || !lun->present)
		rc = -ENODEV;
	else if (device->binding || device->recovering)
		rc = -EAGAIN;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

static int storvsc_queue_get_info(struct uk_blkdev *blkdev __unused,
				  __u16 queue_id,
				  struct uk_blkdev_queue_info *info)
{
	if (queue_id != 0)
		return -EINVAL;
	info->nb_min = 1;
	info->nb_max = CONFIG_LIBSTORVSC_QUEUE_DEPTH;
	info->nb_align = 1;
	info->nb_is_power_of_two = 0;
	return 0;
}

static struct uk_blkdev_queue *
storvsc_queue_configure(struct uk_blkdev *blkdev, __u16 queue_id,
			__u16 nb_desc,
			const struct uk_blkdev_queue_conf *queue_conf __unused)
{
	struct storvsc_lun *lun =
		__containerof(blkdev, struct storvsc_lun, blkdev);
	struct storvsc_device *device = lun->controller;
	unsigned long flags;
	int rc = 0;

	if (queue_id != 0 || !nb_desc ||
	    nb_desc > CONFIG_LIBSTORVSC_QUEUE_DEPTH)
		return ERR2PTR(-EINVAL);
	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (!device->online || !lun->present)
		rc = -ENODEV;
	else if (device->binding || device->recovering)
		rc = -EAGAIN;
	else if (lun->queue.configured)
		rc = -EBUSY;
	else {
		lun->queue.lun = lun;
		lun->queue.nb_desc = nb_desc;
		lun->queue.configured = 1;
	}
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc ? ERR2PTR(rc) : &lun->queue;
}

static int storvsc_start(struct uk_blkdev *blkdev)
{
	struct storvsc_lun *lun =
		__containerof(blkdev, struct storvsc_lun, blkdev);
	struct storvsc_device *device = lun->controller;
	unsigned long flags;
	int rc = 0;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (!device->online || !lun->present)
		rc = -ENODEV;
	else if (device->binding || device->recovering)
		rc = -EAGAIN;
	else if (!lun->queue.configured)
		rc = -EINVAL;
	else
		lun->started = 1;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

static int storvsc_lun_active_locked(struct storvsc_lun *lun)
{
	struct storvsc_device *device = lun->controller;
	unsigned int i;

	for (i = 0; i < CONFIG_LIBSTORVSC_QUEUE_DEPTH; i++) {
		if (device->bindings[i].id &&
		    device->bindings[i].lun == lun)
			return 1;
	}
	return 0;
}

static int storvsc_stop(struct uk_blkdev *blkdev)
{
	struct storvsc_lun *lun =
		__containerof(blkdev, struct storvsc_lun, blkdev);
	struct storvsc_device *device = lun->controller;
	unsigned long flags;
	int rc = 0;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (storvsc_lun_active_locked(lun))
		rc = -EBUSY;
	else
		lun->started = 0;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

static int storvsc_queue_intr_enable(struct uk_blkdev *blkdev __unused,
				     struct uk_blkdev_queue *queue)
{
	struct storvsc_lun *lun = queue->lun;
	struct storvsc_device *device = lun->controller;
	struct vmbus_channel *channel;
	unsigned long flags;
	int readable;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (!device->online || device->removing || !lun->present ||
	    device->deferred_action != STORVSC_DEFER_NONE) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -ENODEV;
	}
	if (device->binding || device->recovering) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -EAGAIN;
	}
	channel = storvsc_channel_get(device);
	if (!channel) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -ENODEV;
	}
	if (!queue->intr_user)
		device->interrupt_users++;
	queue->intr_user = 1;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	readable = vmbus_channel_unmask_interrupts(channel);
	if (readable < 0) {
		ukplat_spin_lock_irqsave(&device->lock, flags);
		if (queue->intr_user && device->interrupt_users)
			device->interrupt_users--;
		queue->intr_user = 0;
		queue->intr_active = 0;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return readable;
	}
	if (readable) {
		(void)vmbus_channel_mask_interrupts(channel);
		queue->intr_active = 0;
		(void)storvsc_receive_async(device, 0);
	} else
		queue->intr_active = 1;
	storvsc_notify_pending(device);
	return 0;
}

static int storvsc_queue_intr_disable(struct uk_blkdev *blkdev __unused,
				      struct uk_blkdev_queue *queue)
{
	struct storvsc_lun *lun = queue->lun;
	struct storvsc_device *device = lun->controller;
	struct vmbus_channel *channel;
	unsigned long flags;
	int mask_channel = 0;
	int rc = 0;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	channel = device->online && !device->removing &&
		device->deferred_action == STORVSC_DEFER_NONE ?
		storvsc_channel_get(device) : NULL;
	if (queue->intr_user && device->interrupt_users)
		device->interrupt_users--;
	queue->intr_user = 0;
	queue->intr_active = 0;
	if (!device->online || device->removing ||
	    device->deferred_action != STORVSC_DEFER_NONE)
		rc = -ENODEV;
	else if (device->binding || device->recovering)
		rc = -EAGAIN;
	else if (!channel)
		rc = -ENODEV;
	else
		mask_channel = device->interrupt_users == 0;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (!rc && mask_channel)
		rc = vmbus_channel_mask_interrupts(channel);
	return rc;
}

static int storvsc_queue_unconfigure(struct uk_blkdev *blkdev __unused,
				     struct uk_blkdev_queue *queue)
{
	struct storvsc_lun *lun = queue->lun;
	struct storvsc_device *device = lun->controller;
	unsigned long flags;
	int rc = 0;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (storvsc_lun_active_locked(lun))
		rc = -EBUSY;
	else {
		if (queue->intr_user && device->interrupt_users)
			device->interrupt_users--;
		memset(queue, 0, sizeof(*queue));
	}
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

static int storvsc_unconfigure(struct uk_blkdev *blkdev __unused)
{
	return 0;
}

static const struct uk_blkdev_ops storvsc_blkdev_ops = {
	.get_info = storvsc_get_info,
	.dev_configure = storvsc_configure,
	.queue_get_info = storvsc_queue_get_info,
	.queue_configure = storvsc_queue_configure,
	.dev_start = storvsc_start,
	.dev_stop = storvsc_stop,
	.queue_intr_enable = storvsc_queue_intr_enable,
	.queue_intr_disable = storvsc_queue_intr_disable,
	.queue_unconfigure = storvsc_queue_unconfigure,
	.dev_unconfigure = storvsc_unconfigure,
};

static int storvsc_register_blkdev(struct storvsc_lun *lun,
				   const struct storvsc_capacity *capacity,
				   const struct storvsc_mode *mode,
				   __u32 transfer_limit)
{
	struct uk_alloc *allocator = uk_alloc_get_default();
	int rc;

	if (!allocator)
		return -ENOMEM;
	lun->blkdev.submit_one = storvsc_submit;
	lun->blkdev.finish_reqs = storvsc_finish;
	lun->blkdev.dev_ops = &storvsc_blkdev_ops;
	lun->blkdev.capabilities.sectors = (__sector)capacity->sectors;
	lun->blkdev.capabilities.ssize = capacity->sector_size;
	lun->blkdev.capabilities.ioalign = sizeof(void *);
	lun->blkdev.capabilities.mode =
		mode->read_only ? O_RDONLY : O_RDWR;
	lun->blkdev.capabilities.max_sectors_per_req =
		transfer_limit / capacity->sector_size;
#ifdef STORVSC_HOST_TEST
	rc = storvsc_host_registration_hook(
		lun->controller->index, lun->address.lun);
	if (rc)
		return rc;
#endif
	if (lun->registered)
		return 0;
	rc = uk_blkdev_drv_register(&lun->blkdev, allocator, DRIVER_NAME);
	if (rc < 0)
		return rc;
	lun->uid = (__u16)rc;
	lun->registered = 1;
	return 0;
}

static int storvsc_lun_identity_compare(const struct storvsc_lun *left,
					const struct storvsc_lun *right)
{
	int compared = memcmp(left->controller->instance_id.bytes,
			      right->controller->instance_id.bytes,
			      VMBUS_GUID_SIZE);

	if (compared)
		return compared;
	if (left->address.path_id != right->address.path_id)
		return left->address.path_id < right->address.path_id ? -1 : 1;
	if (left->address.target_id != right->address.target_id)
		return left->address.target_id < right->address.target_id ? -1 : 1;
	if (left->address.lun != right->address.lun)
		return left->address.lun < right->address.lun ? -1 : 1;
	return 0;
}

static unsigned int
storvsc_collect_mappings(struct storvsc_lun **entries,
			 unsigned int capacity, int *unresolved)
{
	unsigned long flags;
	unsigned int controller_index;
	unsigned int count = 0;
	unsigned int lun_index;

	for (controller_index = 0;
	     controller_index < CONFIG_LIBSTORVSC_MAX_DEVICES;
	     controller_index++) {
		struct storvsc_device *device =
			&storvsc_devices[controller_index];

		if (!device->initialized)
			continue;
		ukplat_spin_lock_irqsave(&device->lock, flags);
		if (unresolved &&
		    (device->binding || device->recovering ||
		     device->removing || device->fatal_error ||
		     (!device->online && device->vmbus_device) ||
		     device->deferred_action != STORVSC_DEFER_NONE))
			*unresolved = 1;
		if (!device->online || device->binding || device->removing) {
			ukplat_spin_unlock_irqrestore(&device->lock, flags);
			continue;
		}
		for (lun_index = 0;
		     lun_index < CONFIG_LIBSTORVSC_MAX_LUNS;
		     lun_index++) {
			struct storvsc_lun *lun = &device->luns[lun_index];

			if (lun->registered && lun->present && count < capacity)
				entries[count++] = lun;
		}
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
	}
	for (unsigned int i = 1; i < count; i++) {
		struct storvsc_lun *entry = entries[i];
		unsigned int insertion = i;

		while (insertion > 0 &&
		       storvsc_lun_identity_compare(entries[insertion - 1],
						     entry) > 0) {
			entries[insertion] = entries[insertion - 1];
			insertion--;
		}
		entries[insertion] = entry;
	}
	return count;
}

static int storvsc_fill_mapping_locked(
	struct storvsc_lun *lun, struct uk_storvsc_mapping *mapping)
{
	struct storvsc_device *device = lun->controller;

	memset(mapping, 0, sizeof(*mapping));
	if (!lun->registered || !lun->present || !device->online ||
	    device->binding || device->removing || !device->vmbus_device)
		return -ENOENT;
	if (lun->vpd_id.length > UK_STORVSC_VPD_ID_MAX)
		return -EOVERFLOW;
	mapping->blkdev_id = lun->uid;
	mapping->controller_index = device->index;
	mapping->channel_id = device->vmbus_device->channel_id;
	mapping->connection_id = device->vmbus_device->connection_id;
	memcpy(mapping->instance_id, device->instance_id.bytes,
	       sizeof(mapping->instance_id));
	mapping->path_id = lun->address.path_id;
	mapping->target_id = lun->address.target_id;
	mapping->lun = lun->address.lun;
	mapping->read_only = lun->media.read_only;
	mapping->sectors = lun->media.sectors;
	mapping->sector_size = lun->media.sector_size;
	mapping->vpd_length = lun->vpd_id.length;
	mapping->vpd_code_set = lun->vpd_id.code_set;
	mapping->vpd_designator_type = lun->vpd_id.designator_type;
	mapping->vpd_association = lun->vpd_id.association;
	memcpy(mapping->vpd_id, lun->vpd_id.bytes,
	       lun->vpd_id.length);
	return 0;
}

static int storvsc_copy_mapping(struct storvsc_lun *lun,
				struct uk_storvsc_mapping *mapping)
{
	struct storvsc_device *device;
	unsigned long flags;
	int rc;

	if (!lun || !mapping)
		return -EINVAL;
	device = lun->controller;
	ukplat_spin_lock_irqsave(&device->lock, flags);
	rc = storvsc_fill_mapping_locked(lun, mapping);
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

unsigned int uk_storvsc_mapping_count(void)
{
	struct storvsc_lun *entries[
		CONFIG_LIBSTORVSC_MAX_DEVICES * CONFIG_LIBSTORVSC_MAX_LUNS];

	return storvsc_collect_mappings(
		entries, CONFIG_LIBSTORVSC_MAX_DEVICES *
				 CONFIG_LIBSTORVSC_MAX_LUNS, NULL);
}

int uk_storvsc_mapping_get(unsigned int index,
			   struct uk_storvsc_mapping *mapping)
{
	struct storvsc_lun *entries[
		CONFIG_LIBSTORVSC_MAX_DEVICES * CONFIG_LIBSTORVSC_MAX_LUNS];
	unsigned int count = storvsc_collect_mappings(
		entries, CONFIG_LIBSTORVSC_MAX_DEVICES *
				 CONFIG_LIBSTORVSC_MAX_LUNS, NULL);

	if (index >= count)
		return -ENOENT;
	return storvsc_copy_mapping(entries[index], mapping);
}

int uk_storvsc_mapping_find(__u16 blkdev_id,
			    struct uk_storvsc_mapping *mapping)
{
	struct storvsc_lun *entries[
		CONFIG_LIBSTORVSC_MAX_DEVICES * CONFIG_LIBSTORVSC_MAX_LUNS];
	unsigned int count = storvsc_collect_mappings(
		entries, CONFIG_LIBSTORVSC_MAX_DEVICES *
				 CONFIG_LIBSTORVSC_MAX_LUNS, NULL);

	for (unsigned int i = 0; i < count; i++) {
		if (entries[i]->uid == blkdev_id)
			return storvsc_copy_mapping(entries[i], mapping);
	}
	return -ENOENT;
}

int uk_storvsc_inventory_get(
	struct uk_storvsc_inventory_snapshot *snapshot)
{
	struct storvsc_lun *entries[
		CONFIG_LIBSTORVSC_MAX_DEVICES * CONFIG_LIBSTORVSC_MAX_LUNS];
	__u64 before;
	__u64 after;
	unsigned int count;
	unsigned int attempt;
	int unresolved;

	if (!snapshot)
		return -EINVAL;
	memset(snapshot, 0, sizeof(*snapshot));
	for (attempt = 0; attempt < 4; attempt++) {
		before = __atomic_load_n(
			&storvsc_topology_generation, __ATOMIC_ACQUIRE);
		if (before == UINT64_MAX)
			return -EOVERFLOW;
		unresolved = storvsc_has_unresolved_offer();
		count = storvsc_collect_mappings(
			entries, CONFIG_LIBSTORVSC_MAX_DEVICES *
					 CONFIG_LIBSTORVSC_MAX_LUNS,
			&unresolved);
		after = __atomic_load_n(
			&storvsc_topology_generation, __ATOMIC_ACQUIRE);
		if (before == after) {
			if (unresolved)
				return -EAGAIN;
			snapshot->version =
				UK_STORVSC_INVENTORY_SNAPSHOT_VERSION;
			snapshot->size = sizeof(*snapshot);
			snapshot->topology_generation = before;
			snapshot->count = count;
			return 0;
		}
	}
	return -EAGAIN;
}

int uk_storvsc_inventory_pristine_empty(
	const struct uk_storvsc_inventory_snapshot *first,
	const struct uk_storvsc_inventory_snapshot *second)
{
	unsigned long flags;
	unsigned int i;
	int pristine = 0;

	if (!first || !second ||
	    first->version != UK_STORVSC_INVENTORY_SNAPSHOT_VERSION ||
	    second->version != UK_STORVSC_INVENTORY_SNAPSHOT_VERSION ||
	    first->size != sizeof(*first) ||
	    second->size != sizeof(*second) ||
	    first->reserved || first->reserved2 ||
	    second->reserved || second->reserved2 ||
	    first->count || second->count ||
	    first->topology_generation !=
		    UK_STORVSC_TOPOLOGY_PRISTINE_GENERATION ||
	    second->topology_generation !=
		    UK_STORVSC_TOPOLOGY_PRISTINE_GENERATION)
		return 0;

	ukplat_spin_lock_irqsave(&storvsc_topology_lock, flags);
	if (storvsc_storage_lifetime_observed ||
	    vmbus_storage_offer_lifetime_observed() ||
	    storvsc_topology_generation_exhausted ||
	    storvsc_topology_generation !=
		    UK_STORVSC_TOPOLOGY_PRISTINE_GENERATION ||
	    storvsc_unresolved_offer_overflow)
		goto out;
	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_DEVICES; i++)
		if (storvsc_unresolved_offers[i].active)
			goto out;
	pristine = 1;
out:
	ukplat_spin_unlock_irqrestore(&storvsc_topology_lock, flags);
	return pristine;
}

static int storvsc_fill_target_locked(
	struct storvsc_lun *lun, struct uk_storvsc_target_snapshot *snapshot)
{
	int rc;

	memset(snapshot, 0, sizeof(*snapshot));
	rc = storvsc_fill_mapping_locked(lun, &snapshot->mapping);
	if (rc)
		return rc;
	snapshot->version = UK_STORVSC_TARGET_SNAPSHOT_VERSION;
	snapshot->size = sizeof(*snapshot);
	snapshot->topology_generation = __atomic_load_n(
		&storvsc_topology_generation, __ATOMIC_ACQUIRE);
	snapshot->controller_generation =
		lun->controller->session_generation;
	snapshot->lun_generation = lun->generation;
	return 0;
}

int uk_storvsc_target_get(unsigned int index,
			  struct uk_storvsc_target_snapshot *snapshot)
{
	struct storvsc_lun *entries[
		CONFIG_LIBSTORVSC_MAX_DEVICES * CONFIG_LIBSTORVSC_MAX_LUNS];
	struct storvsc_device *device;
	unsigned long flags;
	unsigned int count;
	int rc;

	if (!snapshot)
		return -EINVAL;
	count = storvsc_collect_mappings(
		entries, CONFIG_LIBSTORVSC_MAX_DEVICES *
				 CONFIG_LIBSTORVSC_MAX_LUNS, NULL);
	if (index >= count)
		return -ENOENT;
	device = entries[index]->controller;
	ukplat_spin_lock_irqsave(&device->lock, flags);
	rc = storvsc_fill_target_locked(entries[index], snapshot);
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

static int storvsc_mapping_equal(const struct uk_storvsc_mapping *left,
				 const struct uk_storvsc_mapping *right)
{
	return memcmp(left, right, sizeof(*left)) == 0;
}

static __u64 storvsc_session_key(const struct storvsc_lun *lun)
{
	__u64 controller = lun->controller->index;
	__u64 slot = (__u64)(lun - lun->controller->luns);

	return controller << 48 | slot << 32 | lun->uid;
}

static void storvsc_fill_session(const struct storvsc_lun *lun,
				 struct uk_storvsc_session *session)
{
	memset(session, 0, sizeof(*session));
	session->version = UK_STORVSC_SESSION_VERSION;
	session->size = sizeof(*session);
	session->opaque[0] = lun->session_cookie;
	session->opaque[1] = lun->session_topology_generation;
	session->opaque[2] = lun->session_controller_generation;
	session->opaque[3] = lun->session_lun_generation;
	session->opaque[4] = storvsc_session_key(lun);
}

static int storvsc_allocate_session_cookie(__u64 *cookie)
{
	__u64 current;

	if (__atomic_load_n(
		    &storvsc_session_cookie_exhausted, __ATOMIC_ACQUIRE))
		return -EOVERFLOW;
	current = __atomic_load_n(
		&storvsc_session_cookie, __ATOMIC_RELAXED);
	for (;;) {
		if (current == UINT64_MAX) {
			__atomic_store_n(
				&storvsc_session_cookie_exhausted, 1,
				__ATOMIC_RELEASE);
			return -EOVERFLOW;
		}
		if (__atomic_compare_exchange_n(
			    &storvsc_session_cookie, &current, current + 1, 0,
			    __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
			*cookie = current + 1;
			return 0;
		}
	}
}

static int storvsc_session_lock(
	const struct uk_storvsc_session *session,
	struct storvsc_device **device_out, struct storvsc_lun **lun_out,
	unsigned long *flags)
{
	struct storvsc_device *device;
	struct storvsc_lun *lun;
	unsigned int controller;
	unsigned int slot;
	__u64 key;

	if (!session ||
	    session->version != UK_STORVSC_SESSION_VERSION ||
	    session->size != sizeof(*session) || session->reserved ||
	    !session->opaque[0])
		return -EINVAL;
	key = session->opaque[4];
	controller = (unsigned int)(key >> 48);
	slot = (unsigned int)((key >> 32) & 0xffffU);
	if ((key & 0xffff0000ULL) ||
	    controller >= CONFIG_LIBSTORVSC_MAX_DEVICES ||
	    slot >= CONFIG_LIBSTORVSC_MAX_LUNS)
		return -EINVAL;
	device = &storvsc_devices[controller];
	lun = &device->luns[slot];
	ukplat_spin_lock_irqsave(&device->lock, *flags);
	if (!device->online || device->binding || device->removing ||
	    device->recovering || !lun->present || !lun->registered ||
	    lun->uid != (__u16)key ||
	    lun->session_state == STORVSC_SESSION_NONE ||
	    lun->session_cookie != session->opaque[0] ||
	    __atomic_load_n(&storvsc_topology_generation,
			    __ATOMIC_ACQUIRE) != session->opaque[1] ||
	    device->session_generation != session->opaque[2] ||
	    lun->generation != session->opaque[3] ||
	    lun->session_topology_generation != session->opaque[1] ||
	    lun->session_controller_generation != session->opaque[2] ||
	    lun->session_lun_generation != session->opaque[3]) {
		ukplat_spin_unlock_irqrestore(&device->lock, *flags);
		return -ESTALE;
	}
	*device_out = device;
	*lun_out = lun;
	return 0;
}

int uk_storvsc_session_begin_read(
	const struct uk_storvsc_target_snapshot *snapshot,
	struct uk_storvsc_session *session)
{
	struct uk_storvsc_mapping current;
	struct storvsc_device *device;
	struct storvsc_lun *lun = NULL;
	unsigned long flags;
	__u64 cookie;
	unsigned int i;
	int rc;

	if (session)
		memset(session, 0, sizeof(*session));
	if (!storvsc_guarded_io_enabled)
		return -ENOTSUP;
	if (!snapshot || !session ||
	    snapshot->version != UK_STORVSC_TARGET_SNAPSHOT_VERSION ||
	    snapshot->size != sizeof(*snapshot) || snapshot->reserved ||
	    !snapshot->topology_generation ||
	    !snapshot->controller_generation || !snapshot->lun_generation ||
	    snapshot->topology_generation == UINT64_MAX ||
	    snapshot->controller_generation == UINT64_MAX ||
	    snapshot->lun_generation == UINT64_MAX ||
	    !snapshot->mapping.vpd_length ||
	    snapshot->mapping.controller_index >=
		    CONFIG_LIBSTORVSC_MAX_DEVICES)
		return -EINVAL;
	device = &storvsc_devices[snapshot->mapping.controller_index];
	ukplat_spin_lock_irqsave(&device->lock, flags);
	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_LUNS; i++) {
		if (device->luns[i].registered &&
		    device->luns[i].uid == snapshot->mapping.blkdev_id) {
			lun = &device->luns[i];
			break;
		}
	}
	if (!lun) {
		rc = -ENOENT;
		goto out;
	}
	if (snapshot->topology_generation !=
		    __atomic_load_n(&storvsc_topology_generation,
				    __ATOMIC_ACQUIRE) ||
	    snapshot->controller_generation != device->session_generation ||
	    snapshot->lun_generation != lun->generation) {
		rc = -ESTALE;
		goto out;
	}
	if (lun->session_state != STORVSC_SESSION_NONE &&
	    lun->session_topology_generation !=
		    snapshot->topology_generation) {
		lun->session_state = STORVSC_SESSION_NONE;
		lun->session_cookie = 0;
		lun->session_topology_generation = 0;
		lun->session_controller_generation = 0;
		lun->session_lun_generation = 0;
		lun->session_cdb_size = UK_STORVSC_CDB_AUTO;
	}
	if (lun->session_state != STORVSC_SESSION_NONE ||
	    storvsc_lun_active_count_locked(device, lun)) {
		rc = -EBUSY;
		goto out;
	}
	rc = storvsc_fill_mapping_locked(lun, &current);
	if (rc)
		goto out;
	if (!storvsc_mapping_equal(&current, &snapshot->mapping)) {
		rc = -ESTALE;
		goto out;
	}
	rc = storvsc_allocate_session_cookie(&cookie);
	if (rc)
		goto out;
	lun->session_cookie = cookie;
	lun->session_topology_generation = snapshot->topology_generation;
	lun->session_controller_generation = device->session_generation;
	lun->session_lun_generation = lun->generation;
	lun->session_state = STORVSC_SESSION_READ;
	lun->session_cdb_size = UK_STORVSC_CDB_AUTO;
	storvsc_fill_session(lun, session);
	rc = 0;
out:
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

int uk_storvsc_session_authorize_write(struct uk_storvsc_session *session)
{
	struct storvsc_lun *expected = NULL;
	struct storvsc_device *device;
	struct storvsc_lun *lun;
	unsigned long flags;
	int rc;

	if (!storvsc_guarded_io_enabled)
		return -ENOTSUP;
	rc = storvsc_session_lock(session, &device, &lun, &flags);
	if (rc)
		return rc;
	if (lun->media.read_only) {
		rc = -EROFS;
		goto out;
	}
	if (lun->session_state != STORVSC_SESSION_READ) {
		rc = -EACCES;
		goto out;
	}
	if (storvsc_lun_active_count_locked(device, lun)) {
		rc = -EBUSY;
		goto out;
	}
	if (!__atomic_compare_exchange_n(
		    &storvsc_write_lun, &expected, lun, 0,
		    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
		rc = -EBUSY;
		goto out;
	}
	lun->session_state = STORVSC_SESSION_WRITE;
	rc = 0;
out:
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

int uk_storvsc_session_set_cdb(struct uk_storvsc_session *session,
			       __u8 cdb_size)
{
	struct storvsc_device *device;
	struct storvsc_lun *lun;
	unsigned long flags;
	int rc;

	if (cdb_size != UK_STORVSC_CDB_AUTO &&
	    cdb_size != UK_STORVSC_CDB_10 &&
	    cdb_size != UK_STORVSC_CDB_16)
		return -EINVAL;
	if (!storvsc_guarded_io_enabled)
		return -ENOTSUP;
	rc = storvsc_session_lock(session, &device, &lun, &flags);
	if (rc)
		return rc;
	if (lun->session_state != STORVSC_SESSION_WRITE ||
	    storvsc_lun_active_count_locked(device, lun))
		rc = -EBUSY;
	else {
		lun->session_cdb_size = cdb_size;
		rc = 0;
	}
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

int uk_storvsc_session_validate(
	const struct uk_storvsc_session *session,
	struct uk_storvsc_target_snapshot *snapshot)
{
	struct storvsc_device *device;
	struct storvsc_lun *lun;
	unsigned long flags;
	int rc;

	if (!snapshot)
		return -EINVAL;
	memset(snapshot, 0, sizeof(*snapshot));
	if (!storvsc_guarded_io_enabled)
		return -ENOTSUP;
	rc = storvsc_session_lock(session, &device, &lun, &flags);
	if (rc)
		return rc;
	rc = storvsc_fill_target_locked(lun, snapshot);
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

int uk_storvsc_session_end(struct uk_storvsc_session *session)
{
	struct storvsc_device *device;
	struct storvsc_lun *lun;
	unsigned long flags;
	int rc;

	if (!storvsc_guarded_io_enabled)
		return -ENOTSUP;
	rc = storvsc_session_lock(session, &device, &lun, &flags);
	if (rc)
		return rc;
	if (storvsc_lun_active_count_locked(device, lun)) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -EBUSY;
	}
	if (lun->session_state == STORVSC_SESSION_WRITE)
		storvsc_release_write_session(lun);
	lun->session_state = STORVSC_SESSION_NONE;
	lun->session_cookie = 0;
	lun->session_topology_generation = 0;
	lun->session_controller_generation = 0;
	lun->session_lun_generation = 0;
	lun->session_cdb_size = UK_STORVSC_CDB_AUTO;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	memset(session, 0, sizeof(*session));
	return 0;
}

static int storvsc_guid_equal(const struct vmbus_guid *left,
			      const struct vmbus_guid *right)
{
	return memcmp(left->bytes, right->bytes, VMBUS_GUID_SIZE) == 0;
}

static struct storvsc_device *
storvsc_find_controller(struct vmbus_device *vmbus_device)
{
	unsigned int i;

	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_DEVICES; i++) {
		struct storvsc_device *device = &storvsc_devices[i];

		if (device->vmbus_device == vmbus_device)
			return device;
		if (device->identity_valid &&
		    storvsc_guid_equal(&device->instance_id,
				       &vmbus_device->instance_id))
			return device;
	}
	return NULL;
}

static struct storvsc_device *
storvsc_allocate_controller(struct vmbus_device *vmbus_device);

static int
storvsc_reserve_controller(struct vmbus_device *vmbus_device,
			   struct storvsc_device **device_out, int *allocated)
{
	struct storvsc_device *device;
	unsigned long topology_flags;
	unsigned long device_flags;
	int rc = 0;

	*allocated = 0;
	*device_out = NULL;
	ukplat_spin_lock_irqsave(&storvsc_topology_lock, topology_flags);
	device = storvsc_find_controller(vmbus_device);
	if (!device) {
		device = storvsc_allocate_controller(vmbus_device);
		*allocated = device != NULL;
	}
	if (!device) {
		rc = -ENOSPC;
		goto out;
	}
	*device_out = device;
	ukplat_spin_lock_irqsave(&device->lock, device_flags);
	if (device->deferred_action != STORVSC_DEFER_NONE ||
	    device->finish_active || device->notify_active)
		rc = -EAGAIN;
	else if (device->binding || device->online || device->removing ||
		 device->recovering || device->deferred_running ||
		 (device->vmbus_device &&
		  device->vmbus_device != vmbus_device &&
		  storvsc_channel_get(device)))
		rc = -ENOSPC;
	else if (device->epoch == UINT32_MAX)
		rc = -ENOSPC;
	else
		device->binding = 1;
	ukplat_spin_unlock_irqrestore(&device->lock, device_flags);
	if (rc && *allocated) {
		memset(&device->instance_id, 0, sizeof(device->instance_id));
		device->identity_valid = 0;
	}
out:
	ukplat_spin_unlock_irqrestore(&storvsc_topology_lock, topology_flags);
	return rc;
}

static void
storvsc_release_controller_identity(struct storvsc_device *device)
{
	unsigned long topology_flags;
	unsigned long device_flags;

	ukplat_spin_lock_irqsave(&storvsc_topology_lock, topology_flags);
	ukplat_spin_lock_irqsave(&device->lock, device_flags);
	memset(&device->instance_id, 0, sizeof(device->instance_id));
	device->identity_valid = 0;
	device->binding = 0;
	ukplat_spin_unlock_irqrestore(&device->lock, device_flags);
	ukplat_spin_unlock_irqrestore(&storvsc_topology_lock, topology_flags);
}

static struct storvsc_device *
storvsc_allocate_controller(struct vmbus_device *vmbus_device)
{
	unsigned int i;
	unsigned int lun_index;

	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_DEVICES; i++) {
		struct storvsc_device *device = &storvsc_devices[i];

		if (device->identity_valid)
			continue;
		if (!device->initialized) {
			ukarch_spin_init(&device->lock);
			ukarch_spin_init(&device->receive_lock);
			device->initialized = 1;
			device->index = (__u16)i;
			for (lun_index = 0;
			     lun_index < CONFIG_LIBSTORVSC_MAX_LUNS;
			     lun_index++) {
				device->luns[lun_index].controller = device;
				device->luns[lun_index].queue.lun =
					&device->luns[lun_index];
			}
		}
		device->instance_id = vmbus_device->instance_id;
		device->identity_valid = 1;
		return device;
	}
	return NULL;
}

static struct storvsc_lun *
storvsc_find_lun(struct storvsc_device *device,
		 const struct storvsc_address *address)
{
	struct storvsc_lun *free_lun = NULL;
	unsigned int i;

	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_LUNS; i++) {
		struct storvsc_lun *lun = &device->luns[i];

		if ((lun->registered || lun->present) &&
		    lun->address.path_id == address->path_id &&
		    lun->address.target_id == address->target_id &&
		    lun->address.lun == address->lun)
			return lun;
		if (!free_lun && !lun->registered && !lun->present)
			free_lun = lun;
	}
	return free_lun;
}

static void storvsc_mark_luns_absent(struct storvsc_device *device)
{
	unsigned int i;

	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_LUNS; i++) {
		device->luns[i].present = 0;
		device->luns[i].completion_pending = 0;
		device->luns[i].queue.intr_active = 0;
	}
}

static int storvsc_add_device(struct vmbus_device *vmbus_device)
{
	struct storvsc_device *device;
	struct storvsc_capacity capacity;
	struct storvsc_mode mode;
	struct storvsc_vpd_id vpd_id;
	struct vmbus_device_bind_token bind_token;
	__u8 open_data[24] = { 0 };
	unsigned long flags;
	size_t i;
	__u32 host_limit;
	__u32 config_limit;
	__u32 transfer_limit;
	__u32 lun_transfer_limit;
	int first_error = 0;
	int registered = 0;
	int allocated_identity = 0;
	int identity_committed = 0;
	int rc;

	if (!vmbus_device)
		return -EINVAL;
	storvsc_note_storage_lifetime();
	if (vmbus_device->subchannel_index)
		return -EINVAL;
	rc = vmbus_device_bind_epoch(vmbus_device, &bind_token);
	if (rc)
		return rc;
	/* This offer remains inventory uncertainty until discovery clears it. */
	storvsc_note_unresolved_offer(
		&vmbus_device->instance_id,
		vmbus_device->channel_id,
		bind_token.device_generation, -EAGAIN);
	rc = storvsc_reserve_controller(vmbus_device, &device,
					 &allocated_identity);
	if (rc) {
		storvsc_note_unresolved_offer(
			&vmbus_device->instance_id,
			vmbus_device->channel_id,
			bind_token.device_generation, rc);
		if (rc == -EAGAIN)
			return vmbus_device_bind_retry(
				vmbus_device, &bind_token);
		if (device)
			return rc;
		uk_pr_err(DRIVER_NAME
			  ": controller pool exhausted for relid=%"PRIu32"\n",
			  vmbus_device->channel_id);
		return -ENOSPC;
	}
	ukplat_spin_lock_irqsave(&device->lock, flags);
	storvsc_invalidate_sessions_locked(device);
	device->epoch++;
	device->vmbus_device = vmbus_device;
	storvsc_channel_set(device, NULL);
	device->online = 0;
	device->removing = 0;
	device->recovering = 0;
	device->reset_done = 0;
	device->fatal_error = 0;
	device->active_sends = 0;
	device->interrupt_users = 0;
	device->finish_active = 0;
	device->notify_active = 0;
	device->notifying_lun = NULL;
	device->deferred_action = STORVSC_DEFER_NONE;
	device->deferred_running = 0;
	device->deferred_wait_vmbus = 0;
	device->deferred_close_busy = 0;
	device->deferred_close_required = 0;
	device->deferred_close_attempts = 0;
	device->deferred_error = 0;
	device->deferred_channel = NULL;
	device->deferred_vmbus_epoch = 0;
	device->deferred_close_deadline = 0;
	memset(device->bindings, 0, sizeof(device->bindings));
	storvsc_mark_luns_absent(device);
	rc = storvsc_core_initialize(device->core, device->epoch,
				      CONFIG_LIBSTORVSC_QUEUE_DEPTH);
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (rc)
		goto failed;

	rc = vmbus_channel_open(vmbus_device,
		CONFIG_LIBSTORVSC_TX_RING_PAGES,
		CONFIG_LIBSTORVSC_RX_RING_PAGES,
		open_data, sizeof(open_data));
	if (rc)
		goto failed;
	storvsc_channel_set(device, vmbus_device->channel);
	if (!storvsc_channel_get(device)) {
		rc = -ENODEV;
		goto failed;
	}
	rc = storvsc_send_initialization(device);
	if (rc)
		goto failed;
	host_limit = storvsc_core_host_max_transfer(device->core);
	config_limit =
		(CONFIG_LIBSTORVSC_MAX_TRANSFER_PAGES - 1) *
		STORVSC_PAGE_SIZE;
	transfer_limit = host_limit < config_limit ?
		host_limit : config_limit;
	rc = storvsc_core_set_transfer_limit(device->core, transfer_limit);
	if (rc)
		goto failed;
	rc = storvsc_enumerate_luns(device);
	if (rc)
		goto failed;
	if (device->lun_count > CONFIG_LIBSTORVSC_MAX_LUNS) {
		uk_pr_err(DRIVER_NAME
			  ": controller%u reports %zu LUNs, capacity is %u\n",
			  device->index, device->lun_count,
			  CONFIG_LIBSTORVSC_MAX_LUNS);
	}
	for (i = 0; i < device->lun_count; i++) {
		struct storvsc_address *address = &device->lun_addresses[i];
		struct storvsc_lun *lun = storvsc_find_lun(device, address);
		int was_registered;

		if (!lun) {
			if (!first_error)
				first_error = -ENOSPC;
			uk_pr_err(DRIVER_NAME
				  ": controller%u LUN pool exhausted\n",
				  device->index);
			continue;
		}
		rc = storvsc_discover_lun(device, address, &capacity, &mode,
					  &vpd_id);
		if (rc) {
			if (!first_error)
				first_error = rc;
			uk_pr_err(DRIVER_NAME
				  ": controller%u %u:%u:%u discovery failed: %d\n",
				  device->index, address->path_id,
				  address->target_id, address->lun, rc);
			continue;
		}
		if (!capacity.sectors || capacity.sectors > SIZE_MAX ||
		    transfer_limit < capacity.sector_size) {
			if (!first_error)
				first_error = -EOVERFLOW;
			continue;
		}
		lun_transfer_limit = transfer_limit -
			transfer_limit % capacity.sector_size;
		lun->address = *address;
		lun->media.sectors = capacity.sectors;
		lun->media.sector_size = capacity.sector_size;
		lun->media.read_only = mode.read_only;
		memset(lun->media.reserved, 0,
		       sizeof(lun->media.reserved));
		lun->vpd_id = vpd_id;
		if (lun->generation == UINT64_MAX) {
			if (!first_error)
				first_error = -EOVERFLOW;
			continue;
		}
		lun->generation++;
		was_registered = lun->registered;
		rc = storvsc_register_blkdev(lun, &capacity, &mode,
					      lun_transfer_limit);
		if (rc) {
			if (!first_error)
				first_error = rc;
			continue;
		}
		if (!was_registered)
			identity_committed = 1;
		lun->present = 1;
		registered++;
		uk_pr_info(DRIVER_NAME
			   ": controller%u relid=%"PRIu32" blkdev%u "
			   "%u:%u:%u, %"PRIu64" sectors of %u bytes%s\n",
			   device->index, vmbus_device->channel_id, lun->uid,
			   address->path_id, address->target_id, address->lun,
			   capacity.sectors, capacity.sector_size,
			   mode.read_only ? ", read-only" : "");
	}
	if (!registered && (!storvsc_lun_discovery_enabled ||
			    device->lun_count)) {
		rc = first_error ? first_error : -ENODEV;
		goto failed_registered;
	}
	if (!registered)
		uk_pr_info(DRIVER_NAME
			   ": controller%u relid=%"PRIu32
			   " bound with verified empty LUN inventory\n",
			   device->index, vmbus_device->channel_id);
	if (first_error) {
		storvsc_note_unresolved_offer(
			&vmbus_device->instance_id,
			vmbus_device->channel_id,
			bind_token.device_generation, first_error);
		uk_pr_err(DRIVER_NAME
			  ": controller%u inventory unresolved: %d\n",
			  device->index, first_error);
	} else {
		storvsc_clear_unresolved_offer(
			&vmbus_device->instance_id,
			vmbus_device->channel_id,
			bind_token.device_generation);
	}
	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->online = 1;
	storvsc_advance_topology_generation();
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
#ifdef STORVSC_HOST_TEST
	storvsc_host_binding_publish_hook(device->index);
#endif
	vmbus_channel_set_callback(storvsc_channel_get(device),
				   storvsc_channel_callback, device);
	rc = storvsc_start_timeout_worker(device);
	if (rc)
		goto failed_registered;
	rc = storvsc_rearm_interrupts(device);
	if (rc)
		goto failed_registered;
	ukplat_spin_lock_irqsave(&device->lock, flags);
	storvsc_advance_topology_generation();
	device->binding = 0;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	storvsc_notify_pending(device);
	if (vmbus_channel_poll(storvsc_channel_get(device)) > 0)
		(void)storvsc_receive_async(device, 1);
	uk_pr_info(DRIVER_NAME ": controller%u VMStor %u.%u, %d LUNs\n",
		   device->index, storvsc_core_version(device->core) >> 8,
		   storvsc_core_version(device->core) & 0xff, registered);
	return 0;

failed_registered:
	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->online = 0;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (storvsc_channel_get(device))
		vmbus_channel_set_callback(storvsc_channel_get(device),
					   NULL, NULL);
failed:
	storvsc_note_unresolved_offer(
		&vmbus_device->instance_id,
		vmbus_device->channel_id,
		bind_token.device_generation, rc);
	if (storvsc_channel_get(device))
		(void)storvsc_close_channel(device);
	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->online = 0;
	if (!allocated_identity || identity_committed)
		device->binding = 0;
	device->vmbus_device = NULL;
	storvsc_mark_luns_absent(device);
	storvsc_channel_set(device, NULL);
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (allocated_identity && !identity_committed)
		storvsc_release_controller_identity(device);
	return rc;
}

static int storvsc_deferred_try_run(struct storvsc_device *device)
{
	struct storvsc_event events[CONFIG_LIBSTORVSC_QUEUE_DEPTH];
	struct uk_blkreq *requests[CONFIG_LIBSTORVSC_QUEUE_DEPTH];
	struct vmbus_channel *channel;
	unsigned long flags;
	unsigned int count = 0;
	unsigned int action;
	unsigned int close_attempts = 0;
	unsigned int busy_retry_limit = STORVSC_BUSY_RETRY_LIMIT;
	__u64 busy_retry_timeout_ns = STORVSC_BUSY_RETRY_TIMEOUT_NS;
	__u64 now;
	__u64 quiesce_epoch = vmbus_connection_quiesce_epoch();
	int error;
	int rc = 0;

#ifdef STORVSC_HOST_TEST
	busy_retry_limit = storvsc_busy_retry_limit;
	busy_retry_timeout_ns = storvsc_busy_retry_timeout_ns;
	storvsc_host_deferred_epoch_sample_hook(quiesce_epoch);
#endif
	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (device->deferred_action == STORVSC_DEFER_NONE) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return 0;
	}
	if (device->deferred_wait_vmbus) {
		/* Pair the proof read with the locked obligation snapshot. */
		if (vmbus_connection_quiesce_epoch() ==
		    device->deferred_vmbus_epoch) {
			ukplat_spin_unlock_irqrestore(&device->lock, flags);
			return -EINPROGRESS;
		}
		device->deferred_wait_vmbus = 0;
		device->deferred_close_busy = 0;
		device->deferred_close_required = 0;
		device->deferred_close_attempts = 0;
		device->deferred_channel = NULL;
		device->deferred_close_deadline = 0;
	}
	if (device->deferred_running || device->active_sends ||
	    device->finish_active || device->notify_active) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -EAGAIN;
	}
	if (device->deferred_close_required &&
	    !device->deferred_channel) {
		device->deferred_vmbus_epoch = quiesce_epoch;
		device->deferred_wait_vmbus = 1;
		device->deferred_close_busy = 0;
		device->deferred_close_attempts = 0;
		device->deferred_close_deadline = 0;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		(void)vmbus_connection_fail();
		return -EINPROGRESS;
	}
	device->deferred_running = 1;
	device->deferred_close_busy = 0;
	channel = device->deferred_close_required ?
		device->deferred_channel : NULL;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);

	if (channel)
		rc = storvsc_close_channel_pointer(channel, &close_attempts);
	if (rc && rc != -ENODEV && rc != -ECANCELED) {
		quiesce_epoch = vmbus_connection_quiesce_epoch();
		now = ukplat_monotonic_clock();
		ukplat_spin_lock_irqsave(&device->lock, flags);
		action = device->deferred_action;
		if (rc == -EBUSY) {
			if (close_attempts >
			    UINT16_MAX - device->deferred_close_attempts)
				device->deferred_close_attempts = UINT16_MAX;
			else
				device->deferred_close_attempts +=
					(__u16)close_attempts;
			if (!device->deferred_close_deadline)
				device->deferred_close_deadline =
					now > UINT64_MAX -
						busy_retry_timeout_ns ?
					UINT64_MAX :
					now + busy_retry_timeout_ns;
			if (action != STORVSC_DEFER_REMOVE &&
			    device->deferred_close_attempts <
				    busy_retry_limit &&
			    now < device->deferred_close_deadline) {
				device->deferred_close_busy = 1;
				device->deferred_running = 0;
				ukplat_spin_unlock_irqrestore(
					&device->lock, flags);
				return -EINPROGRESS;
			}
		}
		/*
		 * A failed guest close does not prove that StorVSP released
		 * GPA-direct buffers. This remains true if REMOVE upgraded the
		 * action while close was in flight: clear_devices() precedes
		 * host-confirmed UNLOAD. Require a connection-generation proof.
		 */
		device->deferred_vmbus_epoch = quiesce_epoch;
		device->deferred_wait_vmbus = 1;
		device->deferred_close_busy = 0;
		device->deferred_running = 0;
		device->deferred_close_attempts = 0;
		device->deferred_channel = NULL;
		device->deferred_close_deadline = 0;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		(void)vmbus_connection_fail();
		return -EINPROGRESS;
	}

	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->deferred_close_required = 0;
	device->deferred_close_attempts = 0;
	device->deferred_channel = NULL;
	device->deferred_close_deadline = 0;
	action = device->deferred_action;
	error = device->deferred_error;
	(void)storvsc_core_cancel_all(device->core, error);
	while (count < CONFIG_LIBSTORVSC_QUEUE_DEPTH) {
		if (storvsc_take_completion_locked(device, &requests[count],
						   &events[count]))
			break;
		count++;
	}
	device->timeout_stop = 1;
	if (action == STORVSC_DEFER_REMOVE) {
		device->vmbus_device = NULL;
		device->interrupt_users = 0;
		storvsc_mark_luns_absent(device);
	}
	ukplat_spin_unlock_irqrestore(&device->lock, flags);

	for (unsigned int i = 0; i < count; i++) {
		if (!requests[i])
			continue;
		requests[i]->result = events[i].error;
		uk_blkreq_finished(requests[i]);
		if (requests[i]->cb)
			requests[i]->cb(requests[i],
					requests[i]->cb_cookie);
	}
	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->deferred_action = STORVSC_DEFER_NONE;
	device->deferred_running = 0;
	device->deferred_wait_vmbus = 0;
	device->deferred_close_busy = 0;
	device->deferred_close_required = 0;
	device->deferred_close_attempts = 0;
	device->deferred_error = 0;
	device->deferred_channel = NULL;
	device->deferred_vmbus_epoch = 0;
	device->deferred_close_deadline = 0;
	device->recovering = 0;
	device->removing = 0;
	device->notify_active = 0;
	device->notifying_lun = NULL;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	vmbus_device_bind_ready();
	storvsc_wake_timeout(device);
	return 1;
}

static void
storvsc_offer_removed(const struct vmbus_offer_identity *offer)
{
	storvsc_note_storage_lifetime();
	if (!offer || !offer->generation)
		return;
	storvsc_clear_unresolved_offer(
		&offer->instance_id, offer->channel_id,
		offer->generation);
}

static void storvsc_remove_device(struct vmbus_device *vmbus_device)
{
	struct storvsc_device *device;
	unsigned long topology_flags;
	unsigned long flags;

	ukplat_spin_lock_irqsave(&storvsc_topology_lock, topology_flags);
	device = storvsc_find_controller(vmbus_device);
	ukplat_spin_unlock_irqrestore(&storvsc_topology_lock, topology_flags);
	if (!device)
		return;
	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (device->vmbus_device != vmbus_device) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return;
	}
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	storvsc_deferred_schedule(device, STORVSC_DEFER_REMOVE, -ENODEV);
	if (storvsc_wait_active_sends(device))
		return;
	storvsc_wait_finish(device);
	(void)storvsc_deferred_try_run(device);
	if (!storvsc_deferred_pending(device))
		storvsc_stop_timeout_worker(device);
}

static struct vmbus_driver storvsc_driver = {
	.name = DRIVER_NAME,
	.device_ids = storvsc_device_ids,
	.add_dev = storvsc_add_device,
	.remove_dev = storvsc_remove_device,
	.offer_removed = storvsc_offer_removed,
};

VMBUS_DRIVER_REGISTER(&storvsc_driver);

#ifdef STORVSC_HOST_TEST
struct vmbus_driver *storvsc_host_driver(void)
{
	return &storvsc_driver;
}

struct uk_blkdev *storvsc_host_blkdev(void)
{
	return &storvsc_devices[0].luns[0].blkdev;
}

struct uk_blkdev *storvsc_host_blkdev_at(unsigned int controller,
					 unsigned int lun_slot)
{
	if (controller >= CONFIG_LIBSTORVSC_MAX_DEVICES ||
	    lun_slot >= CONFIG_LIBSTORVSC_MAX_LUNS)
		return NULL;
	return &storvsc_devices[controller].luns[lun_slot].blkdev;
}

struct uk_blkdev *storvsc_host_blkdev_address(unsigned int controller,
					      __u8 lun_id)
{
	unsigned int i;

	if (controller >= CONFIG_LIBSTORVSC_MAX_DEVICES)
		return NULL;
	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_LUNS; i++) {
		struct storvsc_lun *lun = &storvsc_devices[controller].luns[i];

		if (lun->present && lun->address.lun == lun_id)
			return &lun->blkdev;
	}
	return NULL;
}

int storvsc_host_controller_online(unsigned int controller)
{
	if (controller >= CONFIG_LIBSTORVSC_MAX_DEVICES)
		return 0;
	return storvsc_devices[controller].online;
}

size_t storvsc_host_lun_count(void)
{
	return storvsc_devices[0].lun_count;
}

void storvsc_host_set_lun_discovery(int enabled)
{
	storvsc_lun_discovery_enabled = !!enabled;
}

void storvsc_host_set_guarded_io(int enabled)
{
	unsigned long flags;
	unsigned int i;

	storvsc_guarded_io_enabled = !!enabled;
	for (i = 0; i < CONFIG_LIBSTORVSC_MAX_DEVICES; i++) {
		if (!storvsc_devices[i].initialized)
			continue;
		ukplat_spin_lock_irqsave(&storvsc_devices[i].lock, flags);
		storvsc_invalidate_sessions_locked(&storvsc_devices[i]);
		ukplat_spin_unlock_irqrestore(&storvsc_devices[i].lock, flags);
	}
}

int storvsc_host_lun_address(size_t index, struct storvsc_address *address)
{
	if (!address || index >= storvsc_devices[0].lun_count)
		return -EINVAL;
	*address = storvsc_devices[0].lun_addresses[index];
	return 0;
}

int storvsc_host_receive(void)
{
	return storvsc_receive_async(&storvsc_devices[0], 1);
}

int storvsc_host_reset_timed_out_io(void)
{
	return storvsc_reset_timed_out_io(&storvsc_devices[0]);
}

int storvsc_host_reset_controller(unsigned int controller)
{
	if (controller >= CONFIG_LIBSTORVSC_MAX_DEVICES)
		return -EINVAL;
	return storvsc_reset_timed_out_io(&storvsc_devices[controller]);
}

int storvsc_host_start_timeout_worker(void)
{
	return storvsc_start_timeout_worker(&storvsc_devices[0]);
}

void storvsc_host_stop_timeout_worker(void)
{
	storvsc_stop_timeout_worker(&storvsc_devices[0]);
}

void storvsc_host_set_send_wait_limit(unsigned int limit)
{
	storvsc_send_wait_limit = limit ? limit : 1;
}

void storvsc_host_set_busy_retry(unsigned int limit, __u64 timeout_ns)
{
	storvsc_busy_retry_limit = limit ? limit : 1;
	storvsc_busy_retry_timeout_ns = timeout_ns ? timeout_ns : 1;
}

int storvsc_host_deferred_action(void)
{
	struct storvsc_device *device = &storvsc_devices[0];
	unsigned long flags;
	int action;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	action = device->deferred_action;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return action;
}

int storvsc_host_online(void)
{
	struct storvsc_device *device = &storvsc_devices[0];
	unsigned long flags;
	int online;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	online = device->online;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return online;
}

int storvsc_host_has_channel(void)
{
	return storvsc_channel_get(&storvsc_devices[0]) != NULL;
}

int storvsc_host_worker_present(void)
{
	struct storvsc_device *device = &storvsc_devices[0];
	unsigned long flags;
	int present;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	present = device->timeout_thread != NULL;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return present;
}

int storvsc_host_deferred_wait_vmbus(void)
{
	struct storvsc_device *device = &storvsc_devices[0];
	unsigned long flags;
	int waiting;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	waiting = device->deferred_wait_vmbus;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return waiting;
}

int storvsc_host_deferred_close_busy(void)
{
	struct storvsc_device *device = &storvsc_devices[0];
	unsigned long flags;
	int busy;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	busy = device->deferred_close_busy;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return busy;
}

int storvsc_host_deferred_close_required(void)
{
	struct storvsc_device *device = &storvsc_devices[0];
	unsigned long flags;
	int required;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	required = device->deferred_close_required;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return required;
}

unsigned int storvsc_host_deferred_close_attempts(void)
{
	struct storvsc_device *device = &storvsc_devices[0];
	unsigned long flags;
	unsigned int attempts;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	attempts = device->deferred_close_attempts;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return attempts;
}

__u64 storvsc_host_deferred_vmbus_epoch(void)
{
	struct storvsc_device *device = &storvsc_devices[0];
	unsigned long flags;
	__u64 epoch;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	epoch = device->deferred_vmbus_epoch;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return epoch;
}

int storvsc_host_update_deferred_vmbus_epoch(__u64 expected,
					     __u64 replacement)
{
	struct storvsc_device *device = &storvsc_devices[0];
	unsigned long flags;
	int rc = 0;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (!replacement || !device->deferred_wait_vmbus ||
	    device->deferred_vmbus_epoch != expected)
		rc = -EINVAL;
	else
		device->deferred_vmbus_epoch = replacement;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

int storvsc_host_request_bound(struct uk_blkreq *request)
{
	struct storvsc_device *device = &storvsc_devices[0];
	unsigned long flags;
	int bound = 0;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	for (unsigned int i = 0; i < CONFIG_LIBSTORVSC_QUEUE_DEPTH; i++)
		if (device->bindings[i].req == request) {
			bound = 1;
			break;
		}
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return bound;
}

__u64 storvsc_host_request_pfn(struct uk_blkreq *request,
			       unsigned int index)
{
	struct storvsc_device *device = &storvsc_devices[0];
	unsigned long flags;
	__u64 pfn = 0;

	if (index >= CONFIG_LIBSTORVSC_MAX_TRANSFER_PAGES)
		return 0;
	ukplat_spin_lock_irqsave(&device->lock, flags);
	for (unsigned int i = 0; i < CONFIG_LIBSTORVSC_QUEUE_DEPTH; i++)
		if (device->bindings[i].req == request) {
			pfn = device->bindings[i].pfns[index];
			break;
		}
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return pfn;
}

void storvsc_host_force_timeout(void)
{
	struct storvsc_device *device = &storvsc_devices[0];
	unsigned long flags;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	for (unsigned int i = 0; i < CONFIG_LIBSTORVSC_QUEUE_DEPTH; i++)
		if (device->bindings[i].id)
			device->fatal_error = -ETIMEDOUT;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	storvsc_wake_timeout(device);
}
#endif
