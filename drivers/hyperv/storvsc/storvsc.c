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
#include <uk/thread.h>
#include <uk/vmbus.h>

#include "storvsc_core.h"

#define DRIVER_NAME			"hyperv-storvsc"
#define STORVSC_PAGE_SIZE		4096U
#define STORVSC_RX_DESCRIPTOR_SIZE	1024U
#define STORVSC_INQUIRY_SIZE		96U
#define STORVSC_CAPACITY16_SIZE		32U
#define STORVSC_MODE_SENSE_SIZE		192U
#define STORVSC_WORKER_SLEEP_NS		1000000ULL
#define STORVSC_STOP_WAIT_LIMIT		2000U
#define STORVSC_CLOSE_RETRY_LIMIT	2000U
#define STORVSC_SEND_WAIT_LIMIT		2000U
#define STORVSC_CONTROL_TIMEOUT_NS	\
	((__u64)CONFIG_LIBSTORVSC_CONTROL_TIMEOUT_MS * 1000000ULL)
#define STORVSC_REQUEST_TIMEOUT_NS	\
	((__u64)CONFIG_LIBSTORVSC_REQUEST_TIMEOUT_MS * 1000000ULL)

struct storvsc_device;

struct uk_blkdev_queue {
	struct storvsc_device *device;
	__u16 nb_desc;
	__u8 configured;
	__u8 intr_user;
	__u8 intr_active;
};

struct storvsc_request_binding {
	struct uk_blkreq *req;
	__u64 id;
	__u64 pfns[CONFIG_LIBSTORVSC_MAX_TRANSFER_PAGES];
	__u8 synchronous;
};

struct storvsc_device {
	struct uk_blkdev blkdev;
	struct uk_blkdev_queue queue;
	struct vmbus_device *vmbus_device;
	struct vmbus_channel *channel;
	struct storvsc_request_binding
		bindings[CONFIG_LIBSTORVSC_QUEUE_DEPTH];
	__u8 core[STORVSC_CORE_STORAGE_SIZE]
		__attribute__((aligned(STORVSC_CORE_STORAGE_ALIGN)));
	__u8 rx_descriptor[STORVSC_RX_DESCRIPTOR_SIZE];
	__u8 rx_payload[STORVSC_PACKET_MAX];
	__u8 inquiry_data[STORVSC_INQUIRY_SIZE];
	__u8 capacity_data[STORVSC_CAPACITY16_SIZE];
	__u8 mode_data[STORVSC_MODE_SENSE_SIZE];
	struct uk_thread *timeout_thread;
	__spinlock lock;
	__spinlock receive_lock;
	__u32 epoch;
	__u16 uid;
	__u8 initialized;
	__u8 registered;
	__u8 online;
	__u8 removing;
	__u8 started;
	__u8 timeout_stop;
	__u8 recovering;
	__u8 reset_done;
	int reset_result;
	int fatal_error;
	__u8 finish_active;
	__u16 active_sends;
};

static struct storvsc_device storvsc_devices[CONFIG_LIBSTORVSC_MAX_DEVICES];

_Static_assert(CONFIG_LIBSTORVSC_MAX_DEVICES == 1,
	       "StorVSC supports exactly one device");
_Static_assert(CONFIG_LIBSTORVSC_MAX_QUEUES == 1,
	       "StorVSC supports exactly one queue");
_Static_assert(CONFIG_LIBSTORVSC_QUEUE_DEPTH <=
	       STORVSC_CORE_MAX_CONTEXTS,
	       "StorVSC request pool exceeds the core ABI");
_Static_assert(CONFIG_LIBSTORVSC_MAX_TRANSFER_PAGES <=
	       VMBUS_GPA_DIRECT_MAX_PFNS,
	       "StorVSC transfer exceeds the VMBus GPA-direct ABI");

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
static void storvsc_timeout_worker(void *arg) __attribute__((noreturn));

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

static int storvsc_build_gpa_range(
	struct storvsc_request_binding *binding, const void *buffer,
	__u32 length, struct vmbus_gpa_range *range)
{
	uintptr_t address = (uintptr_t)buffer;
	uintptr_t page;
	__u64 covered;
	__u64 page_count;
	__u32 offset;
	unsigned int i;

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
				     &range);
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
	if (!device->fatal_error) {
		device->fatal_error = error ? error : -EIO;
		device->online = 0;
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
	unsigned long flags;
	int wake = 0;

	switch (event->kind) {
	case STORVSC_EVENT_REQUEST_COMPLETE:
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
	case STORVSC_EVENT_PROTOCOL_ERROR:
	case STORVSC_EVENT_INITIALIZATION_FAILED:
		(void)storvsc_schedule_fatal(device,
					     event->error ? event->error : -EPROTO);
		break;
	case STORVSC_EVENT_TRANSMIT:
	case STORVSC_EVENT_INITIALIZATION_READY:
		(void)storvsc_schedule_fatal(device, -EPROTO);
		break;
	case STORVSC_EVENT_ENUMERATE_BUS:
	case STORVSC_EVENT_REQUEST_TIMEOUT:
	case STORVSC_EVENT_IGNORED:
	default:
		break;
	}
}

static int storvsc_receive_async(struct storvsc_device *device,
				 int notify_user)
{
	struct storvsc_event event;
	unsigned long receive_flags;
	unsigned long flags;
	int completed = 0;
	int notify = 0;
	int rc;

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

	if (completed && notify_user) {
		ukplat_spin_lock_irqsave(&device->lock, flags);
		if (device->registered && device->queue.configured &&
		    device->queue.intr_user && device->blkdev._data &&
		    device->blkdev._data->state == UK_BLKDEV_RUNNING) {
			device->queue.intr_active = 0;
			notify = 1;
		}
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		if (notify) {
			struct vmbus_channel *channel =
				storvsc_channel_get(device);

			if (channel)
				(void)vmbus_channel_mask_interrupts(channel);
			uk_blkdev_drv_queue_event(&device->blkdev, 0);
		}
	}
	return rc == -EAGAIN ? 0 : rc;
}

static void storvsc_channel_callback(struct vmbus_channel *channel __unused,
				     void *arg)
{
	struct storvsc_device *device = arg;

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
					__asm__ __volatile__("pause");
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
				__asm__ __volatile__("pause");
			continue;
		}
		if (rc)
			return rc;
		if (event.kind == STORVSC_EVENT_REMOVE_DEVICE)
			return -ENODEV;
		if (event.kind != STORVSC_EVENT_REQUEST_COMPLETE ||
		    event.transaction_id != tx.transaction_id)
			continue;
		rc = storvsc_core_take_completed(device->core, tx.slot,
				tx.transaction_id, &event);
		memset(binding, 0, sizeof(*binding));
		if (rc)
			return rc;
		if (transferred)
			*transferred = event.transferred;
		return event.error;
	}
}

static void storvsc_scsi_spec_init(struct storvsc_scsi_spec *spec,
				   __u8 opcode, __u8 cdb_len,
				   __u8 direction, __u32 transfer_len,
				   __u32 minimum_transfer, int allow_short)
{
	memset(spec, 0, sizeof(*spec));
	spec->cdb[0] = opcode;
	spec->cdb_len = cdb_len;
	spec->direction = direction;
	spec->transfer_len = transfer_len;
	spec->minimum_transfer = minimum_transfer;
	spec->allow_short = !!allow_short;
	spec->timeout_ns = STORVSC_CONTROL_TIMEOUT_NS;
}

static int storvsc_discover(struct storvsc_device *device,
			    struct storvsc_capacity *capacity,
			    struct storvsc_mode *mode)
{
	struct storvsc_scsi_spec spec;
	struct storvsc_inquiry inquiry;
	__u32 transferred;
	unsigned int retry;
	int rc;

	memset(device->inquiry_data, 0, sizeof(device->inquiry_data));
	storvsc_scsi_spec_init(&spec, 0x12, 6, STORVSC_DIRECTION_READ,
			       sizeof(device->inquiry_data), 36, 1);
	spec.cdb[4] = sizeof(device->inquiry_data);
	rc = storvsc_execute_scsi(device, &spec, device->inquiry_data,
				  &transferred);
	if (rc)
		return rc;
	rc = storvsc_parse_inquiry(device->inquiry_data, transferred,
				   &inquiry);
	if (rc)
		return rc;

	for (retry = 0; retry < 3; retry++) {
		storvsc_scsi_spec_init(&spec, 0x00, 6,
				       STORVSC_DIRECTION_NONE, 0, 0, 0);
		rc = storvsc_execute_scsi(device, &spec, NULL, NULL);
		if (rc != -EAGAIN)
			break;
		uk_sched_thread_sleep(100000000ULL);
	}
	if (rc)
		return rc;

	memset(device->capacity_data, 0, sizeof(device->capacity_data));
	storvsc_scsi_spec_init(&spec, 0x25, 10, STORVSC_DIRECTION_READ,
			       8, 8, 0);
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
				       sizeof(device->capacity_data), 12, 1);
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
			       sizeof(device->mode_data), 4, 1);
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

	memset(device->mode_data, 0, sizeof(device->mode_data));
	storvsc_scsi_spec_init(&spec, 0x5a, 10, STORVSC_DIRECTION_READ,
			       sizeof(device->mode_data), 8, 1);
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

static void storvsc_notify_completions(struct storvsc_device *device)
{
	unsigned long flags;
	int notify = 0;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (device->registered && device->queue.configured &&
	    device->queue.intr_user && device->blkdev._data &&
	    device->blkdev._data->state == UK_BLKDEV_RUNNING) {
		device->queue.intr_active = 0;
		notify = 1;
	}
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (notify)
		uk_blkdev_drv_queue_event(&device->blkdev, 0);
}

static int storvsc_close_channel(struct storvsc_device *device)
{
	struct vmbus_channel *channel;
	unsigned int attempt;
	int rc = -ENODEV;

	channel = storvsc_channel_get(device);
	if (!channel)
		return 0;
	vmbus_channel_set_callback(channel, NULL, NULL);
	for (attempt = 0; attempt < STORVSC_CLOSE_RETRY_LIMIT; attempt++) {
		rc = vmbus_channel_close(channel);
		if (rc != -EBUSY)
			break;
		if (!uk_sched_current() || uk_lcpu_irqs_disabled())
			break;
		uk_sched_thread_sleep(STORVSC_WORKER_SLEEP_NS);
	}
	if (!rc || rc == -ENODEV || rc == -ECANCELED)
		storvsc_channel_set(device, NULL);
	return rc;
}

static void storvsc_wait_active_sends(struct storvsc_device *device)
{
	unsigned long flags;
	unsigned int attempt;
	__u16 active;

	if (!uk_sched_current() || uk_lcpu_irqs_disabled())
		return;
	for (attempt = 0; attempt < STORVSC_SEND_WAIT_LIMIT; attempt++) {
		ukplat_spin_lock_irqsave(&device->lock, flags);
		active = device->active_sends;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		if (!active)
			return;
		uk_sched_thread_sleep(STORVSC_WORKER_SLEEP_NS);
	}
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
		active = device->finish_active;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		if (!active)
			return;
		uk_sched_thread_sleep(STORVSC_WORKER_SLEEP_NS);
	}
}

static void storvsc_fail_after_quiesce(struct storvsc_device *device,
				       int error)
{
	unsigned long flags;

	(void)storvsc_close_channel(device);
	storvsc_wait_active_sends(device);
	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->online = 0;
	device->recovering = 0;
	(void)storvsc_core_cancel_all(device->core, error);
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	storvsc_notify_completions(device);
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
	int fatal;
	int stop;

	for (;;) {
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
			break;
		}
		if (event.kind == STORVSC_EVENT_REQUEST_TIMEOUT) {
			int rc = storvsc_reset_timed_out_io(device);

			if (rc && rc != -ECANCELED) {
				storvsc_fail_after_quiesce(device,
					rc == -ENODEV ? -ENODEV : -ETIMEDOUT);
				break;
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

	if (!sched)
		return -ENOSYS;
	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->timeout_stop = 0;
	if (device->timeout_thread) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -EBUSY;
	}
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

static int storvsc_submit(struct uk_blkdev *blkdev,
			  struct uk_blkdev_queue *queue,
			  struct uk_blkreq *request)
{
	struct storvsc_device *device = queue->device;
	struct storvsc_request_binding *binding;
	struct storvsc_tx tx;
	unsigned long flags;
	__u32 active;
	int published;
	int rc;
	int status;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (!device->online || device->removing) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -ENODEV;
	}
	if (!queue->configured || !device->started || !queue->nb_desc) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -EINVAL;
	}
	active = storvsc_core_active_count(device->core);
	if (active >= queue->nb_desc) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -ENOSPC;
	}
	rc = storvsc_core_prepare_block(device->core, request->operation,
		request->start_sector, request->nb_sectors,
		(uintptr_t)request->aio_buf, ukplat_monotonic_clock(),
		STORVSC_REQUEST_TIMEOUT_NS, &tx);
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
	device->active_sends++;
	request->result = -EINPROGRESS;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);

	rc = storvsc_send_tx(device, binding, &tx, request->aio_buf,
			     &published);
	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (device->active_sends)
		device->active_sends--;
	if (rc && !published) {
		(void)storvsc_core_abort(device->core, tx.slot,
					 tx.transaction_id);
		memset(binding, 0, sizeof(*binding));
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return rc == -EAGAIN ? -ENOSPC : rc;
	}
	active = storvsc_core_active_count(device->core);
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (rc == -ECANCELED || rc == -ENODEV)
		(void)storvsc_schedule_fatal(device, -ENODEV);

	status = UK_BLKDEV_STATUS_SUCCESS;
	if (active < queue->nb_desc)
		status |= UK_BLKDEV_STATUS_MORE;
	(void)blkdev;
	return status;
}

static int storvsc_finish(struct uk_blkdev *blkdev,
			  struct uk_blkdev_queue *queue)
{
	struct storvsc_device *device = queue->device;
	struct storvsc_event event;
	struct uk_blkreq *request;
	unsigned long flags;
	int rc = 0;
	int readable;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (device->finish_active || device->removing) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return 0;
	}
	device->finish_active = 1;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);

again:
	(void)storvsc_receive_async(device, 0);
	for (;;) {
		ukplat_spin_lock_irqsave(&device->lock, flags);
		rc = storvsc_take_completion_locked(device, &request, &event);
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
	if (!rc && queue->intr_user && storvsc_channel_get(device)) {
		struct vmbus_channel *channel = storvsc_channel_get(device);

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
	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->finish_active = 0;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
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
	struct storvsc_device *device =
		__containerof(blkdev, struct storvsc_device, blkdev);

	if (!conf || conf->nb_queues != 1)
		return -EINVAL;
	if (!device->online)
		return -ENODEV;
	return 0;
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
	struct storvsc_device *device =
		__containerof(blkdev, struct storvsc_device, blkdev);
	unsigned long flags;
	int rc = 0;

	if (queue_id != 0 || !nb_desc ||
	    nb_desc > CONFIG_LIBSTORVSC_QUEUE_DEPTH)
		return ERR2PTR(-EINVAL);
	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (device->queue.configured)
		rc = -EBUSY;
	else {
		device->queue.device = device;
		device->queue.nb_desc = nb_desc;
		device->queue.configured = 1;
	}
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc ? ERR2PTR(rc) : &device->queue;
}

static int storvsc_start(struct uk_blkdev *blkdev)
{
	struct storvsc_device *device =
		__containerof(blkdev, struct storvsc_device, blkdev);
	unsigned long flags;
	int rc = 0;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (!device->online)
		rc = -ENODEV;
	else if (!device->queue.configured)
		rc = -EINVAL;
	else
		device->started = 1;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

static int storvsc_stop(struct uk_blkdev *blkdev)
{
	struct storvsc_device *device =
		__containerof(blkdev, struct storvsc_device, blkdev);
	unsigned long flags;
	int rc = 0;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (storvsc_core_active_count(device->core))
		rc = -EBUSY;
	else
		device->started = 0;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

static int storvsc_queue_intr_enable(struct uk_blkdev *blkdev __unused,
				     struct uk_blkdev_queue *queue)
{
	struct storvsc_device *device = queue->device;
	struct vmbus_channel *channel;
	unsigned long flags;
	int readable;

	channel = storvsc_channel_get(device);
	if (!channel)
		return -ENODEV;
	ukplat_spin_lock_irqsave(&device->lock, flags);
	queue->intr_user = 1;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	readable = vmbus_channel_unmask_interrupts(channel);
	if (readable < 0) {
		ukplat_spin_lock_irqsave(&device->lock, flags);
		queue->intr_user = 0;
		queue->intr_active = 0;
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return readable;
	}
	if (readable) {
		(void)vmbus_channel_mask_interrupts(channel);
		queue->intr_active = 0;
		(void)storvsc_receive_async(device, 0);
		uk_blkdev_drv_queue_event(&device->blkdev, 0);
	} else {
		queue->intr_active = 1;
	}
	return 0;
}

static int storvsc_queue_intr_disable(struct uk_blkdev *blkdev __unused,
				      struct uk_blkdev_queue *queue)
{
	struct storvsc_device *device = queue->device;
	struct vmbus_channel *channel;
	unsigned long flags;
	int rc = 0;

	channel = storvsc_channel_get(device);
	if (channel)
		rc = vmbus_channel_mask_interrupts(channel);
	ukplat_spin_lock_irqsave(&device->lock, flags);
	queue->intr_user = 0;
	queue->intr_active = 0;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

static int storvsc_queue_unconfigure(struct uk_blkdev *blkdev __unused,
				     struct uk_blkdev_queue *queue)
{
	struct storvsc_device *device = queue->device;
	unsigned long flags;
	int rc = 0;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (storvsc_core_active_count(device->core))
		rc = -EBUSY;
	else
		memset(queue, 0, sizeof(*queue));
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

static int storvsc_register_blkdev(struct storvsc_device *device,
				   const struct storvsc_capacity *capacity,
				   const struct storvsc_mode *mode,
				   __u32 transfer_limit)
{
	struct uk_alloc *allocator = uk_alloc_get_default();
	int rc;

	if (!allocator)
		return -ENOMEM;
	device->blkdev.submit_one = storvsc_submit;
	device->blkdev.finish_reqs = storvsc_finish;
	device->blkdev.dev_ops = &storvsc_blkdev_ops;
	device->blkdev.capabilities.sectors = (__sector)capacity->sectors;
	device->blkdev.capabilities.ssize = capacity->sector_size;
	device->blkdev.capabilities.ioalign = sizeof(void *);
	device->blkdev.capabilities.mode =
		mode->read_only ? O_RDONLY : O_RDWR;
	device->blkdev.capabilities.max_sectors_per_req =
		transfer_limit / capacity->sector_size;
	if (device->registered)
		return 0;
	rc = uk_blkdev_drv_register(&device->blkdev, allocator, DRIVER_NAME);
	if (rc < 0)
		return rc;
	device->uid = (__u16)rc;
	device->registered = 1;
	return 0;
}

static int storvsc_add_device(struct vmbus_device *vmbus_device)
{
	struct storvsc_device *device = &storvsc_devices[0];
	struct storvsc_capacity capacity;
	struct storvsc_mode mode;
	__u8 open_data[24] = { 0 };
	unsigned long flags;
	__u32 host_limit;
	__u32 config_limit;
	__u32 transfer_limit;
	int registered_now = 0;
	int rc;

	if (!vmbus_device || vmbus_device->subchannel_index)
		return -EINVAL;
	if (!device->initialized) {
		ukarch_spin_init(&device->lock);
		ukarch_spin_init(&device->receive_lock);
		device->initialized = 1;
		device->queue.device = device;
	}
	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (device->online || device->removing ||
	    (device->vmbus_device && device->vmbus_device != vmbus_device &&
	     storvsc_channel_get(device))) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -ENOSPC;
	}
	if (device->epoch == UINT32_MAX) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return -ENOSPC;
	}
	device->epoch++;
	device->vmbus_device = vmbus_device;
	storvsc_channel_set(device, NULL);
	device->online = 0;
	device->removing = 0;
	device->recovering = 0;
	device->reset_done = 0;
	device->fatal_error = 0;
	device->active_sends = 0;
	memset(device->bindings, 0, sizeof(device->bindings));
	rc = storvsc_core_initialize(device->core, device->epoch,
				      CONFIG_LIBSTORVSC_QUEUE_DEPTH);
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (rc)
		return rc;

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
	rc = storvsc_discover(device, &capacity, &mode);
	if (rc)
		goto failed;
	if (!capacity.sectors || capacity.sectors > SIZE_MAX ||
	    transfer_limit < capacity.sector_size) {
		rc = -EOVERFLOW;
		goto failed;
	}
	transfer_limit -= transfer_limit % capacity.sector_size;
	rc = storvsc_core_set_transfer_limit(device->core, transfer_limit);
	if (rc)
		goto failed;
	rc = storvsc_core_set_media(device->core, capacity.sectors,
				     capacity.sector_size, mode.read_only);
	if (rc)
		goto failed;
	registered_now = !device->registered;
	rc = storvsc_register_blkdev(device, &capacity, &mode,
				      transfer_limit);
	if (rc)
		goto failed;
	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->online = 1;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	vmbus_channel_set_callback(storvsc_channel_get(device),
				   storvsc_channel_callback, device);
	rc = storvsc_start_timeout_worker(device);
	if (rc)
		goto failed_registered;
	if (vmbus_channel_poll(storvsc_channel_get(device)) > 0)
		(void)storvsc_receive_async(device, 1);
	uk_pr_info(DRIVER_NAME ": blkdev%u, VMStor %u.%u, %"
		   PRIu64 " sectors of %u bytes%s\n",
		   device->uid, storvsc_core_version(device->core) >> 8,
		   storvsc_core_version(device->core) & 0xff,
		   capacity.sectors, capacity.sector_size,
		   mode.read_only ? ", read-only" : "");
	return 0;

failed_registered:
	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->online = 0;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (storvsc_channel_get(device))
		vmbus_channel_set_callback(storvsc_channel_get(device),
					   NULL, NULL);
	if (registered_now && device->registered && device->blkdev._data &&
	    device->blkdev._data->state == UK_BLKDEV_UNCONFIGURED) {
		uk_blkdev_drv_unregister(&device->blkdev);
		device->blkdev._data = NULL;
		device->registered = 0;
	}
failed:
	if (storvsc_channel_get(device))
		(void)storvsc_close_channel(device);
	ukplat_spin_lock_irqsave(&device->lock, flags);
	device->online = 0;
	device->vmbus_device = NULL;
	storvsc_channel_set(device, NULL);
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	return rc;
}

static void storvsc_complete_remove(struct storvsc_device *device)
{
	struct storvsc_event events[CONFIG_LIBSTORVSC_QUEUE_DEPTH];
	struct uk_blkreq *requests[CONFIG_LIBSTORVSC_QUEUE_DEPTH];
	unsigned long flags;
	unsigned int count = 0;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	(void)storvsc_core_cancel_all(device->core, -ENODEV);
	while (count < CONFIG_LIBSTORVSC_QUEUE_DEPTH) {
		if (storvsc_take_completion_locked(device, &requests[count],
						   &events[count]))
			break;
		count++;
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
}

static void storvsc_remove_device(struct vmbus_device *vmbus_device)
{
	struct storvsc_device *device = &storvsc_devices[0];
	unsigned long flags;

	ukplat_spin_lock_irqsave(&device->lock, flags);
	if (device->vmbus_device != vmbus_device) {
		ukplat_spin_unlock_irqrestore(&device->lock, flags);
		return;
	}
	device->removing = 1;
	device->online = 0;
	device->timeout_stop = 1;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
	if (storvsc_channel_get(device))
		vmbus_channel_set_callback(storvsc_channel_get(device),
					   NULL, NULL);
	storvsc_stop_timeout_worker(device);
	storvsc_wait_active_sends(device);
	storvsc_wait_finish(device);
	storvsc_complete_remove(device);
	ukplat_spin_lock_irqsave(&device->lock, flags);
	storvsc_channel_set(device, NULL);
	device->vmbus_device = NULL;
	device->recovering = 0;
	device->removing = 0;
	ukplat_spin_unlock_irqrestore(&device->lock, flags);
}

static struct vmbus_driver storvsc_driver = {
	.name = DRIVER_NAME,
	.device_ids = storvsc_device_ids,
	.add_dev = storvsc_add_device,
	.remove_dev = storvsc_remove_device,
};

VMBUS_DRIVER_REGISTER(&storvsc_driver);

#ifdef STORVSC_HOST_TEST
struct vmbus_driver *storvsc_host_driver(void)
{
	return &storvsc_driver;
}

struct uk_blkdev *storvsc_host_blkdev(void)
{
	return &storvsc_devices[0].blkdev;
}

int storvsc_host_receive(void)
{
	return storvsc_receive_async(&storvsc_devices[0], 1);
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
