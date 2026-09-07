/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <stdint.h>
#include <uk/alloc.h>
#include <uk/arch/spinlock.h>
#include <uk/assert.h>
#include <uk/config.h>
#include <uk/errptr.h>
#include <uk/essentials.h>
#include <uk/lcpu.h>
#include <uk/netbuf.h>
#include <uk/netdev_driver.h>
#include <uk/paging.h>
#include <uk/plat/time.h>
#include <uk/print.h>
#include <uk/sched.h>
#include <uk/vmbus.h>

#include "netvsc_protocol.h"

#define NETVSC_DRIVER_NAME		"hyperv-netvsc"
#define NETVSC_PAGE_SIZE		4096U
#define NETVSC_ETH_HEADER		14U
#define NETVSC_ETH_HEADER_MAX		18U
#define NETVSC_DEFAULT_MTU		1500U
#define NETVSC_MIN_FRAME		NETVSC_ETH_HEADER
#define NETVSC_RNDIS_HEADER_SIZE	44U
#define NETVSC_CONTROL_PAGE_SIZE	NETVSC_PAGE_SIZE
#define NETVSC_CONTROL_INFO_SIZE	256U
#define NETVSC_NVS_RESPONSE_SIZE	\
	(((12U + NETVSC_NVS_MAX_SECTIONS * 16U) + 7U) & ~7U)
#define NETVSC_PACKET_SCRATCH_SIZE	65536U
#define NETVSC_CONTROL_WAIT_NS		1000000ULL
#define NETVSC_INVALID_SECTION		NETVSC_NVS_SEND_SECTION_INVALID
#define NETVSC_GPA_MAX_RANGES		VMBUS_GPA_DIRECT_MAX_RANGES
#define NETVSC_GPA_MAX_PFNS		VMBUS_GPA_DIRECT_MAX_PFNS
#define NETVSC_ACK_SLOTS		(CONFIG_LIBNETVSC_CHANNEL_RX_PAGES * \
					 (NETVSC_PAGE_SIZE / 32U))
#define NETVSC_ID_TOMBSTONES		(CONFIG_LIBNETVSC_TX_SLOTS + \
					 CONFIG_LIBNETVSC_CONTROL_SLOTS + 8U)
#define NETVSC_TX_STAGE_BEFORE_COPY	1U
#define NETVSC_TX_STAGE_SECTION_COPY	2U
#define NETVSC_TX_STAGE_BUILD_RANGES	3U
#define NETVSC_TX_STAGE_AFTER_PUBLISH	4U
#define NETVSC_CONTROL_STAGE_AFTER_PUBLISH 1U
#define NETVSC_CONTROL_STAGE_WAIT_DONE	2U
#define NETVSC_CONTROL_STAGE_CANCELLED	3U

#define NETVSC_RX_BUFFER_SIZE		((size_t)CONFIG_LIBNETVSC_RX_BUFFER_MB * \
					 1024U * 1024U)
#define NETVSC_RX_BUFFER_LEGACY_SIZE	(15U * 1024U * 1024U)
#define NETVSC_SEND_BUFFER_SIZE		((size_t)CONFIG_LIBNETVSC_SEND_BUFFER_MB * \
					 1024U * 1024U)
#define NETVSC_SECTION_LIMIT		(CONFIG_LIBNETVSC_TX_SLOTS + \
					 CONFIG_LIBNETVSC_CONTROL_SLOTS)

struct uk_netdev_rx_queue {
	struct uk_netdev *netdev;
	uk_netdev_alloc_rxpkts alloc_rxpkts;
	void *alloc_rxpkts_argp;
	__u16 queue_id;
	__u16 descriptors;
	__u8 configured;
	__u8 interrupt_requested;
	__u8 interrupt_armed;
};

struct uk_netdev_tx_queue {
	struct uk_netdev *netdev;
	__u16 queue_id;
	__u16 descriptors;
	__u8 configured;
};

enum netvsc_control_state {
	NETVSC_CONTROL_FREE,
	NETVSC_CONTROL_BUILDING,
	NETVSC_CONTROL_SENT,
	NETVSC_CONTROL_CANCELLED,
	NETVSC_CONTROL_FINALIZING,
};

enum netvsc_tx_state {
	NETVSC_TX_FREE,
	/* Completion may be recorded, but only the publishing sender finalizes. */
	NETVSC_TX_BUILDING,
	NETVSC_TX_SENT,
	NETVSC_TX_COMPLETING,
};

struct netvsc_control {
	__u64 transaction_id;
	__u32 request_id;
	__u32 expected_type;
	__u32 section_index;
	__u32 request_length;
	struct netvsc_rndis_completion completion;
	__u16 info_length;
	__s16 error;
	__u8 state;
	__u8 nvs_done;
	__u8 nvs_completion_pending;
	__u8 rndis_done;
	__u8 needs_rndis;
	/* Keeps the slot generation stable until the waiter copies its reply. */
	__u8 waiter_owned;
};

struct netvsc_nvs_wait {
	__u64 transaction_id;
	__u32 expected_type;
	__u16 response_length;
	__s16 error;
	__u8 active;
	__u8 done;
	__u8 response[NETVSC_NVS_RESPONSE_SIZE];
};

struct netvsc_tx_context {
	__u64 transaction_id;
	struct uk_netbuf *packet;
	__u32 section_index;
	__u16 range_count;
	__u16 pfn_count;
	__u8 state;
	__u8 completion_pending;
	__u8 completion_malformed;
	__u8 header[NETVSC_RNDIS_HEADER_SIZE];
	struct vmbus_gpa_range ranges[NETVSC_GPA_MAX_RANGES];
	__u64 pfns[NETVSC_GPA_MAX_PFNS];
};

struct netvsc_pending_ack {
	__u64 transaction_id;
	__u32 generation;
	__u32 status;
};

struct netvsc_device {
	struct uk_netdev netdev;
	struct uk_netdev_rx_queue rxq;
	struct uk_netdev_tx_queue txq;
	struct vmbus_device *vmbus_device;
	struct vmbus_channel *channel;
	struct vmbus_gpadl receive_gpadl;
	struct vmbus_gpadl send_gpadl;
	struct netvsc_nvs_section receive_sections[NETVSC_NVS_MAX_SECTIONS];
	struct netvsc_control controls[CONFIG_LIBNETVSC_CONTROL_SLOTS];
	struct netvsc_tx_context tx[CONFIG_LIBNETVSC_TX_SLOTS];
	struct netvsc_nvs_wait nvs_wait;
	struct uk_netbuf *receive_ready[CONFIG_LIBNETVSC_RX_SLOTS];
	struct netvsc_pending_ack pending_acks[NETVSC_ACK_SLOTS];
	struct uk_netbuf *quarantined_tx[CONFIG_LIBNETVSC_TX_SLOTS];
	__u64 transaction_tombstones[NETVSC_ID_TOMBSTONES];
	__u32 request_tombstones[NETVSC_ID_TOMBSTONES];
	__u8 control_info[CONFIG_LIBNETVSC_CONTROL_SLOTS]
			 [NETVSC_CONTROL_INFO_SIZE];
	__u8 section_used[NETVSC_SECTION_LIMIT];
	struct uk_hwaddr current_address;
	struct uk_hwaddr permanent_address;
	__spinlock state_lock;
	__spinlock control_lock;
	__spinlock tx_lock;
	__spinlock rx_lock;
	__u64 next_transaction;
	__u64 quarantined_vmbus_epoch;
	__u32 generation;
	__u32 nvs_version;
	__u32 ndis_version;
	__u32 receive_buffer_size;
	__u32 receive_section_count;
	__u32 send_section_size;
	__u32 send_section_count;
	__u32 transaction_tombstone_next;
	__u32 request_tombstone_next;
	__u32 malformed_messages;
	__u32 unknown_completions;
	__u32 duplicate_completions;
	__u32 early_completions;
	__u32 receive_events;
	__u16 next_request;
	__u16 mtu;
	__u16 max_mtu;
	__u16 receive_head;
	__u16 receive_tail;
	__u16 receive_count;
	__u16 pending_ack_head;
	__u16 pending_ack_tail;
	__u16 pending_ack_count;
	__u16 operations;
	__u16 quarantined_tx_count;
	__u8 initialized;
	__u8 attaching;
	__u8 attached;
	__u8 stopping;
	__u8 registered;
	__u8 configured;
	__u8 running;
	__u8 host_running;
	__u8 rndis_initialized;
	__u8 receive_connected;
	__u8 send_connected;
	__u8 link_up;
	__u8 promiscuous;
	__u8 drain_active;
	__u8 drain_pending;
	__u8 quarantined_wait_vmbus;
	__u8 recovering;
	__u8 failed;
};

static struct netvsc_device netvsc;
static __u8 netvsc_receive_buffer[NETVSC_RX_BUFFER_SIZE]
	__align(NETVSC_PAGE_SIZE);
static __u8 netvsc_send_buffer[NETVSC_SEND_BUFFER_SIZE]
	__align(NETVSC_PAGE_SIZE);
static __u8 netvsc_control_pages[CONFIG_LIBNETVSC_CONTROL_SLOTS]
				   [NETVSC_CONTROL_PAGE_SIZE]
	__align(NETVSC_PAGE_SIZE);
static __u8 netvsc_descriptor_scratch[NETVSC_PACKET_SCRATCH_SIZE];
static __u8 netvsc_payload_scratch[NETVSC_PACKET_SCRATCH_SIZE];

static void netvsc_channel_callback(struct vmbus_channel *channel, void *arg);
static void netvsc_drain_channel(struct netvsc_device *device);
static void netvsc_detach_host(struct netvsc_device *device, int revoked);

#ifdef NETVSC_HOST_TEST
extern void netvsc_host_tx_stage(unsigned int stage, __u64 transaction_id);
extern void netvsc_host_control_stage(unsigned int stage,
				      __u64 transaction_id,
				      __u32 request_id);
#define NETVSC_TX_STAGE(stage, id)	netvsc_host_tx_stage((stage), (id))
#define NETVSC_CONTROL_STAGE(stage, tx, req) \
	netvsc_host_control_stage((stage), (tx), (req))
#else
#define NETVSC_TX_STAGE(stage, id) \
	do { (void)(stage); (void)(id); } while (0)
#define NETVSC_CONTROL_STAGE(stage, tx, req) \
	do { (void)(stage); (void)(tx); (void)(req); } while (0)
#endif

static void netvsc_fail_channel(struct netvsc_device *device)
{
	struct vmbus_channel *channel;
	unsigned long flags;

	if (__atomic_exchange_n(&device->recovering, 1,
				 __ATOMIC_ACQ_REL))
		return;
	ukplat_spin_lock_irqsave(&device->state_lock, flags);
	device->failed = 1;
	device->host_running = 0;
	device->quarantined_vmbus_epoch =
		vmbus_connection_quiesce_epoch();
	device->quarantined_wait_vmbus = 1;
	channel = device->channel;
	ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
	if (channel)
		vmbus_channel_set_callback(channel, NULL, NULL);
	(void)vmbus_connection_fail();
}

static void copy_bytes(void *destination, const void *source, size_t length)
{
	__u8 *dst = destination;
	const __u8 *src = source;
	size_t i;

	for (i = 0; i < length; i++)
		dst[i] = src[i];
}

static void zero_bytes(void *destination, size_t length)
{
	__u8 *dst = destination;
	size_t i;

	for (i = 0; i < length; i++)
		dst[i] = 0;
}

static __u32 read_le32(const __u8 *data)
{
	return (__u32)data[0] | ((__u32)data[1] << 8) |
		((__u32)data[2] << 16) | ((__u32)data[3] << 24);
}

static void write_le32(__u8 *data, __u32 value)
{
	data[0] = (__u8)value;
	data[1] = (__u8)(value >> 8);
	data[2] = (__u8)(value >> 16);
	data[3] = (__u8)(value >> 24);
}

static int netvsc_can_wait(void)
{
	return uk_sched_current() && !uk_lcpu_irqs_disabled();
}

static int netvsc_operation_begin(struct netvsc_device *device,
				  int require_running)
{
	unsigned long flags;
	int rc = 0;

	ukplat_spin_lock_irqsave(&device->state_lock, flags);
	if (!device->attached || device->stopping ||
	    (require_running && !device->host_running))
		rc = -ENODEV;
	else if (device->operations == UINT16_MAX)
		rc = -ENOSPC;
	else
		device->operations++;
	ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
	return rc;
}

static void netvsc_operation_end(struct netvsc_device *device)
{
	unsigned long flags;

	ukplat_spin_lock_irqsave(&device->state_lock, flags);
	UK_ASSERT(device->operations != 0);
	device->operations--;
	ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
}

static void netvsc_wait_once(void)
{
	if (uk_sched_current())
		uk_sched_thread_sleep(NETVSC_CONTROL_WAIT_NS);
	else
		__asm__ __volatile__("pause");
}

static __u64 netvsc_deadline(void)
{
	__u64 now = ukplat_monotonic_clock();
	__u64 interval = (__u64)CONFIG_LIBNETVSC_CONTROL_TIMEOUT_MS *
		1000000ULL;

	return now > UINT64_MAX - interval ? UINT64_MAX : now + interval;
}

static void netvsc_init_once(struct netvsc_device *device)
{
	if (device->initialized)
		return;
	ukarch_spin_init(&device->state_lock);
	ukarch_spin_init(&device->control_lock);
	ukarch_spin_init(&device->tx_lock);
	ukarch_spin_init(&device->rx_lock);
	device->rxq.netdev = &device->netdev;
	device->txq.netdev = &device->netdev;
	device->rxq.queue_id = 0;
	device->txq.queue_id = 0;
	device->mtu = NETVSC_DEFAULT_MTU;
	device->max_mtu = NETVSC_DEFAULT_MTU;
	device->next_transaction = 1;
	device->initialized = 1;
}

static int netvsc_transaction_id(struct netvsc_device *device, __u64 *id)
{
	unsigned long flags;
	__u64 sequence;

	ukplat_spin_lock_irqsave(&device->state_lock, flags);
	sequence = device->next_transaction;
	if (!sequence || sequence > UINT32_MAX || !device->generation) {
		ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
		return -ENOSPC;
	}
	device->next_transaction++;
	*id = ((__u64)device->generation << 32) | sequence;
	ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
	return 0;
}

static int netvsc_request_id(struct netvsc_device *device, __u32 *id)
{
	unsigned long flags;
	__u16 sequence;

	ukplat_spin_lock_irqsave(&device->state_lock, flags);
	sequence = device->next_request;
	if (!sequence || device->generation > UINT16_MAX) {
		ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
		return -ENOSPC;
	}
	device->next_request++;
	if (!device->next_request)
		device->next_request = 0;
	*id = (device->generation << 16) | sequence;
	ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
	return 0;
}

static void netvsc_remember_transaction(struct netvsc_device *device, __u64 id)
{
	unsigned int slot;

	if (!id)
		return;
	slot = __atomic_fetch_add(&device->transaction_tombstone_next, 1,
				 __ATOMIC_RELAXED) % NETVSC_ID_TOMBSTONES;
	__atomic_store_n(&device->transaction_tombstones[slot], id,
			 __ATOMIC_RELEASE);
}

static void netvsc_remember_request(struct netvsc_device *device, __u32 id)
{
	unsigned int slot;

	if (!id)
		return;
	slot = __atomic_fetch_add(&device->request_tombstone_next, 1,
				 __ATOMIC_RELAXED) % NETVSC_ID_TOMBSTONES;
	__atomic_store_n(&device->request_tombstones[slot], id,
			 __ATOMIC_RELEASE);
}

static void netvsc_count_unknown_completion(struct netvsc_device *device)
{
	(void)__atomic_add_fetch(&device->unknown_completions, 1,
				 __ATOMIC_RELAXED);
}

static void netvsc_count_duplicate_completion(struct netvsc_device *device)
{
	(void)__atomic_add_fetch(&device->duplicate_completions, 1,
				 __ATOMIC_RELAXED);
}

static void netvsc_count_early_completion(struct netvsc_device *device)
{
	(void)__atomic_add_fetch(&device->early_completions, 1,
				 __ATOMIC_RELAXED);
}

static int netvsc_known_transaction(const struct netvsc_device *device,
				    __u64 id)
{
	unsigned int i;

	for (i = 0; i < NETVSC_ID_TOMBSTONES; i++)
		if (__atomic_load_n(&device->transaction_tombstones[i],
				    __ATOMIC_ACQUIRE) == id)
			return 1;
	return 0;
}

static int netvsc_known_request(const struct netvsc_device *device, __u32 id)
{
	unsigned int i;

	for (i = 0; i < NETVSC_ID_TOMBSTONES; i++)
		if (__atomic_load_n(&device->request_tombstones[i],
				    __ATOMIC_ACQUIRE) == id)
			return 1;
	return 0;
}

static int netvsc_send_section_allocate(struct netvsc_device *device,
					__u32 required, __u32 *section)
{
	unsigned long flags;
	unsigned int i;

	*section = NETVSC_INVALID_SECTION;
	ukplat_spin_lock_irqsave(&device->tx_lock, flags);
	if (!device->send_connected || !device->send_section_size ||
	    required > device->send_section_size) {
		ukplat_spin_unlock_irqrestore(&device->tx_lock, flags);
		return -ENOSPC;
	}
	for (i = 0; i < device->send_section_count; i++) {
		if (device->section_used[i])
			continue;
		device->section_used[i] = 1;
		*section = i;
		ukplat_spin_unlock_irqrestore(&device->tx_lock, flags);
		return 0;
	}
	ukplat_spin_unlock_irqrestore(&device->tx_lock, flags);
	return -ENOSPC;
}

static void netvsc_send_section_release(struct netvsc_device *device,
					__u32 section)
{
	unsigned long flags;

	if (section == NETVSC_INVALID_SECTION ||
	    section >= NETVSC_SECTION_LIMIT)
		return;
	ukplat_spin_lock_irqsave(&device->tx_lock, flags);
	device->section_used[section] = 0;
	ukplat_spin_unlock_irqrestore(&device->tx_lock, flags);
}

static int netvsc_copy_to_send_section(struct netvsc_device *device,
				       __u32 section, const __u8 *data,
				       __u32 length)
{
	__u64 offset = (__u64)section * device->send_section_size;

	if (section >= device->send_section_count ||
	    length > device->send_section_size ||
	    offset > NETVSC_SEND_BUFFER_SIZE ||
	    length > NETVSC_SEND_BUFFER_SIZE - offset)
		return -EINVAL;
	copy_bytes(&netvsc_send_buffer[offset], data, length);
	return 0;
}

static int netvsc_single_gpa(const void *data, __u32 length,
			     struct vmbus_gpa_range *range, __u64 *pfns,
			     __u32 pfn_capacity)
{
	uintptr_t address = (uintptr_t)data;
	uintptr_t page = address & ~(uintptr_t)(NETVSC_PAGE_SIZE - 1);
	__u32 offset = (__u32)(address & (NETVSC_PAGE_SIZE - 1));
	__u64 covered = (__u64)offset + length;
	__u32 pages;
	__u32 i;

	if (!data || !length || covered > UINT32_MAX)
		return -EINVAL;
	pages = (__u32)((covered + NETVSC_PAGE_SIZE - 1) /
			NETVSC_PAGE_SIZE);
	if (!pages || pages > pfn_capacity)
		return -E2BIG;
	for (i = 0; i < pages; i++) {
		__paddr_t physical = uk_paging_virt_to_phys(
			(__vaddr_t)(page + (uintptr_t)i * NETVSC_PAGE_SIZE));

		if (physical == UK_PAGING_PADDR_INV ||
		    (physical & (NETVSC_PAGE_SIZE - 1)))
			return -EINVAL;
		pfns[i] = physical >> 12;
	}
	range->byte_count = length;
	range->byte_offset = offset;
	range->pfns = pfns;
	range->pfn_count = pages;
	return 0;
}

static struct netvsc_control *
netvsc_control_allocate(struct netvsc_device *device, __u32 expected_type,
			int needs_rndis)
{
	unsigned long flags;
	unsigned int i;
	struct netvsc_control *control = NULL;
	__u32 request_id;
	__u64 transaction_id;

	if (netvsc_request_id(device, &request_id) ||
	    netvsc_transaction_id(device, &transaction_id))
		return NULL;
	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	for (i = 0; i < CONFIG_LIBNETVSC_CONTROL_SLOTS; i++) {
		if (device->controls[i].state != NETVSC_CONTROL_FREE)
			continue;
		control = &device->controls[i];
		zero_bytes(control, sizeof(*control));
		control->state = NETVSC_CONTROL_BUILDING;
		control->request_id = request_id;
		control->transaction_id = transaction_id;
		control->expected_type = expected_type;
		control->needs_rndis = needs_rndis;
		control->waiter_owned = 1;
		control->section_index = NETVSC_INVALID_SECTION;
		break;
	}
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
	return control;
}

static unsigned int netvsc_control_index(struct netvsc_device *device,
					 struct netvsc_control *control)
{
	return (unsigned int)(control - &device->controls[0]);
}

struct netvsc_control_release {
	struct netvsc_control *control;
	__u64 transaction_id;
	__u32 request_id;
	__u32 section;
	int elected;
};

static void netvsc_control_elect_release_locked(
					struct netvsc_device *device,
					struct netvsc_control *control,
					struct netvsc_control_release *release)
{
	if (control->state == NETVSC_CONTROL_FREE ||
	    control->state == NETVSC_CONTROL_FINALIZING ||
	    control->waiter_owned)
		return;
	release->control = control;
	release->transaction_id = control->transaction_id;
	release->request_id = control->request_id;
	release->section = control->section_index;
	release->elected = 1;
	control->section_index = NETVSC_INVALID_SECTION;
	control->state = NETVSC_CONTROL_FINALIZING;
	netvsc_remember_transaction(device, release->transaction_id);
	netvsc_remember_request(device, release->request_id);
}

static void netvsc_control_finish_release(
				struct netvsc_device *device,
				struct netvsc_control_release *release)
{
	unsigned long flags;

	if (!release->elected)
		return;
	netvsc_send_section_release(device, release->section);
	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	if (release->control->state == NETVSC_CONTROL_FINALIZING &&
	    release->control->transaction_id == release->transaction_id &&
	    release->control->request_id == release->request_id) {
		zero_bytes(release->control, sizeof(*release->control));
		release->control->section_index = NETVSC_INVALID_SECTION;
	}
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
}

static void netvsc_control_release(struct netvsc_device *device,
				   struct netvsc_control *control)
{
	struct netvsc_control_release release = {
		.section = NETVSC_INVALID_SECTION,
	};
	unsigned long flags;

	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	if (control->state != NETVSC_CONTROL_FREE &&
	    control->state != NETVSC_CONTROL_FINALIZING) {
		if (control->state == NETVSC_CONTROL_BUILDING &&
		    control->nvs_completion_pending)
			netvsc_count_early_completion(device);
		control->waiter_owned = 0;
		netvsc_control_elect_release_locked(device, control, &release);
	}
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
	netvsc_control_finish_release(device, &release);
}

static void netvsc_control_cancel(struct netvsc_device *device,
				  struct netvsc_control *control)
{
	struct netvsc_control_release release = {
		.section = NETVSC_INVALID_SECTION,
	};
	unsigned long flags;
	__u64 transaction_id = 0;
	__u32 request_id = 0;

	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	if (control->state == NETVSC_CONTROL_BUILDING) {
		control->waiter_owned = 0;
		netvsc_control_elect_release_locked(device, control, &release);
	} else if (control->state == NETVSC_CONTROL_SENT ||
		   control->state == NETVSC_CONTROL_CANCELLED) {
		control->state = NETVSC_CONTROL_CANCELLED;
		control->waiter_owned = 0;
		transaction_id = control->transaction_id;
		request_id = control->request_id;
		if (control->nvs_done)
			netvsc_control_elect_release_locked(device, control,
							    &release);
	}
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
	if (transaction_id)
		NETVSC_CONTROL_STAGE(NETVSC_CONTROL_STAGE_CANCELLED,
				     transaction_id, request_id);
	netvsc_control_finish_release(device, &release);
}

static void netvsc_control_publish(struct netvsc_device *device,
				   struct netvsc_control *control)
{
	unsigned long flags;
	__u32 section = NETVSC_INVALID_SECTION;

	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	if (control->state == NETVSC_CONTROL_BUILDING) {
		control->state = NETVSC_CONTROL_SENT;
		if (control->nvs_completion_pending) {
			control->nvs_completion_pending = 0;
			control->nvs_done = 1;
			section = control->section_index;
			control->section_index = NETVSC_INVALID_SECTION;
		}
	}
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
	netvsc_send_section_release(device, section);
}

static int netvsc_control_done(const struct netvsc_control *control)
{
	return control->nvs_done &&
		(!control->needs_rndis || control->rndis_done);
}

static int netvsc_send_control(struct netvsc_device *device,
			       struct netvsc_control *control,
			       int *was_published)
{
	unsigned int index = netvsc_control_index(device, control);
	__u8 nvs[NETVSC_NVS_REQUEST_SIZE];
	struct vmbus_gpa_range range;
	__u64 pfns[2];
	unsigned long flags;
	__u32 section = NETVSC_INVALID_SECTION;
	int nvs_length;
	int published = 0;
	int rc;

	*was_published = 0;
	nvs_length = netvsc_nvs_build_rndis(nvs, sizeof(nvs),
			NETVSC_NVS_RNDIS_CONTROL,
			NETVSC_NVS_SEND_SECTION_INVALID, 0);
	if (nvs_length < 0)
		return -EINVAL;
	if (!netvsc_send_section_allocate(device, control->request_length,
					   &section)) {
		rc = netvsc_copy_to_send_section(device, section,
				netvsc_control_pages[index],
				control->request_length);
		if (rc) {
			netvsc_send_section_release(device, section);
			return rc;
		}
		ukplat_spin_lock_irqsave(&device->control_lock, flags);
		if (control->state != NETVSC_CONTROL_BUILDING) {
			ukplat_spin_unlock_irqrestore(&device->control_lock,
						     flags);
			netvsc_send_section_release(device, section);
			return -ECANCELED;
		}
		control->section_index = section;
		ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
		nvs_length = netvsc_nvs_build_rndis(nvs, sizeof(nvs),
				NETVSC_NVS_RNDIS_CONTROL, section,
				control->request_length);
		rc = vmbus_channel_send_ex(device->channel,
				VMBUS_PACKET_DATA_INBAND,
				VMBUS_PACKET_FLAG_REQUEST_COMPLETION,
				control->transaction_id, NULL, 0,
				nvs, (size_t)nvs_length, &published);
	} else {
		rc = netvsc_single_gpa(netvsc_control_pages[index],
				control->request_length, &range, pfns, 2);
		if (rc)
			return rc;
		rc = vmbus_channel_send_gpa_direct_ex(device->channel,
				VMBUS_PACKET_FLAG_REQUEST_COMPLETION,
				control->transaction_id, &range, 1,
				nvs, (size_t)nvs_length, &published);
	}
	*was_published = published;
	if (published) {
		NETVSC_CONTROL_STAGE(NETVSC_CONTROL_STAGE_AFTER_PUBLISH,
				     control->transaction_id,
				     control->request_id);
		netvsc_control_publish(device, control);
	}
	if (rc && published)
		netvsc_fail_channel(device);
	return rc;
}

static int netvsc_control_wait(struct netvsc_device *device,
			       struct netvsc_control *control,
			       struct netvsc_rndis_completion *completion,
			       void *information, size_t *information_length)
{
	struct netvsc_control_release release = {
		.section = NETVSC_INVALID_SECTION,
	};
	__u64 deadline;
	__u64 transaction_id = 0;
	__u32 request_id = 0;
	unsigned long flags;
	int done;
	int error;

	if (!netvsc_can_wait())
		return -EWOULDBLOCK;
	deadline = netvsc_deadline();
	for (;;) {
		netvsc_drain_channel(device);
		ukplat_spin_lock_irqsave(&device->control_lock, flags);
		done = netvsc_control_done(control);
		error = control->error;
		if (done) {
			transaction_id = control->transaction_id;
			request_id = control->request_id;
		}
		ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
		if (done)
			break;
		if (ukplat_monotonic_clock() >= deadline) {
			netvsc_control_cancel(device, control);
			return -ETIMEDOUT;
		}
		netvsc_wait_once();
	}

	NETVSC_CONTROL_STAGE(NETVSC_CONTROL_STAGE_WAIT_DONE,
			     transaction_id, request_id);
	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	if (control->state == NETVSC_CONTROL_FREE ||
	    control->state == NETVSC_CONTROL_FINALIZING ||
	    control->transaction_id != transaction_id ||
	    control->request_id != request_id ||
	    !control->waiter_owned) {
		ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
		return -ECANCELED;
	}
	error = control->error;
	if (completion)
		*completion = control->completion;
	if (information_length) {
		size_t available = control->info_length;
		size_t capacity = *information_length;
		unsigned int index = netvsc_control_index(device, control);

		*information_length = available;
		if (available > capacity)
			error = -ENOBUFS;
		else if (available && information)
			copy_bytes(information, device->control_info[index],
				   available);
	}
	control->waiter_owned = 0;
	netvsc_control_elect_release_locked(device, control, &release);
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
	netvsc_control_finish_release(device, &release);
	return error;
}

static int netvsc_rndis_execute(struct netvsc_device *device,
				struct netvsc_control *control,
				struct netvsc_rndis_completion *completion,
				void *information,
				size_t *information_length)
{
	int published;
	int rc;

	if (!netvsc_can_wait()) {
		netvsc_control_release(device, control);
		return -EWOULDBLOCK;
	}
	rc = netvsc_send_control(device, control, &published);

	if (rc) {
		if (published)
			netvsc_control_cancel(device, control);
		else
			netvsc_control_release(device, control);
		return rc;
	}
	return netvsc_control_wait(device, control, completion, information,
				   information_length);
}

static int netvsc_rndis_initialize_device(struct netvsc_device *device)
{
	struct netvsc_rndis_completion completion;
	struct netvsc_control *control = netvsc_control_allocate(device,
			NETVSC_RNDIS_INITIALIZE_COMPLETE, 1);
	unsigned int index;
	int length;

	if (!control)
		return -ENOSPC;
	index = netvsc_control_index(device, control);
	length = netvsc_rndis_build_initialize(netvsc_control_pages[index],
			NETVSC_CONTROL_PAGE_SIZE, control->request_id, 2048);
	if (length < 0) {
		netvsc_control_release(device, control);
		return -EINVAL;
	}
	control->request_length = (__u32)length;
	if (netvsc_rndis_execute(device, control, &completion, NULL, NULL))
		return -EIO;
	if (completion.max_transfer_size < NETVSC_RNDIS_HEADER_SIZE +
		    NETVSC_MIN_FRAME)
		return -EPROTO;
	device->rndis_initialized = 1;
	return 0;
}

static int netvsc_rndis_query(struct netvsc_device *device, __u32 oid,
			      void *output, size_t *output_length)
{
	struct netvsc_control *control = netvsc_control_allocate(device,
			NETVSC_RNDIS_QUERY_COMPLETE, 1);
	unsigned int index;
	int length;

	if (!control)
		return -ENOSPC;
	index = netvsc_control_index(device, control);
	length = netvsc_rndis_build_query(netvsc_control_pages[index],
			NETVSC_CONTROL_PAGE_SIZE, control->request_id, oid,
			netvsc_control_pages[index], 0);
	if (length < 0) {
		netvsc_control_release(device, control);
		return -EINVAL;
	}
	control->request_length = (__u32)length;
	return netvsc_rndis_execute(device, control, NULL, output,
				    output_length);
}

static int netvsc_rndis_set(struct netvsc_device *device, __u32 oid,
			    const void *input, size_t input_length)
{
	struct netvsc_control *control = netvsc_control_allocate(device,
			NETVSC_RNDIS_SET_COMPLETE, 1);
	unsigned int index;
	int length;

	if (!control)
		return -ENOSPC;
	index = netvsc_control_index(device, control);
	length = netvsc_rndis_build_set(netvsc_control_pages[index],
			NETVSC_CONTROL_PAGE_SIZE, control->request_id, oid,
			input, input_length);
	if (length < 0) {
		netvsc_control_release(device, control);
		return -EINVAL;
	}
	control->request_length = (__u32)length;
	return netvsc_rndis_execute(device, control, NULL, NULL, NULL);
}

static int netvsc_rndis_keepalive_device(struct netvsc_device *device)
{
	struct netvsc_control *control = netvsc_control_allocate(device,
			NETVSC_RNDIS_KEEPALIVE_COMPLETE, 1);
	unsigned int index;
	int length;

	if (!control)
		return -ENOSPC;
	index = netvsc_control_index(device, control);
	length = netvsc_rndis_build_keepalive(netvsc_control_pages[index],
			NETVSC_CONTROL_PAGE_SIZE, control->request_id);
	if (length < 0) {
		netvsc_control_release(device, control);
		return -EINVAL;
	}
	control->request_length = (__u32)length;
	return netvsc_rndis_execute(device, control, NULL, NULL, NULL);
}

static int netvsc_rndis_halt_device(struct netvsc_device *device)
{
	struct netvsc_control *control = netvsc_control_allocate(device, 0, 0);
	unsigned int index;
	int length;
	int rc;

	if (!control)
		return -ENOSPC;
	index = netvsc_control_index(device, control);
	length = netvsc_rndis_build_halt(netvsc_control_pages[index],
			NETVSC_CONTROL_PAGE_SIZE, control->request_id);
	if (length < 0) {
		netvsc_control_release(device, control);
		return -EINVAL;
	}
	control->request_length = (__u32)length;
	rc = netvsc_rndis_execute(device, control, NULL, NULL, NULL);
	if (!rc)
		device->rndis_initialized = 0;
	return rc;
}

static int netvsc_nvs_exchange(struct netvsc_device *device,
			       const __u8 *request, size_t request_length,
			       __u32 expected_type, __u8 *response,
			       size_t *response_length)
{
	struct netvsc_nvs_wait *wait = &device->nvs_wait;
	unsigned long flags;
	__u64 transaction_id;
	__u64 deadline;
	int published = 0;
	int rc;

	if (!netvsc_can_wait() || !response || !response_length)
		return -EWOULDBLOCK;
	rc = netvsc_transaction_id(device, &transaction_id);
	if (rc)
		return rc;
	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	if (wait->active) {
		ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
		return -EBUSY;
	}
	zero_bytes(wait, sizeof(*wait));
	wait->active = 1;
	wait->transaction_id = transaction_id;
	wait->expected_type = expected_type;
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);

	rc = vmbus_channel_send_ex(device->channel,
			VMBUS_PACKET_DATA_INBAND,
			VMBUS_PACKET_FLAG_REQUEST_COMPLETION, transaction_id,
			NULL, 0, request, request_length, &published);
	if (rc) {
		if (published)
			netvsc_fail_channel(device);
		ukplat_spin_lock_irqsave(&device->control_lock, flags);
		wait->active = 0;
		netvsc_remember_transaction(device, transaction_id);
		ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
		return rc;
	}
	deadline = netvsc_deadline();
	for (;;) {
		unsigned int done;

		netvsc_drain_channel(device);
		ukplat_spin_lock_irqsave(&device->control_lock, flags);
		done = wait->done;
		rc = wait->error;
		ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
		if (done)
			break;
		if (ukplat_monotonic_clock() >= deadline) {
			ukplat_spin_lock_irqsave(&device->control_lock, flags);
			if (wait->active &&
			    wait->transaction_id == transaction_id) {
				netvsc_remember_transaction(device,
							 transaction_id);
				zero_bytes(wait, sizeof(*wait));
			}
			ukplat_spin_unlock_irqrestore(&device->control_lock,
						     flags);
			return -ETIMEDOUT;
		}
		netvsc_wait_once();
	}

	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	if (wait->response_length > *response_length)
		rc = -ENOBUFS;
	else {
		copy_bytes(response, wait->response, wait->response_length);
		*response_length = wait->response_length;
	}
	netvsc_remember_transaction(device, transaction_id);
	zero_bytes(wait, sizeof(*wait));
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
	return rc;
}

static int netvsc_nvs_send(struct netvsc_device *device,
			   const __u8 *request, size_t request_length)
{
	int published = 0;
	int rc = vmbus_channel_send_ex(device->channel,
			VMBUS_PACKET_DATA_INBAND, 0, 0, NULL, 0,
			request, request_length, &published);

	if (rc && published)
		netvsc_fail_channel(device);
	return rc;
}

static int netvsc_negotiate_nvs(struct netvsc_device *device)
{
	__u8 request[NETVSC_NVS_REQUEST_SIZE];
	__u8 response[NETVSC_NVS_RESPONSE_SIZE];
	unsigned int i;

	for (i = 0; i < netvsc_nvs_version_count(); i++) {
		struct netvsc_nvs_init_complete complete;
		size_t response_length = sizeof(response);
		__u32 version = netvsc_nvs_version(i);
		int length = netvsc_nvs_build_init(request, sizeof(request),
						   version);
		int rc;

		if (length < 0)
			return -EINVAL;
		rc = netvsc_nvs_exchange(device, request, (size_t)length,
				2, response, &response_length);
		if (rc)
			return rc;
		rc = netvsc_nvs_parse_init_complete(response,
				response_length, version, &complete);
		if (rc == NETVSC_PROTOCOL_VERSION_UNSUPPORTED)
			continue;
		if (rc)
			return -EPROTO;
		device->nvs_version = version;
		device->ndis_version = netvsc_nvs_ndis_version(version);
		return device->ndis_version ? 0 : -EPROTO;
	}
	return -ENODEV;
}

static int netvsc_connect_receive_buffer(struct netvsc_device *device)
{
	__u8 request[NETVSC_NVS_REQUEST_SIZE];
	__u8 response[NETVSC_NVS_RESPONSE_SIZE];
	size_t response_length = sizeof(response);
	int length;
	int rc;

	device->receive_buffer_size = device->nvs_version <=
		NETVSC_NVS_VERSION_2 ? NETVSC_RX_BUFFER_LEGACY_SIZE :
		(__u32)NETVSC_RX_BUFFER_SIZE;
	if (device->receive_buffer_size > NETVSC_RX_BUFFER_SIZE)
		return -EINVAL;
	rc = vmbus_channel_gpadl_map(device->channel, netvsc_receive_buffer,
			device->receive_buffer_size, &device->receive_gpadl);
	if (rc)
		return rc;
	length = netvsc_nvs_build_receive_buffer(request, sizeof(request),
						 device->receive_gpadl.id);
	if (length < 0)
		return -EINVAL;
	rc = netvsc_nvs_exchange(device, request, (size_t)length,
			102, response, &response_length);
	if (rc)
		return rc;
	rc = netvsc_nvs_parse_receive_buffer_complete(response,
			response_length, device->receive_buffer_size,
			device->receive_sections,
			NETVSC_NVS_MAX_SECTIONS,
			&device->receive_section_count);
	if (rc)
		return -EPROTO;
	device->receive_connected = 1;
	return 0;
}

static int netvsc_connect_send_buffer(struct netvsc_device *device)
{
	struct netvsc_nvs_send_buffer_complete complete;
	__u8 request[NETVSC_NVS_REQUEST_SIZE];
	__u8 response[NETVSC_NVS_RESPONSE_SIZE];
	size_t response_length = sizeof(response);
	int length;
	int rc;

	rc = vmbus_channel_gpadl_map(device->channel, netvsc_send_buffer,
			NETVSC_SEND_BUFFER_SIZE, &device->send_gpadl);
	if (rc)
		return rc;
	length = netvsc_nvs_build_send_buffer(request, sizeof(request),
					      device->send_gpadl.id);
	if (length < 0)
		return -EINVAL;
	rc = netvsc_nvs_exchange(device, request, (size_t)length,
			105, response, &response_length);
	if (rc)
		return rc;
	rc = netvsc_nvs_parse_send_buffer_complete(response,
			response_length, (__u32)NETVSC_SEND_BUFFER_SIZE,
			&complete);
	if (rc)
		return -EPROTO;
	device->send_section_size = complete.section_size;
	device->send_section_count = complete.section_count;
	if (device->send_section_count > NETVSC_SECTION_LIMIT)
		device->send_section_count = NETVSC_SECTION_LIMIT;
	zero_bytes(device->section_used, sizeof(device->section_used));
	device->send_connected = 1;
	return 0;
}

static int netvsc_send_ndis_setup(struct netvsc_device *device)
{
	__u8 request[NETVSC_NVS_REQUEST_SIZE];
	int length;
	int rc;

	if (device->nvs_version >= NETVSC_NVS_VERSION_2) {
		length = netvsc_nvs_build_ndis_config(request,
				sizeof(request), device->mtu +
				NETVSC_ETH_HEADER);
		if (length < 0)
			return -EINVAL;
		rc = netvsc_nvs_send(device, request, (size_t)length);
		if (rc)
			return rc;
	}
	length = netvsc_nvs_build_ndis_version(request, sizeof(request),
					       device->ndis_version);
	if (length < 0)
		return -EINVAL;
	return netvsc_nvs_send(device, request, (size_t)length);
}

static int netvsc_mac_valid(const __u8 *address)
{
	unsigned int i;
	__u8 any = 0;

	if (address[0] & 1)
		return 0;
	for (i = 0; i < UK_NETDEV_HWADDR_LEN; i++)
		any |= address[i];
	return any != 0;
}

static int netvsc_query_device(struct netvsc_device *device)
{
	__u8 address[UK_NETDEV_HWADDR_LEN];
	__u8 scalar[4];
	__u32 value;
	__u32 total_size;
	size_t length;
	int rc;

	length = sizeof(address);
	rc = netvsc_rndis_query(device,
			NETVSC_OID_802_3_PERMANENT_ADDRESS,
			address, &length);
	if (rc || length != sizeof(address) || !netvsc_mac_valid(address))
		return -EPROTO;
	copy_bytes(device->permanent_address.addr_bytes, address,
		   sizeof(address));

	length = sizeof(address);
	rc = netvsc_rndis_query(device, NETVSC_OID_802_3_CURRENT_ADDRESS,
			address, &length);
	if (rc || length != sizeof(address) || !netvsc_mac_valid(address))
		copy_bytes(address, device->permanent_address.addr_bytes,
			   sizeof(address));
	copy_bytes(device->current_address.addr_bytes, address,
		   sizeof(address));

	length = sizeof(scalar);
	rc = netvsc_rndis_query(device, NETVSC_OID_GEN_MAXIMUM_FRAME_SIZE,
			scalar, &length);
	if (rc || length != sizeof(scalar))
		return -EPROTO;
	value = read_le32(scalar);
	if (value < 68 || value > UINT16_MAX)
		return -EPROTO;
	length = sizeof(scalar);
	rc = netvsc_rndis_query(device, NETVSC_OID_GEN_MAXIMUM_TOTAL_SIZE,
			scalar, &length);
	if (rc || length != sizeof(scalar))
		return -EPROTO;
	total_size = read_le32(scalar);
	if (total_size < value ||
	    total_size - value < NETVSC_ETH_HEADER)
		return -EPROTO;
	device->max_mtu = (__u16)value;
	if (device->mtu > device->max_mtu)
		device->mtu = device->max_mtu;

	length = sizeof(scalar);
	rc = netvsc_rndis_query(device,
			NETVSC_OID_GEN_MEDIA_CONNECT_STATUS,
			scalar, &length);
	if (rc || length != sizeof(scalar))
		return -EPROTO;
	value = read_le32(scalar);
	if (value > 1)
		return -EPROTO;
	__atomic_store_n(&device->link_up, value == 0, __ATOMIC_RELEASE);
	return netvsc_rndis_keepalive_device(device);
}

static __u32 netvsc_packet_filter(const struct netvsc_device *device)
{
	__u32 filter = NETVSC_PACKET_FILTER_DIRECTED |
		NETVSC_PACKET_FILTER_BROADCAST |
		NETVSC_PACKET_FILTER_ALL_MULTICAST;

	if (device->promiscuous)
		filter |= NETVSC_PACKET_FILTER_PROMISCUOUS;
	return filter;
}

static int netvsc_set_packet_filter(struct netvsc_device *device,
				    __u32 filter)
{
	__u8 value[4];

	write_le32(value, filter);
	return netvsc_rndis_set(device,
			NETVSC_OID_GEN_CURRENT_PACKET_FILTER,
			value, sizeof(value));
}

static void netvsc_complete_nvs(struct netvsc_device *device,
				const struct vmbus_packet *packet,
				const __u8 *payload, size_t payload_length)
{
	struct netvsc_nvs_wait *wait = &device->nvs_wait;
	unsigned long flags;
	__u32 message_type = 0;

	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	if (!wait->active || wait->transaction_id != packet->transaction_id) {
		ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
		return;
	}
	if (wait->done) {
		ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
		return;
	}
	if (payload_length > sizeof(wait->response)) {
		wait->error = -ENOBUFS;
		wait->done = 1;
		ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
		return;
	}
	if (netvsc_nvs_message_type(payload, payload_length,
				    &message_type) ||
	    message_type != wait->expected_type) {
		wait->error = -EPROTO;
		wait->done = 1;
		ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
		return;
	}
	copy_bytes(wait->response, payload, payload_length);
	wait->response_length = (__u16)payload_length;
	wait->done = 1;
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
}

static int netvsc_complete_control_tx(struct netvsc_device *device,
				      const struct vmbus_packet *packet,
				      const __u8 *payload,
				      size_t payload_length)
{
	struct netvsc_control_release release = {
		.section = NETVSC_INVALID_SECTION,
	};
	unsigned long flags;
	unsigned int i;
	__u32 section = NETVSC_INVALID_SECTION;
	int found = 0;
	int parse_result = netvsc_nvs_parse_rndis_completion(payload,
							      payload_length);

	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	for (i = 0; i < CONFIG_LIBNETVSC_CONTROL_SLOTS; i++) {
		struct netvsc_control *control = &device->controls[i];

		if (control->state == NETVSC_CONTROL_FREE ||
		    control->transaction_id != packet->transaction_id)
			continue;
		found = 1;
		if (control->state == NETVSC_CONTROL_FINALIZING) {
			netvsc_count_duplicate_completion(device);
			break;
		}
		if (control->state == NETVSC_CONTROL_BUILDING) {
			if (control->nvs_completion_pending ||
			    control->nvs_done)
				netvsc_count_duplicate_completion(device);
			else {
				control->nvs_completion_pending = 1;
				if (parse_result)
					control->error = -EPROTO;
			}
			break;
		}
		if (control->nvs_done) {
			netvsc_count_duplicate_completion(device);
		} else {
			control->nvs_done = 1;
			if (parse_result)
				control->error = -EPROTO;
			section = control->section_index;
			control->section_index = NETVSC_INVALID_SECTION;
		}
		if (control->state == NETVSC_CONTROL_CANCELLED &&
		    !control->waiter_owned && control->nvs_done)
			netvsc_control_elect_release_locked(device, control,
							    &release);
		break;
	}
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
	netvsc_send_section_release(device, section);
	netvsc_control_finish_release(device, &release);
	return found;
}

struct netvsc_tx_release {
	struct netvsc_tx_context *context;
	struct uk_netbuf *packet;
	__u64 transaction_id;
	__u32 section;
	__u8 malformed;
	int elected;
};

static void netvsc_tx_elect_completion_locked(
				struct netvsc_device *device,
				struct netvsc_tx_context *context,
				struct netvsc_tx_release *release)
{
	if (context->state != NETVSC_TX_BUILDING &&
	    context->state != NETVSC_TX_SENT)
		return;
	release->context = context;
	release->packet = context->packet;
	release->transaction_id = context->transaction_id;
	release->section = context->section_index;
	release->malformed = context->completion_malformed;
	release->elected = 1;
	context->packet = NULL;
	context->section_index = NETVSC_INVALID_SECTION;
	context->state = NETVSC_TX_COMPLETING;
	if (release->section < NETVSC_SECTION_LIMIT)
		device->section_used[release->section] = 0;
	netvsc_remember_transaction(device, release->transaction_id);
}

static void netvsc_tx_finish_completion(struct netvsc_device *device,
					struct netvsc_tx_release *release)
{
	unsigned long flags;

	if (!release->elected)
		return;
	if (release->malformed)
		(void)__atomic_add_fetch(&device->malformed_messages, 1,
					 __ATOMIC_RELAXED);
	if (release->packet)
		uk_netbuf_free(release->packet);
	ukplat_spin_lock_irqsave(&device->tx_lock, flags);
	if (release->context->state == NETVSC_TX_COMPLETING &&
	    release->context->transaction_id == release->transaction_id) {
		zero_bytes(release->context, sizeof(*release->context));
		release->context->section_index = NETVSC_INVALID_SECTION;
	}
	ukplat_spin_unlock_irqrestore(&device->tx_lock, flags);
}

static int netvsc_complete_tx(struct netvsc_device *device,
			      const struct vmbus_packet *packet,
			      const __u8 *payload, size_t payload_length)
{
	struct netvsc_tx_release release = {
		.section = NETVSC_INVALID_SECTION,
	};
	unsigned long flags;
	unsigned int i;
	int found = 0;
	int malformed =
		netvsc_nvs_parse_rndis_completion(payload, payload_length) != 0;

	ukplat_spin_lock_irqsave(&device->tx_lock, flags);
	for (i = 0; i < CONFIG_LIBNETVSC_TX_SLOTS; i++) {
		struct netvsc_tx_context *context = &device->tx[i];

		if (context->state == NETVSC_TX_FREE ||
		    context->transaction_id != packet->transaction_id)
			continue;
		found = 1;
		if (context->state == NETVSC_TX_BUILDING) {
			if (context->completion_pending)
				netvsc_count_duplicate_completion(device);
			else {
				context->completion_pending = 1;
				context->completion_malformed = malformed;
			}
			break;
		}
		if (context->state == NETVSC_TX_COMPLETING) {
			netvsc_count_duplicate_completion(device);
			break;
		}
		context->completion_malformed = malformed;
		netvsc_tx_elect_completion_locked(device, context, &release);
		break;
	}
	ukplat_spin_unlock_irqrestore(&device->tx_lock, flags);
	if (!found)
		return 0;
	netvsc_tx_finish_completion(device, &release);
	return 1;
}

static void netvsc_handle_completion(struct netvsc_device *device,
				     const struct vmbus_packet *packet,
				     const __u8 *payload,
				     size_t payload_length)
{
	unsigned long flags;

	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	if (device->nvs_wait.active &&
	    device->nvs_wait.transaction_id == packet->transaction_id) {
		ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
		netvsc_complete_nvs(device, packet, payload, payload_length);
		return;
	}
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
	if (netvsc_complete_control_tx(device, packet, payload,
				       payload_length))
		return;
	if (netvsc_complete_tx(device, packet, payload, payload_length))
		return;
	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	if (netvsc_known_transaction(device, packet->transaction_id))
		netvsc_count_duplicate_completion(device);
	else
		netvsc_count_unknown_completion(device);
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
}

static void netvsc_handle_rndis_completion(struct netvsc_device *device,
					   const __u8 *message,
					   size_t message_length,
					   __u32 request_id)
{
	struct netvsc_rndis_completion completion;
	unsigned long flags;
	unsigned int i;
	__u32 expected = 0;
	int found = 0;
	int parse_result;

	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	for (i = 0; i < CONFIG_LIBNETVSC_CONTROL_SLOTS; i++) {
		if (device->controls[i].state == NETVSC_CONTROL_FREE ||
		    device->controls[i].request_id != request_id)
			continue;
		if (device->controls[i].state ==
		    NETVSC_CONTROL_FINALIZING ||
		    device->controls[i].rndis_done) {
			netvsc_count_duplicate_completion(device);
			ukplat_spin_unlock_irqrestore(&device->control_lock,
						     flags);
			return;
		}
		expected = device->controls[i].expected_type;
		found = 1;
		break;
	}
	if (!found) {
		if (netvsc_known_request(device, request_id))
			netvsc_count_duplicate_completion(device);
		else
			netvsc_count_unknown_completion(device);
		ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
		return;
	}
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);

	parse_result = netvsc_rndis_parse_completion(message, message_length,
			expected, request_id, &completion);
	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	if (device->controls[i].state == NETVSC_CONTROL_FREE ||
	    device->controls[i].state == NETVSC_CONTROL_FINALIZING ||
	    device->controls[i].request_id != request_id) {
		ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
		return;
	}
	if (device->controls[i].rndis_done) {
		netvsc_count_duplicate_completion(device);
		ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
		return;
	}
	if (parse_result) {
		device->controls[i].error = -EPROTO;
	} else {
		device->controls[i].completion = completion;
		if (completion.info_length) {
			if (completion.info_length > NETVSC_CONTROL_INFO_SIZE) {
				device->controls[i].error = -EMSGSIZE;
			} else {
				copy_bytes(device->control_info[i],
					message + completion.info_offset,
					completion.info_length);
				device->controls[i].info_length =
					(__u16)completion.info_length;
			}
		}
	}
	device->controls[i].rndis_done = 1;
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
}

static int netvsc_copy_frame(struct netvsc_device *device,
			     const __u8 *frame, __u32 frame_length)
{
	struct uk_netbuf *packet = NULL;
	struct uk_netbuf *segment;
	struct uk_netbuf *previous = NULL;
	struct uk_netbuf *last_used = NULL;
	struct uk_netbuf *allocated[1] = { NULL };
	size_t remaining = frame_length;
	size_t source_offset = 0;
	unsigned int segments = 0;
	unsigned int count;
	unsigned long flags;

	if (!__atomic_load_n(&device->running, __ATOMIC_ACQUIRE) ||
	    !__atomic_load_n(&device->host_running, __ATOMIC_ACQUIRE) ||
	    !device->rxq.configured ||
	    frame_length < NETVSC_MIN_FRAME ||
	    frame_length > (__u32)device->mtu + NETVSC_ETH_HEADER_MAX)
		return -EINVAL;
	count = device->rxq.alloc_rxpkts(device->rxq.alloc_rxpkts_argp,
					 allocated, 1);
	if (count != 1 || !allocated[0]) {
		if (count && allocated[0])
			uk_netbuf_free(allocated[0]);
		return -ENOMEM;
	}
	packet = allocated[0];
	for (segment = packet; segment; segment = segment->next) {
		uintptr_t data = (uintptr_t)segment->data;
		uintptr_t buffer = (uintptr_t)segment->buf;
		size_t offset;
		size_t capacity;
		size_t take;

		if (++segments > NETVSC_GPA_MAX_RANGES || segment->prev !=
		    previous || data < buffer || data - buffer > segment->buflen) {
			uk_netbuf_free(packet);
			return -EINVAL;
		}
		offset = data - buffer;
		capacity = segment->len;
		if (capacity > segment->buflen - offset) {
			uk_netbuf_free(packet);
			return -EINVAL;
		}
		if (!capacity && remaining) {
			uk_netbuf_free(packet);
			return -EINVAL;
		}
		take = capacity < remaining ? capacity : remaining;
		if (take)
			copy_bytes(segment->data, frame + source_offset, take);
		segment->len = (__u16)take;
		if (take)
			last_used = segment;
		segment->flags = 0;
		source_offset += take;
		remaining -= take;
		previous = segment;
	}
	if (remaining) {
		uk_netbuf_free(packet);
		return -ENOBUFS;
	}
	if (!last_used) {
		uk_netbuf_free(packet);
		return -EINVAL;
	}
	if (last_used->next) {
		segment = last_used->next;
		last_used->next = NULL;
		segment->prev = NULL;
		uk_netbuf_free(segment);
	}

	ukplat_spin_lock_irqsave(&device->rx_lock, flags);
	if (!__atomic_load_n(&device->running, __ATOMIC_ACQUIRE) ||
	    !__atomic_load_n(&device->host_running, __ATOMIC_ACQUIRE) ||
	    device->receive_count >= device->rxq.descriptors ||
	    device->receive_count >= CONFIG_LIBNETVSC_RX_SLOTS) {
		ukplat_spin_unlock_irqrestore(&device->rx_lock, flags);
		uk_netbuf_free(packet);
		return -ENOSPC;
	}
	device->receive_ready[device->receive_head] = packet;
	device->receive_head = (device->receive_head + 1) %
		CONFIG_LIBNETVSC_RX_SLOTS;
	device->receive_count++;
	__atomic_add_fetch(&device->receive_events, 1, __ATOMIC_RELEASE);
	ukplat_spin_unlock_irqrestore(&device->rx_lock, flags);
	return 0;
}

static int netvsc_handle_rndis(struct netvsc_device *device,
			       const __u8 *message, size_t message_length,
			       __u32 channel_type __unused)
{
	struct netvsc_rndis_packet_info packet;
	struct netvsc_rndis_status_info status;
	__u32 type;
	__u32 declared;
	int rc;

	rc = netvsc_rndis_message_type(message, message_length, &type,
				       &declared);
	if (rc)
		return -EPROTO;
	switch (type) {
	case NETVSC_RNDIS_PACKET:
		rc = netvsc_rndis_parse_packet(message, message_length,
					      &packet);
		if (rc)
			return -EPROTO;
		return netvsc_copy_frame(device, message + packet.data_offset,
					 packet.data_length);
	case NETVSC_RNDIS_INITIALIZE_COMPLETE:
	case NETVSC_RNDIS_QUERY_COMPLETE:
	case NETVSC_RNDIS_SET_COMPLETE:
	case NETVSC_RNDIS_KEEPALIVE_COMPLETE:
		if (declared < 12)
			return -EPROTO;
		netvsc_handle_rndis_completion(device, message, declared,
					       read_le32(message + 8));
		return 0;
	case NETVSC_RNDIS_INDICATE_STATUS:
		rc = netvsc_rndis_parse_status(message, message_length,
					      &status);
		if (rc)
			return -EPROTO;
		if (status.link_state >= 0)
			__atomic_store_n(&device->link_up,
					 status.link_state != 0,
					 __ATOMIC_RELEASE);
		return 0;
	default:
		return -EPROTO;
	}
}

static int netvsc_ack_send(struct netvsc_device *device, __u64 transaction_id,
			   __u32 status)
{
	__u8 acknowledgement[NETVSC_NVS_REQUEST_SIZE];
	int length = netvsc_nvs_build_rndis_ack(acknowledgement,
			sizeof(acknowledgement), status);
	int published = 0;
	int rc;

	if (length < 0)
		return -EINVAL;
	rc = vmbus_channel_send_ex(device->channel,
			VMBUS_PACKET_COMPLETION,
			0, transaction_id, NULL, 0, acknowledgement,
			(size_t)length, &published);
	if (rc && published)
		netvsc_fail_channel(device);
	return published ? 0 : rc;
}

static void netvsc_ack_queue(struct netvsc_device *device,
			     __u64 transaction_id, __u32 status)
{
	unsigned long flags;
	struct netvsc_pending_ack *ack;

	ukplat_spin_lock_irqsave(&device->state_lock, flags);
	if (device->pending_ack_count >= NETVSC_ACK_SLOTS) {
		__atomic_store_n(&device->failed, 1, __ATOMIC_RELEASE);
		ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
		return;
	}
	ack = &device->pending_acks[device->pending_ack_head];
	ack->transaction_id = transaction_id;
	ack->generation = device->generation;
	ack->status = status;
	device->pending_ack_head = (device->pending_ack_head + 1) %
		NETVSC_ACK_SLOTS;
	device->pending_ack_count++;
	ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
}

static void netvsc_retry_acks(struct netvsc_device *device)
{
	unsigned long flags;

	for (;;) {
		struct netvsc_pending_ack ack;
		__u32 generation;
		int rc;

		ukplat_spin_lock_irqsave(&device->state_lock, flags);
		if (!device->pending_ack_count) {
			ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
			return;
		}
		ack = device->pending_acks[device->pending_ack_tail];
		generation = device->generation;
		ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
		if (ack.generation != generation)
			rc = 0;
		else
			rc = netvsc_ack_send(device, ack.transaction_id,
					     ack.status);
		if (rc == -EAGAIN)
			return;
		ukplat_spin_lock_irqsave(&device->state_lock, flags);
		device->pending_ack_tail = (device->pending_ack_tail + 1) %
			NETVSC_ACK_SLOTS;
		device->pending_ack_count--;
		if (rc)
			__atomic_store_n(&device->failed, 1,
					 __ATOMIC_RELEASE);
		ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
	}
}

static int netvsc_handle_transfer(struct netvsc_device *device,
				  const struct vmbus_packet *packet,
				  const __u8 *descriptor,
				  size_t descriptor_length,
				  const __u8 *payload,
				  size_t payload_length)
{
	struct netvsc_transfer_range range;
	__u32 range_count;
	__u32 channel_type;
	__u32 status = NETVSC_NVS_STATUS_OK;
	unsigned int i;
	int rc;

	rc = netvsc_nvs_parse_rndis(payload, payload_length, &channel_type);
	if (rc)
		status = NETVSC_NVS_STATUS_FAILED;
	rc = netvsc_nvs_transfer_range_count(descriptor,
			descriptor_length, &range_count);
	if (rc)
		status = NETVSC_NVS_STATUS_FAILED;
	if (status == NETVSC_NVS_STATUS_OK) {
		for (i = 0; i < range_count; i++) {
			rc = netvsc_nvs_parse_transfer_range(descriptor,
					descriptor_length, i,
					device->receive_buffer_size,
					device->receive_sections,
					device->receive_section_count,
					&range);
			if (rc || range.offset > device->receive_buffer_size ||
			    range.length >
				    device->receive_buffer_size - range.offset ||
			    netvsc_handle_rndis(device,
				    &netvsc_receive_buffer[range.offset],
				    range.length, channel_type)) {
				status = NETVSC_NVS_STATUS_FAILED;
				device->malformed_messages++;
			}
		}
	}
	rc = netvsc_ack_send(device, packet->transaction_id, status);
	if (rc == -EAGAIN)
		netvsc_ack_queue(device, packet->transaction_id, status);
	else if (rc)
		__atomic_store_n(&device->failed, 1, __ATOMIC_RELEASE);
	return status == NETVSC_NVS_STATUS_OK ? 0 : -EPROTO;
}

static void netvsc_drain_channel(struct netvsc_device *device)
{
	struct vmbus_packet packet;
	__u32 receive_events;
	int notify = 0;

	if (!device->channel)
		return;
	if (__atomic_exchange_n(&device->drain_active, 1,
				 __ATOMIC_ACQ_REL)) {
		__atomic_store_n(&device->drain_pending, 1,
				 __ATOMIC_RELEASE);
		return;
	}
	for (;;) {
		__atomic_store_n(&device->drain_pending, 0,
				 __ATOMIC_RELEASE);
		receive_events = __atomic_load_n(&device->receive_events,
						 __ATOMIC_ACQUIRE);
		netvsc_retry_acks(device);
		for (;;) {
			unsigned long flags;
			int acknowledgements_full;
			int rc;

			ukplat_spin_lock_irqsave(&device->state_lock, flags);
			acknowledgements_full =
				device->pending_ack_count >= NETVSC_ACK_SLOTS;
			ukplat_spin_unlock_irqrestore(
				&device->state_lock, flags);
			if (acknowledgements_full)
				break;
			rc = vmbus_channel_receive(device->channel, &packet,
					netvsc_descriptor_scratch,
					sizeof(netvsc_descriptor_scratch),
					netvsc_payload_scratch,
					sizeof(netvsc_payload_scratch));

			if (rc == -EAGAIN)
				break;
			if (rc) {
				if (rc == -EPROTO || rc == -ENOBUFS)
					netvsc_fail_channel(device);
				else if (rc != -ECANCELED)
					__atomic_store_n(&device->failed, 1,
							 __ATOMIC_RELEASE);
				break;
			}
			if (packet.trailer_mismatch)
				device->malformed_messages++;
			switch (packet.type) {
			case VMBUS_PACKET_COMPLETION:
				netvsc_handle_completion(device, &packet,
					netvsc_payload_scratch,
					packet.payload_size);
				break;
			case VMBUS_PACKET_DATA_USING_TRANSFER_PAGES:
				(void)netvsc_handle_transfer(device, &packet,
					netvsc_descriptor_scratch,
					packet.descriptor_size,
					netvsc_payload_scratch,
					packet.payload_size);
				break;
			case VMBUS_PACKET_DATA_INBAND:
				break;
			default:
				device->malformed_messages++;
				break;
			}
		}
		netvsc_retry_acks(device);
		{
			unsigned long flags;

			ukplat_spin_lock_irqsave(&device->rx_lock, flags);
			if (__atomic_load_n(&device->receive_events,
					    __ATOMIC_ACQUIRE) != receive_events &&
			    device->receive_count &&
			    device->rxq.interrupt_armed) {
				device->rxq.interrupt_armed = 0;
				notify = 1;
			}
			ukplat_spin_unlock_irqrestore(&device->rx_lock,
						     flags);
		}
		if (__atomic_exchange_n(&device->drain_pending, 0,
					__ATOMIC_ACQ_REL))
			continue;
		__atomic_store_n(&device->drain_active, 0,
				 __ATOMIC_RELEASE);
		if (!__atomic_exchange_n(&device->drain_pending, 0,
					 __ATOMIC_ACQ_REL))
			break;
		if (__atomic_exchange_n(&device->drain_active, 1,
					 __ATOMIC_ACQ_REL))
			break;
	}
	if (notify) {
		unsigned long flags;

		ukplat_spin_lock_irqsave(&device->rx_lock, flags);
		notify = device->rxq.interrupt_requested;
		ukplat_spin_unlock_irqrestore(&device->rx_lock, flags);
	}
	if (notify) {
		if (__atomic_load_n(&device->running, __ATOMIC_ACQUIRE) &&
		    __atomic_load_n(&device->host_running,
				    __ATOMIC_ACQUIRE) &&
		    device->registered)
			uk_netdev_drv_rx_event(&device->netdev, 0);
	}
}

static void netvsc_channel_callback(struct vmbus_channel *channel, void *arg)
{
	struct netvsc_device *device = arg;

	if (device->channel != channel)
		return;
	netvsc_drain_channel(device);
}

static int netvsc_frame_length(struct uk_netbuf *packet, __u32 *length)
{
	struct uk_netbuf *current;
	struct uk_netbuf *previous = NULL;
	__u32 total = 0;
	unsigned int count = 0;

	if (!packet || packet->prev ||
	    (packet->flags & (UK_NETBUF_F_PARTIAL_CSUM |
			      UK_NETBUF_F_GSO_TCPV4)))
		return -ENOTSUP;
	for (current = packet; current; current = current->next) {
		uintptr_t buffer = (uintptr_t)current->buf;
		uintptr_t data = (uintptr_t)current->data;

		if (++count >= NETVSC_GPA_MAX_RANGES ||
		    current->prev != previous || data < buffer ||
		    data - buffer > current->buflen ||
		    current->len > current->buflen - (data - buffer) ||
		    total > UINT32_MAX - current->len)
			return -EINVAL;
		total += current->len;
		previous = current;
	}
	if (!total)
		return -EINVAL;
	*length = total;
	return 0;
}

static struct netvsc_tx_context *
netvsc_tx_allocate(struct netvsc_device *device, __u64 transaction_id)
{
	unsigned int i;
	unsigned int active = 0;

	for (i = 0; i < CONFIG_LIBNETVSC_TX_SLOTS; i++)
		active += device->tx[i].state != NETVSC_TX_FREE;
	if (active >= device->txq.descriptors)
		return NULL;
	for (i = 0; i < CONFIG_LIBNETVSC_TX_SLOTS; i++) {
		if (device->tx[i].state != NETVSC_TX_FREE)
			continue;
		zero_bytes(&device->tx[i], sizeof(device->tx[i]));
		device->tx[i].state = NETVSC_TX_BUILDING;
		device->tx[i].transaction_id = transaction_id;
		device->tx[i].section_index = NETVSC_INVALID_SECTION;
		return &device->tx[i];
	}
	return NULL;
}

static int netvsc_tx_has_room(struct netvsc_device *device)
{
	unsigned int i;
	unsigned int active = 0;

	for (i = 0; i < CONFIG_LIBNETVSC_TX_SLOTS; i++)
		active += device->tx[i].state != NETVSC_TX_FREE;
	return active < device->txq.descriptors;
}

static void netvsc_tx_rollback(struct netvsc_device *device,
			       struct netvsc_tx_context *context,
			       __u64 transaction_id)
{
	unsigned long flags;

	ukplat_spin_lock_irqsave(&device->tx_lock, flags);
	if (context->state == NETVSC_TX_BUILDING &&
	    context->transaction_id == transaction_id) {
		if (context->completion_pending)
			netvsc_count_early_completion(device);
		if (context->section_index < NETVSC_SECTION_LIMIT)
			device->section_used[context->section_index] = 0;
		netvsc_remember_transaction(device, transaction_id);
		zero_bytes(context, sizeof(*context));
		context->section_index = NETVSC_INVALID_SECTION;
	}
	ukplat_spin_unlock_irqrestore(&device->tx_lock, flags);
}

static int netvsc_tx_publish(struct netvsc_device *device,
			     struct netvsc_tx_context *context,
			     __u64 transaction_id)
{
	struct netvsc_tx_release release = {
		.section = NETVSC_INVALID_SECTION,
	};
	unsigned long flags;
	int rc = 0;

	ukplat_spin_lock_irqsave(&device->tx_lock, flags);
	if (context->state != NETVSC_TX_BUILDING ||
	    context->transaction_id != transaction_id) {
		rc = -ECANCELED;
	} else {
		context->state = NETVSC_TX_SENT;
		if (context->completion_pending)
			netvsc_tx_elect_completion_locked(device, context,
							  &release);
	}
	ukplat_spin_unlock_irqrestore(&device->tx_lock, flags);
	netvsc_tx_finish_completion(device, &release);
	return rc;
}

static int netvsc_tx_append_range(struct netvsc_tx_context *context,
				  const void *data, __u32 length)
{
	struct vmbus_gpa_range *range;
	__u32 remaining_pfns;
	int rc;

	if (!length)
		return 0;
	if (context->range_count >= NETVSC_GPA_MAX_RANGES ||
	    context->pfn_count >= NETVSC_GPA_MAX_PFNS)
		return -E2BIG;
	range = &context->ranges[context->range_count];
	remaining_pfns = NETVSC_GPA_MAX_PFNS - context->pfn_count;
	rc = netvsc_single_gpa(data, length, range,
			&context->pfns[context->pfn_count], remaining_pfns);
	if (rc)
		return rc;
	context->pfn_count += range->pfn_count;
	context->range_count++;
	return 0;
}

static int netvsc_tx_one(struct uk_netdev *netdev,
			 struct uk_netdev_tx_queue *queue,
			 struct uk_netbuf *packet)
{
	struct netvsc_device *device =
		__containerof(netdev, struct netvsc_device, netdev);
	struct netvsc_tx_context *context;
	struct uk_netbuf *segment;
	__u8 nvs[NETVSC_NVS_REQUEST_SIZE];
	unsigned long flags;
	__u64 transaction_id;
	__u32 frame_length;
	__u32 section = NETVSC_INVALID_SECTION;
	int published = 0;
	int nvs_length;
	int rc;
	int result;

	UK_ASSERT(queue == &device->txq);
	rc = netvsc_operation_begin(device, 1);
	if (rc)
		return rc;
	if (__atomic_load_n(&device->failed, __ATOMIC_ACQUIRE)) {
		result = -ENODEV;
		goto out;
	}
	if (!__atomic_load_n(&device->link_up, __ATOMIC_ACQUIRE)) {
		result = -ENETDOWN;
		goto out;
	}
	rc = netvsc_frame_length(packet, &frame_length);
	if (rc) {
		result = rc;
		goto out;
	}
	if (frame_length < NETVSC_MIN_FRAME ||
	    frame_length > (__u32)device->mtu + NETVSC_ETH_HEADER_MAX) {
		result = -EMSGSIZE;
		goto out;
	}
	netvsc_drain_channel(device);
	rc = netvsc_transaction_id(device, &transaction_id);
	if (rc) {
		result = rc;
		goto out;
	}

	ukplat_spin_lock_irqsave(&device->tx_lock, flags);
	context = netvsc_tx_allocate(device, transaction_id);
	if (!context) {
		ukplat_spin_unlock_irqrestore(&device->tx_lock, flags);
		result = 0;
		goto out;
	}
	context->packet = packet;
	rc = netvsc_rndis_build_packet_header(context->header,
			sizeof(context->header), frame_length);
	if (rc < 0) {
		ukplat_spin_unlock_irqrestore(&device->tx_lock, flags);
		netvsc_tx_rollback(device, context, transaction_id);
		result = -EINVAL;
		goto out;
	}

	if (device->send_connected &&
	    frame_length + NETVSC_RNDIS_HEADER_SIZE <=
		    device->send_section_size) {
		unsigned int i;

		for (i = 0; i < device->send_section_count; i++)
			if (!device->section_used[i]) {
				device->section_used[i] = 1;
				section = i;
				break;
			}
	}
	context->section_index = section;
	ukplat_spin_unlock_irqrestore(&device->tx_lock, flags);
	NETVSC_TX_STAGE(NETVSC_TX_STAGE_BEFORE_COPY, transaction_id);

	if (section != NETVSC_INVALID_SECTION) {
		__u64 offset = (__u64)section * device->send_section_size;
		__u32 cursor = NETVSC_RNDIS_HEADER_SIZE;

		if (offset > NETVSC_SEND_BUFFER_SIZE ||
		    frame_length + cursor > NETVSC_SEND_BUFFER_SIZE - offset) {
			rc = -EINVAL;
			goto reject;
		}
		copy_bytes(&netvsc_send_buffer[offset], context->header,
			   sizeof(context->header));
		NETVSC_TX_STAGE(NETVSC_TX_STAGE_SECTION_COPY,
				 transaction_id);
		for (segment = packet; segment; segment = segment->next) {
			copy_bytes(&netvsc_send_buffer[offset + cursor],
				   segment->data, segment->len);
			cursor += segment->len;
		}
		nvs_length = netvsc_nvs_build_rndis(nvs, sizeof(nvs),
				NETVSC_NVS_RNDIS_DATA, section, cursor);
		if (nvs_length < 0) {
			rc = -EINVAL;
			goto reject;
		}
		rc = vmbus_channel_send_ex(device->channel,
				VMBUS_PACKET_DATA_INBAND,
				VMBUS_PACKET_FLAG_REQUEST_COMPLETION,
				transaction_id, NULL, 0, nvs,
				(size_t)nvs_length, &published);
	} else {
		rc = netvsc_tx_append_range(context, context->header,
					     sizeof(context->header));
		if (!rc)
			NETVSC_TX_STAGE(NETVSC_TX_STAGE_BUILD_RANGES,
					 transaction_id);
		for (segment = packet; !rc && segment; segment = segment->next)
			rc = netvsc_tx_append_range(context, segment->data,
						    segment->len);
		if (rc)
			goto reject;
		nvs_length = netvsc_nvs_build_rndis(nvs, sizeof(nvs),
				NETVSC_NVS_RNDIS_DATA,
				NETVSC_NVS_SEND_SECTION_INVALID, 0);
		if (nvs_length < 0) {
			rc = -EINVAL;
			goto reject;
		}
		rc = vmbus_channel_send_gpa_direct_ex(device->channel,
				VMBUS_PACKET_FLAG_REQUEST_COMPLETION,
				transaction_id, context->ranges,
				context->range_count, nvs,
				(size_t)nvs_length, &published);
	}
	if (!published) {
		if (!rc)
			rc = -EIO;
		goto reject;
	}
	NETVSC_TX_STAGE(NETVSC_TX_STAGE_AFTER_PUBLISH, transaction_id);
	if (netvsc_tx_publish(device, context, transaction_id))
		netvsc_fail_channel(device);
	if (rc)
		netvsc_fail_channel(device);
	result = UK_NETDEV_STATUS_SUCCESS;
	ukplat_spin_lock_irqsave(&device->tx_lock, flags);
	if (netvsc_tx_has_room(device))
		result |= UK_NETDEV_STATUS_MORE;
	ukplat_spin_unlock_irqrestore(&device->tx_lock, flags);
	goto out;

reject:
	netvsc_tx_rollback(device, context, transaction_id);
	result = rc == -EAGAIN ? 0 : rc;
out:
	netvsc_operation_end(device);
	return result;
}

static int netvsc_rx_one(struct uk_netdev *netdev,
			 struct uk_netdev_rx_queue *queue,
			 struct uk_netbuf **packet)
{
	struct netvsc_device *device =
		__containerof(netdev, struct netvsc_device, netdev);
	unsigned long flags;
	int status = 0;
	int rc;

	UK_ASSERT(queue == &device->rxq);
	*packet = NULL;
	rc = netvsc_operation_begin(device, 1);
	if (rc)
		return rc;
	netvsc_drain_channel(device);
	ukplat_spin_lock_irqsave(&device->rx_lock, flags);
	if (device->receive_count) {
		*packet = device->receive_ready[device->receive_tail];
		device->receive_ready[device->receive_tail] = NULL;
		device->receive_tail = (device->receive_tail + 1) %
			CONFIG_LIBNETVSC_RX_SLOTS;
		device->receive_count--;
		status = UK_NETDEV_STATUS_SUCCESS;
		if (device->receive_count)
			status |= UK_NETDEV_STATUS_MORE;
	}
	if (!device->receive_count && queue->interrupt_requested)
		queue->interrupt_armed = 1;
	ukplat_spin_unlock_irqrestore(&device->rx_lock, flags);
	netvsc_operation_end(device);
	return status;
}

static int netvsc_probe(struct uk_netdev *netdev)
{
	struct netvsc_device *device =
		__containerof(netdev, struct netvsc_device, netdev);

	return __atomic_load_n(&device->attached, __ATOMIC_ACQUIRE) &&
		!__atomic_load_n(&device->failed, __ATOMIC_ACQUIRE) ?
		0 : -ENODEV;
}

static void netvsc_info_get(struct uk_netdev *netdev,
			    struct uk_netdev_info *info)
{
	struct netvsc_device *device =
		__containerof(netdev, struct netvsc_device, netdev);

	info->max_rx_queues = 1;
	info->max_tx_queues = 1;
	info->max_mtu = device->max_mtu;
	info->nb_encap_tx = 0;
	info->nb_encap_rx = 0;
	info->ioalign = 1;
	info->features = UK_NETDEV_F_RXQ_INTR;
}

static int netvsc_configure(struct uk_netdev *netdev,
			    const struct uk_netdev_conf *configuration)
{
	struct netvsc_device *device =
		__containerof(netdev, struct netvsc_device, netdev);
	int rc;

	rc = netvsc_operation_begin(device, 0);
	if (rc)
		return rc;
	if (configuration->nb_rx_queues != 1 ||
	    configuration->nb_tx_queues != 1 || configuration->lro) {
		netvsc_operation_end(device);
		return -ENOTSUP;
	}
	device->configured = 1;
	netvsc_operation_end(device);
	return 0;
}

static int netvsc_rxq_info_get(struct uk_netdev *netdev __unused,
			       __u16 queue_id,
			       struct uk_netdev_queue_info *info)
{
	if (queue_id)
		return -EINVAL;
	info->nb_min = 1;
	info->nb_max = CONFIG_LIBNETVSC_RX_SLOTS;
	info->nb_align = 1;
	info->nb_is_power_of_two = 0;
	return 0;
}

static int netvsc_txq_info_get(struct uk_netdev *netdev __unused,
			       __u16 queue_id,
			       struct uk_netdev_queue_info *info)
{
	if (queue_id)
		return -EINVAL;
	info->nb_min = 1;
	info->nb_max = CONFIG_LIBNETVSC_TX_SLOTS;
	info->nb_align = 1;
	info->nb_is_power_of_two = 0;
	return 0;
}

static struct uk_netdev_rx_queue *
netvsc_rxq_configure(struct uk_netdev *netdev, __u16 queue_id,
		      __u16 descriptors,
		      struct uk_netdev_rxqueue_conf *configuration)
{
	struct netvsc_device *device =
		__containerof(netdev, struct netvsc_device, netdev);
	int rc;

	if (queue_id || !configuration || !configuration->alloc_rxpkts ||
	    descriptors > CONFIG_LIBNETVSC_RX_SLOTS)
		return ERR2PTR(-EINVAL);
	rc = netvsc_operation_begin(device, 0);
	if (rc)
		return ERR2PTR(rc);
	if (!descriptors)
		descriptors = CONFIG_LIBNETVSC_RX_SLOTS;
	device->rxq.alloc_rxpkts = configuration->alloc_rxpkts;
	device->rxq.alloc_rxpkts_argp = configuration->alloc_rxpkts_argp;
	device->rxq.descriptors = descriptors;
	device->rxq.configured = 1;
	netvsc_operation_end(device);
	return &device->rxq;
}

static struct uk_netdev_tx_queue *
netvsc_txq_configure(struct uk_netdev *netdev, __u16 queue_id,
		      __u16 descriptors,
		      struct uk_netdev_txqueue_conf *configuration __unused)
{
	struct netvsc_device *device =
		__containerof(netdev, struct netvsc_device, netdev);
	int rc;

	if (queue_id || descriptors > CONFIG_LIBNETVSC_TX_SLOTS)
		return ERR2PTR(-EINVAL);
	rc = netvsc_operation_begin(device, 0);
	if (rc)
		return ERR2PTR(rc);
	if (!descriptors)
		descriptors = CONFIG_LIBNETVSC_TX_SLOTS;
	device->txq.descriptors = descriptors;
	device->txq.configured = 1;
	netvsc_operation_end(device);
	return &device->txq;
}

static int netvsc_start(struct uk_netdev *netdev)
{
	struct netvsc_device *device =
		__containerof(netdev, struct netvsc_device, netdev);
	unsigned long flags;
	int rc;

	rc = netvsc_operation_begin(device, 0);
	if (rc)
		return rc;
	if (!device->configured || !device->rxq.configured ||
	    !device->txq.configured) {
		netvsc_operation_end(device);
		return -EINVAL;
	}
	rc = netvsc_set_packet_filter(device, netvsc_packet_filter(device));
	if (rc) {
		netvsc_operation_end(device);
		return rc;
	}
	rc = netvsc_rndis_keepalive_device(device);
	if (rc) {
		netvsc_operation_end(device);
		return rc;
	}
	ukplat_spin_lock_irqsave(&device->state_lock, flags);
	if (device->stopping)
		rc = -ECANCELED;
	else {
		unsigned long rx_flags;

		ukplat_spin_lock_irqsave(&device->rx_lock, rx_flags);
		device->rxq.interrupt_requested = 0;
		device->rxq.interrupt_armed = 0;
		ukplat_spin_unlock_irqrestore(&device->rx_lock, rx_flags);
		device->running = 1;
		device->host_running = 1;
	}
	ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
	netvsc_operation_end(device);
	return rc;
}

static int netvsc_rx_intr_enable(struct uk_netdev *netdev,
				 struct uk_netdev_rx_queue *queue)
{
	struct netvsc_device *device =
		__containerof(netdev, struct netvsc_device, netdev);
	unsigned long flags;
	int pending;
	int rc;

	UK_ASSERT(queue == &device->rxq);
	rc = netvsc_operation_begin(device, 1);
	if (rc)
		return rc;
	netvsc_drain_channel(device);
	ukplat_spin_lock_irqsave(&device->rx_lock, flags);
	queue->interrupt_requested = 1;
	pending = device->receive_count != 0;
	queue->interrupt_armed = !pending;
	ukplat_spin_unlock_irqrestore(&device->rx_lock, flags);
	netvsc_operation_end(device);
	return pending;
}

static int netvsc_rx_intr_disable(struct uk_netdev *netdev,
				  struct uk_netdev_rx_queue *queue)
{
	struct netvsc_device *device =
		__containerof(netdev, struct netvsc_device, netdev);
	unsigned long flags;
	int rc;

	UK_ASSERT(queue == &device->rxq);
	rc = netvsc_operation_begin(device, 1);
	if (rc)
		return rc;
	ukplat_spin_lock_irqsave(&device->rx_lock, flags);
	queue->interrupt_requested = 0;
	queue->interrupt_armed = 0;
	ukplat_spin_unlock_irqrestore(&device->rx_lock, flags);
	netvsc_operation_end(device);
	return 0;
}

static const struct uk_hwaddr *netvsc_hwaddr_get(struct uk_netdev *netdev)
{
	struct netvsc_device *device =
		__containerof(netdev, struct netvsc_device, netdev);

	return &device->current_address;
}

static __u16 netvsc_mtu_get(struct uk_netdev *netdev)
{
	struct netvsc_device *device =
		__containerof(netdev, struct netvsc_device, netdev);

	return device->mtu;
}

static unsigned int netvsc_promiscuous_get(struct uk_netdev *netdev)
{
	struct netvsc_device *device =
		__containerof(netdev, struct netvsc_device, netdev);

	return device->promiscuous;
}

static int netvsc_promiscuous_set(struct uk_netdev *netdev,
				  unsigned int enabled)
{
	struct netvsc_device *device =
		__containerof(netdev, struct netvsc_device, netdev);
	__u8 previous = device->promiscuous;
	int rc;

	rc = netvsc_operation_begin(device, 1);
	if (rc)
		return rc;
	device->promiscuous = enabled != 0;
	rc = netvsc_set_packet_filter(device, netvsc_packet_filter(device));
	if (rc)
		device->promiscuous = previous;
	netvsc_operation_end(device);
	return rc;
}

static const struct uk_netdev_ops netvsc_ops = {
	.probe = netvsc_probe,
	.configure = netvsc_configure,
	.rxq_configure = netvsc_rxq_configure,
	.txq_configure = netvsc_txq_configure,
	.start = netvsc_start,
	.rxq_intr_enable = netvsc_rx_intr_enable,
	.rxq_intr_disable = netvsc_rx_intr_disable,
	.info_get = netvsc_info_get,
	.promiscuous_get = netvsc_promiscuous_get,
	.promiscuous_set = netvsc_promiscuous_set,
	.hwaddr_get = netvsc_hwaddr_get,
	.mtu_get = netvsc_mtu_get,
	.txq_info_get = netvsc_txq_info_get,
	.rxq_info_get = netvsc_rxq_info_get,
};

static void netvsc_free_queued_packets(struct netvsc_device *device)
{
	struct uk_netbuf *packets[CONFIG_LIBNETVSC_RX_SLOTS];
	unsigned long flags;
	unsigned int count = 0;

	ukplat_spin_lock_irqsave(&device->rx_lock, flags);
	while (device->receive_count) {
		packets[count++] =
			device->receive_ready[device->receive_tail];
		device->receive_ready[device->receive_tail] = NULL;
		device->receive_tail = (device->receive_tail + 1) %
			CONFIG_LIBNETVSC_RX_SLOTS;
		device->receive_count--;
	}
	device->receive_head = device->receive_tail = 0;
	device->rxq.interrupt_armed =
		device->rxq.interrupt_requested;
	ukplat_spin_unlock_irqrestore(&device->rx_lock, flags);
	while (count)
		uk_netbuf_free(packets[--count]);
}

static void netvsc_cancel_tx(struct netvsc_device *device, int quarantine)
{
	struct uk_netbuf *packets[CONFIG_LIBNETVSC_TX_SLOTS];
	unsigned long flags;
	unsigned int i;
	unsigned int count = 0;

	ukplat_spin_lock_irqsave(&device->tx_lock, flags);
	for (i = 0; i < CONFIG_LIBNETVSC_TX_SLOTS; i++) {
		if (device->tx[i].state == NETVSC_TX_FREE)
			continue;
		if (device->tx[i].packet) {
			if (quarantine && device->quarantined_tx_count <
			    CONFIG_LIBNETVSC_TX_SLOTS)
				device->quarantined_tx[
					device->quarantined_tx_count++] =
					device->tx[i].packet;
			else
				packets[count++] = device->tx[i].packet;
		}
		if (device->tx[i].section_index < NETVSC_SECTION_LIMIT)
			device->section_used[device->tx[i].section_index] = 0;
		netvsc_remember_transaction(device,
					    device->tx[i].transaction_id);
		zero_bytes(&device->tx[i], sizeof(device->tx[i]));
		device->tx[i].section_index = NETVSC_INVALID_SECTION;
	}
	ukplat_spin_unlock_irqrestore(&device->tx_lock, flags);
	while (count)
		uk_netbuf_free(packets[--count]);
}

static void netvsc_release_quarantined_tx(struct netvsc_device *device)
{
	struct uk_netbuf *packets[CONFIG_LIBNETVSC_TX_SLOTS];
	unsigned long flags;
	unsigned int count;

	ukplat_spin_lock_irqsave(&device->tx_lock, flags);
	count = device->quarantined_tx_count;
	if (count)
		copy_bytes(packets, device->quarantined_tx,
			   count * sizeof(packets[0]));
	zero_bytes(device->quarantined_tx,
		   sizeof(device->quarantined_tx));
	device->quarantined_tx_count = 0;
	ukplat_spin_unlock_irqrestore(&device->tx_lock, flags);
	while (count)
		uk_netbuf_free(packets[--count]);
}

static void netvsc_cancel_controls(struct netvsc_device *device)
{
	unsigned long flags;
	unsigned int i;
	__u32 sections[CONFIG_LIBNETVSC_CONTROL_SLOTS];
	unsigned int section_count = 0;

	ukplat_spin_lock_irqsave(&device->control_lock, flags);
	if (device->nvs_wait.active) {
		netvsc_remember_transaction(device,
				device->nvs_wait.transaction_id);
		zero_bytes(&device->nvs_wait, sizeof(device->nvs_wait));
	}
	for (i = 0; i < CONFIG_LIBNETVSC_CONTROL_SLOTS; i++) {
		if (device->controls[i].state == NETVSC_CONTROL_FREE)
			continue;
		if (device->controls[i].section_index !=
		    NETVSC_INVALID_SECTION)
			sections[section_count++] =
				device->controls[i].section_index;
		netvsc_remember_transaction(device,
				device->controls[i].transaction_id);
		netvsc_remember_request(device,
				device->controls[i].request_id);
		zero_bytes(&device->controls[i],
			   sizeof(device->controls[i]));
		device->controls[i].section_index =
			NETVSC_INVALID_SECTION;
	}
	ukplat_spin_unlock_irqrestore(&device->control_lock, flags);
	for (i = 0; i < section_count; i++)
		netvsc_send_section_release(device, sections[i]);
}

static void netvsc_detach_host(struct netvsc_device *device, int revoked)
{
	__u8 request[NETVSC_NVS_REQUEST_SIZE];
	unsigned long flags;
	int close_rc = 0;
	int quarantine;
	int recovering;
	int length;

	ukplat_spin_lock_irqsave(&device->state_lock, flags);
	device->stopping = 1;
	device->host_running = 0;
	ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
	recovering = __atomic_load_n(&device->recovering,
				    __ATOMIC_ACQUIRE);
	for (;;) {
		unsigned int operations;

		ukplat_spin_lock_irqsave(&device->state_lock, flags);
		operations = device->operations;
		ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
		if (!operations)
			break;
		netvsc_wait_once();
	}
	if (!revoked && !recovering && device->channel &&
	    device->rndis_initialized) {
		if (device->running)
			(void)netvsc_set_packet_filter(device,
					NETVSC_PACKET_FILTER_NONE);
		(void)netvsc_rndis_halt_device(device);
	}
	if (!revoked && !recovering && device->channel &&
	    device->send_connected) {
		length = netvsc_nvs_build_revoke_send_buffer(request,
						      sizeof(request));
		if (length > 0)
			(void)netvsc_nvs_send(device, request, (size_t)length);
	}
	if (!revoked && !recovering && device->channel &&
	    device->receive_connected) {
		length = netvsc_nvs_build_revoke_receive_buffer(request,
							 sizeof(request));
		if (length > 0)
			(void)netvsc_nvs_send(device, request, (size_t)length);
	}
	if (device->channel)
		vmbus_channel_set_callback(device->channel, NULL, NULL);
	while (__atomic_load_n(&device->drain_active, __ATOMIC_ACQUIRE))
		netvsc_wait_once();
	if (!revoked && device->channel)
		close_rc = vmbus_channel_close(device->channel);
	recovering = __atomic_load_n(&device->recovering,
				    __ATOMIC_ACQUIRE);
	if (!revoked && close_rc && !recovering) {
		netvsc_fail_channel(device);
		recovering = 1;
	}
	/*
	 * GPA-direct TX and control pages remain host-owned until the channel
	 * is quiesced. Release packet ownership only after close, or after a
	 * rescind has already revoked host access.
	 */
	netvsc_cancel_controls(device);
	quarantine = recovering || (!revoked && close_rc);
	netvsc_cancel_tx(device, quarantine);
	netvsc_free_queued_packets(device);
	ukplat_spin_lock_irqsave(&device->state_lock, flags);
	device->pending_ack_head = 0;
	device->pending_ack_tail = 0;
	device->pending_ack_count = 0;
	zero_bytes(device->pending_acks, sizeof(device->pending_acks));
	ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
	zero_bytes(&device->send_gpadl, sizeof(device->send_gpadl));
	zero_bytes(&device->receive_gpadl, sizeof(device->receive_gpadl));
	ukplat_spin_lock_irqsave(&device->state_lock, flags);
	device->channel = NULL;
	device->vmbus_device = NULL;
	device->attached = 0;
	device->attaching = 0;
	device->stopping = 0;
	device->receive_connected = 0;
	device->send_connected = 0;
	device->rndis_initialized = 0;
	device->receive_section_count = 0;
	device->send_section_count = 0;
	device->send_section_size = 0;
	device->recovering = 0;
	device->failed = 0;
	ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
}

static int netvsc_attach_host(struct netvsc_device *device,
			      struct vmbus_device *vmbus_device)
{
	struct uk_alloc *allocator;
	unsigned long flags;
	int rc;

	netvsc_init_once(device);
	if (device->quarantined_wait_vmbus) {
		if (vmbus_connection_quiesce_epoch() ==
		    device->quarantined_vmbus_epoch)
			return vmbus_device_bind_retry(vmbus_device);
		netvsc_release_quarantined_tx(device);
		device->quarantined_wait_vmbus = 0;
		device->quarantined_vmbus_epoch = 0;
		vmbus_device_bind_ready();
	} else {
		netvsc_release_quarantined_tx(device);
	}
	ukplat_spin_lock_irqsave(&device->state_lock, flags);
	if (device->attaching || device->attached) {
		ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
		return -EBUSY;
	}
	if (!device->generation || device->generation == UINT16_MAX) {
		if (device->generation == UINT16_MAX) {
			ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
			return -ENOSPC;
		}
		device->generation = 1;
	} else {
		device->generation++;
	}
	device->next_request = 1;
	device->next_transaction = 1;
	device->attaching = 1;
	device->stopping = 0;
	device->recovering = 0;
	device->vmbus_device = vmbus_device;
	device->failed = 0;
	ukplat_spin_unlock_irqrestore(&device->state_lock, flags);

	rc = vmbus_channel_open(vmbus_device,
			CONFIG_LIBNETVSC_CHANNEL_TX_PAGES,
			CONFIG_LIBNETVSC_CHANNEL_RX_PAGES, NULL, 0);
	if (rc)
		goto failed;
	device->channel = vmbus_device->channel;
	if (!device->channel) {
		rc = -ENODEV;
		goto failed;
	}
	vmbus_channel_set_callback(device->channel,
				   netvsc_channel_callback, device);
	rc = netvsc_negotiate_nvs(device);
	if (rc)
		goto failed;
	rc = netvsc_send_ndis_setup(device);
	if (rc)
		goto failed;
	rc = netvsc_connect_receive_buffer(device);
	if (rc)
		goto failed;
	rc = netvsc_connect_send_buffer(device);
	if (rc)
		goto failed;
	rc = netvsc_rndis_initialize_device(device);
	if (rc)
		goto failed;
	rc = netvsc_query_device(device);
	if (rc)
		goto failed;

	if (!device->registered) {
		allocator = uk_alloc_get_default();
		if (!allocator) {
			rc = -ENOMEM;
			goto failed;
		}
		device->netdev.rx_one = netvsc_rx_one;
		device->netdev.tx_one = netvsc_tx_one;
		device->netdev.ops = &netvsc_ops;
		rc = uk_netdev_drv_register(&device->netdev, allocator,
					     NETVSC_DRIVER_NAME);
		if (rc < 0)
			goto failed;
		device->registered = 1;
	}
	if (device->running) {
		rc = netvsc_set_packet_filter(device,
					      netvsc_packet_filter(device));
		if (rc)
			goto failed;
	}
	ukplat_spin_lock_irqsave(&device->state_lock, flags);
	device->host_running = device->running;
	device->attached = 1;
	device->attaching = 0;
	ukplat_spin_unlock_irqrestore(&device->state_lock, flags);
	uk_pr_info("NetVSC: channel %u NVS 0x%x, MAC "
		   "%02x:%02x:%02x:%02x:%02x:%02x, MTU %u\n",
		   vmbus_device->channel_id, device->nvs_version,
		   device->current_address.addr_bytes[0],
		   device->current_address.addr_bytes[1],
		   device->current_address.addr_bytes[2],
		   device->current_address.addr_bytes[3],
		   device->current_address.addr_bytes[4],
		   device->current_address.addr_bytes[5], device->mtu);
	return 0;

failed:
	netvsc_detach_host(device, 0);
	return rc;
}

static int netvsc_add_device(struct vmbus_device *device)
{
	if (!device || device->subchannel_index)
		return -EINVAL;
	return netvsc_attach_host(&netvsc, device);
}

static void netvsc_remove_device(struct vmbus_device *device)
{
	int revoked = !device || !device->channel ||
		netvsc.channel != device->channel;

	netvsc_detach_host(&netvsc, revoked);
}

static const struct vmbus_device_id netvsc_device_ids[] = {
	{ .class_id = {
		.bytes = {
			0xf8, 0x61, 0x51, 0x63, 0xdf, 0x3e, 0x46, 0xc5,
			0x91, 0x3f, 0xf2, 0xd2, 0xf9, 0x65, 0xed, 0x0e,
		},
	} },
	{ .class_id = VMBUS_GUID_END },
};

static struct vmbus_driver netvsc_driver = {
	.name = NETVSC_DRIVER_NAME,
	.device_ids = netvsc_device_ids,
	.add_dev = netvsc_add_device,
	.remove_dev = netvsc_remove_device,
};

VMBUS_DRIVER_REGISTER(&netvsc_driver);

#ifdef NETVSC_HOST_TEST
struct netvsc_device *netvsc_host_device(void)
{
	netvsc_init_once(&netvsc);
	return &netvsc;
}

int netvsc_host_add_device(struct vmbus_device *device)
{
	return netvsc_add_device(device);
}

void netvsc_host_remove_device(struct vmbus_device *device)
{
	netvsc_remove_device(device);
}

struct uk_netdev *netvsc_host_netdev(void)
{
	return &netvsc.netdev;
}

__u8 *netvsc_host_receive_buffer(void)
{
	return netvsc_receive_buffer;
}

__u8 *netvsc_host_send_buffer(void)
{
	return netvsc_send_buffer;
}

size_t netvsc_host_receive_buffer_capacity(void)
{
	return sizeof(netvsc_receive_buffer);
}

size_t netvsc_host_send_buffer_capacity(void)
{
	return sizeof(netvsc_send_buffer);
}

__u32 netvsc_host_nvs_version(void)
{
	return netvsc.nvs_version;
}

__u32 netvsc_host_send_section_size(void)
{
	return netvsc.send_section_size;
}

__u16 netvsc_host_receive_count(void)
{
	return netvsc.receive_count;
}

__u16 netvsc_host_tx_active(void)
{
	unsigned int i;
	__u16 count = 0;

	for (i = 0; i < CONFIG_LIBNETVSC_TX_SLOTS; i++)
		count += netvsc.tx[i].state != NETVSC_TX_FREE;
	return count;
}

__u8 netvsc_host_tx_state(unsigned int index)
{
	return index < CONFIG_LIBNETVSC_TX_SLOTS ?
		netvsc.tx[index].state : NETVSC_TX_FREE;
}

__u64 netvsc_host_tx_transaction(unsigned int index)
{
	return index < CONFIG_LIBNETVSC_TX_SLOTS ?
		netvsc.tx[index].transaction_id : 0;
}

__u16 netvsc_host_quarantined_tx(void)
{
	return netvsc.quarantined_tx_count;
}

__u64 netvsc_host_control_transaction(unsigned int index)
{
	return index < CONFIG_LIBNETVSC_CONTROL_SLOTS ?
		netvsc.controls[index].transaction_id : 0;
}

__u32 netvsc_host_control_request(unsigned int index)
{
	return index < CONFIG_LIBNETVSC_CONTROL_SLOTS ?
		netvsc.controls[index].request_id : 0;
}

__u8 netvsc_host_control_state(unsigned int index)
{
	return index < CONFIG_LIBNETVSC_CONTROL_SLOTS ?
		netvsc.controls[index].state : NETVSC_CONTROL_FREE;
}

__u32 netvsc_host_unknown_completions(void)
{
	return __atomic_load_n(&netvsc.unknown_completions,
			       __ATOMIC_RELAXED);
}

__u32 netvsc_host_duplicate_completions(void)
{
	return __atomic_load_n(&netvsc.duplicate_completions,
			       __ATOMIC_RELAXED);
}

__u32 netvsc_host_early_completions(void)
{
	return __atomic_load_n(&netvsc.early_completions,
			       __ATOMIC_RELAXED);
}

__u32 netvsc_host_malformed_messages(void)
{
	return __atomic_load_n(&netvsc.malformed_messages,
			       __ATOMIC_RELAXED);
}

int netvsc_host_keepalive(void)
{
	return netvsc_rndis_keepalive_device(&netvsc);
}

void netvsc_host_reset(void)
{
	netvsc_init_once(&netvsc);
	netvsc_detach_host(&netvsc, 1);
	netvsc_release_quarantined_tx(&netvsc);
	netvsc.quarantined_wait_vmbus = 0;
	netvsc.quarantined_vmbus_epoch = 0;
	netvsc.registered = 0;
	netvsc.configured = 0;
	netvsc.running = 0;
	netvsc.rxq.configured = 0;
	netvsc.txq.configured = 0;
	netvsc.generation = 0;
	netvsc.next_request = 1;
	netvsc.next_transaction = 1;
	zero_bytes(netvsc.transaction_tombstones,
		   sizeof(netvsc.transaction_tombstones));
	zero_bytes(netvsc.request_tombstones,
		   sizeof(netvsc.request_tombstones));
}

int netvsc_host_process_transfer(const __u8 *descriptor,
				 size_t descriptor_length,
				 const __u8 *payload,
				 size_t payload_length,
				 __u64 transaction_id)
{
	struct vmbus_packet packet = {
		.type = VMBUS_PACKET_DATA_USING_TRANSFER_PAGES,
		.transaction_id = transaction_id,
	};

	return netvsc_handle_transfer(&netvsc, &packet, descriptor,
			descriptor_length, payload, payload_length);
}

int netvsc_host_control_in_use(void)
{
	unsigned int i;
	int count = 0;

	for (i = 0; i < CONFIG_LIBNETVSC_CONTROL_SLOTS; i++)
		count += netvsc.controls[i].state != NETVSC_CONTROL_FREE;
	return count;
}
#endif
