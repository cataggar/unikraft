/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <hyperv/hyperv.h>
#include <uk/arch/spinlock.h>
#include <uk/config.h>
#include <uk/paging.h>
#include <uk/plat/time.h>
#include <uk/print.h>
#include <uk/sched.h>
#include <uk/vmbus.h>

#include "vmbus_channel_core.h"
#include "vmbus_channel_args.h"
#include "vmbus_channel_owner.h"
#include "vmbus_channel_state.h"
#include "vmbus_internal.h"
#include "vmbus_page_pool.h"
#include "vmbus_protocol.h"
#include "vmbus_signal_policy.h"

#define VMBUS_PAGE_SIZE			4096U
#define VMBUS_CONTROL_TICKS_PER_MS	10000ULL
#define VMBUS_CONTROL_WAIT_NS		1000000ULL
#define VMBUS_MAX_GPA_RANGES		32U
#define VMBUS_MAX_GPA_PFNS		64U

enum vmbus_gpadl_record_state {
	VMBUS_GPADL_RECORD_FREE,
	VMBUS_GPADL_RECORD_OWNED,
	VMBUS_GPADL_RECORD_ASYNC,
	VMBUS_GPADL_RECORD_RESET,
	VMBUS_GPADL_RECORD_RECLAIMING,
};

struct vmbus_gpadl_record {
	struct vmbus_channel_transaction *transaction;
	__u64 channel_generation;
	__u32 gpadl_id;
	__u32 relid;
	__u16 page_start;
	__u16 page_count;
	__u8 state;
	__u8 host_done;
	__u8 local_drained;
};

struct vmbus_channel {
	struct vmbus_device *device;
	__u8 *tx_ring;
	__u8 *rx_ring;
	__u16 tx_pages;
	__u16 rx_pages;
	__u16 page_start;
	__u16 page_count;
	__u32 gpadl_id;
	__u32 open_id;
	__u32 relid;
	__u32 connection_id;
	__u64 relid_sequence;
	__u8 state;
	__u8 rescinded;
	__u8 event_pending;
	__u8 gpadl_live;
	__u8 close_posted;
	__u8 teardown_posted;
	__u8 gpadl_posted;
	__u16 gpadl_record;
	struct vmbus_channel_owner owner;
	__spinlock lifetime_lock;
	__spinlock tx_lock;
	__spinlock rx_lock;
	__spinlock signal_lock;
	struct vmbus_signal_input_abi signal_input __align(8);
	__u64 signal_input_gpa;
	vmbus_channel_callback_t callback;
	void *callback_arg;
};

static struct vmbus_channel channels[CONFIG_LIBVMBUS_MAX_DEVICES];
static struct vmbus_channel_transaction
	transactions[CONFIG_LIBVMBUS_MAX_TRANSACTIONS];
static struct vmbus_gpadl_record
	gpadl_records[CONFIG_LIBVMBUS_MAX_GPADLS];
static __u8 ring_pages[CONFIG_LIBVMBUS_RING_PAGES][VMBUS_PAGE_SIZE]
	__align(VMBUS_PAGE_SIZE);
static __u8 ring_page_used[CONFIG_LIBVMBUS_RING_PAGES];
static __u32 next_gpadl_id = 0x10000U;
static __u32 next_open_id = 1U;
static unsigned int live_gpadls;
static __u32 ignored_responses;
static __u64 next_channel_generation = 1;
static int channel_locks_initialized;
static __spinlock transaction_lock;
static const __u8 empty_input;
static __u8 empty_output;

/*
 * Lifetime state is sampled only under lifetime_lock. Data operations take a
 * reference there, drop it, then take tx_lock, rx_lock, or signal_lock and
 * revalidate. Revocation never holds lifetime_lock while waiting for an I/O
 * lock or issuing a hypercall, so callbacks may safely re-enter close paths.
 */
static void free_ring_pages(unsigned int start, unsigned int count);
static void
transaction_release(struct vmbus_channel_transaction *transaction);
static void gpadl_record_release(struct vmbus_gpadl_record *record,
				 int free_pages);
static void gpadl_record_try_reclaim(struct vmbus_gpadl_record *record);

static void initialize_channel_locks(void)
{
	unsigned int i;

	if (channel_locks_initialized)
		return;
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		ukarch_spin_init(&channels[i].lifetime_lock);
		ukarch_spin_init(&channels[i].tx_lock);
		ukarch_spin_init(&channels[i].rx_lock);
		ukarch_spin_init(&channels[i].signal_lock);
	}
	ukarch_spin_init(&transaction_lock);
	channel_locks_initialized = 1;
}

static int channel_operation_begin(struct vmbus_channel *channel,
				   struct vmbus_channel_token *token,
				   int require_open)
{
	unsigned long flags;
	int rc;

	if (!channel)
		return -ENODEV;
	ukplat_spin_lock_irqsave(&channel->lifetime_lock, flags);
	if (!channel->owner.generation || channel->state == CHANNEL_FREE)
		rc = -ENODEV;
	else if (channel->owner.revoked)
		rc = -ECANCELED;
	else if (require_open && channel->state != CHANNEL_OPEN)
		rc = -ENODEV;
	else
		rc = vmbus_channel_owner_begin(&channel->owner, token);
	ukplat_spin_unlock_irqrestore(&channel->lifetime_lock, flags);
	return rc;
}

static int channel_operation_pin(struct vmbus_channel *channel,
				 struct vmbus_channel_token *token)
{
	unsigned long flags;
	int rc = 0;

	ukplat_spin_lock_irqsave(&channel->lifetime_lock, flags);
	if (!channel->owner.generation || channel->state == CHANNEL_FREE ||
	    channel->owner.operations == UINT16_MAX ||
	    channel->owner.cleanup_pending)
		rc = -ENODEV;
	else {
		channel->owner.operations++;
		token->owner = &channel->owner;
		token->generation = channel->owner.generation;
	}
	ukplat_spin_unlock_irqrestore(&channel->lifetime_lock, flags);
	return rc;
}

static int channel_operation_valid(const struct vmbus_channel_token *token,
				   int require_open)
{
	struct vmbus_channel *channel;
	unsigned long flags;
	int valid;

	if (!token || !token->owner)
		return 0;
	channel = (struct vmbus_channel *)((char *)token->owner -
			offsetof(struct vmbus_channel, owner));
	ukplat_spin_lock_irqsave(&channel->lifetime_lock, flags);
	valid = vmbus_channel_owner_valid(token) &&
		(!require_open || channel->state == CHANNEL_OPEN);
	ukplat_spin_unlock_irqrestore(&channel->lifetime_lock, flags);
	return valid;
}

static int channel_revoke(struct vmbus_channel *channel, int rescinded)
{
	unsigned long flags;
	int cleanup_now;

	ukplat_spin_lock_irqsave(&channel->lifetime_lock, flags);
	if (rescinded)
		channel->rescinded = 1;
	cleanup_now = vmbus_channel_owner_revoke(&channel->owner);
	ukplat_spin_unlock_irqrestore(&channel->lifetime_lock, flags);
	return cleanup_now;
}

static void channel_synchronize_io(struct vmbus_channel *channel)
{
	unsigned long flags;

	ukplat_spin_lock_irqsave(&channel->tx_lock, flags);
	ukplat_spin_unlock_irqrestore(&channel->tx_lock, flags);
	ukplat_spin_lock_irqsave(&channel->rx_lock, flags);
	ukplat_spin_unlock_irqrestore(&channel->rx_lock, flags);
	ukarch_spin_lock(&channel->signal_lock);
	ukarch_spin_unlock(&channel->signal_lock);
}

static __u32 read_le32(const __u8 *p)
{
	return (__u32)p[0] | ((__u32)p[1] << 8) |
		((__u32)p[2] << 16) | ((__u32)p[3] << 24);
}

static __u64 channel_hypercall(void *arg __unused, __u64 input_gpa)
{
	return hyperv_hypercall(0x005d, input_gpa, 0);
}

static struct vmbus_channel *find_channel(__u32 channel_id)
{
	unsigned int i;

	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++)
		if (__atomic_load_n(&channels[i].state, __ATOMIC_ACQUIRE) !=
			    CHANNEL_FREE &&
		    channels[i].relid == channel_id)
			return &channels[i];
	return NULL;
}

static struct vmbus_channel *allocate_channel(struct vmbus_device *device)
{
	unsigned int i;
	unsigned long flags;

	if (device->channel)
		return device->channel;
	initialize_channel_locks();
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		ukplat_spin_lock_irqsave(&channels[i].lifetime_lock, flags);
		if (channels[i].state != CHANNEL_FREE ||
		    channels[i].owner.operations ||
		    channels[i].owner.cleanup_pending) {
			ukplat_spin_unlock_irqrestore(
				&channels[i].lifetime_lock, flags);
			continue;
		}
		if (!next_channel_generation) {
			ukplat_spin_unlock_irqrestore(
				&channels[i].lifetime_lock, flags);
			return NULL;
		}
		channels[i].device = device;
		channels[i].relid = device->channel_id;
		channels[i].connection_id = device->connection_id;
		channels[i].relid_sequence =
			vmbus_control_relid_sequence(device->channel_id);
		channels[i].owner.generation = next_channel_generation;
		next_channel_generation =
			next_channel_generation == UINT64_MAX ?
			0 : next_channel_generation + 1;
		channels[i].owner.operations = 0;
		channels[i].owner.revoked = 0;
		channels[i].owner.cleanup_pending = 0;
		channels[i].owner.cleanup_claimed = 0;
		channels[i].rescinded = 0;
		__atomic_store_n(&channels[i].state, CHANNEL_ALLOCATED,
				 __ATOMIC_RELEASE);
		device->channel = &channels[i];
		ukplat_spin_unlock_irqrestore(&channels[i].lifetime_lock,
					     flags);
		return &channels[i];
	}
	return NULL;
}

static void release_channel_object_locked(struct vmbus_channel *channel)
{
	if (channel->device && channel->device->channel == channel)
		channel->device->channel = NULL;
	channel->device = NULL;
	channel->tx_ring = NULL;
	channel->rx_ring = NULL;
	channel->tx_pages = 0;
	channel->rx_pages = 0;
	channel->page_start = 0;
	channel->page_count = 0;
	channel->gpadl_id = 0;
	channel->open_id = 0;
	channel->relid = 0;
	channel->connection_id = 0;
	channel->relid_sequence = 0;
	channel->rescinded = 0;
	channel->event_pending = 0;
	channel->gpadl_live = 0;
	channel->close_posted = 0;
	channel->teardown_posted = 0;
	channel->gpadl_posted = 0;
	channel->gpadl_record = 0;
	channel->owner.generation = 0;
	channel->owner.operations = 0;
	channel->owner.revoked = 0;
	channel->owner.cleanup_pending = 0;
	channel->owner.cleanup_claimed = 0;
	channel->callback = NULL;
	channel->callback_arg = NULL;
	channel->signal_input_gpa = 0;
	__atomic_store_n(&channel->state, CHANNEL_FREE, __ATOMIC_RELEASE);
}

static void finalize_channel_locked(struct vmbus_channel *channel)
{
	struct vmbus_gpadl_record *record = NULL;

	if (channel->gpadl_record &&
	    channel->gpadl_record <= CONFIG_LIBVMBUS_MAX_GPADLS)
		record = &gpadl_records[channel->gpadl_record - 1];
	if (record &&
	    (__atomic_load_n(&record->state, __ATOMIC_ACQUIRE) ==
		     VMBUS_GPADL_RECORD_ASYNC ||
	     __atomic_load_n(&record->state, __ATOMIC_ACQUIRE) ==
		     VMBUS_GPADL_RECORD_RESET)) {
		__atomic_store_n(&record->local_drained, 1, __ATOMIC_RELEASE);
		channel->gpadl_record = 0;
		gpadl_record_try_reclaim(record);
	}
	if (channel->page_count)
		free_ring_pages(channel->page_start, channel->page_count);
	release_channel_object_locked(channel);
}

#ifdef VMBUS_CHANNEL_HOST_TEST
static void release_channel_object(struct vmbus_channel *channel)
{
	unsigned long flags;

	ukplat_spin_lock_irqsave(&channel->lifetime_lock, flags);
	release_channel_object_locked(channel);
	ukplat_spin_unlock_irqrestore(&channel->lifetime_lock, flags);
	vmbus_control_channel_resource_released();
}
#endif

static void end_channel_operation(struct vmbus_channel *channel,
				  struct vmbus_channel_token *token)
{
	unsigned long flags;
	__u32 relid;
	__u64 relid_sequence;
	int release_relid;
	int cleanup;

	ukplat_spin_lock_irqsave(&channel->lifetime_lock, flags);
	cleanup = vmbus_channel_owner_end(token);
	if (cleanup) {
		relid = channel->relid;
		relid_sequence = channel->relid_sequence;
		release_relid = channel->rescinded;
		finalize_channel_locked(channel);
	} else {
		relid = 0;
		relid_sequence = 0;
		release_relid = 0;
	}
	ukplat_spin_unlock_irqrestore(&channel->lifetime_lock, flags);
	if (cleanup) {
		vmbus_control_channel_resource_released();
		if (release_relid &&
		    vmbus_control_release_relid(relid, relid_sequence))
			vmbus_control_fail();
	}
}

static int allocate_ring_pages(unsigned int count, unsigned int *start)
{
	return vmbus_page_pool_allocate(ring_page_used,
			CONFIG_LIBVMBUS_RING_PAGES, count, start);
}

static void free_ring_pages(unsigned int start, unsigned int count)
{
	if (!count)
		return;
	vmbus_page_pool_free(ring_page_used, CONFIG_LIBVMBUS_RING_PAGES,
			     start, count);
	vmbus_control_channel_resource_released();
}

static struct vmbus_gpadl_record *gpadl_record_allocate(void)
{
	unsigned int i;

	for (i = 0; i < CONFIG_LIBVMBUS_MAX_GPADLS; i++) {
		__u8 expected = VMBUS_GPADL_RECORD_FREE;

		if (!__atomic_compare_exchange_n(&gpadl_records[i].state,
				&expected, VMBUS_GPADL_RECORD_RECLAIMING, 0,
				__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
			continue;
		gpadl_records[i].transaction = NULL;
		gpadl_records[i].host_done = 0;
		gpadl_records[i].local_drained = 0;
		__atomic_add_fetch(&live_gpadls, 1, __ATOMIC_RELAXED);
		__atomic_store_n(&gpadl_records[i].state,
				 VMBUS_GPADL_RECORD_OWNED, __ATOMIC_RELEASE);
		return &gpadl_records[i];
	}
	return NULL;
}

static struct vmbus_gpadl_record *gpadl_record_find(__u32 gpadl_id)
{
	unsigned int i;

	for (i = 0; i < CONFIG_LIBVMBUS_MAX_GPADLS; i++) {
		if (__atomic_load_n(&gpadl_records[i].state,
				    __ATOMIC_ACQUIRE) !=
		    VMBUS_GPADL_RECORD_ASYNC)
			continue;
		if (gpadl_records[i].gpadl_id == gpadl_id)
			return &gpadl_records[i];
	}
	return NULL;
}

static void gpadl_record_release(struct vmbus_gpadl_record *record,
				 int free_pages)
{
	if (!record)
		return;
	if (record->transaction)
		transaction_release(record->transaction);
	if (free_pages && record->page_count)
		free_ring_pages(record->page_start, record->page_count);
	record->transaction = NULL;
	record->channel_generation = 0;
	record->gpadl_id = 0;
	record->relid = 0;
	record->page_start = 0;
	record->page_count = 0;
	record->host_done = 0;
	record->local_drained = 0;
	if (__atomic_load_n(&live_gpadls, __ATOMIC_RELAXED))
		__atomic_sub_fetch(&live_gpadls, 1, __ATOMIC_RELAXED);
	__atomic_store_n(&record->state, VMBUS_GPADL_RECORD_FREE,
			 __ATOMIC_RELEASE);
}

static void gpadl_record_try_reclaim(struct vmbus_gpadl_record *record)
{
	__u8 state;

	if (!__atomic_load_n(&record->host_done, __ATOMIC_ACQUIRE) ||
	    !__atomic_load_n(&record->local_drained, __ATOMIC_ACQUIRE))
		return;
	state = __atomic_load_n(&record->state, __ATOMIC_ACQUIRE);
	if (state != VMBUS_GPADL_RECORD_ASYNC &&
	    state != VMBUS_GPADL_RECORD_RESET)
		return;
	if (!__atomic_compare_exchange_n(&record->state, &state,
			VMBUS_GPADL_RECORD_RECLAIMING, 0,
			__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return;
	gpadl_record_release(record, 1);
}

static struct vmbus_gpadl_record *
channel_gpadl_record(struct vmbus_channel *channel)
{
	unsigned int index;

	if (!channel->gpadl_record)
		return NULL;
	index = channel->gpadl_record - 1;
	if (index >= CONFIG_LIBVMBUS_MAX_GPADLS ||
	    __atomic_load_n(&gpadl_records[index].state, __ATOMIC_ACQUIRE) ==
		    VMBUS_GPADL_RECORD_FREE ||
	    gpadl_records[index].gpadl_id != channel->gpadl_id ||
	    gpadl_records[index].channel_generation !=
		    channel->owner.generation)
		return NULL;
	return &gpadl_records[index];
}

static void quarantine_channel_pages(
	struct vmbus_channel *channel, struct vmbus_gpadl_record *record,
	struct vmbus_channel_transaction *transaction, int posted)
{
	/*
	 * TLFS completes a GPADL teardown with GPADL_TORNDOWN. FreeBSD's
	 * vmbus_chan_gpadl_disconnect likewise waits for that response and
	 * abandons the ring allocation when disconnect cannot be confirmed.
	 * Keep these pages unavailable until confirmation or connection reset.
	 */
	record->page_start = channel->page_start;
	record->page_count = channel->page_count;
	record->transaction = transaction;
	__atomic_store_n(&record->state,
			 posted ? VMBUS_GPADL_RECORD_ASYNC :
				  VMBUS_GPADL_RECORD_RESET,
			 __ATOMIC_RELEASE);
	channel->page_start = 0;
	channel->page_count = 0;
	channel->tx_ring = NULL;
	channel->rx_ring = NULL;
	channel->tx_pages = 0;
	channel->rx_pages = 0;
	channel->gpadl_id = 0;
	channel->gpadl_live = 0;
}

static void complete_async_gpadl(__u32 gpadl_id)
{
	struct vmbus_gpadl_record *record = gpadl_record_find(gpadl_id);

	if (!record ||
	    __atomic_load_n(&record->state, __ATOMIC_ACQUIRE) !=
		    VMBUS_GPADL_RECORD_ASYNC)
		return;
	__atomic_store_n(&record->host_done, 1, __ATOMIC_RELEASE);
	gpadl_record_try_reclaim(record);
}

static struct vmbus_channel_transaction *
transaction_allocate(enum vmbus_transaction_type type, __u32 channel_id,
		     __u32 id)
{
	struct vmbus_channel_transaction *transaction;
	unsigned long flags;

	ukplat_spin_lock_irqsave(&transaction_lock, flags);
	transaction = vmbus_transaction_allocate(transactions,
			CONFIG_LIBVMBUS_MAX_TRANSACTIONS, type, channel_id, id);
	ukplat_spin_unlock_irqrestore(&transaction_lock, flags);
	return transaction;
}

static struct vmbus_channel_transaction *
transaction_find(enum vmbus_transaction_type type, __u32 channel_id,
		 __u32 id)
{
	struct vmbus_channel_transaction *transaction = NULL;
	unsigned long flags;
	unsigned int i;

	ukplat_spin_lock_irqsave(&transaction_lock, flags);
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_TRANSACTIONS; i++)
		if (transactions[i].used && transactions[i].type == type &&
		    transactions[i].channel_id == channel_id &&
		    transactions[i].id == id) {
			transaction = &transactions[i];
			break;
		}
	ukplat_spin_unlock_irqrestore(&transaction_lock, flags);
	return transaction;
}

static void
transaction_release(struct vmbus_channel_transaction *transaction)
{
	unsigned long flags;
	int used;

	ukplat_spin_lock_irqsave(&transaction_lock, flags);
	used = transaction->used;
	vmbus_transaction_release(transaction);
	ukplat_spin_unlock_irqrestore(&transaction_lock, flags);
	if (used)
		vmbus_control_channel_resource_released();
}

static unsigned int transaction_cancel_channel(__u32 channel_id,
					       __u32 status)
{
	unsigned long flags;
	unsigned int cancelled;

	ukplat_spin_lock_irqsave(&transaction_lock, flags);
	cancelled = vmbus_transaction_cancel_channel_except(transactions,
			CONFIG_LIBVMBUS_MAX_TRANSACTIONS, channel_id,
			VMBUS_TRANSACTION_GPADL_TEARDOWN, status);
	ukplat_spin_unlock_irqrestore(&transaction_lock, flags);
	return cancelled;
}

static int
transaction_wait(struct vmbus_channel_transaction *transaction,
		 const struct vmbus_channel_token *token)
{
	__u64 deadline = hyperv_reference_time() +
		(__u64)CONFIG_LIBVMBUS_CHANNEL_TIMEOUT_MS *
		VMBUS_CONTROL_TICKS_PER_MS;
	int rc;

	while (!__atomic_load_n(&transaction->done, __ATOMIC_ACQUIRE)) {
		rc = vmbus_control_pump();
		if (rc)
			return rc;
		if (token && !channel_operation_valid(token, 0))
			return -ECANCELED;
		if (vmbus_transaction_timed_out(hyperv_reference_time(),
					       deadline))
			return -ETIMEDOUT;
		if (uk_sched_current())
			uk_sched_thread_sleep(VMBUS_CONTROL_WAIT_NS);
		else
			__asm__ __volatile__("pause");
	}
	if (transaction->status == (__u32)-ECANCELED)
		return -ECANCELED;
	return transaction->status ? -EIO : 0;
}

static int transmit_message(const __u8 *message, int length)
{
	if (length <= 0)
		return length ? length : -EINVAL;
	return vmbus_control_transmit(message, (size_t)length);
}

static int create_gpadl(struct vmbus_channel *channel,
			const struct vmbus_channel_token *token)
{
	struct vmbus_gpadl_record *record;
	struct vmbus_channel_transaction *transaction;
	__u64 pfns[CONFIG_LIBVMBUS_RING_PAGES];
	__u8 message[240];
	size_t consumed;
	size_t offset;
	unsigned int i;
	__u64 capacity_epoch;
	__u32 message_number = 1;
	int length;
	int rc;

	if (channel->page_count > CONFIG_LIBVMBUS_RING_PAGES)
		return -EINVAL;
	if (channel->gpadl_id || channel->gpadl_record)
		return -EBUSY;
	capacity_epoch =
		vmbus_control_channel_capacity_epoch(channel->device);
	record = gpadl_record_allocate();
	if (!record) {
		vmbus_control_note_channel_capacity(channel->device,
						    capacity_epoch);
		return -ENOSPC;
	}
	rc = vmbus_monotonic_id_allocate(&next_gpadl_id,
					 &channel->gpadl_id);
	if (rc) {
		gpadl_record_release(record, 0);
		return rc;
	}
	record->gpadl_id = channel->gpadl_id;
	record->relid = channel->relid;
	record->channel_generation = channel->owner.generation;
	record->page_start = channel->page_start;
	record->page_count = channel->page_count;
	channel->gpadl_record =
		(__u16)(record - &gpadl_records[0] + 1);
	capacity_epoch =
		vmbus_control_channel_capacity_epoch(channel->device);
	transaction = transaction_allocate(VMBUS_TRANSACTION_GPADL_CREATE,
			channel->relid, channel->gpadl_id);
	if (!transaction) {
		channel->gpadl_id = 0;
		channel->gpadl_record = 0;
		gpadl_record_release(record, 0);
		vmbus_control_note_channel_capacity(channel->device,
						    capacity_epoch);
		return -ENOSPC;
	}
	for (i = 0; i < channel->page_count; i++) {
		__paddr_t gpa = uk_paging_virt_to_phys(
			(__vaddr_t)&ring_pages[channel->page_start + i][0]);

		if (gpa == UK_PAGING_PADDR_INV || (gpa & (VMBUS_PAGE_SIZE - 1))) {
			rc = -EINVAL;
			goto out;
		}
		pfns[i] = gpa >> 12;
	}
	length = vmbus_gpadl_header(message, sizeof(message),
			channel->relid, channel->gpadl_id,
			channel->page_count * VMBUS_PAGE_SIZE, pfns,
			channel->page_count, &consumed);
	rc = transmit_message(message, length);
	if (rc)
		goto out;
	channel->gpadl_posted = 1;
	offset = consumed;
	while (offset < channel->page_count) {
		length = vmbus_gpadl_body(message, sizeof(message),
				message_number++, channel->gpadl_id,
				&pfns[offset], channel->page_count - offset,
				&consumed);
		rc = transmit_message(message, length);
		if (rc)
			goto out;
		offset += consumed;
	}
	rc = transaction_wait(transaction, token);
	if (!rc) {
		rc = vmbus_channel_state_gpadl_created(&channel->state);
		if (rc)
			goto out;
		channel->gpadl_live = 1;
	}
out:
	transaction_release(transaction);
	if (rc && !channel->gpadl_posted) {
		channel->gpadl_id = 0;
		channel->gpadl_record = 0;
		gpadl_record_release(record, 0);
	}
	return rc;
}

static int teardown_gpadl(struct vmbus_channel *channel,
			  const struct vmbus_channel_token *token)
{
	struct vmbus_gpadl_record *record;
	struct vmbus_channel_transaction *transaction;
	__u8 message[16];
	__u64 capacity_epoch;
	int length;
	int rc;

	if (!channel->gpadl_id)
		return 0;
	record = channel_gpadl_record(channel);
	if (!record)
		return -EPROTO;
	capacity_epoch =
		vmbus_control_channel_capacity_epoch(channel->device);
	transaction = transaction_allocate(VMBUS_TRANSACTION_GPADL_TEARDOWN,
			channel->relid, channel->gpadl_id);
	if (!transaction) {
		vmbus_control_note_channel_capacity(channel->device,
						    capacity_epoch);
		quarantine_channel_pages(channel, record, NULL, 0);
		return -ENOSPC;
	}
	length = vmbus_gpadl_teardown_message(message, sizeof(message),
			channel->relid, channel->gpadl_id);
	rc = transmit_message(message, length);
	if (!rc) {
		channel->teardown_posted = 1;
		rc = transaction_wait(transaction, token);
	}
	if (!rc) {
		transaction_release(transaction);
		channel->gpadl_id = 0;
		channel->gpadl_record = 0;
		channel->gpadl_live = 0;
		channel->gpadl_posted = 0;
		gpadl_record_release(record, 0);
	} else if (__atomic_load_n(&record->state, __ATOMIC_ACQUIRE) ==
		   VMBUS_GPADL_RECORD_FREE) {
		/* A nested pump completed asynchronous teardown and reclamation. */
		return rc;
	} else if (__atomic_load_n(&record->state, __ATOMIC_ACQUIRE) ==
			   VMBUS_GPADL_RECORD_ASYNC ||
		   __atomic_load_n(&record->state, __ATOMIC_ACQUIRE) ==
			   VMBUS_GPADL_RECORD_RESET) {
		if (record->transaction != transaction)
			transaction_release(transaction);
	} else {
		if (channel->teardown_posted) {
			record->transaction = transaction;
			record->host_done = __atomic_load_n(
				&transaction->done, __ATOMIC_ACQUIRE);
		} else {
			transaction_release(transaction);
		}
		quarantine_channel_pages(channel, record,
					 record->transaction,
					 channel->teardown_posted);
	}
	return rc;
}

static int teardown_gpadl_nowait(struct vmbus_channel *channel)
{
	struct vmbus_gpadl_record *record;
	struct vmbus_channel_transaction *transaction;
	__u8 message[16];
	int length;
	int rc;

	if (!channel->gpadl_id)
		return 0;
	record = channel_gpadl_record(channel);
	if (!record)
		return -EPROTO;
	if (!channel->gpadl_posted) {
		channel->gpadl_id = 0;
		channel->gpadl_record = 0;
		gpadl_record_release(record, 0);
		return 0;
	}
	transaction = transaction_find(VMBUS_TRANSACTION_GPADL_TEARDOWN,
			channel->relid, channel->gpadl_id);
	rc = 0;
	if (!channel->teardown_posted) {
		transaction = transaction_allocate(
			VMBUS_TRANSACTION_GPADL_TEARDOWN,
			channel->relid, channel->gpadl_id);
		if (!transaction) {
			quarantine_channel_pages(channel, record, NULL, 0);
			return -ENOSPC;
		}
		length = vmbus_gpadl_teardown_message(message, sizeof(message),
				channel->relid, channel->gpadl_id);
		rc = transmit_message(message, length);
		channel->teardown_posted = !rc;
	}
	if (channel->teardown_posted && transaction) {
		record->transaction = transaction;
		record->host_done = __atomic_load_n(&transaction->done,
						    __ATOMIC_ACQUIRE);
	} else {
		if (transaction)
			transaction_release(transaction);
		record->transaction = NULL;
	}
	quarantine_channel_pages(channel, record, record->transaction,
				 channel->teardown_posted && transaction);
	return rc;
}

static int open_channel_control(struct vmbus_channel *channel,
				const void *user_data, size_t user_data_size,
				const struct vmbus_channel_token *token)
{
	struct vmbus_channel_transaction *transaction;
	__u8 message[148];
	int length;
	int rc;

	rc = vmbus_monotonic_id_allocate(&next_open_id, &channel->open_id);
	if (rc)
		return rc;
	transaction = transaction_allocate(VMBUS_TRANSACTION_OPEN,
			channel->relid, channel->open_id);
	if (!transaction)
		return -ENOSPC;
	length = vmbus_open_message(message, sizeof(message),
			channel->relid, channel->open_id,
			channel->gpadl_id, 0, channel->tx_pages,
			user_data, user_data_size);
	rc = vmbus_channel_state_open_begin(&channel->state);
	if (rc)
		goto done;
	rc = transmit_message(message, length);
	if (!rc)
		rc = transaction_wait(transaction, token);
	if (__atomic_load_n(&transaction->done, __ATOMIC_ACQUIRE)) {
		int transition_rc =
			vmbus_channel_state_open_complete(&channel->state, rc);

		if (!rc)
			rc = transition_rc;
	}
done:
	transaction_release(transaction);
	return rc;
}

static int close_channel_control(struct vmbus_channel *channel)
{
	__u8 message[12];
	__u8 previous_state = channel->state;
	int length;
	int rc;

	if (channel->state == CHANNEL_GPADL)
		return 0;
	if (vmbus_channel_state_close_begin(&channel->state))
		return -EPROTO;
	length = vmbus_close_message(message, sizeof(message),
				     channel->relid);
	rc = transmit_message(message, length);
	if (rc) {
		channel->state = previous_state;
	} else {
		channel->close_posted = 1;
	}
	return rc;
}

static int signal_channel(struct vmbus_channel *channel,
			  const struct vmbus_channel_token *token)
{
	int rc;

	if (!hyperv_has_signal_events())
		return -EACCES;
	ukarch_spin_lock(&channel->signal_lock);
	if (!channel_operation_valid(token, 1)) {
		rc = -ECANCELED;
		goto out;
	}
	if (!channel->signal_input_gpa) {
		channel->signal_input_gpa = uk_paging_virt_to_phys(
			(__vaddr_t)&channel->signal_input);
		if (channel->signal_input_gpa == UK_PAGING_PADDR_INV ||
		    (channel->signal_input_gpa & 7)) {
			rc = -EINVAL;
			goto out;
		}
	}
	/*
	 * The offer's dedicated flag controls host-to-guest interrupt routing.
	 * Guest-to-host notification still publishes the shared send bit before
	 * SignalEvent, matching the TLFS connection/event contract and FreeBSD.
	 */
	rc = vmbus_control_set_event(channel->relid);
	if (rc && rc != -ERANGE)
		goto out;
	rc = vmbus_signal_event(&channel->signal_input,
			vmbus_signal_connection_id(vmbus_protocol_version(),
				channel->connection_id), 0,
			channel->signal_input_gpa, channel_hypercall, NULL);
out:
	ukarch_spin_unlock(&channel->signal_lock);
	return rc;
}

int vmbus_channel_open(struct vmbus_device *device, __u16 tx_pages,
		       __u16 rx_pages, const void *user_data,
		       size_t user_data_size)
{
	struct vmbus_channel *channel;
	struct vmbus_channel_token token = { 0 };
	unsigned int start;
	__u64 capacity_epoch;
	int acquired;
	int rc;

	if (!device || !device->present || device->subchannel_index ||
	    tx_pages < 2 || rx_pages < 2 ||
	    (__u32)tx_pages + rx_pages > CONFIG_LIBVMBUS_RING_PAGES ||
	    vmbus_channel_validate_open_data(user_data, user_data_size,
					      VMBUS_USER_DATA_SIZE))
		return -EINVAL;
	rc = vmbus_control_enter(&acquired);
	if (rc)
		return rc;
	capacity_epoch = vmbus_control_channel_capacity_epoch(device);
	channel = allocate_channel(device);
	if (!channel) {
		vmbus_control_note_channel_capacity(device, capacity_epoch);
		rc = -ENOSPC;
		goto out_control;
	}
	if (channel->state == CHANNEL_OPEN) {
		rc = -EALREADY;
		goto out_control;
	}
	if (channel->state != CHANNEL_ALLOCATED) {
		rc = -EBUSY;
		goto out_control;
	}
	rc = channel_operation_begin(channel, &token, 0);
	if (rc)
		goto out_control;
	capacity_epoch = vmbus_control_channel_capacity_epoch(device);
	rc = allocate_ring_pages(tx_pages + rx_pages, &start);
	if (rc) {
		vmbus_control_note_channel_capacity(device, capacity_epoch);
		goto out_failed;
	}
	channel->page_start = start;
	channel->page_count = tx_pages + rx_pages;
	channel->tx_pages = tx_pages;
	channel->rx_pages = rx_pages;
	channel->tx_ring = &ring_pages[start][0];
	channel->rx_ring = &ring_pages[start + tx_pages][0];
	rc = vmbus_ring_initialize(channel->tx_ring,
				   (size_t)tx_pages * VMBUS_PAGE_SIZE);
	if (rc)
		goto out_pages;
	rc = vmbus_ring_initialize(channel->rx_ring,
				   (size_t)rx_pages * VMBUS_PAGE_SIZE);
	if (rc)
		goto out_pages;
	rc = create_gpadl(channel, &token);
	if (rc)
		goto out_partial_gpadl;
	rc = open_channel_control(channel,
			user_data ? user_data : &empty_input, user_data_size,
			&token);
	if (!rc)
		goto out_operation;
	if (!channel_operation_valid(&token, 0))
		goto out_operation;
	if (close_channel_control(channel)) {
		vmbus_control_fail();
		goto out_partial_gpadl;
	}
out_partial_gpadl:
	if (!channel_operation_valid(&token, 0))
		goto out_operation;
	if (channel->gpadl_id) {
		int cleanup_rc = teardown_gpadl(channel, &token);

		if (cleanup_rc) {
			if (cleanup_rc == -ECANCELED)
				goto out_operation;
			vmbus_control_fail();
			rc = cleanup_rc;
			goto out_failed;
		}
	}
out_pages:
	free_ring_pages(channel->page_start, channel->page_count);
	channel->page_count = 0;
out_failed:
	(void)channel_revoke(channel, 0);
out_operation:
	end_channel_operation(channel, &token);
out_control:
	vmbus_control_exit(acquired);
	return rc;
}

int vmbus_channel_close(struct vmbus_channel *channel)
{
	struct vmbus_channel_token token = { 0 };
	int acquired;
	int rc;
	int rc2;

	if (!channel)
		return -ENODEV;
	rc = vmbus_control_enter(&acquired);
	if (rc)
		return rc;
	rc = channel_operation_begin(channel, &token, 0);
	if (rc)
		goto out;
	(void)channel_revoke(channel, 0);
	if (channel->device && channel->device->channel == channel)
		channel->device->channel = NULL;
	channel_synchronize_io(channel);
	rc = close_channel_control(channel);
	rc2 = teardown_gpadl(channel, NULL);
	if (!rc)
		rc = rc2;
	if (rc)
		vmbus_control_fail();
	end_channel_operation(channel, &token);
out:
	vmbus_control_exit(acquired);
	return rc;
}

int vmbus_channel_send(struct vmbus_channel *channel, __u16 packet_type,
		       __u16 flags, __u64 transaction_id,
		       const void *descriptor, size_t descriptor_size,
		       const void *payload, size_t payload_size)
{
	struct vmbus_channel_token token = { 0 };
	__u8 need_signal;
	unsigned long irq_flags;
	int rc;

	if ((!descriptor && descriptor_size) || (!payload && payload_size))
		return -EINVAL;
	rc = channel_operation_begin(channel, &token, 1);
	if (rc)
		return rc;
	ukplat_spin_lock_irqsave(&channel->tx_lock, irq_flags);
	if (!channel_operation_valid(&token, 1))
		rc = -ECANCELED;
	else
		rc = vmbus_ring_write(channel->tx_ring,
			(size_t)channel->tx_pages * VMBUS_PAGE_SIZE,
			packet_type, flags, transaction_id,
			descriptor ? descriptor : &empty_input,
			descriptor_size, payload ? payload : &empty_input,
			payload_size, &need_signal);
	ukplat_spin_unlock_irqrestore(&channel->tx_lock, irq_flags);
	if (!rc && need_signal) {
		int signal_rc = signal_channel(channel, &token);

		if (signal_rc)
			rc = signal_rc == -ECANCELED ? signal_rc : -EIO;
	}
	end_channel_operation(channel, &token);
	if (rc == -ECANCELED)
		return rc;
	if (rc == -EIO)
		return rc;
	if (rc)
		return rc == -1 ? -EAGAIN : -EPROTO;
	return 0;
}

int vmbus_channel_send_gpa_direct(struct vmbus_channel *channel,
				  __u16 flags, __u64 transaction_id,
				  const struct vmbus_gpa_range *ranges,
				  __u32 range_count,
				  const void *payload, size_t payload_size)
{
	__u8 descriptor[8 + VMBUS_MAX_GPA_RANGES * 8 +
			VMBUS_MAX_GPA_PFNS * 8];
	size_t offset = 8;
	unsigned int range_index;
	unsigned int pfn_index;
	unsigned int total_pfns = 0;

	if (!ranges || !range_count || range_count > VMBUS_MAX_GPA_RANGES)
		return -EINVAL;
	for (range_index = 0; range_index < range_count; range_index++) {
		__u64 covered;
		__u64 required_pfns;

		if (!ranges[range_index].pfns ||
		    !ranges[range_index].pfn_count ||
		    ranges[range_index].byte_offset >= VMBUS_PAGE_SIZE ||
		    total_pfns + ranges[range_index].pfn_count >
			    VMBUS_MAX_GPA_PFNS)
			return -EINVAL;
		covered = (__u64)ranges[range_index].byte_offset +
			ranges[range_index].byte_count;
		required_pfns = (covered + VMBUS_PAGE_SIZE - 1) /
			VMBUS_PAGE_SIZE;
		if (!ranges[range_index].byte_count ||
		    required_pfns != ranges[range_index].pfn_count)
			return -EINVAL;
		descriptor[offset++] = (__u8)ranges[range_index].byte_count;
		descriptor[offset++] = (__u8)(ranges[range_index].byte_count >> 8);
		descriptor[offset++] = (__u8)(ranges[range_index].byte_count >> 16);
		descriptor[offset++] = (__u8)(ranges[range_index].byte_count >> 24);
		descriptor[offset++] = (__u8)ranges[range_index].byte_offset;
		descriptor[offset++] = (__u8)(ranges[range_index].byte_offset >> 8);
		descriptor[offset++] = (__u8)(ranges[range_index].byte_offset >> 16);
		descriptor[offset++] = (__u8)(ranges[range_index].byte_offset >> 24);
		for (pfn_index = 0;
		     pfn_index < ranges[range_index].pfn_count; pfn_index++) {
			__u64 pfn = ranges[range_index].pfns[pfn_index];
			unsigned int byte;

			for (byte = 0; byte < 8; byte++)
				descriptor[offset++] = (__u8)(pfn >> (byte * 8));
		}
		total_pfns += ranges[range_index].pfn_count;
	}
	descriptor[0] = descriptor[1] = descriptor[2] = descriptor[3] = 0;
	descriptor[4] = (__u8)range_count;
	descriptor[5] = (__u8)(range_count >> 8);
	descriptor[6] = (__u8)(range_count >> 16);
	descriptor[7] = (__u8)(range_count >> 24);
	return vmbus_channel_send(channel, VMBUS_PACKET_DATA_USING_GPA_DIRECT,
			flags, transaction_id, descriptor, offset,
			payload, payload_size);
}

int vmbus_channel_receive(struct vmbus_channel *channel,
			  struct vmbus_packet *packet,
			  void *descriptor, size_t descriptor_capacity,
			  void *payload, size_t payload_capacity)
{
	struct vmbus_channel_token token = { 0 };
	struct vmbus_packet_meta_abi meta;
	unsigned long irq_flags;
	int rc;

	if (!packet || (!descriptor && descriptor_capacity) ||
	    (!payload && payload_capacity))
		return -EINVAL;
	rc = channel_operation_begin(channel, &token, 1);
	if (rc)
		return rc;
	ukplat_spin_lock_irqsave(&channel->rx_lock, irq_flags);
	if (!channel_operation_valid(&token, 1))
		rc = -ECANCELED;
	else
		rc = vmbus_ring_read(channel->rx_ring,
			(size_t)channel->rx_pages * VMBUS_PAGE_SIZE, &meta,
			descriptor ? descriptor : &empty_output,
			descriptor_capacity, payload ? payload : &empty_output,
			payload_capacity);
	ukplat_spin_unlock_irqrestore(&channel->rx_lock, irq_flags);
	if (!rc) {
		packet->type = meta.packet_type;
		packet->flags = meta.flags;
		packet->transaction_id = meta.transaction_id;
		packet->descriptor_size = meta.descriptor_size;
		packet->payload_size = meta.payload_size;
		packet->total_size = meta.total_size;
		packet->trailer_mismatch = meta.trailer_mismatch;
		if (meta.need_signal) {
			int signal_rc = signal_channel(channel, &token);

			if (signal_rc)
				rc = signal_rc == -ECANCELED ?
					signal_rc : -EIO;
		}
	}
	end_channel_operation(channel, &token);
	if (rc == 1)
		return -EAGAIN;
	if (rc == -ECANCELED)
		return rc;
	if (rc == -EIO)
		return rc;
	if (rc)
		return rc == -3 ? -ENOBUFS : -EPROTO;
	return 0;
}

int vmbus_channel_poll(struct vmbus_channel *channel)
{
	struct vmbus_channel_token token = { 0 };
	unsigned long flags;
	int rc;

	rc = channel_operation_begin(channel, &token, 1);
	if (rc)
		return rc;
	ukplat_spin_lock_irqsave(&channel->rx_lock, flags);
	if (!channel_operation_valid(&token, 1))
		rc = -ECANCELED;
	else
		rc = vmbus_ring_readable(channel->rx_ring,
			(size_t)channel->rx_pages * VMBUS_PAGE_SIZE) != 0;
	ukplat_spin_unlock_irqrestore(&channel->rx_lock, flags);
	end_channel_operation(channel, &token);
	return rc;
}

void vmbus_channel_set_callback(struct vmbus_channel *channel,
				vmbus_channel_callback_t callback, void *arg)
{
	struct vmbus_channel_token token = { 0 };
	unsigned long flags;

	if (channel_operation_begin(channel, &token, 1))
		return;
	ukplat_spin_lock_irqsave(&channel->lifetime_lock, flags);
	if (vmbus_channel_owner_valid(&token)) {
		channel->callback = callback;
		channel->callback_arg = arg;
	}
	ukplat_spin_unlock_irqrestore(&channel->lifetime_lock, flags);
	end_channel_operation(channel, &token);
}

int vmbus_channel_mask_interrupts(struct vmbus_channel *channel)
{
	struct vmbus_channel_token token = { 0 };
	unsigned long flags;
	int rc;

	rc = channel_operation_begin(channel, &token, 1);
	if (rc)
		return rc;
	ukplat_spin_lock_irqsave(&channel->rx_lock, flags);
	if (!channel_operation_valid(&token, 1))
		rc = -ECANCELED;
	else
		rc = vmbus_ring_set_interrupt_mask(channel->rx_ring,
			(size_t)channel->rx_pages * VMBUS_PAGE_SIZE, 1);
	ukplat_spin_unlock_irqrestore(&channel->rx_lock, flags);
	end_channel_operation(channel, &token);
	return rc;
}

int vmbus_channel_unmask_interrupts(struct vmbus_channel *channel)
{
	struct vmbus_channel_token token = { 0 };
	unsigned long flags;
	__u32 readable;
	int rc;

	rc = channel_operation_begin(channel, &token, 1);
	if (rc)
		return rc;
	ukplat_spin_lock_irqsave(&channel->rx_lock, flags);
	if (!channel_operation_valid(&token, 1))
		rc = -ECANCELED;
	else {
		readable = vmbus_ring_unmask_and_readable(channel->rx_ring,
				(size_t)channel->rx_pages * VMBUS_PAGE_SIZE);
		rc = readable != 0;
	}
	ukplat_spin_unlock_irqrestore(&channel->rx_lock, flags);
	end_channel_operation(channel, &token);
	return rc;
}

int vmbus_channel_control_receive(const __u8 *message, size_t length)
{
	unsigned long flags;
	__u32 type;
	__u32 channel_id;
	__u32 id;
	__u32 status = 0;
	int rc;
	enum vmbus_transaction_type expected;

	if (!message || length < 12)
		return -EPROTO;
	type = read_le32(message);
	switch (type) {
	case 6:
		if (length < 20)
			return -EPROTO;
		channel_id = read_le32(message + 8);
		id = read_le32(message + 12);
		status = read_le32(message + 16);
		expected = VMBUS_TRANSACTION_OPEN;
		break;
	case 10:
		if (length < 20)
			return -EPROTO;
		channel_id = read_le32(message + 8);
		id = read_le32(message + 12);
		status = read_le32(message + 16);
		expected = VMBUS_TRANSACTION_GPADL_CREATE;
		break;
	case 12:
		if (length < 12)
			return -EPROTO;
		channel_id = 0;
		id = read_le32(message + 8);
		expected = VMBUS_TRANSACTION_GPADL_TEARDOWN;
		break;
	default:
		return -EPROTO;
	}
	ukplat_spin_lock_irqsave(&transaction_lock, flags);
	rc = vmbus_transaction_complete(transactions,
			CONFIG_LIBVMBUS_MAX_TRANSACTIONS, expected,
			channel_id, id, status);
	ukplat_spin_unlock_irqrestore(&transaction_lock, flags);
	if (!rc && expected == VMBUS_TRANSACTION_GPADL_TEARDOWN)
		complete_async_gpadl(id);
	rc = vmbus_transaction_completion_policy(rc, &ignored_responses);
	return rc ? -EPROTO : 0;
}

__u32 vmbus_channel_take_ignored_responses(void)
{
	return __atomic_exchange_n(&ignored_responses, 0, __ATOMIC_ACQ_REL);
}

void vmbus_channel_event(__u32 event)
{
	struct vmbus_channel *channel = find_channel(event);
	struct vmbus_channel_token token = { 0 };
	vmbus_channel_callback_t callback;
	unsigned long flags;
	void *callback_arg;

	if (channel_operation_begin(channel, &token, 1))
		return;
	ukplat_spin_lock_irqsave(&channel->lifetime_lock, flags);
	if (!vmbus_channel_owner_valid(&token)) {
		callback = NULL;
		callback_arg = NULL;
	} else {
		channel->event_pending = 1;
		callback = channel->callback;
		callback_arg = channel->callback_arg;
	}
	ukplat_spin_unlock_irqrestore(&channel->lifetime_lock, flags);
	if (callback)
		callback(channel, callback_arg);
	end_channel_operation(channel, &token);
}

int vmbus_channel_rescind(__u32 channel_id)
{
	struct vmbus_channel *channel = find_channel(channel_id);
	struct vmbus_channel_token token = { 0 };
	struct vmbus_rescind_plan plan;
	int rc;

	if (!channel)
		return 0;
	rc = channel_operation_begin(channel, &token, 0);
	if (rc == -ECANCELED) {
		unsigned long flags;

		ukplat_spin_lock_irqsave(&channel->lifetime_lock, flags);
		channel->rescinded = 1;
		ukplat_spin_unlock_irqrestore(&channel->lifetime_lock, flags);
		return -EINPROGRESS;
	}
	if (rc)
		return 0;
	(void)channel_revoke(channel, 1);
	channel_synchronize_io(channel);
	(void)transaction_cancel_channel(channel_id, (__u32)-ECANCELED);
	plan = vmbus_channel_rescind_plan(channel->state,
					 channel->gpadl_id != 0);
	if (plan.send_close && !channel->close_posted) {
		__u8 message[12];
		int length = vmbus_close_message(message, sizeof(message),
						 channel_id);
		int close_rc = transmit_message(message, length);

		if (!close_rc)
			channel->close_posted = 1;
		else
			vmbus_control_fail();
	}
	if (plan.send_gpadl_teardown &&
	    teardown_gpadl_nowait(channel))
		vmbus_control_fail();
	if (channel->device && channel->device->channel == channel)
		channel->device->channel = NULL;
	channel->device = NULL;
	__atomic_store_n(&channel->state, CHANNEL_RESCINDED, __ATOMIC_RELEASE);
	end_channel_operation(channel, &token);
	return -EINPROGRESS;
}

void vmbus_channel_close_all(void)
{
	unsigned int i;

	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		struct vmbus_channel_token token = { 0 };
		int rc;

		if (__atomic_load_n(&channels[i].state, __ATOMIC_ACQUIRE) ==
		    CHANNEL_FREE)
			continue;
		if (channel_operation_begin(&channels[i], &token, 0))
			continue;
		(void)channel_revoke(&channels[i], 0);
		channel_synchronize_io(&channels[i]);
		(void)transaction_cancel_channel(channels[i].relid,
					 (__u32)-ECANCELED);
		rc = close_channel_control(&channels[i]);
		(void)rc;
		(void)teardown_gpadl(&channels[i], NULL);
		if (channels[i].device &&
		    channels[i].device->channel == &channels[i])
			channels[i].device->channel = NULL;
		channels[i].device = NULL;
		end_channel_operation(&channels[i], &token);
	}
}

void vmbus_channel_reset_all(void)
{
	unsigned int i;

	initialize_channel_locks();
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_GPADLS; i++) {
		gpadl_records[i].transaction = NULL;
		if (__atomic_load_n(&gpadl_records[i].state,
				    __ATOMIC_ACQUIRE) ==
			    VMBUS_GPADL_RECORD_ASYNC ||
		    __atomic_load_n(&gpadl_records[i].state,
				    __ATOMIC_ACQUIRE) ==
			    VMBUS_GPADL_RECORD_RESET) {
			__atomic_store_n(&gpadl_records[i].host_done, 1,
					 __ATOMIC_RELEASE);
			gpadl_record_try_reclaim(&gpadl_records[i]);
		}
	}
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_TRANSACTIONS; i++)
		transaction_release(&transactions[i]);
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		struct vmbus_gpadl_record *record = NULL;
		struct vmbus_channel_token token = { 0 };

		if (__atomic_load_n(&channels[i].state, __ATOMIC_ACQUIRE) ==
		    CHANNEL_FREE)
			continue;
		if (channel_operation_pin(&channels[i], &token))
			continue;
		if (channels[i].gpadl_record &&
		    channels[i].gpadl_record <= CONFIG_LIBVMBUS_MAX_GPADLS)
			record = &gpadl_records[channels[i].gpadl_record - 1];
		if (record &&
		    __atomic_load_n(&record->state, __ATOMIC_ACQUIRE) ==
			    VMBUS_GPADL_RECORD_OWNED) {
			gpadl_record_release(record, 0);
			channels[i].gpadl_record = 0;
		}
		channels[i].gpadl_id = 0;
		channels[i].gpadl_live = 0;
		if (channels[i].device &&
		    channels[i].device->channel == &channels[i])
			channels[i].device->channel = NULL;
		channels[i].device = NULL;
		(void)channel_revoke(&channels[i], 0);
		__atomic_store_n(&channels[i].state, CHANNEL_RESCINDED,
				 __ATOMIC_RELEASE);
		end_channel_operation(&channels[i], &token);
	}
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_GPADLS; i++)
		if (__atomic_load_n(&gpadl_records[i].state,
				    __ATOMIC_ACQUIRE) ==
			    VMBUS_GPADL_RECORD_ASYNC ||
		    __atomic_load_n(&gpadl_records[i].state,
				    __ATOMIC_ACQUIRE) ==
			    VMBUS_GPADL_RECORD_RESET) {
			unsigned int channel_index;
			int locally_owned = 0;

			for (channel_index = 0;
			     channel_index < CONFIG_LIBVMBUS_MAX_DEVICES;
			     channel_index++) {
				if (__atomic_load_n(&channels[channel_index].state,
						    __ATOMIC_ACQUIRE) ==
					    CHANNEL_FREE)
					continue;
				if (channels[channel_index].owner.generation ==
					    gpadl_records[i].channel_generation &&
				    channels[channel_index].gpadl_record ==
					    i + 1) {
					locally_owned = 1;
					break;
				}
			}
			if (!locally_owned)
				__atomic_store_n(
					&gpadl_records[i].local_drained, 1,
					__ATOMIC_RELEASE);
			gpadl_record_try_reclaim(&gpadl_records[i]);
		}
	__atomic_store_n(&ignored_responses, 0, __ATOMIC_RELEASE);
}

#ifdef VMBUS_CHANNEL_HOST_TEST
static unsigned int host_release_page;
static __u32 host_release_relid;
static int host_release_pending;
static struct vmbus_channel_token host_pinned_token;

int vmbus_channel_host_release_ready(__u32 relid)
{
	return host_release_pending && relid == host_release_relid &&
		!ring_page_used[host_release_page] && !find_channel(relid);
}

struct vmbus_channel *
vmbus_channel_host_allocate_open(struct vmbus_device *device)
{
	struct vmbus_channel *channel;
	unsigned int page;

	channel = allocate_channel(device);
	if (!channel || allocate_ring_pages(4, &page))
		return NULL;
	channel->page_start = page;
	channel->page_count = 4;
	channel->tx_pages = 2;
	channel->rx_pages = 2;
	channel->tx_ring = &ring_pages[page][0];
	channel->rx_ring = &ring_pages[page + 2][0];
	__atomic_store_n(&channel->state, CHANNEL_OPEN, __ATOMIC_RELEASE);
	return channel;
}

struct vmbus_channel *
vmbus_channel_host_allocate_slot(struct vmbus_device *device)
{
	return allocate_channel(device);
}

struct vmbus_channel *
vmbus_channel_host_prepare_open(struct vmbus_device *device)
{
	vmbus_channel_reset_all();
	return vmbus_channel_host_allocate_open(device);
}

int vmbus_channel_host_pages_used(void)
{
	unsigned int i;
	int used = 0;

	for (i = 0; i < CONFIG_LIBVMBUS_RING_PAGES; i++)
		used += !!ring_page_used[i];
	return used;
}

int vmbus_channel_host_record_count(void)
{
	unsigned int i;
	int used = 0;

	for (i = 0; i < CONFIG_LIBVMBUS_MAX_GPADLS; i++)
		used += __atomic_load_n(&gpadl_records[i].state,
					__ATOMIC_ACQUIRE) !=
			VMBUS_GPADL_RECORD_FREE;
	return used;
}

int vmbus_channel_host_live_gpadls(void)
{
	return (int)__atomic_load_n(&live_gpadls, __ATOMIC_ACQUIRE);
}

int vmbus_channel_host_is_free(struct vmbus_channel *channel)
{
	return __atomic_load_n(&channel->state, __ATOMIC_ACQUIRE) ==
		CHANNEL_FREE;
}

int vmbus_channel_host_is_revoked(struct vmbus_channel *channel)
{
	unsigned long flags;
	int revoked;

	ukplat_spin_lock_irqsave(&channel->lifetime_lock, flags);
	revoked = channel->owner.revoked;
	ukplat_spin_unlock_irqrestore(&channel->lifetime_lock, flags);
	return revoked;
}

int vmbus_channel_host_attach_gpadl(struct vmbus_channel *channel,
				    __u32 gpadl_id)
{
	struct vmbus_gpadl_record *record = gpadl_record_allocate();

	if (!record || !channel || channel->state != CHANNEL_OPEN)
		return -EINVAL;
	record->gpadl_id = gpadl_id;
	record->relid = channel->relid;
	record->channel_generation = channel->owner.generation;
	record->page_start = channel->page_start;
	record->page_count = channel->page_count;
	channel->gpadl_id = gpadl_id;
	channel->gpadl_record =
		(__u16)(record - &gpadl_records[0] + 1);
	channel->gpadl_live = 1;
	channel->gpadl_posted = 1;
	return 0;
}

int vmbus_channel_host_pin(struct vmbus_channel *channel)
{
	host_pinned_token.owner = NULL;
	host_pinned_token.generation = 0;
	return channel_operation_begin(channel, &host_pinned_token, 0);
}

void vmbus_channel_host_unpin(struct vmbus_channel *channel)
{
	end_channel_operation(channel, &host_pinned_token);
}

int vmbus_channel_host_nested_ownership_test(void)
{
	struct vmbus_device first_device = {
		.channel_id = 1,
		.connection_id = 10,
		.present = 1,
	};
	struct vmbus_device second_device = {
		.channel_id = 2,
		.connection_id = 20,
		.present = 1,
	};
	struct vmbus_device third_device = {
		.channel_id = 3,
		.connection_id = 30,
		.present = 1,
	};
	struct vmbus_channel_token token = { 0 };
	struct vmbus_channel *first;
	struct vmbus_channel *second;
	struct vmbus_channel *third;
	unsigned int page;

	vmbus_channel_reset_all();
	first = allocate_channel(&first_device);
	if (!first || channel_operation_begin(first, &token, 0))
		return 1;
	if (allocate_ring_pages(2, &page))
		return 2;
	first->page_start = page;
	first->page_count = 2;
	if (vmbus_channel_rescind(first->relid) != -EINPROGRESS ||
	    first->state != CHANNEL_RESCINDED)
		return 3;
	if (first_device.channel || first->state == CHANNEL_FREE ||
	    !ring_page_used[page])
		return 4;
	second = allocate_channel(&second_device);
	if (!second || second == first)
		return 5;
	host_release_page = page;
	host_release_relid = first->relid;
	host_release_pending = 1;
	end_channel_operation(first, &token);
	host_release_pending = 0;
	if (first->state != CHANNEL_FREE || ring_page_used[page])
		return 6;
	third = allocate_channel(&third_device);
	if (third != first || second_device.channel != second)
		return 7;
	release_channel_object(second);
	release_channel_object(third);
	return 0;
}
#endif
