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
	__u8 state;
	__u8 rescinded;
	__u8 event_pending;
	__u8 gpadl_live;
	__u8 close_posted;
	__u8 teardown_posted;
	struct vmbus_channel_owner owner;
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
static __u8 ring_pages[CONFIG_LIBVMBUS_RING_PAGES][VMBUS_PAGE_SIZE]
	__align(VMBUS_PAGE_SIZE);
static __u8 ring_page_used[CONFIG_LIBVMBUS_RING_PAGES];
static __u32 next_gpadl_id = 0x10000U;
static __u32 next_open_id = 1U;
static unsigned int live_gpadls;
static __u32 ignored_responses;
static __u64 next_channel_generation = 1;
static const __u8 empty_input;
static __u8 empty_output;

static void free_ring_pages(unsigned int start, unsigned int count);

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
		if (channels[i].state != CHANNEL_FREE &&
		    channels[i].device &&
		    channels[i].device->channel_id == channel_id)
			return &channels[i];
	return NULL;
}

static struct vmbus_channel *allocate_channel(struct vmbus_device *device)
{
	unsigned int i;

	if (device->channel)
		return device->channel;
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		if (channels[i].state != CHANNEL_FREE)
			continue;
		channels[i].device = device;
		channels[i].relid = device->channel_id;
		channels[i].connection_id = device->connection_id;
		channels[i].owner.generation = next_channel_generation++;
		if (!next_channel_generation)
			next_channel_generation = 1;
		channels[i].owner.operations = 0;
		channels[i].owner.revoked = 0;
		channels[i].owner.cleanup_pending = 0;
		channels[i].state = CHANNEL_ALLOCATED;
		ukarch_spin_init(&channels[i].tx_lock);
		ukarch_spin_init(&channels[i].rx_lock);
		ukarch_spin_init(&channels[i].signal_lock);
		device->channel = &channels[i];
		return &channels[i];
	}
	return NULL;
}

static void release_channel_object(struct vmbus_channel *channel)
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
	channel->state = CHANNEL_FREE;
	channel->rescinded = 0;
	channel->event_pending = 0;
	channel->gpadl_live = 0;
	channel->close_posted = 0;
	channel->teardown_posted = 0;
	channel->owner.generation = 0;
	channel->owner.operations = 0;
	channel->owner.revoked = 0;
	channel->owner.cleanup_pending = 0;
	channel->callback = NULL;
	channel->callback_arg = NULL;
	channel->signal_input_gpa = 0;
}

static void finalize_channel(struct vmbus_channel *channel)
{
	if (channel->page_count)
		free_ring_pages(channel->page_start, channel->page_count);
	release_channel_object(channel);
}

static void end_channel_operation(struct vmbus_channel *channel,
				  struct vmbus_channel_token *token)
{
	if (vmbus_channel_owner_end(token))
		finalize_channel(channel);
}

static int allocate_ring_pages(unsigned int count, unsigned int *start)
{
	return vmbus_page_pool_allocate(ring_page_used,
			CONFIG_LIBVMBUS_RING_PAGES, count, start);
}

static void free_ring_pages(unsigned int start, unsigned int count)
{
	vmbus_page_pool_free(ring_page_used, CONFIG_LIBVMBUS_RING_PAGES,
			     start, count);
}

static struct vmbus_channel_transaction *
transaction_allocate(enum vmbus_transaction_type type, __u32 channel_id,
		     __u32 id)
{
	return vmbus_transaction_allocate(transactions,
			CONFIG_LIBVMBUS_MAX_TRANSACTIONS, type, channel_id, id);
}

static void
transaction_release(struct vmbus_channel_transaction *transaction)
{
	vmbus_transaction_release(transaction);
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
		if (token && !vmbus_channel_owner_valid(token))
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
	struct vmbus_channel_transaction *transaction;
	__u64 pfns[CONFIG_LIBVMBUS_RING_PAGES];
	__u8 message[240];
	size_t consumed;
	size_t offset;
	unsigned int i;
	__u32 message_number = 1;
	int length;
	int rc;

	if (channel->page_count > CONFIG_LIBVMBUS_RING_PAGES)
		return -EINVAL;
	if (live_gpadls >= CONFIG_LIBVMBUS_MAX_GPADLS)
		return -ENOSPC;
	rc = vmbus_monotonic_id_allocate(&next_gpadl_id,
					 &channel->gpadl_id);
	if (rc)
		return rc;
	transaction = transaction_allocate(VMBUS_TRANSACTION_GPADL_CREATE,
			channel->relid, channel->gpadl_id);
	if (!transaction) {
		channel->gpadl_id = 0;
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
		live_gpadls++;
	}
out:
	transaction_release(transaction);
	return rc;
}

static int teardown_gpadl(struct vmbus_channel *channel,
			  const struct vmbus_channel_token *token)
{
	struct vmbus_channel_transaction *transaction;
	__u8 message[16];
	int length;
	int rc;

	if (!channel->gpadl_id)
		return 0;
	transaction = transaction_allocate(VMBUS_TRANSACTION_GPADL_TEARDOWN,
			channel->relid, channel->gpadl_id);
	if (!transaction)
		return -ENOSPC;
	length = vmbus_gpadl_teardown_message(message, sizeof(message),
			channel->relid, channel->gpadl_id);
	rc = transmit_message(message, length);
	if (!rc) {
		channel->teardown_posted = 1;
		rc = transaction_wait(transaction, token);
	}
	transaction_release(transaction);
	if (!rc) {
		channel->gpadl_id = 0;
		if (channel->gpadl_live && live_gpadls)
			live_gpadls--;
		channel->gpadl_live = 0;
	}
	return rc;
}

static int teardown_gpadl_nowait(struct vmbus_channel *channel)
{
	__u8 message[16];
	int length;
	int rc;

	if (!channel->gpadl_id)
		return 0;
	rc = 0;
	if (!channel->teardown_posted) {
		length = vmbus_gpadl_teardown_message(message, sizeof(message),
				channel->relid, channel->gpadl_id);
		rc = transmit_message(message, length);
		channel->teardown_posted = !rc;
	}
	channel->gpadl_id = 0;
	if (channel->gpadl_live && live_gpadls)
		live_gpadls--;
	channel->gpadl_live = 0;
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

static int signal_channel(struct vmbus_channel *channel)
{
	int rc;

	if (!hyperv_has_signal_events())
		return -EACCES;
	ukarch_spin_lock(&channel->signal_lock);
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
	channel = allocate_channel(device);
	if (!channel) {
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
	rc = vmbus_channel_owner_begin(&channel->owner, &token);
	if (rc)
		goto out_control;
	rc = allocate_ring_pages(tx_pages + rx_pages, &start);
	if (rc)
		goto out_failed;
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
	if (!vmbus_channel_owner_valid(&token))
		goto out_operation;
	if (close_channel_control(channel)) {
		vmbus_control_fail();
		goto out_operation;
	}
out_partial_gpadl:
	if (!vmbus_channel_owner_valid(&token))
		goto out_operation;
	if (channel->gpadl_id) {
		int cleanup_rc = teardown_gpadl(channel, &token);

		if (cleanup_rc) {
			if (cleanup_rc == -ECANCELED)
				goto out_operation;
			vmbus_control_fail();
			rc = cleanup_rc;
			goto out_operation;
		}
	}
out_pages:
	free_ring_pages(channel->page_start, channel->page_count);
	channel->page_count = 0;
out_failed:
	vmbus_channel_owner_revoke(&channel->owner);
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

	if (!channel || channel->state == CHANNEL_FREE)
		return -EINVAL;
	rc = vmbus_control_enter(&acquired);
	if (rc)
		return rc;
	rc = vmbus_channel_owner_begin(&channel->owner, &token);
	if (rc)
		goto out;
	rc = close_channel_control(channel);
	rc2 = rc ? 0 : teardown_gpadl(channel, &token);
	if (!rc)
		rc = rc2;
	if (!rc)
		vmbus_channel_owner_revoke(&channel->owner);
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
	__u8 need_signal;
	unsigned long irq_flags;
	int rc;

	if (!channel || channel->state != CHANNEL_OPEN ||
	    (!descriptor && descriptor_size) || (!payload && payload_size))
		return -EINVAL;
	ukplat_spin_lock_irqsave(&channel->tx_lock, irq_flags);
	rc = vmbus_ring_write(channel->tx_ring,
			(size_t)channel->tx_pages * VMBUS_PAGE_SIZE,
			packet_type, flags, transaction_id,
			descriptor ? descriptor : &empty_input,
			descriptor_size, payload ? payload : &empty_input,
			payload_size, &need_signal);
	ukplat_spin_unlock_irqrestore(&channel->tx_lock, irq_flags);
	if (rc)
		return rc == -1 ? -EAGAIN : -EPROTO;
	if (need_signal && signal_channel(channel))
		return -EIO;
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
	struct vmbus_packet_meta_abi meta;
	unsigned long irq_flags;
	int rc;

	if (!channel || channel->state != CHANNEL_OPEN || !packet ||
	    (!descriptor && descriptor_capacity) ||
	    (!payload && payload_capacity))
		return -EINVAL;
	ukplat_spin_lock_irqsave(&channel->rx_lock, irq_flags);
	rc = vmbus_ring_read(channel->rx_ring,
			(size_t)channel->rx_pages * VMBUS_PAGE_SIZE, &meta,
			descriptor ? descriptor : &empty_output,
			descriptor_capacity, payload ? payload : &empty_output,
			payload_capacity);
	ukplat_spin_unlock_irqrestore(&channel->rx_lock, irq_flags);
	if (rc == 1)
		return -EAGAIN;
	if (rc)
		return rc == -3 ? -ENOBUFS : -EPROTO;
	packet->type = meta.packet_type;
	packet->flags = meta.flags;
	packet->transaction_id = meta.transaction_id;
	packet->descriptor_size = meta.descriptor_size;
	packet->payload_size = meta.payload_size;
	packet->total_size = meta.total_size;
	packet->trailer_mismatch = meta.trailer_mismatch;
	if (meta.need_signal && signal_channel(channel))
		return -EIO;
	return 0;
}

int vmbus_channel_poll(struct vmbus_channel *channel)
{
	if (!channel || channel->state != CHANNEL_OPEN)
		return -EINVAL;
	return vmbus_ring_readable(channel->rx_ring,
			(size_t)channel->rx_pages * VMBUS_PAGE_SIZE) != 0;
}

void vmbus_channel_set_callback(struct vmbus_channel *channel,
				vmbus_channel_callback_t callback, void *arg)
{
	if (!channel)
		return;
	channel->callback = callback;
	channel->callback_arg = arg;
}

int vmbus_channel_mask_interrupts(struct vmbus_channel *channel)
{
	if (!channel || channel->state != CHANNEL_OPEN)
		return -EINVAL;
	return vmbus_ring_set_interrupt_mask(channel->rx_ring,
			(size_t)channel->rx_pages * VMBUS_PAGE_SIZE, 1);
}

int vmbus_channel_unmask_interrupts(struct vmbus_channel *channel)
{
	__u32 readable;

	if (!channel || channel->state != CHANNEL_OPEN)
		return -EINVAL;
	readable = vmbus_ring_unmask_and_readable(channel->rx_ring,
			(size_t)channel->rx_pages * VMBUS_PAGE_SIZE);
	return readable != 0;
}

int vmbus_channel_control_receive(const __u8 *message, size_t length)
{
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
	rc = vmbus_transaction_complete(transactions,
			CONFIG_LIBVMBUS_MAX_TRANSACTIONS, expected,
			channel_id, id, status);
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

	if (!channel || channel->state != CHANNEL_OPEN)
		return;
	channel->event_pending = 1;
	if (channel->callback)
		channel->callback(channel, channel->callback_arg);
}

int vmbus_channel_rescind(__u32 channel_id)
{
	struct vmbus_channel *channel = find_channel(channel_id);
	struct vmbus_rescind_plan plan;
	int cleanup_now;

	if (!channel)
		return 0;
	channel->rescinded = 1;
	cleanup_now = vmbus_channel_owner_revoke(&channel->owner);
	(void)vmbus_transaction_cancel_channel(transactions,
			CONFIG_LIBVMBUS_MAX_TRANSACTIONS, channel_id,
			(__u32)-ECANCELED);
	plan = vmbus_channel_rescind_plan(channel->state,
					 channel->gpadl_id != 0);
	if (plan.send_close && !channel->close_posted) {
		__u8 message[12];
		int length = vmbus_close_message(message, sizeof(message),
						 channel_id);

		if (!transmit_message(message, length))
			channel->close_posted = 1;
	}
	if (plan.send_gpadl_teardown)
		(void)teardown_gpadl_nowait(channel);
	if (channel->device && channel->device->channel == channel)
		channel->device->channel = NULL;
	channel->device = NULL;
	vmbus_channel_state_rescind(&channel->state);
	if (cleanup_now)
		finalize_channel(channel);
	return 0;
}

void vmbus_channel_close_all(void)
{
	unsigned int i;

	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		int rc;

		if (channels[i].state == CHANNEL_FREE)
			continue;
		if (channels[i].owner.operations) {
			(void)vmbus_channel_owner_revoke(&channels[i].owner);
			(void)vmbus_transaction_cancel_channel(transactions,
				CONFIG_LIBVMBUS_MAX_TRANSACTIONS,
				channels[i].relid, (__u32)-ECANCELED);
			if (channels[i].device &&
			    channels[i].device->channel == &channels[i])
				channels[i].device->channel = NULL;
			channels[i].device = NULL;
			vmbus_channel_state_rescind(&channels[i].state);
			continue;
		}
		rc = close_channel_control(&channels[i]);
		if (!rc)
			rc = teardown_gpadl(&channels[i], NULL);
		if (!rc) {
			free_ring_pages(channels[i].page_start,
					channels[i].page_count);
			release_channel_object(&channels[i]);
		}
	}
}

void vmbus_channel_reset_all(void)
{
	unsigned int i;

	for (i = 0; i < CONFIG_LIBVMBUS_MAX_TRANSACTIONS; i++)
		transaction_release(&transactions[i]);
	for (i = 0; i < CONFIG_LIBVMBUS_MAX_DEVICES; i++) {
		if (channels[i].state == CHANNEL_FREE)
			continue;
		channels[i].gpadl_id = 0;
		channels[i].gpadl_live = 0;
		if (channels[i].device &&
		    channels[i].device->channel == &channels[i])
			channels[i].device->channel = NULL;
		channels[i].device = NULL;
		if (vmbus_channel_owner_revoke(&channels[i].owner))
			finalize_channel(&channels[i]);
		else
			vmbus_channel_state_rescind(&channels[i].state);
	}
	live_gpadls = 0;
	__atomic_store_n(&ignored_responses, 0, __ATOMIC_RELEASE);
}

#ifdef VMBUS_CHANNEL_HOST_TEST
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
	if (!first || vmbus_channel_owner_begin(&first->owner, &token))
		return 1;
	if (allocate_ring_pages(2, &page))
		return 2;
	first->page_start = page;
	first->page_count = 2;
	if (vmbus_channel_rescind(first->relid))
		return 3;
	if (first_device.channel || first->state == CHANNEL_FREE ||
	    !ring_page_used[page])
		return 4;
	second = allocate_channel(&second_device);
	if (!second || second == first)
		return 5;
	end_channel_operation(first, &token);
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
