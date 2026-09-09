/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __UK_VMBUS_H__
#define __UK_VMBUS_H__

#include <stddef.h>
#include <uk/arch/types.h>
#include <uk/bus.h>
#include <uk/ctors.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VMBUS_GUID_SIZE			16U
#define VMBUS_USER_DATA_SIZE		120U
#define VMBUS_GPA_DIRECT_MAX_RANGES	32U
#define VMBUS_GPA_DIRECT_MAX_PFNS	64U

struct vmbus_guid {
	__u8 bytes[VMBUS_GUID_SIZE];
};

struct vmbus_channel;

struct vmbus_device {
	struct vmbus_guid class_id;
	struct vmbus_guid instance_id;
	__u32 channel_id;
	__u32 connection_id;
	__u16 flags;
	__u16 mmio_megabytes;
	__u16 mmio_megabytes_optional;
	__u16 subchannel_index;
	__u8 monitor_id;
	__u8 monitor_allocated;
	__u16 dedicated;
	__u8 user_data[VMBUS_USER_DATA_SIZE];
	const struct vmbus_driver *driver;
	struct vmbus_channel *channel;
	__u8 present;
};

struct vmbus_device_id {
	struct vmbus_guid class_id;
};

struct vmbus_device_bind_token {
	__u64 device_generation;
	__u64 resource_epoch;
};

struct vmbus_offer_identity {
	struct vmbus_guid instance_id;
	__u32 channel_id;
	__u64 generation;
};

/*
 * offer_removed ends exactly one generation-bearing offer lifetime. It is
 * distinct from remove_dev(), which may also be used to roll back a failed
 * add, and does not itself prove channel or DMA quiescence.
 */
struct vmbus_driver {
	const char *name;
	const struct vmbus_device_id *device_ids;
	int (*add_dev)(struct vmbus_device *dev);
	void (*remove_dev)(struct vmbus_device *dev);
	void (*offer_removed)(const struct vmbus_offer_identity *offer);
};

enum vmbus_packet_type {
	VMBUS_PACKET_DATA_INBAND = 6,
	VMBUS_PACKET_DATA_USING_TRANSFER_PAGES = 7,
	VMBUS_PACKET_DATA_USING_GPADL = 8,
	VMBUS_PACKET_DATA_USING_GPA_DIRECT = 9,
	VMBUS_PACKET_CANCEL_REQUEST = 10,
	VMBUS_PACKET_COMPLETION = 11,
	VMBUS_PACKET_DATA_USING_ADDITIONAL_PACKETS = 12,
	VMBUS_PACKET_ADDITIONAL_DATA = 13,
};

#define VMBUS_PACKET_FLAG_REQUEST_COMPLETION	1U

struct vmbus_packet {
	__u16 type;
	__u16 flags;
	__u64 transaction_id;
	__u32 descriptor_size;
	__u32 payload_size;
	__u32 total_size;
	__u8 trailer_mismatch;
};

struct vmbus_gpa_range {
	__u32 byte_count;
	__u32 byte_offset;
	const __u64 *pfns;
	__u32 pfn_count;
};

/*
 * Opaque, generation-bearing handle for a GPADL backed by caller-owned
 * page-aligned memory. GPADL range lengths are 16-bit on the wire, limiting a
 * single mapping to 8,190 pages.
 */
#define VMBUS_GPADL_MAX_PAGES	8190U

struct vmbus_gpadl {
	__u32 id;
	__u32 page_count;
	__u64 generation;
};

typedef void (*vmbus_channel_callback_t)(struct vmbus_channel *channel,
					 void *arg);

extern const struct vmbus_guid vmbus_storage_guid;
extern const struct vmbus_guid vmbus_network_guid;

unsigned int vmbus_device_count(void);
const struct vmbus_device *vmbus_device_get(unsigned int index);
int vmbus_device_is_bound(const struct vmbus_device *device);
int vmbus_reconnect(void);
int vmbus_unload(void);
/*
 * Mark the VMBus control connection failed and schedule whole-bus recovery.
 * The returned epoch is a token for vmbus_connection_quiesce_epoch(); a
 * changed epoch proves that the prior connection completed host teardown.
 */
__u64 vmbus_connection_fail(void);
__u64 vmbus_connection_quiesce_epoch(void);
/*
 * Capture this offer generation's resource epoch before testing the resource
 * that can block add_dev(). If it is unavailable, publish the captured token
 * with vmbus_device_bind_retry(). This ordering prevents a concurrent
 * vmbus_device_bind_ready() from being lost. Tokens are valid only for the
 * captured offer generation; stale generations are rejected. Epoch
 * exhaustion is fail-closed.
 */
int vmbus_device_bind_epoch(struct vmbus_device *device,
			    struct vmbus_device_bind_token *token);
int vmbus_device_bind_retry(
	struct vmbus_device *device,
	const struct vmbus_device_bind_token *token);
void vmbus_device_bind_ready(void);
int _vmbus_register_driver(struct vmbus_driver *driver);
/*
 * Return nonzero after any decoded primary or subchannel storage offer has
 * reached VMBus during this boot, including one rejected before driver
 * admission because the bounded device pool was exhausted.
 */
int vmbus_storage_offer_lifetime_observed(void);

/*
 * Open a primary channel using a statically allocated TX/RX ring pair.
 * Each ring size includes its one-page header. The channel pointer remains
 * owned by VMBus and is valid until close, rescind, or reconnect.
 */
int vmbus_channel_open(struct vmbus_device *device, __u16 tx_pages,
		       __u16 rx_pages, const void *user_data,
		       size_t user_data_size);
int vmbus_channel_close(struct vmbus_channel *channel);
int vmbus_channel_send(struct vmbus_channel *channel, __u16 packet_type,
		       __u16 flags, __u64 transaction_id,
		       const void *descriptor, size_t descriptor_size,
		       const void *payload, size_t payload_size);
/*
 * As vmbus_channel_send(), while reporting whether the packet was committed
 * to the TX ring. A committed packet remains owned by the channel consumer
 * even if a subsequent SignalEvent operation fails.
 */
int vmbus_channel_send_ex(struct vmbus_channel *channel, __u16 packet_type,
			  __u16 flags, __u64 transaction_id,
			  const void *descriptor, size_t descriptor_size,
			  const void *payload, size_t payload_size,
			  int *published);
int vmbus_channel_send_gpa_direct(struct vmbus_channel *channel,
				  __u16 flags, __u64 transaction_id,
				  const struct vmbus_gpa_range *ranges,
				  __u32 range_count,
				  const void *payload, size_t payload_size);
int vmbus_channel_send_gpa_direct_ex(struct vmbus_channel *channel,
				     __u16 flags, __u64 transaction_id,
				     const struct vmbus_gpa_range *ranges,
				     __u32 range_count,
				     const void *payload, size_t payload_size,
				     int *published);
/*
 * Map caller-owned memory into a GPADL. The address and length must both be
 * page aligned; every virtual page is translated independently. Memory must
 * remain valid until unmap succeeds or the VMBus connection is reset. A
 * failed map can return -EINPROGRESS with a non-zero handle when host teardown
 * is still pending; that handle and its backing memory must be retained until
 * reset.
 */
int vmbus_channel_gpadl_map(struct vmbus_channel *channel, void *address,
			    size_t length, struct vmbus_gpadl *gpadl);
int vmbus_channel_gpadl_unmap(struct vmbus_channel *channel,
			      struct vmbus_gpadl *gpadl);
int vmbus_channel_receive(struct vmbus_channel *channel,
			  struct vmbus_packet *packet,
			  void *descriptor, size_t descriptor_capacity,
			  void *payload, size_t payload_capacity);
int vmbus_channel_poll(struct vmbus_channel *channel);
/* Callback runs in VMBus deferred-worker context, never in the SINT ISR. */
void vmbus_channel_set_callback(struct vmbus_channel *channel,
				vmbus_channel_callback_t callback, void *arg);
/* Queue another worker callback pass, independent of hardware event routing. */
void vmbus_channel_schedule_event(__u32 channel_id);
int vmbus_channel_mask_interrupts(struct vmbus_channel *channel);
/* Returns non-zero if packets arrived while interrupts were masked. */
int vmbus_channel_unmask_interrupts(struct vmbus_channel *channel);

#define VMBUS_GUID_END { .bytes = { 0 } }

#define VMBUS_DRIVER_REGISTER(driver) \
	_VMBUS_DRIVER_REGISTER(__LIBNAME__, driver)

#define _VMBUS_DRIVER_REGFNNAME(x, y) x##y
#define _VMBUS_DRIVER_REGISTER(libname, driver)			\
	static void						\
	_VMBUS_DRIVER_REGFNNAME(libname, _vmbus_register_driver)(void) \
	{							\
		(void)_vmbus_register_driver((driver));		\
	}							\
	UK_CTOR_PRIO(						\
		_VMBUS_DRIVER_REGFNNAME(libname, _vmbus_register_driver), \
		UK_PRIO_AFTER(UK_BUS_REGISTER_PRIO))

_Static_assert(sizeof(struct vmbus_guid) == 16,
	       "VMBus GUID ABI must be 16 bytes");
_Static_assert(sizeof(((struct vmbus_device *)0)->user_data) == 120,
	       "VMBus offer user data ABI must be 120 bytes");
_Static_assert(sizeof(struct vmbus_packet) == 32,
	       "VMBus packet ABI must be 32 bytes");
_Static_assert(offsetof(struct vmbus_packet, transaction_id) == 8,
	       "VMBus packet transaction ID offset changed");
_Static_assert(sizeof(struct vmbus_gpadl) == 16,
	       "VMBus GPADL handle ABI must be 16 bytes");
_Static_assert(offsetof(struct vmbus_gpadl, generation) == 8,
	       "VMBus GPADL generation offset changed");

#ifdef __cplusplus
}
#endif

#endif /* __UK_VMBUS_H__ */
