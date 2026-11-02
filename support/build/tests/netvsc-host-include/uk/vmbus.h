#ifndef __UK_VMBUS_H__
#define __UK_VMBUS_H__
#include <stddef.h>
#include <uk/arch/types.h>

#define VMBUS_GUID_SIZE 16U
#define VMBUS_USER_DATA_SIZE 120U
#define VMBUS_PACKET_DATA_INBAND 6
#define VMBUS_PACKET_DATA_USING_TRANSFER_PAGES 7
#define VMBUS_PACKET_DATA_USING_GPA_DIRECT 9
#define VMBUS_PACKET_COMPLETION 11
#define VMBUS_PACKET_FLAG_REQUEST_COMPLETION 1U
#define VMBUS_GPA_DIRECT_MAX_RANGES 32U
#define VMBUS_GPA_DIRECT_MAX_PFNS 64U

struct vmbus_guid {
	__u8 bytes[VMBUS_GUID_SIZE];
};
struct vmbus_channel;
struct vmbus_driver;
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
struct vmbus_offer_identity {
	struct vmbus_guid instance_id;
	__u32 channel_id;
	__u64 generation;
};
struct vmbus_driver {
	const char *name;
	const struct vmbus_device_id *device_ids;
	int (*add_dev)(struct vmbus_device *);
	void (*remove_dev)(struct vmbus_device *);
	void (*offer_removed)(const struct vmbus_offer_identity *);
};
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
struct vmbus_gpadl {
	__u32 id;
	__u32 page_count;
	__u64 generation;
};
struct vmbus_device_bind_token {
	__u64 device_generation;
	__u64 resource_epoch;
};
typedef void (*vmbus_channel_callback_t)(struct vmbus_channel *, void *);

int vmbus_channel_open(struct vmbus_device *, __u16, __u16,
		       const void *, size_t);
int vmbus_channel_close(struct vmbus_channel *);
__u64 vmbus_connection_fail(void);
__u64 vmbus_connection_quiesce_epoch(void);
int vmbus_device_bind_epoch(struct vmbus_device *,
			    struct vmbus_device_bind_token *);
int vmbus_device_bind_retry(struct vmbus_device *,
			    const struct vmbus_device_bind_token *);
void vmbus_device_bind_ready(void);
int vmbus_channel_send(struct vmbus_channel *, __u16, __u16, __u64,
		       const void *, size_t, const void *, size_t);
int vmbus_channel_send_ex(struct vmbus_channel *, __u16, __u16, __u64,
			  const void *, size_t, const void *, size_t, int *);
int vmbus_channel_send_gpa_direct(struct vmbus_channel *, __u16, __u64,
				  const struct vmbus_gpa_range *, __u32,
				  const void *, size_t);
int vmbus_channel_send_gpa_direct_ex(
				  struct vmbus_channel *, __u16, __u64,
				  const struct vmbus_gpa_range *, __u32,
				  const void *, size_t, int *);
int vmbus_channel_gpadl_map(struct vmbus_channel *, void *, size_t,
			    struct vmbus_gpadl *);
int vmbus_channel_gpadl_unmap(struct vmbus_channel *,
			      struct vmbus_gpadl *);
int vmbus_channel_receive(struct vmbus_channel *, struct vmbus_packet *,
			  void *, size_t, void *, size_t);
void vmbus_channel_set_callback(struct vmbus_channel *,
				vmbus_channel_callback_t, void *);
void vmbus_channel_schedule_event(__u32);

#define VMBUS_GUID_END { .bytes = { 0 } }
#define VMBUS_DRIVER_REGISTER(driver) \
	static const void *vmbus_driver_registration __attribute__((used)) = \
		(driver)

#endif
