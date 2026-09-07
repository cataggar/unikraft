#include <uk/arch/types.h>
#define VMBUS_USER_DATA_SIZE 120U
#define VMBUS_PACKET_DATA_USING_GPA_DIRECT 9
struct vmbus_channel;
struct vmbus_driver;
struct vmbus_device {
	__u32 channel_id;
	__u32 connection_id;
	__u16 subchannel_index;
	const struct vmbus_driver *driver;
	struct vmbus_channel *channel;
	__u8 present;
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
typedef void (*vmbus_channel_callback_t)(struct vmbus_channel *, void *);
