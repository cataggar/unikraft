#include <uk/arch/types.h>
#define HYPERV_PAGE_SIZE 4096U
#define HYPERV_MESSAGE_PAYLOAD_SIZE 240U
struct hyperv_message {
	__u32 message_type;
	__u8 payload_size;
	__u8 reserved[3];
	__u8 payload[HYPERV_MESSAGE_PAYLOAD_SIZE];
};
static inline __u64 hyperv_hypercall(__u64 c, __u64 i, __u64 o)
{ (void)c; (void)i; (void)o; return 0; }
static inline __u64 hyperv_reference_time(void)
{
	static __u64 t;

	return t += 10000;
}
static inline int hyperv_has_signal_events(void) { return 1; }
static inline int hyperv_has_post_messages(void) { return 1; }
