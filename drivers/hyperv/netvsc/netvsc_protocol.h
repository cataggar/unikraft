/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __NETVSC_PROTOCOL_H__
#define __NETVSC_PROTOCOL_H__

#include <stddef.h>
#include <uk/arch/types.h>

#define NETVSC_NVS_REQUEST_SIZE			40U
#define NETVSC_NVS_STATUS_OK			1U
#define NETVSC_NVS_STATUS_FAILED		2U
#define NETVSC_NVS_RX_BUFFER_ID			0xcafeU
#define NETVSC_NVS_SEND_BUFFER_ID		0xfaceU
#define NETVSC_NVS_SEND_SECTION_INVALID		0xffffffffU
#define NETVSC_NVS_MAX_SECTIONS			8U
#define NETVSC_NVS_MAX_TRANSFER_RANGES		375U

#define NETVSC_NVS_VERSION_1			0x00000002U
#define NETVSC_NVS_VERSION_2			0x00030002U
#define NETVSC_NVS_VERSION_4			0x00040000U
#define NETVSC_NVS_VERSION_5			0x00050000U
#define NETVSC_NVS_VERSION_6			0x00060000U
#define NETVSC_NVS_VERSION_61			0x00060001U

#define NETVSC_NVS_TYPE_SEND_RNDIS		107U
#define NETVSC_NVS_RNDIS_DATA			0U
#define NETVSC_NVS_RNDIS_CONTROL		1U

#define NETVSC_RNDIS_PACKET			0x00000001U
#define NETVSC_RNDIS_INITIALIZE_COMPLETE	0x80000002U
#define NETVSC_RNDIS_QUERY_COMPLETE		0x80000004U
#define NETVSC_RNDIS_SET_COMPLETE		0x80000005U
#define NETVSC_RNDIS_INDICATE_STATUS		0x00000007U
#define NETVSC_RNDIS_KEEPALIVE_COMPLETE		0x80000008U

#define NETVSC_RNDIS_STATUS_SUCCESS		0U
#define NETVSC_RNDIS_STATUS_MEDIA_CONNECT	0x4001000bU
#define NETVSC_RNDIS_STATUS_MEDIA_DISCONNECT	0x4001000cU

#define NETVSC_OID_GEN_MAXIMUM_FRAME_SIZE	0x00010106U
#define NETVSC_OID_GEN_CURRENT_PACKET_FILTER	0x0001010eU
#define NETVSC_OID_GEN_MAXIMUM_TOTAL_SIZE	0x00010111U
#define NETVSC_OID_GEN_MEDIA_CONNECT_STATUS	0x00010114U
#define NETVSC_OID_802_3_PERMANENT_ADDRESS	0x01010101U
#define NETVSC_OID_802_3_CURRENT_ADDRESS	0x01010102U

#define NETVSC_PACKET_FILTER_NONE		0x00000000U
#define NETVSC_PACKET_FILTER_DIRECTED		0x00000001U
#define NETVSC_PACKET_FILTER_MULTICAST		0x00000002U
#define NETVSC_PACKET_FILTER_ALL_MULTICAST	0x00000004U
#define NETVSC_PACKET_FILTER_BROADCAST		0x00000008U
#define NETVSC_PACKET_FILTER_PROMISCUOUS	0x00000020U

enum netvsc_protocol_result {
	NETVSC_PROTOCOL_OK = 0,
	NETVSC_PROTOCOL_INVALID = -1,
	NETVSC_PROTOCOL_OUTPUT_SMALL = -2,
	NETVSC_PROTOCOL_OVERFLOW = -3,
	NETVSC_PROTOCOL_UNEXPECTED = -4,
	NETVSC_PROTOCOL_REMOTE_FAILURE = -5,
	NETVSC_PROTOCOL_VERSION_UNSUPPORTED = -6,
};

struct netvsc_nvs_init_complete {
	__u32 version;
	__u32 max_mdl_chain;
	__u32 status;
};

struct netvsc_nvs_section {
	__u32 start;
	__u32 slot_size;
	__u32 slot_count;
	__u32 end;
};

struct netvsc_nvs_send_buffer_complete {
	__u32 section_size;
	__u32 section_count;
};

struct netvsc_transfer_range {
	__u32 offset;
	__u32 length;
	__u16 section_index;
	__u16 reserved;
};

struct netvsc_rndis_completion {
	__u32 message_type;
	__u32 message_length;
	__u32 request_id;
	__u32 status;
	__u32 info_offset;
	__u32 info_length;
	__u32 max_packets;
	__u32 max_transfer_size;
	__u32 alignment;
};

struct netvsc_rndis_packet_info {
	__u32 message_length;
	__u32 data_offset;
	__u32 data_length;
	__u32 packet_info_offset;
	__u32 packet_info_length;
};

struct netvsc_rndis_status_info {
	__u32 status;
	__u32 buffer_offset;
	__u32 buffer_length;
	__s32 link_state;
};

__u32 netvsc_nvs_version_count(void);
__u32 netvsc_nvs_version(__u32 index);
__u32 netvsc_nvs_ndis_version(__u32 nvs_version);
int netvsc_nvs_build_init(__u8 *output, size_t capacity, __u32 version);
int netvsc_nvs_build_ndis_config(__u8 *output, size_t capacity,
				 __u32 frame_size);
int netvsc_nvs_build_ndis_version(__u8 *output, size_t capacity,
				  __u32 ndis_version);
int netvsc_nvs_build_receive_buffer(__u8 *output, size_t capacity,
				    __u32 gpadl_id);
int netvsc_nvs_build_revoke_receive_buffer(__u8 *output, size_t capacity);
int netvsc_nvs_build_send_buffer(__u8 *output, size_t capacity,
				 __u32 gpadl_id);
int netvsc_nvs_build_revoke_send_buffer(__u8 *output, size_t capacity);
int netvsc_nvs_build_rndis(__u8 *output, size_t capacity,
			   __u32 channel_type, __u32 section_index,
			   __u32 section_size);
int netvsc_nvs_build_rndis_ack(__u8 *output, size_t capacity, __u32 status);
int netvsc_nvs_parse_init_complete(const __u8 *input, size_t length,
				   __u32 requested_version,
				   struct netvsc_nvs_init_complete *result);
int netvsc_nvs_parse_receive_buffer_complete(
	const __u8 *input, size_t length, __u32 buffer_size,
	struct netvsc_nvs_section *sections, size_t section_capacity,
	__u32 *section_count);
int netvsc_nvs_parse_send_buffer_complete(
	const __u8 *input, size_t length, __u32 buffer_size,
	struct netvsc_nvs_send_buffer_complete *result);
int netvsc_nvs_parse_rndis_completion(const __u8 *input, size_t length);
int netvsc_nvs_message_type(const __u8 *input, size_t length,
			    __u32 *message_type);
int netvsc_nvs_parse_rndis(const __u8 *input, size_t length,
			   __u32 *channel_type);
int netvsc_nvs_transfer_range_count(const __u8 *descriptor,
				    size_t descriptor_length,
				    __u32 *range_count);
int netvsc_nvs_parse_transfer_range(
	const __u8 *descriptor, size_t descriptor_length, __u32 range_index,
	__u32 buffer_size, const struct netvsc_nvs_section *sections,
	__u32 section_count, struct netvsc_transfer_range *result);

int netvsc_rndis_build_initialize(__u8 *output, size_t capacity,
				  __u32 request_id,
				  __u32 max_transfer_size);
int netvsc_rndis_build_query(__u8 *output, size_t capacity,
			     __u32 request_id, __u32 oid,
			     const __u8 *info, size_t info_length);
int netvsc_rndis_build_set(__u8 *output, size_t capacity,
			   __u32 request_id, __u32 oid,
			   const __u8 *info, size_t info_length);
int netvsc_rndis_build_keepalive(__u8 *output, size_t capacity,
				 __u32 request_id);
int netvsc_rndis_build_halt(__u8 *output, size_t capacity,
			    __u32 request_id);
int netvsc_rndis_build_packet_header(__u8 *output, size_t capacity,
				     __u32 frame_length);
int netvsc_rndis_message_type(const __u8 *input, size_t length,
			      __u32 *message_type, __u32 *message_length);
int netvsc_rndis_parse_completion(
	const __u8 *input, size_t length, __u32 expected_type,
	__u32 expected_request_id, struct netvsc_rndis_completion *result);
int netvsc_rndis_parse_packet(const __u8 *input, size_t length,
			      struct netvsc_rndis_packet_info *result);
int netvsc_rndis_parse_status(const __u8 *input, size_t length,
			      struct netvsc_rndis_status_info *result);

_Static_assert(sizeof(struct netvsc_nvs_init_complete) == 12,
	       "NVS init-completion ABI mismatch");
_Static_assert(sizeof(struct netvsc_nvs_section) == 16,
	       "NVS section ABI mismatch");
_Static_assert(sizeof(struct netvsc_nvs_send_buffer_complete) == 8,
	       "NVS send-buffer ABI mismatch");
_Static_assert(sizeof(struct netvsc_transfer_range) == 12,
	       "NVS transfer-range ABI mismatch");
_Static_assert(offsetof(struct netvsc_transfer_range, section_index) == 8,
	       "NVS transfer-range offset mismatch");
_Static_assert(sizeof(struct netvsc_rndis_completion) == 36,
	       "RNDIS completion ABI mismatch");
_Static_assert(offsetof(struct netvsc_rndis_completion, status) == 12,
	       "RNDIS completion offset mismatch");
_Static_assert(sizeof(struct netvsc_rndis_packet_info) == 20,
	       "RNDIS packet parser ABI mismatch");
_Static_assert(sizeof(struct netvsc_rndis_status_info) == 16,
	       "RNDIS status parser ABI mismatch");

#endif /* __NETVSC_PROTOCOL_H__ */
