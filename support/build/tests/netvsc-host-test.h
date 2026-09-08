/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __NETVSC_HOST_TEST_H__
#define __NETVSC_HOST_TEST_H__

#include <stddef.h>
#include <uk/arch/types.h>

struct netvsc_device;
struct uk_netdev;
struct vmbus_device;

#define NETVSC_HOST_TX_STAGE_BEFORE_COPY 1U
#define NETVSC_HOST_TX_STAGE_SECTION_COPY 2U
#define NETVSC_HOST_TX_STAGE_BUILD_RANGES 3U
#define NETVSC_HOST_TX_STAGE_AFTER_PUBLISH 4U
#define NETVSC_HOST_TX_STAGE_WRAPPER_RETURN 5U
#define NETVSC_HOST_CONTROL_STAGE_AFTER_PUBLISH 1U
#define NETVSC_HOST_CONTROL_STAGE_WAIT_DONE 2U
#define NETVSC_HOST_CONTROL_STAGE_CANCELLED 3U
#define NETVSC_HOST_NVS_STAGE_WAITING 1U

struct netvsc_device *netvsc_host_device(void);
int netvsc_host_add_device(struct vmbus_device *device);
void netvsc_host_remove_device(struct vmbus_device *device);
struct uk_netdev *netvsc_host_netdev(void);
__u8 *netvsc_host_receive_buffer(void);
__u8 *netvsc_host_send_buffer(void);
size_t netvsc_host_receive_buffer_capacity(void);
size_t netvsc_host_send_buffer_capacity(void);
__u32 netvsc_host_nvs_version(void);
__u32 netvsc_host_send_section_size(void);
__u16 netvsc_host_receive_count(void);
unsigned int netvsc_host_drain_budget(void);
int netvsc_host_drain_active(void);
int netvsc_host_drain_pending(void);
__u16 netvsc_host_tx_active(void);
__u8 netvsc_host_tx_state(unsigned int index);
__u64 netvsc_host_tx_transaction(unsigned int index);
__u16 netvsc_host_quarantined_tx(void);
__u64 netvsc_host_control_transaction(unsigned int index);
__u32 netvsc_host_control_request(unsigned int index);
__u8 netvsc_host_control_state(unsigned int index);
__u32 netvsc_host_unknown_completions(void);
__u32 netvsc_host_duplicate_completions(void);
__u32 netvsc_host_early_completions(void);
__u32 netvsc_host_malformed_messages(void);
int netvsc_host_keepalive(void);
int netvsc_host_nvs_probe(void);
void netvsc_host_set_identity(__u32 generation, __u64 next_transaction,
			      __u16 next_request);
__u32 netvsc_host_generation(void);
__u64 netvsc_host_next_transaction(void);
int netvsc_host_nvs_active(void);
void netvsc_host_reset(void);
int netvsc_host_process_transfer(const __u8 *descriptor,
				 size_t descriptor_length,
				 const __u8 *payload,
				 size_t payload_length,
				 __u64 transaction_id);
int netvsc_host_control_in_use(void);

#endif
