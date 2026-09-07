/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __NETVSC_HOST_TEST_H__
#define __NETVSC_HOST_TEST_H__

#include <stddef.h>
#include <uk/arch/types.h>

struct netvsc_device;
struct uk_netdev;
struct vmbus_device;

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
__u16 netvsc_host_tx_active(void);
__u16 netvsc_host_quarantined_tx(void);
__u64 netvsc_host_control_transaction(unsigned int index);
__u32 netvsc_host_control_request(unsigned int index);
void netvsc_host_reset(void);
int netvsc_host_process_transfer(const __u8 *descriptor,
				 size_t descriptor_length,
				 const __u8 *payload,
				 size_t payload_length,
				 __u64 transaction_id);
int netvsc_host_control_in_use(void);

#endif
