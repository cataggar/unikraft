/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __UK_NETVSC_H__
#define __UK_NETVSC_H__

#include <stdint.h>

struct uk_netdev;

#ifdef __cplusplus
extern "C" {
#endif

#define UK_NETVSC_DIAGNOSTICS_VERSION	1U

struct uk_netvsc_diagnostics {
	uint16_t version;
	uint16_t size;
	uint32_t generation;
	uint32_t nvs_version;
	uint32_t ndis_version;
	uint64_t tx_submitted;
	uint64_t tx_completed;
	uint64_t rx_packets;
	uint64_t rx_dropped;
	uint64_t channel_packets;
	uint64_t transfer_packets;
	uint32_t malformed_messages;
	uint32_t unknown_completions;
	uint32_t duplicate_completions;
	uint32_t early_completions;
	uint16_t mtu;
	uint16_t tx_pending;
	uint16_t rx_queued;
	uint16_t pending_acks;
	uint8_t attached;
	uint8_t configured;
	uint8_t running;
	uint8_t host_running;
	uint8_t link_up;
	uint8_t failed;
	uint8_t reserved[2];
};

/*
 * Capture a bounded, read-only driver snapshot. Counters cover the lifetime
 * of the registered device, including reconnects.
 */
int uk_netvsc_diagnostics_get(struct uk_netdev *netdev,
			      struct uk_netvsc_diagnostics *diagnostics);

#ifdef __cplusplus
}
#endif

#endif /* __UK_NETVSC_H__ */
