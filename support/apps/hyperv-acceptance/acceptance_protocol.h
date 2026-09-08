/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef HYPERV_ACCEPTANCE_PROTOCOL_H
#define HYPERV_ACCEPTANCE_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define HYPERV_ACCEPTANCE_DHCP_FRAME_SIZE 342U

enum hyperv_acceptance_result {
	HYPERV_ACCEPTANCE_PASS = 0,
	HYPERV_ACCEPTANCE_FAIL = 1,
	HYPERV_ACCEPTANCE_UNAVAILABLE = 2,
};

struct hyperv_acceptance_dhcp_offer {
	uint8_t offered_address[4];
	uint8_t server_identifier[4];
	uint8_t has_server_identifier;
};

size_t hyperv_acceptance_build_discover(uint8_t *frame, size_t capacity,
					const uint8_t mac[6], uint32_t xid);

/*
 * Returns one for a matching DHCP Offer, zero for an unrelated packet, and a
 * negative value for a malformed matching DHCP packet.
 */
int hyperv_acceptance_parse_offer(
	const uint8_t *frame, size_t length, const uint8_t mac[6], uint32_t xid,
	struct hyperv_acceptance_dhcp_offer *offer);

int hyperv_acceptance_has_mbr_signature(const uint8_t *sector, size_t length);
int hyperv_acceptance_has_gpt_signature(const uint8_t *sector, size_t length);

enum hyperv_acceptance_result hyperv_acceptance_final_result(
	enum hyperv_acceptance_result storage,
	enum hyperv_acceptance_result network);

#endif
