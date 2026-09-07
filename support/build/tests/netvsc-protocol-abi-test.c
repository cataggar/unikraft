/* SPDX-License-Identifier: BSD-3-Clause */
#include "netvsc_protocol.h"

int main(void)
{
	struct netvsc_nvs_section section = { 0 };
	struct netvsc_transfer_range range = { 0 };
	struct netvsc_rndis_completion completion = { 0 };
	struct netvsc_rndis_packet_info packet = { 0 };
	struct netvsc_rndis_status_info status = { 0 };

	return section.slot_count || range.length || completion.request_id ||
		packet.data_length || status.link_state;
}
