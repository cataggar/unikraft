/* SPDX-License-Identifier: BSD-3-Clause */
#include <stddef.h>
#include <uk/vmbus.h>

#include "vmbus_protocol.h"
#include "vmbus_channel_core.h"

int main(void)
{
	struct vmbus_action action = { 0 };
	struct vmbus_device device = { 0 };
	struct vmbus_packet_meta_abi packet = { 0 };

	return action.tx_len || device.present || packet.payload_size;
}
