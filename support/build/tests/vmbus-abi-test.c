/* SPDX-License-Identifier: BSD-3-Clause */
#include <stddef.h>
#include <uk/vmbus.h>

#include "vmbus_protocol.h"
#include "vmbus_channel_core.h"

_Static_assert(VMBUS_GPA_DIRECT_MAX_RANGES == 32,
	       "VMBus GPA-direct range limit changed");
_Static_assert(VMBUS_GPA_DIRECT_MAX_PFNS == 64,
	       "VMBus GPA-direct PFN limit changed");

int main(void)
{
	struct vmbus_action action = { 0 };
	struct vmbus_device device = { 0 };
	struct vmbus_packet_meta_abi packet = { 0 };
	__typeof__(&vmbus_channel_send_ex) send_ex = NULL;
	__typeof__(&vmbus_channel_send_gpa_direct_ex) send_gpa_ex = NULL;
	__typeof__(&vmbus_connection_fail) connection_fail = NULL;
	__typeof__(&vmbus_connection_quiesce_epoch) quiesce_epoch = NULL;
	__typeof__(&vmbus_device_bind_retry) bind_retry = NULL;
	__typeof__(&vmbus_device_bind_ready) bind_ready = NULL;

	return action.tx_len || device.present || packet.payload_size ||
		send_ex || send_gpa_ex || connection_fail || quiesce_epoch ||
		bind_retry || bind_ready;
}
