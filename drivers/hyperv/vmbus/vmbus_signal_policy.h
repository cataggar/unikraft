/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __VMBUS_SIGNAL_POLICY_H__
#define __VMBUS_SIGNAL_POLICY_H__

#include <uk/arch/types.h>

#define VMBUS_VERSION_WS2008		13U
#define VMBUS_LEGACY_EVENT_CONNECTION_ID	2U

static inline __u32
vmbus_signal_connection_id(__u32 version, __u32 offer_connection_id)
{
	return version == VMBUS_VERSION_WS2008 ?
		VMBUS_LEGACY_EVENT_CONNECTION_ID : offer_connection_id;
}

#endif /* __VMBUS_SIGNAL_POLICY_H__ */
