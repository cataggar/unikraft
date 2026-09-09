/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef HYPERV_ACCEPTANCE_PERSISTENCE_HOST_H
#define HYPERV_ACCEPTANCE_PERSISTENCE_HOST_H

#include <stdint.h>

enum hyperv_persistence_host_event {
	HYPERV_PERSISTENCE_HOST_INVENTORY = 1,
	HYPERV_PERSISTENCE_HOST_BEFORE_REJECT_END,
	HYPERV_PERSISTENCE_HOST_BEFORE_REVALIDATE,
	HYPERV_PERSISTENCE_HOST_SESSION_END_ERROR,
	HYPERV_PERSISTENCE_HOST_IO_TIMEOUT,
};

#ifdef HYPERV_PERSISTENCE_HOST_TEST
void hyperv_persistence_host_event(enum hyperv_persistence_host_event event,
				  unsigned int index, int value);
void hyperv_acceptance_persistence_host_reset(void);
int hyperv_acceptance_persistence_host_request_owned(void);
int hyperv_acceptance_persistence_host_request_done(void);
void hyperv_acceptance_persistence_host_set_identity_policy(
	unsigned int identity_policy);
int hyperv_acceptance_persistence_host_mapping_in_scope(
	unsigned int identity_policy, uint8_t path, uint8_t target,
	uint8_t lun, uint64_t sectors, uint32_t sector_size);
#endif

#endif
