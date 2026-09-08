/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef HYPERV_ACCEPTANCE_APPLICATION_PROTOCOL_H
#define HYPERV_ACCEPTANCE_APPLICATION_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define HYPERV_ACCEPTANCE_APP_HEADER_SIZE 24U
#define HYPERV_ACCEPTANCE_APP_MAX_BODY_SIZE 1448U
#define HYPERV_ACCEPTANCE_APP_MAX_MESSAGE_SIZE \
	(HYPERV_ACCEPTANCE_APP_HEADER_SIZE + \
	 HYPERV_ACCEPTANCE_APP_MAX_BODY_SIZE)

enum hyperv_acceptance_app_transport {
	HYPERV_ACCEPTANCE_APP_TCP = 1,
	HYPERV_ACCEPTANCE_APP_UDP = 2,
};

enum hyperv_acceptance_app_direction {
	HYPERV_ACCEPTANCE_APP_REQUEST = 1,
	HYPERV_ACCEPTANCE_APP_RESPONSE = 2,
};

enum hyperv_acceptance_app_validation {
	HYPERV_ACCEPTANCE_APP_VALID = 0,
	HYPERV_ACCEPTANCE_APP_TOO_SHORT = -1,
	HYPERV_ACCEPTANCE_APP_BAD_HEADER = -2,
	HYPERV_ACCEPTANCE_APP_BAD_LENGTH = -3,
	HYPERV_ACCEPTANCE_APP_BAD_PAYLOAD = -4,
};

int hyperv_acceptance_app_parse_nonce(const char *text, uint64_t *nonce_out);

size_t hyperv_acceptance_app_build(
	uint8_t *message, size_t capacity,
	enum hyperv_acceptance_app_transport transport,
	enum hyperv_acceptance_app_direction direction, uint32_t sequence,
	size_t body_length, uint64_t nonce);

int hyperv_acceptance_app_validate(
	const uint8_t *message, size_t length,
	enum hyperv_acceptance_app_transport transport,
	enum hyperv_acceptance_app_direction direction, uint32_t sequence,
	size_t body_length, uint64_t nonce);

#endif
