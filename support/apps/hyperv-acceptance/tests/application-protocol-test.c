/* SPDX-License-Identifier: BSD-3-Clause */
#include "application_protocol.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

int main(void)
{
	static const uint8_t expected_header[] = {
		'U', 'K', 'N', 'A', 1, 1, 1, 24,
		0x01, 0x02, 0x03, 0x04,
		0x00, 0x00, 0x00, 0x04,
		0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88,
	};
	uint8_t message[HYPERV_ACCEPTANCE_APP_MAX_MESSAGE_SIZE];
	uint64_t nonce;
	size_t length;

	assert(!hyperv_acceptance_app_parse_nonce(
		"87c0ffee5aa8dfd6", &nonce));
	assert(nonce == UINT64_C(0x87c0ffee5aa8dfd6));
	assert(!hyperv_acceptance_app_parse_nonce(
		"ABCDEF0123456789", &nonce));
	assert(nonce == UINT64_C(0xabcdef0123456789));
	assert(hyperv_acceptance_app_parse_nonce(
		"0x87c0ffee5aa8dfd6", &nonce));
	assert(hyperv_acceptance_app_parse_nonce(
		"87c0ffee5aa8dfdz", &nonce));
	assert(hyperv_acceptance_app_parse_nonce(NULL, &nonce));
	assert(hyperv_acceptance_app_parse_nonce(
		"87c0ffee5aa8dfd6", NULL));

	length = hyperv_acceptance_app_build(
		message, sizeof(message), HYPERV_ACCEPTANCE_APP_TCP,
		HYPERV_ACCEPTANCE_APP_REQUEST, 0x01020304U, 4,
		UINT64_C(0x1122334455667788));
	assert(length == HYPERV_ACCEPTANCE_APP_HEADER_SIZE + 4);
	assert(!memcmp(message, expected_header, sizeof(expected_header)));
	assert(message[24] == 0x76);
	assert(message[25] == 0x5b);
	assert(message[26] == 0x6c);
	assert(message[27] == 0x71);
	assert(hyperv_acceptance_app_validate(
		       message, length, HYPERV_ACCEPTANCE_APP_TCP,
		       HYPERV_ACCEPTANCE_APP_REQUEST, 0x01020304U, 4,
		       UINT64_C(0x1122334455667788)) ==
	       HYPERV_ACCEPTANCE_APP_VALID);

	message[3] ^= 1;
	assert(hyperv_acceptance_app_validate(
		       message, length, HYPERV_ACCEPTANCE_APP_TCP,
		       HYPERV_ACCEPTANCE_APP_REQUEST, 0x01020304U, 4,
		       UINT64_C(0x1122334455667788)) ==
	       HYPERV_ACCEPTANCE_APP_BAD_HEADER);
	message[3] ^= 1;
	message[length - 1] ^= 1;
	assert(hyperv_acceptance_app_validate(
		       message, length, HYPERV_ACCEPTANCE_APP_TCP,
		       HYPERV_ACCEPTANCE_APP_REQUEST, 0x01020304U, 4,
		       UINT64_C(0x1122334455667788)) ==
	       HYPERV_ACCEPTANCE_APP_BAD_PAYLOAD);
	assert(!hyperv_acceptance_app_build(
		message, sizeof(message), HYPERV_ACCEPTANCE_APP_UDP,
		HYPERV_ACCEPTANCE_APP_RESPONSE, 1,
		HYPERV_ACCEPTANCE_APP_MAX_BODY_SIZE + 1, 2));
	return 0;
}
