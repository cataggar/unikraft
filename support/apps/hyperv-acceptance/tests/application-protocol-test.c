/* SPDX-License-Identifier: BSD-3-Clause */
#include "application_protocol.h"

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

struct mock_io {
	unsigned int rx_steps;
	unsigned int tx_steps;
	unsigned int timer_steps;
	unsigned int cleanup_steps;
};

static int mock_rx_flood(void *argument)
{
	struct mock_io *mock = argument;

	mock->rx_steps++;
	return HYPERV_ACCEPTANCE_APP_RX_MORE;
}

static int mock_tx_busy(void *argument)
{
	struct mock_io *mock = argument;

	mock->tx_steps++;
	return 1;
}

static void test_bounded_adapter_policy(void)
{
	struct hyperv_acceptance_app_rx_result result;
	struct mock_io mock = { 0 };
	unsigned int tx_attempts;
	unsigned int tick;
	int tx_status;

	for (tick = 0; tick < 3; tick++) {
		result = hyperv_acceptance_app_bounded_rx_drain(
			mock_rx_flood, &mock);
		assert(result.packets ==
		       HYPERV_ACCEPTANCE_APP_RX_POLL_BUDGET);
		assert(result.budget_exhausted);
		assert(!result.error);
		mock.timer_steps++;
	}
	assert(mock.rx_steps == 3 * HYPERV_ACCEPTANCE_APP_RX_POLL_BUDGET);
	assert(mock.timer_steps == 3);
	assert(tick == 3);

	/* Timer-driven and cleanup sends each return after one busy attempt. */
	mock.timer_steps++;
	tx_status = hyperv_acceptance_app_single_tx_attempt(
		mock_tx_busy, &mock, &tx_attempts);
	assert(tx_status == 1);
	assert(tx_attempts == 1);
	assert(mock.tx_steps == 1);
	tx_status = hyperv_acceptance_app_single_tx_attempt(
		mock_tx_busy, &mock, &tx_attempts);
	assert(tx_status == 1);
	assert(tx_attempts == 1);
	assert(mock.tx_steps == 2);
	mock.cleanup_steps++;
	assert(mock.timer_steps == 4);
	assert(mock.cleanup_steps == 1);
}

static void test_tcp_multipump_eof_guards(void)
{
	/* An established PCB reset with unsent bytes must not be dereferenced. */
	assert(hyperv_acceptance_app_tcp_next_action(
		       1, 0, 1, 1, 0, 0, 0, 0) ==
	       HYPERV_ACCEPTANCE_APP_TCP_FAIL);

	/* A complete response remains observable until a later peer action. */
	assert(hyperv_acceptance_app_tcp_next_action(
		       0, 1, 1, 0, 1, 1, 0, 0) ==
	       HYPERV_ACCEPTANCE_APP_TCP_WAIT);

	/* Delayed extra bytes or a reset on the next pump must fail. */
	assert(hyperv_acceptance_app_tcp_next_action(
		       1, 1, 1, 0, 1, 1, 0, 0) ==
	       HYPERV_ACCEPTANCE_APP_TCP_FAIL);
	assert(hyperv_acceptance_app_tcp_next_action(
		       1, 0, 1, 0, 1, 1, 0, 0) ==
	       HYPERV_ACCEPTANCE_APP_TCP_FAIL);

	/* Orderly peer EOF permits close only after the request is acknowledged. */
	assert(hyperv_acceptance_app_tcp_next_action(
		       0, 1, 1, 0, 1, 0, 1, 0) ==
	       HYPERV_ACCEPTANCE_APP_TCP_WAIT);
	assert(hyperv_acceptance_app_tcp_next_action(
		       0, 1, 1, 0, 1, 1, 1, 0) ==
	       HYPERV_ACCEPTANCE_APP_TCP_CLOSE);

	/* A peer that never sends EOF remains waiting, then hits the deadline. */
	assert(hyperv_acceptance_app_tcp_next_action(
		       0, 1, 1, 0, 1, 1, 0, 0) ==
	       HYPERV_ACCEPTANCE_APP_TCP_WAIT);
	assert(hyperv_acceptance_app_tcp_next_action(
		       0, 1, 1, 0, 1, 1, 0, 1) ==
	       HYPERV_ACCEPTANCE_APP_TCP_FAIL);

	assert(hyperv_acceptance_app_tcp_next_action(
		       0, 1, 1, 1, 0, 0, 0, 0) ==
	       HYPERV_ACCEPTANCE_APP_TCP_SEND);
}

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

	test_bounded_adapter_policy();
	test_tcp_multipump_eof_guards();

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
	puts("hyperv application protocol/control tests passed");
	return 0;
}
