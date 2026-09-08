/* SPDX-License-Identifier: BSD-3-Clause */
#include "application_protocol.h"

#include <string.h>

static const uint8_t application_magic[4] = { 'U', 'K', 'N', 'A' };

static void write_be32(uint8_t *value, uint32_t number)
{
	value[0] = (uint8_t)(number >> 24);
	value[1] = (uint8_t)(number >> 16);
	value[2] = (uint8_t)(number >> 8);
	value[3] = (uint8_t)number;
}

static void write_be64(uint8_t *value, uint64_t number)
{
	write_be32(value, (uint32_t)(number >> 32));
	write_be32(value + 4, (uint32_t)number);
}

static uint32_t read_be32(const uint8_t *value)
{
	return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
	       ((uint32_t)value[2] << 8) | value[3];
}

static uint64_t read_be64(const uint8_t *value)
{
	return ((uint64_t)read_be32(value) << 32) | read_be32(value + 4);
}

int hyperv_acceptance_app_parse_nonce(const char *text, uint64_t *nonce_out)
{
	uint64_t nonce = 0;
	size_t offset;

	if (!text || !nonce_out || strlen(text) != 16)
		return -1;
	for (offset = 0; offset < 16; offset++) {
		uint8_t digit;

		if (text[offset] >= '0' && text[offset] <= '9')
			digit = (uint8_t)(text[offset] - '0');
		else if (text[offset] >= 'a' && text[offset] <= 'f')
			digit = (uint8_t)(text[offset] - 'a' + 10);
		else if (text[offset] >= 'A' && text[offset] <= 'F')
			digit = (uint8_t)(text[offset] - 'A' + 10);
		else
			return -1;
		nonce = (nonce << 4) | digit;
	}
	*nonce_out = nonce;
	return 0;
}

struct hyperv_acceptance_app_rx_result
hyperv_acceptance_app_bounded_rx_drain(
	hyperv_acceptance_app_rx_step_fn step, void *argument)
{
	struct hyperv_acceptance_app_rx_result result = { 0 };
	unsigned int index;

	if (!step) {
		result.error = HYPERV_ACCEPTANCE_APP_RX_ERROR;
		return result;
	}
	for (index = 0; index < HYPERV_ACCEPTANCE_APP_RX_POLL_BUDGET;
	     index++) {
		int status = step(argument);

		if (status < 0) {
			result.error = status;
			return result;
		}
		if (status == HYPERV_ACCEPTANCE_APP_RX_IDLE)
			return result;
		result.packets++;
		if (status == HYPERV_ACCEPTANCE_APP_RX_LAST)
			return result;
		if (status != HYPERV_ACCEPTANCE_APP_RX_MORE) {
			result.error = HYPERV_ACCEPTANCE_APP_RX_ERROR;
			return result;
		}
	}
	result.budget_exhausted = 1;
	return result;
}

int hyperv_acceptance_app_single_tx_attempt(
	hyperv_acceptance_app_tx_attempt_fn attempt, void *argument,
	unsigned int *attempts_out)
{
	if (!attempt || !attempts_out)
		return -1;
	*attempts_out = 1;
	return attempt(argument);
}

enum hyperv_acceptance_app_tcp_action hyperv_acceptance_app_tcp_next_action(
	int failed, int pcb_owned, int connected, int transmit_pending,
	int response_valid, int fully_acknowledged, int peer_closed,
	int deadline_expired)
{
	if (failed || !pcb_owned || deadline_expired)
		return HYPERV_ACCEPTANCE_APP_TCP_FAIL;
	if (connected && transmit_pending)
		return HYPERV_ACCEPTANCE_APP_TCP_SEND;
	if (response_valid && fully_acknowledged && peer_closed)
		return HYPERV_ACCEPTANCE_APP_TCP_CLOSE;
	return HYPERV_ACCEPTANCE_APP_TCP_WAIT;
}

static uint8_t payload_byte(
	enum hyperv_acceptance_app_transport transport,
	enum hyperv_acceptance_app_direction direction, uint32_t sequence,
	uint64_t nonce, size_t offset)
{
	unsigned int nonce_shift = (unsigned int)(7U - (offset & 7U)) * 8U;
	unsigned int sequence_shift = (unsigned int)(3U - (offset & 3U)) * 8U;

	return (uint8_t)((nonce >> nonce_shift) ^
			 (sequence >> sequence_shift) ^
			 ((uint32_t)transport * 0x31U) ^
			 ((uint32_t)direction * 0x57U) ^
			 ((uint32_t)offset * 0x1dU));
}

size_t hyperv_acceptance_app_build(
	uint8_t *message, size_t capacity,
	enum hyperv_acceptance_app_transport transport,
	enum hyperv_acceptance_app_direction direction, uint32_t sequence,
	size_t body_length, uint64_t nonce)
{
	size_t length = HYPERV_ACCEPTANCE_APP_HEADER_SIZE + body_length;
	size_t offset;

	if (!message || body_length > HYPERV_ACCEPTANCE_APP_MAX_BODY_SIZE ||
	    capacity < length)
		return 0;
	memcpy(message, application_magic, sizeof(application_magic));
	message[4] = 1;
	message[5] = (uint8_t)transport;
	message[6] = (uint8_t)direction;
	message[7] = HYPERV_ACCEPTANCE_APP_HEADER_SIZE;
	write_be32(message + 8, sequence);
	write_be32(message + 12, (uint32_t)body_length);
	write_be64(message + 16, nonce);
	for (offset = 0; offset < body_length; offset++)
		message[HYPERV_ACCEPTANCE_APP_HEADER_SIZE + offset] =
			payload_byte(transport, direction, sequence, nonce,
				     offset);
	return length;
}

int hyperv_acceptance_app_validate(
	const uint8_t *message, size_t length,
	enum hyperv_acceptance_app_transport transport,
	enum hyperv_acceptance_app_direction direction, uint32_t sequence,
	size_t body_length, uint64_t nonce)
{
	size_t offset;

	if (!message || length < HYPERV_ACCEPTANCE_APP_HEADER_SIZE)
		return HYPERV_ACCEPTANCE_APP_TOO_SHORT;
	if (memcmp(message, application_magic, sizeof(application_magic)) ||
	    message[4] != 1 || message[5] != (uint8_t)transport ||
	    message[6] != (uint8_t)direction ||
	    message[7] != HYPERV_ACCEPTANCE_APP_HEADER_SIZE ||
	    read_be32(message + 8) != sequence ||
	    read_be64(message + 16) != nonce)
		return HYPERV_ACCEPTANCE_APP_BAD_HEADER;
	if (body_length > HYPERV_ACCEPTANCE_APP_MAX_BODY_SIZE ||
	    read_be32(message + 12) != body_length ||
	    length != HYPERV_ACCEPTANCE_APP_HEADER_SIZE + body_length)
		return HYPERV_ACCEPTANCE_APP_BAD_LENGTH;
	for (offset = 0; offset < body_length; offset++) {
		if (message[HYPERV_ACCEPTANCE_APP_HEADER_SIZE + offset] !=
		    payload_byte(transport, direction, sequence, nonce,
				 offset))
			return HYPERV_ACCEPTANCE_APP_BAD_PAYLOAD;
	}
	return HYPERV_ACCEPTANCE_APP_VALID;
}
