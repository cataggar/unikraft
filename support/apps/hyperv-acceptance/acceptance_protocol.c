/* SPDX-License-Identifier: BSD-3-Clause */
#include "acceptance_protocol.h"

#include <string.h>

#define ETH_HEADER_SIZE 14U
#define IPV4_HEADER_SIZE 20U
#define UDP_HEADER_SIZE 8U
#define DHCP_PAYLOAD_SIZE 300U
#define BOOTP_FIXED_SIZE 236U
#define DHCP_COOKIE_SIZE 4U

#define IPV4_OFFSET ETH_HEADER_SIZE
#define UDP_OFFSET (IPV4_OFFSET + IPV4_HEADER_SIZE)
#define DHCP_OFFSET (UDP_OFFSET + UDP_HEADER_SIZE)
#define DHCP_OPTIONS_OFFSET (DHCP_OFFSET + BOOTP_FIXED_SIZE + DHCP_COOKIE_SIZE)

static uint16_t read_be16(const uint8_t *value)
{
	return (uint16_t)(((uint16_t)value[0] << 8) | value[1]);
}

static uint32_t read_be32(const uint8_t *value)
{
	return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
	       ((uint32_t)value[2] << 8) | value[3];
}

static void write_be16(uint8_t *value, uint16_t number)
{
	value[0] = (uint8_t)(number >> 8);
	value[1] = (uint8_t)number;
}

static void write_be32(uint8_t *value, uint32_t number)
{
	value[0] = (uint8_t)(number >> 24);
	value[1] = (uint8_t)(number >> 16);
	value[2] = (uint8_t)(number >> 8);
	value[3] = (uint8_t)number;
}

static uint32_t checksum_add(uint32_t sum, const uint8_t *data, size_t length)
{
	while (length >= 2) {
		sum += read_be16(data);
		data += 2;
		length -= 2;
	}
	if (length)
		sum += (uint16_t)data[0] << 8;
	return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffffU) + (sum >> 16);
	return (uint16_t)~sum;
}

static uint16_t internet_checksum(const uint8_t *data, size_t length)
{
	return checksum_finish(checksum_add(0, data, length));
}

static uint16_t udp_checksum(const uint8_t *ip, const uint8_t *udp,
			     size_t length)
{
	uint8_t pseudo[4];
	uint32_t sum;
	uint16_t result;

	sum = checksum_add(0, ip + 12, 8);
	pseudo[0] = 0;
	pseudo[1] = 17;
	write_be16(pseudo + 2, (uint16_t)length);
	sum = checksum_add(sum, pseudo, sizeof(pseudo));
	result = checksum_finish(checksum_add(sum, udp, length));
	return result ? result : 0xffffU;
}

size_t hyperv_acceptance_build_discover(uint8_t *frame, size_t capacity,
					const uint8_t mac[6], uint32_t xid)
{
	static const uint8_t broadcast[6] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};
	static const uint8_t cookie[4] = { 99, 130, 83, 99 };
	uint8_t *ip;
	uint8_t *udp;
	uint8_t *dhcp;
	uint8_t *option;
	uint16_t checksum;

	if (!frame || !mac || capacity < HYPERV_ACCEPTANCE_DHCP_FRAME_SIZE)
		return 0;
	memset(frame, 0, HYPERV_ACCEPTANCE_DHCP_FRAME_SIZE);

	memcpy(frame, broadcast, sizeof(broadcast));
	memcpy(frame + 6, mac, 6);
	write_be16(frame + 12, 0x0800);

	ip = frame + IPV4_OFFSET;
	ip[0] = 0x45;
	write_be16(ip + 2, IPV4_HEADER_SIZE + UDP_HEADER_SIZE +
			      DHCP_PAYLOAD_SIZE);
	write_be16(ip + 4, (uint16_t)xid);
	ip[8] = 64;
	ip[9] = 17;
	memset(ip + 12, 0, 4);
	memset(ip + 16, 0xff, 4);
	write_be16(ip + 10, internet_checksum(ip, IPV4_HEADER_SIZE));

	udp = frame + UDP_OFFSET;
	write_be16(udp, 68);
	write_be16(udp + 2, 67);
	write_be16(udp + 4, UDP_HEADER_SIZE + DHCP_PAYLOAD_SIZE);

	dhcp = frame + DHCP_OFFSET;
	dhcp[0] = 1;
	dhcp[1] = 1;
	dhcp[2] = 6;
	write_be32(dhcp + 4, xid);
	write_be16(dhcp + 10, 0x8000);
	memcpy(dhcp + 28, mac, 6);
	memcpy(dhcp + BOOTP_FIXED_SIZE, cookie, sizeof(cookie));

	option = frame + DHCP_OPTIONS_OFFSET;
	*option++ = 53;
	*option++ = 1;
	*option++ = 1;
	*option++ = 61;
	*option++ = 7;
	*option++ = 1;
	memcpy(option, mac, 6);
	option += 6;
	*option++ = 55;
	*option++ = 4;
	*option++ = 1;
	*option++ = 3;
	*option++ = 6;
	*option++ = 15;
	*option = 255;

	checksum = udp_checksum(ip, udp, UDP_HEADER_SIZE + DHCP_PAYLOAD_SIZE);
	write_be16(udp + 6, checksum);
	return HYPERV_ACCEPTANCE_DHCP_FRAME_SIZE;
}

static int valid_destination(const uint8_t *destination, const uint8_t mac[6])
{
	static const uint8_t broadcast[6] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};

	return !memcmp(destination, mac, 6) ||
	       !memcmp(destination, broadcast, sizeof(broadcast));
}

int hyperv_acceptance_parse_offer(
	const uint8_t *frame, size_t length, const uint8_t mac[6], uint32_t xid,
	struct hyperv_acceptance_dhcp_offer *offer)
{
	static const uint8_t cookie[4] = { 99, 130, 83, 99 };
	const uint8_t *ip;
	const uint8_t *udp;
	const uint8_t *dhcp;
	const uint8_t *options;
	size_t ip_header_size;
	size_t ip_total_size;
	size_t udp_size;
	size_t options_size;
	size_t cursor = 0;
	int message_type = 0;
	int saw_end = 0;

	if (!frame || !mac || !offer || length < ETH_HEADER_SIZE)
		return 0;
	memset(offer, 0, sizeof(*offer));
	if (read_be16(frame + 12) != 0x0800 || !valid_destination(frame, mac))
		return 0;
	if (length < ETH_HEADER_SIZE + IPV4_HEADER_SIZE)
		return -1;
	ip = frame + IPV4_OFFSET;
	if ((ip[0] >> 4) != 4)
		return 0;
	ip_header_size = (size_t)(ip[0] & 0x0fU) * 4U;
	if (ip_header_size < IPV4_HEADER_SIZE ||
	    length < ETH_HEADER_SIZE + ip_header_size)
		return -1;
	ip_total_size = read_be16(ip + 2);
	if (ip_total_size < ip_header_size + UDP_HEADER_SIZE ||
	    ip_total_size > length - ETH_HEADER_SIZE)
		return -1;
	if (internet_checksum(ip, ip_header_size) != 0)
		return -1;
	if (ip[9] != 17 || (read_be16(ip + 6) & 0x3fffU))
		return 0;

	udp = ip + ip_header_size;
	udp_size = read_be16(udp + 4);
	if (read_be16(udp) != 67 || read_be16(udp + 2) != 68)
		return 0;
	if (udp_size < UDP_HEADER_SIZE + BOOTP_FIXED_SIZE + DHCP_COOKIE_SIZE ||
	    udp_size > ip_total_size - ip_header_size)
		return -1;
	if (read_be16(udp + 6) &&
	    udp_checksum(ip, udp, udp_size) != 0xffffU)
		return -1;

	dhcp = udp + UDP_HEADER_SIZE;
	if (dhcp[0] != 2 || dhcp[1] != 1 || dhcp[2] != 6)
		return 0;
	if (read_be32(dhcp + 4) != xid || memcmp(dhcp + 28, mac, 6))
		return 0;
	if (memcmp(dhcp + BOOTP_FIXED_SIZE, cookie, sizeof(cookie)))
		return -1;
	if (!(dhcp[16] | dhcp[17] | dhcp[18] | dhcp[19]))
		return -1;

	options = dhcp + BOOTP_FIXED_SIZE + DHCP_COOKIE_SIZE;
	options_size = udp_size - UDP_HEADER_SIZE - BOOTP_FIXED_SIZE -
		       DHCP_COOKIE_SIZE;
	while (cursor < options_size) {
		uint8_t code = options[cursor++];
		uint8_t option_length;

		if (code == 0)
			continue;
		if (code == 255) {
			saw_end = 1;
			break;
		}
		if (cursor >= options_size)
			return -1;
		option_length = options[cursor++];
		if (option_length > options_size - cursor)
			return -1;
		if (code == 53 && option_length == 1)
			message_type = options[cursor];
		else if (code == 54 && option_length == 4) {
			memcpy(offer->server_identifier, options + cursor, 4);
			offer->has_server_identifier = 1;
		}
		cursor += option_length;
	}
	if (message_type != 2)
		return 0;
	if (!saw_end || !offer->has_server_identifier)
		return -1;
	memcpy(offer->offered_address, dhcp + 16, 4);
	return 1;
}

int hyperv_acceptance_has_mbr_signature(const uint8_t *sector, size_t length)
{
	return sector && length >= 512 && sector[510] == 0x55 &&
	       sector[511] == 0xaa;
}

int hyperv_acceptance_has_gpt_signature(const uint8_t *sector, size_t length)
{
	static const uint8_t signature[8] = {
		'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T'
	};

	return sector && length >= sizeof(signature) &&
	       !memcmp(sector, signature, sizeof(signature));
}

enum hyperv_acceptance_result hyperv_acceptance_final_result(
	enum hyperv_acceptance_result storage,
	enum hyperv_acceptance_result network)
{
	if (storage == HYPERV_ACCEPTANCE_PASS &&
	    network == HYPERV_ACCEPTANCE_PASS)
		return HYPERV_ACCEPTANCE_PASS;
	if (storage == HYPERV_ACCEPTANCE_FAIL ||
	    network == HYPERV_ACCEPTANCE_FAIL)
		return HYPERV_ACCEPTANCE_FAIL;
	return HYPERV_ACCEPTANCE_UNAVAILABLE;
}
