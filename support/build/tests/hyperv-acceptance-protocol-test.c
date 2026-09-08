/* SPDX-License-Identifier: BSD-3-Clause */
#include "acceptance_protocol.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expression)						\
	do {								\
		if (!(expression)) {					\
			fprintf(stderr, "check failed at %s:%d: %s\n",	\
				__FILE__, __LINE__, #expression);	\
			return 1;					\
		}							\
	} while (0)

static uint16_t read_be16(const uint8_t *value)
{
	return (uint16_t)(((uint16_t)value[0] << 8) | value[1]);
}

static void write_be16(uint8_t *value, uint16_t number)
{
	value[0] = (uint8_t)(number >> 8);
	value[1] = (uint8_t)number;
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

static uint16_t packet_checksum(const uint8_t *data, size_t length)
{
	return checksum_finish(checksum_add(0, data, length));
}

static void fix_udp_checksum(uint8_t *frame)
{
	uint8_t *ip = frame + 14;
	uint8_t *udp = ip + 20;
	uint8_t pseudo[4] = { 0, 17, 1, 52 };
	uint32_t sum;
	uint16_t checksum;

	udp[6] = udp[7] = 0;
	sum = checksum_add(0, ip + 12, 8);
	sum = checksum_add(sum, pseudo, sizeof(pseudo));
	checksum = checksum_finish(checksum_add(sum, udp, 308));
	write_be16(udp + 6, checksum ? checksum : 0xffffU);
}

static void make_offer(uint8_t *frame, const uint8_t mac[6], uint32_t xid)
{
	uint8_t *ip;
	uint8_t *udp;
	uint8_t *dhcp;
	uint8_t *option;

	(void)hyperv_acceptance_build_discover(
		frame, HYPERV_ACCEPTANCE_DHCP_FRAME_SIZE, mac, xid);
	memcpy(frame, mac, 6);
	ip = frame + 14;
	ip[12] = 10;
	ip[13] = 0;
	ip[14] = 0;
	ip[15] = 1;
	ip[16] = 255;
	ip[17] = 255;
	ip[18] = 255;
	ip[19] = 255;
	ip[10] = ip[11] = 0;
	write_be16(ip + 10, packet_checksum(ip, 20));

	udp = ip + 20;
	write_be16(udp, 67);
	write_be16(udp + 2, 68);
	dhcp = udp + 8;
	dhcp[0] = 2;
	dhcp[16] = 10;
	dhcp[17] = 0;
	dhcp[18] = 0;
	dhcp[19] = 42;
	option = dhcp + 240;
	option[2] = 2;
	option[3] = 54;
	option[4] = 4;
	option[5] = 10;
	option[6] = 0;
	option[7] = 0;
	option[8] = 1;
	option[9] = 255;
	memset(option + 10, 0, 300 - 240 - 10);
	fix_udp_checksum(frame);
}

static int test_dhcp(void)
{
	static const uint8_t mac[6] = { 0, 21, 93, 1, 2, 3 };
	static const uint8_t other_mac[6] = { 0, 21, 93, 1, 2, 4 };
	uint8_t frame[HYPERV_ACCEPTANCE_DHCP_FRAME_SIZE];
	struct hyperv_acceptance_dhcp_offer offer = { 0 };
	uint32_t xid = 0x554b0102;
	size_t length;

	length = hyperv_acceptance_build_discover(frame, sizeof(frame), mac, xid);
	CHECK(length == sizeof(frame));
	CHECK(!memcmp(frame, "\xff\xff\xff\xff\xff\xff", 6));
	CHECK(!memcmp(frame + 6, mac, 6));
	CHECK(read_be16(frame + 12) == 0x0800);
	CHECK(packet_checksum(frame + 14, 20) == 0);
	CHECK(read_be16(frame + 34) == 68);
	CHECK(read_be16(frame + 36) == 67);
	CHECK(read_be16(frame + 40) != 0);

	make_offer(frame, mac, xid);
	CHECK(hyperv_acceptance_parse_offer(frame, sizeof(frame), mac, xid,
					   &offer) == 1);
	CHECK(!memcmp(offer.offered_address, "\x0a\x00\x00\x2a", 4));
	CHECK(offer.has_server_identifier);
	CHECK(!memcmp(offer.server_identifier, "\x0a\x00\x00\x01", 4));

	CHECK(hyperv_acceptance_parse_offer(frame, sizeof(frame) - 1, mac, xid,
					   &offer) < 0);
	make_offer(frame, mac, xid);
	frame[60] ^= 1;
	CHECK(hyperv_acceptance_parse_offer(frame, sizeof(frame), mac, xid,
					   &offer) < 0);
	make_offer(frame, mac, xid);
	CHECK(hyperv_acceptance_parse_offer(frame, sizeof(frame), mac, xid + 1,
					   &offer) == 0);
	make_offer(frame, mac, xid);
	CHECK(hyperv_acceptance_parse_offer(frame, sizeof(frame), other_mac, xid,
					   &offer) == 0);
	make_offer(frame, mac, xid);
	frame[42 + 240 + 1] = 250;
	fix_udp_checksum(frame);
	CHECK(hyperv_acceptance_parse_offer(frame, sizeof(frame), mac, xid,
					   &offer) < 0);
	make_offer(frame, mac, xid);
	frame[42 + 240 + 3] = 255;
	memset(frame + 42 + 240 + 4, 0, 300 - 240 - 4);
	fix_udp_checksum(frame);
	CHECK(hyperv_acceptance_parse_offer(frame, sizeof(frame), mac, xid,
					   &offer) < 0);
	make_offer(frame, mac, xid);
	frame[42 + 240 + 9] = 0;
	fix_udp_checksum(frame);
	CHECK(hyperv_acceptance_parse_offer(frame, sizeof(frame), mac, xid,
					   &offer) < 0);
	return 0;
}

static int test_storage_and_gating(void)
{
	uint8_t sector[512] = { 0 };

	CHECK(!hyperv_acceptance_has_mbr_signature(sector, sizeof(sector)));
	sector[510] = 0x55;
	sector[511] = 0xaa;
	CHECK(hyperv_acceptance_has_mbr_signature(sector, sizeof(sector)));
	CHECK(!hyperv_acceptance_has_mbr_signature(sector, 511));
	memcpy(sector, "EFI PART", 8);
	CHECK(hyperv_acceptance_has_gpt_signature(sector, sizeof(sector)));
	sector[0] = 'X';
	CHECK(!hyperv_acceptance_has_gpt_signature(sector, sizeof(sector)));

	CHECK(hyperv_acceptance_final_result(HYPERV_ACCEPTANCE_PASS,
					    HYPERV_ACCEPTANCE_PASS) ==
	      HYPERV_ACCEPTANCE_PASS);
	CHECK(hyperv_acceptance_final_result(HYPERV_ACCEPTANCE_PASS,
					    HYPERV_ACCEPTANCE_UNAVAILABLE) ==
	      HYPERV_ACCEPTANCE_UNAVAILABLE);
	CHECK(hyperv_acceptance_final_result(HYPERV_ACCEPTANCE_UNAVAILABLE,
					    HYPERV_ACCEPTANCE_PASS) ==
	      HYPERV_ACCEPTANCE_UNAVAILABLE);
	CHECK(hyperv_acceptance_final_result(HYPERV_ACCEPTANCE_UNAVAILABLE,
					    HYPERV_ACCEPTANCE_UNAVAILABLE) ==
	      HYPERV_ACCEPTANCE_UNAVAILABLE);
	CHECK(hyperv_acceptance_final_result(HYPERV_ACCEPTANCE_FAIL,
					    HYPERV_ACCEPTANCE_UNAVAILABLE) ==
	      HYPERV_ACCEPTANCE_FAIL);
	CHECK(hyperv_acceptance_final_result(HYPERV_ACCEPTANCE_PASS,
					    HYPERV_ACCEPTANCE_FAIL) ==
	      HYPERV_ACCEPTANCE_FAIL);
	return 0;
}

static int test_buffer_alignment(void)
{
	static const size_t alignments[] = { 0, 1, 2, 4, 8, 64, 4096 };
	size_t index;

	for (index = 0; index < sizeof(alignments) / sizeof(alignments[0]);
	     index++) {
		size_t alignment =
			hyperv_acceptance_buffer_alignment(alignments[index]);

		CHECK(alignment >= alignments[index]);
		CHECK(alignment >= sizeof(void *));
		CHECK(alignment % sizeof(void *) == 0);
	}
	CHECK(hyperv_acceptance_buffer_alignment(1) == sizeof(void *));
	CHECK(hyperv_acceptance_buffer_alignment(4096) == 4096);
	return 0;
}

static int test_persistence_protocol(void)
{
	struct hyperv_acceptance_persistence_expected expected = {
		.sectors = 4096,
		.sector_size = HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE,
		.path_id = 0,
		.target_id = 0,
		.lun = 2,
	};
	struct hyperv_acceptance_persistence_identity identity = {
		.path_id = 0,
		.target_id = 0,
		.lun = 2,
		.vpd_length = 8,
		.vpd_code_set = 1,
		.vpd_designator_type = 3,
	};
	struct hyperv_acceptance_persistence_checksums checksums;
	struct hyperv_acceptance_persistence_checksums found;
	uint8_t seed0[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t seed1[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t intent[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE] = { 0 };
	uint8_t receipt[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE] = { 0 };
	uint8_t zero[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE] = { 0 };
	uint8_t pattern[HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS *
			HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint8_t repeat[sizeof(pattern)];

	for (unsigned int i = 0;
	     i < HYPERV_ACCEPTANCE_PERSISTENCE_ID_SIZE; i++) {
		expected.run_id[i] = (uint8_t)(0x10 + i);
		expected.disk_id[i] = (uint8_t)(0x80 + i);
		identity.controller_instance[i] = (uint8_t)(0x40 + i);
	}
	memcpy(identity.vpd_id, "\x50\x01\x02\x03\x04\x05\x06\x02", 8);
	CHECK(!hyperv_acceptance_persistence_build_manifest(
		&expected, seed0));
	memcpy(seed1, seed0, sizeof(seed1));
	CHECK(!hyperv_acceptance_persistence_validate_manifest(
		seed0, &expected));
	CHECK(!memcmp(seed0, "UKPSEED1", 8));
	CHECK(hyperv_acceptance_persistence_classify(
		&expected, &identity, seed0, seed1, intent, receipt,
		&found) == HYPERV_ACCEPTANCE_PERSISTENCE_PRISTINE);

	seed1[120] = 1;
	CHECK(hyperv_acceptance_persistence_classify(
		&expected, &identity, seed0, seed1, intent, receipt,
		NULL) == HYPERV_ACCEPTANCE_PERSISTENCE_INVALID);
	memcpy(seed1, seed0, sizeof(seed1));
	seed1[32] ^= 1;
	CHECK(hyperv_acceptance_persistence_classify(
		&expected, &identity, seed0, seed1, intent, receipt,
		NULL) == HYPERV_ACCEPTANCE_PERSISTENCE_INVALID);
	memcpy(seed1, seed0, sizeof(seed1));

	hyperv_acceptance_persistence_pattern(
		&expected, HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_FIRST,
		0, pattern, HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	checksums.first = hyperv_acceptance_persistence_crc32(
		pattern, HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	hyperv_acceptance_persistence_pattern(
		&expected, HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_LAST,
		0, pattern, HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	checksums.last = hyperv_acceptance_persistence_crc32(
		pattern, HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	hyperv_acceptance_persistence_pattern(
		&expected, HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_EXTENT,
		0, pattern, sizeof(pattern));
	memcpy(repeat, pattern, sizeof(repeat));
	checksums.extent = hyperv_acceptance_persistence_crc32(
		pattern, sizeof(pattern));
	CHECK(checksums.first != checksums.last &&
	      checksums.last != checksums.extent);
	hyperv_acceptance_persistence_pattern(
		&expected, HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_EXTENT,
		0, pattern, sizeof(pattern));
	CHECK(!memcmp(pattern, repeat, sizeof(pattern)));
	hyperv_acceptance_persistence_pattern(
		&expected, HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_EXTENT,
		512, pattern, 512);
	CHECK(memcmp(pattern, repeat, 512));

	CHECK(!hyperv_acceptance_persistence_build_intent(
		&expected, &identity, &checksums, intent));
	CHECK(hyperv_acceptance_persistence_classify(
		&expected, &identity, seed0, seed1, intent, receipt,
		&found) == HYPERV_ACCEPTANCE_PERSISTENCE_INCOMPLETE);
	CHECK(!memcmp(&checksums, &found, sizeof(checksums)));
	intent[90] ^= 1;
	CHECK(hyperv_acceptance_persistence_classify(
		&expected, &identity, seed0, seed1, intent, receipt,
		NULL) == HYPERV_ACCEPTANCE_PERSISTENCE_INVALID);
	CHECK(!hyperv_acceptance_persistence_build_intent(
		&expected, &identity, &checksums, intent));

	CHECK(!hyperv_acceptance_persistence_build_receipt(
		&expected, &identity, &checksums, intent, receipt));
	CHECK(hyperv_acceptance_persistence_classify(
		&expected, &identity, seed0, seed1, intent, receipt,
		&found) == HYPERV_ACCEPTANCE_PERSISTENCE_COMPLETE);
	CHECK(!memcmp(&checksums, &found, sizeof(checksums)));
	receipt[172] ^= 1;
	CHECK(hyperv_acceptance_persistence_classify(
		&expected, &identity, seed0, seed1, intent, receipt,
		NULL) == HYPERV_ACCEPTANCE_PERSISTENCE_INVALID);
	CHECK(!hyperv_acceptance_persistence_build_receipt(
		&expected, &identity, &checksums, intent, receipt));

	identity.vpd_id[1] ^= 1;
	CHECK(hyperv_acceptance_persistence_classify(
		&expected, &identity, seed0, seed1, intent, receipt,
		NULL) == HYPERV_ACCEPTANCE_PERSISTENCE_INVALID);
	identity.vpd_id[1] ^= 1;
	CHECK(hyperv_acceptance_persistence_classify(
		&expected, &identity, seed0, seed1, zero, receipt,
		NULL) == HYPERV_ACCEPTANCE_PERSISTENCE_INVALID);

	expected.sectors++;
	CHECK(hyperv_acceptance_persistence_validate_manifest(
		seed0, &expected));
	expected.sectors--;
	identity.vpd_length = 0;
	CHECK(hyperv_acceptance_persistence_classify(
		&expected, &identity, seed0, seed1, intent, receipt,
		NULL) == HYPERV_ACCEPTANCE_PERSISTENCE_INVALID);
	identity.vpd_length = 8;
	memset(identity.controller_instance, 0,
	       sizeof(identity.controller_instance));
	CHECK(hyperv_acceptance_persistence_classify(
		&expected, &identity, seed0, seed1, intent, receipt,
		NULL) == HYPERV_ACCEPTANCE_PERSISTENCE_INVALID);
	return 0;
}

int main(void)
{
	if (test_dhcp() || test_storage_and_gating() ||
	    test_buffer_alignment() || test_persistence_protocol())
		return 1;
	puts("hyperv acceptance protocol tests passed");
	return 0;
}
