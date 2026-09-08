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

static uint16_t read_le16(const uint8_t *value)
{
	return (uint16_t)(value[0] | ((uint16_t)value[1] << 8));
}

static uint32_t read_le32(const uint8_t *value)
{
	return (uint32_t)value[0] | ((uint32_t)value[1] << 8) |
	       ((uint32_t)value[2] << 16) | ((uint32_t)value[3] << 24);
}

static uint64_t read_le64(const uint8_t *value)
{
	return (uint64_t)read_le32(value) |
	       ((uint64_t)read_le32(value + 4) << 32);
}

static void write_le16(uint8_t *value, uint16_t number)
{
	value[0] = (uint8_t)number;
	value[1] = (uint8_t)(number >> 8);
}

static void write_le32(uint8_t *value, uint32_t number)
{
	value[0] = (uint8_t)number;
	value[1] = (uint8_t)(number >> 8);
	value[2] = (uint8_t)(number >> 16);
	value[3] = (uint8_t)(number >> 24);
}

static void write_le64(uint8_t *value, uint64_t number)
{
	write_le32(value, (uint32_t)number);
	write_le32(value + 4, (uint32_t)(number >> 32));
}

uint32_t hyperv_acceptance_persistence_crc32(const void *data, size_t length)
{
	const uint8_t *bytes = data;
	uint32_t crc = UINT32_MAX;

	if (!data && length)
		return 0;
	while (length--) {
		crc ^= *bytes++;
		for (unsigned int bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^
			      (0xedb88320U & (uint32_t)-(int32_t)(crc & 1));
	}
	return ~crc;
}

static int bytes_zero(const uint8_t *bytes, size_t length)
{
	while (length--) {
		if (*bytes++)
			return 0;
	}
	return 1;
}

static int expected_valid(
	const struct hyperv_acceptance_persistence_expected *expected)
{
	return expected && !expected->reserved &&
	       !bytes_zero(expected->run_id, sizeof(expected->run_id)) &&
	       !bytes_zero(expected->disk_id, sizeof(expected->disk_id)) &&
	       expected->sector_size ==
		       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE &&
	       expected->sectors >
		       HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_LBA +
		       HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS;
}

static int identity_valid(
	const struct hyperv_acceptance_persistence_identity *identity)
{
	return identity && !identity->reserved &&
	       !bytes_zero(identity->controller_instance,
			   sizeof(identity->controller_instance)) &&
	       identity->vpd_length &&
	       identity->vpd_length <=
		       HYPERV_ACCEPTANCE_PERSISTENCE_VPD_MAX &&
	       !bytes_zero(identity->vpd_id, identity->vpd_length);
}

static uint32_t record_crc(const uint8_t *sector)
{
	uint8_t copy[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	uint32_t crc;

	memcpy(copy, sector, sizeof(copy));
	memset(copy + 508, 0, 4);
	crc = hyperv_acceptance_persistence_crc32(copy, sizeof(copy));
	return crc;
}

static int record_valid(const uint8_t *sector, const char magic[8],
			uint16_t header_size)
{
	return sector && !memcmp(sector, magic, 8) &&
	       read_le16(sector + 8) == 1 &&
	       read_le16(sector + 10) == header_size &&
	       read_le32(sector + 12) ==
		       HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE &&
	       bytes_zero(sector + header_size, 508 - header_size) &&
	       read_le32(sector + 508) == record_crc(sector);
}

static void record_begin(uint8_t *sector, const char magic[8],
			 uint16_t header_size)
{
	memset(sector, 0, HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
	memcpy(sector, magic, 8);
	write_le16(sector + 8, 1);
	write_le16(sector + 10, header_size);
	write_le32(sector + 12, HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE);
}

static void record_finish(uint8_t *sector)
{
	write_le32(sector + 508, record_crc(sector));
}

int hyperv_acceptance_persistence_build_manifest(
	const struct hyperv_acceptance_persistence_expected *expected,
	uint8_t sector[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE])
{
	static const char magic[] = "UKPSEED1";

	if (!sector || !expected_valid(expected))
		return -1;
	record_begin(sector, magic, 128);
	memcpy(sector + 16, expected->run_id, sizeof(expected->run_id));
	memcpy(sector + 32, expected->disk_id, sizeof(expected->disk_id));
	write_le64(sector + 48, expected->sectors);
	write_le32(sector + 56, expected->sector_size);
	write_le32(sector + 60, 1);
	write_le64(sector + 64, HYPERV_ACCEPTANCE_PERSISTENCE_SEED0_LBA);
	write_le64(sector + 72, HYPERV_ACCEPTANCE_PERSISTENCE_SEED1_LBA);
	write_le64(sector + 80, HYPERV_ACCEPTANCE_PERSISTENCE_INTENT_LBA);
	write_le64(sector + 88, HYPERV_ACCEPTANCE_PERSISTENCE_RECEIPT_LBA);
	write_le64(sector + 96, HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_LBA);
	write_le32(sector + 104,
		   HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS);
	sector[108] = expected->path_id;
	sector[109] = expected->target_id;
	sector[110] = expected->lun;
	record_finish(sector);
	return 0;
}

int hyperv_acceptance_persistence_validate_manifest(
	const uint8_t sector[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	const struct hyperv_acceptance_persistence_expected *expected)
{
	static const char magic[] = "UKPSEED1";

	if (!expected_valid(expected) || !record_valid(sector, magic, 128))
		return -1;
	if (memcmp(sector + 16, expected->run_id, sizeof(expected->run_id)) ||
	    memcmp(sector + 32, expected->disk_id,
		   sizeof(expected->disk_id)) ||
	    read_le64(sector + 48) != expected->sectors ||
	    read_le32(sector + 56) != expected->sector_size ||
	    read_le32(sector + 60) != 1 ||
	    read_le64(sector + 64) !=
		    HYPERV_ACCEPTANCE_PERSISTENCE_SEED0_LBA ||
	    read_le64(sector + 72) !=
		    HYPERV_ACCEPTANCE_PERSISTENCE_SEED1_LBA ||
	    read_le64(sector + 80) !=
		    HYPERV_ACCEPTANCE_PERSISTENCE_INTENT_LBA ||
	    read_le64(sector + 88) !=
		    HYPERV_ACCEPTANCE_PERSISTENCE_RECEIPT_LBA ||
	    read_le64(sector + 96) !=
		    HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_LBA ||
	    read_le32(sector + 104) !=
		    HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS ||
	    sector[108] != expected->path_id ||
	    sector[109] != expected->target_id ||
	    sector[110] != expected->lun || sector[111] ||
	    !bytes_zero(sector + 112, 16))
		return -1;
	return 0;
}

static void fill_identity_record(
	uint8_t *sector,
	const struct hyperv_acceptance_persistence_expected *expected,
	const struct hyperv_acceptance_persistence_identity *identity,
	const struct hyperv_acceptance_persistence_checksums *checksums)
{
	uint8_t manifest[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];

	(void)hyperv_acceptance_persistence_build_manifest(
		expected, manifest);
	memcpy(sector + 16, expected->run_id, sizeof(expected->run_id));
	memcpy(sector + 32, expected->disk_id, sizeof(expected->disk_id));
	write_le32(sector + 48, read_le32(manifest + 508));
	write_le32(sector + 52, expected->sector_size);
	write_le64(sector + 56, expected->sectors);
	memcpy(sector + 64, identity->controller_instance,
	       sizeof(identity->controller_instance));
	sector[80] = identity->path_id;
	sector[81] = identity->target_id;
	sector[82] = identity->lun;
	sector[84] = identity->vpd_length;
	sector[85] = identity->vpd_code_set;
	sector[86] = identity->vpd_designator_type;
	sector[87] = identity->vpd_association;
	memcpy(sector + 88, identity->vpd_id, identity->vpd_length);
	write_le32(sector + 152, checksums->first);
	write_le32(sector + 156, checksums->last);
	write_le32(sector + 160, checksums->extent);
	write_le32(sector + 164, 1);
}

static int identity_record_valid(
	const uint8_t *sector,
	const struct hyperv_acceptance_persistence_expected *expected,
	const struct hyperv_acceptance_persistence_identity *identity,
	struct hyperv_acceptance_persistence_checksums *checksums)
{
	uint8_t manifest[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE];
	size_t vpd_length;

	if (!expected_valid(expected) || !identity_valid(identity))
		return -1;
	if (hyperv_acceptance_persistence_build_manifest(
		    expected, manifest))
		return -1;
	vpd_length = identity->vpd_length;
	if (memcmp(sector + 16, expected->run_id, sizeof(expected->run_id)) ||
	    memcmp(sector + 32, expected->disk_id,
		   sizeof(expected->disk_id)) ||
	    read_le32(sector + 48) != read_le32(manifest + 508) ||
	    read_le32(sector + 52) != expected->sector_size ||
	    read_le64(sector + 56) != expected->sectors ||
	    memcmp(sector + 64, identity->controller_instance,
		   sizeof(identity->controller_instance)) ||
	    sector[80] != identity->path_id ||
	    sector[81] != identity->target_id ||
	    sector[82] != identity->lun || sector[83] ||
	    sector[84] != identity->vpd_length ||
	    sector[85] != identity->vpd_code_set ||
	    sector[86] != identity->vpd_designator_type ||
	    sector[87] != identity->vpd_association ||
	    memcmp(sector + 88, identity->vpd_id, vpd_length) ||
	    !bytes_zero(sector + 88 + vpd_length,
			HYPERV_ACCEPTANCE_PERSISTENCE_VPD_MAX - vpd_length) ||
	    read_le32(sector + 164) != 1)
		return -1;
	if (checksums) {
		checksums->first = read_le32(sector + 152);
		checksums->last = read_le32(sector + 156);
		checksums->extent = read_le32(sector + 160);
	}
	return 0;
}

int hyperv_acceptance_persistence_build_intent(
	const struct hyperv_acceptance_persistence_expected *expected,
	const struct hyperv_acceptance_persistence_identity *identity,
	const struct hyperv_acceptance_persistence_checksums *checksums,
	uint8_t sector[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE])
{
	static const char magic[] = "UKPINT01";

	if (!sector || !checksums || !expected_valid(expected) ||
	    !identity_valid(identity))
		return -1;
	record_begin(sector, magic, 168);
	fill_identity_record(sector, expected, identity, checksums);
	record_finish(sector);
	return 0;
}

int hyperv_acceptance_persistence_build_receipt(
	const struct hyperv_acceptance_persistence_expected *expected,
	const struct hyperv_acceptance_persistence_identity *identity,
	const struct hyperv_acceptance_persistence_checksums *checksums,
	const uint8_t intent[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	uint8_t sector[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE])
{
	static const char intent_magic[] = "UKPINT01";
	static const char magic[] = "UKPDONE1";
	struct hyperv_acceptance_persistence_checksums intent_checksums;

	if (!sector || !checksums ||
	    !record_valid(intent, intent_magic, 168) ||
	    identity_record_valid(
		    intent, expected, identity, &intent_checksums) ||
	    memcmp(checksums, &intent_checksums, sizeof(*checksums)))
		return -1;
	record_begin(sector, magic, 176);
	fill_identity_record(sector, expected, identity, checksums);
	write_le32(sector + 168, read_le32(intent + 508));
	write_le32(sector + 172, 2);
	record_finish(sector);
	return 0;
}

enum hyperv_acceptance_persistence_state
hyperv_acceptance_persistence_classify(
	const struct hyperv_acceptance_persistence_expected *expected,
	const struct hyperv_acceptance_persistence_identity *identity,
	const uint8_t seed0[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	const uint8_t seed1[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	const uint8_t intent[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	const uint8_t receipt[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	struct hyperv_acceptance_persistence_checksums *checksums)
{
	static const char intent_magic[] = "UKPINT01";
	static const char receipt_magic[] = "UKPDONE1";
	struct hyperv_acceptance_persistence_checksums found;

	if (checksums)
		memset(checksums, 0, sizeof(*checksums));
	if (hyperv_acceptance_persistence_validate_manifest(seed0, expected) ||
	    hyperv_acceptance_persistence_validate_manifest(seed1, expected) ||
	    memcmp(seed0, seed1,
		   HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE))
		return HYPERV_ACCEPTANCE_PERSISTENCE_INVALID;
	if (bytes_zero(intent, HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE) &&
	    bytes_zero(receipt, HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE))
		return HYPERV_ACCEPTANCE_PERSISTENCE_PRISTINE;
	if (!record_valid(intent, intent_magic, 168) ||
	    identity_record_valid(intent, expected, identity, &found))
		return HYPERV_ACCEPTANCE_PERSISTENCE_INVALID;
	if (checksums)
		*checksums = found;
	if (bytes_zero(receipt, HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE))
		return HYPERV_ACCEPTANCE_PERSISTENCE_INCOMPLETE;
	if (!record_valid(receipt, receipt_magic, 176) ||
	    identity_record_valid(receipt, expected, identity, NULL) ||
	    memcmp(receipt + 16, intent + 16, 152) ||
	    read_le32(receipt + 168) != read_le32(intent + 508) ||
	    read_le32(receipt + 172) != 2)
		return HYPERV_ACCEPTANCE_PERSISTENCE_INVALID;
	return HYPERV_ACCEPTANCE_PERSISTENCE_COMPLETE;
}

static uint64_t mix64(uint64_t value)
{
	value ^= value >> 30;
	value *= 0xbf58476d1ce4e5b9ULL;
	value ^= value >> 27;
	value *= 0x94d049bb133111ebULL;
	return value ^ (value >> 31);
}

void hyperv_acceptance_persistence_pattern(
	const struct hyperv_acceptance_persistence_expected *expected,
	uint32_t region, uint64_t offset, uint8_t *buffer, size_t length)
{
	uint64_t seed = 0x9e3779b97f4a7c15ULL ^ region;

	if (!buffer || !expected_valid(expected) ||
	    region < HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_FIRST ||
	    region > HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_EXTENT) {
		if (buffer)
			memset(buffer, 0, length);
		return;
	}
	for (unsigned int i = 0;
	     i < HYPERV_ACCEPTANCE_PERSISTENCE_ID_SIZE; i++)
		seed = mix64(seed ^ expected->run_id[i] ^
			     ((uint64_t)expected->disk_id[i] << 8) ^ i);
	for (size_t i = 0; i < length; i++)
		buffer[i] = (uint8_t)mix64(seed + offset + i);
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
