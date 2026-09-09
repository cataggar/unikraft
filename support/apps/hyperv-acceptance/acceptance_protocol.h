/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef HYPERV_ACCEPTANCE_PROTOCOL_H
#define HYPERV_ACCEPTANCE_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define HYPERV_ACCEPTANCE_DHCP_FRAME_SIZE 342U
#define HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE 512U
#define HYPERV_ACCEPTANCE_PERSISTENCE_ID_SIZE 16U
#define HYPERV_ACCEPTANCE_PERSISTENCE_VPD_MAX 64U

#define HYPERV_ACCEPTANCE_PERSISTENCE_SEED0_LBA 8ULL
#define HYPERV_ACCEPTANCE_PERSISTENCE_SEED1_LBA 9ULL
#define HYPERV_ACCEPTANCE_PERSISTENCE_INTENT_LBA 16ULL
#define HYPERV_ACCEPTANCE_PERSISTENCE_RECEIPT_LBA 17ULL
#define HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_LBA 32ULL
#define HYPERV_ACCEPTANCE_PERSISTENCE_EXTENT_SECTORS 16U

#define HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_FIRST 1U
#define HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_LAST 2U
#define HYPERV_ACCEPTANCE_PERSISTENCE_PATTERN_EXTENT 3U

#define HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_ADDRESS_V1 1U
#define HYPERV_ACCEPTANCE_PERSISTENCE_IDENTITY_SEED_ENROLLMENT_V2 2U
#define HYPERV_ACCEPTANCE_PERSISTENCE_UNAVAILABLE_PROTOCOL 1U
#define HYPERV_ACCEPTANCE_PERSISTENCE_UNAVAILABLE_NO_DEVICES "no-devices"

enum hyperv_acceptance_result {
	HYPERV_ACCEPTANCE_PASS = 0,
	HYPERV_ACCEPTANCE_FAIL = 1,
	HYPERV_ACCEPTANCE_UNAVAILABLE = 2,
};

struct hyperv_acceptance_dhcp_offer {
	uint8_t offered_address[4];
	uint8_t server_identifier[4];
	uint8_t has_server_identifier;
};

/*
 * Persistence records are exactly one 512-byte sector. All integers are
 * little-endian and all unspecified bytes must be zero. Every record stores
 * an IEEE CRC-32 in bytes 508..511, calculated with that field zero.
 *
 * Address-v1 manifest (magic "UKPSEED1", record/layout version 1,
 * header size 128):
 *   16 run ID[16], 32 disk ID[16], 48 sectors:u64,
 *   56 sector size:u32, 60 layout version:u32,
 *   64 seed0:u64, 72 seed1:u64, 80 intent:u64, 88 receipt:u64,
 *   96 extent LBA:u64, 104 extent sectors:u32,
 *   108 path:u8, 109 target:u8, 110 LUN:u8, 111 reserved:u8.
 *
 * Seed-enrollment-v2 manifest (magic "UKPSEED2", record/layout version 2,
 * header size 128) has the same bytes through 107, then:
 *   108 identity policy:u8 (=2), 109 reserved:u8,
 *   110 LUN:u8, 111 reserved:u8.
 * Path and target are deliberately absent: the guest enrolls them together
 * with the controller and VPD only after a unique seed and geometry match.
 *
 * Intent (v1 magic "UKPINT01", v2 magic "UKPINT02", header size 168)
 * repeats the IDs and geometry:
 *   48 manifest CRC:u32, 52 sector size:u32, 56 sectors:u64,
 *   64 controller instance ID[16], 80 path/target/LUN,
 *   83 v1 reserved (=0) or v2 identity policy (=2),
 *   84 VPD length/code set/type/association, 88 VPD ID[64],
 *   152 first-sector CRC:u32, 156 last-sector CRC:u32,
 *   160 extent CRC:u32, 164 phase:u32 (=1).
 *
 * Receipt (v1 magic "UKPDONE1", v2 magic "UKPDONE2", header size 176)
 * has the same bytes 16..167 as the intent, then 168 intent CRC:u32 and
 * 172 phase:u32 (=2). Record version, magic, manifest CRC, and policy byte
 * prevent policy downgrade or cross-policy record reuse.
 */
struct hyperv_acceptance_persistence_expected {
	uint8_t run_id[HYPERV_ACCEPTANCE_PERSISTENCE_ID_SIZE];
	uint8_t disk_id[HYPERV_ACCEPTANCE_PERSISTENCE_ID_SIZE];
	uint64_t sectors;
	uint32_t sector_size;
	uint8_t path_id;
	uint8_t target_id;
	uint8_t lun;
	uint8_t identity_policy;
};

struct hyperv_acceptance_persistence_identity {
	uint8_t controller_instance[HYPERV_ACCEPTANCE_PERSISTENCE_ID_SIZE];
	uint8_t path_id;
	uint8_t target_id;
	uint8_t lun;
	uint8_t reserved;
	uint8_t vpd_length;
	uint8_t vpd_code_set;
	uint8_t vpd_designator_type;
	uint8_t vpd_association;
	uint8_t vpd_id[HYPERV_ACCEPTANCE_PERSISTENCE_VPD_MAX];
};

struct hyperv_acceptance_persistence_checksums {
	uint32_t first;
	uint32_t last;
	uint32_t extent;
};

enum hyperv_acceptance_persistence_state {
	HYPERV_ACCEPTANCE_PERSISTENCE_INVALID = -1,
	HYPERV_ACCEPTANCE_PERSISTENCE_PRISTINE = 0,
	HYPERV_ACCEPTANCE_PERSISTENCE_INCOMPLETE = 1,
	HYPERV_ACCEPTANCE_PERSISTENCE_COMPLETE = 2,
};

static inline size_t hyperv_acceptance_buffer_alignment(size_t ioalign)
{
	return ioalign < sizeof(void *) ? sizeof(void *) : ioalign;
}

size_t hyperv_acceptance_build_discover(uint8_t *frame, size_t capacity,
					const uint8_t mac[6], uint32_t xid);

/*
 * Returns one for a matching DHCP Offer, zero for an unrelated packet, and a
 * negative value for a malformed matching DHCP packet.
 */
int hyperv_acceptance_parse_offer(
	const uint8_t *frame, size_t length, const uint8_t mac[6], uint32_t xid,
	struct hyperv_acceptance_dhcp_offer *offer);

int hyperv_acceptance_has_mbr_signature(const uint8_t *sector, size_t length);
int hyperv_acceptance_has_gpt_signature(const uint8_t *sector, size_t length);

uint32_t hyperv_acceptance_persistence_crc32(const void *data, size_t length);
int hyperv_acceptance_persistence_build_manifest(
	const struct hyperv_acceptance_persistence_expected *expected,
	uint8_t sector[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE]);
int hyperv_acceptance_persistence_validate_manifest(
	const uint8_t sector[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	const struct hyperv_acceptance_persistence_expected *expected);
int hyperv_acceptance_persistence_build_intent(
	const struct hyperv_acceptance_persistence_expected *expected,
	const struct hyperv_acceptance_persistence_identity *identity,
	const struct hyperv_acceptance_persistence_checksums *checksums,
	uint8_t sector[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE]);
int hyperv_acceptance_persistence_build_receipt(
	const struct hyperv_acceptance_persistence_expected *expected,
	const struct hyperv_acceptance_persistence_identity *identity,
	const struct hyperv_acceptance_persistence_checksums *checksums,
	const uint8_t intent[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	uint8_t sector[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE]);
enum hyperv_acceptance_persistence_state
hyperv_acceptance_persistence_classify(
	const struct hyperv_acceptance_persistence_expected *expected,
	const struct hyperv_acceptance_persistence_identity *identity,
	const uint8_t seed0[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	const uint8_t seed1[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	const uint8_t intent[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	const uint8_t receipt[HYPERV_ACCEPTANCE_PERSISTENCE_SECTOR_SIZE],
	struct hyperv_acceptance_persistence_checksums *checksums);
void hyperv_acceptance_persistence_pattern(
	const struct hyperv_acceptance_persistence_expected *expected,
	uint32_t region, uint64_t offset, uint8_t *buffer, size_t length);

enum hyperv_acceptance_result hyperv_acceptance_final_result(
	enum hyperv_acceptance_result storage,
	enum hyperv_acceptance_result network);
int hyperv_acceptance_binding_ready(unsigned int offers,
				    unsigned int bound_offers,
				    unsigned int ready_devices);

#endif
