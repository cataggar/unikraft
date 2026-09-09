/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __UK_STORVSC_H__
#define __UK_STORVSC_H__

#include <stddef.h>
#include <stdint.h>
#include <uk/essentials.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UK_STORVSC_INSTANCE_ID_SIZE	16U
#define UK_STORVSC_VPD_ID_MAX		64U
#define UK_STORVSC_TARGET_SNAPSHOT_VERSION	1U
#define UK_STORVSC_INVENTORY_SNAPSHOT_VERSION	1U
#define UK_STORVSC_SESSION_VERSION		1U
#define UK_STORVSC_TOPOLOGY_PRISTINE_GENERATION 0ULL

#define UK_STORVSC_CDB_AUTO	0U
#define UK_STORVSC_CDB_10	10U
#define UK_STORVSC_CDB_16	16U

struct uk_storvsc_mapping {
	uint16_t blkdev_id;
	uint16_t controller_index;
	uint32_t channel_id;
	uint32_t connection_id;
	uint8_t instance_id[UK_STORVSC_INSTANCE_ID_SIZE];
	uint8_t path_id;
	uint8_t target_id;
	uint8_t lun;
	uint8_t read_only;
	uint64_t sectors;
	uint32_t sector_size;
	uint8_t vpd_length;
	uint8_t vpd_code_set;
	uint8_t vpd_designator_type;
	uint8_t vpd_association;
	uint8_t vpd_id[UK_STORVSC_VPD_ID_MAX];
};

struct uk_storvsc_target_snapshot {
	uint16_t version;
	uint16_t size;
	uint32_t reserved;
	uint64_t topology_generation;
	uint64_t controller_generation;
	uint64_t lun_generation;
	struct uk_storvsc_mapping mapping;
};

struct uk_storvsc_inventory_snapshot {
	uint16_t version;
	uint16_t size;
	uint32_t reserved;
	uint64_t topology_generation;
	uint32_t count;
	uint32_t reserved2;
};

struct uk_storvsc_session {
	uint16_t version;
	uint16_t size;
	uint32_t reserved;
	uint64_t opaque[5];
};

/*
 * Active mappings are enumerated by instance GUID and SCSI address.
 * Get/find return a read-only snapshot and may return -ENOENT on removal.
 * A snapshot does not pin an immutable disk across controller removal;
 * callers must obtain and validate a fresh snapshot before acting on it.
 * Controller/LUN and blkdev identities remain reserved for the boot.
 * A zero vpd_length means no supported LU-associated designator was
 * available and must not be treated as a stable disk identity.
 */
unsigned int uk_storvsc_mapping_count(void);
int uk_storvsc_mapping_get(unsigned int index,
			   struct uk_storvsc_mapping *mapping);
int uk_storvsc_mapping_find(uint16_t blkdev_id,
			    struct uk_storvsc_mapping *mapping);
/*
 * Returns a coherent active mapping count and topology generation. Callers
 * that enumerate targets must require every target and a final inventory
 * snapshot to carry the same generation. A snapshot does not pin a target;
 * use a session for that purpose. Returns -EAGAIN while a controller has an
 * unresolved bind, recovery, removal, or deferred topology transition.
 */
int uk_storvsc_inventory_get(
	struct uk_storvsc_inventory_snapshot *snapshot);
int uk_storvsc_target_get(unsigned int index,
			  struct uk_storvsc_target_snapshot *snapshot);
/*
 * Returns one only when two coherent empty snapshots describe the driver's
 * documented initial generation and no storage offer lifetime has ever
 * reached VMBus during this boot, including offers rejected before StorVSC
 * admission. Since sessions and I/O require an admitted offer, this also
 * proves that neither could have occurred. This is platform availability
 * evidence, not storage acceptance.
 */
int uk_storvsc_inventory_pristine_empty(
	const struct uk_storvsc_inventory_snapshot *first,
	const struct uk_storvsc_inventory_snapshot *second);

/*
 * Candidate reads are pinned to the exact mapping and controller, LUN, and
 * global topology generations. Write authorization is a separate transition
 * after the caller proves unique ownership; a concurrent topology change
 * makes the read session permanently stale. No session survives reset,
 * removal, or rebind. In guarded-I/O builds, block reads require a live
 * session for their LUN and writes/flushes require the sole write-authorized
 * session. Session transitions and CDB selection require no outstanding
 * requests. CDB selection chooses only the normal 10- or 16-byte block
 * command form; it is not arbitrary SCSI access.
 */
int uk_storvsc_session_begin_read(
	const struct uk_storvsc_target_snapshot *snapshot,
	struct uk_storvsc_session *session);
int uk_storvsc_session_authorize_write(struct uk_storvsc_session *session);
int uk_storvsc_session_set_cdb(struct uk_storvsc_session *session,
			       uint8_t cdb_size);
int uk_storvsc_session_validate(
	const struct uk_storvsc_session *session,
	struct uk_storvsc_target_snapshot *snapshot);
int uk_storvsc_session_end(struct uk_storvsc_session *session);

UK_CTASSERT(sizeof(struct uk_storvsc_mapping) == 112);
UK_CTASSERT(offsetof(struct uk_storvsc_mapping, sectors) == 32);
UK_CTASSERT(offsetof(struct uk_storvsc_mapping, vpd_id) == 48);
UK_CTASSERT(sizeof(struct uk_storvsc_target_snapshot) == 144);
UK_CTASSERT(offsetof(struct uk_storvsc_target_snapshot, mapping) == 32);
UK_CTASSERT(sizeof(struct uk_storvsc_inventory_snapshot) == 24);
UK_CTASSERT(sizeof(struct uk_storvsc_session) == 48);

#ifdef __cplusplus
}
#endif

#endif /* __UK_STORVSC_H__ */
