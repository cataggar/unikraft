/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __UK_STORVSC_H__
#define __UK_STORVSC_H__

#include <stddef.h>
#include <stdint.h>

#define UK_STORVSC_INSTANCE_ID_SIZE	16U
#define UK_STORVSC_VPD_ID_MAX		64U

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

_Static_assert(sizeof(struct uk_storvsc_mapping) == 112,
	       "StorVSC mapping ABI changed");
_Static_assert(offsetof(struct uk_storvsc_mapping, sectors) == 32,
	       "StorVSC mapping media offset changed");
_Static_assert(offsetof(struct uk_storvsc_mapping, vpd_id) == 48,
	       "StorVSC mapping VPD offset changed");

#endif /* __UK_STORVSC_H__ */
