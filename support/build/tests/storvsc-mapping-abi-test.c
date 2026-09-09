/* SPDX-License-Identifier: BSD-3-Clause */
#include <uk/storvsc.h>

#ifdef __cplusplus
#define STORVSC_STATIC_ASSERT static_assert
#else
#define STORVSC_STATIC_ASSERT _Static_assert
#endif

STORVSC_STATIC_ASSERT(sizeof(struct uk_storvsc_mapping) == 112,
		      "mapping ABI changed");
STORVSC_STATIC_ASSERT(sizeof(struct uk_storvsc_target_snapshot) == 144,
		      "target snapshot ABI changed");
STORVSC_STATIC_ASSERT(sizeof(struct uk_storvsc_inventory_snapshot) == 24,
		      "inventory snapshot ABI changed");
STORVSC_STATIC_ASSERT(sizeof(struct uk_storvsc_session) == 48,
		      "session ABI changed");

int storvsc_mapping_abi_fixture(
	struct uk_storvsc_mapping *mapping,
	struct uk_storvsc_inventory_snapshot *inventory,
	struct uk_storvsc_target_snapshot *target,
	struct uk_storvsc_session *session)
{
	return (int)uk_storvsc_mapping_count() +
		uk_storvsc_mapping_get(0, mapping) +
		uk_storvsc_mapping_find(0, mapping) +
		uk_storvsc_inventory_get(inventory) +
		uk_storvsc_inventory_pristine_empty(inventory, inventory) +
		uk_storvsc_target_get(0, target) +
		uk_storvsc_session_begin_read(target, session) +
		uk_storvsc_session_authorize_write(session) +
		uk_storvsc_session_set_cdb(session, UK_STORVSC_CDB_16) +
		uk_storvsc_session_validate(session, target) +
		uk_storvsc_session_end(session);
}
