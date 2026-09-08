/* SPDX-License-Identifier: BSD-3-Clause */
#include <uk/storvsc.h>

int storvsc_mapping_abi_fixture(struct uk_storvsc_mapping *mapping)
{
	return (int)uk_storvsc_mapping_count() +
		uk_storvsc_mapping_get(0, mapping) +
		uk_storvsc_mapping_find(0, mapping);
}
