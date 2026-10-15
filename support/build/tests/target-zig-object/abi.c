/* SPDX-License-Identifier: BSD-3-Clause */
#include <uk/bits/config.h>
#include "issue34-fixture.h"

extern unsigned int issue34_zig_target_value(void);
extern unsigned int issue34_zig_fixture_checksum(struct issue34_fixture value);
extern unsigned int uk_target_zig_config_marker(void);

int main(void)
{
	struct issue34_fixture value = {
		.value = 0x12345678,
		.tag = 0x4321,
		.lane = 0x56
	};

	if (issue34_zig_target_value() !=
	    CONFIG_ISSUE34_VALUE + ISSUE34_INCLUDE_VALUE + ISSUE34_OBJECT_VALUE)
		return 1;
	if (issue34_zig_fixture_checksum(value) !=
	    value.value + value.tag + value.lane)
		return 2;
	if (uk_target_zig_config_marker() != CONFIG_OPTIMIZE_PIE)
		return 3;
	return 0;
}
