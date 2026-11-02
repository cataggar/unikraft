/* SPDX-License-Identifier: BSD-3-Clause */
#include "../coremark.h"

int check_coremark(const uint8_t *text, size_t length)
{
	return wamr_coremark_crc_ok(text, length);
}
