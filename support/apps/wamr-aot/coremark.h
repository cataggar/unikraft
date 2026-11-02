/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef WAMR_COREMARK_H
#define WAMR_COREMARK_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline int wamr_coremark_equal(const uint8_t *text, size_t length,
				      const char *expected)
{
	return length == strlen(expected) && !memcmp(text, expected, length);
}

static inline int wamr_coremark_crc_ok(const uint8_t *text, size_t length)
{
	static const struct {
		const char *key;
		const char *value;
	} fields[] = {
		{ "Iterations", "100" },
		{ "seedcrc", "0xe9f5" },
		{ "[0]crclist", "0xe714" },
		{ "[0]crcmatrix", "0x1fd7" },
		{ "[0]crcstate", "0x8e3a" },
		{ "[0]crcfinal", "0x988c" },
		{ "CoreMark Size", NULL },
		{ "Total ticks", NULL },
		{ "Total time (secs)", NULL },
		{ "Iterations/Sec", NULL },
		{ "Compiler version", NULL },
		{ "Compiler flags", NULL },
		{ "Memory location", NULL },
	};
	static const char *const lines[] = {
		"2K performance run parameters for coremark.",
		"ERROR! Must execute for at least 10 secs for a valid result!",
		"Errors detected",
	};
	uint32_t seen = 0;
	unsigned int markers = 0;
	size_t start = 0, end, colon, key_end, value, i;

	if (!length || text[length - 1] != '\n')
		return 0;
	while (start < length) {
		end = start;
		while (text[end] != '\n') {
			if ((text[end] < 32 && text[end] != '\t' && text[end] != '\r') ||
			    text[end] > 126)
				return 0;
			end++;
		}
		i = end + 1;
		if (end > start && text[end - 1] == '\r')
			end--;
		while (start < end && (text[start] == ' ' || text[start] == '\t'))
			start++;
		while (end > start && (text[end - 1] == ' ' || text[end - 1] == '\t'))
			end--;
		for (colon = start; colon < end && text[colon] != ':'; colon++)
			;
		if (colon == end) {
			size_t n;

			for (n = 0; n < sizeof(lines) / sizeof(lines[0]); n++)
				if (wamr_coremark_equal(text + start, end - start, lines[n]))
					break;
			if (n == sizeof(lines) / sizeof(lines[0]) || (markers & (1U << n)))
				return 0;
			markers |= 1U << n;
		} else {
			size_t n;

			key_end = colon;
			while (key_end > start &&
			       (text[key_end - 1] == ' ' || text[key_end - 1] == '\t'))
				key_end--;
			value = colon + 1;
			while (value < end && (text[value] == ' ' || text[value] == '\t'))
				value++;
			for (n = 0; n < sizeof(fields) / sizeof(fields[0]); n++)
				if (wamr_coremark_equal(text + start, key_end - start, fields[n].key))
					break;
			if (n == sizeof(fields) / sizeof(fields[0]) || (seen & (1U << n)))
				return 0;
			if (fields[n].value &&
			    !wamr_coremark_equal(text + value, end - value, fields[n].value))
				return 0;
			seen |= 1U << n;
		}
		start = i;
	}
	/* Only the documented short-duration warning is admissible; expected
	 * CRCs in diagnostics or another context cannot satisfy keyed fields. */
	return (seen & 0x3fU) == 0x3fU && markers == 7;
}

#endif
