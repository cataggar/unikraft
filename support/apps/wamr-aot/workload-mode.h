/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef WAMR_WORKLOAD_MODE_H
#define WAMR_WORKLOAD_MODE_H

#include <string.h>

static inline int wamr_workload_mode(unsigned int variant,
				    unsigned int configured, int argc,
				    char **argv, unsigned int *mode)
{
	if (argc < 1 || argc > 2 || !argv)
		return -1;
	if (variant == 2) {
		if (configured != 1 && configured != 2)
			return -1;
		if (argc == 2 && (!argv[1] || strcmp(argv[1],
		    configured == 1 ? "correctness-fast" : "correctness-full")))
			return -1;
		*mode = configured;
		return 0;
	}
	if ((variant != 1 && variant != 3) || configured ||
	    (argc == 2 && (!argv[1] || strcmp(argv[1], "correctness"))))
		return -1;
	*mode = 0;
	return 0;
}
#endif
