/* SPDX-License-Identifier: BSD-3-Clause */
#include "../workload-mode.h"

int check_mode(unsigned int variant, unsigned int configured, int argc,
	       char **argv, unsigned int *mode)
{
	return wamr_workload_mode(variant, configured, argc, argv, mode);
}
