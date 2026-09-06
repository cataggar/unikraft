/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __HYPERV_CLOCK_H__
#define __HYPERV_CLOCK_H__

#include <stdint.h>

#define HYPERV_REFERENCE_TICK_NS	100ULL

static inline uint64_t hyperv_reference_delta_ns(uint64_t current,
						 uint64_t baseline)
{
	uint64_t ticks = current - baseline;

	if (ticks > UINT64_MAX / HYPERV_REFERENCE_TICK_NS)
		return UINT64_MAX;
	return ticks * HYPERV_REFERENCE_TICK_NS;
}

static inline uint64_t hyperv_wall_time_ns(uint64_t epoch_ns,
					   uint64_t baseline,
					   uint64_t current)
{
	uint64_t elapsed_ns = hyperv_reference_delta_ns(current, baseline);

	if (elapsed_ns == UINT64_MAX || epoch_ns > UINT64_MAX - elapsed_ns)
		return UINT64_MAX;
	return epoch_ns + elapsed_ns;
}

#endif /* __HYPERV_CLOCK_H__ */
