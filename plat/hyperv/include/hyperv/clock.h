/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __HYPERV_CLOCK_H__
#define __HYPERV_CLOCK_H__

#include <stdint.h>
#include <errno.h>

#define HYPERV_REFERENCE_TICK_NS	100ULL
#define HYPERV_REALTIME_ABI_VERSION 1U
#define HYPERV_REALTIME_EFI_UTC 1U

/* Separate capability ABI; neither bootinfo v1 nor ukplat_wall_clock changes.
 * All timestamps/resolutions are ns. The EFI rate error is NOT a bound on
 * absolute UTC error. No absolute epoch accuracy is asserted by this API.
 */
struct hyperv_realtime_caps {
	uint32_t version;
	uint32_t source;
	uint64_t resolution_ns;
	uint32_t efi_accuracy_pptrillion;
	uint32_t reserved;
	uint64_t sample_span_ns;
};

/* Kernel-owned, pre-ExitBootServices handoff, not a serialized boot record. */
struct hyperv_realtime_sample {
	struct hyperv_realtime_caps caps;
	uint64_t epoch_ns;
	uint64_t reference_ticks;
};

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

static inline int
hyperv_realtime_read(const struct hyperv_realtime_sample *sample,
		    uint64_t current, struct hyperv_realtime_caps *caps,
		    uint64_t *ns)
{
	uint64_t value;

	if (sample->caps.version != HYPERV_REALTIME_ABI_VERSION ||
	    sample->caps.source != HYPERV_REALTIME_EFI_UTC ||
	    sample->caps.resolution_ns < HYPERV_REFERENCE_TICK_NS ||
	    sample->caps.reserved ||
	    !sample->caps.efi_accuracy_pptrillion ||
	    sample->caps.efi_accuracy_pptrillion == UINT32_MAX)
		return -ENOTSUP;
	if (!sample->epoch_ns || sample->epoch_ns == UINT64_MAX ||
	    sample->caps.resolution_ns == UINT64_MAX ||
	    sample->caps.sample_span_ns == UINT64_MAX ||
	    sample->reference_ticks == UINT64_MAX ||
	    current == UINT64_MAX || current < sample->reference_ticks)
		return -EOVERFLOW;
	value = hyperv_wall_time_ns(sample->epoch_ns, sample->reference_ticks,
				   current);
	if (value == UINT64_MAX)
		return -EOVERFLOW;
	*caps = sample->caps;
	*ns = value;
	return 0;
}

/* Called only by the EFI pre-exit hook, after validating the actual sample. */
void hyperv_clock_set_realtime_sample(
	const struct hyperv_realtime_sample *sample);

/* 0: both outputs valid; -ENOTSUP: no qualified source; -EOVERFLOW: bad ticks
 * or saturated time. Neither output is modified on error. No firmware calls.
 */
int hyperv_clock_realtime(struct hyperv_realtime_caps *caps, uint64_t *ns);

#endif /* __HYPERV_CLOCK_H__ */
