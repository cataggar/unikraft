/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __HYPERV_EFI_CLOCK_H__
#define __HYPERV_EFI_CLOCK_H__

#include <hyperv/clock.h>
#include <uk/efi/time.h>
#include <uk/timeconv.h>

/* Strict opt-in subset: firmware explicitly declares UTC with no daylight
 * adjustment. In particular, unspecified timezone is never treated as UTC.
 * Non-UTC/DST sources need a separately justified conversion policy.
 */
static inline int
hyperv_efi_realtime_sample(const struct uk_efi_time *now,
			  const struct uk_efi_time_caps *caps,
			  uint64_t before, uint64_t after,
			  struct hyperv_realtime_sample *sample)
{
	struct uktimeconv_bmkclock start = { 0 };
	uint64_t epoch, offset, days, resolution, span;
	unsigned int month;

	if (now->time_zone != 0 || now->daylight != 0)
		return -ENOTSUP;
	if (now->year < 1970 || now->year > 2554 ||
	    now->month < 1 || now->month > 12 || now->day < 1 ||
	    now->day > uktimeconv_days_in_month(
		    now->month, uktimeconv_is_leap_year(now->year)) ||
	    now->hour > 23 || now->minute > 59 || now->second > 59 ||
	    now->nanosecond >= 1000000000U)
		return -EINVAL;
	/* Zero/unwritten or sentinel capability values cannot qualify a source.
	 * SetsToZero describes SetTime, not GetTime subsecond or epoch accuracy.
	 */
	if (!caps->resolution || caps->resolution == UINT32_MAX ||
	    !caps->accuracy || caps->accuracy == UINT32_MAX ||
	    *(const unsigned char *)&caps->sets_to_zero > 1)
		return -ENOTSUP;
	if (before == UINT64_MAX || after == UINT64_MAX || after < before)
		return -EOVERFLOW;
	span = hyperv_reference_delta_ns(after, before);
	if (span == UINT64_MAX)
		return -EOVERFLOW;

	/* January 1 fits through 2554. Add the checked remainder separately:
	 * the existing whole-calendar converter otherwise wraps in July 2554.
	 */
	start.dt_year = now->year;
	start.dt_mon = 1;
	start.dt_day = 1;
	epoch = uktimeconv_bmkclock_to_nsec(&start);
	days = now->day - 1;
	for (month = 1; month < now->month; month++)
		days += uktimeconv_days_in_month(
			month, uktimeconv_is_leap_year(now->year));
	offset = ((days * 24 + now->hour) * 3600 +
		  now->minute * 60 + now->second) * 1000000000ULL +
		  now->nanosecond;
	if (epoch >= UINT64_MAX - offset || !(epoch + offset))
		return -EOVERFLOW;
	resolution = (1000000000ULL + caps->resolution - 1) / caps->resolution;
	if (resolution < HYPERV_REFERENCE_TICK_NS)
		resolution = HYPERV_REFERENCE_TICK_NS;
	*sample = (struct hyperv_realtime_sample) {
		.caps = {
			.version = HYPERV_REALTIME_ABI_VERSION,
			.source = HYPERV_REALTIME_EFI_UTC,
			.resolution_ns = resolution,
			.efi_accuracy_pptrillion = caps->accuracy,
			.sample_span_ns = span,
		},
		.epoch_ns = epoch + offset,
		.reference_ticks = after,
	};
	return 0;
}

#endif /* __HYPERV_EFI_CLOCK_H__ */
