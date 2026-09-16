/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <hyperv/clock.h>
#include <hyperv/efi_clock.h>
#include <hyperv/cpu_lifecycle.h>
#include <uk/plat/common/efi_runtime.h>

_Static_assert(sizeof(struct uk_efi_time) == 16, "EFI_TIME ABI");
_Static_assert(offsetof(struct uk_efi_time, time_zone) == 12, "EFI timezone ABI");
_Static_assert(sizeof(struct uk_efi_time_caps) == 12, "EFI capabilities ABI");
_Static_assert(offsetof(struct uk_efi_time_caps, sets_to_zero) == 8,
	       "EFI boolean ABI");
_Static_assert(sizeof(struct hyperv_realtime_caps) == 32, "Realtime ABI");
_Static_assert(offsetof(struct hyperv_realtime_caps, sample_span_ns) == 24,
	       "Realtime ABI fields");

static void test_qualified_efi_realtime(void)
{
	const struct uk_efi_time utc = {
		.year = 2024, .month = 2, .day = 29, .hour = 12, .minute = 34,
		.second = 56, .nanosecond = 123456789,
	};
	const struct uk_efi_time_caps caps = {
		.resolution = 10000000, .accuracy = 50000000,
	};
	struct hyperv_realtime_sample sample = { 0 }, saved;
	struct hyperv_realtime_caps result;
	struct uk_efi_time now;
	struct uk_efi_time_caps bad_caps;
	uint64_t ns = 123;
	unsigned int i;
	const int16_t zones[] = { -1441, -1440, -60, 60, 1440, 1441,
				 UK_EFI_UNSPECIFIED_TIMEZONE, INT16_MAX };
	const uint8_t daylight[] = { UK_EFI_TIME_ADJUST_DAYLIGHT,
				    UK_EFI_TIME_IN_DAYLIGHT, 3, 4, 255 };

	assert(hyperv_realtime_read(&sample, 100, &result, &ns) == -ENOTSUP);
	assert(ns == 123);
	assert(hyperv_efi_realtime_sample(&utc, &caps, 100, 105, &sample) == 0);
	assert(sample.epoch_ns == 1709210096123456789ULL);
	assert(sample.reference_ticks == 105);
	assert(sample.caps.version == HYPERV_REALTIME_ABI_VERSION);
	assert(sample.caps.source == HYPERV_REALTIME_EFI_UTC);
	assert(sample.caps.sample_span_ns == 500);
	assert(sample.caps.resolution_ns == 100);
	assert(sample.caps.efi_accuracy_pptrillion == 50000000);
	assert(hyperv_realtime_read(&sample, 110, &result, &ns) == 0);
	assert(ns == sample.epoch_ns + 500);
	assert(!memcmp(&result, &sample.caps, sizeof(result)));
	saved = sample;

#define BAD_TIME(field, value) do {					\
	now = utc;							\
	now.field = (value);						\
	assert(hyperv_efi_realtime_sample(&now, &caps, 100, 105,		\
					  &sample) != 0);		\
	assert(!memcmp(&saved, &sample, sizeof(sample)));		\
} while (0)
	BAD_TIME(year, 1969);
	BAD_TIME(year, 9999);
	BAD_TIME(year, 2100);
	BAD_TIME(month, 0);
	BAD_TIME(month, 13);
	BAD_TIME(day, 0);
	BAD_TIME(day, 30);
	BAD_TIME(hour, 24);
	BAD_TIME(minute, 60);
	BAD_TIME(second, 60);
	BAD_TIME(nanosecond, 1000000000U);
	for (i = 0; i < sizeof(zones) / sizeof(zones[0]); i++)
		BAD_TIME(time_zone, zones[i]);
	for (i = 0; i < sizeof(daylight) / sizeof(daylight[0]); i++)
		BAD_TIME(daylight, daylight[i]);
#undef BAD_TIME
	now = utc;
	now.month = 4;
	now.day = 31;
	assert(hyperv_efi_realtime_sample(&now, &caps, 100, 105, &sample) ==
	       -EINVAL);
	now = utc;
	now.year = 2000;
	assert(hyperv_efi_realtime_sample(&now, &caps, 100, 105, &sample) == 0);
	assert(sample.epoch_ns == 951827696123456789ULL);
	for (i = 0; i < 4; i++) {
		bad_caps = caps;
		if (i < 2)
			bad_caps.resolution = i ? UINT32_MAX : 0;
		else
			bad_caps.accuracy = i == 2 ? 0 : UINT32_MAX;
		assert(hyperv_efi_realtime_sample(&utc, &bad_caps, 100, 105,
						  &sample) == -ENOTSUP);
	}
	bad_caps = caps;
	*(unsigned char *)&bad_caps.sets_to_zero = 2;
	assert(hyperv_efi_realtime_sample(&utc, &bad_caps, 100, 105,
					  &sample) == -ENOTSUP);
	bad_caps = caps;
	bad_caps.resolution = 3;
	assert(hyperv_efi_realtime_sample(&utc, &bad_caps, 100, 105,
					  &sample) == 0);
	assert(sample.caps.resolution_ns == 333333334);
	bad_caps.resolution = 1;
	bad_caps.sets_to_zero = 1;
	assert(hyperv_efi_realtime_sample(&utc, &bad_caps, 100, 105,
					  &sample) == 0);
	assert(sample.caps.resolution_ns == 1000000000);
	assert(sample.epoch_ns == saved.epoch_ns);
	assert(hyperv_efi_realtime_sample(&utc, &caps, 105, 100, &sample) ==
	       -EOVERFLOW);
	assert(hyperv_efi_realtime_sample(&utc, &caps, UINT64_MAX,
					  UINT64_MAX, &sample) == -EOVERFLOW);
	assert(hyperv_efi_realtime_sample(&utc, &caps, 0,
			UINT64_MAX / 100 + 1, &sample) == -EOVERFLOW);
	now = (struct uk_efi_time) { .year = 1970, .month = 1, .day = 1 };
	assert(hyperv_efi_realtime_sample(&now, &caps, 100, 105, &sample) ==
	       -EOVERFLOW);
	now.nanosecond = 1;
	assert(hyperv_efi_realtime_sample(&now, &caps, 100, 105, &sample) == 0);
	assert(sample.epoch_ns == 1);
	now = (struct uk_efi_time) {
		.year = 2554, .month = 7, .day = 21, .hour = 23, .minute = 34,
		.second = 33, .nanosecond = 709551614,
	};
	assert(hyperv_efi_realtime_sample(&now, &caps, 100, 105, &sample) == 0);
	assert(sample.epoch_ns == UINT64_MAX - 1);
	assert(hyperv_realtime_read(&sample, 105, &result, &ns) == 0);
	assert(ns == UINT64_MAX - 1);
	assert(hyperv_realtime_read(&sample, 106, &result, &ns) == -EOVERFLOW);
	now.nanosecond++;
	assert(hyperv_efi_realtime_sample(&now, &caps, 100, 105, &sample) ==
	       -EOVERFLOW);
	now.second++;
	assert(hyperv_efi_realtime_sample(&now, &caps, 100, 105, &sample) ==
	       -EOVERFLOW);
	assert(hyperv_realtime_read(&saved, UINT64_MAX, &result, &ns) ==
	       -EOVERFLOW);
	assert(hyperv_realtime_read(&saved, 104, &result, &ns) == -EOVERFLOW);
	assert(hyperv_realtime_read(&saved, UINT64_MAX / 100 + 106,
				   &result, &ns) == -EOVERFLOW);
}

static void test_efi_runtime_permissions(void)
{
	unsigned int flags = 0;

	assert(uk_efi_runtime_mrd_flags(UK_EFI_RUNTIME_TYPE_CODE, 0, &flags) ==
	       UK_EFI_RUNTIME_MRD_APPLY);
	assert(flags == (UK_EFI_RUNTIME_MEMRF_READ |
			 UK_EFI_RUNTIME_MEMRF_EXECUTE));

	flags = 0;
	assert(uk_efi_runtime_mrd_flags(UK_EFI_RUNTIME_TYPE_DATA, 0, &flags) ==
	       UK_EFI_RUNTIME_MRD_APPLY);
	assert(flags == (UK_EFI_RUNTIME_MEMRF_READ |
			 UK_EFI_RUNTIME_MEMRF_WRITE));

	flags = 0xdead;
	assert(uk_efi_runtime_mrd_flags(UK_EFI_RUNTIME_TYPE_CODE, 1, &flags) ==
	       UK_EFI_RUNTIME_MRD_SKIP);
	assert(flags == 0xdead);
	assert(uk_efi_runtime_mrd_flags(UK_EFI_RUNTIME_TYPE_DATA, 1, &flags) ==
	       UK_EFI_RUNTIME_MRD_SKIP);
	assert(uk_efi_runtime_mrd_flags(0, 0, &flags) ==
	       UK_EFI_RUNTIME_MRD_NOT_RUNTIME);
}

static void test_paired_wall_clock_baseline(void)
{
	const uint64_t epoch_ns = 1700000000000000000ULL;
	const uint64_t efi_ref = 1000000;
	const uint64_t time_init_ref = efi_ref + 5000;

	assert(hyperv_wall_time_ns(epoch_ns, efi_ref, time_init_ref) ==
	       epoch_ns + 500000);
	assert(hyperv_reference_delta_ns(4, UINT64_MAX - 5) == 1000);
	assert(hyperv_reference_delta_ns(
		       0, UINT64_MAX / HYPERV_REFERENCE_TICK_NS) ==
	       UINT64_MAX);
	assert(hyperv_wall_time_ns(UINT64_MAX - 50, 10, 11) == UINT64_MAX);
}

static void test_hyperv_cpu_lifecycle(void)
{
	struct hyperv_cpu_state cpus[4] = { 0 };
	uint32_t generation = 0;

	assert(hyperv_cpu_state_reserve(cpus, 4, 0, 7, 64,
				       &generation) == 0);
	assert(cpus[0].state == HYPERV_CPU_INITIALIZING);
	assert(hyperv_cpu_state_online(cpus, 4, 0) == 0);
	assert(hyperv_cpu_state_reserve(cpus, 4, 0, 7, 64,
				       &generation) == 1);
	assert(hyperv_cpu_state_reserve(cpus, 4, 1, 7, 64,
				       &generation) == -EEXIST);
	assert(hyperv_cpu_state_reserve(cpus, 4, 1, 64, 64,
				       &generation) == -ERANGE);
	assert(hyperv_cpu_state_reserve(cpus, 4, 4, 8, 64,
				       &generation) == -ERANGE);
	assert(hyperv_cpu_state_reserve(cpus, 4, 1, 8, 64,
				       &generation) == 0);
	/* A failed local MSR/page setup rolls the reserved slot fully back. */
	hyperv_cpu_state_release(cpus, 4, 1);
	assert(cpus[1].state == HYPERV_CPU_OFFLINE);
	assert(cpus[1].vp_index == UINT32_MAX);
	generation = UINT32_MAX;
	assert(hyperv_cpu_state_reserve(cpus, 4, 1, 9, 64,
				       &generation) == -ENOSPC);
	hyperv_cpu_state_release(cpus, 4, 1);
	generation = 2;
	assert(hyperv_cpu_state_reserve(cpus, 4, 1, 0xffff, 0,
				       &generation) == 0);
}

int main(void)
{
	test_efi_runtime_permissions();
	test_paired_wall_clock_baseline();
	test_qualified_efi_realtime();
	test_hyperv_cpu_lifecycle();
	return 0;
}
