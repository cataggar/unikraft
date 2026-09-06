/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <stdint.h>

#include <hyperv/clock.h>
#include <uk/plat/common/efi_runtime.h>

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

int main(void)
{
	test_efi_runtime_permissions();
	test_paired_wall_clock_baseline();
	return 0;
}
