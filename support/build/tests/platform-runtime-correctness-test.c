/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <stdint.h>

#include <hyperv/clock.h>
#include <hyperv/cpu_lifecycle.h>
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
	test_hyperv_cpu_lifecycle();
	return 0;
}
