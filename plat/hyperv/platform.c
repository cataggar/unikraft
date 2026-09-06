/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <hyperv/hyperv.h>
#include <uk/efi.h>
#include <uk/paging.h>
#include <uk/plat/common/bootinfo.h>
#include <uk/pm.h>
#include <uk/print.h>
#include <uk/timeconv.h>

#define HYPERV_SMOKE_INVALID_CALL	0xffffULL
#define HYPERV_UNIKRAFT_VERSION		0x00150000U
#define HYPERV_EFI_UNSPECIFIED_TZ	0x07ff
#define HYPERV_NS_PER_MINUTE		60000000000LL

static struct uk_efi_runtime_services *hyperv_efi_rs;

static const char *hyperv_detect_error(int rc)
{
	switch (rc) {
	case HYPERV_DETECT_NO_HYPERVISOR:
		return "CPUID.1:ECX hypervisor-present bit is clear";
	case HYPERV_DETECT_LEAF_RANGE:
		return "maximum Hyper-V CPUID leaf is below 0x40000005";
	case HYPERV_DETECT_VENDOR:
		return "CPUID vendor is not Microsoft Hv";
	case HYPERV_DETECT_INTERFACE:
		return "CPUID interface is not Hv#1";
	case HYPERV_DETECT_HYPERCALL_PRIVILEGE:
		return "AccessHypercallMsrs privilege is absent";
	case HYPERV_DETECT_TIME_REF_PRIVILEGE:
		return "AccessPartitionReferenceCounter privilege is absent";
	case HYPERV_DETECT_SYNIC_PRIVILEGE:
		return "AccessSynicRegs privilege is absent";
	case HYPERV_DETECT_STIMER_PRIVILEGE:
		return "AccessSyntheticTimerRegs privilege is absent";
	default:
		return "unknown discovery failure";
	}
}

void ukplat_efi_pre_exit(struct uk_efi_runtime_services *rs)
{
	struct uktimeconv_bmkclock date;
	struct uk_efi_time now;
	uk_efi_status_t status;
	__u64 reference_time;
	__u64 epoch_ns;
	__s64 utc_ns;
	int rc;

	rc = hyperv_runtime_detect();
	if (unlikely(rc != HYPERV_DETECT_OK))
		UK_CRASH("Hyper-V discovery failed before ExitBootServices: %s\n",
			 hyperv_detect_error(rc));

	status = rs->get_time(&now, NULL);
	if (unlikely(status != UK_EFI_SUCCESS))
		UK_CRASH("Hyper-V: UEFI GetTime failed: 0x%lx\n", status);
	reference_time = hyperv_time_ref_count();
	if (unlikely(now.year < 1970 || now.month < 1 || now.month > 12 ||
		     now.day < 1 || now.day > 31 || now.hour > 23 ||
		     now.minute > 59 || now.second > 59 ||
		     now.nanosecond >= 1000000000U))
		UK_CRASH("Hyper-V: UEFI returned an invalid wall clock\n");

	date.dt_year = now.year;
	date.dt_mon = now.month;
	date.dt_day = now.day;
	date.dt_hour = now.hour;
	date.dt_min = now.minute;
	date.dt_sec = now.second;
	epoch_ns = uktimeconv_bmkclock_to_nsec(&date) + now.nanosecond;
	utc_ns = (__s64)epoch_ns;
	if (now.time_zone != HYPERV_EFI_UNSPECIFIED_TZ) {
		if (unlikely(now.time_zone < -1440 || now.time_zone > 1440))
			UK_CRASH("Hyper-V: UEFI returned an invalid timezone\n");
		utc_ns -= (__s64)now.time_zone * HYPERV_NS_PER_MINUTE;
	}
	if (unlikely(utc_ns < 0))
		UK_CRASH("Hyper-V: UEFI wall clock predates the Unix epoch\n");
	hyperv_clock_set_efi_sample((__u64)utc_ns, reference_time);
	hyperv_efi_rs = rs;
}

static int hyperv_shutdown(enum uk_efi_reset_type type)
{
	hyperv_runtime_disable();
	if (unlikely(!hyperv_efi_rs))
		return -ENODEV;
	hyperv_efi_rs->reset_system(type, UK_EFI_SUCCESS, 0, NULL);
	return -EIO;
}

static int hyperv_halt(void)
{
	return hyperv_shutdown(UK_EFI_RESET_SHUTDOWN);
}

static int hyperv_restart(void)
{
	return hyperv_shutdown(UK_EFI_RESET_COLD);
}

static int hyperv_crash(void)
{
	return hyperv_shutdown(UK_EFI_RESET_SHUTDOWN);
}

static const struct uk_pm_ops hyperv_pm_ops = {
	.syshalt = hyperv_halt,
	.sysrestart = hyperv_restart,
	.syscrash = hyperv_crash,
};

int ukplat_x86_platform_init(void)
{
	void *page = hyperv_hypercall_page();
	__paddr_t page_gpa;
	__u64 guest_id;
	__u64 result;
	int rc;

	rc = hyperv_runtime_detect();
	if (unlikely(rc != HYPERV_DETECT_OK)) {
		uk_pr_err("Hyper-V discovery failed: %s\n",
			  hyperv_detect_error(rc));
		return -ENODEV;
	}

	page_gpa = uk_paging_virt_to_phys((__vaddr_t)page);
	if (unlikely(page_gpa == UK_PAGING_PADDR_INV ||
		     (page_gpa & (HYPERV_PAGE_SIZE - 1)))) {
		uk_pr_err("Hyper-V hypercall page has invalid GPA 0x%lx\n",
			  page_gpa);
		return -EINVAL;
	}

	/*
	 * TLFS Guest OS ID: open-source bit set, unregistered OS type/ID,
	 * Unikraft 0.21.0 encoded in the 32-bit version field.
	 */
	guest_id = hyperv_guest_id_encode(0, HYPERV_UNIKRAFT_VERSION, 0, 0, 1);
	rc = hyperv_runtime_enable(page_gpa, guest_id);
	if (unlikely(rc != HYPERV_ENABLE_OK)) {
		uk_pr_err("Hyper-V hypercall MSR rejected GPA 0x%lx (rc=%d)\n",
			  page_gpa, rc);
		return -EIO;
	}

	result = hyperv_hypercall(HYPERV_SMOKE_INVALID_CALL, 0, 0);
	if (unlikely(hyperv_status_kind(result) !=
		     HYPERV_STATUS_KNOWN_INVALID_HYPERCALL_CODE)) {
		uk_pr_err("Hyper-V hypercall smoke returned status 0x%x\n",
			  hyperv_status_code(result));
		hyperv_runtime_disable();
		return -EIO;
	}

	rc = uk_pm_ops_register(&hyperv_pm_ops);
	if (unlikely(rc)) {
		hyperv_runtime_disable();
		return rc;
	}

	uk_pr_info("Hyper-V Hv#1 hypercall page enabled at GPA 0x%lx\n",
		   page_gpa);
	return 0;
}
