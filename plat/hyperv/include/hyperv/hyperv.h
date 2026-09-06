/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __HYPERV_H__
#define __HYPERV_H__

#include <uk/arch/types.h>

#define HYPERV_PAGE_SIZE			4096U

enum hyperv_detect_result {
	HYPERV_DETECT_OK = 0,
	HYPERV_DETECT_NO_HYPERVISOR = 1,
	HYPERV_DETECT_LEAF_RANGE = 2,
	HYPERV_DETECT_VENDOR = 3,
	HYPERV_DETECT_INTERFACE = 4,
	HYPERV_DETECT_HYPERCALL_PRIVILEGE = 5,
	HYPERV_DETECT_TIME_REF_PRIVILEGE = 6,
};

enum hyperv_enable_result {
	HYPERV_ENABLE_OK = 0,
	HYPERV_ENABLE_BAD_PAGE = 1,
	HYPERV_ENABLE_MSR_REJECTED = 2,
};

enum hyperv_status_kind {
	HYPERV_STATUS_KNOWN_SUCCESS = 0,
	HYPERV_STATUS_KNOWN_INVALID_HYPERCALL_CODE = 1,
	HYPERV_STATUS_KNOWN_INVALID_HYPERCALL_INPUT = 2,
	HYPERV_STATUS_KNOWN_INVALID_ALIGNMENT = 3,
	HYPERV_STATUS_KNOWN_INVALID_PARAMETER = 4,
	HYPERV_STATUS_KNOWN_ACCESS_DENIED = 5,
	HYPERV_STATUS_KNOWN_OPERATION_DENIED = 6,
	HYPERV_STATUS_UNKNOWN = 0xffff,
};

void *hyperv_hypercall_page(void);
__u64 hyperv_guest_id_encode(__u16 build, __u32 version, __u8 os_id,
			     __u8 os_type, __u8 open_source);
int hyperv_runtime_detect(void);
int hyperv_runtime_enable(__u64 page_gpa, __u64 guest_id);
void hyperv_runtime_disable(void);
__u64 hyperv_hypercall(__u64 control, __u64 input_gpa, __u64 output_gpa);
__u16 hyperv_status_code(__u64 result);
__u16 hyperv_status_kind(__u64 result);
__u64 hyperv_msr_read(__u32 msr);
void hyperv_msr_write(__u32 msr, __u64 value);
__u64 hyperv_time_ref_count(void);
void hyperv_clock_set_efi_sample(__u64 epoch_ns, __u64 reference_time);

_Static_assert(HYPERV_PAGE_SIZE == 4096U, "Hyper-V pages are 4 KiB");

#endif /* __HYPERV_H__ */
