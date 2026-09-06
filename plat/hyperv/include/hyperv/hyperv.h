/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __HYPERV_H__
#define __HYPERV_H__

#include <uk/arch/types.h>

#define HYPERV_PAGE_SIZE			4096U
#define HYPERV_MESSAGE_SIZE			256U
#define HYPERV_MESSAGE_PAYLOAD_SIZE		240U
#define HYPERV_MESSAGE_TIMER_EXPIRED		0x80000010U
#define HYPERV_MESSAGE_SINT			2U
#define HYPERV_TIMER_SINT			4U

enum hyperv_detect_result {
	HYPERV_DETECT_OK = 0,
	HYPERV_DETECT_NO_HYPERVISOR = 1,
	HYPERV_DETECT_LEAF_RANGE = 2,
	HYPERV_DETECT_VENDOR = 3,
	HYPERV_DETECT_INTERFACE = 4,
	HYPERV_DETECT_HYPERCALL_PRIVILEGE = 5,
	HYPERV_DETECT_TIME_REF_PRIVILEGE = 6,
	HYPERV_DETECT_SYNIC_PRIVILEGE = 7,
	HYPERV_DETECT_STIMER_PRIVILEGE = 8,
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

enum hyperv_synic_result {
	HYPERV_SYNIC_OK = 0,
	HYPERV_SYNIC_BAD_PAGE = 1,
	HYPERV_SYNIC_BAD_VECTOR = 2,
	HYPERV_SYNIC_MISSING_PRIVILEGE = 3,
	HYPERV_SYNIC_MSR_REJECTED = 4,
};

enum hyperv_message_result {
	HYPERV_MESSAGE_EMPTY = 0,
	HYPERV_MESSAGE_READY = 1,
	HYPERV_MESSAGE_INVALID_SINT = -1,
	HYPERV_MESSAGE_INVALID_PAYLOAD = -2,
};

struct hyperv_message {
	__u32 message_type;
	__u8 payload_size;
	__u8 flags;
	__u16 reserved;
	__u64 sender;
	__u8 payload[HYPERV_MESSAGE_PAYLOAD_SIZE];
};

void *hyperv_hypercall_page(void);
void *hyperv_simp_page(void);
void *hyperv_siefp_page(void);
void *hyperv_reference_tsc_page(void);
__u64 hyperv_guest_id_encode(__u16 build, __u32 version, __u8 os_id,
			     __u8 os_type, __u8 open_source);
int hyperv_runtime_detect(void);
int hyperv_runtime_enable(__u64 page_gpa, __u64 guest_id);
void hyperv_runtime_disable(void);
int hyperv_synic_enable(__u64 simp_gpa, __u64 siefp_gpa,
			__u64 reference_tsc_gpa, __u8 message_vector,
			__u8 timer_vector);
void hyperv_synic_disable(void);
__u64 hyperv_hypercall(__u64 control, __u64 input_gpa, __u64 output_gpa);
__u16 hyperv_status_code(__u64 result);
__u16 hyperv_status_kind(__u64 result);
__u64 hyperv_msr_read(__u32 msr);
void hyperv_msr_write(__u32 msr, __u64 value);
__u64 hyperv_time_ref_count(void);
__u64 hyperv_reference_time(void);
int hyperv_x86_irq_to_vector(__u32 irq, __u8 *vector);
__u64 hyperv_deadline_reference_ticks(__u64 boot_reference,
				      __u64 deadline_ns);
void hyperv_stimer0_arm(__u64 deadline);
void hyperv_stimer0_cancel(void);
int hyperv_synic_message_take(__u32 sint, struct hyperv_message *message);
int hyperv_synic_event_take_word(__u32 sint, __u32 word, __u64 *value);
void hyperv_clock_set_efi_sample(__u64 epoch_ns, __u64 reference_time);

void hyperv_vmbus_message(const struct hyperv_message *message);
void hyperv_vmbus_event(__u32 event);

_Static_assert(HYPERV_PAGE_SIZE == 4096U, "Hyper-V pages are 4 KiB");
_Static_assert(sizeof(struct hyperv_message) == HYPERV_MESSAGE_SIZE,
	       "Hyper-V message ABI is 256 bytes");

#endif /* __HYPERV_H__ */
