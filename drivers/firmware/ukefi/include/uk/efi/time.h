/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors. */
#ifndef __UK_EFI_TIME_H__
#define __UK_EFI_TIME_H__

#include <uk/arch/types.h>

#define UK_EFI_UNSPECIFIED_TIMEZONE 0x07ff
#define UK_EFI_TIME_ADJUST_DAYLIGHT 0x01
#define UK_EFI_TIME_IN_DAYLIGHT 0x02

struct uk_efi_time_caps {
	/* Reporting frequency, in counts per second, not nanoseconds. */
	__u32 resolution;
	/* Rate error in 1E-6 ppm (parts per trillion), not epoch accuracy. */
	__u32 accuracy;
	__bool sets_to_zero;
};

struct uk_efi_time {
	__u16 year;
	__u8 month;
	__u8 day;
	__u8 hour;
	__u8 minute;
	__u8 second;
	__u8 pad1;
	__u32 nanosecond;
	__s16 time_zone;
	__u8 daylight;
	__u8 pad2;
};

#endif /* __UK_EFI_TIME_H__ */
