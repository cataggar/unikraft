/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __STORVSC_HOST_TYPES_H__
#define __STORVSC_HOST_TYPES_H__
#include <stddef.h>
#include <stdint.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t __s8;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;
typedef size_t __sz;
typedef intptr_t __ssz;
typedef uintptr_t __uptr;
typedef uintptr_t __vaddr_t;
typedef uint64_t __paddr_t;
typedef uint64_t __nsec;
#define __unused __attribute__((unused))
#define __align(x) __attribute__((aligned(x)))
#endif
