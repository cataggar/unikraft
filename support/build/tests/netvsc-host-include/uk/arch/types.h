#ifndef __UK_ARCH_TYPES_H__
#define __UK_ARCH_TYPES_H__
#include <stddef.h>
#include <stdint.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int16_t __s16;
typedef int32_t __s32;
typedef uintptr_t __vaddr_t;
typedef uintptr_t __paddr_t;
#define __unused __attribute__((unused))
#define __align(x) __attribute__((aligned(x)))
#endif
