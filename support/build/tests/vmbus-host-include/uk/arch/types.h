#ifndef __UK_ARCH_TYPES_H__
#define __UK_ARCH_TYPES_H__
#include <stdint.h>
#include <stddef.h>
#define __u8 uint8_t
#define __u16 uint16_t
#define __u32 uint32_t
#define __u64 uint64_t
#define __vaddr_t uintptr_t
#define __paddr_t uintptr_t
#define __nsec unsigned long long
#define __align(x) __attribute__((aligned(x)))
#define __unused __attribute__((unused))
#define __noreturn __attribute__((noreturn))
#endif
