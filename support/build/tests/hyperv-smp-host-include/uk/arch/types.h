#ifndef __HOST_UK_ARCH_TYPES_H__
#define __HOST_UK_ARCH_TYPES_H__
#include <stdint.h>
#include <stddef.h>
#define __u8 uint8_t
#define __u16 uint16_t
#define __u32 uint32_t
#define __u64 uint64_t
#define __s64 int64_t
#define __paddr_t uintptr_t
#define __vaddr_t uintptr_t
#define __nsec uint64_t
#define __snsec int64_t
#define __align(x) __attribute__((aligned(x)))
#define __unused __attribute__((unused))
#define __weak __attribute__((weak))
#define __noreturn __attribute__((noreturn))
#endif
