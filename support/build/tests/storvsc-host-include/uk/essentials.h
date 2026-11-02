/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __STORVSC_HOST_ESSENTIALS_H__
#define __STORVSC_HOST_ESSENTIALS_H__
#include <stddef.h>
#define __containerof(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#ifdef __cplusplus
#define UK_CTASSERT(x) static_assert((x), #x)
#else
#define UK_CTASSERT(x) _Static_assert((x), #x)
#endif
#endif
