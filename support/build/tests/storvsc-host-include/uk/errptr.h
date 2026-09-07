/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __STORVSC_HOST_ERRPTR_H__
#define __STORVSC_HOST_ERRPTR_H__
#include <stdint.h>
#define ERR2PTR(error) ((void *)(intptr_t)(error))
#define PTR2ERR(pointer) ((int)(intptr_t)(pointer))
#define PTRISERR(pointer) ((uintptr_t)(pointer) >= (uintptr_t)-4095)
#endif
