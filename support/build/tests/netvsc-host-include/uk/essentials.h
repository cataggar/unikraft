#ifndef __UK_ESSENTIALS_H__
#define __UK_ESSENTIALS_H__
#include <stddef.h>
#include <stdint.h>
#define __containerof(pointer, type, member) \
	((type *)((char *)(pointer) - offsetof(type, member)))
#define ERR2PTR(error) ((void *)(intptr_t)(error))
#define PTR2ERR(pointer) ((int)(intptr_t)(pointer))
#define PTRISERR(pointer) ((uintptr_t)(pointer) >= (uintptr_t)-4095)
#endif
