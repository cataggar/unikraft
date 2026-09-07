/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __STORVSC_HOST_SPINLOCK_H__
#define __STORVSC_HOST_SPINLOCK_H__
#include <pthread.h>
typedef pthread_mutex_t __spinlock;
static inline void ukarch_spin_init(__spinlock *lock)
{
	pthread_mutex_init(lock, NULL);
}
#define ukplat_spin_lock_irqsave(lock, flags) \
	do { (void)(flags); pthread_mutex_lock((lock)); } while (0)
#define ukplat_spin_unlock_irqrestore(lock, flags) \
	do { (void)(flags); pthread_mutex_unlock((lock)); } while (0)
#endif
