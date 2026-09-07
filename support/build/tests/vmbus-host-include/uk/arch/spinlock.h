#ifndef __UK_ARCH_SPINLOCK_H__
#define __UK_ARCH_SPINLOCK_H__
#include <pthread.h>
typedef pthread_mutex_t __spinlock;
static inline void ukarch_spin_init(__spinlock *lock)
{
	(void)pthread_mutex_init(lock, NULL);
}
static inline void ukarch_spin_lock(__spinlock *lock)
{
	(void)pthread_mutex_lock(lock);
}
static inline void ukarch_spin_unlock(__spinlock *lock)
{
	(void)pthread_mutex_unlock(lock);
}
#define ukplat_spin_lock_irqsave(lock, flags) \
	do { (flags) = 0; ukarch_spin_lock(lock); } while (0)
#define ukplat_spin_unlock_irqrestore(lock, flags) \
	do { (void)(flags); ukarch_spin_unlock(lock); } while (0)
#endif
