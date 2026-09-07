#ifndef __HOST_UK_ARCH_SPINLOCK_H__
#define __HOST_UK_ARCH_SPINLOCK_H__
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
#endif
