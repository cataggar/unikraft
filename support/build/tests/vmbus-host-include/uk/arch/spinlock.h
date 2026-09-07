#ifndef __UK_ARCH_SPINLOCK_H__
#define __UK_ARCH_SPINLOCK_H__
typedef struct { int value; } __spinlock;
static inline void ukarch_spin_init(__spinlock *lock) { lock->value = 0; }
static inline void ukarch_spin_lock(__spinlock *lock) { (void)lock; }
static inline void ukarch_spin_unlock(__spinlock *lock) { (void)lock; }
#define ukplat_spin_lock_irqsave(lock, flags) \
	do { (void)(lock); (flags) = 0; } while (0)
#define ukplat_spin_unlock_irqrestore(lock, flags) \
	do { (void)(lock); (void)(flags); } while (0)
#endif
