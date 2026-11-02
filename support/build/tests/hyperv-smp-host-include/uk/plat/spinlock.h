#include <uk/arch/spinlock.h>
#define ukplat_spin_lock_irqsave(lock, flags) \
	do { (flags) = 0; ukarch_spin_lock(lock); } while (0)
#define ukplat_spin_unlock_irqrestore(lock, flags) \
	do { (void)(flags); ukarch_spin_unlock(lock); } while (0)
