#pragma once

struct uk_sched_wake_host_lock {
	int held;
};

typedef struct uk_sched_wake_host_lock __spinlock;

void uksched_wake_host_lock(__spinlock *lock);
void uksched_wake_host_unlock(__spinlock *lock);

#define ukplat_spin_lock_irqsave(lock, flags) do {	\
	(flags) = 0;					\
	uksched_wake_host_lock(lock);			\
} while (0)

#define ukplat_spin_unlock_irqrestore(lock, flags) do {	\
	(void)(flags);					\
	uksched_wake_host_unlock(lock);			\
} while (0)
