#define uk_and_relax(ptr, value) __atomic_exchange_n((ptr), (value), \
						      __ATOMIC_ACQ_REL)
