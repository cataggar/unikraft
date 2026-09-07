#include <uk/arch/types.h>
typedef int (*uk_intctlr_handler_t)(void *);
static inline int uk_intctlr_time_pending_register(void (*hook)(void))
{
	(void)hook;
	return 0;
}
static inline int uk_intctlr_irq_alloc(unsigned int *irqs, unsigned int count)
{
	for (unsigned int i = 0; i < count; i++)
		irqs[i] = i + 1;
	return 0;
}
static inline void uk_intctlr_irq_free(unsigned int *irqs __unused,
				       unsigned int count __unused) {}
static inline int uk_intctlr_irq_register(unsigned int irq __unused,
					   uk_intctlr_handler_t handler __unused,
					   void *arg __unused) { return 0; }
static inline void uk_intctlr_irq_unregister(
	unsigned int irq __unused, uk_intctlr_handler_t handler __unused) {}
