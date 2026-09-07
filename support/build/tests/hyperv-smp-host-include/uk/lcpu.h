#include <uk/arch/types.h>
struct uk_lcpu_regs;
struct uk_lcpu_func {
	void (*fn)(struct uk_lcpu_regs *, void *);
	void *user;
};
#define UK_LCPU_RFLG_DONOTBLOCK 1
extern _Thread_local __u64 hyperv_host_cpu_index;
static inline int uk_lcpu_current_is_bsp(void)
{
	return hyperv_host_cpu_index == 0;
}
static inline __u64 uk_lcpu_get_current_idx_in_except(void)
{
	return hyperv_host_cpu_index;
}
static inline int uk_lcpu_irqs_disabled(void) { return 1; }
void uk_lcpu_halt_irq(void);
void __attribute__((noreturn)) uk_lcpu_halt(void);
int uk_lcpu_run(const __u64 *, unsigned int *, const struct uk_lcpu_func *,
		 unsigned long);
int uk_lcpu_wait(const __u64 *, unsigned int *, __nsec);
