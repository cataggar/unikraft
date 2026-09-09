#pragma once
#include <uk/boot/smp.h>
struct uk_lcpu { unsigned int idx; };
struct uk_lcpu *uk_lcpu_get_current(void);
int uk_lcpu_current_is_bsp(void);
int uk_lcpu_init(struct uk_lcpu *);
void uk_lcpu_tlsp_set(uintptr_t);
void uk_lcpu_set_auxsp(uintptr_t);
void uk_lcpu_startup_idle(void);
void uk_lcpu_enable_irq(void);
void __noreturn uk_lcpu_halt_error(int);
