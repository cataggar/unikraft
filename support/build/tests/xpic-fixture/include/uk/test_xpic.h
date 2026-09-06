/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __UK_TEST_XPIC_H__
#define __UK_TEST_XPIC_H__

#include <stdint.h>

#define CONFIG_LIBUKINTCTLR_APIC 1
#define UK_ARCH_X86_64_CPUID1_ECX_X2APIC (1U << 21)
#define UK_ARCH_X86_64_APIC_MSR_BASE 0x01bU
#define UK_ARCH_X86_64_APIC_BASE_EN (1U << 11)
#define UK_ARCH_X86_64_APIC_BASE_EXTD (1U << 10)
#define UK_ARCH_X86_64_APIC_MSR_EOI 0x80bU
#define UK_ARCH_X86_64_APIC_MSR_SVR 0x80fU
#define UK_ARCH_X86_64_APIC_SVR_EN (1U << 8)

#define UK_EVENT_NOT_HANDLED 0
#define UK_EVENT_HANDLED 1
#define UK_LCPU_EXCEPT_EVENT_IRQ 0
#define UK_EVENT_HANDLER(event, handler) \
	int (*uk_test_irq_handler)(void *) = handler

#define __unused __attribute__((unused))
#define likely(value) __builtin_expect(!!(value), 1)
#define unlikely(value) __builtin_expect(!!(value), 0)

typedef uint32_t __u32;

struct uk_intctlr_irq {
	unsigned int id;
	unsigned int trigger;
};

struct uk_intctlr_driver_ops {
	int (*configure_irq)(struct uk_intctlr_irq *irq);
	int (*fdt_xlat)(const void *fdt, int nodeoffset, __u32 index,
			struct uk_intctlr_irq *irq);
	void (*mask_irq)(unsigned int irq);
	void (*unmask_irq)(unsigned int irq);
};

struct uk_intctlr_desc {
	char *name;
	struct uk_intctlr_driver_ops *ops;
};

struct uk_lcpu_except_irq_ctx {
	unsigned int irq;
};

void uk_arch_x86_64_cpuid(__u32 leaf, __u32 subleaf, __u32 *eax,
			 __u32 *ebx, __u32 *ecx, __u32 *edx);
void uk_arch_x86_64_rdmsr(__u32 msr, __u32 *eax, __u32 *edx);
void uk_arch_x86_64_wrmsr(__u32 msr, __u32 eax, __u32 edx);
void uk_intctlr_irq_handle(struct uk_lcpu_except_irq_ctx *ctx);
unsigned int
uk_lcpu_except_irq_ctx_get_irq(struct uk_lcpu_except_irq_ctx *ctx);
int uk_intctlr_register(struct uk_intctlr_desc *intctlr);

#endif /* __UK_TEST_XPIC_H__ */
