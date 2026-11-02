/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <errno.h>
#include <uk/arch/util.h>
#include <uk/arch/x86_64.h>
#include <uk/assert.h>
#include <uk/event.h>
#include <uk/config.h>
#include <uk/intctlr.h>
#include <uk/lcpu.h>
#include <uk/print.h>

#if CONFIG_LIBUKINTCTLR_XAPIC
#include <uk/paging.h>

#if CONFIG_HAVE_SMP
#error "Legacy xAPIC fallback does not support SMP"
#endif

#define XAPIC_VERSION		0x030
#define XAPIC_TPR		0x080
#define XAPIC_EOI		0x0b0
#define XAPIC_SVR		0x0f0
#define XAPIC_SPURIOUS_VECTOR	0xff

static __vaddr_t xapic_base;

static int xapic_map_uncached(struct uk_pagetable *pt __unused,
			     __vaddr_t vaddr, __vaddr_t pt_vaddr __unused,
			     unsigned int level, __pte_t *pte,
			     void *ctx __unused)
{
	if (level != UK_PAGING_PAGE_LEVEL)
		return -EINVAL;
	if (UK_PAGING_PT_Lx_PTE_PADDR(*pte, level) != vaddr)
		return -EEXIST;

	/* Native paging resets PAT: entry 3 (PCD|PWT, PAT=0) is UC. */
	*pte |= UK_ARCH_X86_64_PTE_PCD | UK_ARCH_X86_64_PTE_PWT;
	return 0;
}

static int xapic_enable(void)
{
	struct uk_pagetable *pt = uk_paging_pt_get_active();
	struct uk_paging_page_mapx mapx = { .map = xapic_map_uncached };
	__u32 low, high, value, svr;
	__u64 base;
	__paddr_t paddr;
	int rc;

	if (!pt)
		return -ENODEV;
	uk_arch_x86_64_rdmsr(UK_ARCH_X86_64_APIC_MSR_BASE, &low, &high);
	base = ((__u64)high << 32) | low;
	if (!(base & UK_ARCH_X86_64_APIC_BASE_EN) ||
	    (base & UK_ARCH_X86_64_APIC_BASE_EXTD)) {
		uk_pr_err("Legacy APIC requires enabled xAPIC mode: IA32_APIC_BASE=%08x%08x\n",
			  high, low);
		return -ENOTSUP;
	}
	paddr = base & UK_ARCH_X86_64_APIC_BASE_ADDR_MASK;
	if (!paddr ||
	    (base & ~(UK_ARCH_X86_64_APIC_BASE_ADDR_MASK |
		      UK_ARCH_X86_64_APIC_BASE_BSP |
		      UK_ARCH_X86_64_APIC_BASE_EN)) ||
	    !uk_paging_paddr_range_isvalid(paddr, UK_PAGING_PAGE_SIZE))
		return -EINVAL;

	rc = uk_paging_page_mapx(pt, paddr, paddr, 1,
				UK_PAGING_PAGE_ATTR_PROT_RW,
				UK_PAGING_PAGE_FLAG_FORCE_SIZE, &mapx);
	if (rc)
		return rc;

	value = uk_arch_x86_64_readl((void *)(paddr + XAPIC_VERSION));
	if (value == __U32_MAX || (value & 0xff) < 0x10)
		return -EIO;
	svr = uk_arch_x86_64_readl((void *)(paddr + XAPIC_SVR));
	if (svr == __U32_MAX)
		return -EIO;
	value = (svr & ~UK_ARCH_X86_64_APIC_SVR_VECTOR_MASK) |
		UK_ARCH_X86_64_APIC_SVR_EN | XAPIC_SPURIOUS_VECTOR;
	if (value != svr)
		uk_arch_x86_64_writel((void *)(paddr + XAPIC_SVR), value);
	svr = uk_arch_x86_64_readl((void *)(paddr + XAPIC_SVR));
	if ((svr & (UK_ARCH_X86_64_APIC_SVR_EN |
		    UK_ARCH_X86_64_APIC_SVR_VECTOR_MASK)) !=
	    (UK_ARCH_X86_64_APIC_SVR_EN | XAPIC_SPURIOUS_VECTOR))
		return -EIO;
	uk_arch_x86_64_writel((void *)(paddr + XAPIC_TPR), 0);
	xapic_base = paddr;
	uk_pr_info("Using legacy xAPIC MMIO at 0x%lx (uncached, single CPU)\n",
		   (unsigned long)paddr);
	return 0;
}
#endif /* CONFIG_LIBUKINTCTLR_XAPIC */

#if CONFIG_LIBUKINTCTLR_APIC
#include <uk/arch/x86_64.h>
#include <uk/arch/util.h>

static inline int apic_enable(void)
{
	__u32 eax, ebx, ecx, edx;

	/* Check for x2APIC support */
	uk_arch_x86_64_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
	if (!(ecx & UK_ARCH_X86_64_CPUID1_ECX_X2APIC)) {
#if CONFIG_LIBUKINTCTLR_XAPIC
		if ((edx & (UK_ARCH_X86_64_CPUID1_EDX_APIC |
			    UK_ARCH_X86_64_CPUID1_EDX_MSR)) ==
		    (UK_ARCH_X86_64_CPUID1_EDX_APIC |
		     UK_ARCH_X86_64_CPUID1_EDX_MSR))
			return xapic_enable();
#endif
		uk_pr_err("x2APIC unavailable: CPUID.1 eax=%08x ebx=%08x ecx=%08x edx=%08x\n",
			  eax, ebx, ecx, edx);
		return -ENOTSUP;
	}

	/* Check if APIC is active */
	uk_arch_x86_64_rdmsr(UK_ARCH_X86_64_APIC_MSR_BASE,
					    &eax, &edx);
	if (!(eax & UK_ARCH_X86_64_APIC_BASE_EN)) {
		uk_pr_err("APIC globally disabled: IA32_APIC_BASE=%08x%08x\n",
			  edx, eax);
		return -ENOTSUP;
	}

	/* Switch to x2APIC mode */
	eax |= UK_ARCH_X86_64_APIC_BASE_EXTD;
	uk_arch_x86_64_wrmsr(UK_ARCH_X86_64_APIC_MSR_BASE,
					    eax, edx);

	/* Set APIC software enable flag if necessary */
	uk_arch_x86_64_rdmsr(UK_ARCH_X86_64_APIC_MSR_SVR,
					    &eax, &edx);
	if ((eax & UK_ARCH_X86_64_APIC_SVR_EN) == 0) {
		eax |= UK_ARCH_X86_64_APIC_SVR_EN;
		uk_arch_x86_64_wrmsr(UK_ARCH_X86_64_APIC_MSR_SVR,
						    eax, edx);
	}

	/*
	 * TODO: Configure spurious interrupt vector number
	 * After power-up or reset this is 0xff, which might not be
	 * configured in the trap table
	 */

	return 0;
}

static inline void apic_ack_interrupt(void)
{
#if CONFIG_LIBUKINTCTLR_XAPIC
	if (xapic_base) {
		uk_arch_x86_64_wmb();
		uk_arch_x86_64_writel((void *)(xapic_base + XAPIC_EOI), 0);
		return;
	}
#endif
	uk_arch_x86_64_wrmsr(UK_ARCH_X86_64_APIC_MSR_EOI, 0, 0);
}

#endif /* CONFIG_LIBUKINTCTLR_APIC */

#include "pic.h"

static struct uk_intctlr_desc intctlr;
#if CONFIG_LIBUKINTCTLR_APIC
static int apic_ready;
#endif /* CONFIG_LIBUKINTCTLR_APIC */

static int configure_irq(struct uk_intctlr_irq *irq __unused)
{
	return 0;
}

static int uk_intctlr_xpic_handle_irq(void *data)
{
	struct uk_lcpu_except_irq_ctx *ctx;
	__u32 irq;

	ctx = data;
#if CONFIG_LIBUKINTCTLR_APIC
	if (unlikely(!apic_ready))
		return UK_EVENT_NOT_HANDLED;
#endif /* CONFIG_LIBUKINTCTLR_APIC */
	irq = uk_lcpu_except_irq_ctx_get_irq(ctx);
#if CONFIG_LIBUKINTCTLR_XAPIC
	/* A spurious vector has no in-service bit and must not issue EOI. */
	if (xapic_base && irq == XAPIC_SPURIOUS_VECTOR - 32)
		return UK_EVENT_HANDLED;
#endif
	uk_intctlr_irq_handle(ctx);

#if CONFIG_LIBUKINTCTLR_APIC
	apic_ack_interrupt();

	/* FIXME This is here because right now we only use
	 * APIC for IPIs on SMP. This should be removed as
	 * soon as we fully implement APIC and get rid of
	 * PIC
	 */
	if (irq < 16)
		pic_ack_irq(irq);
#else   /* !CONFIG_LIBUKINTCTLR_APIC */
	pic_ack_irq(irq);
#endif /* !CONFIG_LIBUKINTCTLR_APIC */

	return UK_EVENT_HANDLED;
}

UK_EVENT_HANDLER(UK_LCPU_EXCEPT_EVENT_IRQ, uk_intctlr_xpic_handle_irq);

int uk_intctlr_probe(void)
{
	int rc = -ENODEV;
	struct uk_intctlr_driver_ops *ops;

#if CONFIG_LIBUKINTCTLR_APIC
	apic_ready = 0;
#endif
#if CONFIG_LIBUKINTCTLR_XAPIC
	xapic_base = 0;
#endif
	rc = pic_init(&ops);
	if (unlikely(rc))
		return rc;

#if CONFIG_LIBUKINTCTLR_APIC
	rc = apic_enable();
	if (unlikely(rc))
		return rc;
	intctlr.name = "APIC";
#else /* ! CONFIG_LIBUKINTCTLR_APIC */
	intctlr.name = "PIC";
#endif /* CONFIG_LIBUKINTCTLR_APIC */

	intctlr.ops = ops;
	intctlr.ops->configure_irq = configure_irq;

	rc = uk_intctlr_register(&intctlr);
#if CONFIG_LIBUKINTCTLR_APIC
	if (likely(!rc))
		apic_ready = 1;
#endif /* CONFIG_LIBUKINTCTLR_APIC */
	return rc;
}
