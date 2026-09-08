/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <uk/test_xpic.h>

extern int uk_intctlr_probe(void);
extern int (*uk_test_irq_handler)(void *);

static __u32 cpuid_ecx;
static __u32 cpuid_edx;
static __u32 apic_base;
static __u32 apic_base_high;
static __u32 apic_svr;
static int register_result;
static unsigned int register_calls;
static unsigned int eoi_writes;
static unsigned int other_writes;
static unsigned int pic_acks;
static unsigned int handled_irqs;
static unsigned int msr_reads;
static char diagnostic[256];
static struct uk_pagetable page_table;
static struct uk_pagetable *active_pt;
static int valid_paddr;
static int map_result;
static int map_collision;
static unsigned int map_level;
static unsigned int map_calls;
static int mapping_ready;
static __u32 mmio_version;
static __u32 mmio_svr;
static int ignore_svr_write;
static unsigned int mmio_reads;
static unsigned int mmio_svr_writes;
static unsigned int mmio_tpr_writes;
static unsigned int mmio_eoi_writes;
static unsigned int write_barriers;

static struct uk_intctlr_driver_ops pic_ops;

static void reset_state(void)
{
	cpuid_ecx = 0;
	cpuid_edx = 0;
	apic_base = 0xfee00000U | UK_ARCH_X86_64_APIC_BASE_EN |
		    UK_ARCH_X86_64_APIC_BASE_BSP;
	apic_base_high = 0;
	apic_svr = UK_ARCH_X86_64_APIC_SVR_EN;
	register_result = 0;
	register_calls = 0;
	eoi_writes = 0;
	other_writes = 0;
	pic_acks = 0;
	handled_irqs = 0;
	msr_reads = 0;
	diagnostic[0] = '\0';
	active_pt = &page_table;
	valid_paddr = 1;
	map_result = 0;
	map_collision = 0;
	map_level = 0;
	map_calls = 0;
	mapping_ready = 0;
	mmio_version = 0x00050014;
	mmio_svr = 0;
	ignore_svr_write = 0;
	mmio_reads = 0;
	mmio_svr_writes = 0;
	mmio_tpr_writes = 0;
	mmio_eoi_writes = 0;
	write_barriers = 0;
}

void uk_test_xpic_error(const char *format, ...)
{
	va_list args;
	int written;

	va_start(args, format);
	written = vsnprintf(diagnostic, sizeof(diagnostic), format, args);
	va_end(args);
	assert(written > 0 && (size_t)written < sizeof(diagnostic));
}

void uk_arch_x86_64_cpuid(__u32 leaf, __u32 subleaf, __u32 *eax,
			 __u32 *ebx, __u32 *ecx, __u32 *edx)
{
	assert(leaf == 1);
	assert(subleaf == 0);
	*eax = 0;
	*ebx = 0;
	*ecx = cpuid_ecx;
	*edx = cpuid_edx;
}

void uk_arch_x86_64_rdmsr(__u32 msr, __u32 *eax, __u32 *edx)
{
	msr_reads++;
	if (msr == UK_ARCH_X86_64_APIC_MSR_BASE)
		*eax = apic_base;
	else if (msr == UK_ARCH_X86_64_APIC_MSR_SVR) {
		assert(cpuid_ecx & UK_ARCH_X86_64_CPUID1_ECX_X2APIC);
		*eax = apic_svr;
	} else
		assert(0);
	*edx = msr == UK_ARCH_X86_64_APIC_MSR_BASE ? apic_base_high : 0;
}

void uk_arch_x86_64_wrmsr(__u32 msr, __u32 eax, __u32 edx)
{
	(void)eax;
	(void)edx;
	assert(cpuid_ecx & UK_ARCH_X86_64_CPUID1_ECX_X2APIC);
	if (msr == UK_ARCH_X86_64_APIC_MSR_EOI)
		eoi_writes++;
	else
		other_writes++;
}

struct uk_pagetable *uk_paging_pt_get_active(void)
{
	return active_pt;
}

int uk_paging_paddr_range_isvalid(__paddr_t start, size_t length)
{
	assert(start != 0 && (start & 4095) == 0);
	assert(length == 4096);
	return valid_paddr;
}

int uk_paging_page_mapx(struct uk_pagetable *pt, __vaddr_t vaddr,
		       __paddr_t paddr, unsigned long pages,
		       unsigned long attr, unsigned long flags,
		       struct uk_paging_page_mapx *mapx)
{
	__pte_t pte = (paddr + (map_collision ? 4096 : 0)) |
		      3 | (1UL << 63);
	int rc;

	assert(pt == &page_table && pt == active_pt);
	assert(vaddr == paddr && pages == 1);
	assert(attr == UK_PAGING_PAGE_ATTR_PROT_RW);
	assert(flags == UK_PAGING_PAGE_FLAG_FORCE_SIZE);
	map_calls++;
	if (map_result)
		return map_result;
	rc = mapx->map(pt, vaddr, 0, map_level, &pte, mapx->ctx);
	if (rc)
		return rc;
	assert(pte == (paddr | 3 | (1UL << 63) |
		       UK_ARCH_X86_64_PTE_PWT | UK_ARCH_X86_64_PTE_PCD));
	mapping_ready = 1;
	return 0;
}

static unsigned int mmio_offset(const volatile void *addr)
{
	__u64 base = ((__u64)apic_base_high << 32) | apic_base;
	uintptr_t offset = (uintptr_t)addr -
			   (base & UK_ARCH_X86_64_APIC_BASE_ADDR_MASK);

	assert(mapping_ready);
	assert(offset < 4096 && (offset & 3) == 0);
	return (unsigned int)offset;
}

__u32 uk_arch_x86_64_readl(const volatile void *addr)
{
	unsigned int offset = mmio_offset(addr);

	mmio_reads++;
	if (offset == 0x30)
		return mmio_version;
	assert(offset == 0xf0);
	return mmio_svr;
}

void uk_arch_x86_64_writel(volatile void *addr, __u32 value)
{
	unsigned int offset = mmio_offset(addr);

	if (offset == 0xf0) {
		assert(value == 0x1ff);
		mmio_svr_writes++;
		if (!ignore_svr_write)
			mmio_svr = value;
	} else if (offset == 0x80) {
		assert(value == 0);
		mmio_tpr_writes++;
	} else {
		assert(offset == 0xb0 && value == 0);
		assert(write_barriers == mmio_eoi_writes + 1);
		mmio_eoi_writes++;
	}
}

void uk_arch_x86_64_wmb(void)
{
	write_barriers++;
}

int pic_init(struct uk_intctlr_driver_ops **ops)
{
	*ops = &pic_ops;
	return 0;
}

void pic_ack_irq(unsigned int irq)
{
	assert(irq < 16);
	pic_acks++;
}

void uk_intctlr_irq_handle(struct uk_lcpu_except_irq_ctx *ctx)
{
	(void)ctx;
	handled_irqs++;
}

unsigned int
uk_lcpu_except_irq_ctx_get_irq(struct uk_lcpu_except_irq_ctx *ctx)
{
	return ctx->irq;
}

int uk_intctlr_register(struct uk_intctlr_desc *intctlr)
{
	register_calls++;
	assert(strcmp(intctlr->name, "APIC") == 0);
	assert(intctlr->ops == &pic_ops);
	assert(intctlr->ops->configure_irq != NULL);
	return register_result;
}

static void assert_irq_is_not_acknowledged(void)
{
	struct uk_lcpu_except_irq_ctx ctx = { .irq = 5 };

	assert(uk_test_irq_handler(&ctx) == UK_EVENT_NOT_HANDLED);
	assert(eoi_writes == 0);
	assert(pic_acks == 0);
	assert(handled_irqs == 0);
	assert(mmio_eoi_writes == 0);
}

static void test_missing_x2apic_fails_closed(void)
{
	reset_state();
	assert(uk_intctlr_probe() == -ENOTSUP);
	assert(register_calls == 0);
	assert(other_writes == 0);
	assert(msr_reads == 0);
	assert(strcmp(diagnostic, "x2APIC unavailable: CPUID.1 eax=00000000 "
		      "ebx=00000000 ecx=00000000 edx=00000000\n") == 0);
	assert_irq_is_not_acknowledged();
}

static void test_disabled_apic_fails_closed(void)
{
	reset_state();
	cpuid_ecx = UK_ARCH_X86_64_CPUID1_ECX_X2APIC;
	apic_base = 0;
	assert(uk_intctlr_probe() == -ENOTSUP);
	assert(register_calls == 0);
	assert(other_writes == 0);
	assert(msr_reads == 1);
	assert(strcmp(diagnostic, "APIC globally disabled: "
		      "IA32_APIC_BASE=0000000000000000\n") == 0);
	assert_irq_is_not_acknowledged();
}

static void test_registration_failure_does_not_arm_eoi(void)
{
	reset_state();
	cpuid_ecx = UK_ARCH_X86_64_CPUID1_ECX_X2APIC;
	register_result = -EIO;
	assert(uk_intctlr_probe() == -EIO);
	assert(register_calls == 1);
	assert(other_writes == 1);
	assert(diagnostic[0] == '\0');
	assert_irq_is_not_acknowledged();
}

static void test_success_arms_x2apic_eoi(void)
{
	struct uk_lcpu_except_irq_ctx ctx = { .irq = 5 };

	reset_state();
	cpuid_ecx = UK_ARCH_X86_64_CPUID1_ECX_X2APIC;
	assert(uk_intctlr_probe() == 0);
	assert(register_calls == 1);
	assert(other_writes == 1);
	assert(diagnostic[0] == '\0');
	assert(uk_test_irq_handler(&ctx) == UK_EVENT_HANDLED);
	assert(handled_irqs == 1);
	assert(eoi_writes == 1);
	assert(pic_acks == 1);
	assert(map_calls == 0);
	assert(mmio_reads == 0 && mmio_eoi_writes == 0);
}

static void legacy_features(void)
{
	reset_state();
	/* The feature bits actually advertised by the Azure AMD guest. */
	cpuid_ecx = 0xfeda3203;
	cpuid_edx = 0x178bfbff;
}

#if CONFIG_LIBUKINTCTLR_XAPIC
static void test_legacy_success_and_eoi(void)
{
	struct uk_lcpu_except_irq_ctx ctx = { .irq = 5 };

	legacy_features();
	assert(uk_intctlr_probe() == 0);
	assert(msr_reads == 1 && other_writes == 0);
	assert(map_calls == 1 && mmio_reads == 3);
	assert(mmio_svr_writes == 1 && mmio_tpr_writes == 1);
	assert(uk_test_irq_handler(&ctx) == UK_EVENT_HANDLED);
	assert(handled_irqs == 1 && mmio_eoi_writes == 1 && pic_acks == 1);
	ctx.irq = 192;
	assert(uk_test_irq_handler(&ctx) == UK_EVENT_HANDLED);
	assert(handled_irqs == 2 && mmio_eoi_writes == 2 && pic_acks == 1);
	ctx.irq = 223;
	assert(uk_test_irq_handler(&ctx) == UK_EVENT_HANDLED);
	assert(handled_irqs == 2 && mmio_eoi_writes == 2 && pic_acks == 1);
	assert(eoi_writes == 0 && other_writes == 0);

	legacy_features();
	mmio_svr = 0x1ff;
	assert(uk_intctlr_probe() == 0);
	assert(mmio_svr_writes == 0);
}

static void test_legacy_feature_and_base_failures(void)
{
	const __u32 missing[] = {
		UK_ARCH_X86_64_CPUID1_EDX_MSR,
		UK_ARCH_X86_64_CPUID1_EDX_APIC
	};
	size_t i;

	for (i = 0; i < sizeof(missing) / sizeof(missing[0]); i++) {
		legacy_features();
		cpuid_edx &= ~missing[i];
		assert(uk_intctlr_probe() == -ENOTSUP);
		assert(msr_reads == 0 && map_calls == 0);
		assert_irq_is_not_acknowledged();
	}
	legacy_features();
	apic_base &= ~UK_ARCH_X86_64_APIC_BASE_EN;
	assert(uk_intctlr_probe() == -ENOTSUP);
	assert(map_calls == 0 && other_writes == 0);
	assert_irq_is_not_acknowledged();

	legacy_features();
	apic_base |= UK_ARCH_X86_64_APIC_BASE_EXTD;
	assert(uk_intctlr_probe() == -ENOTSUP);
	assert(map_calls == 0 && other_writes == 0);
	assert_irq_is_not_acknowledged();

	legacy_features();
	apic_base = UK_ARCH_X86_64_APIC_BASE_EN;
	assert(uk_intctlr_probe() == -EINVAL);
	assert(map_calls == 0);
	assert_irq_is_not_acknowledged();

	legacy_features();
	apic_base |= 1;
	assert(uk_intctlr_probe() == -EINVAL);
	assert(map_calls == 0);

	legacy_features();
	apic_base_high = 0x10;
	assert(uk_intctlr_probe() == -EINVAL);
	assert(map_calls == 0);

	legacy_features();
	valid_paddr = 0;
	assert(uk_intctlr_probe() == -EINVAL);
	assert(map_calls == 0);
}

static void test_legacy_mapping_and_register_failures(void)
{
	legacy_features();
	active_pt = NULL;
	assert(uk_intctlr_probe() == -ENODEV);
	assert(msr_reads == 0 && map_calls == 0);
	assert_irq_is_not_acknowledged();

	legacy_features();
	map_result = -ENOMEM;
	assert(uk_intctlr_probe() == -ENOMEM);
	assert(mmio_reads == 0 && other_writes == 0);
	assert_irq_is_not_acknowledged();

	legacy_features();
	map_collision = 1;
	assert(uk_intctlr_probe() == -EEXIST);
	assert(mmio_reads == 0);
	assert_irq_is_not_acknowledged();

	legacy_features();
	map_level = 1;
	assert(uk_intctlr_probe() == -EINVAL);
	assert(mmio_reads == 0);

	legacy_features();
	mmio_version = UINT32_MAX;
	assert(uk_intctlr_probe() == -EIO);
	assert(mmio_svr_writes == 0);
	assert_irq_is_not_acknowledged();

	legacy_features();
	mmio_version = 0;
	assert(uk_intctlr_probe() == -EIO);
	assert(mmio_svr_writes == 0);

	legacy_features();
	mmio_svr = UINT32_MAX;
	assert(uk_intctlr_probe() == -EIO);
	assert(mmio_svr_writes == 0);

	legacy_features();
	ignore_svr_write = 1;
	assert(uk_intctlr_probe() == -EIO);
	assert(mmio_tpr_writes == 0);
	assert_irq_is_not_acknowledged();

	legacy_features();
	register_result = -EIO;
	assert(uk_intctlr_probe() == -EIO);
	assert(register_calls == 1);
	assert_irq_is_not_acknowledged();
}
#else
static void test_legacy_disabled(void)
{
	legacy_features();
	assert(uk_intctlr_probe() == -ENOTSUP);
	assert(msr_reads == 0 && map_calls == 0 && other_writes == 0);
	assert_irq_is_not_acknowledged();
}
#endif

int main(void)
{
	test_missing_x2apic_fails_closed();
	test_disabled_apic_fails_closed();
	test_registration_failure_does_not_arm_eoi();
	test_success_arms_x2apic_eoi();
#if CONFIG_LIBUKINTCTLR_XAPIC
	test_legacy_success_and_eoi();
	test_legacy_feature_and_base_failures();
	test_legacy_mapping_and_register_failures();
#else
	test_legacy_disabled();
#endif
	return 0;
}
