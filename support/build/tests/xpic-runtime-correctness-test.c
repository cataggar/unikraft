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
static __u32 apic_base;
static __u32 apic_svr;
static int register_result;
static unsigned int register_calls;
static unsigned int eoi_writes;
static unsigned int other_writes;
static unsigned int pic_acks;
static unsigned int handled_irqs;
static unsigned int msr_reads;
static char diagnostic[256];

static struct uk_intctlr_driver_ops pic_ops;

static void reset_state(void)
{
	cpuid_ecx = 0;
	apic_base = UK_ARCH_X86_64_APIC_BASE_EN;
	apic_svr = UK_ARCH_X86_64_APIC_SVR_EN;
	register_result = 0;
	register_calls = 0;
	eoi_writes = 0;
	other_writes = 0;
	pic_acks = 0;
	handled_irqs = 0;
	msr_reads = 0;
	diagnostic[0] = '\0';
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
	*edx = 0;
}

void uk_arch_x86_64_rdmsr(__u32 msr, __u32 *eax, __u32 *edx)
{
	msr_reads++;
	if (msr == UK_ARCH_X86_64_APIC_MSR_BASE)
		*eax = apic_base;
	else if (msr == UK_ARCH_X86_64_APIC_MSR_SVR)
		*eax = apic_svr;
	else
		assert(0);
	*edx = 0;
}

void uk_arch_x86_64_wrmsr(__u32 msr, __u32 eax, __u32 edx)
{
	(void)eax;
	(void)edx;
	if (msr == UK_ARCH_X86_64_APIC_MSR_EOI)
		eoi_writes++;
	else
		other_writes++;
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
}

int main(void)
{
	test_missing_x2apic_fails_closed();
	test_disabled_apic_fails_closed();
	test_registration_failure_does_not_arm_eoi();
	test_success_arms_x2apic_eoi();
	return 0;
}
