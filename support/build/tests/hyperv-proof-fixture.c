/* SPDX-License-Identifier: BSD-3-Clause */
/* Linked, never executed: real C ABI/macros with kernel-shaped IRQ edges. */
#include <stddef.h>
#include <uk/vmbus.h>
#include <uk/event.h>

#ifndef PROOF_MAX_CPUS
#define PROOF_MAX_CPUS 4
#endif
#ifndef PROOF_FIXED_SMP
#define PROOF_FIXED_SMP 1
#endif
#ifndef PROOF_PAGING
#define PROOF_PAGING 1
#endif

_Static_assert(sizeof(void *) == 8, "x86-64 callback ABI");
_Static_assert(sizeof(struct vmbus_driver) == 40, "native driver proof ABI");
_Static_assert(offsetof(struct vmbus_driver, device_ids) == 8, "ID table offset");
_Static_assert(offsetof(struct vmbus_driver, add_dev) == 16, "add callback offset");
_Static_assert(offsetof(struct vmbus_driver, remove_dev) == 24, "remove callback offset");
_Static_assert(offsetof(struct vmbus_driver, offer_removed) == 32, "removal callback offset");
_Static_assert(sizeof(uk_ctor_func_t) == 8, "constructor pointer ABI");
_Static_assert(PROOF_MAX_CPUS > 0, "logical CPU bound");

#define FN __attribute__((noinline, disable_tail_calls))
static volatile unsigned int proof_fail;
static volatile unsigned int proof_counter;
static int (*volatile irq_callback)(void *);
static void (*volatile time_callback)(void);
static void (*volatile wake_callback)(void);
static const struct vmbus_driver *volatile registered_driver;
unsigned int proof_ctor_writable __attribute__((section(".proof_rw")));

extern void hyperv_vmbus_message(void);
extern void hyperv_vmbus_event(void);
extern void hyperv_vmbus_event_word(void);
extern void hyperv_vmbus_shutdown(void);
extern void hyperv_vmbus_fini(void);
extern void hyperv_synic_message_take_page(void);
extern void hyperv_synic_event_take_word_page(void);
extern const struct vmbus_device_id storvsc_device_ids[2];
extern const struct vmbus_device_id netvsc_device_ids[2];

FN void _uk_printk(void)
{
	__asm__ volatile(".byte 0x66, 0x0f, 0xef, 0xc0"); /* worker-only pxor */
}

FN void schedcoop_thread_woken_isr(void)
{
	proof_counter++;
}

FN void uk_thread_wake_isr(void)
{
	wake_callback();
}

FN int hyperv_message_irq(void *arg)
{
	(void)arg;
	hyperv_synic_message_take_page();
	hyperv_vmbus_message();
	if (proof_fail) {
		_uk_printk();
		__builtin_trap();
	}
	return 0;
}

FN int hyperv_timer_irq(void *arg)
{
	(void)arg;
	hyperv_synic_event_take_word_page();
	hyperv_vmbus_event();
	uk_thread_wake_isr();
	return 0;
}

FN void hyperv_time_mark_pending(void)
{
	hyperv_vmbus_event_word();
}

FN int uk_intctlr_irq_register(unsigned int irq, int (*callback)(void *), void *arg)
{
	(void)irq;
	(void)arg;
	irq_callback = callback;
	return 0;
}

FN int uk_intctlr_time_pending_register(void (*callback)(void))
{
	time_callback = callback;
	return 0;
}

FN void ukplat_time_init(void)
{
	uk_intctlr_time_pending_register(hyperv_time_mark_pending);
	uk_intctlr_irq_register(1, hyperv_message_irq, NULL);
	uk_intctlr_irq_register(2, hyperv_timer_irq, NULL);
}

FN void uk_intctlr_irq_handle(void)
{
	irq_callback(NULL);
	time_callback();
}

FN int uk_intctlr_xpic_handle_irq(void *arg)
{
	(void)arg;
	uk_intctlr_irq_handle();
	return 0;
}

UK_EVENT(native_except_event_irq);
UK_EVENT_HANDLER(native_except_event_irq, uk_intctlr_xpic_handle_irq);

FN void uk_plat_native_except_irq_handler(void)
{
	/* A volatile load preserves the registered event's indirect call site. */
	const uk_event_handler_t volatile *entry =
		&_uk_event_native_except_event_irq_9_uk_intctlr_xpic_handle_irq;
	(*entry)(NULL);
}

FN void schedcoop_create(void)
{
	wake_callback = schedcoop_thread_woken_isr;
}

FN void uk_schedcoop_create(void)
{
#if PROOF_DIRECT_SCHED
	wake_callback = schedcoop_thread_woken_isr;
#else
	schedcoop_create();
#endif
}

__attribute__((naked)) void uk_schedcoop_create_on(void)
{
	__asm__ volatile("jmp schedcoop_create");
}

FN void ukplat_lcpu_init_hook(void) { proof_counter++; }
FN void ukplat_lcpu_fini_hook(void) { hyperv_vmbus_shutdown(); }
FN void uk_lcpu_init(void) { ukplat_lcpu_init_hook(); }
FN void lcpu_halt(void) { ukplat_lcpu_fini_hook(); }
FN void uk_lcpu_start(void) { proof_counter += PROOF_MAX_CPUS; }
FN void ukplat_lcpu_startup_hook(void)
{
#if PROOF_MAX_CPUS > 1
	uk_lcpu_start();
#endif
	proof_counter++;
}

#if PROOF_FIXED_SMP
FN void uk_boot_fixed_smp_prepare(void) { proof_counter++; }
static volatile unsigned int proof_cpus = PROOF_MAX_CPUS;
FN unsigned int uk_acpi_cpu_count(void) { return proof_cpus; }
FN unsigned int ukplat_lcpu_count(void) { return uk_acpi_cpu_count(); }
#if PROOF_PAGING
FN void uk_paging_pt_get_active(void) { proof_counter++; }
FN void uk_paging_pt_activate_lcpu(void) { proof_counter++; }
extern void lcpu_start32(void);
__asm__(
	".pushsection .text.proof.boot16,\"ax\"\n.code16\n"
	".global proof_start16\n.type proof_start16,@function\n"
	"proof_start16:\n"
	"xorl %edi,%edi\nmovw $0x1516,%ax\nmovl %cs,%ebx\n"
	"shll $4,%ebx\nsubl %ebx,%eax\njmp *%eax\n"
	".size proof_start16,.-proof_start16\n"
	".balign 16\n"
	".word 0,23\n.long 0x1516\n"
	".quad 0x00cf9b000000ffff,0x00cf93000000ffff\n"
	".popsection\n"
	".pushsection .text.ap,\"ax\"\n"
	".code32\n"
	".global lcpu_start32\n.type lcpu_start32,@function\n"
	"lcpu_start32:\n"
	".global x86_start16_end\n.set x86_start16_end,lcpu_start32\n"
	"movl $0x20,%eax\nmovl %eax,%cr4\n"
	"xorl %edx,%edx\nmovl $0x900,%eax\nmovl $0xc0000080,%ecx\nwrmsr\n"
	"movl $0x1532,%eax\nnop\nmovl %eax,%cr3\n"
	"movl $0x80010001,%eax\nmovl %eax,%cr0\n"
	"movl $0x1532,%eax\nnop\nlgdt (%eax)\n"
	"movl $0x1532,%eax\nnop\nmovl %eax,-6(%eax)\n"
	"ljmpl $8,$0x1532\n"
	".code64\n"
	".global proof_jump_to64\nproof_jump_to64:\n"
	"movabsq $0x1532,%rax\njmp *%rax\n"
	".global lcpu_start64\nlcpu_start64:\nretq\n"
	".size lcpu_start32,.-lcpu_start32\n.popsection\n"
);
#endif
FN void uk_boot_fixed_smp_lcpu_entry(void)
{
	uk_lcpu_init();
#if PROOF_PAGING
	uk_paging_pt_get_active();
	uk_paging_pt_activate_lcpu();
	lcpu_start32();
#endif
}
#endif

FN void uk_boot_entry(void)
{
	ukplat_lcpu_startup_hook();
#if PROOF_FIXED_SMP
	proof_counter += ukplat_lcpu_count();
	uk_boot_fixed_smp_prepare();
	uk_boot_fixed_smp_lcpu_entry();
#endif
}

FN int _vmbus_register_driver(struct vmbus_driver *driver)
{
	registered_driver = driver;
	return 0;
}

FN int storvsc_add_device(struct vmbus_device *dev) { (void)dev; return 0; }
FN void storvsc_remove_device(struct vmbus_device *dev) { (void)dev; proof_counter++; }
FN void storvsc_offer_removed(const struct vmbus_offer_identity *offer) { (void)offer; proof_counter++; }
FN int netvsc_add_device(struct vmbus_device *dev) { (void)dev; return 0; }
FN void netvsc_remove_device(struct vmbus_device *dev) { (void)dev; proof_counter++; }

static struct vmbus_driver storvsc_driver = {
	.name = "hyperv-storvsc", .device_ids = storvsc_device_ids,
	.add_dev = storvsc_add_device, .remove_dev = storvsc_remove_device,
	.offer_removed = storvsc_offer_removed,
};
static struct vmbus_driver netvsc_driver = {
	.name = "hyperv-netvsc", .device_ids = netvsc_device_ids,
	.add_dev = netvsc_add_device, .remove_dev = netvsc_remove_device,
};
#define __LIBNAME__ libstorvsc
VMBUS_DRIVER_REGISTER(&storvsc_driver);
#undef __LIBNAME__
#define __LIBNAME__ libnetvsc
VMBUS_DRIVER_REGISTER(&netvsc_driver);

FN void _start(void)
{
	uk_boot_entry();
	uk_lcpu_init();
	ukplat_time_init();
	uk_schedcoop_create();
	uk_schedcoop_create_on();
	uk_plat_native_except_irq_handler();
	lcpu_halt();
	__builtin_trap();
}
