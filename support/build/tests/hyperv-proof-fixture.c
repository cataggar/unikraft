/* SPDX-License-Identifier: BSD-3-Clause */
/* Linked, never executed: real C ABI/macros with kernel-shaped IRQ edges. */
#include <stddef.h>
#include <uk/vmbus.h>
#include <uk/event.h>
#if PROOF_HEAP_SCHED
typedef size_t __sz;
typedef ptrdiff_t __ssz;
typedef ptrdiff_t __off;
typedef int64_t __s64;
#define __NULL NULL
#include <uk/alloc.h>
#include <uk/plat/native/arch/ectx.h>
_Static_assert(offsetof(struct uk_alloc, malloc) == 0, "malloc ABI");
_Static_assert(offsetof(struct uk_alloc, calloc) == 8, "calloc ABI");
_Static_assert(offsetof(struct uk_alloc, memalign) == 32, "memalign ABI");
_Static_assert(offsetof(struct uk_alloc, free) == 40, "free ABI");
_Static_assert(UK_PLAT_NATIVE_ECTX_SIZE == 2688, "reviewed ECTX footprint");
_Static_assert(UK_PLAT_NATIVE_ECTX_ALIGN == 64, "reviewed ECTX alignment");
#endif

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
#if PROOF_OBJECT_SCHED
struct proof_thread;
struct proof_sched {
	void (*other[3])(struct proof_sched *, struct proof_thread *);
	void (*wake)(struct proof_sched *, struct proof_thread *);
#if PROOF_HEAP_SCHED
	struct proof_thread *queue_first;
	struct proof_thread **queue_tail;
	struct uk_alloc *allocator;
	struct proof_thread *worker;
	struct proof_sched *next;
#endif
};
struct proof_thread {
	long reserved;
	struct proof_sched *sched;
#if PROOF_HEAP_SCHED
	struct proof_thread *next;
#endif
};
static struct proof_sched proof_scheduler;
static struct proof_thread proof_thread;
static struct proof_sched *volatile published_sched;
#else
unsigned char proof_callback_storage[136] __attribute__((used, aligned(64)));
extern void (*volatile wake_callback)(void) __attribute__((visibility("hidden")));
__asm__(".set wake_callback, proof_callback_storage+64\n"
	".type wake_callback, @object\n.size wake_callback, 8");
#endif
static volatile unsigned long proof_pending;
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

#if PROOF_OBJECT_SCHED
FN void schedcoop_thread_woken_isr(struct proof_sched *sched, struct proof_thread *thread)
{
	(void)sched;
	(void)thread;
	proof_counter++;
}

FN void uk_thread_wake_isr(struct proof_thread *thread)
{
	thread->sched->wake(thread->sched, thread);
}
#else
FN void schedcoop_thread_woken_isr(void)
{
	proof_counter++;
}

FN void uk_thread_wake_isr(void)
{
	wake_callback();
}
#endif

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
#if PROOF_OBJECT_SCHED
	uk_thread_wake_isr(&proof_thread);
#else
	uk_thread_wake_isr();
#endif
	return 0;
}

FN void hyperv_time_mark_pending(void)
{
	__asm__ volatile("lock; orq $1, %0" : "+m"(proof_pending) : : "memory", "cc");
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
	if (proof_fail)
		proof_counter++;
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

#if PROOF_OBJECT_SCHED
#if PROOF_HEAP_SCHED
static unsigned char proof_arena[16384] __attribute__((aligned(64)));
static size_t proof_allocated;
FN void *proof_malloc(struct uk_alloc *a, size_t size)
{
	(void)a;
	if (size > sizeof(proof_arena) - 15)
		return NULL;
	size = (size + 15) & ~(size_t)15;
	if (size > sizeof(proof_arena) - proof_allocated)
		return NULL;
	void *result = proof_arena + proof_allocated;
	proof_allocated += size;
	return result;
}
FN void *proof_calloc(struct uk_alloc *a, size_t count, size_t size)
{
	if (__builtin_mul_overflow(count, size, &size))
		return NULL;
	unsigned char *result = proof_malloc(a, size);
	if (result)
		for (size_t i = 0; i < size; i++)
			result[i] = 0;
	return result;
}
FN void proof_free(struct uk_alloc *a, void *pointer)
{
	(void)a;
	(void)pointer;
}
static struct uk_alloc proof_allocator = {
	.malloc = proof_malloc, .calloc = proof_calloc, .free = proof_free,
};
struct proof_sched *uk_sched_head;
static struct proof_sched *volatile proof_cpu_map[2];
_Static_assert(offsetof(struct proof_sched, other[1]) == 8, "thread_add member ABI");
_Static_assert(offsetof(struct proof_sched, wake) == 24, "consumer fixture field");
_Static_assert(offsetof(struct proof_sched, queue_first) == 32, "queue fixture field");
FN void proof_sched_map(struct proof_sched *sched, unsigned int cpu)
{
	if (cpu > 1)
		return;
	proof_cpu_map[cpu] = sched;
}
FN struct proof_thread *proof_thread_allocate(struct uk_alloc *a,
					     struct proof_sched *sched)
{
	struct proof_thread *thread = a->malloc(a, sizeof(*thread));
	if (thread) {
		thread->sched = sched;
		thread->next = NULL;
	}
	return thread;
}
FN void proof_thread_add(struct proof_sched *sched, struct proof_thread *thread)
{
	*sched->queue_tail = thread;
	sched->queue_tail = &thread->next;
}
FN void proof_heap_hook(struct proof_sched *sched, struct proof_thread *thread)
{
	__asm__ volatile("" : : "r"(sched), "r"(thread) : "memory");
}
FN void proof_heap_preserve(struct proof_sched *sched, struct proof_thread *thread)
{
	(void)thread;
	sched->other[0] = NULL;
}
FN void proof_heap_overwrite(struct proof_sched *sched, struct proof_thread *thread)
{
	(void)thread;
	sched->wake = NULL;
}
static void (*volatile proof_heap_refs[])(struct proof_sched *, struct proof_thread *) = {
	proof_heap_preserve, proof_heap_overwrite,
};
#endif
FN void uk_sched_register(struct proof_sched *sched)
{
#if PROOF_HEAP_SCHED
	struct proof_sched **tail = &uk_sched_head;
	while (*tail)
		tail = &(*tail)->next;
	*tail = sched;
	sched->next = NULL;
#endif
	published_sched = sched;
}
FN struct proof_sched *proof_sched_allocate(void)
{
	return proof_fail ? NULL : &proof_scheduler;
}
FN void proof_sched_initialize(struct proof_sched *sched,
			       void (*callback)(struct proof_sched *, struct proof_thread *))
{
	sched->wake = callback;
	uk_sched_register(sched);
}
#if PROOF_HEAP_SCHED
FN struct proof_sched *schedcoop_create(struct uk_alloc *a)
{
	struct proof_sched *sched = a->calloc(a, 1, sizeof(*sched));
	if (!sched)
		return NULL;
	sched->allocator = a;
	sched->queue_first = NULL;
	sched->queue_tail = &sched->queue_first;
	sched->other[1] = proof_thread_add;
	proof_sched_initialize(sched, schedcoop_thread_woken_isr);
	proof_sched_map(sched, proof_fail & 1);
	struct proof_thread *thread = proof_thread_allocate(a, sched);
	if (!thread) {
		a->free(a, sched);
		return NULL;
	}
	sched->worker = thread;
	sched->other[1](sched, thread);
	proof_heap_hook(sched, thread);
	return sched;
}
FN struct proof_sched *uk_schedcoop_create(struct uk_alloc *a, struct uk_alloc *sa,
					  struct uk_alloc *aux, struct uk_alloc *tls)
{
	(void)sa;
	(void)aux;
	(void)tls;
	return schedcoop_create(a);
}
__attribute__((naked)) struct proof_sched *uk_schedcoop_create_on(
	struct uk_alloc *a, struct uk_alloc *sa, struct uk_alloc *aux,
	struct uk_alloc *tls)
{
	__asm__ volatile("jmp schedcoop_create");
}
#else
FN struct proof_sched *schedcoop_create(void)
{
	struct proof_sched *sched = proof_sched_allocate();
	if (!sched)
		return NULL;
	proof_sched_initialize(sched, schedcoop_thread_woken_isr);
	return sched;
}
FN struct proof_sched *uk_schedcoop_create(void)
{
	return schedcoop_create();
}
__attribute__((naked)) struct proof_sched *uk_schedcoop_create_on(void)
{
	__asm__ volatile("jmp schedcoop_create");
}
#endif
#else
FN void proof_callback_hook(void)
{
	__asm__ volatile("");
}

FN void schedcoop_create(void)
{
	if (proof_fail)
		proof_counter++;
	wake_callback = schedcoop_thread_woken_isr;
	proof_callback_hook();
}

FN void uk_schedcoop_create(void)
{
#if PROOF_DIRECT_SCHED
	wake_callback = schedcoop_thread_woken_isr;
	proof_callback_hook();
#else
	schedcoop_create();
#endif
}

__attribute__((naked)) void uk_schedcoop_create_on(void)
{
	__asm__ volatile("jmp schedcoop_create");
}
#endif

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

#define REGISTER_IMUL(name, factor) \
	__attribute__((naked)) void name(void) \
	{ \
		__asm__ volatile("leaq storvsc_driver(%rip), %rdi\n" \
				 "imulq $" factor ", %rdi, %rdi\n" \
				 "callq _vmbus_register_driver\nretq"); \
	}
REGISTER_IMUL(proof_imul_one, "1")
REGISTER_IMUL(proof_imul_zero, "0")

#if !PROOF_OBJECT_SCHED
#define VECTOR_STORE(name, zero, store, offset) \
	__attribute__((naked)) void name(void) \
	{ \
		__asm__ volatile(zero "\n" store ", wake_callback" offset "(%rip)\nretq"); \
	}
VECTOR_STORE(proof_xmm_before, "pxor %xmm0, %xmm0", "movdqu %xmm0", "-16")
VECTOR_STORE(proof_xmm_overlap, "pxor %xmm0, %xmm0", "movdqu %xmm0", "-15")
VECTOR_STORE(proof_ymm_before, "vpxor %ymm0, %ymm0, %ymm0", "vmovdqu %ymm0", "-32")
VECTOR_STORE(proof_ymm_overlap, "vpxor %ymm0, %ymm0, %ymm0", "vmovdqu %ymm0", "-24")
VECTOR_STORE(proof_ymm_exact, "vpxor %ymm0, %ymm0, %ymm0", "vmovdqu %ymm0", "")
VECTOR_STORE(proof_ymm_after, "vpxor %ymm0, %ymm0, %ymm0", "vmovdqu %ymm0", "+8")
VECTOR_STORE(proof_zmm_before, "vpxord %zmm0, %zmm0, %zmm0", "vmovdqu64 %zmm0", "-64")
VECTOR_STORE(proof_zmm_overlap, "vpxord %zmm0, %zmm0, %zmm0", "vmovdqu64 %zmm0", "-56")
VECTOR_STORE(proof_zmm_after, "vpxord %zmm0, %zmm0, %zmm0", "vmovdqu64 %zmm0", "+8")
#endif
static void (*volatile proof_transform_refs[])(void) = {
	proof_imul_one, proof_imul_zero,
#if !PROOF_OBJECT_SCHED
	proof_xmm_before, proof_xmm_overlap, proof_ymm_before,
	proof_ymm_overlap, proof_ymm_exact, proof_ymm_after,
	proof_zmm_before, proof_zmm_overlap, proof_zmm_after,
#endif
};

FN void _start(void)
{
	if (proof_fail)
		proof_transform_refs[0]();
	uk_boot_entry();
	uk_lcpu_init();
	ukplat_time_init();
#if PROOF_HEAP_SCHED
	if (proof_fail)
		proof_heap_refs[0](&proof_scheduler, &proof_thread);
	proof_thread.sched = uk_schedcoop_create(&proof_allocator, &proof_allocator,
					       &proof_allocator, &proof_allocator);
	uk_schedcoop_create_on(&proof_allocator, &proof_allocator,
			       &proof_allocator, &proof_allocator);
#elif PROOF_OBJECT_SCHED
	proof_thread.sched = uk_schedcoop_create();
#else
	uk_schedcoop_create();
#endif
#if !PROOF_HEAP_SCHED
	uk_schedcoop_create_on();
#endif
	uk_plat_native_except_irq_handler();
	lcpu_halt();
	__builtin_trap();
}
