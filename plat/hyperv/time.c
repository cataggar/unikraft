/* SPDX-License-Identifier: BSD-3-Clause */
#include <hyperv/hyperv.h>
#include <hyperv/clock.h>
#include <stdint.h>
#include <stdlib.h>
#include <uk/assert.h>
#include <uk/atomic.h>
#include <uk/intctlr.h>
#include <uk/lcpu.h>
#include <uk/paging.h>
#include <uk/plat/time.h>
#include <uk/print.h>

#define HYPERV_EVENT_WORDS_PER_SINT	32U
#define HYPERV_DISPATCH_LIMIT		64U

static __u64 hyperv_epoch_ns;
/* Paired with hyperv_epoch_ns before ExitBootServices. */
static __u64 hyperv_efi_ref;
/* Keeps the public monotonic clock anchored at ukplat_time_init(). */
static __u64 hyperv_boot_ref;
static unsigned int hyperv_irqs[2];
static int hyperv_time_initialized;

unsigned long sched_have_pending_events;

void hyperv_clock_set_efi_sample(__u64 epoch_ns, __u64 reference_time)
{
	hyperv_epoch_ns = epoch_ns;
	hyperv_efi_ref = reference_time;
}

void __weak hyperv_vmbus_message(const struct hyperv_message *message)
{
	uk_pr_warn("Hyper-V: unclaimed SINT2 message type 0x%x (%u bytes)\n",
		   message->message_type, message->payload_size);
}

void __weak hyperv_vmbus_event(__u32 event)
{
	uk_pr_warn("Hyper-V: unclaimed SINT2 event flag %u\n", event);
}

static void hyperv_dispatch_events(__u32 sint, int vmbus)
{
	__u64 pending;
	unsigned int bit;
	unsigned int word;

	for (word = 0; word < HYPERV_EVENT_WORDS_PER_SINT; word++) {
		if (unlikely(hyperv_synic_event_take_word(sint, word,
							 &pending)))
			UK_CRASH("Hyper-V: invalid SIEFP slot %u/%u\n",
				 sint, word);
		while (pending) {
			bit = __builtin_ctzll(pending);
			if (vmbus)
				hyperv_vmbus_event(word * 64U + bit);
			else
				uk_pr_warn("Hyper-V: unexpected SINT%u event %u\n",
					   sint, word * 64U + bit);
			pending &= pending - 1;
		}
	}
}

static int hyperv_message_irq(void *arg __unused)
{
	struct hyperv_message message;
	unsigned int count;
	int rc;

	for (count = 0; count < HYPERV_DISPATCH_LIMIT; count++) {
		rc = hyperv_synic_message_take(HYPERV_MESSAGE_SINT, &message);
		if (rc == HYPERV_MESSAGE_EMPTY)
			break;
		if (unlikely(rc < 0))
			UK_CRASH("Hyper-V: malformed SINT2 message (rc=%d)\n", rc);
		hyperv_vmbus_message(&message);
	}
	if (unlikely(count == HYPERV_DISPATCH_LIMIT))
		uk_pr_warn("Hyper-V: SINT2 message dispatch limit reached\n");
	hyperv_dispatch_events(HYPERV_MESSAGE_SINT, 1);
	return 1;
}

static int hyperv_timer_irq(void *arg __unused)
{
	struct hyperv_message message;
	unsigned int count;
	int rc;

	for (count = 0; count < HYPERV_DISPATCH_LIMIT; count++) {
		rc = hyperv_synic_message_take(HYPERV_TIMER_SINT, &message);
		if (rc == HYPERV_MESSAGE_EMPTY)
			break;
		if (unlikely(rc < 0))
			UK_CRASH("Hyper-V: malformed SINT4 message (rc=%d)\n", rc);
		if (unlikely(message.message_type !=
			     HYPERV_MESSAGE_TIMER_EXPIRED))
			uk_pr_warn("Hyper-V: unexpected SINT4 message 0x%x\n",
				   message.message_type);
	}
	if (unlikely(count == HYPERV_DISPATCH_LIMIT))
		uk_pr_warn("Hyper-V: SINT4 message dispatch limit reached\n");
	hyperv_dispatch_events(HYPERV_TIMER_SINT, 0);
	return 1;
}

static __paddr_t hyperv_page_gpa(void *page)
{
	__paddr_t gpa = uk_paging_virt_to_phys((__vaddr_t)page);

	if (gpa == UK_PAGING_PADDR_INV || (gpa & (HYPERV_PAGE_SIZE - 1)))
		UK_CRASH("Hyper-V: shared page %p has invalid GPA 0x%lx\n",
			 page, gpa);
	return gpa;
}

/* Called after the interrupt controller is initialized, with IRQs disabled. */
void ukplat_time_init(void)
{
	__paddr_t simp_gpa;
	__paddr_t siefp_gpa;
	__paddr_t reference_tsc_gpa;
	__u8 message_vector;
	__u8 timer_vector;
	int rc;

	UK_ASSERT(uk_lcpu_irqs_disabled());
	rc = uk_intctlr_irq_alloc(hyperv_irqs, 2);
	if (unlikely(rc))
		UK_CRASH("Hyper-V: failed to allocate SynIC IRQs: %d\n", rc);

	rc = hyperv_x86_irq_to_vector(hyperv_irqs[0], &message_vector);
	if (unlikely(rc))
		goto free_irqs;
	rc = hyperv_x86_irq_to_vector(hyperv_irqs[1], &timer_vector);
	if (unlikely(rc))
		goto free_irqs;

	rc = uk_intctlr_irq_register(hyperv_irqs[0],
				     hyperv_message_irq, NULL);
	if (unlikely(rc))
		goto free_irqs;
	rc = uk_intctlr_irq_register(hyperv_irqs[1], hyperv_timer_irq, NULL);
	if (unlikely(rc))
		goto unregister_message;

	simp_gpa = hyperv_page_gpa(hyperv_simp_page());
	siefp_gpa = hyperv_page_gpa(hyperv_siefp_page());
	reference_tsc_gpa = hyperv_page_gpa(hyperv_reference_tsc_page());
	rc = hyperv_synic_enable(simp_gpa, siefp_gpa, reference_tsc_gpa,
				 message_vector, timer_vector);
	if (unlikely(rc != HYPERV_SYNIC_OK))
		goto unregister_timer;

	hyperv_boot_ref = hyperv_reference_time();
	hyperv_time_initialized = 1;
	uk_pr_info("Hyper-V SynIC: SINT2 IRQ %u/vector 0x%x, "
		   "SINT4/STimer0 IRQ %u/vector 0x%x\n",
		   hyperv_irqs[0], message_vector, hyperv_irqs[1],
		   timer_vector);
	return;

unregister_timer:
	uk_intctlr_irq_unregister(hyperv_irqs[1], hyperv_timer_irq);
unregister_message:
	uk_intctlr_irq_unregister(hyperv_irqs[0], hyperv_message_irq);
free_irqs:
	uk_intctlr_irq_free(hyperv_irqs, 2);
	UK_CRASH("Hyper-V: failed to initialize SynIC/STimer0: %d\n", rc);
}

__nsec ukplat_monotonic_clock(void)
{
	return hyperv_reference_delta_ns(hyperv_reference_time(),
					 hyperv_boot_ref);
}

__nsec ukplat_wall_clock(void)
{
	return hyperv_wall_time_ns(hyperv_epoch_ns, hyperv_efi_ref,
				   hyperv_reference_time());
}

void ukplat_time_fini(void)
{
	if (!hyperv_time_initialized)
		return;
	hyperv_synic_disable();
	uk_intctlr_irq_unregister(hyperv_irqs[1], hyperv_timer_irq);
	uk_intctlr_irq_unregister(hyperv_irqs[0], hyperv_message_irq);
	uk_intctlr_irq_free(hyperv_irqs, 2);
	hyperv_time_initialized = 0;
}

__u32 ukplat_time_get_irq(void)
{
	return hyperv_time_initialized ? hyperv_irqs[1] : UINT32_MAX;
}

void time_block_until(__snsec until)
{
	__u64 deadline;
	__nsec now;

	UK_ASSERT(uk_lcpu_irqs_disabled());
	while (until > 0) {
		now = ukplat_monotonic_clock();
		if ((__snsec)now >= until)
			break;

		deadline = hyperv_deadline_reference_ticks(hyperv_boot_ref,
							   (__u64)until);
		hyperv_stimer0_arm(deadline);
		uk_lcpu_halt_irq();
		hyperv_stimer0_cancel();

		if (uk_and_relax(&sched_have_pending_events, 0))
			break;
	}
}
