/* SPDX-License-Identifier: BSD-3-Clause */
#include <hyperv/hyperv.h>
#include <hyperv/clock.h>
#include <hyperv/cpu_lifecycle.h>
#include <uk/acpi/madt.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <uk/arch/spinlock.h>
#include <uk/assert.h>
#include <uk/atomic.h>
#include <uk/config.h>
#include <uk/intctlr.h>
#include <uk/lcpu.h>
#include <uk/paging.h>
#include <uk/pcpuvar.h>
#include <uk/plat/spinlock.h>
#include <uk/plat/time.h>
#include <uk/plat/common/sections.h>
#include <uk/print.h>
#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
#include <uk/boot/smp.h>
#endif

#define HYPERV_EVENT_WORDS_PER_SINT	32U
#define HYPERV_DISPATCH_LIMIT		64U
#define HYPERV_TIME_OFFLINE		0
#define HYPERV_TIME_RUNNING		1
#define HYPERV_TIME_STOPPING		2
#define HYPERV_TIME_QUIESCED		3
#define HYPERV_AP_START_IDLE		0
#define HYPERV_AP_STARTING		1
#define HYPERV_AP_STARTED		2
#define HYPERV_AP_ROLLING_BACK		3
#define HYPERV_AP_FAILED		4
#define HYPERV_AP_QUARANTINED		5
#define HYPERV_CPU_STOP_TIMEOUT_NS	100000000ULL
#define HYPERV_CPU_INIT_TIMEOUT_TICKS	1000000ULL

static __u64 hyperv_epoch_ns;
/* Paired with hyperv_epoch_ns before ExitBootServices. */
static __u64 hyperv_efi_ref;
/* Keeps the public monotonic clock anchored at ukplat_time_init(). */
static __u64 hyperv_boot_ref;
static unsigned int hyperv_irqs[2];
static int hyperv_time_initialized;
static int hyperv_shutdown_first_error;
static __u8
hyperv_simp_pages[CONFIG_UKPLAT_CPU_MAXCOUNT][HYPERV_PAGE_SIZE]
	__align(HYPERV_PAGE_SIZE);
static __u8
hyperv_siefp_pages[CONFIG_UKPLAT_CPU_MAXCOUNT][HYPERV_PAGE_SIZE]
	__align(HYPERV_PAGE_SIZE);
static struct hyperv_cpu_state
hyperv_cpus[CONFIG_UKPLAT_CPU_MAXCOUNT];
static __spinlock hyperv_cpu_lock;
static __u32 hyperv_cpu_generation;
static __u8 hyperv_message_vector;
static __u8 hyperv_timer_vector;
static __u32 hyperv_irq_dropped;
static __u32 hyperv_vp_refs[CONFIG_UKPLAT_CPU_MAXCOUNT];
static int hyperv_ap_start_state;
static int hyperv_ap_start_error;
static __u32 hyperv_ap_start_generation;
static __u32 hyperv_ap_expected[CONFIG_UKPLAT_CPU_MAXCOUNT];
static unsigned int hyperv_ap_requested;
static unsigned int hyperv_ap_started;
static unsigned int hyperv_ap_waited;
static unsigned int hyperv_ap_late;
static int hyperv_current_cpu_index(__u32 *index);

_Static_assert(CONFIG_UKPLAT_CPU_MAXCOUNT >= 1,
	       "Hyper-V requires at least one configured CPU");
_Static_assert(sizeof(hyperv_simp_pages) ==
	       CONFIG_UKPLAT_CPU_MAXCOUNT * HYPERV_PAGE_SIZE,
	       "Hyper-V SIMP pool size mismatch");
_Static_assert(sizeof(hyperv_siefp_pages) ==
	       CONFIG_UKPLAT_CPU_MAXCOUNT * HYPERV_PAGE_SIZE,
	       "Hyper-V SIEFP pool size mismatch");
_Static_assert(__alignof__(hyperv_simp_pages) >= HYPERV_PAGE_SIZE,
	       "Hyper-V SIMP pool must be page aligned");
_Static_assert(__alignof__(hyperv_siefp_pages) >= HYPERV_PAGE_SIZE,
	       "Hyper-V SIEFP pool must be page aligned");

static __u8 hyperv_pending_events[CONFIG_UKPLAT_CPU_MAXCOUNT];
unsigned long sched_have_pending_events;
#if CONFIG_HAVE_SMP
static __u8 hyperv_ap_stacks[CONFIG_UKPLAT_CPU_MAXCOUNT - 1][__STACK_SIZE]
	__align(16);
#endif

static inline void hyperv_cpu_relax(void)
{
#ifdef HYPERV_TIME_HOST_TEST
	__atomic_signal_fence(__ATOMIC_ACQ_REL);
#else
	__asm__ __volatile__("pause");
#endif
}

static void hyperv_time_mark_pending(void)
{
	__u32 index;

	if (!hyperv_current_cpu_index(&index))
		__atomic_store_n(&hyperv_pending_events[index], 1,
				 __ATOMIC_RELEASE);
}

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

void __weak hyperv_vmbus_event_word(__u32 base_event __unused,
				    __u64 pending __unused)
{
}

void __weak hyperv_vmbus_fini(void)
{
}

int __weak hyperv_vmbus_shutdown(void)
{
	hyperv_vmbus_fini();
	return 0;
}

static int hyperv_current_cpu_index(__u32 *index)
{
	__u64 current = uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx);

	if (current >= CONFIG_UKPLAT_CPU_MAXCOUNT)
		return -ERANGE;
	*index = (__u32)current;
	return 0;
}

static int hyperv_current_irq_cpu_index(__u32 *index)
{
	__u64 current = uk_lcpu_get_current_idx_in_except();

	if (current >= CONFIG_UKPLAT_CPU_MAXCOUNT)
		return -ERANGE;
	*index = (__u32)current;
	return 0;
}

static int hyperv_cpu_page(__u32 index, __u8 **simp, __u8 **siefp)
{
	if (index >= CONFIG_UKPLAT_CPU_MAXCOUNT)
		return -ERANGE;
	if (__atomic_load_n(&hyperv_cpus[index].state, __ATOMIC_ACQUIRE) !=
	    HYPERV_CPU_ONLINE)
		return -ENODEV;
	if (simp)
		*simp = hyperv_simp_pages[index];
	if (siefp)
		*siefp = hyperv_siefp_pages[index];
	return 0;
}

static void hyperv_dispatch_events(__u32 sint, int vmbus)
{
	__u8 *siefp;
	__u64 pending;
	__u32 index;
	unsigned int word;

	if (unlikely(hyperv_current_irq_cpu_index(&index) ||
		     hyperv_cpu_page(index, NULL, &siefp))) {
		__atomic_add_fetch(&hyperv_irq_dropped, 1, __ATOMIC_RELAXED);
		return;
	}
	for (word = 0; word < HYPERV_EVENT_WORDS_PER_SINT; word++) {
		if (unlikely(hyperv_synic_event_take_word_page(
				siefp, sint, word, &pending))) {
			__atomic_add_fetch(&hyperv_irq_dropped, 1,
					   __ATOMIC_RELAXED);
			return;
		}
		if (vmbus && pending)
			hyperv_vmbus_event_word(word * 64U, pending);
		else if (pending)
			__atomic_add_fetch(&hyperv_irq_dropped,
					   __builtin_popcountll(pending),
					   __ATOMIC_RELAXED);
	}
}

static int hyperv_message_irq(void *arg __unused)
{
	__u8 *simp;
	__u32 index;
	struct hyperv_message message;
	unsigned int count;
	int rc;

	if (unlikely(hyperv_current_irq_cpu_index(&index) ||
		     hyperv_cpu_page(index, &simp, NULL))) {
		__atomic_add_fetch(&hyperv_irq_dropped, 1, __ATOMIC_RELAXED);
		return 1;
	}
	for (count = 0; count < HYPERV_DISPATCH_LIMIT; count++) {
		rc = hyperv_synic_message_take_page(
			simp, HYPERV_MESSAGE_SINT, &message);
		if (rc == HYPERV_MESSAGE_EMPTY)
			break;
		if (unlikely(rc < 0)) {
			__atomic_add_fetch(&hyperv_irq_dropped, 1,
					   __ATOMIC_RELAXED);
			break;
		}
		hyperv_vmbus_message(&message);
	}
	if (unlikely(count == HYPERV_DISPATCH_LIMIT))
		__atomic_add_fetch(&hyperv_irq_dropped, 1, __ATOMIC_RELAXED);
	hyperv_dispatch_events(HYPERV_MESSAGE_SINT, 1);
	return 1;
}

static int hyperv_timer_irq(void *arg __unused)
{
	__u8 *simp;
	__u32 index;
	struct hyperv_message message;
	unsigned int count;
	int rc;

	if (unlikely(hyperv_current_irq_cpu_index(&index) ||
		     hyperv_cpu_page(index, &simp, NULL))) {
		__atomic_add_fetch(&hyperv_irq_dropped, 1, __ATOMIC_RELAXED);
		return 1;
	}
	for (count = 0; count < HYPERV_DISPATCH_LIMIT; count++) {
		rc = hyperv_synic_message_take_page(
			simp, HYPERV_TIMER_SINT, &message);
		if (rc == HYPERV_MESSAGE_EMPTY)
			break;
		if (unlikely(rc < 0)) {
			__atomic_add_fetch(&hyperv_irq_dropped, 1,
					   __ATOMIC_RELAXED);
			break;
		}
		if (unlikely(message.message_type !=
			     HYPERV_MESSAGE_TIMER_EXPIRED))
			__atomic_add_fetch(&hyperv_irq_dropped, 1,
					   __ATOMIC_RELAXED);
	}
	if (unlikely(count == HYPERV_DISPATCH_LIMIT))
		__atomic_add_fetch(&hyperv_irq_dropped, 1, __ATOMIC_RELAXED);
	hyperv_dispatch_events(HYPERV_TIMER_SINT, 0);
	return 1;
}

static __paddr_t hyperv_page_gpa(void *page)
{
	__paddr_t gpa = uk_paging_virt_to_phys((__vaddr_t)page);

	if (gpa == UK_PAGING_PADDR_INV || (gpa & (HYPERV_PAGE_SIZE - 1)))
		return UK_PAGING_PADDR_INV;
	return gpa;
}

static int hyperv_cpu_reserve(__u32 index, __u32 vp_index, int bootstrap)
{
	unsigned long flags;
	__u32 max_vp = hyperv_max_vp_count();
	int rc;

	ukplat_spin_lock_irqsave(&hyperv_cpu_lock, flags);
	if (!bootstrap &&
	    __atomic_load_n(&hyperv_time_initialized, __ATOMIC_ACQUIRE) !=
		    HYPERV_TIME_RUNNING) {
		ukplat_spin_unlock_irqrestore(&hyperv_cpu_lock, flags);
		return -EAGAIN;
	}
	if (!bootstrap) {
		int start_state = __atomic_load_n(&hyperv_ap_start_state,
						  __ATOMIC_ACQUIRE);

		if (__atomic_load_n(&hyperv_cpus[index].state,
				    __ATOMIC_ACQUIRE) == HYPERV_CPU_ONLINE) {
			if (start_state != HYPERV_AP_STARTING &&
			    start_state != HYPERV_AP_STARTED) {
				hyperv_ap_late++;
				ukplat_spin_unlock_irqrestore(
					&hyperv_cpu_lock, flags);
				return -ECANCELED;
			}
		} else if (start_state != HYPERV_AP_STARTING ||
			   hyperv_ap_expected[index] !=
				   hyperv_ap_start_generation) {
			hyperv_ap_late++;
			ukplat_spin_unlock_irqrestore(&hyperv_cpu_lock, flags);
			return -ECANCELED;
		}
	}
	rc = hyperv_cpu_state_reserve(hyperv_cpus,
			CONFIG_UKPLAT_CPU_MAXCOUNT, index, vp_index, max_vp,
			&hyperv_cpu_generation);
	ukplat_spin_unlock_irqrestore(&hyperv_cpu_lock, flags);
	return rc;
}

static void hyperv_cpu_release(__u32 index)
{
	unsigned long flags;

	ukplat_spin_lock_irqsave(&hyperv_cpu_lock, flags);
	hyperv_cpu_state_release(hyperv_cpus, CONFIG_UKPLAT_CPU_MAXCOUNT,
				 index);
	ukplat_spin_unlock_irqrestore(&hyperv_cpu_lock, flags);
}

static int hyperv_cpu_init_current(int bootstrap)
{
	__paddr_t simp_gpa;
	__paddr_t siefp_gpa;
	__u32 index;
	__u32 vp_index;
	int rc;

	rc = hyperv_current_cpu_index(&index);
	if (rc)
		return rc;
	vp_index = hyperv_vp_index();
	rc = hyperv_cpu_reserve(index, vp_index, bootstrap);
	if (rc)
		return rc > 0 ? 0 : rc;
	memset(hyperv_simp_pages[index], 0, HYPERV_PAGE_SIZE);
	memset(hyperv_siefp_pages[index], 0, HYPERV_PAGE_SIZE);
	simp_gpa = hyperv_page_gpa(hyperv_simp_pages[index]);
	siefp_gpa = hyperv_page_gpa(hyperv_siefp_pages[index]);
	if (simp_gpa == UK_PAGING_PADDR_INV ||
	    siefp_gpa == UK_PAGING_PADDR_INV) {
		rc = -EINVAL;
		goto failed;
	}
	rc = hyperv_synic_cpu_enable(simp_gpa, siefp_gpa,
				     hyperv_message_vector,
				     hyperv_timer_vector);
	if (rc != HYPERV_SYNIC_OK) {
		rc = -EIO;
		goto failed;
	}
	{
		unsigned long flags;

		ukplat_spin_lock_irqsave(&hyperv_cpu_lock, flags);
		if (!bootstrap &&
		    (__atomic_load_n(&hyperv_time_initialized,
				     __ATOMIC_ACQUIRE) != HYPERV_TIME_RUNNING ||
		     __atomic_load_n(&hyperv_ap_start_state,
				     __ATOMIC_ACQUIRE) !=
			     HYPERV_AP_STARTING ||
		     hyperv_ap_expected[index] !=
			     hyperv_ap_start_generation)) {
			hyperv_ap_late++;
			ukplat_spin_unlock_irqrestore(&hyperv_cpu_lock, flags);
			rc = -ECANCELED;
			goto failed;
		}
		rc = hyperv_cpu_state_online(hyperv_cpus,
				CONFIG_UKPLAT_CPU_MAXCOUNT, index);
		ukplat_spin_unlock_irqrestore(&hyperv_cpu_lock, flags);
		return rc;
	}
failed:
	hyperv_synic_cpu_disable();
	hyperv_cpu_release(index);
	return rc;
}

static int hyperv_cpu_wait_refs(__u32 index, int bounded)
{
	__u64 deadline = hyperv_reference_time() +
		HYPERV_CPU_INIT_TIMEOUT_TICKS;

	while (__atomic_load_n(&hyperv_vp_refs[index], __ATOMIC_ACQUIRE)) {
		if (!bounded || hyperv_reference_time() >= deadline)
			return -EBUSY;
		hyperv_cpu_relax();
	}
	return 0;
}

static int hyperv_cpu_fini_current(int host_quiesced)
{
	__u32 index;
	int rc;

	if (hyperv_current_cpu_index(&index) ||
	    __atomic_load_n(&hyperv_cpus[index].state, __ATOMIC_ACQUIRE) ==
		    HYPERV_CPU_OFFLINE)
		return 0;
	rc = hyperv_cpu_wait_refs(index, host_quiesced);
	if (rc)
		return rc;
	__atomic_store_n(&hyperv_cpus[index].state, HYPERV_CPU_STOPPING,
			 __ATOMIC_RELEASE);
	hyperv_stimer0_cancel();
	hyperv_synic_cpu_disable();
	memset(hyperv_simp_pages[index], 0, HYPERV_PAGE_SIZE);
	memset(hyperv_siefp_pages[index], 0, HYPERV_PAGE_SIZE);
	hyperv_cpu_release(index);
	return 0;
}

#if CONFIG_HAVE_SMP
static void __noreturn
hyperv_cpu_remote_fini(struct uk_lcpu_regs *regs __unused,
		       void *arg)
{
	int host_quiesced = (int)(__uptr)arg;

	(void)hyperv_cpu_fini_current(host_quiesced);
	uk_lcpu_halt();
}

static int
hyperv_cpu_fini_indices(const __u64 candidates[], unsigned int candidate_count,
			int host_quiesced)
{
	const struct uk_lcpu_func fn = {
		.fn = hyperv_cpu_remote_fini,
		.user = (void *)(__uptr)!!host_quiesced,
	};
	__u64 indices[CONFIG_UKPLAT_CPU_MAXCOUNT];
	__nsec deadline = ukplat_monotonic_clock() +
		HYPERV_CPU_STOP_TIMEOUT_NS;
	unsigned int count;
	unsigned int queued;
	unsigned int waited;
	unsigned int i;
	int rc;
	int wait_rc;

	for (;;) {
		count = 0;
		for (i = 0; i < candidate_count; i++) {
			if (candidates[i] >= CONFIG_UKPLAT_CPU_MAXCOUNT)
				return -ERANGE;
			if (__atomic_load_n(
				    &hyperv_cpus[candidates[i]].state,
				    __ATOMIC_ACQUIRE) == HYPERV_CPU_ONLINE)
				indices[count++] = candidates[i];
		}
		if (!count)
			return 0;

		queued = count;
		rc = uk_lcpu_run(indices, &queued, &fn,
				  UK_LCPU_RFLG_DONOTBLOCK);
		if (queued > count)
			return -EIO;
		if (queued) {
			waited = queued;
			wait_rc = uk_lcpu_wait(indices, &waited,
						HYPERV_CPU_STOP_TIMEOUT_NS);
			if (wait_rc || waited != queued)
				return wait_rc ? wait_rc : -ETIMEDOUT;
		}
		if (rc && rc != -EAGAIN)
			return rc;
		if (ukplat_monotonic_clock() >= deadline)
			return -ETIMEDOUT;
		hyperv_cpu_relax();
	}
}

static int
hyperv_ap_start_begin(const __u64 indices[], unsigned int count,
		      __u32 *generation)
{
	unsigned long flags;
	unsigned int i;
	int state;
	int rc = 0;

	ukplat_spin_lock_irqsave(&hyperv_cpu_lock, flags);
	state = __atomic_load_n(&hyperv_ap_start_state, __ATOMIC_ACQUIRE);
	if (state == HYPERV_AP_STARTED) {
		rc = 1;
		goto out;
	}
	if (state == HYPERV_AP_FAILED || state == HYPERV_AP_QUARANTINED) {
		rc = hyperv_ap_start_error ? hyperv_ap_start_error : -EIO;
		goto out;
	}
	if (state != HYPERV_AP_START_IDLE) {
		rc = -EBUSY;
		goto out;
	}
	if (__atomic_load_n(&hyperv_time_initialized, __ATOMIC_ACQUIRE) !=
		    HYPERV_TIME_RUNNING) {
		rc = -EAGAIN;
		goto out;
	}
	if (hyperv_ap_start_generation == UINT32_MAX) {
		rc = -ENOSPC;
		goto out;
	}
	for (i = 0; i < count; i++) {
		if (!indices[i] ||
		    indices[i] >= CONFIG_UKPLAT_CPU_MAXCOUNT) {
			rc = -ERANGE;
			goto out;
		}
	}
	*generation = ++hyperv_ap_start_generation;
	memset(hyperv_ap_expected, 0, sizeof(hyperv_ap_expected));
	for (i = 0; i < count; i++)
		hyperv_ap_expected[indices[i]] = *generation;
	hyperv_ap_requested = count;
	hyperv_ap_started = 0;
	hyperv_ap_waited = 0;
	hyperv_ap_late = 0;
	hyperv_ap_start_error = 0;
	__atomic_store_n(&hyperv_ap_start_state, HYPERV_AP_STARTING,
			 __ATOMIC_RELEASE);
out:
	ukplat_spin_unlock_irqrestore(&hyperv_cpu_lock, flags);
	return rc;
}

static int
hyperv_ap_start_complete(const __u64 indices[], unsigned int count,
			 __u32 generation)
{
	unsigned long flags;
	unsigned int i;
	int rc = 0;

	ukplat_spin_lock_irqsave(&hyperv_cpu_lock, flags);
	if (__atomic_load_n(&hyperv_ap_start_state, __ATOMIC_ACQUIRE) !=
		    HYPERV_AP_STARTING ||
	    generation != hyperv_ap_start_generation) {
		rc = -ECANCELED;
		goto out;
	}
	if (__atomic_load_n(&hyperv_time_initialized, __ATOMIC_ACQUIRE) !=
		    HYPERV_TIME_RUNNING) {
		rc = -ECANCELED;
		goto out;
	}
	for (i = 0; i < count; i++)
		if (__atomic_load_n(&hyperv_cpus[indices[i]].state,
				    __ATOMIC_ACQUIRE) != HYPERV_CPU_ONLINE) {
			rc = -EIO;
			goto out;
		}
	for (i = 0; i < CONFIG_UKPLAT_CPU_MAXCOUNT; i++)
		hyperv_ap_expected[i] = 0;
	__atomic_store_n(&hyperv_ap_start_state, HYPERV_AP_STARTED,
			 __ATOMIC_RELEASE);
out:
	ukplat_spin_unlock_irqrestore(&hyperv_cpu_lock, flags);
	return rc;
}

static int
hyperv_ap_start_rollback(const __u64 indices[], unsigned int count,
			 __u32 generation, int startup_error)
{
	unsigned long flags;
	unsigned int settled = count;
	unsigned int finished = count;
	unsigned int i;
	unsigned int late;
	int clean = 1;
	int rc;
	int rollback_error = 0;

	if (!startup_error)
		startup_error = -EIO;
	ukplat_spin_lock_irqsave(&hyperv_cpu_lock, flags);
	if (__atomic_load_n(&hyperv_ap_start_state, __ATOMIC_ACQUIRE) ==
		    HYPERV_AP_STARTING &&
	    generation == hyperv_ap_start_generation)
		__atomic_store_n(&hyperv_ap_start_state,
				 HYPERV_AP_ROLLING_BACK, __ATOMIC_RELEASE);
	else {
		rollback_error = -ECANCELED;
		clean = 0;
	}
	ukplat_spin_unlock_irqrestore(&hyperv_cpu_lock, flags);

	if (count) {
		rc = uk_lcpu_wait(indices, &settled,
				   HYPERV_CPU_STOP_TIMEOUT_NS);
		if (settled > count) {
			settled = count;
			if (!rollback_error)
				rollback_error = -EIO;
		}
		/*
		 * A failed settle wait does not make rollback unsafe by itself:
		 * closing admission above forces initializing late arrivals to
		 * tear down locally before they can become online.
		 */
		(void)rc;

		rc = hyperv_cpu_fini_indices(indices, count, 0);
		if (rc && !rollback_error)
			rollback_error = rc;

		rc = uk_lcpu_wait(indices, &finished,
				   HYPERV_CPU_STOP_TIMEOUT_NS);
		if (rc || finished != count) {
			clean = 0;
			if (!rollback_error)
				rollback_error = rc ? rc : -ETIMEDOUT;
		}
	}
	for (i = 0; i < count; i++)
		if (__atomic_load_n(&hyperv_cpus[indices[i]].state,
				    __ATOMIC_ACQUIRE) != HYPERV_CPU_OFFLINE) {
			clean = 0;
			if (!rollback_error)
				rollback_error = -EBUSY;
		}

	ukplat_spin_lock_irqsave(&hyperv_cpu_lock, flags);
	late = hyperv_ap_late;
	hyperv_ap_start_error = clean ?
		startup_error : (rollback_error ? rollback_error : -EBUSY);
	if (clean)
		memset(hyperv_ap_expected, 0, sizeof(hyperv_ap_expected));
	__atomic_store_n(&hyperv_ap_start_state,
			 clean ? HYPERV_AP_FAILED : HYPERV_AP_QUARANTINED,
			 __ATOMIC_RELEASE);
	rc = hyperv_ap_start_error;
	ukplat_spin_unlock_irqrestore(&hyperv_cpu_lock, flags);

#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
	uk_boot_fixed_smp_rollback(indices, hyperv_ap_requested, clean);
#endif
	uk_pr_warn("Hyper-V: AP startup failed after %u/%u start(s), "
		   "%u initially settled, %u late; rollback %s (%d)\n",
		   count, hyperv_ap_requested, hyperv_ap_waited, late,
		   clean ? "complete" : "quarantined", rc);
	return rc;
}
#endif

int ukplat_lcpu_init_hook(void)
{
	int rc;

	if (__atomic_load_n(&hyperv_time_initialized, __ATOMIC_ACQUIRE) !=
	    HYPERV_TIME_RUNNING)
		rc = uk_lcpu_current_is_bsp() ? 0 : -EAGAIN;
	else
		rc = hyperv_cpu_init_current(0);
	return rc;
}

int ukplat_lcpu_startup_hook(void)
{
#if CONFIG_HAVE_SMP
	__u64 indices[CONFIG_UKPLAT_CPU_MAXCOUNT - 1];
	__uptr stacks[CONFIG_UKPLAT_CPU_MAXCOUNT - 1];
#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
	__uptr entries[CONFIG_UKPLAT_CPU_MAXCOUNT - 1];
#endif
	unsigned int count = uk_acpi_cpu_count();
	unsigned int requested;
	unsigned int started;
	unsigned int waited;
	unsigned int i;
	__u32 generation;
	int rc;

	if (count <= 1)
		return 0;
	if (count > CONFIG_UKPLAT_CPU_MAXCOUNT)
		return -ERANGE;
	for (i = 1; i < count; i++) {
		indices[i - 1] = i;
		stacks[i - 1] = (__uptr)&hyperv_ap_stacks[i - 1][__STACK_SIZE];
#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
		entries[i - 1] = (__uptr)uk_boot_fixed_smp_lcpu_entry;
#endif
	}
	requested = count - 1;
	rc = hyperv_ap_start_begin(indices, requested, &generation);
	if (rc)
		return rc > 0 ? 0 : rc;

	started = requested;
	rc = uk_lcpu_start(indices, &started, stacks,
#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
			    entries,
#else
			    NULL,
#endif
			    0);
	if (started > requested) {
		started = requested;
		rc = -EIO;
	}
	__atomic_store_n(&hyperv_ap_started, started, __ATOMIC_RELEASE);
	if (rc || started != requested)
		return hyperv_ap_start_rollback(indices, started, generation,
						rc ? rc : -EIO);

	waited = started;
	rc = uk_lcpu_wait(indices, &waited, HYPERV_CPU_STOP_TIMEOUT_NS);
	if (waited > started) {
		waited = started;
		rc = -EIO;
	}
	__atomic_store_n(&hyperv_ap_waited, waited, __ATOMIC_RELEASE);
	if (rc || waited != started)
		return hyperv_ap_start_rollback(indices, started, generation,
						rc ? rc : -ETIMEDOUT);
#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
	rc = uk_boot_fixed_smp_wait_online(indices, started);
	if (rc)
		return hyperv_ap_start_rollback(indices, started, generation,
						rc);
#endif
	rc = hyperv_ap_start_complete(indices, started, generation);
	if (rc)
		return hyperv_ap_start_rollback(indices, started, generation,
						rc);
	uk_pr_info("Hyper-V: started %u secondary CPU(s)\n", started);
#endif
	return 0;
}

#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
unsigned int ukplat_lcpu_count(void)
{
	return uk_acpi_cpu_count();
}
#endif

void ukplat_lcpu_fini_hook(void)
{
	(void)hyperv_cpu_fini_current(0);
}

/* Called after the interrupt controller is initialized, with IRQs disabled. */
void ukplat_time_init(void)
{
	__paddr_t reference_tsc_gpa;
	__u8 message_vector;
	__u8 timer_vector;
	int rc;

	UK_ASSERT(uk_lcpu_irqs_disabled());
	rc = uk_intctlr_time_pending_register(hyperv_time_mark_pending);
	if (unlikely(rc))
		UK_CRASH("Hyper-V: failed to register pending-event hook: %d\n",
			 rc);
	ukarch_spin_init(&hyperv_cpu_lock);
	for (unsigned int i = 0; i < CONFIG_UKPLAT_CPU_MAXCOUNT; i++) {
		hyperv_cpus[i].vp_index = UINT32_MAX;
		hyperv_cpus[i].generation = 0;
		hyperv_cpus[i].state = HYPERV_CPU_OFFLINE;
		hyperv_vp_refs[i] = 0;
		hyperv_ap_expected[i] = 0;
	}
	hyperv_cpu_generation = 0;
	hyperv_ap_start_state = HYPERV_AP_START_IDLE;
	hyperv_ap_start_error = 0;
	hyperv_ap_start_generation = 0;
	hyperv_ap_requested = 0;
	hyperv_ap_started = 0;
	hyperv_ap_waited = 0;
	hyperv_ap_late = 0;
	hyperv_shutdown_first_error = 0;
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

	reference_tsc_gpa = hyperv_page_gpa(hyperv_reference_tsc_page());
	if (reference_tsc_gpa == UK_PAGING_PADDR_INV) {
		rc = -EINVAL;
		goto unregister_timer;
	}
	memset(hyperv_reference_tsc_page(), 0, HYPERV_PAGE_SIZE);
	rc = hyperv_reference_tsc_enable(reference_tsc_gpa);
	if (unlikely(rc != HYPERV_SYNIC_OK))
		goto unregister_timer;
	hyperv_message_vector = message_vector;
	hyperv_timer_vector = timer_vector;
	rc = hyperv_cpu_init_current(1);
	if (unlikely(rc))
		goto disable_reference_tsc;

	hyperv_boot_ref = hyperv_reference_time();
	__atomic_store_n(&hyperv_time_initialized, HYPERV_TIME_RUNNING,
			 __ATOMIC_RELEASE);
	uk_pr_info("Hyper-V SynIC: SINT2 IRQ %u/vector 0x%x, "
		   "SINT4/STimer0 IRQ %u/vector 0x%x, BSP VP %u\n",
		   hyperv_irqs[0], message_vector, hyperv_irqs[1],
		   timer_vector, hyperv_cpus[0].vp_index);
	return;

disable_reference_tsc:
	hyperv_reference_tsc_disable();
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

static int hyperv_cpu_wait_initializing(void)
{
	__u64 deadline = hyperv_reference_time() +
		HYPERV_CPU_INIT_TIMEOUT_TICKS;
	unsigned int i;

	for (;;) {
		int initializing = 0;

		for (i = 0; i < CONFIG_UKPLAT_CPU_MAXCOUNT; i++)
			if (__atomic_load_n(&hyperv_cpus[i].state,
					    __ATOMIC_ACQUIRE) ==
			    HYPERV_CPU_INITIALIZING) {
				initializing = 1;
				break;
			}
		if (!initializing)
			return 0;
		if (hyperv_reference_time() >= deadline)
			return -ETIMEDOUT;
		hyperv_cpu_relax();
	}
}

static int hyperv_cpu_fini_others(int host_quiesced)
{
	int rc = hyperv_cpu_wait_initializing();

	if (rc)
		return rc;
#if CONFIG_HAVE_SMP
	__u64 indices[CONFIG_UKPLAT_CPU_MAXCOUNT];
	unsigned int count = 0;
	unsigned int i;
	__u32 current;

	rc = hyperv_current_cpu_index(&current);
	if (rc)
		return rc;
	for (i = 0; i < CONFIG_UKPLAT_CPU_MAXCOUNT; i++)
		if (i != current)
			indices[count++] = i;
	return hyperv_cpu_fini_indices(indices, count, host_quiesced);
#endif
	return 0;
}

int hyperv_time_shutdown(int crash, int host_quiesced)
{
	int state = __atomic_load_n(&hyperv_time_initialized,
				    __ATOMIC_ACQUIRE);
	int expected = HYPERV_TIME_RUNNING;
	int rc;

	if (state == HYPERV_TIME_OFFLINE || state == HYPERV_TIME_QUIESCED)
		return 0;
	if (!__atomic_compare_exchange_n(&hyperv_time_initialized, &expected,
			HYPERV_TIME_STOPPING, 0, __ATOMIC_ACQ_REL,
			__ATOMIC_ACQUIRE)) {
		if (expected == HYPERV_TIME_OFFLINE ||
		    expected == HYPERV_TIME_QUIESCED)
			return 0;
		/* Another CPU owns teardown. A secondary caller must park. */
		if (!uk_lcpu_current_is_bsp())
			uk_lcpu_halt();
		return -EINPROGRESS;
	}
	rc = hyperv_cpu_fini_others(host_quiesced);
	if (rc && !hyperv_shutdown_first_error)
		hyperv_shutdown_first_error = rc;
	rc = hyperv_cpu_fini_current(host_quiesced);
	if (rc && !hyperv_shutdown_first_error)
		hyperv_shutdown_first_error = rc;
	if (!rc && host_quiesced)
		hyperv_reference_tsc_disable();
	if (crash) {
		__atomic_store_n(&hyperv_time_initialized, rc ?
				 HYPERV_TIME_QUIESCED : HYPERV_TIME_OFFLINE,
				 __ATOMIC_RELEASE);
		return 0;
	}
	if (!host_quiesced || hyperv_shutdown_first_error) {
		__atomic_store_n(&hyperv_time_initialized,
				 HYPERV_TIME_QUIESCED, __ATOMIC_RELEASE);
		return 0;
	}
	{
		__u32 dropped = __atomic_exchange_n(&hyperv_irq_dropped, 0,
						    __ATOMIC_ACQ_REL);

		if (dropped)
			uk_pr_warn("Hyper-V: dropped %u malformed/stale SynIC "
				   "item(s)\n", dropped);
	}
	uk_intctlr_irq_unregister(hyperv_irqs[1], hyperv_timer_irq);
	uk_intctlr_irq_unregister(hyperv_irqs[0], hyperv_message_irq);
	uk_intctlr_irq_free(hyperv_irqs, 2);
	__atomic_store_n(&hyperv_time_initialized, HYPERV_TIME_QUIESCED,
			 __ATOMIC_RELEASE);
	return 0;
}

int hyperv_time_shutdown_error(void)
{
	return __atomic_load_n(&hyperv_shutdown_first_error,
			       __ATOMIC_ACQUIRE);
}

void ukplat_time_fini(void)
{
	int rc = hyperv_vmbus_shutdown();

	(void)hyperv_time_shutdown(0, !rc);
}

__u32 ukplat_time_get_irq(void)
{
	return __atomic_load_n(&hyperv_time_initialized, __ATOMIC_ACQUIRE) ==
		HYPERV_TIME_RUNNING ? hyperv_irqs[1] : UINT32_MAX;
}

int hyperv_vmbus_target_acquire(__u32 *vp_index, __u32 *generation)
{
	unsigned long flags;
	unsigned int index = 0;

	if (!vp_index || !generation)
		return -EINVAL;
	ukplat_spin_lock_irqsave(&hyperv_cpu_lock, flags);
	if (__atomic_load_n(&hyperv_cpus[index].state, __ATOMIC_ACQUIRE) ==
	    HYPERV_CPU_ONLINE) {
		hyperv_vp_refs[index]++;
		*vp_index = hyperv_cpus[index].vp_index;
		*generation = hyperv_cpus[index].generation;
		ukplat_spin_unlock_irqrestore(&hyperv_cpu_lock, flags);
		return 0;
	}
	ukplat_spin_unlock_irqrestore(&hyperv_cpu_lock, flags);
	return -ENODEV;
}

void hyperv_vmbus_target_release(__u32 vp_index, __u32 generation)
{
	unsigned long flags;
	unsigned int i;

	ukplat_spin_lock_irqsave(&hyperv_cpu_lock, flags);
	for (i = 0; i < CONFIG_UKPLAT_CPU_MAXCOUNT; i++) {
		if (hyperv_cpus[i].vp_index != vp_index ||
		    hyperv_cpus[i].generation != generation)
			continue;
		if (hyperv_vp_refs[i])
			hyperv_vp_refs[i]--;
		break;
	}
	ukplat_spin_unlock_irqrestore(&hyperv_cpu_lock, flags);
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

		{
			__u32 index;

			if (!hyperv_current_cpu_index(&index) &&
			    __atomic_exchange_n(&hyperv_pending_events[index],
						0, __ATOMIC_ACQ_REL))
				break;
		}
	}
}

#ifdef HYPERV_TIME_HOST_TEST
int hyperv_time_host_message_irq(void)
{
	return hyperv_message_irq(NULL);
}

int hyperv_time_host_timer_irq(void)
{
	return hyperv_timer_irq(NULL);
}

int hyperv_time_host_cpu_state(unsigned int index)
{
	if (index >= CONFIG_UKPLAT_CPU_MAXCOUNT)
		return -1;
	return __atomic_load_n(&hyperv_cpus[index].state, __ATOMIC_ACQUIRE);
}

int hyperv_time_host_runtime_state(void)
{
	return __atomic_load_n(&hyperv_time_initialized, __ATOMIC_ACQUIRE);
}

int hyperv_time_host_ap_start_state(void)
{
	return __atomic_load_n(&hyperv_ap_start_state, __ATOMIC_ACQUIRE);
}

int hyperv_time_host_ap_start_error(void)
{
	return __atomic_load_n(&hyperv_ap_start_error, __ATOMIC_ACQUIRE);
}

unsigned int hyperv_time_host_ap_requested(void)
{
	return __atomic_load_n(&hyperv_ap_requested, __ATOMIC_ACQUIRE);
}

unsigned int hyperv_time_host_ap_started(void)
{
	return __atomic_load_n(&hyperv_ap_started, __ATOMIC_ACQUIRE);
}

unsigned int hyperv_time_host_ap_waited(void)
{
	return __atomic_load_n(&hyperv_ap_waited, __ATOMIC_ACQUIRE);
}

unsigned int hyperv_time_host_ap_late(void)
{
	return __atomic_load_n(&hyperv_ap_late, __ATOMIC_ACQUIRE);
}

unsigned int hyperv_time_host_cpu_generation(unsigned int index)
{
	if (index >= CONFIG_UKPLAT_CPU_MAXCOUNT)
		return 0;
	return __atomic_load_n(&hyperv_cpus[index].generation,
			       __ATOMIC_ACQUIRE);
}

unsigned int hyperv_time_host_lifecycle_generation(void)
{
	return __atomic_load_n(&hyperv_cpu_generation, __ATOMIC_ACQUIRE);
}

unsigned int hyperv_time_host_vp_refs(unsigned int index)
{
	if (index >= CONFIG_UKPLAT_CPU_MAXCOUNT)
		return 0;
	return __atomic_load_n(&hyperv_vp_refs[index], __ATOMIC_ACQUIRE);
}

void *hyperv_time_host_simp_page(unsigned int index)
{
	return index < CONFIG_UKPLAT_CPU_MAXCOUNT ?
		hyperv_simp_pages[index] : NULL;
}
#endif
