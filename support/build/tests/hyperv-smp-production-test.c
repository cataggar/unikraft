/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>

#include <hyperv/hyperv.h>
#include <hyperv/cpu_lifecycle.h>
#include <uk/boot/smp.h>
#include <uk/config.h>
#include <uk/lcpu.h>

#define HOST_AP_IDLE		0
#define HOST_AP_STARTED		2
#define HOST_AP_FAILED		4
#define HOST_AP_QUARANTINED	5

_Thread_local uint64_t hyperv_host_cpu_index;

static uint32_t vp_indices[4] = { 3, 7, 8, 9 };
static unsigned int enable_count[4];
static unsigned int disable_count[4];
static void *message_pages[4];
static void *event_pages[4];
static uint64_t reference_time;
static int fail_enable_cpu = -1;
static int order;
static int vmbus_fini_order;
static int first_disable_order;
static pthread_mutex_t enable_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t enable_cond = PTHREAD_COND_INITIALIZER;
static int block_enable_cpu = -1;
static int enable_entered;
static int release_enable;
static unsigned char reference_page[4096] __attribute__((aligned(4096)));
static unsigned int host_cpu_count = 1;
static unsigned int start_calls;
static unsigned int host_start_limit;
static int host_start_error;
static int defer_start_cpu = -1;
static int deferred_start[4];
static int ap_init_result[4];
static int host_run_error;
static uintptr_t host_ap_entry;
static int host_boot_wait_error;
static unsigned int host_boot_wait_count;
static unsigned int host_boot_rollback_count;
static int host_boot_rollback_clean;

#define HOST_WAIT_STEPS 8
struct host_wait_step {
	int rc;
	int count;
	int release_cpu;
};
static struct host_wait_step host_wait_steps[HOST_WAIT_STEPS];
static unsigned int host_wait_step_count;
static unsigned int host_wait_calls;

void *hyperv_reference_tsc_page(void) { return reference_page; }
uint32_t hyperv_vp_index(void) { return vp_indices[hyperv_host_cpu_index]; }
uint32_t hyperv_max_vp_count(void) { return 64; }
int hyperv_x86_irq_to_vector(uint32_t irq, uint8_t *vector)
{
	*vector = (uint8_t)(32 + irq);
	return 0;
}
int hyperv_reference_tsc_enable(uint64_t gpa)
{
	return (gpa & 4095) ? HYPERV_SYNIC_BAD_PAGE : HYPERV_SYNIC_OK;
}
void hyperv_reference_tsc_disable(void) {}
int hyperv_synic_cpu_enable(uint64_t simp, uint64_t siefp,
			    uint8_t message_vector, uint8_t timer_vector)
{
	unsigned int cpu = (unsigned int)hyperv_host_cpu_index;

	assert(!(simp & 4095) && !(siefp & 4095));
	assert(message_vector != timer_vector);
	enable_count[cpu]++;
	pthread_mutex_lock(&enable_lock);
	if (block_enable_cpu == (int)cpu) {
		enable_entered = 1;
		pthread_cond_broadcast(&enable_cond);
		while (!release_enable)
			pthread_cond_wait(&enable_cond, &enable_lock);
	}
	pthread_mutex_unlock(&enable_lock);
	return fail_enable_cpu == (int)cpu ?
		HYPERV_SYNIC_MSR_REJECTED : HYPERV_SYNIC_OK;
}
void hyperv_synic_cpu_disable(void)
{
	unsigned int cpu = (unsigned int)hyperv_host_cpu_index;
	int sequence;
	int expected = 0;

	disable_count[cpu]++;
	sequence = __atomic_add_fetch(&order, 1, __ATOMIC_RELAXED);
	(void)__atomic_compare_exchange_n(&first_disable_order, &expected,
					 sequence, 0, __ATOMIC_RELAXED,
					 __ATOMIC_RELAXED);
}
void hyperv_stimer0_cancel(void) {}
void hyperv_stimer0_arm(uint64_t deadline __attribute__((unused))) {}
uint64_t hyperv_reference_time(void)
{
	return __atomic_add_fetch(&reference_time, 1, __ATOMIC_RELAXED);
}
uint64_t hyperv_deadline_reference_ticks(uint64_t boot, uint64_t deadline)
{
	return boot + deadline / 100;
}
int hyperv_synic_message_take_page(void *page, uint32_t sint,
				   struct hyperv_message *message
					   __attribute__((unused)))
{
	message_pages[hyperv_host_cpu_index] = page;
	return sint < 16 ? HYPERV_MESSAGE_EMPTY :
		HYPERV_MESSAGE_INVALID_SINT;
}
int hyperv_synic_event_take_word_page(void *page, uint32_t sint,
				      uint32_t word, uint64_t *value)
{
	event_pages[hyperv_host_cpu_index] = page;
	*value = 0;
	return sint < 16 && word < 32 ? 0 : -1;
}
void hyperv_vmbus_message(const struct hyperv_message *message
			  __attribute__((unused))) {}
void hyperv_vmbus_event(uint32_t event __attribute__((unused))) {}
void hyperv_vmbus_event_word(uint32_t base __attribute__((unused)),
			     uint64_t pending __attribute__((unused))) {}
void hyperv_vmbus_fini(void)
{
	vmbus_fini_order = __atomic_add_fetch(&order, 1, __ATOMIC_RELAXED);
}
void uk_lcpu_halt_irq(void) {}
void uk_lcpu_halt(void)
{
	pthread_exit(NULL);
	__builtin_unreachable();
}

struct host_run {
	uint64_t index;
	const struct uk_lcpu_func *fn;
};

static void *host_run_thread(void *arg)
{
	struct host_run *run = arg;

	hyperv_host_cpu_index = run->index;
	run->fn->fn(NULL, run->fn->user);
	return NULL;
}

int uk_lcpu_run(const uint64_t *indices, unsigned int *count,
		const struct uk_lcpu_func *fn, unsigned long flags
			__attribute__((unused)))
{
	struct host_run runs[4];
	pthread_t threads[4];
	unsigned int created = 0;

	if (host_run_error) {
		*count = 0;
		return host_run_error;
	}
	for (unsigned int i = 0; i < *count; i++) {
		runs[i].index = indices[i];
		runs[i].fn = fn;
		if (pthread_create(&threads[i], NULL, host_run_thread,
				   &runs[i])) {
			*count = created;
			return -EIO;
		}
		created++;
	}
	for (unsigned int i = 0; i < created; i++)
		pthread_join(threads[i], NULL);
	return 0;
}

int ukplat_lcpu_init_hook(void);
int uk_lcpu_wait(const uint64_t *indices __attribute__((unused)),
		 unsigned int *count,
		 uint64_t timeout __attribute__((unused)))
{
	unsigned int call = host_wait_calls++;
	uint64_t caller;
	int cpu;

	if (call >= host_wait_step_count)
		return 0;
	cpu = host_wait_steps[call].release_cpu;
	if (cpu >= 0) {
		assert(cpu < 4 && deferred_start[cpu]);
		caller = hyperv_host_cpu_index;
		hyperv_host_cpu_index = (uint64_t)cpu;
		deferred_start[cpu] = 0;
		ap_init_result[cpu] = ukplat_lcpu_init_hook();
		hyperv_host_cpu_index = caller;
	}
	if (host_wait_steps[call].count >= 0) {
		unsigned int completed =
			(unsigned int)host_wait_steps[call].count;

		if (completed > *count)
			completed = *count;
		*count = completed;
	}
	return host_wait_steps[call].rc;
}
unsigned int uk_acpi_cpu_count(void) { return host_cpu_count; }
void uk_boot_fixed_smp_lcpu_entry(struct uk_lcpu *lcpu __attribute__((unused)))
{
	abort();
}
int uk_boot_fixed_smp_wait_online(const uint64_t *indices,
				   unsigned int count)
{
	for (unsigned int i = 0; i < count; i++)
		assert(indices[i] == i + 1);
	host_boot_wait_count = count;
	return host_boot_wait_error;
}
void uk_boot_fixed_smp_rollback(const uint64_t *indices,
				unsigned int count, int clean)
{
	for (unsigned int i = 0; i < count; i++)
		assert(indices[i] == i + 1);
	host_boot_rollback_count = count;
	host_boot_rollback_clean = clean;
}
int uk_lcpu_start(const uint64_t *indices, unsigned int *count,
		  uintptr_t *stacks, uintptr_t *entries,
		  unsigned long flags __attribute__((unused)))
{
	uint64_t caller = hyperv_host_cpu_index;
	unsigned int requested = *count;

	for (unsigned int i = 0; i < requested; i++) {
		if (i == host_start_limit) {
			*count = i;
			hyperv_host_cpu_index = caller;
			return host_start_error;
		}
		assert(stacks[i]);
#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
		assert(entries);
		assert(entries[i] ==
		       (uintptr_t)uk_boot_fixed_smp_lcpu_entry);
		host_ap_entry = entries[i];
#else
		assert(!entries);
#endif
		assert(indices[i] < 4);
		start_calls++;
		if (defer_start_cpu == (int)indices[i]) {
			deferred_start[indices[i]] = 1;
			continue;
		}
		hyperv_host_cpu_index = indices[i];
		ap_init_result[indices[i]] = ukplat_lcpu_init_hook();
		hyperv_host_cpu_index = caller;
	}
	*count = requested;
	return 0;
}

void ukplat_time_init(void);
int ukplat_lcpu_startup_hook(void);
int hyperv_time_shutdown(int crash, int host_quiesced);
int hyperv_time_shutdown_error(void);
int hyperv_vmbus_target_acquire(uint32_t *, uint32_t *);
void hyperv_vmbus_target_release(uint32_t, uint32_t);
int hyperv_time_host_message_irq(void);
int hyperv_time_host_timer_irq(void);
int hyperv_time_host_cpu_state(unsigned int index);
int hyperv_time_host_runtime_state(void);
int hyperv_time_host_ap_start_state(void);
int hyperv_time_host_ap_start_error(void);
unsigned int hyperv_time_host_ap_requested(void);
unsigned int hyperv_time_host_ap_started(void);
unsigned int hyperv_time_host_ap_waited(void);
unsigned int hyperv_time_host_ap_late(void);
unsigned int hyperv_time_host_cpu_generation(unsigned int index);
unsigned int hyperv_time_host_lifecycle_generation(void);
unsigned int hyperv_time_host_vp_refs(unsigned int index);
void *hyperv_time_host_simp_page(unsigned int index);

static void reset_observations(void)
{
	for (unsigned int i = 0; i < 4; i++) {
		enable_count[i] = 0;
		disable_count[i] = 0;
		message_pages[i] = NULL;
		event_pages[i] = NULL;
		deferred_start[i] = 0;
		ap_init_result[i] = 0;
	}
	fail_enable_cpu = -1;
	block_enable_cpu = -1;
	enable_entered = 0;
	release_enable = 0;
	reference_time = 0;
	host_cpu_count = 1;
	start_calls = 0;
	host_start_limit = UINT_MAX;
	host_start_error = -EIO;
	defer_start_cpu = -1;
	host_run_error = 0;
	host_ap_entry = 0;
	host_boot_wait_error = 0;
	host_boot_wait_count = 0;
	host_boot_rollback_count = 0;
	host_boot_rollback_clean = -1;
	host_wait_step_count = 0;
	host_wait_calls = 0;
	for (unsigned int i = 0; i < HOST_WAIT_STEPS; i++) {
		host_wait_steps[i].rc = 0;
		host_wait_steps[i].count = -1;
		host_wait_steps[i].release_cpu = -1;
	}
	order = 0;
	vmbus_fini_order = 0;
	first_disable_order = 0;
}

static void assert_ap_offline(unsigned int cpu)
{
	assert(hyperv_time_host_cpu_state(cpu) == HYPERV_CPU_OFFLINE);
	assert(hyperv_time_host_cpu_generation(cpu) == 0);
	assert(hyperv_time_host_vp_refs(cpu) == 0);
}

static void assert_bsp_online(void)
{
	assert(hyperv_time_host_cpu_state(0) == HYPERV_CPU_ONLINE);
	assert(hyperv_time_host_cpu_generation(0) == 1);
	assert(hyperv_time_host_vp_refs(0) == 0);
	assert(enable_count[0] == 1 && disable_count[0] == 0);
}

static void test_single_cpu_startup_noop(void)
{
	reset_observations();
	hyperv_host_cpu_index = 0;
	ukplat_time_init();
	assert(ukplat_lcpu_startup_hook() == 0);
	assert(hyperv_time_host_ap_start_state() == HOST_AP_IDLE);
	assert(hyperv_time_host_ap_requested() == 0);
	assert(hyperv_time_host_ap_started() == 0);
	assert(hyperv_time_host_ap_waited() == 0);
	assert(start_calls == 0);
	assert_bsp_online();
	assert(hyperv_time_host_lifecycle_generation() == 1);
	assert(hyperv_time_shutdown(0, 1) == 0);
}

static void test_cpu_setup_routing_and_ap_shutdown(void)
{
	reset_observations();
	hyperv_host_cpu_index = 0;
	ukplat_time_init();
	{
		uint32_t vp;
		uint32_t generation;

		assert(hyperv_vmbus_target_acquire(&vp, &generation) == 0);
		assert(vp == 3 && generation);
		hyperv_vmbus_target_release(vp, generation);
	}
	assert(enable_count[0] == 1);

	host_cpu_count = 3;
	assert(ukplat_lcpu_startup_hook() == 0);
	assert(start_calls == 2);
#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
	assert(host_ap_entry == (uintptr_t)uk_boot_fixed_smp_lcpu_entry);
	assert(host_boot_wait_count == 2);
	assert(host_boot_rollback_count == 0);
#endif
	assert(enable_count[1] == 1);
	assert(enable_count[2] == 1);
	assert(hyperv_time_host_ap_start_state() == HOST_AP_STARTED);
	assert(hyperv_time_host_ap_requested() == 2);
	assert(hyperv_time_host_ap_started() == 2);
	assert(hyperv_time_host_ap_waited() == 2);
	assert(hyperv_time_host_ap_late() == 0);
	assert(hyperv_time_host_lifecycle_generation() == 3);
	for (unsigned int i = 0; i < 3; i++) {
		assert(hyperv_time_host_cpu_state(i) == HYPERV_CPU_ONLINE);
		assert(hyperv_time_host_cpu_generation(i) == i + 1);
		assert(hyperv_time_host_vp_refs(i) == 0);
	}
	{
		uint32_t vp[3];
		uint32_t generation[3];

		for (unsigned int i = 0; i < 3; i++)
			assert(hyperv_vmbus_target_acquire(
				       &vp[i], &generation[i]) == 0);
		assert(vp[0] == 3 && vp[1] == 3 && vp[2] == 3);
		for (unsigned int i = 0; i < 3; i++)
			hyperv_vmbus_target_release(vp[i], generation[i]);
	}
	hyperv_host_cpu_index = 2;
	/* Reinitializing an online CPU is idempotent for the same VP. */
	assert(ukplat_lcpu_init_hook() == 0);
	assert(hyperv_time_host_lifecycle_generation() == 3);

	hyperv_host_cpu_index = 0;
	assert(hyperv_time_host_message_irq() == 1);
	hyperv_host_cpu_index = 1;
	assert(hyperv_time_host_message_irq() == 1);
	assert(message_pages[0] != message_pages[1]);
	assert(message_pages[0] == hyperv_time_host_simp_page(0));
	assert(message_pages[1] == hyperv_time_host_simp_page(1));
	assert(event_pages[0] != event_pages[1]);

	/* Shutdown may originate on an AP; BSP and peer AP run local teardown. */
	order = 0;
	vmbus_fini_order = 0;
	first_disable_order = 0;
	assert(hyperv_vmbus_shutdown() == 0);
	assert(hyperv_time_shutdown(0, 1) == 0);
	assert(__atomic_load_n(&vmbus_fini_order, __ATOMIC_RELAXED) &&
	       __atomic_load_n(&vmbus_fini_order, __ATOMIC_RELAXED) <
		       __atomic_load_n(&first_disable_order,
				       __ATOMIC_RELAXED));
	assert(disable_count[0] && disable_count[1] && disable_count[2]);
	for (unsigned int i = 0; i < 3; i++)
		assert_ap_offline(i);
}

static void test_partial_ap_start_rollback(void)
{
	unsigned int attempts;

	reset_observations();
	hyperv_host_cpu_index = 0;
	ukplat_time_init();
	host_cpu_count = 3;
	host_start_limit = 1;
	host_start_error = -EIO;
	assert(ukplat_lcpu_startup_hook() == -EIO);
	assert(hyperv_time_host_ap_start_state() == HOST_AP_FAILED);
	assert(hyperv_time_host_ap_start_error() == -EIO);
	assert(hyperv_time_host_ap_requested() == 2);
	assert(hyperv_time_host_ap_started() == 1);
	assert(hyperv_time_host_ap_waited() == 0);
	assert(hyperv_time_host_ap_late() == 0);
#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
	assert(host_boot_rollback_count == 2);
	assert(host_boot_rollback_clean == 1);
#endif
	assert(start_calls == 1);
	assert(enable_count[1] == 1 && disable_count[1] == 1);
	assert(enable_count[2] == 0 && disable_count[2] == 0);
	assert_ap_offline(1);
	assert_ap_offline(2);
	assert_bsp_online();
	assert(hyperv_time_host_lifecycle_generation() == 2);

	attempts = start_calls;
	assert(ukplat_lcpu_startup_hook() == -EIO);
	assert(start_calls == attempts);
	assert(hyperv_time_shutdown(0, 1) == 0);
}

static void test_wait_timeout_rollback(void)
{
	unsigned int attempts;

	reset_observations();
	hyperv_host_cpu_index = 0;
	ukplat_time_init();
	host_cpu_count = 3;
	host_wait_step_count = 1;
	host_wait_steps[0].rc = -ETIMEDOUT;
	host_wait_steps[0].count = 1;
	assert(ukplat_lcpu_startup_hook() == -ETIMEDOUT);
	assert(hyperv_time_host_ap_start_state() == HOST_AP_FAILED);
	assert(hyperv_time_host_ap_start_error() == -ETIMEDOUT);
	assert(hyperv_time_host_ap_requested() == 2);
	assert(hyperv_time_host_ap_started() == 2);
	assert(hyperv_time_host_ap_waited() == 1);
	assert(hyperv_time_host_ap_late() == 0);
#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
	assert(host_boot_rollback_count == 2);
	assert(host_boot_rollback_clean == 1);
#endif
	assert(disable_count[1] == 1 && disable_count[2] == 1);
	assert_ap_offline(1);
	assert_ap_offline(2);
	assert_bsp_online();
	assert(hyperv_time_host_lifecycle_generation() == 3);

	attempts = start_calls;
	assert(ukplat_lcpu_startup_hook() == -ETIMEDOUT);
	assert(start_calls == attempts);
	assert(hyperv_time_shutdown(0, 1) == 0);
}

static void test_ap_init_failure_rollback(void)
{
	reset_observations();
	hyperv_host_cpu_index = 0;
	ukplat_time_init();
	host_cpu_count = 3;
	fail_enable_cpu = 2;
	assert(ukplat_lcpu_startup_hook() == -EIO);
	assert(ap_init_result[1] == 0);
	assert(ap_init_result[2] == -EIO);
	assert(hyperv_time_host_ap_start_state() == HOST_AP_FAILED);
	assert(hyperv_time_host_ap_requested() == 2);
	assert(hyperv_time_host_ap_started() == 2);
	assert(hyperv_time_host_ap_waited() == 2);
	assert(hyperv_time_host_ap_late() == 0);
#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
	assert(host_boot_rollback_count == 2);
	assert(host_boot_rollback_clean == 1);
#endif
	assert(enable_count[1] == 1 && disable_count[1] == 1);
	assert(enable_count[2] == 1 && disable_count[2] == 1);
	assert_ap_offline(1);
	assert_ap_offline(2);
	assert_bsp_online();
	assert(hyperv_time_host_lifecycle_generation() == 3);
	assert(hyperv_time_shutdown(0, 1) == 0);
}

static void test_late_ap_arrival_rollback(void)
{
	reset_observations();
	hyperv_host_cpu_index = 0;
	ukplat_time_init();
	host_cpu_count = 3;
	defer_start_cpu = 2;
	host_wait_step_count = 2;
	host_wait_steps[0].rc = -ETIMEDOUT;
	host_wait_steps[0].count = 1;
	host_wait_steps[1].release_cpu = 2;
	assert(ukplat_lcpu_startup_hook() == -ETIMEDOUT);
	assert(ap_init_result[1] == 0);
	assert(ap_init_result[2] == -ECANCELED);
	assert(hyperv_time_host_ap_start_state() == HOST_AP_FAILED);
	assert(hyperv_time_host_ap_requested() == 2);
	assert(hyperv_time_host_ap_started() == 2);
	assert(hyperv_time_host_ap_waited() == 1);
	assert(hyperv_time_host_ap_late() == 1);
#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
	assert(host_boot_rollback_count == 2);
	assert(host_boot_rollback_clean == 1);
#endif
	assert(enable_count[1] == 1 && disable_count[1] == 1);
	assert(enable_count[2] == 0 && disable_count[2] == 0);
	assert_ap_offline(1);
	assert_ap_offline(2);
	assert_bsp_online();
	assert(hyperv_time_host_lifecycle_generation() == 2);
	assert(hyperv_time_shutdown(0, 1) == 0);
}

static void test_rollback_stop_failure_quarantines(void)
{
	unsigned int attempts;

	reset_observations();
	hyperv_host_cpu_index = 0;
	ukplat_time_init();
	host_cpu_count = 2;
	host_wait_step_count = 1;
	host_wait_steps[0].rc = -ETIMEDOUT;
	host_wait_steps[0].count = 0;
	host_run_error = -EIO;
	assert(ukplat_lcpu_startup_hook() == -EIO);
	assert(hyperv_time_host_ap_start_state() == HOST_AP_QUARANTINED);
	assert(hyperv_time_host_ap_start_error() == -EIO);
	assert(hyperv_time_host_ap_requested() == 1);
	assert(hyperv_time_host_ap_started() == 1);
	assert(hyperv_time_host_ap_waited() == 0);
#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
	assert(host_boot_rollback_count == 1);
	assert(host_boot_rollback_clean == 0);
#endif
	assert(hyperv_time_host_cpu_state(1) == HYPERV_CPU_ONLINE);
	assert(hyperv_time_host_cpu_generation(1) == 2);
	assert(hyperv_time_host_vp_refs(1) == 0);
	assert(enable_count[1] == 1 && disable_count[1] == 0);
	assert_bsp_online();

	attempts = start_calls;
	assert(ukplat_lcpu_startup_hook() == -EIO);
	assert(start_calls == attempts);

	hyperv_host_cpu_index = 1;
	assert(ukplat_lcpu_init_hook() == -ECANCELED);
	assert(hyperv_time_host_ap_late() == 1);
	assert(enable_count[1] == 1 && disable_count[1] == 0);

	hyperv_host_cpu_index = 0;
	host_run_error = 0;
	assert(hyperv_time_shutdown(0, 1) == 0);
	assert(disable_count[1] == 1);
	assert_ap_offline(1);
}

#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
static void test_scheduler_readiness_failure_rolls_back(void)
{
	reset_observations();
	hyperv_host_cpu_index = 0;
	ukplat_time_init();
	host_cpu_count = 3;
	host_boot_wait_error = -EIO;
	assert(ukplat_lcpu_startup_hook() == -EIO);
	assert(host_boot_wait_count == 2);
	assert(host_boot_rollback_count == 2);
	assert(host_boot_rollback_clean == 1);
	assert(hyperv_time_host_ap_start_state() == HOST_AP_FAILED);
	assert(hyperv_time_host_ap_started() == 2);
	assert(hyperv_time_host_ap_waited() == 2);
	assert_ap_offline(1);
	assert_ap_offline(2);
	assert_bsp_online();
	assert(hyperv_time_shutdown(0, 1) == 0);
}
#endif

static void *startup_thread(void *arg __attribute__((unused)))
{
	hyperv_host_cpu_index = 0;
	return (void *)(intptr_t)ukplat_lcpu_startup_hook();
}

static void *shutdown_thread(void *arg __attribute__((unused)))
{
	hyperv_host_cpu_index = 0;
	return (void *)(intptr_t)hyperv_time_shutdown(0, 1);
}

static void test_startup_shutdown_race(void)
{
	pthread_t startup;
	pthread_t shutdown;
	void *startup_result;
	void *shutdown_result;

	reset_observations();
	hyperv_host_cpu_index = 0;
	ukplat_time_init();
	host_cpu_count = 2;
	block_enable_cpu = 1;
	assert(!pthread_create(&startup, NULL, startup_thread, NULL));
	pthread_mutex_lock(&enable_lock);
	while (!enable_entered)
		pthread_cond_wait(&enable_cond, &enable_lock);
	pthread_mutex_unlock(&enable_lock);
	assert(!pthread_create(&shutdown, NULL, shutdown_thread, NULL));
	while (hyperv_time_host_runtime_state() != 2)
		sched_yield();
	pthread_mutex_lock(&enable_lock);
	release_enable = 1;
	pthread_cond_broadcast(&enable_cond);
	pthread_mutex_unlock(&enable_lock);
	pthread_join(startup, &startup_result);
	pthread_join(shutdown, &shutdown_result);
	assert((intptr_t)startup_result == -ECANCELED);
	assert((intptr_t)shutdown_result == 0);
	assert(ap_init_result[1] == -ECANCELED);
	assert(hyperv_time_host_ap_late() == 1);
	assert(hyperv_time_host_cpu_state(1) == HYPERV_CPU_OFFLINE);
}

static void test_shutdown_failure_fails_forward(void)
{
	reset_observations();
	hyperv_host_cpu_index = 0;
	ukplat_time_init();
	host_cpu_count = 2;
	assert(ukplat_lcpu_startup_hook() == 0);
	host_run_error = -EIO;
	assert(hyperv_time_shutdown(0, 1) == 0);
	assert(hyperv_time_shutdown_error() == -EIO);
	assert(hyperv_time_host_runtime_state() == 3);
	assert(hyperv_time_shutdown(1, 0) == 0);
}

static void test_crash_keeps_pinned_pages_programmed(void)
{
	uint32_t vp;
	uint32_t generation;

	reset_observations();
	hyperv_host_cpu_index = 0;
	ukplat_time_init();
	assert(hyperv_vmbus_target_acquire(&vp, &generation) == 0);
	assert(hyperv_time_shutdown(1, 0) == 0);
	assert(hyperv_time_host_runtime_state() == 3);
	assert(disable_count[0] == 0);
	hyperv_vmbus_target_release(vp, generation);
}

int main(void)
{
	test_single_cpu_startup_noop();
	test_cpu_setup_routing_and_ap_shutdown();
	test_partial_ap_start_rollback();
	test_wait_timeout_rollback();
	test_ap_init_failure_rollback();
	test_late_ap_arrival_rollback();
	test_rollback_stop_failure_quarantines();
#if CONFIG_HYPERV_FIXED_SMP_WORKLOAD
	test_scheduler_readiness_failure_rolls_back();
#endif
	test_startup_shutdown_race();
	test_shutdown_failure_fails_forward();
	test_crash_keeps_pinned_pages_programmed();
	return 0;
}
