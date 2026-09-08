/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>

#include <hyperv/hyperv.h>
#include <hyperv/cpu_lifecycle.h>
#include <uk/lcpu.h>

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
static int host_run_error;
static int host_wait_error;

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

int uk_lcpu_wait(const uint64_t *indices __attribute__((unused)),
		 unsigned int *count __attribute__((unused)),
		 uint64_t timeout __attribute__((unused)))
{
	return host_wait_error;
}
unsigned int uk_acpi_cpu_count(void) { return host_cpu_count; }
int ukplat_lcpu_init_hook(void);
int uk_lcpu_start(const uint64_t *indices, unsigned int *count,
		  uintptr_t *stacks, uintptr_t *entries __attribute__((unused)),
		  unsigned long flags __attribute__((unused)))
{
	uint64_t caller = hyperv_host_cpu_index;

	for (unsigned int i = 0; i < *count; i++) {
		assert(stacks[i]);
		hyperv_host_cpu_index = indices[i];
		start_calls++;
		if (ukplat_lcpu_init_hook()) {
			*count = i;
			hyperv_host_cpu_index = caller;
			return -EIO;
		}
	}
	hyperv_host_cpu_index = caller;
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
void *hyperv_time_host_simp_page(unsigned int index);

static void reset_observations(void)
{
	for (unsigned int i = 0; i < 4; i++) {
		enable_count[i] = 0;
		disable_count[i] = 0;
		message_pages[i] = NULL;
		event_pages[i] = NULL;
	}
	fail_enable_cpu = -1;
	block_enable_cpu = -1;
	enable_entered = 0;
	release_enable = 0;
	reference_time = 0;
	host_cpu_count = 1;
	start_calls = 0;
	host_run_error = 0;
	host_wait_error = 0;
	order = 0;
	vmbus_fini_order = 0;
	first_disable_order = 0;
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
	assert(enable_count[1] == 1);
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
		assert(hyperv_time_host_cpu_state(i) == HYPERV_CPU_OFFLINE);
}

static void *ap_init_thread(void *arg __attribute__((unused)))
{
	hyperv_host_cpu_index = 1;
	return (void *)(intptr_t)ukplat_lcpu_init_hook();
}

static void *shutdown_thread(void *arg __attribute__((unused)))
{
	hyperv_host_cpu_index = 0;
	return (void *)(intptr_t)hyperv_time_shutdown(0, 1);
}

static void test_startup_shutdown_race(void)
{
	pthread_t ap;
	pthread_t shutdown;
	void *ap_result;
	void *shutdown_result;

	reset_observations();
	hyperv_host_cpu_index = 0;
	ukplat_time_init();
	block_enable_cpu = 1;
	assert(!pthread_create(&ap, NULL, ap_init_thread, NULL));
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
	pthread_join(ap, &ap_result);
	pthread_join(shutdown, &shutdown_result);
	assert((intptr_t)ap_result == -ECANCELED);
	assert((intptr_t)shutdown_result == 0);
	assert(hyperv_time_host_cpu_state(1) == HYPERV_CPU_OFFLINE);
}

static void test_partial_ap_setup_rollback(void)
{
	reset_observations();
	hyperv_host_cpu_index = 0;
	ukplat_time_init();
	hyperv_host_cpu_index = 1;
	fail_enable_cpu = 1;
	assert(ukplat_lcpu_init_hook() == -EIO);
	assert(hyperv_time_host_cpu_state(1) == HYPERV_CPU_OFFLINE);
	assert(enable_count[1] == 1 && disable_count[1] == 1);
	hyperv_host_cpu_index = 0;
	fail_enable_cpu = -1;
	assert(hyperv_time_shutdown(0, 1) == 0);
}

static void test_shutdown_failure_fails_forward(void)
{
	reset_observations();
	hyperv_host_cpu_index = 0;
	ukplat_time_init();
	hyperv_host_cpu_index = 1;
	assert(ukplat_lcpu_init_hook() == 0);
	hyperv_host_cpu_index = 0;
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
	test_cpu_setup_routing_and_ap_shutdown();
	test_partial_ap_setup_rollback();
	test_startup_shutdown_race();
	test_shutdown_failure_fails_forward();
	test_crash_keeps_pinned_pages_programmed();
	return 0;
}
