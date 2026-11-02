/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <stdio.h>
#include <uk/arch/time.h>
#include <uk/lcpu.h>
#include <uk/pcpuvar.h>
#include <uk/plat/time.h>
#include <uk/sched.h>
#include <uk/schedcoop.h>
#include <uk/thread.h>

#define WORK_CPU	1U
#define WORK_ROUNDS	16U
#define WORK_TIMEOUT_NS	(5ULL * 1000ULL * 1000ULL * 1000ULL)
#define WORK_SLEEP_NS	(1ULL * 1000ULL * 1000ULL)
#define KICK_RETRIES	8U

struct workload_state {
	unsigned int expected_round;
	unsigned int completed_rounds;
	unsigned int ap_exec;
	uintptr_t ap_tls;
	uintptr_t bsp_tls;
	int error;
};

static struct workload_state workload;
static __thread unsigned int workload_tls;

static void ap_exec_probe(struct uk_lcpu_regs *regs __unused, void *arg)
{
	struct workload_state *state = arg;

	__atomic_store_n(&state->ap_exec,
		(unsigned int)uk_lcpu_get_current_idx_in_except(),
		__ATOMIC_RELEASE);
}

static int scheduled_work(void *arg)
{
	struct workload_state *state = arg;
	struct uk_sched *sched = uk_sched_current();
	unsigned int round = __atomic_load_n(&state->expected_round,
					     __ATOMIC_ACQUIRE);
	uintptr_t tls_addr = (uintptr_t)&workload_tls;

	if (!sched || !uk_thread_current() ||
	    uk_sched_lcpu(sched) != WORK_CPU ||
	    uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx) != WORK_CPU ||
	    tls_addr == state->bsp_tls) {
		state->error = -EINVAL;
		return state->error;
	}
	if (!state->ap_tls)
		state->ap_tls = tls_addr;
	if (state->ap_tls != tls_addr || workload_tls + 1 != round) {
		state->error = -EUCLEAN;
		return state->error;
	}

	workload_tls = round;
	uk_sched_thread_sleep(WORK_SLEEP_NS);
	if (workload_tls != round) {
		state->error = -EIO;
		return state->error;
	}
	__atomic_store_n(&state->completed_rounds, round, __ATOMIC_RELEASE);
	return 0;
}

static int wait_ap_idle(__nsec deadline)
{
	while (!uk_schedcoop_fixed_idle_armed(WORK_CPU)) {
		if (ukplat_monotonic_clock() >= deadline)
			return -ETIMEDOUT;
		uk_sched_yield();
	}
	return 0;
}

static int fail(const char *stage, int rc)
{
	printf("UK_HYPERV_SMP_WORKLOAD_FAIL:%s:%d\n", stage, rc);
	return 1;
}

int main(void)
{
	const __u64 ap = WORK_CPU;
	const struct uk_lcpu_func ap_fn = {
		.fn = ap_exec_probe,
		.user = &workload,
	};
	unsigned int count;
	unsigned int round;
	int completion_kick_error;
	int published;
	int work_result;
	int rc;

	workload.bsp_tls = (uintptr_t)&workload_tls;

	count = 1;
	rc = uk_lcpu_run(&ap, &count, &ap_fn, 0);
	if (rc || count != 1)
		return fail("AP_EXEC_SUBMIT", rc ? rc : -EIO);
	count = 1;
	rc = uk_lcpu_wait(&ap, &count, WORK_TIMEOUT_NS);
	if (rc || count != 1 ||
	    __atomic_load_n(&workload.ap_exec, __ATOMIC_ACQUIRE) != WORK_CPU)
		return fail("AP_EXEC_WAIT", rc ? rc : -EIO);
	printf("UK_HYPERV_AP_EXEC PASS cpu=%u\n", WORK_CPU);

	for (round = 1; round <= WORK_ROUNDS; ++round) {
		rc = wait_ap_idle(ukplat_monotonic_clock() + WORK_TIMEOUT_NS);
		if (rc)
			return fail("IDLE_ARM", rc);

		__atomic_store_n(&workload.expected_round, round,
				 __ATOMIC_RELEASE);
		rc = uk_schedcoop_fixed_submit(WORK_CPU, scheduled_work,
					       &workload, &published);
		if (rc) {
			if (!published)
				return fail("REMOTE_PUBLISH", rc);
			rc = uk_sched_kick_retry(uk_sched_get_lcpu(WORK_CPU),
						 KICK_RETRIES);
			if (rc)
				return fail("REMOTE_KICK", rc);
		}

		rc = uk_schedcoop_fixed_wait(
			WORK_CPU, ukplat_monotonic_clock() + WORK_TIMEOUT_NS,
			&work_result, &completion_kick_error);
		if (rc || work_result || completion_kick_error)
			return fail("REMOTE_COMPLETE",
				    rc ? rc :
				    (work_result ? work_result :
				     completion_kick_error));
		if (__atomic_load_n(&workload.completed_rounds,
				    __ATOMIC_ACQUIRE) != round)
			return fail("REMOTE_SEQUENCE", -EIO);
	}

	printf("UK_HYPERV_SCHED_THREAD PASS cpu=%u tls=%p rounds=%u\n",
	       WORK_CPU, (void *)workload.ap_tls, WORK_ROUNDS);
	printf("UK_HYPERV_REMOTE_WAKE PASS cpu=%u rounds=%u\n",
	       WORK_CPU, WORK_ROUNDS);
	printf("UK_HYPERV_SMP_WORKLOAD_READY PASS\n");
	return 0;
}
