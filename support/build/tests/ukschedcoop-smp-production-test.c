/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stddef.h>

#include <uk/sched/fixed.h>
#include <uk/schedcoop/fixed.h>

struct idle_race {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct uk_schedcoop_fixed_guard guard;
	unsigned int membership;
	unsigned int stage;
};

static void *idle_arm(void *arg)
{
	struct idle_race *race = arg;

	pthread_mutex_lock(&race->lock);
	assert(uk_schedcoop_idle_prepare(&race->guard));
	race->stage = 1;
	pthread_cond_broadcast(&race->cond);
	while (race->stage != 2)
		pthread_cond_wait(&race->cond, &race->lock);
	assert(race->guard.idle_armed == 0);
	assert(race->guard.run_count == 1);
	uk_schedcoop_run_take(&race->guard, &race->membership);
	pthread_mutex_unlock(&race->lock);
	return NULL;
}

static void *remote_publish(void *arg)
{
	struct idle_race *race = arg;

	pthread_mutex_lock(&race->lock);
	while (race->stage != 1)
		pthread_cond_wait(&race->cond, &race->lock);
	assert(uk_schedcoop_run_publish(&race->guard, &race->membership));
	assert(!uk_schedcoop_run_publish(&race->guard, &race->membership));
	race->stage = 2;
	pthread_cond_broadcast(&race->cond);
	pthread_mutex_unlock(&race->lock);
	return NULL;
}

static void test_exact_queue_membership(void)
{
	struct uk_schedcoop_fixed_guard guard = { 0 };
	unsigned int membership = UK_SCHEDCOOP_QUEUE_NONE;

	guard.idle_armed = 1;
	assert(uk_schedcoop_run_publish(&guard, &membership));
	assert(!uk_schedcoop_run_publish(&guard, &membership));
	assert(guard.run_count == 1);
	assert(guard.sleep_count == 0);
	assert(guard.idle_armed == 0);
	uk_schedcoop_run_take(&guard, &membership);
	assert(guard.run_count == 0);

	uk_schedcoop_sleep_publish(&guard, &membership);
	assert(guard.sleep_count == 1);
	uk_schedcoop_sleep_take(&guard, &membership);
	assert(guard.sleep_count == 0);
	assert(membership == UK_SCHEDCOOP_QUEUE_NONE);
}

static void test_idle_lost_wake_window(void)
{
	for (unsigned int i = 0; i < 64; i++) {
		struct idle_race race = {
			.lock = PTHREAD_MUTEX_INITIALIZER,
			.cond = PTHREAD_COND_INITIALIZER,
		};
		pthread_t idle;
		pthread_t wake;

		assert(!pthread_create(&idle, NULL, idle_arm, &race));
		assert(!pthread_create(&wake, NULL, remote_publish, &race));
		assert(!pthread_join(idle, NULL));
		assert(!pthread_join(wake, NULL));
		assert(race.guard.run_count == 0);
		assert(race.membership == UK_SCHEDCOOP_QUEUE_NONE);
		pthread_cond_destroy(&race.cond);
		pthread_mutex_destroy(&race.lock);
	}
}

static void test_publish_kick_failure_retry(void)
{
	unsigned int state = UK_SCHEDCOOP_WORK_IDLE;
	unsigned int kick_attempts = 0;
	int kick_rc = -EAGAIN;

	assert(uk_schedcoop_work_reserve(&state));
	assert(!uk_schedcoop_work_reserve(&state));
	uk_schedcoop_work_commit(&state);
	assert(state == UK_SCHEDCOOP_WORK_QUEUED);

	/* A failed doorbell never rolls committed work back to IDLE. */
	while (kick_attempts++ < 3) {
		assert(state == UK_SCHEDCOOP_WORK_QUEUED);
		if (kick_attempts == 3)
			kick_rc = 0;
	}
	assert(kick_rc == 0);
	assert(uk_schedcoop_work_take(&state));
	assert(!uk_schedcoop_work_take(&state));
	uk_schedcoop_work_complete(&state);
	assert(state == UK_SCHEDCOOP_WORK_DONE);
	uk_schedcoop_work_reap(&state);
	assert(state == UK_SCHEDCOOP_WORK_IDLE);
}

struct kick_fixture {
	unsigned int calls;
	unsigned int fail_count;
	int error;
};

static int kick_once(void *arg)
{
	struct kick_fixture *fixture = arg;

	fixture->calls++;
	if (fixture->calls <= fixture->fail_count)
		return fixture->error;
	return 0;
}

static void test_bounded_kick_retry(void)
{
	struct kick_fixture transient = {
		.fail_count = 2,
		.error = -EAGAIN,
	};
	struct kick_fixture permanent = {
		.fail_count = 8,
		.error = -EIO,
	};

	assert(uk_sched_kick_bounded(kick_once, &transient, 3) == 0);
	assert(transient.calls == 3);
	assert(uk_sched_kick_bounded(kick_once, &permanent, 3) == -EIO);
	assert(permanent.calls == 3);
	assert(uk_sched_kick_bounded(kick_once, &permanent, 0) == -EINVAL);
	assert(permanent.calls == 3);
}

static void test_publish_before_idle_arm(void)
{
	struct uk_schedcoop_fixed_guard guard = { 0 };
	unsigned int membership = UK_SCHEDCOOP_QUEUE_NONE;

	assert(uk_schedcoop_run_publish(&guard, &membership));
	assert(!uk_schedcoop_idle_prepare(&guard));
	assert(guard.idle_armed == 0);
	uk_schedcoop_run_take(&guard, &membership);
	assert(uk_schedcoop_idle_prepare(&guard));
}

int main(void)
{
	test_exact_queue_membership();
	test_publish_before_idle_arm();
	test_idle_lost_wake_window();
	test_publish_kick_failure_retry();
	test_bounded_kick_retry();
	return 0;
}
