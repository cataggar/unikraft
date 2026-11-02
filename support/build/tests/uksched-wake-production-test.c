/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#include <uk/sched.h>
#include <uk/thread.h>

unsigned int uksched_wake_host_cpu_idx;

static struct uk_sched target_sched;
static struct uk_thread *live_thread;
static size_t page_size;
static unsigned int wake_callbacks;
static unsigned int kick_calls;
static unsigned int retry_calls;
static int kick_error;

unsigned long uk_lcpu_save_irqf(void)
{
	return 0;
}

void uk_lcpu_restore_irqf(unsigned long flags)
{
	assert(flags == 0);
}

void uksched_wake_host_lock(__spinlock *lock)
{
	assert(!lock->held);
	lock->held = 1;
}

void uksched_wake_host_unlock(__spinlock *lock)
{
	assert(lock->held);
	lock->held = 0;
}

void uk_sched_thread_woken(struct uk_thread *thread)
{
	assert(target_sched.lock.held);
	assert(thread == live_thread);
	assert(thread->sched == &target_sched);
	wake_callbacks++;
}

unsigned int uk_sched_state(const struct uk_sched *sched)
{
	assert(sched == &target_sched);
	return sched->state;
}

int uk_sched_kick(struct uk_sched *sched)
{
	assert(sched == &target_sched);
	assert(live_thread);
	kick_calls++;

	/*
	 * Model the destination selecting, terminating, and reclaiming the
	 * newly runnable thread before the failed kick returns.
	 */
	assert(munmap(live_thread, page_size) == 0);
	live_thread = NULL;
	return kick_error;
}

int uk_sched_kick_retry(struct uk_sched *sched, unsigned int attempts)
{
	assert(sched == &target_sched);
	assert(!live_thread);
	assert(attempts == UK_SCHED_KICK_RETRIES_DEFAULT);
	retry_calls++;
	return 0;
}

static struct uk_thread *new_thread(unsigned int flags)
{
	struct uk_thread *thread;

	thread = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(thread != MAP_FAILED);
	thread->sched = &target_sched;
	thread->flags = flags;
	thread->wakeup_time = 123;
	live_thread = thread;
	return thread;
}

static void test_retry_uses_captured_scheduler(void)
{
	struct uk_thread *thread = new_thread(0);

	kick_error = -EAGAIN;
	uk_thread_wake(thread);
	assert(!live_thread);
	assert(wake_callbacks == 1);
	assert(kick_calls == 1);
	assert(retry_calls == 1);
}

static void test_published_entry_does_not_retouch_thread(void)
{
	struct uk_thread *thread = new_thread(0);
	int published = 0;

	kick_error = -EIO;
	assert(uk_thread_wake_published(thread, &published) == -EIO);
	assert(published == 1);
	assert(!live_thread);
	assert(wake_callbacks == 2);
	assert(kick_calls == 2);
	assert(retry_calls == 1);
}

int main(void)
{
	long size = sysconf(_SC_PAGESIZE);

	assert(size > 0);
	page_size = (size_t)size;
	target_sched.lcpu_idx = 1;
	target_sched.state = UK_SCHED_ONLINE;
	uksched_wake_host_cpu_idx = 0;

	test_retry_uses_captured_scheduler();
	test_published_entry_does_not_retouch_thread();
	return 0;
}
