/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <errno.h>

#include "vmbus_lifecycle.h"
#include "vmbus_queue.h"
#include "vmbus_release.h"
#include "vmbus_teardown.h"

enum test_message_type {
	TEST_OFFER = 1,
	TEST_RESCIND = 2,
	TEST_ALL_OFFERS = 4,
};

static void overflow_for_type(enum test_message_type type)
{
	struct vmbus_queue_state queue = { 0 };
	__u32 tickets[2];
	__u32 ignored;

	assert(type == TEST_OFFER || type == TEST_RESCIND ||
	       type == TEST_ALL_OFFERS);
	assert(vmbus_queue_reserve(&queue, 2, &tickets[0]) == 0);
	vmbus_queue_commit(&queue, tickets[0]);
	assert(vmbus_queue_reserve(&queue, 2, &tickets[1]) == 0);
	vmbus_queue_commit(&queue, tickets[1]);
	assert(vmbus_queue_reserve(&queue, 2, &ignored) == -ENOSPC);
	assert(__atomic_load_n(&queue.lost, __ATOMIC_ACQUIRE) == 1);
	assert(vmbus_queue_reserve(&queue, 2, &ignored) == -EPIPE);
	vmbus_queue_recover(&queue);
	assert(__atomic_load_n(&queue.lost, __ATOMIC_ACQUIRE) == 0);
	assert(queue.head == queue.tail);
}

struct unwind_test {
	unsigned int order;
	unsigned int stopped;
	unsigned int removed;
	unsigned int unloaded;
	unsigned int drained;
	unsigned int reset;
	int unload_error;
};

static void stop_work(void *arg)
{
	struct unwind_test *test = arg;

	test->stopped = ++test->order;
}

static void remove_devices(void *arg)
{
	struct unwind_test *test = arg;

	test->removed = ++test->order;
}

static int unload(void *arg)
{
	struct unwind_test *test = arg;

	test->unloaded = ++test->order;
	return test->unload_error;
}

static void drain(void *arg)
{
	struct unwind_test *test = arg;

	test->drained = ++test->order;
}

static void reset(void *arg)
{
	struct unwind_test *test = arg;

	test->reset = ++test->order;
}

static void test_probe_unwind(int failure)
{
	static const struct vmbus_unwind_ops ops = {
		.stop_work = stop_work,
		.remove_devices = remove_devices,
		.unload = unload,
		.drain_queues = drain,
		.reset_protocol = reset,
	};
	struct unwind_test test = { 0 };

	assert(vmbus_probe_unwind_run(&ops, &test, failure) == failure);
	assert(test.stopped == 1);
	assert(test.removed == 2);
	assert(test.unloaded == 3);
	assert(test.drained == 4);
	assert(test.reset == 5);
}

static void test_unload_failure_still_resets(void)
{
	static const struct vmbus_unwind_ops ops = {
		.stop_work = stop_work,
		.remove_devices = remove_devices,
		.unload = unload,
		.drain_queues = drain,
		.reset_protocol = reset,
	};
	struct unwind_test test = {
		.unload_error = -EIO,
	};

	assert(vmbus_probe_unwind_run(&ops, &test, 0) == -EIO);
	assert(test.removed == 2);
	assert(test.drained == 4);
	assert(test.reset == 5);
}

struct teardown_test {
	unsigned int busy_attempts;
	unsigned int worker_checks;
	unsigned int waits;
	unsigned int stop_signals;
	unsigned int deactivations;
	unsigned int busy_until;
	unsigned int worker_until;
	int self;
	int owner;
	int rx_active;
	int worker_stop;
};

static void teardown_deactivate(void *arg)
{
	struct teardown_test *test = arg;

	test->deactivations++;
	test->rx_active = 0;
}

static void teardown_stop(void *arg, int can_schedule)
{
	struct teardown_test *test = arg;

	assert(can_schedule == 0 || can_schedule == 1);
	test->stop_signals++;
	test->worker_stop = 1;
}

static int teardown_acquire(void *arg)
{
	struct teardown_test *test = arg;

	return test->busy_attempts++ < test->busy_until ? -EBUSY : 0;
}

static int teardown_owner(void *arg)
{
	return ((struct teardown_test *)arg)->owner;
}

static int teardown_worker(void *arg)
{
	struct teardown_test *test = arg;

	return test->worker_checks++ < test->worker_until;
}

static int teardown_self(void *arg)
{
	return ((struct teardown_test *)arg)->self;
}

static void teardown_wait(void *arg)
{
	((struct teardown_test *)arg)->waits++;
}

static const struct vmbus_teardown_ops teardown_ops = {
	.deactivate_rx = teardown_deactivate,
	.signal_stop = teardown_stop,
	.try_acquire_control = teardown_acquire,
	.control_owned_by_caller = teardown_owner,
	.worker_present = teardown_worker,
	.caller_is_worker = teardown_self,
	.wait_once = teardown_wait,
};

static void test_bounded_teardown(void)
{
	struct teardown_test test = {
		.busy_until = 4,
		.rx_active = 1,
	};
	int acquired;

	assert(vmbus_teardown_enter(&teardown_ops, &test, 1, 2,
				    &acquired) == -EBUSY);
	assert(!acquired);
	assert(test.deactivations == 0 && test.stop_signals == 0);
	assert(test.rx_active == 1 && test.worker_stop == 0);
	assert(test.waits == 2);

	test = (struct teardown_test){ .worker_until = 10, .rx_active = 1 };
	assert(vmbus_teardown_enter(&teardown_ops, &test, 1, 2,
				    &acquired) == 0);
	assert(acquired);
	assert(test.deactivations == 1 && test.stop_signals == 1);
	assert(test.rx_active == 0 && test.worker_stop == 1);
	assert(test.waits == 2);
}

static void test_context_aware_teardown(void)
{
	struct teardown_test test = {
		.worker_until = 1,
		.self = 1,
		.rx_active = 1,
	};
	int acquired;

	assert(vmbus_teardown_enter(&teardown_ops, &test, 1, 2,
				    &acquired) == 0);
	assert(acquired);
	assert(test.waits == 0);
	assert(test.rx_active == 0 && test.worker_stop == 1);

	test = (struct teardown_test){ .worker_until = 1, .rx_active = 1 };
	assert(vmbus_teardown_enter(&teardown_ops, &test, 0, 2,
				    &acquired) == -EWOULDBLOCK);
	assert(!acquired);
	assert(test.deactivations == 0 && test.stop_signals == 0);
	assert(test.rx_active == 1 && test.worker_stop == 0);
	assert(test.waits == 0);

	test = (struct teardown_test){ .owner = 1, .rx_active = 1 };
	assert(vmbus_teardown_enter(&teardown_ops, &test, 1, 2,
				    &acquired) == -EDEADLK);
	assert(!acquired);
	assert(test.deactivations == 0 && test.stop_signals == 0);
	assert(test.rx_active == 1 && test.worker_stop == 0);

	test = (struct teardown_test){ .owner = 1, .rx_active = 1 };
	vmbus_teardown_final_fallback(&teardown_ops, &test);
	assert(test.deactivations == 1 && test.stop_signals == 1);
	assert(test.rx_active == 0 && test.worker_stop == 1);
	assert(test.busy_attempts == 0 && test.waits == 0);
}

static void test_relid_lifecycles(void)
{
	enum { CAPACITY = 2 };
	struct vmbus_relid_lifecycle entries[CAPACITY] = { 0 };
	__u64 sequence = 0;
	unsigned int id;

	assert(vmbus_relid_offer(entries, CAPACITY, 7, 1, &sequence) == 0);
	assert(vmbus_relid_release_begin(entries, CAPACITY, 7) == 0);
	vmbus_relid_release_finish(entries, CAPACITY, 7, 1, 0);
	assert(vmbus_relid_release_begin(entries, CAPACITY, 7) == -ENOENT);
	assert(vmbus_relid_offer(entries, CAPACITY, 7, 1, &sequence) == 0);
	assert(vmbus_relid_release_begin(entries, CAPACITY, 7) == 0);
	vmbus_relid_release_finish(entries, CAPACITY, 7, 1, 0);

	for (id = 1; id <= 32; id++) {
		assert(vmbus_relid_offer(entries, CAPACITY, id, 1,
					 &sequence) == 0);
		assert(vmbus_relid_release_begin(entries, CAPACITY, id) == 0);
		vmbus_relid_release_finish(entries, CAPACITY, id, 1, 0);
	}

	/* Rejected/no-slot tombstones are deterministically recycled. */
	for (id = 40; id < 48; id++) {
		assert(vmbus_relid_offer(entries, CAPACITY, id, 0,
					 &sequence) == 0);
		assert(vmbus_relid_release_begin(entries, CAPACITY, id) == 0);
		vmbus_relid_release_finish(entries, CAPACITY, id, 1, 1);
	}
	assert(vmbus_relid_offer(entries, CAPACITY, 100, 1, &sequence) == 0);

	entries[0] = (struct vmbus_relid_lifecycle){ 0 };
	entries[1] = (struct vmbus_relid_lifecycle){ 0 };
	assert(vmbus_relid_offer(entries, CAPACITY, 55, 0, &sequence) == 0);
	assert(vmbus_relid_release_begin(entries, CAPACITY, 55) == 0);
	vmbus_relid_release_finish(entries, CAPACITY, 55, 1, 1);
	assert(vmbus_relid_offer(entries, CAPACITY, 55, 0, &sequence) == 1);
	assert(vmbus_relid_release_begin(entries, CAPACITY, 55) == 1);
	assert(vmbus_relid_offer(entries, CAPACITY, 55, 1, &sequence) == 0);
	assert(vmbus_relid_release_begin(entries, CAPACITY, 55) == 0);
	vmbus_relid_release_finish(entries, CAPACITY, 55, 1, 0);

	entries[0] = (struct vmbus_relid_lifecycle){ 0 };
	entries[1] = (struct vmbus_relid_lifecycle){ 0 };
	assert(vmbus_relid_offer(entries, CAPACITY, 70, 0, &sequence) == 0);
	assert(vmbus_relid_release_begin(entries, CAPACITY, 70) == 0);
	vmbus_relid_release_finish(entries, CAPACITY, 70, 0, 1);
	assert(vmbus_relid_offer(entries, CAPACITY, 71, 0, &sequence) == 0);
	assert(vmbus_relid_release_begin(entries, CAPACITY, 71) == 0);
	vmbus_relid_release_finish(entries, CAPACITY, 71, 0, 1);
	assert(vmbus_relid_offer(entries, CAPACITY, 72, 1, &sequence) ==
	       -ENOSPC);
	assert(vmbus_relid_release_begin(entries, CAPACITY, 70) == 0);
}

int main(void)
{
	overflow_for_type(TEST_OFFER);
	overflow_for_type(TEST_RESCIND);
	overflow_for_type(TEST_ALL_OFFERS);

	/* Offer-pool, enumeration-timeout, and worker-create failures. */
	test_probe_unwind(-ENOSPC);
	test_probe_unwind(-ETIMEDOUT);
	test_probe_unwind(-ENOMEM);
	test_unload_failure_still_resets();
	test_bounded_teardown();
	test_context_aware_teardown();
	test_relid_lifecycles();
	return 0;
}
