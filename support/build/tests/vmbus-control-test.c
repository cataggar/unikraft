/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <errno.h>

#include "vmbus_lifecycle.h"
#include "vmbus_queue.h"
#include "vmbus_release.h"

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

int main(void)
{
	__u32 released[2] = { 0 };
	unsigned int released_count = 0;

	overflow_for_type(TEST_OFFER);
	overflow_for_type(TEST_RESCIND);
	overflow_for_type(TEST_ALL_OFFERS);

	assert(vmbus_release_claim(released, &released_count, 2, 17) == 0);
	/* A failed post keeps the claim and cannot generate a duplicate send. */
	assert(vmbus_release_claim(released, &released_count, 2, 17) == 1);
	assert(released_count == 1);
	assert(vmbus_release_claim(released, &released_count, 2, 18) == 0);
	assert(vmbus_release_claim(released, &released_count, 2, 19) ==
	       -ENOSPC);

	/* Offer-pool, enumeration-timeout, and worker-create failures. */
	test_probe_unwind(-ENOSPC);
	test_probe_unwind(-ETIMEDOUT);
	test_probe_unwind(-ENOMEM);
	test_unload_failure_still_resets();
	return 0;
}
