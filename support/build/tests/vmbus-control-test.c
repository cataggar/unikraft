/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <errno.h>

#include "vmbus_lifecycle.h"
#include "vmbus_legacy_events.h"
#include "vmbus_channel_state.h"
#include "vmbus_channel_args.h"
#include "vmbus_event_route.h"
#include "vmbus_page_pool.h"
#include "vmbus_signal_policy.h"
#include "vmbus_queue.h"
#include "vmbus_release.h"
#include "vmbus_teardown.h"
#include "vmbus_worker_stop.h"

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

struct worker_stop_test {
	unsigned int waits;
	unsigned int wake_count;
	unsigned int present_checks;
	unsigned int clear_after;
	int schedulable;
	int irq_disabled;
	int locked;
	int worker_present;
	int self;
	int stop;
};

static int stop_can_wait(void *arg)
{
	struct worker_stop_test *test = arg;

	assert(!test->locked);
	return test->schedulable && !test->irq_disabled;
}

static void stop_lock(void *arg)
{
	struct worker_stop_test *test = arg;

	assert(!test->locked);
	test->locked = 1;
	/* Models ukplat_spin_lock_irqsave masking IRQs after the snapshot. */
	test->irq_disabled = 1;
}

static void stop_unlock(void *arg)
{
	struct worker_stop_test *test = arg;

	assert(test->locked);
	test->locked = 0;
}

static int stop_present_locked(void *arg)
{
	struct worker_stop_test *test = arg;

	assert(test->locked);
	return test->worker_present;
}

static int stop_is_self_locked(void *arg)
{
	struct worker_stop_test *test = arg;

	assert(test->locked);
	return test->self;
}

static void stop_set_locked(void *arg)
{
	struct worker_stop_test *test = arg;

	assert(test->locked);
	test->stop = 1;
}

static void stop_wake_locked(void *arg)
{
	struct worker_stop_test *test = arg;

	assert(test->locked);
	test->wake_count++;
}

static int stop_present(void *arg)
{
	struct worker_stop_test *test = arg;

	assert(!test->locked);
	test->present_checks++;
	return test->worker_present;
}

static void stop_wait(void *arg)
{
	struct worker_stop_test *test = arg;

	assert(!test->locked);
	test->waits++;
	if (test->waits == test->clear_after)
		test->worker_present = 0;
}

static const struct vmbus_worker_stop_ops worker_stop_test_ops = {
	.can_wait_before_lock = stop_can_wait,
	.lock = stop_lock,
	.unlock = stop_unlock,
	.worker_present_locked = stop_present_locked,
	.caller_is_worker_locked = stop_is_self_locked,
	.set_stop_locked = stop_set_locked,
	.wake_locked = stop_wake_locked,
	.worker_present = stop_present,
	.wait_once = stop_wait,
};

static void test_worker_stop_policy(void)
{
	struct worker_stop_test test = {
		.schedulable = 1,
		.worker_present = 1,
		.clear_after = 2,
	};

	assert(vmbus_worker_stop_run(&worker_stop_test_ops, &test, 4) ==
	       VMBUS_WORKER_STOP_JOINED);
	assert(test.stop && test.wake_count == 1 && test.waits == 2);
	assert(!test.locked && test.irq_disabled);

	test = (struct worker_stop_test){
		.schedulable = 1,
		.irq_disabled = 1,
		.worker_present = 1,
	};
	assert(vmbus_worker_stop_run(&worker_stop_test_ops, &test, 4) ==
	       VMBUS_WORKER_STOP_UNSCHEDULABLE);
	assert(test.stop && test.wake_count == 0 && test.waits == 0);

	test = (struct worker_stop_test){ .worker_present = 1 };
	assert(vmbus_worker_stop_run(&worker_stop_test_ops, &test, 4) ==
	       VMBUS_WORKER_STOP_UNSCHEDULABLE);
	assert(test.stop && test.waits == 0);

	test = (struct worker_stop_test){
		.schedulable = 1,
		.worker_present = 1,
		.self = 1,
	};
	assert(vmbus_worker_stop_run(&worker_stop_test_ops, &test, 4) ==
	       VMBUS_WORKER_STOP_SELF);
	assert(test.stop && test.wake_count == 0 && test.waits == 0);

	test = (struct worker_stop_test){
		.schedulable = 1,
		.worker_present = 1,
	};
	assert(vmbus_worker_stop_run(&worker_stop_test_ops, &test, 2) ==
	       VMBUS_WORKER_STOP_TIMED_OUT);
	assert(test.stop && test.wake_count == 1 && test.waits == 2);
}

static void test_channel_transaction_pool(void)
{
	struct vmbus_channel_transaction transactions[2] = { 0 };
	struct vmbus_channel_transaction *first;
	struct vmbus_channel_transaction *second;
	__u32 next = UINT32_MAX - 1;
	__u32 id;
	__u32 ignored = 0;

	first = vmbus_transaction_allocate(transactions, 2,
			VMBUS_TRANSACTION_GPADL_CREATE, 7, 100);
	second = vmbus_transaction_allocate(transactions, 2,
			VMBUS_TRANSACTION_OPEN, 7, 200);
	assert(first && second);
	assert(!vmbus_transaction_allocate(transactions, 2,
			VMBUS_TRANSACTION_OPEN, 8, 201));
	assert(vmbus_transaction_complete(transactions, 2,
			VMBUS_TRANSACTION_OPEN, 8, 200, 0) == -ENOENT);
	assert(vmbus_transaction_complete(transactions, 2,
			VMBUS_TRANSACTION_OPEN, 7, 200, 0) == 0);
	assert(second->done);
	assert(vmbus_transaction_complete(transactions, 2,
			VMBUS_TRANSACTION_OPEN, 7, 200, 0) == -EALREADY);
	assert(vmbus_transaction_timed_out(11, 10));
	assert(!vmbus_transaction_timed_out(10, 10));
	vmbus_transaction_release(first);
	assert(vmbus_transaction_allocate(transactions, 2,
			VMBUS_TRANSACTION_GPADL_TEARDOWN, 7, 100));
	assert(vmbus_transaction_cancel_channel(transactions, 2, 7,
			(__u32)-ECANCELED) == 2);

	assert(vmbus_monotonic_id_allocate(&next, &id) == 0);
	assert(id == UINT32_MAX - 1);
	assert(vmbus_monotonic_id_allocate(&next, &id) == 0);
	assert(id == UINT32_MAX && next == 0);
	assert(vmbus_monotonic_id_allocate(&next, &id) == -ENOSPC);
	assert(vmbus_transaction_completion_policy(-ENOENT, &ignored) == 0);
	assert(vmbus_transaction_completion_policy(-EALREADY, &ignored) == 0);
	assert(ignored == 2);
	assert(vmbus_transaction_completion_policy(-EPROTO, &ignored) ==
	       -EPROTO);
}

static void test_channel_lifecycle_races(void)
{
	__u8 state = CHANNEL_ALLOCATED;
	struct vmbus_rescind_plan plan;

	assert(vmbus_channel_state_open_begin(&state) == -EPROTO);
	assert(vmbus_channel_state_gpadl_created(&state) == 0);
	assert(vmbus_channel_state_open_begin(&state) == 0);
	assert(vmbus_channel_state_open_complete(&state, 1) == -EIO);
	assert(state == CHANNEL_GPADL);
	assert(vmbus_channel_state_open_begin(&state) == 0);
	vmbus_channel_state_rescind(&state);
	assert(vmbus_channel_state_open_complete(&state, 0) == -EPROTO);
	assert(vmbus_channel_state_close_begin(&state) == -EPROTO);

	plan = vmbus_channel_rescind_plan(CHANNEL_ALLOCATED, 0);
	assert(!plan.send_close && !plan.send_gpadl_teardown);
	plan = vmbus_channel_rescind_plan(CHANNEL_ALLOCATED, 1);
	assert(!plan.send_close && plan.send_gpadl_teardown);
	plan = vmbus_channel_rescind_plan(CHANNEL_GPADL, 1);
	assert(!plan.send_close && plan.send_gpadl_teardown);
	plan = vmbus_channel_rescind_plan(CHANNEL_OPENING, 1);
	assert(plan.send_close && plan.send_gpadl_teardown);
	plan = vmbus_channel_rescind_plan(CHANNEL_OPEN, 1);
	assert(plan.send_close && plan.send_gpadl_teardown);
	plan = vmbus_channel_rescind_plan(CHANNEL_CLOSING, 1);
	assert(!plan.send_close && plan.send_gpadl_teardown);
	plan = vmbus_channel_rescind_plan(CHANNEL_RESCINDED, 0);
	assert(!plan.send_close && !plan.send_gpadl_teardown);
}

static void test_ring_page_pool(void)
{
	unsigned char used[8] = { 0 };
	unsigned int first;
	unsigned int second;

	assert(vmbus_page_pool_allocate(used, 8, 4, &first) == 0);
	assert(first == 0);
	assert(vmbus_page_pool_allocate(used, 8, 4, &second) == 0);
	assert(second == 4);
	assert(vmbus_page_pool_allocate(used, 8, 1, &second) == -ENOSPC);
	vmbus_page_pool_free(used, 8, first, 4);
	assert(vmbus_page_pool_allocate(used, 8, 2, &second) == 0);
	assert(second == 0);
}

static void test_open_data_boundaries(void)
{
	unsigned char data[120] = { 0 };

	assert(vmbus_channel_validate_open_data(NULL, 0, sizeof(data)) == 0);
	assert(vmbus_channel_validate_open_data(NULL, 1, sizeof(data)) ==
	       -EINVAL);
	assert(vmbus_channel_validate_open_data(data, sizeof(data),
						 sizeof(data)) == 0);
	assert(vmbus_channel_validate_open_data(data, sizeof(data) + 1,
						 sizeof(data)) == -EINVAL);
}

static void test_signal_connection_policy(void)
{
	assert(vmbus_signal_connection_id(VMBUS_VERSION_WS2008, 99) == 2);
	assert(vmbus_signal_connection_id((1U << 16) | 1U, 99) == 99);
}

struct legacy_event_test {
	__u32 events[8];
	unsigned int count;
	__u64 *race_word;
};

static void collect_legacy_event(__u32 relid, void *arg)
{
	struct legacy_event_test *test = arg;

	test->events[test->count++] = relid;
	if (relid == 3 && test->race_word)
		__atomic_fetch_or(test->race_word, 1ULL << 9, __ATOMIC_RELEASE);
}

static void test_legacy_event_fanout(void)
{
	__u64 words[4] = {
		(1ULL << 0) | (1ULL << 3),
		1ULL << 5,
		0,
		1ULL << 63,
	};
	struct legacy_event_test test = {
		.race_word = &words[0],
	};

	assert(vmbus_legacy_event_scan(words, 4, 192,
			collect_legacy_event, &test) == 2);
	assert(test.count == 2 && test.events[0] == 3 &&
	       test.events[1] == 69);
	assert(words[0] == (1ULL << 9));
	assert(words[1] == 0 && words[3] == 0);
	test.race_word = NULL;
	assert(vmbus_legacy_event_scan(words, 4, 192,
			collect_legacy_event, &test) == 1);
	assert(test.events[2] == 9 && words[0] == 0);

	test = (struct legacy_event_test){ 0 };
	assert(vmbus_event_route(VMBUS_EVENT_VERSION_WIN8, 77, words, 4,
			192, collect_legacy_event, &test) == 1);
	assert(test.count == 1 && test.events[0] == 77);
	assert(vmbus_event_route(VMBUS_EVENT_VERSION_WIN8, 192, words, 4,
			192, collect_legacy_event, &test) == -ERANGE);
	assert(vmbus_event_route(VMBUS_EVENT_VERSION_WIN8, 0, words, 4,
			192, collect_legacy_event, &test) == -ERANGE);
	assert(vmbus_event_route(VMBUS_EVENT_VERSION_WIN8 - 1, 3, words, 4,
			192, collect_legacy_event, &test) == -EINVAL);
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
	test_worker_stop_policy();
	test_channel_transaction_pool();
	test_channel_lifecycle_races();
	test_ring_page_pool();
	test_open_data_boundaries();
	test_signal_connection_policy();
	test_legacy_event_fanout();
	return 0;
}
