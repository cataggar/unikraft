#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <uk/alloc.h>
struct uk_sched;
struct uk_thread {
	uintptr_t tlsp;
	uintptr_t auxsp;
	struct uk_sched *sched;
};
struct uk_thread *uk_thread_create_container(
	struct uk_alloc *, struct uk_alloc *, size_t, struct uk_alloc *,
	size_t, struct uk_alloc *, bool, const char *, void *, void *);
void uk_thread_release(struct uk_thread *);
void uk_thread_block(struct uk_thread *);
