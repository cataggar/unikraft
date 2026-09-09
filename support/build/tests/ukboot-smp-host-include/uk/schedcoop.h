#pragma once
#include <uk/alloc.h>
#include <uk/sched.h>
struct uk_sched *uk_schedcoop_create_on(struct uk_alloc *, struct uk_alloc *,
					struct uk_alloc *, struct uk_alloc *,
					unsigned int);
void uk_schedcoop_fixed_destroy(struct uk_sched *);
