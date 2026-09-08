#pragma once
#include <stdint.h>
#include <uk/config.h>
#define __noreturn __attribute__((noreturn))
#define __weak __attribute__((weak))
#define unlikely(expr) (expr)
typedef uint64_t __u64;
struct uk_alloc;
struct uk_lcpu;
int uk_boot_fixed_smp_prepare(struct uk_alloc *, struct uk_alloc *,
			      struct uk_alloc *, unsigned int);
void __noreturn uk_boot_fixed_smp_lcpu_entry(struct uk_lcpu *);
int uk_boot_fixed_smp_wait_online(const __u64 *, unsigned int);
void uk_boot_fixed_smp_rollback(const __u64 *, unsigned int, int);
