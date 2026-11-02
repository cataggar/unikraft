#pragma once
#include <stdint.h>

struct uk_lcpu;

void uk_boot_fixed_smp_lcpu_entry(struct uk_lcpu *lcpu)
	__attribute__((noreturn));
int uk_boot_fixed_smp_wait_online(const uint64_t *indices,
				   unsigned int count);
void uk_boot_fixed_smp_rollback(const uint64_t *indices,
				unsigned int count, unsigned int attempted);
