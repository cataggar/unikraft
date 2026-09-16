/* SPDX-License-Identifier: BSD-3-Clause */
#include "platform.h"
#include <errno.h>
#include <string.h>
#include <uk/falloc.h>
#include <uk/lcpu.h>

#define PAGE 4096UL
#define CHECK(test) do { if (!(test)) { result = __LINE__; goto out; } } while (0)

struct pressure {
	struct uk_falloc proxy;
	struct uk_falloc *real;
	size_t remaining;
	long outstanding;
	int free_error;
};

static int pressure_alloc(struct uk_falloc *fa, __paddr_t *address,
			   unsigned long pages, unsigned long flags)
{
	struct pressure *s = (struct pressure *)fa;
	int rc;

	if (!s->remaining) {
		*address = UK_PAGING_PADDR_INV;
		return -ENOMEM;
	}
	s->remaining--;
	rc = s->real->falloc(s->real, address, pages, flags);
	if (!rc)
		s->outstanding += pages;
	return rc;
}

static int pressure_free(struct uk_falloc *fa, __paddr_t address,
			  unsigned long pages)
{
	struct pressure *s = (struct pressure *)fa;
	int rc = s->real->ffree(s->real, address, pages);

	if (rc)
		s->free_error = rc;
	else
		s->outstanding -= pages;
	return rc;
}

int wamr_platform_selftest(struct wamr_platform *p, wamr_aot_config *c)
{
	const size_t length = 4 * 1024 * 1024;
	const size_t budgets[] = { 0, 1, 2, 3, 4, 5, 509, 510, 511, 512, 513, 514 };
	void *aligned;
	unsigned char *memory = NULL;
	unsigned long irq;
	struct pressure s = { 0 };
	long prior;
	size_t budget, i;
	int result = 0;

	aligned = c->alloc(p, 129, 8192);
	if (!aligned || (uintptr_t)aligned % 8192)
		return __LINE__;
	c->free(p, aligned, 129, 8192);
	if (p->allocation_bytes)
		return __LINE__;
	/* Reserve before interposing: allocator heap growth is not guest frames. */
	memory = c->reserve(p, length);
	if (!memory)
		return __LINE__;
	s.real = p->pt->fa;
	s.proxy.falloc = pressure_alloc;
	s.proxy.ffree = pressure_free;
	s.remaining = SIZE_MAX;
	/* The image has one CPU. Restore both IRQ state and the allocator on
	 * every exit; no injected callback escapes this native self-test. */
	irq = uk_lcpu_save_irqf();
	p->pt->fa = &s.proxy;
	CHECK(wamr_platform_permissions(p, memory, WAMR_AOT_NONE));
	CHECK(c->commit(p, memory, PAGE) == 0);
	CHECK(wamr_platform_permissions(p, memory, WAMR_AOT_RW));
	for (i = 0; i < PAGE; i++)
		CHECK(memory[i] == 0);
	memset(memory, 0xa5, PAGE);
	prior = s.outstanding;
	/* Cross a 2 MiB page-table boundary. Real frame and intermediate-table
	 * allocations fail both early and around the next leaf-table boundary. */
	for (budget = 0; budget < sizeof(budgets) / sizeof(budgets[0]); budget++) {
		s.remaining = budgets[budget];
		CHECK(c->commit(p, memory + PAGE, length - PAGE) != 0);
		CHECK(s.outstanding == prior && !s.free_error);
		CHECK(p->frame_bytes == PAGE && p->accessible_bytes == PAGE);
		CHECK(p->reserved_bytes == length);
		for (i = 0; i < PAGE; i++)
			CHECK(memory[i] == 0xa5);
		CHECK(wamr_platform_permissions(p, memory + PAGE, WAMR_AOT_NONE));
	}
	s.remaining = SIZE_MAX;
	CHECK(c->commit(p, memory + PAGE, PAGE) == 0);
	CHECK(c->protect(p, memory, PAGE, WAMR_AOT_RX) == 0);
	CHECK(wamr_platform_permissions(p, memory, WAMR_AOT_RX));
	CHECK(memory[0] == 0xa5);
	CHECK(c->protect(p, memory, PAGE, 3) != 0);
	CHECK(wamr_platform_permissions(p, memory, WAMR_AOT_RX));
	CHECK(c->protect(p, memory, PAGE, WAMR_AOT_NONE) == 0);
	CHECK(wamr_platform_permissions(p, memory, WAMR_AOT_NONE));
	CHECK(p->frame_bytes == 2 * PAGE && p->accessible_bytes == PAGE);
	CHECK(c->protect(p, memory, PAGE, WAMR_AOT_RW) == 0);
	CHECK(memory[0] == 0xa5);
	CHECK(c->protect(p, memory, 2 * PAGE, WAMR_AOT_NONE) == 0);
	prior = s.outstanding;
	s.remaining = 0;
	CHECK(c->commit(p, memory, 3 * PAGE) != 0);
	CHECK(s.outstanding == prior && !s.free_error);
	CHECK(p->accessible_bytes == 0 && p->frame_bytes == 2 * PAGE);
	CHECK(wamr_platform_permissions(p, memory, WAMR_AOT_NONE));
	CHECK(c->protect(p, memory, PAGE, WAMR_AOT_RW) == 0);
	CHECK(memory[0] == 0xa5);
	CHECK(c->protect(p, memory, PAGE, WAMR_AOT_NONE) == 0);
	s.remaining = SIZE_MAX;
	CHECK(c->commit(p, memory, PAGE) == 0);
	for (i = 0; i < PAGE; i++)
		CHECK(memory[i] == 0);
	CHECK(c->protect(p, memory, PAGE, WAMR_AOT_NONE) == 0);
	/* Release also works under complete frame/page-table allocation denial,
	 * with retained NONE pages and a never-committed suffix. */
	s.remaining = 0;
out:
	c->unmap(p, memory, length);
	p->pt->fa = s.real;
	uk_lcpu_restore_irqf(irq);
	if (!result && (s.outstanding || s.free_error || p->reserved_bytes ||
			p->frame_bytes || p->accessible_bytes ||
			p->allocation_bytes || p->mappings))
		result = __LINE__;
	return result;
}
