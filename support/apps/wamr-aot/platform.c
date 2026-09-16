/* SPDX-License-Identifier: BSD-3-Clause */
#include "platform.h"
#include <errno.h>
#include <string.h>
#include <uk/alloc.h>
#include <uk/assert.h>
#include <uk/arch/x86_64.h>
#include <uk/paging.h>
#include <uk/plat/time.h>
#include <uk/vmem.h>

#if !CONFIG_ARCH_X86_64 || !CONFIG_PLAT_HYPERV || \
	!CONFIG_LIBUKPLAT_NATIVE_PAGING || !CONFIG_LIBUKFALLOCBUDDY || \
	!CONFIG_LIBUKVMEM || !CONFIG_LIBUKPAGING_DIRECTMAP || \
	CONFIG_LIBUKPAGING_5LEVEL || CONFIG_UKPLAT_CPU_MAXCOUNT != 1
#error "WAMR adapter requires native x86_64 Hyper-V paging, buddy frames, and one CPU"
#endif

#define PAGE 4096UL
#define PAGE_FLAGS (UK_PAGING_PAGE_FLAG_SIZE(0) | UK_PAGING_PAGE_FLAG_FORCE_SIZE)
#define MAX_RESERVATION (256UL * 1024 * 1024)

struct wamr_page {
	/* Retain a present PTE even while hardware access is revoked. */
	__pte_t owned;
	uint32_t protection;
};

struct wamr_mapping {
	struct uk_vma vma;
	struct wamr_platform *owner;
	struct wamr_mapping *next;
	size_t allocation_size;
	struct wamr_page pages[];
};

static void invariant(int valid)
{
	if (!valid)
		UK_CRASH("WAMR native page ownership invariant violated");
}

static int active(struct wamr_platform *p)
{
	return p->pt == uk_paging_pt_get_active() &&
	       p->vas == uk_vas_get_active() &&
	       p->pt->pt_pbase == uk_pal_pt_read_base();
}

static void *allocate(void *ctx, size_t size, size_t alignment)
{
	struct wamr_platform *p = ctx;
	void *result = NULL;

	if (!size || !alignment || (alignment & (alignment - 1)) ||
	    size > SIZE_MAX - p->allocation_bytes)
		return NULL;
	if (alignment < sizeof(void *))
		alignment = sizeof(void *);
	if (uk_posix_memalign(p->allocator, &result, alignment, size))
		return NULL;
	p->allocation_bytes += size;
	return result;
}

static void release_allocation(void *ctx, void *address, size_t size,
			       size_t alignment __unused)
{
	struct wamr_platform *p = ctx;

	if (!address)
		return;
	invariant(size <= p->allocation_bytes);
	uk_free(p->allocator, address);
	p->allocation_bytes -= size;
}

static struct wamr_mapping *find(struct wamr_platform *p, uintptr_t address,
				size_t size)
{
	struct wamr_mapping *m;

	if (!size || ((address | size) % PAGE))
		return NULL;
	for (m = p->mappings; m; m = m->next)
		if (address >= m->vma.start && address < m->vma.end &&
		    size <= m->vma.end - address)
			return m;
	return NULL;
}

static __pte_t read_leaf(struct wamr_platform *p, uintptr_t address,
			 __vaddr_t *table)
{
	unsigned int level = 0;
	__pte_t pte;

	invariant(!uk_paging_pt_walk(p->pt, address, &level, table, &pte));
	invariant(level == 0);
	return pte;
}

static void write_leaf(struct wamr_platform *p, uintptr_t address, __pte_t pte)
{
	__vaddr_t table;

	(void)read_leaf(p, address, &table);
	/* Native x86 PAL is a direct PTE store, with no allocation/error path. */
	invariant(!uk_paging_pte_write(table, 0,
			UK_PAGING_PT_Lx_IDX(address, 0), pte));
	uk_pal_tlb_flush_entry(address);
}

static __pte_t permissions(__pte_t pte, uint32_t protection)
{
	if (protection == WAMR_AOT_NONE)
		return UK_PAGING_PT_Lx_PTE_CLEAR_PRESENT(pte, 0);
	return uk_pal_pte_create(UK_PAGING_PT_Lx_PTE_PADDR(pte, 0),
		protection == WAMR_AOT_RW ? UK_PAGING_PAGE_ATTR_PROT_RW :
			(UK_PAGING_PAGE_ATTR_PROT_READ | UK_PAGING_PAGE_ATTR_PROT_EXEC),
		0, pte, 0);
}

static int deny_split(struct uk_vma *vma __unused, __vaddr_t address __unused,
		      struct uk_vma **out __unused)
{
	return -EPERM;
}

static int deny_merge(struct uk_vma *left __unused,
		      struct uk_vma *right __unused)
{
	return -EPERM;
}

static int new_vma(struct uk_vas *vas __unused, __vaddr_t va __unused,
		   __sz len __unused, void *data, unsigned long attr __unused,
		   unsigned long *flags __unused, struct uk_vma **out)
{
	struct wamr_mapping *m = data;

	m->vma.name = NULL;
	*out = &m->vma;
	return 0;
}

static void destroy_vma(struct uk_vma *vma)
{
	struct wamr_mapping *m = (struct wamr_mapping *)vma;
	struct wamr_platform *p = m->owner;
	struct wamr_mapping **link = &p->mappings;

	while (*link != m) {
		invariant(*link != NULL);
		link = &(*link)->next;
	}
	*link = m->next;
	p->reserved_bytes -= vma->end - vma->start;
	release_allocation(p, m, m->allocation_size, _Alignof(struct wamr_mapping));
}

static int unmap_vma(struct uk_vma *vma, __vaddr_t address, __sz len)
{
	struct wamr_mapping *m = (struct wamr_mapping *)vma;
	struct wamr_platform *p = m->owner;
	size_t i;

	invariant(active(p) && address == vma->start && len == uk_vma_len(vma));
	for (i = 0; i < len / PAGE; i++) {
		if (!m->pages[i].owned)
			continue;
		/* Unmap skips absent leaves. Restore hidden ownership before free,
		 * using RX (not RWX); no guest runs during this callback. */
		if (m->pages[i].protection == WAMR_AOT_NONE)
			write_leaf(p, address + i * PAGE,
				permissions(m->pages[i].owned, WAMR_AOT_RX));
		else
			p->accessible_bytes -= PAGE;
		p->frame_bytes -= PAGE;
	}
	/* Only owned 4 KiB leaves: no split or allocation on teardown. Native
	 * PAL read/write and buddy free of uniquely owned frames cannot fail.
	 * This also frees empty intermediate page tables, including those
	 * left by a failed mapping before its first leaf was installed. */
	invariant(!uk_paging_page_unmap(p->pt, address, len / PAGE, PAGE_FLAGS));
	return 0;
}

static const struct uk_vma_ops reservation_ops = {
	.new = new_vma,
	.destroy = destroy_vma,
	.unmap = unmap_vma,
	.split = deny_split,
	.merge = deny_merge,
	/* No fault, advise, or attribute handler can populate this VMA. */
};

static void *reserve(void *ctx, size_t size)
{
	struct wamr_platform *p = ctx;
	struct wamr_mapping *m;
	__vaddr_t address = UK_PAGING_VADDR_ANY;
	size_t metadata;

	if (!active(p) || !size || size % PAGE || size > MAX_RESERVATION ||
	    p->reserved_bytes > MAX_RESERVATION - size)
		return NULL;
	metadata = sizeof(*m) + size / PAGE * sizeof(m->pages[0]);
	m = allocate(p, metadata, _Alignof(struct wamr_mapping));
	if (!m)
		return NULL;
	memset(m, 0, metadata);
	m->owner = p;
	m->allocation_size = metadata;
	if (uk_vma_map(p->vas, &address, size, 0,
		       UK_VMA_MAP_SIZE(12), "wamr-owned", &reservation_ops, m)) {
		release_allocation(p, m, metadata, _Alignof(struct wamr_mapping));
		return NULL;
	}
	m->next = p->mappings;
	p->mappings = m;
	p->reserved_bytes += size;
	return (void *)address;
}

static int commit(void *ctx, void *address, size_t size)
{
	struct wamr_platform *p = ctx;
	uintptr_t va = (uintptr_t)address;
	struct wamr_mapping *m = find(p, va, size);
	struct wamr_page *pages;
	size_t i, j, count = size / PAGE;
	int rc;

	if (!active(p) || !m)
		return -EINVAL;
	pages = m->pages + (va - m->vma.start) / PAGE;
	for (i = 0; i < count; i++)
		if (pages[i].protection != WAMR_AOT_NONE)
			return -EINVAL;
	for (i = 0; i < count; i++) {
		if (pages[i].owned) {
			write_leaf(p, va + i * PAGE,
				   permissions(pages[i].owned, WAMR_AOT_RW));
			continue;
		}
		rc = uk_paging_page_map(p->pt, va + i * PAGE,
				       UK_PAGING_PADDR_ANY, 1,
				       UK_PAGING_PAGE_ATTR_PROT_RW, PAGE_FLAGS);
		if (!rc)
			continue;
		for (j = 0; j <= i; j++) {
			if (pages[j].owned)
				write_leaf(p, va + j * PAGE,
					permissions(pages[j].owned, WAMR_AOT_NONE));
			else
				invariant(!uk_paging_page_unmap(p->pt,
					va + j * PAGE, 1, PAGE_FLAGS));
		}
		return rc;
	}
	/* Do not erase retained NONE pages until every fallible map succeeds. */
	memset(address, 0, size);
	for (i = 0; i < count; i++) {
		if (!pages[i].owned)
			p->frame_bytes += PAGE;
		pages[i].owned = read_leaf(p, va + i * PAGE, NULL);
		pages[i].protection = WAMR_AOT_RW;
	}
	p->accessible_bytes += size;
	return 0;
}

static int protect(void *ctx, void *address, size_t size, uint32_t protection)
{
	struct wamr_platform *p = ctx;
	uintptr_t va = (uintptr_t)address;
	struct wamr_mapping *m = find(p, va, size);
	struct wamr_page *pages;
	size_t i, count = size / PAGE;

	if (!active(p) || !m || protection > WAMR_AOT_RX)
		return -EINVAL;
	pages = m->pages + (va - m->vma.start) / PAGE;
	for (i = 0; i < count; i++)
		if (!pages[i].owned && protection != WAMR_AOT_NONE)
			return -EINVAL;
	for (i = 0; i < count; i++) {
		if (!pages[i].owned)
			continue;
		write_leaf(p, va + i * PAGE, permissions(pages[i].owned, protection));
		if (pages[i].protection != WAMR_AOT_NONE)
			p->accessible_bytes -= PAGE;
		if (protection != WAMR_AOT_NONE)
			p->accessible_bytes += PAGE;
		pages[i].protection = protection;
	}
	return 0;
}

static void unmap(void *ctx, void *address, size_t size)
{
	struct wamr_platform *p = ctx;
	struct wamr_mapping *m = find(p, (uintptr_t)address, size);

	invariant(active(p) && m && (uintptr_t)address == m->vma.start &&
		  size == uk_vma_len(&m->vma));
	/* Exact, unsplittable, unmergeable VMA: this path never allocates. */
	invariant(!uk_vma_unmap(p->vas, (uintptr_t)address, size,
			       UK_VMA_FLAG_STRICT_VMA_CHECK));
}

static int monotonic_ns(void *ctx __unused, uint64_t *out)
{
	uint64_t ns = ukplat_monotonic_clock();

	if (ns == UINT64_MAX)
		return -EOVERFLOW;
	*out = ns;
	return 0;
}

int wamr_platform_permissions(struct wamr_platform *p, const void *address,
			     uint32_t protection)
{
	unsigned int level = 0;
	__pte_t pte;
	int present;

	if (!active(p) || !find(p, (uintptr_t)address, PAGE) ||
	    uk_paging_pt_walk(p->pt, (uintptr_t)address, &level, NULL, &pte))
		return 0;
	present = UK_PAGING_PT_Lx_PTE_PRESENT(pte, level) != 0;
	if (protection == WAMR_AOT_NONE)
		return !present;
	return level == 0 && present &&
		!!(pte & UK_ARCH_X86_64_PTE_RW) == (protection == WAMR_AOT_RW) &&
		!!(pte & UK_ARCH_X86_64_PTE_NX) == (protection != WAMR_AOT_RX);
}

int wamr_platform_config(struct wamr_platform *p, struct uk_alloc *allocator,
			 wamr_aot_config *config)
{
	memset(p, 0, sizeof(*p));
	p->allocator = allocator;
	p->vas = uk_vas_get_active();
	p->pt = uk_paging_pt_get_active();
	if (!allocator || !p->vas || !p->pt || p->vas->pt != p->pt || !active(p))
		return -ENOTSUP;
	*config = (wamr_aot_config){
		.context = p, .alloc = allocate, .free = release_allocation,
		.reserve = reserve, .commit = commit, .protect = protect,
		.unmap = unmap, .monotonic_ns = monotonic_ns,
		.max_memory_pages = 256, .max_table_elements = 65536,
	};
	return 0;
}
