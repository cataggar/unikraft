#include <uk/arch/types.h>
#define UK_PAGING_PADDR_INV ((uintptr_t)-1)
static inline __paddr_t uk_paging_virt_to_phys(__vaddr_t address)
{ return (__paddr_t)address; }
