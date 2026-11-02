#pragma once

struct uk_pagetable {
	unsigned int token;
};

struct uk_pagetable *uk_paging_pt_get_active(void);
int uk_paging_pt_activate_lcpu(struct uk_pagetable *);
