/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __HYPERV_CPU_LIFECYCLE_H__
#define __HYPERV_CPU_LIFECYCLE_H__

#include <errno.h>
#include <stdint.h>

#define HYPERV_CPU_OFFLINE		0U
#define HYPERV_CPU_INITIALIZING		1U
#define HYPERV_CPU_ONLINE		2U
#define HYPERV_CPU_STOPPING		3U

struct hyperv_cpu_state {
	uint32_t vp_index;
	uint32_t generation;
	uint8_t state;
};

static inline int
hyperv_cpu_state_reserve(struct hyperv_cpu_state *cpus,
			 unsigned int capacity, unsigned int index,
			 uint32_t vp_index, uint32_t max_vp_count,
			 uint32_t *generation)
{
	unsigned int i;

	if (!cpus || !generation || index >= capacity ||
	    vp_index == UINT32_MAX ||
	    (max_vp_count && vp_index >= max_vp_count))
		return -ERANGE;
	if (__atomic_load_n(&cpus[index].state, __ATOMIC_ACQUIRE) ==
	    HYPERV_CPU_ONLINE)
		return cpus[index].vp_index == vp_index ? 1 : -EEXIST;
	if (__atomic_load_n(&cpus[index].state, __ATOMIC_ACQUIRE) !=
	    HYPERV_CPU_OFFLINE)
		return -EBUSY;
	for (i = 0; i < capacity; i++)
		if (i != index &&
		    __atomic_load_n(&cpus[i].state, __ATOMIC_ACQUIRE) !=
			    HYPERV_CPU_OFFLINE &&
		    cpus[i].vp_index == vp_index)
			return -EEXIST;
	if (*generation == UINT32_MAX)
		return -ENOSPC;
	cpus[index].vp_index = vp_index;
	cpus[index].generation = ++*generation;
	__atomic_store_n(&cpus[index].state, HYPERV_CPU_INITIALIZING,
			 __ATOMIC_RELEASE);
	return 0;
}

static inline void
hyperv_cpu_state_release(struct hyperv_cpu_state *cpus,
			 unsigned int capacity, unsigned int index)
{
	if (!cpus || index >= capacity)
		return;
	cpus[index].vp_index = UINT32_MAX;
	cpus[index].generation = 0;
	__atomic_store_n(&cpus[index].state, HYPERV_CPU_OFFLINE,
			 __ATOMIC_RELEASE);
}

static inline int
hyperv_cpu_state_online(struct hyperv_cpu_state *cpus,
			unsigned int capacity, unsigned int index)
{
	if (!cpus || index >= capacity ||
	    __atomic_load_n(&cpus[index].state, __ATOMIC_ACQUIRE) !=
		    HYPERV_CPU_INITIALIZING)
		return -EINVAL;
	__atomic_store_n(&cpus[index].state, HYPERV_CPU_ONLINE,
			 __ATOMIC_RELEASE);
	return 0;
}

#endif /* __HYPERV_CPU_LIFECYCLE_H__ */
