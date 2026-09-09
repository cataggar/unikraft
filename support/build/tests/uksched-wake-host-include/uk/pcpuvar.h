#pragma once

extern unsigned int uksched_wake_host_cpu_idx;

#define uk_pcpuvar_cpu_idx uksched_wake_host_cpu_idx
#define uk_pcpuvar_current_get(symbol) (uksched_wake_host_cpu_idx)
