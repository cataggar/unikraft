#pragma once
extern unsigned int ukboot_host_cpu_idx;
#define uk_pcpuvar_cpu_idx ukboot_host_cpu_idx
#define uk_pcpuvar_current_get(sym) ((void)(sym), ukboot_host_cpu_idx)
