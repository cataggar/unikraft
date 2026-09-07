#include <uk/arch/types.h>
extern _Thread_local __u64 hyperv_host_cpu_index;
#define uk_pcpuvar_cpu_idx hyperv_host_cpu_index
#define uk_pcpuvar_current_get(sym) (hyperv_host_cpu_index)
