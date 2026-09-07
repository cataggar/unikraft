#include <uk/arch/types.h>
static inline __u64 hyperv_hypercall(__u64 c, __u64 i, __u64 o)
{ (void)c; (void)i; (void)o; return 0; }
static inline __u64 hyperv_reference_time(void) { static __u64 t; return ++t; }
static inline int hyperv_has_signal_events(void) { return 1; }
