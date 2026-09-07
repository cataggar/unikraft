struct uk_sched;
static inline struct uk_sched *uk_sched_current(void) { return (void *)0; }
static inline void uk_sched_thread_sleep(unsigned long long ns) { (void)ns; }
