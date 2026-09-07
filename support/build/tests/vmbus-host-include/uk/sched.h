struct uk_sched;
struct uk_thread;
static inline struct uk_sched *uk_sched_current(void) { return (void *)0; }
static inline void uk_sched_thread_sleep(unsigned long long ns) { (void)ns; }
static inline struct uk_thread *
uk_sched_thread_create(struct uk_sched *sched,
		       void (*entry)(void *), void *arg, const char *name)
{
	(void)sched;
	(void)entry;
	(void)arg;
	(void)name;
	return (void *)0;
}
