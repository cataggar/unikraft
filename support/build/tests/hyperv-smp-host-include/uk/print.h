static inline void hyperv_host_print(const char *format, ...) { (void)format; }
#define uk_pr_info(...) hyperv_host_print(__VA_ARGS__)
#define uk_pr_warn(...) hyperv_host_print(__VA_ARGS__)
