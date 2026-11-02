#include <stdarg.h>
static inline void uk_pr_host(const char *format, ...)
{
	(void)format;
}
#define uk_pr_err(...) uk_pr_host(__VA_ARGS__)
#define uk_pr_warn(...) uk_pr_host(__VA_ARGS__)
#define uk_pr_info(...) uk_pr_host(__VA_ARGS__)
#define uk_pr_debug(...) uk_pr_host(__VA_ARGS__)
