#include <assert.h>
#define UK_ASSERT(x) assert(x)
#define UK_CRASH(...) assert(!"UK_CRASH")
#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x) __builtin_expect(!!(x), 1)
