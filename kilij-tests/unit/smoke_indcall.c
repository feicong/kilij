#if defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

NOINLINE int indcall_callee(int x) { return x * 3 + 1; }

NOINLINE int smoke_indcall(int x) { return indcall_callee(x) + 7; }

