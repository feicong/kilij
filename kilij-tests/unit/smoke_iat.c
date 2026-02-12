#if defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

__declspec(dllimport) int iat_import(int);

NOINLINE int smoke_iat(int x) { return iat_import(x) + 1; }

