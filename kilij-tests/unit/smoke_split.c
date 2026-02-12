#if defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

NOINLINE int smoke_split(int x) {
  int a = x + 1;
  int b = a * 3;
  int c = b ^ 0x55AA;
  int d = c + 7;
  return d;
}

