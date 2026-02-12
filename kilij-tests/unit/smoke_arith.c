#if defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

NOINLINE int smoke_arith(int a, int b) {
  int x = a + b;
  int y = x ^ 0x12345678;
  int z = y & 0x0F0F0F0F;
  int w = z | 0x10101010;
  return w - 7;
}

