#if defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

extern int fla_true(int);
extern int fla_false(int, int);

NOINLINE int smoke_fla(int x) {
  if (x & 1)
    return fla_true(x);
  return fla_false(x, 7);
}

