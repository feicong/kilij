#if defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

extern int br_true(int);
extern int br_false(int, int);

NOINLINE int smoke_indbr(int x) {
  if (x & 1)
    return br_true(x);
  return br_false(x, 7);
}

