#include <stdint.h>

#if defined(__clang__)
#define OBF(x) __attribute__((annotate(x)))
#define NOINLINE __attribute__((noinline))
#else
#define OBF(x)
#define NOINLINE
#endif

NOINLINE int unmarked(int x) {
  int y = x * 3 + 7;
  if (y & 1)
    y ^= 0x55AA;
  else
    y += 0x1337;
  return y;
}

// This test exists to catch "annotation parsing is broken" regressions.
// If `readAnnotate()` doesn't correctly parse the annotation string (including
// stripping the trailing NUL clang emits), BCF will silently no-op under
// -obf-only-annotated.
OBF("bcf") NOINLINE int marked(int x) {
  int y = x * 5 + 11;
  if (y & 2)
    y ^= 0xAAAA;
  else
    y += 0x2222;
  return y;
}

int main(void) { return (unmarked(1) ^ marked(2)) & 0xFF; }

