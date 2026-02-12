#include <stdint.h>

#if defined(__clang__)
#define OBF(x) __attribute__((annotate(x)))
#define NOINLINE __attribute__((noinline))
#else
#define OBF(x)
#define NOINLINE
#endif

NOINLINE int plain(int x) {
  int y = x + 1;
  y ^= 0x1234;
  return y;
}

// Opt-in: should be obfuscated when -bcf is enabled (and under -obf-only-annotated).
OBF("bcf") NOINLINE int opt_in(int x) {
  int y = x * 3 + 7;
  y ^= 0x55AA;
  return y;
}

// Precedence: "nobcf" must override "bcf" even if the pass is enabled.
OBF("bcf") OBF("nobcf") NOINLINE int opt_out_nobcf(int x) {
  int y = x * 5 + 11;
  y ^= 0xAAAA;
  return y;
}

// Precedence: global no_obfuscate must override everything.
OBF("bcf") OBF("no_obfuscate") NOINLINE int opt_out_no_obf(int x) {
  int y = x * 7 + 13;
  y ^= 0x2222;
  return y;
}

int main(void) { return plain(1) ^ opt_in(2) ^ opt_out_nobcf(3) ^ opt_out_no_obf(4); }

