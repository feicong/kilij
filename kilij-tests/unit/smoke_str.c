#if defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

NOINLINE const char *smoke_str(void) {
  return "Kilij string obfuscation smoke test";
}

