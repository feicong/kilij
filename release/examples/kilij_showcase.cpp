// kilij_showcase.cpp
// Small deterministic program for quick runtime smoke + VM confirmation.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

static volatile std::uint64_t g_sink = 0;

NOINLINE static std::uint64_t splitmix64(std::uint64_t x) {
  x += 0x9E3779B97F4A7C15ull;
  x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
  x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
  return x ^ (x >> 31);
}

NOINLINE static std::uint64_t fnv1a64(const std::uint8_t *data,
                                      std::size_t len) {
  std::uint64_t h = 1469598103934665603ull;
  for (std::size_t i = 0; i < len; ++i) {
    h ^= static_cast<std::uint64_t>(data[i]);
    h *= 1099511628211ull;
  }
  return h;
}

NOINLINE static std::uint32_t switch_dispatch(std::uint32_t v) {
  switch (v & 7u) {
  case 0:
    return v ^ 0xA5A5A5A5u;
  case 1:
    return (v * 3u) + 0x01234567u;
  case 2:
    return (v << 9) | (v >> (32 - 9));
  case 3:
    return (v ^ (v >> 16)) * 0x45D9F3Bu;
  case 4:
    return (v + 0xDEADBEEFu) ^ 0xC001D00Du;
  case 5:
    return (v * 2654435761u) ^ 0x1337u;
  case 6:
    return (v ^ (v >> 11) ^ (v >> 22)) + 0x9E3779B9u;
  default:
    return v ^ 0xFFFFFFFFu;
  }
}

NOINLINE static int op_add(int a, int b) { return a + b + 7; }
NOINLINE static int op_xor(int a, int b) { return (a ^ b) - 3; }
NOINLINE static int op_mul(int a, int b) { return (a * 3) + (b * 5) + 11; }
NOINLINE static int op_sub(int a, int b) { return (a - b) ^ 0x55AA; }

using Op = int (*)(int, int);

NOINLINE static int indirect_arith(int a, int b, int sel) {
  static Op ops[4] = {op_add, op_xor, op_mul, op_sub};
  return ops[static_cast<unsigned>(sel) & 3u](a, b);
}

NOINLINE static std::uint64_t crunch(std::uint64_t x) {
  for (int i = 0; i < 8; ++i) {
    x = splitmix64(x + static_cast<std::uint64_t>(i) * 0x1111111111111111ull);
    x ^= static_cast<std::uint64_t>(
        switch_dispatch(static_cast<std::uint32_t>(x)));
    x += static_cast<std::uint64_t>(
        indirect_arith(1337 + i, 42 - i, static_cast<int>(x)));
  }
  return x;
}

NOINLINE static void exercise_winapi() {
  // Exercise imports, but keep the deterministic check pure.
  volatile DWORD pid = GetCurrentProcessId();
  volatile DWORD tid = GetCurrentThreadId();
  volatile ULONGLONG t = GetTickCount64();
  (void)pid;
  (void)tid;
  (void)t;
}

int main() {
  const char *banner = "Kilij showcase: vm-select=all";
  const char *payload = "strings/consts/switch/indcall/vm smoke";

  std::uint64_t h = 0x0123456789ABCDEFull;
  h ^=
      fnv1a64(reinterpret_cast<const std::uint8_t *>(banner), std::strlen(banner));
  h ^= fnv1a64(reinterpret_cast<const std::uint8_t *>(payload),
               std::strlen(payload));
  h = crunch(h);

  exercise_winapi();

  // Deterministic expected value (computed from the above logic).
  constexpr std::uint64_t kExpected = 0x8F08D453410A8BFEull;
  g_sink = h;

  if (h != kExpected) {
    std::fprintf(stderr, "FAIL: h=0x%016" PRIx64 " expected=0x%016" PRIx64 "\n",
                 h, kExpected);
    return 1;
  }

  std::puts(banner);
  std::printf("OK: h=0x%016" PRIx64 "\n", h);
  return 0;
}

