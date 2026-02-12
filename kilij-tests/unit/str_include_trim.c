#include <stdint.h>

// This test exists to ensure include/exclude path lists trim whitespace.
// Example user input: -mllvm -obf-str-include=foo, bar
// Without trimming, the second token is " bar" and won't match.

__attribute__((noinline)) const char *get_str(void) {
  // Length >= 4 so it is eligible by default settings.
  return "hello world";
}

int main(void) {
  const char *s = get_str();
  // Prevent the string from being optimized away entirely.
  return (int)(uintptr_t)s & 0xFF;
}

