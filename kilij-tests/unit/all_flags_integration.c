// Integration smoke: build, link, and run with the "max protection" flag set.
// Keep it tiny and deterministic.

#ifdef _WIN32
__declspec(dllimport) int puts(const char *s);
#else
int puts(const char *s);
#endif

static int add(int a, int b) { return a + b; }

int main(void) {
  int x = add(40, 2);
  if (x != 42) return 2;
  puts("kilij_ok");
  return 0;
}

