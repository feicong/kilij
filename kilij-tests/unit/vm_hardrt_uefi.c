// This test exists to ensure Windows-only hard runtime checks do not emit
// WinAPI dependencies on COFF-but-non-Windows targets (e.g. UEFI).

__attribute__((noinline)) int foo(int x) {
  int y = x * 3 + 7;
  if (y & 1)
    y ^= 0x55AA;
  else
    y += 0x1337;
  return y;
}

int main(void) { return foo(5); }

