// This test exists to ensure Windows-only passes don't run on COFF-but-non-Windows
// targets (e.g. UEFI).
int ext(int);

__attribute__((noinline)) int foo(int x) { return ext(x) + 1; }

int main(void) { return foo(3); }

