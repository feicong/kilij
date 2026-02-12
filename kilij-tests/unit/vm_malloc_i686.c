// This test exists to ensure VM heap reg-file allocation uses `size_t` for
// malloc on 32-bit targets (ABI correctness).

__attribute__((noinline)) int foo(int x) { return x + 1; }

int main(void) { return foo(1); }

