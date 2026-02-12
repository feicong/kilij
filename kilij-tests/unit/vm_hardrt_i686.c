// Unit test: On 32-bit Windows, WinAPI calls must use stdcall.
// This is compile-time validated by checking the emitted LLVM IR for
// `x86_stdcallcc` declarations of the WinAPI imports used by -vm-hard-rt.

__attribute__((noinline))
int vm_hardrt_i686(int x) {
  // Keep it simple; we just need VM to virtualize this function.
  return x + 1;
}

