// Unit test: BCF must not crash or generate invalid IR in the presence of
// MSVC-style EH / funclets.

extern "C" int eh_msvc_bcf_maythrow(int);

__attribute__((noinline))
int eh_msvc_bcf(int x) {
  try {
    return eh_msvc_bcf_maythrow(x) + 1;
  } catch (...) {
    return 42;
  }
}

