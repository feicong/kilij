# Contributing

PRs and issues are welcome. The most valuable contributions are usually:

- verifier fixes and minimized reproducers
- EH/funclet hardening
- cross-platform fixes
- regression tests
- documentation corrections (especially around flags and selection)

## Bug reports

Please include:
- OS / target triple
- toolchain (clang/clang-cl/MSVC)
- the exact `-mllvm` flags used
- verifier output (if any)
- IR dumps if you can share them (`-obf-dump-ir`)

## Security issues

Kilij is a compiler transform suite. As such, security issues usually look like correctness bugs:
- silent miscompiles
- transforms that violate IR invariants without tripping the verifier
- memory safety bugs in compiler-side code

Open an issue with a minimized repro if possible.
