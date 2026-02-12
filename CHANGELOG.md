# Changelog

## [v0.1.0] - 2026-02-12

First public release targeting LLVM 20.

### Added

**Control flow (4 passes):**
flattening (`-fla`), bogus control flow (`-bcf`), block splitting (`-split`),
indirect branches (`-indbr`)

**Data flow (4 passes):**
MBA (`-mba`), substitution (`-sub`), constant encryption (`-obf-const`),
string encryption (`-obf-str`)

**Call/import obfuscation (3 passes):**
indirect calls (`-indcall`), IAT obfuscation (`-obf-iat`, Windows x64 only),
extern hiding (`-obf-hide-externs`)

**Opaque predicates (7 families):**
DiffSquares, XorEq, Powmod, Collatz, MinorQuadric, QSeries, Composite --
salted with `readcyclecounter` + FNV

**VM virtualization:**
custom ISA (17 opcodes, 8 type kinds), three execution modes (opcode / bb /
region), three encoding layers (affine / MBA / Feistel), bytecode layout
hardening, encoded PC, indirect dispatch, bogus handlers

**Toolchain:**
- Prebuilt `kilij-clang20-win64.zip` with clang/opt/lld and all passes baked in
- Standalone `Kilij.dll` pass plugin for use with any LLVM 20 opt
- Quickstart scripts and showcase binary (`build_showcase_exe.bat`)
- Release build scripts for Windows and Linux (from-source)

### Platform support

| Platform | Status |
|---|---|
| Windows x86_64 | Full support; prebuilt binaries available |
| Linux x86_64 | Builds, untested; no prebuilt binaries yet |
| Windows ARM64 | Partial (IAT obfuscation disabled) |

### Notes

- All flags are `-mllvm -<flag>`. See [`docs/PASSES.md`](docs/PASSES.md) for
  the full reference.
- `Kilij.dll` imports symbols from the included `opt.exe` (static plugin
  model). To use with a different LLVM 20 build, rebuild from source.
- Linux behavior is not guaranteed. Build from source and test on your target.
