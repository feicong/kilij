# Release Tooling

Scripts for building and packaging prebuilt Kilij toolchains. Currently
shipping one artifact:

- `kilij-clang20-win64.zip`

Linux binaries are not yet available (untested; build from source).

The zip contains `bin/clang` with passes built in (`-mllvm -<flag>`),
`bin/opt` + the pass plugin (`Kilij.dll`) for
`opt -load-pass-plugin=...`, quickstart scripts, and example inputs.

## Full Build

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File release/build_windows.ps1
```

Optional parameters: `-LlvmProjectDir`, `-LlvmCommit` (default:
`llvmorg-20.1.0`), `-BuildDir`, `-OutDir`.

Linux:

```bash
bash release/build_linux.sh
```

Environment variables: `LLVM_PROJECT_DIR`, `LLVM_COMMIT` (default:
`llvmorg-20.1.0`), `BUILD_DIR`, `INSTALL_PREFIX`, `JOBS` (default: 8),
`QUIET`.

Both scripts shallow-clone LLVM, copy Kilij sources into the tree, apply
patches, configure with CMake/Ninja, build, and invoke the packaging script.

## Package Only

If you already have a build, package it directly.

Windows (needs `clang.exe`, `opt.exe`, `Kilij.dll`, `lld-link.exe`,
`llvm-as.exe`, `llvm-dis.exe`, `llvm-objdump.exe` in the build dir):

```powershell
powershell -ExecutionPolicy Bypass -File release/package_windows.ps1 -BuildDir C:\path\to\llvm-build
```

Optional: `-OutDir`, `-VcRedistDir`.

Linux (needs `bin/clang`, `bin/opt`, `lib/Kilij.so` in the install prefix):

```bash
bash release/package_linux.sh --install-prefix /path/to/install
```

Optional: `--out <path.tar.xz>`, `--name <dir-name>`.

## Quickstart Scripts

Shipped inside the archives:

```
quickstart/run_clang_obf_ir.{bat,sh}
quickstart/run_opt_plugin.{bat,sh}
```

## Patches

Two patches under `release/patches/` are applied to the LLVM tree during
the build:

- `kilij_in_tree_clang.patch` -- wires the Kilij obfuscation directory into
  LLVM's CMake build so clang loads the passes automatically.
- `extract_symbols_analysiskey.patch` -- on Windows static builds, pass
  plugins need `AnalysisKey` symbols that `extract_symbols.py` prunes by
  default. This patch adds them back.

## Validation

Both packaging scripts run a smoke test before creating the archive: they
compile or process `release/examples/_tmp_kilij_smoke.{c,ll}` through the
staged `clang` and `opt` to verify the build is functional.
