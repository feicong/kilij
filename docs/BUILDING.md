# Building Kilij

Kilij is an LLVM 20 pass plugin. There are two ways to build it:

1. **Standalone (out-of-tree)** -- build just the plugin `.so`/`.dylib` against an
   installed LLVM 20. This is the normal developer workflow.
2. **In-tree release** -- build a full LLVM+Clang+LLD toolchain with Kilij baked in.
   Used for shipping release artifacts.

This document covers both, starting with the standalone path.

---

## Prerequisites

### Ubuntu / Debian

```bash
sudo apt install llvm-20-dev clang-20 lld-20 cmake ninja-build python3
```

### Fedora

```bash
sudo dnf install llvm-devel clang cmake ninja-build python3
```

If the packaged version is not 20.x, build from source or use the release scripts.

### macOS

```bash
brew install llvm@20 cmake ninja python
```

You may need to set `LLVM_DIR`:

```bash
export LLVM_DIR="$(brew --prefix llvm@20)/lib/cmake/llvm"
```

### Windows

Windows builds use the in-tree release path (full LLVM build). You need:

- Visual Studio Build Tools 2022 (MSVC x64 toolset)
- CMake and Ninja (bundled with VS, or install separately)
- Git for Windows
- Python 3

See [In-tree release builds](#in-tree-release-builds) below, or use
`release/build_windows.ps1` directly.

---

## Standalone plugin build (developer workflow)

### Using Make

The top-level `Makefile` automates the CMake + Ninja steps:

```bash
make build       # configure + build
make test        # run unit tests
make fuzz        # quick fuzz (20 iterations)
make clean       # remove _build/standalone/
```

The Makefile auto-detects LLVM via `llvm-config-20` or `llvm-config` on
`PATH`. Override with `LLVM_DIR`:

```bash
LLVM_DIR=/path/to/llvm/lib/cmake/llvm make build
```

### Manual CMake

```bash
mkdir -p _build/standalone && cd _build/standalone

cmake ../.. -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR="$(llvm-config-20 --cmakedir)"

ninja -j$(nproc)
```

The build produces a shared library (`Kilij.so` on Linux, `Kilij.dylib` on
macOS). Load it with `opt` or `clang`:

```bash
# With opt
opt -load-pass-plugin=_build/standalone/Kilij.so \
    -passes=kilij -S input.ll -o output.ll

# With clang
clang -O2 -fpass-plugin=_build/standalone/Kilij.so \
    -mllvm -fla -mllvm -bcf \
    example.c -o example
```

### CMake options

| Option | Default | Description |
|--------|---------|-------------|
| `CMAKE_BUILD_TYPE` | `Release` | `Debug` for development |
| `LLVM_DIR` | auto | Path to LLVM's CMake config |
| `KILIJ_FORCE_LLVM_ENABLE_PLUGINS` | `OFF` | Force plugin support on static LLVM |
| `KILIJ_THIN_PLUGIN` | auto | Build thin wrapper (shared-LLVM only) |

---

## Running tests

The test runner is `kilij-tests/unit_fuzz_run.py`. It has three modes:

### Unit tests

```bash
python3 kilij-tests/unit_fuzz_run.py unit
```

Compiles small C/IR files through `clang` with obfuscation flags, checks
output IR for expected patterns, and verifies with `opt -passes=verify`.
The final test compiles, links, and runs a binary with every pass enabled.

### Fuzz tests

```bash
python3 kilij-tests/unit_fuzz_run.py fuzz --iterations 200
```

Generates random LLVM IR with `llvm-stress`, runs each pass configuration,
and checks that the output verifies. Good for finding crashes in edge cases.

### All tests

```bash
python3 kilij-tests/unit_fuzz_run.py all
```

Runs both unit and fuzz.

### Test runner options

| Flag | Default | Description |
|------|---------|-------------|
| `--clang <path>` | auto | Path to clang |
| `--opt <path>` | auto | Path to opt |
| `--llvm-stress <path>` | auto | Path to llvm-stress |
| `--llvm-dis <path>` | auto | Path to llvm-dis |
| `--pass-plugin <path>` | none | Path to Kilij plugin `.so`/`.dll`/`.dylib` (standalone builds) |
| `--out <dir>` | `kilij-tests/out/<timestamp>` | Output directory |
| `--timeout <sec>` | 60 | Per-subprocess timeout |
| `--iterations <N>` | 200 | Fuzz iteration count |
| `--size <N>` | 120 | llvm-stress IR size |
| `--jobs <N>` | CPU count | Fuzz parallelism |
| `--keep-going` | off | Continue after fuzz failures |
| `--scalable-vectors` | off | Generate scalable vector IR in fuzz mode |
| `--verbose` / `-v` | off | Verbose output |

The runner auto-detects tools in `llvm-20-build-kilij/bin/`,
`llvm-20-install/bin/`, or `PATH`. For standalone builds, pass
`--pass-plugin` so the runner loads the plugin via `-fpass-plugin`.

### End-to-end tests

`kilij-tests/e2e_run.py` builds real-world
open-source projects (fmt, zstd, libuv, yaml-cpp) with full obfuscation
and runs their test suites:

```bash
python3 kilij-tests/e2e_run.py --toolchain-bin <path-to-kilij-bin>
```

Use `--project <name>` to select specific projects, `--no-tests` to
build without running tests, or `--continue-on-failure` to run all
projects even if one fails.

---

## In-tree release builds

Release builds compile the entire LLVM toolchain with Kilij integrated. The
scripts handle cloning LLVM, patching, copying sources, and building.

### Linux

```bash
bash release/build_linux.sh
```

Key environment variables: `LLVM_PROJECT_DIR`, `BUILD_DIR`, `INSTALL_PREFIX`,
`JOBS`, `LLVM_COMMIT`.

Output: an installed toolchain under
`_install/kilij-llvm20-linux-install/` and a release tarball under
`_release_out/linux/`.

### Windows

```powershell
powershell -ExecutionPolicy Bypass -File release/build_windows.ps1
```

Parameters: `-LlvmProjectDir`, `-LlvmCommit`, `-BuildDir`, `-OutDir`.

The script locates and invokes `VsDevCmd.bat` automatically; no
Developer Command Prompt is required. Output: a release zip under
`_release_out/windows/`.

Both scripts are pinned to `llvmorg-20.1.0` by default.

---

## Troubleshooting

See [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues including:

- Plugin load errors on Windows and Linux
- Output size explosion
- Pass not taking effect
- Path filter matching
