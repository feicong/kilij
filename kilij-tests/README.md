# Kilij Test Suite

Three levels of testing: unit tests, IR fuzzing, and end-to-end project builds.

Run from the repo root after building the toolchain or plugin.

---

## Unit tests and IR fuzzer

### Quick start

```bash
python3 kilij-tests/unit_fuzz_run.py unit    # unit tests
python3 kilij-tests/unit_fuzz_run.py fuzz    # IR fuzzer (200 iterations)
python3 kilij-tests/unit_fuzz_run.py all     # both
```

### Modes

| Mode   | Description                                                    |
|--------|----------------------------------------------------------------|
| `unit` | Compile test inputs with individual passes, verify IR output   |
| `fuzz` | Generate random IR via `llvm-stress`, compile under all configs|
| `all`  | Run unit then fuzz                                             |

### Flags

| Flag                   | Default                       | Description                                               |
|------------------------|-------------------------------|-----------------------------------------------------------|
| `--clang <path>`       | auto-detected                 | Path to clang                                             |
| `--opt <path>`         | auto-detected                 | Path to opt                                               |
| `--llvm-stress <path>` | auto-detected                 | Path to llvm-stress (required for fuzz mode)              |
| `--llvm-dis <path>`    | auto-detected                 | Path to llvm-dis (optional, for readable reproducers)     |
| `--pass-plugin <path>` | none                          | Pass plugin `.so`/`.dll`/`.dylib` for standalone builds   |
| `--out <dir>`          | `kilij-tests/out/<timestamp>` | Output directory for artifacts                            |
| `--timeout <s>`        | 60                            | Per-subprocess timeout in seconds                         |
| `--iterations <n>`     | 200                           | Fuzz iterations                                           |
| `--size <n>`           | 120                           | `llvm-stress` IR size parameter                           |
| `--jobs <n>`           | CPU count                     | Fuzz parallelism                                          |
| `--keep-going`         | off                           | Continue fuzzing after failures                           |
| `--scalable-vectors`   | off                           | Generate scalable vector IR (can trigger upstream asserts) |
| `--verbose`, `-v`      | off                           | Verbose output                                            |

### Tool resolution

The runner searches for `clang`, `opt`, `llvm-stress`, and `llvm-dis` in order:

1. `llvm-20-build-kilij/bin`
2. `llvm-20-install/bin`
3. `PATH`

Override any tool with the corresponding `--<tool>` flag.

### Outputs

Artifacts (reproducers, logs) go to `kilij-tests/out/<timestamp>/`.

Unit tests run `opt -passes=verify` on emitted `.ll` outputs to catch
module-level verifier issues. Fuzz reproducers include the input bitcode,
command line, and stdout/stderr.

---

## End-to-end project builds

Build four real open-source projects (fmt, zstd, libuv, yaml-cpp) with full
obfuscation (`vm-select=all`, all passes on) and run their test suites.

```bash
python3 kilij-tests/e2e_run.py --toolchain-bin path/to/kilij/bin
```

### Projects

| Project    | Tag     | Notes                                   |
|------------|---------|---------------------------------------- |
| `fmt`      | 10.2.1  | C++ formatting library                  |
| `zstd`     | v1.5.6  | Compression (cmake subdir: build/cmake) |
| `libuv`    | v1.48.0 | Async I/O (patched on Windows for obf)  |
| `yaml-cpp` | 0.8.0   | YAML parser                             |

Sources are cloned and built under `_e2e_work/`. Build logs go to
`_e2e_work/_logs/<project>.log`.

### Flags

| Flag                      | Default        | Description                                |
|---------------------------|----------------|--------------------------------------------|
| `--toolchain-bin`         | (required)     | Path to Kilij toolchain `bin/` directory   |
| `--project <name>`        | all four       | Build only the named project (repeatable)  |
| `--clean`                 | off            | Remove build dirs before building          |
| `--no-tests`              | off            | Skip test suites (build only)              |
| `--jobs <n>`              | min(6, cpus)   | Parallel build/test jobs                   |
| `--continue-on-failure`   | off            | Keep going after a project fails           |
| `--timeout-clone <s>`     | 300            | Git clone timeout (0 = no limit)           |
| `--timeout-configure <s>` | 300            | CMake configure timeout (0 = no limit)     |
| `--timeout-build <s>`     | 0              | Build timeout (0 = no limit)               |
| `--timeout-test <s>`      | 0              | Test timeout (0 = no limit)                |

Obfuscation flags are hardcoded: all passes enabled at moderate levels with
`vm-select=all`. The compiler wrapper strips `-mllvm` flags for CMake probes
and link-only invocations, and downgrades `vm-select=all` to `vm-select=cold`
for gtest/gmock files.

### Windows notes

On Windows the runner locates Visual Studio via `vswhere.exe` and wraps
commands in `VsDevCmd.bat`. It increases the stack reserve on test executables
(16 MB via `editbin.exe`) to avoid false stack overflows under heavy VM
obfuscation. The libuv test suite is patched at runtime for timeout scaling
and TTY test skipping.

---

## Z3 predicate tests

`z3_test_predicates.py` tests opaque predicates (Grassmann-Plucker and
q-binomial) against Z3 at various bitvector widths. Requires the `z3-solver`
Python package. Standalone script, not part of the main test runner.

```bash
python3 kilij-tests/z3_test_predicates.py
```
