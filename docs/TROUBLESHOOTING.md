# Troubleshooting

Common build, configuration, and runtime issues. For setup help see
[BUILDING.md](BUILDING.md); for flag details see [PASSES.md](PASSES.md).

## Debugging

- Use `-mllvm -obf-verify` (on by default) to catch IR issues early.
- Use `-mllvm -obf-dump-ir` with `-mllvm -obf-dump-dir=<path>` to inspect
  per-pass IR.
- Set `-mllvm -obf-seed=1234` for deterministic builds while debugging.
- Use `-mllvm -vm-validate` for VM differential testing.
- Cap size growth with `-mllvm -obf-max-bb-growth`, `-mllvm -obf-max-inst-growth`,
  `-mllvm -vm-max-bc-instrs`, and `-mllvm -vm-max-global-bytes`.

Enable one pass at a time when isolating issues.

## Illegal instruction (ud2 / 0xC000001D)

Some hard-fail modes intentionally crash with `ud2`:

- `-obf-iat-fail=trap` (default)
- `-vm-hard-rt` integrity/anti-debug checks
- `-vm-bounds-check`

If you need non-crashing behavior on resolver miss, use
`-obf-iat-fail=fallback` or `-obf-iat-fail=null`.

## Output size exploded

Common causes:

- Stacked arithmetic rewrites (VM encode + MBA + Substitution).
- CFG compounding (`split` then `bcf` then `fla`).
- VM size caps not set (`-mllvm -vm-max-bc-instrs`, `-mllvm -vm-max-global-bytes`).
- Using `-mllvm -vm-mode=bb` on large codebases.

## Nothing changed

Check the following:

- The pass flag is not enabled.
- The function hit a hard skip rule (e.g. `DllMain`, CRT init).
- `-obf-only-annotated` is on and nothing is annotated.
- The function has a `no_obfuscate`, `obf_skip`, or `vm_skip` attribute.
- Generate a selection report with `-mllvm -vm-report=<file>` to see why the VM pass skipped a function.

## Path filters do not match

String-obf include/exclude and VM select-path filters rely on debug info.
Build with `-g` when testing path filters.

## Windows DLL contexts

`DllMain` and CRT entrypoints are intentionally skipped. Move sensitive
initialization out of loader entrypoints.

`-obf-iat-load-missing` is off by default. If you turn it on in an injected DLL,
be careful about calling paths that run during loader initialization.

## Portability

Tested primarily on Windows x64. Report issues with other platforms via
the project's issue tracker.

## Plugin Load Errors

### Windows: `Kilij.dll` fails to load

On Windows static LLVM builds, pass plugins import symbols from one specific
exporting host tool. The shipped `Kilij.dll` imports from the included `opt.exe`.

Use it like:
```text
opt.exe -load-pass-plugin=Kilij.dll -passes=kilij ...
```

If you try to load `Kilij.dll` into a different `opt.exe`/`clang.exe`, Windows
may report "module could not be found" (because the import table references the
wrong host).

### Linux: `Option 'aesSeed' registered more than once!`

This happens if you build a pass plugin that recompiles the full obfuscation
implementation while the host tool already contains the same code (e.g. when
linking tools against `libLLVM.so`).

Fix: build the plugin as a thin wrapper (only `Plugin.cpp`) when
`LLVM_LINK_LLVM_DYLIB` is enabled. The `CMakeLists.txt` does this automatically for non-Windows shared-LLVM
configurations.
