# VM

The VM lowers functions into bytecode and emits an interpreter to run it. This
changes execution enough that a lot of "read the IR and recover structure"
workflows stop being straightforward.

## When to use it

VM is expensive. Use it selectively on:

- License checks
- Cryptographic routines
- Anti-tamper logic
- Small, security-critical functions

Do not virtualize hot loops or very large functions unless you accept major overhead.

## Modes

### opcode (recommended default)

Traditional bytecode interpreter. The function becomes a fetch-decode-execute
loop reading opcodes from a global bytecode array.

```bash
-mllvm -vm-mode=opcode
```

Overhead: can be an order of magnitude slower than native, depending on options
and how branchy the function is.

### bb (basic block)

Like opcode mode but operates at basic block granularity. Each block is a unit
in the dispatch loop.

```bash
-mllvm -vm-mode=bb
```

Overhead: similar to opcode. Can grow code size quickly on large functions.

### region

Compiles VM-IR back to native LLVM IR with indirect dispatch between regions.
Faster than interpreter modes but less obfuscated.

```bash
-mllvm -vm-mode=region
```

Overhead: typically lower than interpreter modes. Better for larger functions
where full interpretation is too slow.

## Security profile (current)

The modes trade security for performance:

- **opcode**: strongest. Full interpreter with bytecode/PC hardening when
  `-vm-hard` is on.
- **bb**: medium. Still interpreter-based, but the basic-block structure is
  more visible and bytecode hardening is weaker.
- **region**: lowest. VM-IR is re-emitted as native LLVM IR with indirect
  dispatch; structure is easier to recover.

If you care about resistance, start with **opcode**. Use **bb/region** when you
need something cheaper.

## Selection

Control which functions get virtualized:

- `-vm-select=all` (default, all eligible functions)
- `-vm-select=none` (disable VM virtualization for all functions)
- `-vm-select=marked` (only `vm_protect` annotated functions)
- `-vm-select=cold` (cold functions or below profile threshold)
- `-vm-select-path=foo,bar` (path substring filter)
- `-vm-cold-threshold=<N>` (profile count threshold)
- `-vm-report=<path>` (write selection report)

Mark functions:

```cpp
__attribute__((annotate("vm_protect")))
void sensitive() { ... }
```

## Encoding

Encoding scrambles VM register values and bytecode.

| Mode | Description | Overhead |
|------|-------------|----------|
| off | No encoding | Baseline |
| affine | Linear transform: y = A*x + B mod 2^n | 2-5x |
| mba | Mixed boolean arithmetic on operations | 3-8x on top of affine |

```bash
-mllvm -vm-encode=affine
-mllvm -vm-encode=mba
```

Feistel encoding adds a non-linear layer on selected registers:

```bash
-mllvm -vm-encode-feistel
-mllvm -vm-encode-feistel-all
-mllvm -vm-feistel-rounds=<0|2-8>
```

`-vm-feistel-rounds=0` selects an automatic default (2 normally, 6 with
`-vm-hard`), then clamps to the 2-8 range.

Partial/full encoding controls:

- `-vm-encode-pct=<0-100>` (default: 25)
- `-vm-encode-full-marked` (force 100% encode for `vm_protect` functions)
- `-vm-encode-full-path=<paths>` (force 100% encode for matching source paths)
- `-vm-encode-full-max-instrs=<N>` (default: 200000, fall back to vm-encode-pct above this)
- `-vm-encode-max-instrs=<N>` (default: 30000, skip encoding entirely above this)
- `-vm-encode-max-growth=<%>` (default: 300)
- `-vm-mba-max-growth=<%>` (default: 200)

## Hard mode

`-vm-hard` (default: on) enables:

- Encoded PC and bytecode
- Indirect dispatch (forced)
- Random handler order (forced if handlers=static)
- Bogus count set to 4 if explicitly set to 0
- MBA encoding if encoding was off

**Note:** Bytecode/PC hardening applies fully to `opcode` mode. `bb` and `region`
still benefit from randomized dispatch/layout, but the instruction stream is not
as opaque.

## Dispatch and handlers

- `-vm-dispatch=switch|indirect` (default: indirect)
- `-vm-handlers=static|random` (default: static)
- `-vm-bogus=<N>` (extra bogus dispatch entries, default: 2)

## Bytecode layout hardening

When hard mode is on:

- Field order shuffled
- Stride randomized per VM (36/40/44 bytes)
- Padding filled with random bytes
- 8-bit fields rotated before XOR

## Runtime checks

`-vm-hard-rt` (default: off) adds anti-debug and integrity checks. Only enable
it if you actually want runtime enforcement; it adds overhead and failure
paths.

**Platform note:** The anti-debug helpers are Windows-only; on non-Windows
targets they compile to no-ops.

## VM runtime

`-vm-obf-runtime` allows other obfuscation passes to run on the VM runtime
itself. This is off by default and can grow size and cost.
`-vm-skip-other-obf` marks VM-failure functions as `obf_skip` to skip other
passes (off by default).

## Limits

- `-vm-max-bc-instrs=<N>` (default: 0, 0 = unlimited)
- `-vm-max-global-bytes=<N>` (default: 0, 0 = unlimited)
- `-vm-max-bbs=<N>` (default: 0, 0 = unlimited)
- `-vm-max-ir-insts=<N>` (default: 0, 0 = unlimited)
- `-vm-max-runtime-insts=<N>` (default: 0, 0 = unlimited)
- `-vm-max-stack-reg-bytes=<N>` (0 = always heap; default: 256KB on Linux, 0 on Windows)

## Debug and validation

- `-vm-debug` and `-vm-debug-max-instrs=<N>` (default: 20000)
- `-vm-debug-rt` / `-vm-trace` require building with `OBF_VM_RUNTIME_DEBUG=1`
- `-vm-trace-limit=<N>` (dump last N PCs after N VM instructions, 0 = off)
- `-vm-bounds-check` (trap on out-of-bounds register access)
- `-vm-counters`
- `-vm-validate` (runtime VM vs native comparison)

## What gets lowered

Supported:

- Arithmetic, bitwise, comparisons
- Loads, stores, GEPs
- Branches, switches, returns
- Calls (wrapped as host calls)
- PHI nodes (converted to moves)

Not supported (function will be skipped by VM):

- invoke / exception handling
- callbr
- dynamic alloca
- musttail calls
- integers > 64 bits

If a function is skipped, `-vm-report` records the reason.

## Examples

Protect a license check with moderate settings:

```bash
clang++ -O2 app.cpp -o app \
  -mllvm -vm-mode=opcode \
  -mllvm -vm-select=marked \
  -mllvm -vm-encode=affine \
  -mllvm -vm-hard
```

Maximum protection (slow):

```text
-mllvm -vm-mode=opcode
-mllvm -vm-encode=mba
-mllvm -vm-encode-feistel-all
-mllvm -vm-feistel-rounds=8
-mllvm -vm-hard
-mllvm -vm-hard-rt
```

Lighter protection for larger functions:

```text
-mllvm -vm-mode=region
-mllvm -vm-encode=affine
-mllvm -vm-hard=false
```
