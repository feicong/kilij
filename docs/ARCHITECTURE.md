# Architecture

Kilij is an LLVM pass plugin that applies code obfuscation transforms at the IR
level. It registers at `OptimizerLastEP` so transforms run after standard
optimization, preventing cleanup passes from folding away the obfuscation.

---

## Plugin registration

`Plugin.cpp` registers all passes with LLVM's `PassBuilder`:

- **OptimizerLastEP callback** -- runs the full pass chain automatically when
  the plugin is loaded into `clang` or `opt`.
- **Pipeline parsing callback** -- allows individual passes to be invoked by
  name (e.g., `-passes=fla,bcf`), plus a combined `kilij` pipeline element.
- **Static registration** -- when built in-tree with
  `LLVM_OBFUSCATION_LINK_INTO_TOOLS`, passes are linked directly into
  `clang`/`opt` without `-fpass-plugin`.

---

## Pass ordering

The passes run in a fixed order chosen to avoid interference:

| Order | Pass | Type | Rationale |
|-------|------|------|-----------|
| 1 | VM | Module | Runs first so later passes see the transformed surface |
| 2 | IAT | Module | Rewrites imports before string/const passes touch them |
| 3 | String | Module | Encrypts string literals |
| 4 | Const | Function | Encodes integer constants |
| 5 | Split | Function | Fragments blocks to give BCF/FLA more material |
| 6 | BCF | Function | Inserts bogus control flow (benefits from split blocks) |
| 7 | FLA | Function | Flattens CFG into switch dispatcher |
| 8 | MBA | Function | Rewrites arithmetic with MBA expressions |
| 9 | IndirectBranch | Module | Redirects calls/branches through tables |
| 10 | Substitution | Function | Last: simple arithmetic rewrites on final IR |

Module-level passes (VM, IAT, String, IndirectBranch) operate on the whole
module. Function-level passes (Const, Split, BCF, FLA, MBA, Substitution) are
wrapped in `createModuleToFunctionPassAdaptor`.

---

## Pass categories

### CFG transforms

- **Flattening** (`Flattening.cpp`) -- switch-based dispatch loop
- **Bogus control flow** (`BogusControlFlow.cpp`) -- opaque predicate branches
- **Block splitting** (`SplitBasicBlock.cpp`) -- fragment blocks
- **Opaque predicates** (`OpaquePredicates.cpp`) -- algebraic/number-theoretic
  predicates used by BCF

### Arithmetic obfuscation

- **MBA** (`MBAObfuscation.cpp`) -- mixed boolean-arithmetic rewrites
- **Substitution** (`Substitution.cpp`) -- random-constant cancellation

### Data encoding

- **String obfuscation** (`StringObfuscation.cpp`) -- compile-time encryption
  with runtime decode-on-first-use
- **Constant obfuscation** (`ConstObfuscation.cpp`) -- XOR-encoded integer
  constants with volatile global keys
- **Indirect branches/calls** (`IndirectBranch.cpp`) -- table-based indirection
  with encoded entries

### Platform-specific

- **IAT obfuscation** (`IATObfuscation.cpp`) -- Windows x64 import table
  rewriting (thunk or PEB-walking resolver backends)

### VM virtualization

- **VMPass** (`VM/VMPass.cpp`) -- entry point; lowers functions to bytecode
  and emits an interpreter

---

## VM subsystem

The VM is the most complex component (10 source files, ~14 headers). It
converts LLVM IR functions into custom bytecode executed by an emitted
interpreter loop.

### Pipeline

```
LLVM IR  -->  VM-IR  -->  Bytecode  -->  Interpreter / Region emit
```

### Source files

| File | Role |
|------|------|
| `VMPass.cpp` | Pass entry point, function selection, orchestration |
| `VMIR.cpp` / `VMIR.h` | VM intermediate representation and instruction set |
| `VMIRBuilder.h` | Builder for constructing VM-IR |
| `VMLowering.cpp` | Lowers LLVM IR to VM-IR |
| `VMBytecode.cpp` | Encodes VM-IR into bytecode arrays |
| `VMInterpreter.cpp` | Emits the fetch-decode-execute interpreter in LLVM IR |
| `VMEmitInterp.cpp` | Interpreter emission helpers |
| `VMEmitRegion.cpp` | Region-mode emission (VM-IR back to native IR) |
| `VMEmitUtils.cpp` | Shared emission utilities |
| `VMRegionFormation.cpp` | Groups basic blocks into regions for region mode |
| `VMEncode.cpp` | Affine, MBA, and Feistel encoding layers |
| `VMRuntime.h` | Runtime support structures (stack frame, anti-debug) |
| `VMConfig.h` | Configuration flags and defaults |
| `VMMath.h` | Math helpers for encoding |

### Execution modes

- **opcode** -- traditional bytecode interpreter (strongest protection)
- **bb** -- basic-block granularity dispatch
- **region** -- compiles VM-IR back to native LLVM IR with indirect dispatch

### Encoding layers

Encoding scrambles register values and bytecode to resist static analysis:

1. **Affine** -- linear transform `y = A*x + B mod 2^n`
2. **MBA** -- mixed boolean-arithmetic on top of affine
3. **Feistel** -- non-linear Feistel network on selected registers
4. **Bytecode hardening** (hard mode) -- field shuffling, stride randomization,
   padding, rotation before XOR

---

## File organization

```
kilij/
  Plugin.cpp              Pass registration and ordering
  Utils.cpp / .h          Shared helpers (verification, naming, growth limits)
  CryptoUtils.cpp / .h    AES-CTR PRNG for deterministic randomness
  BogusControlFlow.cpp    BCF pass
  OpaquePredicates.cpp    Predicate generators
  Flattening.cpp          CFG flattening
  SplitBasicBlock.cpp     Block splitting
  MBAObfuscation.cpp      MBA rewriter
  Substitution.cpp        Arithmetic substitution
  StringObfuscation.cpp   String encryption
  ConstObfuscation.cpp    Constant encoding
  IndirectBranch.cpp      Indirect calls/branches
  IATObfuscation.cpp      Windows IAT rewriting
  VM/                     VM virtualization subsystem (see above)
  CMakeLists.txt          Build system (standalone + in-tree)
  docs/                   Documentation
  kilij-tests/            Unit, fuzz, and end-to-end test runners
  release/                Release build scripts and patches
```

---

## Build modes

The `CMakeLists.txt` supports two configurations:

- **Standalone** -- detected when `CMAKE_SOURCE_DIR == CMAKE_CURRENT_SOURCE_DIR`.
  Finds LLVM via `find_package`, builds the plugin as a loadable module.
- **In-tree** -- when placed under `llvm/lib/Transforms/Obfuscation/`. Builds
  both a static library (`LLVMObfuscation`) linked into tools and a pass
  plugin (`Kilij`) for dynamic loading.

On non-Windows in-tree shared-LLVM builds, the plugin defaults to a thin
wrapper (`KILIJ_THIN_PLUGIN`) containing only `Plugin.cpp` to avoid duplicate
symbol registration. On Windows, the plugin is built as a MODULE importing
from `opt.exe`'s symbol table.
