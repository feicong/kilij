# Passes

## Common behavior

The function passes in Kilij use a shared set of helpers for verification,
IR dumping, symbol naming, and growth limits.

- `-mllvm -obf-verify` - Run the LLVM verifier after each transform (default: on)
- `-mllvm -obf-dump-ir` - Dump IR before/after transforms
- `-mllvm -obf-dump-dir=<path>` - Output directory for dumps
- `-mllvm -obf-max-bb-growth=<%>` - Stop further transforms on the function if BBs grow beyond this (default: 300%)
- `-mllvm -obf-max-inst-growth=<%>` - Stop further transforms on the function if insts grow beyond this (default: 500%)
- `-mllvm -obf-seed=<N>` - Deterministic seed for reproducible builds
- `-mllvm -obf-only-annotated` - Only apply function passes to annotated functions
- `-mllvm -obf-symbols=false` - Keep helper symbol names readable
- `-mllvm -obf-name-prefix=<str>` - Prefix for helper symbols

When growth limits are exceeded, the pass stops adding more transforms to that
function and marks it `no_obfuscate` (already-applied changes remain).

---

## Flattening

Turns a function into a switch-based dispatcher. Basic blocks become cases in a
loop; control flow is driven by a dispatch variable (optionally encoded).

Expect noticeable runtime overhead from the extra dispatch and a code size bump
that depends on the original CFG.

**Flags:**

- `-mllvm -fla` - Enable
- `annotate("fla")` / `annotate("nofla")` - Per-function opt-in/out

---

## Bogus Control Flow

Inserts conditional branches that always take the same path. The untaken edge
contains a cloned/junk copy of the block. Predicates are opaque (designed to
be annoying to simplify statically), and are also exposed as a standalone
feature (see Opaque predicates).

This is primarily a code-size tradeoff; the untaken path shouldn't execute.

**Flags:**

- `-mllvm -bcf` - Enable
- `-mllvm -bcf_prob=<0-100>` - Probability per block (default: 30)
- `-mllvm -bcf_loop=<N>` - Iterations (default: 1)

---

## Block Splitting

Fragments basic blocks into smaller pieces connected by unconditional branches. Often used before flattening or BCF to give them more blocks to work with.

Mostly a size/layout transform. Unconditional branches are cheap, but too much
splitting will bloat the CFG and can hurt I-cache.

**Flags:**

- `-mllvm -split` - Enable
- `-mllvm -split_num=<2-10>` - Splits per block (default: 2)

---

## MBA (Mixed Boolean Arithmetic)

Replaces arithmetic and bitwise operations with algebraically equivalent MBA expressions.

Example: `a + b` -> `(a ^ b) + ((a & b) << 1)`

This increases instruction count and stays in straight-line code. Multiple
iterations can grow quickly.

**Flags:**

- `-mllvm -mba` - Enable
- `-mllvm -mba_loop=<N>` - Iterations (default: 1)
- `-mllvm -mba-max-ir-insts=<N>` - Max IR instruction count per function eligible for MBA (default: 0, 0 = unlimited)

---

## Substitution

Replaces arithmetic operations with equivalent multi-instruction sequences using random constants that cancel out.

Example: `a + b` -> `(a + r) + b - r` where `r` is random.

Fewer instructions than MBA, and usually easier to pattern-match back out.

**Flags:**

- `-mllvm -sub` - Enable
- `-mllvm -sub_loop=<N>` - Iterations (default: 1)

---

## Indirect calls / branches

Replaces direct calls and branches with table lookups. Targets are encoded in global tables and decoded at runtime.

**Indirect calls** build a module-wide function table. Entries are encoded with ADD and decoded with SUB (with XOR/SUB variants per site when `-indcall-vary-decode` is on). Split-key mode combines two globals at runtime.

**Indirect branches** build a per-function block address table encoded with a per-function key.

Skipped for correctness: EH/funclet functions, invokes, callbr, inline asm, musttail, operand bundles, intrinsics.

Expect extra ALU and loads per call/branch. Key loads are volatile to keep the
decode from being folded away.

**Flags:**

- `-mllvm -indcall` - Enable indirect calls
- `-mllvm -indbr` - Enable indirect branches
- `-mllvm -indcall-shuffle` - Shuffle table entries (default: true)
- `-mllvm -indcall-decoys=<N>` - Add N dummy entries that trap (default: 0)
- `-mllvm -indcall-split-key` - Use two-part key (default: true)
- `-mllvm -indcall-vary-decode` - Vary decode patterns per site (default: true)
- `-mllvm -indcall-check` - Null check before call, trap on failure (default: true)
- `-mllvm -indcall-preencode` - Pre-encode call table at compile time (default: true)
- `-mllvm -indcall-lazy-init` - Ensure call table init before use (default: true)
- `-mllvm -indcall-report=<path>` - Write per-module summary
- `-mllvm -indcall-report-per-module` - Use per-module report filenames (default: true)

---

## String obfuscation

Encrypts string literals at compile time. Strings are decoded on first use into
a separate buffer (the ciphertext stays read-only). Optional verification
rehashes the decoded buffer and re-decodes if it was clobbered.

**Flags:**

- `-mllvm -obf-str` - Enable
- `-mllvm -obf-str-prob=<0-100>` - Probability each string is obfuscated (default: 100)
- `-mllvm -obf-str-min=<N>` - Minimum string length (default: 4)
- `-mllvm -obf-str-max-bytes=<N>` - Total byte limit, 0=unlimited
- `-mllvm -obf-str-max-count=<N>` - Max strings, 0=unlimited
- `-mllvm -obf-str-include=<paths>` - Only obfuscate strings from matching source files
- `-mllvm -obf-str-exclude=<paths>` - Skip strings from matching source files
- `-mllvm -obf-str-verify=<0|1>` - Verify decoded strings on access (default: 1)

---

## Constant obfuscation

Replaces integer constants with runtime-computed expressions. Each constant is XOR-encoded with a volatile global key and a per-constant random value.

Adds a few instructions per constant. The global key is loaded volatile to avoid constant-folding.

**Flags:**

- `-mllvm -obf-const` - Enable
- `-mllvm -obf-const-prob=<0-100>` - Probability each constant is obfuscated (default: 40)
- `-mllvm -obf-const-minbits=<N>` - Minimum bit width to consider (default: 8)

---

## Opaque predicates

Generates conditions with a known result (true/false), but built to resist simplification. Used by BCF; the flags below control the predicate mix and complexity.

**Predicate types:**

- **DiffSquares** - Algebraic identity: `(a+b)(a-b) = a^2 - b^2`
- **XorEq** - XOR definition: `x^y = (~x&y)|(x&~y)`
- **Powmod** - Fermat's Little Theorem with 16-bit primes
- **Collatz** - Collatz conjecture (bounded to 64 iterations)
- **MinorQuadric** - Always-zero algebraic residual hostile to symbolic simplification
- **QSeries** - Finite q-series identity (q-binomial theorem)
- **Composite** - Combines MinorQuadric and QSeries residuals with per-module mixing constants

**Flags:**

- `-mllvm -opaque-pred-rate=<0-100>` - Use heavy predicates vs cheap fallback (default: 100)
- `-mllvm -opaque-pred-max-steps=<N>` - Max iterations for loop-based predicates (default: 64)
- `-mllvm -opaque-pred-collatz-mask-bits=<N>` - Mask bits for Collatz input (default: 16)
- `-mllvm -opaque-pred-collatz-variants=<N>` - Collatz helper variants per module (default: 8)
- `-mllvm -opaque-pred-powmod-variants=<N>` - Powmod helper variants per module (default: 4)
- `-mllvm -opaque-pred-minor-variants=<N>` - MinorQuadric helper variants per module (default: 2)
- `-mllvm -opaque-pred-qseries-variants=<N>` - QSeries helper variants per module (default: 1)
- `-mllvm -opaque-pred-composite-variants=<N>` - Composite helper variants per module (default: 1)
- `-mllvm -opaque-pred-w-diffsq=<N>` - Weight for DiffSquares (default: 35)
- `-mllvm -opaque-pred-w-xoreq=<N>` - Weight for XorEq (default: 35)
- `-mllvm -opaque-pred-w-powmod=<N>` - Weight for Powmod (default: 20)
- `-mllvm -opaque-pred-w-collatz=<N>` - Weight for Collatz (default: 10)
- `-mllvm -opaque-pred-w-minorquad=<N>` - Weight for MinorQuadric (default: 8)
- `-mllvm -opaque-pred-w-qseries=<N>` - Weight for QSeries (default: 6)
- `-mllvm -opaque-pred-w-composite=<N>` - Weight for Composite (default: 4)
- `-mllvm -opaque-pred-use-rc` - Use readcyclecounter when supported (default: true)

---

## IAT obfuscation (Windows x64 only)

Rewrites imported calls to avoid direct call sites. The default backend
(`thunk`) keeps the normal import table and uses an encoded pointer to the
import thunk (loader-safe). The `resolver` backend drops IAT entries and
resolves APIs at runtime via PEB walking and export table scanning.

In `thunk` mode, hide rules control which imports are rewritten, but IAT entries
are preserved. In `resolver` mode, missing imports show up at runtime instead
of at load time.

Resolver mode pays a one-time lookup cost per API; caching (default: on) makes
subsequent calls cheap. Hide-map module names are normalized (".dll" optional).
Loading missing modules only happens when `-obf-iat-load-missing` is explicitly
enabled (resolver mode only).

**Flags:**

- `-mllvm -obf-iat` - Enable
- `-mllvm -obf-iat-backend=<thunk|resolver>` - Backend (default: thunk)
- `-mllvm -obf-iat-cache` - Cache resolved pointers (default: true)
- `-mllvm -obf-iat-hide-only` - Only hide imports matching rules (default: false)
- `-mllvm -obf-iat-hide-all` - Hide all imports (default: false)
- `-mllvm -obf-hide-externs` - Obfuscate all external calls (not just dllimport)
- `-mllvm -obf-iat-hide-fn=<list>` - Specific functions to hide
- `-mllvm -obf-iat-hide-pfx=<list>` - Prefixes to hide (e.g., `Nt*`)
- `-mllvm -obf-iat-hide-map=<list>` - Module-specific patterns (".dll" optional): `"kernel32.dll:Virtual*|Create*"`
- `-mllvm -obf-iat-load-missing` - Allow LdrLoadDll for hide-map modules (resolver mode, default: false)
- `-mllvm -obf-iat-fail=<trap|null|fallback>` - Resolver miss behavior (default: trap; fallback skips obfuscation for non-hidden imports)
- `-mllvm -obf-iat-inline` - Inline resolver into callsites (default: true, avoids wrapper symbols)

---

## Full flag reference

All flags are passed as `-mllvm -<flag>`.

### Global

- `-obf-seed=<N>` - Deterministic seed for obfuscation randomness
- `-aesSeed=<str>` - Seed for AES-CTR PRNG (legacy)
- `-obf-dump-ir` - Dump IR before/after transforms
- `-obf-dump-dir=<path>` - Output directory for IR dumps
- `-obf-verify` - Verify IR after each transform
- `-obf-max-bb-growth=<%>` - Max basic block growth before stopping further transforms
- `-obf-max-inst-growth=<%>` - Max instruction growth before stopping further transforms
- `-obf-only-annotated` - Only run function passes on annotated functions
- `-obf-symbols[=true|false]` - Obfuscate helper symbol names
- `-obf-name-prefix=<str>` - Prefix for helper symbols (empty = random)

### Classic passes

- `-fla`
- `-bcf`
- `-bcf_prob=<0-100>`
- `-bcf_loop=<N>`
- `-split`
- `-split_num=<2-10>`
- `-mba`
- `-mba_loop=<N>`
- `-mba-max-ir-insts=<N>`
- `-sub`
- `-sub_loop=<N>`


### Opaque predicates

- `-opaque-pred-rate=<0-100>`
- `-opaque-pred-max-steps=<N>`
- `-opaque-pred-collatz-mask-bits=<N>`
- `-opaque-pred-collatz-variants=<N>`
- `-opaque-pred-powmod-variants=<N>`
- `-opaque-pred-minor-variants=<N>`
- `-opaque-pred-qseries-variants=<N>`
- `-opaque-pred-composite-variants=<N>`
- `-opaque-pred-w-diffsq=<N>`
- `-opaque-pred-w-xoreq=<N>`
- `-opaque-pred-w-powmod=<N>`
- `-opaque-pred-w-collatz=<N>`
- `-opaque-pred-w-minorquad=<N>`
- `-opaque-pred-w-qseries=<N>`
- `-opaque-pred-w-composite=<N>`
- `-opaque-pred-use-rc`

### Indirect calls / branches

- `-indcall`
- `-indbr`
- `-indcall-shuffle`
- `-indcall-decoys=<N>`
- `-indcall-split-key`
- `-indcall-vary-decode`
- `-indcall-check`
- `-indcall-preencode`
- `-indcall-lazy-init`
- `-indcall-report=<path>`
- `-indcall-report-per-module`

### String/constant obfuscation

- `-obf-str`
- `-obf-str-prob=<0-100>`
- `-obf-str-min=<N>`
- `-obf-str-max-bytes=<N>`
- `-obf-str-max-count=<N>`
- `-obf-str-include=<paths>`
- `-obf-str-exclude=<paths>`
- `-obf-str-verify=<0|1>`
- `-obf-const`
- `-obf-const-prob=<0-100>`
- `-obf-const-minbits=<N>`

### IAT / extern obfuscation (Windows only)

- `-obf-iat`
- `-obf-iat-backend=<thunk|resolver>`
- `-obf-iat-cache`
- `-obf-iat-hide-only`
- `-obf-iat-hide-all`
- `-obf-hide-externs`
- `-obf-iat-hide-fn=<list>`
- `-obf-iat-hide-pfx=<list>`
- `-obf-iat-hide-map=<list>`
- `-obf-iat-load-missing`
- `-obf-iat-fail=<trap|null|fallback>` (default: trap)
- `-obf-iat-inline`

### VM

- `-vm-mode=none|opcode|bb|region`
- `-vm-encode=off|affine|mba`
- `-vm-select=none|all|marked|cold`
- `-vm-select-path=<paths>`
- `-vm-handlers=static|random`
- `-vm-dispatch=switch|indirect`
- `-vm-hard`
- `-vm-hard-rt`
- `-vm-bogus=<N>`
- `-vm-max-bbs=<N>`
- `-vm-max-ir-insts=<N>`
- `-vm-max-bc-instrs=<N>`
- `-vm-max-runtime-insts=<N>`
- `-vm-max-stack-reg-bytes=<N>`
- `-vm-max-global-bytes=<N>`
- `-vm-cold-threshold=<N>`
- `-vm-validate`
- `-vm-debug`
- `-vm-debug-rt`
- `-vm-debug-max-instrs=<N>`
- `-vm-counters`
- `-vm-trace`
- `-vm-trace-limit=<N>`
- `-vm-bounds-check`
- `-vm-encode-feistel`
- `-vm-encode-feistel-all`
- `-vm-feistel-rounds=<N>`
- `-vm-encode-pct=<0-100>`
- `-vm-encode-full-marked`
- `-vm-encode-full-path=<paths>`
- `-vm-encode-full-max-instrs=<N>`
- `-vm-encode-max-instrs=<N>`
- `-vm-obf-runtime`
- `-vm-mba-max-growth=<%>`
- `-vm-encode-max-growth=<%>`
- `-vm-report=<path>`
- `-vm-skip-other-obf`
