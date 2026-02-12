#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/bin"
EXAMPLE="$ROOT/examples/_tmp_kilij_smoke.c"
OUTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/out"

if [[ ! -x "$BIN/clang" ]]; then
  echo "ERROR: clang not found at $BIN/clang" >&2
  exit 1
fi
if [[ ! -f "$EXAMPLE" ]]; then
  echo "ERROR: example not found at $EXAMPLE" >&2
  exit 1
fi

mkdir -p "$OUTDIR"

"$BIN/clang" -O2 -S -emit-llvm "$EXAMPLE" -o "$OUTDIR/smoke_obf.ll" \
  -mllvm -obf-seed=123 \
  -mllvm -obf-str \
  -mllvm -fla \
  -mllvm -bcf

echo "Wrote $OUTDIR/smoke_obf.ll"

