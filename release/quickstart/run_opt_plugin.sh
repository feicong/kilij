#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/bin"
PLUGIN="$ROOT/lib/Kilij.so"
EXAMPLE="$ROOT/examples/_tmp_kilij_smoke.ll"

if [[ ! -x "$BIN/opt" ]]; then
  echo "ERROR: opt not found at $BIN/opt" >&2
  exit 1
fi
if [[ ! -f "$PLUGIN" ]]; then
  echo "ERROR: plugin not found at $PLUGIN" >&2
  exit 1
fi
if [[ ! -f "$EXAMPLE" ]]; then
  echo "ERROR: example not found at $EXAMPLE" >&2
  exit 1
fi

"$BIN/opt" -load-pass-plugin="$PLUGIN" -passes=kilij -disable-output "$EXAMPLE"

echo "OK: opt ran Kilij pipeline on $EXAMPLE"

