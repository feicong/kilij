#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash release/package_linux.sh --install-prefix <path> [--out <tar.xz>] [--name <dir>]

Creates a tar.xz that contains:
- the LLVM install prefix contents under <name>/
- quickstart scripts and examples under <name>/quickstart and <name>/examples
EOF
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

INSTALL_PREFIX=""
OUT=""
NAME=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-prefix) INSTALL_PREFIX="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$INSTALL_PREFIX" ]]; then
  echo "ERROR: --install-prefix is required" >&2
  usage
  exit 2
fi

if [[ ! -d "$INSTALL_PREFIX" ]]; then
  echo "ERROR: --install-prefix directory does not exist: $INSTALL_PREFIX" >&2
  echo "       Run build_linux.sh first to create the install prefix." >&2
  exit 1
fi

if [[ -z "$NAME" ]]; then
  arch="$(uname -m)"
  NAME="kilij-clang20-linux-$arch"
fi

if [[ -z "$OUT" ]]; then
  OUT="$ROOT/_release_out/linux/$NAME.tar.xz"
fi

prefix_parent="$(cd "$(dirname "$INSTALL_PREFIX")" && pwd)"
prefix_base="$(basename "$INSTALL_PREFIX")"

if [[ ! -x "$INSTALL_PREFIX/bin/clang" ]]; then
  echo "ERROR: missing $INSTALL_PREFIX/bin/clang" >&2
  echo "       The LLVM build may have failed. Check build output." >&2
  exit 1
fi
if [[ ! -x "$INSTALL_PREFIX/bin/opt" ]]; then
  echo "ERROR: missing $INSTALL_PREFIX/bin/opt" >&2
  exit 1
fi
if [[ ! -f "$INSTALL_PREFIX/lib/Kilij.so" ]]; then
  echo "ERROR: missing $INSTALL_PREFIX/lib/Kilij.so" >&2
  echo "       The Kilij pass was not built. Check the LLVM build output." >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Verify source directories exist.
if [[ ! -d "$ROOT/release/examples" ]]; then
  echo "ERROR: missing examples directory: $ROOT/release/examples" >&2
  exit 1
fi
if [[ ! -d "$ROOT/release/quickstart" ]]; then
  echo "ERROR: missing quickstart directory: $ROOT/release/quickstart" >&2
  exit 1
fi

mkdir -p "$tmp/$NAME/quickstart" "$tmp/$NAME/examples"
cp -f "$ROOT/release/examples/"* "$tmp/$NAME/examples/"
cp -f "$ROOT/release/quickstart/"*.sh "$tmp/$NAME/quickstart/"

cat >"$tmp/$NAME/README.md" <<EOF
# Kilij clang (Linux)

Quickstart:
1) bash quickstart/run_clang_obf_ir.sh
2) bash quickstart/run_opt_plugin.sh
EOF

mkdir -p "$(dirname "$OUT")"

# Validate quickly before packaging.
echo "Validating staged build ..."
smoke_ll="$ROOT/release/examples/_tmp_kilij_smoke.ll"
if [[ ! -f "$smoke_ll" ]]; then
  echo "ERROR: smoke test IR not found: $smoke_ll" >&2
  exit 1
fi
if ! "$INSTALL_PREFIX/bin/opt" -load-pass-plugin="$INSTALL_PREFIX/lib/Kilij.so" \
     -passes=kilij -disable-output "$smoke_ll" >/dev/null; then
  echo "ERROR: opt validation failed. The build may be broken." >&2
  exit 1
fi

echo "Creating release tarball: $OUT ..."
# Escape special regex chars in prefix_base for tar --transform.
prefix_base_escaped="$(printf '%s' "$prefix_base" | sed 's/[.[\*^$/]/\\&/g')"

tar -C "$prefix_parent" -cJf "$OUT" \
  --transform="s,^${prefix_base_escaped},$NAME," \
  "$prefix_base" \
  -C "$tmp" "$NAME"

ls -lah "$OUT"

