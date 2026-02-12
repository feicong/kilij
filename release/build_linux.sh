#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------------------------------------------------------------------
# Safety: verify the Kilij repo root is NOT the LLVM repo.
# A previous bug set origin to llvm-project.git, pulling 585K commits.
# ---------------------------------------------------------------------------
if [[ -d "$ROOT/.git" ]]; then
  _root_origin="$(git -C "$ROOT" remote get-url origin 2>/dev/null || true)"
  if [[ "$_root_origin" == *"llvm/llvm-project"* ]]; then
    echo "FATAL: The Kilij repo root ($ROOT) has origin pointing at llvm-project!" >&2
    echo "       origin = $_root_origin" >&2
    echo "       This is a corrupted state. Fix the remote before running this script." >&2
    exit 1
  fi
  _root_commit_count="$(git -C "$ROOT" rev-list --count HEAD 2>/dev/null || echo 0)"
  if [[ "$_root_commit_count" -gt 500 ]]; then
    echo "FATAL: The Kilij repo root ($ROOT) has $_root_commit_count commits." >&2
    echo "       This looks like the LLVM repo was merged in. Refusing to continue." >&2
    exit 1
  fi
  unset _root_origin _root_commit_count
fi

LLVM_PROJECT_DIR="${LLVM_PROJECT_DIR:-$ROOT/_llvm/llvm-project-linux}"
# Pinned LLVM 20.x ref (tag or commit).
LLVM_COMMIT="${LLVM_COMMIT:-llvmorg-20.1.0}"
BUILD_DIR="${BUILD_DIR:-$ROOT/_build/linux-release}"
INSTALL_PREFIX="${INSTALL_PREFIX:-$ROOT/_install/kilij-llvm20-linux-install}"
JOBS="${JOBS:-8}"
QUIET="${QUIET:-0}"

# ---------------------------------------------------------------------------
# assert_own_git_repo DIR
#   Verify DIR is its own git root (not a child of another repo).
# ---------------------------------------------------------------------------
assert_own_git_repo() {
  local d="$1"
  if [[ ! -d "$d/.git" ]]; then
    echo "ERROR: safety check failed: $d is not a git repo (missing .git)" >&2
    exit 1
  fi
  local top
  top="$(git -C "$d" rev-parse --show-toplevel 2>/dev/null || true)"
  if [[ -z "$top" ]]; then
    echo "ERROR: safety check failed: unable to query git top-level for $d" >&2
    exit 1
  fi
  local expected
  expected="$(cd "$d" && pwd)"
  if [[ "$top" != "$expected" ]]; then
    echo "ERROR: safety check failed: git top-level for $d is $top (expected $expected)" >&2
    echo "Refusing to continue because this could operate on a parent repo." >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# assert_not_kilij_root DIR
#   Abort if DIR resolves to the Kilij repo root (prevents operating on self).
# ---------------------------------------------------------------------------
assert_not_kilij_root() {
  local resolved
  resolved="$(cd "$1" 2>/dev/null && pwd)" || return 0
  if [[ "$resolved" == "$ROOT" ]]; then
    echo "FATAL: LLVM_PROJECT_DIR resolved to the Kilij repo root ($ROOT)." >&2
    echo "       This would corrupt the source repo. Aborting." >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Ensure LLVM_PROJECT_DIR is under _llvm/ (not the repo root itself).
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$LLVM_PROJECT_DIR")"
mkdir -p "$LLVM_PROJECT_DIR"
assert_not_kilij_root "$LLVM_PROJECT_DIR"

if [[ ! -d "$LLVM_PROJECT_DIR/.git" ]]; then
  # Only initialize if empty (avoid stomping on user content).
  if [[ -n "$(ls -A "$LLVM_PROJECT_DIR" 2>/dev/null || true)" ]]; then
    echo "ERROR: LLVM_PROJECT_DIR exists but is not a git repo: $LLVM_PROJECT_DIR" >&2
    echo "Delete it or set LLVM_PROJECT_DIR to an empty folder." >&2
    exit 1
  fi
  echo "Initializing LLVM shallow clone in $LLVM_PROJECT_DIR ..."
  git -C "$LLVM_PROJECT_DIR" init >/dev/null
  git -C "$LLVM_PROJECT_DIR" remote add origin https://github.com/llvm/llvm-project.git
else
  assert_own_git_repo "$LLVM_PROJECT_DIR"
  origin="$(git -C "$LLVM_PROJECT_DIR" remote get-url origin 2>/dev/null || true)"
  if [[ -z "$origin" ]]; then
    git -C "$LLVM_PROJECT_DIR" remote add origin https://github.com/llvm/llvm-project.git
  elif [[ "$origin" != "https://github.com/llvm/llvm-project.git" ]]; then
    echo "WARNING: resetting LLVM origin from $origin to llvm-project.git" >&2
    git -C "$LLVM_PROJECT_DIR" remote set-url origin https://github.com/llvm/llvm-project.git
  fi
fi

assert_own_git_repo "$LLVM_PROJECT_DIR"

# Double-check: the LLVM dir must NOT be the Kilij repo.
assert_not_kilij_root "$LLVM_PROJECT_DIR"

# A previous interrupted fetch/checkout can leave these behind; safe to remove.
rm -f "$LLVM_PROJECT_DIR/.git/index.lock" \
      "$LLVM_PROJECT_DIR/.git/shallow.lock" 2>/dev/null || true

echo "Fetching LLVM $LLVM_COMMIT (shallow) ..."
if ! git -C "$LLVM_PROJECT_DIR" fetch --depth 1 origin "$LLVM_COMMIT"; then
  echo "ERROR: git fetch failed for $LLVM_COMMIT." >&2
  echo "       Check network connectivity and that the ref/tag exists." >&2
  exit 1
fi
git -C "$LLVM_PROJECT_DIR" checkout --detach -f FETCH_HEAD

# ---------------------------------------------------------------------------
# Apply Kilij in-tree build patch (idempotent).
# ---------------------------------------------------------------------------
patch="$ROOT/release/patches/kilij_in_tree_clang.patch"
if [[ ! -f "$patch" ]]; then
  echo "ERROR: patch file not found: $patch" >&2
  exit 1
fi
if git -C "$LLVM_PROJECT_DIR" apply --check "$patch" >/dev/null 2>&1; then
  echo "Applying patch: $patch"
  git -C "$LLVM_PROJECT_DIR" apply "$patch"
else
  # Check whether already applied (reverse-applies cleanly).
  if git -C "$LLVM_PROJECT_DIR" apply -R --check "$patch" >/dev/null 2>&1; then
    echo "Patch already applied: $patch"
  else
    echo "ERROR: patch did not apply cleanly and is not already applied: $patch" >&2
    echo "       The LLVM tree may be in an inconsistent state." >&2
    echo "       Try deleting $LLVM_PROJECT_DIR and re-running." >&2
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Copy Kilij sources into the LLVM tree (excluding build/release artifacts).
# ---------------------------------------------------------------------------
dst="$LLVM_PROJECT_DIR/llvm/lib/Transforms/Obfuscation"
mkdir -p "$dst"

set +e
rsync -a \
  --exclude '.git' \
  --exclude '.claude' \
  --exclude 'release' \
  --exclude 'e2e' \
  --exclude 'kilij-tests' \
  --exclude '_llvm' \
  --exclude '_build' \
  --exclude '_install' \
  --exclude '_release_out' \
  --exclude '_e2e_work' \
  --exclude '_e2e_work*' \
  --exclude '*.zip' \
  "$ROOT/" "$dst/"
rc=$?
set -e
if [[ $rc -ne 0 && $rc -ne 24 ]]; then
  echo "ERROR: rsync failed with exit code $rc" >&2
  exit $rc
fi

# ---------------------------------------------------------------------------
# Configure.
# ---------------------------------------------------------------------------
echo "Configuring LLVM build in $BUILD_DIR ..."
if ! cmake -S "$LLVM_PROJECT_DIR/llvm" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_TARGETS_TO_BUILD="X86" \
  -DLLVM_INCLUDE_TESTS=OFF \
  -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DLLVM_ENABLE_ASSERTIONS=OFF \
  -DLLVM_BUILD_LLVM_DYLIB=ON \
  -DLLVM_LINK_LLVM_DYLIB=ON \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"; then
  echo "ERROR: cmake configuration failed. Check the output above." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Build + install.
# ---------------------------------------------------------------------------
NINJA_FLAGS=()
if [[ "$QUIET" == "1" ]]; then
  NINJA_FLAGS+=("-q")
fi

echo "Building LLVM (jobs=$JOBS) ..."
if ! ninja -C "$BUILD_DIR" "${NINJA_FLAGS[@]}" -j "$JOBS" install; then
  echo "ERROR: ninja build failed. Check the output above." >&2
  echo "       Common causes: out of disk space, out of memory, missing deps." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Package into a release tarball.
# ---------------------------------------------------------------------------
bash "$ROOT/release/package_linux.sh" \
  --install-prefix "$INSTALL_PREFIX" \
  --out "$ROOT/_release_out/linux/kilij-clang20-linux-x86_64.tar.xz" \
  --name "kilij-clang20-linux-x86_64"
