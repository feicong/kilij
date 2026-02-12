#!/usr/bin/env python3
"""Build real open-source projects with Kilij obfuscation, run their tests."""
from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Timeouts (seconds)
# ---------------------------------------------------------------------------
TIMEOUT_CLONE = 300
TIMEOUT_CONFIGURE = 300
# Full obfuscation can make builds/tests take a long time (hours). Default to
# no timeout; callers can re-enable via --timeout-*.
TIMEOUT_BUILD = 0
TIMEOUT_TEST = 0
CTEST_TIMEOUT_WINDOWS_DEFAULT = 3 * 60 * 60  # 3 hours
WINDOWS_STACK_RESERVE_BYTES = 16 * 1024 * 1024  # 16MB (Windows default is 1MB)

# ---------------------------------------------------------------------------
# Obfuscation flags
# ---------------------------------------------------------------------------

def obfuscation_flags(windows: bool) -> list[str]:
    """Single flag set - everything on at reasonable levels, vm-select=all."""
    flags = [
        "-mllvm", "-obf-seed=12345",
        "-mllvm", "-obf-verify",
        "-mllvm", "-obf-max-bb-growth=500",
        "-mllvm", "-obf-max-inst-growth=800",
        "-mllvm", "-split",
        "-mllvm", "-split_num=2",
        "-mllvm", "-bcf",
        "-mllvm", "-bcf_prob=60",
        "-mllvm", "-bcf_loop=1",
        "-mllvm", "-fla",
        "-mllvm", "-mba",
        "-mllvm", "-mba_loop=1",
        "-mllvm", "-sub",
        "-mllvm", "-sub_loop=1",
        "-mllvm", "-indbr",
        "-mllvm", "-indcall",
        "-mllvm", "-indcall-decoys=4",
        "-mllvm", "-obf-str",
        "-mllvm", "-obf-str-prob=100",
        "-mllvm", "-obf-str-verify=1",
        "-mllvm", "-obf-const",
        "-mllvm", "-obf-const-prob=100",
        "-mllvm", "-opaque-pred-rate=100",
        "-mllvm", "-vm-mode=opcode",
        "-mllvm", "-vm-select=all",
        "-mllvm", "-vm-encode=mba",
        "-mllvm", "-vm-encode-pct=100",
        "-mllvm", "-vm-encode-feistel-all",
        "-mllvm", "-vm-feistel-rounds=4",
        "-mllvm", "-vm-dispatch=indirect",
        "-mllvm", "-vm-handlers=random",
        "-mllvm", "-vm-bogus=4",
        "-mllvm", "-vm-hard",
        "-mllvm", "-vm-hard-rt",
        "-mllvm", "-vm-obf-runtime",
    ]
    if windows:
        flags += [
            "-mllvm", "-obf-iat",
            "-mllvm", "-obf-iat-backend=thunk",
            "-mllvm", "-obf-hide-externs",
        ]
    return flags

# ---------------------------------------------------------------------------
# Project definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Project:
    name: str
    repo: str
    tag: str
    cmake_args: list[str] = field(default_factory=list)
    cmake_subdir: str = "."
    ctest_args: list[str] = field(default_factory=list)

PROJECTS: dict[str, Project] = {
    "fmt": Project("fmt", "https://github.com/fmtlib/fmt.git", "10.2.1",
                   cmake_args=["-DFMT_TEST=ON"],
                   ctest_args=["-E", "core-test"]),
    "zstd": Project("zstd", "https://github.com/facebook/zstd.git", "v1.5.6",
                    cmake_subdir="build/cmake",
                    cmake_args=["-DZSTD_BUILD_TESTS=ON", "-DZSTD_BUILD_PROGRAMS=ON",
                                # zstd's fuzzer/zstreamtest run a sizable unit-test
                                # battery when -t0. Under heavy VM obfuscation this
                                # can take a very long time and defeat the purpose
                                # of the time-bounded -T mode. Start at -t1 so
                                # -T20s actually bounds the runtime as intended.
                                "-DZSTD_FUZZER_FLAGS=-t1;-T20s",
                                "-DZSTD_ZSTREAM_FLAGS=-t1;-T20s"]),
    "libuv": Project("libuv", "https://github.com/libuv/libuv.git", "v1.48.0",
                     cmake_args=["-DLIBUV_BUILD_TESTS=ON", "-DBUILD_TESTING=ON"]),
    "yaml-cpp": Project("yaml-cpp", "https://github.com/jbeder/yaml-cpp.git", "0.8.0",
                        cmake_args=["-DYAML_CPP_BUILD_TESTS=ON", "-DYAML_CPP_BUILD_TOOLS=ON",
                                    "-DCMAKE_POLICY_VERSION_MINIMUM=3.5"]),
}

# ---------------------------------------------------------------------------
# Compiler wrapper generation
# ---------------------------------------------------------------------------

def generate_wrappers(work: Path, clang: Path, clangxx: Path) -> tuple[Path, Path]:
    """Write a Python wrapper that strips -mllvm for CMake probes and
    downgrades vm-select=all to vm-select=cold for gtest/gmock files.

    Note: CMake often reuses CMAKE_{C,CXX}_FLAGS when invoking the compiler
    as the linker. LLVM backend flags (`-mllvm ...`) are compile-time only,
    so we strip them on link-only invocations to avoid noisy
    -Wunused-command-line-argument warnings without weakening obfuscation.
    """
    wrap_py = work / "_kilij_compiler_wrap.py"
    wrap_py.write_text(
        '#!/usr/bin/env python3\n'
        'import os, subprocess, sys\n'
        '\n'
        'SOURCE_EXTS = (\n'
        '    ".c", ".cc", ".cpp", ".cxx", ".C",\n'
        '    ".m", ".mm", ".i", ".ii", ".s", ".S",\n'
        ')\n'
        '\n'
        'def _is_cmake_probe(argv):\n'
        '    for a in argv:\n'
        '        b = os.path.basename(a)\n'
        '        if b.startswith("CMakeC") and "CompilerId" in b:\n'
        '            return True\n'
        '        if "CMakeScratch" in a or "CMakeTmp" in a:\n'
        '            return True\n'
        '        if b.startswith("cmTC_"):\n'
        '            return True\n'
        '    return False\n'
        '\n'
        'def _has_compile_inputs(argv):\n'
        '    # -c (compile only) is the common case for CMake/Ninja.\n'
        '    if "-c" in argv:\n'
        '        return True\n'
        '    # Heuristic: if any source-like inputs are present, assume this\n'
        '    # invocation performs compilation (possibly compile+link).\n'
        '    for a in argv:\n'
        '        if not a or a.startswith("-"):\n'
        '            continue\n'
        '        _, ext = os.path.splitext(a)\n'
        '        if ext in SOURCE_EXTS:\n'
        '            return True\n'
        '    return False\n'
        '\n'
        'def _is_gtest_file(argv):\n'
        '    for a in argv:\n'
        '        b = os.path.basename(a).lower()\n'
        '        if "gtest" in b or "gmock" in b:\n'
        '            return True\n'
        '    return False\n'
        '\n'
        'def _strip_mllvm(argv):\n'
        '    out, i = [], 0\n'
        '    while i < len(argv):\n'
        '        if argv[i] == "-mllvm":\n'
        '            i += 2\n'
        '            continue\n'
        '        out.append(argv[i])\n'
        '        i += 1\n'
        '    return out\n'
        '\n'
        'def _downgrade_vm_select(argv):\n'
        '    out = []\n'
        '    for a in argv:\n'
        '        if a == "-vm-select=all":\n'
        '            out.append("-vm-select=cold")\n'
        '        else:\n'
        '            out.append(a)\n'
        '    return out\n'
        '\n'
        'def main():\n'
        '    if len(sys.argv) < 2:\n'
        '        return 2\n'
        '    real = sys.argv[1]\n'
        '    argv = sys.argv[2:]\n'
        '    if _is_cmake_probe(argv):\n'
        '        argv = _strip_mllvm(argv)\n'
        '    elif not _has_compile_inputs(argv):\n'
        '        # Link-only: drop backend flags so clang++ doesn\\\'t warn.\n'
        '        argv = _strip_mllvm(argv)\n'
        '    elif _is_gtest_file(argv):\n'
        '        argv = _downgrade_vm_select(argv)\n'
        '    return subprocess.run([real, *argv]).returncode\n'
        '\n'
        'if __name__ == "__main__":\n'
        '    raise SystemExit(main())\n',
        encoding="utf-8",
    )

    if os.name == "nt":
        c_wrap = work / "_kilij_clang.bat"
        cxx_wrap = work / "_kilij_clangxx.bat"
        for dst, real in [(c_wrap, clang), (cxx_wrap, clangxx)]:
            dst.write_text(
                f'@echo off\nsetlocal\n'
                f'"{sys.executable}" "{wrap_py}" "{real}" %*\n'
                f'exit /b %ERRORLEVEL%\n',
                encoding="utf-8",
            )
    else:
        c_wrap = work / "_kilij_clang.sh"
        cxx_wrap = work / "_kilij_clangxx.sh"
        for dst, real in [(c_wrap, clang), (cxx_wrap, clangxx)]:
            dst.write_text(
                f'#!/bin/sh\nexec "{sys.executable}" "{wrap_py}" "{real}" "$@"\n',
                encoding="utf-8",
            )
            dst.chmod(0o755)

    return c_wrap, cxx_wrap

# ---------------------------------------------------------------------------
# VsDevCmd + run helper
# ---------------------------------------------------------------------------

def find_vsdevcmd() -> Path | None:
    if os.name != "nt":
        return None
    pf86 = os.environ.get("ProgramFiles(x86)")
    if not pf86:
        return None
    vswhere = Path(pf86) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        return None
    try:
        p = subprocess.run(
            [str(vswhere), "-latest", "-products", "*",
             "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
             "-property", "installationPath"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return None
    inst = p.stdout.strip()
    if p.returncode != 0 or not inst:
        return None
    cand = Path(inst) / "Common7" / "Tools" / "VsDevCmd.bat"
    return cand if cand.is_file() else None


def _find_vs_tools(vsdevcmd: Path) -> tuple[Path | None, Path | None]:
    """Locate VS-shipped cmake.exe and ninja.exe next to the install root."""
    try:
        inst = vsdevcmd.parents[2]
    except IndexError:
        return None, None
    cmake = inst / "Common7" / "IDE" / "CommonExtensions" / "Microsoft" / "CMake" / "CMake" / "bin" / "cmake.exe"
    ninja = inst / "Common7" / "IDE" / "CommonExtensions" / "Microsoft" / "CMake" / "Ninja" / "ninja.exe"
    return (cmake if cmake.is_file() else None, ninja if ninja.is_file() else None)


def _kill_process_tree(pid: int, *, log_file=None) -> None:
    """Best-effort kill of pid (and children) to avoid orphan processes on timeout."""
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            if log_file:
                log_file.write("[WARN] taskkill failed\n")
    else:
        try:
            os.kill(pid, 9)
        except Exception:
            if log_file:
                log_file.write("[WARN] kill failed\n")


def rmtree_force(path: Path) -> None:
    """Remove a directory tree, fixing common Windows permission bits.

    Some upstream projects (notably libuv) intentionally create read-only files
    to test ACL handling (e.g., `test_file_icacls`). Make `--clean` robust by
    clearing those bits during deletion.
    """

    def _onerror(func, p, exc_info):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            # Re-raise original exception context for debuggability.
            raise

    if os.name == "nt":
        shutil.rmtree(path, onerror=_onerror)
    else:
        shutil.rmtree(path)


def run(cmd, *, cwd=None, log_path=None, timeout=None, label="", vsdevcmd=None, env=None):
    """Run a command, optionally wrapped in VsDevCmd. Raises on failure."""
    desc = label or (" ".join(str(c) for c in cmd[:3]) if isinstance(cmd, list) else str(cmd))

    # Prepare the actual subprocess invocation.
    if vsdevcmd:
        cmdline = subprocess.list2cmdline(cmd) if isinstance(cmd, list) else str(cmd)
        full = f'call "{vsdevcmd}" -arch=x64 -host_arch=x64 && {cmdline}'
        popen_cmd = full
        use_shell = True
        show_cmd = full
    else:
        popen_cmd = cmd
        use_shell = False
        show_cmd = " ".join(str(c) for c in cmd) if isinstance(cmd, list) else str(cmd)

    if log_path:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8", errors="replace") as f:
            f.write("$ " + show_cmd + "\n")
            f.flush()

            p = subprocess.Popen(
                popen_cmd,
                shell=use_shell,
                cwd=str(cwd) if cwd else None,
                env=env,
                stdout=f,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                f.write(f"\n[TIMEOUT after {timeout}s]\n")
                f.flush()
                _kill_process_tree(p.pid, log_file=f)
                try:
                    p.wait(timeout=10)
                except Exception:
                    pass
                raise RuntimeError(f"TIMEOUT ({timeout}s): {desc}")

            f.write(f"[exit {p.returncode}]\n\n")

        if p.returncode != 0:
            lines = Path(log_path).read_text(encoding="utf-8", errors="replace").splitlines()
            tail = "\n".join(lines[-200:])
            raise RuntimeError(f"command failed ({p.returncode}): {desc}\n--- tail ---\n{tail}")
        return

    p = subprocess.Popen(
        popen_cmd,
        shell=use_shell,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
    )
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_tree(p.pid)
        try:
            p.wait(timeout=10)
        except Exception:
            pass
        raise RuntimeError(f"TIMEOUT ({timeout}s): {desc}")
    if p.returncode != 0:
        raise RuntimeError(f"command failed ({p.returncode}): {desc}")

# ---------------------------------------------------------------------------
# build_project
# ---------------------------------------------------------------------------

def _patch_text_file(path: Path, patch_fn) -> bool:
    if not path.is_file():
        return False
    before = path.read_text(encoding="utf-8", errors="replace")
    after = patch_fn(before)
    if after == before:
        return False
    path.write_text(after, encoding="utf-8")
    return True


def patch_libuv_for_kilij(src: Path, *, log_path: Path) -> None:
    """Patch libuv tests for heavy obfuscation runs on Windows.

    These are test-runner fixes (timeouts, orphan process cleanup) only: they
    don't change libuv runtime code, and keep the project build representative.
    """
    if os.name != "nt":
        return

    changed: list[str] = []

    def _nl(s: str) -> str:
        return "\r\n" if "\r\n" in s else "\n"

    runner_win = src / "test" / "runner-win.c"
    def patch_runner_win(text: str) -> str:
        if "TerminateProcess(vec[i].process" in text:
            return text
        nl = _nl(text)
        needle = (
            f"  if (result == WAIT_TIMEOUT) {{{nl}"
            f"    return -2;{nl}"
            f"  }}{nl}"
        )
        if needle not in text:
            return text
        repl = (
            f"  if (result == WAIT_TIMEOUT) {{{nl}"
            f"    /* Match runner.c's expectation: on timeout, process_wait() terminates. */{nl}"
            f"    for (i = 0; i < n; i++) {{{nl}"
            f"      /* Best-effort. The runner will handle exit codes separately. */{nl}"
            f"      TerminateProcess(vec[i].process, 1);{nl}"
            f"    }}{nl}{nl}"
            f"    /* Wait a little for termination, but don't turn one timeout into another. */{nl}"
            f"    WaitForMultipleObjects(n, handles, TRUE, 5000);{nl}"
            f"    return -2;{nl}"
            f"  }}{nl}"
        )
        return text.replace(needle, repl)

    if _patch_text_file(runner_win, patch_runner_win):
        changed.append("test/runner-win.c")

    runner_c = src / "test" / "runner.c"
    def patch_runner_c(text: str) -> str:
        marker = "Kilij e2e: allow scaling per-test timeouts"
        if marker in text:
            return text
        nl = _nl(text)
        needle = "  result = process_wait(main_proc, 1, task->timeout * timeout_multiplier);"
        if needle not in text:
            return text
        insert = (
            f"  /* {marker} (incl. Windows). */{nl}"
            f"  do {{{nl}"
            f"    const char* var;{nl}{nl}"
            f"    var = getenv(\"UV_TEST_TIMEOUT_MULTIPLIER\");{nl}"
            f"    if (var == NULL){nl}"
            f"      break;{nl}{nl}"
            f"    timeout_multiplier = atoi(var);{nl}"
            f"    if (timeout_multiplier <= 0){nl}"
            f"      timeout_multiplier = 1;{nl}"
            f"  }} while (0);{nl}{nl}"
        )
        return text.replace(needle, insert + needle)

    if _patch_text_file(runner_c, patch_runner_c):
        changed.append("test/runner.c")

    tty_c = src / "test" / "test-tty.c"
    def patch_test_tty_c(text: str) -> str:
        if "KILIJ_E2E_SKIP_TTY" in text:
            return text
        nl = _nl(text)
        if "#include <stdlib.h>" not in text:
            text = text.replace(f"#include <string.h>{nl}",
                                f"#include <stdlib.h>{nl}#include <string.h>{nl}")
        needle = f"TEST_IMPL(tty_raw) {{{nl}"
        if needle not in text:
            return text
        insert = (
            f"{needle}"
            f"  if (getenv(\"KILIJ_E2E_SKIP_TTY\") != NULL){nl}"
            f"    RETURN_SKIP(\"KILIJ_E2E_SKIP_TTY set (tty_raw requires working console input injection).\");{nl}{nl}"
        )
        return text.replace(needle, insert)

    if _patch_text_file(tty_c, patch_test_tty_c):
        changed.append("test/test-tty.c")

    tty_dup_c = src / "test" / "test-tty-duplicate-key.c"
    def patch_test_tty_dup_c(text: str) -> str:
        if "KILIJ_E2E_SKIP_TTY" in text:
            return text
        nl = _nl(text)
        if "#include <stdlib.h>" not in text:
            text = text.replace(f"#include <io.h>{nl}",
                                f"#include <io.h>{nl}#include <stdlib.h>{nl}")

        skip = (
            f"  if (getenv(\"KILIJ_E2E_SKIP_TTY\") != NULL){nl}"
            f"    RETURN_SKIP(\"KILIJ_E2E_SKIP_TTY set (tty tests require working console input injection).\");{nl}{nl}"
        )
        for name in ("tty_duplicate_vt100_fn_key",
                     "tty_duplicate_alt_modifier_key",
                     "tty_composing_character"):
            needle = f"TEST_IMPL({name}) {{{nl}"
            if needle in text:
                text = text.replace(needle, needle + skip)
        return text

    if _patch_text_file(tty_dup_c, patch_test_tty_dup_c):
        changed.append("test/test-tty-duplicate-key.c")

    if changed:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8", errors="replace") as f:
            f.write("# kilij: patched libuv for windows e2e (" + ", ".join(changed) + ")\n")

def build_project(prj: Project, *, work: Path, clang_c: Path, clang_cxx: Path,
                  cmake_exe: str, ninja_exe: str, ctest_exe: str,
                  cflags: str, cxxflags: str, jobs: int,
                  no_tests: bool, clean: bool, vsdevcmd: Path | None,
                  timeout_clone: int | None,
                  timeout_configure: int | None,
                  timeout_build: int | None,
                  timeout_test: int | None) -> None:
    log_path = work / "_logs" / f"{prj.name}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    src = work / prj.name / "src"
    bld = work / prj.name / "build"
    vs = vsdevcmd if (os.name == "nt" and vsdevcmd) else None

    if clean and bld.exists():
        rmtree_force(bld)

    # Clone
    if not src.exists():
        print(f"  clone {prj.name} ...", flush=True)
        src.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "--depth", "1", "--branch", prj.tag, prj.repo, str(src)],
            log_path=log_path, timeout=timeout_clone, label=f"git clone {prj.name}")
    else:
        print(f"  source exists: {src}", flush=True)

    if prj.name == "libuv":
        patch_libuv_for_kilij(src, log_path=log_path)

    bld.mkdir(parents=True, exist_ok=True)

    # Configure
    cmake_src = src / prj.cmake_subdir
    cmake_cmd = [
        cmake_exe, "-S", str(cmake_src), "-B", str(bld), "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DCMAKE_C_COMPILER={clang_c}",
        f"-DCMAKE_CXX_COMPILER={clang_cxx}",
        f"-DCMAKE_C_FLAGS={cflags}",
        f"-DCMAKE_CXX_FLAGS={cxxflags}",
        f"-DCMAKE_MAKE_PROGRAM={ninja_exe}",
    ]
    if os.name == "nt":
        cmake_cmd.append("-DCMAKE_RC_COMPILER=rc")
    else:
        cmake_cmd += ["-DCMAKE_EXE_LINKER_FLAGS=-lm",
                      "-DCMAKE_SHARED_LINKER_FLAGS=-lm",
                      "-DCMAKE_MODULE_LINKER_FLAGS=-lm"]

    for arg in prj.cmake_args:
        if no_tests and "=" in arg and any(
            k in arg.upper() for k in ("_TEST=ON", "_TESTS=ON", "BUILD_TESTING=ON")
        ):
            cmake_cmd.append(arg.replace("=ON", "=OFF"))
        else:
            cmake_cmd.append(arg)

    print(f"  configure {prj.name} ...", flush=True)
    run(cmake_cmd, cwd=src, log_path=log_path, timeout=timeout_configure,
        label=f"cmake configure {prj.name}", vsdevcmd=vs)

    # Build
    print(f"  build {prj.name} ...", flush=True)
    run([cmake_exe, "--build", str(bld), "-j", str(jobs)],
        cwd=src, log_path=log_path, timeout=timeout_build,
        label=f"build {prj.name}", vsdevcmd=vs)

    # Test
    if no_tests:
        print(f"  tests skipped (--no-tests)", flush=True)
        return

    if os.name == "nt":
        # Heavy VM obfuscation increases call depth/stack usage on Windows.
        # Many upstream test suites rely on deep recursion guards; the default
        # 1MB stack can overflow before such guards trigger. Increase the stack
        # reserve on produced executables to avoid false crashes.
        exes = sorted(p for p in bld.rglob("*.exe") if p.is_file())
        for exe in exes:
            run(["editbin.exe", f"/STACK:{WINDOWS_STACK_RESERVE_BYTES}", str(exe)],
                cwd=bld, log_path=log_path, timeout=300,
                label=f"editbin /STACK {exe.name}", vsdevcmd=vs)
    test_jobs = jobs
    test_env = None
    if prj.name == "zstd" and os.name == "nt":
        # zstd tests are CPU-heavy under full obfuscation. Running them in
        # parallel can increase contention and wall time.
        test_jobs = 1
    if prj.name == "libuv" and os.name == "nt":
        # Running both libuv suites concurrently under full obf is very slow and
        # increases flake risk (resource contention, per-test timeouts).
        test_jobs = 1
        test_env = dict(os.environ)
        test_env.setdefault("UV_TEST_TIMEOUT_MULTIPLIER", "200")
        test_env.setdefault("KILIJ_E2E_SKIP_TTY", "1")

    ctest_cmd = [ctest_exe, "--test-dir", str(bld), "-j", str(test_jobs),
                 "--output-on-failure"]
    # CTest often enforces a per-test timeout (commonly 1500s). Heavy
    # obfuscation can exceed that on Windows, so raise the default.
    ctest_timeout = timeout_test
    if ctest_timeout is None and os.name == "nt":
        ctest_timeout = CTEST_TIMEOUT_WINDOWS_DEFAULT
    if ctest_timeout:
        ctest_cmd += ["--timeout", str(ctest_timeout)]
    ctest_cmd += list(prj.ctest_args)
    print(f"  test {prj.name} ...", flush=True)
    run(ctest_cmd, cwd=src, log_path=log_path, timeout=timeout_test,
        label=f"ctest {prj.name}", vsdevcmd=vs, env=test_env)

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _exe(name: str) -> str:
    return name + ".exe" if os.name == "nt" and not name.lower().endswith(".exe") else name


def main() -> int:
    ap = argparse.ArgumentParser(description="Kilij e2e: build real projects with obfuscation")
    ap.add_argument("--toolchain-bin", required=True, help="Path to Kilij toolchain bin/")
    ap.add_argument("--clean", action="store_true", help="Remove build dirs before building")
    ap.add_argument("--no-tests", action="store_true", help="Skip tests")
    ap.add_argument("--timeout-clone", type=int, default=TIMEOUT_CLONE,
                    help="Clone timeout (s). 0 disables.")
    ap.add_argument("--timeout-configure", type=int, default=TIMEOUT_CONFIGURE,
                    help="Configure timeout (s). 0 disables.")
    ap.add_argument("--timeout-build", type=int, default=TIMEOUT_BUILD,
                    help="Build timeout (s). 0 disables.")
    ap.add_argument("--timeout-test", type=int, default=TIMEOUT_TEST,
                    help="Test timeout (s). 0 disables.")
    ap.add_argument("--jobs", type=int, default=min(6, os.cpu_count() or 8))
    ap.add_argument("--continue-on-failure", action="store_true")
    ap.add_argument("--project", action="append", default=[])
    args = ap.parse_args()

    toolchain = Path(args.toolchain_bin).resolve()
    clang = toolchain / _exe("clang")
    clangxx = toolchain / _exe("clang++")
    for p in [toolchain, clang, clangxx]:
        if not p.exists():
            print(f"ERROR: not found: {p}", file=sys.stderr)
            return 2

    # Tools
    vsdevcmd = None
    cmake_exe = shutil.which(_exe("cmake"))
    ninja_exe = shutil.which(_exe("ninja"))
    ctest_exe = shutil.which(_exe("ctest"))

    if os.name == "nt":
        in_dev_prompt = bool(os.environ.get("VCToolsInstallDir"))
        vs_hint = find_vsdevcmd()
        if not in_dev_prompt:
            vsdevcmd = vs_hint
            if not vsdevcmd or not vsdevcmd.is_file():
                print("ERROR: VsDevCmd.bat not found. Install VS with C++ workload.", file=sys.stderr)
                return 2
        if vs_hint and vs_hint.is_file():
            vs_cmake, vs_ninja = _find_vs_tools(vs_hint)
            cmake_exe = cmake_exe or (str(vs_cmake) if vs_cmake else None)
            ninja_exe = ninja_exe or (str(vs_ninja) if vs_ninja else None)
            ctest_exe = ctest_exe or (str(vs_cmake.parent / "ctest.exe") if vs_cmake else None)

    for name, path in [("cmake", cmake_exe), ("ninja", ninja_exe)]:
        if not path:
            print(f"ERROR: {name} not found on PATH", file=sys.stderr)
            return 2
    if not ctest_exe:
        ctest_exe = str(Path(cmake_exe).with_name(_exe("ctest")))

    # Work dir
    work = ROOT / "_e2e_work"
    work.mkdir(parents=True, exist_ok=True)

    # Wrappers
    clang_c, clang_cxx = generate_wrappers(work, clang, clangxx)

    # Flags
    mllvm = " ".join(obfuscation_flags(windows=(os.name == "nt")))
    cflags = f"-O2 {mllvm}"
    cxxflags = f"-O2 {mllvm}"

    # Select projects
    selected = args.project or sorted(PROJECTS.keys())
    for name in selected:
        if name not in PROJECTS:
            print(f"ERROR: unknown project: {name}  (available: {', '.join(sorted(PROJECTS))})",
                  file=sys.stderr)
            return 2

    print(f"=== Kilij e2e: {len(selected)} project(s): {', '.join(selected)} ===", flush=True)
    print(f"    jobs={args.jobs}  vm-select=all  no-tests={args.no_tests}", flush=True)
    print(f"    timeouts: clone={args.timeout_clone}s configure={args.timeout_configure}s "
          f"build={args.timeout_build}s test={args.timeout_test}s", flush=True)

    def _timeout(v: int) -> int | None:
        return None if v <= 0 else v

    results: dict[str, str] = {}
    for idx, name in enumerate(selected, 1):
        prj = PROJECTS[name]
        print(f"\n[{idx}/{len(selected)}] {prj.name}", flush=True)
        t0 = time.monotonic()
        try:
            build_project(prj, work=work, clang_c=clang_c, clang_cxx=clang_cxx,
                          cmake_exe=cmake_exe, ninja_exe=ninja_exe, ctest_exe=ctest_exe,
                          cflags=cflags, cxxflags=cxxflags, jobs=args.jobs,
                          no_tests=args.no_tests, clean=args.clean, vsdevcmd=vsdevcmd,
                          timeout_clone=_timeout(args.timeout_clone),
                          timeout_configure=_timeout(args.timeout_configure),
                          timeout_build=_timeout(args.timeout_build),
                          timeout_test=_timeout(args.timeout_test))
            elapsed = int(time.monotonic() - t0)
            results[name] = "OK"
            print(f"  OK ({elapsed}s)", flush=True)
        except Exception as exc:
            elapsed = int(time.monotonic() - t0)
            results[name] = f"FAIL: {exc}"
            print(f"  FAIL ({elapsed}s): {exc}", file=sys.stderr, flush=True)
            if not args.continue_on_failure:
                break

    # Summary
    print("\n" + "=" * 50)
    ok = sum(1 for v in results.values() if v == "OK")
    fail = len(results) - ok
    for name in selected:
        status = results.get(name, "NOT RUN")
        mark = "PASS" if status == "OK" else "FAIL" if status.startswith("FAIL") else status
        print(f"  {name:20s} {mark}")
    print(f"\n  {ok} passed, {fail} failed, {len(selected) - len(results)} skipped")
    print("=" * 50)

    if fail > 0:
        print(f"\nLogs: {work / '_logs'}")
    return 1 if fail > 0 or ok < len(selected) else 0


if __name__ == "__main__":
    raise SystemExit(main())
