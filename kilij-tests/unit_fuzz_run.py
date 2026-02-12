#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parents[1]
BUILD_BIN = ROOT / "llvm-20-build-kilij" / "bin"
INSTALL_BIN = ROOT / "llvm-20-install" / "bin"

_verbose = False


def _log(msg: str) -> None:
    if _verbose:
        print(f"  [info] {msg}", file=sys.stderr, flush=True)


class TestFailure(RuntimeError):
    pass


def _exe(name: str) -> str:
    if os.name == "nt" and not name.lower().endswith(".exe"):
        return name + ".exe"
    return name


def find_tool(name: str, override: Optional[str]) -> Path:
    if override:
        p = Path(override)
        if p.is_file():
            return p
        # If override looks like a bare name (no path separators), try PATH.
        if os.sep not in override and (os.name != "nt" or "/" not in override):
            found = shutil.which(override)
            if found:
                return Path(found)
        raise FileNotFoundError(
            f"tool override not found: {override!r} (not a file, not on PATH)"
        )
    for base in (BUILD_BIN, INSTALL_BIN):
        cand = base / _exe(name)
        if cand.is_file():
            return cand
    found = shutil.which(_exe(name))
    if found:
        return Path(found)
    raise FileNotFoundError(
        f"unable to find {name!r}\n"
        f"  searched: {BUILD_BIN}\n"
        f"           {INSTALL_BIN}\n"
        f"           PATH\n"
        f"  hint: use --{name} to specify the path manually"
    )


@dataclass(frozen=True)
class Tools:
    clang: Path
    opt: Path
    llvm_stress: Optional[Path] = None
    llvm_dis: Optional[Path] = None


def run_cmd(argv: list[str], *, timeout_s: int, cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        cmd_str = " ".join(argv[:3]) + (" ..." if len(argv) > 3 else "")
        raise TestFailure(
            f"subprocess timed out after {timeout_s}s\n"
            f"  command: {cmd_str}\n"
            f"  hint: increase --timeout (current: {timeout_s}s)"
        )


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def assert_contains(text: str, needle: str, *, where: str) -> None:
    if needle not in text:
        raise TestFailure(f"{where}: expected to find {needle!r}")


def assert_not_contains(text: str, needle: str, *, where: str) -> None:
    if needle in text:
        raise TestFailure(f"{where}: expected NOT to find {needle!r}")


def extract_function_ir(ll: str, fn: str) -> str:
    lines = ll.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.lstrip().startswith("define") and f"@{fn}(" in line:
            start = i
            break
    if start is None:
        raise TestFailure(f"unable to find function definition for {fn!r}")

    brace_depth = 0
    out: list[str] = []
    for j in range(start, len(lines)):
        line = lines[j]
        out.append(line)
        brace_depth += line.count("{")
        brace_depth -= line.count("}")
        if brace_depth == 0 and j > start:
            return "\n".join(out) + "\n"
    raise TestFailure(f"unterminated function definition for {fn!r}")


def _find_decl_line(ll: str, sym: str) -> str | None:
    for line in ll.splitlines():
        t = line.strip()
        if t.startswith("declare") and f"@{sym}" in t:
            return t
    return None


def assert_decl_has_cc_if_present(ll: str, sym: str, cc: str, *, where: str) -> None:
    line = _find_decl_line(ll, sym)
    if not line:
        return
    if cc not in line:
        raise TestFailure(f"{where}: expected {sym} declaration to contain {cc!r}\nline: {line}")


def unit_tests(tools: Tools, out_dir: Path, *, timeout_s: int, pass_plugin: Optional[str] = None) -> None:
    unit_dir = Path(__file__).resolve().parent / "unit"
    # Use a fixed seed so randomized passes/configs remain stable across runs.
    base_mllvm: list[str] = []
    if pass_plugin:
        base_mllvm += [f"-fpass-plugin={pass_plugin}"]
    base_mllvm += ["-mllvm", "-obf-seed=1234"]
    _test_count = [0]

    def _unit_progress(name: str) -> None:
        _test_count[0] += 1
        print(f"  [{_test_count[0]:>2}] {name} ...", end="", flush=True)

    def _unit_ok() -> None:
        print(" ok", flush=True)

    def clang_emit_ll(src: Path, out_ll: Path, extra: list[str]) -> None:
        argv = [
            str(tools.clang),
            "-O2",
            # Unit tests look for pass-created basic block names; clang may
            # discard value names by default in optimized builds.
            "-fno-discard-value-names",
            "-S",
            "-emit-llvm",
            str(src),
            "-o",
            str(out_ll),
            *base_mllvm,
            *extra,
        ]
        p = run_cmd(argv, timeout_s=timeout_s)
        if p.returncode != 0:
            raise TestFailure(
                "clang failed:\n"
                + "argv: "
                + " ".join(argv)
                + "\n\nstdout:\n"
                + p.stdout
                + "\n\nstderr:\n"
                + p.stderr
            )

    def opt_verify_ir(path: Path) -> None:
        argv = [str(tools.opt), "-passes=verify", "-disable-output", str(path)]
        p = run_cmd(argv, timeout_s=timeout_s)
        if p.returncode != 0:
            raise TestFailure(
                "opt verify failed:\n"
                + "argv: "
                + " ".join(argv)
                + "\n\nstdout:\n"
                + p.stdout
                + "\n\nstderr:\n"
                + p.stderr
            )

    def clang_compile(src: Path, out_obj: Path, extra: list[str]) -> None:
        argv = [
            str(tools.clang),
            "-O2",
            "-c",
            str(src),
            "-o",
            str(out_obj),
            *base_mllvm,
            *extra,
        ]
        p = run_cmd(argv, timeout_s=timeout_s)
        if p.returncode != 0:
            raise TestFailure(
                "clang failed:\n"
                + "argv: "
                + " ".join(argv)
                + "\n\nstdout:\n"
                + p.stdout
                + "\n\nstderr:\n"
                + p.stderr
            )

    def clang_link_and_run(src: Path, out_exe: Path, extra: list[str]) -> None:
        argv = [
            str(tools.clang),
            "-O2",
            str(src),
            "-o",
            str(out_exe),
            *base_mllvm,
            *extra,
        ]
        p = run_cmd(argv, timeout_s=timeout_s)
        if p.returncode != 0:
            raise TestFailure(
                "clang link failed:\n"
                + "argv: "
                + " ".join(argv)
                + "\n\nstdout:\n"
                + p.stdout
                + "\n\nstderr:\n"
                + p.stderr
            )

        runp = run_cmd([str(out_exe)], timeout_s=timeout_s)
        if runp.returncode != 0:
            raise TestFailure(
                "exe run failed:\n"
                + f"exe: {out_exe}\n"
                + "\n\nstdout:\n"
                + runp.stdout
                + "\n\nstderr:\n"
                + runp.stderr
            )

    # 1) Annotation-based selection: annotate("bcf") must actually trigger BCF
    # under -obf-only-annotated.
    _unit_progress("annotate_bcf")
    tdir = out_dir / "unit" / "annotate_bcf"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "annotate_bcf.c",
        out_ll,
        [
            "-mllvm",
            "-obf-only-annotated",
            "-mllvm",
            "-obf-verify",
            "-mllvm",
            "-bcf_prob=100",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    marked_ir = extract_function_ir(ll, "marked")
    unmarked_ir = extract_function_ir(ll, "unmarked")
    assert_contains(marked_ir, "originalBB", where="annotate_bcf:marked")
    assert_not_contains(unmarked_ir, "originalBB", where="annotate_bcf:unmarked")
    _unit_ok()

    # 1b) Annotation precedence: nobcf/no_obfuscate must override bcf.
    _unit_progress("annotate_precedence")
    tdir = out_dir / "unit" / "annotate_precedence"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "annotate_precedence.c",
        out_ll,
        [
            "-mllvm",
            "-obf-only-annotated",
            "-mllvm",
            "-bcf",
            "-mllvm",
            "-bcf_prob=100",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    opt_in_ir = extract_function_ir(ll, "opt_in")
    plain_ir = extract_function_ir(ll, "plain")
    opt_out_nobcf_ir = extract_function_ir(ll, "opt_out_nobcf")
    opt_out_no_obf_ir = extract_function_ir(ll, "opt_out_no_obf")
    assert_contains(opt_in_ir, "originalBB", where="annotate_precedence:opt_in")
    assert_not_contains(plain_ir, "originalBB", where="annotate_precedence:plain")
    assert_not_contains(opt_out_nobcf_ir, "originalBB", where="annotate_precedence:opt_out_nobcf")
    assert_not_contains(opt_out_no_obf_ir, "originalBB", where="annotate_precedence:opt_out_no_obf")
    _unit_ok()

    # 1c) Function attribute precedence: "no_obfuscate" and "obf_skip" must
    # override enabled passes.
    _unit_progress("skip_attrs_bcf")
    tdir = out_dir / "unit" / "skip_attrs_bcf"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "skip_attrs_bcf.ll",
        out_ll,
        [
            "-Wno-override-module",
            "-mllvm",
            "-bcf",
            "-mllvm",
            "-bcf_prob=100",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    ok_ir = extract_function_ir(ll, "bcf_ok")
    no_obf_ir = extract_function_ir(ll, "bcf_no_obfuscate")
    skip_ir = extract_function_ir(ll, "bcf_obf_skip")
    assert_contains(ok_ir, "originalBB", where="skip_attrs_bcf:bcf_ok")
    assert_not_contains(no_obf_ir, "originalBB", where="skip_attrs_bcf:bcf_no_obfuscate")
    assert_not_contains(skip_ir, "originalBB", where="skip_attrs_bcf:bcf_obf_skip")
    _unit_ok()

    # 2) musttail correctness: BCF must not break musttail+ret adjacency.
    _unit_progress("musttail")
    tdir = out_dir / "unit" / "musttail"
    tdir.mkdir(parents=True, exist_ok=True)
    clang_compile(
        unit_dir / "musttail.ll",
        tdir / "out.obj",
        [
            "-Wno-override-module",
            "-mllvm",
            "-bcf",
            "-mllvm",
            "-bcf_prob=100",
            "-mllvm",
            "-obf-verify",
        ],
    )
    _unit_ok()

    # 2b) callbr correctness: CFG passes must not break functions using callbr.
    _unit_progress("callbr_bcf")
    tdir = out_dir / "unit" / "callbr_bcf"
    tdir.mkdir(parents=True, exist_ok=True)
    clang_compile(
        unit_dir / "callbr_bcf.ll",
        tdir / "out.obj",
        [
            "-Wno-override-module",
            "-mllvm",
            "-bcf",
            "-mllvm",
            "-bcf_prob=100",
            "-mllvm",
            "-obf-verify",
        ],
    )
    _unit_ok()

    # 2c) indirectbr correctness: CFG passes must not break indirectbr blocks.
    _unit_progress("indirectbr_bcf")
    tdir = out_dir / "unit" / "indirectbr_bcf"
    tdir.mkdir(parents=True, exist_ok=True)
    clang_compile(
        unit_dir / "indirectbr_bcf.ll",
        tdir / "out.obj",
        [
            "-Wno-override-module",
            "-mllvm",
            "-bcf",
            "-mllvm",
            "-bcf_prob=100",
            "-mllvm",
            "-obf-verify",
        ],
    )
    _unit_ok()

    # 2d) MSVC EH: BCF must not crash / produce invalid IR in funclet-heavy IR.
    _unit_progress("eh_msvc_bcf")
    tdir = out_dir / "unit" / "eh_msvc_bcf"
    tdir.mkdir(parents=True, exist_ok=True)
    clang_compile(
        unit_dir / "eh_msvc_bcf.cpp",
        tdir / "out.obj",
        [
            "-fexceptions",
            "-fcxx-exceptions",
            "-mllvm",
            "-bcf",
            "-mllvm",
            "-bcf_prob=100",
            "-mllvm",
            "-obf-verify",
        ],
    )
    _unit_ok()

    # Pass smoke tests: ensure each core pass runs and makes a visible change.

    # split
    _unit_progress("smoke_split")
    tdir = out_dir / "unit" / "smoke_split"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "smoke_split.c",
        out_ll,
        [
            "-mllvm",
            "-split",
            "-mllvm",
            "-split_num=2",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    split_ir = extract_function_ir(ll, "smoke_split")
    assert_contains(split_ir, ".split", where="smoke_split")
    _unit_ok()

    # fla
    _unit_progress("smoke_fla")
    tdir = out_dir / "unit" / "smoke_fla"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "smoke_fla.c",
        out_ll,
        [
            "-mllvm",
            "-fla",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    fla_ir = extract_function_ir(ll, "smoke_fla")
    assert_contains(fla_ir, "loopEntry", where="smoke_fla")
    _unit_ok()

    # sub
    _unit_progress("smoke_sub")
    tdir = out_dir / "unit" / "smoke_sub"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "smoke_arith.c",
        out_ll,
        [
            "-mllvm",
            "-sub",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    arith_ir = extract_function_ir(ll, "smoke_arith")
    assert_contains(arith_ir, "!obf.arith", where="smoke_sub")
    assert_contains(ll, "!\"sub\"", where="smoke_sub")
    _unit_ok()

    # mba
    _unit_progress("smoke_mba")
    tdir = out_dir / "unit" / "smoke_mba"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "smoke_arith.c",
        out_ll,
        [
            "-mllvm",
            "-mba",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    arith_ir = extract_function_ir(ll, "smoke_arith")
    assert_contains(arith_ir, "!obf.arith", where="smoke_mba")
    assert_contains(ll, "!\"mba\"", where="smoke_mba")
    _unit_ok()

    # const
    _unit_progress("smoke_const")
    tdir = out_dir / "unit" / "smoke_const"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "smoke_arith.c",
        out_ll,
        [
            "-mllvm",
            "-obf-symbols=false",
            "-mllvm",
            "-obf-const",
            "-mllvm",
            "-obf-const-prob=100",
            "-mllvm",
            "-obf-const-minbits=1",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    assert_contains(ll, "obf_const_key", where="smoke_const")
    assert_contains(ll, "load volatile", where="smoke_const")
    _unit_ok()

    # str
    _unit_progress("smoke_str")
    tdir = out_dir / "unit" / "smoke_str"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "smoke_str.c",
        out_ll,
        [
            "-mllvm",
            "-obf-symbols=false",
            "-mllvm",
            "-obf-str",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    str_ir = extract_function_ir(ll, "smoke_str")
    assert_contains(ll, "obf_get_str", where="smoke_str")
    assert_contains(str_ir, "obf_get_str", where="smoke_str")
    _unit_ok()

    # indcall
    _unit_progress("smoke_indcall")
    tdir = out_dir / "unit" / "smoke_indcall"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "smoke_indcall.c",
        out_ll,
        [
            "-mllvm",
            "-obf-symbols=false",
            "-mllvm",
            "-indcall",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    assert_contains(ll, "@obf_func_table", where="smoke_indcall")
    indcall_ir = extract_function_ir(ll, "smoke_indcall")
    assert_contains(indcall_ir, "inttoptr", where="smoke_indcall")
    _unit_ok()

    # indbr
    _unit_progress("smoke_indbr")
    tdir = out_dir / "unit" / "smoke_indbr"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "smoke_indbr.c",
        out_ll,
        [
            "-mllvm",
            "-obf-symbols=false",
            "-mllvm",
            "-indbr",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    indbr_ir = extract_function_ir(ll, "smoke_indbr")
    assert_contains(indbr_ir, "indirectbr", where="smoke_indbr")
    _unit_ok()

    # iat (Windows-only)
    _unit_progress("smoke_iat")
    tdir = out_dir / "unit" / "smoke_iat"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "smoke_iat.c",
        out_ll,
        [
            "-target",
            "x86_64-pc-windows-msvc",
            "-fdeclspec",
            "-mllvm",
            "-obf-symbols=false",
            "-mllvm",
            "-obf-iat",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    iat_ir = extract_function_ir(ll, "smoke_iat")
    assert_contains(ll, "iat_ptr_", where="smoke_iat")
    assert_contains(iat_ir, "iat_ptr_", where="smoke_iat")
    assert_not_contains(iat_ir, "call i32 @iat_import", where="smoke_iat")
    assert_not_contains(iat_ir, "tail call i32 @iat_import", where="smoke_iat")
    _unit_ok()

    # 3) Windows-only IAT must not run on UEFI (COFF but non-Windows).
    _unit_progress("iat_skip_uefi")
    tdir = out_dir / "unit" / "iat_skip_uefi"
    dump_dir = tdir / "dumps"
    dump_dir.mkdir(parents=True, exist_ok=True)
    out_obj = tdir / "out.obj"
    clang_compile(
        unit_dir / "iat_skip_uefi.c",
        out_obj,
        [
            "-target",
            "x86_64-unknown-uefi",
            "-mllvm",
            "-obf-dump-ir",
            "-mllvm",
            f"-obf-dump-dir={dump_dir}",
            "-mllvm",
            "-obf-iat",
            "-mllvm",
            "-obf-verify",
        ],
    )
    iat_dumps = list(dump_dir.glob("*.iat.before.ll"))
    if iat_dumps:
        raise TestFailure(
            "iat_skip_uefi: expected IAT pass to be skipped, but found dumps:\n"
            + "\n".join(str(p) for p in iat_dumps)
        )
    _unit_ok()

    # 4) VM hard runtime checks must not emit WinAPI symbols on UEFI.
    _unit_progress("vm_hardrt_uefi")
    tdir = out_dir / "unit" / "vm_hardrt_uefi"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "vm_hardrt_uefi.c",
        out_ll,
        [
            "-target",
            "x86_64-unknown-uefi",
            "-mllvm",
            "-vm-mode=bb",
            "-mllvm",
            "-vm-select=all",
            "-mllvm",
            "-vm-hard-rt",
            "-mllvm",
            "-obf-symbols=false",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    assert_contains(ll, "vm_exec_", where="vm_hardrt_uefi (sanity)")
    for sym in (
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "QueryPerformanceCounter",
        "QueryPerformanceFrequency",
    ):
        assert_not_contains(ll, sym, where="vm_hardrt_uefi")
    _unit_ok()

    # 5) VM malloc signature: on 32-bit targets, malloc should take i32 (size_t).
    _unit_progress("vm_malloc_i686")
    tdir = out_dir / "unit" / "vm_malloc_i686"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "vm_malloc_i686.c",
        out_ll,
        [
            "-target",
            "i686-pc-windows-msvc",
            "-mllvm",
            "-vm-mode=bb",
            "-mllvm",
            "-vm-select=all",
            # Force heap reg-file allocation so we can validate the 32-bit malloc signature.
            "-mllvm",
            "-vm-max-stack-reg-bytes=0",
            "-mllvm",
            "-obf-symbols=false",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    assert_contains(ll, "declare ptr @malloc(i32", where="vm_malloc_i686")
    _unit_ok()

    # 6) String include trimming: include list entries should be trimmed.
    # We intentionally pass a leading space before the real pattern.
    _unit_progress("str_include_trim")
    tdir = out_dir / "unit" / "str_include_trim"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "str_include_trim.c",
        out_ll,
        [
            "-g",
            "-mllvm",
            "-obf-symbols=false",
            "-mllvm",
            "-obf-str",
            "-mllvm",
            "-obf-str-include=notmatch, str_include_trim.c",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    assert_contains(ll, "obf_get_str", where="str_include_trim")
    _unit_ok()

    # 7) 32-bit Windows WinAPI calls: VM hard runtime helpers must use stdcall.
    # This ensures the emitted calls don't smash the stack on i686 Windows.
    _unit_progress("vm_hardrt_i686")
    tdir = out_dir / "unit" / "vm_hardrt_i686"
    tdir.mkdir(parents=True, exist_ok=True)
    out_ll = tdir / "out.ll"
    clang_emit_ll(
        unit_dir / "vm_hardrt_i686.c",
        out_ll,
        [
            "-target",
            "i686-pc-windows-msvc",
            "-mllvm",
            "-vm-mode=bb",
            "-mllvm",
            "-vm-select=all",
            "-mllvm",
            "-vm-hard-rt",
            "-mllvm",
            "-obf-symbols=false",
            "-mllvm",
            "-obf-verify",
        ],
    )
    opt_verify_ir(out_ll)
    ll = read_text(out_ll)
    assert_contains(ll, "x86_stdcallcc i32 @IsDebuggerPresent", where="vm_hardrt_i686")
    for sym in (
        "GetCurrentProcess",
        "CheckRemoteDebuggerPresent",
        "QueryPerformanceCounter",
        "QueryPerformanceFrequency",
        "OutputDebugStringA",
        "CreateFileA",
        "WriteFile",
        "CloseHandle",
    ):
        assert_decl_has_cc_if_present(ll, sym, "x86_stdcallcc", where="vm_hardrt_i686")
    _unit_ok()

    # 8) End-to-end smoke: compile + link + run with every obfuscation pass on.
    # On Windows this requires a VS developer environment (LIB/INCLUDE set).
    if os.name != "nt" or os.environ.get("VCToolsInstallDir"):
        _unit_progress("all_flags_integration")
        tdir = out_dir / "unit" / "all_flags_integration"
        tdir.mkdir(parents=True, exist_ok=True)
        out_exe = tdir / _exe("all_flags_integration")

        all_flags = [
            "-fuse-ld=lld",
            "-mllvm",
            "-obf-verify",
            "-mllvm",
            "-obf-max-bb-growth=1000",
            "-mllvm",
            "-obf-max-inst-growth=1500",
            "-mllvm",
            "-split",
            "-mllvm",
            "-split_num=5",
            "-mllvm",
            "-fla",
            "-mllvm",
            "-bcf",
            "-mllvm",
            "-bcf_prob=100",
            "-mllvm",
            "-bcf_loop=2",
            "-mllvm",
            "-mba",
            "-mllvm",
            "-mba_loop=2",
            "-mllvm",
            "-sub",
            "-mllvm",
            "-sub_loop=2",
            "-mllvm",
            "-indcall",
            "-mllvm",
            "-indbr",
            "-mllvm",
            "-indcall-decoys=8",
            "-mllvm",
            "-obf-str",
            "-mllvm",
            "-obf-str-prob=100",
            "-mllvm",
            "-obf-str-verify=1",
            "-mllvm",
            "-obf-const",
            "-mllvm",
            "-obf-const-prob=100",
            "-mllvm",
            "-opaque-pred-rate=100",
            "-mllvm",
            "-vm-mode=opcode",
            "-mllvm",
            "-vm-select=all",
            "-mllvm",
            "-vm-encode=mba",
            "-mllvm",
            "-vm-encode-pct=100",
            "-mllvm",
            "-vm-encode-feistel-all",
            "-mllvm",
            "-vm-feistel-rounds=8",
            "-mllvm",
            "-vm-dispatch=indirect",
            "-mllvm",
            "-vm-handlers=random",
            "-mllvm",
            "-vm-bogus=8",
            "-mllvm",
            "-vm-hard",
            "-mllvm",
            "-vm-hard-rt",
            "-mllvm",
            "-vm-obf-runtime",
        ]
        if os.name == "nt":
            all_flags += [
                "-mllvm",
                "-obf-iat",
                "-mllvm",
                "-obf-iat-backend=thunk",
                "-mllvm",
                "-obf-hide-externs",
            ]
        else:
            # Some obfuscation paths can introduce FP remainder operations, which may lower
            # to libm calls (e.g. fmod/fmodf) on Linux. Ensure we link successfully.
            all_flags += ["-lm"]

        clang_link_and_run(unit_dir / "all_flags_integration.c", out_exe, all_flags)
        _unit_ok()
    else:
        _unit_progress("all_flags_integration")
        print(" SKIP (no VCToolsInstallDir)", flush=True)

    print(f"  unit: {_test_count[0]} tests passed", flush=True)


def fuzz_tests(
    tools: Tools,
    out_dir: Path,
    *,
    iterations: int,
    size: int,
    timeout_s: int,
    jobs: int,
    keep_going: bool,
    scalable_vectors: bool,
    pass_plugin: Optional[str] = None,
) -> None:
    if tools.llvm_stress is None:
        raise TestFailure(
            "fuzz mode requires llvm-stress but it was not found.\n"
            "  hint: use --llvm-stress to specify the path"
        )
    if tools.llvm_dis is None:
        _log("llvm-dis not found; fuzz reproducers will lack human-readable IR")

    work = out_dir / "work"
    crashers = out_dir / "crashers"
    work.mkdir(parents=True, exist_ok=True)
    crashers.mkdir(parents=True, exist_ok=True)

    # Keep configs modest by default; this is primarily a crash/IR-verifier fuzzer.
    configs: list[tuple[str, list[str]]] = [
        ("split", ["-mllvm", "-split", "-mllvm", "-split_num=2"]),
        ("bcf", ["-mllvm", "-bcf", "-mllvm", "-bcf_prob=60"]),
        ("fla", ["-mllvm", "-fla"]),
        ("sub", ["-mllvm", "-sub"]),
        ("mba", ["-mllvm", "-mba"]),
        ("const", ["-mllvm", "-obf-const"]),
        ("indirect", ["-mllvm", "-indbr", "-mllvm", "-indcall"]),
        ("str", ["-mllvm", "-obf-str"]),
        ("vm_bb", ["-mllvm", "-vm-mode=bb", "-mllvm", "-vm-select=all"]),
        (
            "vm_opcode_hard",
            [
                "-mllvm",
                "-vm-mode=opcode",
                "-mllvm",
                "-vm-select=all",
                "-mllvm",
                "-vm-encode=mba",
                "-mllvm",
                "-vm-encode-feistel-all",
                "-mllvm",
                "-vm-feistel-rounds=6",
                "-mllvm",
                "-vm-dispatch=indirect",
                "-mllvm",
                "-vm-handlers=random",
                "-mllvm",
                "-vm-hard",
            ],
        ),
        (
            "all_flags",
            [
                "-mllvm",
                "-split",
                "-mllvm",
                "-split_num=2",
                "-mllvm",
                "-bcf",
                "-mllvm",
                "-bcf_prob=50",
                "-mllvm",
                "-fla",
                "-mllvm",
                "-mba",
                "-mllvm",
                "-sub",
                "-mllvm",
                "-indbr",
                "-mllvm",
                "-indcall",
                "-mllvm",
                "-obf-str",
                "-mllvm",
                "-obf-const",
                # Opaque predicates are used by BCF, but enable heavy mix explicitly.
                "-mllvm",
                "-opaque-pred-rate=100",
                "-mllvm",
                "-vm-mode=opcode",
                "-mllvm",
                "-vm-select=all",
                "-mllvm",
                "-vm-encode=mba",
                "-mllvm",
                "-vm-encode-feistel-all",
                "-mllvm",
                "-vm-feistel-rounds=6",
                "-mllvm",
                "-vm-dispatch=indirect",
                "-mllvm",
                "-vm-handlers=random",
                "-mllvm",
                "-vm-hard",
            ],
        ),
        (
            "light_combo",
            [
                "-mllvm",
                "-split",
                "-mllvm",
                "-split_num=2",
                "-mllvm",
                "-bcf",
                "-mllvm",
                "-bcf_prob=40",
                "-mllvm",
                "-fla",
                "-mllvm",
                "-sub",
            ],
        ),
    ]

    def one_case(i: int) -> None:
        seed = 0xC0FFEE + i
        bc = work / f"stress_{i}.bc"
        argv = [str(tools.llvm_stress)]
        if scalable_vectors:
            argv.append("--enable-scalable-vectors")
        argv += [f"--seed={seed}", f"--size={size}", "-o", str(bc)]
        p = run_cmd(argv, timeout_s=timeout_s)
        if p.returncode != 0:
            raise TestFailure(
                "llvm-stress failed:\n"
                + "argv: "
                + " ".join(argv)
                + "\n\nstdout:\n"
                + p.stdout
                + "\n\nstderr:\n"
                + p.stderr
            )

        for cfg_name, cfg_args in configs:
            out_ll = work / f"out_{i}_{cfg_name}.ll"
            argv = [str(tools.clang)]
            if pass_plugin:
                argv.append(f"-fpass-plugin={pass_plugin}")
            argv += [
                "-O2",
                "-S",
                "-emit-llvm",
                str(bc),
                "-o",
                str(out_ll),
                "-Wno-override-module",
                "-mllvm",
                "-obf-verify",
                "-mllvm",
                f"-obf-seed={seed}",
                "-mllvm",
                "-obf-max-bb-growth=200",
                "-mllvm",
                "-obf-max-inst-growth=300",
                *cfg_args,
            ]
            p = run_cmd(argv, timeout_s=timeout_s)
            if p.returncode == 0:
                continue

            # Save reproducer.
            case_dir = crashers / f"case_{i}_{cfg_name}"
            case_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(bc, case_dir / bc.name)
            # Best-effort human-readable IR (only if llvm-dis is available).
            if tools.llvm_dis is not None:
                dis_ll = case_dir / "input.ll"
                try:
                    run_cmd([str(tools.llvm_dis), str(bc), "-o", str(dis_ll)], timeout_s=timeout_s)
                except TestFailure:
                    pass  # non-critical
            (case_dir / "argv.txt").write_text(" ".join(argv) + "\n", encoding="utf-8")
            (case_dir / "stdout.txt").write_text(p.stdout, encoding="utf-8")
            (case_dir / "stderr.txt").write_text(p.stderr, encoding="utf-8")
            raise TestFailure(
                f"fuzz failure: iter={i} cfg={cfg_name}\n"
                f"reproducer: {case_dir}\n"
                f"stderr:\n{p.stderr}"
            )

    # Parallelize by iteration; each iteration is independent.
    import concurrent.futures
    import threading

    failures: list[str] = []
    cancel_event = threading.Event()
    completed = [0]
    lock = threading.Lock()
    if jobs < 1:
        jobs = 1

    def guarded_case(i: int) -> None:
        if cancel_event.is_set():
            return
        one_case(i)
        with lock:
            completed[0] += 1
            n = completed[0]
        if n == 1 or n % max(1, iterations // 20) == 0 or n == iterations:
            print(f"  fuzz: {n}/{iterations} iterations done", flush=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = [ex.submit(guarded_case, i) for i in range(iterations)]
        for fut in concurrent.futures.as_completed(futs):
            try:
                fut.result()
            except Exception as e:
                failures.append(str(e))
                if not keep_going:
                    cancel_event.set()
                    for f in futs:
                        f.cancel()
                    break

    if failures:
        raise TestFailure(
            f"fuzz: {len(failures)} failure(s) in {iterations} iterations:\n"
            + "\n\n".join(failures)
        )


def _resolve_tools(args: argparse.Namespace, need_fuzz: bool) -> Tools:
    """Resolve tool paths.  Only require llvm-stress / llvm-dis when fuzzing."""
    clang = find_tool("clang", args.clang)
    opt = find_tool("opt", args.opt)

    llvm_stress: Optional[Path] = None
    llvm_dis: Optional[Path] = None

    if need_fuzz:
        # llvm-stress is mandatory for fuzz mode.
        llvm_stress = find_tool("llvm-stress", args.llvm_stress)
        # llvm-dis is nice-to-have for human-readable reproducers.
        try:
            llvm_dis = find_tool("llvm-dis", args.llvm_dis)
        except FileNotFoundError:
            _log("llvm-dis not found; fuzz reproducers will lack human-readable IR")
    else:
        # User explicitly passed overrides even for non-fuzz mode; validate them.
        if args.llvm_stress:
            llvm_stress = find_tool("llvm-stress", args.llvm_stress)
        if args.llvm_dis:
            llvm_dis = find_tool("llvm-dis", args.llvm_dis)

    return Tools(clang=clang, opt=opt, llvm_stress=llvm_stress, llvm_dis=llvm_dis)


def main() -> int:
    global _verbose

    ap = argparse.ArgumentParser(prog="kilij-tests")
    ap.add_argument("mode", choices=("unit", "fuzz", "all"))
    ap.add_argument("--clang", help="Path to clang executable (override)")
    ap.add_argument("--opt", help="Path to opt executable (override)")
    ap.add_argument("--llvm-stress", dest="llvm_stress", help="Path to llvm-stress executable (override)")
    ap.add_argument("--llvm-dis", dest="llvm_dis", help="Path to llvm-dis executable (override)")
    ap.add_argument(
        "--pass-plugin",
        dest="pass_plugin",
        help="Path to Kilij pass plugin (.so/.dll/.dylib) for standalone builds. "
        "Adds -fpass-plugin=<path> to all clang invocations.",
    )
    ap.add_argument("--out", help="Output directory (default: kilij-tests/out/<timestamp>)")
    ap.add_argument("--timeout", type=int, default=60, help="Per-subprocess timeout in seconds (default: 60)")
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    ap.add_argument("--iterations", type=int, default=200, help="Fuzz iterations (default: 200)")
    ap.add_argument("--size", type=int, default=120, help="llvm-stress size (default: 120)")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4, help="Fuzz parallelism (default: cpu count)")
    ap.add_argument("--keep-going", action="store_true", help="Continue fuzzing after failures (default: stop)")
    ap.add_argument(
        "--scalable-vectors",
        action="store_true",
        help="Generate scalable vector IR with llvm-stress (can tickle upstream LLVM asserts on some targets)",
    )

    args = ap.parse_args()
    _verbose = args.verbose

    need_fuzz = args.mode in ("fuzz", "all")
    try:
        tools = _resolve_tools(args, need_fuzz)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if args.pass_plugin and not Path(args.pass_plugin).is_file():
        print(f"ERROR: pass plugin not found: {args.pass_plugin}", file=sys.stderr)
        return 2

    print(f"tools: clang={tools.clang}", flush=True)
    print(f"       opt={tools.opt}", flush=True)
    if tools.llvm_stress:
        print(f"       llvm-stress={tools.llvm_stress}", flush=True)
    if tools.llvm_dis:
        print(f"       llvm-dis={tools.llvm_dis}", flush=True)

    if args.out:
        out_dir = Path(args.out)
    else:
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_dir = Path(__file__).resolve().parent / "out" / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        if args.mode in ("unit", "all"):
            print("--- unit tests ---", flush=True)
            unit_tests(tools, out_dir, timeout_s=args.timeout, pass_plugin=args.pass_plugin)
        if args.mode in ("fuzz", "all"):
            print(
                f"--- fuzz tests ({args.iterations} iters, {args.jobs} jobs, "
                f"timeout={args.timeout}s) ---",
                flush=True,
            )
            fuzz_tests(
                tools,
                out_dir,
                iterations=args.iterations,
                size=args.size,
                timeout_s=args.timeout,
                jobs=args.jobs,
                keep_going=args.keep_going,
                scalable_vectors=args.scalable_vectors,
                pass_plugin=args.pass_plugin,
            )
    except TestFailure as e:
        print(f"\nFAILED: {e}", file=sys.stderr)
        print(f"artifacts: {out_dir}", file=sys.stderr)
        return 1

    print(f"\nOK ({args.mode})")
    print(f"artifacts: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
