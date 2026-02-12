@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM Build and run a small C++ showcase executable using this extracted Kilij toolchain.
REM Output: quickstart\out\showcase\*

set "ROOT=%~dp0.."
for %%I in ("%ROOT%") do set "ROOT=%%~fI"

set "BIN=%ROOT%\bin"
set "SRC=%ROOT%\examples\kilij_showcase.cpp"
set "OUTDIR=%~dp0out\showcase"

if not exist "%BIN%\clang++.exe" (
  echo ERROR: clang++.exe not found at "%BIN%\clang++.exe"
  exit /b 1
)
if not exist "%SRC%" (
  echo ERROR: showcase source not found at "%SRC%"
  exit /b 1
)

REM Try to ensure MSVC/SDK environment is present (for headers/libs/link).
where link.exe >nul 2>nul
if errorlevel 1 (
  set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
  set "VSDEVCMD="
  if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find Common7\Tools\VsDevCmd.bat`) do (
      set "VSDEVCMD=%%I"
    )
  )
  if not "%VSDEVCMD%"=="" (
    call "%VSDEVCMD%" -arch=x64 -host_arch=x64 >nul
  )
)

REM Make sure the included CRT DLLs (shipped in bin) are found at runtime.
set "PATH=%BIN%;%PATH%"

if not exist "%OUTDIR%" mkdir "%OUTDIR%" || exit /b 1

pushd "%OUTDIR%" >nul || exit /b 1

set "CXX=%BIN%\clang++.exe"
set "COMMON=-O2 -DNDEBUG -std=c++20 -fuse-ld=lld"

set "EXE_PLAIN=kilij_showcase_unobf.exe"
set "EXE_PASSES=kilij_showcase_passes.exe"
set "EXE_VM=kilij_showcase_vm.exe"
set "EXE_FULL=kilij_showcase_full.exe"

set "RSP_PASSES=flags_passes_only.rsp"
set "RSP_VM=flags_vm_only.rsp"
set "RSP_FULL=flags_full.rsp"

if exist "vm_report_vm_only.txt" del /f /q "vm_report_vm_only.txt" >nul 2>nul
if exist "vm_report_full.txt" del /f /q "vm_report_full.txt" >nul 2>nul

REM ------------------------------------------------------------
REM Flags (kept in .rsp files to avoid very long command lines)
REM ------------------------------------------------------------
> "%RSP_PASSES%" (
  echo -mllvm -obf-seed=12345
  echo -mllvm -obf-verify
  echo -mllvm -split
  echo -mllvm -split_num=2
  echo -mllvm -bcf
  echo -mllvm -bcf_prob=40
  echo -mllvm -bcf_loop=1
  echo -mllvm -fla
  echo -mllvm -mba
  echo -mllvm -mba_loop=1
  echo -mllvm -sub
  echo -mllvm -sub_loop=1
  echo -mllvm -indbr
  echo -mllvm -indcall
  echo -mllvm -obf-str
  echo -mllvm -obf-str-prob=100
  echo -mllvm -obf-const
  echo -mllvm -obf-const-prob=100
  echo -mllvm -opaque-pred-rate=100
  echo -mllvm -obf-hide-externs
)

> "%RSP_VM%" (
  echo -mllvm -obf-seed=12345
  echo -mllvm -vm-mode=opcode
  echo -mllvm -vm-select=all
  echo -mllvm -vm-encode=mba
  echo -mllvm -vm-encode-pct=100
  echo -mllvm -vm-encode-feistel-all
  echo -mllvm -vm-feistel-rounds=4
  echo -mllvm -vm-dispatch=indirect
  echo -mllvm -vm-handlers=random
  echo -mllvm -vm-bogus=4
  echo -mllvm -vm-hard
  echo -mllvm -vm-hard-rt
  echo -mllvm -vm-obf-runtime
  echo -mllvm -vm-report=vm_report_vm_only.txt
)

> "%RSP_FULL%" (
  type "%RSP_PASSES%"
  type "%RSP_VM%"
  echo -mllvm -vm-report=vm_report_full.txt
)

REM ------------------------------------------------------------
REM Build
REM ------------------------------------------------------------
echo [build] unobf
"%CXX%" %COMMON% "%SRC%" -o "%EXE_PLAIN%" || (popd >nul & exit /b 1)

echo [build] passes only
"%CXX%" %COMMON% @"%RSP_PASSES%" "%SRC%" -o "%EXE_PASSES%" || (popd >nul & exit /b 1)

echo [build] vm only
"%CXX%" %COMMON% @"%RSP_VM%" "%SRC%" -o "%EXE_VM%" || (popd >nul & exit /b 1)

echo [build] full (passes + vm)
"%CXX%" %COMMON% @"%RSP_FULL%" "%SRC%" -o "%EXE_FULL%" || (popd >nul & exit /b 1)

REM ------------------------------------------------------------
REM Run
REM ------------------------------------------------------------
echo [run] unobf
"%EXE_PLAIN%" || (popd >nul & exit /b 1)
echo [run] passes
"%EXE_PASSES%" || (popd >nul & exit /b 1)
echo [run] vm
"%EXE_VM%" || (popd >nul & exit /b 1)
echo [run] full
"%EXE_FULL%" || (popd >nul & exit /b 1)

echo OK: outputs in "%OUTDIR%"
popd >nul
exit /b 0

