@echo off
setlocal

REM Run clang (from this extracted toolchain) and emit obfuscated LLVM IR.

set ROOT=%~dp0..
set BIN=%ROOT%\bin
set EXAMPLE=%ROOT%\examples\_tmp_kilij_smoke.c
set OUTDIR=%~dp0out

if not exist "%BIN%\clang.exe" (
  echo ERROR: clang.exe not found at "%BIN%\clang.exe"
  exit /b 1
)
if not exist "%EXAMPLE%" (
  echo ERROR: example not found at "%EXAMPLE%"
  exit /b 1
)

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

"%BIN%\clang.exe" -O2 -S -emit-llvm "%EXAMPLE%" -o "%OUTDIR%\smoke_obf.ll" ^
  -mllvm -obf-seed=123 ^
  -mllvm -obf-str ^
  -mllvm -fla ^
  -mllvm -bcf

if errorlevel 1 exit /b %errorlevel%

echo Wrote "%OUTDIR%\smoke_obf.ll"

