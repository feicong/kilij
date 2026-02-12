@echo off
setlocal

REM Run opt (from this extracted toolchain) with the Kilij pass plugin.

set ROOT=%~dp0..
set BIN=%ROOT%\bin
set EXAMPLE=%ROOT%\examples\_tmp_kilij_smoke.ll

if not exist "%BIN%\opt.exe" (
  echo ERROR: opt.exe not found at "%BIN%\opt.exe"
  exit /b 1
)
if not exist "%BIN%\Kilij.dll" (
  echo ERROR: Kilij.dll not found at "%BIN%\Kilij.dll"
  exit /b 1
)
if not exist "%EXAMPLE%" (
  echo ERROR: example not found at "%EXAMPLE%"
  exit /b 1
)

"%BIN%\opt.exe" -load-pass-plugin="%BIN%\Kilij.dll" -passes=kilij -disable-output "%EXAMPLE%"

if errorlevel 1 exit /b %errorlevel%

echo OK: opt ran Kilij pipeline on "%EXAMPLE%"

