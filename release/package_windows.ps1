[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$BuildDir,

  [Parameter(Mandatory = $false)]
  [string]$OutDir = (Join-Path $PSScriptRoot "..\_release_out\windows"),

  [Parameter(Mandatory = $false)]
  [string]$VcRedistDir = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not (Test-Path $BuildDir)) {
  throw "BuildDir does not exist: $BuildDir. Run build_windows.ps1 first."
}
$buildRoot = (Resolve-Path $BuildDir).Path

$name = "kilij-clang20-win64"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"

$stageBase = Join-Path $OutDir "_stage\\$name-$stamp"
$stageRoot = Join-Path $stageBase $name

$stageBin = Join-Path $stageRoot "bin"
$stageLib = Join-Path $stageRoot "lib\\clang\\20"
$stageExamples = Join-Path $stageRoot "examples"
$stageQuickstart = Join-Path $stageRoot "quickstart"

New-Item -ItemType Directory -Force $stageBin, $stageLib, $stageExamples, $stageQuickstart | Out-Null

$buildBin = Join-Path $buildRoot "bin"
$buildRes = Join-Path $buildRoot "lib\\clang\\20"

$bins = @(
  "clang.exe",
  "clang++.exe",
  "opt.exe",
  "Kilij.dll",
  "lld-link.exe",
  "llvm-as.exe",
  "llvm-dis.exe",
  "llvm-objdump.exe"
)

foreach ($b in $bins) {
  $src = Join-Path $buildBin $b
  if (!(Test-Path $src)) { throw "Missing build artifact: $src" }
  Copy-Item -Force $src $stageBin
}

if (!(Test-Path $buildRes)) { throw "Missing clang resource dir: $buildRes" }
Copy-Item -Recurse -Force (Join-Path $buildRes "include") $stageLib

# Ship MSVC runtime alongside the binaries so they run on clean Windows installs.
if ($VcRedistDir -eq "") {
  $searchRoots = @(
    "C:\\Program Files\\Microsoft Visual Studio",
    "C:\\Program Files (x86)\\Microsoft Visual Studio"
  ) | Where-Object { Test-Path $_ }

  foreach ($root in $searchRoots) {
    $crt = Get-ChildItem -Path $root -Recurse -Directory -Filter "Microsoft.VC*.CRT" -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -like "*\x64\Microsoft.VC*.CRT" } |
      Sort-Object FullName -Descending |
      Select-Object -First 1
    if ($crt) {
      $VcRedistDir = $crt.FullName
      break
    }
  }
}
if ($VcRedistDir -eq "" -or !(Test-Path $VcRedistDir)) {
  throw "Could not locate MSVC redist (x64). Pass -VcRedistDir explicitly."
}
Copy-Item -Force (Join-Path $VcRedistDir "*.dll") $stageBin

# Quickstart + examples (from this repo)
$examplesSrc = Join-Path $repoRoot "release\examples"
$quickstartSrc = Join-Path $repoRoot "release\quickstart"
if (-not (Test-Path $examplesSrc)) {
  throw "Examples directory not found: $examplesSrc"
}
if (-not (Test-Path $quickstartSrc)) {
  throw "Quickstart directory not found: $quickstartSrc"
}
Copy-Item -Force (Join-Path $examplesSrc "*") $stageExamples
Copy-Item -Force (Join-Path $quickstartSrc "*.bat") $stageQuickstart

$readme = @(
  "# Kilij clang (Windows)",
  "",
  "Quickstart:",
  "1) quickstart\\run_clang_obf_ir.bat",
  "2) quickstart\\run_opt_plugin.bat",
  "",
  "Notes:",
  "- clang.exe has Kilij passes built-in (use -mllvm flags).",
  "- Kilij.dll imports symbols from the included opt.exe, so load it via opt -load-pass-plugin=..."
)
Set-Content -Encoding ASCII -Path (Join-Path $stageRoot "README.md") -Value $readme

# ---------------------------------------------------------------------------
# Validate: run clang and opt on smoke test to verify the build works.
# ---------------------------------------------------------------------------
Write-Host "Validating staged build ..."
New-Item -ItemType Directory -Force (Join-Path $stageQuickstart "out") | Out-Null

$smokeC = Join-Path $stageExamples "_tmp_kilij_smoke.c"
$smokeLL = Join-Path $stageExamples "_tmp_kilij_smoke.ll"
if (-not (Test-Path $smokeC)) {
  throw "Smoke test source not found: $smokeC"
}

& (Join-Path $stageBin "clang.exe") -O2 -S -emit-llvm "$smokeC" -o (Join-Path $stageQuickstart "out\smoke_obf.ll") -mllvm -obf-str -mllvm -fla -mllvm -bcf | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "clang validation failed (exit code $LASTEXITCODE). The staged clang may be broken."
}

if (-not (Test-Path $smokeLL)) {
  throw "Smoke test IR not found: $smokeLL"
}
$pluginPath = Join-Path $stageBin "Kilij.dll"
& (Join-Path $stageBin "opt.exe") "-load-pass-plugin=$pluginPath" -passes=kilij -disable-output "$smokeLL" | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "opt validation failed (exit code $LASTEXITCODE). The staged opt/Kilij.dll may be broken."
}

$zipPath = Join-Path $OutDir "$name.zip"
New-Item -ItemType Directory -Force $OutDir | Out-Null
Compress-Archive -Path $stageRoot -DestinationPath $zipPath -Force

$zipSize = (Get-Item $zipPath).Length
Write-Host ("Wrote " + $zipPath + " (" + [math]::Round($zipSize / 1MB, 1) + " MB)")
