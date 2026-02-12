[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$LlvmProjectDir = "",

  [Parameter(Mandatory = $false)]
  # Pinned LLVM 20.x ref (tag or commit).
  [string]$LlvmCommit = "llvmorg-20.1.0",

  [Parameter(Mandatory = $false)]
  [string]$BuildDir = "",

  [Parameter(Mandatory = $false)]
  [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$LlvmProjectDir = $(if ($LlvmProjectDir -ne "") { $LlvmProjectDir } else { (Join-Path $repoRoot "_llvm\llvm-project-win") })
$BuildDir = $(if ($BuildDir -ne "") { $BuildDir } else { (Join-Path $repoRoot "_build\windows-release") })
$OutDir = $(if ($OutDir -ne "") { $OutDir } else { (Join-Path $repoRoot "_release_out\windows") })

# ---------------------------------------------------------------------------
# Safety: verify the Kilij repo root is NOT the LLVM repo.
# A previous bug set origin to llvm-project.git, pulling 585K commits / 3.3 GB.
# ---------------------------------------------------------------------------
$repoGitDir = Join-Path $repoRoot ".git"
if (Test-Path $repoGitDir) {
  $prevEap = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $rootOrigin = (& git -C "$repoRoot" remote get-url origin 2>$null)
  } finally {
    $ErrorActionPreference = $prevEap
  }
  if ($rootOrigin -and $rootOrigin -match "llvm/llvm-project") {
    throw "FATAL: The Kilij repo root ($repoRoot) has origin pointing at llvm-project!`n" +
          "       origin = $rootOrigin`n" +
          "       This is a corrupted state. Fix the remote before running this script."
  }
}

function Get-VsInstallationPath {
  $pf86 = ${env:ProgramFiles(x86)}
  if (-not $pf86) { return $null }
  $vswhere = Join-Path $pf86 "Microsoft Visual Studio\\Installer\\vswhere.exe"
  if (-not (Test-Path $vswhere)) { return $null }

  $p = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
  if ($LASTEXITCODE -ne 0) { return $null }
  if (-not $p) { return $null }
  return $p.Trim()
}

function Find-Exe {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $false)]
    [string[]]$CandidatePaths = @()
  )

  $cmd = Get-Command $Name -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  foreach ($p in $CandidatePaths) {
    if ($p -and (Test-Path $p)) { return $p }
  }
  return $null
}

function Invoke-InVsDevCmd {
  param(
    [Parameter(Mandatory = $true)]
    [string]$VsDevCmdBat,

    [Parameter(Mandatory = $true)]
    [string]$CommandLine
  )

  # VsDevCmd sets MSVC env vars required for Ninja builds (cl/link not in PATH by default).
  $cmd = "call `"$VsDevCmdBat`" -arch=x64 -host_arch=x64 && $CommandLine"
  & cmd.exe /d /s /c $cmd
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code $($LASTEXITCODE): $CommandLine"
  }
}

function Assert-OwnGitRepo {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoDir
  )

  if (-not (Test-Path (Join-Path $RepoDir ".git"))) {
    throw "Safety check failed: $RepoDir is not a git repo (missing .git). Refusing to run git commands here."
  }

  $top = (git -C "$RepoDir" rev-parse --show-toplevel 2>$null)
  if ($LASTEXITCODE -ne 0 -or -not $top) {
    throw "Safety check failed: unable to query git top-level for $RepoDir. Refusing to continue."
  }

  $top = $top.Trim()
  $want = (Resolve-Path $RepoDir).Path

  # git prints POSIX-style paths on Windows in some setups (forward slashes).
  $topNorm = $top.Replace("\", "/").TrimEnd("/").ToLowerInvariant()
  $wantNorm = $want.Replace("\", "/").TrimEnd("/").ToLowerInvariant()

  if ($topNorm -ne $wantNorm) {
    throw "Safety check failed: git top-level for $RepoDir is $top (expected $want). This would risk operating on the parent repo. Aborting."
  }
}

function Invoke-Git {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoDir,

    [Parameter(Mandatory = $true)]
    [string[]]$Args,

    [Parameter(Mandatory = $false)]
    [string]$What = "git"
  )

  # Avoid PowerShell terminating on native stderr when $ErrorActionPreference=Stop.
  $prevEap = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $out = & git -C "$RepoDir" @Args 2>&1
  } finally {
    $ErrorActionPreference = $prevEap
  }
  if ($out) { $out | ForEach-Object { Write-Host $_ } }
  if ($LASTEXITCODE -ne 0) {
    throw "$What failed with exit code $($LASTEXITCODE): git -C `"$RepoDir`" $($Args -join ' ')"
  }
}

# ---------------------------------------------------------------------------
# Assert-NotKilijRoot: abort if the given dir resolves to the Kilij repo root.
# ---------------------------------------------------------------------------
function Assert-NotKilijRoot {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Dir
  )
  if (Test-Path $Dir) {
    $resolved = (Resolve-Path $Dir).Path.TrimEnd("\", "/")
    $rootNorm = $repoRoot.TrimEnd("\", "/")
    if ($resolved.ToLowerInvariant() -eq $rootNorm.ToLowerInvariant()) {
      throw "FATAL: LLVM_PROJECT_DIR resolved to the Kilij repo root ($repoRoot).`nThis would corrupt the source repo. Aborting."
    }
  }
}

$vsInstall = Get-VsInstallationPath
$vsDevCmd = $null
$vsCmake = $null
$vsNinja = $null
if ($vsInstall) {
  $vsDevCmd = Join-Path $vsInstall "Common7\\Tools\\VsDevCmd.bat"
  $vsCmake = Join-Path $vsInstall "Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\cmake.exe"
  $vsNinja = Join-Path $vsInstall "Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\Ninja\\ninja.exe"
}

$cmakeExe = Find-Exe -Name "cmake" -CandidatePaths @(
  "C:\\Program Files\\CMake\\bin\\cmake.exe",
  $vsCmake
)
$ninjaExe = Find-Exe -Name "ninja" -CandidatePaths @(
  $vsNinja
)

if (-not $cmakeExe) {
  throw "cmake.exe not found. Install CMake or use a Visual Studio install that includes CMake (CommonExtensions\\Microsoft\\CMake)."
}
if (-not $ninjaExe) {
  throw "ninja.exe not found. Install Ninja or use a Visual Studio install that includes Ninja (CommonExtensions\\Microsoft\\CMake\\Ninja)."
}
if (-not $vsDevCmd -or -not (Test-Path $vsDevCmd)) {
  throw "VsDevCmd.bat not found. Install Visual Studio Build Tools (MSVC x64) or run this script from a Developer Command Prompt."
}

New-Item -ItemType Directory -Force $LlvmProjectDir | Out-Null
Assert-NotKilijRoot -Dir $LlvmProjectDir

$llvmGit = Join-Path $LlvmProjectDir ".git"
if (-not (Test-Path $llvmGit)) {
  # Only initialize if the directory is empty (avoid stomping on user content).
  $count = (Get-ChildItem -Force $LlvmProjectDir | Measure-Object).Count
  if ($count -ne 0) {
    throw "LlvmProjectDir exists but is not a git repo: $LlvmProjectDir. Delete it or pass -LlvmProjectDir to an empty folder."
  }
  Write-Host "Initializing LLVM shallow clone in $LlvmProjectDir ..."
  Invoke-Git -RepoDir $LlvmProjectDir -Args @("init") -What "git init"
  Invoke-Git -RepoDir $LlvmProjectDir -Args @("remote", "add", "origin", "https://github.com/llvm/llvm-project.git") -What "git remote add"
} else {
  Assert-OwnGitRepo -RepoDir $LlvmProjectDir
  $prevEap = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $origin = (& git -C "$LlvmProjectDir" remote get-url origin 2>$null)
  } finally {
    $ErrorActionPreference = $prevEap
  }
  if ($origin) { $origin = $origin.Trim() }
  if (-not $origin) {
    Invoke-Git -RepoDir $LlvmProjectDir -Args @("remote", "add", "origin", "https://github.com/llvm/llvm-project.git") -What "git remote add"
  } elseif ($origin -ne "https://github.com/llvm/llvm-project.git") {
    Write-Host "WARNING: resetting LLVM origin from $origin to llvm-project.git"
    Invoke-Git -RepoDir $LlvmProjectDir -Args @("remote", "set-url", "origin", "https://github.com/llvm/llvm-project.git") -What "git remote set-url"
  }
}

Assert-OwnGitRepo -RepoDir $LlvmProjectDir
Assert-NotKilijRoot -Dir $LlvmProjectDir
$llvmRoot = (Resolve-Path $LlvmProjectDir)

Write-Host ("LLVM dir: " + $llvmRoot.Path)

# A previous interrupted fetch/checkout can leave lock files behind; safe to remove.
foreach ($lockFile in @("shallow.lock", "index.lock")) {
  $lockPath = Join-Path $llvmRoot.Path ".git\$lockFile"
  if (Test-Path $lockPath) {
    Write-Host "Removing stale lock file: $lockPath"
    Remove-Item -Force $lockPath
  }
}

Invoke-Git -RepoDir $llvmRoot.Path -Args @("fetch", "--depth", "1", "origin", $LlvmCommit) -What "git fetch"
Invoke-Git -RepoDir $llvmRoot.Path -Args @("checkout", "--detach", "-f", "FETCH_HEAD") -What "git checkout"

# Copy Kilij sources into the LLVM tree (excluding release tooling).
$dst = Join-Path $llvmRoot.Path "llvm\\lib\\Transforms\\Obfuscation"
New-Item -ItemType Directory -Force $dst | Out-Null

# robocopy exit codes 0-7 are success (bitmask: 1=copied, 2=extras, 4=mismatched).
# Only >=8 indicates an error.
& robocopy "$repoRoot" "$dst" *.cpp *.h *.md *.txt *.gitattributes LICENSE /S /NFL /NDL /NJH /NJS /NP /XD release .git .claude e2e kilij-tests _llvm _build _install _release_out _e2e_work | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy (main sources) failed with exit code $LASTEXITCODE" }

$vmSrc = Join-Path $repoRoot "VM"
if (Test-Path $vmSrc) {
  & robocopy "$vmSrc" (Join-Path $dst "VM") * /S /NFL /NDL /NJH /NJS /NP | Out-Null
  if ($LASTEXITCODE -ge 8) { throw "robocopy (VM) failed with exit code $LASTEXITCODE" }
}

$docsSrc = Join-Path $repoRoot "docs"
if (Test-Path $docsSrc) {
  & robocopy "$docsSrc" (Join-Path $dst "docs") * /S /NFL /NDL /NJH /NJS /NP | Out-Null
  if ($LASTEXITCODE -ge 8) { throw "robocopy (docs) failed with exit code $LASTEXITCODE" }
}

Copy-Item -Force (Join-Path $repoRoot "CMakeLists.txt") (Join-Path $dst "CMakeLists.txt")

# ---------------------------------------------------------------------------
# Apply patches (idempotent). Each patch is checked, applied if needed, or
# skipped if already applied.
# ---------------------------------------------------------------------------
function Apply-PatchIdempotent {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoDir,
    [Parameter(Mandatory = $true)]
    [string]$PatchPath,
    [Parameter(Mandatory = $false)]
    [string]$Label = ""
  )
  if (-not (Test-Path $PatchPath)) {
    throw "Patch file not found: $PatchPath"
  }
  if (-not $Label) { $Label = (Split-Path -Leaf $PatchPath) }

  Push-Location $RepoDir
  try {
    $null = & git apply --check "$PatchPath" 2>&1
    if ($LASTEXITCODE -eq 0) {
      Write-Host "Applying patch: $Label"
      $null = & git apply "$PatchPath" 2>&1
      if ($LASTEXITCODE -ne 0) { throw "Failed to apply patch: $PatchPath" }
    } else {
      $null = & git apply -R --check "$PatchPath" 2>&1
      if ($LASTEXITCODE -ne 0) {
        throw ("Patch did not apply cleanly and is not already applied: $PatchPath`n" +
               "The LLVM tree may be in an inconsistent state. Try deleting $RepoDir and re-running.")
      }
      Write-Host "Patch already applied: $Label"
    }
  } finally {
    Pop-Location
  }
}

Apply-PatchIdempotent -RepoDir $llvmRoot.Path `
  -PatchPath (Join-Path $repoRoot "release\patches\kilij_in_tree_clang.patch") `
  -Label "kilij_in_tree_clang"

Apply-PatchIdempotent -RepoDir $llvmRoot.Path `
  -PatchPath (Join-Path $repoRoot "release\patches\extract_symbols_analysiskey.patch") `
  -Label "extract_symbols_analysiskey"

# ---------------------------------------------------------------------------
# Configure + build.
# ---------------------------------------------------------------------------
Write-Host ("Using cmake: " + $cmakeExe)
Write-Host ("Using ninja: " + $ninjaExe)
Write-Host ("Using VsDevCmd: " + $vsDevCmd)

$llvmSrc = (Join-Path $llvmRoot.Path "llvm")
if (-not (Test-Path $llvmSrc)) {
  throw "LLVM source directory not found: $llvmSrc"
}

$cmakeLine = "`"$cmakeExe`" -S `"$llvmSrc`" -B `"$BuildDir`" -G Ninja " + `
  "-DCMAKE_BUILD_TYPE=Release " + `
  "-DLLVM_ENABLE_PROJECTS=clang;lld " + `
  "-DLLVM_TARGETS_TO_BUILD=X86 " + `
  "-DLLVM_INCLUDE_TESTS=OFF " + `
  "-DLLVM_INCLUDE_EXAMPLES=OFF " + `
  "-DLLVM_ENABLE_ASSERTIONS=OFF " + `
  "-DLLVM_EXPORT_SYMBOLS_FOR_PLUGINS=ON " + `
  # Keep LLVM_ENABLE_PLUGINS=OFF on Windows static builds.
  # Kilij.dll is built as a MODULE that imports symbols from opt.exe (see
  # llvm/lib/Transforms/Obfuscation/CMakeLists.txt), and enabling plugins here
  # causes LLVM headers to switch to dllimport/dllexport modes that require a
  # shared-LLVM build.
  "-DLLVM_ENABLE_PLUGINS=OFF"

$ninjaLine = "`"$ninjaExe`" -C `"$BuildDir`" clang opt lld Kilij llvm-as llvm-dis llvm-objdump llvm-stress"

Write-Host "Configuring LLVM build ..."
Invoke-InVsDevCmd -VsDevCmdBat $vsDevCmd -CommandLine $cmakeLine

Write-Host "Building LLVM (this may take a while) ..."
Invoke-InVsDevCmd -VsDevCmdBat $vsDevCmd -CommandLine $ninjaLine

# ---------------------------------------------------------------------------
# Package into a release zip.
# ---------------------------------------------------------------------------
$packageScript = Join-Path $repoRoot "release\package_windows.ps1"
if (-not (Test-Path $packageScript)) {
  throw "Packaging script not found: $packageScript"
}
powershell -ExecutionPolicy Bypass -File "$packageScript" -BuildDir "$BuildDir" -OutDir "$OutDir"

