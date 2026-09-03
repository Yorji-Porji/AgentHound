<#
.SYNOPSIS
    Bootstrap AgentHound for local development / use on Windows.

.DESCRIPTION
    One-shot setup script. It:
      1. Locates a compatible Python interpreter (3.11 or 3.12 - the range
         pyproject.toml declares) using the `py` launcher, then python3/python.
      2. Creates an isolated virtual environment (.venv at the repo root).
      3. Upgrades pip and installs AgentHound in editable mode.
      4. (Default) installs the dev extras and runs the test suite to verify.
      5. Prints how to activate the environment and the first commands to run.

    The script is idempotent: re-running it reuses an existing .venv unless
    -Recreate is passed. It never installs anything system-wide - everything
    lands in .venv, which .gitignore already excludes.

.PARAMETER VenvPath
    Where to create the virtual environment. Default: .venv at the repo root.

.PARAMETER Minimal
    Install only runtime dependencies (skip the [dev] extras and tests).
    Use this if you only want to *run* AgentHound, not develop it.

.PARAMETER SkipTests
    Install dev extras but skip running pytest at the end.

.PARAMETER Recreate
    Delete and rebuild the virtual environment from scratch. Existing targets
    must be real directories with a pyvenv.cfg marker; roots, links, and the
    repository directory are refused.

.EXAMPLE
    .\setup.ps1
    Full developer setup: venv + editable install + dev extras + tests.

.EXAMPLE
    .\setup.ps1 -Minimal
    Just enough to run the `agenthound` CLI.

.EXAMPLE
    .\setup.ps1 -Recreate
    Throw away the existing .venv and start clean.
#>

[CmdletBinding()]
param(
    [string] $VenvPath,
    [switch] $Minimal,
    [switch] $SkipTests,
    [switch] $Recreate
)

$ErrorActionPreference = "Stop"

# Resolve the script's own directory robustly. $PSScriptRoot is the normal
# source, but it can be empty depending on how the script is invoked, so fall
# back to the invocation path and finally the current directory.
$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) { $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $ScriptRoot) { $ScriptRoot = (Get-Location).Path }

if (-not $VenvPath) { $VenvPath = Join-Path $ScriptRoot ".venv" }

# --- Pretty output helpers ----------------------------------------------------

function Write-Step($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "  OK  $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "  !   $msg" -ForegroundColor Yellow }
function Fail($msg)        { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

function Get-SafeRecreateTarget([string] $Path) {
    $full = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full)) { return $full }

    $item = Get-Item -LiteralPath $full -Force
    if (-not $item.PSIsContainer) {
        Fail "Refusing -Recreate: '$full' is not a directory."
    }
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail "Refusing -Recreate: '$full' is a link or reparse point."
    }

    $trimmed = $full.TrimEnd([System.IO.Path]::DirectorySeparatorChar,
                            [System.IO.Path]::AltDirectorySeparatorChar)
    $root = ([System.IO.Path]::GetPathRoot($full)).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $repo = ([System.IO.Path]::GetFullPath($ScriptRoot)).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    if ([System.StringComparer]::OrdinalIgnoreCase.Equals($trimmed, $root)) {
        Fail "Refusing -Recreate: '$full' is a filesystem root."
    }
    if ([System.StringComparer]::OrdinalIgnoreCase.Equals($trimmed, $repo)) {
        Fail "Refusing -Recreate: '$full' is the repository root."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $full "pyvenv.cfg") -PathType Leaf)) {
        Fail "Refusing -Recreate: '$full' is not a Python virtual environment (pyvenv.cfg missing)."
    }
    return $full
}

# --- Constants ----------------------------------------------------------------

# Keep in sync with pyproject.toml: requires-python = ">=3.11,<3.15"
$MinMinor = 11
$MaxMinor = 14   # inclusive upper bound (3.15 is excluded)

Write-Host ""
Write-Host "AgentHound setup" -ForegroundColor Magenta
Write-Host "Repo: $ScriptRoot"
Write-Host ""

# --- 1. Locate a compatible Python interpreter --------------------------------

Write-Step "Locating a compatible Python interpreter (3.$MinMinor - 3.$MaxMinor)"

# Each candidate is a base command + base args. We probe the version, then keep
# the first one whose version lands inside the supported range.
$candidates = @(
    @{ Exe = "py";      Args = @("-3.14") },
    @{ Exe = "py";      Args = @("-3.13") },
    @{ Exe = "py";      Args = @("-3.12") },
    @{ Exe = "py";      Args = @("-3.11") },
    @{ Exe = "py";      Args = @("-3")    },
    @{ Exe = "python3"; Args = @()        },
    @{ Exe = "python";  Args = @()        }
)

function Get-PyVersion($exe, $baseArgs) {
    # Returns a [version] or $null if the command can't be run.
    try {
        $out = & $exe @baseArgs -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
        return [version]$out.Trim()
    } catch {
        return $null
    }
}

$python = $null
$pythonArgs = @()
$pythonVersion = $null

foreach ($c in $candidates) {
    if (-not (Get-Command $c.Exe -ErrorAction SilentlyContinue)) { continue }
    $v = Get-PyVersion $c.Exe $c.Args
    if ($null -eq $v) { continue }
    if ($v.Major -eq 3 -and $v.Minor -ge $MinMinor -and $v.Minor -le $MaxMinor) {
        $python = $c.Exe
        $pythonArgs = $c.Args
        $pythonVersion = $v
        break
    } else {
        $argStr = ($c.Args -join ' ').Trim()
        Write-Warn2 "Found Python $v via '$($c.Exe) $argStr' - outside supported range, skipping."
    }
}

if ($null -eq $python) {
    $msg = @(
        "No compatible Python interpreter found (need 3.$MinMinor - 3.$MaxMinor)."
        "Install one from https://www.python.org/downloads/ or the Microsoft Store,"
        "then re-run this script. If you have a compatible Python that wasn't detected,"
        "make sure it's on PATH or available via the 'py' launcher."
    ) -join [Environment]::NewLine
    Fail $msg
}

$pythonArgsStr = ($pythonArgs -join ' ').Trim()
Write-Ok "Using Python $pythonVersion ($python $pythonArgsStr)"

# --- 2. Create (or reuse) the virtual environment -----------------------------

$VenvPath = [System.IO.Path]::GetFullPath($VenvPath)

if ($Recreate -and (Test-Path -LiteralPath $VenvPath)) {
    $VenvPath = Get-SafeRecreateTarget $VenvPath
    Write-Step "Removing existing virtual environment (-Recreate)"
    Remove-Item -LiteralPath $VenvPath -Recurse -Force
}

$venvPython = Join-Path $VenvPath "Scripts\python.exe"

if (Test-Path $venvPython) {
    Write-Step "Reusing existing virtual environment at $VenvPath"
    Write-Ok "venv present"
} else {
    Write-Step "Creating virtual environment at $VenvPath"
    & $python @pythonArgs -m venv $VenvPath
    if (-not (Test-Path $venvPython)) {
        Fail "venv creation failed - '$venvPython' not found after running 'python -m venv'."
    }
    Write-Ok "venv created"
}

# --- 3. Upgrade pip and install AgentHound ------------------------------------

Write-Step "Upgrading pip / setuptools / wheel"
& $venvPython -m pip install --quiet --upgrade pip setuptools wheel
if ($LASTEXITCODE -ne 0) { Fail "Failed to upgrade pip toolchain." }
Write-Ok "pip toolchain up to date"

if ($Minimal) {
    Write-Step "Installing AgentHound (runtime only, editable)"
    & $venvPython -m pip install --editable $ScriptRoot
} else {
    Write-Step "Installing AgentHound with dev extras (editable)"
    # Quote the whole "path[dev]" token so the shell treats it literally and
    # PowerShell does not try to index $ScriptRoot with [dev].
    $editableTarget = $ScriptRoot + "[dev]"
    & $venvPython -m pip install --editable $editableTarget
}
if ($LASTEXITCODE -ne 0) { Fail "pip install failed - see output above." }
Write-Ok "AgentHound installed"

# --- 4. Verify ----------------------------------------------------------------

Write-Step "Verifying the agenthound CLI"
$version = & $venvPython -m agenthound.cli --version 2>&1
if ($LASTEXITCODE -ne 0) { Fail "CLI smoke test failed: $version" }
Write-Ok $version

if (-not $Minimal -and -not $SkipTests) {
    Write-Step "Running the test suite (pytest)"
    & $venvPython -m pytest -q
    if ($LASTEXITCODE -ne 0) {
        Write-Warn2 "Tests reported failures - install is usable but something's off. See output above."
    } else {
        Write-Ok "All tests passed"
    }
}

# --- 5. Next steps ------------------------------------------------------------

$activate = Join-Path $VenvPath "Scripts\Activate.ps1"

Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
Write-Host ""
Write-Host "Activate the environment in your shell:" -ForegroundColor White
Write-Host "    $activate"
Write-Host ""
Write-Host "Then try:" -ForegroundColor White
Write-Host "    agenthound --help"
Write-Host "    agenthound local -o local.json          # scan this machine"
Write-Host "    agenthound mcp -i examples\mcp_inventory.yaml -o mcp.json"
Write-Host "    agenthound infer local.json mcp.json -o graph.json"
Write-Host "    agenthound emit graph.json -o bloodhound.json"
Write-Host ""
Write-Host "Without activating, you can always call the venv directly:" -ForegroundColor DarkGray
Write-Host "    $venvPython -m agenthound.cli --help" -ForegroundColor DarkGray
Write-Host ""
