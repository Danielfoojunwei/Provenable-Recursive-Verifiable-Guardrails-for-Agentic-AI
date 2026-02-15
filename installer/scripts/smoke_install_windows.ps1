#Requires -Version 5.1
<#
.SYNOPSIS
    Smoke test for install-proven-aer.ps1
.DESCRIPTION
    Verifies the installer script structure, manifest, security defaults,
    and Rust tooling without performing a full npm install.
    All tooling is Rust-based (no Python dependency).
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$Installer = Join-Path $RepoRoot "install" "install-proven-aer.ps1"
$ToolsBin = Join-Path $RepoRoot "tools" "target" "debug" "installer-tools.exe"

$Pass = 0
$Fail = 0
$Tests = 0

# ── Helpers ───────────────────────────────────────────────────────
function Test-Pass {
    param([string]$Name)
    $script:Pass++; $script:Tests++
    Write-Host "  PASS: $Name" -ForegroundColor Green
}

function Test-Fail {
    param([string]$Name)
    $script:Fail++; $script:Tests++
    Write-Host "  FAIL: $Name" -ForegroundColor Red
}

function Assert-FileExists {
    param([string]$Path, [string]$Name)
    if (Test-Path $Path) { Test-Pass $Name } else { Test-Fail "$Name — file not found: $Path" }
}

function Assert-Contains {
    param([string]$Path, [string]$Pattern, [string]$Name)
    if (Select-String -Path $Path -Pattern $Pattern -Quiet) {
        Test-Pass $Name
    } else {
        Test-Fail "$Name — pattern '$Pattern' not found in $Path"
    }
}

# ── Tests ─────────────────────────────────────────────────────────
Write-Host "=== Smoke Test: install-proven-aer.ps1 ===" -ForegroundColor Cyan
Write-Host ""

# Build Rust tools if needed
Write-Host "--- Build Rust tooling ---"
if (-not (Test-Path $ToolsBin)) {
    Write-Host "  Building installer-tools..."
    Push-Location (Join-Path $RepoRoot "tools")
    & cargo build --quiet 2>&1
    Pop-Location
}
Assert-FileExists $ToolsBin "installer-tools binary exists"

# Test 1: Installer exists
Write-Host ""
Write-Host "--- Pre-flight ---"
Assert-FileExists $Installer "Installer script exists"

# Test 2: Help flag
Write-Host ""
Write-Host "--- Help flag ---"
try {
    $helpOutput = & powershell -File $Installer -Help 2>&1
    Test-Pass "-Help exits cleanly"
} catch {
    Test-Fail "-Help did not exit cleanly"
}

# Test 3: Manifest validation (Rust)
Write-Host ""
Write-Host "--- Manifest validation (Rust) ---"
$Manifest = Join-Path $RepoRoot "manifest" "manifest.json"
Assert-FileExists $Manifest "manifest.json exists"

try {
    $result = & $ToolsBin validate --manifest $Manifest 2>&1
    if ($LASTEXITCODE -eq 0) {
        Test-Pass "installer-tools validate passes"
    } else {
        Test-Fail "installer-tools validate failed: $result"
    }
} catch {
    Test-Fail "installer-tools validate threw exception: $_"
}

# Test 4: Manifest content
Write-Host ""
Write-Host "--- Manifest content ---"
Assert-Contains $Manifest "schema_version" "Manifest has schema_version"
Assert-Contains $Manifest "install_mode" "Manifest has install_mode"
Assert-Contains $Manifest "pinned_versions" "Manifest has pinned_versions"
Assert-Contains $Manifest "default_version" "Manifest has default_version"
Assert-Contains $Manifest "sha256" "Manifest has sha256 checksums"

# Test 5: Security defaults in installer script
Write-Host ""
Write-Host "--- Security defaults in script ---"
Assert-Contains $Installer "127.0.0.1" "Script binds to 127.0.0.1"
Assert-Contains $Installer "authRequired" "Script sets authRequired"
Assert-Contains $Installer "trustedProxies" "Script sets trustedProxies"

# Test 6: Rust tooling exists
Write-Host ""
Write-Host "--- Rust tooling ---"
Assert-FileExists (Join-Path $RepoRoot "tools" "Cargo.toml") "tools/Cargo.toml exists"
Assert-FileExists (Join-Path $RepoRoot "tools" "src" "main.rs") "tools/src/main.rs exists"
Assert-FileExists (Join-Path $RepoRoot "tools" "src" "manifest.rs") "tools/src/manifest.rs exists"
Assert-FileExists (Join-Path $RepoRoot "tools" "src" "validate.rs") "tools/src/validate.rs exists"
Assert-FileExists (Join-Path $RepoRoot "tools" "src" "checksums.rs") "tools/src/checksums.rs exists"
Assert-FileExists (Join-Path $RepoRoot "tools" "src" "pin.rs") "tools/src/pin.rs exists"

# Test 7: Rust tools CLI help
Write-Host ""
Write-Host "--- Rust tools CLI ---"
try {
    & $ToolsBin --help | Out-Null
    if ($LASTEXITCODE -eq 0) { Test-Pass "installer-tools --help works" }
    else { Test-Fail "installer-tools --help failed" }
} catch {
    Test-Fail "installer-tools --help threw exception"
}

try {
    & $ToolsBin validate --help | Out-Null
    if ($LASTEXITCODE -eq 0) { Test-Pass "installer-tools validate --help works" }
    else { Test-Fail "installer-tools validate --help failed" }
} catch {
    Test-Fail "installer-tools validate --help threw exception"
}

# Test 8: PowerShell installer syntax check
Write-Host ""
Write-Host "--- Syntax check ---"
try {
    $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $Installer -Raw), [ref]$null)
    Test-Pass "Installer has valid PowerShell syntax"
} catch {
    Test-Fail "Installer has syntax errors: $_"
}

# ── Summary ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Results ===" -ForegroundColor Cyan
Write-Host "  Total: $Tests"
Write-Host "  Pass:  $Pass"
Write-Host "  Fail:  $Fail"
Write-Host ""

if ($Fail -gt 0) {
    Write-Host "SMOKE TEST FAILED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "SMOKE TEST PASSED" -ForegroundColor Green
    exit 0
}
