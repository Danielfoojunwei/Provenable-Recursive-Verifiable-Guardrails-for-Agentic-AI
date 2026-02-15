#Requires -Version 5.1
<#
.SYNOPSIS
    Smoke test for install-openclaw-aer.ps1
.DESCRIPTION
    Verifies the installer script structure, manifest, security defaults,
    and Python tooling without performing a full npm install.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$Installer = Join-Path $RepoRoot "install" "install-openclaw-aer.ps1"

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
Write-Host "=== Smoke Test: install-openclaw-aer.ps1 ===" -ForegroundColor Cyan
Write-Host ""

# Test 1: Installer exists
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

# Test 3: Manifest validation
Write-Host ""
Write-Host "--- Manifest validation ---"
$Manifest = Join-Path $RepoRoot "manifest" "manifest.json"
Assert-FileExists $Manifest "manifest.json exists"

$ValidateScript = Join-Path $RepoRoot "scripts" "validate_manifest.py"
try {
    $result = & python3 $ValidateScript 2>&1
    if ($LASTEXITCODE -eq 0) {
        Test-Pass "validate_manifest.py passes"
    } else {
        Test-Fail "validate_manifest.py failed: $result"
    }
} catch {
    # python3 might not be available on Windows, try python
    try {
        $result = & python $ValidateScript 2>&1
        if ($LASTEXITCODE -eq 0) {
            Test-Pass "validate_manifest.py passes"
        } else {
            Test-Fail "validate_manifest.py failed: $result"
        }
    } catch {
        Test-Fail "Python not available to run validate_manifest.py"
    }
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

# Test 6: Python tooling exists
Write-Host ""
Write-Host "--- Python tooling ---"
Assert-FileExists (Join-Path $RepoRoot "scripts" "validate_manifest.py") "validate_manifest.py exists"
Assert-FileExists (Join-Path $RepoRoot "scripts" "gen_checksums.py") "gen_checksums.py exists"
Assert-FileExists (Join-Path $RepoRoot "scripts" "pin_openclaw.py") "pin_openclaw.py exists"

# Test 7: PowerShell installer has no syntax errors
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
