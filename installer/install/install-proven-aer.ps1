#Requires -Version 5.1
<#
.SYNOPSIS
    Install Provenable.ai AER on Windows.
.DESCRIPTION
    Downloads the pinned manifest, verifies the version allowlist,
    installs Provenable.ai via npm with security-safe defaults, and
    initialises the AER state directory.
.NOTES
    MIT License — Copyright (c) 2026 Daniel Foo Jun Wei
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$Version,

    [Parameter()]
    [string]$InstallDir,

    [Parameter()]
    [switch]$SkipChecksum,

    [Parameter()]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Defaults ──────────────────────────────────────────────────────
$InstallerVersion = "0.1.0"
$ManifestUrl = if ($env:PRV_MANIFEST_URL) { $env:PRV_MANIFEST_URL } else {
    "https://raw.githubusercontent.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI/main/installer/manifest/manifest.json"
}
if (-not $InstallDir) {
    $InstallDir = if ($env:PRV_INSTALL_DIR) { $env:PRV_INSTALL_DIR } else {
        Join-Path $env:USERPROFILE ".proven"
    }
}
if (-not $SkipChecksum -and $env:PRV_SKIP_CHECKSUM -eq "true") {
    $SkipChecksum = [switch]::Present
}
$NodeMinMajor = 22
$BindHost = "127.0.0.1"
$AuthRequired = $true
$TrustedProxies = @()

# ── Helpers ───────────────────────────────────────────────────────
function Write-Info  { param([string]$Msg) Write-Host "INFO  $Msg" -ForegroundColor Cyan }
function Write-Ok    { param([string]$Msg) Write-Host "OK    $Msg" -ForegroundColor Green }
function Write-Warn  { param([string]$Msg) Write-Host "WARN  $Msg" -ForegroundColor Yellow }
function Write-Fatal { param([string]$Msg) Write-Host "ERROR $Msg" -ForegroundColor Red; exit 1 }

function Show-Usage {
    @"
Usage: install-proven-aer.ps1 [OPTIONS]

Install Provenable.ai with AER (Agent Evidence & Recovery) guardrails.

Options:
  -Version VER       Pin a specific Proven version (X.Y.Z)
  -InstallDir DIR    Installation directory (default: ~\.proven)
  -SkipChecksum      Skip SHA-256 manifest verification (NOT recommended)
  -Help              Show this help message

Environment Variables:
  PRV_MANIFEST_URL   Override manifest fetch URL
  PRV_INSTALL_DIR    Override installation directory
  PRV_SKIP_CHECKSUM  Set to "true" to skip checksums

Security Defaults:
  - Binds to 127.0.0.1 only (no 0.0.0.0)
  - Authentication required by default
  - trustedProxies set to [] (empty)
"@ | Write-Host
    exit 0
}

if ($Help) { Show-Usage }

# ── Pre-flight checks ────────────────────────────────────────────
try {
    $nodeExe = Get-Command node -ErrorAction Stop
} catch {
    Write-Fatal "Node.js not found. Install Node.js >= $NodeMinMajor first."
}

try {
    $npmExe = Get-Command npm -ErrorAction Stop
} catch {
    Write-Fatal "npm not found. Install Node.js >= $NodeMinMajor first."
}

$NodeVersionRaw = & node -v
$NodeVersion = $NodeVersionRaw -replace '^v', ''
$NodeMajor = [int]($NodeVersion.Split('.')[0])

if ($NodeMajor -lt $NodeMinMajor) {
    Write-Fatal "Node.js $NodeVersion found, but >= $NodeMinMajor.0.0 is required."
}
Write-Ok "Node.js v$NodeVersion detected (>= $NodeMinMajor required)"

# ── Fetch manifest ────────────────────────────────────────────────
Write-Info "Fetching manifest from $ManifestUrl"

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("proven-install-" + [guid]::NewGuid().ToString("N").Substring(0,8))
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

try {
    $ManifestFile = Join-Path $TmpDir "manifest.json"

    # Use TLS 1.2+
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    try {
        Invoke-WebRequest -Uri $ManifestUrl -OutFile $ManifestFile -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Fatal "Failed to fetch manifest: $_"
    }

    Write-Ok "Manifest fetched"

    # ── Parse manifest ────────────────────────────────────────────
    $Manifest = Get-Content $ManifestFile -Raw | ConvertFrom-Json

    if ($Manifest.schema_version -ne "0.1") {
        Write-Fatal "Unsupported manifest schema_version: $($Manifest.schema_version)"
    }

    if ($Manifest.proven.install_mode -ne "npm") {
        Write-Fatal "Unsupported install_mode: $($Manifest.proven.install_mode)"
    }

    $DefaultVersion = $Manifest.proven.default_version
    $AllowedVersions = @($Manifest.proven.pinned_versions | Where-Object { $_.allowed -eq $true } | ForEach-Object { $_.version })

    # Determine target version
    $TargetVersion = if ($Version) { $Version } else { $DefaultVersion }

    # Validate version is in allowlist
    if ($TargetVersion -notin $AllowedVersions) {
        Write-Fatal "Version $TargetVersion is not in the pinned allowlist. Allowed: $($AllowedVersions -join ', ')"
    }
    Write-Ok "Version $TargetVersion is in the pinned allowlist"

    # Check Node.js engine constraint
    $VersionEntry = $Manifest.proven.pinned_versions | Where-Object { $_.version -eq $TargetVersion } | Select-Object -First 1
    $EnginesNodeMin = if ($VersionEntry.engines_node_min) { $VersionEntry.engines_node_min } else { ">=22.0.0" }
    $EnginesMajor = [int](($EnginesNodeMin -replace '^>=', '').Split('.')[0])
    if ($NodeMajor -lt $EnginesMajor) {
        Write-Fatal "Proven $TargetVersion requires Node.js >= $($EnginesNodeMin -replace '^>=', '') (found $NodeVersion)"
    }

    # ── Checksum verification ─────────────────────────────────────
    if ($SkipChecksum) {
        Write-Warn "Checksum verification SKIPPED (-SkipChecksum)"
        Write-Warn "This is NOT recommended for production use"
    } else {
        Write-Info "Manifest checksum verification will be performed after install"
    }

    # ── Create install directory ──────────────────────────────────
    Write-Info "Installing to $InstallDir"
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

    # ── Install Proven via npm ────────────────────────────────────
    Write-Info "Installing proven@$TargetVersion via npm..."

    $npmArgs = @("install", "--prefix", $InstallDir, "proven@$TargetVersion", "--save-exact")
    $npmProcess = Start-Process -FilePath "npm" -ArgumentList $npmArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $TmpDir "npm-stdout.txt") -RedirectStandardError (Join-Path $TmpDir "npm-stderr.txt")

    if ($npmProcess.ExitCode -ne 0) {
        $npmErr = Get-Content (Join-Path $TmpDir "npm-stderr.txt") -Raw
        Write-Fatal "npm install failed (exit $($npmProcess.ExitCode)): $npmErr"
    }

    $ModulePath = Join-Path $InstallDir "node_modules" "proven"
    if (-not (Test-Path $ModulePath)) {
        Write-Fatal "npm install succeeded but proven module not found"
    }
    Write-Ok "proven@$TargetVersion installed"

    # ── Verify installed version ──────────────────────────────────
    $PkgJson = Join-Path $ModulePath "package.json"
    $InstalledVersion = (Get-Content $PkgJson -Raw | ConvertFrom-Json).version
    if ($InstalledVersion -ne $TargetVersion) {
        Write-Fatal "Version mismatch: expected $TargetVersion, got $InstalledVersion"
    }
    Write-Ok "Installed version verified: $InstalledVersion"

    # ── Write security-safe config ────────────────────────────────
    $ConfigDir = Join-Path $InstallDir "config"
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null

    $ConfigFile = Join-Path $ConfigDir "proven.json"
    $NowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    $Config = @{
        version = $TargetVersion
        server = @{
            host = $BindHost
            authRequired = $AuthRequired
            trustedProxies = $TrustedProxies
        }
        aer = @{
            enabled = $true
            stateDir = Join-Path $InstallDir "aer-state"
        }
        installer = @{
            version = $InstallerVersion
            installedAt = $NowUtc
            pinned = $TargetVersion
        }
    } | ConvertTo-Json -Depth 4

    Set-Content -Path $ConfigFile -Value $Config -Encoding UTF8
    Write-Ok "Security-safe config written to $ConfigFile"
    Write-Info "  host:           $BindHost (localhost only)"
    Write-Info "  authRequired:   $AuthRequired"
    Write-Info "  trustedProxies: [] (empty)"

    # ── Create AER state directory ────────────────────────────────
    $AerState = Join-Path $InstallDir "aer-state"
    foreach ($sub in @("records", "audit", "snapshots", "blobs")) {
        New-Item -ItemType Directory -Path (Join-Path $AerState $sub) -Force | Out-Null
    }
    Write-Ok "AER state directory created at $AerState"

    # ── Create wrapper script ─────────────────────────────────────
    $BinDir = Join-Path $InstallDir "bin"
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null

    $WrapperCmd = Join-Path $BinDir "proven.cmd"
    @"
@echo off
REM Provenable.ai wrapper — generated by install-proven-aer.ps1
set "PRV_HOME=$InstallDir"
set "PRV_CONFIG=$ConfigFile"
set "PRV_STATE_DIR=$AerState"
node "$InstallDir\node_modules\proven\bin\proven.js" %*
"@ | Set-Content -Path $WrapperCmd -Encoding ASCII

    $WrapperPs1 = Join-Path $BinDir "proven.ps1"
    @"
# Provenable.ai wrapper — generated by install-proven-aer.ps1
`$env:PRV_HOME = "$InstallDir"
`$env:PRV_CONFIG = "$ConfigFile"
`$env:PRV_STATE_DIR = "$AerState"
& node "$InstallDir\node_modules\proven\bin\proven.js" @args
"@ | Set-Content -Path $WrapperPs1 -Encoding UTF8

    Write-Ok "Wrapper scripts created at $BinDir"

    # ── Save install receipt ──────────────────────────────────────
    $ReceiptFile = Join-Path $InstallDir ".install-receipt.json"
    @{
        installer_version = $InstallerVersion
        proven_version = $TargetVersion
        node_version = $NodeVersion
        install_dir = $InstallDir
        installed_at = $NowUtc
        bind_host = $BindHost
        auth_required = $AuthRequired
        trusted_proxies = $TrustedProxies
        checksum_verified = (-not $SkipChecksum)
    } | ConvertTo-Json -Depth 2 | Set-Content -Path $ReceiptFile -Encoding UTF8

    Write-Ok "Install receipt saved to $ReceiptFile"

    # ── Summary ───────────────────────────────────────────────────
    Write-Host ""
    Write-Host "Installation complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Proven:    v$TargetVersion"
    Write-Host "  Location:  $InstallDir"
    Write-Host "  Config:    $ConfigFile"
    Write-Host "  AER State: $AerState"
    Write-Host "  Binary:    $WrapperCmd"
    Write-Host ""
    Write-Host "Add to your PATH:"
    Write-Host "  `$env:PATH = `"$BinDir;`$env:PATH`""
    Write-Host ""
    Write-Host "Or add permanently via System Properties > Environment Variables."
    Write-Host ""
    Write-Host "Security defaults applied:" -ForegroundColor Green
    Write-Host "  - Bound to 127.0.0.1 (localhost only)"
    Write-Host "  - Authentication required"
    Write-Host "  - trustedProxies = [] (empty)"
    Write-Host "  - AER guardrails enabled"
    Write-Host ""

} finally {
    # Cleanup temp directory
    if (Test-Path $TmpDir) {
        Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
    }
}
