# Installer Documentation

## Table of Contents

- [Security Policy](#security-policy)
- [Release Process](#release-process)
- [Verification Guide](#verification-guide)

---

# Security Policy

## Security Defaults

The Provenable.ai AER installer applies the following security-safe defaults:

| Setting | Default | Rationale |
|---------|---------|-----------|
| `server.host` | `127.0.0.1` | Prevents exposure to network; localhost only |
| `server.authRequired` | `true` | All requests must be authenticated |
| `server.trustedProxies` | `[]` | No proxies trusted by default |
| `aer.enabled` | `true` | Agent Evidence & Recovery guardrails active |

These defaults are enforced at install time and verified by CI.

## Pinned Version Allowlist

The installer enforces a strict version allowlist:

1. Only versions listed in `manifest/manifest.json` with `"allowed": true` can be installed
2. Versions must pass semver format validation (`X.Y.Z`)
3. New versions are verified against npm before pinning
4. The `installer-tools pin-version` command automates this with npm verification

This prevents:
- Installation of yanked or compromised npm packages
- Accidental installation of pre-release or untested versions
- Supply chain attacks via version confusion

## Checksum Integrity

All installer artifacts are checksummed with SHA-256:

- `install-proven-aer.sh` — Unix installer
- `install-proven-aer.ps1` — Windows installer
- `manifest.json` — Version manifest

Checksums are stored in both `manifest.json` (for programmatic verification) and `checksums.txt` (for manual verification).

## Node.js Version Requirement

The installer requires Node.js >= 22.0.0, which includes:

- Built-in `--experimental-permission` flag for filesystem/network permission control
- Modern TLS defaults
- Current LTS security patches

## Network Security

- The installer fetches the manifest over HTTPS only
- TLS 1.2+ is enforced on Windows (`[Net.ServicePointManager]::SecurityProtocol`)
- No fallback to HTTP is provided

## AER Guardrails

When AER is enabled (default), the following protections are active:

- **Control-Plane Integrity (CPI)**: Prevents unauthorized modifications to agent configuration files (SOUL.md, AGENTS.md, TOOLS.md, etc.)
- **Memory Integrity (MI)**: Prevents tainted or untrusted data from being written to workspace memory
- **Audit Chain**: Append-only, tamper-evident hash chain records all agent actions
- **Snapshots & Rollback**: Point-in-time snapshots enable recovery from compromised states

## Reporting Vulnerabilities

If you discover a security vulnerability in the installer or AER system:

1. **Do NOT** create a public GitHub issue
2. Contact the maintainer directly via the repository's security advisory feature
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

## Threat Model

### In Scope

- Version pinning bypass (installing non-allowed versions)
- Checksum verification bypass
- Insecure default configurations
- Command injection via installer arguments
- Man-in-the-middle attacks on manifest download
- Privilege escalation during installation

### Out of Scope

- Vulnerabilities in Node.js itself
- Vulnerabilities in npm packages installed by Proven
- Physical access to the host machine
- Compromise of the GitHub repository or npm registry

---

# Release Process

## Overview

The Provenable.ai AER installer uses a tag-based release process with automated CI validation. All tooling is written in Rust.

## Version Scheme

- **Installer version**: `X.Y.Z` (semver) — tracks the installer scripts themselves
- **Proven version**: `X.Y.Z` (semver) — tracks the pinned Proven npm package
- **Release tags**: `installer-vX.Y.Z` — triggers the release workflow

## Releasing a New Installer Version

### 1. Update the Installer Version

Update the version in the following files:

```
installer/manifest/manifest.json  → installer.version
installer/install/install-proven-aer.sh  → INSTALLER_VERSION
installer/install/install-proven-aer.ps1  → $InstallerVersion
```

### 2. Build the Rust tools (if not already built)

```bash
cd installer
cargo build --manifest-path tools/Cargo.toml
```

### 3. Regenerate Checksums

```bash
tools/target/debug/installer-tools gen-checksums
```

This updates `manifest.json` with new artifact SHA-256 hashes and regenerates `checksums.txt`.

### 4. Validate

```bash
tools/target/debug/installer-tools validate
```

### 5. Run Tests

```bash
cargo test --manifest-path tools/Cargo.toml -- --test-threads=1
```

### 6. Run Smoke Tests

```bash
chmod +x install/install-proven-aer.sh scripts/smoke_install_unix.sh
bash scripts/smoke_install_unix.sh
```

### 7. Commit and Tag

```bash
git add installer/
git commit -m "release: installer vX.Y.Z"
git tag installer-vX.Y.Z
git push origin main --tags
```

### 8. Automated Release

The `release.yml` workflow triggers on `installer-v*` tags and:

1. Builds the Rust tools
2. Validates the manifest
3. Verifies checksums haven't drifted
4. Runs smoke tests on Ubuntu and macOS
5. Creates a GitHub Release with the installer artifacts

## Pinning a New Proven Version

### Via GitHub Actions (Recommended)

1. Go to **Actions** > **Pin Proven Version**
2. Click **Run workflow**
3. Enter the version (e.g., `1.2.3`)
4. Optionally check "Set as default version"
5. The workflow creates a PR with the manifest changes

### Via Command Line

```bash
cd installer

# Pin version (verifies on npm first)
tools/target/debug/installer-tools pin-version --version 1.2.3

# Pin and set as default
tools/target/debug/installer-tools pin-version --version 1.2.3 --set-default

# Skip npm check (for testing only)
tools/target/debug/installer-tools pin-version --version 1.2.3 --skip-npm-check

```

### What `pin-version` Does

1. Validates version format (semver)
2. Verifies version exists on npm (`npm view proven@X.Y.Z`)
3. Fetches `engines.node` requirement from npm
4. Adds version to `manifest.json` pinned_versions
5. Optionally sets it as default_version
6. Runs `validate` to check consistency
7. Runs `gen-checksums` to update hashes

## Deprecating a Version

To remove a version from the allowlist without deleting its entry:

1. Edit `manifest/manifest.json`
2. Set `"allowed": false` for the version
3. Ensure `default_version` points to an allowed version
4. Run `tools/target/debug/installer-tools validate`
5. Commit and push

## CI Pipeline

Every push to `main` or PR targeting `main` (under `installer/` paths) runs:

| Job | Description |
|-----|-------------|
| `build-tools` | Compiles the Rust `installer-tools` binary |
| `validate-manifest` | Schema and consistency checks |
| `verify-checksums` | Regenerates and checks for drift |
| `rust-tests` | 18 integration tests |
| `lint-shell` | ShellCheck on `.sh` files |
| `smoke-unix` | Smoke tests on Ubuntu + macOS |
| `smoke-windows` | Smoke tests on Windows |
| `security-scan` | Verifies security defaults |

## Rollback

If a release needs to be rolled back:

1. Delete the GitHub Release (or mark as pre-release)
2. Set the problematic version's `"allowed": false` in `manifest.json`
3. Update `default_version` to the last known good version
4. Commit, tag a new installer release, and push

---

# Verification Guide

This section explains how to verify the integrity of Provenable.ai AER installer artifacts.

## Checksum Verification

Every release includes a `checksums.txt` file containing SHA-256 hashes for all installer artifacts and the manifest.

### Verify on macOS / Linux

```bash
# Download checksums.txt and artifacts
curl -sSLO https://raw.githubusercontent.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI/main/installer/checksums.txt

# Verify the installer script
sha256sum install-proven-aer.sh
# Compare the output with the hash in checksums.txt

# Or verify all artifacts at once (if you have them locally)
sha256sum -c checksums.txt
```

On macOS (which uses `shasum` instead of `sha256sum`):

```bash
shasum -a 256 install-proven-aer.sh
# Compare with checksums.txt
```

### Verify on Windows (PowerShell)

```powershell
# Compute hash of installer script
Get-FileHash install-proven-aer.ps1 -Algorithm SHA256

# Compare with checksums.txt
Get-Content checksums.txt
```

## Manifest Verification

The `manifest/manifest.json` file is the source of truth for:

- **Installer version**: The version of the installer scripts
- **Artifact checksums**: SHA-256 hashes of installer scripts
- **Pinned versions**: Allowed Proven versions
- **Default version**: The version installed when no `--version` flag is provided

### Validate Manifest Locally

```bash
cd installer
cargo run --manifest-path tools/Cargo.toml -- validate
```

Or if you've already built the binary:

```bash
tools/target/debug/installer-tools validate
```

This checks:
- JSON syntax
- Schema version compatibility
- Installer version format
- Artifact checksum format (valid SHA-256 hex)
- Pinned version format (semver)
- Default version is in the allowed list

### Regenerate Checksums

```bash
cd installer
tools/target/debug/installer-tools gen-checksums
```

This recomputes SHA-256 hashes for all artifacts and updates both `manifest.json` and `checksums.txt`.

## CI Verification

Every push and pull request runs automated verification:

1. **Rust build** — Compiles the `installer-tools` binary
2. **Manifest validation** — `installer-tools validate` checks schema
3. **Checksum drift detection** — Regenerates checksums and verifies no changes
4. **Rust tests** — 18 integration tests covering validation, checksums, pinning, and security defaults
5. **ShellCheck** — Static analysis of shell scripts
6. **Smoke tests** — Runs on Ubuntu, macOS, and Windows

## Security Defaults Audit

The CI pipeline also verifies security defaults:

- Installer binds to `127.0.0.1` (not `0.0.0.0`)
- `authRequired` defaults to `true`
- `trustedProxies` defaults to `[]` (empty array)

These checks are enforced in `.github/workflows/ci.yml` under the `security-scan` job.

## Pinned Version Verification

The installer only installs versions listed in `manifest.json` under `proven.pinned_versions` with `"allowed": true`. This prevents supply chain attacks where a compromised npm package could be installed.

To pin a new version:

```bash
tools/target/debug/installer-tools pin-version --version X.Y.Z
```

This verifies the version exists on npm before adding it to the manifest.
