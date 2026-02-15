# Verification Guide

This document explains how to verify the integrity of OpenClaw AER installer artifacts.

## Checksum Verification

Every release includes a `checksums.txt` file containing SHA-256 hashes for all installer artifacts and the manifest.

### Verify on macOS / Linux

```bash
# Download checksums.txt and artifacts
curl -sSLO https://raw.githubusercontent.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI/main/installer/checksums.txt

# Verify the installer script
sha256sum install-openclaw-aer.sh
# Compare the output with the hash in checksums.txt

# Or verify all artifacts at once (if you have them locally)
sha256sum -c checksums.txt
```

On macOS (which uses `shasum` instead of `sha256sum`):

```bash
shasum -a 256 install-openclaw-aer.sh
# Compare with checksums.txt
```

### Verify on Windows (PowerShell)

```powershell
# Compute hash of installer script
Get-FileHash install-openclaw-aer.ps1 -Algorithm SHA256

# Compare with checksums.txt
Get-Content checksums.txt
```

## Manifest Verification

The `manifest/manifest.json` file is the source of truth for:

- **Installer version**: The version of the installer scripts
- **Artifact checksums**: SHA-256 hashes of installer scripts
- **Pinned versions**: Allowed OpenClaw versions
- **Default version**: The version installed when no `--version` flag is provided

### Validate Manifest Locally

```bash
cd installer
python3 scripts/validate_manifest.py
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
python3 scripts/gen_checksums.py
```

This recomputes SHA-256 hashes for all artifacts and updates both `manifest.json` and `checksums.txt`.

## CI Verification

Every push and pull request runs automated verification:

1. **Manifest validation** — `validate_manifest.py` checks schema
2. **Checksum drift detection** — Regenerates checksums and verifies no changes
3. **ShellCheck** — Static analysis of shell scripts
4. **Python syntax** — Validates all Python scripts compile
5. **Smoke tests** — Runs on Ubuntu, macOS, and Windows

## Security Defaults Audit

The CI pipeline also verifies security defaults:

- Installer binds to `127.0.0.1` (not `0.0.0.0`)
- `authRequired` defaults to `true`
- `trustedProxies` defaults to `[]` (empty array)

These checks are enforced in `.github/workflows/ci.yml` under the `security-scan` job.

## Pinned Version Allowlist

The installer only installs versions listed in `manifest.json` under `openclaw.pinned_versions` with `"allowed": true`. This prevents supply chain attacks where a compromised npm package could be installed.

To pin a new version:

```bash
python3 scripts/pin_openclaw.py --version X.Y.Z
```

This verifies the version exists on npm before adding it to the manifest.
