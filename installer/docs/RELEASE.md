# Release Process

## Overview

The OpenClaw AER installer uses a tag-based release process with automated CI validation.

## Version Scheme

- **Installer version**: `X.Y.Z` (semver) — tracks the installer scripts themselves
- **OpenClaw version**: `X.Y.Z` (semver) — tracks the pinned OpenClaw npm package
- **Release tags**: `installer-vX.Y.Z` — triggers the release workflow

## Releasing a New Installer Version

### 1. Update the Installer Version

Update the version in the following files:

```
installer/manifest/manifest.json  → installer.version
installer/install/install-openclaw-aer.sh  → INSTALLER_VERSION
installer/install/install-openclaw-aer.ps1  → $InstallerVersion
```

### 2. Regenerate Checksums

```bash
cd installer
python3 scripts/gen_checksums.py
```

This updates `manifest.json` with new artifact SHA-256 hashes and regenerates `checksums.txt`.

### 3. Validate

```bash
python3 scripts/validate_manifest.py
```

### 4. Run Smoke Tests

```bash
chmod +x install/install-openclaw-aer.sh scripts/smoke_install_unix.sh
bash scripts/smoke_install_unix.sh
```

### 5. Commit and Tag

```bash
git add installer/
git commit -m "release: installer vX.Y.Z"
git tag installer-vX.Y.Z
git push origin main --tags
```

### 6. Automated Release

The `release.yml` workflow triggers on `installer-v*` tags and:

1. Validates the manifest
2. Verifies checksums haven't drifted
3. Runs smoke tests on Ubuntu and macOS
4. Creates a GitHub Release with the installer artifacts

## Pinning a New OpenClaw Version

### Via GitHub Actions (Recommended)

1. Go to **Actions** > **Pin OpenClaw Version**
2. Click **Run workflow**
3. Enter the version (e.g., `1.2.3`)
4. Optionally check "Set as default version"
5. The workflow creates a PR with the manifest changes

### Via Command Line

```bash
cd installer

# Pin version (verifies on npm first)
python3 scripts/pin_openclaw.py --version 1.2.3

# Pin and set as default
python3 scripts/pin_openclaw.py --version 1.2.3 --set-default

# Skip npm check (for testing only)
python3 scripts/pin_openclaw.py --version 1.2.3 --skip-npm-check
```

### What pin_openclaw.py Does

1. Validates version format (semver)
2. Verifies version exists on npm (`npm view openclaw@X.Y.Z`)
3. Fetches `engines.node` requirement from npm
4. Adds version to `manifest.json` pinned_versions
5. Optionally sets it as default_version
6. Runs `validate_manifest.py` to check consistency
7. Runs `gen_checksums.py` to update hashes

## Deprecating a Version

To remove a version from the allowlist without deleting its entry:

1. Edit `manifest/manifest.json`
2. Set `"allowed": false` for the version
3. Ensure `default_version` points to an allowed version
4. Run `python3 scripts/validate_manifest.py`
5. Commit and push

## CI Pipeline

Every push to `main` or PR targeting `main` (under `installer/` paths) runs:

| Job | Description |
|-----|-------------|
| `validate-manifest` | Schema and consistency checks |
| `verify-checksums` | Regenerates and checks for drift |
| `lint-shell` | ShellCheck on `.sh` files |
| `lint-python` | Syntax check on `.py` files |
| `smoke-unix` | Smoke tests on Ubuntu + macOS |
| `smoke-windows` | Smoke tests on Windows |
| `security-scan` | Verifies security defaults |

## Rollback

If a release needs to be rolled back:

1. Delete the GitHub Release (or mark as pre-release)
2. Set the problematic version's `"allowed": false` in `manifest.json`
3. Update `default_version` to the last known good version
4. Commit, tag a new installer release, and push
