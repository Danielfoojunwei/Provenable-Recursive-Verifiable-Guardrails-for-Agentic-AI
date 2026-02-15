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
