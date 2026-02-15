# Provenable.ai AER Installer

Installer for [Provenable.ai](https://github.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI) with **Agent Evidence & Recovery (AER)** guardrails, compatible with OpenClaw and other agentic systems. All tooling is written in Rust.

## Quick Install

### macOS / Linux

```bash
curl -sSL https://raw.githubusercontent.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI/main/installer/install/install-proven-aer.sh | bash
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI/main/installer/install/install-proven-aer.ps1 | iex
```

### Pin a Specific Version

```bash
# Unix
bash install-proven-aer.sh --version 0.1.0

# Windows
.\install-proven-aer.ps1 -Version 0.1.0
```

## Prerequisites

- **Node.js >= 22.0.0** (LTS recommended)
- **npm** (bundled with Node.js)
- **Rust toolchain** (for building the installer tools; not needed for end-user installation)

## Security Defaults

The installer applies security-safe defaults out of the box:

| Setting | Default | Description |
|---------|---------|-------------|
| `server.host` | `127.0.0.1` | Localhost only — not exposed to network |
| `server.authRequired` | `true` | Authentication required for all requests |
| `server.trustedProxies` | `[]` | No proxies trusted |
| `aer.enabled` | `true` | AER guardrails active |

## How It Works

1. **Fetches** the pinned version manifest (`manifest.json`)
2. **Validates** the requested version is in the allowlist
3. **Installs** Proven via `npm install` with `--save-exact`
4. **Verifies** the installed version matches the request
5. **Writes** a security-safe configuration file
6. **Creates** AER state directories for evidence recording
7. **Generates** wrapper scripts for PATH integration

## Repository Structure

```
installer/
├── install/                        # Installer scripts
│   ├── install-proven-aer.sh         # macOS / Linux
│   └── install-proven-aer.ps1        # Windows
├── manifest/
│   └── manifest.json               # Pinned version manifest
├── tools/                          # Rust tooling
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs                     # CLI entry point
│   │   ├── manifest.rs                 # Manifest types & helpers
│   │   ├── validate.rs                 # validate subcommand
│   │   ├── checksums.rs                # gen-checksums subcommand
│   │   └── pin.rs                      # pin-version subcommand
│   └── tests/
│       └── integration_tests.rs        # 18 integration tests
├── scripts/                        # Smoke tests
│   ├── smoke_install_unix.sh           # Unix smoke tests
│   └── smoke_install_windows.ps1       # Windows smoke tests
├── docs/
│   ├── VERIFY.md                   # Checksum verification guide
│   ├── SECURITY.md                 # Security policy
│   └── RELEASE.md                  # Release process
├── .github/workflows/
│   ├── ci.yml                      # CI pipeline
│   ├── release.yml                 # Release automation
│   └── pin-update.yml              # Version pin workflow
├── checksums.txt                   # SHA-256 checksums for artifacts
├── LICENSE                         # MIT License
└── README.md                       # This file
```

## Verification

Verify installer integrity with SHA-256 checksums:

```bash
# Unix
sha256sum install-proven-aer.sh
# Compare with checksums.txt

# macOS
shasum -a 256 install-proven-aer.sh

# Windows
Get-FileHash install-proven-aer.ps1 -Algorithm SHA256
```

See [docs/VERIFY.md](docs/VERIFY.md) for detailed verification instructions.

## Development

### Build Rust Tools

```bash
cd installer
cargo build --manifest-path tools/Cargo.toml
```

### Validate Manifest

```bash
tools/target/debug/installer-tools validate
```

### Regenerate Checksums

```bash
tools/target/debug/installer-tools gen-checksums
```

### Pin a New Version

```bash
tools/target/debug/installer-tools pin-version --version X.Y.Z --set-default
```

### Run Tests

```bash
cargo test --manifest-path tools/Cargo.toml -- --test-threads=1
```

### Run Smoke Tests

```bash
chmod +x install/install-proven-aer.sh scripts/smoke_install_unix.sh
bash scripts/smoke_install_unix.sh
```

## License

[MIT](LICENSE)
