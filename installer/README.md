# OpenClaw AER Installer

Open-source installer for [OpenClaw](https://github.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI) with **Agent Evidence & Recovery (AER)** guardrails.

## Quick Install

### macOS / Linux

```bash
curl -sSL https://raw.githubusercontent.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI/main/installer/install/install-openclaw-aer.sh | bash
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI/main/installer/install/install-openclaw-aer.ps1 | iex
```

### Pin a Specific Version

```bash
# Unix
bash install-openclaw-aer.sh --version 0.1.0

# Windows
.\install-openclaw-aer.ps1 -Version 0.1.0
```

## Prerequisites

- **Node.js >= 22.0.0** (LTS recommended)
- **npm** (bundled with Node.js)
- **python3** (for manifest parsing; pre-installed on macOS/Linux)

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
3. **Installs** OpenClaw via `npm install` with `--save-exact`
4. **Verifies** the installed version matches the request
5. **Writes** a security-safe configuration file
6. **Creates** AER state directories for evidence recording
7. **Generates** wrapper scripts for PATH integration

## Repository Structure

```
installer/
├── install/                    # Installer scripts
│   ├── install-openclaw-aer.sh     # macOS / Linux
│   └── install-openclaw-aer.ps1    # Windows
├── manifest/
│   └── manifest.json           # Pinned version manifest
├── scripts/                    # Tooling
│   ├── validate_manifest.py    # Manifest schema validator
│   ├── gen_checksums.py        # SHA-256 checksum generator
│   ├── pin_openclaw.py         # Version pinning script
│   ├── smoke_install_unix.sh   # Unix smoke tests
│   └── smoke_install_windows.ps1   # Windows smoke tests
├── docs/
│   ├── VERIFY.md               # Checksum verification guide
│   ├── SECURITY.md             # Security policy
│   └── RELEASE.md              # Release process
├── .github/workflows/
│   ├── ci.yml                  # CI pipeline
│   ├── release.yml             # Release automation
│   └── pin-update.yml          # Version pin workflow
├── checksums.txt               # SHA-256 checksums for artifacts
├── LICENSE                     # MIT License
└── README.md                   # This file
```

## Verification

Verify installer integrity with SHA-256 checksums:

```bash
# Unix
sha256sum install-openclaw-aer.sh
# Compare with checksums.txt

# macOS
shasum -a 256 install-openclaw-aer.sh

# Windows
Get-FileHash install-openclaw-aer.ps1 -Algorithm SHA256
```

See [docs/VERIFY.md](docs/VERIFY.md) for detailed verification instructions.

## Development

### Validate Manifest

```bash
python3 scripts/validate_manifest.py
```

### Regenerate Checksums

```bash
python3 scripts/gen_checksums.py
```

### Pin a New Version

```bash
python3 scripts/pin_openclaw.py --version X.Y.Z --set-default
```

### Run Smoke Tests

```bash
chmod +x install/install-openclaw-aer.sh scripts/smoke_install_unix.sh
bash scripts/smoke_install_unix.sh
```

## License

[MIT](LICENSE)
