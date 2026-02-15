# Security Policy

## Security Defaults

The OpenClaw AER installer applies the following security-safe defaults:

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
4. The `pin_openclaw.py` script automates this with npm verification

This prevents:
- Installation of yanked or compromised npm packages
- Accidental installation of pre-release or untested versions
- Supply chain attacks via version confusion

## Checksum Integrity

All installer artifacts are checksummed with SHA-256:

- `install-openclaw-aer.sh` — Unix installer
- `install-openclaw-aer.ps1` — Windows installer
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
- Vulnerabilities in npm packages installed by OpenClaw
- Physical access to the host machine
- Compromise of the GitHub repository or npm registry
