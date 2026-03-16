# Provenable: Recursive Verifiable Guardrails for Agentic AI

Structural security enforcement for agentic AI systems. A unified Rust
workspace implementing four formal theorems (CPI, MI, Noninterference, RVU)
with cross-surface threat correlation, tamper-evident audit chains, and
automated rollback.

**Version: v0.2.0** | **License: MIT** | **161 tests across 6 crates**

---

## Quick Start

```bash
# Install Rust (if needed): https://rustup.rs
cargo build --workspace --release
./target/release/aegx init
./target/release/aegx status
./target/release/aegx prove
```

See [Installation Guide](docs/INSTALL.md) for platform-specific details and
[Quickstart Tutorial](docs/QUICKSTART.md) for a full walkthrough.

---

## Use as an Agent Skill

> **Want to add provable security guardrails to your AI agent?**
> This repo is ready to use as a skill on any agent platform.

| File | Purpose | Platform |
|------|---------|----------|
| **[`SKILL.md`](SKILL.md)** | Skill manifest and command reference | OpenClaw, Claude Code, Manus, any platform reading `SKILL.md` |
| **[`AGENT.md`](AGENT.md)** | Agent integration guide | All agent platforms |

---

## What This System Delivers

| Capability | Description |
|------------|-------------|
| **Tamper-evident audit chains** | Every agent action is a SHA-256 hash-linked record. Any modification is detectable. |
| **Control-plane integrity (CPI)** | Only `User` and `Sys` principals can modify skills, tools, and permissions. |
| **Memory integrity (MI)** | Persistent agent memory (`SOUL.md`, `MEMORY.md`, etc.) cannot be poisoned by untrusted inputs. |
| **Injection detection** | 8-category prompt injection scanner with cross-surface taint propagation. |
| **Automated rollback (RVU)** | Snapshot/restore with contamination scope computation and threshold-based auto-recovery. |
| **Supply-chain defense** | Pre-install skill scanner detecting all 6 ClawHavoc attack vectors. |
| **File read guard** | Blocks untrusted access to `.env`, `*.pem`, `*.key`, credentials. |
| **Network egress monitor** | Evaluates outbound requests against domain blocklist/allowlist. |
| **Sandbox audit** | Verifies container, seccomp, and namespace isolation at session start. |
| **Cross-surface correlation** | CPI denial escalates MI taint; injection taints all surfaces; combined denials trigger rollback. |

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `aegx init` | Initialize AEGX (state dirs, default policy, workspace) |
| `aegx status` | Show initialization status, record/audit/snapshot counts, chain validity |
| `aegx snapshot create <name> [--scope full\|cp\|mem]` | Create a named snapshot |
| `aegx snapshot list` | List existing snapshots |
| `aegx rollback <snapshot-id>` | Rollback to a previous snapshot with verification |
| `aegx bundle export [--agent <id>] [--since <ts>]` | Export evidence bundle (.aegx.zip) |
| `aegx verify <path.aegx.zip>` | Verify bundle integrity (10-step verification) |
| `aegx report <path.aegx.zip>` | Generate human-readable report from bundle |
| `aegx prove [--json] [--category <cat>] [--severity <sev>]` | Query protection status |

Full reference: [CLI Reference](docs/CLI_REFERENCE.md)

---

## Architecture

Six-crate Rust workspace with strict layering:

```
aegx-cli         Unified CLI binary
    ↑
aegx-runtime     Snapshots, rollback, hooks, /prove query engine
    ↑
aegx-guard       Policy engine, injection scanner, guard surfaces
    ↑
aegx-bundle      Evidence bundle export/verify/report
    ↑
aegx-records     Hash-linked audit chain, JSONL record I/O
    ↑
aegx-types       Canonical JSON, SHA-256 IDs, Principal trust lattice
```

---

## Trust Lattice

Principals are assigned based on **transport channel**, not content claims:

```
Sys (trust level 5)
 └── User (trust level 4)
      └── ToolAuth (trust level 3)
           └── ToolUnauth (trust level 2)
                └── Web, Skill (trust level 1)
                     └── Channel, External (trust level 0)
```

Only `User` and `Sys` can modify the control plane or write to persistent memory.

---

## Formal Foundations

The system implements structural guarantees from four published formal theorems:

- [Noninterference Theorem](https://github.com/Danielfoojunwei/Noninterference-theorem) — Taint-based isolation ensuring untrusted inputs cannot influence tool selection.
- [Control-Plane Integrity Theorem](https://github.com/Danielfoojunwei/Control-plane-integrity-theorem-) — No untrusted input can alter the control plane.
- [Memory Integrity Theorem](https://github.com/Danielfoojunwei/Memory-integrity-theorem) — Immutability, taint blocking, and session isolation for persistent memory.
- [Update/Rollback Verifier](https://github.com/Danielfoojunwei/RVU-Machine-Unlearning) — Provenance DAG with contamination detection and verifiable recovery.

---

## Empirical Validation

Tested against the ZeroLeaks attack taxonomy (36 real attack payloads) and
ClawHavoc supply-chain attacks (341 malicious skills on ClawHub):

| Metric | Before | With AEGX (v0.2.0) |
|--------|--------|---------------------|
| Extraction Success Rate | 84.6% (11/13) | **15.4% (2/13)** |
| Injection Success Rate | 91.3% (21/23) | **4.3% (1/23)** |
| ZLSS (1-10, lower=better) | 10/10 | **1/10** |
| Security Score (0-100) | 2/100 | **90/100** |
| ClawHavoc Vectors Blocked | 0/6 | **6/6** |

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation Guide](docs/INSTALL.md) | Prerequisites, build, install, platform notes |
| [Quickstart Tutorial](docs/QUICKSTART.md) | Up and running in 5 minutes |
| [CLI Reference](docs/CLI_REFERENCE.md) | Every command, flag, and exit code |
| [Agent Integration Guide](docs/AGENT_INTEGRATION.md) | Integrate AEGX into your agent pipeline |
| [AEGX Format Specification](docs/SPEC.md) | Formal specification of the bundle format |
| [Bundle Format Guide](docs/BUNDLE_FORMAT_GUIDE.md) | Visual walkthrough of bundle contents |
| [Verification Guide](docs/VERIFICATION_GUIDE.md) | What verify checks and how to interpret results |
| [Threat Model](docs/THREAT_MODEL.md) | Security analysis and mitigations |
| [ClawHub Integration](docs/clawhub-integration.md) | ClawHub marketplace & ClawHavoc prevention |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common errors and how to fix them |
| [Changelog](docs/CHANGELOG.md) | Release notes |

---

## Development

```bash
make build      # Build all crates (release mode)
make test       # Run all 161 tests
make lint       # Run clippy with warnings as errors
make fmt        # Check formatting
make install    # Install aegx to ~/.cargo/bin
make check      # Run lint + fmt + test
```

Or directly:

```bash
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

---

## License

Copyright 2026 Daniel Foo Jun Wei / Provenable.ai.

The **source code** in this repository is licensed under the MIT License — you may
freely use, modify, and distribute it. See [LICENSE](LICENSE) for full terms.

The **AEGX format specification** (`docs/SPEC.md`) is the original intellectual
property of Daniel Foo Jun Wei / Provenable.ai and is provided for reference only.
Creating independent or competing implementations of the AEGX format requires prior
written permission. See [NOTICE](NOTICE) for details.

"Provenable.ai", "Proven", "PRV", "AEGX", and "AER" are trademarks of
Daniel Foo Jun Wei / Provenable.ai. For licensing inquiries: licensing@provenable.ai
