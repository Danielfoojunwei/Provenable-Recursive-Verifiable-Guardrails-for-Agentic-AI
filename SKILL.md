---
name: provenable
description: Provable security guardrails for agentic AI. Audit agent actions, check protection status, query threat alerts, manage snapshots, verify evidence bundles, and enforce CPI/MI guard policies with the unified aegx CLI.
user-invocable: true
metadata:
  openclaw:
    emoji: shield
    os:
      - linux
      - darwin
    requires:
      bins:
        - aegx
    install:
      - url: https://github.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI.git
        targetDir: ~/.proven
---

# Provenable.ai — Provable Security Guardrails for Agentic AI

> **This file is the skill definition.** Import this repo as a skill in
> [OpenClaw](https://openclaw.ai), [Claude Code](https://claude.ai),
> [Manus](https://manus.im), or any agent platform that reads `SKILL.md`.
> See also: [`AGENT.md`](AGENT.md) for agent-level integration instructions.

Single CLI: `aegx` — unified evidence format, runtime guards, snapshots,
rollback, bundle verification, and `/prove` query interface.

## Setup (one-time)

Build from source:

```bash
cd {baseDir}
cargo build --workspace --release
export PATH="{baseDir}/target/release:$PATH"
```

Initialize the guardrail runtime:

```bash
aegx init
```

Creates the state directory, installs the default policy, and sets up the
workspace. Outputs a policy summary showing the default rules.

## Quick Status — "How am I protected?"

```bash
aegx prove --json
```

Returns protection summary, threat alerts, guard metrics, and system health as JSON.

Human-readable output (no `--json`):

```bash
aegx prove
```

## Query Alerts

Show recent alerts:

```bash
aegx prove --limit 10
```

Filter by severity:

```bash
aegx prove --severity CRITICAL
```

Filter by threat category and time range:

```bash
aegx prove --category CPI --since 2026-02-01T00:00:00Z
```

## Check System Health

```bash
aegx status
```

Shows: initialized state, record count, audit chain integrity, snapshot count.

## Snapshots and Rollback

Create a snapshot before risky operations:

```bash
aegx snapshot create "pre-deploy" --scope full
```

List snapshots:

```bash
aegx snapshot list
```

Rollback to a snapshot:

```bash
aegx rollback <SNAPSHOT_ID>
```

## Evidence Bundles

Export an evidence bundle for audit:

```bash
aegx bundle export --agent <AGENT_ID>
```

Verify a bundle:

```bash
aegx verify <BUNDLE_PATH>
```

Generate a report from a bundle:

```bash
aegx report <BUNDLE_PATH>
```

## Guard Behavior

When the guard denies an action:

1. The denial is automatically recorded as a `GuardDecision` record
2. A `ThreatAlert` is emitted with severity and category
3. Do NOT retry the same action — the policy will deny it again
4. Escalate to the user or choose an alternative path

## Guard Surfaces (v0.2.0)

### Control-Plane Integrity (CPI)

Blocks untrusted principals from modifying skills, tools, permissions, and
gateway configuration. Only `USER` and `SYS` principals can alter the control
plane. Cross-surface integration: CPI denial escalates MI taint for that
principal.

### Memory Integrity (MI)

Blocks untrusted writes to durable memory files (`SOUL.md`, `AGENTS.md`,
`TOOLS.md`, `USER.md`, `IDENTITY.md`, `HEARTBEAT.md`, `MEMORY.md`). All
writes route through the hooks pipeline for full audit trail.

### Conversation I/O (Noninterference)

8-category prompt injection scanner analyzes inbound messages. Output leakage
detector scans outbound responses for system prompt tokens. Injection detected
in a session taints all subsequent operations session-wide.

### File Read Guard

Blocks untrusted principals from reading sensitive files:
- Denied: `.env*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `credentials`
- Tainted: `.aws/*`, `.ssh/*`, `.gnupg/*` propagate `SECRET_RISK`

### Network Egress Monitor

Evaluates outbound requests against domain blocklist/allowlist:
- Blocked by default: `webhook.site`, `requestbin.com`, `pipedream.net`, `canarytokens.com`, `interact.sh`

### Sandbox Audit

Verifies OS execution environment at session start:
- Container detection (Docker, Kubernetes)
- Seccomp filter status, namespace isolation
- Emits CRITICAL alert if no sandboxing detected

### Cross-Surface Threat Correlation (v0.2.0)

- CPI denial → MI taint escalation for that principal
- Injection detection → session-wide taint across all surfaces
- Cross-surface denial count → RVU auto-rollback threshold

## Common Chat Queries Mapped to Commands

| User says | Run |
|-----------|-----|
| "Am I protected?" | `aegx prove --json` |
| "Any threats?" | `aegx prove --severity MEDIUM --limit 20` |
| "Show critical alerts" | `aegx prove --severity CRITICAL` |
| "What did the guard block?" | `aegx prove --category CPI` |
| "System health" | `aegx status` |
| "Take a snapshot" | `aegx snapshot create "user-requested"` |
| "List snapshots" | `aegx snapshot list` |
| "Roll back" | `aegx snapshot list` then `aegx rollback <ID>` |
| "Export evidence" | `aegx bundle export` |
| "Verify this bundle" | `aegx verify <PATH>` |
| "Guard performance" | `aegx prove --json` (check `.metrics`) |
| "Is my environment sandboxed?" | `aegx prove --json` (check sandbox in health) |

## CLI Reference

| Command | Description |
|---------|-------------|
| `aegx init` | Initialize state dirs, default policy, workspace |
| `aegx status` | Show initialization status, counts, chain validity |
| `aegx snapshot create <name> [--scope full\|cp\|mem]` | Create a named snapshot |
| `aegx snapshot list` | List existing snapshots |
| `aegx rollback <snapshot-id>` | Rollback to a previous snapshot |
| `aegx bundle export [--agent <id>] [--since <ts>]` | Export evidence bundle |
| `aegx verify <path>` | Verify bundle integrity (10-step) |
| `aegx report <path>` | Generate report from bundle |
| `aegx prove [--json] [--category <cat>] [--severity <sev>] [--since <ts>]` | Query protection status |

## Safety Rules

1. Never bypass guard denials — they exist to protect the system
2. Always create a snapshot before destructive operations
3. Always verify bundles before trusting them (`aegx verify`)
4. Guard denials should be escalated to the user, never silently retried
5. Rollback restores file content only — it cannot reverse external API calls
