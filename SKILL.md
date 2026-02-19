---
name: provenable
description: Provable security guardrails for agentic AI. Use when you need to audit agent actions, check protection status, query threat alerts, manage snapshots, verify evidence bundles, or enforce CPI/MI guard policies. Covers the proven-aer and aegx CLIs.
user-invocable: true
metadata: {"openclaw":{"emoji":"shield","os":["linux","darwin"],"requires":{"bins":["proven-aer","aegx"]},"install":[{"url":"https://github.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI.git","targetDir":"~/.aegx"}]}}
---

# Provenable.ai — Provable Security Guardrails

Two CLIs: `proven-aer` (runtime guards + snapshots + alerts) and `aegx` (evidence bundles).

## Setup (one-time)

If the binaries are not on PATH, run the setup script:

```bash
bash {baseDir}/scripts/setup.sh
```

Then initialize AER:

```bash
proven-aer init
```

## Quick Status — "How am I protected?"

```bash
proven-aer prove --json
```

Returns protection summary, threat alerts, guard metrics, and system health as JSON.

Human-readable output (no `--json`):

```bash
proven-aer prove
```

## Query Alerts

Show recent alerts:

```bash
proven-aer prove --limit 10
```

Filter by severity:

```bash
proven-aer prove --severity CRITICAL
```

Filter by threat category and time range:

```bash
proven-aer prove --category CPI --since 2026-02-01T00:00:00Z
```

## Check System Health

```bash
proven-aer status
```

Shows: initialized state, record count, audit chain integrity, snapshot count.

## Snapshots and Rollback

Create a snapshot before risky operations:

```bash
proven-aer snapshot create "pre-deploy" --scope full
```

List snapshots:

```bash
proven-aer snapshot list
```

Rollback to a snapshot:

```bash
proven-aer rollback <SNAPSHOT_ID>
```

## Evidence Bundles

Export an evidence bundle for audit:

```bash
proven-aer bundle export --agent <AGENT_ID>
```

Verify a bundle:

```bash
proven-aer verify <BUNDLE_PATH>
aegx verify <BUNDLE_DIR>
```

Summarize a bundle:

```bash
aegx summarize <BUNDLE_DIR>
```

## Guard Behavior

When AER denies an action:

1. The denial is automatically recorded as a `GuardDecision` record
2. A `ThreatAlert` is emitted with severity and category
3. Do NOT retry the same action — the policy will deny it again
4. Escalate to the user or choose an alternative path

## Host Environment Hardening (v0.1.6)

AER v0.1.6 adds four new guard surfaces:

### File Read Guard

Blocks untrusted principals from reading sensitive files:
- Denied: `.env*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `credentials`
- Tainted: `.aws/*`, `.ssh/*`, `.gnupg/*` propagate `SECRET_RISK` to downstream derivations

### Network Egress Monitor

Evaluates outbound requests against domain blocklist/allowlist:
- Blocked by default: `webhook.site`, `requestbin.com`, `pipedream.net`, `canarytokens.com`, `interact.sh`
- When allowlist is non-empty, only listed domains are permitted

### Sandbox Audit

Verifies OS execution environment at session start:
- Container detection (Docker, Kubernetes)
- Seccomp filter status
- Namespace isolation (PID, net, mnt, user)
- Emits CRITICAL alert if no sandboxing detected

### Dynamic Token Registry

Caches system prompt tokens for output guard discovery:
- SCREAMING_CASE tokens, camelCase identifiers, `${params.*}` template variables
- Three-tier fallback: caller config → registry → static watchlist

## Channel Integration (Telegram, WhatsApp, etc.)

Messages from Telegram, WhatsApp, and other external channels are assigned `Principal::Channel` (trust level 0). This means:

- **CPI**: All control-plane changes from channel messages are **DENIED** (skill installs, tool registrations, permission changes)
- **MI**: All memory writes from channel messages are **DENIED** (SOUL.md, AGENTS.md, TOOLS.md, etc.)
- **Audit**: Every channel session, message, and guard decision is recorded with full provenance

Channel metadata is captured in session records:

```bash
# Session start from Telegram — channel="telegram"
# Session start from WhatsApp — channel="whatsapp"
# All channel messages use Principal::Channel (trust level 0)
```

For channel-specific configuration and security best practices, see `{baseDir}/references/channel-integration.md`.

## Reference Files

- **Full CLI reference:** Read `{baseDir}/references/cli-reference.md`
- **Alert categories and severities:** Read `{baseDir}/references/alert-categories.md`
- **CPI/MI guard policies:** Read `{baseDir}/references/guard-policies.md`
- **Query patterns and examples:** Read `{baseDir}/references/query-patterns.md`
- **Natural language query mapping:** Read `{baseDir}/references/chat-queries.md`
- **Channel integration (Telegram, WhatsApp):** Read `{baseDir}/references/channel-integration.md`

## Common Chat Queries Mapped to Commands

| User says | Run |
|-----------|-----|
| "Am I protected?" | `proven-aer prove --json` |
| "Any threats?" | `proven-aer prove --severity MEDIUM --limit 20` |
| "Show critical alerts" | `proven-aer prove --severity CRITICAL` |
| "What did the guard block?" | `proven-aer prove --category CPI` |
| "System health" | `proven-aer status` |
| "Take a snapshot" | `proven-aer snapshot create "user-requested"` |
| "List snapshots" | `proven-aer snapshot list` |
| "Roll back" | `proven-aer snapshot list` then `proven-aer rollback <ID>` |
| "Export evidence" | `proven-aer bundle export` |
| "Verify this bundle" | `proven-aer verify <PATH>` |
| "Guard performance" | `proven-aer prove --json` (check `.metrics`) |
| "Is my environment sandboxed?" | `proven-aer prove --json` (check sandbox compliance in health) |
| "Any file read blocks?" | `proven-aer prove --category MI --json` |
| "Any exfil attempts?" | `proven-aer prove --category INJECTION --json` |

## Safety Rules

1. Never bypass guard denials — they exist to protect the system
2. Always create a snapshot before destructive operations
3. Always verify bundles before trusting them (`aegx verify`)
4. Guard denials should be escalated to the user, never silently retried
5. Rollback restores file content only — it cannot reverse external API calls
