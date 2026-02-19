## Alert Categories

# Alert Categories and Severities

## Threat Categories

### CpiViolation

Control-Plane Integrity violation attempt. An untrusted principal tried to modify a CPI-protected surface (skills registry, tool registry, permissions, gateway auth, server config).

**Typical trigger:** A skill or web input tries to install a new skill or change permissions.

**Severity:** HIGH or CRITICAL (CRITICAL if repeated attempts detected).

### MiViolation

Memory Integrity violation attempt. An untrusted or tainted source tried to write to a protected memory file.

**Protected files:** SOUL.md, AGENTS.md, TOOLS.md, USER.md, IDENTITY.md, HEARTBEAT.md, MEMORY.md

**Typical trigger:** A tool output or web-derived content tries to overwrite SOUL.md.

**Severity:** HIGH or CRITICAL.

### TaintBlock

An action was blocked because the data carried taint flags indicating untrusted provenance.

**Typical trigger:** Cross-session data or tool output tries to modify control plane or memory.

**Severity:** MEDIUM or HIGH.

### ProxyMisconfig

Proxy misconfiguration detected. The gateway's `trustedProxies` configuration allows overly permissive origins (`0.0.0.0/0`, `*`, `::/0`).

**Typical trigger:** Gateway starts with wildcard proxy trust.

**Severity:** HIGH.

### RateLimitExceeded

Guard denial rate limit exceeded. More than 100 denials in 60 seconds, indicating a possible log flooding attack.

**Typical trigger:** Automated script hammering a denied endpoint.

**Severity:** CRITICAL.

### InjectionSuspect

Suspected injection attack. Data flagged with the INJECTION_SUSPECT taint bit.

**Typical trigger:** Input containing prompt injection patterns or command injection attempts.

**Severity:** CRITICAL.

### SensitiveFileRead (v0.1.6)

Sensitive file access blocked or tainted. An untrusted principal attempted to read a file matching the denied basename pattern, or a read from a sensitive directory propagated `SECRET_RISK` taint.

**Protected patterns:** `.env*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `credentials`, `*.secret`, `.netrc`, `.pgpass`

**Tainted directories:** `.aws/*`, `.ssh/*`, `.gnupg/*`, `.docker/config.json`

**Typical trigger:** A skill tries to read `.env` or `~/.ssh/id_rsa`.

**Severity:** CRITICAL (denied read) or HIGH (tainted read).

### NetworkExfiltration (v0.1.6)

Outbound network request blocked. A request targeted a domain on the blocklist (known data exfiltration services) or violated the allowlist policy.

**Default blocked domains:** `webhook.site`, `requestbin.com`, `pipedream.net`, `canarytokens.com`, `interact.sh`, `burpcollaborator.net`

**Typical trigger:** A skill attempts to POST data to webhook.site.

**Severity:** CRITICAL.

### SandboxDeficiency (v0.1.6)

Insufficient OS-level sandboxing detected at session start. The execution environment lacks container isolation, seccomp filtering, or namespace isolation.

**Compliance levels:** Full (no alert), Partial (HIGH alert), None (CRITICAL alert).

**Typical trigger:** Session starts on a bare-metal host without Docker or seccomp.

**Severity:** CRITICAL (no sandbox) or HIGH (partial sandbox).

---

## Alert Severities

| Severity | Meaning | Action |
|----------|---------|--------|
| INFO | Informational event, no threat | Log only |
| MEDIUM | Suspicious activity detected | Monitor, investigate if repeated |
| HIGH | Active threat blocked by guard | Review alert details, check provenance |
| CRITICAL | Active attack pattern detected | Immediate escalation to user |

---

## Taint Flags

Bitflags propagated conservatively through the provenance chain. Any tainted parent taints the output.

| Flag | Bit | Meaning |
|------|-----|---------|
| UNTRUSTED | 0x01 | Data from untrusted source |
| INJECTION_SUSPECT | 0x02 | Suspected injection attack |
| PROXY_DERIVED | 0x04 | Derived from proxy headers |
| SECRET_RISK | 0x08 | Contains potential secrets |
| CROSS_SESSION | 0x10 | From a different session |
| TOOL_OUTPUT | 0x20 | Output from tool execution |
| SKILL_OUTPUT | 0x40 | Output from skill execution |
| WEB_DERIVED | 0x80 | From web-sourced input |

---

## Principal Trust Levels

| Principal | Trust Level | Can Modify CP | Can Write Memory |
|-----------|-------------|---------------|------------------|
| Sys | 5 | Yes | Yes |
| User | 4 | Yes | Yes |
| ToolAuth | 3 | No | Yes (if untainted) |
| ToolUnauth | 2 | No | Yes (if untainted) |
| Web | 1 | No | No |
| Skill | 1 | No | No |
| Channel | 0 | No | No |
| External | 0 | No | No |

---

## ThreatAlert JSON Structure

```json
{
  "alert_id": "sha256-derived-id",
  "timestamp": "2026-02-16T12:00:00Z",
  "severity": "CRITICAL",
  "category": "CpiViolation",
  "summary": "Skill principal attempted to modify skills.registry",
  "principal": "Skill",
  "taint": 65,
  "surface": "ControlPlane",
  "rule_id": "cpi-deny-untrusted",
  "record_id": "rec-abc123",
  "target": "skills.registry",
  "blocked": true
}
```

---

## Channel Integration

# Channel Integration Guide — Telegram & WhatsApp

How Provenable.ai guardrails integrate with OpenClaw's Telegram and WhatsApp channels.

## Architecture Overview

OpenClaw routes inbound messages from Telegram/WhatsApp through a **Channel Adapter** into the agent session. Provenable.ai's AER hooks intercept every action at the guard chokepoints:

```
Telegram/WhatsApp Message
         │
         ▼
  OpenClaw Channel Adapter (normalizes message)
         │
         ▼
  on_session_start(channel="telegram"|"whatsapp", ip=...)
         │
         ▼
  on_session_message(principal=Channel, taint=UNTRUSTED)
         │
         ├──► Tool calls ──► on_tool_call() / on_tool_result()
         │
         ├──► CPI change attempt ──► on_control_plane_change() ──► DENIED
         │
         └──► Memory write attempt ──► on_file_write() ──► DENIED
```

## Principal Assignment

All messages from Telegram and WhatsApp are assigned **`Principal::Channel`** (trust level 0, the lowest). This is determined by **transport**, not by content claims — the agent cannot override this by payload manipulation.

| Transport | Principal | Trust Level | Can Modify Control Plane | Can Write Memory |
|-----------|-----------|-------------|--------------------------|------------------|
| Telegram DM | Channel | 0 | NO | NO |
| Telegram Group | Channel | 0 | NO | NO |
| WhatsApp DM | Channel | 0 | NO | NO |
| WhatsApp Group | Channel | 0 | NO | NO |

## Taint Flags

Messages from external channels should be tagged conservatively:

| Scenario | Taint Flags | Rationale |
|----------|-------------|-----------|
| Normal message | `UNTRUSTED` | Untrusted origin |
| Forwarded message | `UNTRUSTED \| PROXY_DERIVED` | Forwarded through gateway |
| Message with URL | `UNTRUSTED \| WEB_DERIVED` | Contains web content |
| Suspicious content | `UNTRUSTED \| INJECTION_SUSPECT` | Potential prompt injection |

## OpenClaw Channel Config

### Telegram (`~/.openclaw/openclaw.json`)

```json
{
  "channels": {
    "telegram": {
      "botToken": "123456:ABCDEF...",
      "groups": {
        "*": { "requireMention": true }
      },
      "allowFrom": ["user_id_1", "user_id_2"]
    }
  }
}
```

### WhatsApp (`~/.openclaw/openclaw.json`)

```json
{
  "channels": {
    "whatsapp": {
      "allowFrom": ["+15551234567"],
      "groups": {
        "*": { "requireMention": true }
      }
    }
  }
}
```

WhatsApp credentials are stored in `~/.openclaw/credentials/whatsapp/<accountId>/creds.json` (QR-paired, not config-based).

## Guard Behavior for Channel Messages

### What Gets Blocked

1. **CPI (Control-Plane Integrity)** — Any attempt to install skills, register tools, change permissions, or modify gateway auth from a Telegram/WhatsApp message is **DENIED** by rule `cpi-deny-untrusted`.

2. **MI (Memory Integrity)** — Any attempt to write to workspace memory files (SOUL.md, AGENTS.md, TOOLS.md, USER.md, IDENTITY.md, HEARTBEAT.md, MEMORY.md) from a Telegram/WhatsApp message is **DENIED** by rules `mi-deny-untrusted-principal` and `mi-deny-tainted`.

### What Gets Allowed

- Reading files (no guard surface)
- Tool calls that don't modify control plane or memory
- Generating responses
- Querying protection status (`proven-aer prove`)

### Every Guard Decision Is Recorded

Whether allowed or denied, every guard evaluation produces:
1. A `GuardDecision` record with the verdict, rule ID, principal, and taint flags
2. An `AuditEntry` in the tamper-evident hash chain
3. A `ThreatAlert` (on denial only) with severity and category

## Credential Security

- **Never store bot tokens in SKILL.md** or any file tracked by git
- Use environment variables: `TELEGRAM_BOT_TOKEN`, `SLACK_BOT_TOKEN`
- OpenClaw config at `~/.openclaw/openclaw.json` should be `chmod 600`
- WhatsApp credentials are auto-managed in `~/.openclaw/credentials/`
- Run `chmod 700 ~/.openclaw/credentials` to restrict access
- Bind the OpenClaw gateway to `127.0.0.1` (not `0.0.0.0`)

## Session Isolation

Each channel gets its own session key, preventing cross-contamination:

| Channel | Session Key Pattern |
|---------|-------------------|
| Telegram DM | `telegram:{user_id}` |
| Telegram Group | `telegram:group:{group_id}` |
| Telegram Forum Topic | `telegram:group:{group_id}:topic:{thread_id}` |
| WhatsApp DM | `whatsapp:{phone_jid}` |
| WhatsApp Group | `whatsapp:group:{group_jid}` |

Each session has its own:
- Audit chain entries
- Guard evaluation history
- Snapshot scope
- Evidence bundle (when filtered by `--agent`)

## Monitoring Channel Threats

### Query channel-specific alerts

```bash
# All threats from the last 24 hours
proven-aer prove --since "2026-02-15T00:00:00Z" --json

# Critical alerts only
proven-aer prove --severity CRITICAL --json

# CPI violations (most common from channel messages)
proven-aer prove --category CPI --json

# Memory integrity violations
proven-aer prove --category MI --json
```

### What to watch for

| Alert Category | Severity | What It Means |
|----------------|----------|---------------|
| CpiViolation | HIGH/CRITICAL | Channel message tried to install skill or change config |
| MiViolation | HIGH/CRITICAL | Channel message tried to modify SOUL.md, AGENTS.md, etc. |
| InjectionSuspect | CRITICAL | Prompt injection detected from channel message |
| TaintBlock | MEDIUM/HIGH | Tainted data from channel tried to reach guarded surface |
| RateLimitExceeded | CRITICAL | >100 denials in 60s — possible flooding attack from channel |

## Troubleshooting

### "AER: not initialized"

Run `proven-aer init` before using any guard features.

### Telegram messages not reaching the agent

1. Check `proven-aer status` — AER must be initialized
2. Check OpenClaw gateway is running and Telegram bot token is valid
3. Verify `allowFrom` in `openclaw.json` includes the sender's user ID

### WhatsApp pairing issues

1. WhatsApp uses QR-code pairing, not token-based auth
2. Credentials stored in `~/.openclaw/credentials/whatsapp/`
3. If pairing expires, re-pair via `openclaw whatsapp pair`

### Guard denying legitimate operations

If a channel message triggers a guard denial that should have been allowed:
1. Check the alert: `proven-aer prove --severity MEDIUM --limit 5`
2. The guard is working correctly — `Principal::Channel` cannot modify control plane or memory by design
3. If the user wants to take that action, they must do it from a `USER` or `SYS` principal (CLI, authenticated web session)
4. **Never** modify the policy to allow `Channel` principals on CPI or MI surfaces — this would violate the security invariant

---

## Chat Queries

# Natural Language Query Mapping

This file maps natural language questions to the exact commands and JSON paths the agent should use.

## Protection Status

| User says | Command | Response focus |
|-----------|---------|----------------|
| "Am I protected?" | `proven-aer prove --json` | `.protection.total_threats_blocked`, `.health.audit_chain_valid` |
| "How secure is my system?" | `proven-aer prove --json` | `.protection.protection_rate`, `.health` |
| "What has Provenable blocked?" | `proven-aer prove --json` | `.protection` summary |
| "Show protection report" | `proven-aer prove` | Full human-readable report |
| "Protection summary" | `proven-aer prove` | Protection section |

## Threat Alerts

| User says | Command | Response focus |
|-----------|---------|----------------|
| "Any threats?" | `proven-aer prove --severity MEDIUM --limit 20 --json` | `.alerts` array |
| "Show critical alerts" | `proven-aer prove --severity CRITICAL --json` | `.alerts` filtered to CRITICAL |
| "Recent attacks" | `proven-aer prove --limit 10 --json` | `.alerts` last 10 |
| "CPI violations" | `proven-aer prove --category CPI --json` | `.alerts` + `.protection.cpi_violations_blocked` |
| "Memory integrity issues" | `proven-aer prove --category MI --json` | `.alerts` + `.protection.mi_violations_blocked` |
| "Injection attempts" | `proven-aer prove --category INJECTION --json` | `.alerts` with InjectionSuspect category |
| "Proxy issues" | `proven-aer prove --category PROXY --json` | `.alerts` + `.protection.proxy_misconfigs_detected` |

## System Health

| User says | Command | Response focus |
|-----------|---------|----------------|
| "System health" | `proven-aer status` | Full status output |
| "Is AER running?" | `proven-aer status` | Initialized state |
| "Is the audit chain valid?" | `proven-aer prove --json` | `.health.audit_chain_valid` |
| "Any warnings?" | `proven-aer prove --json` | `.health.warnings` |
| "How many records?" | `proven-aer prove --json` | `.health.record_count` |

## Guard Performance

| User says | Command | Response focus |
|-----------|---------|----------------|
| "Guard performance" | `proven-aer prove --json` | `.metrics` section |
| "How fast are the guards?" | `proven-aer prove --json` | `.metrics.avg_eval_us`, `.metrics.p95_eval_us` |
| "Evaluations per second" | `proven-aer prove --json` | `.metrics.evals_per_sec` |
| "Guard latency" | `proven-aer prove --json` | `.metrics.p50_eval_us`, `.metrics.p95_eval_us`, `.metrics.p99_eval_us` |
| "How many denials?" | `proven-aer prove --json` | `.metrics.total_denials` |

## Snapshots and Rollback

| User says | Command | Response focus |
|-----------|---------|----------------|
| "Take a snapshot" | `proven-aer snapshot create "user-requested" --scope full` | Snapshot ID and details |
| "List snapshots" | `proven-aer snapshot list` | All snapshots |
| "Roll back" | `proven-aer snapshot list` (show options, let user pick) | Then `proven-aer rollback <ID>` |
| "Undo last change" | `proven-aer snapshot list` (get latest) | Then `proven-aer rollback <ID>` |
| "Restore to before deploy" | `proven-aer snapshot list` (find by name) | Then `proven-aer rollback <ID>` |

## Evidence Bundles

| User says | Command | Response focus |
|-----------|---------|----------------|
| "Export evidence" | `proven-aer bundle export` | Bundle path |
| "Verify bundle" | `proven-aer verify <PATH>` | Verification result |
| "Summarize bundle" | `aegx summarize <DIR>` | Record counts and verification |
| "Generate audit report" | `proven-aer report <PATH>` | Markdown report |

## Host Environment Queries (v0.1.6)

| User says | Command | Response focus |
|-----------|---------|----------------|
| "Is my environment sandboxed?" | `proven-aer prove --json` | `.health` sandbox compliance |
| "Any file read blocks?" | `proven-aer prove --category MI --json` | File read guard denials in `.alerts` |
| "Any exfil attempts?" | `proven-aer prove --category INJECTION --json` | Network egress denials + DataExfiltration alerts |
| "Was anything blocked from reading secrets?" | `proven-aer prove --json` | SensitiveFileRead alerts in `.alerts` |
| "Network security" | `proven-aer prove --json` | NetworkExfiltration alerts + domain blocks |
| "Sandbox status" | `proven-aer prove --json` | SandboxDeficiency alerts (if any) |

## Response Formatting Guidelines

When answering protection queries:

1. Lead with the headline number (e.g., "42 threats blocked, audit chain VALID")
2. Highlight any CRITICAL or HIGH alerts
3. Show the protection rate as a percentage
4. Mention system health status
5. If there are warnings, surface them prominently
6. For performance queries, show p50/p95/p99 latencies
7. Always include the timestamp of the data
8. If AER is not initialized, tell the user to run `proven-aer init`

When answering snapshot/rollback queries:

1. List available snapshots with their names and dates
2. Confirm before executing a rollback
3. Remind that rollback only restores file content, not external actions
4. Show verification result after rollback

---

## CLI Reference

# CLI Reference

## aegx — AEGX Evidence Bundle Tool

### aegx init

Create a new AEGX bundle directory.

```bash
aegx init <BUNDLE_DIR> [--zip-out <PATH>]
```

Creates: `manifest.json`, `records.jsonl`, `audit-log.jsonl`, `blobs/`

### aegx add-record

Append a typed record with an audit chain entry.

```bash
aegx add-record <BUNDLE> \
  --type <TYPE> \
  --principal <PRINCIPAL> \
  --meta '<JSON>' \
  [--parents <ID1,ID2,...>] \
  --inline '<JSON>'
```

Or with a blob reference:

```bash
aegx add-record <BUNDLE> \
  --type <TYPE> \
  --principal <PRINCIPAL> \
  --meta '<JSON>' \
  [--parents <ID1,ID2,...>] \
  --blob <SHA256> --mime <MIME_TYPE> --size <BYTES>
```

Prints the record ID to stdout.

**Record types:** SessionStart, SessionMessage, ToolCall, ToolResult, FileRead, FileWrite, FileDelete, ControlPlaneChangeRequest, MemoryCommitRequest, GuardDecision, NetworkRequest, Snapshot, Rollback

**Principals:** SYS, USER, WEB, TOOL, SKILL, CHANNEL, EXTERNAL

### aegx add-blob

Copy a file into the bundle's blob store, named by its SHA-256 hash.

```bash
aegx add-blob <BUNDLE> <FILE_PATH> --mime <MIME_TYPE>
```

Prints the SHA-256 hash to stdout.

### aegx verify

Run the full 10-step verification pipeline on a bundle.

```bash
aegx verify <BUNDLE_DIR>
```

Exit codes:
- 0: `Verification: PASS`
- 2: Hash mismatch or broken chain (tampering detected)
- 3: Schema validation failure
- 4: I/O error

Checks performed:
1. Manifest JSON schema validation
2. Every record schema validation
3. Every audit entry schema validation
4. Record ID recomputation and comparison
5. Parent reference validation (all parents exist)
6. Blob file existence check
7. Blob SHA-256 recomputation and filename match
8. Audit chain sequential idx and prev linking
9. Audit chain entry hash recomputation
10. Record count and blob count match manifest

### aegx export

Package a bundle directory into a zip file.

```bash
aegx export <BUNDLE_DIR> <OUT_ZIP>
```

### aegx import

Extract a zip into a bundle directory.

```bash
aegx import <BUNDLE_ZIP> <OUT_DIR>
```

### aegx summarize

Print record counts by type and principal, plus verification status.

```bash
aegx summarize <BUNDLE_DIR>
```

Output format:

```
Records: 12
By type:
  FileWrite: 3
  SessionMessage: 4
  SessionStart: 1
  ToolCall: 2
  ToolResult: 2
By principal:
  SYS: 1
  TOOL: 7
  USER: 4
Verification: PASS
```

---

## proven-aer — Agent Evidence & Recovery Runtime

### proven-aer init

Initialize the AER subsystem. Creates the `.aer/` directory structure.

```bash
proven-aer init
```

Creates: `.aer/policy/`, `.aer/records/`, `.aer/records/blobs/`, `.aer/audit/`, `.aer/snapshots/`, `.aer/bundles/`, `.aer/reports/`, `.aer/alerts/`

### proven-aer status

Show AER system state.

```bash
proven-aer status
```

Shows: initialized status, state directory, record count, audit entries, snapshot count, chain integrity.

### proven-aer snapshot create

Capture current state as a snapshot.

```bash
proven-aer snapshot create <NAME> --scope <SCOPE>
```

Scopes: `full`, `control-plane`, `memory`

Output: snapshot ID, name, scope, file count, creation timestamp.

### proven-aer snapshot list

List all snapshots.

```bash
proven-aer snapshot list
```

### proven-aer rollback

Restore files to a specific snapshot.

```bash
proven-aer rollback <SNAPSHOT_ID>
```

Output: files restored count, verification PASS/FAIL.

Limitations: Rollback restores file content only. It cannot reverse external API calls, undo sent messages, or restore deleted database rows.

### proven-aer bundle export

Export an AEGX evidence bundle.

```bash
proven-aer bundle export [--agent <AGENT_ID>] [--since <ISO8601>]
```

### proven-aer verify

Verify an exported AER bundle.

```bash
proven-aer verify <BUNDLE_PATH>
```

### proven-aer report

Generate a markdown report from an evidence bundle.

```bash
proven-aer report <BUNDLE_PATH>
```

### proven-aer prove

Query protection status and alerts (the `/prove` interface).

```bash
proven-aer prove \
  [--since <ISO8601>] \
  [--until <ISO8601>] \
  [--category <CATEGORY>] \
  [--severity <SEVERITY>] \
  [--limit <N>] \
  [--json]
```

Categories: CPI, MI, TAINT, PROXY, RATE_LIMIT, INJECTION

Severities: INFO, MEDIUM, HIGH, CRITICAL

Without `--json`, outputs a formatted protection report. With `--json`, outputs machine-readable JSON.

---

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `PRV_STATE_DIR` | Override state directory (highest priority) | — |
| `PRV_HOME` | Provenable.ai home directory | — |
| `HOME` | Fallback home directory | Required |

Default state directory: `$HOME/.proven`

Default AER root: `$HOME/.proven/.aer`

---

## Guard Policies

# Guard Policies — CPI and MI Rules

## Default Policy

The default policy ships with AER and is stored at `~/.proven/.aer/policy/default.yaml`. It enforces the CPI and MI theorems from the Provenable.ai security model.

## CPI Rules (Control-Plane Integrity)

### Rule: cpi-deny-untrusted

**Surface:** ControlPlane
**Action:** Deny
**Condition:** Principal is Web, Skill, Channel, or External
**Description:** Untrusted principals cannot modify control-plane state.

CPI-protected surfaces:
- Skills registry (install, enable, disable, update, remove)
- Tool registry (register, remove, configure)
- Permissions configuration
- Gateway authentication settings
- Node/server settings

### Rule: cpi-deny-tainted

**Surface:** ControlPlane
**Action:** Deny
**Condition:** Any taint flag is set
**Description:** Tainted data cannot influence control-plane state.

### Rule: cpi-require-approval

**Surface:** ControlPlane
**Action:** Deny
**Condition:** User or Sys principal without explicit approval
**Description:** Even trusted principals need explicit approval for control-plane changes.

### Rule: cpi-allow-approved-user

**Surface:** ControlPlane
**Action:** Allow
**Condition:** Principal is User or Sys, AND approved=true, AND no taint
**Description:** Approved, untainted changes from trusted principals are allowed.

## MI Rules (Memory Integrity)

### Rule: mi-deny-untrusted

**Surface:** DurableMemory
**Action:** Deny
**Condition:** Principal is Web, Skill, Channel, or External
**Description:** Untrusted principals cannot write to persistent memory files.

### Rule: mi-deny-tainted

**Surface:** DurableMemory
**Action:** Deny
**Condition:** Any taint flag is set
**Description:** Tainted data cannot overwrite memory files.

### Rule: mi-require-approval

**Surface:** DurableMemory
**Action:** Deny
**Condition:** User or Sys principal without explicit approval
**Description:** Memory writes require explicit approval even from trusted principals.

### Rule: mi-allow-approved-user

**Surface:** DurableMemory
**Action:** Allow
**Condition:** Principal is User or Sys, AND approved=true, AND no taint
**Description:** Approved, untainted writes from trusted principals are allowed.

## Custom Policies

You can create custom policy packs in YAML format. Each policy must pass structural and safety validation:

- At least one CPI deny rule for untrusted principals must exist
- At least one MI deny rule for untrusted principals must exist
- Policy files are integrity-checked with SHA-256 on load

### Policy YAML Format

```yaml
version: "1.0"
name: custom-policy
rules:
  - id: custom-rule-1
    surface: ControlPlane
    action: Deny
    condition:
      principals: [Web, Skill, Channel, External]
    description: "Block untrusted principals from control plane"

  - id: custom-rule-2
    surface: DurableMemory
    action: Deny
    condition:
      taint_any: 255
    description: "Block any tainted writes to memory"

  - id: custom-rule-3
    surface: ControlPlane
    action: Allow
    condition:
      principals: [User, Sys]
      require_approval: true
    description: "Allow approved changes from trusted principals"
```

Place custom policies at `~/.proven/.aer/policy/default.yaml`.

## File Read Guard Rules (v0.1.6)

### Rule: fs-deny-untrusted-sensitive

**Surface:** FileSystem
**Action:** Deny
**Condition:** Principal is Web, Skill, Channel, or External AND path matches denied basename pattern
**Description:** Block untrusted reads of sensitive files (.env, *.pem, *.key, id_rsa*, credentials).

### Rule: fs-taint-sensitive-dir

**Surface:** FileSystem
**Action:** Allow + SECRET_RISK taint
**Condition:** Path matches tainted directory pattern (.aws/*, .ssh/*, .gnupg/*)
**Description:** Allow read but propagate SECRET_RISK (0x08) taint to all downstream derivations.

### Rule: fs-allow-trusted

**Surface:** FileSystem
**Action:** Allow
**Condition:** Principal is User or Sys
**Description:** Trusted principals can read any file.

## Network Egress Rules (v0.1.6)

### Rule: net-deny-blocked-domain

**Surface:** NetworkIO
**Action:** Deny
**Condition:** Target domain matches blocklist (webhook.site, requestbin.com, pipedream.net, canarytokens.com, interact.sh, burpcollaborator.net)
**Description:** Block outbound requests to known exfiltration services.

### Rule: net-deny-unlisted

**Surface:** NetworkIO
**Action:** Deny
**Condition:** Allowlist is non-empty AND target domain is not on allowlist
**Description:** In strict mode, deny all requests to domains not on the allowlist.

### Rule: net-flag-large-payload

**Surface:** NetworkIO
**Action:** Allow + taint
**Condition:** Outbound payload exceeds configured size limit
**Description:** Flag large outbound payloads for review.

### Rule: net-allow-trusted

**Surface:** NetworkIO
**Action:** Allow
**Condition:** Principal is User or Sys
**Description:** Trusted principals can make any outbound request.

## Guard Evaluation Order

1. Rules are evaluated in order (first match wins)
2. If no rule matches, the default verdict is **Deny** (deny-by-default architecture)
3. Every evaluation produces a `GuardDecision` record in the audit chain
4. Denied evaluations emit a `ThreatAlert` with appropriate category and severity
5. Denial rate limiting prevents log flooding (100 denials per 60 seconds)

## Guard Metrics

Every guard evaluation is timed and recorded:

```json
{
  "total_evaluations": 1500,
  "cpi_evaluations": 900,
  "mi_evaluations": 600,
  "total_denials": 42,
  "total_allows": 1458,
  "avg_eval_us": 15,
  "p50_eval_us": 12,
  "p95_eval_us": 35,
  "p99_eval_us": 80,
  "evals_per_sec": 250.0
}
```

Access via: `proven-aer prove --json` (see `.metrics` in response)

---

## Query Patterns

# Query Patterns and Examples

## The /prove Query Interface

`proven-aer prove` is the primary query interface. It returns a structured response with protection summary, alerts, metrics, and health.

## JSON Response Structure

```json
{
  "version": "0.1.0",
  "generated_at": "2026-02-16T12:00:00Z",
  "protection": {
    "total_threats_blocked": 42,
    "cpi_violations_blocked": 15,
    "mi_violations_blocked": 8,
    "taint_blocks": 12,
    "proxy_misconfigs_detected": 2,
    "critical_alerts": 3,
    "high_alerts": 10,
    "medium_alerts": 15,
    "by_category": {
      "CpiViolation": 15,
      "MiViolation": 8,
      "TaintBlock": 12,
      "ProxyMisconfig": 2,
      "InjectionSuspect": 5
    },
    "by_principal": {
      "Web": 20,
      "Skill": 12,
      "External": 10
    },
    "total_evaluations": 1500,
    "protection_rate": 0.028
  },
  "alerts": [ ... ],
  "metrics": {
    "total_evaluations": 1500,
    "cpi_evaluations": 900,
    "mi_evaluations": 600,
    "total_denials": 42,
    "total_allows": 1458,
    "avg_eval_us": 15,
    "p50_eval_us": 12,
    "p95_eval_us": 35,
    "p99_eval_us": 80,
    "max_eval_us": 250,
    "min_eval_us": 5,
    "evals_per_sec": 250.0,
    "uptime_secs": 86400
  },
  "health": {
    "aer_initialized": true,
    "audit_chain_valid": true,
    "record_count": 1500,
    "audit_entries": 1500,
    "alert_count": 42,
    "state_dir": "/home/user/.proven",
    "warnings": []
  }
}
```

## Common Query Patterns

### Overall protection status

```bash
proven-aer prove --json
```

Parse `.protection.total_threats_blocked` for headline number.

### Critical alerts only

```bash
proven-aer prove --severity CRITICAL --json
```

### CPI violations in the last 24 hours

```bash
proven-aer prove --category CPI --since "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" --json
```

On macOS:

```bash
proven-aer prove --category CPI --since "$(date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)" --json
```

### Memory integrity violations

```bash
proven-aer prove --category MI --json
```

### Last 5 alerts of any kind

```bash
proven-aer prove --limit 5 --json
```

### Guard performance (latency percentiles)

```bash
proven-aer prove --json | jq '.metrics'
```

### System health only

```bash
proven-aer prove --json | jq '.health'
```

### Protection rate (percentage of evaluations that resulted in a block)

```bash
proven-aer prove --json | jq '.protection.protection_rate * 100'
```

### Count of alerts by category

```bash
proven-aer prove --json | jq '.protection.by_category'
```

### Check if audit chain is valid

```bash
proven-aer prove --json | jq '.health.audit_chain_valid'
```

### Check for warnings

```bash
proven-aer prove --json | jq '.health.warnings'
```

## Evidence Bundle Workflow

### Export, verify, and summarize

```bash
# Export
proven-aer bundle export --agent my-agent
BUNDLE=$(ls -t ~/.proven/.aer/bundles/*.aegx.zip | head -1)

# Verify
proven-aer verify "$BUNDLE"

# Import and summarize
TMP=$(mktemp -d)
aegx import "$BUNDLE" "$TMP/bundle"
aegx summarize "$TMP/bundle"
rm -rf "$TMP"
```

### Snapshot workflow

```bash
# Create before risky operation
proven-aer snapshot create "pre-deploy" --scope full

# List all snapshots
proven-aer snapshot list

# Get the latest snapshot ID
SNAP=$(proven-aer snapshot list | tail -1 | awk '{print $1}')

# If something goes wrong, rollback
proven-aer rollback "$SNAP"
```

## Host Environment Queries (v0.1.6)

### File read guard denials

```bash
proven-aer prove --category MI --json
```

Look for alerts with `SensitiveFileRead` category in the `.alerts` array.

### Network exfiltration blocks

```bash
proven-aer prove --category INJECTION --json
```

Look for alerts with `NetworkExfiltration` category.

### Sandbox compliance

```bash
proven-aer prove --json
```

Look for alerts with `SandboxDeficiency` category. If no such alert exists, the
environment is either fully compliant or AER has not been initialized.

### All v0.1.6 guard surface activity

```bash
proven-aer prove --json | jq '.alerts[] | select(.category == "SensitiveFileRead" or .category == "NetworkExfiltration" or .category == "SandboxDeficiency")'
```

## Interpreting Exit Codes

### aegx verify

| Code | Meaning |
|------|---------|
| 0 | PASS — bundle integrity verified |
| 2 | TAMPERED — hash mismatch or broken audit chain |
| 3 | MALFORMED — schema validation failed |
| 4 | IOERROR — cannot read bundle |

### proven-aer (all commands)

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (arguments, I/O, verification failure) |

## Inline vs Blob Decision Rule

| Condition | Use |
|-----------|-----|
| Payload JSON ≤ 4096 bytes | `--inline` |
| Payload > 4096 bytes or binary | `aegx add-blob` first, then `--blob --mime --size` |
