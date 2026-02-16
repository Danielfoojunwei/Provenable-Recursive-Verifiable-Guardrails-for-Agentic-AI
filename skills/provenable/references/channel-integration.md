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
