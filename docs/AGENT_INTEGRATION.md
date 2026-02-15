# Agent Integration Guide

This guide is for AI agents, agent frameworks, and developers who want to integrate AEGX evidence bundles and AER guardrails into an automated pipeline.

Every section is written as a machine-readable procedure with exact commands, expected outputs, and decision points.

---

## Table of Contents

1. [Overview: What Your Agent Gets](#1-overview-what-your-agent-gets)
2. [Install AEGX Programmatically](#2-install-aegx-programmatically)
3. [Lifecycle: Record Every Action](#3-lifecycle-record-every-action)
4. [Pattern A: Standalone Evidence Bundle](#4-pattern-a-standalone-evidence-bundle)
5. [Pattern B: AER Runtime with Guards](#5-pattern-b-aer-runtime-with-guards)
6. [Verification Before Trust](#6-verification-before-trust)
7. [Rollback on Failure](#7-rollback-on-failure)
8. [Machine-Readable Summary](#8-machine-readable-summary)
9. [Integration Checklist](#9-integration-checklist)

---

## 1. Overview: What Your Agent Gets

| Capability | Tool | What It Proves |
|------------|------|----------------|
| Tamper-evident action log | `aegx` CLI | Every action has a content-derived hash; any change breaks the chain |
| Control-plane protection | `proven-aer` | Untrusted inputs cannot change skills, tools, permissions, or config |
| Memory protection | `proven-aer` | Tainted writes to persistent files are blocked |
| Rollback | `proven-aer` | Exact-hash restoration to any previous snapshot |
| Portable evidence | `.aegx.zip` | Self-contained bundle anyone can verify offline |

---

## 2. Install AEGX Programmatically

Run this script at the start of your agent's environment setup. It is idempotent.

```bash
#!/bin/bash
set -euo pipefail

REPO_URL="https://github.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI.git"
INSTALL_DIR="${AEGX_INSTALL_DIR:-$HOME/.aegx}"

# Step 1: Clone or update
if [ -d "$INSTALL_DIR" ]; then
  git -C "$INSTALL_DIR" pull --ff-only
else
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

# Step 2: Build both CLIs
cargo build --release --locked --manifest-path "$INSTALL_DIR/Cargo.toml"
cargo build --release --locked --manifest-path "$INSTALL_DIR/packages/aer/Cargo.toml"

# Step 3: Add to PATH
export PATH="$INSTALL_DIR/target/release:$PATH"

# Step 4: Verify
aegx --help > /dev/null 2>&1 || { echo "FAIL: aegx not on PATH"; exit 1; }
proven-aer --help > /dev/null 2>&1 || { echo "FAIL: proven-aer not on PATH"; exit 1; }

echo "AEGX installed. aegx and proven-aer are on PATH."
```

### Decision: Do You Need AER?

| Situation | Use |
|-----------|-----|
| You only need a tamper-evident log of actions | `aegx` CLI only (Pattern A) |
| You need runtime guards + snapshots + rollback | `aegx` + `proven-aer` (Pattern B) |

---

## 3. Lifecycle: Record Every Action

The core pattern is: **every action your agent takes becomes a record in the bundle**.

### Record Types — When to Use Each

| Agent Action | Record Type | Principal |
|-------------|-------------|-----------|
| Start a session | `SessionStart` | `SYS` |
| Send or receive a message | `SessionMessage` | `USER` or `SYS` |
| Call an external tool | `ToolCall` | `TOOL` |
| Receive a tool result | `ToolResult` | `TOOL` |
| Read a file | `FileRead` | `TOOL` |
| Write a file | `FileWrite` | `TOOL` |
| Delete a file | `FileDelete` | `TOOL` |
| Attempt to change config | `ControlPlaneChangeRequest` | varies |
| Attempt to write memory | `MemoryCommitRequest` | varies |
| Guard allows or denies | `GuardDecision` | `SYS` |
| Take a snapshot | `Snapshot` | `SYS` |
| Roll back | `Rollback` | `SYS` |

### Chaining: Always Set Parents

Every record (except the first `SessionStart`) should reference its causal parent(s) via `--parents`. This creates a DAG that lets auditors trace the exact causal chain from any action back to the session root.

```
SessionStart (root)
  └── SessionMessage (user request)
       ├── ToolCall (agent calls tool)
       │    └── ToolResult (tool returns)
       └── FileWrite (agent writes file)
```

---

## 4. Pattern A: Standalone Evidence Bundle

Use this when you want a portable, verifiable record of what your agent did, without runtime guards.

### Step-by-step

```bash
# 1. Initialize
BUNDLE="session_$(date +%s).aegx"
aegx init "$BUNDLE"

# 2. Record session start
ROOT=$(aegx add-record "$BUNDLE" \
  --type SessionStart \
  --principal SYS \
  --meta "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"agent\":\"$AGENT_ID\"}" \
  --inline '{"reason":"automated session"}')

# 3. Record each action (example: tool call)
PREV="$ROOT"
CALL_ID=$(aegx add-record "$BUNDLE" \
  --type ToolCall \
  --principal TOOL \
  --meta "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"tool_id\":\"web-search\"}" \
  --parents "$PREV" \
  --inline '{"query":"latest CVE list"}')
PREV="$CALL_ID"

# 4. Record the tool result
RESULT_ID=$(aegx add-record "$BUNDLE" \
  --type ToolResult \
  --principal TOOL \
  --meta "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"tool_id\":\"web-search\"}" \
  --parents "$PREV" \
  --inline '{"status":"ok","items":42}')
PREV="$RESULT_ID"

# 5. If the payload is large, use blobs
echo "large output data here..." > /tmp/tool_output.txt
BLOB=$(aegx add-blob "$BUNDLE" /tmp/tool_output.txt --mime text/plain)
SIZE=$(wc -c < /tmp/tool_output.txt | tr -d ' ')
RESULT2=$(aegx add-record "$BUNDLE" \
  --type ToolResult \
  --principal TOOL \
  --meta "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"tool_id\":\"file-read\"}" \
  --parents "$PREV" \
  --blob "$BLOB" --mime text/plain --size "$SIZE")

# 6. Verify before exporting
aegx verify "$BUNDLE"
EXIT=$?
if [ "$EXIT" -ne 0 ]; then
  echo "ERROR: Bundle verification failed with exit code $EXIT"
  exit 1
fi

# 7. Export
aegx export "$BUNDLE" "$BUNDLE.zip"

# 8. Summarize (optional, for logging)
aegx summarize "$BUNDLE"
```

### Inline vs Blob: Decision Rule

| Condition | Use |
|-----------|-----|
| Payload JSON ≤ 4096 bytes | `--inline` |
| Payload > 4096 bytes or binary | `aegx add-blob` first, then `--blob --mime --size` |

---

## 5. Pattern B: AER Runtime with Guards

Use this when your agent runs inside an OpenClaw-compatible environment or any agentic system supporting Provenable.ai and you want CPI/MI protection, snapshots, and rollback.

### Step-by-step

```bash
# 1. Initialize AER (once per environment)
proven-aer init

# 2. Check status
proven-aer status

# 3. Take a snapshot before risky operations
proven-aer snapshot create "pre-deploy" --scope full
SNAP_ID=$(proven-aer snapshot list | tail -1 | awk '{print $1}')

# 4. Run your agent's operations
#    AER automatically records events and enforces CPI/MI guards.
#    If a guard denies an operation, your agent receives an error.

# 5. If something goes wrong, rollback
proven-aer rollback "$SNAP_ID"

# 6. Export evidence for audit
proven-aer bundle export --agent "$AGENT_ID"

# 7. Verify the exported bundle
BUNDLE_PATH=$(ls -t ~/.proven/.aer/bundles/*.aegx.zip | head -1)
proven-aer verify "$BUNDLE_PATH"
```

### Guard Decisions Your Agent Will Encounter

When AER denies an action, your agent should:

1. **Log the denial** — the denial is already recorded as a `GuardDecision` record
2. **Do NOT retry the same action** — the policy will deny it again
3. **Escalate to the user** or choose an alternative path
4. **Never attempt to bypass** — bypasses break the security guarantees

### CPI-Protected Surfaces (Cannot Be Changed by Untrusted Principals)

- Skills registry
- Tool registry
- Permissions configuration
- Gateway authentication settings
- Node/server settings

### MI-Protected Files (Cannot Be Written by Tainted Sources)

- `SOUL.md`, `AGENTS.md`, `TOOLS.md`, `USER.md`
- `IDENTITY.md`, `HEARTBEAT.md`, `MEMORY.md`

---

## 6. Verification Before Trust

**Rule: Never trust a bundle without verifying it first.**

```bash
# For aegx bundles (directory)
aegx verify "$BUNDLE_DIR"

# For aegx bundles (zip — import first)
aegx import "$ZIP" /tmp/verify_target
aegx verify /tmp/verify_target

# For AER bundles
proven-aer verify "$BUNDLE_PATH"
```

### Interpreting Exit Codes

```bash
aegx verify "$BUNDLE"
CODE=$?

case $CODE in
  0) echo "TRUSTED: Bundle integrity verified" ;;
  2) echo "TAMPERED: Hash mismatch or broken chain" ;;
  3) echo "MALFORMED: Schema validation failed" ;;
  4) echo "IOERROR: Cannot read bundle" ;;
  *) echo "UNKNOWN: Unexpected exit code $CODE" ;;
esac
```

---

## 7. Rollback on Failure

### When to Rollback

| Situation | Action |
|-----------|--------|
| Agent wrote incorrect files | Rollback to pre-operation snapshot |
| Guard denied a critical operation mid-flow | Rollback to last known good state |
| Verification of own bundle fails | Rollback and re-run from snapshot |
| User requests undo | Rollback to user-specified snapshot |

### Rollback Procedure

```bash
# List available snapshots
proven-aer snapshot list

# Pick one and rollback
proven-aer rollback <SNAPSHOT_ID>

# Verify rollback succeeded (command prints PASS/FAIL)
```

### Limitations

Rollback restores **file content only**. It cannot:
- Reverse external API calls already made
- Undo messages already sent
- Restore deleted database rows

Plan your snapshot points **before** irreversible actions.

---

## 8. Machine-Readable Summary

After completing a session, generate a summary for upstream systems:

```bash
aegx summarize "$BUNDLE" > /tmp/summary.txt
```

Parse the output:

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

The last line is always `Verification: PASS` or `Verification: FAIL`.

---

## 9. Integration Checklist

Use this checklist to confirm your agent integration is complete.

- [ ] `aegx` binary is on PATH and `aegx --help` succeeds
- [ ] `proven-aer` binary is on PATH (if using AER)
- [ ] `proven-aer init` has been run (if using AER)
- [ ] Every session starts with `aegx init` (Pattern A) or is managed by AER (Pattern B)
- [ ] Every agent action creates a record with correct type and principal
- [ ] Every record (except root) has `--parents` set
- [ ] Large payloads use blobs (`add-blob` + `--blob` reference)
- [ ] `aegx verify` runs before exporting and the exit code is checked
- [ ] Snapshots are created before risky operations (if using AER)
- [ ] Guard denials are handled (not retried, escalated instead)
- [ ] Exported bundles are stored or transmitted for audit
- [ ] Bundle verification runs on the receiving side before any trust decision

---

## Next Steps

- [Quickstart Tutorial](QUICKSTART.md) — hands-on walkthrough
- [CLI Reference](CLI_REFERENCE.md) — every command and flag
- [Verification Guide](VERIFICATION_GUIDE.md) — what verify checks in detail
- [CPI/MI Guard Rules](aer-cpi-mi-rules.md) — policy customization
- [Troubleshooting](TROUBLESHOOTING.md) — common errors and fixes
