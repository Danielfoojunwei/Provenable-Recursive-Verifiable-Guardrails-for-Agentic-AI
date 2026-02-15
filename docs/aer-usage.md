# AER Usage Guide

## Prerequisites

Build the AER binary:

```bash
cd packages/aer
cargo build --release
```

The binary is at `target/release/openclaw-aer`.

## Environment

AER respects the same environment variables as OpenClaw:

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENCLAW_STATE_DIR` | Root state directory | `~/.openclaw` |
| `OPENCLAW_HOME` | Alternative to STATE_DIR | `~/.openclaw` |

AER stores its state under `<STATE_DIR>/.aer/`.

## Initialization

```bash
openclaw-aer init
```

This creates:
- `<STATE_DIR>/.aer/policy/` — policy packs (YAML)
- `<STATE_DIR>/.aer/records/` — records.jsonl + blobs/
- `<STATE_DIR>/.aer/audit/` — audit-log.jsonl (hash chain)
- `<STATE_DIR>/.aer/snapshots/` — snapshot manifests + blobs
- `<STATE_DIR>/.aer/bundles/` — exported .aegx bundles
- `<STATE_DIR>/.aer/reports/` — generated reports

A default policy is installed with deny-by-default rules for CPI and MI.

## Status

```bash
openclaw-aer status
```

Shows record count, audit chain entries, snapshot count, and chain integrity.

## Snapshots

### Create a snapshot

```bash
# Full snapshot (control-plane + memory)
openclaw-aer snapshot create my-snapshot

# Control-plane only
openclaw-aer snapshot create pre-upgrade --scope control-plane

# Memory only
openclaw-aer snapshot create clean-state --scope memory
```

### List snapshots

```bash
openclaw-aer snapshot list
```

## Rollback

```bash
openclaw-aer rollback <snapshot-id>
```

Rollback restores all files in the snapshot scope to their exact snapshotted content. A Rollback evidence record is emitted and the restored files are verified against snapshot hashes.

## Evidence Bundle Export

```bash
# Export all evidence
openclaw-aer bundle export

# Filter by agent
openclaw-aer bundle export --agent agent-123

# Filter by time
openclaw-aer bundle export --since 2025-01-01T00:00:00Z
```

The bundle is saved as a `.aegx.zip` file under `<STATE_DIR>/.aer/bundles/`.

Bundle contents:
- `manifest.json` — bundle metadata
- `records.jsonl` — evidence records
- `audit-log.jsonl` — hash chain
- `blobs/` — large payloads
- `policy.yaml` — policy pack in effect
- `report.md` — human-readable report
- `report.json` — machine-readable report

## Verification

```bash
openclaw-aer verify <path-to-bundle.aegx.zip>
```

Checks:
- Record ID hashes match content
- Audit chain integrity (no gaps, no hash mismatches)
- Blob hashes match references
- Reports all errors found

## Report

```bash
openclaw-aer report <path-to-bundle.aegx.zip>
```

Prints the evidence report (Markdown format) to stdout.

## Policy Customization

The default policy is at `<STATE_DIR>/.aer/policy/default.yaml`. You can edit it to customize guard rules.

Example rule structure:

```yaml
rules:
  - id: my-custom-rule
    surface: ControlPlane
    action: Deny
    condition:
      principals:
        - Web
        - Skill
    description: "Custom denial for web/skill principals"
```

Available surfaces: `ControlPlane`, `DurableMemory`
Available actions: `Allow`, `Deny`
Available principals: `Sys`, `User`, `ToolAuth`, `ToolUnauth`, `Web`, `Skill`, `Channel`, `External`

## Integration with OpenClaw

AER hooks into OpenClaw at these chokepoints:

1. **Tool dispatch**: `hooks::on_tool_call()` / `hooks::on_tool_result()`
2. **Session logging**: `hooks::on_session_start()` / `hooks::on_session_message()`
3. **Control-plane changes**: `hooks::on_control_plane_change()` — returns `Err` if denied
4. **Memory writes**: `workspace::write_memory_file()` — returns `Err` if denied
5. **Proxy trust detection**: `hooks::check_proxy_trust()` — emits audit warnings
