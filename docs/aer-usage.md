# AER Usage Guide

## Prerequisites

Build the AER binary:

```bash
cd packages/aer
cargo build --release
```

The binary is at `target/release/proven-aer`.

## Environment

AER uses the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `PRV_STATE_DIR` | Root state directory | `~/.proven` |
| `PRV_HOME` | Alternative to STATE_DIR | `~/.proven` |

AER stores its state under `<STATE_DIR>/.aer/`.

## Initialization

```bash
proven-aer init
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
proven-aer status
```

Shows record count, audit chain entries, snapshot count, and chain integrity.

## Snapshots

### Create a snapshot

```bash
# Full snapshot (control-plane + memory)
proven-aer snapshot create my-snapshot

# Control-plane only
proven-aer snapshot create pre-upgrade --scope control-plane

# Memory only
proven-aer snapshot create clean-state --scope memory
```

### List snapshots

```bash
proven-aer snapshot list
```

## Rollback

```bash
proven-aer rollback <snapshot-id>
```

Rollback restores all files in the snapshot scope to their exact snapshotted content. A Rollback evidence record is emitted and the restored files are verified against snapshot hashes.

## Evidence Bundle Export

```bash
# Export all evidence
proven-aer bundle export

# Filter by agent
proven-aer bundle export --agent agent-123

# Filter by time
proven-aer bundle export --since 2025-01-01T00:00:00Z
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
proven-aer verify <path-to-bundle.aegx.zip>
```

Checks:
- Record ID hashes match content
- Audit chain integrity (no gaps, no hash mismatches)
- Blob hashes match references
- Reports all errors found

## Report

```bash
proven-aer report <path-to-bundle.aegx.zip>
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

## Integration with OpenClaw (and Compatible Agentic Systems)

AER hooks into OpenClaw at these chokepoints:

1. **Tool dispatch**: `hooks::on_tool_call()` / `hooks::on_tool_result()`
2. **Session logging**: `hooks::on_session_start()` / `hooks::on_session_message()`
3. **Control-plane changes**: `hooks::on_control_plane_change()` — returns `Err` if denied
4. **Memory writes**: `workspace::write_memory_file()` — returns `Err` if denied
5. **Proxy trust detection**: `hooks::check_proxy_trust()` — emits audit warnings
6. **Skill install verification**: `hooks::on_skill_install()` — pre-install skill scanning (v0.1.3)

### ClawHub / Skill Marketplace Integration

AER provides structural defense against supply-chain attacks on skill
marketplaces like [ClawHub](https://clawhub.ai/). The `skill_verifier` module
scans skill packages before installation for all 6 [ClawHavoc](https://www.esecurityplanet.com/threats/hundreds-of-malicious-skills-found-in-openclaws-clawhub/)
attack vectors (shell commands, reverse shells, credential theft, memory
poisoning, name collision, typosquatting).

See [ClawHub Integration](clawhub-integration.md) for the full deep dive.
