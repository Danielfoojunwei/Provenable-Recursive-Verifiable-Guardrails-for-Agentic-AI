# AEGX Quickstart: Up and Running in 5 Minutes

This tutorial walks you through initializing AEGX, creating snapshots, querying protection status, and exporting and verifying evidence bundles. Every command is real -- copy-paste and run.

**Prerequisite:** You have built `aegx` per [INSTALL.md](INSTALL.md). The examples assume `aegx` is on your PATH. If not, replace `aegx` with `./target/release/aegx`.

---

## Step 1: Build from Source

If you have not already built `aegx`, see [INSTALL.md](INSTALL.md) for full instructions. The short version:

```bash
cargo build --release
```

The binary will be at `./target/release/aegx`.

---

## Step 2: Initialize the Runtime

```bash
aegx init
```

Expected output:

```
Initializing AEGX...
  Created AEGX directories under /home/you/.local/share/aegx
  Installed default policy: /home/you/.local/share/aegx/policy.json
  Ensured workspace directory: /home/you/.local/share/aegx/workspace

AEGX initialized successfully.

Policy summary:
  - CPI: deny control-plane changes from non-USER/SYS principals
  - MI: deny memory writes with tainted provenance
  - MI: deny memory writes from untrusted principals
  - CIO: deny injection-suspected conversation messages
  - All clean operations: allowed

State directory: /home/you/.local/share/aegx/state
```

This creates the AEGX state directories and installs a default guardrail policy. Paths will vary depending on your system.

---

## Step 3: Check System Health

```bash
aegx status
```

Expected output:

```
AEGX: initialized
State directory: /home/you/.local/share/aegx/state
AEGX root: /home/you/.local/share/aegx
Records: 0
Audit chain entries: 0
Snapshots: 0
Audit chain: VALID
```

If AEGX has not been initialized, you will see a message directing you to run `aegx init`.

---

## Step 4: Create a Snapshot

Take a snapshot of the current state:

```bash
aegx snapshot create "first-snapshot"
```

Expected output:

```
Creating snapshot 'first-snapshot' (scope: full)...
Snapshot created:
  ID: a1b2c3d4e5f6...
  Name: first-snapshot
  Files: 3
  Created: 2026-03-16T14:00:00+00:00
```

The `--scope` flag is optional and defaults to `full`. Other options are `cp` (control-plane only) and `mem` (durable memory only):

```bash
aegx snapshot create "cp-only" --scope cp
```

---

## Step 5: List Snapshots

```bash
aegx snapshot list
```

Expected output:

```
Snapshots:
  a1b2c3d4 — first-snapshot (Full, 3 files, 2026-03-16T14:00:00+00:00)
```

---

## Step 6: Check Protection Status (Human-Readable)

The `prove` command queries what Provenable.ai has protected:

```bash
aegx prove
```

This prints a human-readable summary of protection status, including intercepted threats, guardrail metrics, and system health.

You can filter results by category or severity:

```bash
aegx prove --category cpi --severity high
```

Available categories: `cpi`, `mi`, `taint`, `injection`, `extraction`, `leakage`, `proxy`, `rollback`, `contamination`.

Available severities: `critical`, `high`, `medium`, `info`.

---

## Step 7: Machine-Readable Protection Status

For integration with other tools, use the `--json` flag:

```bash
aegx prove --json
```

This outputs the same protection data as structured JSON, suitable for piping into `jq` or ingesting in a dashboard.

---

## Step 8: Export an Evidence Bundle

Package the current AEGX state into a portable, verifiable evidence bundle:

```bash
aegx bundle export
```

Expected output:

```
Exporting AEGX evidence bundle...
Bundle exported: /home/you/.local/share/aegx/bundles/aegx-bundle-20260316T140000Z.aegx.zip
```

The exported `.aegx.zip` file contains records, the audit chain, blobs, and a manifest -- everything needed for independent verification.

You can scope the export to a specific agent or time window:

```bash
aegx bundle export --agent my-agent-v1 --since 2026-03-16T00:00:00Z
```

---

## Step 9: Verify the Exported Bundle

Verify the integrity of the bundle you just exported:

```bash
aegx verify /path/to/aegx-bundle-20260316T140000Z.aegx.zip
```

Expected output:

```
Verifying bundle: /path/to/aegx-bundle-20260316T140000Z.aegx.zip
Verification result:
  Valid: true
  Records checked: 0
  Audit entries checked: 0
  Blobs checked: 0

PASS: Bundle integrity verified.
```

If any record, audit entry, or blob has been tampered with, the verifier will report the specific errors and exit with a non-zero status.

---

## Step 10: View the Report

Generate a human-readable report from the bundle:

```bash
aegx report /path/to/aegx-bundle-20260316T140000Z.aegx.zip
```

This prints a Markdown-formatted report summarizing the records and audit entries contained in the bundle. The report includes record counts, types, principals, and the audit chain status.

---

## What You Did

1. **Initialized** AEGX with default guardrail policies (`aegx init`)
2. **Checked** system health and audit chain integrity (`aegx status`)
3. **Snapshotted** the runtime state for rollback capability (`aegx snapshot create`)
4. **Listed** available snapshots (`aegx snapshot list`)
5. **Queried** protection status in both human and machine formats (`aegx prove`)
6. **Exported** a portable evidence bundle (`aegx bundle export`)
7. **Verified** the bundle's cryptographic integrity (`aegx verify`)
8. **Generated** a report from the bundle (`aegx report`)

Every record has a deterministic content-addressed ID. Every audit entry chains to the previous one via hash. Every blob is named by its SHA-256. If any byte changes, `aegx verify` will catch it.

---

## Next Steps

- [CLI Reference](CLI_REFERENCE.md) -- all commands and flags
- [Agent Integration Guide](AGENT_INTEGRATION.md) -- embed AEGX in your agent
