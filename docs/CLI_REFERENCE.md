# AEGX CLI Reference

Complete reference for the unified `aegx` command-line interface (v0.2.0).

---

## Global Usage

```
aegx <COMMAND> [OPTIONS]
aegx --version
aegx --help
```

| Command | Purpose |
|---------|---------|
| `init` | Initialize AEGX in the current state directory |
| `status` | Show system health and initialization state |
| `snapshot create` | Capture a state snapshot |
| `snapshot list` | List existing snapshots |
| `rollback` | Restore state from a snapshot |
| `bundle export` | Export an evidence bundle |
| `verify` | Verify an evidence bundle |
| `report` | Generate a report from an evidence bundle |
| `prove` | Query what Provenable.ai has protected |

---

## `aegx init`

Initialize AEGX in the current Provenable.ai state directory. Creates all required directories, installs the default deny-by-default policy, and ensures the workspace directory exists.

### Usage

```bash
aegx init
```

No arguments.

### What It Creates

```
<STATE_DIR>/.aer/
  policy/default.yaml       # deny-by-default CPI + MI rules
  records/records.jsonl     # event log
  records/blobs/            # blob store
  audit/audit-log.jsonl     # hash-chained audit log
  snapshots/                # snapshot storage
  bundles/                  # exported evidence bundles
  reports/                  # generated reports
  alerts/                   # alert storage

<STATE_DIR>/workspace/      # guarded workspace memory directory
```

### Default Policies Installed

- **CPI:** deny control-plane changes from non-USER/SYS principals
- **MI:** deny memory writes with tainted provenance
- **MI:** deny memory writes from untrusted principals
- **CIO:** deny injection-suspected conversation messages
- All clean operations: allowed

### Example

```bash
aegx init
# Output:
# Initializing AEGX...
#   Created AEGX directories under /home/user/.proven/.aer
#   Installed default policy: /home/user/.proven/.aer/policy/default.yaml
#   Ensured workspace directory: /home/user/.proven/workspace
#
# AEGX initialized successfully.
#
# Policy summary:
#   - CPI: deny control-plane changes from non-USER/SYS principals
#   - MI: deny memory writes with tainted provenance
#   - MI: deny memory writes from untrusted principals
#   - CIO: deny injection-suspected conversation messages
#   - All clean operations: allowed
#
# State directory: /home/user/.proven
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Initialization completed successfully |
| 1 | I/O error (cannot create directories, permission denied) |

---

## `aegx status`

Show the current state of the AEGX subsystem, including record counts, audit chain integrity, and snapshot count.

### Usage

```bash
aegx status
```

No arguments.

### Behavior

If AEGX has not been initialized, prints a message directing the user to run `aegx init`. Otherwise displays:

- State directory and AEGX root paths
- Total record count
- Audit chain entry count
- Snapshot count
- Audit chain integrity status (VALID or BROKEN)

### Example (Initialized)

```
AEGX: initialized
State directory: /home/user/.proven
AEGX root: /home/user/.proven/.aer
Records: 42
Audit chain entries: 42
Snapshots: 3
Audit chain: VALID
```

### Example (Not Initialized)

```
AEGX: not initialized
Run `aegx init` to set up AEGX.
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Status displayed successfully |
| 1 | I/O error |

---

## `aegx snapshot create`

Capture the current state of control-plane files, memory files, or both into a named snapshot.

### Usage

```bash
aegx snapshot create <NAME> [--scope <SCOPE>]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Human-readable name for the snapshot |
| `--scope SCOPE` | No | Scope of files to capture. Default: `full` |

### Scope Values

| Value | Alias | Description |
|-------|-------|-------------|
| `full` | -- | Capture both control-plane and memory files (default) |
| `control-plane` | `cp` | Capture control-plane files only |
| `memory` | `mem` | Capture durable memory files only |

### Behavior

1. Reads all files in the selected scope
2. Stores file contents and computes hashes
3. Creates a snapshot manifest with a unique ID
4. Prints the snapshot ID, name, file count, and creation timestamp

### Example

```bash
aegx snapshot create "before-refactor" --scope full
# Output:
# Creating snapshot 'before-refactor' (scope: full)...
# Snapshot created:
#   ID: a1b2c3d4e5f6a7b8...
#   Name: before-refactor
#   Files: 5
#   Created: 2026-02-15T10:00:00+00:00

aegx snapshot create "cp-backup" --scope cp
aegx snapshot create "mem-backup" --scope mem
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Snapshot created successfully |
| 1 | Invalid scope value or I/O error |

---

## `aegx snapshot list`

List all existing snapshots.

### Usage

```bash
aegx snapshot list
```

No arguments.

### Behavior

Lists all snapshots with their truncated ID (first 8 characters), name, scope, file count, and creation timestamp. If no snapshots exist, prints "No snapshots found."

### Example

```
Snapshots:
  a1b2c3d4 -- before-refactor (Full, 5 files, 2026-02-15T10:00:00+00:00)
  e5f6a7b8 -- cp-backup (ControlPlane, 2 files, 2026-02-15T11:00:00+00:00)
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | List displayed (including when empty) |
| 1 | I/O error |

---

## `aegx rollback`

Restore files to the state captured in a previous snapshot.

### Usage

```bash
aegx rollback <SNAPSHOT_ID>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `SNAPSHOT_ID` | Yes | The snapshot ID (full or prefix, as shown by `snapshot list`) |

### Behavior

1. Loads the snapshot manifest for the given ID
2. Calculates the diff between current state and snapshot (files modified, files removed)
3. If no changes are needed, reports that state already matches the snapshot
4. Restores modified files to their snapshotted content
5. Recreates any files that were deleted since the snapshot
6. Verifies all restored file hashes match the snapshot
7. Prints a rollback report listing restored files, recreated files, any errors, and a PASS/FAIL verification result

### Example

```bash
aegx rollback a1b2c3d4e5f6a7b8
# Output:
# Rolling back to snapshot: a1b2c3d4 (before-refactor)
#   Files to restore: 2
#   Files to recreate: 1
#
# Rollback complete:
#   Restored:
#     /home/user/.proven/.aer/policy/default.yaml
#     /home/user/.proven/workspace/SOUL.md
#   Recreated:
#     /home/user/.proven/workspace/TOOLS.md
#   Verification: PASS
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Rollback completed (check verification status in output) |
| 1 | Snapshot not found or I/O error |

---

## `aegx bundle export`

Export an AEGX evidence bundle from the event log. The bundle is saved as a `.aegx.zip` file.

### Usage

```bash
aegx bundle export [--agent <AGENT_ID>] [--since <TIMESTAMP>]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--agent ID` | No | Filter records to only those belonging to this agent ID |
| `--since TIMESTAMP` | No | Include only records after this timestamp (RFC 3339 format) |

### Behavior

1. Reads the current records, audit log, blobs, and policy from the AEGX state directory
2. Applies any agent or time filters
3. Packages everything into a `.aegx.zip` bundle
4. Prints the path to the exported bundle

### Example

```bash
# Export all evidence
aegx bundle export
# Output: Bundle exported: /home/user/.proven/.aer/bundles/bundle-2026-02-15T10:00:00Z.aegx.zip

# Filter by agent and time
aegx bundle export --agent my-agent-v1 --since 2026-02-15T10:00:00Z
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Bundle exported successfully |
| 1 | Invalid timestamp format or I/O error |

---

## `aegx verify`

Verify the integrity of an exported AEGX evidence bundle. This is the core trust operation.

### Usage

```bash
aegx verify <BUNDLE_PATH>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `BUNDLE_PATH` | Yes | Path to the `.aegx.zip` bundle file |

### Checks Performed

- Record ID hashes match record content
- Audit chain integrity (sequential indexing, correct hash linking)
- Blob file hashes match their references
- Record count and blob count match manifest values
- All errors are reported individually

### Example (Pass)

```
Verifying bundle: evidence.aegx.zip
Verification result:
  Valid: true
  Records checked: 42
  Audit entries checked: 42
  Blobs checked: 5

PASS: Bundle integrity verified.
```

### Example (Fail)

```
Verifying bundle: evidence.aegx.zip
Verification result:
  Valid: false
  Records checked: 42
  Audit entries checked: 42
  Blobs checked: 5
  Errors:
    [RecordHashMismatch] record 3 hash does not match

FAIL: Bundle integrity check failed.
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All integrity checks passed |
| 1 | Bundle file not found or I/O error |
| (process exits with code 1) | Verification failure (tamper detected, hash mismatch, broken chain) |

---

## `aegx report`

Generate or display a Markdown report from an AEGX evidence bundle.

### Usage

```bash
aegx report <BUNDLE_PATH>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `BUNDLE_PATH` | Yes | Path to the `.aegx.zip` bundle file |

### Behavior

1. Extracts the bundle to a temporary directory
2. If the bundle already contains a `report.md`, prints it to stdout
3. Otherwise, reads records and audit log from the bundle and generates a new Markdown report
4. Prints the report to stdout

### Example

```bash
aegx report evidence.aegx.zip
# Prints the Markdown report to stdout
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Report generated and printed |
| 1 | Bundle not found or I/O error |

---

## `aegx prove`

Query what Provenable.ai has protected. This is the `/prove` interface -- it reads local AEGX state (records, audit log, alerts) and returns a summary of protection activity, threats detected, and system health.

### Usage

```bash
aegx prove [--json] [--category <CATEGORY>] [--severity <SEVERITY>] [--since <TIMESTAMP>] [--until <TIMESTAMP>] [--limit <N>]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--json` | No | Output results as JSON instead of human-readable text |
| `--category CAT` | No | Filter results by threat category (see table below) |
| `--severity SEV` | No | Filter results by minimum severity level (see table below) |
| `--since TIMESTAMP` | No | Include only events after this timestamp (RFC 3339) |
| `--until TIMESTAMP` | No | Include only events before this timestamp (RFC 3339) |
| `--limit N` | No | Maximum number of results to return |

### Category Values

| Value | Description |
|-------|-------------|
| `cpi` | Control-Plane Integrity violation |
| `mi` | Memory Integrity violation |
| `taint` | Taint propagation block |
| `injection` | Prompt injection suspect |
| `extraction` | Prompt extraction attempt |
| `leakage` | Prompt leakage detection |
| `proxy` | Proxy misconfiguration |
| `rollback` | Automatic rollback triggered |
| `contamination` | Cross-context contamination detected |

### Severity Values

| Value | Description |
|-------|-------------|
| `critical` | Highest severity -- immediate action required |
| `high` | Significant threat detected |
| `medium` | Moderate concern |
| `info` | Informational event |

### Behavior

1. Reads local AEGX state (records, audit log, alerts)
2. Applies any category, severity, time, or limit filters
3. Includes system health and metrics in the response
4. Outputs results in human-readable format (default) or JSON (`--json`)

### Example

```bash
# Show all protection activity
aegx prove

# Show only critical CPI violations as JSON
aegx prove --json --category cpi --severity critical

# Show recent events with a limit
aegx prove --since 2026-02-15T00:00:00Z --limit 10

# Filter by time range and severity
aegx prove --since 2026-02-01T00:00:00Z --until 2026-02-28T23:59:59Z --severity high
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Query executed and results displayed |
| 1 | Invalid filter value (bad category, severity, or timestamp) or I/O error |

---

## Environment Variables

AEGX resolves its state directory using the following environment variables, checked in order of precedence:

| Variable | Priority | Description |
|----------|----------|-------------|
| `PRV_STATE_DIR` | 1 (highest) | Override the state directory path entirely |
| `PRV_HOME` | 2 | Set the Provenable.ai home directory |
| `HOME` | 3 (fallback) | Used to derive the default path `$HOME/.proven` |

**Precedence:** `PRV_STATE_DIR` > `PRV_HOME` > `$HOME/.proven`

If none of these variables are set, AEGX will refuse to start with a panic. It does not fall back to `/tmp` because that would be a security risk on multi-user systems.

All AEGX state is stored under `<STATE_DIR>/.aer/`.

### Example

```bash
# Use the default location (~/.proven)
aegx status

# Override with a custom state directory
PRV_STATE_DIR=/opt/aegx/state aegx status

# Set a custom Provenable.ai home
PRV_HOME=/data/proven aegx status
```

---

## Exit Code Summary

| Code | Meaning |
|------|---------|
| 0 | Operation completed successfully |
| 1 | Error (invalid arguments, I/O failure, verification failure, invalid filter values) |
