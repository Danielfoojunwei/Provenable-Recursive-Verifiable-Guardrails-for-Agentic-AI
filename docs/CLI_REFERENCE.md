# AEGX CLI Reference

Complete reference for every `aegx` command, flag, and exit code.

---

## Global Usage

```
aegx <COMMAND> [OPTIONS]
```

| Command | Purpose |
|---------|---------|
| `init` | Create a new empty bundle |
| `add-blob` | Copy a file into the bundle's blob store |
| `add-record` | Append a typed record to the bundle |
| `export` | Package a bundle directory into a zip |
| `import` | Extract a zip into a bundle directory |
| `verify` | Check bundle integrity end-to-end |
| `summarize` | Print record counts and verification status |

---

## `aegx init`

Create a new AEGX bundle directory with empty manifest, records, audit log, and blobs folder.

### Usage

```bash
aegx init <BUNDLE_DIR> [--zip-out <PATH>]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `BUNDLE_DIR` | Yes | Path for the new bundle directory |
| `--zip-out PATH` | No | Also export the initialized bundle as a zip |

### What It Creates

```
BUNDLE_DIR/
  manifest.json       # aegx_version=0.1, record_count=0, blob_count=0
  records.jsonl       # empty file
  audit-log.jsonl     # empty file
  blobs/              # empty directory
```

### Example

```bash
aegx init evidence.aegx
# Output: Initialized bundle: evidence.aegx

aegx init evidence.aegx --zip-out evidence.aegx.zip
# Output: Initialized bundle: evidence.aegx
#         Exported to: evidence.aegx.zip
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Bundle created successfully |
| 4 | I/O error (cannot create directory, permission denied) |

---

## `aegx add-blob`

Copy a file from disk into the bundle's `blobs/` directory, named by its SHA-256 hash.

### Usage

```bash
aegx add-blob <BUNDLE> <FILE_PATH> [--mime <MIME_TYPE>]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `BUNDLE` | Yes | Path to the bundle directory |
| `FILE_PATH` | Yes | Path to the file to add |
| `--mime TYPE` | No | MIME type (default: `application/octet-stream`). Stored for reference only. |

### Behavior

1. Reads the file at `FILE_PATH`
2. Computes `sha256(file_bytes)`
3. Copies to `BUNDLE/blobs/<sha256_hex>`
4. If the blob already exists with identical content, skips the copy
5. If the blob already exists with different content, returns an error
6. Prints the SHA-256 hex to stdout

### Example

```bash
aegx add-blob my.aegx report.pdf
# Output: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Blob added (or already existed with same content) |
| 4 | I/O error |

### Important

`add-blob` does NOT create a record. You must call `add-record` separately with the `--blob` flag to reference the blob in a record.

---

## `aegx add-record`

Append a typed record to `records.jsonl`, append a corresponding audit entry to `audit-log.jsonl`, and update `manifest.json`.

### Usage

```bash
# Inline payload
aegx add-record <BUNDLE> \
  --type <RECORD_TYPE> \
  --principal <PRINCIPAL> \
  --meta <JSON> \
  [--parents <ID>,<ID>,...] \
  --inline <JSON>

# Blob payload
aegx add-record <BUNDLE> \
  --type <RECORD_TYPE> \
  --principal <PRINCIPAL> \
  --meta <JSON> \
  [--parents <ID>,<ID>,...] \
  --blob <SHA256> --mime <MIME_TYPE> --size <BYTES>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `BUNDLE` | Yes | Path to the bundle directory |
| `--type TYPE` | Yes | Record type (see table below) |
| `--principal P` | Yes | Principal who produced this record |
| `--meta JSON` | Yes | JSON object; must contain `"ts"` (RFC3339 timestamp) |
| `--parents ID,...` | No | Comma-separated list of parent record IDs |
| `--inline JSON` | One of | Inline JSON payload |
| `--blob SHA256` | One of | SHA-256 of the referenced blob (must already exist in blobs/) |
| `--mime TYPE` | With blob | MIME type of the blob |
| `--size BYTES` | With blob | Size of the blob in bytes |

### Record Types

| Type | When to Use |
|------|-------------|
| `SessionStart` | Beginning of an agent session |
| `SessionMessage` | A message within a session (user or agent) |
| `ToolCall` | Agent invokes a tool |
| `ToolResult` | Tool returns a result |
| `FileRead` | Agent reads a file |
| `FileWrite` | Agent writes a file |
| `FileDelete` | Agent deletes a file |
| `ControlPlaneChangeRequest` | Attempt to modify system config |
| `MemoryCommitRequest` | Attempt to write to persistent memory |
| `GuardDecision` | A CPI/MI guard allowed or denied an action |
| `Snapshot` | State snapshot was taken |
| `Rollback` | State was rolled back to a snapshot |

### Principals

| Principal | Description |
|-----------|-------------|
| `USER` | Human operator |
| `SYS` | System / runtime |
| `WEB` | Web-sourced input |
| `TOOL` | Tool plugin |
| `SKILL` | Skill module |
| `CHANNEL` | Communication channel |
| `EXTERNAL` | External / untrusted source |

### Behavior

1. Parses and validates all inputs
2. Normalizes `meta.ts` to RFC3339 `"Z"` form
3. Computes `recordId = sha256(CANON({type, principal, taint, parents, meta, payload, schema}))`
4. Appends the record as one JSON line to `records.jsonl`
5. Appends an audit entry to `audit-log.jsonl` (chained to previous via hash)
6. Updates manifest: `record_count`, `audit_head`, `root_records`, `blob_count`
7. Prints the `recordId` to stdout

### Example

```bash
# Inline record
RID=$(aegx add-record my.aegx \
  --type SessionStart \
  --principal SYS \
  --meta '{"ts":"2026-02-15T10:00:00Z"}' \
  --inline '{"reason":"new session"}')

# Record referencing a blob
aegx add-record my.aegx \
  --type FileWrite \
  --principal TOOL \
  --meta '{"ts":"2026-02-15T10:01:00Z","path":"/app/config.json"}' \
  --parents "$RID" \
  --blob "e3b0c442..." \
  --mime "application/json" \
  --size 1024
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Record added |
| 1 | Invalid arguments (bad type, principal, JSON) |
| 4 | I/O error |

---

## `aegx export`

Package a bundle directory into a zip archive.

### Usage

```bash
aegx export <BUNDLE_DIR> <OUT_ZIP>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `BUNDLE_DIR` | Yes | Path to the bundle directory |
| `OUT_ZIP` | Yes | Output zip file path |

### Example

```bash
aegx export my.aegx my.aegx.zip
# Output: Exported: my.aegx.zip
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Zip created |
| 4 | I/O error |

---

## `aegx import`

Extract a zip archive into a bundle directory.

### Usage

```bash
aegx import <BUNDLE_ZIP> <OUT_DIR>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `BUNDLE_ZIP` | Yes | Path to the zip file |
| `OUT_DIR` | Yes | Directory to extract into |

### Example

```bash
aegx import my.aegx.zip imported.aegx
# Output: Imported: imported.aegx
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Extracted |
| 4 | I/O error |

---

## `aegx verify`

Run all integrity checks on a bundle. This is the core trust operation.

### Usage

```bash
aegx verify <BUNDLE>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `BUNDLE` | Yes | Path to a bundle directory |

### Checks Performed

1. Validate `manifest.json` against the manifest JSON Schema
2. Validate every record in `records.jsonl` against the record JSON Schema
3. Validate every entry in `audit-log.jsonl` against the audit-entry JSON Schema
4. Recompute `recordId` for each record and compare to the stored value
5. Check that every parent reference points to an existing record
6. Check that every referenced blob file exists in `blobs/`
7. Recompute SHA-256 of each blob file and compare to its filename
8. Verify the audit chain: sequential `idx`, correct `prev` linking, recomputed `entryHash`
9. Compare computed audit head to `manifest.audit_head`
10. Compare actual `record_count` and `blob_count` to manifest values
11. Check that all `root_records` IDs exist

### Output

On success:

```
Verification: PASS
```

On failure, prints each error to stderr, one per line:

```
records.jsonl line 2: recordId mismatch: expected=abc..., got=def...
audit entry 1: expected prev=111..., got prev=222...
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 2 | Verification failure (tamper detected, hash mismatch, broken chain) |
| 3 | Schema validation failure (missing field, wrong type, invalid value) |
| 4 | I/O error (file not found, unreadable) |

---

## `aegx summarize`

Print a summary of bundle contents and verification status.

### Usage

```bash
aegx summarize <BUNDLE>
```

### Example Output

```
Records: 5
By type:
  FileWrite: 2
  SessionMessage: 1
  SessionStart: 1
  ToolCall: 1
By principal:
  SYS: 1
  TOOL: 3
  USER: 1
Verification: PASS
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Summary printed |
| 4 | I/O error |

---

## Exit Code Summary

| Code | Name | Meaning |
|------|------|---------|
| 0 | Success | Operation completed / verification passed |
| 1 | Argument Error | Invalid command-line arguments |
| 2 | Verification Failure | Integrity check failed (tampering detected) |
| 3 | Schema Failure | JSON Schema validation failed |
| 4 | I/O Error | File system error |

---

# openclaw-aer CLI Reference

The AER (Agent Evidence & Recovery) runtime manages CPI/MI guardrails, snapshots, rollback, and incident bundle export. Build it from `packages/aer/`:

```bash
cd packages/aer
cargo build --release --locked
# Binary: target/release/openclaw-aer
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENCLAW_STATE_DIR` | — | Override the state directory entirely (highest priority) |
| `OPENCLAW_HOME` | — | Set the OpenClaw home directory (second priority) |
| `HOME` | `/tmp` | Used to derive default path `~/.openclaw` (fallback) |

**Precedence:** `OPENCLAW_STATE_DIR` > `OPENCLAW_HOME` > `$HOME/.openclaw`

---

## `openclaw-aer init`

Initialize the AER subsystem in the OpenClaw state directory.

### Usage

```bash
openclaw-aer init
```

No arguments.

### What It Creates

```
~/.openclaw/.aer/
  policy/default.yaml       # deny-by-default CPI + MI rules
  records/records.jsonl     # event log
  records/blobs/            # blob store
  audit/audit-log.jsonl     # hash-chained audit log
  snapshots/                # snapshot storage
  bundles/                  # exported evidence bundles
  reports/                  # generated reports
```

### Default Policies Installed

- **CPI:** deny control-plane changes from non-USER/SYS principals
- **MI:** deny memory writes with tainted provenance
- **MI:** deny memory writes from untrusted principals
- All read operations: allowed

---

## `openclaw-aer status`

Show the current state of the AER subsystem.

### Usage

```bash
openclaw-aer status
```

### Example Output (Initialized)

```
AER: initialized
State directory: /home/user/.openclaw
AER root: /home/user/.openclaw/.aer
Records: 42
Audit chain entries: 42
Snapshots: 3
Audit chain integrity: VALID
```

### Example Output (Not Initialized)

```
AER: not initialized
Run `openclaw-aer init` to initialize.
```

---

## `openclaw-aer snapshot create`

Capture the current state of control-plane files, memory files, or both.

### Usage

```bash
openclaw-aer snapshot create <NAME> [--scope <SCOPE>]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Human-readable name for the snapshot |
| `--scope SCOPE` | No | `full` (default), `control-plane` / `cp`, `memory` / `mem` |

### Example

```bash
openclaw-aer snapshot create "before-refactor" --scope full
openclaw-aer snapshot create "cp-backup" --scope cp
openclaw-aer snapshot create "mem-backup" --scope mem
```

### Output

```
Snapshot created:
  ID: a1b2c3d4
  Name: before-refactor
  Scope: Full
  Files: 5
  Created: 2026-02-15T10:00:00Z
```

---

## `openclaw-aer snapshot list`

List all snapshots.

### Usage

```bash
openclaw-aer snapshot list
```

### Example Output

```
a1b2c3d4  before-refactor  Full            5 files  2026-02-15T10:00:00Z
e5f6a7b8  cp-backup        ControlPlane    2 files  2026-02-15T11:00:00Z
```

---

## `openclaw-aer rollback`

Restore files to the state captured in a snapshot.

### Usage

```bash
openclaw-aer rollback <SNAPSHOT_ID>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `SNAPSHOT_ID` | Yes | The snapshot ID (from `snapshot list`) |

### Behavior

1. Loads the snapshot manifest
2. Calculates diff against current state (files to restore, files to recreate)
3. Restores each file to its snapshotted content
4. Verifies all file hashes match the snapshot
5. Prints rollback report with PASS or FAIL

### Example

```bash
openclaw-aer rollback a1b2c3d4
```

---

## `openclaw-aer bundle export`

Export an AEGX evidence bundle from the AER event log.

### Usage

```bash
openclaw-aer bundle export [--agent <AGENT_ID>] [--since <ISO8601>]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--agent ID` | No | Filter records by agent ID |
| `--since TS` | No | Filter records after this timestamp (RFC 3339) |

### Example

```bash
openclaw-aer bundle export
openclaw-aer bundle export --agent my-agent-v1 --since 2026-02-15T10:00:00Z
```

### Output

Path to the exported `.aegx.zip` file.

---

## `openclaw-aer verify`

Verify an exported AER evidence bundle.

### Usage

```bash
openclaw-aer verify <BUNDLE_PATH>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `BUNDLE_PATH` | Yes | Path to the `.aegx.zip` file |

### Output (Pass)

```
Valid: true
Records checked: 42
Audit entries checked: 42
Blobs checked: 5
PASS: Bundle integrity verified.
```

### Output (Fail)

```
Valid: false
Errors:
  - RecordHashMismatch: record 3 hash does not match
FAIL: Bundle integrity check failed.
```

---

## `openclaw-aer report`

Generate or display a Markdown report from an evidence bundle.

### Usage

```bash
openclaw-aer report <BUNDLE_PATH>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `BUNDLE_PATH` | Yes | Path to the `.aegx.zip` file |

If the bundle already contains `report.md`, it is displayed. Otherwise a new report is generated from the records and audit log.

---

## openclaw-aer Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Any error (invalid arguments, I/O failure, verification failure) |
