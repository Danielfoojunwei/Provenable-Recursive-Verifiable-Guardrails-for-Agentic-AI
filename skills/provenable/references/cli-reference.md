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

**Record types:** SessionStart, SessionMessage, ToolCall, ToolResult, FileRead, FileWrite, FileDelete, ControlPlaneChangeRequest, MemoryCommitRequest, GuardDecision, Snapshot, Rollback

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

Categories: CpiViolation, MiViolation, TaintBlock, ProxyMisconfig, RateLimitExceeded, InjectionSuspect

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
