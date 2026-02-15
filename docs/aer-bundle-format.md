# AEGX Bundle Format v0.1

## Overview

An AEGX (Agent Evidence eXchange) bundle is a ZIP archive (`.aegx.zip`) containing tamper-evident evidence from agent sessions. The bundle is self-contained and independently verifiable.

## File Structure

```
bundle.aegx.zip
├── manifest.json         # Bundle metadata
├── records.jsonl         # Evidence records (one JSON per line)
├── audit-log.jsonl       # Append-only hash chain entries
├── blobs/                # Large payloads referenced by hash
│   ├── <sha256-hash>     # Binary blob files
│   └── ...
├── policy.yaml           # Policy pack in effect during recording
├── report.md             # Human-readable summary report
└── report.json           # Machine-readable summary report
```

## manifest.json

```json
{
  "bundle_id": "uuid-v4",
  "created_at": "2025-01-01T00:00:00Z",
  "format_version": "0.1",
  "record_count": 42,
  "audit_entry_count": 42,
  "blob_count": 3,
  "filters": {
    "agent_id": "optional-agent-filter",
    "since_time": "optional-iso8601",
    "since_snapshot": "optional-snapshot-id"
  }
}
```

## Record Format (records.jsonl)

Each line is a JSON object:

```json
{
  "record_id": "<sha256-hex-64-chars>",
  "record_type": "ToolCall",
  "principal": "User",
  "taint": 0,
  "parents": ["<parent-record-id>"],
  "meta": {
    "ts": "2025-01-01T00:00:00Z",
    "agent_id": "agent-1",
    "session_id": "session-1",
    "tool_id": "read_file"
  },
  "payload": {
    "kind": "inline",
    "data": { "path": "/tmp/test.txt" }
  }
}
```

### Record Types

| Type | Description |
|------|-------------|
| `SessionStart` | Agent session initiated |
| `SessionMessage` | Message in a session |
| `ToolCall` | Tool invocation request |
| `ToolResult` | Tool invocation result |
| `FileRead` | File read operation |
| `FileWrite` | File write operation |
| `FileDelete` | File deletion |
| `FileRename` | File rename |
| `ControlPlaneChangeRequest` | Control-plane mutation attempt |
| `MemoryCommitRequest` | Memory write attempt |
| `GuardDecision` | CPI/MI guard allow/deny |
| `Snapshot` | Snapshot creation |
| `Rollback` | Rollback execution |

### Record ID Computation

```
record_id = SHA-256( canonical(payload) || canonical(meta) )
```

Canonicalization sorts object keys lexicographically, removes whitespace, and uses deterministic JSON serialization.

### Payload Variants

**Inline** (for payloads <= 4096 bytes):
```json
{ "kind": "inline", "data": { ... } }
```

**Blob reference** (for larger payloads):
```json
{ "kind": "blob", "hash": "<sha256>", "size": 12345 }
```

Blob files are stored under `blobs/<sha256>`.

## Audit Chain (audit-log.jsonl)

Each line is a chain entry:

```json
{
  "idx": 0,
  "ts": "2025-01-01T00:00:00Z",
  "record_id": "<sha256>",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "entry_hash": "<sha256>"
}
```

### Chain Integrity

```
entry_hash = SHA-256( idx || "||" || ts || "||" || record_id || "||" || prev_hash )
```

- Entry 0 has `prev_hash` = all zeros (genesis)
- Each subsequent entry links to the previous entry's `entry_hash`
- Any modification breaks the chain and is detectable

## Verification Algorithm

1. For each record in `records.jsonl`:
   - Recompute `record_id` from canonical payload + meta
   - Compare with stored `record_id`
   - If payload is a blob reference, verify blob hash

2. For `audit-log.jsonl`:
   - Verify sequential indices (0, 1, 2, ...)
   - Verify `prev_hash` linkage
   - Recompute each `entry_hash` and compare

3. For blobs:
   - Verify SHA-256 hash matches filename

## JSON Schemas

Machine-readable schemas for validation:
- `schemas/record.schema.json`
- `schemas/manifest.schema.json`
- `schemas/policy.schema.json`
