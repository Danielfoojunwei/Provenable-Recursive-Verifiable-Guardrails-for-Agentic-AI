# Bundle Format Guide

A visual, plain-language walkthrough of every file in an AEGX bundle. For the formal specification see [SPEC.md](SPEC.md).

---

## Table of Contents

1. [Bundle Directory Layout](#1-bundle-directory-layout)
2. [manifest.json](#2-manifestjson)
3. [records.jsonl](#3-recordsjsonl)
4. [audit-log.jsonl](#4-audit-logjsonl)
5. [blobs/](#5-blobs)
6. [How It All Connects](#6-how-it-all-connects)
7. [Zip Archive Format](#7-zip-archive-format)
8. [AER Bundle Extensions](#8-aer-bundle-extensions)

---

## 1. Bundle Directory Layout

```
my_session.aegx/
├── manifest.json         ← metadata + counters + integrity anchor
├── records.jsonl         ← one TypedRecord per line (the event log)
├── audit-log.jsonl       ← one hash-chain entry per line (tamper detection)
└── blobs/                ← content-addressed binary storage
    ├── a1b2c3d4e5...     ← file named by SHA-256 of its contents
    └── f6a7b8c9d0...
```

Every file has a specific role. Together, they form a self-contained, independently verifiable evidence package.

---

## 2. manifest.json

The manifest is the bundle's "header". It contains metadata and integrity anchors.

### Example

```json
{
  "aegx_version": "0.1",
  "created_at": "2026-02-15T10:00:00Z",
  "algorithm": "SHA-256",
  "canonicalization": "AEGX_CANON_0_1",
  "record_count": 3,
  "blob_count": 1,
  "audit_head": "f1e2d3c4b5a6978869504132abcdef1234567890abcdef1234567890abcdef12",
  "root_records": [
    "aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd"
  ]
}
```

### Field-by-Field

| Field | Type | What It Means |
|-------|------|---------------|
| `aegx_version` | `"0.1"` | Format version. Always `"0.1"` for this spec. |
| `created_at` | ISO 8601 string | When the bundle was created (UTC, `Z` suffix). |
| `algorithm` | `"SHA-256"` | Hash algorithm used for all content addressing. |
| `canonicalization` | `"AEGX_CANON_0_1"` | The deterministic JSON serialization algorithm. |
| `record_count` | integer | Exact number of records in `records.jsonl`. |
| `blob_count` | integer | Exact number of files in `blobs/`. |
| `audit_head` | 64-char hex | The `entryHash` of the **last** audit entry. This is the integrity anchor — if it matches, the entire chain is intact. |
| `root_records` | array of hex strings | Record IDs that have no parents (the DAG roots). |

### Why It Matters

The verifier uses `record_count`, `blob_count`, and `audit_head` to detect insertions, deletions, and modifications without re-checking every entry from scratch.

---

## 3. records.jsonl

Each line is a JSON object — one **TypedRecord** per line. This is the event log.

### Example (3 records)

```jsonl
{"recordId":"aabb...","type":"SessionStart","principal":"SYS","taint":[],"parents":[],"meta":{"ts":"2026-02-15T10:00:00Z","agent":"my-agent"},"payload":{"inline":{"reason":"user request"}},"schema":"0.1"}
{"recordId":"ccdd...","type":"SessionMessage","principal":"USER","taint":[],"parents":["aabb..."],"meta":{"ts":"2026-02-15T10:00:05Z"},"payload":{"inline":{"content":"Hello"}},"schema":"0.1"}
{"recordId":"eeff...","type":"FileRead","principal":"TOOL","taint":[],"parents":["ccdd..."],"meta":{"ts":"2026-02-15T10:00:10Z","path":"config.yaml"},"payload":{"blob":"a1b2c3...","mime":"text/yaml","size":2048},"schema":"0.1"}
```

### Field-by-Field

| Field | Type | What It Means |
|-------|------|---------------|
| `recordId` | 64-char hex | `SHA-256(AEGX_CANON_0_1({type, principal, taint, parents, meta, payload, schema}))`. Content-derived — if any field changes, the ID changes. |
| `type` | string enum | What kind of action this records: `SessionStart`, `SessionMessage`, `ToolCall`, `ToolResult`, `FileRead`, `FileWrite`, `FileDelete`, `ControlPlaneChangeRequest`, `MemoryCommitRequest`, `GuardDecision`, `Snapshot`, `Rollback` |
| `principal` | string enum | Who produced this record: `USER`, `SYS`, `WEB`, `TOOL`, `SKILL`, `CHANNEL`, `EXTERNAL` |
| `taint` | string array | Taint labels propagated from inputs (e.g., `["UNTRUSTED", "WEB_DERIVED"]`). Empty array if clean. |
| `parents` | string array | RecordIds of causal parents. Empty for root records. Creates a DAG. |
| `meta` | JSON object | Metadata. Always includes `ts` (timestamp). May include `agent`, `session_id`, `tool_id`, `path`. |
| `payload` | JSON object | Either `{"inline": <json>}` for small payloads or `{"blob": "<sha256>", "mime": "<type>", "size": <n>}` for large/binary content. |
| `schema` | `"0.1"` | Schema version of this record. |

### The DAG Structure

Records form a directed acyclic graph through `parents`:

```
SessionStart (aabb...)     ← root, parents=[]
    │
    ▼
SessionMessage (ccdd...)   ← parents=["aabb..."]
    │
    ▼
FileRead (eeff...)         ← parents=["ccdd..."]
```

This lets you trace any action back to the session root.

---

## 4. audit-log.jsonl

Each line is a hash-chain entry. This is the tamper-detection layer.

### Example (3 entries)

```jsonl
{"idx":0,"ts":"2026-02-15T10:00:00Z","recordId":"aabb...","prev":"0000000000000000000000000000000000000000000000000000000000000000","entryHash":"1111..."}
{"idx":1,"ts":"2026-02-15T10:00:05Z","recordId":"ccdd...","prev":"1111...","entryHash":"2222..."}
{"idx":2,"ts":"2026-02-15T10:00:10Z","recordId":"eeff...","prev":"2222...","entryHash":"3333..."}
```

### Field-by-Field

| Field | Type | What It Means |
|-------|------|---------------|
| `idx` | integer | Sequential index starting at 0. Any gap means entries were inserted or deleted. |
| `ts` | ISO 8601 | Timestamp of the entry. |
| `recordId` | 64-char hex | The record this entry refers to. |
| `prev` | 64-char hex | The `entryHash` of the **previous** entry. Entry 0 uses `"0"×64`. |
| `entryHash` | 64-char hex | `SHA-256(idx || "||" || ts || "||" || recordId || "||" || prev)`. This chains the entry to all previous entries. |

### How the Chain Works

```
Entry 0:  prev = 000...000     entryHash = SHA-256("0||2026-..||aabb..||000...000")  = 1111...
Entry 1:  prev = 1111...       entryHash = SHA-256("1||2026-..||ccdd..||1111...")     = 2222...
Entry 2:  prev = 2222...       entryHash = SHA-256("2||2026-..||eeff..||2222...")     = 3333...
                                                                                       ↑
                                                                         manifest.audit_head = 3333...
```

If **any** entry is modified, its `entryHash` changes, which breaks the `prev` link in the next entry, which changes that entry's hash, and so on. A single bit flip is detectable.

---

## 5. blobs/

The `blobs/` directory stores large or binary payloads. Each file is named by the SHA-256 hex hash of its contents.

```
blobs/
  a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2
  f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7
```

### How Blobs Connect to Records

A record with a blob payload references it by hash:

```json
{
  "payload": {
    "blob": "a1b2c3d4e5f6...",
    "mime": "text/yaml",
    "size": 2048
  }
}
```

The verifier checks:
1. The file `blobs/a1b2c3d4e5f6...` exists
2. `SHA-256(file_contents)` == `a1b2c3d4e5f6...`

### When to Use Blobs vs Inline

| Payload | Approach |
|---------|----------|
| JSON ≤ 4096 bytes | Use `"inline"` |
| JSON > 4096 bytes | Store as blob |
| Binary data (images, PDFs, executables) | Always use blob |
| Source code files | Use blob |

---

## 6. How It All Connects

```
┌─────────────────────────────────────────────────────────┐
│                    manifest.json                         │
│  record_count=3, blob_count=1, audit_head="3333..."     │
│  root_records=["aabb..."]                                │
└──────────────────┬──────────────────────────────────────┘
                   │ counters must match
                   ▼
┌──────────────────────────────┐    ┌─────────────────────┐
│       records.jsonl          │    │   audit-log.jsonl    │
│                              │    │                      │
│  Line 1: {recordId:"aabb"}  │◄──►│  Entry 0: aabb       │
│  Line 2: {recordId:"ccdd"}  │◄──►│  Entry 1: ccdd       │
│  Line 3: {recordId:"eeff",  │◄──►│  Entry 2: eeff       │
│    blob:"a1b2..."}          │    │    audit_head ──────┐ │
└──────────┬───────────────────┘    └─────────────────────┘
           │ blob reference                               │
           ▼                          must match          ▼
┌──────────────────────┐        ┌──────────────────────────┐
│       blobs/         │        │  manifest.audit_head     │
│  a1b2c3...  ◄────────│        │  == last entryHash       │
│  (SHA-256 = filename)│        └──────────────────────────┘
└──────────────────────┘
```

**Integrity guarantees at each layer:**

1. **Records:** `recordId` = hash of content → content cannot change
2. **Audit chain:** each entry hashes to the next → entries cannot be reordered, inserted, or deleted
3. **Blobs:** filename = hash of bytes → blob content cannot change
4. **Manifest:** counters and audit_head must match reality → nothing can be added or removed silently

---

## 7. Zip Archive Format

When exported with `aegx export`, the bundle becomes a `.aegx.zip` file with the same internal structure:

```
my_session.aegx.zip
├── manifest.json
├── records.jsonl
├── audit-log.jsonl
└── blobs/
    └── a1b2c3...
```

**Security measures during import:**
- Path traversal prevention (no `../` paths)
- Zip bomb mitigation (size limits)
- Duplicate entry rejection
- Symlink rejection
- UTF-8 encoding validation

---

## 8. AER Bundle Extensions

AER bundles (exported by `openclaw-aer bundle export`) include additional files:

```
incident.aegx.zip
├── manifest.json        ← extended with bundle_id, filters
├── records.jsonl        ← may include AER-specific types (FileRename)
├── audit-log.jsonl
├── blobs/
├── policy.yaml          ← CPI/MI policy in effect at export time
├── report.md            ← human-readable incident report
└── report.json          ← machine-readable incident report
```

### AER manifest.json Extensions

```json
{
  "bundle_id": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2026-02-15T12:00:00Z",
  "format_version": "0.1",
  "record_count": 42,
  "audit_entry_count": 42,
  "blob_count": 5,
  "filters": {
    "agent_id": "my-agent-v1",
    "since_time": "2026-02-15T10:00:00Z",
    "since_snapshot": null
  }
}
```

### AER Taint Flags

AER records may carry taint flags in their `taint` array:

| Flag | Meaning |
|------|---------|
| `UNTRUSTED` | Source is not trusted |
| `INJECTION_SUSPECT` | Content may contain injection attempts |
| `PROXY_DERIVED` | Came through a reverse proxy |
| `SECRET_RISK` | May contain secrets |
| `CROSS_SESSION` | Originated from a different session |
| `TOOL_OUTPUT` | Produced by a tool |
| `SKILL_OUTPUT` | Produced by a skill |
| `WEB_DERIVED` | Originated from the web |

---

## Next Steps

- [AEGX v0.1 Specification](SPEC.md) — formal specification
- [Verification Guide](VERIFICATION_GUIDE.md) — what verify checks
- [AER Bundle Format](aer-bundle-format.md) — AER-specific details
- [CPI/MI Guard Rules](aer-cpi-mi-rules.md) — trust lattice and policy
