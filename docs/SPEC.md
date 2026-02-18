# AEGX v0.1 Format Specification

> **Copyright 2026 Daniel Foo Jun Wei / Provenable.ai. All rights reserved.**
>
> This specification is the original intellectual property of Daniel Foo Jun Wei /
> Provenable.ai. It is provided for reference purposes only. You may NOT use this
> specification to create independent or competing implementations of the AEGX
> format without prior written permission from Daniel Foo Jun Wei / Provenable.ai.
>
> The source code implementing this specification is separately licensed under
> Apache License 2.0. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE) for details.
>
> "Provenable.ai", "AEGX", and "AER" are trademarks of Daniel Foo Jun Wei /
> Provenable.ai. For licensing inquiries: licensing@provenable.ai

**Version:** 0.1
**Status:** Draft
**Date:** 2026-02-15
**Owner:** Provenable.ai

## 1. Overview

AEGX (Agent Evidence eXchange) is a tamper-evident, append-only evidence bundle
format designed for agentic AI systems. An AEGX bundle captures a complete,
verifiable record of agent sessions, tool invocations, file mutations, guard
decisions, and control-plane changes.

Every record in a bundle is content-addressed via SHA-256 over a deterministic
canonical JSON representation. An append-only hash chain (the audit log) links
all records together so that any insertion, deletion, or modification of records
is detectable.

## 2. Bundle Container

An AEGX bundle can exist in two physical forms:

### 2.1 Directory Form

A directory with the following layout:

```
<bundle>/
  manifest.json
  records.jsonl
  audit-log.jsonl
  blobs/
    <sha256-hex>
    <sha256-hex>
    ...
```

- `manifest.json` -- Bundle metadata (see Section 3).
- `records.jsonl` -- One TypedRecord per line in JSON Lines format (see Section 4).
- `audit-log.jsonl` -- One AuditEntry per line in JSON Lines format (see Section 5).
- `blobs/` -- Content-addressed blob store (see Section 8).

### 2.2 Zip Form

A zip archive (conventionally named `*.aegx.zip`) containing the same layout.
The archive MUST use deflate compression. Path separators inside the zip MUST
use forward slashes (`/`). The archive MUST NOT contain entries with absolute
paths, path traversal components (`..`), or entries that resolve outside the
bundle root.

When importing a zip, implementations MUST validate that no entry path escapes
the extraction root.

## 3. manifest.json

The manifest is a single JSON object at the bundle root. It declares the bundle
version, algorithm parameters, and summary counters.

### 3.1 Schema

JSON Schema: `schemas/manifest.schema.json`

### 3.2 Fields

| Field              | Type     | Required | Description                                                                 |
|--------------------|----------|----------|-----------------------------------------------------------------------------|
| `aegx_version`     | string   | Yes      | MUST be `"0.1"`.                                                            |
| `created_at`       | string   | Yes      | RFC 3339 timestamp in UTC with second precision, trailing `Z`. Example: `"2026-02-15T12:00:00Z"`. |
| `hash_alg`         | string   | Yes      | MUST be `"sha256"`.                                                         |
| `canonicalization`  | string   | Yes      | MUST be `"AEGX_CANON_0_1"`.                                                |
| `root_records`     | string[] | Yes      | Array of `recordId` values (64 lowercase hex chars) for records with no parents. |
| `record_count`     | integer  | Yes      | Total number of records in `records.jsonl`. Minimum 0.                      |
| `blob_count`       | integer  | Yes      | Total number of files in `blobs/`. Minimum 0.                               |
| `audit_head`       | string   | Yes      | The `entryHash` of the last entry in `audit-log.jsonl`, or the zero hash if the log is empty. 64 lowercase hex chars. |
| `meta`             | object   | No       | Optional free-form metadata about the bundle.                               |
| `extensions`       | object   | No       | Optional extension data. Reserved for future use.                           |

No additional properties are allowed.

### 3.3 Zero Hash

The zero hash is 64 zero characters:

```
0000000000000000000000000000000000000000000000000000000000000000
```

It is used as the `audit_head` when the audit log is empty, and as the `prev`
field of the first audit entry.

### 3.4 Example

```json
{
  "aegx_version": "0.1",
  "created_at": "2026-02-15T12:00:00Z",
  "hash_alg": "sha256",
  "canonicalization": "AEGX_CANON_0_1",
  "root_records": [
    "a1b2c3d4e5f6..."
  ],
  "record_count": 5,
  "blob_count": 1,
  "audit_head": "f6e5d4c3b2a1..."
}
```

## 4. records.jsonl -- TypedRecord Format

Records are stored in JSON Lines format: one JSON object per line, no trailing
commas, no multi-line formatting. Blank lines are ignored during parsing.

### 4.1 Schema

JSON Schema: `schemas/record.schema.json`

### 4.2 TypedRecord Fields

| Field        | Type     | Required | Description                                                                 |
|--------------|----------|----------|-----------------------------------------------------------------------------|
| `recordId`   | string   | Yes      | SHA-256 hex digest (64 chars) computed per Section 7.                       |
| `type`       | string   | Yes      | One of the record types listed in Section 4.3.                              |
| `principal`  | string   | Yes      | One of the principal identifiers listed in Section 4.4.                     |
| `taint`      | string[] | Yes      | Array of taint labels. May be empty.                                        |
| `parents`    | string[] | Yes      | Array of `recordId` values this record depends on. May be empty.            |
| `meta`       | object   | Yes      | Metadata object. MUST contain a `ts` field (RFC 3339 UTC timestamp, second precision, trailing `Z`). |
| `payload`    | object   | Yes      | Either an inline payload or a blob reference (see Section 4.5).             |
| `schema`     | string   | No       | Schema version. When present, MUST be `"0.1"`.                             |
| `extensions` | object   | No       | Optional extension data.                                                    |

No additional properties are allowed.

### 4.3 Record Types

The `type` field MUST be one of the following values:

| Type                         | Description                                                     |
|------------------------------|-----------------------------------------------------------------|
| `SessionStart`               | Marks the beginning of an agent session.                        |
| `SessionMessage`             | A message within a session (user prompt, assistant response).   |
| `ToolCall`                   | An agent's invocation of a tool.                                |
| `ToolResult`                 | The result returned by a tool.                                  |
| `FileRead`                   | A file read operation performed by the agent.                   |
| `FileWrite`                  | A file write operation performed by the agent.                  |
| `FileDelete`                 | A file deletion performed by the agent.                         |
| `ControlPlaneChangeRequest`  | A request to modify control-plane state (skills, tools, etc.).  |
| `MemoryCommitRequest`        | A request to write to persistent workspace memory.              |
| `GuardDecision`              | A CPI or MI guard's allow/deny decision.                        |
| `Snapshot`                   | A verifiable snapshot of system state.                          |
| `Rollback`                   | A rollback to a previously captured snapshot.                   |
| `NetworkRequest`               | An outbound network request made by the agent or a tool.        |

### 4.4 Principals

The `principal` field MUST be one of the following values:

| Principal   | Description                                                       |
|-------------|-------------------------------------------------------------------|
| `USER`      | The human user directly interacting with the agent.               |
| `SYS`       | The system or platform itself (e.g., startup, scheduled tasks).   |
| `WEB`       | Input originating from a web source.                              |
| `TOOL`      | A tool invoked by the agent.                                      |
| `SKILL`     | A skill (higher-level capability) invoked by the agent.           |
| `CHANNEL`   | Input from a communication channel (e.g., Slack, email).          |
| `EXTERNAL`  | Any other external entity.                                        |

Principals determine trust level for CPI and MI guard enforcement. `USER` and
`SYS` are trusted principals. All others are untrusted by default.

### 4.5 Payload

The `payload` field is a JSON object matching exactly one of two forms:

**Inline payload:**

```json
{
  "inline": <any JSON value>
}
```

The `inline` field may contain any valid JSON value (object, array, string,
number, boolean, null). No additional properties are allowed on the payload
object.

**Blob reference:**

```json
{
  "blob": "<sha256-hex>",
  "mime": "<MIME type>",
  "size": <integer>
}
```

- `blob`: The SHA-256 hex digest of the blob file content. MUST match the
  filename in the `blobs/` directory.
- `mime`: The MIME type of the blob content (e.g., `"application/octet-stream"`).
- `size`: The size of the blob in bytes. MUST be >= 0.

No additional properties are allowed on the payload object.

### 4.6 Example Record

```json
{"recordId":"a1b2c3...","type":"ToolCall","principal":"USER","taint":[],"parents":[],"meta":{"ts":"2026-02-15T12:00:00Z","tool":"grep"},"payload":{"inline":{"query":"TODO"}},"schema":"0.1"}
```

## 5. audit-log.jsonl -- Audit Chain

The audit log is a hash chain stored in JSON Lines format. Each entry links a
record to the chain via a cryptographic hash that includes the previous entry's
hash, creating an append-only tamper-evident sequence.

### 5.1 Schema

JSON Schema: `schemas/audit-entry.schema.json`

### 5.2 AuditEntry Fields

| Field       | Type    | Required | Description                                                                 |
|-------------|---------|----------|-----------------------------------------------------------------------------|
| `idx`       | integer | Yes      | Zero-based index of this entry in the chain. MUST equal the entry's line position. |
| `ts`        | string  | Yes      | RFC 3339 timestamp in UTC with second precision, trailing `Z`.              |
| `recordId`  | string  | Yes      | The `recordId` of the record this entry corresponds to. 64 lowercase hex chars. |
| `prev`      | string  | Yes      | The `entryHash` of the preceding entry, or the zero hash for the first entry. 64 lowercase hex chars. |
| `entryHash` | string  | Yes      | SHA-256 hex digest computed per Section 5.3. 64 lowercase hex chars.        |

No additional properties are allowed.

### 5.3 entryHash Computation

```
entryHash = SHA-256( AEGX_CANON_0_1({ "idx": <idx>, "ts": <ts>, "recordId": <recordId>, "prev": <prev> }) )
```

The input to SHA-256 is the AEGX_CANON_0_1 canonical form (see Section 6) of a
JSON object containing exactly the four fields `idx`, `ts`, `recordId`, and
`prev`.

### 5.4 Chain Rules

1. The first entry (idx=0) MUST have `prev` equal to the zero hash.
2. For all subsequent entries, `prev` MUST equal the `entryHash` of the
   immediately preceding entry.
3. The `idx` field MUST be sequential starting from 0 with no gaps.
4. The `audit_head` in `manifest.json` MUST equal the `entryHash` of the last
   entry in the chain, or the zero hash if the chain is empty.

### 5.5 Example Chain

```json
{"idx":0,"ts":"2026-02-15T12:00:00Z","recordId":"a1b2...","prev":"0000...0000","entryHash":"f1e2..."}
{"idx":1,"ts":"2026-02-15T12:00:01Z","recordId":"b2c3...","prev":"f1e2...","entryHash":"d3c4..."}
```

## 6. AEGX_CANON_0_1 Canonicalization

AEGX_CANON_0_1 is the deterministic JSON canonicalization algorithm used for
all hash computations in AEGX v0.1. It ensures that semantically identical JSON
values always produce identical byte sequences.

### 6.1 Rules

1. **Encoding:** Output MUST be UTF-8.
2. **Object key ordering:** Object keys MUST be sorted lexicographically by
   their Unicode code points (i.e., byte-wise sort of UTF-8 representation).
   This applies recursively to all nested objects.
3. **No insignificant whitespace:** No whitespace between tokens. No space
   after `:` or `,`. No leading or trailing whitespace.
4. **Array order preserved:** Array elements MUST appear in their original order.
5. **NaN and Infinity forbidden:** JSON values MUST NOT contain NaN or Infinity.
   (Standard JSON already forbids these.)
6. **Negative zero normalization:** The floating-point value `-0.0` MUST be
   serialized as `0`, not `-0` or `-0.0`.
7. **String NFC normalization:** All string values (including object keys) MUST
   be normalized to Unicode NFC (Canonical Decomposition followed by Canonical
   Composition) before serialization.
8. **String escaping:** Control characters below U+0020 MUST be escaped as
   `\uXXXX`. The characters `"` and `\` MUST be escaped as `\"` and `\\`.
   Newlines, carriage returns, and tabs MUST be escaped as `\n`, `\r`, `\t`.
9. **Boolean and null literals:** Serialized as `true`, `false`, `null`.
10. **Integer representation:** Integers MUST be serialized without a decimal
    point or exponent.

### 6.2 Timestamp Normalization

Timestamps appearing in the `meta.ts` field of records MUST be normalized to
UTC with second precision and a trailing `Z` suffix before being included in
canonical JSON for `recordId` computation. For example:

- `"2026-02-15T00:00:00+00:00"` becomes `"2026-02-15T00:00:00Z"`
- `"2026-02-15T05:30:00+05:30"` becomes `"2026-02-15T00:00:00Z"`

This normalization is applied to the `meta` object before canonicalization, not
by the canonicalization algorithm itself.

### 6.3 Example

Given the input:

```json
{ "b": 1, "a": [3, 1, 2], "c": { "z": true, "a": null } }
```

The AEGX_CANON_0_1 output is:

```
{"a":[3,1,2],"b":1,"c":{"a":null,"z":true}}
```

## 7. RecordId Computation

The `recordId` of a TypedRecord is the SHA-256 hex digest of the AEGX_CANON_0_1
canonical form of a specific subset of the record's fields.

### 7.1 Input Object

The canonical JSON input is constructed from the following fields:

```json
{
  "type": <record type string>,
  "principal": <principal string>,
  "taint": <taint array>,
  "parents": <parents array>,
  "meta": <meta object, with ts normalized>,
  "payload": <payload object>,
  "schema": "0.1"
}
```

Note:
- The `recordId` field itself is NOT included in the hash input (it is the
  output).
- The `extensions` field is NOT included in the hash input.
- The `meta.ts` timestamp MUST be normalized per Section 6.2 before inclusion.
- The `schema` field is always `"0.1"` in the hash input, regardless of whether
  the record has a `schema` field.

### 7.2 Computation

```
recordId = lowercase_hex( SHA-256( AEGX_CANON_0_1( input_object ) ) )
```

The result is a 64-character lowercase hexadecimal string.

### 7.3 Example

For a record with:
- `type`: `"SessionStart"`
- `principal`: `"USER"`
- `taint`: `[]`
- `parents`: `[]`
- `meta`: `{"ts": "2026-02-15T12:00:00Z"}`
- `payload`: `{"inline": {}}`

The canonical input is:

```
{"meta":{"ts":"2026-02-15T12:00:00Z"},"parents":[],"payload":{"inline":{}},"principal":"USER","schema":"0.1","taint":[],"type":"SessionStart"}
```

The `recordId` is the SHA-256 hex digest of that byte string.

## 8. Blob Integrity

Large or binary payloads are stored as files in the `blobs/` directory. Each
blob file is content-addressed: its filename IS its SHA-256 hex digest.

### 8.1 Rules

1. The filename of each blob MUST be the lowercase SHA-256 hex digest (64
   characters) of the file's content.
2. When a record references a blob via `payload.blob`, the value MUST match
   both the filename and the computed SHA-256 of the file content.
3. The `payload.size` field MUST match the actual byte length of the blob file.
4. No two blob files may exist with the same name but different content (this
   is inherently enforced by content-addressing, but implementations MUST
   verify on write).
5. Blob files MUST NOT have subdirectories within `blobs/`. All blobs reside
   directly in `blobs/`.
6. The file named `.keep` in `blobs/` is reserved and excluded from blob
   counts.

### 8.2 Adding a Blob

To add a blob:

1. Read the file content.
2. Compute `hash = lowercase_hex(SHA-256(content))`.
3. If `blobs/<hash>` already exists, verify the existing file has identical
   content. If content differs, reject (this indicates a hash collision or
   corruption).
4. Write the content to `blobs/<hash>`.
5. Reference the blob in a record's payload with `"blob": "<hash>"`.

## 9. Verification Procedure

A compliant verifier MUST perform all of the following checks. If any check
fails, the bundle MUST be reported as invalid. Verification checks MUST be
performed in an order that allows the verifier to report all errors, not just
the first.

### 9.1 Steps

1. **Read and validate manifest.json** against the manifest JSON schema. If
   the file is missing or unparseable, report IO error.

2. **Read and validate records.jsonl.** Parse each line as a TypedRecord and
   validate against the record JSON schema.

3. **Read and validate audit-log.jsonl.** Parse each line as an AuditEntry and
   validate against the audit entry JSON schema.

4. **Recompute recordId** for every record using the algorithm in Section 7.
   Compare against the stored `recordId`. Report mismatches.

5. **Validate parent references.** For every `parents` entry in every record,
   verify that the referenced `recordId` exists in the records file.

6. **Validate blob references.** For every record with a blob payload:
   - Verify the blob file exists at `blobs/<blob>`.
   - Read the blob file content and compute its SHA-256 hash.
   - Verify the computed hash matches the filename and the `payload.blob` value.

7. **Verify audit chain.** For every audit entry:
   - Verify `idx` is sequential starting from 0.
   - Verify `prev` matches the `entryHash` of the preceding entry (or the
     zero hash for idx=0).
   - Recompute `entryHash` per Section 5.3 and verify it matches.
   - Verify the final `entryHash` matches `manifest.audit_head`.

8. **Verify record_count.** The `record_count` in manifest.json MUST equal
   the number of records in records.jsonl.

9. **Verify blob_count.** The `blob_count` in manifest.json MUST equal the
   number of files in `blobs/` (excluding `.keep`).

10. **Verify root_records.** Every `recordId` listed in `root_records` MUST
    exist in records.jsonl.

### 9.2 Exit Codes

| Code | Meaning              |
|------|----------------------|
| 0    | Verification passed  |
| 2    | Verification failure |
| 3    | Schema validation failure |
| 4    | IO error             |

### 9.3 Verifying a Zip Bundle

To verify a zip bundle:

1. Extract the zip to a temporary directory. During extraction, reject any
   entry whose path contains `..` or resolves outside the extraction root.
2. Verify the extracted directory per the steps above.
3. Clean up the temporary directory.

## 10. Conformance

An implementation is conformant with AEGX v0.1 if:

1. It produces bundles that pass the verification procedure in Section 9.
2. Its canonicalization produces byte-identical output to the reference
   implementation for all valid JSON inputs.
3. It rejects bundles that fail any verification check.
4. It correctly handles all record types and principals defined in this
   specification.

## 11. Security Considerations

See [THREAT_MODEL.md](THREAT_MODEL.md) for a detailed threat analysis. Key
considerations:

- SHA-256 is the sole hash algorithm in v0.1. No algorithm agility is provided.
- The audit chain provides tamper evidence, not tamper prevention. An attacker
  with write access can rebuild the chain; detection requires an external
  witness (e.g., a trusted timestamp or out-of-band head commitment).
- Canonicalization determinism is critical. Any deviation in canonical form
  breaks recordId verification. Implementations MUST use the exact rules in
  Section 6.
- Blob integrity depends on SHA-256 collision resistance. See the threat model
  for collision considerations.

## 12. Empirical Validation

The AEGX + AER implementation has been validated against the ZeroLeaks
attack taxonomy (zeroleaks.ai), which tested 36 attack vectors across prompt
injection (23 attacks) and system prompt extraction (13 attacks).

### 12.1 Benchmark Methodology

Attack payloads were reconstructed from the ZeroLeaks OpenClaw Security
Assessment and run through the actual AER scanner and output guard code.
No mocking or simulation — the real detection functions process real attack
strings. The benchmark test is at `packages/aer/tests/zeroleaks_benchmark.rs`.

### 12.2 Results Summary

| Layer | Metric | v0.1.1 | v0.1.2 | v0.1.3 | v0.1.4 (Current) |
|-------|--------|--------|--------|--------|-------------------|
| Input Scanner | Extraction attacks blocked/tainted | 8/13 (61.5%) | **11/13 (84.6%)** | 11/13 | 11/13 (84.6%) |
| Input Scanner | Injection attacks blocked/tainted | 22/23 (95.7%) | 22/23 | 22/23 | 22/23 (95.7%) |
| Output Guard | Leaked response patterns caught | 11/11 (100%) | 11/11 | 11/11 | 11/11 (100%) |
| Output Guard | False positive rate | 0% | 0% | 0% | 0% |
| Combined | ZLSS (1-10, lower=better) | 2/10 | **1/10** | 1/10 | **1/10** |
| Combined | Security Score (0-100) | 79/100 | **90/100** | 90/100 | **90/100** |
| Skill Verifier | ClawHavoc attack vectors detected | — | — | **6/6** | 6/6 |
| Rollback Policy | Auto-recovery mechanisms | — | — | — | **3 (auto-snapshot, recommendation, auto-rollback)** |
| MI Read-Side | Reader principal taint tracking | — | — | — | **Tracked** |
| Test Suite | Total tests passing | 114 | 152 | 168 | **278** |

### 12.3 Theorem Coverage

Each detection category and defense layer is grounded in a published formal
theorem or a derived corollary:

**Base theorems:**
- **Noninterference Theorem**: EncodedPayload, IndirectInjection, ManyShotPriming, FormatOverride
- **CPI Theorem**: SystemImpersonation, BehaviorManipulation
- **MI Theorem**: ExtractionAttempt, FalseContextInjection (+ Noninterference)
- **RVU Machine Unlearning**: All GuardDecision records feed the contamination DAG

**Corollaries (v0.1.2):**
- **Conversational Noninterference**: Session-level taint accumulation for crescendo detection
- **CPI Behavioral Constraint**: Canary injection → INJECTION_SUSPECT (control-plane mutation)
- **MI Dynamic Token Discovery**: Runtime watchlist from actual system prompt
- **Semantic Intent Detection**: Regex verb+target matching (Noninterference extension)

**Supply-Chain Defense (v0.1.3):**
- **Skill Verifier**: Pre-install scanning for all 6 ClawHavoc attack vectors (CPI + Noninterference)
- **Evidence Chain**: Every skill verification emits a tamper-evident GuardDecision record (RVU)

**Automated Recovery & Theorem Gap Closures (v0.1.4):**
- **Auto-Snapshot Before CPI**: `auto_snapshot_before_cpi()` creates rollback point before every allowed CPI mutation (RVU §2)
- **Rollback Recommendation**: `on_guard_denial()` at 3+ denials emits recommendation alert (RVU §3)
- **Threshold Auto-Rollback**: 5+ denials in 120s triggers automatic rollback + CRITICAL alert (RVU §4)
- **Contamination Scope**: `compute_contamination_scope()` BFS on provenance DAG (RVU closure)
- **MI Read-Side Taint**: `read_memory_file()` now tracks reader principal; untrusted readers get tainted provenance (MI + Noninterference conservative-union)
- **Agent Notification**: `/prove` includes `rollback_status.agent_messages` (all four theorems)

**Host Environment Hardening (v0.1.6):**
- **System Prompt Registry**: `SystemPromptRegistry` singleton caches system prompt tokens for dynamic output guard discovery (MI Dynamic Discovery Corollary)
- **File Read Guard**: `FileReadGuard` blocks/taints sensitive file reads for untrusted principals (MI read-side + Noninterference)
- **Network Egress Monitor**: `NetworkGuard` evaluates outbound requests against domain blocklist/allowlist (Noninterference + CPI)
- **Sandbox Audit**: `SandboxAudit` verifies container/seccomp/namespace at session start (CPI + RVU)
- **Scanner Extensions**: `SensitiveFileContent` and `DataExfiltration` categories (MI + Noninterference)

### 12.4 Known Limitations

1. Regex intent detection only — no LLM-based semantic understanding
2. Benchmark tests individual messages — multi-turn detection verified separately
3. Adversarial prompt evolution may outpace static regex patterns
4. Benchmark measures detection, not LLM compliance with attacks
5. ~~No file-read guards~~ — **Addressed (v0.1.6):** `FileReadGuard` blocks/taints sensitive file reads; scanner `SensitiveFileContent` category catches leaked credentials
6. ~~No outbound network monitoring~~ — **Addressed (v0.1.6):** `NetworkGuard` provides policy-layer domain blocklist/allowlist; full enforcement requires OS-level egress proxy
7. Session state is in-memory only — server restart loses crescendo detection state
8. Auto-rollback requires a prior snapshot to exist — if no snapshot was created, auto-rollback cannot execute

## 13. References

- [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) -- Date and Time on the Internet: Timestamps
- [Unicode NFC](https://unicode.org/reports/tr15/) -- Unicode Normalization Forms
- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12/json-schema-core.html)
- [SHA-256](https://csrc.nist.gov/publications/detail/fips/180/4/final) -- FIPS 180-4 Secure Hash Standard
