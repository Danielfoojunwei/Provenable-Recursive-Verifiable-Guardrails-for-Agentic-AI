# AEGX v0.1 Threat Model

**Version:** 0.1
**Date:** 2026-02-15

## 1. Scope

This document describes the threat model for the AEGX v0.1 evidence bundle
format. It covers attacks against the integrity, authenticity, and consistency
of AEGX bundles. It does NOT cover threats to the runtime agent itself (those
are addressed by CPI/MI guards and the formal theorems) -- only threats to the
evidence format.

## 2. Threat Actors

| Actor         | Capability                                                        |
|---------------|-------------------------------------------------------------------|
| Compromised Agent | Can write arbitrary data to the bundle directory during a session. |
| Local Attacker    | Has filesystem access to the bundle after export.                |
| Network Attacker  | Can intercept or modify bundles in transit (zip files).           |
| Malicious Tool    | A tool that attempts to inject or modify evidence records.       |

## 3. Threats

### 3.1 Tampering with Records

**Threat:** An attacker modifies, inserts, or deletes records in
`records.jsonl` after they have been written.

**Mitigations:**

- **RecordId recomputation.** Each record's `recordId` is a SHA-256 hash of
  its canonical content. Any modification to a record's type, principal, taint,
  parents, meta, or payload changes the recordId, which is detected during
  verification (step 4 of the verification procedure).

- **Audit chain binding.** Each record is referenced by an audit entry whose
  `entryHash` includes the `recordId`. Modifying a recordId invalidates the
  corresponding audit entry and all subsequent entries in the chain.

- **Record count.** The `record_count` in the manifest must match the actual
  number of records. Inserting or deleting records without updating the
  manifest is detected.

**Residual risk:** An attacker with write access can modify a record AND
rebuild the entire audit chain AND update the manifest to produce a
consistent-but-forged bundle. Mitigation requires an external witness such as a
trusted timestamp service or out-of-band commitment of the `audit_head`.

### 3.2 Tampering with the Audit Chain

**Threat:** An attacker modifies `audit-log.jsonl` to remove, reorder, or
alter entries.

**Mitigations:**

- **Sequential index validation.** The `idx` field must be sequential starting
  from 0 with no gaps. Any reordering or deletion is detected.

- **Hash chain.** Each entry's `prev` field must equal the preceding entry's
  `entryHash`. Modifying or removing any entry breaks the chain at that point
  and at all subsequent entries.

- **Entry hash recomputation.** The `entryHash` is recomputed from `idx`, `ts`,
  `recordId`, and `prev`. Any modification to these fields is detected.

- **Manifest audit_head.** The manifest records the head of the chain. If the
  chain is modified, the head changes and no longer matches the manifest.

**Residual risk:** Full chain reconstruction (same as 3.1). The audit chain
provides tamper evidence, not tamper prevention.

### 3.3 Tampering with Blobs

**Threat:** An attacker replaces or modifies a blob file in the `blobs/`
directory.

**Mitigations:**

- **Content addressing.** Each blob's filename IS its SHA-256 hash. Modifying
  the content of a blob changes its hash, which no longer matches the filename.
  Verification recomputes the hash of every blob and compares it to the
  filename.

- **Record binding.** The `payload.blob` field in the referencing record must
  match the blob filename and the computed hash. Changing a blob breaks this
  binding.

**Residual risk:** An attacker could replace a blob AND forge a new record with
the new blob hash AND rebuild the audit chain. Same external witness
requirement.

### 3.4 Schema Validation Attacks

**Threat:** A malformed record or manifest passes validation due to
insufficiently strict schemas, allowing injection of unexpected data.

**Mitigations:**

- **Strict schemas.** All three JSON schemas (manifest, record, audit entry)
  set `additionalProperties: false`. No unexpected fields can be added.

- **Enum constraints.** The `type` and `principal` fields use strict `enum`
  constraints. Only the defined values are accepted.

- **Pattern constraints.** Hash fields (`recordId`, `prev`, `entryHash`,
  `audit_head`, `blob`) are constrained to `^[0-9a-f]{64}$`. Timestamps are
  constrained to `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`.

- **oneOf payload.** The payload field uses `oneOf` to enforce that exactly one
  of inline or blob payload is present, each with its own required fields and
  no additional properties.

**Residual risks:**

- The `meta` object and `inline` payload are open-ended by design. Malicious
  content in these fields is not prevented by schema validation. Consumers must
  treat these as untrusted data.

- Schema validation does not verify semantic correctness (e.g., that a
  `ToolResult` record actually follows a `ToolCall`). Semantic validation is
  the responsibility of higher-level processing.

### 3.5 Hash Collision Considerations

**Threat:** An attacker produces two different records or blobs with the same
SHA-256 hash, allowing substitution without detection.

**Analysis:**

- SHA-256 provides 128 bits of collision resistance. As of 2026, no practical
  collision attack against SHA-256 is known. The best known attack is generic
  birthday at 2^128 operations.

- Unlike SHA-1 (which has known chosen-prefix collisions), SHA-256 has no
  known structural weaknesses.

- The AEGX format does not support algorithm agility in v0.1. If SHA-256 is
  weakened in the future, a new format version will be required.

**Mitigations:**

- Use of SHA-256 (no known practical attacks).
- Content-addressing of blobs with hash verification on both write and read.
- RecordId computation over canonical JSON ensures the hash input is
  deterministic and unambiguous.

**Residual risk:** Theoretical. If SHA-256 collision resistance is broken, the
entire integrity model fails. Monitoring cryptographic research is required.

### 3.6 Canonicalization Attacks

**Threat:** Two semantically equivalent JSON values produce different canonical
byte sequences, or two different JSON values produce the same canonical bytes,
leading to recordId collisions or verification failures.

**Mitigations:**

- **Deterministic key sorting.** Object keys are sorted lexicographically by
  Unicode code points, which is equivalent to byte-wise UTF-8 sorting. This is
  unambiguous and locale-independent.

- **NFC normalization.** All strings (keys and values) are NFC-normalized
  before serialization. This prevents attacks using Unicode normalization
  differences (e.g., composed vs. decomposed characters).

- **Negative zero normalization.** `-0.0` is normalized to `0`, preventing
  IEEE 754 negative zero from causing different byte representations.

- **No whitespace.** Eliminating whitespace removes a source of
  non-determinism across implementations.

- **Timestamp normalization.** Timestamps are normalized to UTC `Z` form before
  hash computation, preventing timezone representation differences.

**Residual risks:**

- **Floating-point precision.** Different implementations may serialize
  floating-point numbers with different precision. AEGX v0.1 relies on
  serde_json's default number serialization. Interoperability with non-Rust
  implementations requires matching this behavior exactly.

- **Unicode edge cases.** While NFC normalization handles most cases, some
  exotic Unicode sequences may behave differently across Unicode versions.
  Implementations should use a well-tested Unicode normalization library.

- **Homoglyph attacks.** NFC normalization does not prevent visual confusion
  attacks using homoglyphs (e.g., Latin 'a' vs. Cyrillic 'a'). These are
  relevant if record content is displayed to humans for review.

### 3.7 Zip-Based Attacks

**Threat:** A malicious `*.aegx.zip` file exploits zip parsing to compromise
the system extracting it.

#### 3.7.1 Path Traversal (Zip Slip)

**Threat:** A zip entry with a path like `../../etc/passwd` or an absolute path
like `/tmp/evil` causes extraction outside the intended directory.

**Mitigations:**

- Implementations MUST validate that no zip entry path contains `..`
  components or begins with `/`.
- Implementations MUST verify that the resolved extraction path is within the
  target directory.
- The reference implementation uses the `zip` crate's default extraction which
  preserves entry names but the caller must validate paths.

#### 3.7.2 Zip Bomb

**Threat:** A highly compressed zip file expands to consume excessive disk
space or memory.

**Mitigations:**

- Implementations SHOULD impose a maximum uncompressed size limit when
  extracting bundles.
- Implementations SHOULD impose a maximum number of entries.
- The `blob_count` and `record_count` fields in the manifest provide
  expected counts that can be checked before full extraction.

#### 3.7.3 Duplicate Entries

**Threat:** A zip file contains multiple entries with the same name, and
different zip libraries resolve the conflict differently (some use first, some
use last).

**Mitigations:**

- Implementations SHOULD reject zip files with duplicate entry names.
- The reference implementation uses sequential extraction which overwrites
  duplicates with the last entry. This is consistent but not ideal.

#### 3.7.4 Symlink Attacks

**Threat:** A zip entry is a symbolic link pointing outside the bundle,
allowing reads or writes to arbitrary files.

**Mitigations:**

- Implementations MUST NOT create symbolic links when extracting AEGX bundles.
- Implementations SHOULD reject zip entries that are symbolic links.

#### 3.7.5 Filename Encoding

**Threat:** Zip entry names use different encodings (CP437, UTF-8, etc.),
causing path misinterpretation.

**Mitigations:**

- AEGX zip files MUST use UTF-8 for all entry names.
- Implementations SHOULD reject entries with non-UTF-8 names.

## 4. Trust Boundaries

```
+---------------------------+
|  Bundle Producer          |
|  (Agent + AER runtime)    |
+---------------------------+
            |
            | writes bundle (directory or zip)
            v
+---------------------------+
|  Bundle at Rest           |
|  (filesystem / storage)   |
+---------------------------+
            |
            | read + verify
            v
+---------------------------+
|  Bundle Consumer          |
|  (verifier, auditor, UI)  |
+---------------------------+
```

Key trust boundaries:

1. **Producer to storage:** The producer writes records, audit entries, and
   blobs. Once written, these are subject to tampering at rest.

2. **Storage to consumer:** The consumer reads and verifies the bundle. The
   verification procedure detects tampering but cannot prevent it.

3. **External witness:** For non-repudiation, the `audit_head` should be
   committed to an external witness (e.g., a transparency log, a blockchain
   anchor, or a trusted timestamp authority). This is outside the scope of
   AEGX v0.1 but is recommended for production deployments.

## 5. Assumptions

1. SHA-256 is collision-resistant and preimage-resistant.
2. The host operating system provides reliable filesystem operations.
3. The producer runtime (agent + AER) is not fully compromised at the time of
   writing. (A fully compromised producer can forge any evidence. The formal
   theorems provide guarantees about runtime integrity.)
4. The verification implementation correctly implements the AEGX_CANON_0_1
   algorithm and SHA-256.

## 6. Recommendations

1. **External audit_head commitment.** Publish or commit the `audit_head`
   hash to an external, append-only store after each bundle export.

2. **Transport encryption.** Use TLS or equivalent when transmitting
   `*.aegx.zip` files over a network.

3. **Access control.** Restrict filesystem permissions on bundle directories
   to prevent unauthorized modification.

4. **Size limits.** Enforce maximum sizes for blobs, records, and zip files
   to prevent resource exhaustion.

5. **Fuzz testing.** Fuzz the JSON parser, canonical serializer, and zip
   extractor to find edge cases. (See `fuzz/` directory.)

6. **Pin dependencies.** Use locked dependency versions to prevent supply
   chain attacks on cryptographic libraries.
