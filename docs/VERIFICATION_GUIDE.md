# Verification Guide

This document explains exactly what `aegx verify` checks, in what order, and how to interpret every possible error.

---

## Table of Contents

1. [Quick Verification](#1-quick-verification)
2. [The 11 Verification Steps](#2-the-11-verification-steps)
3. [Error Messages and Fixes](#3-error-messages-and-fixes)
4. [Exit Codes](#4-exit-codes)
5. [Verifying AER Bundles](#5-verifying-aer-bundles)
6. [Programmatic Verification](#6-programmatic-verification)
7. [What Verification Proves](#7-what-verification-proves)
8. [What Verification Does NOT Prove](#8-what-verification-does-not-prove)

---

## 1. Quick Verification

```bash
# Verify a bundle directory
aegx verify my_session.aegx

# Verify a zip (import first)
aegx import my_session.aegx.zip /tmp/check && aegx verify /tmp/check

# Verify an AER evidence bundle
openclaw-aer verify incident.aegx.zip
```

If the output is `Verification: PASS` and the exit code is `0`, the bundle is intact.

---

## 2. The 11 Verification Steps

The verifier runs these checks in order. It collects all errors and reports them together rather than stopping at the first failure.

### Step 1: Manifest Schema Validation

**What:** `manifest.json` is loaded and validated against `manifest.schema.json`.

**Checks:**
- File exists and is valid JSON
- Required fields present: `aegx_version`, `created_at`, `algorithm`, `canonicalization`, `record_count`, `blob_count`, `audit_head`, `root_records`
- `aegx_version` = `"0.1"`
- `algorithm` = `"SHA-256"`
- `canonicalization` = `"AEGX_CANON_0_1"`
- No extra fields (`additionalProperties: false`)

### Step 2: Record Schema Validation

**What:** Every line in `records.jsonl` is validated against `record.schema.json`.

**Checks:**
- Each line is valid JSON
- Required fields: `recordId`, `type`, `principal`, `taint`, `parents`, `meta`, `payload`
- `type` is one of the 12 allowed values
- `principal` is one of: `USER`, `SYS`, `WEB`, `TOOL`, `SKILL`, `CHANNEL`, `EXTERNAL`
- `taint` is an array of strings
- `parents` is an array of strings
- `payload` is either `{"inline": ...}` or `{"blob": ..., "mime": ..., "size": ...}`

### Step 3: Audit Entry Schema Validation

**What:** Every line in `audit-log.jsonl` is validated against `audit-entry.schema.json`.

**Checks:**
- Each line is valid JSON
- Required fields: `idx`, `ts`, `recordId`, `prev`, `entryHash`
- `idx` is a non-negative integer
- `prev` and `entryHash` are 64-character hex strings

### Step 4: RecordId Recomputation

**What:** For each record, recompute `recordId = SHA-256(AEGX_CANON_0_1({type, principal, taint, parents, meta, payload, schema}))` and compare.

**Checks:**
- Computed recordId matches stored recordId exactly
- Canonicalization is deterministic (sorted keys, NFC normalization, no whitespace)

### Step 5: Audit Chain Index Continuity

**What:** Audit entries must have sequential indices starting at 0.

**Checks:**
- First entry has `idx = 0`
- Each subsequent entry has `idx = previous_idx + 1`

### Step 6: Audit Chain Hash Linking

**What:** Each audit entry's `prev` field must match the `entryHash` of the previous entry. The first entry's `prev` must be `"0"` repeated 64 times.

**Checks:**
- Entry 0: `prev == "0000000000000000000000000000000000000000000000000000000000000000"`
- Entry N: `prev == entries[N-1].entryHash`

### Step 7: Audit EntryHash Recomputation

**What:** Recompute `entryHash = SHA-256(idx || "||" || ts || "||" || recordId || "||" || prev)` and compare.

**Checks:**
- Computed entryHash matches stored entryHash exactly

### Step 8: Parent Reference Validation

**What:** Every recordId listed in a record's `parents` array must exist as a record in the bundle.

**Checks:**
- All parent IDs resolve to existing records
- No dangling references

### Step 9: Blob Integrity

**What:** Every blob file in `blobs/` is re-hashed and compared to its filename. Every blob reference in a record must have a corresponding file.

**Checks:**
- `SHA-256(file_bytes) == filename` for every file in `blobs/`
- Every record with a blob payload has a matching file

### Step 10: Manifest Counter Validation

**What:** The counters in `manifest.json` must match the actual data.

**Checks:**
- `record_count` == number of lines in `records.jsonl`
- `blob_count` == number of files in `blobs/`
- `audit_head` == `entryHash` of the last audit entry

### Step 11: Root Records Validation

**What:** Every ID in `manifest.root_records` must exist and have no parents.

**Checks:**
- Each root record ID resolves to an existing record
- Each referenced record has an empty `parents` array

---

## 3. Error Messages and Fixes

### RecordId Mismatch

```
records.jsonl line 2: recordId mismatch: expected=abc..., got=def...
```

**Cause:** A record's content was modified after it was created (the stored recordId no longer matches the hash of the record's fields).

**Fix:** The record was tampered with. If you produced this bundle, re-create it from scratch. If you received it, reject it.

### Audit Chain Break

```
audit entry 5: expected prev=111..., got prev=222...
```

**Cause:** An audit entry was inserted, deleted, or reordered.

**Fix:** The audit log was tampered with. Reject the bundle.

### EntryHash Mismatch

```
audit entry 3: entryHash mismatch: expected=aaa..., got=bbb...
```

**Cause:** An audit entry's fields were modified after it was appended.

**Fix:** The audit log was tampered with. Reject the bundle.

### Blob Hash Mismatch

```
blob file abc123... content does not match filename hash
```

**Cause:** A blob file's content was changed but the filename was not updated.

**Fix:** The blob store was tampered with. Reject the bundle.

### Missing Blob

```
record references blob abc123... but file not found in blobs/
```

**Cause:** A blob file was deleted from the bundle.

**Fix:** The bundle is incomplete. Reject it or request a fresh export.

### Dangling Parent

```
record xyz... references parent abc... which does not exist
```

**Cause:** A parent record was deleted from the bundle.

**Fix:** The bundle is incomplete. Reject it.

### Counter Mismatch

```
manifest record_count=5 but found 4 records
```

**Cause:** Records were added or removed without updating the manifest.

**Fix:** The manifest was tampered with. Reject the bundle.

### Schema Validation Error

```
manifest.json: missing required field "aegx_version"
```

**Cause:** The manifest (or a record or audit entry) does not match the JSON Schema.

**Fix:** The file was malformed. If you produced it, check your tooling. If you received it, reject it.

---

## 4. Exit Codes

| Code | Name | When |
|------|------|------|
| 0 | Pass | All 11 checks passed |
| 2 | Verification Failure | Hash mismatch, chain break, counter mismatch, dangling ref |
| 3 | Schema Failure | JSON Schema validation failed for manifest, record, or audit entry |
| 4 | I/O Error | Bundle directory not found, file unreadable, permission denied |

### Programmatic Usage

```bash
aegx verify "$BUNDLE"
CODE=$?

if [ "$CODE" -eq 0 ]; then
  echo "Bundle is intact and trustworthy"
elif [ "$CODE" -eq 2 ]; then
  echo "TAMPERED: Do not trust this bundle"
elif [ "$CODE" -eq 3 ]; then
  echo "MALFORMED: Schema validation failed"
elif [ "$CODE" -eq 4 ]; then
  echo "IO ERROR: Cannot read bundle"
fi
```

---

## 5. Verifying AER Bundles

AER bundles (`.aegx.zip` files exported by `openclaw-aer bundle export`) are verified with:

```bash
openclaw-aer verify path/to/bundle.aegx.zip
```

This runs the same checks plus AER-specific validations:
- Record count matches
- Audit chain integrity
- Blob integrity

**Output on pass:**

```
Valid: true
Records checked: 42
Audit entries checked: 42
Blobs checked: 5
PASS: Bundle integrity verified.
```

**Output on fail:**

```
Valid: false
Errors:
  - RecordHashMismatch: record 3 hash does not match
FAIL: Bundle integrity check failed.
```

AER verify uses exit code `0` for pass and `1` for any failure.

---

## 6. Programmatic Verification

### From Rust

The verification logic is available as a library:

```rust
use aegx::verify;

let result = verify::verify_bundle(std::path::Path::new("my_session.aegx"));

if result.is_ok() {
    println!("PASS");
} else {
    for error in &result.errors {
        eprintln!("{}", error);
    }
    std::process::exit(result.exit_code);
}
```

### From Any Language (via CLI)

Shell out to `aegx verify` and check the exit code. The CLI is the canonical verification interface.

```python
import subprocess

result = subprocess.run(["aegx", "verify", "bundle.aegx"], capture_output=True, text=True)
if result.returncode == 0:
    print("PASS")
else:
    print(f"FAIL (code {result.returncode}): {result.stderr}")
```

---

## 7. What Verification Proves

When `aegx verify` returns exit code 0:

- **No record was modified** after creation (recordId = hash of content)
- **No record was inserted or deleted** (audit chain would break)
- **No audit entry was tampered with** (entryHash = hash of entry fields, prev links to prior)
- **No blob was modified** (filename = SHA-256 of content)
- **No blob was deleted** (records reference blobs that exist)
- **The manifest accurately reflects** the bundle contents (counts, audit head, roots)

---

## 8. What Verification Does NOT Prove

- **Correctness of the recorded actions** — verification confirms the log is intact, not that the agent did the right thing
- **Identity of the producer** — AEGX v0.1 does not include digital signatures; it guarantees integrity, not authenticity
- **Completeness** — if the producer omitted actions from the log, verification cannot detect what was never recorded
- **Confidentiality** — bundle contents are not encrypted; anyone with the file can read it

For producer identity, combine AEGX bundles with an external signature or witness commitment (see [Threat Model](THREAT_MODEL.md) for recommendations).

---

## Next Steps

- [CLI Reference](CLI_REFERENCE.md) — complete command documentation
- [Bundle Format Guide](BUNDLE_FORMAT_GUIDE.md) — visual walkthrough of every file
- [Threat Model](THREAT_MODEL.md) — security analysis
- [Troubleshooting](TROUBLESHOOTING.md) — common errors and fixes
