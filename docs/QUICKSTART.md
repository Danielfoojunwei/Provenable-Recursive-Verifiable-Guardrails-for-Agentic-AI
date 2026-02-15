# AEGX Quickstart: Your First Bundle in 5 Minutes

This tutorial walks you through creating, populating, exporting, and verifying an AEGX evidence bundle. Every command is real -- copy-paste and run.

**Prerequisite:** You have built `aegx` per [INSTALL.md](INSTALL.md). The examples assume `aegx` is on your PATH. If not, replace `aegx` with `./target/release/aegx`.

---

## Step 1: Initialize a Bundle

```bash
aegx init my_session.aegx
```

Output:

```
Initialized bundle: my_session.aegx
```

This creates:

```
my_session.aegx/
  manifest.json       # bundle metadata (version, counters, audit head)
  records.jsonl       # empty, will hold typed records
  audit-log.jsonl     # empty, will hold hash-chained audit entries
  blobs/              # empty directory for binary content
```

---

## Step 2: Add a Record (Inline Payload)

Record a session start event:

```bash
aegx add-record my_session.aegx \
  --type SessionStart \
  --principal SYS \
  --meta '{"ts":"2026-02-15T10:00:00Z","agent":"my-agent-v1"}' \
  --inline '{"reason":"user initiated session"}'
```

Output: a 64-character hex string -- the record's unique content-addressed ID.

```
a1b2c3d4...  (64 hex chars)
```

Save it for later:

```bash
RECORD1=$(aegx add-record my_session.aegx \
  --type SessionStart \
  --principal SYS \
  --meta '{"ts":"2026-02-15T10:00:00Z","agent":"my-agent-v1"}' \
  --inline '{"reason":"user initiated session"}')
echo "First record: $RECORD1"
```

---

## Step 3: Add a Second Record with a Parent

Chain a message to the session start:

```bash
RECORD2=$(aegx add-record my_session.aegx \
  --type SessionMessage \
  --principal USER \
  --meta '{"ts":"2026-02-15T10:00:05Z"}' \
  --parents "$RECORD1" \
  --inline '{"content":"Hello, can you help me refactor auth.rs?"}')
echo "Second record: $RECORD2"
```

The `--parents` flag creates a DAG edge from this record back to RECORD1.

---

## Step 4: Add a Binary Blob

Suppose your agent reads a file. First add the file as a blob:

```bash
# Create a sample file
echo "fn main() { println!(\"hello\"); }" > sample.rs

# Add it to the bundle
BLOB_HASH=$(aegx add-blob my_session.aegx sample.rs)
echo "Blob hash: $BLOB_HASH"
```

The blob is copied into `my_session.aegx/blobs/<sha256>`.

Now create a FileRead record referencing the blob:

```bash
FILE_SIZE=$(wc -c < sample.rs | tr -d ' ')
RECORD3=$(aegx add-record my_session.aegx \
  --type FileRead \
  --principal TOOL \
  --meta '{"ts":"2026-02-15T10:00:10Z","path":"sample.rs"}' \
  --parents "$RECORD2" \
  --blob "$BLOB_HASH" \
  --mime "text/x-rust" \
  --size "$FILE_SIZE")
echo "Third record: $RECORD3"
```

---

## Step 5: Verify the Bundle

```bash
aegx verify my_session.aegx
```

Expected output:

```
Verification: PASS
```

This checked:
- manifest.json matches the JSON schema
- Every record matches the record schema
- Every audit entry matches the audit schema
- Every recordId was recomputed and matched
- Parent references all point to existing records
- The blob file hash matches its filename and the record's blob reference
- The audit hash chain is intact
- record_count and blob_count in manifest match reality

---

## Step 6: Export to a Portable Zip

```bash
aegx export my_session.aegx my_session.aegx.zip
```

Output:

```
Exported: my_session.aegx.zip
```

This zip can be sent to anyone for independent verification.

---

## Step 7: Import and Re-Verify

Simulate receiving the zip:

```bash
aegx import my_session.aegx.zip imported_session.aegx
aegx verify imported_session.aegx
```

Expected output:

```
Imported: imported_session.aegx
Verification: PASS
```

---

## Step 8: Summarize

```bash
aegx summarize my_session.aegx
```

Output:

```
Records: 3
By type:
  FileRead: 1
  SessionMessage: 1
  SessionStart: 1
By principal:
  SYS: 1
  TOOL: 1
  USER: 1
Verification: PASS
```

---

## Step 9: Detect Tampering (Demo)

Try editing a record and re-verifying:

```bash
# Copy the bundle
cp -r my_session.aegx tampered.aegx

# Tamper with the second record's payload
# (Change "Hello" to "XXXXX" in records.jsonl line 2)
sed -i '2s/Hello/XXXXX/' tampered.aegx/records.jsonl

# Verify -- will fail
aegx verify tampered.aegx
echo "Exit code: $?"
```

Expected output:

```
records.jsonl line 2: recordId mismatch: expected=..., got=...
Exit code: 2
```

The verifier detected the tampering because the content changed but the recordId was not updated.

---

## What You Built

```
my_session.aegx/
  manifest.json          # version=0.1, record_count=3, blob_count=1, audit_head=<hash>
  records.jsonl          # 3 records: SessionStart -> SessionMessage -> FileRead
  audit-log.jsonl        # 3 hash-chained audit entries
  blobs/
    <sha256-of-sample>   # raw bytes of sample.rs
```

Every record has a deterministic content-addressed ID. Every audit entry chains to the previous one via hash. Every blob is named by its SHA-256. If any byte changes, `aegx verify` will catch it.

---

## Next Steps

- [CLI Reference](CLI_REFERENCE.md) - all commands and flags
- [Agent Integration Guide](AGENT_INTEGRATION.md) - embed AEGX in your agent
- [Format Specification](SPEC.md) - full technical details
- [Verification Guide](VERIFICATION_GUIDE.md) - what verify checks and how
