# Troubleshooting

Common errors, their causes, and fixes for both the `aegx` and `openclaw-aer` CLIs.

---

## Table of Contents

1. [Build Errors](#1-build-errors)
2. [aegx CLI Errors](#2-aegx-cli-errors)
3. [Verification Failures](#3-verification-failures)
4. [openclaw-aer Errors](#4-openclaw-aer-errors)
5. [Snapshot and Rollback Issues](#5-snapshot-and-rollback-issues)
6. [Bundle Export/Import Issues](#6-bundle-exportimport-issues)

---

## 1. Build Errors

### `error: could not compile`

```
error[E0308]: mismatched types
   --> src/...
```

**Cause:** Wrong Rust version.

**Fix:**

```bash
rustup update stable
rustc --version
# Needs: 1.75.0 or later
```

### `error: failed to select a version for ...`

**Cause:** Missing or outdated `Cargo.lock`.

**Fix:**

```bash
cargo update
cargo build --release --locked
```

### `linker 'cc' not found`

**Cause:** C compiler / build tools not installed.

**Fix:**

```bash
# Debian/Ubuntu
sudo apt-get install build-essential

# macOS
xcode-select --install

# Fedora
sudo dnf install gcc make
```

### `cargo: command not found`

**Cause:** Rust toolchain not installed or not on PATH.

**Fix:**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

---

## 2. aegx CLI Errors

### `error: must specify --inline or --blob/--mime/--size`

**Cause:** `add-record` requires either an inline payload or a blob reference. Neither was provided.

**Fix:** Add `--inline '{}'` for an inline payload, or `--blob <hash> --mime <type> --size <bytes>` for a blob.

### `error: invalid meta JSON: ...`

**Cause:** The `--meta` argument is not valid JSON.

**Fix:** Ensure the JSON is properly quoted. Use single quotes around the JSON string in bash:

```bash
# Correct
--meta '{"ts":"2026-02-15T10:00:00Z"}'

# Wrong (double quotes conflict with bash)
--meta "{"ts":"2026-02-15T10:00:00Z"}"
```

### `error: invalid inline JSON: ...`

**Cause:** Same as above but for the `--inline` argument.

**Fix:** Same — use single quotes.

### `error: Unknown variant <TYPE>`

**Cause:** Invalid record type string.

**Fix:** Use one of: `SessionStart`, `SessionMessage`, `ToolCall`, `ToolResult`, `FileRead`, `FileWrite`, `FileDelete`, `ControlPlaneChangeRequest`, `MemoryCommitRequest`, `GuardDecision`, `Snapshot`, `Rollback`. These are case-sensitive.

### `error: Unknown variant <PRINCIPAL>`

**Cause:** Invalid principal string.

**Fix:** Use one of: `USER`, `SYS`, `WEB`, `TOOL`, `SKILL`, `CHANNEL`, `EXTERNAL`. These are case-sensitive and uppercase.

### `Initialized bundle: ... ` but no output from add-record

**Cause:** The `add-record` command prints only the recordId to stdout. If you piped stderr somewhere, the errors are hidden.

**Fix:** Check stderr:

```bash
aegx add-record ... 2>&1
```

---

## 3. Verification Failures

### `Verification: PASS` does not print

If `aegx verify` exits silently with a non-zero code, errors are on stderr.

**Fix:**

```bash
aegx verify my_bundle 2>&1
echo "Exit code: $?"
```

### `recordId mismatch: expected=..., got=...`

**Cause:** A record in `records.jsonl` was modified after creation.

**What happened:** Someone (or something) edited the JSON in `records.jsonl`. The stored `recordId` no longer matches `SHA-256(canonical(record_fields))`.

**Fix:** If you created this bundle, re-create it from scratch. If you received it, **reject it — it has been tampered with**.

### `audit entry N: expected prev=..., got prev=...`

**Cause:** The audit chain is broken. An entry was inserted, deleted, or reordered.

**Fix:** **Reject the bundle.** The audit chain cannot be repaired without the original data.

### `blob file ... content does not match filename hash`

**Cause:** A blob file was modified after being added.

**Fix:** **Reject the bundle** or re-add the blob from the original file:

```bash
aegx add-blob my_bundle /path/to/original/file
```

### `manifest record_count=N but found M records`

**Cause:** Records were added or removed without updating the manifest.

**Fix:** If you created this bundle, re-run the operation that builds it. If you received it, **reject it**.

### `schema validation failed`

**Cause:** A record, manifest, or audit entry has a structural problem (missing field, wrong type, extra field).

**Fix:** Check the file against the JSON Schema in `schemas/`. Common issues:
- Missing `"ts"` in meta
- Extra fields (the schemas use `additionalProperties: false`)
- Wrong type for a field (e.g., string instead of integer)

---

## 4. openclaw-aer Errors

### `AER: not initialized`

**Cause:** `openclaw-aer init` has not been run yet.

**Fix:**

```bash
openclaw-aer init
```

### `Bundle not found: <path>`

**Cause:** The specified `.aegx.zip` file does not exist at the given path.

**Fix:** Check the path. Use `ls` to find the correct bundle:

```bash
ls ~/.openclaw/.aer/bundles/
```

### `Invalid timestamp '<ts>': ...`

**Cause:** The `--since` flag received a timestamp that is not valid RFC 3339.

**Fix:** Use the format `YYYY-MM-DDTHH:MM:SSZ`:

```bash
# Correct
--since "2026-02-15T10:00:00Z"

# Wrong
--since "2026-02-15 10:00:00"
--since "Feb 15, 2026"
```

### `Unknown scope: <scope>. Use: full, control-plane, memory`

**Cause:** Invalid `--scope` value for `snapshot create`.

**Fix:** Use one of: `full`, `control-plane` (or `cp`), `memory` (or `mem`).

---

## 5. Snapshot and Rollback Issues

### No snapshots found

**Cause:** No snapshots have been created yet.

**Fix:**

```bash
openclaw-aer snapshot create "my-snapshot" --scope full
```

### Rollback reports "state already matches snapshot"

**Cause:** The current files already match the snapshot. No changes needed.

**This is not an error.** The system is already in the desired state.

### Rollback FAIL

**Cause:** One or more files could not be restored to their snapshotted state.

**Possible reasons:**
- File permissions prevent writing
- Disk is full
- Directory structure was deleted

**Fix:** Check the error details in the rollback report. Fix the underlying issue (permissions, disk space) and retry.

### Rollback does not undo external API calls

**This is by design.** Rollback restores file content only. It cannot reverse:
- HTTP requests already sent
- Database writes
- Messages posted to Slack, email, etc.
- Files deleted outside the managed workspace

**Mitigation:** Create snapshots **before** irreversible actions, not after.

---

## 6. Bundle Export/Import Issues

### `aegx export` produces an empty zip

**Cause:** The bundle directory is empty (no records added after init).

**Fix:** Add at least one record before exporting.

### `aegx import` fails with path traversal error

**Cause:** The zip contains entries with `../` in their paths.

**This is a security violation.** The zip was likely crafted maliciously. **Do not trust it.**

### Zip is too large to import

**Cause:** Zip bomb or very large bundle.

**Fix:** Check the zip size before importing:

```bash
unzip -l suspect.aegx.zip | tail -1
# Check the total uncompressed size
```

If the uncompressed size is unreasonable, **do not import it**.

### Permission denied during import

**Cause:** The output directory is not writable.

**Fix:**

```bash
ls -la /path/to/parent/
# Check write permissions
```

---

## Getting More Help

- [Installation Guide](INSTALL.md) — build from source
- [CLI Reference](CLI_REFERENCE.md) — every command and flag
- [Verification Guide](VERIFICATION_GUIDE.md) — what verify checks
- [AEGX Specification](SPEC.md) — formal format details
- [Threat Model](THREAT_MODEL.md) — security assumptions and guarantees
- File an issue: https://github.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI/issues
