# Troubleshooting

Common errors, their causes, and fixes for the unified `aegx` CLI.

---

## Table of Contents

1. [Build Errors](#1-build-errors)
2. [Initialization and Status Errors](#2-initialization-and-status-errors)
3. [Verification Failures](#3-verification-failures)
4. [Snapshot and Rollback Issues](#4-snapshot-and-rollback-issues)
5. [Bundle Export Issues](#5-bundle-export-issues)
6. [Guard Surface Errors](#6-guard-surface-errors)
7. [Prove Query Issues](#7-prove-query-issues)

---

## 1. Build Errors

### `error: could not compile`

```
error[E0308]: mismatched types
   --> src/...
```

**Cause:** Wrong Rust version. AEGX requires Rust 1.75.0 or later.

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

## 2. Initialization and Status Errors

### `AEGX: not initialized`

**Cause:** `aegx init` has not been run yet.

**Fix:**

```bash
aegx init
```

### `Bundle not found: <path>`

**Cause:** The specified `.aegx.zip` file does not exist at the given path.

**Fix:** Check the path. Use `ls` to find the correct bundle:

```bash
ls ~/.proven/.aer/bundles/
```

### `Invalid timestamp '<ts>': ...`

**Cause:** The `--since` or `--until` flag received a timestamp that is not valid RFC 3339.

**Fix:** Use the format `YYYY-MM-DDTHH:MM:SSZ`:

```bash
# Correct
--since "2026-02-15T10:00:00Z"

# Wrong
--since "2026-02-15 10:00:00"
--since "Feb 15, 2026"
```

### `Unknown scope: <scope>. Use: full, control-plane, memory`

**Cause:** Invalid `--scope` value for `aegx snapshot create`.

**Fix:** Use one of: `full`, `control-plane` (or `cp`), `memory` (or `mem`).

---

## 3. Verification Failures

### `Verification: PASS` does not print

If `aegx verify` exits silently with a non-zero code, errors are on stderr.

**Fix:**

```bash
aegx verify my_bundle.aegx.zip 2>&1
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

**Fix:** **Reject the bundle.** If you created it, re-export with `aegx bundle export`.

### `manifest record_count=N but found M records`

**Cause:** Records were added or removed without updating the manifest.

**Fix:** If you created this bundle, re-export it. If you received it, **reject it**.

### `schema validation failed`

**Cause:** A record, manifest, or audit entry has a structural problem (missing field, wrong type, extra field).

**Fix:** Check the file against the JSON Schema in `schemas/`. Common issues:
- Missing `"ts"` in meta
- Extra fields (the schemas use `additionalProperties: false`)
- Wrong type for a field (e.g., string instead of integer)

---

## 4. Snapshot and Rollback Issues

### No snapshots found

**Cause:** No snapshots have been created yet.

**Fix:**

```bash
aegx snapshot create "my-snapshot" --scope full
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

## 5. Bundle Export Issues

### `aegx bundle export` produces an empty bundle

**Cause:** No guard events have been recorded yet (no tool calls, no guard decisions).

**Fix:** Use the system first — initialize, create snapshots, or run `aegx prove` to generate some records, then export.

### Path traversal error during verification

**Cause:** The zip contains entries with `../` in their paths.

**This is a security violation.** The zip was likely crafted maliciously. **Do not trust it.**

### Zip is too large to verify

**Cause:** Zip bomb or very large bundle.

**Fix:** Check the zip size before verifying:

```bash
unzip -l suspect.aegx.zip | tail -1
# Check the total uncompressed size
```

If the uncompressed size is unreasonable, **do not trust it**.

### Permission denied during bundle operations

**Cause:** The output directory or state directory is not writable.

**Fix:**

```bash
ls -la ~/.proven/.aer/bundles/
# Check write permissions
```

---

## 6. Guard Surface Errors

### File read denied for sensitive file

```
GuardDecision: DENY — fs-deny-untrusted-sensitive
  Principal: Skill, Path: .env, Rule: fs-deny-untrusted-sensitive
```

**Cause:** An untrusted principal (Skill, Web, Channel, External) attempted to
read a sensitive file that matches the denied basename pattern.

**This is expected behavior.** The File Read Guard blocks untrusted access to
credential files. If the read is legitimate, the operation must be initiated by
a User or Sys principal.

### Network request blocked

```
GuardDecision: DENY — net-deny-blocked-domain
  Principal: Skill, URL: https://webhook.site/abc123
```

**Cause:** An outbound request targeted a domain on the blocklist (known
exfiltration services).

**This is expected behavior.** If you need to reach a blocked domain
legitimately, update the network guard policy to remove it from the blocklist
or add it to the allowlist.

### Sandbox audit — CRITICAL alert

```
CRITICAL: No OS-level sandboxing detected
  Container: false, Seccomp: disabled, Namespaces: none
  Compliance: None
```

**Cause:** AEGX detected that the execution environment has no sandbox
protections. Skills can execute arbitrary code without containment.

**Fix:** Run the agent inside a container with seccomp filtering:

```bash
# Docker with seccomp
docker run --security-opt seccomp=default.json ...

# Kubernetes with securityContext
spec:
  securityContext:
    runAsNonRoot: true
    readOnlyRootFilesystem: true
```

### Dynamic token discovery not active

If the output guard is only using the static watchlist and not discovering
tokens from the system prompt, check that:

1. `hooks::on_system_prompt_available()` was called with the system prompt
2. The `SystemPromptRegistry` singleton was initialized
3. The system prompt contains SCREAMING_CASE tokens, camelCase identifiers,
   or `${params.*}` template variables

This is a platform integration issue — the integration layer must call the
hook when the system prompt becomes available.

---

## 7. Prove Query Issues

### `Unknown category: <cat>`

**Cause:** Invalid `--category` value for `aegx prove`.

**Fix:** Use one of: `cpi`, `mi`, `taint`, `injection`, `extraction`, `leakage`, `proxy`, `rollback`, `contamination`.

### `Unknown severity: <sev>`

**Cause:** Invalid `--severity` value for `aegx prove`.

**Fix:** Use one of: `critical`, `high`, `medium`, `info`.

### `aegx prove` returns empty results

**Cause:** No guard events have occurred yet, or the time/category/severity filters are too restrictive.

**Fix:** Try without filters first:

```bash
aegx prove
```

If that shows results, narrow down with filters. If it shows no results, the system simply hasn't encountered any threats yet — which is good.

---

## Getting More Help

- [Installation Guide](INSTALL.md) — build from source
- [CLI Reference](CLI_REFERENCE.md) — every command and flag
- [Verification Guide](VERIFICATION_GUIDE.md) — what verify checks
- [AEGX Specification](SPEC.md) — formal format details
- [Threat Model](THREAT_MODEL.md) — security assumptions and guarantees
- File an issue: https://github.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI/issues
