# Provenable.ai — Recursive Verifiable Guardrails for Agentic AI

Structural security enforcement for agentic AI systems. This project provides
the **AEGX v0.1** tamper-evident evidence bundle format and the **Agent Evidence
& Recovery (AER)** runtime that together deliver provable integrity guarantees
for agent sessions, tool invocations, file mutations, and control-plane
changes.

---

## The Problem

Agentic AI systems operate with increasing autonomy — calling tools, modifying
files, installing skills, and making decisions on behalf of users. This creates
a fundamental security gap that existing approaches fail to address:

### 1. Unverifiable Agent Behavior

Current AI agent frameworks provide **no cryptographic proof** of what an agent
did, in what order, or under whose authority. If an agent corrupts data or
performs unauthorized actions, there is no tamper-evident record to determine
what happened. Post-incident forensics are impossible when the agent itself
could have altered its own logs.

### 2. Unguarded Control Planes

Most agent systems allow any input — including untrusted web content, tool
outputs, and skill responses — to modify the control plane (permissions, tool
registrations, skill configurations). A single prompt injection or malicious
tool output can escalate privileges, install backdoor skills, or disable
security policies without any structural enforcement preventing it.

### 3. Corrupted Persistent Memory

Agents that persist state across sessions (identity files, user preferences,
agent personality, tool registrations) are vulnerable to **memory poisoning**.
Tainted data from untrusted sources can be written into durable memory,
permanently corrupting the agent's behavior in all future sessions. No existing
system enforces write guards based on data provenance.

### 4. No Provenance Tracking

When an agent produces an output, there is no way to trace the chain of data
dependencies that influenced it. If a tool output was derived from an untrusted
web source, downstream decisions based on that output inherit the taint — but
nothing tracks or enforces this. Confused-deputy attacks are trivial.

### 5. Irreversible Contamination

When contamination is detected, there is no systematic way to identify all
affected records, compute the contamination closure, and roll back to a
verified-clean state. Operators resort to manual inspection or full system
rebuilds.

---

## What This System Delivers

### Outcome 1: Tamper-Evident Evidence Chains

Every action an agent takes — tool calls, file writes, permission changes,
guard decisions — is recorded as a **TypedRecord** whose identity is the
SHA-256 hash of its canonical JSON representation. Records are linked by an
**append-only hash chain** that makes insertion, deletion, or modification of
any record immediately detectable by any verifier, offline, without trusting
the producer.

**Concrete guarantee:** Given a bundle, `aegx verify` performs 10-step
end-to-end verification: schema validation, recordId recomputation, parent
reference checking, blob hash verification, audit chain integrity, and
manifest consistency. Any single bit flip anywhere in the bundle is caught.

### Outcome 2: Control-Plane Integrity (CPI)

A **single-chokepoint guard** evaluates every control-plane mutation (skill
install/enable/disable/update, tool registration, permission changes, gateway
configuration) against a policy engine. The default deny-by-default policy
ensures that only `USER` and `SYS` principals can modify the control plane.
All other principals — `WEB`, `SKILL`, `CHANNEL`, `EXTERNAL`, `TOOL_UNAUTH`,
`TOOL_AUTH` — are structurally blocked regardless of what they claim in their
content.

**Concrete guarantee:** Under assumptions A1-A3 (provenance completeness,
principal accuracy, memory persistence), no untrusted input can alter the
agent's control plane. Every allow/deny decision is recorded as
tamper-evident evidence.

### Outcome 3: Memory Integrity (MI)

A **single-chokepoint guard** protects all writes to durable workspace memory
files (`SOUL.md`, `AGENTS.md`, `TOOLS.md`, `USER.md`, `IDENTITY.md`,
`HEARTBEAT.md`, `MEMORY.md`). Writes are blocked if:

- The requesting principal is untrusted (`WEB`, `SKILL`, `CHANNEL`, `EXTERNAL`)
- The data has tainted provenance (`UNTRUSTED`, `INJECTION_SUSPECT`,
  `WEB_DERIVED`, `SKILL_OUTPUT`)

**Concrete guarantee:** Persistent agent memory cannot be poisoned by
untrusted inputs. Taint propagates conservatively — if any parent is tainted,
all descendants are tainted.

### Outcome 4: Verifiable Rollback (RVU)

Snapshots capture SHA-256 hashes of all files in scope (control-plane config,
workspace memory, or both). Rollback restores files to their exact snapshotted
content, verifies restoration via hash comparison, and emits a tamper-evident
`Rollback` record. Contamination closure is computable: given a tainted record,
the provenance DAG identifies all downstream records that must be invalidated.

**Concrete guarantee:** After rollback, `verify_rollback()` confirms every
file matches its snapshot hash exactly. The rollback itself is recorded as
audit evidence.

### Outcome 5: Self-Contained Portable Evidence

Bundles are self-contained directories (or `.aegx.zip` archives) containing
everything needed for independent, offline verification. No network access, no
trust in the producer, no special software beyond the verifier. Bundles can be
shared, archived, and audited by any party.

---

## Formal Foundations

AER implements the structural guarantees from four published formal theorems:

- [Noninterference Theorem](https://github.com/Danielfoojunwei/Noninterference-theorem) — Taint-based isolation ensuring untrusted inputs cannot influence tool selection.
- [Control-Plane Integrity Theorem](https://github.com/Danielfoojunwei/Control-plane-integrity-theorem-) — Under provenance completeness, principal accuracy, and memory persistence assumptions, no untrusted input alters the control plane.
- [Memory Integrity Theorem](https://github.com/Danielfoojunwei/Memory-integrity-theorem) — Guarantees immutability, taint blocking, and session isolation for persistent memory.
- [RVU Machine Unlearning](https://github.com/Danielfoojunwei/RVU-Machine-Unlearning) — Provenance DAG with contamination detection, closure computation, and verifiable recovery certificates.

---

## Security Hardening Status

All critical, high, and moderate security gaps identified during adversarial
review have been resolved in the reference implementation.

### Resolved: ZIP Extraction Hardening

**Files:** `src/bundle.rs`, `packages/aer/src/bundle.rs`

Both `import_zip` (AEGX core) and `extract_bundle` (AER runtime) now enforce:

- **Path traversal rejection** — Entry names are validated against `..`
  components, absolute paths (Unix and Windows), and null bytes. Resolved
  output paths are verified to remain within the target directory.
- **Zip bomb protection** — Per-entry size limit (1 GB), total extraction
  limit (10 GB), and maximum entry count (100,000).
- **Symlink rejection** — Symlink zip entries are rejected. Output paths
  that are existing symlinks on disk are also rejected (defense-in-depth).
- **Duplicate entry rejection** — Entry names are tracked; duplicates are
  rejected. The `zip` crate also enforces this at write time.
- **UTF-8 enforcement** — Non-UTF-8 entry names (lossy conversion markers)
  are rejected.

Covered by integration tests in `tests/zip_security.rs`.

### Resolved: Memory File Guard Bypass

**File:** `packages/aer/src/hooks.rs`

The memory file detection in `on_file_write` previously used string
`ends_with` matching, which could be bypassed with crafted paths like
`/tmp/not-actually-SOUL.md`. Now uses `Path::file_name()` for exact
basename matching against the `MEMORY_FILES` whitelist.

### Resolved: Policy File Integrity

**File:** `packages/aer/src/policy.rs`

Policy loading now enforces three layers of protection:

1. **SHA-256 sidecar verification** — `save_policy` writes a `.sha256`
   sidecar file. `load_policy` verifies the hash on load if the sidecar
   exists. Tampering is detected and rejected.
2. **Permission validation** — On Unix, world-writable policy files are
   rejected (`chmod o-w` required).
3. **Structural safety validation** — Loaded policies are checked for
   structurally dangerous rules. Any rule that allows untrusted principals
   (`WEB`, `SKILL`, `CHANNEL`, `EXTERNAL`) to modify the control plane
   is rejected, even if the YAML parses correctly.

### Resolved: `/tmp` Fallback Removed

**File:** `packages/aer/src/config.rs`

`resolve_state_dir()` no longer falls back to `/tmp` when `HOME` is unset.
The process panics with a clear error message directing the operator to set
`HOME`, `PRV_HOME`, or `PRV_STATE_DIR`.

### Resolved: Guard Rate Limiting

**File:** `packages/aer/src/guard.rs`

Guard denial decisions are now rate-limited to 100 denials per 60-second
window. Exceeding this limit returns an error, preventing log flooding
attacks where a malicious agent spams denied requests to fill the audit log
with noise.

### Remaining Considerations

These are architectural enhancements documented in `THREAT_MODEL.md` that
require design decisions beyond the reference implementation scope:

| Item | Status | Notes |
|------|--------|-------|
| External witness (RFC 3161 / transparency log) | Future | Prevents full-chain forgery by an attacker with filesystem access |
| Bundle signing (Ed25519) | Future | Enables origin authentication without out-of-band mechanisms |
| CI security scanning (`cargo audit`, `cargo deny`) | Operational | Recommended for deployment pipelines |
| Assumptions A1-A5 | Preconditions | Documented in `docs/aer-threat-model.md`; must be ensured by the caller |

---

## What is AEGX?

AEGX (Agent Evidence eXchange) is a content-addressed, append-only evidence
format. Every action an agent takes is recorded as a **TypedRecord** whose
identity is the SHA-256 hash of its canonical JSON representation. Records are
linked together by an **audit hash chain** that makes any tampering —
insertion, deletion, or modification — immediately detectable.

Key properties:

- **Tamper evidence.** Every record has a content-derived `recordId`. An
  append-only hash chain links all records. Any modification breaks the chain.
- **Deterministic canonicalization.** The `AEGX_CANON_0_1` algorithm (sorted
  keys, NFC Unicode normalization, no whitespace, `-0` to `0`) ensures that
  semantically identical JSON always produces identical bytes.
- **Content-addressed blobs.** Large payloads are stored as files named by
  their SHA-256 digest. Verification recomputes the hash of every blob.
- **Schema-validated.** Manifest, records, and audit entries are validated
  against strict JSON Schemas with `additionalProperties: false`.
- **Self-contained bundles.** A bundle directory (or `.aegx.zip` archive)
  contains everything needed for independent, offline verification.

## Agent Evidence & Recovery (AER)

AER is the runtime subsystem that enforces structural security:

- **CPI (Control-Plane Integrity):** Prevents untrusted principals from
  modifying skills, tools, permissions, or gateway configuration.
- **MI (Memory Integrity):** Prevents tainted or untrusted writes to durable
  workspace memory files.
- **RVU Rollback:** Creates verifiable snapshots and performs exact-hash
  rollback for control-plane state and workspace memory.
- **Incident Bundle Export:** Exports self-contained `.aegx.zip` evidence
  bundles with independent verification tooling.

### Trust Lattice

Principals are assigned based on **transport channel**, not content claims.
This prevents confused-deputy attacks.

```
SYS (trust level 5)
 └── USER (trust level 4)
      └── TOOL_AUTH (trust level 3)
           └── TOOL_UNAUTH (trust level 2)
                └── WEB, SKILL (trust level 1)
                     └── CHANNEL, EXTERNAL (trust level 0)
```

### Taint Model

Taint flags propagate conservatively (union of all parent taints):

| Flag | Bit | Meaning |
|------|-----|---------|
| UNTRUSTED | 0x01 | From untrusted source |
| INJECTION_SUSPECT | 0x02 | Potential injection payload |
| PROXY_DERIVED | 0x04 | Derived from proxy/forwarded request |
| SECRET_RISK | 0x08 | May contain secrets |
| CROSS_SESSION | 0x10 | Transferred across sessions |
| TOOL_OUTPUT | 0x20 | Output from tool execution |
| SKILL_OUTPUT | 0x40 | Output from skill execution |
| WEB_DERIVED | 0x80 | Derived from web/HTTP source |

---

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)

### Build

```bash
cargo build --locked --release
```

The `aegx` binary is produced at `target/release/aegx`.

### Run Tests

```bash
cargo test --locked
```

### Create a Bundle

```bash
# Initialize a new empty bundle
aegx init my-bundle

# Add a record with an inline payload
aegx add-record my-bundle \
  --type SessionStart \
  --principal USER \
  --meta '{"ts":"2026-02-15T12:00:00Z"}' \
  --inline '{}'

# Add a blob file
aegx add-blob my-bundle ./path/to/file.bin

# Add a record referencing the blob
aegx add-record my-bundle \
  --type FileWrite \
  --principal TOOL \
  --meta '{"ts":"2026-02-15T12:00:01Z","path":"/workspace/file.bin"}' \
  --blob <sha256-from-add-blob> \
  --mime application/octet-stream \
  --size 1024
```

### Export and Verify

```bash
# Export to a zip archive
aegx export my-bundle my-bundle.aegx.zip

# Verify bundle integrity (directory or zip)
aegx verify my-bundle
aegx verify my-bundle.aegx.zip

# Summarize bundle contents
aegx summarize my-bundle
```

## CLI Reference

| Command                          | Description                                      |
|----------------------------------|--------------------------------------------------|
| `aegx init <bundle-dir>`        | Initialize a new empty AEGX bundle directory.    |
| `aegx add-blob <bundle> <file>` | Add a blob file to the bundle. Prints the SHA-256 hash. |
| `aegx add-record <bundle> ...`  | Add a typed record. Prints the recordId.         |
| `aegx export <dir> <zip>`       | Export a bundle directory to a `.aegx.zip` file. |
| `aegx import <zip> <dir>`       | Extract a `.aegx.zip` into a directory.          |
| `aegx verify <bundle>`          | Verify bundle integrity end-to-end.              |
| `aegx summarize <bundle>`       | Print record counts by type/principal and verification status. |

### AER CLI (packages/aer)

The AER subsystem has its own CLI for runtime operations:

```bash
proven-aer init                           # Initialize AER
proven-aer status                         # Show status
proven-aer snapshot create <name>         # Create snapshot
proven-aer snapshot list                  # List snapshots
proven-aer rollback <snapshot-id>         # Rollback to snapshot
proven-aer bundle export                  # Export evidence bundle
proven-aer verify <path.aegx.zip>         # Verify bundle integrity
proven-aer report <path.aegx.zip>         # Generate report
```

## Verification

The `aegx verify` command performs a complete end-to-end verification:

1. Validates `manifest.json` against the JSON schema.
2. Validates every record in `records.jsonl` against the record schema.
3. Validates every entry in `audit-log.jsonl` against the audit entry schema.
4. Recomputes the `recordId` of every record and checks for mismatches.
5. Validates all parent references (every parent must exist).
6. Validates all blob references (file must exist, SHA-256 must match filename).
7. Verifies the audit hash chain (sequential indices, prev-linking, entryHash recomputation).
8. Checks `record_count`, `blob_count`, and `root_records` against actual data.

Exit codes: `0` = pass, `2` = verification failure, `3` = schema failure,
`4` = IO error.

## Bundle Format

An AEGX bundle is a directory (or zip) with this layout:

```
<bundle>/
  manifest.json         # Bundle metadata and counters
  records.jsonl         # TypedRecords, one per line
  audit-log.jsonl       # Audit hash chain, one entry per line
  blobs/                # Content-addressed blob store
    <sha256-hex>
    ...
```

See the full specification: [docs/SPEC.md](docs/SPEC.md)

## Architecture

```
src/
  lib.rs              # Library root
  canonical.rs        # AEGX_CANON_0_1 deterministic JSON canonicalization
  hash.rs             # SHA-256 hashing utilities
  schema.rs           # JSON Schema loading and validation
  records.rs          # TypedRecord types, recordId computation, JSONL I/O
  audit.rs            # Audit hash chain: entryHash computation, chain verification
  bundle.rs           # Bundle init, blob management, manifest, zip export/import
  verify.rs           # End-to-end bundle verification and summarization
  bin/aegx.rs         # CLI entry point
schemas/
  manifest.schema.json
  record.schema.json
  audit-entry.schema.json
tests/
  test_vectors/       # Pre-built bundles for regression testing
packages/aer/         # Agent Evidence & Recovery runtime subsystem
fuzz/                 # Fuzz testing targets
```

## Documentation

### Getting Started

| Guide | Audience | Description |
|-------|----------|-------------|
| [Installation Guide](docs/INSTALL.md) | Everyone | Prerequisites, build, install, platform notes |
| [Quickstart Tutorial](docs/QUICKSTART.md) | Everyone | Create your first bundle in 5 minutes |
| [CLI Reference](docs/CLI_REFERENCE.md) | Everyone | Every command, flag, and exit code for both CLIs |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Everyone | Common errors and how to fix them |

### For Agent Developers

| Guide | Description |
|-------|-------------|
| [Agent Integration Guide](docs/AGENT_INTEGRATION.md) | Step-by-step integration for AI agents and pipelines |
| [AER Usage Guide](docs/aer-usage.md) | AER runtime operations (guards, snapshots, rollback) |
| [CPI/MI Guard Rules](docs/aer-cpi-mi-rules.md) | Trust lattice, taint model, policy customization |

### Technical Reference

| Document | Description |
|----------|-------------|
| [AEGX v0.1 Format Specification](docs/SPEC.md) | Formal specification of the bundle format |
| [Bundle Format Guide](docs/BUNDLE_FORMAT_GUIDE.md) | Visual walkthrough of every file in a bundle |
| [Verification Guide](docs/VERIFICATION_GUIDE.md) | What verify checks and how to interpret results |
| [AER Bundle Format](docs/aer-bundle-format.md) | AER-specific bundle extensions |

### Security

| Document | Description |
|----------|-------------|
| [Threat Model](docs/THREAT_MODEL.md) | AEGX security analysis and mitigations |
| [AER Threat Model](docs/aer-threat-model.md) | AER security guarantees and assumptions |
| [Changelog](docs/CHANGELOG.md) | Release notes |

## License

Copyright (c) 2026 Daniel Foo Jun Wei / Provenable.ai. All rights reserved.

This software and the AEGX format specification are proprietary to Provenable.ai.
See [LICENSE](LICENSE) for full terms. Use requires a written license agreement.
