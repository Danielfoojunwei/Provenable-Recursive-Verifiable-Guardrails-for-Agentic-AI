# Provable Recursive Verifiable Guardrails for Agentic AI

Structural security enforcement for agentic AI systems. This project provides
the **AEGX v0.1** tamper-evident evidence bundle format and the **Agent Evidence
& Recovery (AER)** runtime that together deliver provable integrity guarantees
for agent sessions, tool invocations, file mutations, and control-plane
changes.

## What is AEGX?

AEGX (Agent Evidence eXchange) is a content-addressed, append-only evidence
format. Every action an agent takes is recorded as a **TypedRecord** whose
identity is the SHA-256 hash of its canonical JSON representation. Records are
linked together by an **audit hash chain** that makes any tampering --
insertion, deletion, or modification -- immediately detectable.

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

### Formal Foundations

AER implements the structural guarantees from four formal theorems:

- [Noninterference Theorem](https://github.com/Danielfoojunwei/Noninterference-theorem) -- Taint-based isolation ensuring untrusted inputs cannot influence tool selection.
- [Control-Plane Integrity Theorem](https://github.com/Danielfoojunwei/Control-plane-integrity-theorem-) -- Under provenance completeness, principal accuracy, and memory persistence assumptions, no untrusted input alters the control plane.
- [Memory Integrity Theorem](https://github.com/Danielfoojunwei/Memory-integrity-theorem) -- Guarantees immutability, taint blocking, and session isolation for persistent memory.
- [RVU Machine Unlearning](https://github.com/Danielfoojunwei/RVU-Machine-Unlearning) -- Provenance DAG with contamination detection, closure computation, and verifiable recovery certificates.

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
openclaw-aer init                           # Initialize AER
openclaw-aer status                         # Show status
openclaw-aer snapshot create <name>         # Create snapshot
openclaw-aer snapshot list                  # List snapshots
openclaw-aer rollback <snapshot-id>         # Rollback to snapshot
openclaw-aer bundle export                  # Export evidence bundle
openclaw-aer verify <path.aegx.zip>         # Verify bundle integrity
openclaw-aer report <path.aegx.zip>         # Generate report
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

[MIT](LICENSE)
