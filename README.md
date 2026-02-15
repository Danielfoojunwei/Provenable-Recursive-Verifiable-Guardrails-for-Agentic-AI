# Provable Recursive Verifiable Guardrails for Agentic AI

## Agent Evidence & Recovery (AER)

Structural security enforcement for agentic AI systems. AER provides:

- **AEGX Evidence Recording**: Tamper-evident, append-only hash chain capturing all agent sessions, tool calls, file mutations, and guard decisions
- **Control-Plane Integrity (CPI)**: Structural enforcement preventing untrusted principals from modifying skills, tools, permissions, or gateway configuration
- **Memory Integrity (MI)**: Structural enforcement preventing tainted or untrusted writes to durable workspace memory files
- **RVU Rollback**: Verifiable snapshots and exact-hash rollback for control-plane state and workspace memory
- **Incident Bundle Export**: Self-contained `.aegx.zip` evidence bundles with independent verification tooling

### Formal Foundations

AER implements the structural guarantees from four formal theorems:

- [Noninterference Theorem](https://github.com/Danielfoojunwei/Noninterference-theorem) — Taint-based isolation ensuring untrusted inputs cannot influence tool selection
- [Control-Plane Integrity Theorem](https://github.com/Danielfoojunwei/Control-plane-integrity-theorem-) — Under provenance completeness, principal accuracy, and memory persistence assumptions, no untrusted input alters the control plane
- [Memory Integrity Theorem](https://github.com/Danielfoojunwei/Memory-integrity-theorem) — Guarantees immutability, taint blocking, and session isolation for persistent memory
- [RVU Machine Unlearning](https://github.com/Danielfoojunwei/RVU-Machine-Unlearning) — Provenance DAG with contamination detection, closure computation, and verifiable recovery certificates

### Building

```bash
cd packages/aer
cargo build --release
```

### Testing

```bash
cd packages/aer
cargo test -- --test-threads=1
```

28 tests: 17 unit tests + 11 integration tests covering:
- CPI deny (untrusted principal blocked, no state mutation)
- MI deny (tainted memory write blocked, file unchanged)
- CPI allow (USER principal, change recorded)
- Snapshot/rollback (exact hash restoration verified)
- Audit chain tamper detection
- Bundle export/verify roundtrip
- Proxy trust misconfiguration detection

### CLI

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

### Documentation

- [Threat Model](docs/aer-threat-model.md)
- [Usage Guide](docs/aer-usage.md)
- [AEGX Bundle Format v0.1](docs/aer-bundle-format.md)
- [CPI/MI Guard Rules](docs/aer-cpi-mi-rules.md)

### Architecture

```
packages/aer/
├── src/
│   ├── types.rs          # Core types: Principal, TaintFlags, RecordType, etc.
│   ├── config.rs         # State directory resolution (OPENCLAW_STATE_DIR)
│   ├── canonical.rs      # Deterministic JSON canonicalization + SHA-256
│   ├── records.rs        # Record creation, storage, retrieval
│   ├── audit_chain.rs    # Append-only hash chain
│   ├── policy.rs         # Policy pack loading and evaluation
│   ├── guard.rs          # CPI/MI guard enforcement
│   ├── snapshot.rs       # Snapshot creation and management
│   ├── rollback.rs       # Rollback to snapshot
│   ├── bundle.rs         # AEGX bundle export
│   ├── verify.rs         # Bundle and chain verification
│   ├── report.rs         # Report generation
│   ├── hooks.rs          # Integration hooks (tool dispatch, sessions, CPI, MI)
│   ├── workspace.rs      # Single chokepoint for workspace memory writes
│   └── cli/              # CLI command implementations
├── schemas/              # JSON schemas for AEGX format
└── tests/                # Integration tests
```
