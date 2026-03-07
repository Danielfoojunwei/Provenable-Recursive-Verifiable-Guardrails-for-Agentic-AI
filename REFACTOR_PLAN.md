# AEGX First-Principles Refactoring Plan

## Combine · Optimise · Refactor

---

## Executive Summary

The AEGX ecosystem currently exists as **three disconnected codebases** that evolved independently:

1. **`aegx` crate** (1,248 LOC Rust) — Evidence bundle creation/verification CLI
2. **`aer` crate** (11,160 LOC Rust) — Agent Evidence & Recovery runtime with guards, policy, scanning
3. **Mission Control** (~8,000 LOC TypeScript) — Full-stack dashboard for orchestrating the Four-Skill autonomous ecosystem

These share overlapping concerns but have **incompatible type systems, divergent algorithms, and no shared foundation**. Bundles created by `aegx` cannot be verified by `aer` and vice versa. The Mission Control dashboard mocks all Rust integration.

This plan derives the correct architecture **from first principles**, then maps a phased execution path.

---

## Part 1: First-Principles Analysis

### 1.1 What Is the Core Invariant?

The system exists to provide a single guarantee:

> **Every action taken by an autonomous agent is recorded in a tamper-evident chain, verified against policy, and recoverable.**

This decomposes into four atomic properties:

| Property | Description | Current Owner |
|----------|-------------|---------------|
| **Evidence** | Every action produces a cryptographically-bound record | aegx + aer (duplicated) |
| **Verification** | Any party can independently verify the chain's integrity | aegx + aer (incompatible) |
| **Policy** | Actions are evaluated against declared constraints before execution | aer only |
| **Recovery** | Any state can be rolled back to a verified checkpoint | aer only |

### 1.2 What Are the Fundamental Types?

From first principles, the minimal type universe is:

```
Principal     — WHO performed the action (trust-ordered enum)
RecordType    — WHAT kind of action was performed
TaintFlags    — WHY this data may be untrusted (bitflags)
Payload       — THE data (inline JSON or blob reference)
RecordMeta    — WHEN/WHERE/HOW (structured metadata)
TypedRecord   — A complete evidence record (Principal + Type + Taint + Meta + Payload)
AuditEntry    — A hash-chained wrapper around a record (idx, prev, hash, record_id)
Manifest      — Bundle-level metadata (version, timestamps, record count, hashes)
Policy        — Declarative constraint set (rules, thresholds, actions)
```

**Current problem**: These types are defined **twice** with incompatible representations. The `aegx` crate uses untyped strings for taint and unstructured JSON for metadata, while `aer` uses typed bitflags and structured structs. Neither is wrong — but they must converge.

### 1.3 What Are the Fundamental Operations?

```
RECORD    — Create a TypedRecord with computed record_id
CHAIN     — Append record to hash-linked audit chain
EVALUATE  — Check record against policy → Verdict (Allow/Deny/Escalate)
SCAN      — Detect threats in content (injection, extraction, crescendo)
BUNDLE    — Package records + chain + manifest into portable archive
VERIFY    — Independently validate bundle integrity (hashes, chain, schema)
SNAPSHOT  — Capture recoverable system state
ROLLBACK  — Restore to a verified snapshot
EXPORT    — Serialize live state to distributable bundle
```

### 1.4 What Is the Correct Layering?

From the operations above, the natural dependency graph is:

```
Layer 0: aegx-types        (types, canonical hashing, serialization)
Layer 1: aegx-records      (record creation, audit chain, JSONL I/O)
Layer 2: aegx-bundle       (bundle packaging, verification, schema validation)
Layer 3: aegx-guard        (policy evaluation, scanning, verdicts)
Layer 4: aegx-runtime      (snapshots, rollback, live state, hooks)
Layer 5: aegx-cli          (CLI binaries: aegx, proven-aer)
Layer 6: mission-control   (TypeScript dashboard, API, database)
```

Each layer depends only on layers below it. No circular dependencies. No duplication.

---

## Part 2: What Must Change

### 2.1 Critical Incompatibilities to Resolve

| Issue | Severity | Resolution |
|-------|----------|------------|
| **Record ID computation differs** — aegx hashes 6 fields, aer hashes 2 | CRITICAL | Adopt aegx's approach (includes all identity fields) in shared layer |
| **Canonicalization diverges** — aegx has NFC + -0.0 handling, aer doesn't | HIGH | Merge into single implementation with all features |
| **Payload representation differs** — field names (`inline` vs `data`, `Blob` vs `BlobRef`), aer missing `mime` | HIGH | Unify to single Payload enum with `mime` in blob variant |
| **Taint representation differs** — Vec<String> vs TaintFlags bitflags | HIGH | Adopt aer's TaintFlags (type-safe); provide string conversion for JSON interop |
| **Principal enum differs** — different variants and naming | MEDIUM | Adopt aer's trust-ordered Principal with helper methods |
| **Metadata differs** — untyped Value vs structured RecordMeta | MEDIUM | Adopt aer's typed RecordMeta; keep `extensions: Option<Value>` for flexibility |
| **Verification differs** — aegx has 10-step with schema validation, aer has 5-step without | HIGH | Merge: take aegx's comprehensive checks + aer's error types |
| **Mission Control mocks verification** — `Math.random() > 0.1` | HIGH | Replace with real Rust FFI or HTTP bridge to actual verification |

### 2.2 Code Duplication to Eliminate

| Module | aegx lines | aer lines | Duplication | Action |
|--------|-----------|-----------|-------------|--------|
| canonical.rs | 170 | 100 | 60% | Merge → aegx-types |
| audit.rs / audit_chain.rs | 122 | 178 | 70% | Merge → aegx-records |
| records.rs / types.rs | 181 | 317 | 20% (types diverged) | Unify → aegx-types |
| bundle.rs | 397 | 100 | 30% | Merge → aegx-bundle |
| verify.rs | 373 | 202 | 40% | Merge → aegx-bundle |

**Total estimated reduction**: ~600 lines of duplicated Rust code eliminated.

---

## Part 3: Target Architecture

### 3.1 Workspace Structure

```
aegx-workspace/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── aegx-types/               # Layer 0: Fundamental types + canonical hashing
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── principal.rs      # Trust-ordered Principal enum
│   │   │   ├── record_type.rs    # RecordType enum (unified superset)
│   │   │   ├── taint.rs          # TaintFlags bitflags
│   │   │   ├── payload.rs        # Unified Payload enum
│   │   │   ├── meta.rs           # RecordMeta struct
│   │   │   ├── record.rs         # TypedRecord + record_id computation
│   │   │   ├── canonical.rs      # Canonical JSON + hashing (merged, full-featured)
│   │   │   └── error.rs          # Shared error types
│   │   └── Cargo.toml
│   │
│   ├── aegx-records/             # Layer 1: Record I/O + audit chain
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── jsonl.rs          # JSONL read/write (deduplicated)
│   │   │   ├── audit_chain.rs    # Hash-linked chain (merged implementation)
│   │   │   └── manifest.rs       # Manifest read/write
│   │   └── Cargo.toml            # depends: aegx-types
│   │
│   ├── aegx-bundle/              # Layer 2: Bundle packaging + verification
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── create.rs         # Bundle creation (zip/directory)
│   │   │   ├── verify.rs         # Unified 10-step verification
│   │   │   └── schema.rs         # Schema validation
│   │   ├── schemas/              # Single source of truth for schemas
│   │   │   ├── manifest.schema.json
│   │   │   ├── record.schema.json
│   │   │   └── policy.schema.json
│   │   └── Cargo.toml            # depends: aegx-types, aegx-records
│   │
│   ├── aegx-guard/               # Layer 3: Policy + scanning (from aer)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── guard.rs          # 3-surface guard (CPI, MI, ConversationIO)
│   │   │   ├── policy.rs         # Policy rules + evaluation
│   │   │   ├── scanner.rs        # Prompt injection / extraction detection
│   │   │   ├── output_guard.rs   # Output leakage detection
│   │   │   ├── alerts.rs         # Threat alerting
│   │   │   ├── file_read_guard.rs
│   │   │   └── network_guard.rs
│   │   └── Cargo.toml            # depends: aegx-types
│   │
│   ├── aegx-runtime/             # Layer 4: Live state management (from aer)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── snapshot.rs       # State snapshots
│   │   │   ├── rollback.rs       # RVU rollback logic
│   │   │   ├── hooks.rs          # Lifecycle hooks
│   │   │   ├── workspace.rs      # Workspace management
│   │   │   ├── sandbox_audit.rs  # Sandbox auditing
│   │   │   ├── config.rs         # Runtime configuration
│   │   │   └── report.rs         # Report generation
│   │   └── Cargo.toml            # depends: aegx-types, aegx-records, aegx-guard
│   │
│   └── aegx-cli/                 # Layer 5: CLI binaries
│       ├── src/
│       │   ├── bin/
│       │   │   ├── aegx.rs       # Bundle tool CLI
│       │   │   └── proven-aer.rs # Runtime CLI
│       │   └── lib.rs            # Shared CLI utilities
│       └── Cargo.toml            # depends: all above
│
├── mission-control/              # Layer 6: TypeScript dashboard
│   ├── client/                   # React frontend
│   ├── server/                   # tRPC backend
│   ├── shared/                   # Shared types
│   ├── bridge/                   # NEW: Rust↔TypeScript bridge
│   │   ├── src/
│   │   │   ├── ffi.rs            # C-ABI exports for WASM/FFI
│   │   │   └── http.rs           # HTTP API for verification/guard calls
│   │   └── Cargo.toml
│   ├── package.json
│   └── drizzle/
│
├── skills/                       # Skill definitions
│   └── provenable/
│       └── claw.json
│
├── docs/                         # Unified documentation
├── tests/                        # Cross-crate integration tests
│   ├── roundtrip.rs              # aegx creates → aer verifies (and reverse)
│   └── interop.rs                # TypeScript ↔ Rust type compatibility
└── fuzz/                         # Property-based tests
```

### 3.2 Dependency Graph

```
                    aegx-types (Layer 0)
                   /     |      \      \
           aegx-records  aegx-guard  bridge
              |     \       |
          aegx-bundle  aegx-runtime
              \          /
              aegx-cli
```

### 3.3 Type Unification Decisions

| Type | Decision | Rationale |
|------|----------|-----------|
| `Principal` | Use aer's trust-ordered enum with `trust_level()` method | Type safety; trust ordering is a security invariant |
| `RecordType` | Union of both enums + `FileRename` from aer | No data loss |
| `TaintFlags` | Use aer's bitflags; add `From<Vec<String>>` and `Into<Vec<String>>` | Type safety for internal use; string conversion for JSON/interop |
| `Payload` | Unified: `Inline { data: Value }`, `BlobRef { hash: String, mime: String, size: u64 }` | Include `mime` in payload (aegx approach); use `data` field name (aer approach) |
| `RecordMeta` | Use aer's typed struct + `extensions: Option<Value>` | Strong typing where possible; escape hatch for custom metadata |
| `TypedRecord` | Merge: all fields from both + `schema: Option<String>` from aegx | Complete record representation |
| `record_id` | Use aegx's 6-field computation (includes type, principal, taint, parents) | More robust; prevents collisions when payload is identical but context differs |
| `Canonical JSON` | Use aegx's implementation (NFC normalization, -0.0 handling, timestamp normalization) | Correctness; NFC and -0.0 are required by spec |

---

## Part 4: Execution Plan

### Phase 1: Foundation — Create `aegx-types` (Week 1)

**Goal**: Single source of truth for all types and canonical hashing.

1. Create `crates/aegx-types/` with unified types
2. Implement canonical JSON with all features (NFC, -0.0, timestamp normalization)
3. Implement unified `compute_record_id` (6-field aegx approach)
4. Add comprehensive tests (port all existing tests from both crates)
5. Add `From`/`Into` conversions for backward compatibility
6. Property tests: canonical(parse(canonical(x))) == canonical(x)

**Files created**: ~8 files, ~800 lines
**Files deleted**: 0 (old code still exists, not yet migrated)

### Phase 2: Records & Chain — Create `aegx-records` (Week 1-2)

**Goal**: Single implementation for JSONL I/O and audit chain.

1. Create `crates/aegx-records/` depending on `aegx-types`
2. Merge JSONL read/write from both crates (deduplicate ~85%)
3. Merge audit chain verification (deduplicate ~70%)
4. Unified error types (`ChainError` from aer, enhanced with aegx's detail)
5. Manifest I/O
6. Integration tests: write records → read back → verify chain integrity

**Files created**: ~5 files, ~500 lines
**Files eliminated (duplication)**: ~400 lines

### Phase 3: Bundle & Verify — Create `aegx-bundle` (Week 2)

**Goal**: Single bundle format with comprehensive verification.

1. Create `crates/aegx-bundle/` depending on `aegx-types` + `aegx-records`
2. Merge bundle creation logic
3. Merge verification: aegx's 10-step process + aer's typed errors
4. Consolidate schemas into single directory (single source of truth)
5. Schema validation using jsonschema
6. Roundtrip test: create bundle → verify bundle → extract → re-verify

**Files created**: ~5 files, ~700 lines
**Files eliminated (duplication)**: ~500 lines

### Phase 4: Guard & Policy — Create `aegx-guard` (Week 2-3)

**Goal**: Extract guard/policy/scanning from aer into standalone crate.

1. Create `crates/aegx-guard/` depending on `aegx-types`
2. Move guard.rs, policy.rs, scanner.rs, output_guard.rs, alerts.rs, file_read_guard.rs, network_guard.rs from aer
3. Update imports to use `aegx_types::` instead of local types
4. No logic changes — pure extraction
5. Port all guard tests

**Files moved**: 7 files, ~4,500 lines
**Logic changes**: Import paths only

### Phase 5: Runtime — Create `aegx-runtime` (Week 3)

**Goal**: Extract runtime operations from aer into standalone crate.

1. Create `crates/aegx-runtime/`
2. Move snapshot.rs, rollback_policy.rs, hooks.rs, workspace.rs, sandbox_audit.rs, config.rs, report.rs, skill_verifier.rs
3. Update imports to use shared crates
4. Port all runtime tests

**Files moved**: 8 files, ~3,500 lines
**Logic changes**: Import paths only

### Phase 6: CLI Consolidation — Create `aegx-cli` (Week 3-4)

**Goal**: Single CLI crate producing both `aegx` and `proven-aer` binaries.

1. Create `crates/aegx-cli/`
2. Merge CLI argument parsing from both crates
3. Both binaries share common infrastructure (output formatting, error handling)
4. `aegx` binary: bundle create/verify/inspect commands
5. `proven-aer` binary: guard/scan/snapshot/rollback/export commands
6. Delete old `src/` and `packages/aer/src/` directories

**Files created**: ~5 files, ~600 lines
**Files deleted**: All old source files (~12,400 lines)
**Net reduction**: ~5,000+ lines eliminated through deduplication

### Phase 7: Mission Control Integration (Week 4-5)

**Goal**: Replace mocks with real Rust integration.

1. Create `mission-control/bridge/` crate with HTTP API
2. Implement real bundle verification endpoint (replaces `Math.random() > 0.1`)
3. Implement real guard evaluation endpoint
4. Generate TypeScript types from Rust types (via `ts-rs` or manual sync)
5. Update `server/routers.ts` to call bridge instead of mocking
6. Add integration tests: TypeScript → Bridge → Rust → response

**Key replacements**:
- `routers.ts:125` mock verification → real `aegx-bundle::verify()`
- `routers.ts:470` mock API execution → real skill endpoint calls
- Hardcoded guard list → dynamic from `aegx-guard::list_guards()`

### Phase 8: Integration Testing & Documentation (Week 5)

**Goal**: Prove the system works end-to-end.

1. Cross-crate roundtrip tests (aegx creates → verified by same code)
2. TypeScript ↔ Rust type compatibility tests
3. Benchmark suite comparing before/after performance
4. Update all documentation to reflect new workspace structure
5. Migration guide for existing users

---

## Part 5: Optimisation Opportunities

### 5.1 Algorithmic

| Area | Current | Optimised | Impact |
|------|---------|-----------|--------|
| Canonical JSON | Allocates intermediate `Vec<u8>` | Write directly to `io::Write` trait | ~30% less allocation in bundle creation |
| Record ID | Serializes each field separately, then hashes | Single-pass streaming hash | ~40% faster record creation |
| Scanner regex | Compiled on every call | Lazy-static compiled regexes | ~10x faster scanning |
| Audit chain verification | Reads entire file into memory | Streaming line-by-line verification | O(1) memory for large chains |
| Bundle verification | Reads all blobs into memory for hashing | Stream hash blobs | O(1) memory for large bundles |

### 5.2 Structural

| Area | Current | Optimised | Impact |
|------|---------|-----------|--------|
| Schema loading | Loaded from disk per validation | Embedded via `include_str!` at compile time | No filesystem dependency |
| Error handling | Mix of `String`, `Vec<String>`, custom enums | Unified `thiserror` hierarchy | Consistent error reporting |
| Serialization | Mix of manual JSON building and serde | All serde with `#[serde(rename)]` | Less code, fewer bugs |
| Test infrastructure | Separate test patterns in each crate | Shared test utilities crate | DRY test code |

### 5.3 Build

| Area | Current | Optimised | Impact |
|------|---------|-----------|--------|
| Compilation | 2 separate crate compilations | Workspace with shared deps | Faster incremental builds |
| Dependencies | Duplicated deps (sha2, serde, chrono, etc.) | Workspace-level dep inheritance | Consistent versions, smaller lockfile |
| CI | Separate CI for aegx and aer | Single workspace CI with crate-level caching | Faster CI, single test report |

---

## Part 6: Risk Mitigation

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Breaking existing bundle format | Medium | HIGH | Version field in manifest; write migration tool for v0.1 → v0.2 bundles |
| Regression in guard logic during extraction | Low | HIGH | Port all 11,700 lines of aer tests first; run continuously during refactor |
| Mission Control API contract breakage | Medium | MEDIUM | Generate OpenAPI spec from bridge; contract tests |
| Performance regression | Low | MEDIUM | Benchmark suite runs in CI; fail on >10% regression |
| Partial completion leaves codebase worse | Medium | HIGH | Each phase is independently shippable; old code only deleted after new code passes all tests |

---

## Part 7: Success Metrics

| Metric | Before | Target |
|--------|--------|--------|
| Total Rust LOC | 12,408 (duplicated) | ~9,000 (deduplicated) |
| Cross-crate type compatibility | 0% (incompatible) | 100% (shared types) |
| Bundle interoperability | None (different ID algorithms) | Full roundtrip |
| Mission Control Rust integration | 0% (all mocked) | 100% (real verification + guards) |
| Crate count | 2 (monolithic) | 6 (layered, single-responsibility) |
| Build time (incremental) | 2 full rebuilds | 1 workspace build, incremental |
| Test coverage of shared types | ~40% | >90% |

---

## Part 8: Guiding Principles

1. **One type, one definition** — Every type exists in exactly one crate
2. **Layers only depend downward** — No circular dependencies, no peer imports
3. **Verify everything, trust nothing** — Every layer boundary has integration tests
4. **Delete before adding** — Remove duplication before adding features
5. **Each phase ships independently** — No big-bang migration; each phase produces a working system
6. **The spec is the contract** — AEGX_CANON_0_1 canonicalization spec is the single source of truth for hash computation
7. **Types flow from Rust to TypeScript** — Rust types are authoritative; TypeScript types are generated/derived

---

*Generated from first-principles analysis of the aegx crate (src/), aer crate (packages/aer/src/), and Mission Control dashboard (four-skill-mission-control/).*
