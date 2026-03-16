# Provenable: Recursive Verifiable Guardrails for Agentic AI

Structural security enforcement for agentic AI systems. This project provides a
**unified Rust workspace** implementing four formal theorems (CPI, MI,
Noninterference, RVU) as a cohesive, layered architecture with cross-surface
threat correlation, tamper-evident audit chains, and automated rollback.

**Current version: v0.2.0** — Unified 6-crate architecture integrating the AEGX
evidence format, AER runtime guards, and cross-surface threat correlation into a
single system grounded in first principles.

---

## Use as an Agent Skill

> **Want to add provable security guardrails to your AI agent?**
> This repo is ready to use as a skill on any agent platform.

| File | Purpose | Platform |
|------|---------|----------|
| **[`SKILL.md`](SKILL.md)** | Skill manifest and command reference | OpenClaw, Claude Code, Manus, any platform reading `SKILL.md` |
| **[`AGENT.md`](AGENT.md)** | Agent integration guide with architecture, trust model, and platform-specific setup | All agent platforms |

**Quick start:** Clone this repo, run `cargo build --workspace --release`,
then `aegx init`. Your agent reads `SKILL.md` to learn available commands
and `AGENT.md` for integration context.

---

## The Problem — Empirical Evidence

Agentic AI systems operate with increasing autonomy — calling tools, modifying
files, installing skills, and making decisions on behalf of users. This creates
a fundamental security gap that existing approaches fail to address. The
evidence is not theoretical:

### Real-World Evidence: ClawHavoc (February 2026)

Security researchers discovered **341 malicious skills** on ClawHub — the
official skill marketplace for OpenClaw ("npm for AI agents", 3,286+ skills,
1.5M+ downloads). Of these, **335 came from a single coordinated campaign**.

> *"The attacks ranged from sophisticated social engineering to brute-force
> credential theft. Malicious SKILL.md files instructed users to run
> `curl | bash` installers that delivered the Atomic macOS Stealer (AMOS).
> Others silently exfiltrated `.clawdbot/.env` files containing API keys and
> tokens, or poisoned SOUL.md and MEMORY.md to permanently alter agent
> behavior."*
> — [eSecurity Planet, Feb 2026](https://www.esecurityplanet.com/threats/hundreds-of-malicious-skills-found-in-openclaws-clawhub/)

The six attack vectors discovered:

| # | Attack | Impact | What Was Missing |
|---|--------|--------|-----------------|
| V1 | SKILL.md instructs user to run `curl \| bash` | Arbitrary code execution | No pre-install scanning |
| V2 | Skill code spawns reverse shell to attacker C2 | Persistent remote access | No sandboxing, no audit trail |
| V3 | Skill reads `.clawdbot/.env` and exfiltrates API keys | Secret theft | No file-read guards |
| V4 | Skill writes to `SOUL.md` / `MEMORY.md` | Permanent behavioral corruption | **No write guards on agent memory** |
| V5 | Trojan skill shadows legitimate bundled skill | Invisible capability hijack | No name-collision detection |
| V6 | `web-serach` mimics `web-search` | Users install wrong skill | No similarity detection |

### Real-World Evidence: ZeroLeaks Assessment

The ZeroLeaks OpenClaw Security Assessment tested 36 attack vectors against
the unprotected system and found:

- **84.6% extraction success** — 11 of 13 system prompt extraction attacks succeeded
- **91.3% injection success** — 21 of 23 prompt injection attacks succeeded
- **ZLSS: 10/10** (worst possible score)
- **Security Score: 2/100**

> *"Every single extraction technique — JSON conversion, many-shot priming,
> crescendo deepening, roleplay, identity probing, chain-of-thought hijacking
> — succeeded in extracting significant portions of the system prompt."*

### The Five Structural Gaps

1. **Unverifiable Agent Behavior** — No cryptographic proof of what an agent
   did, in what order, or under whose authority.
2. **Unguarded Control Planes** — Any input can modify permissions, tool
   registrations, and skill configurations. ClawHavoc exploited this directly.
3. **Corrupted Persistent Memory** — No write guards based on data provenance.
   ClawHavoc V4 poisoned SOUL.md to permanently corrupt agent behavior.
4. **No Provenance Tracking** — No taint propagation. Confused-deputy attacks
   are trivial.
5. **Irreversible Contamination** — No systematic way to identify affected
   records, compute closure, and roll back.

---

## Unified Architecture (v0.2.0)

The system is organized as a **6-crate Rust workspace** with strict layering.
Each layer depends only on layers below it, ensuring clean separation of
concerns while enabling deep integration:

```
┌──────────────────────────────────────────────────────────────────┐
│                          aegx-cli                                │
│  Unified CLI: init, snapshot, rollback, bundle, verify,          │
│  report, prove, status                                           │
├──────────────────────────────────────────────────────────────────┤
│                        aegx-runtime                              │
│  Snapshots (RVU), rollback policy with auto-rollback,            │
│  integration hooks, workspace MI chokepoint, /prove query        │
│  engine, sandbox auditing                                        │
├──────────────────────────────────────────────────────────────────┤
│                         aegx-guard                               │
│  Policy engine (fail-closed), 8-category injection scanner,      │
│  output leakage detection, file read guard, network egress       │
│  monitor, skill verifier (ClawHavoc), cross-surface              │
│  correlation, guard performance metrics                          │
├──────────────────────────────────────────────────────────────────┤
│                        aegx-bundle                               │
│  Evidence bundle export/import, security-hardened zip,           │
│  10-step verification, markdown/JSON reports                     │
├──────────────────────────────────────────────────────────────────┤
│                        aegx-records                              │
│  Hash-linked audit chain, JSONL record I/O, auto blob            │
│  promotion (>4KB), state directory management                    │
├──────────────────────────────────────────────────────────────────┤
│                         aegx-types                               │
│  Foundation types, canonical JSON (AEGX_CANON_0_1), SHA-256      │
│  record IDs, TaintFlags bitflags, Principal trust lattice,       │
│  AegxError                                                       │
└──────────────────────────────────────────────────────────────────┘
```

### Dependency Graph

```
aegx-types       (no internal deps)
    ↑
aegx-records     (depends on: aegx-types)
    ↑
aegx-bundle      (depends on: aegx-types, aegx-records)
    ↑
aegx-guard       (depends on: aegx-types, aegx-records)
    ↑
aegx-runtime     (depends on: aegx-types, aegx-records, aegx-bundle, aegx-guard)
    ↑
aegx-cli         (depends on: all crates above)
```

### What Changed from the Previous Architecture

The previous codebase consisted of three separate systems:

| Previous | New | What Changed |
|----------|-----|--------------|
| `src/` (aegx crate) — bundle format, canonical hashing, verification | `aegx-types` + `aegx-records` + `aegx-bundle` | Decomposed into layered crates; canonical JSON with NFC normalization and 6-field record IDs are the authoritative implementation |
| AER runtime guards, scanner, rollback, hooks | `aegx-guard` + `aegx-runtime` | Extracted into two crates; guard logic (policy, scanner, alerts) separated from runtime orchestration (hooks, snapshots, rollback) |
| Two separate CLIs | Single `aegx` CLI | Unified entry point with all commands |
| No cross-surface awareness | **Cross-surface threat correlation** | CPI denial → MI taint escalation; injection → session-wide taint; cross-surface denial counts feed RVU escalation |
| Workspace writes bypassed hooks | **All writes route through hooks** | `workspace.rs` calls `hooks::on_file_write()` for full guard → record → audit → rollback pipeline |

---

## What This System Delivers

### Outcome 1: Tamper-Evident Evidence Chains

Every action an agent takes — tool calls, file writes, permission changes,
guard decisions — is recorded as a **TypedRecord** whose identity is the
SHA-256 hash of its canonical JSON representation. Records are linked by an
**append-only hash chain** that makes insertion, deletion, or modification of
any record immediately detectable by any verifier, offline, without trusting
the producer.

**Canonical JSON (`AEGX_CANON_0_1`):**
- Keys sorted lexicographically at every level
- Unicode NFC normalization on all string values
- Negative zero (`-0.0`) normalized to `0`
- No whitespace
- 6-field record ID: `sha256(canonical_json({type, principal, taint, parents, meta, payload, schema}))`

**Concrete guarantee:** Given a bundle, `aegx verify` performs 10-step
end-to-end verification: schema validation, recordId recomputation, parent
reference checking, blob hash verification, audit chain integrity, and
manifest consistency. Any single bit flip anywhere in the bundle is caught.

### Outcome 2: Control-Plane Integrity (CPI Theorem)

A **single-chokepoint guard** evaluates every control-plane mutation (skill
install/enable/disable/update, tool registration, permission changes, gateway
configuration) against a policy engine. The default deny-by-default policy
ensures that only `USER` and `SYS` principals can modify the control plane.
All other principals — `WEB`, `SKILL`, `CHANNEL`, `EXTERNAL`, `TOOL_UNAUTH`,
`TOOL_AUTH` — are structurally blocked regardless of what they claim in their
content.

**Cross-surface integration (v0.2.0):** A CPI denial for principal P
automatically signals the cross-surface correlation engine, which elevates
taint for subsequent MI writes by the same principal. An attacker who fails
to modify config is automatically treated with heightened suspicion on
memory writes.

**Concrete guarantee:** Under assumptions A1-A3 (provenance completeness,
principal accuracy, memory persistence), no untrusted input can alter the
agent's control plane. Every allow/deny decision is recorded as
tamper-evident evidence.

### Outcome 3: Memory Integrity (MI Theorem)

A **single-chokepoint guard** protects all writes to durable workspace memory
files (`SOUL.md`, `AGENTS.md`, `TOOLS.md`, `USER.md`, `IDENTITY.md`,
`HEARTBEAT.md`, `MEMORY.md`). Writes are blocked if:

- The requesting principal is untrusted (`WEB`, `SKILL`, `CHANNEL`, `EXTERNAL`)
- The data has tainted provenance (`UNTRUSTED`, `INJECTION_SUSPECT`,
  `WEB_DERIVED`, `SKILL_OUTPUT`)
- **Cross-surface taint (v0.2.0):** The principal was previously denied CPI access

All workspace memory writes route through `hooks::on_file_write()`, which
provides the complete pipeline: guard evaluation → record emission → audit
chain append → rollback policy check → alert generation.

**Concrete guarantee:** Persistent agent memory cannot be poisoned by
untrusted inputs. Taint propagates conservatively — if any parent is tainted,
all descendants are tainted.

### Outcome 4: Noninterference (Conversation I/O)

An **8-category prompt injection scanner** analyzes all inbound messages:

| Category | What It Detects |
|----------|----------------|
| `SystemImpersonation` | Fake `[SYSTEM]`/`[ADMIN]` tags |
| `IndirectInjection` | Hidden AI directives in documents |
| `BehaviorManipulation` | Persona/instruction override attempts |
| `FalseContextInjection` | Fabricated prior conversation context |
| `EncodedPayload` | Base64/hex-encoded hidden instructions |
| `ExtractionAttempt` | System prompt extraction attempts |
| `ManyShotPriming` | Accumulated examples to override behavior |
| `FormatOverride` | Output format manipulation for exfiltration |

An **output leakage detector** scans outbound LLM responses for system prompt
tokens (static watchlist + dynamic runtime discovery) and structural prompt
patterns.

**Cross-surface integration (v0.2.0):** Injection detected in a conversation
session signals the correlation engine, which taints all subsequent operations
in that session with `INJECTION_SUSPECT | UNTRUSTED` across all guard surfaces.

### Outcome 5: Verifiable Rollback (RVU Theorem)

Snapshots capture SHA-256 hashes of all files in scope (control-plane config,
workspace memory, or both). Rollback restores files to their exact snapshotted
content, verifies restoration via hash comparison, and emits a tamper-evident
`Rollback` record.

Three automated recovery mechanisms:

1. **Auto-Snapshot Before CPI Changes** — Every allowed control-plane mutation
   creates a pre-change snapshot, ensuring rollback is always possible.
2. **Rollback Recommendation** — When 3+ guard denials occur within 2 minutes,
   the system emits a `RollbackRecommended` alert with the snapshot target.
3. **Threshold-Based Auto-Rollback** — When 5+ denials occur within 2 minutes,
   the system automatically rolls back and emits a `CRITICAL` alert.

**Cross-surface integration (v0.2.0):** Rollback thresholds now use
cross-surface denial counts. If CPI denies 2 requests and MI denies 3,
the combined count of 5 triggers auto-rollback — even though no single
surface reached the threshold alone. This catches coordinated attacks
across surfaces.

**Contamination scope computation** traces the provenance DAG from any
contaminated record using BFS to find all downstream records that must be
invalidated.

### Outcome 6: Supply-Chain Defense (ClawHavoc Prevention)

A **pre-install skill verifier** scans skill packages before they enter the
runtime, detecting all six ClawHavoc attack vectors:

| ClawHavoc Vector | Defense | Severity |
|------------------|---------|----------|
| V1: `curl \| bash` social engineering | Shell execution pattern detection | CRITICAL |
| V2: Reverse shell backdoors | Network socket pattern detection | CRITICAL |
| V3: Credential exfiltration | Credential access + exfil patterns | HIGH |
| V4: Memory poisoning | Memory file write detection | HIGH |
| V5: Skill precedence exploit | Name collision detection | HIGH |
| V6: Typosquatting | Levenshtein distance analysis | MEDIUM |

### Outcome 7: Host Environment Hardening

Four guard surfaces close the gap between policy enforcement and host-level security:

1. **File Read Guard** — Blocks untrusted principals from reading sensitive
   files (`.env`, `*.pem`, `*.key`, `id_rsa*`, credentials). Propagates
   `SECRET_RISK` taint for sensitive directory reads.
2. **Network Egress Monitor** — Evaluates outbound requests against domain
   allowlists/blocklists and payload size limits. Blocks known exfiltration
   endpoints.
3. **Sandbox Audit** — Verifies OS-level sandboxing (container, seccomp,
   namespaces) at session start. Records compliance as tamper-evident evidence.
4. **Dynamic Token Registry** — Caches system prompt tokens for runtime
   discovery in the output guard.

### Outcome 8: Unified /prove Query Interface

The `/prove` command provides a queryable interface that pulls from all layers:

```bash
aegx prove                                    # Full protection report
aegx prove --json                             # Machine-readable JSON
aegx prove --category cpi --severity high     # Filter by category/severity
aegx prove --since 2026-03-01T00:00:00Z       # Time-range queries
```

The response includes:
- **Protection summary** — Total blocks, per-surface breakdown, severity distribution
- **Threat alerts** — Filtered by time, category, severity, with limit
- **Guard metrics** — Evaluations/sec, P50/P95/P99 latency, per-surface counters
- **System health** — AER initialization, audit chain validity, record/alert counts
- **Rollback status** — Auto-rollback history, active denial counts, agent messages
- **Agent notifications** — Messages the agent MUST relay to the user (drained on read)

---

## Formal Foundations

The system implements structural guarantees from four published formal theorems:

- [Noninterference Theorem](https://github.com/Danielfoojunwei/Noninterference-theorem) — Taint-based isolation ensuring untrusted inputs cannot influence tool selection.
- [Control-Plane Integrity Theorem](https://github.com/Danielfoojunwei/Control-plane-integrity-theorem-) — Under provenance completeness, principal accuracy, and memory persistence assumptions, no untrusted input alters the control plane.
- [Memory Integrity Theorem](https://github.com/Danielfoojunwei/Memory-integrity-theorem) — Guarantees immutability, taint blocking, and session isolation for persistent memory.
- [Update/Rollback Verifier](https://github.com/Danielfoojunwei/RVU-Machine-Unlearning) — Provenance DAG with contamination detection, closure computation, and verifiable recovery certificates.

### Theorem → Defense Integration Map

Every scanner detection category and guard surface is grounded in a specific
theorem. The table below shows the exact mapping:

| Scanner Category       | Primary Theorem       | What It Prevents                                    |
|------------------------|-----------------------|-----------------------------------------------------|
| `SystemImpersonation`  | CPI Theorem (A2)      | Fake `[SYSTEM]`/`[ADMIN]` tags override transport-assigned principal |
| `IndirectInjection`    | Noninterference       | Hidden AI directives in documents cross trust boundaries |
| `BehaviorManipulation` | CPI Theorem           | Persona/instruction overrides mutate control-plane behavioral state |
| `FalseContextInjection`| MI + Noninterference  | Fabricated prior context poisons working memory (violates A1) |
| `EncodedPayload`       | Noninterference       | Encoded payloads evade taint detection, bypassing isolation |
| `ExtractionAttempt`    | MI (read-side)        | System prompt is protected memory; disclosure violates confidentiality |
| `ManyShotPriming`      | Noninterference       | Accumulated untrusted examples override model behavior |
| `FormatOverride`       | Noninterference       | Format locks enable exfiltration or bypass downstream defenses |

| Guard Surface      | Theorem(s)            | Enforcement Point                     |
|--------------------|-----------------------|---------------------------------------|
| `ControlPlane`     | CPI Theorem           | `guard.check_control_plane()` — skill/tool/permission mutations |
| `DurableMemory`    | MI Theorem            | `guard.check_memory_write()` — SOUL.md, AGENTS.md, etc. |
| `ConversationIO`   | All four theorems     | `guard.check_conversation_input()` + `check_conversation_output()` |
| `FileSystem`       | MI (read-side) + NI   | `file_read_guard` — sensitive file access control |
| `NetworkIO`        | Noninterference + CPI | `network_guard` — egress domain/payload evaluation |
| `SandboxCompliance`| CPI + RVU             | `sandbox_audit` — OS sandbox verification |

| Cross-Surface Correlation (v0.2.0) | Theorem(s)    | Mechanism |
|-------------------------------------|---------------|-----------|
| CPI denial → MI taint escalation    | CPI + MI      | `signal_cpi_denial()` adds UNTRUSTED to principal's MI evaluations |
| Injection → session-wide taint      | NI + All      | `signal_injection_detected()` taints all surfaces for session |
| Cross-surface denial count → RVU    | RVU + All     | `cross_surface_denial_count()` feeds rollback threshold |

---

## Empirical Validation: ZeroLeaks Benchmark

We ran the exact ZeroLeaks attack taxonomy — 36 real attack payloads — against
our ConversationIO guard using the actual scanner and output guard code.
**No mocks, no simulations, no cherry-picking.**

### Results (Worst-Case: USER Principal, Input Scanner Only)

| Metric                     | Before (No Guards) | v0.1.2 | v0.1.4 | v0.2.0 (Current) |
|----------------------------|--------------------|--------|--------|-------------------|
| Extraction Success Rate    | 84.6% (11/13)      | 15.4%  | 15.4%  | **15.4% (2/13)**  |
| Injection Success Rate     | 91.3% (21/23)      | 4.3%   | 4.3%   | **4.3% (1/23)**   |
| **ZLSS (1-10, lower=better)** | **10/10**       | 1/10   | 1/10   | **1/10**          |
| **Security Score (0-100)** | **2/100**           | 90/100 | 90/100 | **90/100**        |
| Supply-chain (ClawHavoc)   | 0/6 vectors blocked | 6/6    | 6/6    | **6/6 detected**  |
| Cross-surface correlation  | None               | None   | None   | **CPI→MI, NI→All, RVU escalation** |
| Automated recovery         | None               | None   | Auto   | **Auto + cross-surface** |
| Total workspace tests      | —                  | 152    | 176    | **161 (unified crate)** |

### Remaining Honest Gaps

1. **No LLM-based semantic understanding** — Regex intent detection only. Novel
   attack phrasings not matching verb+target patterns may bypass detection.
2. **Benchmark tests individual messages** — Multi-turn session detection is
   implemented but not exercised by the per-message benchmark.
3. **Adversarial prompt evolution** — Static regex patterns may be outpaced by
   adversarial prompt engineering research.
4. **Output guard heuristic** — Section header detection may miss novel disclosure
   formats not matching the known header list.
5. **No LLM in the loop** — Benchmark measures scanner/guard detection rates, not
   whether the LLM would comply with the attack.

---

## Security Hardening

All critical, high, and moderate security gaps identified during adversarial
review have been resolved:

| Hardening | Implementation |
|-----------|---------------|
| ZIP extraction hardening | Path traversal rejection, zip bomb limits (1GB/entry, 10GB total, 100K entries), symlink rejection, duplicate entry rejection, UTF-8 enforcement |
| Memory file guard bypass | `Path::file_name()` exact basename matching (not `ends_with`) |
| Policy file integrity | SHA-256 sidecar verification + Unix permission check + structural safety validation |
| `/tmp` fallback removed | Panics with clear message if HOME/PRV_HOME/PRV_STATE_DIR unset |
| Guard rate limiting | 100 denials per 60-second window; prevents log flooding attacks |
| Fail-closed policy | No matching rule → Deny (empty policy blocks everything) |

### Remaining Considerations

| Item | Status | Notes |
|------|--------|-------|
| External witness (RFC 3161 / transparency log) | Future | Prevents full-chain forgery by an attacker with filesystem access |
| Bundle signing (Ed25519) | Future | Enables origin authentication without out-of-band mechanisms |
| CI security scanning (`cargo audit`, `cargo deny`) | Operational | Recommended for deployment pipelines |
| Assumptions A1-A5 | Preconditions | Documented in `docs/aer-threat-model.md`; must be ensured by the caller |

---

## Trust Lattice

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

## Taint Model

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
cargo build --workspace --release
```

The `aegx` binary is produced at `target/release/aegx`.

### Run Tests

```bash
cargo test --workspace
```

161 tests across 6 crates, including 11 integration tests validating the
unified theorem pipeline (CPI enforcement, MI taint blocking, cross-surface
correlation, audit chain integrity, canonical determinism, fail-closed policy,
provenance chains, scanner detection, metrics tracking).

### Initialize AEGX

```bash
aegx init
```

Creates the state directory, installs the default policy, and sets up the
workspace directory. Outputs a policy summary showing the default rules.

### CLI Reference

| Command | Description |
|---------|-------------|
| `aegx init` | Initialize AEGX (state dirs, default policy, workspace) |
| `aegx status` | Show initialization status, record/audit/snapshot counts, chain validity |
| `aegx snapshot create <name> [--scope full\|cp\|mem]` | Create a named snapshot |
| `aegx snapshot list` | List existing snapshots |
| `aegx rollback <snapshot-id>` | Rollback to a previous snapshot with verification |
| `aegx bundle export [--agent <id>] [--since <ts>]` | Export evidence bundle (.aegx.zip) |
| `aegx verify <path.aegx.zip>` | Verify bundle integrity (10-step verification) |
| `aegx report <path.aegx.zip>` | Generate human-readable report from bundle |
| `aegx prove [--json] [--category <cat>] [--severity <sev>] [--since <ts>] [--until <ts>] [--limit <n>]` | Query protection status |

---

## Crate Documentation

### `aegx-types` — Foundation Types

The lowest layer. Contains all shared types, canonical JSON implementation,
and hashing primitives. No dependencies on other workspace crates.

**Key modules:**
- `canonical.rs` — `AEGX_CANON_0_1` deterministic JSON (sorted keys, NFC normalization, `-0.0`→`0`)
- `principal.rs` — 8-variant `Principal` enum with trust lattice methods
- `taint.rs` — `TaintFlags` bitflags with custom serde and string label conversion
- `record.rs` — All shared types (`TypedRecord`, `RecordMeta`, `PolicyPack`, `PolicyRule`, `GuardVerdict`, `GuardSurface`, `SnapshotManifest`, `AuditEntry`, `BundleManifest`, `VerificationResult`, etc.)
- `error.rs` — `AegxError` enum covering all error categories

### `aegx-records` — Evidence Storage

Hash-linked audit chain and JSONL record storage with auto blob promotion.

**Key modules:**
- `records.rs` — `create_record()` with 6-field `compute_record_id`, auto blob promotion (>4096 bytes), JSONL read/write, hash verification
- `audit_chain.rs` — Append-only hash chain with genesis hash, `verify_entries()` with `ChainError` diagnostics
- `config.rs` — State directory resolution (`PRV_STATE_DIR` → `PRV_HOME` → `~/.proven`), path functions, `MEMORY_FILES` whitelist

### `aegx-bundle` — Evidence Bundles

Self-contained, verifiable evidence packages.

**Key modules:**
- `bundle.rs` — `export_bundle()`, `extract_bundle()` (security-hardened), `import_zip()`, `export_dir_to_zip()`
- `verify.rs` — `verify_bundle()` for extracted dirs, `verify_live()` for active state
- `report.rs` — `generate_markdown_report()`, `generate_json_report()`

### `aegx-guard` — Policy Engine & Guard Surfaces

The security enforcement layer. All guard decisions flow through here.

**Key modules:**
- `guard.rs` — `Guard` struct with `check_control_plane()`, `check_memory_write()`, `check_conversation_input()`, `check_conversation_output()`; cross-surface correlation engine (`signal_cpi_denial()`, `signal_injection_detected()`, `correlated_taint_for_principal()`, `correlated_taint_for_session()`, `cross_surface_denial_count()`)
- `policy.rs` — `load_policy()` with SHA-256 sidecar and permission checks, `default_policy()` with 8 rules, `evaluate()` with fail-closed semantics, `validate_policy_safety()`
- `scanner.rs` — 8-category prompt injection/extraction scanner with conversation state tracking and crescendo detection
- `output_guard.rs` — System prompt leakage detection with static + dynamic token discovery
- `alerts.rs` — Threat alert system with 11 categories, JSONL persistence, agent notification queue
- `metrics.rs` — `EvalTimer`, `GuardMetrics` with P50/P95/P99 latency tracking per surface
- `file_read_guard.rs` — Sensitive file read access control
- `network_guard.rs` — Outbound request domain/payload evaluation
- `skill_verifier.rs` — ClawHavoc V1-V6 attack taxonomy scanner

### `aegx-runtime` — Runtime Orchestration

Connects guard decisions to system-level actions (snapshots, rollback, hooks).

**Key modules:**
- `hooks.rs` — Integration hooks for all operations (`on_tool_call`, `on_file_write`, `on_control_plane_change`, `on_message_input`, `on_message_output`, `on_skill_install`, etc.)
- `snapshot.rs` — `create_snapshot()`, `list_snapshots()`, `load_snapshot()`, `diff_snapshot()`
- `rollback_policy.rs` — RVU implementation with `DenialTracker`, auto-snapshot, contamination scope BFS, auto-rollback at threshold
- `workspace.rs` — MI chokepoint routing through `hooks::on_file_write()`
- `prove.rs` — `/prove` query engine pulling from alerts, metrics, audit chain, and health
- `sandbox_audit.rs` — OS sandbox environment verification

### `aegx-cli` — Unified CLI

Single binary entry point connecting all layers.

---

## File Layout

```
crates/
  aegx-types/src/
    lib.rs              # Re-exports all types and canonical functions
    canonical.rs        # AEGX_CANON_0_1 deterministic JSON + SHA-256
    principal.rs        # Principal trust lattice (8 variants)
    taint.rs            # TaintFlags bitflags (8 flags)
    record.rs           # All shared types (TypedRecord, PolicyPack, etc.)
    error.rs            # AegxError enum
  aegx-records/src/
    lib.rs              # Records and audit chain management
    records.rs          # JSONL record I/O with blob promotion
    audit_chain.rs      # Hash-linked audit chain
    config.rs           # State directory resolution
  aegx-bundle/src/
    lib.rs              # Bundle packaging and verification
    bundle.rs           # Export/import with zip security
    verify.rs           # 10-step bundle verification
    report.rs           # Report generation
  aegx-guard/src/
    lib.rs              # Policy engine and guard surfaces
    guard.rs            # Guard evaluation + cross-surface correlation
    policy.rs           # Policy loading, evaluation, fail-closed
    scanner.rs          # 8-category injection scanner
    output_guard.rs     # Output leakage detection
    alerts.rs           # Threat alert system
    metrics.rs          # Guard performance metrics
    file_read_guard.rs  # Sensitive file read guard
    network_guard.rs    # Network egress monitor
    skill_verifier.rs   # ClawHavoc skill scanner
  aegx-runtime/src/
    lib.rs              # Runtime orchestration
    hooks.rs            # Integration hooks for all operations
    snapshot.rs         # Snapshot management
    rollback_policy.rs  # RVU rollback with auto-recovery
    workspace.rs        # MI chokepoint (routes through hooks)
    prove.rs            # /prove query engine
    sandbox_audit.rs    # OS sandbox verification
  aegx-runtime/tests/
    unified_pipeline.rs # Integration tests for theorem pipeline
  aegx-cli/src/
    main.rs             # CLI entry point
    cli.rs              # Command definitions and handlers
docs/                   # Documentation
```

## Documentation

### Getting Started

| Guide | Audience | Description |
|-------|----------|-------------|
| [Installation Guide](docs/INSTALL.md) | Everyone | Prerequisites, build, install, platform notes |
| [Quickstart Tutorial](docs/QUICKSTART.md) | Everyone | Create your first bundle in 5 minutes |
| [CLI Reference](docs/CLI_REFERENCE.md) | Everyone | Every command, flag, and exit code |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Everyone | Common errors and how to fix them |

### For Agent Developers

| Guide | Description |
|-------|-------------|
| [Agent Integration Guide](docs/AGENT_INTEGRATION.md) | Step-by-step integration for AI agents and pipelines |
| [ClawHub Integration](docs/clawhub-integration.md) | ClawHub marketplace integration & ClawHavoc prevention |

### Technical Reference

| Document | Description |
|----------|-------------|
| [AEGX v0.1 Format Specification](docs/SPEC.md) | Formal specification of the bundle format |
| [Bundle Format Guide](docs/BUNDLE_FORMAT_GUIDE.md) | Visual walkthrough of every file in a bundle |
| [Verification Guide](docs/VERIFICATION_GUIDE.md) | What verify checks and how to interpret results |

### Security

| Document | Description |
|----------|-------------|
| [Threat Model](docs/THREAT_MODEL.md) | AEGX security analysis and mitigations |
| [ClawHub Integration](docs/clawhub-integration.md) | ClawHub marketplace & ClawHavoc prevention |
| [Changelog](docs/CHANGELOG.md) | Release notes |

## License

Copyright 2026 Daniel Foo Jun Wei / Provenable.ai.

The **source code** in this repository is licensed under the Apache License, Version
2.0 — you may freely use, modify, and distribute it in compliance with the License.
See [LICENSE](LICENSE) for full terms.

The **AEGX format specification** (`docs/SPEC.md`) is the original intellectual
property of Daniel Foo Jun Wei / Provenable.ai and is provided for reference only.
Creating independent or competing implementations of the AEGX format requires prior
written permission. See [NOTICE](NOTICE) for details.

"Provenable.ai", "Proven", "PRV", "AEGX", and "AER" are trademarks of
Daniel Foo Jun Wei / Provenable.ai. For licensing inquiries: licensing@provenable.ai
