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


---

## Part 2: AER Runtime Threat Model


## Scope

Agent Evidence & Recovery (AER) provides **structural security guarantees** for agentic AI systems. It is designed to enforce control-plane integrity (CPI), memory integrity (MI), and provide verifiable evidence bundles and rollback capabilities.

AER operates as a reference monitor at the chokepoints where control-plane mutations and memory writes occur. It does **not** rely on LLM behavior, prompt secrecy, or text-based defenses.

### Why This Matters: Real-World Evidence

**ClawHavoc (Feb 2026)**: 341 malicious skills discovered on ClawHub (OpenClaw's official marketplace, 3,286+ skills, 1.5M+ downloads). 335 from a single coordinated campaign delivering the Atomic macOS Stealer. Attack vectors included social engineering (`curl | bash` in SKILL.md), reverse shell backdoors, `.clawdbot/.env` credential exfiltration, and SOUL.md/MEMORY.md memory poisoning. Source: [eSecurity Planet](https://www.esecurityplanet.com/threats/hundreds-of-malicious-skills-found-in-openclaws-clawhub/)

**ZeroLeaks Assessment**: Unprotected OpenClaw scored ZLSS 10/10 (worst), Security Score 2/100, with 84.6% extraction and 91.3% injection success across 36 attack vectors.

AER addresses these with structural enforcement validated by 278 passing tests across 7 test suites.

## What AER Guarantees

### Control-Plane Integrity (CPI)

**Theorem basis**: Under assumptions A1–A3 (provenance completeness, principal accuracy, memory persistence), if the AER verifier enforces guard rules at every control-plane mutation, then no untrusted input can alter the control plane.

**In practice**:
- Skills install/enable/disable/update operations are gated through a single chokepoint
- Tool registry changes require USER or SYS principal
- Permission and gateway auth changes are guarded
- Every allow/deny decision is recorded as tamper-evident evidence

**Boundary**: CPI protects the control-plane state (permissions, integrations, policies). It does NOT protect against:
- Data-plane attacks (reading sensitive data through authorized tools)
- Social engineering where a legitimate USER approves a malicious change

### Memory Integrity (MI)

**Theorem basis**: Memory Write Integrity guarantees immutability of protected memory, taint blocking for writes with untrusted provenance, and session isolation for cross-session transfers.

**In practice**:
- Workspace memory files (SOUL.md, AGENTS.md, TOOLS.md, USER.md, IDENTITY.md, HEARTBEAT.md, MEMORY.md) are guarded at a single write chokepoint
- Writes from WEB, SKILL, CHANNEL, or EXTERNAL principals are denied by default
- Writes with tainted provenance (UNTRUSTED, INJECTION_SUSPECT, WEB_DERIVED, SKILL_OUTPUT) are denied
- All decisions are recorded as evidence

**Boundary**: MI does NOT protect against:
- Inference-layer attacks within a single turn (model reasoning manipulation)
- Read confidentiality or data exfiltration through model outputs
- User-channel attacks where humans paste malicious content voluntarily

### ConversationIO Guard (Prompt Injection / Extraction Defense)

**Theorem basis**: The ConversationIO guard integrates all four published theorems to defend against prompt injection and system prompt extraction at the conversation boundary:

- **Noninterference Theorem** — Scanner detects encoded payloads, indirect injection, many-shot priming, and format overrides that would allow untrusted data to influence model behavior across trust boundaries.
- **CPI Theorem (A2)** — Scanner detects system/authority impersonation (fake `[SYSTEM]`/`[ADMIN]` tags) that attempt to override transport-assigned principals, and behavior manipulation that targets control-plane behavioral state.
- **MI Theorem (read-side)** — Output guard detects leaked internal tokens, structural prompt patterns, and identity statements. The system prompt is a protected memory artifact; unauthorized disclosure violates confidentiality.
- **RVU Machine Unlearning** — Every blocked attack is recorded as a tamper-evident `GuardDecision` in the audit chain, enabling contamination detection and provenance-based closure computation.

**In practice** (two-layer enforcement):

Layer 1 — Input Scanner (8 detection categories):

| Category | Taint | ZeroLeaks Attacks | Theorem |
|----------|-------|-------------------|---------|
| `SystemImpersonation` | `INJECTION_SUSPECT` + `UNTRUSTED` | 4.1: system/authority impersonation | CPI (A2) |
| `IndirectInjection` | `INJECTION_SUSPECT` + `UNTRUSTED` | 4.1: document/email/code injection | Noninterference |
| `BehaviorManipulation` | `INJECTION_SUSPECT` + `UNTRUSTED` | 4.1: persona/behavior override | CPI |
| `FalseContextInjection` | `INJECTION_SUSPECT` + `UNTRUSTED` | 4.1: false memory/context | MI + Noninterference |
| `EncodedPayload` | `INJECTION_SUSPECT` + `UNTRUSTED` | 4.1: base64/ROT13/reversal | Noninterference |
| `ExtractionAttempt` | `UNTRUSTED` | 3.1-3.11: all extraction variants | MI (read-side) |
| `ManyShotPriming` | `UNTRUSTED` | 3.2, 3.9: 8/14-example priming | Noninterference |
| `FormatOverride` | `UNTRUSTED` | 4.1: format/language/case override | Noninterference |

Layer 2 — Output Guard (leaked-content detection):
- Internal tokens: `SILENT_REPLY_TOKEN`, `HEARTBEAT_OK`, `buildSkillsSection`, etc.
- Structural patterns: skill loading logic, memory search protocol, reply tag syntax
- Identity statements: platform identity, masked variants
- Multi-section heuristic: 4+ section headers indicate prompt dump

Layer 3 — Session State (v0.1.2, Conversational Noninterference Corollary):
- Sliding window of 10 messages / 5 minutes per session
- Accumulated extraction score with threshold 1.5
- Crescendo detection: accumulated score, sequential probe, sustained extraction (3+ messages)
- Session isolation via per-session state

Layer 4 — Semantic Intent Detection (v0.1.2, Noninterference Semantic Corollary):
- Regex verb+target matching ("walk me through your skill loading", "explain your exact protocol")
- Catches novel phrasings beyond static substring patterns
- EXTRACTION_VERBS × EXTRACTION_TARGETS combinatorial coverage

Layer 5 — CPI Behavioral Constraint (v0.1.2):
- Canary/forced-phrase injection escalated to `INJECTION_SUSPECT` taint
- Blocked for ALL principals (including USER) via `cio-deny-injection` policy

Layer 6 — Dynamic Token Discovery (v0.1.2, MI Dynamic Discovery Corollary):
- `extract_protected_identifiers()` discovers SCREAMING_CASE, camelCase, `${params.*}` from actual system prompt
- `config_with_runtime_discovery()` merges static watchlist with runtime-discovered tokens

Layer 7 — Pre-Install Skill Verification (v0.1.3, CPI + Noninterference):
- `skill_verifier::verify_skill_package()` scans skill packages before installation
- Detects all 6 ClawHavoc attack vectors: shell commands (V1), reverse shells (V2), credential exfiltration (V3), memory poisoning (V4), name collision (V5), typosquatting (V6)
- `hooks::on_skill_install()` emits tamper-evident verification record
- See [ClawHub Integration](clawhub-integration.md) for full analysis

Layer 8 — File Read Guard (v0.1.6, MI read-side + Noninterference):
- `file_read_guard.rs` blocks untrusted principals from reading sensitive files
- Default denied basenames: `.env*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `credentials`, `*.secret`, `.netrc`, `.pgpass`
- Default tainted directories: `.aws/*`, `.ssh/*`, `.gnupg/*`, `.docker/config.json`
- `hooks::on_file_read()` evaluates reads, records with proper taint, feeds rollback policy
- Defense in depth: scanner `SensitiveFileContent` category catches leaked credentials in tool output

Layer 9 — Network Egress Monitor (v0.1.6, Noninterference + CPI):
- `network_guard.rs` evaluates outbound requests against domain allowlist/blocklist
- Default blocked domains: `webhook.site`, `requestbin.com`, `pipedream.net`, `canarytokens.com`, `interact.sh`, `burpcollaborator.net`
- Payload size limits and exfiltration heuristics (base64 in query params)
- `hooks::on_outbound_request()` evaluates domain/payload, records with taint
- Scanner `DataExfiltration` category detects suspicious URL patterns in tool output
- `skill_verifier.rs` detects hardcoded exfiltration URLs at install time

Layer 10 — Sandbox Audit (v0.1.6, CPI + RVU):
- `sandbox_audit.rs` verifies the OS execution environment at session start
- Container detection: `/.dockerenv`, `/proc/1/cgroup`, `KUBERNETES_SERVICE_HOST`
- Seccomp detection: `/proc/self/status` Seccomp line (disabled/strict/filter)
- Namespace detection: `/proc/self/ns/` symlinks (pid, net, mnt, user)
- Read-only root filesystem, resource limits parsing
- Compliance levels: Full (container + seccomp + namespace), Partial, None
- `hooks::on_session_start()` auto-runs audit, emits CRITICAL/HIGH alerts if insufficient

Layer 11 — Dynamic Token Registry (v0.1.6, MI Dynamic Discovery Corollary):
- `system_prompt_registry.rs` singleton caches system prompt tokens
- `hooks::on_system_prompt_available()` activates discovery transparently
- Output guard queries: caller config → registry → static default (three-tier fallback)
- Backward compatible — callers passing `None` fall back to static watchlist

**Empirical validation** (ZeroLeaks benchmark, no mocks — `packages/aer/tests/zeroleaks_benchmark.rs`):

| Metric | Before | v0.1.1 | v0.1.2 | v0.1.3 | v0.1.4 | v0.1.6 (Current) |
|--------|--------|--------|--------|--------|--------|-------------------|
| Extraction success | 84.6% | 38.5% | **15.4%** | 15.4% | 15.4% | **15.4%** (worst-case USER) |
| Injection success | 91.3% | 4.3% | **4.3%** | 4.3% | 4.3% | **4.3%** (worst-case USER) |
| ZLSS (1-10) | 10/10 | 2/10 | **1/10** | 1/10 | 1/10 | **1/10** |
| Security Score | 2/100 | 79/100 | **90/100** | 90/100 | 90/100 | **90/100** |
| Output guard catch rate | N/A | 11/11 | 11/11 | 11/11 | 11/11 | 11/11 (100%) |
| ClawHavoc vectors detected | 0/6 | — | — | **6/6** | 6/6 | 6/6 |
| Auto-recovery | None | — | — | — | Auto-rollback | **Auto-rollback + contamination scope** |
| MI read-side taint | None | — | — | — | Reader tracked | **Reader principal tracked** |
| File read guard | None | — | — | — | — | **Sensitive reads blocked + tainted** |
| Network egress monitor | None | — | — | — | — | **Domain blocklist + exfil detection** |
| Sandbox audit | None | — | — | — | — | **Container/seccomp/namespace verified** |
| Dynamic token registry | None | — | — | — | — | **System prompt tokens cached** |
| Total tests passing | — | 114 | 152 | 168 | 176 | **278** |

**Boundary**: ConversationIO does NOT protect against:
- Novel phrasings not matching regex verb+target patterns
- Attacks where the USER principal is the attacker and no injection taint is detected
- Model-internal reasoning manipulation that doesn't trigger syntactic patterns
- Adversarial prompt evolution that outpaces static regex patterns

### Tamper-Evident Evidence

**Guarantee**: The append-only hash chain (Merkle-style) ensures that:
- Any modification to the audit log is detectable
- Records are linked by SHA-256 hashes
- The full chain can be verified independently

**Boundary**: The chain does not prevent deletion of the entire log — it detects tampering within a chain. Physical security of the state directory is assumed.

### RVU Rollback & Automated Recovery (v0.1.4)

**Guarantee**: Snapshots capture content hashes of all files in scope. Rollback restores files to their exact snapshotted content and emits a verifiable Rollback record.

**v0.1.4 enhancements**:
- **Auto-snapshot before CPI changes**: Every allowed control-plane mutation creates a rollback point with cooldown, ensuring recoverability (RVU §2)
- **Rollback recommendation**: 3+ denials in 120s → `RollbackRecommended` alert with snapshot target and CLI command
- **Threshold-based auto-rollback**: 5+ denials in 120s → automatic rollback to most recent snapshot + `CRITICAL` alert
- **Contamination scope computation**: `compute_contamination_scope()` traces the provenance DAG via BFS to identify all downstream records affected by a contaminated source (RVU closure property)
- **Agent notification**: `/prove` endpoint includes `rollback_status.agent_messages` that the agent MUST relay to the user

**Boundary**: Rollback restores file content but cannot reverse side effects (e.g., external API calls, network traffic). Session logs are NOT rolled back (they are audit evidence). Auto-rollback requires a prior snapshot to exist.

## Trust Lattice

```
SYS (trust level 5)
 └── USER (trust level 4)
      └── TOOL_AUTH (trust level 3)
           └── TOOL_UNAUTH (trust level 2)
                └── WEB, SKILL (trust level 1)
                     └── CHANNEL, EXTERNAL (trust level 0)
```

Principals are assigned based on **transport channel**, not content claims. This prevents confused-deputy attacks.

## Taint Model

Taint flags propagate conservatively: if any parent is tainted, the output is tainted. Taint flags:

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

## Assumptions

1. **A1 (Provenance Completeness)**: Every derived record tracks all data sources in its parent list
2. **A2 (Principal Accuracy)**: Principals are assigned from transport channels, not content
3. **A3 (Memory Persistence)**: Provenance chains survive store/load cycles
4. **A4 (Runtime Integrity)**: The AER runtime itself is not compromised
5. **A5 (Filesystem Access)**: The state directory has appropriate OS-level permissions

## What AER Does NOT Cover

- Model behavior during inference (AER operates structurally, not on model internals)
- ~~Prompt injection within a single inference turn~~ **Addressed**: The ConversationIO scanner (with semantic intent detection and session state tracking) detects known injection patterns and blocks 22/23 injection attacks. Multi-turn crescendo attacks are now detected via session-level taint accumulation.
- ~~Data exfiltration through authorized read paths~~ **Addressed**: The output guard with dynamic token discovery detects leaked system prompt tokens at runtime, adapting to the actual system prompt content. Remaining gap: exfiltration of user data or tool outputs that don't match token patterns.
- Physical compromise of the host system
- Availability attacks / performance degradation
- Social engineering of legitimate users

## Residual Risk After Guards (v0.1.2 + v0.1.3 + v0.1.4 + v0.1.6)

### v0.1.2 — Conversation Guard Corollaries

| Gap (v0.1.1) | Status | Corollary Applied |
|--------------|--------|-------------------|
| Multi-turn crescendo | **Addressed** | Conversational Noninterference — session-level taint accumulation |
| Novel phrasings | **Partially addressed** | Semantic Intent Detection — regex verb+target matching |
| Format override (USER) | **Addressed** | CPI Behavioral Constraint — canary injection → INJECTION_SUSPECT |
| Unknown internal tokens | **Addressed** | MI Dynamic Discovery — runtime extraction from system prompt |

### v0.1.3 — Supply-Chain Defense (ClawHavoc)

| Gap | Status | Defense Applied |
|-----|--------|----------------|
| No pre-install skill scanning | **Addressed** | `skill_verifier.rs` — scans all code + SKILL.md for 6 attack vectors |
| No name collision detection | **Addressed** | Case-insensitive registry comparison at install time |
| No typosquatting detection | **Addressed** | Levenshtein distance ≤ 2 against popular skill names |
| Memory poisoning by skills | **Already addressed (v0.1.0)** | MI guard blocks SKILL principal writes to all memory files |
| No file-read guards | **Addressed (v0.1.6)** | `FileReadGuard` blocks/taints sensitive file reads; scanner `SensitiveFileContent` catches leaked credentials |
| No outbound network monitoring | **Addressed (v0.1.6)** | `NetworkGuard` domain blocklist/allowlist; `DataExfiltration` scanner; skill verifier exfil URL detection |

### v0.1.4 — Automated Recovery & Theorem Gap Closures

| Gap | Status | Fix Applied |
|-----|--------|-------------|
| No auto-snapshot before CPI | **Addressed** | `rollback_policy::auto_snapshot_before_cpi()` with cooldown |
| No rollback recommendation | **Addressed** | `on_guard_denial()` emits `RollbackRecommended` at 3+ denials |
| No threshold-based auto-rollback | **Addressed** | Auto-rollback at 5+ denials in 120s + `CRITICAL` alert |
| No contamination scope computation | **Addressed** | `compute_contamination_scope()` BFS on provenance DAG |
| MI reads had clean provenance | **Addressed** | `read_memory_file()` tracks reader principal and applies taint |
| Agent not notified of rollback | **Addressed** | `/prove` includes `rollback_status.agent_messages` |

### v0.1.6 — Host Environment Hardening

| Gap | Status | Fix Applied |
|-----|--------|-------------|
| Dynamic tokens never receive system prompt | **Addressed** | `SystemPromptRegistry` singleton with `on_system_prompt_available()` hook |
| No file-read guards for sensitive files | **Addressed** | `FileReadGuard` with denied/tainted basename patterns; `on_file_read()` hook |
| No outbound network monitoring | **Addressed** | `NetworkGuard` with domain blocklist/allowlist; `on_outbound_request()` hook; skill verifier exfil URL detection |
| No OS sandbox verification | **Addressed** | `SandboxAudit` with container/seccomp/namespace checks at session start |

### Remaining Residual Risks

| Attack Class | Estimated Risk | Why |
|-------------|---------------|-----|
| LLM-based adversarial evolution | Unknown | Static regex patterns may be outpaced by adversarial research |
| Novel disclosure formats | Low | Output guard heuristic (section headers) may miss novel formats |
| Model-internal reasoning manipulation | Not addressable | AER operates structurally, not on model internals |
| Social engineering of USER principal | Not addressable | Legitimate USER approvals cannot be structurally prevented |
| ~~File-read exfiltration~~ | ~~Medium~~ **Low** | **Addressed (v0.1.6):** `FileReadGuard` blocks/taints sensitive reads; scanner catches leaked credentials. Residual: skills with direct filesystem access bypassing hooks |
| ~~Outbound network exfiltration~~ | ~~Medium~~ **Low** | **Addressed (v0.1.6):** `NetworkGuard` provides policy-layer blocklist. Residual: full enforcement requires OS-level egress proxy (squid, envoy, eBPF) |
| Sandbox bypass | Low–Medium | `SandboxAudit` detects but cannot enforce sandboxing; container escape or seccomp bypass remains platform responsibility |

### Roadmap (path from 90/100 to ~98/100)

1. **LLM-assisted semantic classification** — Use a lightweight classifier model to detect extraction intent beyond regex
2. **Adversarial pattern update pipeline** — Automated ingestion of new attack patterns from security research
3. **Output guard learning** — Dynamically learn output patterns that indicate disclosure from past incidents
4. ~~**FileRead guard surface**~~ — **Done (v0.1.6):** `FileReadGuard` blocks/taints sensitive file reads for untrusted principals
5. ~~**Sandbox integration guide**~~ — **Done (v0.1.6):** `SandboxAudit` verifies container/seccomp/namespace at session start; reference configs for squid, envoy, eBPF documented
6. **OS-level egress proxy enforcement** — Integrate `NetworkGuard` policy with squid/envoy/eBPF for true network enforcement
7. **Kernel-level seccomp profile generation** — Auto-generate seccomp profiles from skill manifests
