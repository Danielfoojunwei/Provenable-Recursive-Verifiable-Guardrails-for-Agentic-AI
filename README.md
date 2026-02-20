# Provenable.ai — Recursive Verifiable Guardrails for Agentic AI

Structural security enforcement for agentic AI systems. This project provides
the **AEGX v0.1** tamper-evident evidence bundle format and the **Agent Evidence
& Recovery (AER)** runtime that together deliver provable integrity guarantees
for agent sessions, tool invocations, file mutations, and control-plane
changes.

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

### Outcome 5: Supply-Chain Defense (ClawHavoc Prevention)

A **pre-install skill verifier** scans skill packages before they enter the
runtime, detecting all six ClawHavoc attack vectors. The `hooks::on_skill_install()`
chokepoint ensures no skill is installed without verification, and every
verification result is recorded as tamper-evident evidence.

**Concrete guarantee:** `skill_verifier::verify_skill_package()` scans SKILL.md
through the full 8-category input scanner plus 6 ClawHavoc-specific pattern
detectors. Critical/High findings block installation; Medium findings require
explicit user approval. 16 tests validate detection of all attack vectors with
zero false positives on legitimate skills.

### Outcome 6: Automated Recovery & Agent Notification (v0.1.4)

Three automated rollback mechanisms ensure the system can detect, recommend,
and execute recovery without manual intervention:

1. **Auto-Snapshot Before CPI Changes** — Every allowed control-plane mutation
   (skill install, permission change, etc.) creates a pre-change snapshot
   automatically, ensuring rollback is always possible.
2. **Rollback Recommendation** — When 3+ guard denials occur within 2 minutes,
   the system emits a `RollbackRecommended` alert with the snapshot target and
   CLI command. The agent relays this to the user.
3. **Threshold-Based Auto-Rollback** — When 5+ denials occur within 2 minutes,
   the system automatically rolls back to the most recent snapshot, emits a
   `CRITICAL` alert, and the agent immediately notifies the user.

Additionally, **RVU contamination scope computation** traces the provenance
DAG from any contaminated record to find all downstream records that may be
affected, enabling targeted review or rollback.

**Concrete guarantee:** The `/prove` endpoint includes `rollback_status` with
`agent_messages` that the agent MUST relay to the user. Every auto-rollback
and contamination event is recorded as tamper-evident evidence.

### Outcome 7: Self-Contained Portable Evidence

Bundles are self-contained directories (or `.aegx.zip` archives) containing
everything needed for independent, offline verification. No network access, no
trust in the producer, no special software beyond the verifier. Bundles can be
shared, archived, and audited by any party.

### Outcome 8: Host Environment Hardening (v0.1.6)

Four new guard surfaces close the remaining gaps between AER's policy
enforcement and host-level security:

1. **Dynamic Token Registry** — The `SystemPromptRegistry` singleton caches
   system prompt tokens and activates runtime discovery in the output guard.
   `config_with_runtime_discovery(system_prompt)` now receives the actual
   prompt, catching SCREAMING_CASE, camelCase, and `${params.*}` tokens
   dynamically. Backward compatible — callers passing `None` fall back to the
   static watchlist.
2. **File Read Guard** — `file_read_guard.rs` blocks untrusted principals from
   reading sensitive files (`.env`, `*.pem`, `*.key`, `id_rsa*`, `credentials`).
   Reads of files in `.aws/`, `.ssh/`, `.gnupg/` propagate `SECRET_RISK` taint.
   Defense in depth: the scanner's `SensitiveFileContent` category catches
   leaked credentials in tool output even if the hook is bypassed.
3. **Network Egress Monitor** — `network_guard.rs` evaluates outbound requests
   against domain allowlists/blocklists and payload size limits. Blocked by
   default: `webhook.site`, `requestbin.com`, `pipedream.net`,
   `canarytokens.com`, `interact.sh`, `burpcollaborator.net`. The scanner's
   `DataExfiltration` category detects suspicious URL patterns.
   `skill_verifier.rs` now detects hardcoded exfiltration URLs at install time.
4. **Sandbox Audit** — `sandbox_audit.rs` verifies the OS execution environment
   at session start: container detection (`/.dockerenv`, cgroup), seccomp
   status, namespace isolation, read-only root, resource limits. Emits
   `CRITICAL` alert if no sandboxing is detected. Records compliance level
   (Full/Partial/None) as tamper-evident evidence.

**Concrete guarantee:** Every guard decision, file-read block, network denial,
and sandbox audit result is recorded as tamper-evident evidence in the audit
chain. The `/prove` endpoint surfaces all four new surfaces in protection
reports and agent notifications.

---

## Formal Foundations

AER implements the structural guarantees from four published formal theorems:

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
| `FileSystem`       | MI (read-side) + NI | `guard.check_file_read()` — sensitive file access control |
| `NetworkIO`        | Noninterference + CPI | `guard.check_outbound_request()` — egress domain/payload evaluation |
| `SandboxCompliance`| CPI + RVU             | `sandbox_audit.audit_environment()` — OS sandbox verification |

| Output Guard Layer          | Theorem                       | What It Catches                       |
|-----------------------------|-------------------------------|---------------------------------------|
| Token watchlist (static)    | MI (read-side)                | Internal tokens (SILENT_REPLY_TOKEN, HEARTBEAT_OK, etc.) |
| Token watchlist (dynamic)   | MI Dynamic Discovery Corollary| Runtime-discovered SCREAMING_CASE, camelCase, `${params.*}` |
| Structural patterns         | MI + CPI                      | Prompt structure disclosure (skill loading, reply tags, identity) |
| Section heuristic           | MI                            | Multi-section prompt dumps (4+ section headers) |

| Session-Level Defense           | Theorem Corollary               | What It Prevents                       |
|---------------------------------|---------------------------------|----------------------------------------|
| Conversation state tracker      | Conversational Noninterference  | Crescendo/multi-turn extraction across message sequences |
| Canary injection escalation     | CPI Behavioral Constraint       | Forced-phrase injection denied for ALL principals |
| Semantic intent detection       | Semantic Intent (Noninterference) | Novel extraction phrasings (verb + target regex matching) |

| Supply-Chain Defense             | Theorem(s)                      | What It Prevents (ClawHavoc)            |
|----------------------------------|---------------------------------|-----------------------------------------|
| Pre-install skill verifier       | CPI + Noninterference           | Shell commands, reverse shells, credential theft, memory poisoning |
| Name collision detection         | CPI                             | Skill precedence exploitation (V5)      |
| Typosquatting detection          | CPI                             | Name similarity attacks (V6)            |
| MI write guard at runtime        | MI Theorem                      | Memory poisoning blocked structurally — **V4 fully prevented** |

| Automated Recovery (v0.1.4)        | Theorem(s)                      | What It Provides                        |
|------------------------------------|---------------------------------|-----------------------------------------|
| Auto-snapshot before CPI           | RVU Machine Unlearning          | Every CPI mutation has a rollback point |
| Rollback recommendation (3+ denials) | RVU + All four theorems       | Agent alerts user with snapshot target and CLI command |
| Auto-rollback (5+ denials)         | RVU Machine Unlearning          | Automatic recovery when attack burst detected |
| Contamination scope computation    | RVU Machine Unlearning          | Transitive closure identifies all affected downstream records |
| MI read-side taint tracking        | MI + Noninterference            | Untrusted readers get tainted provenance, preventing laundering |

| Host Environment Hardening (v0.1.6)    | Theorem(s)                      | What It Provides                        |
|----------------------------------------|---------------------------------|-----------------------------------------|
| Dynamic Token Registry                 | MI Dynamic Discovery Corollary  | System prompt tokens cached → output guard catches runtime-specific leaks |
| File Read Guard                        | MI (read-side) + Noninterference | Sensitive file reads blocked/tainted for untrusted principals |
| Network Egress Monitor                 | Noninterference + CPI           | Outbound exfiltration blocked; skill verifier detects hardcoded exfil URLs |
| Sandbox Audit                          | CPI + RVU                       | Environment trustworthiness verified and recorded as evidence |
| SensitiveFileContent scanner           | MI + Noninterference            | Leaked credentials caught in tool output (defense in depth) |
| DataExfiltration scanner               | Noninterference                 | Suspicious URL patterns in tool output detected |

---

## Empirical Validation: ZeroLeaks Benchmark

We ran the exact ZeroLeaks attack taxonomy — 36 real attack payloads — against
our ConversationIO guard using the actual scanner and output guard code.
**No mocks, no simulations, no cherry-picking** (`packages/aer/tests/zeroleaks_benchmark.rs`).

### Results (Worst-Case: USER Principal, Input Scanner Only)

| Metric                     | Before (No Guards) | v0.1.1 | v0.1.2 | v0.1.3 | v0.1.4 (Current) |
|----------------------------|--------------------|--------|--------|--------|-------------------|
| Extraction Success Rate    | 84.6% (11/13)      | 38.5%  | **15.4%** | 15.4% | **15.4% (2/13)**  |
| Injection Success Rate     | 91.3% (21/23)      | 4.3%   | **4.3%**  | 4.3%  | **4.3% (1/23)**   |
| **ZLSS (1-10, lower=better)** | **10/10**       | 2/10   | **1/10**  | 1/10  | **1/10**          |
| **Security Score (0-100)** | **2/100**           | 79/100 | **90/100**| 90/100| **90/100**        |
| Supply-chain (ClawHavoc)   | 0/6 vectors blocked | —      | —         | **6/6** | 6/6 detected    |
| Automated recovery         | None               | —      | —         | —     | **Auto-rollback + contamination scope** |
| MI read-side taint         | None               | —      | —         | —     | **Reader principal tracked** |
| Total tests                | —                  | 114    | 152       | 168   | 176      |
| **v0.1.6 (Current)** | | | | | |
| File read guard        | None               | —      | —         | —     | **Sensitive reads blocked + tainted** |
| Network egress monitor | None               | —      | —         | —     | **Domain blocklist + exfil detection** |
| Sandbox audit          | None               | —      | —         | —     | **Container/seccomp/namespace verified** |
| Dynamic token registry | None               | —      | —         | —     | **System prompt tokens cached at runtime** |
| Total tests            | —                  | 114    | 152       | 168   | **278 pass**      |

### Layer-by-Layer Breakdown

**Layer 1 — Input Scanner (with Semantic Intent + Session State):**

| Attack Type | Blocked | Suspicious (Tainted) | Clean (Passed) |
|-------------|---------|---------------------|----------------|
| Extraction (13 attacks) | 4 | 7 | 2 |
| Injection (23 attacks) | 13 | 9 | 1 |

**Layer 2 — Output Guard (with Dynamic Token Discovery):**

| Metric | Result |
|--------|--------|
| Leaked response patterns caught | 11/11 (100%) |
| False positives on clean responses | 0 |

**Layer 3 — Policy Enforcement:**

Suspicious verdicts carry taint flags that trigger policy denial:

| Taint Flag | Policy Rule | Effect |
|------------|-------------|--------|
| `INJECTION_SUSPECT` | `cio-deny-injection` | Denied for **all** principals (including USER) |
| `UNTRUSTED` | `cio-deny-untrusted-tainted` | Denied for WEB, SKILL, CHANNEL, EXTERNAL |

With policy enforcement for untrusted principals (the actual threat model for
Discord bots, web interfaces, and API integrations):
- **Injection success drops to 4.3%** (1/23 — only a bare canary word passes)
- **Extraction**: all tainted messages blocked; output guard catches the rest

### Gaps Addressed in v0.1.2 (Four Corollaries)

The jump from 79/100 to 90/100 came from four **corollaries** to the existing
theorems — no new theorems were needed:

| Gap (v0.1.1)          | Corollary                              | Theorem Basis          | Implementation |
|-----------------------|----------------------------------------|------------------------|----------------|
| Stateless scanner     | Conversational Noninterference         | Noninterference        | `conversation_state.rs` — session-level taint accumulation with crescendo detection |
| Canary injection soft | CPI Behavioral Constraint              | CPI Theorem            | `scanner.rs` — canary injection escalated to `INJECTION_SUSPECT` taint |
| Static watchlist      | MI Dynamic Token Discovery             | MI Theorem             | `output_guard.rs` — runtime extraction of SCREAMING_CASE, camelCase, `${params.*}` from actual system prompt |
| Brittle patterns      | Semantic Intent Detection              | Noninterference        | `scanner.rs` — regex verb+target analysis catches novel phrasings ("walk me through your skill loading") |

### Gaps Addressed in v0.1.3 (ClawHavoc Supply-Chain Defense)

The ClawHavoc incident (341 malicious skills on ClawHub) exposed a supply-chain
attack surface that runtime guards alone cannot address. v0.1.3 adds
**pre-install skill verification**:

| ClawHavoc Vector       | AER Defense                | Implementation |
|------------------------|---------------------------|----------------|
| V1: `curl \| bash` social engineering | Shell execution pattern detection | `skill_verifier.rs` — CRITICAL severity, blocks install |
| V2: Reverse shell backdoors | Reverse shell pattern detection | Detects `/dev/tcp/`, `nc -e`, Python/Ruby/Perl sockets |
| V3: Credential exfiltration | Credential access + exfiltration patterns | Detects `.clawdbot/.env`, `~/.ssh/`, API key references |
| V4: Memory poisoning | Memory file write pattern detection | Detects `open('SOUL.md', 'w')`, write-to-protected-file patterns |
| V5: Skill precedence exploit | Name collision detection | Case-insensitive match against existing skill registry |
| V6: Typosquatting | Levenshtein distance analysis | Flags names within edit distance ≤ 2 of popular skills |

See the full analysis: [ClawHub Integration & ClawHavoc Prevention](docs/clawhub-integration.md)

### Gaps Addressed in v0.1.4 (Automated Recovery & Theorem Gap Closures)

Six theorem execution gaps were identified and fixed:

| Gap | Theorem | Fix |
|-----|---------|-----|
| No auto-snapshot before CPI changes | RVU | `auto_snapshot_before_cpi()` creates rollback point before every allowed CPI mutation |
| No rollback recommendation on denial | RVU | `on_guard_denial()` emits `RollbackRecommended` alert at 3+ denials |
| No threshold-based auto-rollback | RVU | Auto-rollback at 5+ denials in 120s, `CRITICAL` alert emitted |
| No contamination scope computation | RVU | `compute_contamination_scope()` BFS on provenance DAG |
| MI reads had clean provenance | MI/Noninterference | `read_memory_file()` tracks reader principal and applies taint |
| Agent not notified of rollback events | All four | `/prove` includes `rollback_status.agent_messages` |

### Gaps Addressed in v0.1.6 (Host Environment Hardening)

Four implementation limitations identified in the architecture review have been
addressed with new guard surfaces:

| Limitation | Theorem | Fix |
|-----------|---------|-----|
| Output guard dynamic tokens never receive system prompt | MI Dynamic Discovery | `SystemPromptRegistry` singleton caches prompt; `on_system_prompt_available()` hook activates discovery |
| No file-read guards for sensitive files | MI (read-side) + Noninterference | `FileReadGuard` with denied/tainted basename patterns; `on_file_read()` hook |
| No outbound network monitoring | Noninterference + CPI | `NetworkGuard` with domain blocklist/allowlist; `on_outbound_request()` hook; skill verifier exfil URL detection |
| No OS sandbox verification | CPI + RVU | `SandboxAudit` checks container/seccomp/namespace/readonly-root at session start; emits compliance evidence |

### Remaining Honest Gaps

1. **No LLM-based semantic understanding** — Regex intent detection only. Novel
   attack phrasings not matching verb+target patterns may bypass detection.
2. **Benchmark tests individual messages** — Multi-turn session detection is
   implemented in `guard.rs` but not exercised by the per-message benchmark.
3. **Adversarial prompt evolution** — Static regex patterns may be outpaced by
   adversarial prompt engineering research.
4. **Output guard heuristic** — Section header detection may miss novel disclosure
   formats not matching the known header list.
5. **No LLM in the loop** — Benchmark measures scanner/guard detection rates, not
   whether the LLM would comply with the attack. Actual success rates depend on
   model behavior.
6. ~~No file-read guards~~ — **Addressed (v0.1.6):** `FileReadGuard` blocks/taints sensitive file reads. Scanner `SensitiveFileContent` category catches leaked credentials.
7. ~~No outbound network monitoring~~ — **Addressed (v0.1.6):** `NetworkGuard` provides domain blocklist/allowlist. Full enforcement requires OS-level egress proxy.

### How to Run the Benchmark

```bash
cd packages/aer
cargo test zeroleaks_full_benchmark -- --nocapture
```

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
- **File Read Guard (v0.1.6):** Blocks untrusted reads of sensitive files
  (`.env`, SSH keys, credentials) and taints reads from sensitive directories.
- **Network Egress Monitor (v0.1.6):** Evaluates outbound requests against
  domain blocklists/allowlists with payload size limits and exfiltration detection.
- **Sandbox Audit (v0.1.6):** Verifies OS-level sandboxing (container, seccomp,
  namespaces) at session start, recording compliance as tamper-evident evidence.

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
packages/aer/src/
  system_prompt_registry.rs  # v0.1.6: SystemPromptRegistry for dynamic token discovery
  file_read_guard.rs         # v0.1.6: Sensitive file read access control
  network_guard.rs           # v0.1.6: Outbound network request monitoring
  sandbox_audit.rs           # v0.1.6: OS sandbox environment verification
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
| [ClawHub Integration](docs/clawhub-integration.md) | ClawHub marketplace integration & ClawHavoc prevention |

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
