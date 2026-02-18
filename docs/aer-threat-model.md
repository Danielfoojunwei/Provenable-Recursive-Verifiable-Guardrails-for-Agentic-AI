# AER Threat Model

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
