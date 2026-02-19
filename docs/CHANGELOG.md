# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.6] - 2026-02-17

### Added

- **System Prompt Registry** (`system_prompt_registry.rs`) — Singleton that
  caches system prompt tokens for dynamic output guard discovery. Provides
  `register_system_prompt()` and `register_tokens_only()` entry points.
  `on_system_prompt_available()` hook activates discovery transparently.
  Backward compatible — callers passing `None` fall back to static watchlist.
- **File Read Guard** (`file_read_guard.rs`) — Sensitive file access control
  with denied and tainted basename patterns. Default denied: `.env*`, `*.pem`,
  `*.key`, `id_rsa*`, `id_ed25519*`, `credentials`, `*.secret`, `.netrc`,
  `.pgpass`. Default tainted: `.aws/*`, `.ssh/*`, `.gnupg/*`,
  `.docker/config.json`, `*token*`, `*password*`. Integrated via
  `hooks::on_file_read()`.
- **Network Egress Monitor** (`network_guard.rs`) — Outbound request
  evaluation with domain allowlist/blocklist, payload size limits, and
  exfiltration heuristics. Default blocked domains: `webhook.site`,
  `requestbin.com`, `pipedream.net`, `canarytokens.com`, `interact.sh`,
  `burpcollaborator.net`. Integrated via `hooks::on_outbound_request()`.
  `skill_verifier.rs` now detects hardcoded exfiltration URLs at install time.
- **Sandbox Audit** (`sandbox_audit.rs`) — OS sandbox environment verification
  at session start. Checks: container detection (`/.dockerenv`, cgroup),
  seccomp status (`/proc/self/status`), namespace isolation (`/proc/self/ns/`),
  read-only root filesystem, resource limits. Compliance levels: Full, Partial,
  None. Integrated via `hooks::on_session_start()`. Emits `CRITICAL` alert if
  no sandboxing detected.
- **Scanner Categories**: `SensitiveFileContent` (defense-in-depth for leaked
  credentials in tool output), `DataExfiltration` (suspicious URL patterns).
- **Record Type**: `NetworkRequest` for outbound network call evidence.
- New hooks: `on_system_prompt_available()`, `on_file_read()`,
  `on_outbound_request()`.
- Guard surfaces: `FileSystem`, `NetworkIO`, `SandboxCompliance`.
- Total tests: 185 → **278 pass**.

### Changed

- `hooks::on_session_start()` now runs sandbox audit automatically and emits
  compliance evidence.
- `hooks::on_message_output()` uses `SystemPromptRegistry` when available,
  falling back to static config.
- `output_guard.rs` — `check_output()` now queries registry before caller
  config before static default (three-tier fallback chain).
- `prove::ProveResponse` version updated to `0.1.6`.

### Theorem Gap Closures (v0.1.6)

| Limitation | Theorem | Status | Fix |
|-----------|---------|--------|-----|
| Dynamic tokens never receive system prompt | MI Dynamic Discovery | **Addressed** | `SystemPromptRegistry` singleton with `on_system_prompt_available()` hook |
| No file-read guards | MI (read-side) + Noninterference | **Addressed** | `FileReadGuard` with denied/tainted patterns, `on_file_read()` hook |
| No outbound network monitoring | Noninterference + CPI | **Addressed** | `NetworkGuard` with domain blocklist/allowlist, `on_outbound_request()` hook |
| No OS sandbox verification | CPI + RVU | **Addressed** | `SandboxAudit` with container/seccomp/namespace checks at session start |

## [0.1.5] - 2026-02-15

### Added

- **Agent Notification System** (`agent_notifications.rs`) — Thread-safe,
  append-only notification store ensuring NO event is silent. Every guard
  decision, snapshot, rollback, denial, alert, and skill verification produces
  a human-readable notification with severity, source, message, record ID,
  and suggested action for the agent to relay to the user.
- 9 new unit tests for agent notification system (notify/drain, peek, capacity,
  level filtering, serialization, convenience helpers, display formats).

### Changed

- **hooks.rs — Zero Silent Drops**: All `let _` drops of rollback policy results
  replaced with proper notification dispatch via `notif::notify_denial_policy()`.
  Auto-snapshot failures now emit `notify_auto_snapshot_failed()` instead of
  being silently swallowed by `unwrap_or(None)`.
- **hooks.rs — Rich Rationales**: All `GuardDecisionDetail` objects now include
  descriptive rationale strings instead of empty strings. CPI denials explain
  "CPI change 'X' denied for Y principal (taint: Z)". MI denials explain
  "Memory write to 'X' denied for Y principal". CIO denials explain
  "Inbound message from X blocked by rule Y". Output blocks explain
  "Output blocked: N leaked tokens, M structural patterns detected".
- **hooks.rs — Full Notification Coverage**: Every event path now emits an
  agent notification: CPI allow/deny, MI allow/deny, CIO input block,
  output leakage block, skill verify (all verdicts), proxy misconfig,
  auto-snapshot success/failure, contamination scope, denial policy results.
- **prove.rs — Agent Notifications in Response**: `ProveResponse` now includes
  `agent_notifications: Vec<AgentNotification>` drained on each query.
  Agent notifications appear in the formatted report under
  "Agent Notifications" section with icons, source tags, and suggested actions.
- **prove.rs — Expanded ProtectionSummary**: Added `auto_rollbacks`,
  `rollback_recommendations`, `contamination_events`, `skills_verified`
  fields to `ProtectionSummary`.
- **prove_cmd.rs — New Category Filters**: CLI `prove` command now supports
  filtering by EXTRACTION, LEAKAGE, ROLLBACK, AUTO_ROLLBACK, CONTAMINATION
  categories.
- `prove::ProveResponse` version updated to `0.1.5`.
- Total tests: 176 → **185 pass** (9 new agent notification tests).

### UX/Agent Experience Gaps Closed (v0.1.5)

| Gap | Severity | Fix |
|-----|----------|-----|
| `let _` drops agent messages from denial policy | Critical | Replaced with `notif::notify_denial_policy()` |
| Auto-snapshot failures silently ignored | High | `notify_auto_snapshot_failed()` emitted with suggested action |
| Empty rationale in all denial `GuardDecisionDetail` | High | Rich format strings with principal, rule, taint context |
| No notification for CPI/MI allows | Medium | `notify_cpi_allowed()`, `notify_mi_write_allowed()` |
| No notification for skill verification | High | `notify_skill_verdict()` for all verdicts (allow/require/deny) |
| Prove response missing auto-rollback/contamination/skill stats | Medium | Added to `ProtectionSummary` and formatted report |
| Contamination alert emission failures silent | High | Error notification + fallback message |
| CLI prove_cmd missing category filters | Medium | 5 new categories added |
| Agent notifications not drained to prove response | Critical | `drain_notifications()` in `execute_query()` |

## [0.1.4] - 2026-02-15

### Added

- **Automated Rollback Policy Engine** (`rollback_policy.rs`) — Three automated
  rollback mechanisms addressing RVU Machine Unlearning theorem gaps:
  1. **Auto-Snapshot Before CPI Changes** — Every allowed control-plane mutation
     now creates a rollback point (with cooldown), ensuring recoverability if an
     approved change turns out harmful (RVU §2).
  2. **Rollback Recommendation on Denial** — When 3+ guard denials occur within
     120 seconds, emits a `RollbackRecommended` alert with the recommended
     snapshot ID and CLI command for the agent to relay to the user.
  3. **Threshold-Based Auto-Rollback** — When 5+ denials occur within 120 seconds,
     automatically rolls back to the most recent snapshot and emits a `CRITICAL`
     `AutoRollback` alert. The agent MUST notify the user immediately.
- **RVU Contamination Scope Computation** (`rollback_policy::compute_contamination_scope()`)
  — Computes the transitive closure of records contaminated by a source record.
  Uses BFS on the provenance DAG to identify all downstream records affected by
  a successful attack, enabling targeted review or rollback.
- **MI Read-Side Taint Tracking** — `workspace::read_memory_file()` now accepts
  `principal` and `taint` parameters. Untrusted principals reading protected
  memory files get `UNTRUSTED` taint applied to the FileRead record, preventing
  clean-provenance laundering. Previously all reads were recorded as `Principal::Sys`
  with empty taint regardless of who was reading.
- **Agent Alert Integration** — Three new alert categories
  (`RollbackRecommended`, `AutoRollback`, `ContaminationDetected`) surface
  through the `/prove` query engine. The `ProveResponse` now includes a
  `rollback_status` field with `agent_messages` that the agent MUST relay
  to the user.
- **Rollback & Recovery section** in `/prove` report output showing auto-rollback
  count, recommendations, contamination events, and ACTION REQUIRED messages.
- 8 new unit tests for rollback policy engine (denial tracking, cooldown,
  serialization, threshold constants).

### Changed

- `hooks::on_control_plane_change()` now creates auto-snapshot before allowing
  CPI mutations and feeds denials into the rollback policy engine.
- `hooks::on_file_write()` feeds MI denials into the rollback policy engine.
- `hooks::on_message_input()` feeds CIO denials into the rollback policy engine.
- `hooks::on_message_output()` computes RVU contamination scope on leakage detection
  and feeds denials into the rollback policy engine.
- `prove::ProveResponse` version updated to `0.1.4`.
- Total tests: 168 → **176 pass** (8 new rollback policy tests).

### Theorem Gap Closures (v0.1.4)

| Gap | Theorem | Status | Fix |
|-----|---------|--------|-----|
| No auto-snapshot before CPI | RVU | **Addressed** | `auto_snapshot_before_cpi()` in `on_control_plane_change()` |
| No rollback recommendation | RVU | **Addressed** | `on_guard_denial()` at threshold 3 |
| No auto-rollback on burst | RVU | **Addressed** | `on_guard_denial()` at threshold 5 |
| No contamination scope | RVU | **Addressed** | `compute_contamination_scope()` with BFS on DAG |
| MI reads had clean provenance | MI/Noninterference | **Addressed** | `read_memory_file()` now tracks reader principal and taint |
| Agent not notified of rollback | All | **Addressed** | `/prove` includes `rollback_status.agent_messages` |

## [0.1.3] - 2026-02-15

### Added

- **ClawHub Integration & ClawHavoc Prevention** — Deep dive analysis mapping
  all 6 ClawHavoc attack vectors (V1-V6) to specific AER structural defenses.
  New `docs/clawhub-integration.md` with attack taxonomy, defense coverage
  matrix, gap analysis, and integration architecture.
- **Skill Verifier Module** (`skill_verifier.rs`) — Pre-install skill package
  verification that scans for all 6 ClawHavoc attack vectors before a skill
  enters the runtime:
  - V1: Shell execution patterns (`curl | bash`, `pip install`, `sudo`)
  - V2: Reverse shell backdoors (`/dev/tcp/`, `nc -e`, Python/Ruby/Perl sockets)
  - V3: Credential exfiltration (`.clawdbot/.env`, `~/.ssh/`, API keys)
  - V4: Memory poisoning (`open('SOUL.md', 'w')`, write to protected files)
  - V5: Skill precedence exploitation (name collision detection)
  - V6: Typosquatting (Levenshtein distance-based similarity detection)
- **`hooks::on_skill_install()`** — New hook point for pre-install skill
  verification, emits tamper-evident SkillVerification evidence record.
- 16 new unit tests for skill verifier covering all attack vectors, false
  positive resistance, and edge cases.
- ClawHub integration referenced in README.md, threat model, and CPI/MI rules.

## [0.1.2] - 2026-02-15

### Added

- **Conversational Noninterference Corollary** — Session-level state tracking
  for crescendo/multi-turn attack detection (`conversation_state.rs`).
  Sliding window of 10 messages / 5 minutes with accumulated extraction score
  threshold, sequential probe detection, and sustained extraction detection.
- **CPI Behavioral Constraint Corollary** — Canary/forced-phrase injection
  escalated from `UNTRUSTED` to `INJECTION_SUSPECT` taint, blocked for ALL
  principals (including USER) via `cio-deny-injection` policy rule.
- **MI Dynamic Token Discovery Corollary** — Runtime extraction of
  SCREAMING_CASE tokens, camelCase function names, and `${params.*}` template
  variables from the actual system prompt (`output_guard.rs:extract_protected_identifiers()`).
  `config_with_runtime_discovery()` merges static watchlist with discovered tokens.
- **Semantic Intent Detection Corollary** — Regex-based verb+target matching
  (`scanner.rs:check_extraction_intent_semantic()`) catches novel extraction
  phrasings beyond static substring patterns.
- Session state wired into guard pipeline (`guard.rs:check_conversation_input()`):
  crescendo detection injects synthetic ExtractionAttempt findings and escalates taint.
- 7 new unit tests for dynamic token discovery and runtime watchlist merging.
- Updated ZeroLeaks benchmark with addressed/remaining gap reporting.

### Changed

- ZLSS improved from 2/10 to **1/10**; Security Score from 79/100 to **90/100**.
- Extraction success rate reduced from 38.5% to **15.4%** (2/13 clean, down from 5/13).
- Input scanner now detects 4/13 extraction attacks as Block (up from 3/13) and
  7/13 as Suspicious (up from 5/13).
- Threat model residual risk section updated: 4 of 4 v0.1.1 gaps addressed.
- README Theorem → Defense Integration Map expanded with session-level defenses.

## [0.1.1] - 2026-02-15

### Added

- ConversationIO guard surface with two-layer defense against prompt injection
  and system prompt extraction (scanner + output guard).
- Input scanner with 8 detection categories mapped to ZeroLeaks attack taxonomy:
  SystemImpersonation, IndirectInjection, BehaviorManipulation,
  FalseContextInjection, EncodedPayload, ExtractionAttempt, ManyShotPriming,
  FormatOverride.
- Output guard with token watchlist, structural pattern detection, and
  multi-section disclosure heuristic.
- ConversationIO policy rules: `cio-deny-injection`, `cio-deny-untrusted-tainted`,
  `cio-allow-clean`.
- ZeroLeaks benchmark test (`packages/aer/tests/zeroleaks_benchmark.rs`) with
  36 real attack payloads — no mocks, no simulations.
- Formal theorem grounding in scanner and output guard source code: each
  detection category references specific published theorems (Noninterference,
  CPI, MI, RVU).
- Theorem → Defense Integration Map in README.md.
- Empirical Validation section in README.md with ZeroLeaks benchmark results.
- ConversationIO Guard section in AER threat model with layer-by-layer analysis.
- CIO policy rules documentation in aer-cpi-mi-rules.md.
- Empirical Validation section in SPEC.md (Section 12).
- Residual risk analysis with honest gap documentation.

### Changed

- AER threat model "What AER Does NOT Cover" updated to reflect partial
  coverage of prompt injection and data exfiltration via ConversationIO guard.
- ZLSS improved from 10/10 to 2/10; Security Score from 2/100 to 79/100.

## [0.1.0] - 2026-02-15

### Added

- AEGX v0.1 bundle format specification with manifest, records, audit log, and
  blob store.
- AEGX_CANON_0_1 deterministic JSON canonicalization algorithm with sorted
  keys, NFC normalization, no whitespace, and negative-zero normalization.
- Content-addressed recordId computation via SHA-256 over canonical JSON.
- Append-only audit hash chain with sequential indexing and prev-linking.
- Content-addressed blob storage (filename = SHA-256 of content).
- JSON Schema validation for manifest, record, and audit entry structures.
- `aegx` CLI tool with subcommands: `init`, `add-blob`, `add-record`,
  `export`, `import`, `verify`, `summarize`.
- Bundle export to and import from `.aegx.zip` archives.
- End-to-end verification procedure covering schema validation, recordId
  recomputation, audit chain integrity, blob integrity, count checks, and
  parent/root reference validation.
- Agent Evidence & Recovery (AER) subsystem with CPI/MI guard enforcement,
  snapshot/rollback, and incident bundle export.
- Test vectors for minimal valid bundles, tampered records, and tampered audit
  chains.
- Fuzz testing targets for canonicalization and parsing.
- Threat model documentation.
- Format specification documentation.


---

## Development Plan


## Context

These four limitations are architectural boundaries where AER (as a reference monitor / policy engine) meets the host platform. The strategy for each is:
1. Build the **policy layer and evidence hooks** inside AER so it's ready when the platform catches up
2. Provide **detection/audit** even when enforcement isn't possible
3. Ship **reference configurations** for the OS/network layers that provide true enforcement
4. Add **tests** validating the new guard surfaces and integration points

---

## Limitation 1: Output Guard Dynamic Tokens

**Problem**: `config_with_runtime_discovery(system_prompt)` exists but the actual system prompt is never passed in. `on_message_output()` receives `Option<&OutputGuardConfig>` which is always `None` in practice, falling back to the static ZeroLeaks watchlist. OpenClaw doesn't expose system prompt content through its plugin API.

**Approach**: Build a `SystemPromptRegistry` that caches system prompt tokens, and wire it into the output guard so the dynamic discovery activates automatically without requiring the caller to manually construct an `OutputGuardConfig`.

### Files to create/modify

#### 1a. New: `packages/aer/src/system_prompt_registry.rs`
- Thread-safe singleton (`Mutex<Option<CachedPromptConfig>>`) storing:
  - `config: OutputGuardConfig` (merged static + dynamic)
  - `prompt_hash: String` (SHA-256 of the registered prompt, for audit)
  - `registered_at: DateTime<Utc>`
  - `token_count: usize`
- Public API:
  - `register_system_prompt(prompt: &str)` — extracts tokens via `config_with_runtime_discovery()`, caches result, emits a `GuardDecision` record as evidence of registration
  - `register_tokens_only(tokens: Vec<String>)` — for when the full prompt isn't available but the platform can expose individual tokens (future OpenClaw API)
  - `get_cached_config() -> Option<OutputGuardConfig>` — returns the cached config
  - `prompt_hash() -> Option<String>` — returns the hash for audit correlation
  - `clear()` — for testing/session reset
- Emits a tamper-evident record (`RecordType::GuardDecision` with a `system-prompt-registered` rule ID) so the audit chain proves when/whether dynamic discovery was active

#### 1b. Modify: `packages/aer/src/guard.rs` — `check_conversation_output()`
- When `config` param is `None`, check `system_prompt_registry::get_cached_config()` before falling back to `default_config()`
- This means dynamic tokens are used automatically once registered, zero change needed by callers

#### 1c. New hook: `packages/aer/src/hooks.rs` — `on_system_prompt_available()`
- Integration point for OpenClaw or any host platform
- Calls `system_prompt_registry::register_system_prompt()`
- Records the event in the audit chain
- Returns the count of dynamically discovered tokens (for diagnostics)

#### 1d. Modify: `packages/aer/src/hooks.rs` — `on_message_output()`
- If `output_guard_config` is `None`, transparently use the registry-cached config
- No API change — existing callers continue to work

#### 1e. Modify: `packages/aer/src/lib.rs`
- Export the new `system_prompt_registry` module

#### 1f. Tests: `packages/aer/tests/output_guard_dynamic_tokens.rs`
- Test that registering a system prompt activates dynamic tokens in subsequent `on_message_output()` calls
- Test that tokens discovered from the prompt are caught in output
- Test that clean output remains clean after registration
- Test re-registration (prompt update) replaces the cached config
- Test `register_tokens_only()` path
- Test that audit record is emitted on registration

---

## Limitation 2: File Read Guard

**Problem**: AER guards memory file **writes** via the MI surface, and tracks reads with taint (v0.1.4), but a skill with raw filesystem access can read `.env`, `~/.ssh/id_rsa`, `~/.aws/credentials`, etc. The `read_memory_file()` function only covers the 7 workspace MEMORY_FILES.

**Approach**: Add a `FileReadGuard` that can **policy-gate arbitrary file reads** (not just workspace memory files). Since AER can't intercept raw syscalls, this is a hook-based design — the integration layer must route reads through the hook. We also provide detection heuristics for tool output that contains file contents.

### Files to create/modify

#### 2a. New: `packages/aer/src/file_read_guard.rs`
- `SensitiveFileConfig`:
  - `denied_patterns: Vec<GlobPattern>` — files that should never be read by untrusted principals
  - `tainted_patterns: Vec<GlobPattern>` — files whose content should carry SECRET_RISK taint
  - Default patterns:
    - Denied: `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `credentials`, `*.secret`, `.netrc`, `.pgpass`
    - Tainted: `.aws/*`, `.ssh/*`, `.gnupg/*`, `.docker/config.json`, `*token*`, `*password*`
- `check_file_read(principal, taint, file_path, config) -> (GuardVerdict, TaintFlags)`
  - If path matches a denied pattern and principal is untrusted → Deny
  - If path matches a tainted pattern → add SECRET_RISK to taint
  - Otherwise → Allow with propagated taint
- Uses `Path::file_name()` and glob matching (reuse approach from MI basename matching)

#### 2b. New hook: `packages/aer/src/hooks.rs` — `on_file_read()`
- Parameters: `agent_id, session_id, principal, taint, file_path, parent_records`
- Calls `file_read_guard::check_file_read()`
- Records `FileRead` with proper taint
- On deny: emits alert, feeds rollback policy
- On allow with SECRET_RISK: records taint for downstream propagation

#### 2c. Modify: `packages/aer/src/workspace.rs` — `read_memory_file()`
- Refactor to call the new `on_file_read()` hook internally (unifying the read paths)
- Preserves backward compatibility

#### 2d. Modify: `packages/aer/src/types.rs`
- Add `GuardSurface::FileSystem` variant (or reuse `DurableMemory` — design decision: separate surface gives finer policy control)

#### 2e. Modify: `packages/aer/src/policy.rs`
- Add default policy rules for the FileSystem surface:
  - `fs-deny-sensitive-untrusted`: Deny untrusted principals reading sensitive files
  - `fs-taint-secrets`: Taint reads from secret-containing paths
  - `fs-allow-default`: Allow other reads

#### 2f. Add tool-output heuristic: `packages/aer/src/scanner.rs`
- New `ScanCategory::SensitiveFileContent` — detect tool results that contain file paths like `/home/*/.env` or content patterns like `API_KEY=`, `-----BEGIN RSA PRIVATE KEY-----`, `aws_secret_access_key`
- This catches cases where the integration layer doesn't route reads through the hook (defense in depth)

#### 2g. Tests: `packages/aer/tests/file_read_guard.rs`
- Test denied patterns block untrusted reads
- Test USER/SYS can read sensitive files
- Test taint propagation on secret-containing reads
- Test glob matching edge cases (path traversal, symlinks)
- Test the scanner heuristic catches leaked credentials in tool output

---

## Limitation 3: Outbound Network Monitoring

**Problem**: AER doesn't monitor outbound HTTP requests. A skill could exfiltrate data via `curl`, `fetch()`, or direct socket connections. AER is a reference monitor, not a network proxy.

**Approach**: Build the **policy and recording layer** so AER can gate/audit network requests when the integration layer routes them through hooks. Also add **detection heuristics** for exfiltration patterns in tool calls and output.

### Files to create/modify

#### 3a. New: `packages/aer/src/network_guard.rs`
- `NetworkEgressConfig`:
  - `allowed_domains: Vec<String>` — allowlist (empty = allow all, for backward compat)
  - `blocked_domains: Vec<String>` — blocklist
  - `blocked_ip_ranges: Vec<String>` — e.g., internal RFC1918 ranges from external principals
  - `max_payload_size: usize` — cap outbound payload to detect bulk exfiltration
  - `flag_patterns: Vec<String>` — URL patterns that indicate exfiltration (e.g., base64 in query params)
- `check_outbound_request(principal, taint, url, method, payload_size, config) -> (GuardVerdict, TaintFlags)`
  - Deny if domain is blocked
  - Deny if allowlist is non-empty and domain isn't in it
  - Flag if payload exceeds threshold or URL matches exfiltration pattern
  - Untrusted principals get tighter restrictions

#### 3b. New: `packages/aer/src/types.rs` — `RecordType::NetworkRequest`
- New record type for outbound network events

#### 3c. Add `GuardSurface::NetworkIO` to `types.rs`

#### 3d. New hook: `packages/aer/src/hooks.rs` — `on_outbound_request()`
- Records the request with principal/taint
- Evaluates network egress policy
- Emits alerts on blocked or flagged requests

#### 3e. Exfiltration detection in `packages/aer/src/scanner.rs`
- New `ScanCategory::DataExfiltration` — detect tool calls that contain:
  - URLs with suspiciously long query parameters
  - Base64-encoded payloads in URLs
  - Requests to known paste/bin services
  - POST requests with large bodies from untrusted principals

#### 3f. Modify: `packages/aer/src/skill_verifier.rs`
- Add detection for hardcoded exfiltration URLs in skill code
- New ClawHavoc vector pattern: skills that `fetch()` or `XMLHttpRequest` to non-allowlisted domains

#### 3g. Default policy: `packages/aer/src/policy.rs`
- `net-deny-untrusted-exfil`: Block outbound from SKILL/WEB/EXTERNAL principals to non-allowlisted domains
- `net-taint-external`: Taint all data received from external network requests
- `net-allow-default`: Allow USER/SYS-initiated requests

#### 3h. Reference config: `packages/aer/reference/egress-proxy.md`
- Documentation for setting up an actual network proxy (squid, envoy sidecar)
- eBPF-based egress monitoring reference
- iptables/nftables rules for container environments

#### 3i. Tests: `packages/aer/tests/network_guard.rs`
- Test domain allowlist/blocklist enforcement
- Test exfiltration pattern detection
- Test payload size limits
- Test taint propagation from network responses
- Test skill verifier catches hardcoded exfil URLs

---

## Limitation 4: OS Sandboxing

**Problem**: AER records and enforces policy but can't prevent arbitrary code execution. A skill script can spawn processes, access raw filesystem, make syscalls. This requires containers or seccomp.

**Approach**: Build a **sandbox audit layer** that verifies the runtime environment meets security requirements, plus provide reference sandbox configurations.

### Files to create/modify

#### 4a. New: `packages/aer/src/sandbox_audit.rs`
- `SandboxProfile`:
  - `require_container: bool`
  - `require_seccomp: bool`
  - `require_readonly_root: bool`
  - `allowed_syscalls: Option<Vec<String>>`
  - `max_processes: Option<u32>`
  - `max_open_files: Option<u32>`
  - `network_namespace: bool`
- `audit_sandbox_environment() -> SandboxAuditResult`:
  - Detect container: check `/proc/1/cgroup`, `/.dockerenv`, `KUBERNETES_SERVICE_HOST`
  - Detect seccomp: read `/proc/self/status` for `Seccomp:` line
  - Detect namespaces: check `/proc/self/ns/` symlinks
  - Detect read-only root: check mount flags on `/`
  - Detect resource limits: read `/proc/self/limits`
  - Returns `SandboxAuditResult` with findings and an overall compliance score
- `SandboxAuditResult`:
  - `in_container: bool`
  - `seccomp_active: bool`
  - `seccomp_mode: Option<String>` (disabled/strict/filter)
  - `namespaces: Vec<String>` (pid, net, mnt, user, etc.)
  - `readonly_root: bool`
  - `resource_limits: HashMap<String, String>`
  - `compliance: SandboxCompliance` (Full, Partial, None)
  - `findings: Vec<SandboxFinding>` (individual check results)

#### 4b. Modify: `packages/aer/src/hooks.rs` — `on_session_start()`
- After recording the session start, run `audit_sandbox_environment()`
- Record the result as a `GuardDecision` with sandbox findings
- If compliance is `None`, emit a `Critical` alert
- If compliance is `Partial`, emit a `High` alert
- The audit result becomes part of the tamper-evident chain

#### 4c. New: `packages/aer/src/skill_sandbox.rs`
- `SkillExecutionConfig`:
  - `use_subprocess: bool` — spawn skill in isolated subprocess
  - `seccomp_profile: Option<PathBuf>` — apply seccomp filter
  - `filesystem_allowlist: Vec<PathBuf>` — landlock-style path restrictions
  - `timeout_ms: u64`
  - `max_memory_bytes: u64`
- `prepare_skill_sandbox(config) -> SandboxHandle`:
  - On Linux: uses `prctl(PR_SET_SECCOMP)` if available, `setrlimit()` for resource limits
  - Returns a handle that the caller uses to spawn the skill process
  - This is a **best-effort** layer — true isolation requires the container runtime
- Records the sandbox configuration as evidence

#### 4d. Reference configs
- `packages/aer/reference/seccomp-skill-profile.json` — seccomp BPF profile blocking dangerous syscalls (execve from non-approved paths, ptrace, mount, etc.)
- `packages/aer/reference/Dockerfile.skill-runner` — minimal container for skill execution with:
  - Read-only root filesystem
  - No network (or restricted egress)
  - Dropped capabilities
  - Seccomp profile applied
  - Resource limits (CPU, memory, PIDs)
- `packages/aer/reference/landlock-policy.rs` — example landlock ruleset for Linux 5.13+

#### 4e. Tests: `packages/aer/tests/sandbox_audit.rs`
- Test sandbox detection in various environments (mocked `/proc` entries)
- Test compliance scoring logic
- Test alert emission on insufficient sandbox
- Test that sandbox audit result is recorded in audit chain

---

## Implementation Order

The work is structured in four phases, one per limitation. Each phase is independent and can be done in parallel, but within each phase the steps are sequential.

### Phase 1: Output Guard Dynamic Tokens (Limitation 1)
1. Create `system_prompt_registry.rs` with thread-safe singleton
2. Wire it into `guard.rs::check_conversation_output()` fallback chain
3. Add `on_system_prompt_available()` hook
4. Update `on_message_output()` to use registry when config is None
5. Export module in `lib.rs`
6. Write integration tests

### Phase 2: File Read Guard (Limitation 2)
1. Create `file_read_guard.rs` with sensitive file patterns
2. Add `GuardSurface::FileSystem` to types
3. Add policy rules for FileSystem surface
4. Create `on_file_read()` hook
5. Add `SensitiveFileContent` scanner category
6. Refactor `read_memory_file()` to use the new hook
7. Write integration tests

### Phase 3: Outbound Network Monitoring (Limitation 3)
1. Create `network_guard.rs` with egress policy
2. Add `GuardSurface::NetworkIO` and `RecordType::NetworkRequest` to types
3. Add policy rules for NetworkIO surface
4. Create `on_outbound_request()` hook
5. Add `DataExfiltration` scanner category
6. Extend skill verifier with exfil URL detection
7. Write integration tests

### Phase 4: OS Sandboxing (Limitation 4)
1. Create `sandbox_audit.rs` with environment detection
2. Wire into `on_session_start()` hook
3. Create `skill_sandbox.rs` with execution config
4. Create reference configs (seccomp profile, Dockerfile, landlock example)
5. Write integration tests

---

## Design Principles

1. **Hook-first, enforce-when-possible**: Every limitation gets an AER hook and policy surface. Enforcement is best-effort within AER, with clear documentation on what the platform must provide for full enforcement.

2. **Evidence always flows**: Even when AER can't block an action, it records it with proper taint. The audit chain captures what happened, enabling post-hoc detection and remediation.

3. **Backward compatible**: No existing API changes. New hooks are additive. Callers that pass `None` for configs get upgraded behavior automatically.

4. **Defense in depth**: Each limitation gets multiple detection layers — hook-based gating, scanner heuristics in tool output, and skill verifier patterns.

5. **Testable without the platform**: All new code is testable in isolation. Reference configs and documentation bridge the gap to real deployment.
