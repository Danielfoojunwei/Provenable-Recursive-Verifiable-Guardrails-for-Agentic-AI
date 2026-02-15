# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
