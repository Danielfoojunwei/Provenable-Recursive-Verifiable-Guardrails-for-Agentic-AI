# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
