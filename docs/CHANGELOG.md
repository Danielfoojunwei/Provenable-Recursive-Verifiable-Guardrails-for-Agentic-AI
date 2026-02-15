# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
