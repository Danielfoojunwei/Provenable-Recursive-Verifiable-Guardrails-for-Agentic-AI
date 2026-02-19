use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn aegx_cmd() -> Command {
    Command::cargo_bin("aegx").unwrap()
}

// ===========================================================================
// Inline test vector data (consolidated from tests/test_vectors/)
// ===========================================================================

const MINIMAL_MANIFEST: &str = r#"{
  "aegx_version": "0.1",
  "audit_head": "2cfdc7afc59aaa0306357ccd58a010d8ba019b175c3e9aa7d26da0ff85ffbd16",
  "blob_count": 0,
  "canonicalization": "AEGX_CANON_0_1",
  "created_at": "2026-02-15T04:15:08Z",
  "hash_alg": "sha256",
  "record_count": 2,
  "root_records": [
    "a61ecc31a3cdcfaf35686574a2a2e239c32156601c27bd9f83b272574ed152d7"
  ]
}"#;

const MINIMAL_RECORDS: &str = r#"{"recordId":"a61ecc31a3cdcfaf35686574a2a2e239c32156601c27bd9f83b272574ed152d7","type":"SessionStart","principal":"SYS","taint":[],"parents":[],"meta":{"session":"test-session-001","ts":"2026-02-15T00:00:00Z"},"payload":{"inline":{"reason":"test session"}},"schema":"0.1"}
{"recordId":"34cbb2e19f6d8d3543530fc0c2bc7dd366a829711fdc036c5ae38d614bcfd54e","type":"SessionMessage","principal":"USER","taint":[],"parents":["a61ecc31a3cdcfaf35686574a2a2e239c32156601c27bd9f83b272574ed152d7"],"meta":{"ts":"2026-02-15T00:00:01Z"},"payload":{"inline":{"content":"Hello, world!"}},"schema":"0.1"}
"#;

const MINIMAL_AUDIT: &str = r#"{"idx":0,"ts":"2026-02-15T00:00:00Z","recordId":"a61ecc31a3cdcfaf35686574a2a2e239c32156601c27bd9f83b272574ed152d7","prev":"0000000000000000000000000000000000000000000000000000000000000000","entryHash":"21973306d3de394fdcc8d1032935673157bf474c0c28713db53b73a336004b03"}
{"idx":1,"ts":"2026-02-15T00:00:01Z","recordId":"34cbb2e19f6d8d3543530fc0c2bc7dd366a829711fdc036c5ae38d614bcfd54e","prev":"21973306d3de394fdcc8d1032935673157bf474c0c28713db53b73a336004b03","entryHash":"2cfdc7afc59aaa0306357ccd58a010d8ba019b175c3e9aa7d26da0ff85ffbd16"}
"#;

const TAMPER_RECORD_RECORDS: &str = r#"{"recordId":"a61ecc31a3cdcfaf35686574a2a2e239c32156601c27bd9f83b272574ed152d7","type":"SessionStart","principal":"SYS","taint":[],"parents":[],"meta":{"session":"test-session-001","ts":"2026-02-15T00:00:00Z"},"payload":{"inline":{"reason":"test session"}},"schema":"0.1"}
{"recordId":"34cbb2e19f6d8d3543530fc0c2bc7dd366a829711fdc036c5ae38d614bcfd54e","type":"SessionMessage","principal":"USER","taint":[],"parents":["a61ecc31a3cdcfaf35686574a2a2e239c32156601c27bd9f83b272574ed152d7"],"meta":{"ts":"2026-02-15T00:00:01Z"},"payload":{"inline":{"content":"TAMPERED content!"}},"schema":"0.1"}
"#;

const TAMPER_AUDIT_LOG: &str = r#"{"idx":0,"ts":"2026-02-15T00:00:00Z","recordId":"a61ecc31a3cdcfaf35686574a2a2e239c32156601c27bd9f83b272574ed152d7","prev":"0000000000000000000000000000000000000000000000000000000000000000","entryHash":"21973306d3de394fdcc8d1032935673157bf474c0c28713db53b73a336004b03"}
{"idx":1,"ts":"2026-02-15T00:00:01Z","recordId":"34cbb2e19f6d8d3543530fc0c2bc7dd366a829711fdc036c5ae38d614bcfd54e","prev":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entryHash":"2cfdc7afc59aaa0306357ccd58a010d8ba019b175c3e9aa7d26da0ff85ffbd16"}
"#;

/// Create a test bundle directory from inline data.
fn create_test_bundle(tmp: &TempDir, name: &str, manifest: &str, records: &str, audit: &str) -> std::path::PathBuf {
    let bundle = tmp.path().join(name);
    fs::create_dir_all(bundle.join("blobs")).unwrap();
    fs::write(bundle.join("manifest.json"), manifest).unwrap();
    fs::write(bundle.join("records.jsonl"), records).unwrap();
    fs::write(bundle.join("audit-log.jsonl"), audit).unwrap();
    bundle
}

// ===========================================================================
// Schema Validation Failures
// ===========================================================================

#[test]
fn test_missing_manifest_field_fails_schema() {
    let tmp = TempDir::new().unwrap();
    let bundle_dir = tmp.path().join("bad_schema.aegx");

    // Init a valid bundle
    aegx_cmd()
        .args(["init", bundle_dir.to_str().unwrap()])
        .assert()
        .success();

    // Remove the hash_alg field from manifest
    let manifest_path = bundle_dir.join("manifest.json");
    let content = fs::read_to_string(&manifest_path).unwrap();
    let mut manifest: serde_json::Value = serde_json::from_str(&content).unwrap();
    manifest.as_object_mut().unwrap().remove("hash_alg");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // Verify should fail with schema error
    aegx_cmd()
        .args(["verify", bundle_dir.to_str().unwrap()])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("schema"));
}

#[test]
fn test_invalid_aegx_version_fails_schema() {
    let tmp = TempDir::new().unwrap();
    let bundle_dir = tmp.path().join("bad_version.aegx");

    aegx_cmd()
        .args(["init", bundle_dir.to_str().unwrap()])
        .assert()
        .success();

    let manifest_path = bundle_dir.join("manifest.json");
    let content = fs::read_to_string(&manifest_path).unwrap();
    let mut manifest: serde_json::Value = serde_json::from_str(&content).unwrap();
    manifest["aegx_version"] = serde_json::json!("9.9");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    aegx_cmd()
        .args(["verify", bundle_dir.to_str().unwrap()])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("schema"));
}

#[test]
fn test_extra_field_in_manifest_fails_schema() {
    let tmp = TempDir::new().unwrap();
    let bundle_dir = tmp.path().join("extra_field.aegx");

    aegx_cmd()
        .args(["init", bundle_dir.to_str().unwrap()])
        .assert()
        .success();

    let manifest_path = bundle_dir.join("manifest.json");
    let content = fs::read_to_string(&manifest_path).unwrap();
    let mut manifest: serde_json::Value = serde_json::from_str(&content).unwrap();
    manifest["unknown_field"] = serde_json::json!("bad");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    aegx_cmd()
        .args(["verify", bundle_dir.to_str().unwrap()])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("schema"));
}

// ===========================================================================
// Verification Test Vectors (inlined)
// ===========================================================================

#[test]
fn test_minimal_bundle_passes() {
    let tmp = TempDir::new().unwrap();
    let bundle = create_test_bundle(&tmp, "v0.1_minimal_bundle", MINIMAL_MANIFEST, MINIMAL_RECORDS, MINIMAL_AUDIT);
    aegx_cmd()
        .args(["verify", bundle.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS"));
}

#[test]
fn test_tamper_record_bundle_fails() {
    let tmp = TempDir::new().unwrap();
    let bundle = create_test_bundle(&tmp, "v0.1_tamper_record_bundle", MINIMAL_MANIFEST, TAMPER_RECORD_RECORDS, MINIMAL_AUDIT);
    aegx_cmd()
        .args(["verify", bundle.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("recordId mismatch"));
}

#[test]
fn test_tamper_audit_bundle_fails() {
    let tmp = TempDir::new().unwrap();
    let bundle = create_test_bundle(&tmp, "v0.1_tamper_audit_bundle", MINIMAL_MANIFEST, MINIMAL_RECORDS, TAMPER_AUDIT_LOG);
    aegx_cmd()
        .args(["verify", bundle.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(
            predicate::str::contains("expected prev=").or(predicate::str::contains("entryHash")),
        );
}
