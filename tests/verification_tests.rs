use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn aegx_cmd() -> Command {
    Command::cargo_bin("aegx").unwrap()
}

// ===========================================================================
// Tests from schema_failures.rs — Schema Validation Failures
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
// Tests from verify_vectors.rs — Verification Test Vectors
// ===========================================================================

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_vectors")
}

#[test]
fn test_minimal_bundle_passes() {
    let bundle = vectors_dir().join("v0.1_minimal_bundle");
    aegx_cmd()
        .args(["verify", bundle.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS"));
}

#[test]
fn test_tamper_record_bundle_fails() {
    let bundle = vectors_dir().join("v0.1_tamper_record_bundle");
    aegx_cmd()
        .args(["verify", bundle.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("recordId mismatch"));
}

#[test]
fn test_tamper_audit_bundle_fails() {
    let bundle = vectors_dir().join("v0.1_tamper_audit_bundle");
    aegx_cmd()
        .args(["verify", bundle.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(
            predicate::str::contains("expected prev=").or(predicate::str::contains("entryHash")),
        );
}
