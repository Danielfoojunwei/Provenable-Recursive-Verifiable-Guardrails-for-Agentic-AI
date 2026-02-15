use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn aegx_cmd() -> Command {
    Command::cargo_bin("aegx").unwrap()
}

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
