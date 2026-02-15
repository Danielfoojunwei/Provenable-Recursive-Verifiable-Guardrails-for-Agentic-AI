use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn aegx_cmd() -> Command {
    Command::cargo_bin("aegx").unwrap()
}

#[test]
fn test_tampered_blob_detected() {
    let tmp = TempDir::new().unwrap();
    let bundle_dir = tmp.path().join("blob_tamper.aegx");

    // Init bundle
    aegx_cmd()
        .args(["init", bundle_dir.to_str().unwrap()])
        .assert()
        .success();

    // Create a real file
    let blob_file = tmp.path().join("original.bin");
    let data: Vec<u8> = [0xDE, 0xAD, 0xBE, 0xEF]
        .iter()
        .copied()
        .cycle()
        .take(1024)
        .collect();
    fs::write(&blob_file, &data).unwrap();

    // Add blob
    let output = aegx_cmd()
        .args([
            "add-blob",
            bundle_dir.to_str().unwrap(),
            blob_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let blob_hash = String::from_utf8(output.stdout).unwrap().trim().to_string();

    // Add record referencing the blob
    aegx_cmd()
        .args([
            "add-record",
            bundle_dir.to_str().unwrap(),
            "--type",
            "FileWrite",
            "--principal",
            "TOOL",
            "--meta",
            r#"{"ts":"2026-02-15T00:00:00Z","path":"/test"}"#,
            "--blob",
            &blob_hash,
            "--mime",
            "application/octet-stream",
            "--size",
            &data.len().to_string(),
        ])
        .assert()
        .success();

    // Verify passes before tampering
    aegx_cmd()
        .args(["verify", bundle_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS"));

    // Tamper: modify one byte in the blob file
    let blob_path = bundle_dir.join("blobs").join(&blob_hash);
    let mut blob_data = fs::read(&blob_path).unwrap();
    blob_data[0] ^= 0xFF; // flip bits
    fs::write(&blob_path, &blob_data).unwrap();

    // Verify should fail with hash mismatch
    aegx_cmd()
        .args(["verify", bundle_dir.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("hash mismatch"));
}

#[test]
fn test_missing_blob_detected() {
    let tmp = TempDir::new().unwrap();
    let bundle_dir = tmp.path().join("missing_blob.aegx");

    aegx_cmd()
        .args(["init", bundle_dir.to_str().unwrap()])
        .assert()
        .success();

    // Create and add blob
    let blob_file = tmp.path().join("file.bin");
    fs::write(&blob_file, b"test content here").unwrap();
    let output = aegx_cmd()
        .args([
            "add-blob",
            bundle_dir.to_str().unwrap(),
            blob_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let blob_hash = String::from_utf8(output.stdout).unwrap().trim().to_string();

    // Add record referencing blob
    aegx_cmd()
        .args([
            "add-record",
            bundle_dir.to_str().unwrap(),
            "--type",
            "FileWrite",
            "--principal",
            "TOOL",
            "--meta",
            r#"{"ts":"2026-02-15T00:00:00Z"}"#,
            "--blob",
            &blob_hash,
            "--mime",
            "text/plain",
            "--size",
            "17",
        ])
        .assert()
        .success();

    // Delete the blob file
    fs::remove_file(bundle_dir.join("blobs").join(&blob_hash)).unwrap();

    // Verify should fail - blob does not exist
    aegx_cmd()
        .args(["verify", bundle_dir.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn test_record_count_mismatch_detected() {
    let tmp = TempDir::new().unwrap();
    let bundle_dir = tmp.path().join("count_tamper.aegx");

    aegx_cmd()
        .args(["init", bundle_dir.to_str().unwrap()])
        .assert()
        .success();

    aegx_cmd()
        .args([
            "add-record",
            bundle_dir.to_str().unwrap(),
            "--type",
            "SessionStart",
            "--principal",
            "SYS",
            "--meta",
            r#"{"ts":"2026-02-15T00:00:00Z"}"#,
            "--inline",
            r#"{"x":1}"#,
        ])
        .assert()
        .success();

    // Tamper manifest record_count
    let manifest_path = bundle_dir.join("manifest.json");
    let content = fs::read_to_string(&manifest_path).unwrap();
    let mut manifest: serde_json::Value = serde_json::from_str(&content).unwrap();
    manifest["record_count"] = serde_json::json!(99);
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    aegx_cmd()
        .args(["verify", bundle_dir.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("record_count mismatch"));
}
