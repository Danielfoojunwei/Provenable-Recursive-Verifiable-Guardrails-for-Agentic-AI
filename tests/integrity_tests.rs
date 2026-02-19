use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn aegx_cmd() -> Command {
    Command::cargo_bin("aegx").unwrap()
}

// ===========================================================================
// Tests from canonical_determinism.rs — Canonical Determinism
// ===========================================================================

#[test]
fn test_same_record_produces_same_id() {
    let tmp = TempDir::new().unwrap();

    // Create two bundles and add the same record to each
    let bundle1 = tmp.path().join("bundle1.aegx");
    let bundle2 = tmp.path().join("bundle2.aegx");

    aegx_cmd()
        .args(["init", bundle1.to_str().unwrap()])
        .assert()
        .success();
    aegx_cmd()
        .args(["init", bundle2.to_str().unwrap()])
        .assert()
        .success();

    let meta = r#"{"ts":"2026-02-15T00:00:00Z","key":"value"}"#;
    let inline = r#"{"data":"test content","numbers":[1,2,3]}"#;

    let out1 = aegx_cmd()
        .args([
            "add-record",
            bundle1.to_str().unwrap(),
            "--type",
            "SessionStart",
            "--principal",
            "SYS",
            "--meta",
            meta,
            "--inline",
            inline,
        ])
        .output()
        .unwrap();
    assert!(out1.status.success());
    let id1 = String::from_utf8(out1.stdout).unwrap().trim().to_string();

    let out2 = aegx_cmd()
        .args([
            "add-record",
            bundle2.to_str().unwrap(),
            "--type",
            "SessionStart",
            "--principal",
            "SYS",
            "--meta",
            meta,
            "--inline",
            inline,
        ])
        .output()
        .unwrap();
    assert!(out2.status.success());
    let id2 = String::from_utf8(out2.stdout).unwrap().trim().to_string();

    assert_eq!(id1, id2, "Same record content must produce same recordId");
    assert_eq!(id1.len(), 64, "recordId must be 64 hex chars");
}

#[test]
fn test_different_content_produces_different_id() {
    let tmp = TempDir::new().unwrap();

    let bundle1 = tmp.path().join("b1.aegx");
    let bundle2 = tmp.path().join("b2.aegx");

    aegx_cmd()
        .args(["init", bundle1.to_str().unwrap()])
        .assert()
        .success();
    aegx_cmd()
        .args(["init", bundle2.to_str().unwrap()])
        .assert()
        .success();

    let out1 = aegx_cmd()
        .args([
            "add-record",
            bundle1.to_str().unwrap(),
            "--type",
            "SessionStart",
            "--principal",
            "SYS",
            "--meta",
            r#"{"ts":"2026-02-15T00:00:00Z"}"#,
            "--inline",
            r#"{"data":"content A"}"#,
        ])
        .output()
        .unwrap();
    let id1 = String::from_utf8(out1.stdout).unwrap().trim().to_string();

    let out2 = aegx_cmd()
        .args([
            "add-record",
            bundle2.to_str().unwrap(),
            "--type",
            "SessionStart",
            "--principal",
            "SYS",
            "--meta",
            r#"{"ts":"2026-02-15T00:00:00Z"}"#,
            "--inline",
            r#"{"data":"content B"}"#,
        ])
        .output()
        .unwrap();
    let id2 = String::from_utf8(out2.stdout).unwrap().trim().to_string();

    assert_ne!(
        id1, id2,
        "Different content must produce different recordIds"
    );
}

#[test]
fn test_timestamp_normalization_determinism() {
    let tmp = TempDir::new().unwrap();

    let bundle1 = tmp.path().join("ts1.aegx");
    let bundle2 = tmp.path().join("ts2.aegx");

    aegx_cmd()
        .args(["init", bundle1.to_str().unwrap()])
        .assert()
        .success();
    aegx_cmd()
        .args(["init", bundle2.to_str().unwrap()])
        .assert()
        .success();

    // Use +00:00 offset vs Z - both should normalize to Z
    let out1 = aegx_cmd()
        .args([
            "add-record",
            bundle1.to_str().unwrap(),
            "--type",
            "SessionStart",
            "--principal",
            "SYS",
            "--meta",
            r#"{"ts":"2026-02-15T00:00:00+00:00"}"#,
            "--inline",
            r#"{"x":1}"#,
        ])
        .output()
        .unwrap();
    let id1 = String::from_utf8(out1.stdout).unwrap().trim().to_string();

    let out2 = aegx_cmd()
        .args([
            "add-record",
            bundle2.to_str().unwrap(),
            "--type",
            "SessionStart",
            "--principal",
            "SYS",
            "--meta",
            r#"{"ts":"2026-02-15T00:00:00Z"}"#,
            "--inline",
            r#"{"x":1}"#,
        ])
        .output()
        .unwrap();
    let id2 = String::from_utf8(out2.stdout).unwrap().trim().to_string();

    assert_eq!(id1, id2, "Timestamp normalization must be deterministic");
}

// ===========================================================================
// Tests from tamper_detection.rs — Tamper Detection
// ===========================================================================

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
