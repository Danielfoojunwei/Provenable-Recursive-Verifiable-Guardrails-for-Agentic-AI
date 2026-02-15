use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn aegx_cmd() -> Command {
    Command::cargo_bin("aegx").unwrap()
}

#[test]
fn test_full_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let bundle_dir = tmp.path().join("test.aegx");
    let zip_path = tmp.path().join("test.aegx.zip");
    let imported_dir = tmp.path().join("imported.aegx");

    // 1. Init bundle
    aegx_cmd()
        .args(["init", bundle_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Initialized bundle"));

    // 2. Create a real 5MB file on disk
    let blob_file = tmp.path().join("testblob.bin");
    let data: Vec<u8> = (0u8..=255).cycle().take(5 * 1024 * 1024).collect();
    fs::write(&blob_file, &data).unwrap();

    // 3. Add blob
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
    assert_eq!(blob_hash.len(), 64);

    // 4. Add a FileWrite record referencing the blob
    let file_size = data.len();
    let output = aegx_cmd()
        .args([
            "add-record",
            bundle_dir.to_str().unwrap(),
            "--type",
            "FileWrite",
            "--principal",
            "TOOL",
            "--meta",
            r#"{"ts":"2026-02-15T00:01:00Z","path":"/tmp/testblob.bin"}"#,
            "--blob",
            &blob_hash,
            "--mime",
            "application/octet-stream",
            "--size",
            &file_size.to_string(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let record_id = String::from_utf8(output.stdout).unwrap().trim().to_string();
    assert_eq!(record_id.len(), 64);

    // 5. Export to zip
    aegx_cmd()
        .args([
            "export",
            bundle_dir.to_str().unwrap(),
            zip_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported"));

    // 6. Import from zip
    aegx_cmd()
        .args([
            "import",
            zip_path.to_str().unwrap(),
            imported_dir.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported"));

    // 7. Verify imported bundle
    aegx_cmd()
        .args(["verify", imported_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS"));

    // 8. Also verify original bundle
    aegx_cmd()
        .args(["verify", bundle_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS"));

    // 9. Summarize
    aegx_cmd()
        .args(["summarize", bundle_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("FileWrite: 1"))
        .stdout(predicate::str::contains("Verification: PASS"));
}

#[test]
fn test_init_creates_structure() {
    let tmp = TempDir::new().unwrap();
    let bundle_dir = tmp.path().join("newbundle.aegx");

    aegx_cmd()
        .args(["init", bundle_dir.to_str().unwrap()])
        .assert()
        .success();

    assert!(bundle_dir.join("manifest.json").exists());
    assert!(bundle_dir.join("records.jsonl").exists());
    assert!(bundle_dir.join("audit-log.jsonl").exists());
    assert!(bundle_dir.join("blobs").is_dir());

    // Verify manifest content
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(bundle_dir.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["aegx_version"], "0.1");
    assert_eq!(manifest["record_count"], 0);
    assert_eq!(manifest["blob_count"], 0);
}

#[test]
fn test_inline_record_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let bundle_dir = tmp.path().join("inline.aegx");

    aegx_cmd()
        .args(["init", bundle_dir.to_str().unwrap()])
        .assert()
        .success();

    // Add inline record
    let output = aegx_cmd()
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
            r#"{"msg":"hello"}"#,
        ])
        .output()
        .unwrap();
    assert!(output.status.success());

    aegx_cmd()
        .args(["verify", bundle_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS"));
}
