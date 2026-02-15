use assert_cmd::Command;
use tempfile::TempDir;

fn aegx_cmd() -> Command {
    Command::cargo_bin("aegx").unwrap()
}

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
