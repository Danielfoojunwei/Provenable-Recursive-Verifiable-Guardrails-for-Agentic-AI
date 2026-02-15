use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn aegx_cmd() -> Command {
    Command::cargo_bin("aegx").unwrap()
}

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
