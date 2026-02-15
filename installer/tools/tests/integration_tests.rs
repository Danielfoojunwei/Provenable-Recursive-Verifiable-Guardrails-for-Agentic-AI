use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Path to the installer repo root (relative to where cargo test runs)
fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Create a minimal valid manifest in a temp directory for isolated testing
fn setup_test_repo() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();

    // manifest/
    fs::create_dir_all(root.join("manifest")).unwrap();
    fs::write(
        root.join("manifest").join("manifest.json"),
        r#"{
  "schema_version": "0.1",
  "installer": {
    "version": "0.1.0",
    "artifacts": {
      "install-openclaw-aer.sh": {
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
      },
      "install-openclaw-aer.ps1": {
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
      }
    }
  },
  "openclaw": {
    "install_mode": "npm",
    "pinned_versions": [
      {
        "version": "0.1.0",
        "engines_node_min": ">=22.0.0",
        "notes": "Test version",
        "allowed": true
      }
    ],
    "default_version": "0.1.0"
  }
}
"#,
    )
    .unwrap();

    // install/ — dummy artifacts
    fs::create_dir_all(root.join("install")).unwrap();
    fs::write(
        root.join("install").join("install-openclaw-aer.sh"),
        "#!/bin/bash\necho test\n",
    )
    .unwrap();
    fs::write(
        root.join("install").join("install-openclaw-aer.ps1"),
        "Write-Host test\n",
    )
    .unwrap();

    tmp
}

// ── Validate tests ──────────────────────────────────────────────

#[test]
fn validate_passes_on_valid_manifest() {
    let tmp = setup_test_repo();
    let manifest_path = tmp
        .path()
        .join("manifest")
        .join("manifest.json")
        .to_string_lossy()
        .to_string();

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args(["validate", "--manifest", &manifest_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK: Manifest valid"));
}

#[test]
fn validate_fails_on_bad_schema_version() {
    let tmp = setup_test_repo();
    let manifest_path = tmp.path().join("manifest").join("manifest.json");

    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["schema_version"] = serde_json::json!("9.9");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args(["validate", "--manifest", &manifest_path.to_string_lossy()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unsupported schema_version"));
}

#[test]
fn validate_fails_on_invalid_semver() {
    let tmp = setup_test_repo();
    let manifest_path = tmp.path().join("manifest").join("manifest.json");

    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["installer"]["version"] = serde_json::json!("not-semver");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args(["validate", "--manifest", &manifest_path.to_string_lossy()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid installer version"));
}

#[test]
fn validate_fails_on_invalid_sha256() {
    let tmp = setup_test_repo();
    let manifest_path = tmp.path().join("manifest").join("manifest.json");

    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["installer"]["artifacts"]["install-openclaw-aer.sh"]["sha256"] =
        serde_json::json!("not-a-hash");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args(["validate", "--manifest", &manifest_path.to_string_lossy()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid sha256"));
}

#[test]
fn validate_fails_on_missing_artifact() {
    let tmp = setup_test_repo();
    let manifest_path = tmp.path().join("manifest").join("manifest.json");

    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["installer"]["artifacts"]
        .as_object_mut()
        .unwrap()
        .remove("install-openclaw-aer.sh");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args(["validate", "--manifest", &manifest_path.to_string_lossy()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Missing artifact entry"));
}

#[test]
fn validate_fails_on_bad_install_mode() {
    let tmp = setup_test_repo();
    let manifest_path = tmp.path().join("manifest").join("manifest.json");

    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["openclaw"]["install_mode"] = serde_json::json!("docker");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args(["validate", "--manifest", &manifest_path.to_string_lossy()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unsupported install_mode"));
}

#[test]
fn validate_fails_on_empty_pinned_versions() {
    let tmp = setup_test_repo();
    let manifest_path = tmp.path().join("manifest").join("manifest.json");

    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["openclaw"]["pinned_versions"] = serde_json::json!([]);
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args(["validate", "--manifest", &manifest_path.to_string_lossy()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pinned_versions must be a non-empty list"));
}

#[test]
fn validate_fails_when_default_not_allowed() {
    let tmp = setup_test_repo();
    let manifest_path = tmp.path().join("manifest").join("manifest.json");

    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["openclaw"]["pinned_versions"][0]["allowed"] = serde_json::json!(false);
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args(["validate", "--manifest", &manifest_path.to_string_lossy()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not in allowed pinned_versions"));
}

#[test]
fn validate_fails_on_bad_engines_node_min() {
    let tmp = setup_test_repo();
    let manifest_path = tmp.path().join("manifest").join("manifest.json");

    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["openclaw"]["pinned_versions"][0]["engines_node_min"] =
        serde_json::json!("22.0.0");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args(["validate", "--manifest", &manifest_path.to_string_lossy()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid engines_node_min"));
}

// ── GenChecksums tests ──────────────────────────────────────────

#[test]
fn gen_checksums_updates_manifest_and_writes_file() {
    let tmp = setup_test_repo();
    let root = tmp.path().to_string_lossy().to_string();

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args(["gen-checksums", "--repo-root", &root])
        .assert()
        .success()
        .stdout(predicate::str::contains("Checksums written"));

    // Verify checksums.txt was created
    let checksums_path = tmp.path().join("checksums.txt");
    assert!(checksums_path.exists(), "checksums.txt should exist");

    let checksums = fs::read_to_string(&checksums_path).unwrap();
    assert!(checksums.contains("install-openclaw-aer.sh"));
    assert!(checksums.contains("install-openclaw-aer.ps1"));
    assert!(checksums.contains("manifest.json"));

    // Verify manifest was updated with real hashes
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(tmp.path().join("manifest").join("manifest.json")).unwrap(),
    )
    .unwrap();

    let sh_hash = manifest["installer"]["artifacts"]["install-openclaw-aer.sh"]["sha256"]
        .as_str()
        .unwrap();
    assert_ne!(
        sh_hash,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "sha256 should be updated from placeholder"
    );
    assert_eq!(sh_hash.len(), 64, "sha256 should be 64 hex chars");
}

#[test]
fn gen_checksums_fails_on_missing_artifact() {
    let tmp = setup_test_repo();
    // Remove one artifact
    fs::remove_file(tmp.path().join("install").join("install-openclaw-aer.sh")).unwrap();

    let root = tmp.path().to_string_lossy().to_string();

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args(["gen-checksums", "--repo-root", &root])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Artifact not found"));
}

// ── PinVersion tests ────────────────────────────────────────────

#[test]
fn pin_version_adds_new_version() {
    let tmp = setup_test_repo();
    let root = tmp.path().to_string_lossy().to_string();

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args([
            "pin-version",
            "--version", "1.2.3",
            "--skip-npm-check",
            "--repo-root", &root,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added version 1.2.3"));

    // Verify manifest was updated
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(tmp.path().join("manifest").join("manifest.json")).unwrap(),
    )
    .unwrap();

    let pinned = manifest["openclaw"]["pinned_versions"].as_array().unwrap();
    assert_eq!(pinned.len(), 2, "Should have 2 pinned versions");
    assert_eq!(pinned[1]["version"].as_str().unwrap(), "1.2.3");
    assert!(pinned[1]["allowed"].as_bool().unwrap());
}

#[test]
fn pin_version_with_set_default() {
    let tmp = setup_test_repo();
    let root = tmp.path().to_string_lossy().to_string();

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args([
            "pin-version",
            "--version", "2.0.0",
            "--set-default",
            "--skip-npm-check",
            "--repo-root", &root,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Set default_version to 2.0.0"));

    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(tmp.path().join("manifest").join("manifest.json")).unwrap(),
    )
    .unwrap();

    assert_eq!(
        manifest["openclaw"]["default_version"].as_str().unwrap(),
        "2.0.0"
    );
}

#[test]
fn pin_version_rejects_invalid_semver() {
    let tmp = setup_test_repo();
    let root = tmp.path().to_string_lossy().to_string();

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args([
            "pin-version",
            "--version", "not-a-version",
            "--skip-npm-check",
            "--repo-root", &root,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid version format"));
}

#[test]
fn pin_version_updates_existing() {
    let tmp = setup_test_repo();
    let root = tmp.path().to_string_lossy().to_string();

    // Pin the already-existing version 0.1.0
    Command::cargo_bin("installer-tools")
        .unwrap()
        .args([
            "pin-version",
            "--version", "0.1.0",
            "--skip-npm-check",
            "--repo-root", &root,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("already pinned — updating"));

    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(tmp.path().join("manifest").join("manifest.json")).unwrap(),
    )
    .unwrap();

    // Should still have only 1 pinned version (not a duplicate)
    let pinned = manifest["openclaw"]["pinned_versions"].as_array().unwrap();
    assert_eq!(pinned.len(), 1);
}

// ── Security defaults tests ─────────────────────────────────────

#[test]
fn installer_sh_has_security_defaults() {
    let sh_path = repo_root().join("install").join("install-openclaw-aer.sh");
    if !sh_path.exists() {
        // Skip if running from a different context
        return;
    }
    let content = fs::read_to_string(&sh_path).unwrap();
    assert!(
        content.contains("127.0.0.1"),
        "Installer must bind to 127.0.0.1"
    );
    assert!(
        content.contains("authRequired"),
        "Installer must set authRequired"
    );
    assert!(
        content.contains("trustedProxies"),
        "Installer must set trustedProxies"
    );
}

#[test]
fn installer_ps1_has_security_defaults() {
    let ps1_path = repo_root().join("install").join("install-openclaw-aer.ps1");
    if !ps1_path.exists() {
        return;
    }
    let content = fs::read_to_string(&ps1_path).unwrap();
    assert!(
        content.contains("127.0.0.1"),
        "Installer must bind to 127.0.0.1"
    );
    assert!(
        content.contains("authRequired"),
        "Installer must set authRequired"
    );
    assert!(
        content.contains("trustedProxies"),
        "Installer must set trustedProxies"
    );
}

// ── Validate real manifest test ──────────────────────────────────

#[test]
fn validate_real_manifest() {
    let manifest_path = repo_root()
        .join("manifest")
        .join("manifest.json");
    if !manifest_path.exists() {
        return;
    }

    Command::cargo_bin("installer-tools")
        .unwrap()
        .args(["validate", "--manifest", &manifest_path.to_string_lossy()])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK: Manifest valid"));
}
