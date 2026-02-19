// =============================================================================
// commands.rs — Consolidated command implementations
//
// Merged from: checksums.rs, pin.rs, validate.rs
// =============================================================================

use crate::manifest::{self, PinnedVersion};
use std::collections::{BTreeMap, HashSet};
use std::process::Command;

// =============================================================================
// validate command (from validate.rs)
// =============================================================================

pub fn validate_run(manifest_path: Option<String>) -> Result<(), String> {
    let path = manifest::resolve_manifest_path(manifest_path.as_deref(), None);

    if !path.is_file() {
        return Err(format!("Manifest not found: {}", path.display()));
    }

    let data = manifest::load(&path)?;

    // --- schema_version ---
    if data.schema_version != "0.1" {
        return Err(format!(
            "Unsupported schema_version: {}",
            data.schema_version
        ));
    }

    // --- installer section ---
    if !manifest::is_semver(&data.installer.version) {
        return Err(format!(
            "Invalid installer version: {}",
            data.installer.version
        ));
    }

    let required_artifacts = [
        "install-proven-aer.sh",
        "install-proven-aer.ps1",
    ];
    for name in &required_artifacts {
        match data.installer.artifacts.get(*name) {
            Some(entry) => {
                if !manifest::is_sha256_hex(&entry.sha256) {
                    return Err(format!("Invalid sha256 for {name}: {}", entry.sha256));
                }
            }
            None => {
                return Err(format!("Missing artifact entry for {name}"));
            }
        }
    }

    // --- proven section ---
    if data.proven.install_mode != "npm" {
        return Err(format!(
            "Unsupported install_mode: {}",
            data.proven.install_mode
        ));
    }

    if data.proven.pinned_versions.is_empty() {
        return Err("pinned_versions must be a non-empty list".to_string());
    }

    let mut allowed_versions = HashSet::new();
    for entry in &data.proven.pinned_versions {
        if !manifest::is_semver(&entry.version) {
            return Err(format!("Invalid pinned version: {}", entry.version));
        }
        if !entry.engines_node_min.starts_with(">=") {
            return Err(format!(
                "Invalid engines_node_min for {}: {}",
                entry.version, entry.engines_node_min
            ));
        }
        if entry.allowed {
            allowed_versions.insert(entry.version.clone());
        }
    }

    if !manifest::is_semver(&data.proven.default_version) {
        return Err(format!(
            "Invalid default_version: {}",
            data.proven.default_version
        ));
    }

    if !allowed_versions.contains(&data.proven.default_version) {
        return Err(format!(
            "default_version '{}' is not in allowed pinned_versions",
            data.proven.default_version
        ));
    }

    println!(
        "OK: Manifest valid — installer v{}, default Proven v{}, {} allowed version(s)",
        data.installer.version,
        data.proven.default_version,
        allowed_versions.len()
    );

    Ok(())
}

// =============================================================================
// checksums command (from checksums.rs)
// =============================================================================

pub fn checksums_run(repo_root_override: Option<String>) -> Result<(), String> {
    let repo_root = manifest::resolve_repo_root(repo_root_override.as_deref());
    let manifest_path = repo_root.join("manifest").join("manifest.json");
    let checksums_path = repo_root.join("checksums.txt");

    let artifacts: BTreeMap<&str, _> = BTreeMap::from([
        (
            "install-proven-aer.sh",
            repo_root.join("install").join("install-proven-aer.sh"),
        ),
        (
            "install-proven-aer.ps1",
            repo_root.join("install").join("install-proven-aer.ps1"),
        ),
    ]);

    // Compute hashes for each artifact
    let mut hashes: BTreeMap<String, String> = BTreeMap::new();
    for (name, path) in &artifacts {
        if !path.is_file() {
            return Err(format!("Artifact not found: {}", path.display()));
        }
        let hash = manifest::sha256_file(path)?;
        println!("  {hash}  {name}");
        hashes.insert(name.to_string(), hash);
    }

    // Update manifest artifact hashes
    let mut data = manifest::load(&manifest_path)?;
    for (name, digest) in &hashes {
        match data.installer.artifacts.get_mut(name.as_str()) {
            Some(entry) => {
                entry.sha256 = digest.clone();
            }
            None => {
                return Err(format!("Artifact '{name}' not in manifest"));
            }
        }
    }
    manifest::save(&manifest_path, &data)?;

    // Re-hash manifest after update (it now contains the correct artifact hashes)
    let manifest_hash = manifest::sha256_file(&manifest_path)?;

    // Write checksums.txt
    let mut lines: Vec<String> = hashes
        .iter()
        .map(|(name, digest)| format!("{digest}  {name}"))
        .collect();
    lines.push(format!("{manifest_hash}  manifest.json"));

    std::fs::write(&checksums_path, format!("{}\n", lines.join("\n")))
        .map_err(|e| format!("Cannot write checksums.txt: {e}"))?;

    println!("\nChecksums written to {}", checksums_path.display());
    println!("Manifest updated at {}", manifest_path.display());

    Ok(())
}

// =============================================================================
// pin command (from pin.rs)
// =============================================================================

/// Verify version exists on npm and return the exact version string.
fn npm_view_version(version: &str) -> Result<String, String> {
    let output = Command::new("npm")
        .args(["view", &format!("proven@{version}"), "version"])
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "npm not found — install Node.js first".to_string()
            } else {
                format!("Failed to run npm: {e}")
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "npm view failed for proven@{version}: {stderr}"
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Get the engines.node requirement from npm.
fn npm_view_engines(version: &str) -> String {
    let default = ">=22.0.0".to_string();

    let output = match Command::new("npm")
        .args(["view", &format!("proven@{version}"), "engines", "--json"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return default,
    };

    if !output.status.success() {
        return default;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    match serde_json::from_str::<serde_json::Value>(stdout.as_ref()) {
        Ok(val) => val
            .get("node")
            .and_then(|v| v.as_str())
            .unwrap_or(">=22.0.0")
            .to_string(),
        Err(_) => default,
    }
}

pub fn pin_run(
    version: String,
    set_default: bool,
    skip_npm_check: bool,
    repo_root_override: Option<String>,
) -> Result<(), String> {
    if !manifest::is_semver(&version) {
        return Err(format!("Invalid version format: {version}"));
    }

    // Verify on npm
    let engines_node = if !skip_npm_check {
        let actual = npm_view_version(&version)?;
        if actual != version {
            return Err(format!(
                "npm returned version '{actual}', expected '{version}'"
            ));
        }
        npm_view_engines(&version)
    } else {
        ">=22.0.0".to_string()
    };

    // Load manifest
    let repo_root = manifest::resolve_repo_root(repo_root_override.as_deref());
    let manifest_path = repo_root.join("manifest").join("manifest.json");
    let mut data = manifest::load(&manifest_path)?;

    // Check if version already pinned
    if let Some(existing) = data
        .proven
        .pinned_versions
        .iter_mut()
        .find(|e| e.version == version)
    {
        println!("Version {version} already pinned — updating.");
        existing.allowed = true;
        existing.engines_node_min = engines_node;
    } else {
        data.proven.pinned_versions.push(PinnedVersion {
            version: version.clone(),
            engines_node_min: engines_node,
            notes: "Pinned via installer-tools pin-version".to_string(),
            allowed: true,
        });
        println!("Added version {version} to pinned_versions.");
    }

    if set_default {
        data.proven.default_version = version.clone();
        println!("Set default_version to {version}.");
    }

    // Write manifest
    manifest::save(&manifest_path, &data)?;

    // Run validate
    let validate_manifest = manifest::resolve_manifest_path(None, repo_root_override.as_deref());
    validate_run(Some(validate_manifest.to_string_lossy().to_string()))?;

    // Run gen-checksums
    checksums_run(repo_root_override)?;

    println!("\nDone. Version {version} pinned successfully.");
    Ok(())
}
