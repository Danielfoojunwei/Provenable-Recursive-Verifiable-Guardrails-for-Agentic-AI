use crate::manifest::{self, PinnedVersion};
use std::process::Command;

/// Verify version exists on npm and return the exact version string.
fn npm_view_version(version: &str) -> Result<String, String> {
    let output = Command::new("npm")
        .args(["view", &format!("openclaw@{version}"), "version"])
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
            "npm view failed for openclaw@{version}: {stderr}"
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Get the engines.node requirement from npm.
fn npm_view_engines(version: &str) -> String {
    let default = ">=22.0.0".to_string();

    let output = match Command::new("npm")
        .args(["view", &format!("openclaw@{version}"), "engines", "--json"])
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

pub fn run(
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
        .openclaw
        .pinned_versions
        .iter_mut()
        .find(|e| e.version == version)
    {
        println!("Version {version} already pinned — updating.");
        existing.allowed = true;
        existing.engines_node_min = engines_node;
    } else {
        data.openclaw.pinned_versions.push(PinnedVersion {
            version: version.clone(),
            engines_node_min: engines_node,
            notes: "Pinned via installer-tools pin-version".to_string(),
            allowed: true,
        });
        println!("Added version {version} to pinned_versions.");
    }

    if set_default {
        data.openclaw.default_version = version.clone();
        println!("Set default_version to {version}.");
    }

    // Write manifest
    manifest::save(&manifest_path, &data)?;

    // Run validate
    let validate_manifest = manifest::resolve_manifest_path(None, repo_root_override.as_deref());
    crate::validate::run(Some(validate_manifest.to_string_lossy().to_string()))?;

    // Run gen-checksums
    crate::checksums::run(repo_root_override)?;

    println!("\nDone. Version {version} pinned successfully.");
    Ok(())
}
