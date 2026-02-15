use crate::manifest;

pub fn run(manifest_path: Option<String>) -> Result<(), String> {
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

    let mut allowed_versions = std::collections::HashSet::new();
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
