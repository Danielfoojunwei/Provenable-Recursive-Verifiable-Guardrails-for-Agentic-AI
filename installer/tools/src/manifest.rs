use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level manifest structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: String,
    pub installer: InstallerSection,
    pub proven: ProvenSection,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstallerSection {
    pub version: String,
    pub artifacts: std::collections::HashMap<String, ArtifactEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactEntry {
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProvenSection {
    pub install_mode: String,
    pub pinned_versions: Vec<PinnedVersion>,
    pub default_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedVersion {
    pub version: String,
    pub engines_node_min: String,
    #[serde(default)]
    pub notes: String,
    pub allowed: bool,
}

/// Resolve the repo root directory.
/// If `override_path` is Some, use that; otherwise walk up from the binary location.
pub fn resolve_repo_root(override_path: Option<&str>) -> PathBuf {
    if let Some(p) = override_path {
        return PathBuf::from(p);
    }
    // Default: assume binary is in tools/target/debug or tools/target/release,
    // so repo root is 3-4 levels up. Fallback to current dir parent.
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    // If cwd contains a manifest/ dir, use cwd as repo root
    if cwd.join("manifest").join("manifest.json").exists() {
        return cwd;
    }
    // Otherwise try parent
    if let Some(parent) = cwd.parent() {
        if parent.join("manifest").join("manifest.json").exists() {
            return parent.to_path_buf();
        }
    }
    cwd
}

/// Resolve the manifest.json path
pub fn resolve_manifest_path(override_path: Option<&str>, repo_root: Option<&str>) -> PathBuf {
    if let Some(p) = override_path {
        return PathBuf::from(p);
    }
    let root = resolve_repo_root(repo_root);
    root.join("manifest").join("manifest.json")
}

/// Load manifest from path
pub fn load(path: &Path) -> Result<Manifest, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON in {}: {e}", path.display()))
}

/// Save manifest to path (pretty-printed with trailing newline)
pub fn save(path: &Path, manifest: &Manifest) -> Result<(), String> {
    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| format!("Failed to serialize manifest: {e}"))?;
    std::fs::write(path, format!("{json}\n"))
        .map_err(|e| format!("Cannot write {}: {e}", path.display()))
}

/// Validate semver format (X.Y.Z)
pub fn is_semver(s: &str) -> bool {
    let re = regex::Regex::new(r"^\d+\.\d+\.\d+$").unwrap();
    re.is_match(s)
}

/// Validate SHA-256 hex string (64 lowercase hex chars)
pub fn is_sha256_hex(s: &str) -> bool {
    let re = regex::Regex::new(r"^[a-f0-9]{64}$").unwrap();
    re.is_match(s)
}

/// Compute SHA-256 of a file, returning lowercase hex
pub fn sha256_file(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};

    let data = std::fs::read(path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    let hash = Sha256::digest(&data);
    Ok(hex::encode(hash))
}
