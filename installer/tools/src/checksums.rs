use crate::manifest;
use std::collections::BTreeMap;

pub fn run(repo_root_override: Option<String>) -> Result<(), String> {
    let repo_root = manifest::resolve_repo_root(repo_root_override.as_deref());
    let manifest_path = repo_root.join("manifest").join("manifest.json");
    let checksums_path = repo_root.join("checksums.txt");

    let artifacts: BTreeMap<&str, _> = BTreeMap::from([
        (
            "install-openclaw-aer.sh",
            repo_root.join("install").join("install-openclaw-aer.sh"),
        ),
        (
            "install-openclaw-aer.ps1",
            repo_root.join("install").join("install-openclaw-aer.ps1"),
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
