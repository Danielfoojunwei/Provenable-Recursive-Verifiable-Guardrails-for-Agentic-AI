use crate::audit_chain;
use crate::canonical::sha256_file;
use crate::config;
use crate::records;
use crate::types::*;
use chrono::Utc;
use serde_json::json;
use std::fs;
use std::io;
use std::path::Path;
use uuid::Uuid;
use walkdir::WalkDir;

/// Create a snapshot of current control-plane config and workspace memory.
pub fn create_snapshot(name: &str, scope: SnapshotScope) -> io::Result<SnapshotManifest> {
    let state_dir = config::resolve_state_dir();
    let snapshot_id = Uuid::new_v4().to_string();
    let mut files = Vec::new();

    match scope {
        SnapshotScope::Full => {
            collect_control_plane_files(&state_dir, &mut files)?;
            collect_memory_files(&state_dir, &mut files)?;
        }
        SnapshotScope::ControlPlane => {
            collect_control_plane_files(&state_dir, &mut files)?;
        }
        SnapshotScope::DurableMemory => {
            collect_memory_files(&state_dir, &mut files)?;
        }
    }

    let manifest = SnapshotManifest {
        snapshot_id: snapshot_id.clone(),
        name: name.to_string(),
        created_at: Utc::now(),
        scope,
        files,
    };

    // Save manifest
    let snap_dir = config::snapshots_dir().join(&snapshot_id);
    fs::create_dir_all(&snap_dir)?;

    let manifest_path = snap_dir.join("manifest.json");
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    fs::write(&manifest_path, &manifest_json)?;

    // Copy file blobs
    let blobs_dir = snap_dir.join("blobs");
    fs::create_dir_all(&blobs_dir)?;
    for entry in &manifest.files {
        let src = state_dir.join(&entry.path);
        if src.exists() {
            let dest = blobs_dir.join(&entry.sha256);
            fs::copy(&src, &dest)?;
        }
    }

    // Emit snapshot record
    let mut meta = RecordMeta::now();
    meta.snapshot_id = Some(snapshot_id.clone());

    let payload = json!({
        "snapshot_id": snapshot_id,
        "name": name,
        "scope": scope,
        "file_count": manifest.files.len(),
    });

    let record = records::emit_record(
        RecordType::Snapshot,
        Principal::User,
        TaintFlags::empty(),
        vec![],
        meta,
        payload,
    )?;
    audit_chain::emit_audit(&record.record_id)?;

    Ok(manifest)
}

/// Collect control-plane relevant files relative to state_dir.
fn collect_control_plane_files(
    state_dir: &Path,
    files: &mut Vec<SnapshotFileEntry>,
) -> io::Result<()> {
    // Skills registry, tool config, gateway config, general config
    let config_patterns = [
        "config.yaml",
        "config.json",
        "gateway.yaml",
        "gateway.json",
        "skills",
        "tools",
    ];

    for pattern in &config_patterns {
        let path = state_dir.join(pattern);
        if path.is_file() {
            add_file_entry(state_dir, &path, files)?;
        } else if path.is_dir() {
            for entry in WalkDir::new(&path).min_depth(1).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    add_file_entry(state_dir, entry.path(), files)?;
                }
            }
        }
    }

    // Also snapshot the AER policy
    let policy_dir = config::policy_dir();
    if policy_dir.exists() {
        for entry in WalkDir::new(&policy_dir).min_depth(1).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                add_file_entry(state_dir, entry.path(), files)?;
            }
        }
    }

    Ok(())
}

/// Collect workspace memory files.
fn collect_memory_files(
    state_dir: &Path,
    files: &mut Vec<SnapshotFileEntry>,
) -> io::Result<()> {
    let workspace = state_dir.join("workspace");
    for filename in config::MEMORY_FILES {
        let path = workspace.join(filename);
        if path.exists() {
            add_file_entry(state_dir, &path, files)?;
        }
    }
    Ok(())
}

fn add_file_entry(
    base: &Path,
    path: &Path,
    files: &mut Vec<SnapshotFileEntry>,
) -> io::Result<()> {
    let relative = path.strip_prefix(base).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Path strip error: {e}"))
    })?;
    let metadata = fs::metadata(path)?;
    let hash = sha256_file(path)?;
    let mtime = metadata.modified().ok().map(|t| chrono::DateTime::<Utc>::from(t));

    files.push(SnapshotFileEntry {
        path: relative.to_string_lossy().to_string(),
        sha256: hash,
        size: metadata.len(),
        mtime,
    });
    Ok(())
}

/// List all snapshots.
pub fn list_snapshots() -> io::Result<Vec<SnapshotManifest>> {
    let dir = config::snapshots_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut manifests = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let manifest_path = entry.path().join("manifest.json");
            if manifest_path.exists() {
                let content = fs::read_to_string(&manifest_path)?;
                let manifest: SnapshotManifest = serde_json::from_str(&content).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("Bad manifest: {e}"))
                })?;
                manifests.push(manifest);
            }
        }
    }
    manifests.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(manifests)
}

/// Load a specific snapshot manifest by ID.
pub fn load_snapshot(snapshot_id: &str) -> io::Result<SnapshotManifest> {
    let manifest_path = config::snapshots_dir()
        .join(snapshot_id)
        .join("manifest.json");
    if !manifest_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Snapshot not found: {snapshot_id}"),
        ));
    }
    let content = fs::read_to_string(&manifest_path)?;
    serde_json::from_str(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Bad manifest: {e}")))
}

/// Compute diff between a snapshot and current state.
/// Returns (modified, added, removed) file paths.
pub fn diff_snapshot(
    manifest: &SnapshotManifest,
) -> io::Result<(Vec<String>, Vec<String>, Vec<String>)> {
    let state_dir = config::resolve_state_dir();
    let mut modified = Vec::new();
    let mut removed = Vec::new();

    for entry in &manifest.files {
        let path = state_dir.join(&entry.path);
        if !path.exists() {
            removed.push(entry.path.clone());
        } else {
            let current_hash = sha256_file(&path)?;
            if current_hash != entry.sha256 {
                modified.push(entry.path.clone());
            }
        }
    }

    // We don't track added files in the diff (snapshot is a known-good baseline)
    Ok((modified, Vec::new(), removed))
}
