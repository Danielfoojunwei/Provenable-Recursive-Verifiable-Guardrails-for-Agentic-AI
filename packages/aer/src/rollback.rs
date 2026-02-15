use crate::audit_chain;
use crate::config;
use crate::records;
use crate::snapshot;
use crate::types::*;
use serde_json::json;
use std::fs;
use std::io;

/// Rollback to a specific snapshot, restoring all files to their snapshot state.
/// Returns a report of what was changed.
pub fn rollback_to_snapshot(snapshot_id: &str) -> io::Result<RollbackReport> {
    let manifest = snapshot::load_snapshot(snapshot_id)?;
    let state_dir = config::resolve_state_dir();
    let snap_blobs = config::snapshots_dir().join(snapshot_id).join("blobs");

    // Compute pre-rollback diff
    let (modified, _added, removed) = snapshot::diff_snapshot(&manifest)?;

    let mut restored = Vec::new();
    let mut recreated = Vec::new();
    let mut errors = Vec::new();

    for entry in &manifest.files {
        let target = state_dir.join(&entry.path);
        let source = snap_blobs.join(&entry.sha256);

        if !source.exists() {
            errors.push(format!(
                "Blob missing for {}: {}",
                entry.path, entry.sha256
            ));
            continue;
        }

        // Ensure parent directory exists
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }

        // Restore the file
        fs::copy(&source, &target)?;

        if removed.contains(&entry.path) {
            recreated.push(entry.path.clone());
        } else if modified.contains(&entry.path) {
            restored.push(entry.path.clone());
        }
    }

    let report = RollbackReport {
        snapshot_id: snapshot_id.to_string(),
        snapshot_name: manifest.name.clone(),
        files_restored: restored.clone(),
        files_recreated: recreated.clone(),
        errors: errors.clone(),
    };

    // Emit rollback record
    let mut meta = RecordMeta::now();
    meta.snapshot_id = Some(snapshot_id.to_string());

    let payload = json!({
        "snapshot_id": snapshot_id,
        "snapshot_name": manifest.name,
        "files_restored": restored,
        "files_recreated": recreated,
        "errors": errors,
    });

    let record = records::emit_record(
        RecordType::Rollback,
        Principal::User,
        TaintFlags::empty(),
        vec![],
        meta,
        payload,
    )?;
    audit_chain::emit_audit(&record.record_id)?;

    Ok(report)
}

/// Verify that a rollback restored files to the correct hashes.
pub fn verify_rollback(snapshot_id: &str) -> io::Result<bool> {
    let manifest = snapshot::load_snapshot(snapshot_id)?;
    let state_dir = config::resolve_state_dir();

    for entry in &manifest.files {
        let path = state_dir.join(&entry.path);
        if !path.exists() {
            return Ok(false);
        }
        let current_hash = crate::canonical::sha256_file(&path)?;
        if current_hash != entry.sha256 {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Report of what a rollback changed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RollbackReport {
    pub snapshot_id: String,
    pub snapshot_name: String,
    pub files_restored: Vec<String>,
    pub files_recreated: Vec<String>,
    pub errors: Vec<String>,
}
