use crate::rollback_policy;
use crate::snapshot;
use crate::types::SnapshotScope;

pub fn create(name: &str, scope_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let scope = match scope_str {
        "full" => SnapshotScope::Full,
        "control-plane" | "cp" => SnapshotScope::ControlPlane,
        "memory" | "mem" => SnapshotScope::DurableMemory,
        _ => {
            eprintln!("Unknown scope: {scope_str}. Use: full, control-plane, memory");
            return Err("Invalid scope".into());
        }
    };

    println!("Creating snapshot '{name}' (scope: {scope_str})...");
    let manifest = snapshot::create_snapshot(name, scope)?;

    println!("Snapshot created:");
    println!("  ID: {}", manifest.snapshot_id);
    println!("  Name: {}", manifest.name);
    println!("  Files: {}", manifest.files.len());
    println!("  Created: {}", manifest.created_at.to_rfc3339());

    if !manifest.files.is_empty() {
        println!("  Contents:");
        for f in &manifest.files {
            println!(
                "    {} ({} bytes, sha256: {})",
                f.path,
                f.size,
                &f.sha256[..12]
            );
        }
    }

    Ok(())
}

pub fn list() -> Result<(), Box<dyn std::error::Error>> {
    let snapshots = snapshot::list_snapshots()?;

    if snapshots.is_empty() {
        println!("No snapshots found.");
        return Ok(());
    }

    println!("Snapshots:");
    for s in &snapshots {
        println!(
            "  {} — {} ({:?}, {} files, {})",
            &s.snapshot_id[..8],
            s.name,
            s.scope,
            s.files.len(),
            s.created_at.to_rfc3339()
        );
    }

    Ok(())
}

pub fn rollback_run(snapshot_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Load manifest to show what will be rolled back
    let manifest = snapshot::load_snapshot(snapshot_id)?;
    let (modified, _added, removed) = snapshot::diff_snapshot(&manifest)?;

    println!(
        "Rolling back to snapshot: {} ({})",
        &snapshot_id[..8],
        manifest.name
    );
    println!("  Files to restore: {}", modified.len());
    println!("  Files to recreate: {}", removed.len());

    if modified.is_empty() && removed.is_empty() {
        println!("  No changes needed — state matches snapshot.");
        return Ok(());
    }

    let report = rollback_policy::rollback_to_snapshot(snapshot_id)?;

    println!();
    println!("Rollback complete:");
    if !report.files_restored.is_empty() {
        println!("  Restored:");
        for f in &report.files_restored {
            println!("    {f}");
        }
    }
    if !report.files_recreated.is_empty() {
        println!("  Recreated:");
        for f in &report.files_recreated {
            println!("    {f}");
        }
    }
    if !report.errors.is_empty() {
        println!("  Errors:");
        for e in &report.errors {
            println!("    {e}");
        }
    }

    // Verify rollback
    let verified = rollback_policy::verify_rollback(snapshot_id)?;
    if verified {
        println!("  Verification: PASS — all files match snapshot hashes");
    } else {
        println!("  Verification: FAIL — some files do not match snapshot hashes");
    }

    Ok(())
}
