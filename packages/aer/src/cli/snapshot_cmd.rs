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
            println!("    {} ({} bytes, sha256: {})", f.path, f.size, &f.sha256[..12]);
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
