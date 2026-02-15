use crate::rollback;
use crate::snapshot;

pub fn run(snapshot_id: &str) -> Result<(), Box<dyn std::error::Error>> {
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

    let report = rollback::rollback_to_snapshot(snapshot_id)?;

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
    let verified = rollback::verify_rollback(snapshot_id)?;
    if verified {
        println!("  Verification: PASS — all files match snapshot hashes");
    } else {
        println!("  Verification: FAIL — some files do not match snapshot hashes");
    }

    Ok(())
}
