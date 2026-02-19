use crate::bundle;
use crate::verify;
use chrono::DateTime;
use std::path::Path;

pub fn export(
    agent_id: Option<&str>,
    since: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let since_dt = match since {
        Some(s) => Some(
            DateTime::parse_from_rfc3339(s)
                .map_err(|e| format!("Invalid timestamp '{s}': {e}"))?
                .with_timezone(&chrono::Utc),
        ),
        None => None,
    };

    println!("Exporting AEGX evidence bundle...");
    if let Some(aid) = agent_id {
        println!("  Filter: agent_id = {aid}");
    }
    if let Some(s) = since {
        println!("  Filter: since = {s}");
    }

    let bundle_path = bundle::export_bundle(agent_id, since_dt)?;

    println!();
    println!("Bundle exported: {bundle_path}");

    Ok(())
}

pub fn verify_run(bundle_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(bundle_path);
    if !path.exists() {
        eprintln!("Bundle not found: {bundle_path}");
        return Err("Bundle not found".into());
    }

    println!("Verifying bundle: {bundle_path}");

    let tmp = bundle::extract_bundle(path)?;
    let result = verify::verify_bundle(tmp.path())?;

    println!();
    println!("Verification result:");
    println!("  Valid: {}", result.valid);
    println!("  Records checked: {}", result.record_count);
    println!("  Audit entries checked: {}", result.audit_entries_checked);
    println!("  Blobs checked: {}", result.blobs_checked);

    if !result.errors.is_empty() {
        println!("  Errors:");
        for e in &result.errors {
            println!("    [{:?}] {}", e.kind, e.detail);
        }
    }

    if result.valid {
        println!();
        println!("PASS: Bundle integrity verified.");
    } else {
        println!();
        println!("FAIL: Bundle integrity check failed.");
        std::process::exit(1);
    }

    Ok(())
}
