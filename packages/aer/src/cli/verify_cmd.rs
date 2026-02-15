use crate::bundle;
use crate::verify;
use std::path::Path;

pub fn run(bundle_path: &str) -> Result<(), Box<dyn std::error::Error>> {
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
