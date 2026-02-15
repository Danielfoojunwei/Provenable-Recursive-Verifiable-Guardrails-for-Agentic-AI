use crate::bundle;
use crate::types::*;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;

pub fn run(bundle_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(bundle_path);
    if !path.exists() {
        eprintln!("Bundle not found: {bundle_path}");
        return Err("Bundle not found".into());
    }

    let tmp = bundle::extract_bundle(path)?;

    // Check if report.md already exists in the bundle
    let report_md_path = tmp.path().join("report.md");
    if report_md_path.exists() {
        let content = fs::read_to_string(&report_md_path)?;
        println!("{content}");
        return Ok(());
    }

    // Otherwise generate from records and audit log
    let records_path = tmp.path().join("records.jsonl");
    let audit_path = tmp.path().join("audit-log.jsonl");

    let records = if records_path.exists() {
        let file = fs::File::open(&records_path)?;
        let reader = io::BufReader::new(file);
        reader
            .lines()
            .map_while(Result::ok)
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<TypedRecord>(&l).ok())
            .collect()
    } else {
        Vec::new()
    };

    let audit_entries = if audit_path.exists() {
        let file = fs::File::open(&audit_path)?;
        let reader = io::BufReader::new(file);
        reader
            .lines()
            .map_while(Result::ok)
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<AuditEntry>(&l).ok())
            .collect()
    } else {
        Vec::new()
    };

    let report = crate::report::generate_markdown_report(&records, &audit_entries);
    println!("{report}");

    Ok(())
}
