// Bundle commands (merged from bundle_cmd.rs)

use crate::bundle;
use crate::prove::{self, ProveQuery};
use crate::report;
use crate::rollback_policy;
use crate::snapshot;
use crate::types::*;
use crate::verify;
use chrono::DateTime;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;

pub fn bundle_export(
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

pub fn bundle_verify(bundle_path: &str) -> Result<(), Box<dyn std::error::Error>> {
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

// Prove commands (merged from prove_cmd.rs)

pub fn prove_run(
    since: Option<&str>,
    until: Option<&str>,
    category: Option<&str>,
    severity: Option<&str>,
    limit: Option<usize>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let since_dt = since
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|d| d.with_timezone(&chrono::Utc))
                .map_err(|e| format!("Invalid --since timestamp: {e}"))
        })
        .transpose()?;

    let until_dt = until
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|d| d.with_timezone(&chrono::Utc))
                .map_err(|e| format!("Invalid --until timestamp: {e}"))
        })
        .transpose()?;

    let category_filter = category
        .map(|c| match c.to_uppercase().as_str() {
            "CPI" | "CPI_VIOLATION" => Ok(crate::alerts::ThreatCategory::CpiViolation),
            "MI" | "MI_VIOLATION" => Ok(crate::alerts::ThreatCategory::MiViolation),
            "TAINT" | "TAINT_BLOCK" => Ok(crate::alerts::ThreatCategory::TaintBlock),
            "PROXY" | "PROXY_MISCONFIG" => Ok(crate::alerts::ThreatCategory::ProxyMisconfig),
            "RATE_LIMIT" => Ok(crate::alerts::ThreatCategory::RateLimitExceeded),
            "INJECTION" => Ok(crate::alerts::ThreatCategory::InjectionSuspect),
            "EXTRACTION" | "PROMPT_EXTRACTION" => {
                Ok(crate::alerts::ThreatCategory::PromptExtraction)
            }
            "LEAKAGE" | "PROMPT_LEAKAGE" => Ok(crate::alerts::ThreatCategory::PromptLeakage),
            "ROLLBACK" | "ROLLBACK_RECOMMENDED" => {
                Ok(crate::alerts::ThreatCategory::RollbackRecommended)
            }
            "AUTO_ROLLBACK" => Ok(crate::alerts::ThreatCategory::AutoRollback),
            "CONTAMINATION" | "CONTAMINATION_DETECTED" => {
                Ok(crate::alerts::ThreatCategory::ContaminationDetected)
            }
            _ => Err(format!(
                "Unknown category '{}'. Valid: CPI, MI, TAINT, PROXY, RATE_LIMIT, INJECTION, \
                 EXTRACTION, LEAKAGE, ROLLBACK, AUTO_ROLLBACK, CONTAMINATION",
                c
            )),
        })
        .transpose()?;

    let severity_filter = severity
        .map(|s| match s.to_uppercase().as_str() {
            "INFO" => Ok(crate::alerts::AlertSeverity::Info),
            "MEDIUM" => Ok(crate::alerts::AlertSeverity::Medium),
            "HIGH" => Ok(crate::alerts::AlertSeverity::High),
            "CRITICAL" => Ok(crate::alerts::AlertSeverity::Critical),
            _ => Err(format!(
                "Unknown severity '{}'. Valid: INFO, MEDIUM, HIGH, CRITICAL",
                s
            )),
        })
        .transpose()?;

    let query = ProveQuery {
        since: since_dt,
        until: until_dt,
        category: category_filter,
        severity_min: severity_filter,
        limit,
        include_metrics: true,
        include_health: true,
    };

    let response = prove::execute_query(&query)?;

    if json_output {
        let json = prove::format_prove_json(&response)?;
        println!("{}", json);
    } else {
        let formatted = prove::format_prove_response(&response);
        print!("{}", formatted);
    }

    Ok(())
}

pub fn prove_report(bundle_path: &str) -> Result<(), Box<dyn std::error::Error>> {
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

    let report = report::generate_markdown_report(&records, &audit_entries);
    println!("{report}");

    Ok(())
}

// Snapshot commands (merged from snapshot_cmd.rs)

pub fn snapshot_create(name: &str, scope_str: &str) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn snapshot_list() -> Result<(), Box<dyn std::error::Error>> {
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

pub fn snapshot_rollback(snapshot_id: &str) -> Result<(), Box<dyn std::error::Error>> {
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
