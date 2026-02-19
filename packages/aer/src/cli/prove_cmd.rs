use crate::bundle;
use crate::prove::{self, ProveQuery};
use crate::types::*;
use chrono::DateTime;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;

pub fn run(
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
            "EXTRACTION" | "PROMPT_EXTRACTION" => Ok(crate::alerts::ThreatCategory::PromptExtraction),
            "LEAKAGE" | "PROMPT_LEAKAGE" => Ok(crate::alerts::ThreatCategory::PromptLeakage),
            "ROLLBACK" | "ROLLBACK_RECOMMENDED" => Ok(crate::alerts::ThreatCategory::RollbackRecommended),
            "AUTO_ROLLBACK" => Ok(crate::alerts::ThreatCategory::AutoRollback),
            "CONTAMINATION" | "CONTAMINATION_DETECTED" => Ok(crate::alerts::ThreatCategory::ContaminationDetected),
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

pub fn report_run(bundle_path: &str) -> Result<(), Box<dyn std::error::Error>> {
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
