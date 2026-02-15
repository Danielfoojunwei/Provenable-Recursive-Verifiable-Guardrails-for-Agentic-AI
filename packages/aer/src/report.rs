use crate::types::*;
use chrono::Utc;
use serde_json::json;

/// Generate a Markdown report from records and audit entries.
pub fn generate_markdown_report(
    records: &[TypedRecord],
    audit_entries: &[AuditEntry],
) -> String {
    let mut md = String::new();
    md.push_str("# AER Evidence Report\n\n");
    md.push_str(&format!("Generated: {}\n\n", Utc::now().to_rfc3339()));

    // Summary
    md.push_str("## Summary\n\n");
    md.push_str(&format!("- Total records: {}\n", records.len()));
    md.push_str(&format!("- Audit chain entries: {}\n", audit_entries.len()));

    // Record type breakdown
    let mut type_counts = std::collections::HashMap::new();
    for r in records {
        *type_counts.entry(format!("{:?}", r.record_type)).or_insert(0u64) += 1;
    }
    md.push_str("\n### Record Types\n\n");
    md.push_str("| Type | Count |\n|------|-------|\n");
    let mut types: Vec<_> = type_counts.iter().collect();
    types.sort_by_key(|&(k, _)| k.clone());
    for (t, c) in &types {
        md.push_str(&format!("| {} | {} |\n", t, c));
    }

    // Guard decisions
    let guard_decisions: Vec<_> = records
        .iter()
        .filter(|r| r.record_type == RecordType::GuardDecision)
        .collect();
    if !guard_decisions.is_empty() {
        md.push_str("\n## Guard Decisions\n\n");
        let allow_count = guard_decisions.iter().filter(|r| {
            matches!(&r.payload, Payload::Inline { data } if data.get("guard_decision")
                .and_then(|d| d.get("verdict"))
                .and_then(|v| v.as_str())
                == Some("Allow"))
        }).count();
        let deny_count = guard_decisions.len() - allow_count;
        md.push_str(&format!("- Allowed: {}\n", allow_count));
        md.push_str(&format!("- Denied: {}\n", deny_count));

        md.push_str("\n### Denial Details\n\n");
        for r in &guard_decisions {
            if let Payload::Inline { data } = &r.payload {
                if let Some(gd) = data.get("guard_decision") {
                    if gd.get("verdict").and_then(|v| v.as_str()) == Some("Deny") {
                        let surface = gd.get("surface").and_then(|s| s.as_str()).unwrap_or("unknown");
                        let rule = gd.get("rule_id").and_then(|s| s.as_str()).unwrap_or("unknown");
                        let rationale = gd.get("rationale").and_then(|s| s.as_str()).unwrap_or("");
                        md.push_str(&format!(
                            "- **{}** (rule: `{}`): {}\n",
                            surface, rule, rationale
                        ));
                    }
                }
            }
        }
    }

    // Snapshots and rollbacks
    let snapshots: Vec<_> = records
        .iter()
        .filter(|r| r.record_type == RecordType::Snapshot)
        .collect();
    let rollbacks: Vec<_> = records
        .iter()
        .filter(|r| r.record_type == RecordType::Rollback)
        .collect();
    if !snapshots.is_empty() || !rollbacks.is_empty() {
        md.push_str("\n## Snapshots & Rollbacks\n\n");
        md.push_str(&format!("- Snapshots created: {}\n", snapshots.len()));
        md.push_str(&format!("- Rollbacks performed: {}\n", rollbacks.len()));
    }

    // Principal distribution
    let mut principal_counts = std::collections::HashMap::new();
    for r in records {
        *principal_counts.entry(format!("{:?}", r.principal)).or_insert(0u64) += 1;
    }
    md.push_str("\n## Principal Distribution\n\n");
    md.push_str("| Principal | Records |\n|-----------|--------|\n");
    let mut principals: Vec<_> = principal_counts.iter().collect();
    principals.sort_by_key(|&(k, _)| k.clone());
    for (p, c) in &principals {
        md.push_str(&format!("| {} | {} |\n", p, c));
    }

    md
}

/// Generate a JSON report from records and audit entries.
pub fn generate_json_report(
    records: &[TypedRecord],
    audit_entries: &[AuditEntry],
) -> serde_json::Result<String> {
    let mut type_counts = std::collections::HashMap::new();
    for r in records {
        *type_counts.entry(format!("{:?}", r.record_type)).or_insert(0u64) += 1;
    }

    let guard_decisions: Vec<_> = records
        .iter()
        .filter(|r| r.record_type == RecordType::GuardDecision)
        .collect();
    let allow_count = guard_decisions.iter().filter(|r| {
        matches!(&r.payload, Payload::Inline { data } if data.get("guard_decision")
            .and_then(|d| d.get("verdict"))
            .and_then(|v| v.as_str())
            == Some("Allow"))
    }).count();

    let report = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "summary": {
            "total_records": records.len(),
            "audit_chain_entries": audit_entries.len(),
            "record_types": type_counts,
        },
        "guard_decisions": {
            "total": guard_decisions.len(),
            "allowed": allow_count,
            "denied": guard_decisions.len() - allow_count,
        },
        "snapshots": records.iter().filter(|r| r.record_type == RecordType::Snapshot).count(),
        "rollbacks": records.iter().filter(|r| r.record_type == RecordType::Rollback).count(),
    });

    serde_json::to_string_pretty(&report)
}
