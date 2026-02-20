use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::path::Path;

use crate::canonical::{canonical_json, sha256_hex};

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// An audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub idx: u64,
    pub ts: String,
    pub record_id: String,
    pub prev: String,
    pub entry_hash: String,
}

/// Compute entryHash = sha256( CANON({idx, ts, recordId, prev}) )
pub fn compute_entry_hash(idx: u64, ts: &str, record_id: &str, prev: &str) -> String {
    let obj = serde_json::json!({
        "idx": idx,
        "ts": ts,
        "recordId": record_id,
        "prev": prev
    });
    let canon = canonical_json(&obj);
    sha256_hex(&canon)
}

/// Create a new audit entry.
pub fn new_audit_entry(idx: u64, ts: &str, record_id: &str, prev: &str) -> AuditEntry {
    let entry_hash = compute_entry_hash(idx, ts, record_id, prev);
    AuditEntry {
        idx,
        ts: ts.to_string(),
        record_id: record_id.to_string(),
        prev: prev.to_string(),
        entry_hash,
    }
}

/// Read audit entries from a JSONL file.
pub fn read_audit_log(path: &Path) -> Result<Vec<AuditEntry>, String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {}", path.display(), e))?;
    let reader = std::io::BufReader::new(file);
    let mut entries = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("read error at line {}: {}", i + 1, e))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(trimmed)
            .map_err(|e| format!("parse error at line {}: {}", i + 1, e))?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Append an audit entry to audit-log.jsonl
pub fn append_audit_entry(path: &Path, entry: &AuditEntry) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("cannot open {}: {}", path.display(), e))?;
    let json = serde_json::to_string(entry).map_err(|e| format!("serialize error: {}", e))?;
    writeln!(file, "{}", json).map_err(|e| format!("write error: {}", e))?;
    Ok(())
}

/// Get the current audit head from the log file.
/// Returns the zero hash if the log is empty.
pub fn get_audit_head(path: &Path) -> Result<String, String> {
    let entries = read_audit_log(path)?;
    Ok(entries
        .last()
        .map(|e| e.entry_hash.clone())
        .unwrap_or_else(|| ZERO_HASH.to_string()))
}

/// Verify audit chain integrity: sequential idx, prev chain, entryHash recomputation.
pub fn verify_audit_chain(entries: &[AuditEntry]) -> Result<String, Vec<String>> {
    let mut errors = Vec::new();

    if entries.is_empty() {
        return Ok(ZERO_HASH.to_string());
    }

    let mut prev_hash = ZERO_HASH.to_string();
    for (i, entry) in entries.iter().enumerate() {
        if entry.idx != i as u64 {
            errors.push(format!(
                "audit entry {}: expected idx={}, got idx={}",
                i, i, entry.idx
            ));
        }
        if entry.prev != prev_hash {
            errors.push(format!(
                "audit entry {}: expected prev={}, got prev={}",
                i, prev_hash, entry.prev
            ));
        }
        let expected_hash = compute_entry_hash(entry.idx, &entry.ts, &entry.record_id, &entry.prev);
        if entry.entry_hash != expected_hash {
            errors.push(format!(
                "audit entry {}: expected entryHash={}, got entryHash={}",
                i, expected_hash, entry.entry_hash
            ));
        }
        prev_hash = entry.entry_hash.clone();
    }

    if errors.is_empty() {
        Ok(prev_hash)
    } else {
        Err(errors)
    }
}
