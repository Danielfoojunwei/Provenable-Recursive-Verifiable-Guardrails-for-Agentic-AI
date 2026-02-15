use crate::canonical::compute_entry_hash;
use crate::config;
use crate::types::AuditEntry;
use chrono::Utc;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};

/// Genesis hash for the first entry in the chain.
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Append a new entry to the audit chain for a given record ID.
pub fn append_audit_entry(record_id: &str) -> io::Result<AuditEntry> {
    let path = config::audit_log_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let last = read_last_entry()?;
    let idx = last.as_ref().map(|e| e.idx + 1).unwrap_or(0);
    let prev_hash = last
        .as_ref()
        .map(|e| e.entry_hash.clone())
        .unwrap_or_else(|| GENESIS_HASH.to_string());

    let ts = Utc::now();
    let ts_str = ts.to_rfc3339();
    let entry_hash = compute_entry_hash(idx, &ts_str, record_id, &prev_hash);

    let entry = AuditEntry {
        idx,
        ts,
        record_id: record_id.to_string(),
        prev_hash,
        entry_hash,
    };

    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    let line = serde_json::to_string(&entry)?;
    writeln!(file, "{}", line)?;

    Ok(entry)
}

/// Read the last entry in the audit chain.
pub fn read_last_entry() -> io::Result<Option<AuditEntry>> {
    let entries = read_all_entries()?;
    Ok(entries.into_iter().last())
}

/// Read all entries from the audit chain.
pub fn read_all_entries() -> io::Result<Vec<AuditEntry>> {
    let path = config::audit_log_file();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(&path)?;
    let reader = io::BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Bad audit entry: {e}"))
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Verify the integrity of the entire audit chain.
/// Returns Ok(()) if chain is valid, Err with details of the first break.
pub fn verify_chain() -> io::Result<Result<u64, ChainError>> {
    let entries = read_all_entries()?;
    Ok(verify_entries(&entries))
}

/// Verify a slice of audit entries.
pub fn verify_entries(entries: &[AuditEntry]) -> Result<u64, ChainError> {
    if entries.is_empty() {
        return Ok(0);
    }

    let mut prev_hash = GENESIS_HASH.to_string();

    for (i, entry) in entries.iter().enumerate() {
        // Check index continuity
        if entry.idx != i as u64 {
            return Err(ChainError::IndexGap {
                expected: i as u64,
                found: entry.idx,
            });
        }

        // Check prev_hash linkage
        if entry.prev_hash != prev_hash {
            return Err(ChainError::PrevHashMismatch {
                idx: entry.idx,
                expected: prev_hash,
                found: entry.prev_hash.clone(),
            });
        }

        // Recompute entry_hash
        let ts_str = entry.ts.to_rfc3339();
        let expected_hash = compute_entry_hash(entry.idx, &ts_str, &entry.record_id, &prev_hash);
        if entry.entry_hash != expected_hash {
            return Err(ChainError::EntryHashMismatch {
                idx: entry.idx,
                expected: expected_hash,
                found: entry.entry_hash.clone(),
            });
        }

        prev_hash = entry.entry_hash.clone();
    }

    Ok(entries.len() as u64)
}

/// Chain verification errors.
#[derive(Debug, Clone)]
pub enum ChainError {
    IndexGap { expected: u64, found: u64 },
    PrevHashMismatch { idx: u64, expected: String, found: String },
    EntryHashMismatch { idx: u64, expected: String, found: String },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::IndexGap { expected, found } => {
                write!(f, "Index gap: expected {expected}, found {found}")
            }
            ChainError::PrevHashMismatch { idx, expected, found } => {
                write!(f, "prev_hash mismatch at idx {idx}: expected {expected}, found {found}")
            }
            ChainError::EntryHashMismatch { idx, expected, found } => {
                write!(f, "entry_hash mismatch at idx {idx}: expected {expected}, found {found}")
            }
        }
    }
}

impl std::error::Error for ChainError {}

/// Emit a record to the audit chain (convenience: appends and returns the entry).
pub fn emit_audit(record_id: &str) -> io::Result<AuditEntry> {
    append_audit_entry(record_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_empty_chain() {
        let entries: Vec<AuditEntry> = vec![];
        assert_eq!(verify_entries(&entries).unwrap(), 0);
    }

    #[test]
    fn test_verify_single_entry() {
        let ts = Utc::now();
        let ts_str = ts.to_rfc3339();
        let prev = GENESIS_HASH.to_string();
        let hash = compute_entry_hash(0, &ts_str, "rec1", &prev);
        let entry = AuditEntry {
            idx: 0,
            ts,
            record_id: "rec1".to_string(),
            prev_hash: prev,
            entry_hash: hash,
        };
        assert_eq!(verify_entries(&[entry]).unwrap(), 1);
    }

    #[test]
    fn test_verify_chain_linkage() {
        let ts1 = Utc::now();
        let ts1_str = ts1.to_rfc3339();
        let prev0 = GENESIS_HASH.to_string();
        let hash0 = compute_entry_hash(0, &ts1_str, "r1", &prev0);
        let e0 = AuditEntry {
            idx: 0,
            ts: ts1,
            record_id: "r1".to_string(),
            prev_hash: prev0,
            entry_hash: hash0.clone(),
        };

        let ts2 = Utc::now();
        let ts2_str = ts2.to_rfc3339();
        let hash1 = compute_entry_hash(1, &ts2_str, "r2", &hash0);
        let e1 = AuditEntry {
            idx: 1,
            ts: ts2,
            record_id: "r2".to_string(),
            prev_hash: hash0,
            entry_hash: hash1,
        };

        assert_eq!(verify_entries(&[e0, e1]).unwrap(), 2);
    }

    #[test]
    fn test_detect_tamper() {
        let ts = Utc::now();
        let ts_str = ts.to_rfc3339();
        let prev = GENESIS_HASH.to_string();
        let hash = compute_entry_hash(0, &ts_str, "rec1", &prev);
        let mut entry = AuditEntry {
            idx: 0,
            ts,
            record_id: "rec1".to_string(),
            prev_hash: prev,
            entry_hash: hash,
        };
        // Tamper with the record_id
        entry.record_id = "TAMPERED".to_string();
        assert!(verify_entries(&[entry]).is_err());
    }
}
