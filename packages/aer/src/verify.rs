use crate::audit_chain;
use crate::canonical::{compute_record_id, sha256_hex};
use crate::types::*;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;

/// Verify an exported AEGX bundle directory (extracted zip).
pub fn verify_bundle(bundle_dir: &Path) -> io::Result<VerificationResult> {
    let mut errors = Vec::new();
    let mut record_count = 0u64;
    let mut audit_entries_checked = 0u64;
    let mut blobs_checked = 0u64;

    // 1. Verify records
    let records_path = bundle_dir.join("records.jsonl");
    if records_path.exists() {
        let file = fs::File::open(&records_path)?;
        let reader = io::BufReader::new(file);
        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            record_count += 1;
            match serde_json::from_str::<TypedRecord>(&line) {
                Ok(record) => {
                    let payload_val = match serde_json::to_value(&record.payload) {
                        Ok(v) => v,
                        Err(e) => {
                            errors.push(VerificationError {
                                kind: VerificationErrorKind::MalformedEntry,
                                detail: format!("Line {}: payload serialize error: {e}", line_num + 1),
                            });
                            continue;
                        }
                    };
                    let meta_val = match serde_json::to_value(&record.meta) {
                        Ok(v) => v,
                        Err(e) => {
                            errors.push(VerificationError {
                                kind: VerificationErrorKind::MalformedEntry,
                                detail: format!("Line {}: meta serialize error: {e}", line_num + 1),
                            });
                            continue;
                        }
                    };
                    let expected_id = compute_record_id(&payload_val, &meta_val);
                    if expected_id != record.record_id {
                        errors.push(VerificationError {
                            kind: VerificationErrorKind::RecordHashMismatch,
                            detail: format!(
                                "Record at line {}: expected ID {}, found {}",
                                line_num + 1,
                                expected_id,
                                record.record_id
                            ),
                        });
                    }
                    // Verify blob reference if present
                    if let Payload::BlobRef { hash, .. } = &record.payload {
                        let blob_path = bundle_dir.join("blobs").join(hash);
                        blobs_checked += 1;
                        if !blob_path.exists() {
                            errors.push(VerificationError {
                                kind: VerificationErrorKind::MissingBlob,
                                detail: format!("Missing blob: {hash}"),
                            });
                        } else {
                            let data = fs::read(&blob_path)?;
                            let actual_hash = sha256_hex(&data);
                            if actual_hash != *hash {
                                errors.push(VerificationError {
                                    kind: VerificationErrorKind::BlobHashMismatch,
                                    detail: format!(
                                        "Blob hash mismatch: expected {hash}, got {actual_hash}"
                                    ),
                                });
                            }
                        }
                    }
                }
                Err(e) => {
                    errors.push(VerificationError {
                        kind: VerificationErrorKind::MalformedEntry,
                        detail: format!("Line {}: parse error: {e}", line_num + 1),
                    });
                }
            }
        }
    }

    // 2. Verify audit chain
    let audit_path = bundle_dir.join("audit-log.jsonl");
    if audit_path.exists() {
        let file = fs::File::open(&audit_path)?;
        let reader = io::BufReader::new(file);
        let mut entries = Vec::new();
        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEntry>(&line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    errors.push(VerificationError {
                        kind: VerificationErrorKind::MalformedEntry,
                        detail: format!("Audit line {}: parse error: {e}", line_num + 1),
                    });
                }
            }
        }

        audit_entries_checked = entries.len() as u64;
        match audit_chain::verify_entries(&entries) {
            Ok(_) => {}
            Err(chain_err) => {
                errors.push(VerificationError {
                    kind: VerificationErrorKind::AuditChainBreak,
                    detail: format!("Audit chain integrity failure: {chain_err}"),
                });
            }
        }
    }

    Ok(VerificationResult {
        valid: errors.is_empty(),
        record_count,
        audit_entries_checked,
        blobs_checked,
        errors,
    })
}

/// Verify the live AER state (not from a bundle, but from the active state dir).
pub fn verify_live() -> io::Result<VerificationResult> {
    let aer_root = crate::config::aer_root();
    if !aer_root.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "AER not initialized (no .aer directory found)",
        ));
    }

    let mut errors = Vec::new();
    let mut blobs_checked = 0u64;

    // Verify records
    let records = crate::records::read_all_records()?;
    let record_count = records.len() as u64;
    for record in &records {
        if !crate::records::verify_record_hash(record) {
            errors.push(VerificationError {
                kind: VerificationErrorKind::RecordHashMismatch,
                detail: format!("Record {} hash mismatch", record.record_id),
            });
        }
        if let Payload::BlobRef { hash, .. } = &record.payload {
            blobs_checked += 1;
            match crate::records::verify_blob(hash) {
                Ok(true) => {}
                Ok(false) => {
                    errors.push(VerificationError {
                        kind: VerificationErrorKind::BlobHashMismatch,
                        detail: format!("Blob {hash} missing or hash mismatch"),
                    });
                }
                Err(e) => {
                    errors.push(VerificationError {
                        kind: VerificationErrorKind::MissingBlob,
                        detail: format!("Blob {hash} read error: {e}"),
                    });
                }
            }
        }
    }

    // Verify audit chain
    let chain_result = crate::audit_chain::verify_chain()?;
    let audit_entries_checked = match chain_result {
        Ok(count) => count,
        Err(chain_err) => {
            errors.push(VerificationError {
                kind: VerificationErrorKind::AuditChainBreak,
                detail: format!("Audit chain integrity failure: {chain_err}"),
            });
            0
        }
    };

    Ok(VerificationResult {
        valid: errors.is_empty(),
        record_count,
        audit_entries_checked,
        blobs_checked,
        errors,
    })
}
