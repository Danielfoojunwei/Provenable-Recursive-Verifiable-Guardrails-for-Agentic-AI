use std::collections::HashSet;
use std::path::Path;

use crate::audit;
use crate::bundle;
use crate::hash::sha256_hex;
use crate::records::{self, Payload};
use crate::schema;

/// Exit codes for verification.
pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_VERIFY_FAILURE: i32 = 2;
pub const EXIT_SCHEMA_FAILURE: i32 = 3;
pub const EXIT_IO_ERROR: i32 = 4;

/// Verification result.
#[derive(Debug)]
pub struct VerifyResult {
    pub exit_code: i32,
    pub errors: Vec<String>,
}

impl VerifyResult {
    pub fn ok() -> Self {
        VerifyResult {
            exit_code: EXIT_SUCCESS,
            errors: Vec::new(),
        }
    }

    pub fn is_ok(&self) -> bool {
        self.exit_code == EXIT_SUCCESS
    }
}

/// Verify a bundle end-to-end.
pub fn verify_bundle(bundle_dir: &Path) -> VerifyResult {
    let mut errors: Vec<String> = Vec::new();
    let mut schema_errors = false;

    // 1. Read and validate manifest
    let manifest = match bundle::read_manifest(bundle_dir) {
        Ok(m) => m,
        Err(e) => {
            return VerifyResult {
                exit_code: EXIT_IO_ERROR,
                errors: vec![format!("manifest.json: {}", e)],
            };
        }
    };

    if let Err(errs) = schema::validate_manifest(&manifest) {
        for e in &errs {
            errors.push(format!("manifest.json: schema: {}", e));
        }
        schema_errors = true;
    }

    // 2. Read and validate records
    let records_path = bundle_dir.join("records.jsonl");
    let records = match records::read_records(&records_path) {
        Ok(r) => r,
        Err(e) => {
            return VerifyResult {
                exit_code: EXIT_IO_ERROR,
                errors: vec![format!("records.jsonl: {}", e)],
            };
        }
    };

    // Validate each record schema
    for (i, record) in records.iter().enumerate() {
        let val = serde_json::to_value(record).unwrap();
        if let Err(errs) = schema::validate_record(&val) {
            for e in &errs {
                errors.push(format!("records.jsonl line {}: schema: {}", i + 1, e));
            }
            schema_errors = true;
        }
    }

    // 3. Read and validate audit log
    let audit_path = bundle_dir.join("audit-log.jsonl");
    let audit_entries = match audit::read_audit_log(&audit_path) {
        Ok(e) => e,
        Err(e) => {
            return VerifyResult {
                exit_code: EXIT_IO_ERROR,
                errors: vec![format!("audit-log.jsonl: {}", e)],
            };
        }
    };

    for (i, entry) in audit_entries.iter().enumerate() {
        let val = serde_json::to_value(entry).unwrap();
        if let Err(errs) = schema::validate_audit_entry(&val) {
            for e in &errs {
                errors.push(format!("audit-log.jsonl line {}: schema: {}", i + 1, e));
            }
            schema_errors = true;
        }
    }

    if schema_errors {
        return VerifyResult {
            exit_code: EXIT_SCHEMA_FAILURE,
            errors,
        };
    }

    // 4. Recompute recordId for each record
    let mut record_ids: HashSet<String> = HashSet::new();
    for (i, record) in records.iter().enumerate() {
        let computed = records::compute_record_id(
            &record.record_type,
            &record.principal,
            &record.taint,
            &record.parents,
            &record.meta,
            &record.payload,
        );
        if computed != record.record_id {
            errors.push(format!(
                "records.jsonl line {}: recordId mismatch: expected={}, got={}",
                i + 1,
                computed,
                record.record_id
            ));
        }
        record_ids.insert(record.record_id.clone());
    }

    // 5. Check parent references
    for (i, record) in records.iter().enumerate() {
        for parent in &record.parents {
            if !record_ids.contains(parent) {
                errors.push(format!(
                    "records.jsonl line {}: dangling parent reference: {}",
                    i + 1,
                    parent
                ));
            }
        }
    }

    // 6. Check blob references
    for (i, record) in records.iter().enumerate() {
        if let Payload::Blob { blob, .. } = &record.payload {
            let blob_path = bundle_dir.join("blobs").join(blob);
            if !blob_path.exists() {
                errors.push(format!(
                    "records.jsonl line {}: referenced blob {} does not exist",
                    i + 1,
                    blob
                ));
            } else {
                // Verify blob content hash matches filename
                match std::fs::read(&blob_path) {
                    Ok(data) => {
                        let computed = sha256_hex(&data);
                        if computed != *blob {
                            errors.push(format!(
                                "blobs/{}: hash mismatch: computed={}, filename={}",
                                blob, computed, blob
                            ));
                        }
                    }
                    Err(e) => {
                        errors.push(format!("blobs/{}: cannot read: {}", blob, e));
                    }
                }
            }
        }
    }

    // 7. Verify audit chain
    match audit::verify_audit_chain(&audit_entries) {
        Ok(head) => {
            // Check audit_head matches manifest
            if let Some(manifest_head) = manifest.get("audit_head").and_then(|v| v.as_str()) {
                if head != manifest_head {
                    errors.push(format!(
                        "audit_head mismatch: manifest={}, computed={}",
                        manifest_head, head
                    ));
                }
            }
        }
        Err(chain_errors) => {
            errors.extend(chain_errors);
        }
    }

    // 8. Check record_count
    if let Some(expected) = manifest.get("record_count").and_then(|v| v.as_u64()) {
        if expected != records.len() as u64 {
            errors.push(format!(
                "record_count mismatch: manifest={}, actual={}",
                expected,
                records.len()
            ));
        }
    }

    // 9. Check blob_count
    match bundle::count_blobs(bundle_dir) {
        Ok(actual) => {
            if let Some(expected) = manifest.get("blob_count").and_then(|v| v.as_u64()) {
                if expected != actual {
                    errors.push(format!(
                        "blob_count mismatch: manifest={}, actual={}",
                        expected, actual
                    ));
                }
            }
        }
        Err(e) => {
            errors.push(format!("cannot count blobs: {}", e));
        }
    }

    // 10. Check root_records exist
    if let Some(roots) = manifest.get("root_records").and_then(|v| v.as_array()) {
        for root in roots {
            if let Some(root_id) = root.as_str() {
                if !record_ids.contains(root_id) {
                    errors.push(format!("root_records: {} not found in records", root_id));
                }
            }
        }
    }

    if errors.is_empty() {
        VerifyResult::ok()
    } else {
        VerifyResult {
            exit_code: EXIT_VERIFY_FAILURE,
            errors,
        }
    }
}

/// Summarize a bundle: counts by record type and principal + verification status.
pub fn summarize_bundle(bundle_dir: &Path) -> Result<String, String> {
    let records_path = bundle_dir.join("records.jsonl");
    let records = records::read_records(&records_path)?;

    let mut type_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut principal_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for record in &records {
        *type_counts
            .entry(record.record_type.to_string())
            .or_insert(0) += 1;
        *principal_counts
            .entry(record.principal.to_string())
            .or_insert(0) += 1;
    }

    let verify_result = verify_bundle(bundle_dir);

    let mut out = String::new();
    out.push_str(&format!("Records: {}\n", records.len()));
    out.push_str("By type:\n");
    let mut types: Vec<_> = type_counts.into_iter().collect();
    types.sort_by(|a, b| a.0.cmp(&b.0));
    for (t, c) in &types {
        out.push_str(&format!("  {}: {}\n", t, c));
    }
    out.push_str("By principal:\n");
    let mut principals: Vec<_> = principal_counts.into_iter().collect();
    principals.sort_by(|a, b| a.0.cmp(&b.0));
    for (p, c) in &principals {
        out.push_str(&format!("  {}: {}\n", p, c));
    }
    if verify_result.is_ok() {
        out.push_str("Verification: PASS\n");
    } else {
        out.push_str("Verification: FAIL\n");
        for e in &verify_result.errors {
            out.push_str(&format!("  {}\n", e));
        }
    }

    Ok(out)
}
