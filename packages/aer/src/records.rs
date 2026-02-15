use crate::canonical::{compute_record_id, sha256_hex};
use crate::config;
use crate::types::*;
use serde_json;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};

/// Maximum inline payload size in bytes before promoting to blob storage.
const INLINE_THRESHOLD: usize = 4096;

/// Create a new typed record with automatic ID computation.
pub fn create_record(
    record_type: RecordType,
    principal: Principal,
    taint: TaintFlags,
    parents: Vec<String>,
    meta: RecordMeta,
    payload_data: serde_json::Value,
) -> io::Result<TypedRecord> {
    let payload_bytes = serde_json::to_vec(&payload_data)?;
    let payload = if payload_bytes.len() > INLINE_THRESHOLD {
        let hash = sha256_hex(&payload_bytes);
        let blob_path = config::blobs_dir().join(&hash);
        fs::write(&blob_path, &payload_bytes)?;
        Payload::BlobRef {
            hash,
            size: payload_bytes.len() as u64,
        }
    } else {
        Payload::Inline { data: payload_data }
    };

    let payload_val = serde_json::to_value(&payload)?;
    let meta_val = serde_json::to_value(&meta)?;
    let record_id = compute_record_id(&payload_val, &meta_val);

    Ok(TypedRecord {
        record_id,
        record_type,
        principal,
        taint,
        parents,
        meta,
        payload,
    })
}

/// Append a record to the records JSONL file.
pub fn append_record(record: &TypedRecord) -> io::Result<()> {
    let path = config::records_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    let line = serde_json::to_string(record)?;
    writeln!(file, "{}", line)?;
    Ok(())
}

/// Read all records from the records JSONL file.
pub fn read_all_records() -> io::Result<Vec<TypedRecord>> {
    let path = config::records_file();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(&path)?;
    let reader = io::BufReader::new(file);
    let mut records = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: TypedRecord = serde_json::from_str(&line).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Bad record: {e}"))
        })?;
        records.push(record);
    }
    Ok(records)
}

/// Read records filtered by optional agent_id and/or since timestamp.
pub fn read_filtered_records(
    agent_id: Option<&str>,
    since: Option<chrono::DateTime<chrono::Utc>>,
) -> io::Result<Vec<TypedRecord>> {
    let all = read_all_records()?;
    Ok(all
        .into_iter()
        .filter(|r| {
            if let Some(aid) = agent_id {
                if r.meta.agent_id.as_deref() != Some(aid) {
                    return false;
                }
            }
            if let Some(since_ts) = since {
                if r.meta.ts < since_ts {
                    return false;
                }
            }
            true
        })
        .collect())
}

/// Resolve payload content for a record, reading from blob storage if needed.
pub fn resolve_payload(record: &TypedRecord) -> io::Result<serde_json::Value> {
    match &record.payload {
        Payload::Inline { data } => Ok(data.clone()),
        Payload::BlobRef { hash, .. } => {
            let blob_path = config::blobs_dir().join(hash);
            let data = fs::read(&blob_path)?;
            serde_json::from_slice(&data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
        }
    }
}

/// Verify that a record's ID matches its content.
pub fn verify_record_hash(record: &TypedRecord) -> bool {
    let payload_val = match serde_json::to_value(&record.payload) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let meta_val = match serde_json::to_value(&record.meta) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let expected = compute_record_id(&payload_val, &meta_val);
    expected == record.record_id
}

/// Verify a blob reference by checking its hash.
pub fn verify_blob(hash: &str) -> io::Result<bool> {
    let blob_path = config::blobs_dir().join(hash);
    if !blob_path.exists() {
        return Ok(false);
    }
    let data = fs::read(&blob_path)?;
    Ok(sha256_hex(&data) == hash)
}

/// Get total count of stored records.
pub fn record_count() -> io::Result<u64> {
    let path = config::records_file();
    if !path.exists() {
        return Ok(0);
    }
    let file = fs::File::open(&path)?;
    let reader = io::BufReader::new(file);
    Ok(reader.lines().filter_map(|l| l.ok()).filter(|l| !l.trim().is_empty()).count() as u64)
}

/// Collect all blob hashes referenced by records.
pub fn collect_blob_refs() -> io::Result<Vec<String>> {
    let records = read_all_records()?;
    let mut refs = Vec::new();
    for r in &records {
        if let Payload::BlobRef { hash, .. } = &r.payload {
            refs.push(hash.clone());
        }
    }
    Ok(refs)
}

/// List all blob files on disk.
pub fn list_blobs() -> io::Result<Vec<String>> {
    let dir = config::blobs_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut blobs = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Some(name) = entry.file_name().to_str() {
                blobs.push(name.to_string());
            }
        }
    }
    Ok(blobs)
}

/// Convenience: create a record, append it, and return it.
pub fn emit_record(
    record_type: RecordType,
    principal: Principal,
    taint: TaintFlags,
    parents: Vec<String>,
    meta: RecordMeta,
    payload_data: serde_json::Value,
) -> io::Result<TypedRecord> {
    let record = create_record(record_type, principal, taint, parents, meta, payload_data)?;
    append_record(&record)?;
    Ok(record)
}
