use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, Write};
use std::path::Path;

use crate::canonical::{canonical_json, normalize_timestamp, sha256_hex};

/// Record type enum for AEGX v0.1
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecordType {
    SessionStart,
    SessionMessage,
    ToolCall,
    ToolResult,
    FileRead,
    FileWrite,
    FileDelete,
    ControlPlaneChangeRequest,
    MemoryCommitRequest,
    GuardDecision,
    Snapshot,
    Rollback,
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self).unwrap();
        write!(f, "{}", s.as_str().unwrap())
    }
}

impl std::str::FromStr for RecordType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let quoted = format!("\"{}\"", s);
        serde_json::from_str(&quoted).map_err(|_| format!("unknown record type: {}", s))
    }
}

/// Principal enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Principal {
    USER,
    SYS,
    WEB,
    TOOL,
    SKILL,
    CHANNEL,
    EXTERNAL,
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self).unwrap();
        write!(f, "{}", s.as_str().unwrap())
    }
}

impl std::str::FromStr for Principal {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let quoted = format!("\"{}\"", s);
        serde_json::from_str(&quoted).map_err(|_| format!("unknown principal: {}", s))
    }
}

/// Payload variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Payload {
    Inline {
        inline: Value,
    },
    Blob {
        blob: String,
        mime: String,
        size: u64,
    },
}

/// A TypedRecord as stored in records.jsonl
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypedRecord {
    pub record_id: String,
    #[serde(rename = "type")]
    pub record_type: RecordType,
    pub principal: Principal,
    pub taint: Vec<String>,
    pub parents: Vec<String>,
    pub meta: Value,
    pub payload: Payload,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

/// Compute the recordId from the record's fields.
pub fn compute_record_id(
    record_type: &RecordType,
    principal: &Principal,
    taint: &[String],
    parents: &[String],
    meta: &Value,
    payload: &Payload,
) -> String {
    let type_val = serde_json::to_value(record_type).unwrap();
    let principal_val = serde_json::to_value(principal).unwrap();
    let taint_val = serde_json::to_value(taint).unwrap();
    let parents_val = serde_json::to_value(parents).unwrap();

    // Normalize meta.ts
    let meta_normalized = normalize_meta(meta);

    let payload_val = match payload {
        Payload::Inline { inline } => {
            serde_json::json!({"inline": inline})
        }
        Payload::Blob { blob, mime, size } => {
            serde_json::json!({"blob": blob, "mime": mime, "size": size})
        }
    };

    let obj = serde_json::json!({
        "type": type_val,
        "principal": principal_val,
        "taint": taint_val,
        "parents": parents_val,
        "meta": meta_normalized,
        "payload": payload_val,
        "schema": "0.1"
    });

    let canon = canonical_json(&obj);
    sha256_hex(&canon)
}

/// Normalize the meta object: normalize meta.ts timestamp if present.
pub fn normalize_meta(meta: &Value) -> Value {
    let mut m = meta.clone();
    if let Some(obj) = m.as_object_mut() {
        if let Some(ts) = obj.get("ts").and_then(|v| v.as_str()) {
            if let Ok(normalized) = normalize_timestamp(ts) {
                obj.insert("ts".to_string(), Value::String(normalized));
            }
        }
    }
    m
}

/// Read records from a JSONL file.
pub fn read_records(path: &Path) -> Result<Vec<TypedRecord>, String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {}", path.display(), e))?;
    let reader = std::io::BufReader::new(file);
    let mut records = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("read error at line {}: {}", i + 1, e))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let record: TypedRecord = serde_json::from_str(trimmed)
            .map_err(|e| format!("parse error at line {}: {}", i + 1, e))?;
        records.push(record);
    }
    Ok(records)
}

/// Append a record as a JSON line to records.jsonl
pub fn append_record(path: &Path, record: &TypedRecord) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("cannot open {}: {}", path.display(), e))?;
    let json = serde_json::to_string(record).map_err(|e| format!("serialize error: {}", e))?;
    writeln!(file, "{}", json).map_err(|e| format!("write error: {}", e))?;
    Ok(())
}
