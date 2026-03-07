//! Canonical JSON and cryptographic hashing for AEGX.
//!
//! Implements AEGX_CANON_0_1:
//! - UTF-8 output, no BOM
//! - Object keys sorted lexicographically
//! - No insignificant whitespace
//! - Arrays preserve order
//! - NaN/Inf forbidden (serde_json already enforces)
//! - -0.0 normalized to 0
//! - String values are NFC-normalized (Unicode Normalization Form C)
//! - Timestamps must be pre-normalized by caller
//!
//! This is the merged superset of aegx's full-featured canonicalization
//! (NFC + -0.0 handling) and aer's simpler version. The aegx version
//! is authoritative for bundle interoperability.

use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

// ---- Hashing utilities ----

/// Compute SHA-256 hash of bytes, returning raw 32-byte array.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute SHA-256 hash of bytes, returning lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256_bytes(data))
}

/// SHA-256 hash of a file's contents.
pub fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    let data = std::fs::read(path)?;
    Ok(sha256_hex(&data))
}

// ---- Canonicalization ----

/// Normalize a timestamp to RFC3339 "Z" form with second precision.
///
/// Accepts formats like "2026-02-15T00:00:00Z", "2026-02-15T00:00:00+00:00", etc.
/// Returns normalized form: "2026-02-15T00:00:00Z"
pub fn normalize_timestamp(ts: &str) -> Result<String, String> {
    let dt = chrono::DateTime::parse_from_rfc3339(ts)
        .map_err(|e| format!("invalid RFC3339 timestamp '{}': {}", ts, e))?;
    let utc = dt.with_timezone(&chrono::Utc);
    Ok(utc.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Normalize a string to Unicode NFC form.
pub fn nfc_normalize(s: &str) -> String {
    s.nfc().collect::<String>()
}

/// Produce deterministic canonical JSON bytes from a serde_json::Value.
///
/// Implements AEGX_CANON_0_1 with NFC normalization and -0.0 handling.
pub fn canonical_json(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    write_canonical(value, &mut buf);
    buf
}

fn write_canonical(value: &Value, buf: &mut Vec<u8>) {
    match value {
        Value::Null => buf.extend_from_slice(b"null"),
        Value::Bool(b) => {
            if *b {
                buf.extend_from_slice(b"true");
            } else {
                buf.extend_from_slice(b"false");
            }
        }
        Value::Number(n) => {
            // Handle -0.0 -> 0 (AEGX_CANON_0_1 requirement)
            if let Some(f) = n.as_f64() {
                if f == 0.0 && f.is_sign_negative() {
                    buf.extend_from_slice(b"0");
                    return;
                }
            }
            let s = n.to_string();
            buf.extend_from_slice(s.as_bytes());
        }
        Value::String(s) => {
            let normalized = nfc_normalize(s);
            write_json_string(&normalized, buf);
        }
        Value::Array(arr) => {
            buf.push(b'[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                write_canonical(v, buf);
            }
            buf.push(b']');
        }
        Value::Object(map) => {
            buf.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                let normalized_key = nfc_normalize(k);
                write_json_string(&normalized_key, buf);
                buf.push(b':');
                write_canonical(&map[*k], buf);
            }
            buf.push(b'}');
        }
    }
}

fn write_json_string(s: &str, buf: &mut Vec<u8>) {
    buf.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => buf.extend_from_slice(b"\\\""),
            '\\' => buf.extend_from_slice(b"\\\\"),
            '\n' => buf.extend_from_slice(b"\\n"),
            '\r' => buf.extend_from_slice(b"\\r"),
            '\t' => buf.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                let hex = format!("\\u{:04x}", c as u32);
                buf.extend_from_slice(hex.as_bytes());
            }
            c => {
                let mut b = [0u8; 4];
                let encoded = c.encode_utf8(&mut b);
                buf.extend_from_slice(encoded.as_bytes());
            }
        }
    }
    buf.push(b'"');
}

/// Normalize the meta object: normalize meta.ts timestamp if present.
///
/// Used by `compute_record_id` to ensure timestamp-invariant record IDs.
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

/// Compute the record ID using aegx's 6-field canonical hash.
///
/// This is the authoritative record ID computation that includes all
/// content-bearing fields: type, principal, taint, parents, meta, payload.
///
/// Uses `sha256(canonical_json({type, principal, taint, parents, meta, payload, schema}))`.
pub fn compute_record_id(
    record_type: &Value,
    principal: &Value,
    taint: &Value,
    parents: &Value,
    meta: &Value,
    payload: &Value,
) -> String {
    let meta_normalized = normalize_meta(meta);
    let obj = serde_json::json!({
        "type": record_type,
        "principal": principal,
        "taint": taint,
        "parents": parents,
        "meta": meta_normalized,
        "payload": payload,
        "schema": "0.1"
    });
    let canon = canonical_json(&obj);
    sha256_hex(&canon)
}

/// Compute an audit chain entry hash.
///
/// Uses aegx's canonical JSON approach: `sha256(canonical_json({idx, ts, recordId, prev}))`.
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_sorted_keys() {
        let val = json!({"z": 1, "a": 2, "m": 3});
        let out = String::from_utf8(canonical_json(&val)).unwrap();
        assert_eq!(out, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_nested_sort() {
        let val = json!({"b": {"d": 1, "c": 2}, "a": [3, 2, 1]});
        let out = String::from_utf8(canonical_json(&val)).unwrap();
        assert_eq!(out, r#"{"a":[3,2,1],"b":{"c":2,"d":1}}"#);
    }

    #[test]
    fn test_array_order_preserved() {
        let val = json!([3, 1, 2]);
        let out = String::from_utf8(canonical_json(&val)).unwrap();
        assert_eq!(out, "[3,1,2]");
    }

    #[test]
    fn test_stability() {
        let val = json!({"type": "ToolCall", "principal": "USER", "data": {"x": 1}});
        let c1 = canonical_json(&val);
        let c2 = canonical_json(&val);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_string_escaping() {
        let val = json!({"msg": "line1\nline2\ttab"});
        let out = String::from_utf8(canonical_json(&val)).unwrap();
        assert!(out.contains("\\n"));
        assert!(out.contains("\\t"));
    }

    #[test]
    fn test_sha256_known_vector() {
        let h = sha256_hex(b"");
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_normalize_timestamp() {
        assert_eq!(
            normalize_timestamp("2026-02-15T00:00:00+00:00").unwrap(),
            "2026-02-15T00:00:00Z"
        );
        assert_eq!(
            normalize_timestamp("2026-02-15T00:00:00Z").unwrap(),
            "2026-02-15T00:00:00Z"
        );
    }

    #[test]
    fn test_record_id_deterministic() {
        let rt = json!("ToolCall");
        let p = json!("USER");
        let t = json!([]);
        let parents = json!([]);
        let meta = json!({"ts": "2025-01-01T00:00:00Z"});
        let payload = json!({"inline": {"x": 1}});
        let id1 = compute_record_id(&rt, &p, &t, &parents, &meta, &payload);
        let id2 = compute_record_id(&rt, &p, &t, &parents, &meta, &payload);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64);
    }

    #[test]
    fn test_entry_hash_deterministic() {
        let h1 = compute_entry_hash(0, "2025-01-01T00:00:00Z", "abc", "000");
        let h2 = compute_entry_hash(0, "2025-01-01T00:00:00Z", "abc", "000");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_normalize_meta() {
        let meta = json!({"ts": "2026-02-15T00:00:00+00:00", "agent_id": "a1"});
        let normalized = normalize_meta(&meta);
        assert_eq!(
            normalized["ts"].as_str().unwrap(),
            "2026-02-15T00:00:00Z"
        );
        assert_eq!(normalized["agent_id"].as_str().unwrap(), "a1");
    }
}
