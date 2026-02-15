use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

/// Normalize a timestamp to RFC3339 "Z" form with second precision.
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
/// Rules (AEGX_CANON_0_1):
/// - UTF-8 output
/// - Object keys sorted lexicographically
/// - No insignificant whitespace
/// - Arrays preserve order
/// - NaN/Inf forbidden (serde_json already forbids)
/// - -0.0 normalized to 0
/// - String values are NFC-normalized
/// - Timestamps in string values are NOT auto-normalized here (caller must pre-normalize)
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
            // Handle -0.0 -> 0
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
                // Control characters as \uXXXX
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_sorted_keys() {
        let val = json!({"b": 1, "a": 2});
        let out = String::from_utf8(canonical_json(&val)).unwrap();
        assert_eq!(out, r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn test_array_order_preserved() {
        let val = json!([3, 1, 2]);
        let out = String::from_utf8(canonical_json(&val)).unwrap();
        assert_eq!(out, "[3,1,2]");
    }

    #[test]
    fn test_nested_sort() {
        let val = json!({"z": {"b": 1, "a": 2}, "a": 0});
        let out = String::from_utf8(canonical_json(&val)).unwrap();
        assert_eq!(out, r#"{"a":0,"z":{"a":2,"b":1}}"#);
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
}
