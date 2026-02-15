use sha2::{Digest, Sha256};
use serde_json::Value;

/// Produce a canonical JSON byte representation suitable for hashing.
/// Rules:
/// - Objects: keys sorted lexicographically, no whitespace
/// - Arrays: preserve order
/// - Strings: UTF-8, no BOM
/// - Numbers: serialized as-is (serde_json default is fine)
/// - Null: literal "null"
/// - No trailing newline
pub fn canonicalize(value: &Value) -> Vec<u8> {
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
            let s = n.to_string();
            buf.extend_from_slice(s.as_bytes());
        }
        Value::String(s) => {
            buf.push(b'"');
            for ch in s.chars() {
                match ch {
                    '"' => buf.extend_from_slice(b"\\\""),
                    '\\' => buf.extend_from_slice(b"\\\\"),
                    '\n' => buf.extend_from_slice(b"\\n"),
                    '\r' => buf.extend_from_slice(b"\\r"),
                    '\t' => buf.extend_from_slice(b"\\t"),
                    c if (c as u32) < 0x20 => {
                        let escaped = format!("\\u{:04x}", c as u32);
                        buf.extend_from_slice(escaped.as_bytes());
                    }
                    c => {
                        let mut tmp = [0u8; 4];
                        buf.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes());
                    }
                }
            }
            buf.push(b'"');
        }
        Value::Array(arr) => {
            buf.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                write_canonical(item, buf);
            }
            buf.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            buf.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                write_canonical(&Value::String((*key).clone()), buf);
                buf.push(b':');
                write_canonical(&map[*key], buf);
            }
            buf.push(b'}');
        }
    }
}

/// SHA-256 hash of arbitrary bytes, returned as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// SHA-256 hash of a file's contents.
pub fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    let data = std::fs::read(path)?;
    Ok(sha256_hex(&data))
}

/// Compute the record ID: sha256(canonical(payload) || canonical(meta)).
pub fn compute_record_id(payload: &Value, meta: &Value) -> String {
    let cp = canonicalize(payload);
    let cm = canonicalize(meta);
    let mut combined = cp;
    combined.extend_from_slice(&cm);
    sha256_hex(&combined)
}

/// Compute an audit chain entry hash: sha256(idx || ts || record_id || prev_hash).
pub fn compute_entry_hash(idx: u64, ts: &str, record_id: &str, prev_hash: &str) -> String {
    let input = format!("{idx}||{ts}||{record_id}||{prev_hash}");
    sha256_hex(input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonicalize_sorted_keys() {
        let val = json!({"z": 1, "a": 2, "m": 3});
        let canon = canonicalize(&val);
        let s = String::from_utf8(canon).unwrap();
        assert_eq!(s, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_canonicalize_nested() {
        let val = json!({"b": {"d": 1, "c": 2}, "a": [3, 2, 1]});
        let canon = canonicalize(&val);
        let s = String::from_utf8(canon).unwrap();
        assert_eq!(s, r#"{"a":[3,2,1],"b":{"c":2,"d":1}}"#);
    }

    #[test]
    fn test_canonicalize_stability() {
        let val = json!({"type": "ToolCall", "principal": "USER", "data": {"x": 1}});
        let c1 = canonicalize(&val);
        let c2 = canonicalize(&val);
        assert_eq!(c1, c2, "Canonical form must be deterministic");
    }

    #[test]
    fn test_sha256_known_vector() {
        // SHA-256 of empty string
        let h = sha256_hex(b"");
        assert_eq!(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_record_id_deterministic() {
        let payload = json!({"tool": "read_file", "args": {"path": "/tmp/x"}});
        let meta = json!({"ts": "2025-01-01T00:00:00Z", "agent_id": "a1"});
        let id1 = compute_record_id(&payload, &meta);
        let id2 = compute_record_id(&payload, &meta);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // SHA-256 hex length
    }

    #[test]
    fn test_entry_hash_deterministic() {
        let h1 = compute_entry_hash(0, "2025-01-01T00:00:00Z", "abc", "000");
        let h2 = compute_entry_hash(0, "2025-01-01T00:00:00Z", "abc", "000");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_canonicalize_string_escaping() {
        let val = json!({"msg": "line1\nline2\ttab"});
        let canon = canonicalize(&val);
        let s = String::from_utf8(canon).unwrap();
        assert!(s.contains("\\n"));
        assert!(s.contains("\\t"));
    }
}
