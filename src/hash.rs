use sha2::{Digest, Sha256};

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
