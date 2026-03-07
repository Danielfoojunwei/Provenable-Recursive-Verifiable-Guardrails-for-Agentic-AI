//! Unified error types for the AEGX system.

use thiserror::Error;

/// Top-level error type for AEGX operations.
#[derive(Debug, Error)]
pub enum AegxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid timestamp: {0}")]
    Timestamp(String),

    #[error("record hash mismatch: expected {expected}, got {actual}")]
    RecordHashMismatch { expected: String, actual: String },

    #[error("audit chain break at index {idx}: {detail}")]
    AuditChainBreak { idx: u64, detail: String },

    #[error("blob not found: {hash}")]
    BlobNotFound { hash: String },

    #[error("blob hash mismatch for {hash}")]
    BlobHashMismatch { hash: String },

    #[error("bundle error: {0}")]
    Bundle(String),

    #[error("policy error: {0}")]
    Policy(String),

    #[error("guard denied: {0}")]
    GuardDenied(String),

    #[error("snapshot error: {0}")]
    Snapshot(String),

    #[error("rollback error: {0}")]
    Rollback(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("{0}")]
    Other(String),
}

impl From<String> for AegxError {
    fn from(s: String) -> Self {
        AegxError::Other(s)
    }
}

impl From<&str> for AegxError {
    fn from(s: &str) -> Self {
        AegxError::Other(s.to_string())
    }
}

/// Convenience type alias.
pub type AegxResult<T> = Result<T, AegxError>;
