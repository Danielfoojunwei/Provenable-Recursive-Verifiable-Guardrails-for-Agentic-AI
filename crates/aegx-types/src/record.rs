use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::principal::Principal;
use crate::taint::TaintFlags;

/// Record types in the AEGX evidence model.
///
/// Unified from aegx (12 variants) and aer (13 variants, includes FileRename).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecordType {
    SessionStart,
    SessionMessage,
    ToolCall,
    ToolResult,
    FileRead,
    FileWrite,
    FileDelete,
    FileRename,
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

/// Metadata attached to each record.
///
/// Uses aer's structured fields (typed DateTime, optional agent_id, etc.)
/// rather than aegx's opaque serde_json::Value, while remaining serializable
/// to the same JSON shape for bundle compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordMeta {
    pub ts: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
}

impl RecordMeta {
    pub fn now() -> Self {
        RecordMeta {
            ts: Utc::now(),
            agent_id: None,
            session_id: None,
            tool_id: None,
            path: None,
            channel: None,
            ip: None,
            config_key: None,
            rule_id: None,
            snapshot_id: None,
        }
    }
}

/// Payload: either inline (small data) or a reference to a blob stored on disk.
///
/// Uses tagged serde (aer format) with optional `mime` field from aegx for
/// blob references. The `mime` field enables content-type awareness in bundles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Payload {
    #[serde(rename = "inline")]
    Inline { data: serde_json::Value },
    #[serde(rename = "blob")]
    BlobRef {
        hash: String,
        size: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        mime: Option<String>,
    },
}

/// A single AEGX typed record — the fundamental evidence unit.
///
/// This is the unified record type used throughout the system. It uses:
/// - aer's `TaintFlags` (bitflags) for runtime efficiency
/// - aer's typed `RecordMeta` for structured access
/// - aegx's 6-field `compute_record_id` for cryptographic integrity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedRecord {
    pub record_id: String,
    pub record_type: RecordType,
    pub principal: Principal,
    pub taint: TaintFlags,
    pub parents: Vec<String>,
    pub meta: RecordMeta,
    pub payload: Payload,
}

/// Guard decision outcome (CPI/MI Theorem enforcement).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardVerdict {
    Allow,
    Deny,
}

/// Guard decision detail recorded as evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardDecisionDetail {
    pub verdict: GuardVerdict,
    pub rule_id: String,
    pub rationale: String,
    pub surface: GuardSurface,
    pub principal: Principal,
    pub taint: TaintFlags,
}

/// The surface being guarded.
///
/// Three guard surfaces corresponding to the formal theorems:
/// - ControlPlane: CPI Theorem
/// - DurableMemory: MI Theorem
/// - ConversationIO: Noninterference Theorem (input/output scanning)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GuardSurface {
    ControlPlane,
    DurableMemory,
    ConversationIO,
}

/// Snapshot manifest entry for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFileEntry {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<DateTime<Utc>>,
}

/// Snapshot manifest (RVU Theorem: point-in-time state capture).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub snapshot_id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub scope: SnapshotScope,
    pub files: Vec<SnapshotFileEntry>,
}

/// What a snapshot covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotScope {
    Full,
    ControlPlane,
    DurableMemory,
}

/// Audit log entry in the append-only hash chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub idx: u64,
    pub ts: DateTime<Utc>,
    pub record_id: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// AEGX bundle manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub bundle_id: String,
    pub created_at: DateTime<Utc>,
    pub format_version: String,
    pub record_count: u64,
    pub audit_entry_count: u64,
    pub blob_count: u64,
    pub filters: BundleFilters,
}

/// Filters used when exporting a bundle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BundleFilters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_time: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_snapshot: Option<String>,
}

/// Policy rule for guard enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub surface: GuardSurface,
    pub action: GuardVerdict,
    pub condition: PolicyCondition,
    pub description: String,
}

/// Conditions under which a policy rule applies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principals: Option<Vec<Principal>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint_any: Option<TaintFlags>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_approval: Option<bool>,
}

/// A complete policy pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPack {
    pub version: String,
    pub name: String,
    pub rules: Vec<PolicyRule>,
}

/// Verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub record_count: u64,
    pub audit_entries_checked: u64,
    pub blobs_checked: u64,
    pub errors: Vec<VerificationError>,
}

/// A specific verification error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationError {
    pub kind: VerificationErrorKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationErrorKind {
    RecordHashMismatch,
    AuditChainBreak,
    BlobHashMismatch,
    SnapshotMismatch,
    MissingBlob,
    MalformedEntry,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_display() {
        assert_eq!(RecordType::ToolCall.to_string(), "ToolCall");
        assert_eq!(RecordType::FileRename.to_string(), "FileRename");
    }

    #[test]
    fn test_record_type_from_str() {
        assert_eq!(
            "ToolCall".parse::<RecordType>().unwrap(),
            RecordType::ToolCall
        );
    }

    #[test]
    fn test_payload_serde() {
        let inline = Payload::Inline {
            data: serde_json::json!({"x": 1}),
        };
        let json = serde_json::to_string(&inline).unwrap();
        assert!(json.contains("\"kind\":\"inline\""));

        let blob = Payload::BlobRef {
            hash: "abc123".into(),
            size: 42,
            mime: Some("application/json".into()),
        };
        let json = serde_json::to_string(&blob).unwrap();
        assert!(json.contains("\"kind\":\"blob\""));
        assert!(json.contains("\"mime\""));
    }

    #[test]
    fn test_meta_now() {
        let meta = RecordMeta::now();
        assert!(meta.agent_id.is_none());
        // ts should be approximately now
        let diff = Utc::now() - meta.ts;
        assert!(diff.num_seconds() < 2);
    }
}
