use bitflags::bitflags;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Principal identity in the trust lattice.
/// Trust ordering: WEB, SKILL <= TOOL_UNAUTH <= TOOL_AUTH <= USER <= SYS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Principal {
    Sys,
    User,
    ToolAuth,
    ToolUnauth,
    Web,
    Skill,
    Channel,
    External,
}

impl Principal {
    /// Returns the trust level (higher = more trusted).
    pub fn trust_level(self) -> u8 {
        match self {
            Principal::Sys => 5,
            Principal::User => 4,
            Principal::ToolAuth => 3,
            Principal::ToolUnauth => 2,
            Principal::Web | Principal::Skill => 1,
            Principal::Channel | Principal::External => 0,
        }
    }

    /// Returns true if this principal has authority to modify control-plane state.
    pub fn can_modify_control_plane(self) -> bool {
        matches!(self, Principal::User | Principal::Sys)
    }

    /// Returns true if this principal is considered untrusted for memory writes.
    pub fn is_untrusted_for_memory(self) -> bool {
        matches!(
            self,
            Principal::Web | Principal::Skill | Principal::Channel | Principal::External
        )
    }
}

bitflags! {
    /// Taint flags for provenance tracking.
    /// Conservative propagation: any tainted dependency taints the output.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TaintFlags: u32 {
        const UNTRUSTED        = 0b0000_0001;
        const INJECTION_SUSPECT = 0b0000_0010;
        const PROXY_DERIVED    = 0b0000_0100;
        const SECRET_RISK      = 0b0000_1000;
        const CROSS_SESSION    = 0b0001_0000;
        const TOOL_OUTPUT      = 0b0010_0000;
        const SKILL_OUTPUT     = 0b0100_0000;
        const WEB_DERIVED      = 0b1000_0000;
    }
}

impl Serialize for TaintFlags {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.bits().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TaintFlags {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = u32::deserialize(deserializer)?;
        TaintFlags::from_bits(bits)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid taint flags: {bits}")))
    }
}

impl TaintFlags {
    /// Returns true if any taint bit is set.
    pub fn is_tainted(self) -> bool {
        !self.is_empty()
    }

    /// Compute the union of taint from all parent records.
    pub fn propagate(parents: &[TaintFlags]) -> TaintFlags {
        let mut result = TaintFlags::empty();
        for t in parents {
            result |= *t;
        }
        result
    }
}

/// Record types in the AEGX evidence model.
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

/// Metadata attached to each record.
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

/// Payload: either inline (small) or a reference to a blob stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Payload {
    #[serde(rename = "inline")]
    Inline { data: serde_json::Value },
    #[serde(rename = "blob")]
    BlobRef { hash: String, size: u64 },
}

/// A single AEGX typed record — the fundamental evidence unit.
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

/// Guard decision outcome.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GuardSurface {
    ControlPlane,
    DurableMemory,
    /// Conversation I/O surface — guards LLM inputs and outputs against
    /// prompt injection, system prompt extraction, and behavioral manipulation.
    ConversationIO,
}

/// Snapshot manifest entry for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFileEntry {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    /// Informational only; not trusted for verification.
    pub mtime: Option<DateTime<Utc>>,
}

/// Snapshot manifest.
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
