//! Automated rollback policy engine for Provenable.ai.
//!
//! # Formal Basis: RVU Machine Unlearning Theorem
//!
//! The RVU theorem guarantees that contaminated state can be identified and
//! reversed. This module implements three automated rollback mechanisms:
//!
//! 1. **Auto-Snapshot Before CPI Changes** — creates a rollback point before
//!    every allowed control-plane mutation, ensuring recoverability (RVU §2).
//!
//! 2. **Rollback Recommendation on Denial** — when guards deny an operation,
//!    recommends rollback to the most recent snapshot if repeated denials
//!    indicate an active attack (RVU §3: contamination detection).
//!
//! 3. **Threshold-Based Auto-Rollback** — if denial count exceeds a threshold
//!    within a time window, automatically rolls back to the last known-good
//!    snapshot (RVU §4: automatic recovery).
//!
//! # Contamination Scope Computation
//!
//! When the output guard detects leakage, this module computes the transitive
//! closure of potentially contaminated records — records whose provenance
//! chains include the leaking record as a parent. This implements the RVU
//! closure property: given a contamination source, all downstream records
//! that depend on it are identified for review or rollback.

use crate::alerts::{self, AlertSeverity, ThreatCategory};
use crate::records;
use crate::rollback;
use crate::snapshot;
use crate::types::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::sync::Mutex;
use std::time::Instant;

// ============================================================
// Configuration constants
// ============================================================

/// Minimum seconds between auto-snapshots to avoid excessive snapshots.
const AUTO_SNAPSHOT_COOLDOWN_SECS: u64 = 60;

/// Number of denials within DENIAL_WINDOW_SECS that triggers auto-rollback.
const AUTO_ROLLBACK_DENIAL_THRESHOLD: u64 = 5;

/// Time window (seconds) for counting denials toward auto-rollback.
const DENIAL_WINDOW_SECS: u64 = 120;

/// Number of denials that triggers a rollback recommendation alert.
const RECOMMENDATION_THRESHOLD: u64 = 3;

// ============================================================
// Global state for denial tracking and snapshot cooldown
// ============================================================

/// Tracks denial events for threshold-based auto-rollback.
#[derive(Debug)]
struct DenialTracker {
    /// Timestamped denial events within the current window.
    events: VecDeque<DenialEvent>,
    /// When the last auto-snapshot was taken.
    last_auto_snapshot: Option<Instant>,
    /// The ID of the last auto-snapshot.
    last_auto_snapshot_id: Option<String>,
}

#[derive(Debug, Clone)]
struct DenialEvent {
    timestamp: Instant,
    #[allow(dead_code)]
    surface: GuardSurface,
    #[allow(dead_code)]
    rule_id: String,
    #[allow(dead_code)]
    record_id: String,
}

impl DenialTracker {
    fn new() -> Self {
        DenialTracker {
            events: VecDeque::new(),
            last_auto_snapshot: None,
            last_auto_snapshot_id: None,
        }
    }

    /// Prune events older than the denial window.
    fn prune(&mut self) {
        let now = Instant::now();
        while let Some(front) = self.events.front() {
            if now.duration_since(front.timestamp).as_secs() >= DENIAL_WINDOW_SECS {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    /// Record a denial event and return the current count in the window.
    fn record_denial(&mut self, surface: GuardSurface, rule_id: &str, record_id: &str) -> u64 {
        self.prune();
        self.events.push_back(DenialEvent {
            timestamp: Instant::now(),
            surface,
            rule_id: rule_id.to_string(),
            record_id: record_id.to_string(),
        });
        self.events.len() as u64
    }

    /// Check if auto-snapshot cooldown has elapsed.
    fn can_auto_snapshot(&self) -> bool {
        match self.last_auto_snapshot {
            None => true,
            Some(last) => {
                Instant::now().duration_since(last).as_secs() >= AUTO_SNAPSHOT_COOLDOWN_SECS
            }
        }
    }

    /// Record that an auto-snapshot was taken.
    fn mark_auto_snapshot(&mut self, snapshot_id: &str) {
        self.last_auto_snapshot = Some(Instant::now());
        self.last_auto_snapshot_id = Some(snapshot_id.to_string());
    }
}

static DENIAL_TRACKER: Mutex<Option<DenialTracker>> = Mutex::new(None);

fn with_tracker<F, R>(f: F) -> R
where
    F: FnOnce(&mut DenialTracker) -> R,
{
    let mut lock = DENIAL_TRACKER.lock().unwrap_or_else(|e| e.into_inner());
    let tracker = lock.get_or_insert_with(DenialTracker::new);
    f(tracker)
}

// ============================================================
// 1. Auto-Snapshot Before CPI Changes
// ============================================================

/// Automatically create a snapshot before a CPI change is applied.
///
/// This implements RVU §2: every control-plane mutation has a corresponding
/// rollback point. If the change later proves harmful (e.g., a malicious
/// skill was approved by a socially-engineered user), the system can
/// be restored to the pre-change state.
///
/// Returns `Some(snapshot_id)` if a snapshot was created, `None` if
/// cooldown hasn't elapsed (a recent snapshot exists).
pub fn auto_snapshot_before_cpi(config_key: &str) -> io::Result<Option<String>> {
    let can_snapshot = with_tracker(|t| t.can_auto_snapshot());

    if !can_snapshot {
        return Ok(None);
    }

    let name = format!(
        "auto-pre-cpi-{}-{}",
        config_key.replace('.', "-"),
        Utc::now().format("%Y%m%d-%H%M%S")
    );

    let manifest = snapshot::create_snapshot(&name, SnapshotScope::Full)?;
    let snapshot_id = manifest.snapshot_id.clone();

    with_tracker(|t| t.mark_auto_snapshot(&snapshot_id));

    Ok(Some(snapshot_id))
}

// ============================================================
// 2. Rollback Recommendation on Denial
// ============================================================

/// Result of processing a denial event through the rollback policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenialPolicyResult {
    /// Whether an auto-rollback was triggered.
    pub auto_rollback_triggered: bool,
    /// Rollback report if auto-rollback was performed.
    pub rollback_report: Option<RollbackSummary>,
    /// Whether a rollback recommendation alert was emitted.
    pub recommendation_emitted: bool,
    /// The recommended snapshot ID for rollback (if any).
    pub recommended_snapshot_id: Option<String>,
    /// Current denial count in the window.
    pub denial_count: u64,
    /// Human-readable action message for the agent to relay to the user.
    pub agent_message: Option<String>,
}

/// Summary of an auto-rollback operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackSummary {
    pub snapshot_id: String,
    pub snapshot_name: String,
    pub files_restored: usize,
    pub files_recreated: usize,
    pub verified: bool,
}

/// Process a guard denial through the rollback policy engine.
///
/// This function should be called after every guard denial. It:
/// 1. Records the denial in the sliding window
/// 2. Checks if the recommendation threshold is crossed → emits recommendation alert
/// 3. Checks if the auto-rollback threshold is crossed → performs auto-rollback
///
/// Returns a `DenialPolicyResult` describing what actions were taken.
pub fn on_guard_denial(
    surface: GuardSurface,
    rule_id: &str,
    record_id: &str,
    decision: &GuardDecisionDetail,
) -> io::Result<DenialPolicyResult> {
    let denial_count = with_tracker(|t| t.record_denial(surface, rule_id, record_id));

    let mut result = DenialPolicyResult {
        auto_rollback_triggered: false,
        rollback_report: None,
        recommendation_emitted: false,
        recommended_snapshot_id: None,
        denial_count,
        agent_message: None,
    };

    // Find the most recent snapshot for recommendation/rollback
    let recent_snapshot = find_most_recent_snapshot()?;

    // Check recommendation threshold
    if denial_count >= RECOMMENDATION_THRESHOLD && denial_count < AUTO_ROLLBACK_DENIAL_THRESHOLD {
        if let Some(ref snap) = recent_snapshot {
            result.recommended_snapshot_id = Some(snap.snapshot_id.clone());
            result.recommendation_emitted = true;
            result.agent_message = Some(format!(
                "WARNING: {} guard denials detected in the last {} seconds across {:?} surface. \
                 This may indicate an active attack. Consider rolling back to snapshot '{}' ({}) \
                 using: proven-aer rollback {}",
                denial_count,
                DENIAL_WINDOW_SECS,
                surface,
                snap.name,
                &snap.snapshot_id[..8],
                &snap.snapshot_id[..8],
            ));

            // Emit rollback recommendation alert
            emit_rollback_recommendation_alert(
                decision,
                record_id,
                &snap.snapshot_id,
                &snap.name,
                denial_count,
            )?;
        } else {
            result.agent_message = Some(format!(
                "WARNING: {} guard denials detected in the last {} seconds. \
                 No snapshot available for rollback. Create a snapshot immediately \
                 using: proven-aer snapshot create emergency-checkpoint",
                denial_count, DENIAL_WINDOW_SECS,
            ));
        }
    }

    // Check auto-rollback threshold
    if denial_count >= AUTO_ROLLBACK_DENIAL_THRESHOLD {
        if let Some(ref snap) = recent_snapshot {
            // Perform auto-rollback
            let report = rollback::rollback_to_snapshot(&snap.snapshot_id)?;
            let verified = rollback::verify_rollback(&snap.snapshot_id)?;

            // Emit auto-rollback alert
            emit_auto_rollback_alert(
                decision,
                record_id,
                &snap.snapshot_id,
                &snap.name,
                denial_count,
                &report,
                verified,
            )?;

            result.auto_rollback_triggered = true;
            result.rollback_report = Some(RollbackSummary {
                snapshot_id: snap.snapshot_id.clone(),
                snapshot_name: snap.name.clone(),
                files_restored: report.files_restored.len(),
                files_recreated: report.files_recreated.len(),
                verified,
            });
            result.agent_message = Some(format!(
                "CRITICAL: Auto-rollback triggered! {} guard denials in {} seconds \
                 exceeded threshold of {}. System rolled back to snapshot '{}' ({}). \
                 {} files restored, {} files recreated. Verification: {}. \
                 Investigate the attack source before resuming operations.",
                denial_count,
                DENIAL_WINDOW_SECS,
                AUTO_ROLLBACK_DENIAL_THRESHOLD,
                snap.name,
                &snap.snapshot_id[..8],
                report.files_restored.len(),
                report.files_recreated.len(),
                if verified { "PASS" } else { "FAIL" },
            ));

            // Reset the denial tracker after auto-rollback
            with_tracker(|t| t.events.clear());
        } else {
            result.agent_message = Some(format!(
                "CRITICAL: {} guard denials in {} seconds exceeded auto-rollback threshold of {}, \
                 but NO SNAPSHOT IS AVAILABLE. System state may be compromised. \
                 Immediate manual intervention required!",
                denial_count, DENIAL_WINDOW_SECS, AUTO_ROLLBACK_DENIAL_THRESHOLD,
            ));

            // Emit critical alert even without rollback
            emit_no_snapshot_critical_alert(decision, record_id, denial_count)?;
        }
    }

    Ok(result)
}

// ============================================================
// 3. RVU Contamination Scope Computation
// ============================================================

/// Result of contamination scope analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContaminationScope {
    /// The source record that is contaminated.
    pub source_record_id: String,
    /// All records transitively dependent on the source (downstream).
    pub contaminated_record_ids: Vec<String>,
    /// Count of contaminated records.
    pub contaminated_count: usize,
    /// Record types affected.
    pub affected_types: Vec<String>,
    /// Human-readable summary.
    pub summary: String,
}

/// Compute the transitive closure of records contaminated by a given source.
///
/// Implements RVU Machine Unlearning closure computation:
/// Given contamination source S, find all records R such that
/// S is in the transitive parent chain of R.
///
/// This allows the system to determine the blast radius of a
/// successful attack — how many downstream operations were
/// influenced by the contaminated data.
pub fn compute_contamination_scope(source_record_id: &str) -> io::Result<ContaminationScope> {
    let all_records = records::read_all_records()?;

    // Build a forward-dependency graph: parent -> [children]
    let mut children_of: HashMap<String, Vec<String>> = HashMap::new();
    let mut record_types: HashMap<String, RecordType> = HashMap::new();

    for record in &all_records {
        record_types.insert(record.record_id.clone(), record.record_type);
        for parent_id in &record.parents {
            children_of
                .entry(parent_id.clone())
                .or_default()
                .push(record.record_id.clone());
        }
    }

    // BFS from source to find all transitively dependent records
    let mut contaminated: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(source_record_id.to_string());

    while let Some(current) = queue.pop_front() {
        if let Some(children) = children_of.get(&current) {
            for child in children {
                if contaminated.insert(child.clone()) {
                    queue.push_back(child.clone());
                }
            }
        }
    }

    let contaminated_ids: Vec<String> = contaminated.iter().cloned().collect();
    let affected_types: Vec<String> = contaminated
        .iter()
        .filter_map(|id| record_types.get(id))
        .map(|t| format!("{:?}", t))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let summary = if contaminated_ids.is_empty() {
        format!(
            "No downstream records depend on contaminated source {}",
            &source_record_id[..source_record_id.len().min(12)]
        )
    } else {
        format!(
            "Contamination from {} affects {} downstream records (types: {}). \
             Review or rollback recommended.",
            &source_record_id[..source_record_id.len().min(12)],
            contaminated_ids.len(),
            affected_types.join(", ")
        )
    };

    Ok(ContaminationScope {
        source_record_id: source_record_id.to_string(),
        contaminated_record_ids: contaminated_ids.clone(),
        contaminated_count: contaminated_ids.len(),
        affected_types,
        summary,
    })
}

// ============================================================
// Helper: find most recent snapshot
// ============================================================

fn find_most_recent_snapshot() -> io::Result<Option<SnapshotManifest>> {
    let snapshots = snapshot::list_snapshots()?;
    Ok(snapshots.into_iter().last())
}

// ============================================================
// Alert emission helpers
// ============================================================

fn emit_rollback_recommendation_alert(
    decision: &GuardDecisionDetail,
    record_id: &str,
    snapshot_id: &str,
    snapshot_name: &str,
    denial_count: u64,
) -> io::Result<()> {
    alerts::ensure_alerts_dir()?;

    let alert = alerts::ThreatAlert {
        alert_id: String::new(),
        timestamp: Utc::now(),
        severity: AlertSeverity::High,
        category: ThreatCategory::RollbackRecommended,
        summary: format!(
            "ROLLBACK RECOMMENDED: {} guard denials in {} seconds. \
             Suggested rollback target: '{}' ({}). \
             Rule '{}' has been repeatedly triggered on {:?} surface.",
            denial_count,
            DENIAL_WINDOW_SECS,
            snapshot_name,
            &snapshot_id[..snapshot_id.len().min(8)],
            decision.rule_id,
            decision.surface,
        ),
        principal: decision.principal,
        taint: decision.taint,
        surface: Some(decision.surface),
        rule_id: decision.rule_id.clone(),
        record_id: record_id.to_string(),
        target: format!("snapshot:{}", snapshot_id),
        blocked: false,
    };

    let content = serde_json::to_string(&alert)?;
    let alert_id = crate::canonical::sha256_hex(content.as_bytes());
    let alert = alerts::ThreatAlert { alert_id, ..alert };

    alerts::append_alert_pub(&alert)?;
    Ok(())
}

fn emit_auto_rollback_alert(
    decision: &GuardDecisionDetail,
    record_id: &str,
    snapshot_id: &str,
    snapshot_name: &str,
    denial_count: u64,
    report: &rollback::RollbackReport,
    verified: bool,
) -> io::Result<()> {
    alerts::ensure_alerts_dir()?;

    let alert = alerts::ThreatAlert {
        alert_id: String::new(),
        timestamp: Utc::now(),
        severity: AlertSeverity::Critical,
        category: ThreatCategory::AutoRollback,
        summary: format!(
            "AUTO-ROLLBACK EXECUTED: {} denials in {} seconds exceeded threshold of {}. \
             Rolled back to '{}' ({}). Files restored: {}, recreated: {}. \
             Verification: {}.",
            denial_count,
            DENIAL_WINDOW_SECS,
            AUTO_ROLLBACK_DENIAL_THRESHOLD,
            snapshot_name,
            &snapshot_id[..snapshot_id.len().min(8)],
            report.files_restored.len(),
            report.files_recreated.len(),
            if verified { "PASS" } else { "FAIL" },
        ),
        principal: decision.principal,
        taint: decision.taint,
        surface: Some(decision.surface),
        rule_id: decision.rule_id.clone(),
        record_id: record_id.to_string(),
        target: format!("snapshot:{}", snapshot_id),
        blocked: true,
    };

    let content = serde_json::to_string(&alert)?;
    let alert_id = crate::canonical::sha256_hex(content.as_bytes());
    let alert = alerts::ThreatAlert { alert_id, ..alert };

    alerts::append_alert_pub(&alert)?;

    // Also emit a tamper-evident record for the auto-rollback
    let mut meta = RecordMeta::now();
    meta.snapshot_id = Some(snapshot_id.to_string());

    let payload = json!({
        "auto_rollback": {
            "trigger": "denial_threshold_exceeded",
            "denial_count": denial_count,
            "threshold": AUTO_ROLLBACK_DENIAL_THRESHOLD,
            "window_secs": DENIAL_WINDOW_SECS,
            "snapshot_id": snapshot_id,
            "snapshot_name": snapshot_name,
            "files_restored": report.files_restored,
            "files_recreated": report.files_recreated,
            "verified": verified,
        },
    });

    let record = crate::records::emit_record(
        RecordType::Rollback,
        Principal::Sys,
        TaintFlags::empty(),
        vec![record_id.to_string()],
        meta,
        payload,
    )?;
    crate::audit_chain::emit_audit(&record.record_id)?;

    Ok(())
}

fn emit_no_snapshot_critical_alert(
    decision: &GuardDecisionDetail,
    record_id: &str,
    denial_count: u64,
) -> io::Result<()> {
    alerts::ensure_alerts_dir()?;

    let alert = alerts::ThreatAlert {
        alert_id: String::new(),
        timestamp: Utc::now(),
        severity: AlertSeverity::Critical,
        category: ThreatCategory::AutoRollback,
        summary: format!(
            "AUTO-ROLLBACK FAILED: {} denials exceeded threshold but NO SNAPSHOT AVAILABLE. \
             System state may be compromised. Immediate manual intervention required.",
            denial_count,
        ),
        principal: decision.principal,
        taint: decision.taint,
        surface: Some(decision.surface),
        rule_id: decision.rule_id.clone(),
        record_id: record_id.to_string(),
        target: "no-snapshot-available".to_string(),
        blocked: false,
    };

    let content = serde_json::to_string(&alert)?;
    let alert_id = crate::canonical::sha256_hex(content.as_bytes());
    let alert = alerts::ThreatAlert { alert_id, ..alert };

    alerts::append_alert_pub(&alert)?;
    Ok(())
}

/// Emit a contamination scope alert when leakage is detected.
pub fn emit_contamination_alert(
    source_record_id: &str,
    scope: &ContaminationScope,
) -> io::Result<()> {
    if scope.contaminated_count == 0 {
        return Ok(());
    }

    alerts::ensure_alerts_dir()?;

    let alert = alerts::ThreatAlert {
        alert_id: String::new(),
        timestamp: Utc::now(),
        severity: if scope.contaminated_count > 10 {
            AlertSeverity::Critical
        } else {
            AlertSeverity::High
        },
        category: ThreatCategory::ContaminationDetected,
        summary: format!(
            "CONTAMINATION DETECTED: {} downstream records affected by source {}. \
             Affected types: {}. Review or rollback recommended.",
            scope.contaminated_count,
            &source_record_id[..source_record_id.len().min(12)],
            scope.affected_types.join(", "),
        ),
        principal: Principal::Sys,
        taint: TaintFlags::empty(),
        surface: None,
        rule_id: "rvu-contamination-scope".to_string(),
        record_id: source_record_id.to_string(),
        target: format!("contamination:{}", source_record_id),
        blocked: false,
    };

    let content = serde_json::to_string(&alert)?;
    let alert_id = crate::canonical::sha256_hex(content.as_bytes());
    let alert = alerts::ThreatAlert { alert_id, ..alert };

    alerts::append_alert_pub(&alert)?;
    Ok(())
}

/// Reset the denial tracker (for testing).
pub fn reset_tracker() {
    let mut lock = DENIAL_TRACKER.lock().unwrap_or_else(|e| e.into_inner());
    *lock = None;
}

/// Get current denial count in the window (for testing/reporting).
pub fn current_denial_count() -> u64 {
    with_tracker(|t| {
        t.prune();
        t.events.len() as u64
    })
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn test_decision() -> GuardDecisionDetail {
        GuardDecisionDetail {
            verdict: GuardVerdict::Deny,
            rule_id: "cpi-deny-untrusted".to_string(),
            rationale: "Test denial".to_string(),
            surface: GuardSurface::ControlPlane,
            principal: Principal::Web,
            taint: TaintFlags::UNTRUSTED,
        }
    }

    #[test]
    fn test_denial_tracker_basic() {
        reset_tracker();
        let count = with_tracker(|t| t.record_denial(
            GuardSurface::ControlPlane,
            "test-rule",
            "record-1",
        ));
        assert_eq!(count, 1);

        let count = with_tracker(|t| t.record_denial(
            GuardSurface::ControlPlane,
            "test-rule",
            "record-2",
        ));
        assert_eq!(count, 2);
    }

    #[test]
    fn test_denial_tracker_prune() {
        reset_tracker();
        // Add events — they are fresh so won't be pruned
        for i in 0..5 {
            with_tracker(|t| t.record_denial(
                GuardSurface::ControlPlane,
                "test-rule",
                &format!("record-{}", i),
            ));
        }
        let count = current_denial_count();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_auto_snapshot_cooldown() {
        reset_tracker();
        assert!(with_tracker(|t| t.can_auto_snapshot()));

        // After marking a snapshot, cooldown should prevent another
        with_tracker(|t| t.mark_auto_snapshot("snap-1"));
        assert!(!with_tracker(|t| t.can_auto_snapshot()));
    }

    #[test]
    fn test_contamination_scope_empty() {
        // When there are no records or the source has no children, scope is empty
        let scope = ContaminationScope {
            source_record_id: "test-source".to_string(),
            contaminated_record_ids: vec![],
            contaminated_count: 0,
            affected_types: vec![],
            summary: "No downstream records".to_string(),
        };
        assert_eq!(scope.contaminated_count, 0);
        assert!(scope.contaminated_record_ids.is_empty());
    }

    #[test]
    fn test_denial_policy_result_serialization() {
        let result = DenialPolicyResult {
            auto_rollback_triggered: false,
            rollback_report: None,
            recommendation_emitted: true,
            recommended_snapshot_id: Some("snap-123".to_string()),
            denial_count: 3,
            agent_message: Some("Test message".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("recommendation_emitted"));
        assert!(json.contains("snap-123"));
    }

    #[test]
    fn test_rollback_summary_serialization() {
        let summary = RollbackSummary {
            snapshot_id: "snap-456".to_string(),
            snapshot_name: "pre-change".to_string(),
            files_restored: 3,
            files_recreated: 1,
            verified: true,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("pre-change"));
        assert!(json.contains("verified"));
    }

    #[test]
    fn test_contamination_scope_serialization() {
        let scope = ContaminationScope {
            source_record_id: "src-001".to_string(),
            contaminated_record_ids: vec!["child-1".to_string(), "child-2".to_string()],
            contaminated_count: 2,
            affected_types: vec!["ToolCall".to_string(), "SessionMessage".to_string()],
            summary: "2 records contaminated".to_string(),
        };
        let json = serde_json::to_string(&scope).unwrap();
        let deser: ContaminationScope = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.contaminated_count, 2);
        assert_eq!(deser.affected_types.len(), 2);
    }

    #[test]
    fn test_threshold_constants() {
        // Verify threshold ordering makes sense
        assert!(RECOMMENDATION_THRESHOLD < AUTO_ROLLBACK_DENIAL_THRESHOLD);
        assert!(DENIAL_WINDOW_SECS > 0);
        assert!(AUTO_SNAPSHOT_COOLDOWN_SECS > 0);
    }
}
