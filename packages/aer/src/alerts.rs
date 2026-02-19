//! Threat alert system for Provenable.ai.
//!
//! Emits structured alerts when CPI/MI guards block threats, providing
//! a feedback loop for OpenClaw hosts and users to understand protection value.

use crate::config;
use crate::types::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

/// Alert severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    /// Informational — no threat, just tracking.
    Info,
    /// Medium — suspicious activity detected.
    Medium,
    /// High — threat blocked by guard.
    High,
    /// Critical — active attack pattern detected (e.g. repeated CPI bypass attempts).
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "INFO"),
            AlertSeverity::Medium => write!(f, "MEDIUM"),
            AlertSeverity::High => write!(f, "HIGH"),
            AlertSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Category of threat that was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCategory {
    /// Control-Plane Integrity violation attempt.
    CpiViolation,
    /// Memory Integrity violation attempt.
    MiViolation,
    /// Taint-based block (untrusted data propagation).
    TaintBlock,
    /// Proxy misconfiguration detected.
    ProxyMisconfig,
    /// Rate limit exceeded (possible log flooding).
    RateLimitExceeded,
    /// Injection attempt suspected.
    InjectionSuspect,
    /// System prompt extraction attempt blocked.
    PromptExtraction,
    /// System prompt leakage detected in output.
    PromptLeakage,
    /// Rollback recommended due to repeated denials.
    RollbackRecommended,
    /// Auto-rollback triggered by denial threshold.
    AutoRollback,
    /// RVU contamination scope detected — downstream records affected.
    ContaminationDetected,
}

impl std::fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatCategory::CpiViolation => write!(f, "CPI_VIOLATION"),
            ThreatCategory::MiViolation => write!(f, "MI_VIOLATION"),
            ThreatCategory::TaintBlock => write!(f, "TAINT_BLOCK"),
            ThreatCategory::ProxyMisconfig => write!(f, "PROXY_MISCONFIG"),
            ThreatCategory::RateLimitExceeded => write!(f, "RATE_LIMIT_EXCEEDED"),
            ThreatCategory::InjectionSuspect => write!(f, "INJECTION_SUSPECT"),
            ThreatCategory::PromptExtraction => write!(f, "PROMPT_EXTRACTION"),
            ThreatCategory::PromptLeakage => write!(f, "PROMPT_LEAKAGE"),
            ThreatCategory::RollbackRecommended => write!(f, "ROLLBACK_RECOMMENDED"),
            ThreatCategory::AutoRollback => write!(f, "AUTO_ROLLBACK"),
            ThreatCategory::ContaminationDetected => write!(f, "CONTAMINATION_DETECTED"),
        }
    }
}

/// A structured threat alert emitted when Provenable.ai blocks or detects a threat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    /// Unique alert ID (SHA-256 of alert content).
    pub alert_id: String,
    /// When the alert was emitted.
    pub timestamp: DateTime<Utc>,
    /// Severity level.
    pub severity: AlertSeverity,
    /// Category of threat.
    pub category: ThreatCategory,
    /// Human-readable summary of what happened.
    pub summary: String,
    /// The principal that triggered the alert.
    pub principal: Principal,
    /// Taint flags present at the time.
    pub taint: TaintFlags,
    /// Guard surface involved (if applicable).
    pub surface: Option<GuardSurface>,
    /// The policy rule that fired.
    pub rule_id: String,
    /// The record ID of the guard decision that generated this alert.
    pub record_id: String,
    /// Target of the blocked action (e.g. config key, file path).
    pub target: String,
    /// Whether the threat was blocked (true) or just detected/warned (false).
    pub blocked: bool,
}

/// Path to the alerts JSONL file.
pub fn alerts_file() -> PathBuf {
    config::aer_root().join("alerts").join("alerts.jsonl")
}

/// Ensure alerts directory exists.
pub fn ensure_alerts_dir() -> io::Result<()> {
    let dir = config::aer_root().join("alerts");
    fs::create_dir_all(dir)
}

/// Emit a threat alert from a guard decision.
pub fn emit_alert(
    category: ThreatCategory,
    decision: &GuardDecisionDetail,
    record_id: &str,
    target: &str,
) -> io::Result<ThreatAlert> {
    ensure_alerts_dir()?;

    let severity = classify_severity(category, decision);
    let summary = format_summary(category, decision, target);

    let alert = ThreatAlert {
        alert_id: String::new(), // computed below
        timestamp: Utc::now(),
        severity,
        category,
        summary,
        principal: decision.principal,
        taint: decision.taint,
        surface: Some(decision.surface),
        rule_id: decision.rule_id.clone(),
        record_id: record_id.to_string(),
        target: target.to_string(),
        blocked: decision.verdict == GuardVerdict::Deny,
    };

    // Compute alert_id from content
    let content = serde_json::to_string(&alert)?;
    let alert_id = crate::canonical::sha256_hex(content.as_bytes());

    let alert = ThreatAlert { alert_id, ..alert };

    append_alert(&alert)?;
    Ok(alert)
}

/// Emit a proxy misconfiguration alert.
pub fn emit_proxy_alert(
    proxies: &[String],
    gateway_addr: &str,
    record_id: &str,
) -> io::Result<ThreatAlert> {
    ensure_alerts_dir()?;

    let alert = ThreatAlert {
        alert_id: String::new(),
        timestamp: Utc::now(),
        severity: AlertSeverity::High,
        category: ThreatCategory::ProxyMisconfig,
        summary: format!(
            "Overly permissive trustedProxies detected: {:?}. \
             An attacker can spoof IP addresses via X-Forwarded-For headers.",
            proxies
        ),
        principal: Principal::Sys,
        taint: TaintFlags::PROXY_DERIVED,
        surface: None,
        rule_id: "proxy-trust-check".to_string(),
        record_id: record_id.to_string(),
        target: format!("gateway.trustedProxies @ {}", gateway_addr),
        blocked: false,
    };

    let content = serde_json::to_string(&alert)?;
    let alert_id = crate::canonical::sha256_hex(content.as_bytes());
    let alert = ThreatAlert { alert_id, ..alert };

    append_alert(&alert)?;
    Ok(alert)
}

/// Append an alert to the alerts JSONL file (public for rollback_policy).
pub fn append_alert_pub(alert: &ThreatAlert) -> io::Result<()> {
    append_alert(alert)
}

/// Append an alert to the alerts JSONL file.
fn append_alert(alert: &ThreatAlert) -> io::Result<()> {
    let path = alerts_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    let line = serde_json::to_string(alert)?;
    writeln!(file, "{}", line)?;
    Ok(())
}

/// Read all alerts from the alerts file.
pub fn read_all_alerts() -> io::Result<Vec<ThreatAlert>> {
    let path = alerts_file();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(&path)?;
    let reader = io::BufReader::new(file);
    let mut alerts = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let alert: ThreatAlert = serde_json::from_str(&line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Bad alert: {e}")))?;
        alerts.push(alert);
    }
    Ok(alerts)
}

/// Read alerts filtered by time range and optional category.
pub fn read_filtered_alerts(
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    category: Option<ThreatCategory>,
    severity_min: Option<AlertSeverity>,
) -> io::Result<Vec<ThreatAlert>> {
    let all = read_all_alerts()?;
    Ok(all
        .into_iter()
        .filter(|a| {
            if let Some(s) = since {
                if a.timestamp < s {
                    return false;
                }
            }
            if let Some(u) = until {
                if a.timestamp > u {
                    return false;
                }
            }
            if let Some(cat) = category {
                if a.category != cat {
                    return false;
                }
            }
            if let Some(min_sev) = severity_min {
                if a.severity < min_sev {
                    return false;
                }
            }
            true
        })
        .collect())
}

/// Get count of alerts.
pub fn alert_count() -> io::Result<u64> {
    let path = alerts_file();
    if !path.exists() {
        return Ok(0);
    }
    let file = fs::File::open(&path)?;
    let reader = io::BufReader::new(file);
    Ok(reader
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .count() as u64)
}

/// Classify severity based on threat category and context.
fn classify_severity(category: ThreatCategory, decision: &GuardDecisionDetail) -> AlertSeverity {
    match category {
        ThreatCategory::CpiViolation => {
            if decision.taint.contains(TaintFlags::INJECTION_SUSPECT)
                || decision.principal.trust_level() == 0
            {
                AlertSeverity::Critical
            } else {
                AlertSeverity::High
            }
        }
        ThreatCategory::MiViolation => {
            if decision.taint.contains(TaintFlags::INJECTION_SUSPECT) {
                AlertSeverity::Critical
            } else {
                AlertSeverity::High
            }
        }
        ThreatCategory::TaintBlock => AlertSeverity::Medium,
        ThreatCategory::ProxyMisconfig => AlertSeverity::High,
        ThreatCategory::RateLimitExceeded => AlertSeverity::Critical,
        ThreatCategory::InjectionSuspect => AlertSeverity::Critical,
        ThreatCategory::PromptExtraction => AlertSeverity::Critical,
        ThreatCategory::PromptLeakage => AlertSeverity::Critical,
        ThreatCategory::RollbackRecommended => AlertSeverity::High,
        ThreatCategory::AutoRollback => AlertSeverity::Critical,
        ThreatCategory::ContaminationDetected => AlertSeverity::Critical,
    }
}

/// Format a human-readable alert summary.
fn format_summary(
    category: ThreatCategory,
    decision: &GuardDecisionDetail,
    target: &str,
) -> String {
    match category {
        ThreatCategory::CpiViolation => format!(
            "BLOCKED: {:?} principal attempted control-plane modification on '{}'. \
             Rule '{}' denied the request. {}",
            decision.principal, target, decision.rule_id, decision.rationale
        ),
        ThreatCategory::MiViolation => format!(
            "BLOCKED: {:?} principal attempted memory write to '{}'. \
             Rule '{}' denied the request. {}",
            decision.principal, target, decision.rule_id, decision.rationale
        ),
        ThreatCategory::TaintBlock => format!(
            "BLOCKED: Tainted data (flags: {:?}) attempted to reach '{}'. \
             Rule '{}' denied the request.",
            decision.taint, target, decision.rule_id
        ),
        ThreatCategory::ProxyMisconfig => format!(
            "WARNING: Proxy trust misconfiguration detected at '{}'.",
            target
        ),
        ThreatCategory::RateLimitExceeded => format!(
            "CRITICAL: Denial rate limit exceeded — possible log flooding attack targeting '{}'.",
            target
        ),
        ThreatCategory::InjectionSuspect => format!(
            "CRITICAL: Injection attempt suspected from {:?} targeting '{}'. \
             Taint flags: {:?}.",
            decision.principal, target, decision.taint
        ),
        ThreatCategory::PromptExtraction => format!(
            "CRITICAL: System prompt extraction attempt blocked from {:?} targeting '{}'. \
             Taint flags: {:?}.",
            decision.principal, target, decision.taint
        ),
        ThreatCategory::PromptLeakage => format!(
            "CRITICAL: System prompt leakage detected in outbound response for '{}'. \
             Rule '{}' blocked the response.",
            target, decision.rule_id
        ),
        ThreatCategory::RollbackRecommended => format!(
            "ROLLBACK RECOMMENDED: Repeated denials on {:?} surface targeting '{}'. \
             Consider rolling back to a known-good snapshot.",
            decision.surface, target
        ),
        ThreatCategory::AutoRollback => format!(
            "AUTO-ROLLBACK: Denial threshold exceeded. System automatically \
             rolled back targeting '{}'. Rule '{}' triggered the rollback.",
            target, decision.rule_id
        ),
        ThreatCategory::ContaminationDetected => format!(
            "CONTAMINATION: Downstream records affected by compromised source '{}'. \
             RVU closure computation identified affected records for review.",
            target
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_decision(verdict: GuardVerdict, surface: GuardSurface) -> GuardDecisionDetail {
        GuardDecisionDetail {
            verdict,
            rule_id: "test-rule".to_string(),
            rationale: "Test rationale".to_string(),
            surface,
            principal: Principal::Web,
            taint: TaintFlags::UNTRUSTED,
        }
    }

    #[test]
    fn test_classify_severity_cpi_injection() {
        let mut decision = make_decision(GuardVerdict::Deny, GuardSurface::ControlPlane);
        decision.taint = TaintFlags::INJECTION_SUSPECT;
        assert_eq!(
            classify_severity(ThreatCategory::CpiViolation, &decision),
            AlertSeverity::Critical
        );
    }

    #[test]
    fn test_classify_severity_cpi_external() {
        let mut decision = make_decision(GuardVerdict::Deny, GuardSurface::ControlPlane);
        decision.principal = Principal::External;
        assert_eq!(
            classify_severity(ThreatCategory::CpiViolation, &decision),
            AlertSeverity::Critical
        );
    }

    #[test]
    fn test_classify_severity_mi_web() {
        let mut decision = make_decision(GuardVerdict::Deny, GuardSurface::DurableMemory);
        decision.taint = TaintFlags::WEB_DERIVED;
        assert_eq!(
            classify_severity(ThreatCategory::MiViolation, &decision),
            AlertSeverity::High
        );
    }

    #[test]
    fn test_format_summary_cpi() {
        let decision = make_decision(GuardVerdict::Deny, GuardSurface::ControlPlane);
        let summary = format_summary(ThreatCategory::CpiViolation, &decision, "skills.install");
        assert!(summary.contains("BLOCKED"));
        assert!(summary.contains("skills.install"));
        assert!(summary.contains("test-rule"));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(AlertSeverity::Info < AlertSeverity::Medium);
        assert!(AlertSeverity::Medium < AlertSeverity::High);
        assert!(AlertSeverity::High < AlertSeverity::Critical);
    }
}

// ============================================================
// Agent notification system (merged from agent_notifications.rs)
// ============================================================

use std::collections::VecDeque;
use std::sync::Mutex;

/// Maximum notifications retained in-memory before oldest are dropped.
const MAX_NOTIFICATIONS: usize = 200;

/// Severity levels for agent notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NotificationLevel {
    /// Informational — routine operation.
    Info,
    /// Warning — something unusual but not blocking.
    Warning,
    /// Error — operation failed or was denied.
    Error,
    /// Critical — immediate user attention required.
    Critical,
}

impl std::fmt::Display for NotificationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotificationLevel::Info => write!(f, "INFO"),
            NotificationLevel::Warning => write!(f, "WARN"),
            NotificationLevel::Error => write!(f, "ERROR"),
            NotificationLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Source of the notification — which subsystem generated it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationSource {
    /// CPI guard decision.
    CpiGuard,
    /// MI guard decision.
    MiGuard,
    /// ConversationIO guard (input scanner or output guard).
    ConversationGuard,
    /// Snapshot/rollback system.
    SnapshotRollback,
    /// Rollback policy engine (threshold tracking, auto-rollback).
    RollbackPolicy,
    /// Skill verifier (ClawHavoc defense).
    SkillVerifier,
    /// Proxy trust checker.
    ProxyChecker,
    /// System (audit chain, record emission, etc.).
    System,
}

impl std::fmt::Display for NotificationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotificationSource::CpiGuard => write!(f, "CPI"),
            NotificationSource::MiGuard => write!(f, "MI"),
            NotificationSource::ConversationGuard => write!(f, "CIO"),
            NotificationSource::SnapshotRollback => write!(f, "SNAPSHOT"),
            NotificationSource::RollbackPolicy => write!(f, "ROLLBACK"),
            NotificationSource::SkillVerifier => write!(f, "SKILL"),
            NotificationSource::ProxyChecker => write!(f, "PROXY"),
            NotificationSource::System => write!(f, "SYS"),
        }
    }
}

/// A notification that the agent MUST relay to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentNotification {
    /// When this notification was created.
    pub timestamp: DateTime<Utc>,
    /// Severity level.
    pub level: NotificationLevel,
    /// Which subsystem generated this notification.
    pub source: NotificationSource,
    /// Human-readable summary for the user.
    pub message: String,
    /// Optional: the record ID associated with this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    /// Optional: suggested action the user should take.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_action: Option<String>,
}

/// Global notification store.
static NOTIFICATIONS: Mutex<Option<VecDeque<AgentNotification>>> = Mutex::new(None);

fn with_store<F, R>(f: F) -> R
where
    F: FnOnce(&mut VecDeque<AgentNotification>) -> R,
{
    let mut lock = NOTIFICATIONS.lock().unwrap_or_else(|e| e.into_inner());
    let store = lock.get_or_insert_with(VecDeque::new);
    f(store)
}

/// Push a notification into the store.
pub fn notify(
    level: NotificationLevel,
    source: NotificationSource,
    message: impl Into<String>,
    record_id: Option<&str>,
    suggested_action: Option<&str>,
) {
    let notification = AgentNotification {
        timestamp: Utc::now(),
        level,
        source,
        message: message.into(),
        record_id: record_id.map(|s| s.to_string()),
        suggested_action: suggested_action.map(|s| s.to_string()),
    };
    with_store(|store| {
        store.push_back(notification);
        // Evict oldest if over capacity
        while store.len() > MAX_NOTIFICATIONS {
            store.pop_front();
        }
    });
}

/// Drain all notifications from the store.
pub fn drain_notifications() -> Vec<AgentNotification> {
    with_store(|store| store.drain(..).collect())
}

/// Read all notifications without draining (peek).
pub fn peek_notifications() -> Vec<AgentNotification> {
    with_store(|store| store.iter().cloned().collect())
}

/// Get count of pending notifications.
pub fn notification_count() -> usize {
    with_store(|store| store.len())
}

/// Get only notifications at or above a given level.
pub fn notifications_at_level(min_level: NotificationLevel) -> Vec<AgentNotification> {
    with_store(|store| {
        store
            .iter()
            .filter(|n| n.level >= min_level)
            .cloned()
            .collect()
    })
}

/// Reset notifications (for testing).
pub fn reset_notifications() {
    let mut lock = NOTIFICATIONS.lock().unwrap_or_else(|e| e.into_inner());
    *lock = None;
}

// ============================================================
// Convenience helpers for common notification patterns
// ============================================================

/// Notify: CPI change allowed.
pub fn notify_cpi_allowed(config_key: &str, principal: &str, snapshot_id: Option<&str>) {
    let snap_msg = match snapshot_id {
        Some(id) => format!(" Pre-change snapshot: {}.", &id[..id.len().min(12)]),
        None => " No pre-change snapshot (cooldown active).".to_string(),
    };
    notify(
        NotificationLevel::Info,
        NotificationSource::CpiGuard,
        format!(
            "Control-plane change '{}' ALLOWED for {} principal.{}",
            config_key, principal, snap_msg
        ),
        None,
        None,
    );
}

/// Notify: CPI change denied.
pub fn notify_cpi_denied(config_key: &str, principal: &str, rule_id: &str, record_id: &str) {
    notify(
        NotificationLevel::Error,
        NotificationSource::CpiGuard,
        format!(
            "Control-plane change '{}' DENIED for {} principal. Rule: {}.",
            config_key, principal, rule_id
        ),
        Some(record_id),
        Some("Only USER or SYS principals can modify the control plane. Check the request source."),
    );
}

/// Notify: MI write allowed.
pub fn notify_mi_write_allowed(file_path: &str, principal: &str) {
    notify(
        NotificationLevel::Info,
        NotificationSource::MiGuard,
        format!(
            "Memory write to '{}' ALLOWED for {} principal.",
            file_path, principal
        ),
        None,
        None,
    );
}

/// Notify: MI write denied.
pub fn notify_mi_write_denied(file_path: &str, principal: &str, rule_id: &str, record_id: &str) {
    notify(
        NotificationLevel::Error,
        NotificationSource::MiGuard,
        format!(
            "Memory write to '{}' DENIED for {} principal. Rule: {}.",
            file_path, principal, rule_id
        ),
        Some(record_id),
        Some("Untrusted or tainted data cannot modify protected memory files."),
    );
}

/// Notify: conversation input blocked.
pub fn notify_input_blocked(principal: &str, rule_id: &str, record_id: &str) {
    notify(
        NotificationLevel::Warning,
        NotificationSource::ConversationGuard,
        format!(
            "Inbound message from {} principal BLOCKED. Rule: {}. Possible injection attempt detected.",
            principal, rule_id
        ),
        Some(record_id),
        Some("Review the message content for injection patterns."),
    );
}

/// Notify: output leakage blocked.
pub fn notify_output_blocked(leaked_count: usize, structural_count: usize, record_id: &str) {
    notify(
        NotificationLevel::Critical,
        NotificationSource::ConversationGuard,
        format!(
            "Outbound response BLOCKED — system prompt leakage detected. \
             {} leaked tokens, {} structural patterns found.",
            leaked_count, structural_count
        ),
        Some(record_id),
        Some("The response contained internal tokens or prompt structure. It was not sent."),
    );
}

/// Notify: auto-snapshot created.
pub fn notify_auto_snapshot(config_key: &str, snapshot_id: &str) {
    notify(
        NotificationLevel::Info,
        NotificationSource::SnapshotRollback,
        format!(
            "Auto-snapshot created before CPI change '{}'. Snapshot: {}.",
            config_key,
            &snapshot_id[..snapshot_id.len().min(12)]
        ),
        None,
        None,
    );
}

/// Notify: auto-snapshot failed.
pub fn notify_auto_snapshot_failed(config_key: &str, error: &str) {
    notify(
        NotificationLevel::Warning,
        NotificationSource::SnapshotRollback,
        format!(
            "Auto-snapshot FAILED before CPI change '{}': {}. \
             CPI change will proceed without rollback safety net.",
            config_key, error
        ),
        None,
        Some("Create a manual snapshot with: proven-aer snapshot create emergency-checkpoint"),
    );
}

/// Notify: skill verification result.
pub fn notify_skill_verdict(
    skill_name: &str,
    verdict: &str,
    findings_count: usize,
    record_id: &str,
) {
    let (level, action) = match verdict {
        "deny" => (
            NotificationLevel::Error,
            Some("This skill has been blocked due to security findings. Do not install it."),
        ),
        "require_approval" => (
            NotificationLevel::Warning,
            Some("This skill has security findings. Review findings before approving installation."),
        ),
        _ => (NotificationLevel::Info, None),
    };

    notify(
        level,
        NotificationSource::SkillVerifier,
        format!(
            "Skill '{}' verification: {}. {} security findings detected.",
            skill_name,
            verdict.to_uppercase(),
            findings_count
        ),
        Some(record_id),
        action,
    );
}

/// Notify: proxy misconfiguration.
pub fn notify_proxy_misconfig(proxies: &[String], gateway_addr: &str) {
    notify(
        NotificationLevel::Warning,
        NotificationSource::ProxyChecker,
        format!(
            "Overly permissive trustedProxies detected: {:?} at {}. \
             Attackers can spoof IP addresses via X-Forwarded-For headers.",
            proxies, gateway_addr
        ),
        None,
        Some("Restrict trustedProxies to specific reverse proxy IPs."),
    );
}

/// Notify: rollback policy result.
pub fn notify_denial_policy(result: &crate::rollback_policy::DenialPolicyResult) {
    if let Some(msg) = &result.agent_message {
        let level = if result.auto_rollback_triggered {
            NotificationLevel::Critical
        } else if result.recommendation_emitted {
            NotificationLevel::Warning
        } else {
            return; // No notification needed for low denial counts
        };

        let action = if result.auto_rollback_triggered {
            Some("Investigate the attack source before resuming operations.")
        } else if result.recommended_snapshot_id.is_some() {
            None // Action embedded in the message
        } else {
            None
        };

        notify(
            level,
            NotificationSource::RollbackPolicy,
            msg.clone(),
            None,
            action,
        );
    }
}

// ============================================================
// Agent notification tests
// ============================================================

#[cfg(test)]
mod notification_tests {
    use super::*;

    /// Serialize tests that share the global NOTIFICATIONS singleton.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_notify_and_drain() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_notifications();
        notify(
            NotificationLevel::Info,
            NotificationSource::System,
            "Test notification",
            None,
            None,
        );
        assert_eq!(notification_count(), 1);

        let notifications = drain_notifications();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].message, "Test notification");

        // After drain, store should be empty
        assert_eq!(notification_count(), 0);
    }

    #[test]
    fn test_peek_does_not_drain() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_notifications();
        notify(
            NotificationLevel::Warning,
            NotificationSource::CpiGuard,
            "CPI warning",
            Some("record-123"),
            Some("Do something"),
        );
        let peeked = peek_notifications();
        assert_eq!(peeked.len(), 1);
        assert_eq!(notification_count(), 1); // Still there
    }

    #[test]
    fn test_max_capacity() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_notifications();
        for i in 0..MAX_NOTIFICATIONS + 50 {
            notify(
                NotificationLevel::Info,
                NotificationSource::System,
                format!("Notification {}", i),
                None,
                None,
            );
        }
        assert_eq!(notification_count(), MAX_NOTIFICATIONS);
        // First notification should be dropped, last should remain
        let all = peek_notifications();
        assert!(all.last().unwrap().message.contains(&format!("{}", MAX_NOTIFICATIONS + 49)));
    }

    #[test]
    fn test_level_filtering() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_notifications();
        notify(NotificationLevel::Info, NotificationSource::System, "info", None, None);
        notify(NotificationLevel::Warning, NotificationSource::System, "warn", None, None);
        notify(NotificationLevel::Error, NotificationSource::System, "err", None, None);
        notify(NotificationLevel::Critical, NotificationSource::System, "crit", None, None);

        let high = notifications_at_level(NotificationLevel::Error);
        assert_eq!(high.len(), 2); // Error + Critical
        assert!(high.iter().all(|n| n.level >= NotificationLevel::Error));
    }

    #[test]
    fn test_notification_serialization() {
        let n = AgentNotification {
            timestamp: Utc::now(),
            level: NotificationLevel::Warning,
            source: NotificationSource::MiGuard,
            message: "Test".to_string(),
            record_id: Some("abc123".to_string()),
            suggested_action: Some("Do X".to_string()),
        };
        let json = serde_json::to_string(&n).unwrap();
        let deser: AgentNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.message, "Test");
        assert_eq!(deser.level, NotificationLevel::Warning);
        assert_eq!(deser.source, NotificationSource::MiGuard);
    }

    #[test]
    fn test_convenience_cpi_allowed() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_notifications();
        notify_cpi_allowed("skills.install", "User", Some("snap-123456789012"));
        let all = peek_notifications();
        assert_eq!(all.len(), 1);
        assert!(all[0].message.contains("ALLOWED"));
        assert!(all[0].message.contains("skills.install"));
    }

    #[test]
    fn test_convenience_cpi_denied() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_notifications();
        notify_cpi_denied("skills.install", "Web", "cpi-deny-untrusted", "record-1");
        let all = peek_notifications();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].level, NotificationLevel::Error);
        assert!(all[0].message.contains("DENIED"));
        assert!(all[0].suggested_action.is_some());
    }

    #[test]
    fn test_convenience_output_blocked() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_notifications();
        notify_output_blocked(3, 2, "record-leak-1");
        let all = peek_notifications();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].level, NotificationLevel::Critical);
        assert!(all[0].message.contains("3 leaked tokens"));
    }

    #[test]
    fn test_display_formats() {
        assert_eq!(format!("{}", NotificationLevel::Critical), "CRITICAL");
        assert_eq!(format!("{}", NotificationSource::CpiGuard), "CPI");
        assert_eq!(format!("{}", NotificationSource::SkillVerifier), "SKILL");
    }
}
