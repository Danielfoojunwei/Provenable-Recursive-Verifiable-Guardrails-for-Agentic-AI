//! Agent notification system for Provenable.ai.
//!
//! Provides a thread-safe, append-only notification store that all guard
//! surfaces, hooks, and rollback operations push messages into. The agent
//! reads these notifications via `/prove` or by calling `drain_notifications()`.
//!
//! This ensures that **no event is silent** — every guard decision, snapshot,
//! rollback, denial, and alert produces a human-readable notification that
//! the agent can relay to the user.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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
