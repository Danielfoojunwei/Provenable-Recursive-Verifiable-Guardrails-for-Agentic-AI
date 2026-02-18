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
