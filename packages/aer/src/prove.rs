//! The `/prove` query engine for Provenable.ai.
//!
//! Provides a queryable interface for OpenClaw bots and users to inspect
//! what Provenable.ai has protected, with structured responses showing
//! threat alerts, guard performance, and system health.

use crate::alerts::{self, AlertSeverity, ThreatAlert, ThreatCategory};
use crate::audit_chain;
use crate::records;
use crate::types::*;
use crate::verify;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Query parameters for the `/prove` command.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProveQuery {
    /// Time range start (inclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<DateTime<Utc>>,
    /// Time range end (inclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<DateTime<Utc>>,
    /// Filter by threat category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<ThreatCategory>,
    /// Minimum severity to include.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity_min: Option<AlertSeverity>,
    /// Maximum number of alerts to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// Include performance metrics.
    #[serde(default = "default_true")]
    pub include_metrics: bool,
    /// Include system health check.
    #[serde(default = "default_true")]
    pub include_health: bool,
}

fn default_true() -> bool {
    true
}

/// Response from the `/prove` query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveResponse {
    /// Provenable.ai version.
    pub version: String,
    /// When this response was generated.
    pub generated_at: DateTime<Utc>,
    /// Protection summary.
    pub protection: ProtectionSummary,
    /// Recent threat alerts (filtered by query).
    pub alerts: Vec<ThreatAlert>,
    /// Guard performance metrics (if requested).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<GuardMetrics>,
    /// System health (if requested).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<SystemHealth>,
    /// Rollback status — active recommendations or auto-rollback history.
    /// The agent MUST relay these messages to the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_status: Option<RollbackStatus>,
    /// Pending agent notifications — messages the agent MUST relay to the user.
    /// These are drained on read; subsequent queries will not include them.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub agent_notifications: Vec<crate::alerts::AgentNotification>,
}

/// Summary of what Provenable.ai has protected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionSummary {
    /// Total threats blocked since records began.
    pub total_threats_blocked: u64,
    /// Total CPI violations blocked.
    pub cpi_violations_blocked: u64,
    /// Total MI violations blocked.
    pub mi_violations_blocked: u64,
    /// Total conversation I/O threats blocked (injection + leakage).
    pub conversation_threats_blocked: u64,
    /// Total taint-based blocks.
    pub taint_blocks: u64,
    /// Total proxy misconfigurations detected.
    pub proxy_misconfigs_detected: u64,
    /// Total auto-rollbacks executed.
    pub auto_rollbacks: u64,
    /// Total rollback recommendations issued.
    pub rollback_recommendations: u64,
    /// Total contamination events detected.
    pub contamination_events: u64,
    /// Total skill verifications performed.
    pub skills_verified: u64,
    /// Critical alerts count.
    pub critical_alerts: u64,
    /// High alerts count.
    pub high_alerts: u64,
    /// Medium alerts count.
    pub medium_alerts: u64,
    /// Breakdown by threat category.
    pub by_category: HashMap<String, u64>,
    /// Breakdown by principal.
    pub by_principal: HashMap<String, u64>,
    /// Total guard evaluations (allow + deny).
    pub total_evaluations: u64,
    /// Overall protection rate (denials / total evaluations).
    pub protection_rate: f64,
}

/// System health check results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    /// Whether AER is initialized.
    pub aer_initialized: bool,
    /// Audit chain integrity status.
    pub audit_chain_valid: bool,
    /// Total records in evidence store.
    pub record_count: u64,
    /// Total audit chain entries.
    pub audit_entries: u64,
    /// Total alerts emitted.
    pub alert_count: u64,
    /// State directory path.
    pub state_dir: String,
    /// Any health warnings.
    pub warnings: Vec<String>,
}

/// Rollback status information for the agent to relay to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackStatus {
    /// Number of auto-rollbacks that have occurred.
    pub auto_rollbacks_performed: u64,
    /// Number of rollback recommendations issued.
    pub rollback_recommendations: u64,
    /// Number of contamination scopes detected.
    pub contamination_events: u64,
    /// Current denial count in the active window.
    pub active_denial_count: u64,
    /// Human-readable messages the agent MUST tell the user.
    pub agent_messages: Vec<String>,
}

/// Execute a `/prove` query and return the response.
pub fn execute_query(query: &ProveQuery) -> io::Result<ProveResponse> {
    let all_alerts =
        alerts::read_filtered_alerts(query.since, query.until, query.category, query.severity_min)?;

    let mut alerts_result = all_alerts;
    if let Some(limit) = query.limit {
        // Return the most recent alerts up to the limit
        let start = alerts_result.len().saturating_sub(limit);
        alerts_result = alerts_result[start..].to_vec();
    }

    let protection = compute_protection_summary()?;

    let metrics_data = if query.include_metrics {
        Some(get_metrics())
    } else {
        None
    };

    let health = if query.include_health {
        Some(compute_health()?)
    } else {
        None
    };

    let rollback_status = compute_rollback_status(&alerts_result);

    // Drain pending agent notifications
    let agent_notifications = crate::alerts::drain_notifications();

    Ok(ProveResponse {
        version: "0.1.5".to_string(),
        generated_at: Utc::now(),
        protection,
        alerts: alerts_result,
        metrics: metrics_data,
        health,
        rollback_status,
        agent_notifications,
    })
}

/// Compute the protection summary from all stored alerts.
fn compute_protection_summary() -> io::Result<ProtectionSummary> {
    let all_alerts = alerts::read_all_alerts()?;

    let mut total_blocked = 0u64;
    let mut cpi_blocked = 0u64;
    let mut mi_blocked = 0u64;
    let mut taint_blocks = 0u64;
    let mut proxy_misconfigs = 0u64;
    let mut conversation_blocked = 0u64;
    let mut auto_rollbacks = 0u64;
    let mut rollback_recs = 0u64;
    let mut contamination_events = 0u64;
    let mut critical = 0u64;
    let mut high = 0u64;
    let mut medium = 0u64;
    let mut by_category: HashMap<String, u64> = HashMap::new();
    let mut by_principal: HashMap<String, u64> = HashMap::new();

    for alert in &all_alerts {
        if alert.blocked {
            total_blocked += 1;
        }

        match alert.category {
            ThreatCategory::CpiViolation => {
                if alert.blocked {
                    cpi_blocked += 1;
                }
            }
            ThreatCategory::MiViolation => {
                if alert.blocked {
                    mi_blocked += 1;
                }
            }
            ThreatCategory::TaintBlock => taint_blocks += 1,
            ThreatCategory::ProxyMisconfig => proxy_misconfigs += 1,
            ThreatCategory::PromptExtraction | ThreatCategory::PromptLeakage => {
                if alert.blocked {
                    conversation_blocked += 1;
                }
            }
            ThreatCategory::AutoRollback => auto_rollbacks += 1,
            ThreatCategory::RollbackRecommended => rollback_recs += 1,
            ThreatCategory::ContaminationDetected => contamination_events += 1,
            _ => {}
        }

        match alert.severity {
            AlertSeverity::Critical => critical += 1,
            AlertSeverity::High => high += 1,
            AlertSeverity::Medium => medium += 1,
            AlertSeverity::Info => {}
        }

        *by_category
            .entry(format!("{}", alert.category))
            .or_insert(0) += 1;
        *by_principal
            .entry(format!("{:?}", alert.principal))
            .or_insert(0) += 1;
    }

    // Get total evaluations from records (guard decisions)
    let all_records = records::read_all_records()?;
    let total_evaluations = all_records
        .iter()
        .filter(|r| r.record_type == RecordType::GuardDecision)
        .count() as u64;

    let protection_rate = if total_evaluations > 0 {
        total_blocked as f64 / total_evaluations as f64
    } else {
        0.0
    };

    // Count skill verifications from records
    let skills_verified = all_records
        .iter()
        .filter(|r| {
            if r.record_type != RecordType::GuardDecision {
                return false;
            }
            r.meta.config_key.as_deref() == Some("skills.install")
        })
        .count() as u64;

    Ok(ProtectionSummary {
        total_threats_blocked: total_blocked,
        cpi_violations_blocked: cpi_blocked,
        mi_violations_blocked: mi_blocked,
        conversation_threats_blocked: conversation_blocked,
        taint_blocks,
        proxy_misconfigs_detected: proxy_misconfigs,
        auto_rollbacks,
        rollback_recommendations: rollback_recs,
        contamination_events,
        skills_verified,
        critical_alerts: critical,
        high_alerts: high,
        medium_alerts: medium,
        by_category,
        by_principal,
        total_evaluations,
        protection_rate,
    })
}

/// Compute system health.
fn compute_health() -> io::Result<SystemHealth> {
    let aer_root = crate::config::aer_root();
    let aer_initialized = aer_root.exists();

    let mut warnings = Vec::new();

    let record_count = if aer_initialized {
        records::record_count()?
    } else {
        warnings.push("AER is not initialized. Run `proven-aer init`.".to_string());
        0
    };

    let entries = if aer_initialized {
        audit_chain::read_all_entries()?
    } else {
        Vec::new()
    };

    let audit_chain_valid = if !entries.is_empty() {
        match audit_chain::verify_chain()? {
            Ok(_) => true,
            Err(e) => {
                warnings.push(format!("Audit chain integrity failure: {e}"));
                false
            }
        }
    } else {
        true // Empty chain is valid
    };

    // Run live verification if initialized
    if aer_initialized && record_count > 0 {
        let vr = verify::verify_live()?;
        if !vr.valid {
            for err in &vr.errors {
                warnings.push(format!(
                    "Verification error: {:?} — {}",
                    err.kind, err.detail
                ));
            }
        }
    }

    let alert_count = alerts::alert_count()?;

    Ok(SystemHealth {
        aer_initialized,
        audit_chain_valid,
        record_count,
        audit_entries: entries.len() as u64,
        alert_count,
        state_dir: crate::config::resolve_state_dir().display().to_string(),
        warnings,
    })
}

/// Compute rollback status from alerts.
fn compute_rollback_status(alerts: &[ThreatAlert]) -> Option<RollbackStatus> {
    let auto_rollbacks = alerts
        .iter()
        .filter(|a| a.category == ThreatCategory::AutoRollback)
        .count() as u64;
    let recommendations = alerts
        .iter()
        .filter(|a| a.category == ThreatCategory::RollbackRecommended)
        .count() as u64;
    let contamination = alerts
        .iter()
        .filter(|a| a.category == ThreatCategory::ContaminationDetected)
        .count() as u64;

    let active_denials = crate::rollback_policy::current_denial_count();

    // Collect agent messages from recent rollback/contamination alerts
    let mut messages = Vec::new();
    for alert in alerts.iter().rev().take(10) {
        match alert.category {
            ThreatCategory::AutoRollback
            | ThreatCategory::RollbackRecommended
            | ThreatCategory::ContaminationDetected => {
                messages.push(alert.summary.clone());
            }
            _ => {}
        }
    }

    if auto_rollbacks == 0 && recommendations == 0 && contamination == 0 && active_denials == 0 {
        return None;
    }

    Some(RollbackStatus {
        auto_rollbacks_performed: auto_rollbacks,
        rollback_recommendations: recommendations,
        contamination_events: contamination,
        active_denial_count: active_denials,
        agent_messages: messages,
    })
}

/// Format a ProveResponse as a human-readable string for CLI output.
pub fn format_prove_response(response: &ProveResponse) -> String {
    let mut out = String::new();

    out.push_str("╔══════════════════════════════════════════════════════════════╗\n");
    out.push_str("║           Provenable.ai — Protection Report                ║\n");
    out.push_str("╚══════════════════════════════════════════════════════════════╝\n\n");

    // Protection Summary
    let p = &response.protection;
    out.push_str("── Protection Summary ──────────────────────────────────────────\n\n");
    out.push_str(&format!(
        "  Threats Blocked:         {}\n",
        p.total_threats_blocked
    ));
    out.push_str(&format!(
        "  CPI Violations Blocked:  {}\n",
        p.cpi_violations_blocked
    ));
    out.push_str(&format!(
        "  MI Violations Blocked:   {}\n",
        p.mi_violations_blocked
    ));
    out.push_str(&format!(
        "  Conversation Blocked:    {}\n",
        p.conversation_threats_blocked
    ));
    out.push_str(&format!("  Taint Blocks:            {}\n", p.taint_blocks));
    out.push_str(&format!(
        "  Proxy Misconfigs:        {}\n",
        p.proxy_misconfigs_detected
    ));
    out.push_str(&format!("  Auto-Rollbacks:          {}\n", p.auto_rollbacks));
    out.push_str(&format!(
        "  Rollback Recs:           {}\n",
        p.rollback_recommendations
    ));
    out.push_str(&format!(
        "  Contamination Events:    {}\n",
        p.contamination_events
    ));
    out.push_str(&format!("  Skills Verified:         {}\n", p.skills_verified));
    out.push_str(&format!(
        "  Protection Rate:         {:.1}%\n",
        p.protection_rate * 100.0
    ));
    out.push_str(&format!(
        "  Total Evaluations:       {}\n",
        p.total_evaluations
    ));

    // Severity Breakdown
    out.push_str(&format!(
        "\n  CRITICAL: {}  |  HIGH: {}  |  MEDIUM: {}\n",
        p.critical_alerts, p.high_alerts, p.medium_alerts
    ));

    // Metrics
    if let Some(m) = &response.metrics {
        out.push_str("\n── Guard Performance ───────────────────────────────────────────\n\n");
        out.push_str(&format!("  Evaluations/sec:  {:.1}\n", m.evals_per_sec));
        out.push_str(&format!("  Avg Latency:      {} μs\n", m.avg_eval_us));
        out.push_str(&format!("  P50 Latency:      {} μs\n", m.p50_eval_us));
        out.push_str(&format!("  P95 Latency:      {} μs\n", m.p95_eval_us));
        out.push_str(&format!("  P99 Latency:      {} μs\n", m.p99_eval_us));
        out.push_str(&format!("  Max Latency:      {} μs\n", m.max_eval_us));
        out.push_str(&format!("  Uptime:           {}s\n", m.uptime_secs));
    }

    // Health
    if let Some(h) = &response.health {
        out.push_str("\n── System Health ───────────────────────────────────────────────\n\n");
        out.push_str(&format!(
            "  AER Initialized:   {}\n",
            if h.aer_initialized { "YES" } else { "NO" }
        ));
        out.push_str(&format!(
            "  Audit Chain:       {}\n",
            if h.audit_chain_valid {
                "VALID"
            } else {
                "BROKEN"
            }
        ));
        out.push_str(&format!("  Records:           {}\n", h.record_count));
        out.push_str(&format!("  Audit Entries:     {}\n", h.audit_entries));
        out.push_str(&format!("  Alerts Emitted:    {}\n", h.alert_count));
        out.push_str(&format!("  State Dir:         {}\n", h.state_dir));

        if !h.warnings.is_empty() {
            out.push_str("\n  Warnings:\n");
            for w in &h.warnings {
                out.push_str(&format!("    ! {}\n", w));
            }
        }
    }

    // Rollback Status
    if let Some(rs) = &response.rollback_status {
        out.push_str("\n── Rollback & Recovery ─────────────────────────────────────────\n\n");
        out.push_str(&format!("  Auto-Rollbacks:          {}\n", rs.auto_rollbacks_performed));
        out.push_str(&format!("  Recommendations:         {}\n", rs.rollback_recommendations));
        out.push_str(&format!("  Contamination Events:    {}\n", rs.contamination_events));
        out.push_str(&format!("  Active Denial Count:     {}\n", rs.active_denial_count));

        if !rs.agent_messages.is_empty() {
            out.push_str("\n  ACTION REQUIRED:\n");
            for msg in &rs.agent_messages {
                out.push_str(&format!("    >> {}\n", msg));
            }
        }
    }

    // Recent Alerts
    if !response.alerts.is_empty() {
        out.push_str("\n── Recent Alerts ──────────────────────────────────────────────\n\n");
        for alert in response.alerts.iter().rev().take(20) {
            let icon = match alert.severity {
                AlertSeverity::Critical => "[!!]",
                AlertSeverity::High => "[! ]",
                AlertSeverity::Medium => "[. ]",
                AlertSeverity::Info => "[  ]",
            };
            out.push_str(&format!(
                "  {} {} {} — {}\n",
                icon,
                alert.timestamp.format("%Y-%m-%d %H:%M:%S"),
                alert.severity,
                alert.summary,
            ));
        }
    } else {
        out.push_str("\n── Recent Alerts ──────────────────────────────────────────────\n\n");
        out.push_str("  No alerts in the selected time range.\n");
    }

    // Agent Notifications
    if !response.agent_notifications.is_empty() {
        out.push_str("\n── Agent Notifications ─────────────────────────────────────────\n\n");
        for n in &response.agent_notifications {
            let icon = match n.level {
                crate::alerts::NotificationLevel::Critical => "[!!]",
                crate::alerts::NotificationLevel::Error => "[! ]",
                crate::alerts::NotificationLevel::Warning => "[. ]",
                crate::alerts::NotificationLevel::Info => "[  ]",
            };
            out.push_str(&format!(
                "  {} [{}] {} — {}\n",
                icon,
                n.source,
                n.level,
                n.message,
            ));
            if let Some(action) = &n.suggested_action {
                out.push_str(&format!("       Action: {}\n", action));
            }
        }
    }

    out.push_str("\n───────────────────────────────────────────────────────────────\n");
    out.push_str(&format!(
        "  Report generated: {}\n",
        response.generated_at.to_rfc3339()
    ));
    out.push_str(&format!("  Provenable.ai v{}\n", response.version));

    out
}

/// Format a ProveResponse as JSON for API consumption.
pub fn format_prove_json(response: &ProveResponse) -> io::Result<String> {
    serde_json::to_string_pretty(response)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

// ============================================================
// Performance metrics (merged from metrics.rs)
// ============================================================

/// Global metrics collector.
static METRICS: Mutex<Option<MetricsCollector>> = Mutex::new(None);

/// Individual guard evaluation timing record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardEvaluation {
    pub timestamp: DateTime<Utc>,
    pub surface: GuardSurface,
    pub verdict: GuardVerdict,
    pub duration_us: u64,
}

/// Accumulated metrics for the guard pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardMetrics {
    pub total_evaluations: u64,
    pub cpi_evaluations: u64,
    pub mi_evaluations: u64,
    pub total_denials: u64,
    pub total_allows: u64,
    pub cpi_denials: u64,
    pub mi_denials: u64,
    pub cio_evaluations: u64,
    pub cio_denials: u64,
    pub avg_eval_us: u64,
    pub p50_eval_us: u64,
    pub p95_eval_us: u64,
    pub p99_eval_us: u64,
    pub max_eval_us: u64,
    pub min_eval_us: u64,
    pub evals_per_sec: f64,
    pub started_at: DateTime<Utc>,
    pub snapshot_at: DateTime<Utc>,
    pub uptime_secs: u64,
}

/// Internal metrics collector state.
struct MetricsCollector {
    started: Instant,
    started_at: DateTime<Utc>,
    evaluations: Vec<GuardEvaluation>,
    total_evaluations: u64,
    cpi_evaluations: u64,
    mi_evaluations: u64,
    total_denials: u64,
    total_allows: u64,
    cpi_denials: u64,
    mi_denials: u64,
    cio_evaluations: u64,
    cio_denials: u64,
    recent_durations: Vec<u64>,
}

impl MetricsCollector {
    fn new() -> Self {
        MetricsCollector {
            started: Instant::now(),
            started_at: Utc::now(),
            evaluations: Vec::new(),
            total_evaluations: 0,
            cpi_evaluations: 0,
            mi_evaluations: 0,
            total_denials: 0,
            total_allows: 0,
            cpi_denials: 0,
            mi_denials: 0,
            cio_evaluations: 0,
            cio_denials: 0,
            recent_durations: Vec::with_capacity(10_000),
        }
    }

    fn record(&mut self, surface: GuardSurface, verdict: GuardVerdict, duration: Duration) {
        let duration_us = duration.as_micros() as u64;

        self.total_evaluations += 1;
        match surface {
            GuardSurface::ControlPlane => {
                self.cpi_evaluations += 1;
                if verdict == GuardVerdict::Deny {
                    self.cpi_denials += 1;
                }
            }
            GuardSurface::DurableMemory => {
                self.mi_evaluations += 1;
                if verdict == GuardVerdict::Deny {
                    self.mi_denials += 1;
                }
            }
            GuardSurface::ConversationIO => {
                self.cio_evaluations += 1;
                if verdict == GuardVerdict::Deny {
                    self.cio_denials += 1;
                }
            }
        }

        match verdict {
            GuardVerdict::Allow => self.total_allows += 1,
            GuardVerdict::Deny => self.total_denials += 1,
        }

        if self.recent_durations.len() >= 10_000 {
            self.recent_durations.remove(0);
        }
        self.recent_durations.push(duration_us);

        let eval = GuardEvaluation {
            timestamp: Utc::now(),
            surface,
            verdict,
            duration_us,
        };
        if self.evaluations.len() >= 1000 {
            self.evaluations.remove(0);
        }
        self.evaluations.push(eval);
    }

    fn snapshot(&self) -> GuardMetrics {
        let now = Instant::now();
        let uptime = now.duration_since(self.started);

        let (avg, p50, p95, p99, min_val, max_val) = if self.recent_durations.is_empty() {
            (0, 0, 0, 0, 0, 0)
        } else {
            let mut sorted = self.recent_durations.clone();
            sorted.sort_unstable();
            let len = sorted.len();
            let avg = sorted.iter().sum::<u64>() / len as u64;
            let p50 = sorted[len / 2];
            let p95 = sorted[(len as f64 * 0.95) as usize];
            let p99 = sorted[std::cmp::min((len as f64 * 0.99) as usize, len - 1)];
            let min_val = sorted[0];
            let max_val = sorted[len - 1];
            (avg, p50, p95, p99, min_val, max_val)
        };

        let uptime_secs = uptime.as_secs().max(1);
        let evals_per_sec = self.total_evaluations as f64 / uptime_secs as f64;

        GuardMetrics {
            total_evaluations: self.total_evaluations,
            cpi_evaluations: self.cpi_evaluations,
            mi_evaluations: self.mi_evaluations,
            total_denials: self.total_denials,
            total_allows: self.total_allows,
            cpi_denials: self.cpi_denials,
            mi_denials: self.mi_denials,
            cio_evaluations: self.cio_evaluations,
            cio_denials: self.cio_denials,
            avg_eval_us: avg,
            p50_eval_us: p50,
            p95_eval_us: p95,
            p99_eval_us: p99,
            max_eval_us: max_val,
            min_eval_us: min_val,
            evals_per_sec,
            started_at: self.started_at,
            snapshot_at: Utc::now(),
            uptime_secs,
        }
    }

    fn recent_evaluations(&self, limit: usize) -> Vec<GuardEvaluation> {
        let start = self.evaluations.len().saturating_sub(limit);
        self.evaluations[start..].to_vec()
    }
}

/// Record a guard evaluation with its timing.
pub fn record_evaluation(surface: GuardSurface, verdict: GuardVerdict, duration: Duration) {
    let mut lock = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    let collector = lock.get_or_insert_with(MetricsCollector::new);
    collector.record(surface, verdict, duration);
}

/// Get a snapshot of current guard metrics.
pub fn get_metrics() -> GuardMetrics {
    let lock = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    match lock.as_ref() {
        Some(collector) => collector.snapshot(),
        None => GuardMetrics {
            total_evaluations: 0,
            cpi_evaluations: 0,
            mi_evaluations: 0,
            total_denials: 0,
            total_allows: 0,
            cpi_denials: 0,
            mi_denials: 0,
            cio_evaluations: 0,
            cio_denials: 0,
            avg_eval_us: 0,
            p50_eval_us: 0,
            p95_eval_us: 0,
            p99_eval_us: 0,
            max_eval_us: 0,
            min_eval_us: 0,
            evals_per_sec: 0.0,
            started_at: Utc::now(),
            snapshot_at: Utc::now(),
            uptime_secs: 0,
        },
    }
}

/// Get recent guard evaluations for detailed inspection.
pub fn get_recent_evaluations(limit: usize) -> Vec<GuardEvaluation> {
    let lock = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    match lock.as_ref() {
        Some(collector) => collector.recent_evaluations(limit),
        None => Vec::new(),
    }
}

/// Reset all metrics (primarily for testing).
pub fn reset_metrics() {
    let mut lock = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    *lock = Some(MetricsCollector::new());
}

/// A timing guard that records the evaluation duration on drop.
pub struct EvalTimer {
    start: Instant,
    surface: GuardSurface,
    verdict: Option<GuardVerdict>,
}

impl EvalTimer {
    /// Start timing a guard evaluation.
    pub fn start(surface: GuardSurface) -> Self {
        EvalTimer {
            start: Instant::now(),
            surface,
            verdict: None,
        }
    }

    /// Record the verdict and stop timing.
    pub fn finish(mut self, verdict: GuardVerdict) {
        self.verdict = Some(verdict);
        let duration = self.start.elapsed();
        record_evaluation(self.surface, verdict, duration);
    }
}

impl Drop for EvalTimer {
    fn drop(&mut self) {
        if self.verdict.is_none() {
            let duration = self.start.elapsed();
            record_evaluation(self.surface, GuardVerdict::Deny, duration);
        }
    }
}

#[cfg(test)]
mod metrics_tests {
    use super::*;

    static METRICS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_metrics_recording() {
        let _lock = METRICS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_metrics();

        record_evaluation(
            GuardSurface::ControlPlane,
            GuardVerdict::Deny,
            Duration::from_micros(100),
        );
        record_evaluation(
            GuardSurface::DurableMemory,
            GuardVerdict::Allow,
            Duration::from_micros(50),
        );
        record_evaluation(
            GuardSurface::ControlPlane,
            GuardVerdict::Allow,
            Duration::from_micros(75),
        );

        let m = get_metrics();
        assert_eq!(m.total_evaluations, 3);
        assert_eq!(m.cpi_evaluations, 2);
        assert_eq!(m.mi_evaluations, 1);
        assert_eq!(m.total_denials, 1);
        assert_eq!(m.total_allows, 2);
        assert_eq!(m.cpi_denials, 1);
        assert_eq!(m.mi_denials, 0);
    }

    #[test]
    fn test_percentiles() {
        let _lock = METRICS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_metrics();

        for i in 1..=100 {
            record_evaluation(
                GuardSurface::ControlPlane,
                GuardVerdict::Allow,
                Duration::from_micros(i),
            );
        }

        let m = get_metrics();
        assert_eq!(m.total_evaluations, 100);
        assert!(m.p50_eval_us > 0);
        assert!(m.p95_eval_us >= m.p50_eval_us);
        assert!(m.p99_eval_us >= m.p95_eval_us);
        assert_eq!(m.min_eval_us, 1);
        assert_eq!(m.max_eval_us, 100);
    }

    #[test]
    fn test_eval_timer() {
        let _lock = METRICS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_metrics();

        let timer = EvalTimer::start(GuardSurface::ControlPlane);
        std::thread::sleep(Duration::from_micros(10));
        timer.finish(GuardVerdict::Deny);

        let m = get_metrics();
        assert_eq!(m.total_evaluations, 1);
        assert_eq!(m.total_denials, 1);
        assert!(m.avg_eval_us >= 10);
    }

    #[test]
    fn test_recent_evaluations() {
        let _lock = METRICS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_metrics();

        for _ in 0..5 {
            record_evaluation(
                GuardSurface::ControlPlane,
                GuardVerdict::Allow,
                Duration::from_micros(10),
            );
        }

        let recent = get_recent_evaluations(3);
        assert_eq!(recent.len(), 3);
    }
}
