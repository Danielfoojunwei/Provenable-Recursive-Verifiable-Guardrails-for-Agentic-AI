//! Guard context: CPI, MI, and CIO enforcement.
//!
//! Provides the `Guard` struct which loads policy and evaluates
//! control-plane, memory, and conversation requests.

use crate::alerts::{self, ThreatCategory};
use crate::metrics::EvalTimer;
use crate::policy;
use aegx_records::{audit_chain, config, records};
use aegx_types::*;
use serde_json::json;
use std::io;
use std::sync::Mutex;
use std::time::Instant;

/// Maximum number of denied guard evaluations per window.
const RATE_LIMIT_MAX_DENIALS: u64 = 100;
/// Rate limit window duration in seconds.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

static DENIAL_RATE_LIMITER: Mutex<Option<RateLimiterState>> = Mutex::new(None);

struct RateLimiterState {
    window_start: Instant,
    denial_count: u64,
}

fn check_denial_rate_limit() -> io::Result<()> {
    let mut lock = DENIAL_RATE_LIMITER
        .lock()
        .map_err(|_| io::Error::other("rate limiter lock poisoned"))?;

    let now = Instant::now();
    let state = lock.get_or_insert_with(|| RateLimiterState {
        window_start: now,
        denial_count: 0,
    });

    if now.duration_since(state.window_start).as_secs() >= RATE_LIMIT_WINDOW_SECS {
        state.window_start = now;
        state.denial_count = 0;
    }

    state.denial_count += 1;

    if state.denial_count > RATE_LIMIT_MAX_DENIALS {
        return Err(io::Error::other(format!(
            "Guard denial rate limit exceeded: {} denials in {} seconds. \
             Possible log flooding attack.",
            state.denial_count, RATE_LIMIT_WINDOW_SECS
        )));
    }

    Ok(())
}

fn classify_threat(surface: GuardSurface, taint: TaintFlags) -> ThreatCategory {
    if taint.contains(TaintFlags::INJECTION_SUSPECT) {
        return ThreatCategory::InjectionSuspect;
    }
    match surface {
        GuardSurface::ControlPlane => {
            if taint.is_tainted() {
                ThreatCategory::TaintBlock
            } else {
                ThreatCategory::CpiViolation
            }
        }
        GuardSurface::DurableMemory => {
            if taint.is_tainted() {
                ThreatCategory::TaintBlock
            } else {
                ThreatCategory::MiViolation
            }
        }
        GuardSurface::ConversationIO => {
            if taint.is_tainted() {
                ThreatCategory::TaintBlock
            } else {
                ThreatCategory::PromptExtraction
            }
        }
    }
}

/// Guard context holds the loaded policy and provides enforcement.
pub struct Guard {
    policy: PolicyPack,
}

impl Guard {
    pub fn new(policy: PolicyPack) -> Self {
        Guard { policy }
    }

    pub fn load_default() -> io::Result<Self> {
        let path = config::default_policy_file();
        let policy = if path.exists() {
            policy::load_policy(&path)?
        } else {
            policy::default_policy()
        };
        Ok(Guard { policy })
    }

    /// Evaluate a control-plane change request.
    pub fn check_control_plane(
        &self,
        principal: Principal,
        taint: TaintFlags,
        approved: bool,
        config_key: &str,
        change_detail: serde_json::Value,
        parent_records: Vec<String>,
    ) -> io::Result<(GuardVerdict, TypedRecord)> {
        let timer = EvalTimer::start(GuardSurface::ControlPlane);

        let (verdict, rule_id, rationale) = policy::evaluate(
            &self.policy,
            GuardSurface::ControlPlane,
            principal,
            taint,
            approved,
        );

        if verdict == GuardVerdict::Deny {
            check_denial_rate_limit()?;
        }

        let detail = GuardDecisionDetail {
            verdict,
            rule_id: rule_id.clone(),
            rationale: rationale.clone(),
            surface: GuardSurface::ControlPlane,
            principal,
            taint,
        };

        let mut meta = RecordMeta::now();
        meta.config_key = Some(config_key.to_string());
        meta.rule_id = Some(rule_id);

        let payload = json!({
            "guard_decision": detail,
            "change_request": change_detail,
        });

        let record = records::emit_record(
            RecordType::GuardDecision,
            principal,
            taint,
            parent_records,
            meta,
            payload,
        )?;

        audit_chain::emit_audit(&record.record_id)?;
        timer.finish(verdict);

        if verdict == GuardVerdict::Deny {
            let category = classify_threat(GuardSurface::ControlPlane, taint);
            let _ = alerts::emit_alert(category, &detail, &record.record_id, config_key);
            // Cross-surface correlation: CPI denial taints subsequent MI writes
            signal_cpi_denial(principal);
        }

        Ok((verdict, record))
    }

    /// Evaluate a memory write request.
    ///
    /// Cross-surface integration: if the principal was previously denied CPI
    /// access, their taint is automatically elevated (the attacker who tried
    /// to mutate config may also be trying to poison memory).
    pub fn check_memory_write(
        &self,
        principal: Principal,
        taint: TaintFlags,
        approved: bool,
        file_path: &str,
        content_hash: &str,
        parent_records: Vec<String>,
    ) -> io::Result<(GuardVerdict, TypedRecord)> {
        let timer = EvalTimer::start(GuardSurface::DurableMemory);

        // Apply cross-surface correlated taint
        let correlated = correlated_taint_for_principal(principal);
        let effective_taint = taint | correlated;

        let (verdict, rule_id, rationale) = policy::evaluate(
            &self.policy,
            GuardSurface::DurableMemory,
            principal,
            effective_taint,
            approved,
        );

        if verdict == GuardVerdict::Deny {
            check_denial_rate_limit()?;
        }

        let detail = GuardDecisionDetail {
            verdict,
            rule_id: rule_id.clone(),
            rationale: rationale.clone(),
            surface: GuardSurface::DurableMemory,
            principal,
            taint: effective_taint,
        };

        let mut meta = RecordMeta::now();
        meta.path = Some(file_path.to_string());
        meta.rule_id = Some(rule_id);

        let payload = json!({
            "guard_decision": detail,
            "file_path": file_path,
            "content_hash": content_hash,
            "correlated_taint_applied": !correlated.is_empty(),
        });

        let record = records::emit_record(
            RecordType::GuardDecision,
            principal,
            effective_taint,
            parent_records,
            meta,
            payload,
        )?;

        audit_chain::emit_audit(&record.record_id)?;
        timer.finish(verdict);

        if verdict == GuardVerdict::Deny {
            let category = classify_threat(GuardSurface::DurableMemory, effective_taint);
            let _ = alerts::emit_alert(category, &detail, &record.record_id, file_path);
        }

        Ok((verdict, record))
    }

    /// Evaluate an inbound message for prompt injection and extraction.
    pub fn check_conversation_input(
        &self,
        principal: Principal,
        base_taint: TaintFlags,
        content: &str,
        session_id: &str,
        parent_records: Vec<String>,
    ) -> io::Result<(GuardVerdict, crate::scanner::ScanResult, TypedRecord)> {
        let timer = EvalTimer::start(GuardSurface::ConversationIO);

        let mut scan_result = crate::scanner::scan_input(content);
        let conv_analysis = crate::scanner::analyze_in_context(session_id, content, &scan_result);

        if conv_analysis.crescendo_detected {
            scan_result.findings.push(crate::scanner::ScanFinding {
                category: crate::scanner::ScanCategory::ExtractionAttempt,
                description: format!(
                    "Crescendo attack detected via session analysis: {}",
                    conv_analysis.rationale
                ),
                confidence: 0.90,
                evidence: format!(
                    "Accumulated score: {:.2}, extraction messages: {}",
                    conv_analysis.accumulated_score, conv_analysis.extraction_message_count,
                ),
            });
            scan_result.taint_flags |= TaintFlags::UNTRUSTED.bits();

            scan_result.verdict = if scan_result.findings.iter().any(|f| {
                matches!(
                    f.category,
                    crate::scanner::ScanCategory::SystemImpersonation
                        | crate::scanner::ScanCategory::ExtractionAttempt
                ) && f.confidence >= 0.9
            }) || scan_result
                .findings
                .iter()
                .filter(|f| f.confidence >= 0.75)
                .count()
                >= 3
            {
                crate::scanner::ScanVerdict::Block
            } else {
                crate::scanner::ScanVerdict::Suspicious
            };
        }

        let scanner_taint =
            TaintFlags::from_bits(scan_result.taint_flags).unwrap_or(TaintFlags::empty());
        let combined_taint = base_taint | scanner_taint;

        let (verdict, rule_id, rationale) = match scan_result.verdict {
            crate::scanner::ScanVerdict::Block => (
                GuardVerdict::Deny,
                "scanner-block".to_string(),
                format!(
                    "Scanner blocked: {} findings (crescendo: {})",
                    scan_result.findings.len(),
                    conv_analysis.crescendo_detected
                ),
            ),
            _ => policy::evaluate(
                &self.policy,
                GuardSurface::ConversationIO,
                principal,
                combined_taint,
                false,
            ),
        };

        if verdict == GuardVerdict::Deny {
            check_denial_rate_limit()?;
        }

        let detail = GuardDecisionDetail {
            verdict,
            rule_id: rule_id.clone(),
            rationale: rationale.clone(),
            surface: GuardSurface::ConversationIO,
            principal,
            taint: combined_taint,
        };

        let mut meta = RecordMeta::now();
        meta.session_id = Some(session_id.to_string());
        meta.rule_id = Some(rule_id);

        let payload = json!({
            "guard_decision": detail,
            "scan_verdict": format!("{:?}", scan_result.verdict),
            "findings_count": scan_result.findings.len(),
        });

        let record = records::emit_record(
            RecordType::GuardDecision,
            principal,
            combined_taint,
            parent_records,
            meta,
            payload,
        )?;

        audit_chain::emit_audit(&record.record_id)?;
        timer.finish(verdict);

        if verdict == GuardVerdict::Deny {
            let category = classify_threat(GuardSurface::ConversationIO, combined_taint);
            let _ = alerts::emit_alert(category, &detail, &record.record_id, session_id);
            // Cross-surface: injection in conversation taints all subsequent operations
            if combined_taint.contains(TaintFlags::INJECTION_SUSPECT) {
                signal_injection_detected(session_id);
            }
        }

        Ok((verdict, scan_result, record))
    }

    /// Scan an outbound LLM response for system prompt leakage.
    pub fn check_conversation_output(
        &self,
        content: &str,
        session_id: &str,
        config: Option<&crate::output_guard::OutputGuardConfig>,
        parent_records: Vec<String>,
    ) -> io::Result<(bool, crate::output_guard::OutputScanResult, TypedRecord)> {
        let timer = EvalTimer::start(GuardSurface::ConversationIO);

        let registry_config = if config.is_none() {
            crate::output_guard::get_cached_config()
        } else {
            None
        };
        let effective_config = config.or(registry_config.as_ref());

        let scan_result = crate::output_guard::scan_output(content, effective_config);

        let verdict = if scan_result.safe {
            GuardVerdict::Allow
        } else {
            GuardVerdict::Deny
        };

        if verdict == GuardVerdict::Deny {
            check_denial_rate_limit()?;
        }

        let taint = if scan_result.safe {
            TaintFlags::empty()
        } else {
            TaintFlags::SECRET_RISK
        };

        let rule_id = if scan_result.safe {
            "output-clean".to_string()
        } else {
            "output-leak-detected".to_string()
        };

        let detail = GuardDecisionDetail {
            verdict,
            rule_id: rule_id.clone(),
            rationale: if scan_result.safe {
                "Output scan clean".to_string()
            } else {
                format!(
                    "Output leakage detected: {} tokens, {} structural leaks",
                    scan_result.leaked_tokens.len(),
                    scan_result.structural_leaks.len()
                )
            },
            surface: GuardSurface::ConversationIO,
            principal: Principal::Sys,
            taint,
        };

        let mut meta = RecordMeta::now();
        meta.session_id = Some(session_id.to_string());
        meta.rule_id = Some(rule_id);

        let payload = json!({
            "guard_decision": detail,
            "output_safe": scan_result.safe,
            "leaked_token_count": scan_result.leaked_tokens.len(),
            "structural_leak_count": scan_result.structural_leaks.len(),
        });

        let record = records::emit_record(
            RecordType::GuardDecision,
            Principal::Sys,
            taint,
            parent_records,
            meta,
            payload,
        )?;

        audit_chain::emit_audit(&record.record_id)?;
        timer.finish(verdict);

        if verdict == GuardVerdict::Deny {
            let _ = alerts::emit_alert(
                ThreatCategory::PromptLeakage,
                &detail,
                &record.record_id,
                session_id,
            );
        }

        Ok((scan_result.safe, scan_result, record))
    }
}

/// Convenience: gate a control-plane mutation.
pub fn gate_control_plane_change(
    principal: Principal,
    taint: TaintFlags,
    approved: bool,
    config_key: &str,
    change_detail: serde_json::Value,
    parent_records: Vec<String>,
) -> io::Result<GuardVerdict> {
    let guard = Guard::load_default()?;
    let (verdict, _) = guard.check_control_plane(
        principal,
        taint,
        approved,
        config_key,
        change_detail,
        parent_records,
    )?;
    Ok(verdict)
}

/// Convenience: gate a memory write.
pub fn gate_memory_write(
    principal: Principal,
    taint: TaintFlags,
    approved: bool,
    file_path: &str,
    content_hash: &str,
    parent_records: Vec<String>,
) -> io::Result<GuardVerdict> {
    let guard = Guard::load_default()?;
    let (verdict, _) = guard.check_memory_write(
        principal,
        taint,
        approved,
        file_path,
        content_hash,
        parent_records,
    )?;
    Ok(verdict)
}

// ============================================================
// Cross-Surface Correlation — First-Principles Integration
// ============================================================
//
// The four theorems (CPI, MI, Noninterference, RVU) are not independent:
// - A CPI violation by principal P implies all subsequent MI writes by P
//   should carry elevated taint (the attacker who mutates config may
//   also try to poison memory).
// - An injection detected in ConversationIO should escalate taint for
//   any tool calls or memory writes that follow in the same session.
// - Repeated denials across any surface trigger RVU (rollback), which
//   is handled by the runtime layer but informed by guard-level signals.
//
// This module tracks cross-surface signals so that guard decisions on
// one surface can inform decisions on others.

/// Cross-surface threat correlation state.
static CORRELATED_TAINT: Mutex<Option<CorrelationState>> = Mutex::new(None);

/// Tracks threat signals across guard surfaces.
#[derive(Debug, Clone)]
struct CorrelationState {
    /// Principals that have been denied on CPI — their MI writes get extra taint.
    cpi_denied_principals: Vec<(Principal, Instant)>,
    /// Sessions with detected injection — all subsequent operations tainted.
    injection_sessions: Vec<(String, Instant)>,
    /// Total denials across all surfaces in current window (for RVU escalation).
    cross_surface_denials: u64,
    /// Window start for cross-surface denial counting.
    window_start: Instant,
}

impl CorrelationState {
    fn new() -> Self {
        CorrelationState {
            cpi_denied_principals: Vec::new(),
            injection_sessions: Vec::new(),
            cross_surface_denials: 0,
            window_start: Instant::now(),
        }
    }

    /// Expire entries older than 5 minutes.
    fn expire(&mut self) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(300);
        self.cpi_denied_principals.retain(|(_, t)| *t > cutoff);
        self.injection_sessions.retain(|(_, t)| *t > cutoff);

        if self.window_start < cutoff {
            self.cross_surface_denials = 0;
            self.window_start = Instant::now();
        }
    }
}

/// Record a cross-surface signal: a CPI denial for a principal.
pub fn signal_cpi_denial(principal: Principal) {
    let mut lock = CORRELATED_TAINT.lock().unwrap_or_else(|e| e.into_inner());
    let state = lock.get_or_insert_with(CorrelationState::new);
    state.expire();
    state
        .cpi_denied_principals
        .push((principal, Instant::now()));
    state.cross_surface_denials += 1;
}

/// Record a cross-surface signal: injection detected in a session.
pub fn signal_injection_detected(session_id: &str) {
    let mut lock = CORRELATED_TAINT.lock().unwrap_or_else(|e| e.into_inner());
    let state = lock.get_or_insert_with(CorrelationState::new);
    state.expire();
    state
        .injection_sessions
        .push((session_id.to_string(), Instant::now()));
    state.cross_surface_denials += 1;
}

/// Query whether a principal has elevated taint due to cross-surface correlation.
/// Returns additional taint flags to apply.
pub fn correlated_taint_for_principal(principal: Principal) -> TaintFlags {
    let lock = CORRELATED_TAINT.lock().unwrap_or_else(|e| e.into_inner());
    match &*lock {
        Some(state) => {
            if state
                .cpi_denied_principals
                .iter()
                .any(|(p, _)| *p == principal)
            {
                // Principal was denied CPI access → taint their MI writes
                TaintFlags::UNTRUSTED
            } else {
                TaintFlags::empty()
            }
        }
        None => TaintFlags::empty(),
    }
}

/// Query whether a session has elevated taint due to injection detection.
pub fn correlated_taint_for_session(session_id: &str) -> TaintFlags {
    let lock = CORRELATED_TAINT.lock().unwrap_or_else(|e| e.into_inner());
    match &*lock {
        Some(state) => {
            if state
                .injection_sessions
                .iter()
                .any(|(s, _)| s == session_id)
            {
                TaintFlags::INJECTION_SUSPECT | TaintFlags::UNTRUSTED
            } else {
                TaintFlags::empty()
            }
        }
        None => TaintFlags::empty(),
    }
}

/// Reset cross-surface correlation state (for testing).
pub fn reset_correlation_state() {
    let mut lock = CORRELATED_TAINT.lock().unwrap_or_else(|e| e.into_inner());
    *lock = Some(CorrelationState::new());
}

/// Get the current cross-surface denial count (for RVU escalation decisions).
pub fn cross_surface_denial_count() -> u64 {
    let lock = CORRELATED_TAINT.lock().unwrap_or_else(|e| e.into_inner());
    match &*lock {
        Some(state) => state.cross_surface_denials,
        None => 0,
    }
}
