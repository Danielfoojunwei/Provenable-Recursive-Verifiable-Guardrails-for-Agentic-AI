use crate::alerts::{self, ThreatCategory};
use crate::audit_chain;
use crate::config;
use crate::policy;
use crate::prove::EvalTimer;
use crate::records;
use crate::types::*;
use serde_json::json;
use std::io;
use std::sync::Mutex;
use std::time::Instant;

/// Maximum number of denied guard evaluations per window.
const RATE_LIMIT_MAX_DENIALS: u64 = 100;

/// Rate limit window duration in seconds.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Global rate limiter state for guard denials.
/// Tracks denied requests to detect log flooding attacks.
static DENIAL_RATE_LIMITER: Mutex<Option<RateLimiterState>> = Mutex::new(None);

struct RateLimiterState {
    window_start: Instant,
    denial_count: u64,
}

/// Check and update the denial rate limiter.
/// Returns Err if the rate limit has been exceeded (possible log flooding attack).
fn check_denial_rate_limit() -> io::Result<()> {
    let mut lock = DENIAL_RATE_LIMITER
        .lock()
        .map_err(|_| io::Error::other("rate limiter lock poisoned"))?;

    let now = Instant::now();
    let state = lock.get_or_insert_with(|| RateLimiterState {
        window_start: now,
        denial_count: 0,
    });

    // Reset window if expired
    if now.duration_since(state.window_start).as_secs() >= RATE_LIMIT_WINDOW_SECS {
        state.window_start = now;
        state.denial_count = 0;
    }

    state.denial_count += 1;

    if state.denial_count > RATE_LIMIT_MAX_DENIALS {
        return Err(io::Error::other(format!(
            "Guard denial rate limit exceeded: {} denials in {} seconds. \
             Possible log flooding attack. Further evaluations are blocked \
             until the window resets.",
            state.denial_count, RATE_LIMIT_WINDOW_SECS
        )));
    }

    Ok(())
}

/// Determine the threat category for a denial based on context.
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
    /// Create a guard with the given policy pack.
    pub fn new(policy: PolicyPack) -> Self {
        Guard { policy }
    }

    /// Load the guard from the default policy file, or use built-in defaults.
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
    /// Returns the guard decision record and whether the change is allowed.
    /// Denied requests are rate-limited to prevent log flooding attacks.
    /// Emits a ThreatAlert on denial for the feedback loop.
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

        // Rate-limit denied requests to prevent log flooding
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

        // Record metrics
        timer.finish(verdict);

        // Emit threat alert on denial
        if verdict == GuardVerdict::Deny {
            let category = classify_threat(GuardSurface::ControlPlane, taint);
            let _ = alerts::emit_alert(category, &detail, &record.record_id, config_key);
        }

        Ok((verdict, record))
    }

    /// Evaluate a memory write request.
    /// Returns the guard decision record and whether the write is allowed.
    /// Denied requests are rate-limited to prevent log flooding attacks.
    /// Emits a ThreatAlert on denial for the feedback loop.
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

        let (verdict, rule_id, rationale) = policy::evaluate(
            &self.policy,
            GuardSurface::DurableMemory,
            principal,
            taint,
            approved,
        );

        // Rate-limit denied requests to prevent log flooding
        if verdict == GuardVerdict::Deny {
            check_denial_rate_limit()?;
        }

        let detail = GuardDecisionDetail {
            verdict,
            rule_id: rule_id.clone(),
            rationale: rationale.clone(),
            surface: GuardSurface::DurableMemory,
            principal,
            taint,
        };

        let mut meta = RecordMeta::now();
        meta.path = Some(file_path.to_string());
        meta.rule_id = Some(rule_id);

        let payload = json!({
            "guard_decision": detail,
            "file_path": file_path,
            "content_hash": content_hash,
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

        // Record metrics
        timer.finish(verdict);

        // Emit threat alert on denial
        if verdict == GuardVerdict::Deny {
            let category = classify_threat(GuardSurface::DurableMemory, taint);
            let _ = alerts::emit_alert(category, &detail, &record.record_id, file_path);
        }

        Ok((verdict, record))
    }

    /// Evaluate an inbound message for prompt injection and extraction.
    /// Scans the message content, applies taint from findings, evaluates
    /// conversation-level state (crescendo detection), and evaluates policy.
    pub fn check_conversation_input(
        &self,
        principal: Principal,
        base_taint: TaintFlags,
        content: &str,
        session_id: &str,
        parent_records: Vec<String>,
    ) -> io::Result<(GuardVerdict, crate::scanner::ScanResult, TypedRecord)> {
        let timer = EvalTimer::start(GuardSurface::ConversationIO);

        // Run the per-message scanner
        let mut scan_result = crate::scanner::scan_input(content);

        // Conversation-level state analysis (Conversational Noninterference Corollary)
        // Detects crescendo attacks that distribute extraction intent across messages.
        let conv_analysis = crate::scanner::analyze_in_context(session_id, content, &scan_result);

        if conv_analysis.crescendo_detected {
            // Inject a synthetic ExtractionAttempt finding from session analysis
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
            // Escalate taint — crescendo probes carry UNTRUSTED at minimum
            scan_result.taint_flags |= TaintFlags::UNTRUSTED.bits();

            // Recompute verdict with the injected finding
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

        // Merge scanner taint with base taint
        let scanner_taint =
            TaintFlags::from_bits(scan_result.taint_flags).unwrap_or(TaintFlags::empty());
        let combined_taint = base_taint | scanner_taint;

        // Determine verdict: if scanner says Block, deny without policy check
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
            _ => {
                // Evaluate policy with combined taint
                policy::evaluate(
                    &self.policy,
                    GuardSurface::ConversationIO,
                    principal,
                    combined_taint,
                    false,
                )
            }
        };

        // Rate-limit denied requests
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

        // Emit threat alert on denial
        if verdict == GuardVerdict::Deny {
            let category = classify_threat(GuardSurface::ConversationIO, combined_taint);
            let _ = alerts::emit_alert(category, &detail, &record.record_id, session_id);
        }

        Ok((verdict, scan_result, record))
    }

    /// Scan an outbound LLM response for system prompt leakage.
    ///
    /// **v0.1.5**: When `config` is `None`, the guard now checks the
    /// `system_prompt_registry` for a cached config built from dynamic
    /// token discovery. This means dynamically discovered tokens are
    /// used automatically once a system prompt has been registered via
    /// `hooks::on_system_prompt_available()`.
    pub fn check_conversation_output(
        &self,
        content: &str,
        session_id: &str,
        config: Option<&crate::output_guard::OutputGuardConfig>,
        parent_records: Vec<String>,
    ) -> io::Result<(bool, crate::output_guard::OutputScanResult, TypedRecord)> {
        let timer = EvalTimer::start(GuardSurface::ConversationIO);

        // Fallback chain: explicit config > registry cache > static default
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

        // Emit alert on leakage detection
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

/// Convenience function: gate a control-plane mutation.
/// If denied, the mutation is NOT applied and an error is returned.
/// If allowed, the change record is emitted and the caller proceeds.
pub fn gate_control_plane_change(
    principal: Principal,
    taint: TaintFlags,
    approved: bool,
    config_key: &str,
    change_detail: serde_json::Value,
    parent_records: Vec<String>,
) -> io::Result<GuardVerdict> {
    let guard = Guard::load_default()?;
    let (verdict, _record) = guard.check_control_plane(
        principal,
        taint,
        approved,
        config_key,
        change_detail,
        parent_records,
    )?;
    Ok(verdict)
}

/// Convenience function: gate a memory write.
/// If denied, the write is NOT applied and an error is returned.
/// If allowed, the guard decision record is emitted and the caller proceeds.
pub fn gate_memory_write(
    principal: Principal,
    taint: TaintFlags,
    approved: bool,
    file_path: &str,
    content_hash: &str,
    parent_records: Vec<String>,
) -> io::Result<GuardVerdict> {
    let guard = Guard::load_default()?;
    let (verdict, _record) = guard.check_memory_write(
        principal,
        taint,
        approved,
        file_path,
        content_hash,
        parent_records,
    )?;
    Ok(verdict)
}
