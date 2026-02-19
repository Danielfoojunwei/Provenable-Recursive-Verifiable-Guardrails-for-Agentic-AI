use crate::alerts::{self as notif};
use crate::audit_chain;
use crate::canonical::sha256_hex;
use crate::config;
use crate::guard;
use crate::records;
use crate::rollback_policy;
use crate::types::*;
use serde_json::json;
use std::io;

/// Hook: capture a tool call event.
pub fn on_tool_call(
    agent_id: &str,
    session_id: &str,
    tool_id: &str,
    principal: Principal,
    taint: TaintFlags,
    arguments: serde_json::Value,
    parent_records: Vec<String>,
) -> io::Result<TypedRecord> {
    let mut meta = RecordMeta::now();
    meta.agent_id = Some(agent_id.to_string());
    meta.session_id = Some(session_id.to_string());
    meta.tool_id = Some(tool_id.to_string());

    let payload = json!({
        "tool_id": tool_id,
        "arguments": arguments,
    });

    let record = records::emit_record(
        RecordType::ToolCall,
        principal,
        taint,
        parent_records,
        meta,
        payload,
    )?;
    audit_chain::emit_audit(&record.record_id)?;
    Ok(record)
}

/// Hook: capture a tool result event.
pub fn on_tool_result(
    agent_id: &str,
    session_id: &str,
    tool_id: &str,
    principal: Principal,
    taint: TaintFlags,
    result: serde_json::Value,
    parent_records: Vec<String>,
) -> io::Result<TypedRecord> {
    let mut meta = RecordMeta::now();
    meta.agent_id = Some(agent_id.to_string());
    meta.session_id = Some(session_id.to_string());
    meta.tool_id = Some(tool_id.to_string());

    let payload = json!({
        "tool_id": tool_id,
        "result": result,
    });

    let record = records::emit_record(
        RecordType::ToolResult,
        principal,
        taint,
        parent_records,
        meta,
        payload,
    )?;
    audit_chain::emit_audit(&record.record_id)?;
    Ok(record)
}

/// Hook: capture a session start event.
pub fn on_session_start(
    agent_id: &str,
    session_id: &str,
    channel: &str,
    ip: Option<&str>,
) -> io::Result<TypedRecord> {
    let mut meta = RecordMeta::now();
    meta.agent_id = Some(agent_id.to_string());
    meta.session_id = Some(session_id.to_string());
    meta.channel = Some(channel.to_string());
    if let Some(ip) = ip {
        meta.ip = Some(ip.to_string());
    }

    let payload = json!({
        "agent_id": agent_id,
        "session_id": session_id,
        "channel": channel,
    });

    let record = records::emit_record(
        RecordType::SessionStart,
        Principal::Sys,
        TaintFlags::empty(),
        vec![],
        meta,
        payload,
    )?;
    audit_chain::emit_audit(&record.record_id)?;
    Ok(record)
}

/// Hook: capture a session message event.
pub fn on_session_message(
    agent_id: &str,
    session_id: &str,
    principal: Principal,
    taint: TaintFlags,
    content: serde_json::Value,
    parent_records: Vec<String>,
) -> io::Result<TypedRecord> {
    let mut meta = RecordMeta::now();
    meta.agent_id = Some(agent_id.to_string());
    meta.session_id = Some(session_id.to_string());

    let record = records::emit_record(
        RecordType::SessionMessage,
        principal,
        taint,
        parent_records,
        meta,
        content,
    )?;
    audit_chain::emit_audit(&record.record_id)?;
    Ok(record)
}

/// Hook: gate a control-plane change (skills install, config change, etc.)
/// This is the single chokepoint for CPI enforcement.
///
/// **v0.1.4**: Auto-snapshot before allowing CPI changes (RVU §2).
/// On denial, feeds the rollback policy engine for threshold-based
/// auto-rollback and recommendation alerts.
///
/// Returns Ok(Ok(record)) if allowed, Ok(Err(record)) if denied.
/// The `agent_message` field in the denial result may contain a
/// rollback recommendation or auto-rollback notification for the agent
/// to relay to the user.
pub fn on_control_plane_change(
    principal: Principal,
    taint: TaintFlags,
    approved: bool,
    config_key: &str,
    change_detail: serde_json::Value,
    parent_records: Vec<String>,
) -> io::Result<Result<TypedRecord, TypedRecord>> {
    let g = guard::Guard::load_default()?;
    let (verdict, decision_record) = g.check_control_plane(
        principal,
        taint,
        approved,
        config_key,
        change_detail.clone(),
        parent_records.clone(),
    )?;

    match verdict {
        GuardVerdict::Allow => {
            // RVU §2: Auto-snapshot before CPI change for recoverability
            let snapshot_id = match rollback_policy::auto_snapshot_before_cpi(config_key) {
                Ok(Some(id)) => {
                    notif::notify_auto_snapshot(config_key, &id);
                    Some(id)
                }
                Ok(None) => None, // Cooldown active, recent snapshot exists
                Err(e) => {
                    notif::notify_auto_snapshot_failed(config_key, &e.to_string());
                    None
                }
            };

            notif::notify_cpi_allowed(
                config_key,
                &format!("{:?}", principal),
                snapshot_id.as_deref(),
            );

            // Emit the actual change record
            let mut meta = RecordMeta::now();
            meta.config_key = Some(config_key.to_string());

            let record = records::emit_record(
                RecordType::ControlPlaneChangeRequest,
                principal,
                taint,
                vec![decision_record.record_id.clone()],
                meta,
                change_detail,
            )?;
            audit_chain::emit_audit(&record.record_id)?;
            Ok(Ok(record))
        }
        GuardVerdict::Deny => {
            let rule_id = decision_record.meta.rule_id.clone().unwrap_or_default();

            // Notify agent of denial
            notif::notify_cpi_denied(
                config_key,
                &format!("{:?}", principal),
                &rule_id,
                &decision_record.record_id,
            );

            // Feed denial into rollback policy engine
            let detail = GuardDecisionDetail {
                verdict: GuardVerdict::Deny,
                rule_id: rule_id.clone(),
                rationale: format!(
                    "CPI change '{}' denied for {:?} principal (taint: {:?})",
                    config_key, principal, taint
                ),
                surface: GuardSurface::ControlPlane,
                principal,
                taint,
            };
            if let Ok(policy_result) = rollback_policy::on_guard_denial(
                GuardSurface::ControlPlane,
                &detail.rule_id,
                &decision_record.record_id,
                &detail,
            ) {
                notif::notify_denial_policy(&policy_result);
            }

            Ok(Err(decision_record))
        }
    }
}

/// Hook: gate and record a file write event (for workspace memory files).
/// This is the single chokepoint for MI enforcement.
///
/// **v0.1.4**: On denial, feeds the rollback policy engine for threshold-based
/// auto-rollback and recommendation alerts.
///
/// Returns Ok(record) if allowed, Err if denied.
pub fn on_file_write(
    principal: Principal,
    taint: TaintFlags,
    approved: bool,
    file_path: &str,
    content: &[u8],
    parent_records: Vec<String>,
) -> io::Result<Result<TypedRecord, TypedRecord>> {
    let content_hash = sha256_hex(content);

    // Check if this is a memory file that needs MI guarding.
    // Use Path::file_name() for exact basename matching to prevent bypass
    // via crafted paths like "/tmp/not-actually-SOUL.md".
    let is_memory_file = std::path::Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|basename| config::MEMORY_FILES.contains(&basename))
        .unwrap_or(false);

    if is_memory_file {
        let g = guard::Guard::load_default()?;
        let (verdict, decision_record) = g.check_memory_write(
            principal,
            taint,
            approved,
            file_path,
            &content_hash,
            parent_records.clone(),
        )?;

        match verdict {
            GuardVerdict::Allow => {
                notif::notify_mi_write_allowed(file_path, &format!("{:?}", principal));

                // Emit FileWrite record
                let mut meta = RecordMeta::now();
                meta.path = Some(file_path.to_string());

                let payload = json!({
                    "file_path": file_path,
                    "content_hash": content_hash,
                    "content_size": content.len(),
                });

                let record = records::emit_record(
                    RecordType::FileWrite,
                    principal,
                    taint,
                    vec![decision_record.record_id.clone()],
                    meta,
                    payload,
                )?;
                audit_chain::emit_audit(&record.record_id)?;
                Ok(Ok(record))
            }
            GuardVerdict::Deny => {
                let rule_id = decision_record.meta.rule_id.clone().unwrap_or_default();

                notif::notify_mi_write_denied(
                    file_path,
                    &format!("{:?}", principal),
                    &rule_id,
                    &decision_record.record_id,
                );

                // Feed denial into rollback policy engine
                let detail = GuardDecisionDetail {
                    verdict: GuardVerdict::Deny,
                    rule_id: rule_id.clone(),
                    rationale: format!(
                        "Memory write to '{}' denied for {:?} principal (taint: {:?})",
                        file_path, principal, taint
                    ),
                    surface: GuardSurface::DurableMemory,
                    principal,
                    taint,
                };
                if let Ok(policy_result) = rollback_policy::on_guard_denial(
                    GuardSurface::DurableMemory,
                    &detail.rule_id,
                    &decision_record.record_id,
                    &detail,
                ) {
                    notif::notify_denial_policy(&policy_result);
                }

                Ok(Err(decision_record))
            }
        }
    } else {
        // Not a guarded memory file — allow but still record
        let mut meta = RecordMeta::now();
        meta.path = Some(file_path.to_string());

        let payload = json!({
            "file_path": file_path,
            "content_hash": content_hash,
            "content_size": content.len(),
        });

        let record = records::emit_record(
            RecordType::FileWrite,
            principal,
            taint,
            parent_records,
            meta,
            payload,
        )?;
        audit_chain::emit_audit(&record.record_id)?;
        Ok(Ok(record))
    }
}

/// Hook: detect proxy trust misconfiguration.
/// Emits an audit warning record (does not block).
pub fn check_proxy_trust(
    trusted_proxies: &[String],
    gateway_addr: &str,
) -> io::Result<Option<TypedRecord>> {
    // Detect common misconfigurations
    let is_misconfig = trusted_proxies
        .iter()
        .any(|p| p == "0.0.0.0/0" || p == "*" || p == "::/0");

    if is_misconfig {
        let mut meta = RecordMeta::now();
        meta.config_key = Some("gateway.trustedProxies".to_string());
        meta.ip = Some(gateway_addr.to_string());

        let payload = json!({
            "warning": "Overly permissive trustedProxies configuration detected",
            "trusted_proxies": trusted_proxies,
            "gateway_addr": gateway_addr,
            "recommendation": "Restrict trustedProxies to specific reverse proxy IPs",
        });

        let record = records::emit_record(
            RecordType::GuardDecision,
            Principal::Sys,
            TaintFlags::PROXY_DERIVED,
            vec![],
            meta,
            payload,
        )?;
        audit_chain::emit_audit(&record.record_id)?;

        // Emit proxy misconfiguration alert and notify agent
        if let Ok(_alert) = notif::emit_proxy_alert(trusted_proxies, gateway_addr, &record.record_id) {
            notif::notify_proxy_misconfig(trusted_proxies, gateway_addr);
        }

        Ok(Some(record))
    } else {
        Ok(None)
    }
}

/// Hook: verify a skill package before installation (ClawHub/ClawHavoc defense).
///
/// This hook should be called BEFORE `on_control_plane_change("skills.install", ...)`.
/// It scans the skill package for all known ClawHavoc attack vectors and returns
/// Ok(Ok(record)) if safe, Ok(Err(record)) if denied.
///
/// The verification result is recorded as tamper-evident evidence regardless of verdict.
pub fn on_skill_install(
    principal: Principal,
    taint: TaintFlags,
    package: &crate::skill_verifier::SkillPackage,
    existing_skills: &[&str],
    popular_skills: &[&str],
    parent_records: Vec<String>,
) -> io::Result<Result<TypedRecord, TypedRecord>> {
    let result = crate::skill_verifier::verify_skill_package(
        package,
        existing_skills,
        popular_skills,
    );

    let verdict_str = match result.verdict {
        crate::skill_verifier::SkillVerdict::Allow => "allow",
        crate::skill_verifier::SkillVerdict::RequireApproval => "require_approval",
        crate::skill_verifier::SkillVerdict::Deny => "deny",
    };

    let findings_json: Vec<serde_json::Value> = result.findings.iter().map(|f| {
        json!({
            "attack_vector": f.attack_vector,
            "severity": format!("{:?}", f.severity),
            "description": f.description,
            "file": f.file,
            "evidence": f.evidence,
        })
    }).collect();

    let mut meta = RecordMeta::now();
    meta.config_key = Some("skills.install".to_string());

    let payload = json!({
        "skill_verification": {
            "skill_name": package.name,
            "verdict": verdict_str,
            "findings_count": result.findings.len(),
            "findings": findings_json,
            "name_collision": result.name_collision,
            "name_similar_to": result.name_similar_to,
        },
    });

    let record_taint = if result.verdict == crate::skill_verifier::SkillVerdict::Deny {
        taint | TaintFlags::UNTRUSTED | TaintFlags::INJECTION_SUSPECT
    } else if result.verdict == crate::skill_verifier::SkillVerdict::RequireApproval {
        taint | TaintFlags::UNTRUSTED
    } else {
        taint
    };

    let record = records::emit_record(
        RecordType::GuardDecision,
        principal,
        record_taint,
        parent_records,
        meta,
        payload,
    )?;
    audit_chain::emit_audit(&record.record_id)?;

    // Notify agent of skill verification result
    notif::notify_skill_verdict(
        &package.name,
        verdict_str,
        result.findings.len(),
        &record.record_id,
    );

    // Emit alert on denial
    if result.verdict == crate::skill_verifier::SkillVerdict::Deny {
        let detail = GuardDecisionDetail {
            verdict: GuardVerdict::Deny,
            rule_id: "skill-verify-deny".to_string(),
            rationale: format!(
                "Skill '{}' blocked: {} findings (max severity: {:?})",
                package.name,
                result.findings.len(),
                result.findings.iter().map(|f| f.severity).max().unwrap_or(
                    crate::skill_verifier::SkillFindingSeverity::Info
                ),
            ),
            surface: GuardSurface::ControlPlane,
            principal,
            taint: record_taint,
        };
        if let Err(e) = notif::emit_alert(
            notif::ThreatCategory::CpiViolation,
            &detail,
            &record.record_id,
            &package.name,
        ) {
            notif::notify(
                notif::NotificationLevel::Warning,
                notif::NotificationSource::System,
                format!("Failed to emit skill denial alert: {}", e),
                Some(&record.record_id),
                None,
            );
        }
    }

    match result.verdict {
        crate::skill_verifier::SkillVerdict::Allow => Ok(Ok(record)),
        crate::skill_verifier::SkillVerdict::RequireApproval => {
            // Return Ok but the caller should prompt user for approval
            Ok(Ok(record))
        }
        crate::skill_verifier::SkillVerdict::Deny => Ok(Err(record)),
    }
}

/// Hook: scan an inbound user/channel message through the ConversationIO guard.
///
/// **v0.1.4**: On denial, feeds the rollback policy engine.
///
/// Returns Ok(Ok(record)) if the message is allowed, Ok(Err(record)) if blocked.
pub fn on_message_input(
    agent_id: &str,
    session_id: &str,
    principal: Principal,
    taint: TaintFlags,
    content: &str,
    parent_records: Vec<String>,
) -> io::Result<Result<TypedRecord, TypedRecord>> {
    let g = guard::Guard::load_default()?;
    let (verdict, scan_result, decision_record) = g.check_conversation_input(
        principal,
        taint,
        content,
        session_id,
        parent_records.clone(),
    )?;

    match verdict {
        GuardVerdict::Allow => {
            // Record the message as a session message
            let mut meta = RecordMeta::now();
            meta.agent_id = Some(agent_id.to_string());
            meta.session_id = Some(session_id.to_string());

            let scanner_taint = crate::types::TaintFlags::from_bits(scan_result.taint_flags)
                .unwrap_or(TaintFlags::empty());

            let payload = json!({
                "direction": "inbound",
                "content_length": content.len(),
                "scan_verdict": format!("{:?}", scan_result.verdict),
            });

            let record = records::emit_record(
                RecordType::SessionMessage,
                principal,
                taint | scanner_taint,
                vec![decision_record.record_id.clone()],
                meta,
                payload,
            )?;
            audit_chain::emit_audit(&record.record_id)?;
            Ok(Ok(record))
        }
        GuardVerdict::Deny => {
            let rule_id = decision_record.meta.rule_id.clone().unwrap_or_default();

            // Notify agent of input block
            notif::notify_input_blocked(
                &format!("{:?}", principal),
                &rule_id,
                &decision_record.record_id,
            );

            // Feed denial into rollback policy engine
            let detail = GuardDecisionDetail {
                verdict: GuardVerdict::Deny,
                rule_id: rule_id.clone(),
                rationale: format!(
                    "Inbound message from {:?} blocked by rule '{}' (taint: {:?})",
                    principal, rule_id, taint
                ),
                surface: GuardSurface::ConversationIO,
                principal,
                taint,
            };
            if let Ok(policy_result) = rollback_policy::on_guard_denial(
                GuardSurface::ConversationIO,
                &detail.rule_id,
                &decision_record.record_id,
                &detail,
            ) {
                notif::notify_denial_policy(&policy_result);
            }

            Ok(Err(decision_record))
        }
    }
}

/// Hook: scan an outbound LLM response through the output guard.
///
/// **v0.1.4**: On leakage detection, computes RVU contamination scope and
/// emits contamination alert so the agent can notify the user.
///
/// Returns Ok(Ok(record)) if the output is safe, Ok(Err(record)) if leakage detected.
pub fn on_message_output(
    agent_id: &str,
    session_id: &str,
    content: &str,
    output_guard_config: Option<&crate::output_guard::OutputGuardConfig>,
    parent_records: Vec<String>,
) -> io::Result<Result<TypedRecord, TypedRecord>> {
    let g = guard::Guard::load_default()?;
    let (safe, scan_result, decision_record) = g.check_conversation_output(
        content,
        session_id,
        output_guard_config,
        parent_records.clone(),
    )?;

    if safe {
        // Record the outbound message
        let mut meta = RecordMeta::now();
        meta.agent_id = Some(agent_id.to_string());
        meta.session_id = Some(session_id.to_string());

        let payload = json!({
            "direction": "outbound",
            "content_length": content.len(),
            "output_safe": true,
        });

        let record = records::emit_record(
            RecordType::SessionMessage,
            Principal::Sys,
            TaintFlags::empty(),
            vec![decision_record.record_id.clone()],
            meta,
            payload,
        )?;
        audit_chain::emit_audit(&record.record_id)?;
        Ok(Ok(record))
    } else {
        // Notify agent of output leakage block
        let leaked_count = scan_result.leaked_tokens.len();
        let structural_count = scan_result.structural_leaks.len();
        notif::notify_output_blocked(leaked_count, structural_count, &decision_record.record_id);

        // RVU: Compute contamination scope for leakage source
        if let Ok(scope) = rollback_policy::compute_contamination_scope(&decision_record.record_id) {
            if scope.contaminated_count > 0 {
                notif::notify(
                    notif::NotificationLevel::Critical,
                    notif::NotificationSource::RollbackPolicy,
                    format!(
                        "CONTAMINATION: {} downstream records affected by leakage source {}. Types: {}",
                        scope.contaminated_count,
                        &decision_record.record_id[..decision_record.record_id.len().min(12)],
                        scope.affected_types.join(", "),
                    ),
                    Some(&decision_record.record_id),
                    Some("Review contaminated records and consider rollback."),
                );
            }
            if let Err(e) = rollback_policy::emit_contamination_alert(&decision_record.record_id, &scope) {
                notif::notify(
                    notif::NotificationLevel::Warning,
                    notif::NotificationSource::System,
                    format!("Failed to emit contamination alert: {}", e),
                    Some(&decision_record.record_id),
                    None,
                );
            }
        }

        // Feed denial into rollback policy engine
        let rule_id = decision_record.meta.rule_id.clone().unwrap_or_default();
        let detail = GuardDecisionDetail {
            verdict: GuardVerdict::Deny,
            rule_id: rule_id.clone(),
            rationale: format!(
                "Output blocked: {} leaked tokens, {} structural patterns detected",
                leaked_count, structural_count
            ),
            surface: GuardSurface::ConversationIO,
            principal: Principal::Sys,
            taint: TaintFlags::SECRET_RISK,
        };
        if let Ok(policy_result) = rollback_policy::on_guard_denial(
            GuardSurface::ConversationIO,
            &detail.rule_id,
            &decision_record.record_id,
            &detail,
        ) {
            notif::notify_denial_policy(&policy_result);
        }

        Ok(Err(decision_record))
    }
}

// ============================================================
// v0.1.5 Hooks — Remaining Known Limitations
// ============================================================

/// Hook: register a system prompt for dynamic output guard token discovery.
///
/// **v0.1.5**: Implements the MI Dynamic Discovery Corollary. When the host
/// platform (OpenClaw or otherwise) makes the system prompt available, this
/// hook extracts protected identifiers and caches them in the
/// `system_prompt_registry`. Subsequent calls to `on_message_output()` will
/// automatically use the dynamically discovered tokens.
///
/// Returns Ok(record) with the count of dynamically discovered tokens.
pub fn on_system_prompt_available(
    agent_id: &str,
    session_id: &str,
    system_prompt: &str,
) -> io::Result<TypedRecord> {
    let token_count = crate::output_guard::register_system_prompt(system_prompt);
    let prompt_hash = crate::output_guard::prompt_hash()
        .unwrap_or_else(|| "unknown".to_string());

    let mut meta = RecordMeta::now();
    meta.agent_id = Some(agent_id.to_string());
    meta.session_id = Some(session_id.to_string());
    meta.config_key = Some("system_prompt.registered".to_string());

    let payload = json!({
        "event": "system_prompt_registered",
        "prompt_hash": prompt_hash,
        "dynamic_token_count": token_count,
        "prompt_length": system_prompt.len(),
    });

    let record = records::emit_record(
        RecordType::GuardDecision,
        Principal::Sys,
        TaintFlags::empty(),
        vec![],
        meta,
        payload,
    )?;
    audit_chain::emit_audit(&record.record_id)?;

    notif::notify(
        notif::NotificationLevel::Info,
        notif::NotificationSource::ConversationGuard,
        format!(
            "System prompt registered for dynamic output guard. \
             {} tokens discovered, prompt hash: {}.",
            token_count,
            &prompt_hash[..prompt_hash.len().min(12)]
        ),
        Some(&record.record_id),
        None,
    );

    Ok(record)
}

/// Hook: gate a file read through the file read guard.
///
/// **v0.1.5**: Extends the MI Theorem read-side to arbitrary files (not just
/// workspace MEMORY_FILES). Sensitive files (`.env`, SSH keys, credentials)
/// are denied for untrusted principals and tainted with SECRET_RISK.
///
/// Returns Ok(Ok(record)) if allowed, Ok(Err(record)) if denied.
pub fn on_file_read(
    agent_id: &str,
    session_id: &str,
    principal: Principal,
    taint: TaintFlags,
    file_path: &str,
    parent_records: Vec<String>,
) -> io::Result<Result<TypedRecord, TypedRecord>> {
    let check = crate::file_read_guard::check_file_read(principal, taint, file_path, None);

    let mut meta = RecordMeta::now();
    meta.agent_id = Some(agent_id.to_string());
    meta.session_id = Some(session_id.to_string());
    meta.path = Some(file_path.to_string());

    match check.verdict {
        GuardVerdict::Allow => {
            let payload = json!({
                "event": "file_read",
                "file_path": file_path,
                "verdict": "allow",
                "output_taint": check.output_taint.bits(),
                "matched_pattern": check.matched_pattern,
            });

            let record = records::emit_record(
                RecordType::FileRead,
                principal,
                check.output_taint,
                parent_records,
                meta,
                payload,
            )?;
            audit_chain::emit_audit(&record.record_id)?;
            Ok(Ok(record))
        }
        GuardVerdict::Deny => {
            meta.rule_id = Some("fs-deny-sensitive".to_string());

            let payload = json!({
                "guard_decision": {
                    "verdict": "Deny",
                    "rule_id": "fs-deny-sensitive",
                    "rationale": check.rationale,
                    "surface": "FileSystem",
                    "principal": format!("{:?}", principal),
                    "taint": check.output_taint.bits(),
                },
                "file_path": file_path,
                "matched_pattern": check.matched_pattern,
            });

            let record = records::emit_record(
                RecordType::GuardDecision,
                principal,
                check.output_taint,
                parent_records,
                meta,
                payload,
            )?;
            audit_chain::emit_audit(&record.record_id)?;

            notif::notify(
                notif::NotificationLevel::Error,
                notif::NotificationSource::MiGuard,
                format!(
                    "File read DENIED: {:?} principal attempted to read sensitive file '{}'. {}",
                    principal, file_path, check.rationale
                ),
                Some(&record.record_id),
                Some("Untrusted principals cannot read sensitive files (.env, SSH keys, credentials)."),
            );

            Ok(Err(record))
        }
    }
}

/// Hook: gate an outbound network request through the network egress guard.
///
/// **v0.1.5**: Extends the Noninterference Theorem to the network boundary.
/// Requests to known exfiltration services are denied. Domain allowlists
/// restrict untrusted principals. Oversized payloads are flagged.
///
/// Returns Ok(Ok(record)) if allowed, Ok(Err(record)) if denied.
pub fn on_outbound_request(
    agent_id: &str,
    session_id: &str,
    principal: Principal,
    taint: TaintFlags,
    url: &str,
    method: &str,
    payload_size: usize,
    parent_records: Vec<String>,
) -> io::Result<Result<TypedRecord, TypedRecord>> {
    let check = crate::network_guard::check_outbound_request(
        principal, taint, url, method, payload_size, None,
    );

    let mut meta = RecordMeta::now();
    meta.agent_id = Some(agent_id.to_string());
    meta.session_id = Some(session_id.to_string());

    let flags_json: Vec<serde_json::Value> = check
        .flags
        .iter()
        .map(|f| json!({
            "category": format!("{:?}", f.category),
            "description": &f.description,
        }))
        .collect();

    match check.verdict {
        GuardVerdict::Allow => {
            let payload = json!({
                "event": "outbound_request",
                "url": url,
                "method": method,
                "payload_size": payload_size,
                "verdict": "allow",
                "flags": flags_json,
                "output_taint": check.output_taint.bits(),
            });

            let record = records::emit_record(
                RecordType::ToolCall,
                principal,
                check.output_taint,
                parent_records,
                meta,
                payload,
            )?;
            audit_chain::emit_audit(&record.record_id)?;
            Ok(Ok(record))
        }
        GuardVerdict::Deny => {
            meta.rule_id = Some("net-deny-egress".to_string());

            let payload = json!({
                "guard_decision": {
                    "verdict": "Deny",
                    "rule_id": "net-deny-egress",
                    "rationale": check.rationale,
                    "surface": "NetworkIO",
                    "principal": format!("{:?}", principal),
                    "taint": check.output_taint.bits(),
                },
                "url": url,
                "method": method,
                "payload_size": payload_size,
                "flags": flags_json,
            });

            let record = records::emit_record(
                RecordType::GuardDecision,
                principal,
                check.output_taint,
                parent_records,
                meta,
                payload,
            )?;
            audit_chain::emit_audit(&record.record_id)?;

            notif::notify(
                notif::NotificationLevel::Error,
                notif::NotificationSource::ConversationGuard,
                format!(
                    "Outbound {} request DENIED: {:?} principal attempted {} — {}",
                    method, principal, url, check.rationale
                ),
                Some(&record.record_id),
                Some("Request was blocked by the network egress guard."),
            );

            Ok(Err(record))
        }
    }
}

/// Hook: audit the OS sandbox environment on session start.
///
/// **v0.1.5**: Runs the sandbox audit and records the result as tamper-evident
/// evidence. Emits alerts if the sandbox is insufficient.
///
/// Returns the audit result and the evidence record.
pub fn on_sandbox_audit(
    agent_id: &str,
    session_id: &str,
) -> io::Result<(crate::sandbox_audit::SandboxAuditResult, TypedRecord)> {
    let audit = crate::sandbox_audit::audit_sandbox_environment();
    let profile = crate::sandbox_audit::default_profile();
    let violations = crate::sandbox_audit::evaluate_profile(&audit, &profile);

    let mut meta = RecordMeta::now();
    meta.agent_id = Some(agent_id.to_string());
    meta.session_id = Some(session_id.to_string());
    meta.config_key = Some("sandbox.audit".to_string());

    let payload = json!({
        "event": "sandbox_audit",
        "compliance": format!("{}", audit.compliance),
        "in_container": audit.in_container,
        "seccomp_active": audit.seccomp_active,
        "seccomp_mode": audit.seccomp_mode,
        "namespaces": audit.namespaces,
        "readonly_root": audit.readonly_root,
        "resource_limits": audit.resource_limits,
        "violations": violations,
        "findings_count": audit.findings.len(),
    });

    let record = records::emit_record(
        RecordType::GuardDecision,
        Principal::Sys,
        TaintFlags::empty(),
        vec![],
        meta,
        payload,
    )?;
    audit_chain::emit_audit(&record.record_id)?;

    // Emit notifications based on compliance level
    match audit.compliance {
        crate::sandbox_audit::SandboxCompliance::Full => {
            notif::notify(
                notif::NotificationLevel::Info,
                notif::NotificationSource::System,
                "Sandbox audit: FULL compliance. Container + seccomp + namespaces + readonly root.",
                Some(&record.record_id),
                None,
            );
        }
        crate::sandbox_audit::SandboxCompliance::Partial => {
            notif::notify(
                notif::NotificationLevel::Warning,
                notif::NotificationSource::System,
                format!(
                    "Sandbox audit: PARTIAL compliance. {} violation(s): {}",
                    violations.len(),
                    violations.join("; ")
                ),
                Some(&record.record_id),
                Some("Consider adding missing sandbox layers for full protection."),
            );
        }
        crate::sandbox_audit::SandboxCompliance::None => {
            notif::notify(
                notif::NotificationLevel::Critical,
                notif::NotificationSource::System,
                format!(
                    "Sandbox audit: NO OS sandboxing detected. {} violation(s): {}. \
                     Skills can execute arbitrary code without restriction.",
                    violations.len(),
                    violations.join("; ")
                ),
                Some(&record.record_id),
                Some("Deploy in a container with seccomp filtering for production use."),
            );
        }
    }

    Ok((audit, record))
}
