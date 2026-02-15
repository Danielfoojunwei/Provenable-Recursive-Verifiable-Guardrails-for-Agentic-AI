use crate::alerts;
use crate::audit_chain;
use crate::canonical::sha256_hex;
use crate::config;
use crate::guard;
use crate::records;
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
/// Returns Ok(record) if allowed, Err if denied.
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
        GuardVerdict::Deny => Ok(Err(decision_record)),
    }
}

/// Hook: gate and record a file write event (for workspace memory files).
/// This is the single chokepoint for MI enforcement.
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
            GuardVerdict::Deny => Ok(Err(decision_record)),
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

        // Emit proxy misconfiguration alert
        let _ = alerts::emit_proxy_alert(trusted_proxies, gateway_addr, &record.record_id);

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
        let _ = alerts::emit_alert(
            alerts::ThreatCategory::CpiViolation,
            &detail,
            &record.record_id,
            &package.name,
        );
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
        GuardVerdict::Deny => Ok(Err(decision_record)),
    }
}

/// Hook: scan an outbound LLM response through the output guard.
/// Returns Ok(Ok(record)) if the output is safe, Ok(Err(record)) if leakage detected.
pub fn on_message_output(
    agent_id: &str,
    session_id: &str,
    content: &str,
    output_guard_config: Option<&crate::output_guard::OutputGuardConfig>,
    parent_records: Vec<String>,
) -> io::Result<Result<TypedRecord, TypedRecord>> {
    let g = guard::Guard::load_default()?;
    let (safe, _scan_result, decision_record) = g.check_conversation_output(
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
        Ok(Err(decision_record))
    }
}
