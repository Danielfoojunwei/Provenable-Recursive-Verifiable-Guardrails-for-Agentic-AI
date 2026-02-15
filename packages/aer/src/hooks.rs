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
pub fn check_proxy_trust(trusted_proxies: &[String], gateway_addr: &str) -> io::Result<Option<TypedRecord>> {
    // Detect common misconfigurations
    let is_misconfig = trusted_proxies.iter().any(|p| {
        p == "0.0.0.0/0" || p == "*" || p == "::/0"
    });

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
        Ok(Some(record))
    } else {
        Ok(None)
    }
}
